"""v0.64.0 — Attack Path (Bob Pathfinding) Phase 4.

Pins the confidence-gated **escalation tier** ("try harder" deep pass before
abstaining) and the Attack Path **master feature flag**:

* the pure decision helper ``_should_escalate_deep_pass`` — fires on
  low-confidence + high/critical, skips on low-severity / when disabled / when
  already high-confidence, and never re-escalates (single-retry guard);
* ``_escalation_deep_pass`` — runs one more-sampled pass (samples/model from
  config) and is a safe no-op when the LLM is unavailable (air-gap);
* the resolve semantics via ``_write_bob_outputs`` — a deep pass that clears
  threshold suppresses the abstention (verdict persists), one that stays low
  falls through to the existing auto-escalate badge; both flag
  ``escalation_attempted`` on the Investigation + AIFeedback rows;
* the master flag ``ION_ATTACK_PATH_ENABLED=false`` degrades
  ``build_attack_path`` (endpoint + Bob injection + recurrence) to an empty
  graph without touching ES.

All tested WITHOUT a real LLM (the deep pass is monkeypatched / crafted).
"""
from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ion.models.ai_feedback import AIFeedback
from ion.models.alert_triage import AlertTriage, AlertTriageStatus
from ion.models.base import Base
from ion.models.investigation import Investigation
from ion.models.user import User
from ion.services.investigation_service import (
    InvestigationError,
    InvestigationService,
    _bob_escalation_model,
    _bob_escalation_samples,
    _bob_escalation_tier_enabled,
    _compute_confidence,
    _severity_is_high,
    _should_escalate_deep_pass,
    _write_bob_outputs,
)
from ion.storage.database import _run_migrations

# ---------------------------------------------------------------------------
# Crafted parsed envelopes (as _parse_llm_json would return)
# ---------------------------------------------------------------------------


def _parsed(confidence: int, severity: str = "high", verdict: str = "true_positive") -> dict:
    """A parsed dict whose _compute_confidence == confidence (no deductions)."""
    return {
        "confidence": confidence,
        "confidence_level": "high" if confidence >= 60 else "low",
        "verdict": verdict,
        "severity": severity,
        "summary": "crafted",
        "recommended_actions": [],
        "recommended_actions_structured": [],
        "suggested_closure_reason": verdict,  # matches verdict -> no -15
        "key_observations": [
            {"field": "process.name", "value": "cmd.exe", "significance": "shell"}
        ],
        "analyst_explanation": "crafted",
        "mitre": {"techniques": [], "tactics": []},
        "iocs": [],
        "tuning_recommendation": {"rule_needs_tuning": False},
    }


# ---------------------------------------------------------------------------
# TASK 1a — pure decision helper
# ---------------------------------------------------------------------------


class TestShouldEscalateDecision:
    def test_fires_low_confidence_high_severity(self, monkeypatch):
        monkeypatch.delenv("ION_BOB_ESCALATION_TIER_ENABLED", raising=False)
        monkeypatch.delenv("ION_BOB_CONFIDENCE_THRESHOLD", raising=False)
        # confidence 30 < 60 threshold, severity high, tier on, first attempt.
        assert _should_escalate_deep_pass(_parsed(30, "high")) is True

    def test_fires_on_critical(self, monkeypatch):
        monkeypatch.delenv("ION_BOB_ESCALATION_TIER_ENABLED", raising=False)
        assert _should_escalate_deep_pass(_parsed(10, "critical")) is True

    def test_skipped_low_severity(self, monkeypatch):
        monkeypatch.delenv("ION_BOB_ESCALATION_TIER_ENABLED", raising=False)
        # Low severity → cheap alert just abstains as today.
        assert _should_escalate_deep_pass(_parsed(30, "low")) is False
        assert _should_escalate_deep_pass(_parsed(30, "medium")) is False

    def test_input_alert_severity_overrides_low_bob_severity(self, monkeypatch):
        monkeypatch.delenv("ION_BOB_ESCALATION_TIER_ENABLED", raising=False)
        # Bob assessed 'low' but the *input* alert is critical → still fires.
        assert (
            _should_escalate_deep_pass(_parsed(30, "low"), severity="critical")
            is True
        )

    def test_skipped_when_confidence_already_meets_threshold(self, monkeypatch):
        monkeypatch.delenv("ION_BOB_ESCALATION_TIER_ENABLED", raising=False)
        monkeypatch.setenv("ION_BOB_CONFIDENCE_THRESHOLD", "60")
        assert _should_escalate_deep_pass(_parsed(80, "high")) is False

    def test_single_retry_guard_no_loop(self, monkeypatch):
        monkeypatch.delenv("ION_BOB_ESCALATION_TIER_ENABLED", raising=False)
        # An already-escalated attempt must never escalate again.
        assert (
            _should_escalate_deep_pass(_parsed(10, "critical"), already_escalated=True)
            is False
        )

    def test_skipped_when_tier_disabled(self, monkeypatch):
        monkeypatch.setenv("ION_BOB_ESCALATION_TIER_ENABLED", "false")
        assert _should_escalate_deep_pass(_parsed(10, "critical")) is False

    def test_severity_helper(self):
        assert _severity_is_high("high") is True
        assert _severity_is_high("CRITICAL") is True
        assert _severity_is_high("low", None, "") is False
        assert _severity_is_high(None, "medium") is False


class TestEscalationConfigKnobs:
    def test_samples_default_and_clamp(self, monkeypatch):
        monkeypatch.delenv("ION_BOB_ESCALATION_SAMPLES", raising=False)
        assert _bob_escalation_samples() == 3
        monkeypatch.setenv("ION_BOB_ESCALATION_SAMPLES", "5")
        assert _bob_escalation_samples() == 5
        monkeypatch.setenv("ION_BOB_ESCALATION_SAMPLES", "99")
        assert _bob_escalation_samples() == 5  # clamped
        monkeypatch.setenv("ION_BOB_ESCALATION_SAMPLES", "0")
        assert _bob_escalation_samples() == 1  # clamped
        monkeypatch.setenv("ION_BOB_ESCALATION_SAMPLES", "notint")
        assert _bob_escalation_samples() == 3  # falls back to default

    def test_model_default_empty(self, monkeypatch):
        monkeypatch.delenv("ION_BOB_ESCALATION_MODEL", raising=False)
        # Default air-gap-safe: empty → same 8B model.
        assert _bob_escalation_model() == ""
        monkeypatch.setenv("ION_BOB_ESCALATION_MODEL", "big-prod-model")
        assert _bob_escalation_model() == "big-prod-model"

    def test_tier_enabled_default_on(self, monkeypatch):
        monkeypatch.delenv("ION_BOB_ESCALATION_TIER_ENABLED", raising=False)
        assert _bob_escalation_tier_enabled() is True
        monkeypatch.setenv("ION_BOB_ESCALATION_TIER_ENABLED", "0")
        assert _bob_escalation_tier_enabled() is False


# ---------------------------------------------------------------------------
# TASK 1b — the deep-pass runner (LLM monkeypatched)
# ---------------------------------------------------------------------------


class TestEscalationDeepPass:
    def test_runs_with_escalation_samples_and_model(self, monkeypatch):
        monkeypatch.setenv("ION_BOB_ESCALATION_SAMPLES", "3")
        monkeypatch.setenv("ION_BOB_ESCALATION_MODEL", "prod-big")
        svc = InvestigationService()
        captured = {}

        async def _fake_call_llm(*, system_prompt, user_body, anon_map, samples, model):
            captured["samples"] = samples
            captured["model"] = model
            return _parsed(75, "high"), "prod-big", 100, 1234, "{}"

        monkeypatch.setattr(svc, "_call_llm", _fake_call_llm)
        result = asyncio.run(
            svc._escalation_deep_pass(system_prompt="s", user_body="u", anon_map=None)
        )
        assert result is not None
        parsed, model, _eval, _ms, _raw = result
        assert _compute_confidence(parsed) == 75
        assert captured["samples"] == 3
        assert captured["model"] == "prod-big"

    def test_airgap_no_op_when_llm_unavailable(self, monkeypatch):
        """Ollama unconfigured → InvestigationError → None (caller abstains)."""
        svc = InvestigationService()

        async def _boom(*, system_prompt, user_body, anon_map, samples, model):
            raise InvestigationError("Ollama service is not available")

        monkeypatch.setattr(svc, "_call_llm", _boom)
        result = asyncio.run(
            svc._escalation_deep_pass(system_prompt="s", user_body="u", anon_map=None)
        )
        assert result is None


# ---------------------------------------------------------------------------
# TASK 1c — resolve semantics via _write_bob_outputs (real SQLite DB)
# ---------------------------------------------------------------------------


@pytest.fixture()
def session(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'esc.db'}")
    Base.metadata.create_all(eng)
    try:
        _run_migrations(eng)
    except Exception:
        pass
    sess = sessionmaker(bind=eng)()
    yield sess
    sess.close()


@pytest.fixture()
def bob_user(session):
    bob = User(
        username="bob",
        email="bob@ion.local",
        password_hash="x",
        is_service_account=True,
        is_active=True,
    )
    session.add(bob)
    session.flush()
    from ion.services import ai_user as _ai_user
    _ai_user._bob_user_id_cache = bob.id
    return bob


@pytest.fixture()
def triage(session):
    t = AlertTriage(es_alert_id="esc-alert-001", status=AlertTriageStatus.OPEN)
    session.add(t)
    session.flush()
    return t


def _seed_inv(session) -> Investigation:
    inv = Investigation(
        alert_id_ref="esc-alert-001", alert_signature="sig", status="running"
    )
    session.add(inv)
    session.flush()
    return inv


class TestResolveSemantics:
    def test_deep_pass_raises_confidence_suppresses_abstention(
        self, session, bob_user, triage, monkeypatch
    ):
        monkeypatch.setenv("ION_BOB_CONFIDENCE_THRESHOLD", "60")
        inv = _seed_inv(session)
        # Deep pass now returns 82 >= 60 → verdict persists, no abstention.
        deep_parsed = _parsed(82, "high")
        _write_bob_outputs(
            db=session,
            alert_id="esc-alert-001",
            investigation_id=inv.id,
            parsed=deep_parsed,
            template=None,
            escalation_attempted=True,
        )
        session.flush()

        t = session.query(AlertTriage).filter_by(es_alert_id="esc-alert-001").one()
        assert t.suggested_verdict == "true_positive"
        assert t.bob_escalation_badge is None
        fb = session.query(AIFeedback).filter_by(investigation_id=inv.id).one()
        assert fb.auto_escalated is False
        assert fb.escalation_attempted is True
        assert session.get(Investigation, inv.id).escalation_attempted is True

    def test_deep_pass_still_low_falls_through_to_auto_escalate(
        self, session, bob_user, triage, monkeypatch
    ):
        monkeypatch.setenv("ION_BOB_CONFIDENCE_THRESHOLD", "60")
        inv = _seed_inv(session)
        # Deep pass stayed at 25 < 60 → existing circuit breaker fires.
        deep_parsed = _parsed(25, "high")
        _write_bob_outputs(
            db=session,
            alert_id="esc-alert-001",
            investigation_id=inv.id,
            parsed=deep_parsed,
            template=None,
            escalation_attempted=True,
        )
        session.flush()

        t = session.query(AlertTriage).filter_by(es_alert_id="esc-alert-001").one()
        assert t.suggested_verdict is None
        assert t.bob_escalation_badge == "low_confidence_triage"
        fb = session.query(AIFeedback).filter_by(investigation_id=inv.id).one()
        assert fb.auto_escalated is True
        # Telemetry records the deep pass DID run even though it stayed low.
        assert fb.escalation_attempted is True
        assert session.get(Investigation, inv.id).escalation_attempted is True

    def test_no_escalation_flag_defaults_false(
        self, session, bob_user, triage, monkeypatch
    ):
        monkeypatch.setenv("ION_BOB_CONFIDENCE_THRESHOLD", "60")
        inv = _seed_inv(session)
        _write_bob_outputs(
            db=session,
            alert_id="esc-alert-001",
            investigation_id=inv.id,
            parsed=_parsed(90, "high"),
            template=None,
        )
        session.flush()
        fb = session.query(AIFeedback).filter_by(investigation_id=inv.id).one()
        assert fb.escalation_attempted is False
        assert session.get(Investigation, inv.id).escalation_attempted is False


# ---------------------------------------------------------------------------
# TASK 2 — Attack Path master feature flag
# ---------------------------------------------------------------------------


class TestAttackPathMasterFlag:
    def test_helper_default_on(self, monkeypatch):
        import ion.services.attack_path_service as aps

        monkeypatch.delenv("ION_ATTACK_PATH_ENABLED", raising=False)
        assert aps.attack_path_enabled() is True
        monkeypatch.setenv("ION_ATTACK_PATH_ENABLED", "false")
        assert aps.attack_path_enabled() is False
        monkeypatch.setenv("ION_ATTACK_PATH_ENABLED", "1")
        assert aps.attack_path_enabled() is True

    def test_build_attack_path_empty_when_disabled(self, monkeypatch):
        import ion.services.attack_path_service as aps

        called = {"fetch": False}

        async def _fake_fetch(session, case_id):
            called["fetch"] = True
            return [
                {
                    "id": "a1",
                    "timestamp": "2026-07-30T12:00:00+00:00",
                    "host": "HOST-A",
                    "user": "alice",
                    "parent_process_name": "explorer.exe",
                    "process_name": "powershell.exe",
                    "mitre_tactic_name": "Execution",
                    "observables": [],
                }
            ]

        monkeypatch.setattr(aps, "_fetch_case_alert_dicts", _fake_fetch)

        # Disabled → empty graph, ES fetch never happens.
        monkeypatch.setenv("ION_ATTACK_PATH_ENABLED", "false")
        g = asyncio.run(aps.build_attack_path(None, 5))
        assert g["case_id"] == 5
        assert g["nodes"] == []
        assert g["edges"] == []
        assert called["fetch"] is False

        # Enabled → populated graph, ES fetch runs.
        monkeypatch.setenv("ION_ATTACK_PATH_ENABLED", "1")
        g2 = asyncio.run(aps.build_attack_path(None, 5))
        assert called["fetch"] is True
        assert any(n["id"] == "host:HOST-A" for n in g2["nodes"])
