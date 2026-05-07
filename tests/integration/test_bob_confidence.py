"""Integration tests for Bob confidence scoring + circuit breakers.

Uses SQLite in-process (no mocks, no Docker). Exercises _write_bob_outputs
directly with a real session to verify DB writes.

Setup notes:
- Creates a bare DB using Base.metadata.create_all (plus migrations) so all
  new columns exist.
- Seeds a Bob service account (is_service_account=True) — required by
  _write_bob_outputs to proceed.
- Does NOT test LLM calls; calls _write_bob_outputs directly with a
  hand-crafted parsed dict.
"""
from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ion.models.base import Base
from ion.models.alert_triage import AlertTriage, AlertTriageStatus
from ion.models.ai_feedback import AIFeedback
from ion.models.alert_prompt import AlertPromptTemplate
from ion.models.user import User
from ion.storage.database import _run_migrations


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    db_path = tmp_path / "bob_confidence_test.db"
    eng = create_engine(f"sqlite:///{db_path}")
    # Create all tables via SQLAlchemy metadata (handles new columns in models)
    Base.metadata.create_all(eng)
    # Run idempotent migrations to handle any alter-table columns not in models
    try:
        _run_migrations(eng)
    except Exception:
        pass  # Migrations are best-effort on fresh DB
    return eng


@pytest.fixture()
def session(engine):
    factory = sessionmaker(bind=engine)
    sess = factory()
    yield sess
    sess.close()


@pytest.fixture()
def bob_user(session):
    """Seed the Bob service account so _write_bob_outputs proceeds."""
    bob = User(
        username="bob",
        email="bob@ion.local",
        password_hash="x",
        is_service_account=True,
        is_active=True,
    )
    session.add(bob)
    session.flush()
    # Stash in the module-level cache that get_bob_user_id uses
    from ion.services import ai_user as _ai_user
    _ai_user._bob_user_id_cache = bob.id
    return bob


@pytest.fixture()
def alert_triage(session):
    """A bare AlertTriage row for the test alert."""
    triage = AlertTriage(
        es_alert_id="test-alert-001",
        status=AlertTriageStatus.OPEN,
    )
    session.add(triage)
    session.flush()
    return triage


def _base_parsed(**overrides) -> dict:
    """Minimal parsed dict (as _parse_llm_json would return) for testing."""
    base = {
        "confidence": 85,
        "confidence_level": "high",
        "verdict": "true_positive",
        "severity": "high",
        "summary": "Malicious activity confirmed.",
        "recommended_actions": ["Block the IP", "Quarantine host"],
        "recommended_actions_structured": [],
        "suggested_closure_reason": "true_positive",
        "key_observations": [
            {"field": "process.name", "value": "cmd.exe", "significance": "suspicious shell"},
        ],
        "analyst_explanation": "Confirmed lateral movement.",
        "technical_details": "",
        "mitre": {"techniques": ["T1059"], "tactics": ["execution"]},
        "iocs": [],
        "affected_assets": [],
        "timeline": [],
        "kill_chain_phase": "unknown",
        "containment_state": "not_applicable",
        "blast_radius": None,
        "references": [],
        "tuning_recommendation": {"rule_needs_tuning": False, "rationale": None, "suggested_change": None},
        "template_specific": {},
    }
    base.update(overrides)
    return base


def _call_write_bob_outputs(session, alert_id, inv_id, parsed, template=None):
    from ion.services.investigation_service import _write_bob_outputs
    _write_bob_outputs(
        db=session,
        alert_id=alert_id,
        investigation_id=inv_id,
        parsed=parsed,
        template=template,
    )
    session.flush()


def _seed_investigation(session, alert_id="test-alert-001", template_id=None):
    from ion.models.investigation import Investigation
    inv = Investigation(
        alert_id_ref=alert_id,
        alert_signature="test-sig",
        status="running",
        prompt_template_id=template_id,
    )
    session.add(inv)
    session.flush()
    return inv


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAboveThreshold:
    """Happy path: confidence >= threshold writes verdict + non-escalated feedback."""

    def test_happy_path_writes_suggested_verdict(
        self, session, bob_user, alert_triage, monkeypatch
    ):
        monkeypatch.setenv("ION_BOB_CONFIDENCE_THRESHOLD", "60")
        inv = _seed_investigation(session)
        parsed = _base_parsed(confidence=85)  # 85 - 0 deductions = 85
        _call_write_bob_outputs(session, "test-alert-001", inv.id, parsed)

        triage = session.query(AlertTriage).filter_by(es_alert_id="test-alert-001").one()
        assert triage.suggested_verdict == "true_positive"
        assert triage.suggested_verdict_confidence == "high"
        assert triage.suggested_verdict_confidence_int == 85
        assert triage.bob_escalation_badge is None

    def test_happy_path_writes_aifeedback_not_escalated(
        self, session, bob_user, alert_triage, monkeypatch
    ):
        monkeypatch.setenv("ION_BOB_CONFIDENCE_THRESHOLD", "60")
        inv = _seed_investigation(session)
        parsed = _base_parsed(confidence=85)
        _call_write_bob_outputs(session, "test-alert-001", inv.id, parsed)

        fb = (
            session.query(AIFeedback)
            .filter_by(investigation_id=inv.id)
            .one()
        )
        assert fb.auto_escalated is False
        assert fb.bob_confidence_int == 85
        assert fb.bob_suggested_verdict == "true_positive"

    def test_confidence_stored_on_investigation(
        self, session, bob_user, alert_triage, monkeypatch
    ):
        monkeypatch.setenv("ION_BOB_CONFIDENCE_THRESHOLD", "60")
        from ion.models.investigation import Investigation
        inv = _seed_investigation(session)
        parsed = _base_parsed(confidence=85)
        _call_write_bob_outputs(session, "test-alert-001", inv.id, parsed)

        inv_row = session.get(Investigation, inv.id)
        assert inv_row.confidence_int == 85


class TestBelowThreshold:
    """Circuit breaker: confidence < threshold suppresses verdict + escalates."""

    def test_below_threshold_no_suggested_verdict(
        self, session, bob_user, alert_triage, monkeypatch
    ):
        monkeypatch.setenv("ION_BOB_CONFIDENCE_THRESHOLD", "60")
        inv = _seed_investigation(session)
        # confidence=10 valid verdict, no closure mismatch, has observations -> stays 10
        parsed = _base_parsed(confidence=10)
        _call_write_bob_outputs(session, "test-alert-001", inv.id, parsed)

        triage = session.query(AlertTriage).filter_by(es_alert_id="test-alert-001").one()
        assert triage.suggested_verdict is None
        assert triage.bob_escalation_badge == "low_confidence_triage"

    def test_below_threshold_aifeedback_escalated(
        self, session, bob_user, alert_triage, monkeypatch
    ):
        monkeypatch.setenv("ION_BOB_CONFIDENCE_THRESHOLD", "60")
        inv = _seed_investigation(session)
        parsed = _base_parsed(confidence=10)
        _call_write_bob_outputs(session, "test-alert-001", inv.id, parsed)

        fb = (
            session.query(AIFeedback)
            .filter_by(investigation_id=inv.id)
            .one()
        )
        assert fb.auto_escalated is True
        assert fb.bob_suggested_verdict is None
        assert fb.bob_confidence_int == 10


class TestPerTemplateOverride:
    """Per-template confidence_threshold_override beats global env."""

    def test_template_override_beats_global(
        self, session, bob_user, alert_triage, monkeypatch
    ):
        monkeypatch.setenv("ION_BOB_CONFIDENCE_THRESHOLD", "80")
        # Template lowers threshold to 40 → confidence=50 should pass
        template = AlertPromptTemplate(
            name="low-bar-template",
            prompt_text="investigate",
            confidence_threshold_override=40,
        )
        session.add(template)
        session.flush()

        inv = _seed_investigation(session, template_id=template.id)
        parsed = _base_parsed(confidence=50)
        _call_write_bob_outputs(session, "test-alert-001", inv.id, parsed, template=template)

        triage = session.query(AlertTriage).filter_by(es_alert_id="test-alert-001").one()
        # confidence=50 >= template threshold 40 -> happy path
        assert triage.suggested_verdict == "true_positive"
        assert triage.bob_escalation_badge is None

    def test_template_override_stricter_than_global(
        self, session, bob_user, alert_triage, monkeypatch
    ):
        monkeypatch.setenv("ION_BOB_CONFIDENCE_THRESHOLD", "40")
        # Template raises threshold to 80 → confidence=50 should fail
        template = AlertPromptTemplate(
            name="strict-template",
            prompt_text="investigate strictly",
            confidence_threshold_override=80,
        )
        session.add(template)
        session.flush()

        inv = _seed_investigation(session, template_id=template.id)
        parsed = _base_parsed(confidence=50)
        _call_write_bob_outputs(session, "test-alert-001", inv.id, parsed, template=template)

        triage = session.query(AlertTriage).filter_by(es_alert_id="test-alert-001").one()
        assert triage.suggested_verdict is None
        assert triage.bob_escalation_badge == "low_confidence_triage"


class TestThresholdZeroDisablesBreaker:
    """threshold=0 means everything passes (breaker disabled)."""

    def test_threshold_zero_always_passes(
        self, session, bob_user, alert_triage, monkeypatch
    ):
        monkeypatch.setenv("ION_BOB_CONFIDENCE_THRESHOLD", "0")
        inv = _seed_investigation(session)
        # Even confidence=0 should pass when threshold=0
        parsed = _base_parsed(confidence=0)
        _call_write_bob_outputs(session, "test-alert-001", inv.id, parsed)

        triage = session.query(AlertTriage).filter_by(es_alert_id="test-alert-001").one()
        # confidence_int after compute: 0 - 10 (no observations? no — we have key_observations)
        # actually parsed has key_observations -> 0 - 0 = 0 >= threshold 0 -> pass
        assert triage.bob_escalation_badge is None


class TestReasoningStorage:
    """ION_BOB_STORE_REASONING gates reasoning_text persistence."""

    def test_reasoning_not_stored_by_default(
        self, session, bob_user, alert_triage, monkeypatch
    ):
        monkeypatch.setenv("ION_BOB_CONFIDENCE_THRESHOLD", "60")
        monkeypatch.delenv("ION_BOB_STORE_REASONING", raising=False)
        from ion.models.investigation import Investigation
        inv = _seed_investigation(session)
        parsed = _base_parsed(confidence=85)
        _call_write_bob_outputs(session, "test-alert-001", inv.id, parsed)

        inv_row = session.get(Investigation, inv.id)
        assert inv_row.reasoning_text is None

    def test_reasoning_stored_when_flag_set(
        self, session, bob_user, alert_triage, monkeypatch
    ):
        monkeypatch.setenv("ION_BOB_CONFIDENCE_THRESHOLD", "60")
        monkeypatch.setenv("ION_BOB_STORE_REASONING", "true")
        from ion.models.investigation import Investigation
        inv = _seed_investigation(session)
        parsed = _base_parsed(confidence=85, analyst_explanation="Detailed reasoning here.")
        _call_write_bob_outputs(session, "test-alert-001", inv.id, parsed)

        inv_row = session.get(Investigation, inv.id)
        assert inv_row.reasoning_text == "Detailed reasoning here."
