"""v0.47.0 — Detection Health (per-rule performance analytics).

Covers the aggregation correctness (dedup, FP/TP math, MIN_SAMPLE suppression,
silent/noisy/decaying flags, unmapped bucket, Bob-disagreement excluding
abstentions, empty DB) and the endpoints (security:read gate on metrics,
tuning:review gate + validation on the proposal POST).
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.models.ai_feedback import AIFeedback
from ion.models.alert_triage import AlertTriage, AlertTriageStatus
from ion.models.user import User
from ion.services.detection_health_service import get_detection_health
from ion.web.api import get_db_session
from ion.web.server import app

_NAIVE_NOW = datetime.now(timezone.utc).replace(tzinfo=None)


def _triage(session, alert_id, rule_name):
    session.add(AlertTriage(es_alert_id=alert_id, rule_name=rule_name,
                            status=AlertTriageStatus.OPEN))


def _fb(session, alert_id, human_verdict, *, template_id=None, bob=None,
        agreement=None, auto_escalated=False, days_ago=1):
    fb = AIFeedback(
        alert_id=alert_id,
        alert_prompt_template_id=template_id,
        human_verdict=human_verdict,
        bob_suggested_verdict=bob,
        agreement=agreement,
        auto_escalated=auto_escalated,
    )
    fb.created_at = _NAIVE_NOW - timedelta(days=days_ago)
    session.add(fb)
    return fb


def _rule(health, name):
    return next((r for r in health["rules"] if r["rule_name"] == name), None)


# ── dedup ──────────────────────────────────────────────────────────────────


def test_dedup_keeps_close_row_over_pending(session, monkeypatch):
    monkeypatch.setenv("ION_DH_MIN_SAMPLE", "1")
    _triage(session, "es-1", "Rule A")
    # fire-time pending row, then the case-close row (higher id) for same alert.
    _fb(session, "es-1", "pending", template_id=5)
    _fb(session, "es-1", "true_positive", template_id=5)
    session.commit()

    health = get_detection_health(session, days=365)
    a = _rule(health, "Rule A")
    assert a is not None
    assert a["volume"] == 1  # deduped to one row
    assert a["closed"] == 1
    assert a["tp_count"] == 1
    assert a["tp_yield"] == 100.0


# ── FP/TP math + thresholds ─────────────────────────────────────────────────


def test_fp_tp_rates_and_noisy_silent_flags(session, monkeypatch):
    monkeypatch.setenv("ION_DH_MIN_SAMPLE", "4")
    monkeypatch.setenv("ION_DH_NOISY_FP_PCT", "70")
    # Noisy rule: 4 FP / 1 TP over 5 closed → fp_rate 80% ≥ 70 → noisy, not silent.
    for i in range(4):
        _triage(session, f"noisy-{i}", "Noisy Rule")
        _fb(session, f"noisy-{i}", "false_positive")
    _triage(session, "noisy-tp", "Noisy Rule")
    _fb(session, "noisy-tp", "true_positive")
    # Silent rule: 5 FP, 0 TP → silent + noisy.
    for i in range(5):
        _triage(session, f"silent-{i}", "Silent Rule")
        _fb(session, f"silent-{i}", "false_positive")
    session.commit()

    health = get_detection_health(session, days=365)
    noisy = _rule(health, "Noisy Rule")
    assert noisy["fp_rate"] == 80.0
    assert noisy["tp_yield"] == 20.0
    assert noisy["flags"]["noisy"] is True
    assert noisy["flags"]["silent"] is False

    silent = _rule(health, "Silent Rule")
    assert silent["flags"]["silent"] is True
    assert silent["tp_count"] == 0


def test_min_sample_suppresses_flags_and_rates_stay_but_no_flag(session, monkeypatch):
    monkeypatch.setenv("ION_DH_MIN_SAMPLE", "5")
    # Only 2 closed (below MIN_SAMPLE 5) → no flags even though 100% FP.
    for i in range(2):
        _triage(session, f"tiny-{i}", "Tiny Rule")
        _fb(session, f"tiny-{i}", "false_positive")
    session.commit()

    health = get_detection_health(session, days=365)
    tiny = _rule(health, "Tiny Rule")
    assert tiny["closed"] == 2
    assert tiny["flags"]["noisy"] is False  # suppressed under MIN_SAMPLE
    assert tiny["flags"]["silent"] is False


def test_benign_tp_counts_as_fp_toggle(session, monkeypatch):
    monkeypatch.setenv("ION_DH_MIN_SAMPLE", "1")
    monkeypatch.setenv("ION_DH_BENIGN_TP_AS_FP", "false")
    _triage(session, "b-1", "Benign Rule")
    _fb(session, "b-1", "benign_true_positive")
    session.commit()
    health = get_detection_health(session, days=365)
    r = _rule(health, "Benign Rule")
    assert r["fp_count"] == 0  # benign not counted as FP when toggle off


# ── decay ──────────────────────────────────────────────────────────────────


def test_decaying_flag(session, monkeypatch):
    monkeypatch.setenv("ION_DH_MIN_SAMPLE", "4")
    monkeypatch.setenv("ION_DH_DECAY_DELTA_PCT", "20")
    # window 90d → midpoint 45d. Older half (TP-heavy) vs recent half (FP-heavy).
    for i in range(3):
        _triage(session, f"old-tp-{i}", "Decay Rule")
        _fb(session, f"old-tp-{i}", "true_positive", days_ago=70)
    for i in range(3):
        _triage(session, f"new-fp-{i}", "Decay Rule")
        _fb(session, f"new-fp-{i}", "false_positive", days_ago=5)
    session.commit()

    health = get_detection_health(session, days=90)
    r = _rule(health, "Decay Rule")
    assert r["flags"]["decaying"] is True


# ── unmapped + bob disagreement ─────────────────────────────────────────────


def test_null_rule_name_buckets_as_unmapped(session, monkeypatch):
    monkeypatch.setenv("ION_DH_MIN_SAMPLE", "1")
    # feedback with no matching triage row → rule_name resolves NULL → "(unmapped)".
    _fb(session, "orphan-1", "true_positive")
    session.commit()
    health = get_detection_health(session, days=365)
    assert _rule(health, "(unmapped)") is not None
    assert health["summary"]["unmapped_alerts"] == 1


def test_bob_disagreement_excludes_abstentions(session, monkeypatch):
    monkeypatch.setenv("ION_DH_MIN_SAMPLE", "1")
    _triage(session, "d-1", "Bob Rule")
    _fb(session, "d-1", "true_positive", bob="false_positive", agreement=False)  # scored disagree
    _triage(session, "d-2", "Bob Rule")
    _fb(session, "d-2", "true_positive", bob="true_positive", agreement=True)  # scored agree
    _triage(session, "d-3", "Bob Rule")
    _fb(session, "d-3", "true_positive", bob=None, agreement=None)  # no suggestion
    _triage(session, "d-4", "Bob Rule")
    _fb(session, "d-4", "true_positive", bob="false_positive", agreement=False, auto_escalated=True)  # abstention
    session.commit()

    health = get_detection_health(session, days=365)
    r = _rule(health, "Bob Rule")
    assert r["bob_scored"] == 2  # only d-1 + d-2 (excludes no-suggestion + abstention)
    assert r["bob_disagreement_rate"] == 50.0


# ── empty ──────────────────────────────────────────────────────────────────


def test_empty_db_is_safe(session):
    health = get_detection_health(session, days=90)
    assert health["rules"] == []
    assert health["summary"]["rules_tracked"] == 0
    assert health["summary"]["noisy_rules"] == 0


# ── endpoints ───────────────────────────────────────────────────────────────


def _client(session, perms):
    user = User(id=1, username="lead", email="l@x", password_hash="x",
                display_name="Lead", is_active=True)
    user.has_permission = lambda p: p in perms  # type: ignore[method-assign]
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: session
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.clear()


def test_metrics_requires_security_read(session):
    client = _client(session, perms=set())  # no perms
    assert client.get("/api/detection-health/metrics").status_code == 403
    client2 = _client(session, perms={"security:read"})
    r = client2.get("/api/detection-health/metrics?days=30")
    assert r.status_code == 200
    assert "rules" in r.json()


def test_create_proposal_gate_and_validation(session):
    """v0.72.0 (route audit phase 8): this action now files a DetectionProposal
    into the DE module's governed queue instead of the retired TuningProposal
    table, so the gate moved tuning:review -> de:propose. The gate itself is
    unchanged in strength — a user without it still gets 403."""
    from ion.models.detection_proposal import DetectionProposal

    # Without de:propose → 403 (security:read alone can read, not file).
    client = _client(session, perms={"security:read"})
    assert client.post("/api/detection-health/tuning-proposal",
                       json={"rule_name": "R", "suggested_change": "x"}).status_code == 403

    # With de:propose → happy path persists a DetectionProposal draft.
    client2 = _client(session, perms={"de:propose"})
    r = client2.post("/api/detection-health/tuning-proposal",
                     json={"rule_name": "Noisy Rule", "suggested_change": "raise threshold to 5",
                           "rationale": "80% FP"})
    assert r.status_code == 200
    body = r.json()
    assert body["rule_name"] == "Noisy Rule"
    assert body["status"] == "draft"
    assert body["source"] == "human"      # an analyst filed it, not Bob
    assert session.query(DetectionProposal).filter_by(rule_name="Noisy Rule").count() == 1

    # Missing suggested_change → 400.
    assert client2.post("/api/detection-health/tuning-proposal",
                        json={"rule_name": "R", "suggested_change": "  "}).status_code == 400
