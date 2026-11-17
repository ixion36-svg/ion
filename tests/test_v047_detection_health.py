"""v0.47.0 — Detection Health (per-rule performance analytics).

Covers the aggregation correctness (closure-basis FP/TP math, MIN_SAMPLE
suppression, silent/noisy/decaying flags, unmapped bucket, Bob-disagreement
deduped and excluding abstentions, empty DB) and the endpoints (security:read
gate on metrics, de:propose gate + validation on the proposal POST).

Closure figures come from rule_outcome_service since the rule-outcomes change:
a closed case is the verdict, whether or not Bob saw the alert.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.models.ai_feedback import AIFeedback
from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage, AlertTriageStatus
from ion.models.user import User
from ion.services.detection_health_service import get_detection_health
from ion.web.api import get_db_session
from ion.web.server import app

_NAIVE_NOW = datetime.now(timezone.utc).replace(tzinfo=None)


def _triage(session, alert_id, rule_name, *, case=None, days_ago=1):
    t = AlertTriage(es_alert_id=alert_id, rule_name=rule_name,
                    status=AlertTriageStatus.OPEN, case_id=case.id if case else None)
    t.created_at = _NAIVE_NOW - timedelta(days=days_ago, hours=1)
    session.add(t)


def _closed(session, alert_id, rule_name, reason, *, days_ago=1):
    """One alert on one rule, in a case closed with ``reason``."""
    c = AlertCase(case_number=f"C-{alert_id}", title=alert_id, created_by_id=1,
                  status=AlertCaseStatus.CLOSED, closure_reason=reason, severity="medium")
    c.closed_at = _NAIVE_NOW - timedelta(days=days_ago)
    session.add(c)
    session.flush()
    _triage(session, alert_id, rule_name, case=c, days_ago=days_ago)


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


def test_bob_dedup_keeps_close_row_over_pending(session, monkeypatch):
    monkeypatch.setenv("ION_DH_MIN_SAMPLE", "1")
    _closed(session, "es-1", "Rule A", "true_positive")
    # fire-time pending row, then the case-close row (higher id) for same alert.
    _fb(session, "es-1", "pending", template_id=5, bob="true_positive", agreement=None)
    _fb(session, "es-1", "true_positive", template_id=5, bob="false_positive", agreement=False)
    session.commit()

    a = _rule(get_detection_health(session, days=365), "Rule A")
    assert a["volume"] == 1
    assert a["closed"] == 1
    assert a["tp_yield"] == 100.0
    assert a["bob_scored"] == 1  # deduped to the close row
    assert a["bob_disagreement_rate"] == 100.0


# ── FP/TP math + thresholds ─────────────────────────────────────────────────


def test_fp_tp_rates_and_noisy_silent_flags(session, monkeypatch):
    monkeypatch.setenv("ION_DH_MIN_SAMPLE", "4")
    monkeypatch.setenv("ION_DH_NOISY_FP_PCT", "70")
    # Noisy rule: 4 FP / 1 TP over 5 closed → fp_rate 80% ≥ 70 → noisy, not silent.
    for i in range(4):
        _closed(session, f"noisy-{i}", "Noisy Rule", "false_positive")
    _closed(session, "noisy-tp", "Noisy Rule", "true_positive")
    # Silent rule: 5 FP, 0 TP → silent + noisy.
    for i in range(5):
        _closed(session, f"silent-{i}", "Silent Rule", "false_positive")
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
        _closed(session, f"tiny-{i}", "Tiny Rule", "false_positive")
    session.commit()

    tiny = _rule(get_detection_health(session, days=365), "Tiny Rule")
    assert tiny["closed"] == 2
    assert tiny["fp_rate"] == 100.0
    assert tiny["flags"]["noisy"] is False  # suppressed under MIN_SAMPLE
    assert tiny["flags"]["silent"] is False


def test_benign_closure_is_closed_but_not_a_false_positive(session, monkeypatch):
    monkeypatch.setenv("ION_DH_MIN_SAMPLE", "1")
    _closed(session, "b-1", "Benign Rule", "benign_true_positive")
    session.commit()
    r = _rule(get_detection_health(session, days=365), "Benign Rule")
    assert r["closed"] == 1
    assert r["fp_count"] == 0
    assert r["fp_rate"] == 0.0


# ── decay ──────────────────────────────────────────────────────────────────


def test_decaying_flag(session, monkeypatch):
    monkeypatch.setenv("ION_DH_MIN_SAMPLE", "4")
    monkeypatch.setenv("ION_DH_DECAY_DELTA_PCT", "20")
    # window 90d → midpoint 45d. Older half (TP-heavy) vs recent half (FP-heavy).
    for i in range(3):
        _closed(session, f"old-tp-{i}", "Decay Rule", "true_positive", days_ago=70)
    for i in range(3):
        _closed(session, f"new-fp-{i}", "Decay Rule", "false_positive", days_ago=5)
    session.commit()

    r = _rule(get_detection_health(session, days=90), "Decay Rule")
    assert r["flags"]["decaying"] is True


# ── unmapped + bob disagreement ─────────────────────────────────────────────


def test_null_rule_name_buckets_as_unmapped(session, monkeypatch):
    monkeypatch.setenv("ION_DH_MIN_SAMPLE", "1")
    _closed(session, "orphan-1", None, "true_positive")
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


def test_a_rule_bob_scored_but_nobody_closed_keeps_its_name(session, monkeypatch):
    """A triage row older than the window, scored by Bob inside it."""
    t = AlertTriage(es_alert_id="old-1", rule_name="Old Rule", rule_id="r-old",
                    status=AlertTriageStatus.OPEN)
    t.created_at = _NAIVE_NOW - timedelta(days=200)
    session.add(t)
    _fb(session, "old-1", "pending", bob="false_positive", agreement=False)
    session.commit()

    rule = next(r for r in get_detection_health(session, days=90)["rules"] if r["rule_id"] == "r-old")
    assert rule["rule_name"] == "Old Rule"
    assert rule["bob_scored"] == 1
