"""v0.55.0 — Detection Engineering module, Phase 0 (DE Metrics).

Read-only measurement over existing data — no write path. Covers:
- Noise-campaign clustering of FP/benign closures by rule (counts, cost math,
  min-cluster filter, benign toggle, first/last-seen window),
- signature / host / MITRE roll-up inside a campaign,
- Bob-vs-human agreement off the deduped AIFeedback ledger (excludes abstentions),
- noise-trend direction (recent vs older half),
- empty DB safety,
- the endpoints' `de:read` gate.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.models.ai_feedback import AIFeedback
from ion.models.alert_triage import (
    AlertCase,
    AlertCaseStatus,
    AlertTriage,
    AlertTriageStatus,
)
from ion.models.user import User
from ion.services.de_metrics_service import get_de_metrics, get_noise_campaigns
from ion.web.api import get_db_session
from ion.web.server import app

_NAIVE_NOW = datetime.now(timezone.utc).replace(tzinfo=None)


def _case(session, num, *, reason, days_ago=1, severity="medium", hosts=None):
    c = AlertCase(
        case_number=num,
        title=f"case {num}",
        created_by_id=1,
        status=AlertCaseStatus.CLOSED,
        closure_reason=reason,
        severity=severity,
        affected_hosts=hosts or [],
    )
    c.closed_at = _NAIVE_NOW - timedelta(days=days_ago)
    session.add(c)
    session.flush()  # assign c.id for the triage FK
    return c


def _triage(session, alert_id, rule_name, case_id, *, observables=None, mitre=None):
    session.add(AlertTriage(
        es_alert_id=alert_id,
        rule_name=rule_name,
        status=AlertTriageStatus.CLOSED,
        case_id=case_id,
        observables=observables,
        mitre_techniques=mitre,
    ))


def _fp_alerts(session, rule_name, n, *, reason="false_positive", days_ago=1, prefix=""):
    """A closed FP/benign case with n triage alerts on one rule."""
    c = _case(session, f"C-{prefix}{rule_name}-{days_ago}", reason=reason, days_ago=days_ago)
    for i in range(n):
        _triage(session, f"{prefix}{rule_name}-{i}-{days_ago}", rule_name, c.id)
    return c


def _camp(result, rule_name):
    return next((x for x in result["campaigns"] if x["rule_name"] == rule_name), None)


# ── clustering + cost ────────────────────────────────────────────────────────


def test_clusters_fp_by_rule_with_cost(session, monkeypatch):
    monkeypatch.setenv("ION_DE_MINUTES_PER_ALERT", "15")
    monkeypatch.setenv("ION_DE_MIN_CAMPAIGN", "2")
    _fp_alerts(session, "Noisy Rule", 4)
    _fp_alerts(session, "Small Rule", 2)
    session.commit()

    nc = get_noise_campaigns(session, days=365)
    noisy = _camp(nc, "Noisy Rule")
    small = _camp(nc, "Small Rule")
    assert noisy["fp_alerts"] == 4
    assert noisy["cost_hours"] == 1.0  # 4 × 15min = 60min = 1.0h
    assert small["cost_hours"] == 0.5  # 2 × 15min = 30min
    # costliest first
    assert nc["campaigns"][0]["rule_name"] == "Noisy Rule"
    assert nc["total_fp_alerts"] == 6
    assert nc["addressable_hours"] == 1.5


def test_min_campaign_filters_small_clusters(session, monkeypatch):
    monkeypatch.setenv("ION_DE_MIN_CAMPAIGN", "3")
    _fp_alerts(session, "Below", 2)
    _fp_alerts(session, "Above", 3)
    session.commit()

    nc = get_noise_campaigns(session, days=365)
    assert _camp(nc, "Below") is None  # under min cluster size
    assert _camp(nc, "Above")["fp_alerts"] == 3


def test_benign_split_and_toggle(session, monkeypatch):
    monkeypatch.setenv("ION_DE_MIN_CAMPAIGN", "1")
    _fp_alerts(session, "Rule X", 2, reason="false_positive", prefix="fp")
    _fp_alerts(session, "Rule X", 3, reason="benign_true_positive", prefix="bn")
    session.commit()

    nc = get_noise_campaigns(session, days=365)
    x = _camp(nc, "Rule X")
    assert x["false_positive"] == 2
    assert x["benign_true_positive"] == 3
    assert x["fp_alerts"] == 5

    # Toggle benign OFF → only the 2 false_positive alerts remain.
    monkeypatch.setenv("ION_DE_BENIGN_TP_AS_FP", "false")
    nc2 = get_noise_campaigns(session, days=365)
    x2 = _camp(nc2, "Rule X")
    assert x2["fp_alerts"] == 2
    assert x2["benign_true_positive"] == 0


def test_signatures_hosts_and_mitre_rollup(session, monkeypatch):
    monkeypatch.setenv("ION_DE_MIN_CAMPAIGN", "1")
    c = _case(session, "C-sig", reason="false_positive", severity="low",
              hosts=["web01", "web01", "db02"])
    _triage(session, "a1", "Scanner Rule", c.id,
            observables=[{"type": "process", "value": "nessus.exe"}],
            mitre=["T1046"])
    _triage(session, "a2", "Scanner Rule", c.id,
            observables=[{"type": "process", "value": "nessus.exe"}],
            mitre=[{"technique_id": "T1046"}, "T1595"])
    session.commit()

    nc = get_noise_campaigns(session, days=365)
    r = _camp(nc, "Scanner Rule")
    assert r["fp_alerts"] == 2
    top_sig = r["top_signatures"][0]
    assert top_sig["value"] == "process:nessus.exe" and top_sig["count"] == 2
    assert set(r["mitre_techniques"]) == {"T1046", "T1595"}
    assert {h["value"] for h in r["top_hosts"]} == {"web01", "db02"}


def test_window_first_last_seen(session, monkeypatch):
    monkeypatch.setenv("ION_DE_MIN_CAMPAIGN", "2")
    _fp_alerts(session, "Rule W", 1, days_ago=10, prefix="old")
    _fp_alerts(session, "Rule W", 1, days_ago=2, prefix="new")
    session.commit()
    r = _camp(get_noise_campaigns(session, days=365), "Rule W")
    assert r["first_seen"] < r["last_seen"]


# ── metrics roll-up: trend + Bob agreement ───────────────────────────────────


def test_bob_agreement_excludes_abstentions(session, monkeypatch):
    monkeypatch.setenv("ION_DE_MIN_CAMPAIGN", "1")
    # scored agree, scored disagree, no-suggestion, abstention.
    def fb(aid, bob, agreement, auto=False):
        f = AIFeedback(alert_id=aid, alert_prompt_template_id=7,
                       human_verdict="true_positive", bob_suggested_verdict=bob,
                       agreement=agreement, auto_escalated=auto)
        f.created_at = _NAIVE_NOW - timedelta(days=1)
        session.add(f)
    fb("x1", "true_positive", True)
    fb("x2", "false_positive", False)
    fb("x3", None, None)
    fb("x4", "false_positive", False, auto=True)
    session.commit()

    m = get_de_metrics(session, days=365)
    agree = m["summary"]["bob_agreement"]
    assert agree["scored"] == 2       # excludes no-suggestion + abstention
    assert agree["agreed"] == 1
    assert agree["agreement_rate"] == 50.0


def test_noise_trend_rising(session, monkeypatch):
    # window 90d → midpoint 45d. More FP closures recently than before → rising.
    _fp_alerts(session, "Trend Rule", 1, days_ago=70, prefix="old")
    for i in range(4):
        _fp_alerts(session, "Trend Rule", 1, days_ago=5, prefix=f"new{i}")
    session.commit()
    trend = get_de_metrics(session, days=90)["summary"]["noise_trend"]
    assert trend["recent_fp_closures"] == 4
    assert trend["older_fp_closures"] == 1
    assert trend["direction"] == "rising"


def test_empty_db_is_safe(session):
    m = get_de_metrics(session, days=90)
    assert m["campaigns"] == []
    assert m["summary"]["campaign_count"] == 0
    assert m["summary"]["addressable_hours"] == 0.0
    assert m["summary"]["bob_agreement"]["agreement_rate"] is None


# ── endpoints ────────────────────────────────────────────────────────────────


def _client(session, perms):
    user = User(id=1, username="eng", email="e@x", password_hash="x",
                display_name="Eng", is_active=True)
    user.has_permission = lambda p: p in perms  # type: ignore[method-assign]
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: session
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.clear()


def test_metrics_endpoint_requires_de_read(session):
    assert _client(session, perms=set()).get("/api/de/metrics").status_code == 403
    r = _client(session, perms={"de:read"}).get("/api/de/metrics?days=30")
    assert r.status_code == 200
    assert "campaigns" in r.json() and "summary" in r.json()


def test_campaigns_endpoint_requires_de_read(session):
    assert _client(session, perms=set()).get("/api/de/campaigns").status_code == 403
    r = _client(session, perms={"de:read"}).get("/api/de/campaigns?days=30")
    assert r.status_code == 200
    assert "campaigns" in r.json()
