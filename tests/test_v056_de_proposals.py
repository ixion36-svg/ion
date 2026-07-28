"""v0.56.0 — Detection Engineering module, Phase 1 (Detection Proposals).

Covers the write path (still: ION records the draft + decision, never touches a
detection backend):
- deterministic draft_from_campaign (fields, None when no campaign),
- create/update validation + draft-only editing,
- one-shot decide (draft → applied/rejected, applied_at, re-decide blocked),
- outcome measurement (before/after FP counts, drop%, applied-only guard),
- fp_alerts_for_rule window count,
- endpoint gates (de:read read, de:propose write).
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage, AlertTriageStatus
from ion.models.detection_proposal import DetectionProposal, DetectionProposalStatus
from ion.models.user import User
from ion.services import de_proposal_service as svc
from ion.services.de_metrics_service import fp_alerts_for_rule
from ion.web.api import get_db_session
from ion.web.server import app

_NOW = datetime.now(timezone.utc).replace(tzinfo=None)


def _case(session, num, *, reason="false_positive", days_ago=1, severity="medium", hosts=None):
    c = AlertCase(case_number=num, title=f"case {num}", created_by_id=1,
                  status=AlertCaseStatus.CLOSED, closure_reason=reason,
                  severity=severity, affected_hosts=hosts or [])
    c.closed_at = _NOW - timedelta(days=days_ago)
    session.add(c)
    session.flush()
    return c


def _triage(session, alert_id, rule_name, case_id, *, observables=None, mitre=None):
    session.add(AlertTriage(es_alert_id=alert_id, rule_name=rule_name,
                            status=AlertTriageStatus.CLOSED, case_id=case_id,
                            observables=observables, mitre_techniques=mitre))


def _campaign(session, rule, n, *, days_ago=1, prefix="", hosts=None, obs=None, mitre=None):
    c = _case(session, f"C-{prefix}{rule}-{days_ago}", days_ago=days_ago, hosts=hosts)
    for i in range(n):
        _triage(session, f"{prefix}{rule}-{i}-{days_ago}", rule, c.id, observables=obs, mitre=mitre)
    return c


# ── drafting ─────────────────────────────────────────────────────────────────


def test_draft_from_campaign_fields(session, monkeypatch):
    monkeypatch.setenv("ION_DE_MIN_CAMPAIGN", "1")
    monkeypatch.setenv("ION_DE_MINUTES_PER_ALERT", "12")
    _campaign(session, "Scanner Rule", 5,
              hosts=["web01", "web01", "db02"],
              obs=[{"type": "process", "value": "nessus.exe"}],
              mitre=["T1046"])
    session.commit()

    d = svc.draft_from_campaign(session, "Scanner Rule", days=90)
    assert d is not None
    assert d["rule_name"] == "Scanner Rule"
    assert d["change_type"] == "exclusion"
    assert d["expected_fp_reduction"] == 5
    assert d["expected_hours_reclaimed"] == 1.0  # 5 × 12min
    assert "nessus.exe" in d["suggested_change"]
    assert "T1046" in d["mitre_techniques"]
    assert d["campaign_snapshot"]["fp_alerts"] == 5


def test_draft_none_when_no_campaign(session):
    assert svc.draft_from_campaign(session, "Nonexistent Rule", days=90) is None


# ── create / update ──────────────────────────────────────────────────────────


def test_create_validation(session):
    with pytest.raises(ValueError):
        svc.create_proposal(session, {"suggested_change": "x"}, 1)  # no title
    with pytest.raises(ValueError):
        svc.create_proposal(session, {"title": "t"}, 1)  # no change
    with pytest.raises(ValueError):
        svc.create_proposal(session, {"title": "t", "suggested_change": "c", "change_type": "bogus"}, 1)

    p = svc.create_proposal(session, {"title": "Tune X", "suggested_change": "exclude host", "rule_name": "X"}, 7)
    assert p.id and p.status == DetectionProposalStatus.DRAFT
    assert p.created_by_id == 7


def test_update_only_drafts(session):
    p = svc.create_proposal(session, {"title": "t", "suggested_change": "c", "rule_name": "R"}, 1)
    p2 = svc.update_proposal(session, p.id, {"title": "new title", "scope": "host web01"})
    assert p2.title == "new title" and p2.scope == "host web01"
    # once decided, editing is blocked
    svc.decide_proposal(session, p.id, "rejected", 1, notes="nope")
    with pytest.raises(ValueError):
        svc.update_proposal(session, p.id, {"title": "again"})


# ── decide (one-shot) ────────────────────────────────────────────────────────


def test_decide_applied_and_rejected_and_oneshot(session):
    p = svc.create_proposal(session, {"title": "t", "suggested_change": "c", "rule_name": "R"}, 1)
    applied_iso = (_NOW - timedelta(days=3)).isoformat()
    d = svc.decide_proposal(session, p.id, "applied", 9, notes="raised threshold", applied_at=applied_iso)
    assert d.status == DetectionProposalStatus.APPLIED
    assert d.decided_by_id == 9 and d.applied_at is not None
    # one-shot
    with pytest.raises(ValueError):
        svc.decide_proposal(session, p.id, "rejected", 9)

    p2 = svc.create_proposal(session, {"title": "t2", "suggested_change": "c2", "rule_name": "R2"}, 1)
    r = svc.decide_proposal(session, p2.id, "rejected", 5, notes="not benign")
    assert r.status == DetectionProposalStatus.REJECTED and r.applied_at is None

    with pytest.raises(ValueError):
        svc.decide_proposal(session, p2.id + 999, "applied", 1)  # not found


# ── outcome measurement ──────────────────────────────────────────────────────


def test_measure_outcome_before_after(session, monkeypatch):
    monkeypatch.setenv("ION_DE_MIN_CAMPAIGN", "1")
    # FP alerts for rule "R": 2 before applied (days_ago 40, 20), 1 after (days_ago 5).
    _campaign(session, "R", 1, days_ago=40, prefix="b1")
    _campaign(session, "R", 1, days_ago=20, prefix="b2")
    _campaign(session, "R", 1, days_ago=5, prefix="a1")
    session.commit()

    p = svc.create_proposal(session, {"title": "t", "suggested_change": "c", "rule_name": "R"}, 1)
    svc.decide_proposal(session, p.id, "applied", 1, applied_at=(_NOW - timedelta(days=15)).isoformat())

    out = svc.measure_outcome(session, p.id, days=30)
    assert out["before_count"] == 2
    assert out["after_count"] == 1
    assert out["drop_pct"] == 50.0
    # persisted on the proposal
    assert svc.get_proposal(session, p.id)["outcome"]["drop_pct"] == 50.0


def test_measure_requires_applied(session):
    p = svc.create_proposal(session, {"title": "t", "suggested_change": "c", "rule_name": "R"}, 1)
    with pytest.raises(ValueError):
        svc.measure_outcome(session, p.id)  # still a draft


def test_fp_alerts_for_rule_window(session):
    _campaign(session, "W", 3, days_ago=10, prefix="in")
    _campaign(session, "W", 2, days_ago=40, prefix="out")
    session.commit()
    n = fp_alerts_for_rule(session, "W", _NOW - timedelta(days=20), _NOW)
    assert n == 3  # only the in-window ones


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


def test_list_requires_de_read(session):
    assert _client(session, set()).get("/api/de/proposals").status_code == 403
    r = _client(session, {"de:read"}).get("/api/de/proposals?status=all")
    assert r.status_code == 200 and "proposals" in r.json()


def test_create_and_decide_require_de_propose(session):
    # de:read alone cannot create
    assert _client(session, {"de:read"}).post(
        "/api/de/proposals", json={"title": "t", "suggested_change": "c"}).status_code == 403
    # de:propose can create then decide
    c = _client(session, {"de:read", "de:propose"})
    r = c.post("/api/de/proposals", json={"title": "Tune R", "suggested_change": "exclude host", "rule_name": "R"})
    assert r.status_code == 200
    pid = r.json()["id"]
    d = c.post(f"/api/de/proposals/{pid}/decide", json={"decision": "rejected", "notes": "no"})
    assert d.status_code == 200 and d.json()["status"] == "rejected"
    # second decide is one-shot → 409
    assert c.post(f"/api/de/proposals/{pid}/decide", json={"decision": "applied"}).status_code == 409
