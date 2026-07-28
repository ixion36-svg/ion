"""v0.57.0 — Detection Engineering module, Phase 2 (System Quirks).

Pins the anti-abuse guarantees (roadmap §4):
- separation of duties: the raiser cannot verify their own quirk,
- NO suppression: the matcher only decorates alert dicts — never drops/hides/closes,
- scoped: at least one concrete scope required, wildcards rejected,
- mandatory expiry: review_date required + must be future; on-read expiry,
- verify one-shot + revert, and a full audit trail,
- endpoint gates (de:read / de:propose / de:verify) + SoD 409.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.models.system_quirk import SystemQuirk, SystemQuirkStatus
from ion.models.user import AuditLog, User
from ion.services import de_quirk_service as svc
from ion.web.api import get_db_session
from ion.web.server import app

_NOW = datetime.now(timezone.utc).replace(tzinfo=None)
_FUTURE = (_NOW + timedelta(days=30)).isoformat()


def _payload(**over):
    p = {"title": "SCCM PowerShell", "annotation": "Known-benign SCCM patch cycle",
         "justification": "Confirmed w/ platform team", "review_date": _FUTURE,
         "scope_rules": ["Suspicious PowerShell Execution"], "scope_hosts": ["web01"]}
    p.update(over)
    return p


def _raise(session, user_id=1, **over):
    return svc.raise_quirk(session, _payload(**over), user_id)


# ── scope validation ─────────────────────────────────────────────────────────


def test_scope_required_and_no_wildcards(session):
    with pytest.raises(ValueError):  # no scope at all
        _raise(session, scope_rules=[], scope_hosts=[])
    with pytest.raises(ValueError):  # wildcard
        _raise(session, scope_rules=["*"], scope_hosts=[])
    with pytest.raises(ValueError):  # blank required fields
        _raise(session, annotation="")
    q = _raise(session)  # valid
    assert q.id and q.status == SystemQuirkStatus.PENDING


def test_review_date_must_be_future(session):
    with pytest.raises(ValueError):
        _raise(session, review_date=None)
    with pytest.raises(ValueError):
        _raise(session, review_date=(_NOW - timedelta(days=1)).isoformat())


# ── separation of duties ─────────────────────────────────────────────────────


def test_sod_raiser_cannot_verify_own(session):
    q = _raise(session, user_id=7)
    with pytest.raises(ValueError, match="separation of duties"):
        svc.verify_quirk(session, q.id, 7)  # same user
    v = svc.verify_quirk(session, q.id, 9)  # different user
    assert v.status == SystemQuirkStatus.ACTIVE and v.verified_by_id == 9


def test_verify_one_shot_and_revert(session):
    q = _raise(session, user_id=1)
    svc.verify_quirk(session, q.id, 2)
    with pytest.raises(ValueError):  # already active, not pending
        svc.verify_quirk(session, q.id, 3)
    r = svc.revert_quirk(session, q.id, 4, reason="tuned out")
    assert r.status == SystemQuirkStatus.REVERTED and r.reverted_by_id == 4


# ── advisory matcher: NO suppression ─────────────────────────────────────────


def _active(session, user_id=1, verifier=2, **over):
    q = _raise(session, user_id=user_id, **over)
    return svc.verify_quirk(session, q.id, verifier)


def test_match_is_advisory_and_scoped(session):
    _active(session, scope_rules=["Suspicious PowerShell Execution"], scope_hosts=["web01"])
    # AND across dimensions: rule matches but host doesn't → no match
    assert svc.quirk_match(session, {"rule_name": "Suspicious PowerShell Execution", "host": "db99"}) == []
    # both match → one advisory annotation
    hits = svc.quirk_match(session, {"rule_name": "Suspicious PowerShell Execution", "host": "web01"})
    assert len(hits) == 1 and hits[0]["annotation"].startswith("Known-benign")


def test_annotate_alerts_never_hides_or_mutates(session):
    _active(session, scope_rules=["R"], scope_hosts=["h1"])
    alerts = [
        {"id": "a1", "rule_name": "R", "host": "h1", "status": "open", "verdict": None},
        {"id": "a2", "rule_name": "Malware C2", "host": "h1", "status": "open"},  # rule differs → no quirk
    ]
    out = svc.annotate_alerts(session, alerts)
    assert len(out) == 2                      # nothing dropped
    assert out[0]["quirks"][0]["quirk_id"]    # matched alert annotated
    assert out[0]["status"] == "open" and out[0]["verdict"] is None  # untouched
    assert "quirks" not in out[1]             # non-match not annotated
    assert out[1]["status"] == "open"


def test_expired_quirk_is_inert(session):
    q = _raise(session, user_id=1)
    svc.verify_quirk(session, q.id, 2)
    # force review_date into the past
    q.review_date = _NOW - timedelta(days=1)
    session.commit()
    assert svc.quirk_match(session, {"rule_name": "Suspicious PowerShell Execution", "host": "web01"}) == []


def test_reverted_quirk_does_not_match(session):
    q = _active(session)
    svc.revert_quirk(session, q.id, 3)
    assert svc.quirk_match(session, {"rule_name": "Suspicious PowerShell Execution", "host": "web01"}) == []


# ── audit trail ──────────────────────────────────────────────────────────────


def test_audit_trail_records_lifecycle(session):
    q = _raise(session, user_id=1)
    svc.verify_quirk(session, q.id, 2)
    svc.revert_quirk(session, q.id, 3, reason="x")
    actions = [a.action for a in session.query(AuditLog)
               .filter(AuditLog.resource_type == "system_quirk", AuditLog.resource_id == q.id).all()]
    assert set(actions) == {"quirk_raised", "quirk_verified", "quirk_reverted"}


# ── endpoints ────────────────────────────────────────────────────────────────


def _client(session, perms, uid=1):
    user = User(id=uid, username=f"u{uid}", email="e@x", password_hash="x",
                display_name="U", is_active=True)
    user.has_permission = lambda p: p in perms  # type: ignore[method-assign]
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: session
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.clear()


def test_endpoint_gates_and_sod(session):
    # raise needs de:propose
    assert _client(session, {"de:read"}).post("/api/de/quirks", json=_payload()).status_code == 403
    r = _client(session, {"de:read", "de:propose"}, uid=1).post("/api/de/quirks", json=_payload())
    assert r.status_code == 200
    qid = r.json()["id"]
    # verify needs de:verify
    assert _client(session, {"de:propose"}, uid=2).post(f"/api/de/quirks/{qid}/verify").status_code == 403
    # SoD: same user (uid=1) who raised cannot verify → 409
    assert _client(session, {"de:verify"}, uid=1).post(f"/api/de/quirks/{qid}/verify").status_code == 409
    # different user with de:verify → 200
    assert _client(session, {"de:verify"}, uid=2).post(f"/api/de/quirks/{qid}/verify").status_code == 200
