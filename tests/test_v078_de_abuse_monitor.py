"""v0.78.0 — Detection Engineering module, abuse monitor (roadmap §4 control #7).

The other six §4 controls are *preventive* (SoD, no-silence, scope caps, expiry,
audit, no-drift). This is the missing *detective* control: a read-only scan over
the DE domain tables that flags what preventive controls allow — namely two-person
collusion (SoD stops one person, not a colluding pair), high-volume actors, and
blanket-scope quirks.

Pins:
- recurring (raiser→verifier) quirk pairs and (drafter→approver) Bob pairs,
- high per-user action volume,
- over-broad quirk scope,
- window filtering (old activity is excluded),
- the scan is strictly READ-ONLY (mutates nothing, writes no audit rows).
"""

from datetime import datetime, timedelta, timezone

from ion.models.bob_tuning_proposal import BobTuningProposal, BobTuningProposalStatus
from ion.models.system_quirk import SystemQuirk, SystemQuirkStatus
from ion.models.user import AuditLog
from ion.services import de_abuse_service as svc

_NOW = datetime.now(timezone.utc).replace(tzinfo=None)


def _quirk(session, raised_by, verified_by=None, *, rules=None, created=None,
           verified_at=None, status=None, review_days=30):
    q = SystemQuirk(
        title="q", annotation="a", justification="j",
        scope_rules=rules if rules is not None else ["Rule A"],
        scope_hosts=["h1"],
        review_date=_NOW + timedelta(days=review_days),
        status=status or (SystemQuirkStatus.ACTIVE if verified_by else SystemQuirkStatus.PENDING),
        raised_by_id=raised_by, verified_by_id=verified_by,
        verified_at=verified_at or (_NOW if verified_by else None),
        created_at=created or _NOW,
    )
    session.add(q)
    session.flush()
    return q


def _bob(session, created_by, decided_by, *, decided_at=None, created=None):
    p = BobTuningProposal(
        title="t", proposed_text="text", status=BobTuningProposalStatus.APPROVED,
        created_by_id=created_by, decided_by_id=decided_by,
        decided_at=decided_at or _NOW, created_at=created or _NOW,
    )
    session.add(p)
    session.flush()
    return p


def _types(result):
    return [s["type"] for s in result["signals"]]


def test_clean_estate_yields_no_signals(session):
    # distinct pairs, small scope, low volume — nothing to flag
    _quirk(session, raised_by=1, verified_by=2)
    _quirk(session, raised_by=3, verified_by=4)
    _bob(session, created_by=5, decided_by=6)
    session.commit()
    r = svc.scan_abuse(session)
    assert r["signals"] == []
    assert r["summary"]["total"] == 0


def test_detects_recurring_quirk_collusion_pair(session):
    for _ in range(4):  # same raiser=1 verified by same user=2, over min_pair_count
        _quirk(session, raised_by=1, verified_by=2)
    session.commit()
    r = svc.scan_abuse(session, min_pair_count=3)
    sig = next(s for s in r["signals"] if s["type"] == "collusion_pair")
    assert sig["domain"] == "quirk"
    assert {sig["actor_a_id"], sig["actor_b_id"]} == {1, 2}
    assert sig["count"] == 4


def test_detects_recurring_bob_collusion_pair(session):
    for _ in range(3):
        _bob(session, created_by=7, decided_by=8)
    session.commit()
    r = svc.scan_abuse(session, min_pair_count=3)
    sig = next(s for s in r["signals"] if s["type"] == "collusion_pair" and s["domain"] == "bob")
    assert {sig["actor_a_id"], sig["actor_b_id"]} == {7, 8}
    assert sig["count"] == 3


def test_pair_below_threshold_not_flagged(session):
    _quirk(session, raised_by=1, verified_by=2)
    _quirk(session, raised_by=1, verified_by=2)  # only 2, under threshold 3
    session.commit()
    r = svc.scan_abuse(session, min_pair_count=3)
    assert "collusion_pair" not in _types(r)


def test_detects_broad_scope_quirk(session):
    _quirk(session, raised_by=1, verified_by=2, rules=[f"Rule {i}" for i in range(15)])
    session.commit()
    r = svc.scan_abuse(session, max_scope_rules=10)
    sig = next(s for s in r["signals"] if s["type"] == "broad_scope_quirk")
    assert sig["quirk_id"]
    assert sig["rule_count"] == 15


def test_detects_high_volume_actor(session):
    for _ in range(30):  # user 9 raises many pending quirks (no verifier → no pair)
        _quirk(session, raised_by=9, verified_by=None)
    session.commit()
    r = svc.scan_abuse(session, max_actions_per_user=25)
    sig = next(s for s in r["signals"] if s["type"] == "high_volume_actor")
    assert sig["user_id"] == 9
    assert sig["count"] >= 30


def test_window_excludes_old_activity(session):
    old = _NOW - timedelta(days=200)
    for _ in range(4):
        _quirk(session, raised_by=1, verified_by=2, created=old, verified_at=old)
    session.commit()
    assert "collusion_pair" not in _types(svc.scan_abuse(session, days=90, min_pair_count=3))
    assert "collusion_pair" in _types(svc.scan_abuse(session, days=365, min_pair_count=3))


def test_scan_is_read_only(session):
    for _ in range(4):
        _quirk(session, raised_by=1, verified_by=2)
    session.commit()
    q_before = session.query(SystemQuirk).count()
    audit_before = session.query(AuditLog).count()
    svc.scan_abuse(session)
    assert session.query(SystemQuirk).count() == q_before
    assert session.query(AuditLog).count() == audit_before  # scan writes no audit rows


# ── endpoint ─────────────────────────────────────────────────────────────────

import pytest
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.models.user import User
from ion.web.api import get_db_session
from ion.web.server import app


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


def test_abuse_scan_gated_de_verify(session):
    # de:read alone is not enough — this is oversight tooling
    assert _client(session, {"de:read"}).get("/api/de/abuse-scan").status_code == 403
    assert _client(session, {"de:verify"}).get("/api/de/abuse-scan").status_code == 200


def test_abuse_scan_endpoint_returns_signals(session):
    for _ in range(4):
        _quirk(session, raised_by=1, verified_by=2)
    session.commit()
    r = _client(session, {"de:verify"}).get("/api/de/abuse-scan")
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["total"] >= 1
    assert any(s["type"] == "collusion_pair" for s in body["signals"])
