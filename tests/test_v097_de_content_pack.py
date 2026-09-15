"""v0.97.0 — DE content-pack export/import safety.

Pins that import cannot bypass the module's governance:
- imported quirks land PENDING with no verifier (SoD intact),
- imported proposals land DRAFT with no decision/applied,
- wildcard scopes are still rejected on import,
- re-import is idempotent (dedup by content signature),
- a stale review_date is refreshed rather than rejecting the whole quirk.
"""

from datetime import datetime, timedelta, timezone

import pytest

from ion.models.detection_proposal import DetectionProposal, DetectionProposalStatus
from ion.models.system_quirk import SystemQuirk, SystemQuirkStatus
from ion.services import de_proposal_service, de_quirk_service
from ion.services.de_content_pack_service import PACK_SCHEMA, export_pack, import_pack

_NOW = datetime.now(timezone.utc).replace(tzinfo=None)
_FUTURE = (_NOW + timedelta(days=30)).isoformat()


def _pack(quirks=None, proposals=None):
    return {"pack_schema": PACK_SCHEMA, "ion_version": "test", "exported_at": "x",
            "quirks": quirks or [], "proposals": proposals or []}


def _quirk(**over):
    q = {"title": "SCCM PS", "annotation": "known-benign patch cycle",
         "justification": "confirmed with platform team", "review_date": _FUTURE,
         "scope_rules": ["Suspicious PowerShell"], "scope_hosts": ["web01"],
         "priority_nudge": -1}
    q.update(over)
    return q


def _prop(**over):
    p = {"title": "Exclude scanner", "suggested_change": "add exclusion for host scan01",
         "change_type": "exclusion", "rule_name": "Brute Force"}
    p.update(over)
    return p


def test_import_quirk_lands_pending_no_verifier(session):
    summ = import_pack(session, _pack(quirks=[_quirk()]), user_id=7)
    assert summ["quirks_created"] == 1
    q = session.query(SystemQuirk).one()
    assert q.status == SystemQuirkStatus.PENDING
    assert q.raised_by_id == 7 and q.verified_by_id is None  # SoD preserved


def test_import_proposal_lands_draft_no_decision(session):
    summ = import_pack(session, _pack(proposals=[_prop()]), user_id=7)
    assert summ["proposals_created"] == 1
    p = session.query(DetectionProposal).one()
    assert p.status == DetectionProposalStatus.DRAFT
    assert p.decided_by_id is None and p.applied_at is None and p.created_by_id == 7


def test_import_rejects_wildcard_quirk(session):
    summ = import_pack(session, _pack(quirks=[_quirk(scope_rules=["*"], scope_hosts=[])]), user_id=7)
    assert summ["quirks_created"] == 0 and summ["errors"]
    assert session.query(SystemQuirk).count() == 0


def test_reimport_is_idempotent(session):
    pack = _pack(quirks=[_quirk()])
    import_pack(session, pack, user_id=7)
    summ2 = import_pack(session, pack, user_id=7)
    assert summ2["quirks_created"] == 0 and summ2["quirks_skipped"] == 1
    assert session.query(SystemQuirk).count() == 1


def test_stale_review_date_is_refreshed(session):
    past = (_NOW - timedelta(days=5)).isoformat()
    summ = import_pack(session, _pack(quirks=[_quirk(review_date=past)]), user_id=7)
    assert summ["quirks_created"] == 1  # refreshed, not rejected
    q = session.query(SystemQuirk).one()
    assert q.review_date > _NOW


def test_bad_schema_raises(session):
    with pytest.raises(ValueError):
        import_pack(session, {"pack_schema": 999, "quirks": [], "proposals": []}, user_id=7)


def test_export_shape_is_importable(session):
    de_quirk_service.raise_quirk(session, _quirk(), user_id=1)
    de_proposal_service.create_proposal(session, _prop(), user_id=1)
    pack = export_pack(session)
    assert pack["pack_schema"] == PACK_SCHEMA
    assert len(pack["quirks"]) == 1 and len(pack["proposals"]) == 1
    assert "title" in pack["quirks"][0] and "suggested_change" in pack["proposals"][0]
    # content only — no local identity/decision leaks into the pack
    assert "raised_by_id" not in pack["quirks"][0]
    assert "decided_by_id" not in pack["proposals"][0] and "id" not in pack["proposals"][0]
