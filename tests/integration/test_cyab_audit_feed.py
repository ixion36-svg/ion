"""Integration tests for the /cyab/audit chronological feed.

Uses the project-wide ``client`` + ``temp_db`` fixtures from
``tests/integration/conftest.py`` (which inject an admin user via
dependency overrides — no real login round-trip required). The feed
endpoint resolves its DB session through ``get_db_session`` (a Depends),
which the conftest's monkeypatch of ``ion.storage.database.get_engine``
honours.

The seeded fixture creates one system, one snapshot (treated as a
sign-off because its notes contain "Signed off by"), and one checklist
item with status="done" — that's three event sources in one payload.
"""

import pytest
from datetime import date


@pytest.fixture
def seeded_audit_events(temp_db):
    """A system with: a sign-off snapshot + a checklist item + a create event."""
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSnapshot, CyabSystem
    from ion.models.cyab_doc_checklist import CyabDocChecklistItem

    Session = sessionmaker(bind=temp_db)
    s = Session()
    sys = CyabSystem(name="audit-test", department="X", soc_analyst_owner="alice")
    s.add(sys)
    s.flush()

    snap = CyabSnapshot(
        system_id=sys.id,
        snapshot_date=date.today(),
        readiness_score=80,
        notes="Signed off by Alice",
    )
    s.add(snap)

    item = CyabDocChecklistItem(
        system_id=sys.id, kind="HLD",
        label="High-level design", status="done",
    )
    s.add(item)
    s.commit()
    sid = sys.id
    s.close()
    yield sid


def test_audit_feed_returns_events(client, seeded_audit_events):
    r = client.get("/api/cyab/audit/feed")
    assert r.status_code == 200
    data = r.json()
    assert "events" in data
    assert len(data["events"]) >= 2  # at least create + signoff


def test_audit_feed_event_shape(client, seeded_audit_events):
    r = client.get("/api/cyab/audit/feed")
    for ev in r.json()["events"]:
        assert "when" in ev
        assert "who" in ev
        assert "what" in ev
        assert "system_id" in ev
        assert "action_type" in ev
        assert ev["action_type"] in (
            "create", "signoff", "checklist_update",
            "containment_change", "archive", "snapshot",
        )


def test_audit_feed_sorted_descending(client, seeded_audit_events):
    r = client.get("/api/cyab/audit/feed")
    events = r.json()["events"]
    timestamps = [e["when"] for e in events]
    assert timestamps == sorted(timestamps, reverse=True)


def test_audit_feed_filter_by_system(client, seeded_audit_events):
    sid = seeded_audit_events
    r = client.get(f"/api/cyab/audit/feed?system_id={sid}")
    for ev in r.json()["events"]:
        assert ev["system_id"] == sid


def test_audit_feed_filter_by_action_type(client, seeded_audit_events):
    r = client.get("/api/cyab/audit/feed?action_type=signoff")
    events = r.json()["events"]
    assert len(events) >= 1
    for ev in events:
        assert ev["action_type"] == "signoff"
