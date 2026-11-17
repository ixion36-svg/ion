"""The case inbox's reads: last-activity order, the Changed window, the
chip counts and each row's latest activity.

The inbox sorts by "last activity", which is not `updated_at`: adding a
note inserts into `notes` and leaves the case row alone, so a case sorted
by `updated_at` would not move when an analyst wrote on it.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import ion.models  # noqa: F401
from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage, Note, NoteEntityType
from ion.models.base import Base
from ion.models.user import User
from ion.services import case_query_service as cq

T0 = datetime(2026, 11, 1, 12, 0, 0)


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'inbox.db'}")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    for uid, name in ((1, "alice"), (2, "bob")):
        s.add(User(id=uid, username=name, email=f"{name}@x", password_hash="x", display_name=name, is_active=True))
    s.commit()
    yield s
    s.close()
    engine.dispose()


def case(db, n, *, at, status=AlertCaseStatus.OPEN, severity="medium", owner=None, hosts=None):
    row = AlertCase(case_number=f"CASE-{n:04d}", title=f"Case {n}", status=status, severity=severity,
                    created_by_id=1, assigned_to_id=owner, affected_hosts=hosts, created_at=at, updated_at=at)
    db.add(row)
    db.commit()
    return row


def note(db, row, *, at, content="looked at it", user=2):
    db.add(Note(entity_type=NoteEntityType.CASE, entity_id=str(row.id), user_id=user, content=content, created_at=at))
    db.commit()


def alert(db, row, n, *, created, updated, rule="Rule", status="open"):
    db.add(AlertTriage(es_alert_id=f"a-{n}", case_id=row.id, rule_name=rule, status=status, created_at=created, updated_at=updated))
    db.commit()


def order(db, **kw):
    return [c["case_number"] for c in cq.list_cases_page(db, sort="last_activity", **kw)["cases"]]


def test_a_note_moves_a_case_up_though_the_case_row_did_not_change(db):
    old = case(db, 1, at=T0)
    case(db, 2, at=T0 + timedelta(hours=1))
    assert order(db) == ["CASE-0002", "CASE-0001"]
    note(db, old, at=T0 + timedelta(hours=2))
    assert order(db) == ["CASE-0001", "CASE-0002"]
    assert cq.list_cases_page(db, sort="last_activity")["cases"][0]["last_activity_at"] == (T0 + timedelta(hours=2)).isoformat()


def test_an_alert_change_counts_as_activity(db):
    old = case(db, 1, at=T0)
    case(db, 2, at=T0 + timedelta(hours=1))
    alert(db, old, 1, created=T0, updated=T0 + timedelta(hours=3))
    assert order(db) == ["CASE-0001", "CASE-0002"]


def test_closed_cases_sink_below_live_ones(db):
    case(db, 1, at=T0)
    case(db, 2, at=T0 + timedelta(hours=5), status=AlertCaseStatus.CLOSED)
    assert order(db) == ["CASE-0001", "CASE-0002"]


def test_the_changed_window_reads_last_activity(db):
    quiet = case(db, 1, at=T0)
    case(db, 2, at=T0 + timedelta(hours=30))
    since = T0 + timedelta(hours=24)
    assert order(db, active_since=since) == ["CASE-0002"]
    note(db, quiet, at=T0 + timedelta(hours=31))
    assert order(db, active_since=since) == ["CASE-0001", "CASE-0002"]
    assert cq.list_cases_page(db, sort="last_activity", active_since=since)["total"] == 2


def test_chip_counts_are_whole_table_counts(db):
    case(db, 1, at=T0, severity="critical", owner=1)
    case(db, 2, at=T0 + timedelta(hours=30), severity="CRITICAL")
    case(db, 3, at=T0, status=AlertCaseStatus.CLOSED, owner=2)
    counts = cq.inbox_counts(db, user_id=1, active_since=T0 + timedelta(hours=24))
    assert counts == {"changed": 1, "mine": 1, "unassigned": 1, "critical": 2, "closed": 1}


def test_mine_is_unknown_without_a_user_not_zero(db):
    case(db, 1, at=T0)
    assert cq.inbox_counts(db, user_id=None, active_since=T0)["mine"] is None


def test_an_empty_table_counts_zero(db):
    assert cq.inbox_counts(db, user_id=1, active_since=T0) == {"changed": 0, "mine": 0, "unassigned": 0, "critical": 0, "closed": 0}


def test_case_activity_takes_the_newest_note_and_alert_per_case(db):
    a = case(db, 1, at=T0, hosts=["", "srv-file01", "srv-db01"])
    b = case(db, 2, at=T0)
    note(db, a, at=T0 + timedelta(hours=1), content="first")
    note(db, a, at=T0 + timedelta(hours=2), content="second", user=1)
    alert(db, a, 1, created=T0, updated=T0 + timedelta(hours=1), rule="Old")
    alert(db, a, 2, created=T0 + timedelta(hours=3), updated=T0 + timedelta(hours=3), rule="New")
    got = cq.case_activity(db, [a.id, b.id])
    assert got[a.id]["host"] == "srv-file01"
    assert got[a.id]["note"] == {"at": (T0 + timedelta(hours=2)).isoformat(), "user": "alice", "content": "second"}
    assert got[a.id]["alert"]["rule"] == "New"
    assert got[a.id]["alert"]["linked"] is True
    assert got[b.id] == {"host": None, "note": None, "alert": None}


def test_case_activity_of_no_ids_reads_nothing(db):
    assert cq.case_activity(db, []) == {}


def test_last_activity_is_a_sortable_field(db):
    assert "last_activity" in cq.SORTABLE_FIELDS
