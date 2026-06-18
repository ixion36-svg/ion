"""v0.43.0 — daily-work data layer (WorkTaskType + WorkLogEntry).

Wave 1, step 1 of the daily-work feature. Verifies the models create, the
default task taxonomy seeds idempotently, and a manual log entry round-trips.
"""

# Importing the models at module load registers them on Base.metadata so the
# conftest `temp_db` fixture's create_all() builds their tables.
from ion.models.worklog import (
    DEFAULT_TASK_TYPES,
    WorkLogEntry,
    WorkTaskType,
    seed_default_task_types,
)


def test_seed_default_task_types_is_idempotent(session):
    inserted = seed_default_task_types(session)
    assert inserted == len(DEFAULT_TASK_TYPES) == 10
    assert session.query(WorkTaskType).count() == 10

    # Second call is a no-op (admin edits/deletions must stick).
    again = seed_default_task_types(session)
    assert again == 0
    assert session.query(WorkTaskType).count() == 10


def test_default_taxonomy_has_expected_keys_and_shape(session):
    seed_default_task_types(session)
    keys = {t.key for t in session.query(WorkTaskType).all()}
    assert {"meeting", "training", "ir", "hunt", "docs", "pairing", "break"} <= keys

    ir = session.query(WorkTaskType).filter_by(key="ir").one()
    d = ir.to_dict()
    assert d["label"] == "IR engagement"
    assert d["category"] == "response"
    assert d["color"] == "red"
    assert d["is_active"] is True


def test_work_log_entry_round_trips(session):
    seed_default_task_types(session)
    entry = WorkLogEntry(user_id=7, task_type="meeting", text="Daily stand-up")
    session.add(entry)
    session.commit()

    fetched = session.query(WorkLogEntry).filter_by(user_id=7).one()
    assert fetched.task_type == "meeting"
    assert fetched.text == "Daily stand-up"
    assert fetched.logged_at is not None  # server default applied

    d = fetched.to_dict()
    assert d["source"] == "logged"
    assert d["task_type"] == "meeting"
    assert d["user_id"] == 7
    assert "logged_at" in d


def test_task_type_key_is_unique(session):
    import pytest
    from sqlalchemy.exc import IntegrityError

    session.add(WorkTaskType(key="dup", label="One"))
    session.commit()
    session.add(WorkTaskType(key="dup", label="Two"))
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
