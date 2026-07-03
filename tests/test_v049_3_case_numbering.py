"""v0.49.3 code-review fix (v0.39.8 baseline F5): collision-free case numbers.

The Arkime auto-case loop and the RTMON monitor both did
``case_number = max(AlertCase.id) + 1`` — a read-then-write that races under
concurrency and diverges from reality after row deletion, then trips the
UNIQUE constraint on case_number. Both now derive the number from the
DB-assigned id AFTER flush via one shared helper.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.models.document import Base
from ion.services.case_numbering import assign_case_number


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _new_case():
    return AlertCase(
        title="t", description="d", status=AlertCaseStatus.OPEN,
        severity="low", created_by_id=1,
    )


def test_assigns_number_from_db_id(session):
    case = _new_case()
    num = assign_case_number(session, case)
    assert num == case.case_number
    assert case.case_number == f"CASE-{case.id:04d}"


def test_no_clash_with_live_row_after_deletion(session):
    """After deleting a row, a fresh case must still get a number that does
    not collide with any live row (the UNIQUE constraint must never trip)."""
    c1 = _new_case()
    assign_case_number(session, c1)
    session.commit()
    c2 = _new_case()
    assign_case_number(session, c2)
    session.commit()
    session.delete(c2)
    session.commit()

    c3 = _new_case()
    assign_case_number(session, c3)
    session.commit()  # must not raise IntegrityError
    live_numbers = {c.case_number for c in session.query(AlertCase).all()}
    assert len(live_numbers) == session.query(AlertCase).count()  # all unique
    assert c3.case_number in live_numbers


def test_no_duplicate_numbers_across_many(session):
    numbers = []
    for _ in range(25):
        c = _new_case()
        assign_case_number(session, c)
        session.commit()
        numbers.append(c.case_number)
    assert len(set(numbers)) == 25
