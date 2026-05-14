"""Regression guard: how SQLEnum(native_enum=False) actually behaves.

This test exists because the v0.32.0 audit (driven by the v0.30.0 lab
fixture incident) initially mis-diagnosed 15 ORM filters as broken. They
weren't — SQLAlchemy's `Enum` bind processor coerces strings on the way
to SQL. The real footgun is raw `text()` SQL, which bypasses the
processor and binds the literal string as-is.

This test documents the two distinct cases:

1. **ORM filters** — `Column == "lowercase"` or `Column == EnumX.value`.
   SQLAlchemy's `Enum.bind_processor` looks the string up in
   `_object_lookup` (keyed on BOTH `.name` and `.value`), resolves it to
   the enum member, and binds the member's `.name`. So lowercase ORM
   filters work. The test asserts they match the right row.

2. **Raw `text()` SQL** — `text("WHERE col = 'lowercase'")`. No bind
   processor runs on the literal. The DB stores the enum NAME
   (uppercase), so the lowercase literal matches NOTHING. The seed
   script v0.30.0 Bug 3 was exactly this shape:
   `text("SELECT ... WHERE l.lesson_type = 'lab'")` → zero rows.

If a future SQLAlchemy version tightens `validate_strings` to True by
default, case (1) will start failing — and the test will tell you.
If anyone changes the storage to use `.value` instead of `.name`, the
"stored as NAME" assertion will catch it too.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401 — register all model tables
from ion.models.alert_triage import (
    AlertCase,
    AlertCaseStatus,
    AlertTriage,
    AlertTriageStatus,
)
from ion.models.base import Base
from ion.models.observable import (
    Observable,
    ObservableLink,
    ObservableLinkType,
    ObservableType,
)
from ion.models.user import User
from ion.storage.database import _run_migrations


@pytest.fixture(scope="function")
def engine(tmp_path):
    db_path = tmp_path / "sqlenum.db"
    eng = create_engine(
        f"sqlite:///{db_path}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(eng)
    _run_migrations(eng)
    yield eng
    eng.dispose()


@pytest.fixture(scope="function")
def session(engine):
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    db = factory()
    user = User(
        username="tester",
        email="tester@test.ion",
        password_hash="x",
        is_active=True,
        display_name="Tester",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.info["user_id"] = user.id
    yield db
    db.rollback()
    db.close()


def _seed_cases(session: Session) -> dict[str, int]:
    uid = session.info["user_id"]
    for status in (AlertCaseStatus.OPEN, AlertCaseStatus.ACKNOWLEDGED, AlertCaseStatus.CLOSED):
        session.add(
            AlertCase(
                case_number=f"CASE-{status.name}",
                title=f"Test case in {status.name}",
                status=status,
                severity="medium",
                created_by_id=uid,
            )
        )
    session.commit()
    return {c.status.name: c.id for c in session.query(AlertCase).all()}


def test_alertcase_status_stored_as_enum_name(session: Session):
    """Load-bearing fact: SQLEnum(native_enum=False) stores the enum NAME."""
    _seed_cases(session)
    stored = {
        row[0]
        for row in session.execute(text("SELECT DISTINCT status FROM alert_cases")).all()
    }
    assert stored == {"OPEN", "ACKNOWLEDGED", "CLOSED"}, (
        f"Storage changed: got {stored!r}. Every gotchas reference assumes uppercase NAMEs."
    )


def test_orm_filter_with_dot_value_works(session: Session):
    """ORM coercion: `Column == Enum.X.value` (lowercase) matches via bind processor."""
    ids = _seed_cases(session)
    rows = (
        session.query(AlertCase)
        .filter(AlertCase.status == AlertCaseStatus.CLOSED.value)
        .all()
    )
    assert len(rows) == 1 and rows[0].id == ids["CLOSED"], (
        "ORM .value filter must match via bind processor. If this fails, SQLAlchemy "
        "tightened validate_strings — flip the codebase to enum instances everywhere."
    )


def test_orm_filter_with_bare_lowercase_string_works(session: Session):
    """ORM coercion: bare lowercase string literal also matches."""
    ids = _seed_cases(session)
    rows = (
        session.query(AlertCase).filter(AlertCase.status == "closed").all()
    )
    assert len(rows) == 1 and rows[0].id == ids["CLOSED"], (
        "ORM with a literal lowercase string must match via bind processor."
    )


def test_orm_filter_with_enum_instance_works(session: Session):
    """The most idiomatic and future-proof form."""
    ids = _seed_cases(session)
    rows = (
        session.query(AlertCase).filter(AlertCase.status == AlertCaseStatus.CLOSED).all()
    )
    assert len(rows) == 1 and rows[0].id == ids["CLOSED"]

    not_closed = (
        session.query(AlertCase).filter(AlertCase.status != AlertCaseStatus.CLOSED).all()
    )
    assert {c.status for c in not_closed} == {AlertCaseStatus.OPEN, AlertCaseStatus.ACKNOWLEDGED}


def test_orm_in_list_with_enum_instances_works(session: Session):
    """`.in_([enum, enum])` — the ioc_staleness_service.py shape."""
    _seed_cases(session)
    open_like = (
        session.query(AlertCase)
        .filter(AlertCase.status.in_([AlertCaseStatus.OPEN, AlertCaseStatus.ACKNOWLEDGED]))
        .all()
    )
    assert len(open_like) == 2


def test_raw_text_sql_with_lowercase_matches_nothing(session: Session):
    """THE FOOTGUN: `text()` bypasses bind processor → lowercase doesn't match."""
    _seed_cases(session)
    # The v0.30.0 lab fixture seed bug shape — but on alert_cases.
    rows = session.execute(
        text("SELECT id FROM alert_cases WHERE status = :s"), {"s": "closed"}
    ).all()
    assert rows == [], (
        f"Expected zero rows from raw-SQL lowercase filter (NAME is 'CLOSED' in storage); "
        f"got {rows!r}. If this changes, SQLite started doing case-insensitive comparison."
    )
    # The defensive idiom that works regardless of case:
    rows_upper = session.execute(
        text("SELECT id FROM alert_cases WHERE UPPER(status) = :s"), {"s": "CLOSED"}
    ).all()
    assert len(rows_upper) == 1


def test_raw_text_sql_with_correct_uppercase_name_matches(session: Session):
    """The fix for raw SQL: use the uppercase enum NAME directly."""
    _seed_cases(session)
    rows = session.execute(
        text("SELECT id FROM alert_cases WHERE status = :s"), {"s": "CLOSED"}
    ).all()
    assert len(rows) == 1


def test_alerttriage_status_same_rules(session: Session):
    """Mirror coverage on AlertTriage.status."""
    for status in (AlertTriageStatus.OPEN, AlertTriageStatus.CLOSED):
        session.add(AlertTriage(es_alert_id=f"es-{status.name}", status=status))
    session.commit()

    stored = {
        row[0]
        for row in session.execute(text("SELECT DISTINCT status FROM alert_triage")).all()
    }
    assert stored == {"OPEN", "CLOSED"}

    # ORM filter with .value: works (1 row != CLOSED → only OPEN).
    via_value = (
        session.query(AlertTriage)
        .filter(AlertTriage.status != AlertTriageStatus.CLOSED.value)
        .count()
    )
    assert via_value == 1

    # Raw SQL with lowercase: footgun, zero matches.
    raw_zero = session.execute(
        text("SELECT id FROM alert_triage WHERE status = 'closed'")
    ).all()
    assert raw_zero == []


def test_observable_link_type_same_rules(session: Session):
    """Mirror coverage on ObservableLink.link_type."""
    obs = Observable(type=ObservableType.IPV4, value="10.0.0.1", normalized_value="10.0.0.1")
    session.add(obs)
    session.commit()
    for link_type, entity_id in (
        (ObservableLinkType.CASE, 100),
        (ObservableLinkType.ALERT, 200),
    ):
        session.add(
            ObservableLink(
                observable_id=obs.id,
                link_type=link_type,
                entity_id=entity_id,
                context="test",
            )
        )
    session.commit()

    stored = {
        row[0]
        for row in session.execute(text("SELECT DISTINCT link_type FROM observable_links")).all()
    }
    assert "CASE" in stored and "ALERT" in stored

    via_value = (
        session.query(ObservableLink)
        .filter(ObservableLink.link_type == ObservableLinkType.CASE.value)
        .all()
    )
    assert len(via_value) == 1, "ORM coercion handles .value just fine."


def test_string_value_constructor_for_user_input(session: Session):
    """When the input is a raw user-provided string (e.g. URL query param),
    converting to enum first is the defensive pattern: `AlertTriageStatus(s)`
    raises `ValueError` on bad input so the caller can guard.
    """
    for status in (AlertTriageStatus.OPEN, AlertTriageStatus.CLOSED):
        session.add(AlertTriage(es_alert_id=f"es-{status.name}", status=status))
    session.commit()

    enum_instance = AlertTriageStatus("open")
    assert enum_instance is AlertTriageStatus.OPEN

    rows = (
        session.query(AlertTriage).filter(AlertTriage.status == enum_instance).all()
    )
    assert len(rows) == 1

    with pytest.raises(ValueError):
        AlertTriageStatus("bogus")
