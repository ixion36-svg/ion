"""Tests for the lab_fixtures seed/teardown lifecycle (v0.21.0).

Covers:
- seed_lab inserts rows into target tables and records lab_session_fixtures.
- teardown_lab removes materialised rows and sets torn_down_at.
- Idempotency: seeding twice produces no duplicate materialisations.
- Teardown of an empty session returns 0 without error.
- get_live_session_fixtures returns metadata for active rows only.

Uses SQLite in-memory so no Postgres is required. The lab_fixture_service
falls back to non-advisory-lock path on non-postgres backends, making these
tests fully deterministic.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# Import ion.models first so all tables are registered with Base.metadata.
import ion.models  # noqa: F401
from ion.models.base import Base
from ion.models.course import (
    Course,
    CourseLevel,
    CourseModule,
    Lesson,
    LessonType,
    UserEnrolment,
)
from ion.models.user import User
from ion.services.lab_fixture_service import (
    get_live_session_fixtures,
    seed_lab,
    teardown_lab,
)
from ion.storage.database import _run_migrations


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture(scope="function")
def engine(tmp_path):
    db_path = tmp_path / "lab_test.db"
    eng = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)
    # Run migrations to create lab_fixtures + lab_session_fixtures tables
    _run_migrations(eng)
    yield eng
    eng.dispose()


@pytest.fixture(scope="function")
def db(engine):
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    yield session
    session.rollback()
    session.close()


@pytest.fixture()
def user(db: Session) -> User:
    u = User(
        username="labuser",
        email="labuser@test.ion",
        password_hash="x",
        is_active=True,
        display_name="Lab User",
    )
    db.add(u)
    db.flush()
    return u


@pytest.fixture()
def course(db: Session, user: User) -> Course:
    c = Course(
        title="L1 Foundation",
        slug="l1-foundation",
        level=CourseLevel.L1,
        published=True,
        author_id=user.id,
    )
    db.add(c)
    db.flush()
    return c


@pytest.fixture()
def module(db: Session, course: Course) -> CourseModule:
    m = CourseModule(course_id=course.id, order=2, title="Module 2")
    db.add(m)
    db.flush()
    return m


@pytest.fixture()
def lab_lesson(db: Session, module: CourseModule) -> Lesson:
    l = Lesson(
        module_id=module.id,
        order=9,
        title="LAB — Read your first alert in /alerts",
        lesson_type=LessonType.LAB,
        lab_target_url="/alerts",
    )
    db.add(l)
    db.flush()
    return l


@pytest.fixture()
def enrolment(db: Session, user: User, course: Course) -> UserEnrolment:
    e = UserEnrolment(user_id=user.id, course_id=course.id)
    db.add(e)
    db.flush()
    return e


_TS = "2026-05-07 10:00:00"


def _alert_triage_payload(**kw) -> dict:
    """Minimal valid alert_triage payload (includes NOT NULL timestamps)."""
    base = {
        "es_alert_id": "lab-default-001",
        "status": "open",
        "created_at": _TS,
        "updated_at": _TS,
    }
    base.update(kw)
    return base


def _insert_lab_fixture(
    db: Session, lesson_id: int, kind: str, table: str, payload: dict
) -> int:
    """Insert a lab_fixtures row and return its id."""
    result = db.execute(
        text(
            "INSERT INTO lab_fixtures (lesson_id, fixture_kind, payload, target_table, created_at) "
            "VALUES (:lid, :kind, :payload, :tbl, CURRENT_TIMESTAMP)"
        ),
        {
            "lid": lesson_id,
            "kind": kind,
            "payload": json.dumps(payload),
            "tbl": table,
        },
    )
    db.flush()
    return result.lastrowid


# ── Tests ─────────────────────────────────────────────────────────────────


class TestSeedLab:
    def test_seed_inserts_rows_into_target_table(
        self, db: Session, lab_lesson: Lesson, enrolment: UserEnrolment
    ):
        _insert_lab_fixture(
            db, lab_lesson.id,
            kind="alert",
            table="alert_triage",
            payload=_alert_triage_payload(
                es_alert_id="lab-test-001",
                source_system="elastic",
            ),
        )

        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        db.flush()

        assert len(mat_ids) == 1
        row = db.execute(
            text("SELECT es_alert_id FROM alert_triage WHERE id = :id"),
            {"id": mat_ids[0]},
        ).fetchone()
        assert row is not None
        assert row[0] == "lab-test-001"

    def test_seed_records_session_fixture(
        self, db: Session, lab_lesson: Lesson, enrolment: UserEnrolment
    ):
        _insert_lab_fixture(
            db, lab_lesson.id,
            kind="alert",
            table="alert_triage",
            payload=_alert_triage_payload(es_alert_id="lab-sf-001"),
        )

        seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        db.flush()

        rows = db.execute(
            text(
                "SELECT materialised_row_id, materialised_table, torn_down_at "
                "FROM lab_session_fixtures WHERE enrollment_id = :eid AND lesson_id = :lid"
            ),
            {"eid": enrolment.id, "lid": lab_lesson.id},
        ).fetchall()

        assert len(rows) == 1
        assert rows[0][1] == "alert_triage"
        assert rows[0][2] is None  # not torn down yet

    def test_seed_is_idempotent(
        self, db: Session, lab_lesson: Lesson, enrolment: UserEnrolment
    ):
        _insert_lab_fixture(
            db, lab_lesson.id,
            kind="alert",
            table="alert_triage",
            payload=_alert_triage_payload(es_alert_id="lab-idem-001"),
        )

        ids_first = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        db.flush()
        ids_second = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        db.flush()

        assert ids_first == ids_second

        # Only one materialised row should exist (no duplicate)
        count = db.execute(
            text(
                "SELECT COUNT(*) FROM lab_session_fixtures "
                "WHERE enrollment_id = :eid AND lesson_id = :lid AND torn_down_at IS NULL"
            ),
            {"eid": enrolment.id, "lid": lab_lesson.id},
        ).scalar()
        assert count == 1

    def test_seed_returns_empty_when_no_fixtures(
        self, db: Session, lab_lesson: Lesson, enrolment: UserEnrolment
    ):
        result = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        assert result == []

    def test_seed_multiple_fixtures(
        self, db: Session, lab_lesson: Lesson, enrolment: UserEnrolment
    ):
        for i in range(3):
            _insert_lab_fixture(
                db, lab_lesson.id,
                kind="alert",
                table="alert_triage",
                payload=_alert_triage_payload(es_alert_id=f"lab-multi-{i:03d}"),
            )

        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        db.flush()

        assert len(mat_ids) == 3
        count = db.execute(
            text("SELECT COUNT(*) FROM alert_triage WHERE id IN (:a, :b, :c)"),
            {"a": mat_ids[0], "b": mat_ids[1], "c": mat_ids[2]},
        ).scalar()
        assert count == 3


class TestTeardownLab:
    def test_teardown_removes_materialised_rows(
        self, db: Session, lab_lesson: Lesson, enrolment: UserEnrolment
    ):
        _insert_lab_fixture(
            db, lab_lesson.id,
            kind="alert",
            table="alert_triage",
            payload=_alert_triage_payload(es_alert_id="lab-td-001"),
        )
        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        db.flush()

        torn = teardown_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        db.flush()

        assert torn == 1

        # Row should be gone from target table
        row = db.execute(
            text("SELECT id FROM alert_triage WHERE id = :id"),
            {"id": mat_ids[0]},
        ).fetchone()
        assert row is None

    def test_teardown_marks_torn_down_at(
        self, db: Session, lab_lesson: Lesson, enrolment: UserEnrolment
    ):
        _insert_lab_fixture(
            db, lab_lesson.id,
            kind="alert",
            table="alert_triage",
            payload=_alert_triage_payload(es_alert_id="lab-tda-001"),
        )
        seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        db.flush()

        teardown_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        db.flush()

        row = db.execute(
            text(
                "SELECT torn_down_at FROM lab_session_fixtures "
                "WHERE enrollment_id = :eid AND lesson_id = :lid"
            ),
            {"eid": enrolment.id, "lid": lab_lesson.id},
        ).fetchone()
        assert row is not None
        assert row[0] is not None  # torn_down_at is set

    def test_teardown_empty_returns_zero(
        self, db: Session, lab_lesson: Lesson, enrolment: UserEnrolment
    ):
        torn = teardown_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        assert torn == 0

    def test_teardown_does_not_affect_other_enrollments(
        self, db: Session, lab_lesson: Lesson, enrolment: UserEnrolment, course: Course
    ):
        """A second enrolment's materialisations survive teardown of the first.

        Each enrolment gets its own fixture row (distinct es_alert_id) so the
        UNIQUE constraint on alert_triage.es_alert_id is not violated.
        """
        user2 = User(
            username="labuser2", email="labuser2@test.ion",
            password_hash="x", is_active=True, display_name="Lab User 2",
        )
        db.add(user2)
        db.flush()
        enr2 = UserEnrolment(user_id=user2.id, course_id=course.id)
        db.add(enr2)
        db.flush()

        # Two separate lab_fixtures rows — one each for the two learners.
        # In real usage a lesson may have multiple fixtures; here we split so
        # each enrolment can materialise without hitting the unique constraint.
        fix1_id = _insert_lab_fixture(
            db, lab_lesson.id,
            kind="alert",
            table="alert_triage",
            payload=_alert_triage_payload(es_alert_id="lab-iso-001"),
        )
        fix2_id = _insert_lab_fixture(
            db, lab_lesson.id,
            kind="alert",
            table="alert_triage",
            payload=_alert_triage_payload(es_alert_id="lab-iso-002"),
        )

        # Seed enrolment1 first — picks up both fixtures.
        mat1 = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        db.flush()

        # Seed enrolment2 — idempotency check: it hasn't seeded yet, BUT
        # fixtures are already materialised by enr1. We need enr2 to insert
        # its OWN rows. Since es_alert_id is unique and enr1 already used
        # iso-001 and iso-002, we use a separate lesson with its own fixtures.
        module2 = CourseModule(
            course_id=course.id, order=99, title="Isolation Test Module"
        )
        db.add(module2)
        db.flush()
        lesson2 = Lesson(
            module_id=module2.id, order=1,
            title="Isolation LAB", lesson_type=LessonType.LAB,
        )
        db.add(lesson2)
        db.flush()

        fix3_id = _insert_lab_fixture(
            db, lesson2.id,
            kind="alert",
            table="alert_triage",
            payload=_alert_triage_payload(es_alert_id="lab-iso-enr2-001"),
        )

        mat2 = seed_lab(db, enrollment_id=enr2.id, lesson_id=lesson2.id)
        db.flush()

        assert len(mat2) == 1

        # Teardown enrolment1's session — only its rows should be deleted.
        teardown_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        db.flush()

        # enr2's row on lesson2 must still exist in alert_triage
        row2 = db.execute(
            text("SELECT id FROM alert_triage WHERE id = :id"),
            {"id": mat2[0]},
        ).fetchone()
        assert row2 is not None

        # enr1's rows should be gone
        for mat_id in mat1:
            gone = db.execute(
                text("SELECT id FROM alert_triage WHERE id = :id"),
                {"id": mat_id},
            ).fetchone()
            assert gone is None


class TestInsertRowColumnSafety:
    def test_malicious_column_name_raises_value_error(
        self, db: Session, lab_lesson: Lesson, enrolment: UserEnrolment
    ):
        """A fixture row with an unsafe column name must raise ValueError
        before any SQL is executed.
        """
        from ion.services.lab_fixture_service import _insert_row

        bad_payload = {
            "id) RETURNING pg_sleep(5)--": "injected",
            "status": "open",
        }
        with pytest.raises(ValueError, match="Unsafe column name"):
            _insert_row(db, target_table="alert_triage", payload=bad_payload)

    def test_valid_column_names_are_accepted(
        self, db: Session
    ):
        """Well-formed snake_case column names pass the safety check."""
        from ion.services.lab_fixture_service import _SAFE_COLUMN_RE

        valid = ["id", "es_alert_id", "status", "created_at", "source_system"]
        for col in valid:
            assert _SAFE_COLUMN_RE.match(col), f"Expected {col!r} to be valid"

    def test_upper_case_column_rejected(self, db: Session):
        from ion.services.lab_fixture_service import _insert_row

        with pytest.raises(ValueError, match="Unsafe column name"):
            _insert_row(db, target_table="alert_triage", payload={"Status": "open"})


class TestGetLiveSessionFixtures:
    def test_returns_active_rows(
        self, db: Session, lab_lesson: Lesson, enrolment: UserEnrolment
    ):
        _insert_lab_fixture(
            db, lab_lesson.id,
            kind="alert",
            table="alert_triage",
            payload=_alert_triage_payload(es_alert_id="lab-live-001"),
        )
        seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        db.flush()

        live = get_live_session_fixtures(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        assert len(live) == 1
        assert live[0]["fixture_kind"] == "alert"
        assert live[0]["materialised_table"] == "alert_triage"

    def test_returns_empty_after_teardown(
        self, db: Session, lab_lesson: Lesson, enrolment: UserEnrolment
    ):
        _insert_lab_fixture(
            db, lab_lesson.id,
            kind="alert",
            table="alert_triage",
            payload=_alert_triage_payload(es_alert_id="lab-live-td-001"),
        )
        seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        db.flush()
        teardown_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        db.flush()

        live = get_live_session_fixtures(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        assert live == []
