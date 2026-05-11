"""Tests for the v0.26.0 lab history endpoint.

``GET /api/courses/{slug}/lessons/{id}/lab-sessions`` returns the
calling user's past lab attempts for the lesson, newest-first, with
per-criterion breakdown for each attempt and the course's
``pass_threshold`` for the UI to render a pass-mark hint.

Covers:
- Empty history for a lesson with no sessions.
- Multiple sessions returned newest-first by completed_at.
- Per-session criteria breakdown included in payload.
- Scope is the calling user's enrolment only (no cross-user peek).
- pass_threshold from the course surfaces in the payload.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

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
from ion.services import lab_grading_service, lab_session_service
from ion.storage.database import _run_migrations


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture(scope="function")
def engine(tmp_path):
    db_path = tmp_path / "lab_history_test.db"
    eng = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)
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
        username="hist_user",
        email="hist_user@test.ion",
        password_hash="x",
        is_active=True,
        display_name="Hist User",
    )
    db.add(u)
    db.flush()
    return u


@pytest.fixture()
def other_user(db: Session) -> User:
    u = User(
        username="other_user",
        email="other_user@test.ion",
        password_hash="x",
        is_active=True,
        display_name="Other User",
    )
    db.add(u)
    db.flush()
    return u


@pytest.fixture()
def course(db: Session, user: User) -> Course:
    c = Course(
        title="L1 History",
        slug="l1-history",
        level=CourseLevel.L1,
        published=True,
        author_id=user.id,
        pass_threshold=70,
    )
    db.add(c)
    db.flush()
    return c


@pytest.fixture()
def module(db: Session, course: Course) -> CourseModule:
    m = CourseModule(course_id=course.id, order=1, title="M1")
    db.add(m)
    db.flush()
    return m


@pytest.fixture()
def lab_lesson(db: Session, module: CourseModule) -> Lesson:
    l = Lesson(
        module_id=module.id,
        order=1,
        title="LAB — view an alert",
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


def _add_rubric(db, lesson_id, *, kind, points, sort_order=0, config=None):
    res = db.execute(
        text(
            "INSERT INTO lab_rubrics "
            "(lesson_id, criterion_kind, criterion_config, points, sort_order, description) "
            "VALUES (:lid, :ck, :cfg, :pts, :so, :desc)"
        ),
        {
            "lid": lesson_id, "ck": kind,
            "cfg": json.dumps(config or {}),
            "pts": points, "so": sort_order,
            "desc": f"crit {kind}",
        },
    )
    db.flush()
    return res.lastrowid


def _run_completed_session(db, *, enr_id, lesson_id, score, points_earned, points_max):
    """Start, grade (stub), and complete a lab session with a fixed score."""
    sid = lab_session_service.start_or_resume(
        db, enrollment_id=enr_id, lesson_id=lesson_id
    )
    lab_session_service.complete(
        db, session_id=sid, score=score,
        points_earned=points_earned, points_max=points_max,
    )
    return sid


# ── Endpoint behaviour ───────────────────────────────────────────────────


class TestLabHistoryEndpoint:
    def test_returns_empty_sessions_for_lesson_with_no_attempts(
        self, db, enrolment, lab_lesson, user, course
    ):
        from ion.web.labs_api import get_lab_sessions

        result = get_lab_sessions.__wrapped__(  # bypass FastAPI deps
            slug=course.slug,
            lesson_id=lab_lesson.id,
            current_user=user,
            session=db,
        ) if hasattr(get_lab_sessions, "__wrapped__") else get_lab_sessions(
            slug=course.slug,
            lesson_id=lab_lesson.id,
            current_user=user,
            session=db,
        )
        assert result["lesson_id"] == lab_lesson.id
        assert result["pass_threshold"] == 70
        assert result["sessions"] == []

    def test_returns_sessions_newest_first(
        self, db, enrolment, lab_lesson, user, course
    ):
        from ion.web.labs_api import get_lab_sessions

        # Three completed sessions across three attempts.
        # lab_session_service.start_or_resume requires the previous
        # session to be completed before bumping attempt_number.
        for score in (50, 80, 90):
            _run_completed_session(
                db, enr_id=enrolment.id, lesson_id=lab_lesson.id,
                score=score, points_earned=score, points_max=100,
            )

        result = get_lab_sessions(
            slug=course.slug,
            lesson_id=lab_lesson.id,
            current_user=user,
            session=db,
        )
        sessions = result["sessions"]
        assert len(sessions) == 3
        # Newest-first by completed_at: the third (score 90) was
        # completed last.
        assert sessions[0]["score"] == 90
        assert sessions[0]["attempt_number"] == 3
        assert sessions[-1]["score"] == 50
        assert sessions[-1]["attempt_number"] == 1

    def test_status_reflects_pass_threshold(
        self, db, enrolment, lab_lesson, user, course
    ):
        from ion.web.labs_api import get_lab_sessions

        # Two attempts: one below 70 → failed, one at threshold → completed.
        _run_completed_session(
            db, enr_id=enrolment.id, lesson_id=lab_lesson.id,
            score=50, points_earned=50, points_max=100,
        )
        _run_completed_session(
            db, enr_id=enrolment.id, lesson_id=lab_lesson.id,
            score=70, points_earned=70, points_max=100,
        )

        result = get_lab_sessions(
            slug=course.slug,
            lesson_id=lab_lesson.id,
            current_user=user,
            session=db,
        )
        by_score = {s["score"]: s["status"] for s in result["sessions"]}
        assert by_score == {50: "failed", 70: "completed"}

    def test_includes_criteria_breakdown_per_session(
        self, db, enrolment, lab_lesson, user, course
    ):
        from ion.web.labs_api import get_lab_sessions

        # Set up a rubric so the grader produces criterion results.
        _add_rubric(
            db, lab_lesson.id, kind="observable_created",
            points=100, sort_order=0, config={"min_count": 1},
        )
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        # Grade with no audit row → criterion missed → score=0, failed.
        grade = lab_grading_service.grade_session(db, session_id=sid)
        lab_session_service.complete(
            db, session_id=sid, score=grade.get("score"),
            points_earned=grade.get("points_earned", 0),
            points_max=grade.get("points_max", 0),
        )

        result = get_lab_sessions(
            slug=course.slug,
            lesson_id=lab_lesson.id,
            current_user=user,
            session=db,
        )
        assert len(result["sessions"]) == 1
        session_one = result["sessions"][0]
        assert session_one["status"] == "failed"
        assert session_one["score"] == 0
        criteria = session_one["criteria"]
        assert len(criteria) == 1
        assert criteria[0]["kind"] == "observable_created"
        assert criteria[0]["matched"] is False
        assert criteria[0]["points_earned"] == 0
        assert criteria[0]["points_max"] == 100

    def test_other_users_sessions_not_returned(
        self, db, enrolment, lab_lesson, user, other_user, course
    ):
        from ion.web.labs_api import get_lab_sessions

        # Both users have an enrolment + a completed session for the
        # same lesson. The endpoint must scope to the calling user.
        other_enr = UserEnrolment(user_id=other_user.id, course_id=course.id)
        db.add(other_enr)
        db.flush()

        _run_completed_session(
            db, enr_id=enrolment.id, lesson_id=lab_lesson.id,
            score=80, points_earned=80, points_max=100,
        )
        _run_completed_session(
            db, enr_id=other_enr.id, lesson_id=lab_lesson.id,
            score=20, points_earned=20, points_max=100,
        )

        my_result = get_lab_sessions(
            slug=course.slug,
            lesson_id=lab_lesson.id,
            current_user=user,
            session=db,
        )
        assert len(my_result["sessions"]) == 1
        assert my_result["sessions"][0]["score"] == 80

        their_result = get_lab_sessions(
            slug=course.slug,
            lesson_id=lab_lesson.id,
            current_user=other_user,
            session=db,
        )
        assert len(their_result["sessions"]) == 1
        assert their_result["sessions"][0]["score"] == 20
