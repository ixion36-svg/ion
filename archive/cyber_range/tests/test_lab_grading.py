"""Tests for the adaptive lab grading service (v0.23.0).

Covers:
- LabSessionService.start_or_resume is idempotent and bumps attempt_number
  after a session is completed.
- LabSessionService.link_fixtures attaches materialised rows to the session.
- LabGradingService.grade_session:
    * empty rubric → score=None, no rows written.
    * viewed_alert criterion with a matching audit_logs row → matched=True,
      points awarded, score=100.
    * viewed_alert with no matching audit row → matched=False, score=0.
    * re-grading the same session is idempotent (upsert by (session, rubric)).
    * audit row tied to a different alert_triage id does not match.
    * audit row with action != 'alert_view' does not match.
- LabGradingService rejects unknown criterion_kind values gracefully.

Uses SQLite in-memory so no Postgres is required. The grading service uses
raw SQL so behaviour is dialect-symmetric across the LATERAL-free path.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
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
from ion.models.user import AuditLog, User
from ion.services import lab_grading_service, lab_session_service
from ion.services.lab_fixture_service import seed_lab
from ion.storage.database import _run_migrations


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture(scope="function")
def engine(tmp_path):
    db_path = tmp_path / "lab_grading_test.db"
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
        username="grader_user",
        email="grader_user@test.ion",
        password_hash="x",
        is_active=True,
        display_name="Grader User",
    )
    db.add(u)
    db.flush()
    return u


@pytest.fixture()
def course(db: Session, user: User) -> Course:
    c = Course(
        title="L1 Grading",
        slug="l1-grading",
        level=CourseLevel.L1,
        published=True,
        author_id=user.id,
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


_TS = "2026-05-11 12:00:00"


def _add_alert_triage_fixture(db: Session, lesson_id: int, es_alert_id: str) -> int:
    """Insert one lab_fixtures row whose payload targets alert_triage."""
    payload = {
        "es_alert_id": es_alert_id,
        "status": "open",
        "created_at": _TS,
        "updated_at": _TS,
    }
    res = db.execute(
        text(
            "INSERT INTO lab_fixtures (lesson_id, fixture_kind, payload, "
            "target_table, created_at) "
            "VALUES (:lid, :kind, :payload, :tbl, CURRENT_TIMESTAMP)"
        ),
        {
            "lid": lesson_id, "kind": "alert", "tbl": "alert_triage",
            "payload": json.dumps(payload),
        },
    )
    db.flush()
    return res.lastrowid


def _add_rubric(
    db: Session, lesson_id: int, *,
    kind: str = "viewed_alert",
    points: int = 100,
    sort_order: int = 0,
    config: dict | None = None,
) -> int:
    res = db.execute(
        text(
            "INSERT INTO lab_rubrics "
            "(lesson_id, criterion_kind, criterion_config, points, sort_order) "
            "VALUES (:lid, :ck, :cfg, :pts, :so)"
        ),
        {
            "lid": lesson_id, "ck": kind,
            "cfg": json.dumps(config or {}),
            "pts": points, "so": sort_order,
        },
    )
    db.flush()
    return res.lastrowid


def _add_audit(db: Session, user_id: int, action: str, resource_type: str,
               resource_id: int, when=None) -> int:
    row = AuditLog(
        user_id=user_id, action=action,
        resource_type=resource_type, resource_id=resource_id,
        details=f"test audit {action}",
    )
    if when is not None:
        row.timestamp = when
    db.add(row)
    db.flush()
    return row.id


# ── LabSessionService ─────────────────────────────────────────────────────


class TestLabSessionService:
    def test_start_or_resume_creates_session_on_first_call(
        self, db, enrolment, lab_lesson
    ):
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        assert isinstance(sid, int) and sid > 0
        attempt = db.execute(
            text("SELECT attempt_number FROM lab_sessions WHERE id = :sid"),
            {"sid": sid},
        ).scalar()
        assert attempt == 1

    def test_start_or_resume_is_idempotent(self, db, enrolment, lab_lesson):
        sid1 = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        sid2 = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        assert sid1 == sid2

    def test_start_or_resume_bumps_attempt_after_completion(
        self, db, enrolment, lab_lesson
    ):
        sid1 = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        lab_session_service.complete(db, session_id=sid1, score=50,
                                     points_earned=5, points_max=10)
        sid2 = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        assert sid2 != sid1
        attempt = db.execute(
            text("SELECT attempt_number FROM lab_sessions WHERE id = :sid"),
            {"sid": sid2},
        ).scalar()
        assert attempt == 2


# ── LabGradingService ─────────────────────────────────────────────────────


class TestGradeSession:
    def test_empty_rubric_returns_none_score(self, db, enrolment, lab_lesson):
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["score"] is None
        assert result["points_earned"] == 0
        assert result["points_max"] == 0
        assert result["criteria"] == []

    def test_viewed_alert_matches_when_audit_row_exists(
        self, db, enrolment, lab_lesson, user
    ):
        _add_alert_triage_fixture(db, lab_lesson.id, "lab-alert-001")
        _add_rubric(db, lab_lesson.id, points=100)
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        lab_session_service.link_fixtures(
            db, session_id=sid, materialised_ids=mat_ids
        )
        _add_audit(db, user_id=user.id, action="alert_view",
                   resource_type="alert_triage", resource_id=mat_ids[0])

        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["score"] == 100
        assert result["points_earned"] == 100
        assert result["points_max"] == 100
        assert len(result["criteria"]) == 1
        assert result["criteria"][0]["matched"] is True

        persisted = db.execute(
            text("SELECT matched, points_earned FROM lab_criterion_results "
                 "WHERE session_id = :sid"),
            {"sid": sid},
        ).fetchone()
        assert persisted is not None
        assert bool(persisted[0]) is True
        assert int(persisted[1]) == 100

    def test_viewed_alert_does_not_match_without_audit_row(
        self, db, enrolment, lab_lesson
    ):
        _add_alert_triage_fixture(db, lab_lesson.id, "lab-alert-002")
        _add_rubric(db, lab_lesson.id, points=100)
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        lab_session_service.link_fixtures(
            db, session_id=sid, materialised_ids=mat_ids
        )
        # No alert_view audit row inserted.
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["score"] == 0
        assert result["criteria"][0]["matched"] is False

    def test_audit_row_for_different_alert_does_not_match(
        self, db, enrolment, lab_lesson, user
    ):
        _add_alert_triage_fixture(db, lab_lesson.id, "lab-alert-003")
        _add_rubric(db, lab_lesson.id, points=100)
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        lab_session_service.link_fixtures(
            db, session_id=sid, materialised_ids=mat_ids
        )
        # Audit a DIFFERENT (non-fixture) triage id.
        _add_audit(db, user_id=user.id, action="alert_view",
                   resource_type="alert_triage", resource_id=mat_ids[0] + 999)
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["criteria"][0]["matched"] is False
        assert result["score"] == 0

    def test_audit_row_with_wrong_action_does_not_match(
        self, db, enrolment, lab_lesson, user
    ):
        _add_alert_triage_fixture(db, lab_lesson.id, "lab-alert-004")
        _add_rubric(db, lab_lesson.id, points=100)
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        lab_session_service.link_fixtures(
            db, session_id=sid, materialised_ids=mat_ids
        )
        _add_audit(db, user_id=user.id, action="case_update",  # wrong action
                   resource_type="alert_triage", resource_id=mat_ids[0])
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["criteria"][0]["matched"] is False

    def test_regrade_same_session_is_idempotent(
        self, db, enrolment, lab_lesson, user
    ):
        _add_alert_triage_fixture(db, lab_lesson.id, "lab-alert-005")
        _add_rubric(db, lab_lesson.id, points=100)
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        lab_session_service.link_fixtures(
            db, session_id=sid, materialised_ids=mat_ids
        )
        _add_audit(db, user_id=user.id, action="alert_view",
                   resource_type="alert_triage", resource_id=mat_ids[0])
        lab_grading_service.grade_session(db, session_id=sid)
        # Re-grade: same data, must yield ONE result row not two.
        lab_grading_service.grade_session(db, session_id=sid)
        count = db.execute(
            text("SELECT COUNT(*) FROM lab_criterion_results WHERE session_id = :sid"),
            {"sid": sid},
        ).scalar()
        assert count == 1

    def test_unknown_criterion_kind_does_not_raise(
        self, db, enrolment, lab_lesson
    ):
        _add_alert_triage_fixture(db, lab_lesson.id, "lab-alert-006")
        _add_rubric(db, lab_lesson.id, kind="not_a_real_kind", points=50)
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        # No fixtures linked (unknown kind doesn't read them anyway).
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["score"] == 0
        assert result["criteria"][0]["matched"] is False
        # Persisted row records the diagnostic note.
        notes = db.execute(
            text("SELECT notes FROM lab_criterion_results WHERE session_id = :sid"),
            {"sid": sid},
        ).scalar()
        assert "unknown criterion_kind" in (notes or "")


# ── Integration: launch → view → complete cycle ──────────────────────────


class TestEndToEnd:
    def test_full_cycle_yields_correct_score(
        self, db, enrolment, lab_lesson, user
    ):
        """Launch lab → simulate audit row for alert_view → complete-and-grade."""
        _add_alert_triage_fixture(db, lab_lesson.id, "lab-alert-e2e")
        _add_rubric(db, lab_lesson.id, points=100)

        # Launch
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        lab_session_service.link_fixtures(
            db, session_id=sid, materialised_ids=mat_ids
        )
        db.commit()

        # Simulate the learner opening the seeded alert.
        _add_audit(db, user_id=user.id, action="alert_view",
                   resource_type="alert_triage", resource_id=mat_ids[0])
        db.commit()

        # Complete
        result = lab_grading_service.grade_session(db, session_id=sid)
        lab_session_service.complete(
            db, session_id=sid,
            score=result["score"],
            points_earned=result["points_earned"],
            points_max=result["points_max"],
        )
        db.commit()

        completed = db.execute(
            text("SELECT score, completed_at FROM lab_sessions WHERE id = :sid"),
            {"sid": sid},
        ).fetchone()
        assert completed.score == 100
        assert completed.completed_at is not None


# ── v0.24.0: linked_to_case criterion + multi-criterion grading ──────────


def _add_alert_triage_fixture_n(db: Session, lesson_id: int, n: int) -> list[str]:
    """Add N alert_triage fixtures to a lesson; return the es_alert_ids."""
    ids = []
    for i in range(n):
        es_id = f"lab-alert-multi-{i:03d}"
        _add_alert_triage_fixture(db, lesson_id, es_id)
        ids.append(es_id)
    return ids


def _add_link_audit(
    db: Session, user_id: int, triage_id: int, case_id: int
) -> int:
    """Insert an alert_linked audit row pointing at a triage + case pair."""
    import json as _json
    row = AuditLog(
        user_id=user_id,
        action="alert_linked",
        resource_type="alert_triage",
        resource_id=triage_id,
        details=_json.dumps({"case_id": case_id, "es_alert_id": f"es-{triage_id}"}),
    )
    db.add(row)
    db.flush()
    return row.id


class TestLinkedToCaseEvaluator:
    """v0.24.0: linked_to_case fires when N materialised alerts converge on a case."""

    def test_no_match_without_audit_rows(self, db, enrolment, lab_lesson):
        _add_alert_triage_fixture_n(db, lab_lesson.id, 2)
        _add_rubric(db, lab_lesson.id, kind="linked_to_case", points=60,
                    config={"min_alerts": 2})
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        lab_session_service.link_fixtures(
            db, session_id=sid, materialised_ids=mat_ids
        )
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["criteria"][0]["matched"] is False
        assert result["score"] == 0

    def test_match_when_two_alerts_link_to_same_case(
        self, db, enrolment, lab_lesson, user
    ):
        _add_alert_triage_fixture_n(db, lab_lesson.id, 2)
        _add_rubric(db, lab_lesson.id, kind="linked_to_case", points=60,
                    config={"min_alerts": 2})
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        lab_session_service.link_fixtures(
            db, session_id=sid, materialised_ids=mat_ids
        )
        # Both alerts linked to case_id=42.
        _add_link_audit(db, user.id, mat_ids[0], 42)
        _add_link_audit(db, user.id, mat_ids[1], 42)
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["criteria"][0]["matched"] is True
        assert result["score"] == 100

    def test_no_match_when_alerts_link_to_different_cases(
        self, db, enrolment, lab_lesson, user
    ):
        _add_alert_triage_fixture_n(db, lab_lesson.id, 2)
        _add_rubric(db, lab_lesson.id, kind="linked_to_case", points=60,
                    config={"min_alerts": 2})
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        lab_session_service.link_fixtures(
            db, session_id=sid, materialised_ids=mat_ids
        )
        # Alerts linked to DIFFERENT cases — no convergence.
        _add_link_audit(db, user.id, mat_ids[0], 42)
        _add_link_audit(db, user.id, mat_ids[1], 99)
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["criteria"][0]["matched"] is False
        assert result["score"] == 0

    def test_no_match_with_only_one_alert_linked(
        self, db, enrolment, lab_lesson, user
    ):
        _add_alert_triage_fixture_n(db, lab_lesson.id, 2)
        _add_rubric(db, lab_lesson.id, kind="linked_to_case", points=60,
                    config={"min_alerts": 2})
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        lab_session_service.link_fixtures(
            db, session_id=sid, materialised_ids=mat_ids
        )
        # Only one alert linked.
        _add_link_audit(db, user.id, mat_ids[0], 42)
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["criteria"][0]["matched"] is False


class TestMultiCriterionRubric:
    """v0.24.0: a rubric with viewed_alert (40) + linked_to_case (60) scores partial."""

    def _setup_multi_rubric(self, db, lab_lesson):
        _add_alert_triage_fixture_n(db, lab_lesson.id, 2)
        _add_rubric(db, lab_lesson.id, kind="viewed_alert", points=40, sort_order=0)
        _add_rubric(db, lab_lesson.id, kind="linked_to_case", points=60,
                    sort_order=1, config={"min_alerts": 2})

    def test_only_viewed_scores_40(self, db, enrolment, lab_lesson, user):
        self._setup_multi_rubric(db, lab_lesson)
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        lab_session_service.link_fixtures(
            db, session_id=sid, materialised_ids=mat_ids
        )
        _add_audit(db, user_id=user.id, action="alert_view",
                   resource_type="alert_triage", resource_id=mat_ids[0])
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["points_earned"] == 40
        assert result["points_max"] == 100
        assert result["score"] == 40

    def test_only_linked_scores_60(self, db, enrolment, lab_lesson, user):
        self._setup_multi_rubric(db, lab_lesson)
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        lab_session_service.link_fixtures(
            db, session_id=sid, materialised_ids=mat_ids
        )
        _add_link_audit(db, user.id, mat_ids[0], 42)
        _add_link_audit(db, user.id, mat_ids[1], 42)
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["points_earned"] == 60
        assert result["score"] == 60

    def test_both_score_100(self, db, enrolment, lab_lesson, user):
        self._setup_multi_rubric(db, lab_lesson)
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        lab_session_service.link_fixtures(
            db, session_id=sid, materialised_ids=mat_ids
        )
        _add_audit(db, user_id=user.id, action="alert_view",
                   resource_type="alert_triage", resource_id=mat_ids[0])
        _add_link_audit(db, user.id, mat_ids[0], 42)
        _add_link_audit(db, user.id, mat_ids[1], 42)
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["points_earned"] == 100
        assert result["score"] == 100
        # Both rubric rows individually matched.
        assert all(c["matched"] for c in result["criteria"])

    def test_neither_scores_0(self, db, enrolment, lab_lesson):
        self._setup_multi_rubric(db, lab_lesson)
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        mat_ids = seed_lab(db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id)
        lab_session_service.link_fixtures(
            db, session_id=sid, materialised_ids=mat_ids
        )
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["points_earned"] == 0
        assert result["score"] == 0
        assert not any(c["matched"] for c in result["criteria"])


# ── v0.25.0: observable_created + case_closed_with_reason criteria ───────


def _add_obs_audit(
    db: Session, user_id: int, *, observable_id: int = 1, obs_type: str = "ip"
) -> int:
    """Insert an observable_linked audit row with details JSON the evaluator parses."""
    import json as _json
    row = AuditLog(
        user_id=user_id,
        action="observable_linked",
        resource_type="observable",
        resource_id=observable_id,
        details=_json.dumps({
            "observable_id": observable_id,
            "observable_type": obs_type,
            "link_type": "alert",
            "entity_id": 100,
            "context": obs_type,
        }),
    )
    db.add(row)
    db.flush()
    return row.id


def _add_case_close_audit(
    db: Session, user_id: int, *, case_id: int = 1, reason: str = "true_positive"
) -> int:
    """Insert a case_closed audit row with details JSON the evaluator parses."""
    import json as _json
    row = AuditLog(
        user_id=user_id,
        action="case_closed",
        resource_type="alert_case",
        resource_id=case_id,
        details=_json.dumps({
            "case_id": case_id,
            "case_number": f"CASE-{case_id:04d}",
            "closure_reason": reason,
            "closure_notes": None,
        }),
    )
    db.add(row)
    db.flush()
    return row.id


class TestObservableCreatedEvaluator:
    """v0.25.0: observable_created fires when audit rows accumulate to min_count."""

    def test_no_match_without_audit_rows(self, db, enrolment, lab_lesson):
        _add_rubric(db, lab_lesson.id, kind="observable_created", points=100,
                    config={"min_count": 1})
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["criteria"][0]["matched"] is False
        assert result["score"] == 0

    def test_match_with_single_audit_row(self, db, enrolment, lab_lesson, user):
        _add_rubric(db, lab_lesson.id, kind="observable_created", points=100,
                    config={"min_count": 1})
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        _add_obs_audit(db, user.id, observable_id=1, obs_type="ip")
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["criteria"][0]["matched"] is True
        assert result["score"] == 100

    def test_min_count_unmet(self, db, enrolment, lab_lesson, user):
        _add_rubric(db, lab_lesson.id, kind="observable_created", points=100,
                    config={"min_count": 2})
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        _add_obs_audit(db, user.id, observable_id=1)
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["criteria"][0]["matched"] is False

    def test_type_filter_match(self, db, enrolment, lab_lesson, user):
        _add_rubric(db, lab_lesson.id, kind="observable_created", points=100,
                    config={"min_count": 1, "types": ["ip"]})
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        _add_obs_audit(db, user.id, observable_id=1, obs_type="ip")
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["criteria"][0]["matched"] is True

    def test_type_filter_miss(self, db, enrolment, lab_lesson, user):
        _add_rubric(db, lab_lesson.id, kind="observable_created", points=100,
                    config={"min_count": 1, "types": ["domain"]})
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        # Audit row is an ip; rubric wants domain — no match.
        _add_obs_audit(db, user.id, observable_id=1, obs_type="ip")
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["criteria"][0]["matched"] is False


class TestCaseClosedWithReasonEvaluator:
    """v0.25.0: case_closed_with_reason fires when closure_reason ∈ required_reasons."""

    def test_no_match_without_audit_rows(self, db, enrolment, lab_lesson):
        _add_rubric(db, lab_lesson.id, kind="case_closed_with_reason", points=100,
                    config={"required_reasons": ["true_positive"]})
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["criteria"][0]["matched"] is False

    def test_match_with_correct_reason(self, db, enrolment, lab_lesson, user):
        _add_rubric(db, lab_lesson.id, kind="case_closed_with_reason", points=100,
                    config={"required_reasons": ["true_positive"]})
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        _add_case_close_audit(db, user.id, case_id=42, reason="true_positive")
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["criteria"][0]["matched"] is True
        assert result["score"] == 100

    def test_no_match_with_wrong_reason(self, db, enrolment, lab_lesson, user):
        _add_rubric(db, lab_lesson.id, kind="case_closed_with_reason", points=100,
                    config={"required_reasons": ["true_positive"]})
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        # Case closed with false_positive — required_reasons does not include it.
        _add_case_close_audit(db, user.id, case_id=42, reason="false_positive")
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["criteria"][0]["matched"] is False

    def test_match_with_multi_reason_list(self, db, enrolment, lab_lesson, user):
        _add_rubric(db, lab_lesson.id, kind="case_closed_with_reason", points=100,
                    config={"required_reasons": ["true_positive", "duplicate"]})
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        _add_case_close_audit(db, user.id, case_id=42, reason="duplicate")
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["criteria"][0]["matched"] is True


class TestThreeCriterionPartialCredit:
    """v0.25.0: 3-criterion rubric (viewed_alert + observable_created + case_closed)."""

    def test_two_of_three_match_partial_score(
        self, db, enrolment, lab_lesson, user
    ):
        # Mirror an L1 M7 style rubric: 30 viewed_alert + 30 observable_created
        # + 40 case_closed_with_reason. Cover the multi-kind path explicitly.
        _add_alert_triage_fixture(db, lab_lesson.id, "es-three-001")
        _add_rubric(db, lab_lesson.id, kind="viewed_alert",
                    points=30, sort_order=0)
        _add_rubric(db, lab_lesson.id, kind="observable_created",
                    points=30, sort_order=1, config={"min_count": 1})
        _add_rubric(db, lab_lesson.id, kind="case_closed_with_reason",
                    points=40, sort_order=2,
                    config={"required_reasons": ["true_positive"]})
        sid = lab_session_service.start_or_resume(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        mat_ids = seed_lab(
            db, enrollment_id=enrolment.id, lesson_id=lab_lesson.id
        )
        lab_session_service.link_fixtures(
            db, session_id=sid, materialised_ids=mat_ids
        )
        # Learner only does two of three: views the alert + extracts an
        # observable; never closes a case. Score should be 30+30 = 60.
        _add_audit(db, user_id=user.id, action="alert_view",
                   resource_type="alert_triage", resource_id=mat_ids[0])
        _add_obs_audit(db, user.id, observable_id=1)
        result = lab_grading_service.grade_session(db, session_id=sid)
        assert result["points_earned"] == 60
        assert result["points_max"] == 100
        assert result["score"] == 60
        matched_kinds = [c["kind"] for c in result["criteria"] if c["matched"]]
        assert "viewed_alert" in matched_kinds
        assert "observable_created" in matched_kinds
        assert "case_closed_with_reason" not in matched_kinds


# ── v0.26.0: pass-threshold enforcement (pick_lab_lesson_status) ─────────


class TestPickLabLessonStatus:
    """v0.26.0: the helper that decides completed vs failed on lab completion.

    The function lives in ion.web.labs_api so it can be re-used by both
    the endpoint and (in a follow-up) a real-time grading ticker that
    grades open sessions in the background. Threshold defaults to 70
    via Course.pass_threshold but the helper is threshold-agnostic.
    """

    def test_score_none_stays_completed(self):
        """Legacy lessons without rubrics return score=None; they shouldn't
        be penalised — keep the v0.23.0 "always completed" semantics in
        that case."""
        from ion.web.labs_api import pick_lab_lesson_status
        assert pick_lab_lesson_status(None, 70) == "completed"

    def test_score_below_threshold_fails(self):
        from ion.web.labs_api import pick_lab_lesson_status
        assert pick_lab_lesson_status(50, 70) == "failed"

    def test_score_at_threshold_passes(self):
        """Boundary is inclusive — score == threshold is a pass."""
        from ion.web.labs_api import pick_lab_lesson_status
        assert pick_lab_lesson_status(70, 70) == "completed"

    def test_score_above_threshold_passes(self):
        from ion.web.labs_api import pick_lab_lesson_status
        assert pick_lab_lesson_status(95, 70) == "completed"

    def test_zero_score_fails(self):
        from ion.web.labs_api import pick_lab_lesson_status
        assert pick_lab_lesson_status(0, 70) == "failed"

    def test_perfect_score_passes(self):
        from ion.web.labs_api import pick_lab_lesson_status
        assert pick_lab_lesson_status(100, 70) == "completed"

    def test_custom_threshold_respected(self):
        """A course with a stricter pass_threshold (e.g. L3 set to 80)
        should fail learners scoring between 70-79."""
        from ion.web.labs_api import pick_lab_lesson_status
        assert pick_lab_lesson_status(75, 80) == "failed"
        assert pick_lab_lesson_status(80, 80) == "completed"
