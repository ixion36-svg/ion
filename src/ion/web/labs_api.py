"""Lab fixture API — launch / complete lifecycle for LAB-type lessons (v0.21.0).

Routes (all relative — server.py mounts this router with prefix=""):

    POST /api/courses/{slug}/lessons/{lesson_id}/lab/launch
        Seed mock data for the learner's lab session.
        Returns {materialised_count, observable_links}.

    POST /api/courses/{slug}/lessons/{lesson_id}/lab/complete
        Tear down materialised data and mark the lesson completed.
        Returns {torn_down_count}.

Auth: requires an active course enrolment for the requesting user.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user
from ion.models.course import Course, Lesson, LessonProgressStatus, LessonType, UserEnrolment
from ion.models.user import AuditLog, User
from ion.services.lab_fixture_service import (
    _observable_link,
    get_live_session_fixtures,
    seed_lab,
    teardown_lab,
)
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(tags=["labs"])


# ── Helpers ──────────────────────────────────────────────────────────────


def _resolve_lesson(session: Session, slug: str, lesson_id: int) -> Lesson:
    """Return the Lesson, 404 if not found or not under the given course slug."""
    course = session.query(Course).filter(Course.slug == slug).one_or_none()
    if course is None:
        raise HTTPException(status_code=404, detail="Course not found")
    lesson = session.get(Lesson, lesson_id)
    if lesson is None or lesson.module is None:
        raise HTTPException(status_code=404, detail="Lesson not found")
    if lesson.module.course_id != course.id:
        raise HTTPException(status_code=404, detail="Lesson does not belong to this course")
    return lesson


def _require_enrollment(
    session: Session, user_id: int, course_id: int
) -> UserEnrolment:
    """Return the UserEnrolment or raise 403."""
    enr = (
        session.query(UserEnrolment)
        .filter_by(user_id=user_id, course_id=course_id)
        .one_or_none()
    )
    if enr is None:
        raise HTTPException(status_code=403, detail="Not enrolled in this course")
    return enr


def _audit(
    session: Session,
    *,
    action: str,
    user_id: int,
    lesson_id: int,
    enrollment_id: int,
    detail: str,
) -> None:
    """Write an audit_log row for lab launch/complete events."""
    session.add(
        AuditLog(
            user_id=user_id,
            action=action,
            resource_type="lesson",
            resource_id=lesson_id,
            details=detail,
        )
    )


def _build_observable_links(live_rows: list[dict]) -> List[Optional[str]]:
    return [
        _observable_link(r["materialised_row_id"], r["materialised_table"])
        for r in live_rows
    ]


# ── Routes ────────────────────────────────────────────────────────────────


@router.post("/courses/{slug}/lessons/{lesson_id}/lab/launch")
def launch_lab(
    slug: str,
    lesson_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Seed mock data for the learner's lab session.

    Idempotent: calling twice before completing returns the same
    materialised_count without creating duplicate rows.
    """
    lesson = _resolve_lesson(session, slug, lesson_id)
    if lesson.lesson_type != LessonType.LAB:
        raise HTTPException(status_code=400, detail="Only LAB-type lessons can be launched")

    enr = _require_enrollment(session, current_user.id, lesson.module.course_id)

    mat_ids = seed_lab(session, enrollment_id=enr.id, lesson_id=lesson_id)

    live = get_live_session_fixtures(session, enrollment_id=enr.id, lesson_id=lesson_id)
    links = _build_observable_links(live)

    _audit(
        session,
        action="lab_launch",
        user_id=current_user.id,
        lesson_id=lesson_id,
        enrollment_id=enr.id,
        detail=f"Launched lab for lesson {lesson_id}; materialised {len(mat_ids)} rows",
    )
    session.commit()

    return {
        "materialised_count": len(mat_ids),
        "materialised_ids": mat_ids,
        "observable_links": [lnk for lnk in links if lnk],
    }


@router.post("/courses/{slug}/lessons/{lesson_id}/lab/complete")
def complete_lab(
    slug: str,
    lesson_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Tear down materialised data and mark the lesson completed.

    Best-effort teardown: rows already deleted externally are logged and
    skipped. The lesson progress is set to COMPLETED regardless.
    """
    lesson = _resolve_lesson(session, slug, lesson_id)
    if lesson.lesson_type != LessonType.LAB:
        raise HTTPException(status_code=400, detail="Only LAB-type lessons can be completed this way")

    enr = _require_enrollment(session, current_user.id, lesson.module.course_id)

    torn_down = teardown_lab(session, enrollment_id=enr.id, lesson_id=lesson_id)

    # Mark lesson progress completed.
    prog_row = session.execute(
        text(
            "SELECT id, status FROM course_lesson_progress "
            "WHERE user_id = :uid AND lesson_id = :lid"
        ),
        {"uid": current_user.id, "lid": lesson_id},
    ).fetchone()

    if prog_row is None:
        session.execute(
            text(
                "INSERT INTO course_lesson_progress "
                "(user_id, lesson_id, status, completed_at, last_accessed_at, attempts) "
                "VALUES (:uid, :lid, 'completed', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)"
            ),
            {"uid": current_user.id, "lid": lesson_id},
        )
    else:
        session.execute(
            text(
                "UPDATE course_lesson_progress SET status = 'completed', "
                "completed_at = CURRENT_TIMESTAMP WHERE id = :id"
            ),
            {"id": prog_row[0]},
        )

    _audit(
        session,
        action="lab_complete",
        user_id=current_user.id,
        lesson_id=lesson_id,
        enrollment_id=enr.id,
        detail=f"Completed lab for lesson {lesson_id}; torn_down {torn_down} rows",
    )
    session.commit()

    return {
        "torn_down_count": torn_down,
        "lesson_status": LessonProgressStatus.COMPLETED,
    }
