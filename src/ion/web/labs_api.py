"""Lab fixture API — launch / complete lifecycle for LAB-type lessons.

Routes (all relative — server.py mounts this router with prefix=""):

    POST /api/courses/{slug}/lessons/{lesson_id}/lab/launch
        Start or resume a lab session, seed mock data for it.
        Returns {session_id, materialised_count, observable_links}.

    POST /api/courses/{slug}/lessons/{lesson_id}/lab/complete
        Grade the current lab session against its lesson rubric, tear down
        materialised data, and mark the lesson completed.
        Returns {session_id, score, points_earned, points_max, criteria,
        torn_down_count}.

v0.23.0 (adaptive lab grading): launch creates/resumes a lab_sessions row;
complete grades via LabGradingService before teardown. The session id flows
through to the UI so the score panel can render per-criterion results.

Auth: requires an active course enrolment for the requesting user.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user
from ion.models.course import Course, Lesson, LessonType, UserEnrolment
from ion.models.user import AuditLog, User
from ion.services import lab_grading_service, lab_session_service
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


def pick_lab_lesson_status(score: Optional[int], pass_threshold: int) -> str:
    """v0.26.0: decide whether a completed lab transitions to
    ``"completed"`` or ``"failed"`` based on the score vs threshold.

    Returns ``"completed"`` when:
      - ``score is None`` (no rubric on the lesson, no judgement to
        make — legacy lessons without criterion rows aren't penalised).
      - ``score >= pass_threshold`` (boundary inclusive — a score that
        ties the threshold passes).

    Returns ``"failed"`` when ``score < pass_threshold``.

    Pulled out of ``complete_lab`` so the threshold logic can be unit
    tested without booting a FastAPI TestClient.
    """
    if score is None:
        return "completed"
    if int(score) >= int(pass_threshold):
        return "completed"
    return "failed"


# ── Routes ────────────────────────────────────────────────────────────────


@router.post("/api/courses/{slug}/lessons/{lesson_id}/lab/launch")
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

    # open or resume a lab session before seeding fixtures so the
    # materialised rows can be back-correlated by the grader.
    sess_id = lab_session_service.start_or_resume(
        session, enrollment_id=enr.id, lesson_id=lesson_id
    )

    mat_ids = seed_lab(session, enrollment_id=enr.id, lesson_id=lesson_id)
    lab_session_service.link_fixtures(
        session, session_id=sess_id, materialised_ids=mat_ids
    )

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
        "session_id": sess_id,
        "materialised_count": len(mat_ids),
        "materialised_ids": mat_ids,
        "observable_links": [lnk for lnk in links if lnk],
    }


@router.post("/api/courses/{slug}/lessons/{lesson_id}/lab/complete")
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

    # grade BEFORE teardown so the grader can read the
    # lab_session_fixtures rows that still point at the materialised data.
    sess_id = lab_session_service.current_for(
        session, enrollment_id=enr.id, lesson_id=lesson_id
    )
    grade_summary: dict = {}
    if sess_id is not None:
        grade_summary = lab_grading_service.grade_session(session, session_id=sess_id)
        lab_session_service.complete(
            session,
            session_id=sess_id,
            score=grade_summary.get("score"),
            points_earned=grade_summary.get("points_earned", 0),
            points_max=grade_summary.get("points_max", 0),
        )

    torn_down = teardown_lab(session, enrollment_id=enr.id, lesson_id=lesson_id)

    # Mark lesson progress and persist the cached score.
    #
    # pass-threshold enforcement. Until v0.25.x the lab path
    # always set status='completed' regardless of score, which mirrored
    # the v0.23.0 first-cut grader's "rubric is informational" stance.
    # Now that v0.24/0.25.x have populated rubrics on the major LAB
    # lessons and AnyEvaluator scoring is reliable, the status should
    # reflect whether the analyst's session genuinely passed.
    #
    # Rules:
    #   - score is None  → no rubric on this lesson, no judgement to
    #                      make. Stay 'completed' so learners aren't
    #                      penalised for legacy lessons without
    #                      criterion rows.
    #   - score >= threshold → 'completed'.
    #   - score < threshold  → 'failed' (LessonProgressStatus.FAILED
    #                          already exists in the enum; used by the
    #                          quiz path since v0.23.0).
    #
    # ``Course.pass_threshold`` defaults to 70 at the model layer
    # (``src/ion/models/course.py``).
    score = grade_summary.get("score") if sess_id is not None else None
    threshold_row = session.execute(
        text(
            "SELECT c.pass_threshold "
            "FROM courses c "
            "JOIN course_modules m ON m.course_id = c.id "
            "JOIN lessons l ON l.module_id = m.id "
            "WHERE l.id = :lid"
        ),
        {"lid": lesson_id},
    ).fetchone()
    pass_threshold = int(threshold_row[0]) if threshold_row and threshold_row[0] is not None else 70

    new_status = pick_lab_lesson_status(score, pass_threshold)

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
                "(user_id, lesson_id, status, score, completed_at, "
                " last_accessed_at, attempts) "
                "VALUES (:uid, :lid, :status, :score, CURRENT_TIMESTAMP, "
                "        CURRENT_TIMESTAMP, 1)"
            ),
            {
                "uid": current_user.id, "lid": lesson_id,
                "status": new_status, "score": score,
            },
        )
    else:
        session.execute(
            text(
                "UPDATE course_lesson_progress SET status = :status, "
                "score = :score, completed_at = CURRENT_TIMESTAMP "
                "WHERE id = :id"
            ),
            {"id": prog_row[0], "status": new_status, "score": score},
        )

    _audit(
        session,
        action="lab_complete",
        user_id=current_user.id,
        lesson_id=lesson_id,
        enrollment_id=enr.id,
        detail=(
            f"Completed lab for lesson {lesson_id}; torn_down {torn_down} rows; "
            f"score={score}; status={new_status}; pass_threshold={pass_threshold}"
        ),
    )
    session.commit()

    return {
        "session_id": sess_id,
        "score": score,
        "points_earned": grade_summary.get("points_earned", 0),
        "points_max": grade_summary.get("points_max", 0),
        "criteria": grade_summary.get("criteria", []),
        "torn_down_count": torn_down,
        "lesson_status": new_status,
        "pass_threshold": pass_threshold,
    }


@router.get("/api/courses/{slug}/lessons/{lesson_id}/lab-sessions")
def get_lab_sessions(
    slug: str,
    lesson_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """v0.26.0: return the analyst's past lab attempts for this lesson.

    Used by the lesson detail page's new "Lab history" subpanel.
    Sessions are returned newest-first; each session includes the
    per-criterion breakdown so the UI can expand individual attempts
    without a second round trip.

    Scope: the calling user's own enrolment only. No cross-user peeking.
    """
    lesson = _resolve_lesson(session, slug, lesson_id)
    if lesson.lesson_type != LessonType.LAB:
        raise HTTPException(
            status_code=400,
            detail="Only LAB-type lessons have lab session history",
        )

    enr = _require_enrollment(session, current_user.id, lesson.module.course_id)

    # Pull the threshold so the UI can render a "pass mark X%" hint
    # alongside each session's score.
    threshold_row = session.execute(
        text("SELECT pass_threshold FROM courses WHERE id = :cid"),
        {"cid": lesson.module.course_id},
    ).fetchone()
    pass_threshold = (
        int(threshold_row[0]) if threshold_row and threshold_row[0] is not None else 70
    )

    # All this user's sessions for the lesson. ``completed_at NULLS LAST``
    # so an in-progress current session sorts after completed ones.
    sess_rows = session.execute(
        text(
            "SELECT id, attempt_number, started_at, completed_at, "
            "       score, points_earned, points_max "
            "FROM lab_sessions "
            "WHERE enrollment_id = :eid AND lesson_id = :lid "
            "ORDER BY completed_at DESC NULLS LAST, started_at DESC"
        ),
        {"eid": enr.id, "lid": lesson_id},
    ).fetchall()

    sessions_out: List[dict] = []
    if sess_rows:
        # Fetch every (criterion result + rubric) for the matching session
        # ids in one query so we don't N+1 the loop.
        sess_ids = [int(r[0]) for r in sess_rows]
        placeholders = ", ".join(f":id_{i}" for i in range(len(sess_ids)))
        params = {f"id_{i}": sid for i, sid in enumerate(sess_ids)}
        crit_rows = session.execute(
            text(
                "SELECT lcr.session_id, lcr.rubric_id, lcr.points_earned, "
                "       lcr.points_max, lcr.matched, lcr.notes, "
                "       lr.criterion_kind, lr.description, lr.sort_order "
                "FROM lab_criterion_results lcr "
                "JOIN lab_rubrics lr ON lr.id = lcr.rubric_id "
                f"WHERE lcr.session_id IN ({placeholders}) "
                "ORDER BY lcr.session_id, lr.sort_order, lr.id"
            ),
            params,
        ).fetchall()
        criteria_by_session: dict[int, list[dict]] = {}
        for cr in crit_rows:
            criteria_by_session.setdefault(int(cr[0]), []).append({
                "rubric_id": int(cr[1]),
                "points_earned": int(cr[2]),
                "points_max": int(cr[3]),
                "matched": bool(cr[4]),
                "notes": cr[5],
                "kind": cr[6],
                "description": cr[7],
                "sort_order": int(cr[8]),
            })

        for r in sess_rows:
            sess_id_i = int(r[0])
            completed_at = r[3]
            score_v = r[4]
            if completed_at is None:
                status = "in_progress"
            else:
                status = pick_lab_lesson_status(
                    int(score_v) if score_v is not None else None,
                    pass_threshold,
                )
            sessions_out.append({
                "session_id": sess_id_i,
                "attempt_number": int(r[1]),
                "started_at": r[2].isoformat() if hasattr(r[2], "isoformat") else r[2],
                "completed_at": (
                    completed_at.isoformat()
                    if hasattr(completed_at, "isoformat") and completed_at is not None
                    else completed_at
                ),
                "score": int(score_v) if score_v is not None else None,
                "points_earned": int(r[5]),
                "points_max": int(r[6]),
                "status": status,
                "criteria": criteria_by_session.get(sess_id_i, []),
            })

    return {
        "lesson_id": lesson_id,
        "pass_threshold": pass_threshold,
        "sessions": sessions_out,
    }
