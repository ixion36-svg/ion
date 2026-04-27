"""Training course API + page routes (v0.11.2).

Endpoints split by audience:

**Analyst (taking courses):**
- ``GET    /api/courses``                            list published catalog (filterable by level)
- ``GET    /api/courses/{slug}``                     course detail with modules + lessons (no answers)
- ``POST   /api/courses/{id}/enrol``                 enrol the current user
- ``GET    /api/my-courses``                         current user's enrolments + progress
- ``GET    /api/lessons/{id}``                       lesson content + questions (no correct answers)
- ``POST   /api/lessons/{id}/complete``              mark a READING/LAB lesson complete
- ``POST   /api/lessons/{id}/submit-quiz``           submit answers; returns score + per-question result

**Pages:**
- ``GET /courses``                                   catalog
- ``GET /courses/{slug}``                            detail
- ``GET /lessons/{id}``                              lesson view
- ``GET /my-courses``                                analyst's enrolments dashboard
"""
from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_page_auth
from ion.models.course import (
    Course, CourseLevel, CourseModule, Lesson, LessonProgressStatus,
    LessonType, Question, QuestionKind, UserAnswer, UserEnrolment,
    UserLessonProgress,
)
from ion.models.user import User
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(tags=["courses"])

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
try:
    import ion as _ion_pkg
    _templates.env.globals["ion_version"] = _ion_pkg.__version__
except Exception:
    _templates.env.globals.setdefault("ion_version", "")


# ── Serialisers ──────────────────────────────────────────────────────────


def _course_summary(c: Course, *, progress: Optional[UserLessonProgress] = None) -> dict:
    return {
        "id": c.id,
        "title": c.title,
        "slug": c.slug,
        "level": c.level,
        "description_md": c.description_md,
        "estimated_hours": c.estimated_hours,
        "badge_image_path": c.badge_image_path,
        "prerequisite_course_id": c.prerequisite_course_id,
        "order_in_level": c.order_in_level,
        "pass_threshold": c.pass_threshold,
        "published": c.published,
    }


def _question_for_taker(q: Question) -> dict:
    """Question payload sent to a taker — strips correct_answer + explanation."""
    options = []
    if q.options_json:
        try:
            options = json.loads(q.options_json)
        except (TypeError, ValueError):
            options = []
    return {
        "id": q.id,
        "order": q.order,
        "kind": q.kind,
        "stem_md": q.stem_md,
        "options": options,
        "points": q.points,
    }


def _question_with_key(q: Question) -> dict:
    """Internal — includes correct answer + explanation. Never returned to a taker."""
    base = _question_for_taker(q)
    try:
        correct = json.loads(q.correct_answer_json) if q.correct_answer_json else None
    except (TypeError, ValueError):
        correct = None
    base["correct_answer"] = correct
    base["explanation_md"] = q.explanation_md
    return base


def _lesson_summary(l: Lesson, *, prog: Optional[UserLessonProgress] = None) -> dict:
    return {
        "id": l.id,
        "module_id": l.module_id,
        "order": l.order,
        "title": l.title,
        "lesson_type": l.lesson_type,
        "duration_min": l.duration_min,
        "lab_target_url": l.lab_target_url,
        "question_count": len(l.questions or []),
        "user_status": prog.status if prog else LessonProgressStatus.NOT_STARTED,
        "user_score": prog.score if prog else None,
    }


def _module_with_lessons(m: CourseModule, *, progress_by_lesson: Dict[int, UserLessonProgress]) -> dict:
    return {
        "id": m.id,
        "order": m.order,
        "title": m.title,
        "description_md": m.description_md,
        "estimated_minutes": m.estimated_minutes,
        "lessons": [
            _lesson_summary(l, prog=progress_by_lesson.get(l.id))
            for l in (m.lessons or [])
        ],
    }


def _my_progress_for_course(session: Session, user_id: int, course_id: int) -> Dict[int, UserLessonProgress]:
    rows = (
        session.query(UserLessonProgress)
        .join(Lesson, Lesson.id == UserLessonProgress.lesson_id)
        .join(CourseModule, CourseModule.id == Lesson.module_id)
        .filter(CourseModule.course_id == course_id)
        .filter(UserLessonProgress.user_id == user_id)
        .all()
    )
    return {p.lesson_id: p for p in rows}


def _ensure_progress(session: Session, user_id: int, lesson_id: int) -> UserLessonProgress:
    row = (
        session.query(UserLessonProgress)
        .filter(UserLessonProgress.user_id == user_id, UserLessonProgress.lesson_id == lesson_id)
        .one_or_none()
    )
    if row is None:
        row = UserLessonProgress(
            user_id=user_id, lesson_id=lesson_id,
            status=LessonProgressStatus.IN_PROGRESS,
        )
        session.add(row)
        session.flush()
    return row


def _recompute_enrolment_completion(
    session: Session, user_id: int, course_id: int,
) -> Optional[UserEnrolment]:
    """After any lesson progress change, refresh the enrolment record.

    A course is "completed" when every lesson is in COMPLETED status.
    Sets ``completed_at`` + ``badge_earned`` on first crossover; computes
    ``score_pct`` as the average of per-quiz-lesson scores.
    """
    enr = (
        session.query(UserEnrolment)
        .filter(UserEnrolment.user_id == user_id, UserEnrolment.course_id == course_id)
        .one_or_none()
    )
    if enr is None:
        return None
    course = session.get(Course, course_id)
    if course is None:
        return enr
    all_lesson_ids: List[int] = []
    for m in course.modules or []:
        for l in (m.lessons or []):
            all_lesson_ids.append(l.id)
    if not all_lesson_ids:
        return enr

    progress_rows = (
        session.query(UserLessonProgress)
        .filter(UserLessonProgress.user_id == user_id)
        .filter(UserLessonProgress.lesson_id.in_(all_lesson_ids))
        .all()
    )
    progress_by_lesson = {p.lesson_id: p for p in progress_rows}

    completed_count = 0
    quiz_scores: List[int] = []
    for lid in all_lesson_ids:
        p = progress_by_lesson.get(lid)
        if p is None:
            continue
        if p.status == LessonProgressStatus.COMPLETED:
            completed_count += 1
        if p.score is not None:
            quiz_scores.append(int(p.score))

    if quiz_scores:
        enr.score_pct = round(sum(quiz_scores) / len(quiz_scores))

    if completed_count == len(all_lesson_ids) and enr.completed_at is None:
        enr.completed_at = datetime.utcnow()
        enr.badge_earned = True
    elif completed_count < len(all_lesson_ids):
        # If a re-attempt regressed a lesson from completed back to failed,
        # reopen the enrolment.
        enr.completed_at = None
        enr.badge_earned = False
    session.flush()
    return enr


# ── Catalog endpoints ────────────────────────────────────────────────────


@router.get("/api/courses")
def list_courses(
    level: Optional[str] = None,
    include_unpublished: bool = False,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    q = session.query(Course)
    if not include_unpublished:
        q = q.filter(Course.published.is_(True))
    if level:
        q = q.filter(Course.level == level.upper())
    q = q.order_by(Course.level.asc(), Course.order_in_level.asc(), Course.id.asc())
    rows = q.all()
    return {
        "courses": [_course_summary(c) for c in rows],
        "count": len(rows),
    }


@router.get("/api/courses/{slug}")
def get_course(
    slug: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    course = session.query(Course).filter(Course.slug == slug).one_or_none()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    progress = _my_progress_for_course(session, current_user.id, course.id)
    enrol = (
        session.query(UserEnrolment)
        .filter_by(user_id=current_user.id, course_id=course.id)
        .one_or_none()
    )
    return {
        **_course_summary(course),
        "modules": [
            _module_with_lessons(m, progress_by_lesson=progress)
            for m in (course.modules or [])
        ],
        "enrolment": {
            "enrolled": enrol is not None,
            "started_at": enrol.started_at.isoformat() if enrol and enrol.started_at else None,
            "completed_at": enrol.completed_at.isoformat() if enrol and enrol.completed_at else None,
            "badge_earned": enrol.badge_earned if enrol else False,
            "score_pct": enrol.score_pct if enrol else None,
        },
    }


@router.post("/api/courses/{course_id}/enrol")
def enrol_in_course(
    course_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    course = session.get(Course, course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    # Prerequisite gate — block enrolment if the prereq isn't completed
    if course.prerequisite_course_id:
        prereq_enr = (
            session.query(UserEnrolment)
            .filter_by(user_id=current_user.id, course_id=course.prerequisite_course_id)
            .one_or_none()
        )
        if not prereq_enr or prereq_enr.completed_at is None:
            raise HTTPException(
                status_code=400,
                detail=f"Prerequisite course #{course.prerequisite_course_id} must be completed first",
            )

    existing = (
        session.query(UserEnrolment)
        .filter_by(user_id=current_user.id, course_id=course_id)
        .one_or_none()
    )
    if existing:
        return {"enrolment_id": existing.id, "already_enrolled": True}

    enr = UserEnrolment(user_id=current_user.id, course_id=course_id)
    session.add(enr)
    session.commit()
    session.refresh(enr)
    return {"enrolment_id": enr.id, "already_enrolled": False}


@router.get("/api/my-courses")
def list_my_courses(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    enrolments = (
        session.query(UserEnrolment)
        .filter(UserEnrolment.user_id == current_user.id)
        .order_by(UserEnrolment.id.desc())
        .all()
    )
    out = []
    for enr in enrolments:
        course = session.get(Course, enr.course_id)
        if not course:
            continue
        out.append({
            **_course_summary(course),
            "started_at": enr.started_at.isoformat() if enr.started_at else None,
            "completed_at": enr.completed_at.isoformat() if enr.completed_at else None,
            "badge_earned": enr.badge_earned,
            "score_pct": enr.score_pct,
        })
    return {"courses": out, "count": len(out)}


# ── Lesson endpoints ─────────────────────────────────────────────────────


@router.get("/api/lessons/{lesson_id}")
def get_lesson(
    lesson_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    lesson = session.get(Lesson, lesson_id)
    if not lesson:
        raise HTTPException(status_code=404, detail="Lesson not found")

    # Mark IN_PROGRESS on first view (or keep prior status if already past
    # that). Fast write so the catalog reflects the user re-engaged.
    prog = _ensure_progress(session, current_user.id, lesson_id)
    if prog.status == LessonProgressStatus.NOT_STARTED:
        prog.status = LessonProgressStatus.IN_PROGRESS
    session.commit()

    return {
        "id": lesson.id,
        "module_id": lesson.module_id,
        "course_id": lesson.module.course_id if lesson.module else None,
        "order": lesson.order,
        "title": lesson.title,
        "lesson_type": lesson.lesson_type,
        "content_md": lesson.content_md,
        "duration_min": lesson.duration_min,
        "lab_target_url": lesson.lab_target_url,
        "questions": [_question_for_taker(q) for q in (lesson.questions or [])],
        "user_status": prog.status,
        "user_score": prog.score,
        "user_attempts": prog.attempts,
    }


@router.post("/api/lessons/{lesson_id}/complete")
def mark_lesson_complete(
    lesson_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    lesson = session.get(Lesson, lesson_id)
    if not lesson:
        raise HTTPException(status_code=404, detail="Lesson not found")
    if lesson.lesson_type == LessonType.QUIZ:
        raise HTTPException(
            status_code=400,
            detail="Quiz lessons require submit-quiz to complete; this endpoint is for reading/lab",
        )
    prog = _ensure_progress(session, current_user.id, lesson_id)
    prog.status = LessonProgressStatus.COMPLETED
    prog.completed_at = datetime.utcnow()
    session.flush()
    course_id = lesson.module.course_id if lesson.module else None
    if course_id:
        _recompute_enrolment_completion(session, current_user.id, course_id)
    session.commit()
    return {"lesson_id": lesson_id, "status": prog.status}


class QuizSubmission(BaseModel):
    answers: Dict[int, Any]  # {question_id: answer_value}


@router.post("/api/lessons/{lesson_id}/submit-quiz")
def submit_quiz(
    lesson_id: int,
    body: QuizSubmission,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    lesson = session.get(Lesson, lesson_id)
    if not lesson:
        raise HTTPException(status_code=404, detail="Lesson not found")
    if lesson.lesson_type != LessonType.QUIZ and lesson.lesson_type != LessonType.LAB:
        raise HTTPException(
            status_code=400,
            detail="Only QUIZ/LAB lessons accept quiz submissions",
        )

    questions = lesson.questions or []
    if not questions:
        raise HTTPException(status_code=400, detail="This lesson has no questions")

    # Grade each question
    attempt_id = secrets.token_urlsafe(16)
    total_points = sum(q.points for q in questions) or 1
    earned = 0
    per_question_results: List[dict] = []

    for q in questions:
        submitted = body.answers.get(q.id)
        try:
            correct = json.loads(q.correct_answer_json) if q.correct_answer_json else None
        except (TypeError, ValueError):
            correct = None

        is_correct = False
        points_earned = 0

        if q.kind in (QuestionKind.SINGLE, QuestionKind.TRUEFALSE):
            is_correct = (
                submitted is not None
                and isinstance(correct, str)
                and str(submitted).strip() == correct
            )
            if is_correct:
                points_earned = q.points
        elif q.kind == QuestionKind.MULTI:
            sub_set = set(submitted) if isinstance(submitted, list) else set()
            cor_set = set(correct) if isinstance(correct, list) else set()
            if sub_set and cor_set:
                # Partial credit: |intersection|/|union| of correct/submitted
                intersect = len(sub_set & cor_set)
                union = len(sub_set | cor_set)
                ratio = intersect / union if union else 0
                points_earned = round(q.points * ratio)
                is_correct = (sub_set == cor_set)
        elif q.kind == QuestionKind.SHORTANSWER:
            sub_norm = (str(submitted) if submitted is not None else "").strip().lower()
            valid = {a.strip().lower() for a in (correct or []) if isinstance(a, str)}
            is_correct = sub_norm in valid and bool(sub_norm)
            if is_correct:
                points_earned = q.points

        earned += points_earned
        # Persist the answer row
        session.add(UserAnswer(
            user_id=current_user.id,
            question_id=q.id,
            attempt_id=attempt_id,
            answer_json=json.dumps(submitted, default=str),
            is_correct=is_correct,
            points_earned=points_earned,
        ))
        per_question_results.append({
            "question_id": q.id,
            "is_correct": is_correct,
            "points_earned": points_earned,
            "points_max": q.points,
            "correct_answer": correct,
            "explanation_md": q.explanation_md,
        })

    score_pct = round(100 * earned / total_points)

    # Update lesson progress
    prog = _ensure_progress(session, current_user.id, lesson_id)
    prog.attempts = (prog.attempts or 0) + 1
    prog.score = score_pct
    prog.last_accessed_at = datetime.utcnow()

    # Pass threshold lives on the parent course
    course = lesson.module.course if lesson.module else None
    threshold = (course.pass_threshold if course else 70)
    if score_pct >= threshold:
        prog.status = LessonProgressStatus.COMPLETED
        prog.completed_at = datetime.utcnow()
    else:
        prog.status = LessonProgressStatus.FAILED

    session.flush()
    if course:
        _recompute_enrolment_completion(session, current_user.id, course.id)
    session.commit()

    return {
        "attempt_id": attempt_id,
        "score_pct": score_pct,
        "passed": score_pct >= threshold,
        "threshold": threshold,
        "earned_points": earned,
        "total_points": total_points,
        "results": per_question_results,
        "status": prog.status,
    }


# ── Page routes ──────────────────────────────────────────────────────────


@router.get("/courses", response_class=HTMLResponse)
def courses_page(request: Request, _user: User = Depends(require_page_auth)):
    return _templates.TemplateResponse(request=request, name="courses.html")


@router.get("/courses/{slug}", response_class=HTMLResponse)
def course_detail_page(
    slug: str, request: Request, _user: User = Depends(require_page_auth),
):
    return _templates.TemplateResponse(
        request=request, name="course_detail.html", context={"slug": slug},
    )


@router.get("/lessons/{lesson_id}", response_class=HTMLResponse)
def lesson_page(
    lesson_id: int, request: Request, _user: User = Depends(require_page_auth),
):
    return _templates.TemplateResponse(
        request=request, name="lesson.html", context={"lesson_id": lesson_id},
    )
