"""Training course API + page routes (v0.11.2+).

Endpoints split by audience:

**Analyst (taking courses):**
- ``GET    /api/courses``                            list published catalog (filterable by level)
- ``GET    /api/courses/{slug}``                     course detail with modules + lessons (no answers)
- ``POST   /api/courses/{id}/enrol``                 enrol the current user
- ``GET    /api/my-courses``                         current user's enrolments + progress
- ``GET    /api/lessons/{id}``                       lesson content + questions (no correct answers)
- ``POST   /api/lessons/{id}/complete``              mark a READING/LAB lesson complete
- ``POST   /api/lessons/{id}/submit-quiz``           submit answers; returns score + per-question result

**Author (v0.11.3):**
- ``POST   /api/courses/{slug}/images``              upload an image asset for a course (PNG/JPG/SVG/WebP only)

**Pages:**
- ``GET /courses``                                   catalog
- ``GET /courses/{slug}``                            detail
- ``GET /lessons/{id}``                              lesson view
- ``GET /my-courses``                                analyst's enrolments dashboard
"""
from __future__ import annotations

import json
import logging
import re
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_page_auth, require_permission
from ion.models.course import (
    Course,
    CourseModule,
    Lesson,
    LessonProgressStatus,
    LessonType,
    Question,
    QuestionKind,
    UserAnswer,
    UserEnrolment,
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


# ── Course-completion certificate (v0.13.0) ──────────────────────────────


def _render_certificate_html(
    course: Course, user: User, enrolment: UserEnrolment,
) -> str:
    """Build the weasyprint HTML for a single course-completion certificate.

    The artefact a learner downloads after completing a course. Carries
    the level / course title / learner name / completion date / aggregate
    score / module + lesson totals. Uses the same weasyprint pattern as
    the CyAB Onboarding Pack (v0.12.0).
    """
    import html as _html_mod

    def h(v: Any) -> str:
        return _html_mod.escape("" if v is None else str(v), quote=True)

    completed_on = enrolment.completed_at or datetime.utcnow()
    completed_str = completed_on.strftime("%d %B %Y")

    # Module / lesson totals from the course
    total_modules = len(course.modules or [])
    total_lessons = sum(len(m.lessons or []) for m in (course.modules or []))

    # Display name fallback: full_name / email / username
    learner_name = (
        getattr(user, "full_name", None)
        or getattr(user, "name", None)
        or user.email
        or user.username
    )

    # Level styling
    level_text = (course.level or "").upper()
    level_palette = {
        "L1": ("#0ea5e9", "#082f49"),  # cyan
        "L2": ("#a78bfa", "#1e1b4b"),  # iris
        "L3": ("#facc15", "#451a03"),  # amber
        "L4": ("#f97316", "#431407"),  # orange
    }
    level_fg, level_bg = level_palette.get(level_text, ("#64748b", "#0f172a"))

    score_block = (
        f'<tr><td>Aggregate score</td><td><strong>{h(enrolment.score_pct)}%</strong></td></tr>'
        if enrolment.score_pct is not None else ""
    )

    style = """
    <style>
      @page { size: A4 landscape; margin: 14mm; }
      body { font-family: "Times New Roman", Georgia, serif; color: #1a1a1a; }
      .frame { border: 4px double #0b3d91; padding: 38mm 24mm 24mm 24mm; min-height: calc(210mm - 28mm - 8px);
               position: relative; }
      .seal { position: absolute; top: 18mm; right: 18mm; width: 38mm; height: 38mm;
              border: 3px solid #0b3d91; border-radius: 50%;
              display: flex; align-items: center; justify-content: center;
              font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
              font-weight: 700; color: #0b3d91; font-size: 11pt; line-height: 1.1; text-align: center; }
      .level-pill { display: inline-block; padding: 3pt 10pt; border-radius: 4pt;
                    font-family: -apple-system, "Segoe UI", sans-serif; font-weight: 700;
                    font-size: 11pt; letter-spacing: 0.18em; }
      h1 { font-size: 38pt; margin: 6pt 0 0 0; line-height: 1.05; color: #0b3d91; }
      h2 { font-size: 16pt; margin: 22pt 0 4pt 0; color: #444; font-weight: 400; letter-spacing: 0.04em; }
      .learner { font-size: 30pt; margin: 4pt 0 22pt 0; color: #1a1a1a; font-weight: 700; }
      .body-text { font-size: 13pt; line-height: 1.55; max-width: 200mm; }
      table.meta { margin-top: 22pt; border-collapse: collapse; font-family: -apple-system, "Segoe UI", sans-serif; }
      table.meta td { border: none; padding: 4pt 24pt 4pt 0; font-size: 11pt; vertical-align: top; }
      table.meta td:first-child { color: #555; }
      .signoff { margin-top: 24pt; font-family: -apple-system, "Segoe UI", sans-serif;
                 display: flex; justify-content: space-between; gap: 30mm; font-size: 10pt; color: #444; }
      .sig-block { flex: 1; border-top: 1px solid #555; padding-top: 4pt; }
      .footer-id { position: absolute; bottom: 10mm; right: 24mm; font-family: ui-monospace, "SF Mono", Menlo, monospace;
                   color: #888; font-size: 8pt; }
    </style>
    """

    body = f"""
    <div class="frame">
      <div class="seal">
        ION<br>SOC<br>CURRICULUM
      </div>

      <div>
        <span class="level-pill" style="background:{level_bg};color:{level_fg};">{h(level_text)}</span>
      </div>

      <h2>Certificate of Completion</h2>
      <h1>{h(course.title)}</h1>

      <p class="body-text" style="margin-top: 22pt;">
        This is to certify that
      </p>
      <div class="learner">{h(learner_name)}</div>
      <p class="body-text">
        has successfully completed the <strong>{h(course.title)}</strong> course
        — <strong>{h(total_modules)} modules</strong> and <strong>{h(total_lessons)} lessons</strong> at
        BTL1 / SANS GCTH-equivalent depth — on <strong>{h(completed_str)}</strong>.
      </p>

      <table class="meta">
        <tr><td>Course level</td><td>{h(level_text)}</td></tr>
        <tr><td>Modules completed</td><td>{h(total_modules)}</td></tr>
        <tr><td>Lessons completed</td><td>{h(total_lessons)}</td></tr>
        {score_block}
        <tr><td>Completion date</td><td>{h(completed_str)}</td></tr>
      </table>

      <div class="signoff">
        <div class="sig-block">
          ION SOC Curriculum<br>
          Issued by the Detection-Engineering Programme
        </div>
        <div class="sig-block" style="text-align: right;">
          Verification: enrolment #{h(enrolment.id)}<br>
          Issued {h(datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'))}
        </div>
      </div>

      <div class="footer-id">CERT-{h(course.slug)}-{h(enrolment.id)}-{h(completed_on.strftime('%Y%m%d'))}</div>
    </div>
    """
    return f"<!DOCTYPE html><html><head><meta charset=\"UTF-8\">{style}</head><body>{body}</body></html>"


@router.get("/api/courses/{slug}/certificate.pdf")
def get_course_certificate(
    slug: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Render and return a PDF course-completion certificate for the current user.

    Returns 404 if the course doesn't exist; 403 if the user isn't enrolled
    or hasn't completed the course; 200 + application/pdf otherwise.
    """
    from fastapi.responses import Response

    course = session.query(Course).filter(Course.slug == slug).one_or_none()
    if course is None:
        raise HTTPException(status_code=404, detail="Course not found")

    enr = (
        session.query(UserEnrolment)
        .filter_by(user_id=current_user.id, course_id=course.id)
        .one_or_none()
    )
    if enr is None:
        raise HTTPException(status_code=403, detail="Not enrolled")
    if enr.completed_at is None:
        raise HTTPException(
            status_code=403,
            detail="Course not yet completed — finish all lessons first",
        )

    full_html = _render_certificate_html(course, current_user, enr)

    # Cache the URL-style metadata so the catalog can show the issued state.
    if not enr.certificate_url:
        enr.certificate_url = f"/api/courses/{slug}/certificate.pdf"
        session.commit()

    try:
        from weasyprint import HTML as WpHTML
        pdf_bytes = WpHTML(string=full_html).write_pdf()
        slug_safe = re.sub(r"[^A-Za-z0-9._-]+", "_", slug).strip("_")[:60] or "certificate"
        filename = f"ion_certificate_{slug_safe}_enr{enr.id}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Content-Type-Options": "nosniff",
            },
        )
    except (ImportError, OSError):
        return Response(
            content=full_html,
            media_type="text/html",
            headers={
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:",
                "X-Content-Type-Options": "nosniff",
            },
        )


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


# ── Authoring CRUD (v0.11.4) ─────────────────────────────────────────────
#
# Permission model: read uses `playbook:read`, mutating ops use
# `playbook:create`/`playbook:update`/`playbook:delete` (mirroring the
# Stories subsystem). Course authors typically hold engineering or admin
# roles which already carry these.


def _slugify(s: str) -> str:
    """Course slug from title — lowercase, hyphenated, ASCII-only."""
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-") or "course"


class CourseCreate(BaseModel):
    title: str
    slug: Optional[str] = None
    level: str  # "L1" | "L2" | "L3" | "L4"
    description_md: Optional[str] = ""
    estimated_hours: int = 1
    pass_threshold: int = 70
    order_in_level: int = 0
    published: bool = False
    skill_keys: Optional[List[str]] = None
    prerequisite_course_id: Optional[int] = None
    badge_image_path: Optional[str] = None


class CoursePatch(BaseModel):
    title: Optional[str] = None
    slug: Optional[str] = None
    level: Optional[str] = None
    description_md: Optional[str] = None
    estimated_hours: Optional[int] = None
    pass_threshold: Optional[int] = None
    order_in_level: Optional[int] = None
    published: Optional[bool] = None
    skill_keys: Optional[List[str]] = None
    prerequisite_course_id: Optional[int] = None
    badge_image_path: Optional[str] = None


class ModuleCreate(BaseModel):
    title: str
    description_md: Optional[str] = ""
    estimated_minutes: int = 30
    order: Optional[int] = None


class ModulePatch(BaseModel):
    title: Optional[str] = None
    description_md: Optional[str] = None
    estimated_minutes: Optional[int] = None
    order: Optional[int] = None


class LessonCreate(BaseModel):
    title: str
    lesson_type: str = "reading"  # "reading" | "quiz" | "lab"
    content_md: str = ""
    duration_min: int = 10
    order: Optional[int] = None
    lab_target_url: Optional[str] = None


class LessonPatch(BaseModel):
    title: Optional[str] = None
    lesson_type: Optional[str] = None
    content_md: Optional[str] = None
    duration_min: Optional[int] = None
    order: Optional[int] = None
    lab_target_url: Optional[str] = None


class QuestionCreate(BaseModel):
    kind: str  # "single" | "multi" | "truefalse" | "shortanswer"
    stem_md: str
    options: Optional[List[Dict[str, str]]] = None
    correct_answer: Any  # str | list[str] depending on kind
    explanation_md: Optional[str] = None
    points: int = 1
    order: Optional[int] = None


class QuestionPatch(BaseModel):
    kind: Optional[str] = None
    stem_md: Optional[str] = None
    options: Optional[List[Dict[str, str]]] = None
    correct_answer: Any = None
    explanation_md: Optional[str] = None
    points: Optional[int] = None
    order: Optional[int] = None


def _next_order(items: List[Any]) -> int:
    if not items:
        return 0
    return max(getattr(it, "order", 0) for it in items) + 1


@router.post("/api/courses", status_code=201)
def create_course(
    body: CourseCreate,
    current_user: User = Depends(require_permission("playbook:create")),
    session: Session = Depends(get_db_session),
):
    """Create a new course shell. Modules/lessons/questions added separately."""
    slug = body.slug or _slugify(body.title)
    if session.query(Course).filter(Course.slug == slug).first():
        raise HTTPException(status_code=409, detail=f"Course slug '{slug}' already exists")
    course = Course(
        title=body.title, slug=slug, level=body.level,
        description_md=body.description_md or "",
        estimated_hours=body.estimated_hours,
        pass_threshold=body.pass_threshold,
        order_in_level=body.order_in_level,
        published=body.published,
        skill_keys=json.dumps(body.skill_keys) if body.skill_keys else None,
        prerequisite_course_id=body.prerequisite_course_id,
        badge_image_path=body.badge_image_path,
        author_id=current_user.id if current_user else None,
    )
    session.add(course)
    session.commit()
    session.refresh(course)
    return _course_summary(course)


@router.put("/api/courses/{course_id}")
def update_course(
    course_id: int, body: CoursePatch,
    current_user: User = Depends(require_permission("playbook:update")),
    session: Session = Depends(get_db_session),
):
    course = session.get(Course, course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    data = body.model_dump(exclude_unset=True)
    if "skill_keys" in data:
        data["skill_keys"] = json.dumps(data["skill_keys"]) if data["skill_keys"] else None
    if "slug" in data and data["slug"] and data["slug"] != course.slug:
        existing = session.query(Course).filter(Course.slug == data["slug"]).first()
        if existing and existing.id != course_id:
            raise HTTPException(status_code=409, detail=f"Slug '{data['slug']}' already in use")
    for k, v in data.items():
        setattr(course, k, v)
    session.commit()
    session.refresh(course)
    return _course_summary(course)


@router.delete("/api/courses/{course_id}", status_code=204)
def delete_course(
    course_id: int,
    current_user: User = Depends(require_permission("playbook:delete")),
    session: Session = Depends(get_db_session),
):
    course = session.get(Course, course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    session.delete(course)
    session.commit()
    return None


@router.post("/api/courses/{course_id}/modules", status_code=201)
def create_module(
    course_id: int, body: ModuleCreate,
    current_user: User = Depends(require_permission("playbook:create")),
    session: Session = Depends(get_db_session),
):
    course = session.get(Course, course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    order = body.order if body.order is not None else _next_order(course.modules or [])
    m = CourseModule(
        course_id=course_id, order=order,
        title=body.title, description_md=body.description_md or "",
        estimated_minutes=body.estimated_minutes,
    )
    session.add(m)
    session.commit()
    session.refresh(m)
    return {"id": m.id, "course_id": course_id, "order": m.order, "title": m.title}


@router.put("/api/modules/{module_id}")
def update_module(
    module_id: int, body: ModulePatch,
    current_user: User = Depends(require_permission("playbook:update")),
    session: Session = Depends(get_db_session),
):
    m = session.get(CourseModule, module_id)
    if not m:
        raise HTTPException(status_code=404, detail="Module not found")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(m, k, v)
    session.commit()
    session.refresh(m)
    return {"id": m.id, "course_id": m.course_id, "order": m.order, "title": m.title}


@router.delete("/api/modules/{module_id}", status_code=204)
def delete_module(
    module_id: int,
    current_user: User = Depends(require_permission("playbook:delete")),
    session: Session = Depends(get_db_session),
):
    m = session.get(CourseModule, module_id)
    if not m:
        raise HTTPException(status_code=404, detail="Module not found")
    session.delete(m)
    session.commit()
    return None


@router.post("/api/modules/{module_id}/lessons", status_code=201)
def create_lesson(
    module_id: int, body: LessonCreate,
    current_user: User = Depends(require_permission("playbook:create")),
    session: Session = Depends(get_db_session),
):
    module = session.get(CourseModule, module_id)
    if not module:
        raise HTTPException(status_code=404, detail="Module not found")
    if body.lesson_type not in {"reading", "quiz", "lab"}:
        raise HTTPException(status_code=400, detail="lesson_type must be reading|quiz|lab")
    order = body.order if body.order is not None else _next_order(module.lessons or [])
    l = Lesson(
        module_id=module_id, order=order, title=body.title,
        lesson_type=body.lesson_type, content_md=body.content_md,
        duration_min=body.duration_min, lab_target_url=body.lab_target_url,
    )
    session.add(l)
    session.commit()
    session.refresh(l)
    return {"id": l.id, "module_id": module_id, "order": l.order, "title": l.title, "lesson_type": l.lesson_type}


@router.put("/api/lessons/{lesson_id}")
def update_lesson_metadata(
    lesson_id: int, body: LessonPatch,
    current_user: User = Depends(require_permission("playbook:update")),
    session: Session = Depends(get_db_session),
):
    l = session.get(Lesson, lesson_id)
    if not l:
        raise HTTPException(status_code=404, detail="Lesson not found")
    data = body.model_dump(exclude_unset=True)
    if "lesson_type" in data and data["lesson_type"] not in {"reading", "quiz", "lab"}:
        raise HTTPException(status_code=400, detail="lesson_type must be reading|quiz|lab")
    for k, v in data.items():
        setattr(l, k, v)
    session.commit()
    session.refresh(l)
    return {"id": l.id, "module_id": l.module_id, "order": l.order, "title": l.title, "lesson_type": l.lesson_type}


@router.delete("/api/lessons/{lesson_id}", status_code=204)
def delete_lesson(
    lesson_id: int,
    current_user: User = Depends(require_permission("playbook:delete")),
    session: Session = Depends(get_db_session),
):
    l = session.get(Lesson, lesson_id)
    if not l:
        raise HTTPException(status_code=404, detail="Lesson not found")
    session.delete(l)
    session.commit()
    return None


@router.post("/api/lessons/{lesson_id}/questions", status_code=201)
def create_question(
    lesson_id: int, body: QuestionCreate,
    current_user: User = Depends(require_permission("playbook:create")),
    session: Session = Depends(get_db_session),
):
    lesson = session.get(Lesson, lesson_id)
    if not lesson:
        raise HTTPException(status_code=404, detail="Lesson not found")
    if body.kind not in {"single", "multi", "truefalse", "shortanswer"}:
        raise HTTPException(status_code=400, detail="kind must be single|multi|truefalse|shortanswer")
    order = body.order if body.order is not None else _next_order(lesson.questions or [])
    q = Question(
        lesson_id=lesson_id, order=order, kind=body.kind, stem_md=body.stem_md,
        options_json=json.dumps(body.options) if body.options else None,
        correct_answer_json=json.dumps(body.correct_answer),
        explanation_md=body.explanation_md, points=body.points,
    )
    session.add(q)
    session.commit()
    session.refresh(q)
    return {"id": q.id, "lesson_id": lesson_id, "order": q.order, "kind": q.kind}


@router.put("/api/questions/{question_id}")
def update_question(
    question_id: int, body: QuestionPatch,
    current_user: User = Depends(require_permission("playbook:update")),
    session: Session = Depends(get_db_session),
):
    q = session.get(Question, question_id)
    if not q:
        raise HTTPException(status_code=404, detail="Question not found")
    data = body.model_dump(exclude_unset=True)
    # Only persist correct_answer if explicitly set (None has special meaning here)
    if "correct_answer" in data and data["correct_answer"] is not None:
        q.correct_answer_json = json.dumps(data.pop("correct_answer"))
    elif "correct_answer" in data:
        data.pop("correct_answer")
    if "options" in data:
        opts = data.pop("options")
        q.options_json = json.dumps(opts) if opts is not None else None
    if "kind" in data and data["kind"] not in {"single", "multi", "truefalse", "shortanswer"}:
        raise HTTPException(status_code=400, detail="kind invalid")
    for k, v in data.items():
        setattr(q, k, v)
    session.commit()
    session.refresh(q)
    return {"id": q.id, "lesson_id": q.lesson_id, "order": q.order, "kind": q.kind}


@router.delete("/api/questions/{question_id}", status_code=204)
def delete_question(
    question_id: int,
    current_user: User = Depends(require_permission("playbook:delete")),
    session: Session = Depends(get_db_session),
):
    q = session.get(Question, question_id)
    if not q:
        raise HTTPException(status_code=404, detail="Question not found")
    session.delete(q)
    session.commit()
    return None


# ── JSON import / export (v0.11.4) ───────────────────────────────────────


def _course_to_full_dict(course: Course) -> dict:
    """Full export payload: course + modules + lessons + questions (with answers)."""
    out = {
        "title": course.title,
        "slug": course.slug,
        "level": course.level,
        "description_md": course.description_md or "",
        "estimated_hours": course.estimated_hours,
        "pass_threshold": course.pass_threshold,
        "order_in_level": course.order_in_level,
        "published": course.published,
        "badge_image_path": course.badge_image_path,
        "skill_keys": json.loads(course.skill_keys) if course.skill_keys else None,
        "modules": [],
    }
    for m in course.modules or []:
        m_dict = {
            "title": m.title,
            "description_md": m.description_md or "",
            "estimated_minutes": m.estimated_minutes,
            "order": m.order,
            "lessons": [],
        }
        for l in m.lessons or []:
            l_dict = {
                "title": l.title,
                "lesson_type": l.lesson_type,
                "content_md": l.content_md,
                "duration_min": l.duration_min,
                "lab_target_url": l.lab_target_url,
                "order": l.order,
                "questions": [],
            }
            for q in l.questions or []:
                q_dict = {
                    "kind": q.kind,
                    "stem_md": q.stem_md,
                    "options": json.loads(q.options_json) if q.options_json else None,
                    "correct_answer": json.loads(q.correct_answer_json) if q.correct_answer_json else None,
                    "explanation_md": q.explanation_md,
                    "points": q.points,
                    "order": q.order,
                }
                l_dict["questions"].append(q_dict)
            m_dict["lessons"].append(l_dict)
        out["modules"].append(m_dict)
    return out


@router.get("/api/courses/{slug}/export")
def export_course(
    slug: str,
    current_user: User = Depends(require_permission("playbook:read")),
    session: Session = Depends(get_db_session),
):
    """Export a course as a JSON payload that can be re-imported elsewhere."""
    course = session.query(Course).filter(Course.slug == slug).one_or_none()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    return _course_to_full_dict(course)


class CourseImport(BaseModel):
    course: dict


@router.post("/api/courses/import", status_code=201)
def import_course(
    body: CourseImport,
    current_user: User = Depends(require_permission("playbook:create")),
    session: Session = Depends(get_db_session),
):
    """Import a full course JSON.

    Accepts the shape produced by ``GET /api/courses/{slug}/export``. If a
    course with the same slug already exists, returns 409 — caller must
    delete or rename first. Whole import is one transaction.
    """
    src = body.course or {}
    title = src.get("title")
    level = src.get("level")
    if not title or not level:
        raise HTTPException(status_code=400, detail="title + level are required")
    slug = src.get("slug") or _slugify(title)
    if session.query(Course).filter(Course.slug == slug).first():
        raise HTTPException(status_code=409, detail=f"Course slug '{slug}' already exists — delete or rename first")
    if level not in {"L1", "L2", "L3", "L4"}:
        raise HTTPException(status_code=400, detail="level must be L1|L2|L3|L4")

    course = Course(
        title=title, slug=slug, level=level,
        description_md=src.get("description_md", "") or "",
        estimated_hours=int(src.get("estimated_hours", 1)),
        pass_threshold=int(src.get("pass_threshold", 70)),
        order_in_level=int(src.get("order_in_level", 0)),
        published=bool(src.get("published", False)),
        badge_image_path=src.get("badge_image_path"),
        skill_keys=json.dumps(src.get("skill_keys")) if src.get("skill_keys") else None,
        author_id=current_user.id if current_user else None,
    )
    session.add(course)
    session.flush()

    for m_idx, m_src in enumerate(src.get("modules") or []):
        m = CourseModule(
            course_id=course.id,
            order=int(m_src.get("order", m_idx)),
            title=m_src.get("title", f"Module {m_idx + 1}"),
            description_md=m_src.get("description_md", "") or "",
            estimated_minutes=int(m_src.get("estimated_minutes", 30)),
        )
        session.add(m)
        session.flush()
        for l_idx, l_src in enumerate(m_src.get("lessons") or []):
            ltype = l_src.get("lesson_type", "reading")
            if ltype not in {"reading", "quiz", "lab"}:
                ltype = "reading"
            l = Lesson(
                module_id=m.id,
                order=int(l_src.get("order", l_idx)),
                title=l_src.get("title", f"Lesson {l_idx + 1}"),
                lesson_type=ltype,
                content_md=l_src.get("content_md", "") or "",
                duration_min=int(l_src.get("duration_min", 10)),
                lab_target_url=l_src.get("lab_target_url"),
            )
            session.add(l)
            session.flush()
            for q_idx, q_src in enumerate(l_src.get("questions") or []):
                kind = q_src.get("kind", "single")
                if kind not in {"single", "multi", "truefalse", "shortanswer"}:
                    kind = "single"
                q = Question(
                    lesson_id=l.id,
                    order=int(q_src.get("order", q_idx)),
                    kind=kind,
                    stem_md=q_src.get("stem_md", ""),
                    options_json=json.dumps(q_src.get("options")) if q_src.get("options") else None,
                    correct_answer_json=json.dumps(q_src.get("correct_answer")),
                    explanation_md=q_src.get("explanation_md"),
                    points=int(q_src.get("points", 1)),
                )
                session.add(q)
    session.commit()
    session.refresh(course)
    return {"id": course.id, "slug": course.slug, "imported": True}


# ── Image upload (v0.11.3) ───────────────────────────────────────────────


_ALLOWED_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif"}
_MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5 MB cap

# Static asset root inside the package so the existing /static mount serves
# course images without extra wiring. Layout:
#
#   src/ion/web/static/img/courses/<course-slug>/<unique-name>.<ext>
#
# Authors reference these in lesson markdown as:
#   ![Alt text](/static/img/courses/demo-l1-alert-triage-fundamentals/lifecycle.png)
_COURSE_IMAGES_ROOT = Path(__file__).resolve().parent / "static" / "img" / "courses"


def _safe_slug(s: str) -> str:
    """Sanitise a string so it's safe as a path component."""
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9_.-]+", "-", s)
    return s.strip("-.") or "untitled"


@router.post("/api/courses/{slug}/images")
async def upload_course_image(
    slug: str,
    file: UploadFile = File(...),
    name_override: Optional[str] = Form(None),
    current_user: User = Depends(require_permission("playbook:create")),
    session: Session = Depends(get_db_session),
):
    """Upload an image asset for a course's lessons.

    Files land under ``static/img/courses/<course-slug>/`` and are served
    by the existing ``/static`` mount. Authors paste the returned URL
    directly into lesson markdown:

        ![Lifecycle diagram](/static/img/courses/demo-l1.../lifecycle.png)

    Air-gap safe — no external CDNs, no third-party storage. Constraints:
    - Allowed extensions: png/jpg/svg/webp/gif
    - 5 MB per file
    - Author needs ``playbook:create`` permission (mirrors story authoring)
    """
    course = session.query(Course).filter(Course.slug == slug).one_or_none()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    raw_name = (name_override or file.filename or "image").strip()
    ext = Path(raw_name).suffix.lower()
    if ext not in _ALLOWED_IMAGE_EXT:
        raise HTTPException(
            status_code=400,
            detail=f"Extension {ext!r} not allowed (allowed: {sorted(_ALLOWED_IMAGE_EXT)})",
        )

    # Stem the file name (no extension) and add a random suffix so re-uploads
    # don't clobber prior files; authors get a stable URL per upload.
    stem = _safe_slug(Path(raw_name).stem)[:64] or "image"
    unique = secrets.token_urlsafe(6).replace("_", "").replace("-", "")[:8].lower()
    fname = f"{stem}-{unique}{ext}"

    course_dir = _COURSE_IMAGES_ROOT / _safe_slug(course.slug)
    course_dir.mkdir(parents=True, exist_ok=True)
    target = course_dir / fname

    # Stream + size-cap the read so a malicious giant upload doesn't OOM us.
    bytes_written = 0
    chunk_size = 1024 * 1024
    try:
        with target.open("wb") as out:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > _MAX_IMAGE_BYTES:
                    out.close()
                    target.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"Image exceeds {_MAX_IMAGE_BYTES // (1024 * 1024)} MB cap",
                    )
                out.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        # v0.19.17: was f"Upload failed: {exc}", which could leak
        # filesystem paths from PermissionError / FileNotFoundError.
        from ion.core.safe_errors import safe_error
        target.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Upload failed: {safe_error(exc, 'course_image_upload')}")

    public_url = f"/static/img/courses/{_safe_slug(course.slug)}/{fname}"
    return {
        "url": public_url,
        "bytes": bytes_written,
        "filename": fname,
        "course_slug": course.slug,
        "markdown": f"![{stem}]({public_url})",
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


# v0.13.2 — analyst's "My Courses" enrolment dashboard
# (was referenced in nav since v0.11.x but the page route + template
# were never built — fixing the gap as part of the labs ship)
@router.get("/my-courses", response_class=HTMLResponse)
def my_courses_page(request: Request, _user: User = Depends(require_page_auth)):
    return _templates.TemplateResponse(request=request, name="my_courses.html")


# v0.11.4 — admin authoring pages
@router.get("/admin/courses", response_class=HTMLResponse)
def admin_courses_page(request: Request, _user: User = Depends(require_page_auth)):
    return _templates.TemplateResponse(request=request, name="admin_courses.html")


@router.get("/admin/courses/{course_id}/edit", response_class=HTMLResponse)
def admin_course_edit_page(
    course_id: int, request: Request, _user: User = Depends(require_page_auth),
):
    return _templates.TemplateResponse(
        request=request, name="admin_course_edit.html",
        context={"course_id": course_id},
    )
