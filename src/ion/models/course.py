"""Training course models — L1/L2/L3/L4 SOC analyst training subsystem (v0.11.2).

Distinct from `TrainingPlan` (which tracks external certs like CompTIA/SANS).
Courses are interactive, in-app curriculum: modules → lessons → quizzes,
with per-user progress tracking and badge/certificate awards on completion.

Hierarchy:

    Course (level=L1|L2|L3|L4)
      └─ CourseModule (ordered)
           └─ Lesson (lesson_type=reading|quiz|lab)
                └─ Question (kind=single|multi|truefalse|shortanswer)

Per-user state:

    UserEnrolment       (one per (user_id, course_id))
    UserLessonProgress  (one per (user_id, lesson_id))
    UserAnswer          (one per quiz attempt — multiple per question allowed)

A user's score on a quiz lesson is the sum of points earned on the most
recent attempt; the `UserLessonProgress.score` column caches that for
catalog/dashboard rendering. A course is "completed" when every lesson
is `completed` AND every quiz lesson scored ≥ pass_threshold.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from sqlalchemy import (
    Boolean, DateTime, Enum as SQLEnum, ForeignKey, Index, Integer,
    String, Text, UniqueConstraint, func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base


class CourseLevel(str, Enum):
    """Training tier — maps to SOC career ladder."""
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    L4 = "L4"


class LessonType(str, Enum):
    READING = "reading"        # markdown content, no questions, completed by viewing
    QUIZ = "quiz"              # markdown intro + question bank, completed by passing
    LAB = "lab"                # hands-on link into ION, with verification questions


class QuestionKind(str, Enum):
    SINGLE = "single"            # exactly one correct option
    MULTI = "multi"              # multiple correct options; partial-credit scoring
    TRUEFALSE = "truefalse"      # special case of single with "true"/"false" options
    SHORTANSWER = "shortanswer"  # free text, exact-match (case-insensitive) against answer set


class LessonProgressStatus(str, Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"            # quiz attempted but score below pass_threshold


class Course(Base):
    """A training course at a specific tier (L1/L2/L3/L4)."""

    __tablename__ = "courses"
    __table_args__ = (
        Index("ix_courses_level", "level"),
        Index("ix_courses_published", "published"),
        Index("ix_courses_slug", "slug", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), nullable=False)  # URL-safe, unique
    level: Mapped[str] = mapped_column(
        SQLEnum(CourseLevel, native_enum=False), nullable=False
    )
    description_md: Mapped[str] = mapped_column(Text, nullable=False, default="")
    estimated_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    badge_image_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    # Optional prerequisite — UI can lock the course until the prereq is
    # completed. Self-referential FK so existing v0 courses stay valid.
    prerequisite_course_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("courses.id", ondelete="SET NULL"), nullable=True
    )
    order_in_level: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    pass_threshold: Mapped[int] = mapped_column(
        Integer, nullable=False, default=70
    )  # percent — quiz lessons need ≥ this to be marked completed
    published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    skill_keys: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # JSON array — skills bumped on course completion (links to SkillAssessment.skill_key)
    author_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    modules: Mapped[List["CourseModule"]] = relationship(
        "CourseModule", back_populates="course", cascade="all, delete-orphan",
        order_by="CourseModule.order",
    )

    def __repr__(self) -> str:
        return f"<Course(id={self.id}, level={self.level}, title='{self.title}')>"


class CourseModule(Base):
    """One module within a Course — a coherent topic unit."""

    __tablename__ = "course_modules"
    __table_args__ = (
        Index("ix_course_modules_course", "course_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    course_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("courses.id", ondelete="CASCADE"), nullable=False
    )
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description_md: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    estimated_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=30)

    course: Mapped["Course"] = relationship("Course", back_populates="modules")
    lessons: Mapped[List["Lesson"]] = relationship(
        "Lesson", back_populates="module", cascade="all, delete-orphan",
        order_by="Lesson.order",
    )

    def __repr__(self) -> str:
        return f"<CourseModule(id={self.id}, course_id={self.course_id}, title='{self.title}')>"


class Lesson(Base):
    """One lesson within a Module."""

    __tablename__ = "lessons"
    __table_args__ = (
        Index("ix_lessons_module", "module_id"),
        Index("ix_lessons_type", "lesson_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    module_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("course_modules.id", ondelete="CASCADE"), nullable=False
    )
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    lesson_type: Mapped[str] = mapped_column(
        SQLEnum(LessonType, native_enum=False), nullable=False, default=LessonType.READING
    )
    # Markdown body. For READING lessons this is the entire content. For
    # QUIZ lessons it's the introductory framing before the question bank.
    # For LAB lessons it includes the task description + a link into ION.
    content_md: Mapped[str] = mapped_column(Text, nullable=False, default="")
    duration_min: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    # Optional ION URL the LAB lesson directs the analyst to. The lesson
    # then asks verification questions about what they did/saw.
    lab_target_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    module: Mapped["CourseModule"] = relationship("CourseModule", back_populates="lessons")
    questions: Mapped[List["Question"]] = relationship(
        "Question", back_populates="lesson", cascade="all, delete-orphan",
        order_by="Question.order",
    )

    def __repr__(self) -> str:
        return f"<Lesson(id={self.id}, module_id={self.module_id}, type={self.lesson_type}, title='{self.title}')>"


class Question(Base):
    """A quiz question on a Lesson."""

    __tablename__ = "course_questions"
    __table_args__ = (
        Index("ix_course_questions_lesson", "lesson_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lesson_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("lessons.id", ondelete="CASCADE"), nullable=False
    )
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    kind: Mapped[str] = mapped_column(
        SQLEnum(QuestionKind, native_enum=False), nullable=False, default=QuestionKind.SINGLE
    )
    stem_md: Mapped[str] = mapped_column(Text, nullable=False)
    # JSON-serialised: list[{value: str, label: str}] for single/multi/truefalse;
    # null for shortanswer.
    options_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # JSON-serialised correct answer:
    #   single/truefalse → string (the correct option's value)
    #   multi            → list[str] (all correct option values)
    #   shortanswer      → list[str] (acceptable case-insensitive answers)
    correct_answer_json: Mapped[str] = mapped_column(Text, nullable=False)
    explanation_md: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    points: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    lesson: Mapped["Lesson"] = relationship("Lesson", back_populates="questions")

    def __repr__(self) -> str:
        return f"<Question(id={self.id}, lesson_id={self.lesson_id}, kind={self.kind})>"


class UserEnrolment(Base):
    """A user's enrolment in a Course."""

    __tablename__ = "course_enrolments"
    __table_args__ = (
        UniqueConstraint("user_id", "course_id", name="uq_course_enrolment_user_course"),
        Index("ix_course_enrolments_user", "user_id"),
        Index("ix_course_enrolments_course", "course_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    course_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("courses.id", ondelete="CASCADE"), nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    badge_earned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # URL of generated PDF certificate (v0.11.7+). Nullable until then.
    certificate_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    # Aggregate score across all quiz lessons (percent). Caches expensive
    # rollup so the catalog can sort by score without touching UserAnswer.
    score_pct: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    def __repr__(self) -> str:
        return f"<UserEnrolment(user={self.user_id}, course={self.course_id}, completed={self.completed_at is not None})>"


class UserLessonProgress(Base):
    """A user's progress on a single Lesson."""

    __tablename__ = "course_lesson_progress"
    __table_args__ = (
        UniqueConstraint("user_id", "lesson_id", name="uq_lesson_progress_user_lesson"),
        Index("ix_lesson_progress_user", "user_id"),
        Index("ix_lesson_progress_lesson", "lesson_id"),
        Index("ix_lesson_progress_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    lesson_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("lessons.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        SQLEnum(LessonProgressStatus, native_enum=False),
        nullable=False, default=LessonProgressStatus.NOT_STARTED,
    )
    # For QUIZ/LAB lessons — most-recent attempt's score in percent (0-100).
    score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_accessed_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<UserLessonProgress(user={self.user_id}, lesson={self.lesson_id}, status={self.status})>"


class UserAnswer(Base):
    """A user's answer to a Question on a specific quiz attempt.

    Multiple rows per question are expected — re-attempts keep history.
    The latest attempt's rows drive UserLessonProgress.score.
    """

    __tablename__ = "course_user_answers"
    __table_args__ = (
        Index("ix_course_user_answers_user_question", "user_id", "question_id"),
        Index("ix_course_user_answers_attempt", "attempt_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    question_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("course_questions.id", ondelete="CASCADE"), nullable=False
    )
    # Attempt id is opaque — generated server-side per quiz submit. Groups
    # all answers for one quiz round together so we can replay attempts.
    attempt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # JSON-serialised answer in the same shape as Question.correct_answer_json
    # for the question's kind. Single/truefalse → string; multi → list;
    # shortanswer → string.
    answer_json: Mapped[str] = mapped_column(Text, nullable=False)
    is_correct: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    points_earned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<UserAnswer(user={self.user_id}, question={self.question_id}, correct={self.is_correct})>"
