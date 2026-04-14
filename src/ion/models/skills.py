"""Skills assessment, SOC-CMM alignment, team schedule, and training plan models."""

from datetime import date, datetime
from typing import Optional

from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from ion.models.base import Base, TimestampMixin


class AssessmentReviewCycle(Base, TimestampMixin):
    """Tracks when a user last submitted their self-assessment and when the next review is due."""

    __tablename__ = "assessment_review_cycles"
    __table_args__ = (
        UniqueConstraint("user_id", name="uq_review_cycle_user"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    submitted_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    next_review_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    is_locked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class SkillAssessment(Base, TimestampMixin):
    """User self-assessment rating for a specific skill."""

    __tablename__ = "skill_assessments"
    __table_args__ = (
        UniqueConstraint("user_id", "skill_key", name="uq_user_skill"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    skill_key: Mapped[str] = mapped_column(String(100), nullable=False)
    rating: Mapped[int] = mapped_column(Integer, nullable=False)  # 1-5
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class UserCareerGoal(Base, TimestampMixin):
    """User's current and target role for training forecast."""

    __tablename__ = "user_career_goals"
    __table_args__ = (
        UniqueConstraint("user_id", name="uq_user_career_goal"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    current_role: Mapped[str] = mapped_column(String(100), nullable=False)
    target_role: Mapped[str] = mapped_column(String(100), nullable=False)


class AssessmentSnapshot(Base):
    """Daily aggregate snapshot of team skill proficiency."""

    __tablename__ = "assessment_snapshots"
    __table_args__ = (
        UniqueConstraint("snapshot_date", "skill_key", name="uq_snapshot_date_skill"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    skill_key: Mapped[str] = mapped_column(String(100), nullable=False)
    avg_proficiency: Mapped[float] = mapped_column(Float, nullable=False)
    num_assessors: Mapped[int] = mapped_column(Integer, nullable=False)
    coverage_count: Mapped[int] = mapped_column(Integer, nullable=False)  # users >= 3
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )


class TeamScheduleEntry(Base, TimestampMixin):
    """Team member daily schedule / availability entry."""

    __tablename__ = "team_schedule"
    __table_args__ = (
        UniqueConstraint("user_id", "date", name="uq_schedule_user_date"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # working, leave, sick, training, off
    shift: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # day, night, early, late
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class TeamCertification(Base, TimestampMixin):
    """Team member certification / qualification record (SOC-CMM Training & Education)."""

    __tablename__ = "team_certifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    cert_name: Mapped[str] = mapped_column(String(150), nullable=False)  # e.g. CISSP, CEH, GCIA
    issuing_body: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)  # e.g. ISC2, EC-Council, GIAC
    obtained_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    expiry_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")  # active, expired, planned
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class SOCCMMAssessment(Base, TimestampMixin):
    """SOC-CMM People Domain maturity assessment (5 aspects, 0-5 scale)."""

    __tablename__ = "soc_cmm_assessments"
    __table_args__ = (
        UniqueConstraint("aspect", name="uq_cmm_aspect"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    aspect: Mapped[str] = mapped_column(String(50), nullable=False)  # employees, roles, people_mgmt, knowledge_mgmt, training
    rating: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # 0-5 SOC-CMM maturity
    target_rating: Mapped[int] = mapped_column(Integer, nullable=False, default=3)  # target maturity
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    assessed_by_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    assessed_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)


class TrainingPlan(Base, TimestampMixin):
    """A user's personal training plan with selected certifications and cost tracking."""

    __tablename__ = "training_plans"
    __table_args__ = (
        UniqueConstraint("user_id", "name", name="uq_user_plan_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    target_role: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")  # draft, active, completed, archived
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class TrainingPlanItem(Base, TimestampMixin):
    """Individual certification or training item within a training plan."""

    __tablename__ = "training_plan_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    plan_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    cert_name: Mapped[str] = mapped_column(String(200), nullable=False)
    provider: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    price: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    difficulty: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # beginner, intermediate, advanced, expert
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="planned")  # planned, in_progress, completed, skipped
    funding_type: Mapped[str] = mapped_column(String(20), nullable=False, default="tbd")  # company, self, split, tbd
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # ordering
    target_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class KnowledgeArticle(Base, TimestampMixin):
    """Knowledge documentation status per capability area (SOC-CMM Knowledge Management)."""

    __tablename__ = "knowledge_articles"
    __table_args__ = (
        UniqueConstraint("capability_key", name="uq_knowledge_cap"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    capability_key: Mapped[str] = mapped_column(String(100), nullable=False)  # matches SOC_CAPABILITIES key
    doc_status: Mapped[str] = mapped_column(String(20), nullable=False, default="undocumented")  # undocumented, basic, comprehensive
    has_runbooks: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    has_procedures: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    knowledge_sharing: Mapped[str] = mapped_column(String(20), nullable=False, default="siloed")  # siloed, shared, trained
    spof_risk: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)  # single point of failure
    owner_user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # knowledge domain owner
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class RoleAssessment(Base, TimestampMixin):
    """A user's self-assessment for a specific career role.

    The user picks a role (L1/L2/L3 SOC Analyst, SOC Engineer, Threat Hunter,
    etc.), answers a per-role Elastic-stack-focused questionnaire, and the
    service stores their responses + calculated per-area scores + an
    overall match percentage. History is preserved across submissions so
    progress over time is visible.
    """

    __tablename__ = "role_assessments"
    __table_args__ = (
        Index("ix_role_assessment_user_taken", "user_id", "taken_at"),
        Index("ix_role_assessment_role", "role_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    role_id: Mapped[str] = mapped_column(String(64), nullable=False)
    role_name: Mapped[str] = mapped_column(String(120), nullable=False)
    # responses: {area_id: {question_id: rating(int 1-5)}}
    responses: Mapped[dict] = mapped_column(JSON, nullable=False)
    # scores:    {area_id: {avg: float, total: int, max: int, pct: int}}
    scores: Mapped[dict] = mapped_column(JSON, nullable=False)
    overall_match_pct: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    overall_level: Mapped[str] = mapped_column(String(40), nullable=False, default="Developing")
    # Recommendations blob set at submit time:
    #   {"strengths":[area_ids], "gaps":[area_ids],
    #    "kb_articles":[{capability_key, ...}],
    #    "sim_scenarios":[{id, name, ...}], "ai_summary": "..."}
    recommendations: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    taken_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
