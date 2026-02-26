"""Skills assessment, SOC-CMM alignment, and team schedule models."""

from datetime import date, datetime
from typing import Optional

from sqlalchemy import Boolean, Date, DateTime, Float, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from ixion.models.base import Base, TimestampMixin


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
