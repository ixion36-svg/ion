"""Alert triage, comment, and case models for SOC workflow."""

from datetime import datetime
from enum import Enum
from typing import Optional, List

from sqlalchemy import (
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ixion.models.base import Base, TimestampMixin


class AlertTriageStatus(str, Enum):
    """Triage status for ES alerts."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class AlertCaseStatus(str, Enum):
    """Status for investigation cases."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class AlertCase(Base, TimestampMixin):
    """Investigation case grouping multiple alerts."""

    __tablename__ = "alert_cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_number: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        SQLEnum(AlertCaseStatus), default=AlertCaseStatus.OPEN, nullable=False
    )
    severity: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    created_by_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    assigned_to_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    # Structured alert context
    affected_hosts: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    affected_users: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    triggered_rules: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    evidence_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_alert_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    observables: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Kibana Cases integration
    kibana_case_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    kibana_case_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Relationships
    created_by: Mapped["User"] = relationship(
        "User", foreign_keys=[created_by_id]
    )
    assigned_to: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[assigned_to_id]
    )
    triage_entries: Mapped[List["AlertTriage"]] = relationship(
        "AlertTriage", back_populates="case"
    )
    notes: Mapped[List["CaseNote"]] = relationship(
        "CaseNote", back_populates="case", order_by="CaseNote.created_at"
    )

    def __repr__(self) -> str:
        return f"<AlertCase(id={self.id}, case_number='{self.case_number}')>"


class AlertTriage(Base, TimestampMixin):
    """Local triage state per ES alert."""

    __tablename__ = "alert_triage"
    __table_args__ = (
        Index("ix_alert_triage_es_alert_id", "es_alert_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    es_alert_id: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(
        SQLEnum(AlertTriageStatus), default=AlertTriageStatus.OPEN, nullable=False
    )
    assigned_to_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    case_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("alert_cases.id"), nullable=True
    )
    priority: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    analyst_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    observables: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    mitre_techniques: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Relationships
    assigned_to: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[assigned_to_id]
    )
    case: Mapped[Optional["AlertCase"]] = relationship(
        "AlertCase", back_populates="triage_entries"
    )

    def __repr__(self) -> str:
        return f"<AlertTriage(id={self.id}, es_alert_id='{self.es_alert_id}')>"


class AlertComment(Base):
    """Comment on an ES alert."""

    __tablename__ = "alert_comments"
    __table_args__ = (
        Index("ix_alert_comments_es_alert_id", "es_alert_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    es_alert_id: Mapped[str] = mapped_column(String(500), nullable=False)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    # Relationships
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])

    def __repr__(self) -> str:
        return f"<AlertComment(id={self.id}, es_alert_id='{self.es_alert_id}')>"


class CaseNote(Base):
    """Investigation note on a case."""

    __tablename__ = "case_notes"
    __table_args__ = (
        Index("ix_case_notes_case_id", "case_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("alert_cases.id"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    # Relationships
    case: Mapped["AlertCase"] = relationship("AlertCase", back_populates="notes")
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])

    def __repr__(self) -> str:
        return f"<CaseNote(id={self.id}, case_id={self.case_id})>"
