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

from ion.models.base import Base, TimestampMixin


class AlertTriageStatus(str, Enum):
    """Triage status for ES alerts — mirrors Elasticsearch workflow statuses."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


class AlertCaseStatus(str, Enum):
    """Status for investigation cases — mirrors Elasticsearch workflow statuses."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


class CaseClosureReason(str, Enum):
    """Reason for closing an investigation case."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_TRUE_POSITIVE = "benign_true_positive"
    DUPLICATE = "duplicate"
    INSUFFICIENT_DATA = "insufficient_data"
    NOT_APPLICABLE = "not_applicable"


class NoteEntityType(str, Enum):
    """Entity types that can have notes attached."""

    ALERT = "alert"
    CASE = "case"


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

    # DFIR-IRIS integration
    dfir_iris_case_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Closure metadata
    closure_reason: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    closure_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    closed_by_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    created_by: Mapped["User"] = relationship(
        "User", foreign_keys=[created_by_id]
    )
    assigned_to: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[assigned_to_id]
    )
    closed_by: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[closed_by_id]
    )
    triage_entries: Mapped[List["AlertTriage"]] = relationship(
        "AlertTriage", back_populates="case"
    )

    @property
    def notes(self) -> List["Note"]:
        """Get notes for this case (compatibility property)."""
        from sqlalchemy.orm import joinedload
        from ion.storage.database import get_session_factory
        session_factory = get_session_factory()
        with session_factory() as session:
            return session.query(Note).options(
                joinedload(Note.user)
            ).filter(
                Note.entity_type == NoteEntityType.CASE,
                Note.entity_id == str(self.id)
            ).order_by(Note.created_at).all()

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


class Note(Base):
    """Unified note/comment model for alerts and cases."""

    __tablename__ = "notes"
    __table_args__ = (
        Index("ix_notes_entity", "entity_type", "entity_id"),
        Index("ix_notes_user_id", "user_id"),
        Index("ix_notes_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entity_type: Mapped[str] = mapped_column(
        SQLEnum(NoteEntityType), nullable=False
    )
    entity_id: Mapped[str] = mapped_column(String(500), nullable=False)  # es_alert_id or case_id as string
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    # Relationships
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])

    # Convenience properties for backward compatibility
    @property
    def es_alert_id(self) -> Optional[str]:
        """Get alert ID if this is an alert note."""
        return self.entity_id if self.entity_type == NoteEntityType.ALERT else None

    @property
    def case_id(self) -> Optional[int]:
        """Get case ID if this is a case note."""
        return int(self.entity_id) if self.entity_type == NoteEntityType.CASE else None

    def __repr__(self) -> str:
        return f"<Note(id={self.id}, entity_type='{self.entity_type}', entity_id='{self.entity_id}')>"


class KnownFalsePositive(Base, TimestampMixin):
    """Registry of known false positive patterns for quick case resolution."""

    __tablename__ = "known_false_positives"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Matching criteria (any match = suggestion)
    match_hosts: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    match_users: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    match_ips: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    match_rules: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    source_case_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("alert_cases.id"), nullable=True
    )
    created_by_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )

    # Relationships
    created_by: Mapped["User"] = relationship("User", foreign_keys=[created_by_id])
    source_case: Mapped[Optional["AlertCase"]] = relationship("AlertCase")

    def __repr__(self) -> str:
        return f"<KnownFalsePositive(id={self.id}, title='{self.title}')>"


# Backward compatibility aliases
AlertComment = Note
CaseNote = Note
