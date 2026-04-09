"""Post-Incident Review (PIR) models.

Each closed case can have one PIR — a structured "lessons learned" document
recording the timeline, what worked, what didn't, root cause, and resulting
improvement action items with owners and due dates.

Two tables:

- ``post_incident_reviews`` — one row per case (FK), free-form structured fields.
- ``pir_action_items``      — many-per-PIR backlog of improvements with status.
"""

from datetime import date, datetime
from enum import Enum
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from ion.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from ion.models.user import User
    from ion.models.alert_triage import AlertCase


class PIRStatus(str, Enum):
    DRAFT = "draft"
    REVIEW = "review"
    APPROVED = "approved"


class PIRActionStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    BLOCKED = "blocked"
    DROPPED = "dropped"


class PostIncidentReview(Base, TimestampMixin):
    """Lessons-learned write-up for a closed case."""

    __tablename__ = "post_incident_reviews"
    __table_args__ = (
        UniqueConstraint("case_id", name="uq_pir_case_id"),
        Index("ix_pir_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("alert_cases.id", ondelete="CASCADE"), nullable=False
    )

    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=PIRStatus.DRAFT.value
    )
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timeline: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    what_worked: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    what_didnt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    root_cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detection_gaps: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    response_gaps: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    metrics: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # Compliance evidence — list of {framework_id, control_id} this incident touched
    linked_controls: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # AI-suggested improvements (stored separately so the analyst can edit
    # the human fields without losing the suggestion).
    ai_suggestions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_generated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    created_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    approved_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    case: Mapped["AlertCase"] = relationship("AlertCase", foreign_keys=[case_id])
    created_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[created_by_id])
    approved_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[approved_by_id])

    actions: Mapped[list["PIRActionItem"]] = relationship(
        "PIRActionItem",
        back_populates="pir",
        cascade="all, delete-orphan",
        order_by="PIRActionItem.due_date.asc().nullslast()",
    )

    def to_dict(self, include_actions: bool = True) -> dict:
        out = {
            "id": self.id,
            "case_id": self.case_id,
            "status": self.status,
            "summary": self.summary,
            "timeline": self.timeline,
            "what_worked": self.what_worked,
            "what_didnt": self.what_didnt,
            "root_cause": self.root_cause,
            "detection_gaps": self.detection_gaps,
            "response_gaps": self.response_gaps,
            "metrics": self.metrics,
            "linked_controls": self.linked_controls or [],
            "ai_suggestions": self.ai_suggestions,
            "ai_generated_at": self.ai_generated_at.isoformat() if self.ai_generated_at else None,
            "created_by_id": self.created_by_id,
            "created_by_username": self.created_by.username if self.created_by else None,
            "approved_by_id": self.approved_by_id,
            "approved_by_username": self.approved_by.username if self.approved_by else None,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_actions:
            out["actions"] = [a.to_dict() for a in (self.actions or [])]
        return out


class PIRActionItem(Base, TimestampMixin):
    """An improvement action coming out of a PIR."""

    __tablename__ = "pir_action_items"
    __table_args__ = (
        Index("ix_pir_action_pir_id", "pir_id"),
        Index("ix_pir_action_status", "status"),
        Index("ix_pir_action_owner", "owner_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    pir_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("post_incident_reviews.id", ondelete="CASCADE"), nullable=False
    )

    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)
    # Free-form ("detection", "response", "training", "tooling", "process")
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=PIRActionStatus.OPEN.value
    )
    owner_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    due_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    pir: Mapped["PostIncidentReview"] = relationship("PostIncidentReview", back_populates="actions")
    owner: Mapped[Optional["User"]] = relationship("User", foreign_keys=[owner_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "pir_id": self.pir_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "priority": self.priority,
            "status": self.status,
            "owner_id": self.owner_id,
            "owner_username": self.owner.username if self.owner else None,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
