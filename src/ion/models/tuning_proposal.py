"""Detection-engineering tuning proposals.

Captured from Bob's false-positive verdicts that include a concrete
``tuning_recommendation.suggested_change``. A detection engineer reviews
pending proposals and accepts / rejects / marks-duplicate. Accepted ones
feed into the rule-tuning backlog.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import (
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base, TimestampMixin


class TuningProposalStatus(str, Enum):
    """Lifecycle of a tuning proposal."""

    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"


class TuningProposal(Base, TimestampMixin):
    """Bob-suggested rule tuning — reviewed by detection engineering."""

    __tablename__ = "tuning_proposals"
    __table_args__ = (
        Index("ix_tuning_proposals_status", "status"),
        Index("ix_tuning_proposals_rule_id", "rule_id"),
        Index("ix_tuning_proposals_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("investigations.id"), nullable=True
    )
    alert_id: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    alert_prompt_template_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("alert_prompt_templates.id"), nullable=True
    )

    rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    suggested_change: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[str] = mapped_column(
        SQLEnum(TuningProposalStatus, native_enum=False),
        default=TuningProposalStatus.PENDING,
        nullable=False,
    )
    reviewed_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    review_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Attribution — usually Bob's user id
    created_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    reviewed_by = relationship("User", foreign_keys=[reviewed_by_id])
    created_by = relationship("User", foreign_keys=[created_by_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "alert_prompt_template_id": self.alert_prompt_template_id,
            "rationale": self.rationale,
            "suggested_change": self.suggested_change,
            "status": self.status,
            "reviewed_by_id": self.reviewed_by_id,
            "reviewed_by_username": (
                self.reviewed_by.username if self.reviewed_by else None
            ),
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "review_notes": self.review_notes,
            "created_by_id": self.created_by_id,
            "created_by_username": (
                self.created_by.username if self.created_by else None
            ),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
