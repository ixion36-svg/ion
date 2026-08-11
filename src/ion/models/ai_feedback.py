"""AIFeedback ledger — captures Bob's verdict vs human verdict on case close.

Foundation for Tier-1 "training" — per-template agreement metrics and
tuning-engineering feedback. A row is written at case-close time for each
alert in the case that had both (a) an Investigation with a suggested
verdict and (b) a human-set closure reason. No UI feedback loop needed —
the scorecard reads straight out of this ledger.
"""

from typing import Optional

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base, TimestampMixin


class AIFeedback(Base, TimestampMixin):
    """One row per (alert, case-close) event comparing Bob to the human."""

    __tablename__ = "ai_feedback"
    __table_args__ = (
        Index("ix_ai_feedback_template", "alert_prompt_template_id"),
        Index("ix_ai_feedback_agreement", "agreement"),
        Index("ix_ai_feedback_created_at", "created_at"),
        # supports the detection-health dedup GROUP BY
        # (MAX(id) per alert_id, template) over the lookback window.
        Index("ix_ai_feedback_alert_template", "alert_id", "alert_prompt_template_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("investigations.id"), nullable=True
    )
    case_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("alert_cases.id"), nullable=True
    )
    alert_id: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    alert_prompt_template_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("alert_prompt_templates.id"), nullable=True
    )

    # What Bob said
    bob_suggested_verdict: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    bob_confidence: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # What the human ultimately closed it as (CaseClosureReason)
    human_verdict: Mapped[str] = mapped_column(String(50), nullable=False)
    human_closed_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    # Derived agreement flag — null when Bob had no suggestion
    agreement: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    # Optional free-text delta reason supplied by the closer
    delta_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # numeric confidence score (0-100) alongside the legacy string tier
    bob_confidence_int: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # True when circuit breaker fired — Bob's confidence was below threshold so
    # no verdict was written to triage; a human must resolve this alert manually.
    auto_escalated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )
    # True when Bob's confidence-gated escalation "deep pass" ran for
    # this alert before the verdict/abstention was recorded (Attack Path Phase 4).
    escalation_attempted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )

    human_closed_by = relationship("User", foreign_keys=[human_closed_by_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "case_id": self.case_id,
            "alert_id": self.alert_id,
            "alert_prompt_template_id": self.alert_prompt_template_id,
            "bob_suggested_verdict": self.bob_suggested_verdict,
            "bob_confidence": self.bob_confidence,
            "human_verdict": self.human_verdict,
            "human_closed_by_id": self.human_closed_by_id,
            "human_closed_by_username": (
                self.human_closed_by.username if self.human_closed_by else None
            ),
            "agreement": self.agreement,
            "delta_reason": self.delta_reason,
            "bob_confidence_int": self.bob_confidence_int,
            "auto_escalated": self.auto_escalated,
            "escalation_attempted": self.escalation_attempted,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
