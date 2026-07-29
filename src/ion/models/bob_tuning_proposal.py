"""Bob-tuning proposals — Phase 3 of the Detection Engineering module.

A reviewable, **versioned, reversible** edit to a detection rule's Bob prompt-stack
guidance (``AlertPromptTemplate.prompt_text``), drafted from a Bob Feedback Item
(a cluster of closures where Bob disagreed with the analyst).

Governance (roadmap §3 — "applied only after human approval, versioned, and
reversible; no silent online learning"):
- **No silent learning.** Nothing here mutates a template automatically. A human
  authors the improved guidance; another human approves it.
- **Separation of duties.** Draft requires ``de:propose``; *approve* requires the
  reserved ``de:approve`` permission AND a *different* person than the drafter.
- **Versioned + reversible.** Because ``prompt_text`` renders into Bob's prompt
  **live** (no cache), approving snapshots the template's text *before* the write
  (``before_text``) so a one-click revert restores it exactly.

States: ``draft`` → ``approved`` (applied to the template) | ``rejected`` →
``reverted`` (the applied change rolled back).
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy import (
    Enum as SQLEnum,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base, TimestampMixin


class BobTuningProposalStatus(str, Enum):
    """Lifecycle of a Bob-tuning proposal."""

    DRAFT = "draft"
    APPROVED = "approved"   # applied to the template (live)
    REJECTED = "rejected"
    REVERTED = "reverted"   # an approved change rolled back


class BobTuningProposal(Base, TimestampMixin):
    """A human-owned, approve-gated, reversible edit to a rule's Bob guidance."""

    __tablename__ = "bob_tuning_proposals"
    __table_args__ = (
        Index("ix_bob_tuning_proposals_status", "status"),
        Index("ix_bob_tuning_proposals_template_id", "template_id"),
        Index("ix_bob_tuning_proposals_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_name: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    template_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("alert_prompt_templates.id"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)

    # What the disagreement evidence was (Bob Feedback Item snapshot at draft time).
    problem_statement: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    feedback_snapshot: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # The prompt-stack text: the current guide (reference) and the proposed new one.
    current_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    proposed_text: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[str] = mapped_column(
        SQLEnum(BobTuningProposalStatus, native_enum=False),
        default=BobTuningProposalStatus.DRAFT,
        nullable=False,
    )

    created_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    # Decision record (approve/reject) — approver must differ from the drafter.
    decided_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    decision_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Versioning for reversibility: the template's text captured at apply time.
    before_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    reverted_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    reverted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    created_by = relationship("User", foreign_keys=[created_by_id])
    decided_by = relationship("User", foreign_keys=[decided_by_id])
    reverted_by = relationship("User", foreign_keys=[reverted_by_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "template_id": self.template_id,
            "title": self.title,
            "problem_statement": self.problem_statement,
            "feedback_snapshot": self.feedback_snapshot,
            "current_text": self.current_text,
            "proposed_text": self.proposed_text,
            "status": self.status,
            "created_by_id": self.created_by_id,
            "created_by_username": self.created_by.username if self.created_by else None,
            "decided_by_id": self.decided_by_id,
            "decided_by_username": self.decided_by.username if self.decided_by else None,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "decision_notes": self.decision_notes,
            "applied_at": self.applied_at.isoformat() if self.applied_at else None,
            "reverted_by_id": self.reverted_by_id,
            "reverted_by_username": self.reverted_by.username if self.reverted_by else None,
            "reverted_at": self.reverted_at.isoformat() if self.reverted_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
