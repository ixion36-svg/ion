"""Detection Proposals — Phase 1 of the optional Detection Engineering module.

A **reviewable draft** of a detection tuning change (exclusion / threshold /
new-rule / retire) born from a Phase-0 Noise Campaign. It is an *artifact*, never
a deployed change: ION records the draft and the human's decision, and the human
applies it in their own detection backend. ION never writes to a detection
backend (roadmap: *ION drafts and measures; the analyst decides and acts*).

Lifecycle: **draft → applied | rejected** (one-shot decision, cloned from the
`tuning_proposals` review pattern). Once *applied*, the outcome is measured by
re-running the Phase-0 noise metric for the rule before vs after `applied_at`,
proving (or disproving) the drop — stored in `outcome_json`.

Campaigns are computed on-read (no PK), so a proposal **snapshots the campaign by
value** in `campaign_snapshot` (rule_name + metrics) at draft time.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
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


class DetectionProposalStatus(str, Enum):
    """Lifecycle of a detection proposal."""

    DRAFT = "draft"
    APPLIED = "applied"
    REJECTED = "rejected"
    # carried over from the retired TuningProposalStatus so a reviewer
    # can still triage a proposal as a duplicate of one already filed.
    DUPLICATE = "duplicate"


class DetectionProposalChangeType(str, Enum):
    """The kind of detection change a proposal describes."""

    EXCLUSION = "exclusion"       # add a benign-trigger exception
    THRESHOLD = "threshold"       # raise a count/rate threshold
    NEW_RULE = "new_rule"         # add a narrower/replacement rule
    RETIRE = "retire"             # retire or disable the rule
    OTHER = "other"


class DetectionProposalSource(str, Enum):
    """Who authored the proposal.

    v0.72.0: the retired ``TuningProposal`` pipeline had Bob writing proposals
    unattended off a false-positive verdict. That provenance matters on review —
    a human drafted from a noise campaign is a different artifact from one Bob
    inferred from a single alert — so it is recorded rather than flattened.
    """

    HUMAN = "human"
    BOB = "bob"


class DetectionProposal(Base, TimestampMixin):
    """A human-owned, reviewable draft of a detection tuning change."""

    __tablename__ = "detection_proposals"
    __table_args__ = (
        Index("ix_detection_proposals_status", "status"),
        Index("ix_detection_proposals_rule_name", "rule_name"),
        Index("ix_detection_proposals_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Which campaign/rule this addresses (the DE campaign natural key).
    rule_name: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    change_type: Mapped[str] = mapped_column(
        SQLEnum(DetectionProposalChangeType, native_enum=False),
        default=DetectionProposalChangeType.EXCLUSION,
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    # The human-applicable change (backend-agnostic in Phase 1).
    suggested_change: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Explicit blast radius (host / account / signature) — keeps scope visible.
    scope: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Snapshot of the campaign at draft time (computed-on-read has no PK to FK).
    expected_fp_reduction: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    expected_hours_reclaimed: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    campaign_snapshot: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    mitre_techniques: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    status: Mapped[str] = mapped_column(
        SQLEnum(DetectionProposalStatus, native_enum=False),
        default=DetectionProposalStatus.DRAFT,
        nullable=False,
    )

    created_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    # absorbed from the retired TuningProposal model so Bob's
    # per-alert tuning recommendations have somewhere to land. A campaign-driven
    # proposal leaves all three NULL.
    source: Mapped[str] = mapped_column(
        SQLEnum(DetectionProposalSource, native_enum=False),
        default=DetectionProposalSource.HUMAN,
        nullable=False,
    )
    alert_id: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    investigation_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("investigations.id"), nullable=True
    )
    # Set when a row was carried over from the legacy tuning_proposals table;
    # makes the one-time backfill idempotent and keeps the audit trail.
    legacy_tuning_proposal_id: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True, index=True
    )
    # Decision record (one-shot: who marked it applied/rejected, when, why).
    decided_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    decision_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # When the human applied it in their backend — anchors outcome measurement.
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # Measured noise drop after applied (before/after FP counts, realized drop).
    outcome_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    created_by = relationship("User", foreign_keys=[created_by_id])
    decided_by = relationship("User", foreign_keys=[decided_by_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "change_type": self.change_type,
            "title": self.title,
            "suggested_change": self.suggested_change,
            "rationale": self.rationale,
            "scope": self.scope,
            "expected_fp_reduction": self.expected_fp_reduction,
            "expected_hours_reclaimed": self.expected_hours_reclaimed,
            "campaign_snapshot": self.campaign_snapshot,
            "mitre_techniques": self.mitre_techniques or [],
            "status": self.status,
            # provenance absorbed from the retired TuningProposal.
            # Exposed so a reviewer can tell a Bob-authored draft (inferred from
            # a single alert, unattended) from one a human drafted off a noise
            # campaign, and so the /de-proposals source filter has something to
            # render.
            "source": self.source,
            "alert_id": self.alert_id,
            "investigation_id": self.investigation_id,
            "legacy_tuning_proposal_id": self.legacy_tuning_proposal_id,
            "created_by_id": self.created_by_id,
            "created_by_username": self.created_by.username if self.created_by else None,
            "decided_by_id": self.decided_by_id,
            "decided_by_username": self.decided_by.username if self.decided_by else None,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "decision_notes": self.decision_notes,
            "applied_at": self.applied_at.isoformat() if self.applied_at else None,
            "outcome": self.outcome_json,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
