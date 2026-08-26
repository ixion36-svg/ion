"""Analyst-raised tuning requests — the intake side of Detection Engineering.

A request is an analyst's ask ("this rule is noisy for us"), distinct from a
DetectionProposal (the DE's drafted change). Requests are raised from the
alert-detail workspace by any analyst (``alert:read``), tracked here AND as a
GitLab issue when the integration is configured (the DB row is authoritative;
the ticket is best-effort and back-linked). The DE team works the queue from
the DE Workbench; linking a proposal or closing a request comments the ticket.
"""

from typing import Optional

from sqlalchemy import JSON, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base, TimestampMixin

# Analyst-selectable reasons; String column (not SQLEnum) on purpose — the
# native_enum=False NAME-storage trap isn't worth five values.
TUNING_REQUEST_REASONS = ("false_positive", "noisy", "threshold", "duplicate", "other")
# open → triaged → linked (proposal drafted) → closed. Terminal: closed.
TUNING_REQUEST_STATUSES = ("open", "triaged", "linked", "closed")


class TuningRequest(Base, TimestampMixin):
    """One analyst-raised detection-tuning request."""

    __tablename__ = "tuning_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    rule_name: Mapped[str] = mapped_column(String(512), nullable=False)
    reason: Mapped[str] = mapped_column(String(32), nullable=False, default="other")
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Up to a handful of example ES alert ids the analyst had selected/open.
    example_alert_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    # Auto-collected context at submit time (fp counts, window) — snapshot by
    # value so the ticket stays meaningful after the noise moves.
    evidence_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    requested_by_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    triaged_by_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # Loose reference to detection_proposals.id once a DE drafts from this.
    proposal_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    resolution: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    gitlab_issue_iid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    gitlab_issue_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "reason": self.reason,
            "details": self.details,
            "example_alert_ids": self.example_alert_ids or [],
            "evidence_json": self.evidence_json or {},
            "status": self.status,
            "requested_by_id": self.requested_by_id,
            "triaged_by_id": self.triaged_by_id,
            "proposal_id": self.proposal_id,
            "resolution": self.resolution,
            "gitlab_issue_iid": self.gitlab_issue_iid,
            "gitlab_issue_url": self.gitlab_issue_url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
