"""Service-desk models — user bug reports and CAB change requests.

Two operator-facing workflows:

* :class:`BugReport` — any authenticated user files a bug; ION opens a linked
  GitLab issue and tracks its state (open/closed) back into the local record.
* :class:`ChangeRequest` — a CAB (Change Advisory Board) record for an ION
  version upgrade, carrying the full change dataset (current→target version,
  risk, impact, implementation + backout/test plans, maintenance window) with a
  reviewed status workflow and an optional linked GitLab issue.

Both mirror the established model conventions: ``Base`` + ``TimestampMixin``
(server-side naive-UTC timestamps) and ``SQLEnum(native_enum=False)`` storing
the enum value as a string.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import (
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


# ── Bug reports ──────────────────────────────────────────────────────────────
class BugReportSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BugReportStatus(str, Enum):
    """Local lifecycle. Kept in sync with the linked GitLab issue state where
    one exists (GitLab ``opened`` → OPEN/IN_PROGRESS, ``closed`` → RESOLVED)."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class BugReport(Base, TimestampMixin):
    """A user-submitted bug, optionally mirrored to a GitLab issue."""

    __tablename__ = "bug_reports"
    __table_args__ = (
        Index("ix_bug_reports_status", "status"),
        Index("ix_bug_reports_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    steps_to_reproduce: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    component: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    severity: Mapped[str] = mapped_column(
        SQLEnum(BugReportSeverity, native_enum=False),
        default=BugReportSeverity.MEDIUM,
        nullable=False,
    )
    # Operating context captured at submit time — invaluable on a bug ticket.
    ion_version: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    page_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    status: Mapped[str] = mapped_column(
        SQLEnum(BugReportStatus, native_enum=False),
        default=BugReportStatus.OPEN,
        nullable=False,
    )

    # GitLab linkage (best-effort — null when GitLab is unconfigured/unreachable)
    gitlab_issue_iid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    gitlab_issue_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    gitlab_state: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    gitlab_synced_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    gitlab_error: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)

    reported_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    reported_by = relationship("User", foreign_keys=[reported_by_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "steps_to_reproduce": self.steps_to_reproduce,
            "component": self.component,
            "severity": self.severity,
            "ion_version": self.ion_version,
            "page_url": self.page_url,
            "status": self.status,
            "gitlab_issue_iid": self.gitlab_issue_iid,
            "gitlab_issue_url": self.gitlab_issue_url,
            "gitlab_state": self.gitlab_state,
            "gitlab_synced_at": self.gitlab_synced_at.isoformat() if self.gitlab_synced_at else None,
            "gitlab_error": self.gitlab_error,
            "reported_by_id": self.reported_by_id,
            "reported_by_username": self.reported_by.username if self.reported_by else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# ── Change requests (CAB) ────────────────────────────────────────────────────
class ChangeRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ChangeRequestStatus(str, Enum):
    """CAB lifecycle. DRAFT is editable; everything from SUBMITTED on is a
    reviewed state stamped with who/when."""

    DRAFT = "draft"
    SUBMITTED = "submitted"
    APPROVED = "approved"
    REJECTED = "rejected"
    SCHEDULED = "scheduled"
    IMPLEMENTED = "implemented"
    CLOSED = "closed"
    CANCELLED = "cancelled"


class ChangeRequest(Base, TimestampMixin):
    """A CAB change request — typically an ION version upgrade."""

    __tablename__ = "change_requests"
    __table_args__ = (
        Index("ix_change_requests_status", "status"),
        Index("ix_change_requests_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    reference: Mapped[str] = mapped_column(String(40), nullable=False, unique=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    change_type: Mapped[str] = mapped_column(String(80), default="ION version upgrade", nullable=False)

    # Version delta — current is auto-captured at create time.
    current_version: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    target_version: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)

    # CAB narrative dataset.
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    changes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # what's changing (changelog delta)
    risk_level: Mapped[str] = mapped_column(
        SQLEnum(ChangeRiskLevel, native_enum=False),
        default=ChangeRiskLevel.MEDIUM,
        nullable=False,
    )
    impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    affected_systems: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    implementation_plan: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    backout_plan: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    test_plan: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scheduled_start: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    scheduled_end: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    status: Mapped[str] = mapped_column(
        SQLEnum(ChangeRequestStatus, native_enum=False),
        default=ChangeRequestStatus.DRAFT,
        nullable=False,
    )

    # Review / decision trail.
    requested_by_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    decided_by_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    decision_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    implemented_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # GitLab linkage (best-effort).
    gitlab_issue_iid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    gitlab_issue_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    gitlab_error: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)

    requested_by = relationship("User", foreign_keys=[requested_by_id])
    decided_by = relationship("User", foreign_keys=[decided_by_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "reference": self.reference,
            "title": self.title,
            "change_type": self.change_type,
            "current_version": self.current_version,
            "target_version": self.target_version,
            "justification": self.justification,
            "changes": self.changes,
            "risk_level": self.risk_level,
            "impact": self.impact,
            "affected_systems": self.affected_systems,
            "implementation_plan": self.implementation_plan,
            "backout_plan": self.backout_plan,
            "test_plan": self.test_plan,
            "scheduled_start": self.scheduled_start.isoformat() if self.scheduled_start else None,
            "scheduled_end": self.scheduled_end.isoformat() if self.scheduled_end else None,
            "status": self.status,
            "requested_by_id": self.requested_by_id,
            "requested_by_username": self.requested_by.username if self.requested_by else None,
            "decided_by_id": self.decided_by_id,
            "decided_by_username": self.decided_by.username if self.decided_by else None,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "decision_notes": self.decision_notes,
            "implemented_at": self.implemented_at.isoformat() if self.implemented_at else None,
            "gitlab_issue_iid": self.gitlab_issue_iid,
            "gitlab_issue_url": self.gitlab_issue_url,
            "gitlab_error": self.gitlab_error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
