"""System Quirks — Phase 2 of the optional Detection Engineering module.

A **quirk** is a human-verified, scoped, expiring record of known-benign
behaviour in *this* estate ("the vuln scanner trips rule X every Tuesday"). It is
**advisory only**: a matching quirk annotates/deprioritises triage (a badge, a
context note, a priority nudge) — it NEVER hides, closes, or suppresses an alert.

Anti-abuse is the whole point of this model (roadmap §4). Baked in:
- **No silencing.** The quirk matcher's output only decorates the alert dict; there
  is no code path from a quirk to closing/filtering an alert. (Contrast the
  separate `KnownFalsePositive`, which *does* auto-close — quirks must never feed
  that path.)
- **Separation of duties.** A quirk is *raised* (pending) by one person and must be
  *verified* by a DIFFERENT person before it has any effect. Enforced in the
  service (`verified_by_id != raised_by_id`) regardless of permissions held.
- **Scoped blast radius.** Bound to specific rules/entities — at least one scope is
  required; a global/wildcard quirk is rejected.
- **Mandatory expiry.** Every quirk carries a `review_date`; a past-review quirk is
  inert on read (on-read expiry — no background worker, cannot suppress).
- **Full audit + revert.** raised/verified/reverted attribution on the row plus an
  append-only AuditLog trail; one-click revert.

States: ``pending`` → ``active`` (on verify) → ``reverted`` (revoked). "Lapsed" is
computed on read (active AND ``review_date`` in the past), never a stored effect.
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


class SystemQuirkStatus(str, Enum):
    """Lifecycle of a system quirk (lapsed is computed on-read, not stored)."""

    PENDING = "pending"   # raised, awaiting a different person's verification
    ACTIVE = "active"     # verified — advisory annotation is live (until review_date)
    REVERTED = "reverted"  # revoked; no effect


class SystemQuirk(Base, TimestampMixin):
    """Advisory, scoped, expiring known-benign annotation for triage."""

    __tablename__ = "system_quirks"
    __table_args__ = (
        Index("ix_system_quirks_status", "status"),
        Index("ix_system_quirks_review_date", "review_date"),
        Index("ix_system_quirks_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)

    # Scope — at least one must be non-empty (enforced in the service; no wildcards).
    scope_rules: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    scope_hosts: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    scope_users: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    scope_ips: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    # [{type, value}] — e.g. {"type":"domain","value":"updates.vendor.com"}
    scope_observables: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Advisory effect — a context note + a (display-only) priority nudge. Never hides.
    annotation: Mapped[str] = mapped_column(Text, nullable=False)
    priority_nudge: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[str] = mapped_column(
        SQLEnum(SystemQuirkStatus, native_enum=False),
        default=SystemQuirkStatus.PENDING,
        nullable=False,
    )
    # Mandatory expiry — a past review_date makes the quirk inert on read.
    review_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # Attribution — separation of duties: raised_by ≠ verified_by (service-enforced).
    raised_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    verified_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    reverted_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    reverted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    revert_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    raised_by = relationship("User", foreign_keys=[raised_by_id])
    verified_by = relationship("User", foreign_keys=[verified_by_id])
    reverted_by = relationship("User", foreign_keys=[reverted_by_id])

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        from datetime import timezone
        ref = now or datetime.now(timezone.utc).replace(tzinfo=None)
        return self.review_date is not None and self.review_date <= ref

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "scope_rules": self.scope_rules or [],
            "scope_hosts": self.scope_hosts or [],
            "scope_users": self.scope_users or [],
            "scope_ips": self.scope_ips or [],
            "scope_observables": self.scope_observables or [],
            "annotation": self.annotation,
            "priority_nudge": self.priority_nudge,
            "justification": self.justification,
            "status": self.status,
            "expired": self.is_expired(),
            "review_date": self.review_date.isoformat() if self.review_date else None,
            "raised_by_id": self.raised_by_id,
            "raised_by_username": self.raised_by.username if self.raised_by else None,
            "verified_by_id": self.verified_by_id,
            "verified_by_username": self.verified_by.username if self.verified_by else None,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "reverted_by_id": self.reverted_by_id,
            "reverted_by_username": self.reverted_by.username if self.reverted_by else None,
            "reverted_at": self.reverted_at.isoformat() if self.reverted_at else None,
            "revert_reason": self.revert_reason,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
