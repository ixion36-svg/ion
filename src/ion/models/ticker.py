"""Ticker / announcement models.

A "ticker" is a short, high-visibility message shown to every ION user
until dismissed (for non-critical) or resolved (for critical). Two producers:

1. Auto — background task flags critical alerts that have sat OPEN without a
   case for longer than a threshold.
2. Manual — admins/leads post ongoing-event updates (active incident,
   maintenance window, reminders).
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
    UniqueConstraint,
)
from sqlalchemy import (
    Enum as SQLEnum,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base, TimestampMixin


class TickerKind(str, Enum):
    """What produced the ticker item — determines lifecycle semantics."""

    CRITICAL_ALERT = "critical_alert"   # auto — critical alert with no case
    MANUAL_EVENT = "manual_event"       # admin — ongoing incident / event
    MAINTENANCE = "maintenance"         # admin — planned maintenance window
    REMINDER = "reminder"               # admin — reminder / heads-up


class TickerSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class TickerSourceType(str, Enum):
    AUTO = "auto"
    MANUAL = "manual"


class Ticker(Base, TimestampMixin):
    """A ticker entry visible to all users with `ticker:read`."""

    __tablename__ = "tickers"
    __table_args__ = (
        Index("ix_tickers_kind", "kind"),
        Index("ix_tickers_severity", "severity"),
        Index("ix_tickers_resolved_at", "resolved_at"),
        Index("ix_tickers_expires_at", "expires_at"),
        # One auto ticker per (kind, source_ref) — prevents duplicates on
        # repeated producer runs.
        UniqueConstraint(
            "kind", "source_ref", name="uq_tickers_kind_source_ref"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(
        SQLEnum(TickerKind, native_enum=False), nullable=False
    )
    severity: Mapped[str] = mapped_column(
        SQLEnum(TickerSeverity, native_enum=False),
        default=TickerSeverity.INFO,
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    body: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    link_url: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)

    source_type: Mapped[str] = mapped_column(
        SQLEnum(TickerSourceType, native_enum=False),
        default=TickerSourceType.MANUAL,
        nullable=False,
    )
    # For auto tickers: reference to the underlying entity (es alert id,
    # case id, etc.). Included in the uniqueness constraint so the producer
    # is idempotent.
    source_ref: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    source_user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    source_user = relationship("User", foreign_keys=[source_user_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "severity": self.severity,
            "title": self.title,
            "body": self.body,
            "link_url": self.link_url,
            "source_type": self.source_type,
            "source_ref": self.source_ref,
            "source_user_id": self.source_user_id,
            "source_username": (
                self.source_user.username if self.source_user else None
            ),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    @property
    def is_dismissable(self) -> bool:
        """Critical tickers can't be dismissed — they resolve automatically."""
        return self.severity != TickerSeverity.CRITICAL


class TickerDismissal(Base):
    """Per-user dismissal of a non-critical ticker."""

    __tablename__ = "ticker_dismissals"
    __table_args__ = (
        Index("ix_ticker_dismissals_user", "user_id"),
    )

    ticker_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("tickers.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), primary_key=True
    )
    dismissed_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False
    )
