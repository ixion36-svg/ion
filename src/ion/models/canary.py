"""Canary / Deception Tracker models.

A canary is a fake observable (file path, account name, URL, hostname, IP,
DNS name, etc.) that is intentionally planted in the environment so that an
attacker who interacts with it triggers a high-confidence breach alert.
Because real users have no reason to touch a canary, fire events have an
extremely low false-positive rate.

Two tables:

- ``canaries``     — the registry of planted canary tokens.
- ``canary_hits``  — every time ION detects an alert that touches a canary,
                     a hit row is recorded for the audit trail.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from ion.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from ion.models.user import User


class CanaryType(str, Enum):
    """The kind of decoy a canary represents.

    These map to ATT&CK / observable types so that ION's existing alert and
    observable plumbing can detect interactions without needing a new
    detection pipeline.
    """

    FILE = "file"               # decoy file path or filename
    USER = "user"               # decoy user / service account
    HOST = "host"               # decoy hostname / endpoint
    IP = "ip"                   # decoy IP address
    DOMAIN = "domain"           # decoy DNS name
    URL = "url"                 # decoy URL / web canary
    AWS_KEY = "aws_key"         # AWS access key honeytoken
    DATABASE = "database"       # decoy DB / table / column
    EMAIL = "email"             # decoy mailbox
    PROCESS = "process"         # decoy named binary
    OTHER = "other"


class CanaryStatus(str, Enum):
    """Lifecycle state of a canary."""

    ACTIVE = "active"           # planted and being monitored
    INACTIVE = "inactive"       # paused — not currently monitored
    BURNED = "burned"           # adversary aware; needs replacement
    RETIRED = "retired"         # decommissioned


class Canary(Base, TimestampMixin):
    """A planted canary token / decoy."""

    __tablename__ = "canaries"
    __table_args__ = (
        Index("ix_canaries_value", "value"),
        Index("ix_canaries_type", "canary_type"),
        Index("ix_canaries_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    canary_type: Mapped[str] = mapped_column(String(40), nullable=False)
    # The literal string an alert needs to mention to count as a hit
    # (e.g. "C:\\HR\\Salaries_2026.xlsx" or "svc_backup_old").
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=CanaryStatus.ACTIVE.value
    )
    # Where the canary lives — a free-form label so analysts know where to
    # look when it fires (e.g. "DC01 file share", "OnPrem AD", "billing DB").
    location: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # Tags / labels for filtering (campaign name, owner, intent, etc.)
    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    # If true, the canary firing should escalate to a high-confidence breach
    # alert; otherwise it is logged for analyst review.
    high_confidence: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )

    # Audit
    created_by_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    last_hit_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Relationships
    created_by: Mapped["User"] = relationship("User", foreign_keys=[created_by_id])
    hits: Mapped[list["CanaryHit"]] = relationship(
        "CanaryHit",
        back_populates="canary",
        cascade="all, delete-orphan",
        order_by="desc(CanaryHit.detected_at)",
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "canary_type": self.canary_type,
            "value": self.value,
            "description": self.description,
            "status": self.status,
            "location": self.location,
            "tags": self.tags or [],
            "high_confidence": self.high_confidence,
            "created_by_id": self.created_by_id,
            "created_by_username": self.created_by.username if self.created_by else None,
            "last_hit_at": self.last_hit_at.isoformat() if self.last_hit_at else None,
            "hit_count": self.hit_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class CanaryHit(Base):
    """An observed interaction with a canary."""

    __tablename__ = "canary_hits"
    __table_args__ = (
        Index("ix_canary_hits_canary_id", "canary_id"),
        Index("ix_canary_hits_detected_at", "detected_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    canary_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("canaries.id", ondelete="CASCADE"), nullable=False
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )
    # The Elasticsearch alert id (or other source id) that triggered the hit
    source: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    source_alert_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    actor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # Snippet of the alert message / event that mentioned the canary value
    snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    canary: Mapped["Canary"] = relationship("Canary", back_populates="hits")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "canary_id": self.canary_id,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
            "source": self.source,
            "source_alert_id": self.source_alert_id,
            "actor": self.actor,
            "host": self.host,
            "snippet": self.snippet,
        }
