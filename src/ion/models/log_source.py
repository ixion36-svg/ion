"""Log source health monitor models.

A *log source* is anything that ingests events into the SIEM (Sysmon agents,
Windows event forwarders, firewall syslog, EDR appliances, cloud audit feeds,
etc.). The health monitor compares each source's expected ingestion baseline
against the most recent event timestamp in Elasticsearch and flags sources
that have gone silent — these are detection blind spots.
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


class LogSourceCategory(str, Enum):
    """Top-level categories for log sources."""

    ENDPOINT = "endpoint"          # EDR, AV, Sysmon
    NETWORK = "network"            # firewall, IDS, proxy, DNS
    IDENTITY = "identity"          # AD, Okta, IdP
    CLOUD = "cloud"                # AWS, Azure, GCP audit
    APPLICATION = "application"    # web app, custom app logs
    OS = "os"                      # Windows event log, syslog
    OTHER = "other"


class LogSource(Base, TimestampMixin):
    """A log source ION expects to see events from."""

    __tablename__ = "log_sources"
    __table_args__ = (
        Index("ix_log_sources_category", "category"),
        Index("ix_log_sources_enabled", "enabled"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # The Elasticsearch query that selects this source's documents.
    # Stored as JSON so we can support either:
    #   {"match_field": "agent.type", "match_value": "winlogbeat"}
    # or a raw bool query:
    #   {"raw": {"bool": {...}}}
    query: Mapped[dict] = mapped_column(JSON, nullable=False)

    # Index pattern (overrides the default ES alert index pattern). Optional.
    index_pattern: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # The expected event cadence in minutes. If we haven't seen an event in
    # this window, the source is "silent". e.g. 60 = expect at least one event
    # per hour. Lower bound for status calculation.
    expected_interval_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=60
    )

    # Severity tier for prioritization on the dashboard.
    criticality: Mapped[str] = mapped_column(
        String(20), nullable=False, default="medium"
    )

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    owner: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    created_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    # Cached snapshot of the most recent ES check (refreshed by the API).
    last_event_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_event_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    last_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    created_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[created_by_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "query": self.query,
            "index_pattern": self.index_pattern,
            "expected_interval_minutes": self.expected_interval_minutes,
            "criticality": self.criticality,
            "enabled": self.enabled,
            "owner": self.owner,
            "tags": self.tags or [],
            "created_by_id": self.created_by_id,
            "last_event_at": self.last_event_at.isoformat() if self.last_event_at else None,
            "last_checked_at": self.last_checked_at.isoformat() if self.last_checked_at else None,
            "last_event_count": self.last_event_count,
            "last_status": self.last_status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
