"""Observable models for centralized IOC tracking.

Provides normalized storage for observables (IPs, domains, URLs, etc.) with
enrichment history, alert/case correlation, threat level tracking, and watchlist functionality.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ixion.models.base import Base, TimestampMixin


class WatchlistAlertType(str, Enum):
    """Types of watchlist alerts that can be triggered."""

    NEW_SIGHTING = "new_sighting"      # Observable seen in new alert
    THREAT_LEVEL_CHANGE = "threat_level_change"  # Threat level changed
    NEW_ENRICHMENT = "new_enrichment"  # New enrichment data available
    PATTERN_MATCH = "pattern_match"    # Observable matched a pattern


class ObservableType(str, Enum):
    """Types of observables that can be tracked."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    EMAIL = "email"
    FILE_HASH_MD5 = "md5"
    FILE_HASH_SHA1 = "sha1"
    FILE_HASH_SHA256 = "sha256"
    USER_ACCOUNT = "user_account"
    MAC_ADDRESS = "mac"
    CVE = "cve"


class ThreatLevel(str, Enum):
    """Threat level for an observable based on enrichment data."""

    UNKNOWN = "unknown"
    BENIGN = "benign"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Observable(Base, TimestampMixin):
    """Normalized observable record with enrichment and correlation tracking."""

    __tablename__ = "observables"
    __table_args__ = (
        UniqueConstraint("type", "normalized_value", name="uq_observable_type_value"),
        Index("ix_observables_type", "type"),
        Index("ix_observables_normalized_value", "normalized_value"),
        Index("ix_observables_threat_level", "threat_level"),
        Index("ix_observables_first_seen", "first_seen"),
        Index("ix_observables_last_seen", "last_seen"),
        Index("ix_observables_is_watched", "is_watched"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(
        SQLEnum(ObservableType), nullable=False
    )
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )
    sighting_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    threat_level: Mapped[str] = mapped_column(
        SQLEnum(ThreatLevel), default=ThreatLevel.UNKNOWN, nullable=False
    )
    is_whitelisted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Watchlist functionality
    is_watched: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    watch_reason: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    watched_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    watched_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Auto-enrichment settings
    auto_enrich: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_auto_enriched: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    enrichments: Mapped[List["ObservableEnrichment"]] = relationship(
        "ObservableEnrichment",
        back_populates="observable",
        order_by="desc(ObservableEnrichment.enriched_at)",
        cascade="all, delete-orphan",
    )
    alert_links: Mapped[List["ObservableAlertLink"]] = relationship(
        "ObservableAlertLink",
        back_populates="observable",
        cascade="all, delete-orphan",
    )
    case_links: Mapped[List["ObservableCaseLink"]] = relationship(
        "ObservableCaseLink",
        back_populates="observable",
        cascade="all, delete-orphan",
    )
    watchlist_alerts: Mapped[List["WatchlistAlert"]] = relationship(
        "WatchlistAlert",
        back_populates="observable",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Observable(id={self.id}, type='{self.type}', value='{self.value[:50]}...')>"

    @property
    def latest_enrichment(self) -> Optional["ObservableEnrichment"]:
        """Get the most recent enrichment record."""
        return self.enrichments[0] if self.enrichments else None

    @staticmethod
    def normalize_value(obs_type: ObservableType, value: str) -> str:
        """Normalize an observable value for consistent matching.

        Args:
            obs_type: The type of observable
            value: The raw value

        Returns:
            Normalized value suitable for comparison
        """
        if not value:
            return ""

        normalized = value.strip()

        # Type-specific normalization
        if obs_type in (ObservableType.IPV4, ObservableType.IPV6):
            # IPs: lowercase (for IPv6)
            normalized = normalized.lower()
        elif obs_type in (ObservableType.DOMAIN, ObservableType.HOSTNAME):
            # Domains/hostnames: lowercase, strip trailing dots
            normalized = normalized.lower().rstrip(".")
        elif obs_type == ObservableType.URL:
            # URLs: lowercase scheme and host
            normalized = normalized.lower()
        elif obs_type == ObservableType.EMAIL:
            # Email: lowercase
            normalized = normalized.lower()
        elif obs_type in (
            ObservableType.FILE_HASH_MD5,
            ObservableType.FILE_HASH_SHA1,
            ObservableType.FILE_HASH_SHA256,
        ):
            # Hashes: lowercase
            normalized = normalized.lower()
        elif obs_type == ObservableType.MAC_ADDRESS:
            # MAC: lowercase, normalize separators to colons
            normalized = normalized.lower().replace("-", ":").replace(".", ":")
        elif obs_type == ObservableType.USER_ACCOUNT:
            # User accounts: lowercase
            normalized = normalized.lower()
        elif obs_type == ObservableType.CVE:
            # CVE: uppercase
            normalized = normalized.upper()

        return normalized


class ObservableEnrichment(Base):
    """Enrichment data for an observable from external threat intel sources."""

    __tablename__ = "observable_enrichments"
    __table_args__ = (
        Index("ix_observable_enrichments_observable_id", "observable_id"),
        Index("ix_observable_enrichments_source", "source"),
        Index("ix_observable_enrichments_enriched_at", "enriched_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    observable_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("observables.id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    enriched_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    raw_response: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Extracted fields for quick access
    is_malicious: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    labels: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    threat_actors: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    indicators: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    reports: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Relationship
    observable: Mapped["Observable"] = relationship(
        "Observable", back_populates="enrichments"
    )

    def __repr__(self) -> str:
        return f"<ObservableEnrichment(id={self.id}, source='{self.source}')>"


class ObservableAlertLink(Base):
    """Junction table linking observables to alert triage records."""

    __tablename__ = "observable_alert_links"
    __table_args__ = (
        UniqueConstraint(
            "observable_id", "alert_triage_id", "context",
            name="uq_observable_alert_context"
        ),
        Index("ix_observable_alert_links_observable_id", "observable_id"),
        Index("ix_observable_alert_links_alert_triage_id", "alert_triage_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    observable_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("observables.id", ondelete="CASCADE"), nullable=False
    )
    alert_triage_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("alert_triage.id", ondelete="CASCADE"), nullable=False
    )
    context: Mapped[str] = mapped_column(String(100), nullable=False)
    extracted_from: Mapped[str] = mapped_column(
        String(50), default="auto", nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    # Relationships
    observable: Mapped["Observable"] = relationship(
        "Observable", back_populates="alert_links"
    )
    alert_triage: Mapped["AlertTriage"] = relationship("AlertTriage")

    def __repr__(self) -> str:
        return f"<ObservableAlertLink(observable_id={self.observable_id}, alert_triage_id={self.alert_triage_id})>"


class ObservableCaseLink(Base):
    """Junction table linking observables to investigation cases."""

    __tablename__ = "observable_case_links"
    __table_args__ = (
        UniqueConstraint(
            "observable_id", "case_id", "context",
            name="uq_observable_case_context"
        ),
        Index("ix_observable_case_links_observable_id", "observable_id"),
        Index("ix_observable_case_links_case_id", "case_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    observable_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("observables.id", ondelete="CASCADE"), nullable=False
    )
    case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("alert_cases.id", ondelete="CASCADE"), nullable=False
    )
    context: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    # Relationships
    observable: Mapped["Observable"] = relationship(
        "Observable", back_populates="case_links"
    )
    case: Mapped["AlertCase"] = relationship("AlertCase")

    def __repr__(self) -> str:
        return f"<ObservableCaseLink(observable_id={self.observable_id}, case_id={self.case_id})>"


class WatchlistAlert(Base):
    """Alerts triggered when a watched observable is seen again."""

    __tablename__ = "watchlist_alerts"
    __table_args__ = (
        Index("ix_watchlist_alerts_observable_id", "observable_id"),
        Index("ix_watchlist_alerts_created_at", "created_at"),
        Index("ix_watchlist_alerts_is_read", "is_read"),
        Index("ix_watchlist_alerts_alert_type", "alert_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    observable_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("observables.id", ondelete="CASCADE"), nullable=False
    )
    alert_type: Mapped[str] = mapped_column(
        SQLEnum(WatchlistAlertType), nullable=False
    )
    message: Mapped[str] = mapped_column(String(1000), nullable=False)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    read_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    read_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Link to the triggering alert (if applicable)
    triggered_by_alert_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("alert_triage.id", ondelete="SET NULL"), nullable=True
    )

    # Relationship
    observable: Mapped["Observable"] = relationship(
        "Observable", back_populates="watchlist_alerts"
    )

    def __repr__(self) -> str:
        return f"<WatchlistAlert(id={self.id}, type='{self.alert_type}', observable_id={self.observable_id})>"


class ObservableSighting(Base):
    """Historical record of observable sightings for timeline view."""

    __tablename__ = "observable_sightings"
    __table_args__ = (
        Index("ix_observable_sightings_observable_id", "observable_id"),
        Index("ix_observable_sightings_seen_at", "seen_at"),
        Index("ix_observable_sightings_source_type", "source_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    observable_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("observables.id", ondelete="CASCADE"), nullable=False
    )
    seen_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)  # "alert", "case", "manual"
    source_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # alert_id or case_id
    context: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)  # e.g., "source_ip", "destination_ip"

    # Relationship
    observable: Mapped["Observable"] = relationship("Observable")

    def __repr__(self) -> str:
        return f"<ObservableSighting(observable_id={self.observable_id}, seen_at={self.seen_at})>"
