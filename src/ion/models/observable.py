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

from ion.models.base import Base, TimestampMixin


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


class ObservableLinkType(str, Enum):
    """Types of entities that observables can be linked to."""

    ALERT = "alert"
    CASE = "case"
    MANUAL = "manual"


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
        SQLEnum(ObservableType, native_enum=False), nullable=False
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
        SQLEnum(ThreatLevel, native_enum=False), default=ThreatLevel.UNKNOWN, nullable=False
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
    links: Mapped[List["ObservableLink"]] = relationship(
        "ObservableLink",
        back_populates="observable",
        cascade="all, delete-orphan",
    )
    watchlist_alerts: Mapped[List["WatchlistAlert"]] = relationship(
        "WatchlistAlert",
        back_populates="observable",
        cascade="all, delete-orphan",
    )

    @property
    def alert_links(self) -> List["ObservableLink"]:
        """Get links to alerts (backward compatibility)."""
        return [l for l in self.links if l.link_type == ObservableLinkType.ALERT]

    @property
    def case_links(self) -> List["ObservableLink"]:
        """Get links to cases (backward compatibility)."""
        return [l for l in self.links if l.link_type == ObservableLinkType.CASE]

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


class ObservableLink(Base):
    """Unified junction table linking observables to alerts, cases, or manual entries."""

    __tablename__ = "observable_links"
    __table_args__ = (
        UniqueConstraint(
            "observable_id", "link_type", "entity_id", "context",
            name="uq_observable_link"
        ),
        Index("ix_observable_links_observable_id", "observable_id"),
        Index("ix_observable_links_link_type", "link_type"),
        Index("ix_observable_links_entity_id", "entity_id"),
        Index("ix_observable_links_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    observable_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("observables.id", ondelete="CASCADE"), nullable=False
    )
    link_type: Mapped[str] = mapped_column(
        SQLEnum(ObservableLinkType, native_enum=False), nullable=False
    )
    entity_id: Mapped[int] = mapped_column(Integer, nullable=False)  # alert_triage.id or alert_cases.id
    context: Mapped[str] = mapped_column(String(100), nullable=False)
    extracted_from: Mapped[str] = mapped_column(
        String(50), default="auto", nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    # Relationships
    observable: Mapped["Observable"] = relationship(
        "Observable", back_populates="links"
    )

    # Backward compatibility properties
    @property
    def alert_triage_id(self) -> Optional[int]:
        """Get alert triage ID if this is an alert link."""
        return self.entity_id if self.link_type == ObservableLinkType.ALERT else None

    @property
    def case_id(self) -> Optional[int]:
        """Get case ID if this is a case link."""
        return self.entity_id if self.link_type == ObservableLinkType.CASE else None

    @property
    def seen_at(self) -> datetime:
        """Alias for created_at (backward compatibility with ObservableSighting)."""
        return self.created_at

    @property
    def source_type(self) -> str:
        """Get source type (backward compatibility with ObservableSighting)."""
        return self.link_type.value

    @property
    def source_id(self) -> int:
        """Get source ID (backward compatibility with ObservableSighting)."""
        return self.entity_id

    def __repr__(self) -> str:
        return f"<ObservableLink(observable_id={self.observable_id}, link_type='{self.link_type}', entity_id={self.entity_id})>"


# Backward compatibility aliases
ObservableAlertLink = ObservableLink
ObservableCaseLink = ObservableLink
ObservableSighting = ObservableLink


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
        SQLEnum(WatchlistAlertType, native_enum=False), nullable=False
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


