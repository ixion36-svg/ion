"""Network Mapper / CMDB models — live asset inventory from Elasticsearch."""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    DateTime, ForeignKey, Index, Integer, JSON, String, Text,
    UniqueConstraint, func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base, TimestampMixin


class NetworkAsset(TimestampMixin, Base):
    """A host observed in Elasticsearch log data.

    Keyed on lowercased hostname. IP addresses, MAC addresses, and source
    systems that have seen this host are tracked in child tables so the
    full history is preserved without JSON-column merging.
    """

    __tablename__ = "network_assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    hostname: Mapped[str] = mapped_column(String(512), unique=True, nullable=False, index=True)
    display_hostname: Mapped[str] = mapped_column(String(512), nullable=False)
    os_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    os_version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    os_family: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    os_platform: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    architecture: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_index: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    # User-editable enrichment fields
    criticality: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False)
    environment: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False)
    owner: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Source systems that have seen this host (e.g. data_stream.namespace values)
    source_systems: Mapped[Optional[list]] = mapped_column(JSON, default=list, nullable=True)

    # Child relationships
    ips: Mapped[list["NetworkAssetIP"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", lazy="selectin",
    )
    macs: Mapped[list["NetworkAssetMAC"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", lazy="selectin",
    )

    __table_args__ = (
        Index("ix_network_assets_last_seen", "last_seen"),
        Index("ix_network_assets_criticality", "criticality"),
        Index("ix_network_assets_environment", "environment"),
    )


class NetworkAssetIP(Base):
    """An IP address observed on a network asset."""

    __tablename__ = "network_asset_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[int] = mapped_column(Integer, ForeignKey("network_assets.id", ondelete="CASCADE"), nullable=False)
    ip: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    asset: Mapped["NetworkAsset"] = relationship(back_populates="ips")

    __table_args__ = (
        UniqueConstraint("asset_id", "ip", name="uq_asset_ip"),
        Index("ix_network_asset_ips_ip", "ip"),
    )


class NetworkAssetMAC(Base):
    """A MAC address observed on a network asset."""

    __tablename__ = "network_asset_macs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[int] = mapped_column(Integer, ForeignKey("network_assets.id", ondelete="CASCADE"), nullable=False)
    mac: Mapped[str] = mapped_column(String(32), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)

    asset: Mapped["NetworkAsset"] = relationship(back_populates="macs")

    __table_args__ = (
        UniqueConstraint("asset_id", "mac", name="uq_asset_mac"),
    )
