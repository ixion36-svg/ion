"""Threat Intel watch models for tracking OpenCTI threat actors and campaigns."""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base


class ThreatIntelWatch(Base):
    """A watched threat actor or campaign from OpenCTI."""

    __tablename__ = "threat_intel_watches"
    __table_args__ = (
        Index("ix_tiw_entity_type", "entity_type"),
        Index("ix_tiw_opencti_id", "opencti_id", unique=True),
        Index("ix_tiw_is_active", "is_active"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)  # "threat_actor" or "campaign"
    opencti_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    aliases: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array
    labels: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    match_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    watched_by: Mapped[str] = mapped_column(String(100), nullable=False)
    watch_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<ThreatIntelWatch(id={self.id}, type='{self.entity_type}', name='{self.name}')>"
