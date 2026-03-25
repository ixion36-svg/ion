"""CyAB (Cyber Assurance Baseline) models — systems, data sources, and history."""

from datetime import date, datetime
from typing import List, Optional

from sqlalchemy import Date, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base


# ---------------------------------------------------------------------------
# System icon choices (mapped to Lucide icon names in the UI)
# ---------------------------------------------------------------------------
SYSTEM_ICONS = {
    "server": "Server / Endpoint",
    "shield": "Firewall / IDS",
    "globe": "Network",
    "key": "Identity / Auth",
    "cloud": "Cloud",
    "mail": "Email",
    "database": "Database",
    "search": "DNS",
    "code": "Application",
    "monitor": "Generic",
    "hard-drive": "Storage",
    "wifi": "Wireless",
    "lock": "Security",
    "cpu": "Infrastructure",
}


class CyabSystem(Base):
    """A department/system covered by a CyAB ingestion agreement.

    A system groups one or more data sources and tracks the overall agreement
    lifecycle (review dates, sign-off, department ownership).
    """

    __tablename__ = "cyab_systems"
    __table_args__ = (
        Index("ix_cyab_department", "department"),
        Index("ix_cyab_next_review", "next_review_date"),
        Index("ix_cyab_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Identity
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    department: Mapped[str] = mapped_column(String(255), nullable=False)
    department_lead: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    soc_team: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    soc_lead: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    reference: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(16), nullable=True, default="1.0")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="DRAFT")

    # Visual
    icon: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, default="monitor")
    tags: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array

    # Aggregate scores (cached from data sources)
    readiness_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    field_mapping_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    mandatory_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_rating: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    sal_compliance: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)

    # Legacy data-source fields (kept for backwards compat / single-source systems)
    sal_tier: Mapped[str] = mapped_column(String(8), nullable=False, default="SAL-2")
    data_source_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    uptime_target: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    max_latency: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    retention: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    p1_sla: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    field_mapping: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    field_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    use_case_status: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    use_case_review_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    use_case_gaps: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    use_case_remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Review tracking
    review_cadence_days: Mapped[int] = mapped_column(Integer, nullable=False, default=90)
    next_review_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    last_reviewed_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)

    # Authorization sign-off
    sign_dept_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    sign_dept_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    sign_soc_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    sign_soc_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)

    # Ownership
    created_by: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    creator: Mapped[Optional["User"]] = relationship("User", foreign_keys=[created_by])
    data_sources: Mapped[List["CyabDataSource"]] = relationship(
        "CyabDataSource", back_populates="system", cascade="all, delete-orphan",
        order_by="CyabDataSource.name"
    )
    snapshots: Mapped[List["CyabSnapshot"]] = relationship(
        "CyabSnapshot", back_populates="system", cascade="all, delete-orphan",
        order_by="CyabSnapshot.snapshot_date.desc()"
    )

    def __repr__(self) -> str:
        return f"<CyabSystem(id={self.id}, name='{self.name}', dept='{self.department}')>"


class CyabDataSource(Base):
    """An individual data source within a CyAB system agreement."""

    __tablename__ = "cyab_data_sources"
    __table_args__ = (
        Index("ix_cyab_ds_system", "system_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    system_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("cyab_systems.id"), nullable=False
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    data_source_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    icon: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    sal_tier: Mapped[str] = mapped_column(String(8), nullable=False, default="SAL-2")
    uptime_target: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    max_latency: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    retention: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    p1_sla: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Field mapping
    field_mapping: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    field_mapping_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    mandatory_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    readiness_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_rating: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    sal_compliance: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    field_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Use case coverage
    use_case_status: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    use_case_review_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    use_case_gaps: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    use_case_remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    system: Mapped["CyabSystem"] = relationship("CyabSystem", back_populates="data_sources")

    def __repr__(self) -> str:
        return f"<CyabDataSource(id={self.id}, name='{self.name}', system_id={self.system_id})>"


class CyabSnapshot(Base):
    """Point-in-time snapshot of a CyAB system's health metrics."""

    __tablename__ = "cyab_snapshots"
    __table_args__ = (
        Index("ix_cyab_snap_system", "system_id"),
        Index("ix_cyab_snap_date", "snapshot_date"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    system_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("cyab_systems.id"), nullable=False
    )
    data_source_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("cyab_data_sources.id", ondelete="SET NULL"), nullable=True
    )

    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False)
    readiness_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    field_mapping_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    mandatory_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_rating: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    sal_compliance: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    total_data_sources: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    # Relationships
    system: Mapped["CyabSystem"] = relationship("CyabSystem", back_populates="snapshots")

    def __repr__(self) -> str:
        return f"<CyabSnapshot(id={self.id}, system_id={self.system_id}, date={self.snapshot_date})>"
