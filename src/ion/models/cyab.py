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

    # onboarding metadata. All nullable so existing rows stay
    # valid; the wizard captures these on system creation but the legacy
    # quick-create modal still works without setting them.
    business_unit: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    data_classification: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    dept_lead_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    dept_lead_phone: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    dept_deputy_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    dept_deputy_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    soc_lead_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    soc_analyst_owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    stakeholder_distribution: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ir_runbook_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)

    # containment authority paragraph captured on the
    # Onboarding Pack approval flow. Free-text — references a runbook,
    # names the on-call team, etc.
    containment_authority: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

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

    # TIDE system link (stores TIDE system ID for use case coverage tracking)
    tide_system_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # ES alert mapping (data_stream.namespace value for this system)
    data_namespace: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Onboarding Studio sub-profile tag. Nullable so legacy
    # rows stay valid until backfilled. The catalogue lives in
    # cyab_subprofiles (see ion.models.cyab_subprofile).
    subprofile_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("cyab_subprofiles.id"), nullable=True
    )

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


# ---------------------------------------------------------------------------
# Assessment models — discovery questionnaire results
#
# Two granularities:
#   - CyabAssessment           (org-wide, no FK to a system)
#   - CyabSystemAssessment     (per CyabSystem, FK)
#
# Both immutable + versioned: every submission is a new row, prior versions
# are kept verbatim so quarter-over-quarter posture trending is possible.
# Responses are stored as JSON-as-text so the question schema can evolve
# without an alembic migration; the versioned `schema_version` column
# tracks which question set the responses were captured against.
# ---------------------------------------------------------------------------


class CyabAssessment(Base):
    """Org-wide questionnaire submission.

    Captures profile (sector, geo, stack, controls, concerns) once for the
    whole organisation. Drives baseline use-case ranking + threat-actor
    relevance for every CyAB system that doesn't override via a
    `CyabSystemAssessment`.
    """

    __tablename__ = "cyab_assessments"
    __table_args__ = (
        Index("ix_cyab_assessment_submitted_at", "submitted_at"),
        Index("ix_cyab_assessment_submitted_by", "submitted_by"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    submitted_by: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now()
    )

    # JSON blobs — stored as Text, parsed at read time. JSON-as-text avoids
    # vendor-specific JSON column types and keeps the homegrown migration
    # pattern simple (an ALTER TABLE ADD COLUMN TEXT works on PG and SQLite).
    responses_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    computed_profile_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ranked_use_cases_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ranked_actors_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<CyabAssessment(id={self.id}, submitted_at={self.submitted_at})>"


class CyabSystemAssessment(Base):
    """Per-system questionnaire submission.

    Inherits the org-wide profile and adds system-specific context
    (criticality, exposure, system controls). Scoring layers a delta on
    top of the org-wide baseline ranking — so an internet-facing,
    BYOD-allowing system gets initial-access playbooks ranked higher than
    its sibling internal-only system.
    """

    __tablename__ = "cyab_system_assessments"
    __table_args__ = (
        Index("ix_cyab_sys_assessment_system", "system_id"),
        Index("ix_cyab_sys_assessment_submitted_at", "submitted_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    system_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("cyab_systems.id", ondelete="CASCADE"), nullable=False
    )
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    submitted_by: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now()
    )

    # Optional FK to the org-wide assessment that was current at submit
    # time. Nullable because per-system assessments can be filed without
    # an org-wide one (the scoring service falls back to defaults).
    org_assessment_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("cyab_assessments.id", ondelete="SET NULL"), nullable=True
    )

    responses_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    computed_profile_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ranked_use_cases_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ranked_actors_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<CyabSystemAssessment(id={self.id}, system_id={self.system_id}, "
            f"submitted_at={self.submitted_at})>"
        )
