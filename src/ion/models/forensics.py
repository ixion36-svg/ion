"""Forensic investigation models for chain of custody, evidence tracking, and case management."""

from datetime import datetime
from enum import Enum
from typing import Optional, List, TYPE_CHECKING
from sqlalchemy import (
    ForeignKey,
    Integer,
    String,
    Text,
    Boolean,
    DateTime,
    Float,
    Index,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from ion.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from ion.models.user import User
    from ion.models.alert_triage import AlertCase


# =============================================================================
# Enums
# =============================================================================

class ForensicCaseStatus(str, Enum):
    """Status of a forensic investigation."""
    INTAKE = "intake"
    EVIDENCE_COLLECTION = "evidence_collection"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    REVIEW = "review"
    CLOSED = "closed"


class ForensicCasePriority(str, Enum):
    """Priority of a forensic investigation."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class InvestigationType(str, Enum):
    """Type of forensic investigation."""
    MALWARE_ANALYSIS = "malware_analysis"
    INSIDER_THREAT = "insider_threat"
    DATA_BREACH = "data_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    NETWORK_INTRUSION = "network_intrusion"
    FRAUD = "fraud"
    POLICY_VIOLATION = "policy_violation"
    OTHER = "other"


class EvidenceType(str, Enum):
    """Type of evidence item."""
    DISK_IMAGE = "disk_image"
    MEMORY_DUMP = "memory_dump"
    NETWORK_CAPTURE = "network_capture"
    LOG_FILES = "log_files"
    DOCUMENTS = "documents"
    EMAIL = "email"
    MOBILE_DEVICE = "mobile_device"
    PHYSICAL_MEDIA = "physical_media"
    SCREENSHOT = "screenshot"
    OTHER = "other"


class EvidenceStatus(str, Enum):
    """Status of an evidence item."""
    COLLECTED = "collected"
    IN_TRANSIT = "in_transit"
    IN_STORAGE = "in_storage"
    UNDER_ANALYSIS = "under_analysis"
    RETURNED = "returned"
    DESTROYED = "destroyed"


class CustodyAction(str, Enum):
    """Action performed on evidence in chain of custody."""
    COLLECTED = "collected"
    TRANSFERRED = "transferred"
    CHECKED_OUT = "checked_out"
    CHECKED_IN = "checked_in"
    ANALYZED = "analyzed"
    IMAGED = "imaged"
    RETURNED = "returned"
    DESTROYED = "destroyed"


# =============================================================================
# Models
# =============================================================================

class ForensicCase(Base, TimestampMixin):
    """Forensic investigation case."""

    __tablename__ = "forensic_cases"
    __table_args__ = (
        Index("ix_forensic_cases_status", "status"),
        Index("ix_forensic_cases_priority", "priority"),
        Index("ix_forensic_cases_type", "investigation_type"),
        Index("ix_forensic_cases_lead", "lead_investigator_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_number: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default=ForensicCaseStatus.INTAKE.value
    )
    priority: Mapped[str] = mapped_column(
        String(20), nullable=False, default=ForensicCasePriority.MEDIUM.value
    )
    investigation_type: Mapped[str] = mapped_column(String(50), nullable=False)
    classification: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Investigator
    lead_investigator_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    # Optional link to SOC case
    alert_case_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("alert_cases.id"), nullable=True
    )

    # Playbook used for this investigation
    playbook_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("forensic_playbooks.id"), nullable=True
    )

    # Report fields (populated on close)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    findings: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommendations: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # SLA profile (JSON with hours for each milestone)
    sla_profile: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # SLA due dates
    sla_initial_response_due: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    sla_evidence_collection_due: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    sla_analysis_due: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    sla_reporting_due: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # SLA met dates (set on status transitions)
    sla_initial_response_met: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    sla_evidence_collection_met: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    sla_analysis_met: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    sla_reporting_met: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Lock
    is_locked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    locked_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    locked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Closure
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    closed_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    # Generated report document
    report_document_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("documents.id"), nullable=True
    )

    # Relationships
    lead_investigator: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[lead_investigator_id]
    )
    closed_by: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[closed_by_id]
    )
    locked_by: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[locked_by_id]
    )
    alert_case: Mapped[Optional["AlertCase"]] = relationship(
        "AlertCase", foreign_keys=[alert_case_id]
    )
    playbook: Mapped[Optional["ForensicPlaybook"]] = relationship(
        "ForensicPlaybook", foreign_keys=[playbook_id]
    )
    case_steps: Mapped[List["ForensicCaseStep"]] = relationship(
        "ForensicCaseStep", back_populates="forensic_case", cascade="all, delete-orphan",
        order_by="ForensicCaseStep.step_order"
    )
    evidence_items: Mapped[List["EvidenceItem"]] = relationship(
        "EvidenceItem", back_populates="forensic_case", cascade="all, delete-orphan"
    )
    timeline_entries: Mapped[List["ForensicTimelineEntry"]] = relationship(
        "ForensicTimelineEntry", back_populates="forensic_case", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<ForensicCase(id={self.id}, case_number='{self.case_number}')>"

    def to_dict(self, include_evidence: bool = False, include_timeline: bool = False) -> dict:
        result = {
            "id": self.id,
            "case_number": self.case_number,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "priority": self.priority,
            "investigation_type": self.investigation_type,
            "classification": self.classification,
            "lead_investigator_id": self.lead_investigator_id,
            "lead_investigator_username": (
                self.lead_investigator.username if self.lead_investigator else None
            ),
            "alert_case_id": self.alert_case_id,
            "summary": self.summary,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "sla_profile": self.sla_profile,
            "sla_initial_response_due": self.sla_initial_response_due.isoformat() if self.sla_initial_response_due else None,
            "sla_evidence_collection_due": self.sla_evidence_collection_due.isoformat() if self.sla_evidence_collection_due else None,
            "sla_analysis_due": self.sla_analysis_due.isoformat() if self.sla_analysis_due else None,
            "sla_reporting_due": self.sla_reporting_due.isoformat() if self.sla_reporting_due else None,
            "sla_initial_response_met": self.sla_initial_response_met.isoformat() if self.sla_initial_response_met else None,
            "sla_evidence_collection_met": self.sla_evidence_collection_met.isoformat() if self.sla_evidence_collection_met else None,
            "sla_analysis_met": self.sla_analysis_met.isoformat() if self.sla_analysis_met else None,
            "sla_reporting_met": self.sla_reporting_met.isoformat() if self.sla_reporting_met else None,
            "is_locked": self.is_locked,
            "locked_by_id": self.locked_by_id,
            "locked_by_username": self.locked_by.username if self.locked_by else None,
            "locked_at": self.locked_at.isoformat() if self.locked_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "closed_by_id": self.closed_by_id,
            "report_document_id": self.report_document_id,
            "playbook_id": self.playbook_id,
            "playbook_name": self.playbook.name if self.playbook else None,
            "evidence_count": len(self.evidence_items) if self.evidence_items else 0,
            "step_count": len(self.case_steps) if self.case_steps else 0,
            "steps_completed": sum(1 for s in (self.case_steps or []) if s.is_completed),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_evidence and self.evidence_items:
            result["evidence_items"] = [e.to_dict() for e in self.evidence_items]
        if include_timeline and self.timeline_entries:
            result["timeline_entries"] = [
                t.to_dict() for t in sorted(self.timeline_entries, key=lambda x: x.timestamp, reverse=True)
            ]
        if self.case_steps:
            result["case_steps"] = [s.to_dict() for s in self.case_steps]
        return result


class EvidenceItem(Base, TimestampMixin):
    """Evidence item linked to a forensic case."""

    __tablename__ = "forensic_evidence_items"
    __table_args__ = (
        Index("ix_forensic_evidence_case", "forensic_case_id"),
        Index("ix_forensic_evidence_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    forensic_case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("forensic_cases.id"), nullable=False
    )
    evidence_number: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default=EvidenceStatus.COLLECTED.value
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    hash_md5: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    hash_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    storage_location: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    collected_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    collected_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    metadata_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Relationships
    forensic_case: Mapped["ForensicCase"] = relationship(
        "ForensicCase", back_populates="evidence_items"
    )
    collected_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[collected_by_id])
    custody_log: Mapped[List["CustodyLogEntry"]] = relationship(
        "CustodyLogEntry", back_populates="evidence_item", cascade="all, delete-orphan",
        order_by="CustodyLogEntry.timestamp.desc()"
    )

    def __repr__(self) -> str:
        return f"<EvidenceItem(id={self.id}, evidence_number='{self.evidence_number}')>"

    def to_dict(self, include_custody: bool = False) -> dict:
        result = {
            "id": self.id,
            "forensic_case_id": self.forensic_case_id,
            "evidence_number": self.evidence_number,
            "name": self.name,
            "evidence_type": self.evidence_type,
            "status": self.status,
            "description": self.description,
            "source": self.source,
            "hash_md5": self.hash_md5,
            "hash_sha256": self.hash_sha256,
            "storage_location": self.storage_location,
            "collected_by_id": self.collected_by_id,
            "collected_by_username": self.collected_by.username if self.collected_by else None,
            "collected_at": self.collected_at.isoformat() if self.collected_at else None,
            "metadata": self.metadata_json,
            "custody_entries": len(self.custody_log) if self.custody_log else 0,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_custody and self.custody_log:
            result["custody_log"] = [c.to_dict() for c in self.custody_log]
        return result


class CustodyLogEntry(Base):
    """Chain of custody log entry for an evidence item."""

    __tablename__ = "forensic_custody_log"
    __table_args__ = (
        Index("ix_forensic_custody_evidence", "evidence_item_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    evidence_item_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("forensic_evidence_items.id"), nullable=False
    )
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    performed_by_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    received_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now()
    )
    location: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    evidence_item: Mapped["EvidenceItem"] = relationship(
        "EvidenceItem", back_populates="custody_log"
    )
    performed_by: Mapped["User"] = relationship("User", foreign_keys=[performed_by_id])
    received_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[received_by_id])

    def __repr__(self) -> str:
        return f"<CustodyLogEntry(id={self.id}, action='{self.action}')>"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "evidence_item_id": self.evidence_item_id,
            "action": self.action,
            "performed_by_id": self.performed_by_id,
            "performed_by_username": self.performed_by.username if self.performed_by else None,
            "received_by_id": self.received_by_id,
            "received_by_username": self.received_by.username if self.received_by else None,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "location": self.location,
            "notes": self.notes,
        }


class ForensicPlaybook(Base, TimestampMixin):
    """Forensic investigation playbook template."""

    __tablename__ = "forensic_playbooks"
    __table_args__ = (
        Index("ix_forensic_playbooks_type", "investigation_type"),
        Index("ix_forensic_playbooks_active", "is_active"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    investigation_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )

    # Relationships
    created_by: Mapped["User"] = relationship("User", foreign_keys=[created_by_id])
    steps: Mapped[List["ForensicPlaybookStep"]] = relationship(
        "ForensicPlaybookStep", back_populates="playbook",
        cascade="all, delete-orphan", order_by="ForensicPlaybookStep.step_order"
    )

    def __repr__(self) -> str:
        return f"<ForensicPlaybook(id={self.id}, name='{self.name}')>"

    def to_dict(self, include_steps: bool = True) -> dict:
        result = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "investigation_type": self.investigation_type,
            "is_active": self.is_active,
            "created_by_id": self.created_by_id,
            "created_by_username": self.created_by.username if self.created_by else None,
            "step_count": len(self.steps) if self.steps else 0,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_steps and self.steps:
            result["steps"] = [s.to_dict() for s in self.steps]
        return result


class ForensicPlaybookStep(Base):
    """Step in a forensic investigation playbook."""

    __tablename__ = "forensic_playbook_steps"
    __table_args__ = (
        Index("ix_forensic_pb_steps_playbook", "playbook_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    playbook_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("forensic_playbooks.id"), nullable=False
    )
    step_order: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    expected_duration_hours: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    fields_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    playbook: Mapped["ForensicPlaybook"] = relationship(
        "ForensicPlaybook", back_populates="steps"
    )

    def __repr__(self) -> str:
        return f"<ForensicPlaybookStep(id={self.id}, order={self.step_order})>"

    @property
    def fields(self) -> list:
        if self.fields_json:
            import json
            return json.loads(self.fields_json)
        return []

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "playbook_id": self.playbook_id,
            "step_order": self.step_order,
            "title": self.title,
            "description": self.description,
            "is_required": self.is_required,
            "expected_duration_hours": self.expected_duration_hours,
            "fields": self.fields,
        }


class ForensicCaseStep(Base, TimestampMixin):
    """Fillable investigation step — copied from a playbook when a case is created."""

    __tablename__ = "forensic_case_steps"
    __table_args__ = (
        Index("ix_forensic_case_steps_case", "forensic_case_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    forensic_case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("forensic_cases.id"), nullable=False
    )
    playbook_step_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("forensic_playbook_steps.id"), nullable=True
    )
    step_order: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    fields_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    fields_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_completed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    completed_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    forensic_case: Mapped["ForensicCase"] = relationship(
        "ForensicCase", back_populates="case_steps"
    )
    completed_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[completed_by_id])

    def __repr__(self) -> str:
        return f"<ForensicCaseStep(id={self.id}, order={self.step_order}, completed={self.is_completed})>"

    @property
    def fields(self) -> list:
        if self.fields_json:
            import json
            return json.loads(self.fields_json)
        return []

    @property
    def field_values(self) -> dict:
        if self.fields_data:
            import json
            return json.loads(self.fields_data)
        return {}

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "forensic_case_id": self.forensic_case_id,
            "playbook_step_id": self.playbook_step_id,
            "step_order": self.step_order,
            "title": self.title,
            "description": self.description,
            "content": self.content,
            "fields": self.fields,
            "fields_data": self.field_values,
            "is_required": self.is_required,
            "is_completed": self.is_completed,
            "completed_by_id": self.completed_by_id,
            "completed_by_username": self.completed_by.username if self.completed_by else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class ForensicTimelineEntry(Base):
    """Timeline entry for a forensic investigation."""

    __tablename__ = "forensic_timeline_entries"
    __table_args__ = (
        Index("ix_forensic_timeline_case", "forensic_case_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    forensic_case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("forensic_cases.id"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    entry_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default="note"
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now()
    )
    metadata_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Relationships
    forensic_case: Mapped["ForensicCase"] = relationship(
        "ForensicCase", back_populates="timeline_entries"
    )
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])

    def __repr__(self) -> str:
        return f"<ForensicTimelineEntry(id={self.id}, type='{self.entry_type}')>"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "forensic_case_id": self.forensic_case_id,
            "user_id": self.user_id,
            "username": self.user.username if self.user else None,
            "content": self.content,
            "entry_type": self.entry_type,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "metadata": self.metadata_json,
        }
