"""Case evidence pins + tamper-evident ledger.

v0.20.0 — Workbench feature inspired by Heimdall-DFIR. Two tables:

- ``case_evidence_pins``: per-case pinned forensic items. Unlike the heavier
  ``forensic_evidence_items`` (intended for sealed artifacts with SHA-256
  hashes and storage_location), pins are lightweight references — pin an
  alert, an observable, or a free-form analyst observation as "key evidence
  in this case". Status flows Triage → Confirmed → Reported, or → Dismissed
  (soft-delete; the row stays so the chain stays meaningful).

- ``case_evidence_ledger``: append-only tamper-evident audit. Every pin add,
  status change, summary edit, etc. emits a row whose ``content_hash`` is
  ``sha256(prev_hash || "|" || action || "|" || canonical_json(payload))``.
  Per-case ``seq`` is monotonic and unique so an attacker can't insert in
  the middle without recomputing every downstream hash.

v0.20.0 attaches both to AlertCase only. v0.20.1 will add ForensicCase as a
parallel attachment point (alert_case_id and forensic_case_id both nullable,
exactly one set).
"""

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from ion.models.alert_triage import AlertCase
    from ion.models.user import User


class PinSourceType(str, Enum):
    """Where the pin originated. Open-ended on purpose — new sources can be
    added without a migration since this is stored as VARCHAR."""

    ALERT = "alert"           # source_ref = alert triage id or es_alert_id
    OBSERVABLE = "observable" # source_ref = observable id
    ES_EVENT = "es_event"     # source_ref = "<index>/<doc_id>"
    NOTE = "note"             # free-form analyst observation, no external ref
    FILE = "file"             # uploaded artifact id
    HOST = "host"             # affected host name


class FindingStatus(str, Enum):
    """Kanban column for a pinned finding."""

    TRIAGE = "triage"
    CONFIRMED = "confirmed"
    REPORTED = "reported"
    DISMISSED = "dismissed"


class PinSeverity(str, Enum):
    """Severity tag on the pin itself (not the source case's severity)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CaseEvidencePin(Base, TimestampMixin):
    """A pinned piece of evidence on a case's Workbench."""

    __tablename__ = "case_evidence_pins"
    __table_args__ = (
        UniqueConstraint(
            "alert_case_id", "source_type", "source_ref",
            name="uq_case_evidence_pins_dedupe",
        ),
        Index("ix_case_evidence_pins_case", "alert_case_id"),
        Index("ix_case_evidence_pins_status", "alert_case_id", "finding_status"),
        Index("ix_case_evidence_pins_pinned_by", "pinned_by_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("alert_cases.id", ondelete="CASCADE"), nullable=False
    )
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # source_ref is the external identifier ("alert:1234", "obs:5", "es:idx/abc").
    # For source_type=note we store an empty string so the UNIQUE constraint
    # still fires per-case but doesn't collapse multiple notes into one row.
    # We disambiguate notes via metadata.note_id (uuid) — see service.
    source_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    finding_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=FindingStatus.TRIAGE.value
    )
    severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    mitre_techniques: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    pinned_by_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    pinned_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now()
    )
    pin_metadata: Mapped[Optional[dict]] = mapped_column(
        "metadata", JSON, nullable=True
    )

    alert_case: Mapped["AlertCase"] = relationship(
        "AlertCase", foreign_keys=[alert_case_id]
    )
    pinned_by: Mapped["User"] = relationship("User", foreign_keys=[pinned_by_id])

    def __repr__(self) -> str:
        return (
            f"<CaseEvidencePin(id={self.id}, case={self.alert_case_id}, "
            f"src={self.source_type}:{self.source_ref}, status={self.finding_status})>"
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "alert_case_id": self.alert_case_id,
            "source_type": self.source_type,
            "source_ref": self.source_ref,
            "title": self.title,
            "summary": self.summary,
            "finding_status": self.finding_status,
            "severity": self.severity,
            "mitre_techniques": self.mitre_techniques or [],
            "tags": self.tags or [],
            "pinned_by_id": self.pinned_by_id,
            "pinned_by_username": self.pinned_by.username if self.pinned_by else None,
            "pinned_at": self.pinned_at.isoformat() if self.pinned_at else None,
            "metadata": self.pin_metadata or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class CaseEvidenceLedger(Base):
    """Append-only tamper-evident ledger for case Workbench actions.

    Never UPDATE, never DELETE. Status reversals etc. emit a NEW row.
    Validation walks rows in seq order and recomputes every content_hash
    against the stored canonicalised payload + previous hash.
    """

    __tablename__ = "case_evidence_ledger"
    __table_args__ = (
        UniqueConstraint("alert_case_id", "seq", name="uq_case_evidence_ledger_seq"),
        Index("ix_case_evidence_ledger_case", "alert_case_id"),
        Index("ix_case_evidence_ledger_timestamp", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("alert_cases.id", ondelete="CASCADE"), nullable=False
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now()
    )

    actor: Mapped[Optional["User"]] = relationship("User", foreign_keys=[actor_id])

    def __repr__(self) -> str:
        return (
            f"<CaseEvidenceLedger(case={self.alert_case_id}, "
            f"seq={self.seq}, action={self.action})>"
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "alert_case_id": self.alert_case_id,
            "seq": self.seq,
            "action": self.action,
            "actor_id": self.actor_id,
            "actor_username": self.actor.username if self.actor else None,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "content_hash": self.content_hash,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
