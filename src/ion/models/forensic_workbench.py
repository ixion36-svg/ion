"""ForensicCase Workbench — pinned evidence + tamper-evident ledger (v0.20.1).

Parallel to ``case_evidence.py`` (AlertCase Workbench, v0.20.0).

Two tables:

- ``forensic_case_pins``: lightweight workbench pins on a ForensicCase. Same
  status/source semantics as ``case_evidence_pins`` but FK'd to
  ``forensic_cases.id``.

- ``forensic_case_ledger``: append-only tamper-evident audit for forensic
  case mutations. Every pin add, status change, summary edit, dismiss, and
  evidence file upload emits a row whose ``content_hash`` is
  ``sha256(prev_hash || "|" || action || "|" || canonical_json(payload))``.
  Per-case ``seq`` is monotonic (UNIQUE forensic_case_id, seq) so gaps or
  mid-chain inserts are detectable.
"""

from datetime import datetime
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
from ion.models.case_evidence import FindingStatus

if TYPE_CHECKING:
    from ion.models.forensics import ForensicCase
    from ion.models.user import User


class ForensicCasePin(Base, TimestampMixin):
    """A pinned piece of evidence on a ForensicCase Workbench.

    Mirrors ``CaseEvidencePin`` exactly — only the FK target differs.
    """

    __tablename__ = "forensic_case_pins"
    __table_args__ = (
        UniqueConstraint(
            "forensic_case_id", "source_type", "source_ref",
            name="uq_forensic_case_pins_dedupe",
        ),
        Index("ix_forensic_case_pins_case", "forensic_case_id"),
        Index("ix_forensic_case_pins_status", "forensic_case_id", "finding_status"),
        Index("ix_forensic_case_pins_pinned_by", "pinned_by_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    forensic_case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("forensic_cases.id", ondelete="CASCADE"), nullable=False
    )
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
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

    forensic_case: Mapped["ForensicCase"] = relationship(
        "ForensicCase", foreign_keys=[forensic_case_id]
    )
    pinned_by: Mapped["User"] = relationship("User", foreign_keys=[pinned_by_id])

    def __repr__(self) -> str:
        return (
            f"<ForensicCasePin(id={self.id}, case={self.forensic_case_id}, "
            f"src={self.source_type}:{self.source_ref}, status={self.finding_status})>"
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "forensic_case_id": self.forensic_case_id,
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


class ForensicCaseLedger(Base):
    """Append-only tamper-evident ledger for ForensicCase Workbench actions.

    Mirrors ``CaseEvidenceLedger`` exactly — only the FK target differs.
    Never UPDATE, never DELETE. Validation walks rows in seq order and
    recomputes every content_hash against stored canonical payload + prev hash.
    """

    __tablename__ = "forensic_case_ledger"
    __table_args__ = (
        UniqueConstraint(
            "forensic_case_id", "seq", name="uq_forensic_case_ledger_seq"
        ),
        Index("ix_forensic_case_ledger_case", "forensic_case_id"),
        Index("ix_forensic_case_ledger_timestamp", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    forensic_case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("forensic_cases.id", ondelete="CASCADE"), nullable=False
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
            f"<ForensicCaseLedger(case={self.forensic_case_id}, "
            f"seq={self.seq}, action={self.action})>"
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "forensic_case_id": self.forensic_case_id,
            "seq": self.seq,
            "action": self.action,
            "actor_id": self.actor_id,
            "actor_username": self.actor.username if self.actor else None,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "content_hash": self.content_hash,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
