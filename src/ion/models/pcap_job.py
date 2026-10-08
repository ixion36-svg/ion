"""Durable PCAP analysis jobs (review 2026-10-08, §13).

    "standalone upload returns results without a persistent
    job/history/case association"

``POST /api/pcap/analyze`` parsed the upload and returned the result. Nothing
was stored, so a capture that took forty seconds to parse had to be
re-uploaded to look at again, two analysts could not see each other's work,
and a finding that mattered could not reach the case except by retyping it.

``content_sha256`` plus ``parser_version`` is what makes a result reusable:
the same bytes parsed by the same parser cannot produce a different answer,
so a second upload of the same capture serves the stored result and records
which job it came from. A parser upgrade invalidates that automatically,
which is the reason the version is on the row rather than assumed.

The raw capture is deliberately **not** stored. ION already has a forensic
evidence store with custody tracking for artefacts that must be retained;
duplicating multi-megabyte captures into this table would quietly become the
largest thing in the database for no stated custody benefit. The hash is kept
so a capture presented later can be shown to be the one that was analysed.
"""

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from ion.models.user import User


class PcapJobStatus(str, Enum):
    """Where a parse has got to.

    ``CANCELLED`` is only reached when the runner actually notices a cancel
    request; asking for a cancel sets ``cancel_requested`` and leaves the
    status alone, because until the runner checks, the work may well still be
    going.
    """

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PcapJob(Base, TimestampMixin):
    """One capture analysis, with its provenance and reusable result."""

    __tablename__ = "pcap_jobs"
    __table_args__ = (
        Index("ix_pcap_jobs_status", "status"),
        Index("ix_pcap_jobs_case", "case_id"),
        # The reuse lookup: same bytes, same parser, completed.
        Index("ix_pcap_jobs_reuse", "content_sha256", "parser_version", "status"),
        Index("ix_pcap_jobs_requester", "requested_by_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    #: sha256 of the uploaded bytes. The capture itself is not stored.
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Which parser produced (or will produce) the result.
    parser_version: Mapped[str] = mapped_column(String(32), nullable=False)

    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=PcapJobStatus.QUEUED.value
    )
    result: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    requested_by_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    case_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("alert_cases.id", ondelete="SET NULL"), nullable=True
    )

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    #: Cooperative cancellation: set by the request, honoured by the runner.
    cancel_requested: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    cancelled_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    #: The earlier job whose result this one serves, when the bytes and the
    #: parser version matched.
    reused_from_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("pcap_jobs.id", ondelete="SET NULL"), nullable=True
    )

    requested_by: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[requested_by_id]
    )
    cancelled_by: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[cancelled_by_id]
    )

    def summary(self) -> dict:
        """Row for the history list. Deliberately excludes ``result``.

        A history list that shipped every parsed capture would transfer
        megabytes to render a table of filenames.
        """
        result = self.result if isinstance(self.result, dict) else {}
        findings = result.get("findings")
        return {
            "id": self.id,
            "filename": self.filename,
            "file_size": self.file_size,
            "content_sha256": self.content_sha256,
            "parser_version": self.parser_version,
            "status": self.status,
            "error": self.error,
            "requested_by_id": self.requested_by_id,
            "requested_by": self.requested_by.username if self.requested_by else None,
            "case_id": self.case_id,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "duration_ms": self.duration_ms,
            "cancel_requested": self.cancel_requested,
            "reused_from_id": self.reused_from_id,
            "verdict": result.get("verdict"),
            "packet_count": result.get("packet_count"),
            "finding_count": len(findings) if isinstance(findings, list) else 0,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def to_dict(self) -> dict:
        """Full row, including the stored parse result."""
        payload = self.summary()
        payload["result"] = self.result or {}
        return payload


__all__ = ["PcapJobStatus", "PcapJob"]
