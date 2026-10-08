"""Durable record of outbound integration syncs (review 2026-10-08, stage 3).

Every outbound sync in ION was fire-and-forget::

    try:
        service.add_comment(kibana_case_id, comment_text)
    except Exception as e:
        logger.warning("Failed to sync note to Kibana: %s", e)

So a failure existed only in a log line: the case page showed a note ION
believed was mirrored to Kibana and was not, nothing could retry it because
nothing recorded what to retry with, and nobody could see how much had
silently drifted. The review asks for failed sync to sit "beside the affected
action", and for stage 3 to leave "recoverable failures".

One row per *logical* sync, identified by ``dedupe_key``, so repeating the
same sync reuses its row instead of piling up. ``case_id`` is denormalised
onto the row specifically so the case page can show the problem next to the
case it affects without a join through every entity type.
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
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from ion.models.alert_triage import AlertCase


class SyncStatus(str, Enum):
    """Where an outbound sync has got to.

    ``ABANDONED`` is deliberately distinct from ``FAILED``: once the retry
    budget is spent ION has stopped trying, and the row says so rather than
    sitting at ``FAILED`` with a ``next_retry_at`` that will never be
    honoured. A queue that looks like it is still working is worse than one
    that admits it gave up.
    """

    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ABANDONED = "abandoned"


class SyncAttempt(Base, TimestampMixin):
    """One logical outbound sync, with its outcome and retry schedule."""

    __tablename__ = "integration_sync_attempts"
    __table_args__ = (
        UniqueConstraint("dedupe_key", name="uq_integration_sync_dedupe"),
        Index("ix_integration_sync_status", "status"),
        Index("ix_integration_sync_case", "case_id"),
        Index("ix_integration_sync_retry", "status", "next_retry_at"),
        Index("ix_integration_sync_target", "target"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    #: Which integration the sync was aimed at (kibana, dfir_iris, ...).
    target: Mapped[str] = mapped_column(String(32), nullable=False)
    #: What was being done (note_add, case_create, case_update, status_push).
    operation: Mapped[str] = mapped_column(String(48), nullable=False)
    #: The ION object being mirrored, for traceability back from the journal.
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(128), nullable=False)

    #: Denormalised so a failure can be shown beside the case it affects.
    case_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("alert_cases.id", ondelete="CASCADE"), nullable=True
    )

    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=SyncStatus.PENDING.value
    )
    #: Everything the retry handler needs to perform the sync again. Must not
    #: contain credentials — the handler resolves those from configuration.
    payload: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_attempt_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True
    )
    #: None when there is nothing scheduled: either resolved or abandoned.
    next_retry_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    #: Unique per logical sync, e.g. "kibana:note_add:77".
    dedupe_key: Mapped[str] = mapped_column(String(255), nullable=False)

    case: Mapped[Optional["AlertCase"]] = relationship(
        "AlertCase", foreign_keys=[case_id]
    )

    def to_dict(self, *, max_attempts: Optional[int] = None) -> dict:
        from datetime import timezone as _tz

        def _iso(value: Optional[datetime]) -> Optional[str]:
            if value is None:
                return None
            # Stored naive UTC; stamp it so a reader does not apply its own zone.
            aware = value if value.tzinfo else value.replace(tzinfo=_tz.utc)
            return aware.isoformat()

        remaining = None
        if max_attempts is not None:
            if self.status == SyncStatus.ABANDONED.value:
                remaining = 0
            else:
                remaining = max(0, max_attempts - self.attempt_count)

        return {
            "id": self.id,
            "target": self.target,
            "operation": self.operation,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "case_id": self.case_id,
            "status": self.status,
            "attempt_count": self.attempt_count,
            "attempts_remaining": remaining,
            "last_error": self.last_error,
            "last_attempt_at": _iso(self.last_attempt_at),
            "next_retry_at": _iso(self.next_retry_at),
            "resolved_at": _iso(self.resolved_at),
            "dedupe_key": self.dedupe_key,
            "created_at": _iso(self.created_at),
        }


__all__ = ["SyncStatus", "SyncAttempt"]
