"""Arkime packet-search (hunt) job tracking.

One row per hunt ION has submitted to the Arkime viewer. Arkime owns the job
itself; this table is ION's durable handle on it — required because ION runs
multi-worker, so job state can never live in module globals. The retention-
awareness loop polls unfinished rows and, for case-linked hunts, posts a
completion note to the case.

Submissions are lead-gated (``security:read``) and audit-logged: a hunt scans
raw packets on the sensors and costs real capture-node CPU.
"""

from typing import Optional

from sqlalchemy import Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base, TimestampMixin


class ArkimeHunt(Base, TimestampMixin):
    """One packet-search job submitted to Arkime."""

    __tablename__ = "arkime_hunts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Arkime's own job id — nullable for the window between our INSERT and the
    # viewer accepting the submission.
    arkime_hunt_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    search: Mapped[str] = mapped_column(String(512), nullable=False)
    search_type: Mapped[str] = mapped_column(String(16), nullable=False, default="ascii")
    expression: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    # submitted | running | finished | failed
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="submitted")
    matched_sessions: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    case_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_by_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # Completion note posted to the linked case (never re-posted).
    notified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "arkime_hunt_id": self.arkime_hunt_id,
            "name": self.name,
            "search": self.search,
            "search_type": self.search_type,
            "expression": self.expression,
            "status": self.status,
            "matched_sessions": self.matched_sessions,
            "case_id": self.case_id,
            "created_by_id": self.created_by_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
