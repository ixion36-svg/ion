"""Generic cron-style job scheduler models.

These tables back the generic scheduler_service — a single-worker background
loop that fires registered handler functions on a crontab-style cadence.

Distinct from ``ScheduledReport`` (ion.models.sla): that model is purpose-built
for report generation with fixed ``daily/weekly/monthly`` schedules, whereas
``ScheduledJob`` accepts a full 5-field crontab and dispatches to any handler
registered via ``@register_handler`` in the scheduler service.
"""

from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base

if TYPE_CHECKING:
    from ion.models.user import User


class ScheduledJob(Base):
    """A crontab-scheduled job that dispatches to a registered handler."""

    __tablename__ = "scheduled_jobs"
    __table_args__ = (
        Index("ix_scheduled_jobs_enabled", "enabled"),
        Index("ix_scheduled_jobs_next_run_at", "next_run_at"),
        Index("ix_scheduled_jobs_handler_key", "handler_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Human-readable unique job name.
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # 5-field crontab expression (minute hour day-of-month month day-of-week).
    cron_expr: Mapped[str] = mapped_column(String(120), nullable=False)

    # Name of a handler registered via @register_handler in scheduler_service.
    handler_key: Mapped[str] = mapped_column(String(100), nullable=False)

    # JSON-serialised parameter dict passed to the handler on dispatch.
    params_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Next firing timestamp — the scheduler loop selects rows where this is
    # in the past. Recomputed from cron_expr after every execution.
    next_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_run_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # "success" | "error" | "running"
    last_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    created_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    created_by: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[created_by_id]
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "cron_expr": self.cron_expr,
            "handler_key": self.handler_key,
            "params_json": self.params_json,
            "enabled": self.enabled,
            "next_run_at": self.next_run_at.isoformat() if self.next_run_at else None,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "last_status": self.last_status,
            "created_by_id": self.created_by_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class JobExecution(Base):
    """A single run of a ScheduledJob — kept for history/debugging."""

    __tablename__ = "job_executions"
    __table_args__ = (
        Index("ix_job_executions_job_id", "job_id"),
        Index("ix_job_executions_started_at", "started_at"),
        Index("ix_job_executions_job_started", "job_id", "started_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    job_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("scheduled_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # "running" | "success" | "error"
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="running")

    error_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    output_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    job: Mapped["ScheduledJob"] = relationship("ScheduledJob", foreign_keys=[job_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "job_id": self.job_id,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status,
            "error_text": self.error_text,
            "output_json": self.output_json,
            "duration_ms": self.duration_ms,
        }
