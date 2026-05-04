"""Repository for ScheduledJob / JobExecution CRUD."""

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from ion.models.scheduler import JobExecution, ScheduledJob


class SchedulerRepository:
    """CRUD + due-query + execution-record helpers for the generic scheduler."""

    def __init__(self, session: Session):
        self.session = session

    # ------------------------------------------------------------------
    # Job CRUD
    # ------------------------------------------------------------------

    def create_job(
        self,
        name: str,
        cron_expr: str,
        handler_key: str,
        next_run_at: datetime,
        description: Optional[str] = None,
        params_json: Optional[str] = None,
        enabled: bool = True,
        created_by_id: Optional[int] = None,
    ) -> ScheduledJob:
        job = ScheduledJob(
            name=name,
            description=description,
            cron_expr=cron_expr,
            handler_key=handler_key,
            params_json=params_json,
            enabled=enabled,
            next_run_at=next_run_at,
            created_by_id=created_by_id,
        )
        self.session.add(job)
        self.session.flush()
        return job

    def get_job(self, job_id: int) -> Optional[ScheduledJob]:
        return self.session.get(ScheduledJob, job_id)

    def get_by_name(self, name: str) -> Optional[ScheduledJob]:
        stmt = select(ScheduledJob).where(ScheduledJob.name == name)
        return self.session.execute(stmt).scalar_one_or_none()

    def list_jobs(self) -> List[ScheduledJob]:
        stmt = select(ScheduledJob).order_by(ScheduledJob.name)
        return list(self.session.execute(stmt).scalars().all())

    def update_job(self, job_id: int, **fields) -> Optional[ScheduledJob]:
        """Patch-style update. Only non-None fields are applied."""
        job = self.get_job(job_id)
        if job is None:
            return None
        for key, value in fields.items():
            if value is None:
                continue
            if hasattr(job, key):
                setattr(job, key, value)
        self.session.flush()
        return job

    def delete_job(self, job_id: int) -> bool:
        job = self.get_job(job_id)
        if job is None:
            return False
        self.session.delete(job)
        self.session.flush()
        return True

    def list_due_jobs(self, now: datetime) -> List[ScheduledJob]:
        """Return enabled jobs whose next_run_at is in the past."""
        stmt = (
            select(ScheduledJob)
            .where(
                and_(
                    ScheduledJob.enabled == True,  # noqa: E712
                    ScheduledJob.next_run_at <= now,
                )
            )
            .order_by(ScheduledJob.next_run_at)
        )
        return list(self.session.execute(stmt).scalars().all())

    # ------------------------------------------------------------------
    # Execution records
    # ------------------------------------------------------------------

    def record_execution_start(self, job_id: int) -> JobExecution:
        """Insert a JobExecution row with status=running. Flushes so the
        caller gets an ``id`` back to thread through to ``record_execution_end``."""
        now = datetime.now(timezone.utc)
        exe = JobExecution(
            job_id=job_id,
            started_at=now,
            status="running",
        )
        self.session.add(exe)
        self.session.flush()
        return exe

    def record_execution_end(
        self,
        execution_id: int,
        status: str,
        error_text: Optional[str] = None,
        output_json: Optional[str] = None,
    ) -> Optional[JobExecution]:
        """Update a JobExecution row to terminal status + fill duration_ms."""
        exe = self.session.get(JobExecution, execution_id)
        if exe is None:
            return None
        now = datetime.now(timezone.utc)
        exe.completed_at = now
        exe.status = status
        exe.error_text = error_text
        exe.output_json = output_json
        # Compute duration defensively: started_at may be naive from some DBs.
        try:
            started = exe.started_at
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
            exe.duration_ms = int((now - started).total_seconds() * 1000)
        except Exception:
            exe.duration_ms = None
        self.session.flush()
        return exe

    def list_executions_for_job(
        self,
        job_id: int,
        limit: int = 50,
    ) -> List[JobExecution]:
        stmt = (
            select(JobExecution)
            .where(JobExecution.job_id == job_id)
            .order_by(JobExecution.started_at.desc())
            .limit(limit)
        )
        return list(self.session.execute(stmt).scalars().all())
