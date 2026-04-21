"""Generic scheduler API — CRUD + manual trigger + execution history.

Mounted at ``/api/scheduler`` (prefix set on the router itself, so
``server.py`` should include it with ``prefix=""``).
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.services.scheduler_service import (
    create_job as svc_create_job,
    delete_job as svc_delete_job,
    get_job as svc_get_job,
    list_executions as svc_list_executions,
    list_handlers as svc_list_handlers,
    list_jobs as svc_list_jobs,
    trigger_now as svc_trigger_now,
    update_job as svc_update_job,
    validate_cron_expr,
)
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scheduler", tags=["scheduler"])


# ---------------------------------------------------------------------------
# Pydantic payloads
# ---------------------------------------------------------------------------


class JobCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    cron_expr: str = Field(..., min_length=1, max_length=120)
    handler_key: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    params: Optional[dict] = None
    enabled: bool = True


class JobUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=200)
    cron_expr: Optional[str] = Field(default=None, max_length=120)
    handler_key: Optional[str] = Field(default=None, max_length=100)
    description: Optional[str] = None
    params: Optional[dict] = None
    enabled: Optional[bool] = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/jobs", dependencies=[Depends(require_permission("system:settings"))])
def list_jobs(session: Session = Depends(get_db_session)):
    """List all scheduled jobs."""
    return {"jobs": svc_list_jobs(session)}


@router.post("/jobs", dependencies=[Depends(require_permission("system:settings"))])
def create_job(
    data: JobCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Create a new scheduled job."""
    if not validate_cron_expr(data.cron_expr):
        raise HTTPException(status_code=400, detail=f"Invalid cron expression: {data.cron_expr!r}")
    try:
        return svc_create_job(
            session,
            name=data.name,
            cron_expr=data.cron_expr,
            handler_key=data.handler_key,
            params=data.params,
            description=data.description,
            enabled=data.enabled,
            created_by_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.put(
    "/jobs/{job_id}",
    dependencies=[Depends(require_permission("system:settings"))],
)
def update_job(
    job_id: int,
    data: JobUpdate,
    session: Session = Depends(get_db_session),
):
    """Update an existing scheduled job. All fields optional."""
    fields = data.model_dump(exclude_unset=True, exclude_none=False)
    # params is handled specially (serialised to JSON) inside the service.
    try:
        result = svc_update_job(session, job_id, **fields)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if result is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return result


@router.delete(
    "/jobs/{job_id}",
    dependencies=[Depends(require_permission("system:settings"))],
)
def delete_job(
    job_id: int,
    session: Session = Depends(get_db_session),
):
    """Delete a scheduled job and its execution history."""
    ok = svc_delete_job(session, job_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"ok": True}


@router.post(
    "/jobs/{job_id}/run",
    dependencies=[Depends(require_permission("system:settings"))],
)
def run_now(
    job_id: int,
    session: Session = Depends(get_db_session),
):
    """Manually trigger a job immediately — bypasses the cron schedule.

    Does NOT update ``next_run_at`` differently from a scheduled run: the
    dispatcher always recomputes next_run_at from the cron_expr after a
    successful run.
    """
    # Verify the job exists so we can return 404 cleanly before kicking off
    # the dispatch (which uses its own session).
    if svc_get_job(session, job_id) is None:
        raise HTTPException(status_code=404, detail="Job not found")
    result = svc_trigger_now(job_id)
    # Strip internal error text to keep responses concise.
    if isinstance(result, dict) and result.get("error"):
        result = {**result, "has_error": True}
    return result


@router.get(
    "/jobs/{job_id}/executions",
    dependencies=[Depends(require_permission("system:settings"))],
)
def list_executions(
    job_id: int,
    limit: int = 50,
    session: Session = Depends(get_db_session),
):
    """Return recent execution history for a job (newest first)."""
    if svc_get_job(session, job_id) is None:
        raise HTTPException(status_code=404, detail="Job not found")
    limit = max(1, min(limit, 500))
    return {"executions": svc_list_executions(session, job_id, limit=limit)}


@router.get(
    "/handlers",
    dependencies=[Depends(require_permission("system:settings"))],
)
def list_handlers():
    """Return the list of handler keys registered at this moment.

    Handlers are registered at import time via ``@register_handler`` in
    whatever service defines them, so this list reflects the modules
    that have been imported in the current worker process.
    """
    return {"handlers": svc_list_handlers()}
