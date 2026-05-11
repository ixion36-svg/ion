"""Autonomous investigation API endpoints.

Thin HTTP surface over ``investigation_service``. Investigations are
fire-and-forget (``asyncio.create_task``) so the web worker returns
immediately — the LLM pass can take 30-120s and we don't want to block
the request pool waiting on it.

Permissions:

* Read endpoints (``/jobs``, ``/jobs/{id}``) use ``alert:read`` — every
  analyst who can view alerts should be able to see the investigation
  queue.
* Trigger endpoints (``/investigate``, ``/investigate/sweep``) use
  ``alert:triage`` — triggering an AI investigation is a triage action.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_page_auth, require_permission
from ion.models.user import User
from ion.services import system_flags
from ion.services.investigation_memory_service import (
    get_investigation_memory_service,
)
from ion.services.investigation_service import (
    InvestigationError,
    get_investigation_service,
)
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["investigation"])

# Reuse the same templates dir as the rest of the app — importing
# server.templates would create a circular import.
_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=_TEMPLATES_DIR)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class InvestigateRequest(BaseModel):
    alert_id: str = Field(..., min_length=1, max_length=255)
    force: bool = False


class InvestigateResponse(BaseModel):
    investigation_id: Optional[int] = None
    queued: bool = True
    status: Optional[str] = None
    note: Optional[str] = None


class SweepResponse(BaseModel):
    started: bool
    note: Optional[str] = None


class InvestigationSummary(BaseModel):
    id: int
    alert_id_ref: str
    alert_signature: str
    host: Optional[str] = None
    source_ip: Optional[str] = None
    user_name: Optional[str] = None
    status: str
    verdict: Optional[str] = None
    severity_assessment: Optional[str] = None
    summary_text: Optional[str] = None
    llm_model_used: Optional[str] = None
    tokens_used: Optional[int] = None
    duration_ms: Optional[int] = None
    prompt_template_id: Optional[int] = None
    created_at: Optional[str] = None
    completed_at: Optional[str] = None
    recommended_actions: Optional[Any] = None
    ioc_snapshot: Optional[Any] = None


def _iso(v: Optional[datetime]) -> Optional[str]:
    return v.isoformat() if v else None


def _maybe_json(raw: Optional[str]) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw


def _inv_to_summary(inv) -> InvestigationSummary:
    return InvestigationSummary(
        id=inv.id,
        alert_id_ref=inv.alert_id_ref,
        alert_signature=inv.alert_signature,
        host=inv.host,
        source_ip=inv.source_ip,
        user_name=inv.user_name,
        status=inv.status,
        verdict=inv.verdict,
        severity_assessment=inv.severity_assessment,
        summary_text=inv.summary_text,
        llm_model_used=inv.llm_model_used,
        tokens_used=inv.tokens_used,
        duration_ms=inv.duration_ms,
        prompt_template_id=inv.prompt_template_id,
        created_at=_iso(inv.created_at),
        completed_at=_iso(inv.completed_at),
        recommended_actions=_maybe_json(inv.recommended_actions_json),
        ioc_snapshot=_maybe_json(inv.ioc_snapshot_json),
    )


# ---------------------------------------------------------------------------
# Background-task helper
# ---------------------------------------------------------------------------


def _spawn_investigation(alert_id: str, force: bool, triggered_by: str) -> None:
    """Kick an investigation off in the background. Never raises."""
    service = get_investigation_service()

    async def _runner() -> None:
        try:
            await service.investigate_alert(
                alert_id=alert_id, force=force, triggered_by=triggered_by,
            )
        except InvestigationError as exc:
            logger.info("Investigation for %s stopped: %s", alert_id, exc)
        except Exception as exc:  # pragma: no cover — defensive
            logger.exception("Investigation for %s crashed: %s", alert_id, exc)

    try:
        asyncio.create_task(_runner())
    except RuntimeError:
        # No running loop (unlikely in FastAPI) — run in a throwaway loop.
        try:
            asyncio.run(_runner())
        except Exception:
            pass


def _spawn_sweep(force: bool = False) -> None:
    """Kick a full sweep off in the background. Never raises."""
    service = get_investigation_service()

    async def _runner() -> None:
        try:
            result = await service.investigate_open_alerts_sweep(force=force)
            logger.info("Manual sweep complete: %s", result)
        except Exception as exc:  # pragma: no cover — defensive
            logger.exception("Manual sweep crashed: %s", exc)

    try:
        asyncio.create_task(_runner())
    except RuntimeError:
        try:
            asyncio.run(_runner())
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Trigger endpoints
# ---------------------------------------------------------------------------


@router.post("/api/investigate", response_model=InvestigateResponse)
async def trigger_investigation(
    payload: InvestigateRequest,
    user: User = Depends(require_permission("alert:triage")),
) -> InvestigateResponse:
    """Queue an autonomous investigation for a single alert.

    If ``force=false`` (default) and a completed/running investigation
    already exists for this alert id, the existing row is returned
    immediately without spawning a new run.
    """
    service = get_investigation_service()

    # Fast path: existing row when not forcing.
    if not payload.force:
        existing = service._find_recent_investigation(payload.alert_id)
        if existing is not None:
            return InvestigateResponse(
                investigation_id=existing.id,
                queued=False,
                status=existing.status,
                note="Existing investigation found; pass force=true to re-run.",
            )

    _spawn_investigation(
        alert_id=payload.alert_id,
        force=payload.force,
        triggered_by=f"user:{user.id}",
    )
    return InvestigateResponse(
        investigation_id=None,
        queued=True,
        status="queued",
        note="Investigation scheduled — poll /api/investigate/jobs for progress.",
    )


@router.post("/api/investigate/sweep", response_model=SweepResponse)
async def trigger_sweep(
    force: bool = False,
    user: User = Depends(require_permission("alert:triage")),
) -> SweepResponse:
    """Trigger an out-of-band sweep of open alerts.

    Pass ``?force=true`` to re-investigate alerts even when an existing
    investigation record (or ``ion.investigation_id`` ES flag) exists.
    """
    _spawn_sweep(force=force)
    return SweepResponse(
        started=True,
        note="Sweep dispatched — poll /api/investigate/jobs for progress.",
    )


# ---------------------------------------------------------------------------
# Read endpoints
# ---------------------------------------------------------------------------


@router.get("/api/investigate/jobs")
async def list_jobs(
    user: User = Depends(require_permission("alert:read")),
) -> dict:
    """List currently running / pending jobs + the last 20 completed runs."""
    memory = get_investigation_memory_service()

    # Pending + running — newest first
    active = memory.list_investigations(
        filters={"status": "running"}, limit=50
    )
    pending = memory.list_investigations(
        filters={"status": "pending"}, limit=50
    )
    completed = memory.list_investigations(
        filters={"status": "completed"}, limit=20
    )
    failed = memory.list_investigations(
        filters={"status": "failed"}, limit=10
    )

    return {
        "running":   [_inv_to_summary(r).model_dump() for r in active],
        "pending":   [_inv_to_summary(r).model_dump() for r in pending],
        "completed": [_inv_to_summary(r).model_dump() for r in completed],
        "failed":    [_inv_to_summary(r).model_dump() for r in failed],
    }


@router.get("/api/investigate/jobs/{inv_id}", response_model=InvestigationSummary)
async def get_job(
    inv_id: int,
    user: User = Depends(require_permission("alert:read")),
) -> InvestigationSummary:
    """Fetch a single investigation row."""
    memory = get_investigation_memory_service()
    inv = memory.get_investigation(inv_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return _inv_to_summary(inv)


# ---------------------------------------------------------------------------
# Queue control (v0.23.1) — pause/resume + cancel-pending + per-row cancel
# ---------------------------------------------------------------------------


class LoopStatusResponse(BaseModel):
    paused: bool
    updated_at: Optional[str] = None
    updated_by_id: Optional[int] = None


class CancelResponse(BaseModel):
    cancelled_count: int


@router.get("/api/investigate/loop/status", response_model=LoopStatusResponse)
async def get_loop_status(
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
) -> LoopStatusResponse:
    """Return whether the investigation sweep loop is currently paused."""
    meta = system_flags.get_flag_metadata(
        session, system_flags.INVESTIGATION_LOOP_PAUSED
    )
    return LoopStatusResponse(
        paused=system_flags.is_truthy(meta.get("value")),
        updated_at=meta.get("updated_at"),
        updated_by_id=meta.get("updated_by_id"),
    )


@router.post("/api/investigate/loop/pause", response_model=LoopStatusResponse)
async def pause_loop(
    user: User = Depends(require_permission("alert:triage")),
    session: Session = Depends(get_db_session),
) -> LoopStatusResponse:
    """Pause the sweep loop — next iteration returns without fetching alerts.

    Pending investigations already in the database remain; bulk-cancel
    them via ``POST /api/investigate/jobs/cancel-pending`` if needed.
    """
    system_flags.set_flag(
        session, system_flags.INVESTIGATION_LOOP_PAUSED, "true",
        user_id=user.id,
    )
    session.commit()
    meta = system_flags.get_flag_metadata(
        session, system_flags.INVESTIGATION_LOOP_PAUSED
    )
    logger.info("Investigation sweep loop paused by user_id=%s", user.id)
    return LoopStatusResponse(
        paused=True,
        updated_at=meta.get("updated_at"),
        updated_by_id=meta.get("updated_by_id"),
    )


@router.post("/api/investigate/loop/resume", response_model=LoopStatusResponse)
async def resume_loop(
    user: User = Depends(require_permission("alert:triage")),
    session: Session = Depends(get_db_session),
) -> LoopStatusResponse:
    """Resume the sweep loop — clear the pause flag."""
    system_flags.clear_flag(session, system_flags.INVESTIGATION_LOOP_PAUSED)
    session.commit()
    logger.info("Investigation sweep loop resumed by user_id=%s", user.id)
    return LoopStatusResponse(paused=False)


@router.post(
    "/api/investigate/jobs/cancel-pending",
    response_model=CancelResponse,
)
async def cancel_all_pending(
    user: User = Depends(require_permission("alert:triage")),
    session: Session = Depends(get_db_session),
) -> CancelResponse:
    """Bulk-cancel every pending investigation (sweep will skip them next pass).

    Idempotent: a second call cancels zero rows. Running investigations are
    left alone — they will complete or fail on their own; cancel them
    individually via the per-row endpoint if needed.
    """
    result = session.execute(
        text(
            "UPDATE investigations SET status = 'cancelled', "
            "completed_at = CURRENT_TIMESTAMP "
            "WHERE status = 'pending'"
        ),
    )
    session.commit()
    count = result.rowcount or 0
    logger.info(
        "Bulk-cancelled %d pending investigation(s) by user_id=%s",
        count, user.id,
    )
    return CancelResponse(cancelled_count=count)


@router.post(
    "/api/investigate/jobs/{inv_id}/cancel",
    response_model=CancelResponse,
)
async def cancel_one(
    inv_id: int,
    user: User = Depends(require_permission("alert:triage")),
    session: Session = Depends(get_db_session),
) -> CancelResponse:
    """Cancel a single pending or running investigation.

    Returns ``{cancelled_count: 1}`` on success, ``{cancelled_count: 0}`` if
    the row was already terminal (completed/failed/cancelled). 404 if the
    investigation id does not exist.
    """
    existing = session.execute(
        text("SELECT id, status FROM investigations WHERE id = :id"),
        {"id": inv_id},
    ).fetchone()
    if existing is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    result = session.execute(
        text(
            "UPDATE investigations SET status = 'cancelled', "
            "completed_at = CURRENT_TIMESTAMP "
            "WHERE id = :id AND status IN ('pending', 'running')"
        ),
        {"id": inv_id},
    )
    session.commit()
    count = result.rowcount or 0
    if count:
        logger.info(
            "Cancelled investigation id=%d (was %s) by user_id=%s",
            inv_id, existing[1], user.id,
        )
    return CancelResponse(cancelled_count=count)


# ---------------------------------------------------------------------------
# HTML page
# ---------------------------------------------------------------------------


@router.get("/investigate", response_class=HTMLResponse)
async def investigation_queue_page(
    request: Request,
    user: User = Depends(require_page_auth),
) -> HTMLResponse:
    """Render the running-jobs dashboard."""
    return templates.TemplateResponse(
        request=request, name="investigation_queue.html",
    )
