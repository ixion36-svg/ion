"""Bob Prompt Evaluation Harness API (v0.21.0).

Routes:
  POST   /api/bob-eval/runs           — start a new eval run
  GET    /api/bob-eval/runs           — list eval runs
  GET    /api/bob-eval/runs/{run_id}  — get single run + metrics
  GET    /api/bob-eval/runs/{run_id}/samples — paginated samples
  GET    /bob-eval                    — HTML page

Auth: system:settings permission required on all routes.
"""

from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.services.bob_eval_service import (
    _MAX_SAMPLE_SIZE,
    create_eval_run,
    get_eval_run,
    list_eval_run_samples,
    list_eval_runs,
    run_eval_async,
)
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["bob-eval"])

from ion.web._csp_nonce import _CSPNonceProxy as _CspNonceProxy  # noqa: E402
_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
_templates.env.globals["csp_nonce"] = _CspNonceProxy()
try:
    import ion as _ion_pkg
    _templates.env.globals["ion_version"] = _ion_pkg.__version__
except Exception:
    _templates.env.globals.setdefault("ion_version", "")

_SETTINGS_PERM = require_permission("system:settings")


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class CreateEvalRunRequest(BaseModel):
    template_id: Optional[int] = Field(None, description="NULL = evaluate all templates")
    sample_size: int = Field(50, ge=1, le=_MAX_SAMPLE_SIZE)


class CreateEvalRunResponse(BaseModel):
    run_id: int
    status: str
    estimated_seconds: int


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/api/bob-eval/runs",
    response_model=CreateEvalRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def start_eval_run(
    body: CreateEvalRunRequest,
    current_user: User = Depends(_SETTINGS_PERM),
    session: Session = Depends(get_db_session),
):
    """Create and asynchronously start a new eval run."""
    try:
        run = create_eval_run(
            template_id=body.template_id,
            sample_size=body.sample_size,
            triggered_by_id=current_user.id,
            session=session,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    run_eval_async(run.id)

    # Rough estimate: ~3s per Ollama call.
    estimated_seconds = body.sample_size * 3

    return CreateEvalRunResponse(
        run_id=run.id,
        status=run.status,
        estimated_seconds=estimated_seconds,
    )


@router.get("/api/bob-eval/runs")
def get_eval_runs(
    template_id: Optional[int] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(_SETTINGS_PERM),
    session: Session = Depends(get_db_session),
):
    """List eval runs, optionally filtered by template_id."""
    runs = list_eval_runs(template_id=template_id, limit=limit, session=session)
    return {"runs": [r.to_dict() for r in runs]}


@router.get("/api/bob-eval/runs/{run_id}")
def get_run(
    run_id: int,
    current_user: User = Depends(_SETTINGS_PERM),
    session: Session = Depends(get_db_session),
):
    """Get a single run with its metrics."""
    run = get_eval_run(run_id, session)
    if run is None:
        raise HTTPException(status_code=404, detail="Eval run not found")
    return run.to_dict()


@router.get("/api/bob-eval/runs/{run_id}/samples")
def get_run_samples(
    run_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: User = Depends(_SETTINGS_PERM),
    session: Session = Depends(get_db_session),
):
    """Paginated samples for a run."""
    run = get_eval_run(run_id, session)
    if run is None:
        raise HTTPException(status_code=404, detail="Eval run not found")

    offset = (page - 1) * page_size
    samples = list_eval_run_samples(run_id, limit=page_size, offset=offset, session=session)

    # Total count for pagination.
    from sqlalchemy import func

    from ion.models.bob_eval import BobEvalRunSample
    total = session.query(func.count(BobEvalRunSample.id)).filter(
        BobEvalRunSample.eval_run_id == run_id
    ).scalar() or 0

    # L5 (v0.22.1): reasoning_text is only emitted when ION_BOB_STORE_REASONING
    # is true at request time. v0.36.0 flips the default ON. Setting it back to
    # false stops emitting reasoning at the response layer even for rows that
    # were persisted while it was enabled — no back-fill purge required.
    # Shared single-source gate (see investigation_service) so persistence and
    # response-layer emission never disagree on the default.
    from ion.services.investigation_service import _bob_store_reasoning_enabled
    store_reasoning = _bob_store_reasoning_enabled()
    sample_dicts = []
    for s in samples:
        d = s.to_dict()
        if not store_reasoning:
            d.pop("reasoning_text", None)
        sample_dicts.append(d)

    return {
        "run_id": run_id,
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": max(1, math.ceil(total / page_size)),
        "samples": sample_dicts,
    }


# ---------------------------------------------------------------------------
# HTML page
# ---------------------------------------------------------------------------


@router.get("/bob-eval", response_class=HTMLResponse)
def bob_eval_page(
    request: Request,
    current_user: User = Depends(_SETTINGS_PERM),
    session: Session = Depends(get_db_session),
):
    """Bob Prompt Evaluation Harness page."""
    from ion.models.alert_prompt import AlertPromptTemplate
    templates_list = (
        session.query(AlertPromptTemplate)
        .filter(AlertPromptTemplate.enabled.is_(True))
        .order_by(AlertPromptTemplate.priority, AlertPromptTemplate.name)
        .all()
    )
    recent_runs = list_eval_runs(template_id=None, limit=20, session=session)

    # v0.26.1: rewrote from the legacy positional form
    # ``TemplateResponse("bob_eval.html", {...})`` which collided with
    # Starlette's modern signature ``TemplateResponse(request, name,
    # context, ...)`` — the dict was being interpreted as the ``name``
    # argument and failed downstream with "cannot use 'tuple' as a
    # dict key". Matches the kwargs convention used everywhere else
    # in the codebase (see course_api.py for examples).
    return _templates.TemplateResponse(
        request=request,
        name="bob_eval.html",
        context={
            "current_user": current_user,
            "templates_list": templates_list,
            "recent_runs": [r.to_dict() for r in recent_runs],
            "max_sample_size": _MAX_SAMPLE_SIZE,
        },
    )
