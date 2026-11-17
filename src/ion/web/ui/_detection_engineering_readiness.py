"""Actor and system readiness reads; alert:read, without a module gate."""
from __future__ import annotations

import logging
from typing import Any, Literal, TypedDict

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web import de_tide_api
from ion.web.ui._shared import render_view, rows

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(require_permission('alert:read'))])


class ReadinessView(TypedDict):
    state: Literal['failed', 'empty', 'data']
    error: str | None
    actors: list[dict[str, Any]] | None
    tide_covered_techniques: int | None
    tide_total_techniques: int | None


class ReadinessShellView(TypedDict):
    systems: list[dict[str, Any]] | None
    error: str | None


class SystemReadinessView(TypedDict):
    state: Literal['failed', 'data']
    error: str | None
    actor_id: str
    actor_type: str
    actor: dict[str, Any] | None
    system: dict[str, Any] | None
    readiness_pct: float | None
    covered_count: int | None
    gap_count: int | None
    total_ttps: int | None
    coverage_matrix: list[dict[str, Any]] | None
    ai_summary: str | None


def _error(payload: Any, fallback: str) -> str | None:
    if not isinstance(payload, dict) or payload.get('enabled') is not True:
        return str(payload.get('error') or fallback) if isinstance(payload, dict) else fallback
    return str(payload['error']) if payload.get('error') else None


@router.get('/detection-engineering/readiness', response_class=HTMLResponse)
def readiness_shell(request: Request, session: Session = Depends(get_db_session)):
    systems = None
    try:
        payload = de_tide_api.tide_de_systems(session=session)
        systems = payload if isinstance(payload, list) and all(isinstance(s, dict) and s.get('id') is not None for s in payload) else None
    except Exception:
        logger.exception('Could not read readiness systems')
    view: ReadinessShellView = {'systems': systems, 'error': 'Could not load systems' if systems is None else None}
    return render_view(request, '_fragments/detection_engineering_readiness_shell.html', view)


@router.get('/detection-engineering/readiness/actors', response_class=HTMLResponse)
async def readiness_actors(request: Request, search: str = ''):
    data = None
    try:
        data = await de_tide_api.tide_de_actor_readiness(search=search)
    except Exception:
        logger.exception('Could not read actor readiness')
    actors = rows(data, 'actors')
    error = _error(data, 'Failed to load actor readiness')
    if actors is None:
        error = error or 'Failed to load actor readiness'
    view: ReadinessView = {
        'state': 'failed' if error else 'data' if actors else 'empty', 'error': error, 'actors': actors,
        'tide_covered_techniques': data.get('tide_covered_techniques') if isinstance(data, dict) else None,
        'tide_total_techniques': data.get('tide_total_techniques') if isinstance(data, dict) else None,
    }
    return render_view(request, '_fragments/detection_engineering_readiness_actors.html', view)


@router.post('/detection-engineering/readiness/system', response_class=HTMLResponse)
async def system_readiness(request: Request, actor_id: str = Form(...), actor_type: str = Form('threat_actor'),
                           system_id: str | None = Form(None), session: Session = Depends(get_db_session)):
    data = None
    try:
        req = de_tide_api.ReadinessReportRequest(actor_id=actor_id, actor_type=actor_type, system_id=system_id, generate_ai=False)
        data = await de_tide_api.tide_de_system_readiness(req=req, session=session)
    except Exception:
        logger.exception('Could not assess system readiness')
    error = _error(data, 'Failed to assess system readiness')
    matrix = rows(data, 'coverage_matrix')
    actor = data.get('actor') if isinstance(data, dict) else None
    if matrix is None or not isinstance(actor, dict):
        error = error or 'Failed to assess system readiness'
    data = data if isinstance(data, dict) else {}
    view: SystemReadinessView = {
        'state': 'failed' if error else 'data', 'error': error, 'actor_id': actor_id, 'actor_type': actor_type,
        'actor': actor, 'system': data.get('system'), 'readiness_pct': data.get('readiness_pct'),
        'covered_count': data.get('covered_count'), 'gap_count': data.get('gap_count'), 'total_ttps': data.get('total_ttps'),
        'coverage_matrix': matrix, 'ai_summary': data.get('ai_summary'),
    }
    return render_view(request, '_fragments/detection_engineering_readiness_system.html', view)
