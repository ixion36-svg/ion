"""Execution and actor readiness reads; alert:read, without a module gate."""
from __future__ import annotations

import logging
import math
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


class ExecutionView(TypedDict):
    state: Literal['failed', 'empty', 'data']
    error: str | None
    hours: int
    summary: dict[str, Any] | None
    timeline: list[dict[str, Any]] | None
    severity_timeline: list[dict[str, Any]] | None
    top_firing: list[dict[str, Any]] | None
    noisy_rules: list[dict[str, Any]] | None
    silent_rules: list[dict[str, Any]] | None
    volume_max: float
    severity_max: float
    open_pct: int | None
    volume_incomplete: bool
    severity_incomplete: bool


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


def _measurement(value: Any) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value if value >= 0 and math.isfinite(value) else None


def _chart_rows(payload: Any, key: str, fields: tuple[str, ...]) -> list[dict[str, Any]] | None:
    found = rows(payload, key)
    if found is None or any(not isinstance(row, dict) for row in found):
        return None
    return [{**row, **{field: _measurement(row.get(field)) for field in fields}} for row in found]


@router.get('/detection-engineering/execution', response_class=HTMLResponse)
async def execution(request: Request, hours: int = 168):
    data = None
    try:
        data = await de_tide_api.tide_de_execution(hours=hours)
    except Exception:
        logger.exception('Could not read execution metrics')
    error = _error(data, 'Failed to load execution metrics')
    summary = data.get('summary') if isinstance(data, dict) else None
    if not isinstance(summary, dict):
        summary = None
        error = error or 'Failed to load execution metrics'
    timeline = _chart_rows(data, 'timeline', ('count',))
    severities = ('critical', 'high', 'medium', 'low')
    severity_timeline = _chart_rows(data, 'severity_timeline', severities)
    volume_max = max([t['count'] for t in timeline or [] if t['count'] is not None] + [1])
    severity_max = max([sum(t[s] for s in severities if t[s] is not None) for t in severity_timeline or []] + [1])
    total = _measurement(summary.get('total_alerts')) if summary is not None else None
    status = summary.get('status') if summary is not None else None
    opened = _measurement(status.get('open')) if isinstance(status, dict) else None
    open_pct = round(opened / total * 100) if total and opened is not None else 0 if total == 0 and opened is not None else None
    view: ExecutionView = {
        'state': 'failed' if error else 'empty' if total == 0 else 'data', 'error': error, 'hours': min(hours, 720), 'summary': summary,
        'timeline': timeline, 'severity_timeline': severity_timeline, 'top_firing': rows(data, 'top_firing'),
        'noisy_rules': rows(data, 'noisy_rules'), 'silent_rules': rows(data, 'silent_rules'),
        'volume_max': volume_max, 'severity_max': severity_max, 'open_pct': open_pct,
        'volume_incomplete': any(t['count'] is None for t in timeline or []),
        'severity_incomplete': any(t[s] is None for t in severity_timeline or [] for s in severities),
    }
    return render_view(request, '_fragments/detection_engineering_execution.html', view)


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
