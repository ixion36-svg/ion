"""Read-only observable analysis panels, matching their JSON permissions."""
from __future__ import annotations

import logging
from typing import Any, Literal, TypedDict

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.services.observable_service import ObservableService
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, render_view, rows

router = APIRouter()
logger = logging.getLogger(__name__)
State = Literal['failed', 'empty', 'data']


class GraphPanel(TypedDict):
    state: State
    graph: dict[str, Any] | None


class PatternsPanel(TypedDict):
    state: State
    patterns: list[dict[str, Any]] | None


class TimelinePanel(TypedDict):
    state: State
    events: list[dict[str, Any]] | None


class HeatmapPanel(TypedDict):
    state: State
    heatmap: dict[str, int] | None


class TimelineInfo(TypedDict):
    state: State
    observable: dict[str, Any] | None


def _state(items: object) -> State:
    return 'failed' if items is None else 'data' if items else 'empty'


def _records(items: object) -> list[dict[str, Any]] | None:
    records = rows({'items': items}, 'items')
    return records if records is not None and all(isinstance(item, dict) for item in records) else None


@router.get('/observables/graph', response_class=HTMLResponse)
def graph(request: Request, observable_id: int | None = None,
          limit: int = Query(100, ge=10, le=500), min_co_occurrence: int = Query(2, ge=1, le=100),
          session: Session = Depends(get_db_session), user: User = Depends(require_permission('observable:read'))):
    payload = None
    try:
        candidate = ObservableService(session).get_relationship_graph(observable_id=observable_id, limit=limit, min_co_occurrence=min_co_occurrence)
        if isinstance(candidate, dict) and _records(candidate.get('nodes')) is not None and _records(candidate.get('edges')) is not None:
            payload = candidate
    except Exception:
        logger.exception('Could not read observable graph')
    view: GraphPanel = {'state': _state(payload['nodes'] if payload is not None else None), 'graph': payload}
    return render_view(request, '_fragments/observables_analysis_graph.html', view)


@router.get('/observables/patterns', response_class=HTMLResponse)
def patterns(request: Request, min_occurrences: int = Query(3, ge=2, le=100),
             session: Session = Depends(get_db_session), user: User = Depends(require_permission('observable:read'))):
    items = None
    try:
        items = _records(ObservableService(session).detect_patterns(time_window_minutes=60, min_occurrences=min_occurrences, limit=20))
        if items is not None and any(_records(item.get('observables')) is None for item in items):
            items = None
    except Exception:
        logger.exception('Could not read observable patterns')
    view: PatternsPanel = {'state': _state(items), 'patterns': items}
    return render_view(request, '_fragments/observables_analysis_patterns.html', view)


@router.get('/observables/{observable_id}/timeline', response_class=HTMLResponse)
def timeline(request: Request, observable_id: int,
             session: Session = Depends(get_db_session), user: User = Depends(require_permission('observable:read'))):
    items = None
    try:
        service = ObservableService(session)
        if service.get_by_id(observable_id) is not None:
            items = _records(service.get_timeline(observable_id, limit=50))
    except Exception:
        logger.exception('Could not read observable timeline')
    view: TimelinePanel = {'state': _state(items), 'events': items}
    return render_view(request, '_fragments/observables_analysis_timeline.html', view)


@router.get('/observables/{observable_id}/heatmap', response_class=HTMLResponse)
def heatmap(request: Request, observable_id: int,
            session: Session = Depends(get_db_session), user: User = Depends(require_permission('observable:read'))):
    payload = None
    try:
        service = ObservableService(session)
        if service.get_by_id(observable_id) is not None:
            candidate = service.get_activity_heatmap(observable_id, days=30)
            if isinstance(candidate, dict) and all(isinstance(key, str) and isinstance(value, int) and value >= 0 for key, value in candidate.items()):
                payload = candidate
    except Exception:
        logger.exception('Could not read observable heatmap')
    view: HeatmapPanel = {'state': _state(payload), 'heatmap': payload}
    return render_view(request, '_fragments/observables_analysis_heatmap.html', view)


@router.get('/observables/{observable_id}/timeline-info', response_class=HTMLResponse)
def timeline_info(request: Request, observable_id: int,
                  session: Session = Depends(get_db_session), user: User = Depends(require_permission('observable:read'))):
    observable = None
    try:
        obs = ObservableService(session).get_by_id(observable_id)
        if obs is not None:
            observable = {key: plain(getattr(obs, key, None)) for key in ('type', 'value', 'sighting_count')}
            observable.update({key: str(getattr(obs, key)) if getattr(obs, key, None) is not None else None for key in ('first_seen', 'last_seen')})
    except Exception:
        logger.exception('Could not read observable timeline info')
    view: TimelineInfo = {'state': 'data' if observable is not None else 'failed', 'observable': observable}
    return render_view(request, '_fragments/observables_analysis_info.html', view)
