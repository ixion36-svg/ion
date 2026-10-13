"""Detection posture, gaps and spaces, without the separate DE licence gate."""
from __future__ import annotations

import logging
import math
from typing import Any, Literal, TypedDict

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web import de_tide_api
from ion.web.ui._shared import render_view, rows

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(require_permission('alert:read'))])
State = Literal['failed', 'unconfigured', 'empty', 'data']


class PosturePanel(TypedDict):
    state: State
    stats: dict[str, int | float | None]
    enabled_pct: int | None
    disabled_pct: int | None
    coverage_pct: int | None
    severity: list[dict[str, Any]] | None
    severity_total: int | float | None
    quality: list[dict[str, Any]] | None
    avg_quality: int | float | None
    disabled_critical: list[dict[str, Any]] | None


class GapsPanel(TypedDict):
    state: State
    total_blind_spots: int | float | None
    blind_spots_by_tactic: dict[str, list[dict[str, Any]]] | None
    unmapped_rules: list[dict[str, Any]] | None
    quick_wins: list[dict[str, Any]] | None
    systems_coverage: list[dict[str, Any]] | None


class SpacesView(TypedDict):
    state: Literal['failed', 'empty', 'data']
    spaces: list[dict[str, Any]] | None
    active: str | None


def _number(value: object) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value < 0 or isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _percent(value: object, total: object) -> int | None:
    value, total = _number(value), _number(total)
    if value is None or total is None:
        return None
    if total == 0:
        return 0 if value == 0 else None
    return round(value / total * 100)


def _records(payload: object, key: str) -> list[dict[str, Any]] | None:
    found = rows(payload, key)
    return found if found is not None and all(isinstance(item, dict) for item in found) else None


def _severity(payload: object) -> tuple[list[dict[str, Any]] | None, int | float | None]:
    if not isinstance(payload, dict):
        return None, None
    result = []
    for key in ('critical', 'high', 'medium', 'low'):
        counts = payload.get(key, {'total':0, 'enabled':0, 'disabled':0})
        if not isinstance(counts, dict):
            counts = {}
        result.append({'key':key, **{name:_number(counts.get(name)) for name in ('total','enabled','disabled')}})
    total = sum(item['total'] for item in result) if all(item['total'] is not None for item in result) else None
    position = 0.0
    for item in result:
        item['start'] = position if total is not None else None
        if total:
            position += item['total'] / total * 100
        item['end'] = position if total is not None else None
    return result, total


@router.get('/detection-engineering/posture', response_class=HTMLResponse)
def posture(request: Request, session: Session = Depends(get_db_session)):
    payload = None
    disabled = None
    try:
        payload = de_tide_api.tide_de_posture(session=session)
    except Exception:
        logger.exception('Could not read detection posture')
    data = payload if isinstance(payload, dict) else {}
    configured = data.get('enabled')
    if configured is True:
        try:
            result = de_tide_api.tide_de_disabled_critical(session=session)
            disabled = _records({'rows':result}, 'rows')
        except Exception:
            logger.exception('Could not read disabled critical rules')
    stats = {key:_number(data.get(key)) for key in ('total_rules','enabled_rules','disabled_rules','covered_techniques','total_techniques','unmapped_rules','total_systems')}
    severity, severity_total = _severity(data.get('severity'))
    quality_payload = data.get('quality')
    quality = None
    if isinstance(quality_payload, dict):
        quality = [{'key':key, 'count':_number(quality_payload.get(key)), 'percentage':_percent(quality_payload.get(key),stats['total_rules'])} for key in ('excellent','good','fair','poor')]
    view: PosturePanel = {
        'state':'failed' if not isinstance(configured, bool) else 'unconfigured' if not configured else 'empty' if stats['total_rules'] == 0 else 'data',
        'stats':stats, 'enabled_pct':_percent(stats['enabled_rules'],stats['total_rules']),
        'disabled_pct':_percent(stats['disabled_rules'],stats['total_rules']),
        'coverage_pct':_percent(stats['covered_techniques'],stats['total_techniques']) if stats['total_techniques'] else None,
        'severity':severity, 'severity_total':severity_total, 'quality':quality,
        'avg_quality':_number(quality_payload.get('avg_quality')) if isinstance(quality_payload,dict) else None,
        'disabled_critical':disabled,
    }
    return render_view(request, '_fragments/detection_engineering_posture.html', view)


@router.get('/detection-engineering/gaps', response_class=HTMLResponse)
def gaps(request: Request, session: Session = Depends(get_db_session)):
    payload = None
    try:
        payload = de_tide_api.tide_de_gaps(session=session)
    except Exception:
        logger.exception('Could not read detection gaps')
    data = payload if isinstance(payload,dict) else {}
    tactics = data.get('blind_spots_by_tactic')
    if not isinstance(tactics,dict) or not all(isinstance(value,list) and all(isinstance(item,dict) for item in value) for value in tactics.values()):
        tactics = None
    elif tactics:
        tactics = dict(sorted(tactics.items(),key=lambda item:len(item[1]), reverse=True))
    unmapped = _records(data,'unmapped_rules')
    wins = _records(data,'quick_wins')
    systems = _records(data,'systems_coverage')
    total = _number(data.get('total_blind_spots'))
    configured = data.get('enabled')
    empty = total == 0 and tactics == {} and unmapped == [] and wins == [] and systems == []
    view: GapsPanel = {
        'state':'failed' if not isinstance(configured,bool) else 'unconfigured' if not configured else 'empty' if empty else 'data',
        'total_blind_spots':total, 'blind_spots_by_tactic':tactics,
        'unmapped_rules':unmapped,'quick_wins':wins,'systems_coverage':systems,
    }
    return render_view(request, '_fragments/detection_engineering_gaps.html', view)


@router.get('/detection-engineering/spaces', response_class=HTMLResponse)
def spaces(request: Request):
    payload = None
    try:
        payload = de_tide_api.tide_de_spaces()
    except Exception:
        logger.exception('Could not read TIDE spaces')
    found = _records(payload,'spaces')
    if found is not None and not all(isinstance(item.get('space'),str) and item['space'] for item in found):
        found = None
    active = payload.get('active') if isinstance(payload,dict) else None
    view: SpacesView = {
        'state':'failed' if found is None else 'data' if found else 'empty',
        'spaces':found,'active':active if isinstance(active,str) else None,
    }
    return render_view(request, '_fragments/detection_engineering_spaces.html', view)
