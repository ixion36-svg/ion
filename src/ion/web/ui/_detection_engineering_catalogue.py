"""Catalogue panels mirror ungated alert:read APIs; mutation controls need triage."""
from __future__ import annotations

import logging
from typing import Any, Literal, TypedDict

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.services import emulation_service, vulnerability_service
from ion.services.d3fend_service import get_d3fend_coverage
from ion.storage.database import get_db_session
from ion.web.ui._shared import render_view, rows

logger = logging.getLogger(__name__)
router = APIRouter()


class D3fendPanel(TypedDict):
    state: Literal['failed', 'empty', 'data']
    summary: dict[str, Any]
    tactics: list[dict[str, Any]] | None
    techniques: list[dict[str, Any]] | None


class VulnsPanel(TypedDict):
    state: Literal['failed', 'empty', 'data']
    summary: dict[str, Any]
    vulnerabilities: list[dict[str, Any]] | None
    can_edit: bool






def _state(items: list | None) -> Literal['failed', 'empty', 'data']:
    return 'failed' if items is None else 'data' if items else 'empty'


def _records(payload: object, key: str) -> list[dict[str, Any]] | None:
    result = rows(payload, key)
    return result if result is not None and all(isinstance(row, dict) for row in result) else None


@router.get('/detection-engineering/d3fend', response_class=HTMLResponse)
def d3fend(request: Request, current_user: User = Depends(require_permission('alert:read'))):
    payload = None
    try:
        payload = get_d3fend_coverage()
    except Exception:
        logger.exception('Could not read defensive coverage')
    data = payload if isinstance(payload, dict) and not payload.get('error') else {}
    tactics, techniques = _records(data, 'tactics'), _records(data, 'techniques')
    view: D3fendPanel = {'state': 'failed' if techniques is None else _state(tactics),
                         'summary': data.get('summary') if isinstance(data.get('summary'), dict) else {},
                         'tactics': tactics, 'techniques': techniques}
    return render_view(request, '_fragments/detection_engineering_d3fend.html', view)


@router.get('/detection-engineering/vulns', response_class=HTMLResponse)
def vulns(request: Request, current_user: User = Depends(require_permission('alert:read')),
          session: Session = Depends(get_db_session)):
    payload = None
    try:
        payload = vulnerability_service.coverage_overview(session)
    except Exception:
        logger.exception('Could not read vulnerability coverage')
    data = payload if isinstance(payload, dict) and not payload.get('error') else {}
    items = _records(data, 'vulnerabilities')
    view: VulnsPanel = {'state': _state(items), 'vulnerabilities': items,
                        'summary': data.get('summary') if isinstance(data.get('summary'), dict) else {},
                        'can_edit': current_user.has_permission('alert:triage')}
    return render_view(request, '_fragments/detection_engineering_vulns.html', view)




