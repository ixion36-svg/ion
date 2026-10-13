"""Detection engineering rule, use-case and progression read fragments."""
from __future__ import annotations

import logging
from copy import deepcopy
from typing import Any, Literal, TypedDict

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web import de_tide_api
from ion.web.ui._shared import render_view, rows

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(require_permission('alert:read'))])
State = Literal['failed', 'empty', 'data']


class KillChainsView(TypedDict):
    state: State
    playbooks: list[dict[str, Any]] | None


class RulesView(TypedDict):
    state: State
    rules: list[dict[str, Any]] | None
    total: int | None
    offset: int
    limit: int




def _state(items: list | None) -> State:
    return 'failed' if items is None else 'data' if items else 'empty'


def _objects(items: object) -> list[dict[str, Any]] | None:
    return items if isinstance(items, list) and all(isinstance(item, dict) for item in items) else None


def _coverage(playbooks: list[dict[str, Any]] | None) -> None:
    if playbooks is None:
        return
    for playbook in playbooks:
        coverage = playbook.get('technique_coverage')
        for step in playbook.get('steps') or []:
            techniques = step.get('techniques')
            counts = [coverage.get(tid) for tid in techniques] if isinstance(coverage, dict) and isinstance(techniques, list) else None
            total = enabled = None
            if counts and all(isinstance(c, dict) and isinstance(c.get('rule_count'), (int, float)) and isinstance(c.get('enabled_rules'), (int, float)) for c in counts):
                total = sum(c['rule_count'] for c in counts)
                enabled = sum(c['enabled_rules'] for c in counts)
            step['rule_count'] = total
            step['enabled_rules'] = enabled
            step['coverage_state'] = 'unknown' if total is None else 'covered' if enabled > 0 else 'partial' if total > 0 else 'blind'


@router.get('/detection-engineering/killchains', response_class=HTMLResponse)
def killchains(request: Request, session: Session = Depends(get_db_session)):
    playbooks = None
    try:
        playbooks = _objects(deepcopy(de_tide_api.tide_de_use_cases(session=session)))
        _coverage(playbooks)
    except Exception:
        logger.exception('Could not read detection use cases')
        playbooks = None
    view: KillChainsView = {'state': _state(playbooks), 'playbooks': playbooks}
    return render_view(request, '_fragments/detection_engineering_killchains.html', view)


@router.get('/detection-engineering/rules', response_class=HTMLResponse)
def rules_panel(request: Request, search: str = '', severity: str = '', enabled: str = '',
                offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200)):
    rules = None
    total = None
    try:
        payload = de_tide_api.tide_de_rules(search=search, severity=severity, enabled=enabled, offset=offset, limit=limit)
        rules = _objects(rows(payload, 'rows'))
        total = payload.get('total') if isinstance(payload, dict) else None
    except Exception:
        logger.exception('Could not read detection rules')
    view: RulesView = {'state': _state(rules), 'rules': rules, 'total': total, 'offset': offset, 'limit': limit}
    return render_view(request, '_fragments/detection_engineering_rules.html', view)


