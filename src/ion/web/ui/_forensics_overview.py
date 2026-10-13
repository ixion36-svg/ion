"""Forensic overview and independently authorized analyst options."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Literal, TypedDict

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web import forensics_api
from ion.web.api import users_list_payload
from ion.web.ui._shared import parse_instant, render_view, rows

logger = logging.getLogger(__name__)
router = APIRouter()
PERMISSION = require_permission('forensic:read')
State = Literal['failed', 'empty', 'data']
STAGES = ('intake','evidence_collection','analysis','reporting','review','closed')


class OverviewPanel(TypedDict):
    state: State
    cases: list[dict[str, Any]] | None
    all_cases: list[dict[str, Any]] | None
    metrics: dict[str, int | None]
    stages: list[dict[str, Any]]


class OptionsPanel(TypedDict):
    enums: dict[str, Any] | None
    enums_state: State
    playbooks: list[dict[str, Any]] | None
    playbooks_state: State
    users: list[dict[str, Any]] | None
    users_state: Literal['withheld','failed','empty','data']
    can_create: bool
    can_update: bool
    can_close: bool
    can_manage_playbooks: bool


class OverduePanel(TypedDict):
    state: State
    total: int | None


def _read(fn, **kwargs):
    try:
        return fn(**kwargs)
    except Exception:
        logger.exception('Could not read forensic overview data')
        return None


def _records(payload: object) -> list[dict[str, Any]] | None:
    found = rows({'items':payload}, 'items')
    return found if found is not None and all(isinstance(item, dict) for item in found) else None


def _state(payload: object) -> State:
    return 'failed' if payload is None else 'data' if payload else 'empty'


def _sla(case: dict[str, Any]) -> str:
    if case.get('status') == 'closed':
        return 'met'
    now = datetime.now(timezone.utc)
    result = 'unknown'
    for name in ('initial_response','evidence_collection','analysis','reporting'):
        due = parse_instant(case.get('sla_' + name + '_due'))
        met_key = 'sla_' + name + '_met'
        met = case.get(met_key)
        if due is None:
            continue
        if parse_instant(met) is not None:
            if result == 'unknown': result = 'on_track'
            continue
        if met_key not in case or met is not None:
            continue
        if due < now:
            return 'breached'
        created = parse_instant(case.get('created_at'))
        if created is not None and (due-created).total_seconds() > 0 and (due-now).total_seconds() / (due-created).total_seconds() < .25:
            result = 'at_risk'
        elif result == 'unknown':
            result = 'on_track'
    return result


def _case(case: dict[str, Any]) -> dict[str, Any]:
    total, done = case.get('step_count'), case.get('steps_completed')
    progress = round(done / total * 100) if isinstance(total, int) and isinstance(done, int) and total > 0 else 0 if total == 0 and done == 0 else None
    return {**case, 'progress':progress, 'sla':_sla(case)}


@router.get('/forensics/overview', response_class=HTMLResponse)
def overview(request:Request, status:str|None=None, investigation_type:str|None=None, priority:str|None=None,
             search:str='', user=Depends(PERMISSION), session:Session=Depends(get_db_session)):
    records = _records(_read(forensics_api.list_cases,status=status,investigation_type=investigation_type,priority=priority,lead_investigator_id=None,user=user,session=session))
    cases = [_case(case) for case in records] if records is not None else None
    statuses_known = cases is not None and all(case.get('status') in STAGES for case in cases)
    metrics = {
        'intake':sum(case.get('status') == 'intake' for case in cases) if statuses_known else None,
        'active':sum(case.get('status') not in ('intake','closed') for case in cases) if statuses_known else None,
        'closed':sum(case.get('status') == 'closed' for case in cases) if statuses_known else None,
        'evidence':sum(case['evidence_count'] for case in cases) if cases is not None and all(isinstance(case.get('evidence_count'),int) for case in cases) else None,
        'locked':sum(case.get('is_locked') is True for case in cases) if cases is not None and all(case.get('is_locked') is not None for case in cases) else None,
    }
    stages = [{'name':stage,'total':sum(case.get('status') == stage for case in cases) if statuses_known else None,
               'cases':[case for case in cases if case.get('status') == stage] if statuses_known else None} for stage in STAGES]
    filtered = [case for case in cases if any(search.casefold() in str(case.get(key) or '').casefold()
                                              for key in ('case_number', 'title'))] if cases is not None else None
    view:OverviewPanel = {'state':_state(filtered),'cases':filtered,'all_cases':cases,'metrics':metrics,'stages':stages}
    return render_view(request,'_fragments/forensics_overview.html',view)


@router.get('/forensics/overdue', response_class=HTMLResponse)
def overdue(request:Request,user=Depends(PERMISSION),session:Session=Depends(get_db_session)):
    cases = _records(_read(forensics_api.get_overdue_cases,user=user,session=session))
    view:OverduePanel = {'state':_state(cases),'total':len(cases) if cases is not None else None}
    return render_view(request,'_fragments/forensics_overdue.html',view)


@router.get('/forensics/options', response_class=HTMLResponse)
def options(request:Request,user=Depends(PERMISSION),session:Session=Depends(get_db_session)):
    payload = _read(forensics_api.get_enums,user=user)
    enums = payload if isinstance(payload,dict) and all(isinstance(payload.get(key),list) for key in ('investigation_types','evidence_types','custody_actions','case_statuses')) else None
    playbooks = _records(_read(forensics_api.list_playbooks,active_only=True,investigation_type=None,user=user,session=session))
    users = _records(_read(users_list_payload,session=session,include_inactive=False)) if user.has_permission('user:read') else None
    view:OptionsPanel = {'enums':enums,'enums_state':_state(enums),'playbooks':playbooks,'playbooks_state':_state(playbooks),
                         'users':users,'users_state':_state(users) if user.has_permission('user:read') else 'withheld',
                         'can_create':user.has_permission('forensic:create'),'can_update':user.has_permission('forensic:update'),
                         'can_close':user.has_permission('forensic:close'),'can_manage_playbooks':user.has_permission('forensic:manage_playbooks')}
    return render_view(request,'_fragments/forensics_options.html',view)
