"""Case sync diagnostics and response action fragments."""

from __future__ import annotations

import json
import logging
from typing import Literal, TypedDict

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web import integration_api, response_api
from ion.web.ui._shared import instant_label, render_view, rows

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(require_permission("case:read"))])

APPLIES = {
    "ip": ("block_ip",),
    "ipv4": ("block_ip",),
    "ipv6": ("block_ip",),
    "domain": ("block_domain",),
    "url": ("block_domain",),
    "user": ("disable_account", "reset_password"),
    "username": ("disable_account", "reset_password"),
    "host": ("quarantine_host",),
    "hostname": ("quarantine_host",),
    "email": ("block_sender",),
}


class SyncRow(TypedDict):
    target: str | None
    operation: str | None
    error: str | None
    abandoned: bool
    retry_at: str | None
    attempts: int | None
    remaining: int | None


class SyncView(TypedDict):
    state: Literal["failed", "empty", "data"]
    abandoned_count: int | None
    retrying_count: int | None
    items: list[SyncRow] | None


class ResponseAction(TypedDict):
    id: int
    name: str | None
    approval: bool


class ObservableActions(TypedDict):
    type: str
    value: str
    actions: list[ResponseAction]


class ResponseActionsView(TypedDict):
    state: Literal["failed", "empty", "data", "disabled"]
    case_id: int
    items: list[ObservableActions] | None
    can_execute: bool


class ResponseLogRow(TypedDict):
    status: str | None
    action_type: str | None
    target: str | None
    dry_run: bool


class ResponseLogView(TypedDict):
    state: Literal["failed", "empty", "data", "disabled"]
    items: list[ResponseLogRow] | None


def text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def sync_view(payload: object) -> SyncView:
    view: SyncView = {"state": "failed", "abandoned_count": None, "retrying_count": None, "items": None}
    unresolved = rows(payload, "unresolved")
    if not isinstance(payload, dict):
        return view
    abandoned = count(payload.get("abandoned_count"))
    retrying = count(payload.get("retrying_count"))
    problems = payload.get("has_problems")
    if unresolved is None or abandoned is None or retrying is None or not isinstance(problems, bool) or any(not isinstance(row, dict) for row in unresolved):
        return view
    if problems != bool(unresolved) or len(unresolved) != abandoned + retrying:
        return view
    items: list[SyncRow] = []
    for row in unresolved:
        items.append(
            {
                "target": text(row.get("target")),
                "operation": text(row.get("operation")).replace("_", " ") if text(row.get("operation")) else None,
                "error": text(row.get("last_error")),
                "abandoned": row.get("status") == "abandoned",
                "retry_at": instant_label(row.get("next_retry_at")),
                "attempts": count(row.get("attempt_count")),
                "remaining": count(row.get("attempts_remaining")),
            }
        )
    return {"state": "data" if unresolved else "empty", "abandoned_count": abandoned, "retrying_count": retrying, "items": items}


def response_actions_view(payload: object, observables: object, case_id: int, can_execute: bool, enabled: bool) -> ResponseActionsView:
    view: ResponseActionsView = {"state": "failed" if enabled else "disabled", "case_id": case_id, "items": None, "can_execute": can_execute}
    catalogue = rows(payload, "actions")
    if not enabled or catalogue is None or not isinstance(observables, list) or any(not isinstance(row, dict) for row in catalogue + observables):
        return view
    by_type = {}
    for action in catalogue:
        action_id = count(action.get("id"))
        action_type = text(action.get("action_type"))
        if action_id is None or action_type is None:
            return view
        by_type[action_type] = {"id": action_id, "name": text(action.get("name")), "approval": action.get("requires_approval") is True}
    items: list[ObservableActions] = []
    seen: set[tuple[str, str]] = set()
    for observable in observables:
        kind, value = text(observable.get("type")), text(observable.get("value"))
        if kind is None or value is None:
            return view
        if (kind, value) in seen:
            continue
        seen.add((kind, value))
        applicable = [by_type[action_type] for action_type in APPLIES.get(kind.lower(), ()) if action_type in by_type]
        if applicable:
            items.append({"type": kind, "value": value, "actions": applicable})
    return {"state": "data" if items else "empty", "case_id": case_id, "items": items, "can_execute": can_execute}


def response_log_view(payload: object, enabled: bool) -> ResponseLogView:
    records = rows(payload, "log")
    if not enabled:
        return {"state": "disabled", "items": None}
    if records is None or any(not isinstance(row, dict) for row in records):
        return {"state": "failed", "items": None}
    items: list[ResponseLogRow] = [
        {
            "status": text(row.get("status")),
            "action_type": text(row.get("action_type")),
            "target": text(row.get("target")),
            "dry_run": isinstance(row.get("result"), dict) and row["result"].get("dry_run") is True,
        }
        for row in records
    ]
    return {"state": "data" if items else "empty", "items": items}


@router.get("/cases/{case_id}/sync-status", response_class=HTMLResponse)
def case_sync_status(case_id: int, request: Request, user=Depends(integration_api.require_integration_access), session: Session = Depends(get_db_session)):
    try:
        payload = integration_api.get_case_sync_journal(case_id=case_id, session=session)
    except Exception:
        logger.warning("Case sync status read failed", exc_info=True)
        payload = None
    return render_view(request, "_fragments/cases_detail_sync.html", sync_view(payload))


@router.post("/cases/{case_id}/response-actions", response_class=HTMLResponse)
def case_response_actions(case_id: int, request: Request, observables: str = Form("null"), user=Depends(require_permission("playbook:read")), session: Session = Depends(get_db_session)):
    enabled = response_api.response_actions_enabled()
    payload = None
    if enabled:
        try:
            payload = response_api.list_actions(_user=user, session=session)
        except Exception:
            logger.warning("Case response actions read failed", exc_info=True)
    try:
        decoded_observables = json.loads(observables)
    except (ValueError, TypeError):
        decoded_observables = None
    return render_view(request, "_fragments/cases_detail_response_actions.html", response_actions_view(payload, decoded_observables, case_id, user.has_permission("playbook:execute"), enabled))


@router.get("/cases/{case_id}/response-log", response_class=HTMLResponse)
def case_response_log(case_id: int, request: Request, user=Depends(require_permission("playbook:read")), session: Session = Depends(get_db_session)):
    enabled = response_api.response_actions_enabled()
    payload = None
    if enabled:
        try:
            payload = response_api.response_action_log(limit=100, case_id=case_id, _user=user, session=session)
        except Exception:
            logger.warning("Case response action log read failed", exc_info=True)
    return render_view(request, "_fragments/cases_detail_response_log.html", response_log_view(payload, enabled))
