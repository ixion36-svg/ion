"""Playbooks: the library, one playbook, the step form, and executions.

The page script used to paint both tables from `data.playbooks || []` and
`data.executions || []`. A failed library fetch only toasted, so the table
stayed on "Loading playbooks..." or, once a bad payload was coerced into
an empty list, said "No playbooks found". The executions badge added
`in_progress + pending` with no type check, so a missing bucket became
NaN and the badge stayed hidden: the same picture as zero active work.

Executions are `playbook:execute`. Opening the page only needs
`playbook:read`, and read does not imply execute. A reader is told the
figures are withheld, and the executions API is not called. Rendering
them as zero, or as "no executions", would say the queue was quiet.

The enrich step rendered OpenCTI checked in both branches of its
ternary, so a saved step that had turned the source off still showed it
on. It is checked only for a new step, or when the saved sources list
contains it.

Calls into the JSON handlers are keyword-only. The tests replace those
handlers with fakes that accept `**kwargs` or named parameters, and a
positional argument would miss them.
"""
from __future__ import annotations

import json
import logging
import math
import re
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_any_permission, require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.api import (
    get_playbook,
    get_playbook_execution,
    list_playbook_executions,
    list_playbooks,
    playbook_executions_summary,
)
from ion.web.ui._shared import render_view, rows

logger = logging.getLogger(__name__)

router = APIRouter()

LIBRARY = "_fragments/playbooks_library.html"
VIEW = "_fragments/playbooks_view.html"
STEP = "_fragments/playbooks_step.html"
PARAMS = "_fragments/playbooks_step_params.html"
EXECUTIONS = "_fragments/playbooks_executions.html"
DETAIL = "_fragments/playbooks_execution.html"
BADGE = "_fragments/playbooks_badge.html"

READ = "playbook:read"
EXECUTE = "playbook:execute"
PAGE_OR_EXECUTE = ["playbook:read", "playbook:execute"]

_STEP_TYPES = (
    "manual_checklist",
    "auto_enrich_observables",
    "auto_update_status",
    "auto_create_case",
)
_STATUSES = ("investigating", "escalated", "contained", "resolved")
_PRIORITIES = ("low", "medium", "high", "critical")
_SEVERITIES = ("low", "medium", "high", "critical")
_SAFE_CLASS = re.compile(r"^[a-z0-9_-]+$")
_DONE = ("completed", "skipped")


def _is_int(value: object) -> bool:
    """A real integer. True is an int, and it is not a count of one."""
    return isinstance(value, int) and not isinstance(value, bool)


def _label(value: object) -> str:
    if not isinstance(value, str) or not value:
        return "unknown"
    return value.replace("_", " ")


def _class_name(value: object) -> str:
    if isinstance(value, str) and _SAFE_CLASS.fullmatch(value):
        return value
    return ""


def _snippet(description: object) -> Optional[str]:
    if not isinstance(description, str) or description == "":
        return None
    if len(description) > 50:
        return description[:50] + "..."
    return description


def _triggers(conditions: object) -> dict:
    """None means every alert. Anything that is not an object was not read."""
    if conditions is None:
        return {"state": "data", "labels": ["All alerts"]}
    if not isinstance(conditions, dict):
        return {"state": "unreadable", "labels": []}
    labels: list[str] = []
    severities = conditions.get("severities")
    if isinstance(severities, list) and severities:
        labels.append("Sev: " + ", ".join(str(item) for item in severities))
    patterns = conditions.get("rule_patterns")
    if isinstance(patterns, list) and patterns:
        labels.append(f"{len(patterns)} rule pattern(s)")
    techniques = conditions.get("mitre_techniques")
    if isinstance(techniques, list) and techniques:
        labels.append(f"{len(techniques)} MITRE technique(s)")
    tactics = conditions.get("mitre_tactics")
    if isinstance(tactics, list) and tactics:
        labels.append(f"{len(tactics)} MITRE tactic(s)")
    if not labels:
        labels = ["All alerts"]
    return {"state": "data", "labels": labels}


def _library_row(row: dict) -> dict:
    triggers = _triggers(row.get("trigger_conditions"))
    step_count = row.get("step_count")
    priority = row.get("priority")
    active = row.get("is_active")
    if active is True:
        active_state = "active"
    elif active is False:
        active_state = "inactive"
    else:
        active_state = "unknown"
    name = row.get("name") if isinstance(row.get("name"), str) else "unknown"
    return {
        "id": row.get("id"),
        "name": name,
        "snippet": _snippet(row.get("description")),
        "triggers_state": triggers["state"],
        "trigger_labels": triggers["labels"],
        "step_label": f"{step_count} steps" if _is_int(step_count) else None,
        "priority_label": str(priority) if _is_int(priority) else None,
        "active_state": active_state,
    }


def _failed(kind: str) -> dict:
    return {"state": "failed", "kind": kind, "title": "This could not be read."}


def _missing_execution() -> dict:
    return {"state": "missing", "title": "This execution is no longer there."}


def _library_view(payload: object, user: User) -> dict:
    found = rows(payload, "playbooks")
    if found is None or any(not isinstance(row, dict) for row in found):
        return {
            "state": "unreadable",
            "playbooks": [],
            "can_update": False,
            "can_delete": False,
        }
    return {
        "state": "empty" if not found else "data",
        "playbooks": [_library_row(row) for row in found],
        "can_update": bool(user.has_permission("playbook:update")),
        "can_delete": bool(user.has_permission("playbook:delete")),
    }


def _playbook_view(payload: object, *, missing: bool = False) -> dict:
    if missing:
        return {"state": "missing", "title": "This playbook is no longer there.", "playbook": None}
    if not isinstance(payload, dict) or not isinstance(payload.get("playbook"), dict):
        return {"state": "unreadable", "title": "This playbook could not be read.", "playbook": None}
    playbook = payload["playbook"]
    steps = playbook.get("steps")
    if not isinstance(steps, list) or any(not isinstance(step, dict) for step in steps):
        return {"state": "unreadable", "title": "This playbook could not be read.", "playbook": playbook}
    description = playbook.get("description")
    if description is None or description == "":
        description_text = None
    elif isinstance(description, str):
        description_text = description
    else:
        return {"state": "unreadable", "title": "This playbook could not be read.", "playbook": playbook}
    active = playbook.get("is_active")
    if active is True:
        active_state = "active"
    elif active is False:
        active_state = "inactive"
    else:
        active_state = "unknown"
    name = playbook.get("name") if isinstance(playbook.get("name"), str) else "unknown"
    prepared = []
    for step in steps:
        prepared.append({
            "title": step.get("title") if isinstance(step.get("title"), str) else "unknown",
            "step_type": step.get("step_type") if isinstance(step.get("step_type"), str) else "unknown",
            "is_required": step.get("is_required") is True,
            "description": step.get("description") if isinstance(step.get("description"), str) and step.get("description") else None,
        })
    priority = playbook.get("priority")
    return {
        "state": "data",
        "title": name,
        "playbook": playbook,
        "name": name,
        "description": description_text,
        "active_state": active_state,
        "priority_label": str(priority) if _is_int(priority) else None,
        "steps_state": "empty" if not prepared else "data",
        "steps": prepared,
        "created_by": playbook.get("created_by_username") if isinstance(playbook.get("created_by_username"), str) else None,
        "created_at": playbook.get("created_at"),
        "updated_at": playbook.get("updated_at"),
        "triggers": _triggers(playbook.get("trigger_conditions")),
    }


def _parse_step_params(raw: Optional[str]):
    """None when the editor has no saved params. 'bad' when the blob is not an object."""
    if raw is None or raw == "":
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return "bad"
    if not isinstance(parsed, dict):
        return "bad"
    return parsed


def _options(choices: tuple, selected: Optional[str]) -> list:
    values = list(choices)
    if isinstance(selected, str) and selected not in values:
        values.append(selected)
    return [{"value": value, "selected": value == selected} for value in values]


def _choice(parsed: object, key: str) -> Optional[str]:
    if not isinstance(parsed, dict) or key not in parsed:
        return None
    value = parsed[key]
    return value if isinstance(value, str) else None


def _params_view(step_type: str, parsed: object) -> dict:
    view = {
        "params_state": "data",
        "checklist_text": "",
        "opencti_checked": False,
        "status_options": _options(_STATUSES, None),
        "priority_options": _options(_PRIORITIES, None),
        "severity_options": _options(_SEVERITIES, None),
        "title_template": "",
    }
    if parsed == "bad":
        view["params_state"] = "unreadable"
        return view
    if step_type == "manual_checklist":
        if parsed is None or "checklist_items" not in parsed:
            return view
        items = parsed["checklist_items"]
        if not isinstance(items, list) or any(not isinstance(item, str) for item in items):
            view["params_state"] = "unreadable"
            return view
        view["checklist_text"] = "\n".join(items)
        return view
    if step_type == "auto_enrich_observables":
        if parsed is None:
            view["opencti_checked"] = True
            return view
        if "sources" not in parsed:
            return view
        sources = parsed["sources"]
        if not isinstance(sources, list):
            view["params_state"] = "unreadable"
            return view
        view["opencti_checked"] = "opencti" in sources
        return view
    if step_type == "auto_update_status":
        status = _choice(parsed, "new_status") if isinstance(parsed, dict) else None
        priority = _choice(parsed, "priority") if isinstance(parsed, dict) else None
        view["status_options"] = _options(_STATUSES, status)
        view["priority_options"] = _options(_PRIORITIES, priority)
        return view
    if step_type == "auto_create_case":
        if parsed is None:
            view["title_template"] = "Case: {rule_name}"
            return view
        if "title_template" not in parsed:
            view["title_template"] = ""
        else:
            title = parsed["title_template"]
            if title is None:
                view["title_template"] = ""
            elif isinstance(title, str):
                view["title_template"] = title
            else:
                view["params_state"] = "unreadable"
                return view
        severity = _choice(parsed, "severity")
        view["severity_options"] = _options(_SEVERITIES, severity)
        return view
    return view


def _step_view(n: int, step_type: Optional[str], title: Optional[str], description: Optional[str], is_required: bool, step_params: Optional[str]) -> dict:
    chosen = step_type if step_type in _STEP_TYPES else "manual_checklist"
    view = {
        "n": n,
        "step_type": chosen,
        "title": title or "",
        "description": description or "",
        "is_required": is_required,
    }
    view.update(_params_view(chosen, _parse_step_params(step_params)))
    return view


def _js_round(value: float) -> int:
    """Math.round for a non-negative percentage. Python round is bankers."""
    return int(math.floor(value + 0.5))


def _status_of(statuses: dict, step_id: object) -> Optional[str]:
    found = statuses.get(step_id)
    if found is None and step_id is not None:
        found = statuses.get(str(step_id))
    if not isinstance(found, dict):
        return None
    status = found.get("status")
    return status if isinstance(status, str) else None


def _recompute(steps: list, statuses: object) -> Optional[dict]:
    if not isinstance(statuses, dict):
        if statuses is not None:
            return None
        statuses = {}
    completed = 0
    for step in steps:
        if isinstance(step, dict) and _status_of(statuses, step.get("id")) in _DONE:
            completed += 1
    total = len(steps)
    pct = _js_round(completed / total * 100) if total else 0
    return {"completed": completed, "total": total, "pct": pct}


def _list_progress(row: dict) -> Optional[dict]:
    total = row.get("total_steps")
    done = row.get("completed_steps")
    pct = row.get("progress_pct")
    if _is_int(total) and _is_int(done) and _is_int(pct):
        return {"completed": done, "total": total, "pct": pct}
    playbook = row.get("playbook")
    steps = playbook.get("steps") if isinstance(playbook, dict) else None
    if not isinstance(steps, list):
        return None
    return _recompute(steps, row.get("step_statuses"))


def _short_alert(alert_id: object) -> tuple:
    if not isinstance(alert_id, str) or alert_id == "":
        return None, None
    if len(alert_id) > 20:
        return alert_id[:20] + "...", alert_id
    return alert_id, alert_id


def _execution_row(row: dict) -> dict:
    playbook = row.get("playbook")
    name = playbook.get("name") if isinstance(playbook, dict) else None
    short, full = _short_alert(row.get("es_alert_id"))
    case_number = row.get("case_number")
    report_id = row.get("report_document_id")
    return {
        "id": row.get("id"),
        "name": name if isinstance(name, str) and name else "unknown",
        "alert_short": short,
        "alert_title": full,
        "case_number": case_number if isinstance(case_number, str) and case_number else None,
        "progress": _list_progress(row),
        "status_label": _label(row.get("status")),
        "status_class": _class_name(row.get("status")),
        "outcome_label": _label(row.get("outcome")) if isinstance(row.get("outcome"), str) and row.get("outcome") else None,
        "outcome_class": _class_name(row.get("outcome")),
        "report": _is_int(report_id),
        "analyst": row.get("executed_by_username") if isinstance(row.get("executed_by_username"), str) else None,
        "started_at": row.get("started_at"),
    }


def _executions_view(payload: object) -> dict:
    found = rows(payload, "executions")
    if found is None or any(not isinstance(row, dict) for row in found):
        return {"state": "unreadable", "executions": []}
    if not found:
        return {"state": "empty", "executions": []}
    return {"state": "data", "executions": [_execution_row(row) for row in found]}


def _withheld(title: str) -> dict:
    return {"state": "withheld", "title": title}


def _step_detail(step: dict, statuses: dict, active: bool) -> dict:
    found = statuses.get(step.get("id"))
    if found is None and step.get("id") is not None:
        found = statuses.get(str(step.get("id")))
    status_row = found if isinstance(found, dict) else {}
    status = status_row.get("status") if isinstance(status_row.get("status"), str) else ""
    action = status_row.get("action_data") if isinstance(status_row.get("action_data"), dict) else {}
    risks = []
    saved_risk = action.get("risk_assessment") if isinstance(action.get("risk_assessment"), str) else ""
    for value, label in (("", "—"), ("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")):
        risks.append({"value": value, "label": label, "selected": value == saved_risk and value != ""})
    return {
        "id": step.get("id"),
        "title": step.get("title") if isinstance(step.get("title"), str) else "unknown",
        "is_required": step.get("is_required") is True,
        "done": status in _DONE,
        "status": status,
        "active": active,
        "completed_by": status_row.get("completed_by_username") if isinstance(status_row.get("completed_by_username"), str) else None,
        "completed_at": status_row.get("completed_at"),
        "action_taken": action.get("action_taken") if isinstance(action.get("action_taken"), str) else "",
        "findings": action.get("findings") if isinstance(action.get("findings"), str) else "",
        "evidence": action.get("evidence_collected") if isinstance(action.get("evidence_collected"), str) else "",
        "risks": risks,
    }


def _detail_view(payload: object) -> dict:
    if not isinstance(payload, dict) or not isinstance(payload.get("execution"), dict):
        return {"state": "unreadable", "title": "This execution could not be read."}
    execution = payload["execution"]
    playbook = execution.get("playbook") if isinstance(execution.get("playbook"), dict) else {}
    name = playbook.get("name") if isinstance(playbook.get("name"), str) and playbook.get("name") else "Execution"
    steps = playbook.get("steps") if isinstance(playbook, dict) else None
    if not isinstance(steps, list) or any(not isinstance(step, dict) for step in steps):
        steps_state = "unreadable"
        steps = []
    elif not steps:
        steps_state = "empty"
    else:
        steps_state = "data"
    statuses = execution.get("step_statuses")
    progress = _recompute(steps, statuses) if steps_state != "unreadable" else None
    status = execution.get("status") if isinstance(execution.get("status"), str) else ""
    active = status == "in_progress"
    prepared = []
    if steps_state == "data":
        status_map = statuses if isinstance(statuses, dict) else {}
        prepared = [_step_detail(step, status_map, active) for step in steps]
    report_id = execution.get("report_document_id")
    outcome = execution.get("outcome") if isinstance(execution.get("outcome"), str) and execution.get("outcome") else None
    case_number = execution.get("case_number") if isinstance(execution.get("case_number"), str) else None
    return {
        "state": "data",
        "title": name,
        "execution_id": execution.get("id"),
        "name": name,
        "alert_id": execution.get("es_alert_id") if isinstance(execution.get("es_alert_id"), str) else None,
        "case_number": case_number,
        "case_title": execution.get("case_title") if isinstance(execution.get("case_title"), str) else "",
        "progress": progress,
        "status": status,
        "status_class": _class_name(status),
        "steps_state": steps_state,
        "steps": prepared,
        "show_complete": active,
        "show_outcome": status == "completed",
        "outcome_label": _label(outcome) if outcome else None,
        "outcome_class": _class_name(outcome),
        "report": _is_int(report_id),
    }


def _bucket(counts: dict, key: str) -> Optional[int]:
    """A missing status is a true zero. A value of the wrong type is not."""
    if key not in counts:
        return 0
    value = counts[key]
    if not _is_int(value):
        return None
    return value


def _badge_view(counts: object) -> dict:
    if not isinstance(counts, dict):
        return {"state": "unreadable", "count": None}
    running = _bucket(counts, "in_progress")
    pending = _bucket(counts, "pending")
    if running is None or pending is None:
        return {"state": "unreadable", "count": None}
    active = running + pending
    if active == 0:
        return {"state": "zero", "count": 0}
    return {"state": "count", "count": active}


@router.get("/playbooks/library", response_class=HTMLResponse)
def playbook_library(
    request: Request,
    active_only: bool = False,
    user: User = Depends(require_permission(READ)),
    session: Session = Depends(get_db_session),
):
    try:
        payload = list_playbooks(active_only=active_only, current_user=user, session=session)
    except Exception:
        logger.exception("playbook library read failed")
        return render_view(request, LIBRARY, _failed("library"))
    return render_view(request, LIBRARY, _library_view(payload, user))


@router.get("/playbooks/step", response_class=HTMLResponse)
def playbook_step(
    request: Request,
    n: int,
    step_type: Optional[str] = None,
    title: Optional[str] = None,
    description: Optional[str] = None,
    is_required: bool = False,
    step_params: Optional[str] = None,
    user: User = Depends(require_permission(READ)),
):
    return render_view(
        request, STEP, _step_view(n, step_type, title, description, is_required, step_params),
    )


@router.get("/playbooks/step-params", response_class=HTMLResponse)
def playbook_step_params(
    request: Request,
    n: int,
    step_type: Optional[str] = None,
    title: Optional[str] = None,
    description: Optional[str] = None,
    is_required: bool = False,
    step_params: Optional[str] = None,
    user: User = Depends(require_permission(READ)),
):
    return render_view(
        request, PARAMS, _step_view(n, step_type, title, description, is_required, step_params),
    )


@router.get("/playbooks/executions/badge", response_class=HTMLResponse)
def playbook_badge(
    request: Request,
    user: User = Depends(require_any_permission(PAGE_OR_EXECUTE)),
    session: Session = Depends(get_db_session),
):
    if not user.has_permission(EXECUTE):
        return render_view(request, BADGE, _withheld("Executions are withheld."))
    try:
        counts = playbook_executions_summary(current_user=user, session=session)
    except Exception:
        logger.exception("playbook execution summary read failed")
        return render_view(request, BADGE, _failed("badge"))
    return render_view(request, BADGE, _badge_view(counts))


@router.get("/playbooks/executions", response_class=HTMLResponse)
def playbook_executions(
    request: Request,
    status: Optional[str] = None,
    user: User = Depends(require_any_permission(PAGE_OR_EXECUTE)),
    session: Session = Depends(get_db_session),
):
    if not user.has_permission(EXECUTE):
        return render_view(request, EXECUTIONS, _withheld("Executions are withheld."))
    if not status:
        status = None
    try:
        payload = list_playbook_executions(
            status=status, limit=50, current_user=user, session=session,
        )
    except Exception:
        logger.exception("playbook executions read failed")
        return render_view(request, EXECUTIONS, _failed("executions"))
    return render_view(request, EXECUTIONS, _executions_view(payload))


@router.get("/playbooks/executions/{execution_id}", response_class=HTMLResponse)
def playbook_execution(
    request: Request,
    execution_id: int,
    user: User = Depends(require_any_permission(PAGE_OR_EXECUTE)),
    session: Session = Depends(get_db_session),
):
    if not user.has_permission(EXECUTE):
        return render_view(request, DETAIL, _withheld("This execution is withheld."))
    try:
        payload = get_playbook_execution(
            execution_id=execution_id, current_user=user, session=session,
        )
    except HTTPException as exc:
        if exc.status_code == 404:
            return render_view(request, DETAIL, _missing_execution())
        logger.exception("playbook execution %s read failed", execution_id)
        return render_view(request, DETAIL, _failed("execution"))
    except Exception:
        logger.exception("playbook execution %s read failed", execution_id)
        return render_view(request, DETAIL, _failed("execution"))
    return render_view(request, DETAIL, _detail_view(payload))


@router.get("/playbooks/{playbook_id}", response_class=HTMLResponse)
def playbook_view(
    request: Request,
    playbook_id: int,
    user: User = Depends(require_permission(READ)),
    session: Session = Depends(get_db_session),
):
    try:
        payload = get_playbook(playbook_id=playbook_id, current_user=user, session=session)
    except HTTPException as exc:
        if exc.status_code == 404:
            return render_view(request, VIEW, _playbook_view(None, missing=True))
        logger.exception("playbook %s read failed", playbook_id)
        return render_view(request, VIEW, _failed("playbook"))
    except Exception:
        logger.exception("playbook %s read failed", playbook_id)
        return render_view(request, VIEW, _failed("playbook"))
    return render_view(request, VIEW, _playbook_view(payload))
