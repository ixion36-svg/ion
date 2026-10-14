"""Case process context and rule guidance, with the shared raw read retained."""

from __future__ import annotations

import json
import logging
from typing import Any, Literal, TypedDict

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from ion.auth.dependencies import require_permission
from ion.web import elasticsearch_api
from ion.web.ui._shared import render_view

logger = logging.getLogger(__name__)
router = APIRouter()
READ = require_permission("case:read")


class ProcessNode(TypedDict):
    name: str
    role: str
    is_alert: bool
    is_child: bool
    branch: bool
    meta: str
    command: str | None
    command_key: str
    pin_title: str


class ProcessTreeView(TypedDict):
    state: Literal["failed", "empty", "data"]
    unavailable: bool
    nodes: list[ProcessNode] | None
    truncated: int | None
    commands: dict[str, str]
    case_id: int | None
    can_pin: bool


class RuleGuideView(TypedDict):
    state: Literal["failed", "empty", "data"]
    raw_missing: bool
    description: str | None
    guide: str | None


def _text(value: Any) -> str | None:
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        return str(value) if value != "" else None
    return None


def process_tree_view(payload: Any, alert_id: str, case_id: int | None, can_pin: bool, unavailable: bool = False) -> ProcessTreeView:
    view: ProcessTreeView = {"state": "failed", "unavailable": unavailable, "nodes": None, "truncated": None, "commands": {}, "case_id": case_id, "can_pin": can_pin}
    if not isinstance(payload, dict) or not isinstance(payload.get("available"), bool):
        return view
    nodes, children = payload.get("nodes"), payload.get("children")
    if not isinstance(nodes, list) or not isinstance(children, list) or not all(isinstance(n, dict) for n in nodes + children):
        return view
    if not payload["available"]:
        if not nodes and not children:
            view.update(state="empty", nodes=[])
        return view
    if not nodes:
        return view
    items: list[ProcessNode] = []
    for index, node in enumerate(nodes + children):
        is_child = index >= len(nodes) or node.get("role") == "child"
        is_alert = node.get("is_alert") is True
        role = _text(node.get("role"))
        label = _text(node.get("name")) or _text(node.get("executable")) or "(unknown)"
        pid = _text(node.get("pid"))
        user = _text(node.get("user"))
        command = _text(node.get("command_line"))
        key = f"pc-{alert_id}-{'c' if is_child else 'n'}-{index}"
        if command:
            view["commands"][key] = command
        items.append(
            {
                "name": label,
                "role": "this alert" if is_alert else "ancestor" if role == "grandparent" else "child" if is_child else role or "process",
                "is_alert": is_alert,
                "is_child": is_child,
                "branch": index > 0,
                "meta": " · ".join(part for part in [f"PID {pid}" if pid is not None else None, user] if part),
                "command": command,
                "command_key": key,
                "pin_title": f"Process: {label}" + (f" (PID {pid})" if pid is not None else ""),
            }
        )
    truncated = payload.get("truncated_ancestors")
    view.update(state="data", nodes=items, truncated=truncated if isinstance(truncated, int) and not isinstance(truncated, bool) and truncated >= 0 else None)
    return view


def _flatten(value: Any, prefix: str = "", result: dict[str, Any] | None = None) -> dict[str, Any]:
    if result is None:
        result = {}
    if isinstance(value, dict):
        for key, child in value.items():
            _flatten(child, f"{prefix}.{key}" if prefix else key, result)
    elif isinstance(value, list):
        if all(not isinstance(child, (dict, list)) for child in value):
            if value:
                result[prefix] = ", ".join("" if child is None else "true" if child is True else "false" if child is False else str(child) for child in value)
        else:
            for index, child in enumerate(value):
                _flatten(child, f"{prefix}[{index}]", result)
    elif value is not None and value != "":
        result[prefix] = value
    return result


def rule_guide_view(payload: Any) -> RuleGuideView:
    view: RuleGuideView = {"state": "failed", "raw_missing": False, "description": None, "guide": None}
    if not isinstance(payload, dict):
        return view
    if payload.get("state") == "empty":
        view.update(state="empty", raw_missing=True)
        return view
    if payload.get("state") != "data" or not isinstance(payload.get("raw"), dict):
        return view
    flat = _flatten(payload["raw"])
    description = next((_text(flat.get(key)) for key in ("kibana.alert.rule.description", "signal.rule.description", "rule.description") if _text(flat.get(key))), None)
    guide = next((_text(flat.get(key)) for key in ("kibana.alert.rule.note", "kibana.alert.rule.parameters.note", "signal.rule.note", "rule.note") if _text(flat.get(key))), None)
    view.update(state="data" if description or guide else "empty", description=description, guide=guide)
    return view


@router.get("/cases/detail/process-tree/{alert_id}", response_class=HTMLResponse)
async def process_tree(request: Request, alert_id: str, case_id: int | None = Query(None, ge=1), current_user=Depends(READ)):
    if not current_user.has_permission("alert:read"):
        raise HTTPException(status_code=403, detail="Permission denied")
    unavailable = False
    try:
        payload = await elasticsearch_api.get_alert_process_tree(alert_id=alert_id, current_user=current_user)
    except HTTPException as error:
        unavailable = error.status_code == 503
        payload = None
    except Exception:
        logger.exception("Case process tree read failed")
        payload = None
    view = process_tree_view(payload, alert_id, case_id, current_user.has_permission("case:update"), unavailable)
    return render_view(request, "_fragments/cases_detail_process.html", view)


@router.post("/cases/detail/rule-guide", response_class=HTMLResponse)
def rule_guide(request: Request, state: str = Form(...), raw: str | None = Form(None), current_user=Depends(READ)):
    if not current_user.has_permission("alert:read"):
        raise HTTPException(status_code=403, detail="Permission denied")
    try:
        document = json.loads(raw) if raw is not None else None
    except (ValueError, TypeError):
        document = None
    view = rule_guide_view({"state": state, "raw": document})
    return render_view(request, "_fragments/cases_detail_rule_guide.html", view)
