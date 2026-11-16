"""Bounded case board reads; the detail and closure flows remain client-side."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Literal, TypedDict

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web import api, case_lifecycle_api
from ion.web.ui._shared import age_label, instant_label, parse_instant, plain, render_view, rows

logger = logging.getLogger(__name__)
router = APIRouter()
READ = require_permission("case:read")


class CaseCard(TypedDict):
    id: int | None
    number: str | None
    title: str
    description: str | None
    severity: str
    status: str
    assignee: str | None
    initials: str
    counts: dict[str, int | None]
    age: str | None
    age_band: str
    created_label: str | None
    closure: str | None
    rules: list[str] | None
    kibana: bool
    iris: bool


class AttentionItem(TypedDict):
    id: int
    number: str | None
    title: str
    kind: str
    label: str


class BoardView(TypedDict):
    state: Literal["failed", "empty", "data"]
    cards: list[CaseCard] | None
    cache: list[dict[str, Any]] | None
    total: int | None
    shown: int | None
    offset: int
    next_offset: int | None
    has_more: bool | None
    attention: list[AttentionItem] | None
    can_update: bool
    alerts_sort_gap: bool


class AssigneesView(TypedDict):
    state: Literal["failed", "empty", "data", "withheld"]
    users: list[dict[str, Any]] | None


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def count(value: object) -> int | None:
    if isinstance(value, list):
        return len(value)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def text(value: object) -> str | None:
    value = plain(value)
    return value if isinstance(value, str) and value else None


def case_card(row: dict, now: datetime) -> CaseCard:
    created = parse_instant(row.get("created_at"))
    hours = max(0, (now - created).total_seconds() / 3600) if created is not None else None
    band = "unknown" if hours is None else "fresh" if hours < 24 else "normal" if hours < 72 else "stale" if hours < 168 else "old"
    assignee = text(row.get("assigned_to"))
    monogram = "".join(part[0] for part in re.split(r"[ ._@-]+", assignee or "") if part)[:2].upper() or "?"
    severity = text(row.get("severity"))
    status = text(row.get("status"))
    rules = row.get("triggered_rules")
    return {
        "id": count(row.get("id")),
        "number": text(row.get("case_number")),
        "title": text(row.get("title")) or "Untitled case",
        "description": text(row.get("description")) or text(row.get("evidence_summary")),
        "severity": severity if severity in ("critical", "high", "medium", "low", "info") else "unknown",
        "status": status if status in ("open", "acknowledged", "closed") else "unknown",
        "assignee": assignee,
        "initials": monogram,
        "counts": {key: count(row.get(key, row.get("observables") if key == "observables_count" else None)) for key in ("alert_count", "affected_hosts", "affected_users", "observables_count")},
        "age": age_label(created, now),
        "age_band": band,
        "created_label": instant_label(created),
        "closure": text(row.get("closure_reason")),
        "rules": [item for item in rules if isinstance(item, str) and item][:6] if isinstance(rules, list) else None,
        "kibana": bool(row.get("kibana_case_id") or row.get("kibana_url")),
        "iris": bool(row.get("dfir_iris_case_id")),
    }


def attention_items(records: list[dict], now: datetime) -> list[AttentionItem]:
    result: list[AttentionItem] = []
    for row in records:
        status = plain(row.get("status"))
        if status not in ("open", "acknowledged") or count(row.get("id")) is None:
            continue
        updated, created = parse_instant(row.get("updated_at")), parse_instant(row.get("created_at"))
        reasons = [
            ("stale", "Stale", updated is not None and (now - updated).total_seconds() > 86400),
            ("unassigned", "Unassigned", not row.get("assigned_to") and row.get("assigned_to_id") is None),
            ("not-picked-up", "Not Picked Up", row.get("severity") in ("critical", "high") and status == "open"),
            ("aged", "Aged >7d", created is not None and (now - created).total_seconds() > 7 * 86400),
        ]
        for kind, label, applies in reasons:
            if applies:
                result.append({"id": row["id"], "number": text(row.get("case_number")), "title": text(row.get("title")) or "Untitled case", "kind": kind, "label": label})
    return result


def board_view(payload: object, user, offset: int, mode: str) -> BoardView:
    records = rows(payload, "cases")
    if records is not None and not all(isinstance(row, dict) for row in records):
        records = None
    now = utc_now()
    total = count(payload.get("total")) if isinstance(payload, dict) else None
    more = payload.get("has_more") if isinstance(payload, dict) else None
    shown = offset + len(records) if records is not None else None
    return {
        "state": "failed" if records is None else "data" if records else "empty",
        "cards": [case_card(row, now) for row in records] if records is not None else None,
        "cache": [{key: row.get(key) for key in ("id", "case_number", "title", "status", "severity", "assigned_to", "created_at", "updated_at")} for row in records] if records is not None else None,
        "total": total,
        "shown": min(shown, total) if shown is not None and total is not None else shown,
        "offset": offset,
        "next_offset": shown,
        "has_more": more if isinstance(more, bool) and records is not None else None,
        "attention": attention_items(records, now) if records is not None else None,
        "can_update": user.has_permission("case:update"),
        "alerts_sort_gap": mode == "alerts",
    }


@router.get("/cases/board", response_class=HTMLResponse)
async def board(
    request: Request,
    status: str | None = None,
    severity: str | None = None,
    assigned_to_id: int | None = None,
    unassigned: bool = False,
    q: str | None = None,
    mode: Literal["newest", "oldest", "severity", "alerts"] = "newest",
    limit: int = Query(24, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(READ),
    session: Session = Depends(get_db_session),
):
    sort, order = {"newest": ("created_at", "desc"), "oldest": ("created_at", "asc"), "severity": ("severity", "desc"), "alerts": ("created_at", "desc")}[mode]
    try:
        payload = await case_lifecycle_api.list_cases(
            status=status, severity=severity, assigned_to_id=assigned_to_id, unassigned=unassigned, q=q, sort=sort, order=order, limit=limit, offset=offset, current_user=user, session=session
        )
    except Exception:
        logger.exception("Case board could not read its page")
        payload = None
    return render_view(request, "_fragments/cases_board.html", board_view(payload, user, offset, mode))


def assignees_view(payload: object, permitted: bool) -> AssigneesView:
    records = rows(payload, "users") if permitted else None
    if records is not None and not all(isinstance(row, dict) for row in records):
        records = None
    users = [{key: row.get(key) for key in ("id", "username", "display_name", "has_elastic_profile")} for row in records] if records is not None else None
    return {"state": "withheld" if not permitted else "failed" if users is None else "data" if users else "empty", "users": users}


@router.get("/cases/assignees", response_class=HTMLResponse)
async def assignees(request: Request, user=Depends(READ), session: Session = Depends(get_db_session)):
    permitted = user.has_permission("alert:read")
    payload = None
    if permitted:
        try:
            payload = await api.list_assignable_users(session=session)
        except Exception:
            logger.exception("Case assignees could not be read")
    return render_view(request, "_fragments/cases_assignees.html", assignees_view(payload, permitted))
