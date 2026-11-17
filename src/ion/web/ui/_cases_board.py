"""The /cases inbox: a bounded, last-activity-ordered case list and the
preview of the selected case. Opening a case is still /cases/{id}.

Three outcomes stay three here as everywhere: a read that failed is None,
an empty result is empty, and data is data.

The prototype this follows also had unread dots and "since you last
looked". ION does not record when a user last viewed a case, so both are
left out rather than imitated with something that only looks like them.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional, TypedDict

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.services import case_query_service as cq
from ion.storage.database import get_db_session
from ion.web import api, case_lifecycle_api
from ion.web.ui._cases_window import RETENTION_MARKER, alert_verdicts, blockers, case_alerts
from ion.web.ui._shared import age_label, closure_label, closure_short, instant_label, parse_instant, plain, render_view, rows

logger = logging.getLogger(__name__)
router = APIRouter()
READ = require_permission("case:read")

#: What "Changed" means: activity within this window.
CHANGED_WINDOW = timedelta(hours=24)

#: Sort control value -> (field, order). "alerts" has no server ordering
#: yet, so it falls back to newest and says so.
SORTS: dict[str, tuple[str, str]] = {
    "activity": ("last_activity", "desc"),
    "newest": ("created_at", "desc"),
    "oldest": ("created_at", "asc"),
    "severity": ("severity", "desc"),
    "alerts": ("created_at", "desc"),
}

ChipKey = Literal["changed", "mine", "unassigned", "critical", "closed"]
CHIPS: tuple[tuple[ChipKey, str], ...] = (
    ("changed", "Changed"),
    ("mine", "Mine"),
    ("unassigned", "Unassigned"),
    ("critical", "Critical"),
    ("closed", "Closed"),
)

SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("open", "acknowledged", "closed")
_CACHE_KEYS = ("id", "case_number", "title", "status", "severity", "assigned_to",
               "assigned_to_id", "created_at", "updated_at")


class Filters(TypedDict):
    status: Optional[str]
    severity: Optional[str]
    assigned_to_id: Optional[int]
    unassigned: bool
    changed: bool


class Chip(TypedDict):
    key: ChipKey
    label: str
    count: Optional[int]
    on: bool


class InboxRow(TypedDict):
    id: Optional[int]
    number: Optional[str]
    title: str
    host: Optional[str]
    severity: str
    status: str
    assignee: Optional[str]
    initials: str
    hue: Optional[int]
    alert_count: Optional[int]
    activity: Optional[str]
    activity_kind: str
    age: Optional[str]
    activity_label: Optional[str]


class AttentionItem(TypedDict):
    id: int
    number: Optional[str]
    title: str
    kind: str
    label: str


class InboxView(TypedDict):
    state: Literal["failed", "empty", "data"]
    rows: Optional[list[InboxRow]]
    cache: Optional[list[dict[str, Any]]]
    total: Optional[int]
    shown: Optional[int]
    offset: int
    next_offset: Optional[int]
    has_more: Optional[bool]
    attention: Optional[list[AttentionItem]]
    chips: list[Chip]
    filtered: bool
    me: Optional[int]
    can_update: bool
    alerts_sort_gap: bool


class AssigneesView(TypedDict):
    state: Literal["failed", "empty", "data", "withheld"]
    users: Optional[list[dict[str, Any]]]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def count(value: object) -> Optional[int]:
    if isinstance(value, list):
        return len(value)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def text(value: object) -> Optional[str]:
    value = plain(value)
    return value if isinstance(value, str) and value else None


def initials(name: Optional[str]) -> str:
    return "".join(part[0] for part in re.split(r"[ ._@-]+", name or "") if part)[:2].upper() or "?"


#: Avatar colour classes, av-0 to av-5.
HUES = 6


def hue(name: Optional[str]) -> Optional[int]:
    """A stable colour slot per name, so one analyst reads the same colour on
    every row. None for no owner."""
    return sum(map(ord, name)) % HUES if name else None


_MARKUP = re.compile(r"```\w*|[#*>`_]+")


def one_line(value: object, limit: int = 140) -> Optional[str]:
    """The first non-empty line of a note, without its markdown."""
    raw = text(value)
    if raw is None:
        return None
    for line in raw.splitlines():
        line = " ".join(_MARKUP.sub(" ", line).split())
        if line:
            return line if len(line) <= limit else line[: limit - 1] + "…"
    return None


def distinct_host(host: Optional[str], title: object) -> Optional[str]:
    """The host, unless the title already names it: grouped cases are
    titled "<rule> — <host>", and printing it twice costs the row its width."""
    title = text(title) or ""
    return host if host and host.lower() not in title.lower() else None


def latest_activity(row: dict, extra: Optional[dict]) -> tuple[str, Optional[str]]:
    """The row's "latest activity" line: (kind, words).

    The newest of the case's newest note, its newest alert change and its
    own lifecycle, the same three sources the last-activity sort reads.
    Bob's investigations and playbook runs are on the case's timeline but
    not here: reading them for every row is the timeline query fifty times.
    """
    candidates: list[tuple[datetime, int, str, Optional[str]]] = []
    updated, created = parse_instant(row.get("updated_at")), parse_instant(row.get("created_at"))
    if updated is not None:
        if text(row.get("status")) == "closed":
            reason = closure_label(row.get("closure_reason"))
            words = "Closed as " + reason.lower() if reason else "Closed"
            kind = "closed"
        elif created is not None and (updated - created).total_seconds() < 60:
            words, kind = "Case opened", "opened"
        else:
            words, kind = "Case updated", "updated"
        candidates.append((updated, 0, kind, words))
    extra = extra or {}
    alert = extra.get("alert") if isinstance(extra.get("alert"), dict) else None
    if alert and parse_instant(alert.get("at")) is not None:
        rule = text(alert.get("rule")) or "an alert"
        words = ("Alert linked: " if alert.get("linked") else "Alert " + (text(alert.get("status")) or "changed") + ": ") + rule
        candidates.append((parse_instant(alert["at"]), 1, "alert", words))
    note = extra.get("note") if isinstance(extra.get("note"), dict) else None
    if note and parse_instant(note.get("at")) is not None:
        body = one_line(note.get("content"))
        who = text(note.get("user"))
        words = ": ".join(part for part in (who, body) if part) or "Note added"
        candidates.append((parse_instant(note["at"]), 2, "note", words))
    if not candidates:
        return "unknown", None
    _, _, kind, words = max(candidates, key=lambda c: (c[0], c[1]))
    return kind, words


def inbox_row(row: dict, extra: Optional[dict], now: datetime) -> InboxRow:
    severity, status = text(row.get("severity")), text(row.get("status"))
    severity = severity.lower() if severity else None
    assignee = text(row.get("assigned_to"))
    kind, words = latest_activity(row, extra)
    last = row.get("last_activity_at") or row.get("updated_at")
    return {
        "id": count(row.get("id")),
        "number": text(row.get("case_number")),
        "title": text(row.get("title")) or "Untitled case",
        "host": distinct_host(text((extra or {}).get("host")), row.get("title")),
        "severity": severity if severity in SEVERITIES else "unknown",
        "status": status if status in STATUSES else "unknown",
        "assignee": assignee,
        "initials": initials(assignee),
        "hue": hue(assignee),
        "alert_count": count(row.get("alert_count")),
        "activity": words,
        "activity_kind": kind,
        "age": age_label(last, now),
        "activity_label": instant_label(last),
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


def chips_view(counts: Optional[dict], filters: Filters, me: Optional[int]) -> list[Chip]:
    """Each chip with its whole-table count and whether the current filters
    are what it applies. A count that could not be read is None, not 0."""
    counts = counts if isinstance(counts, dict) else {}
    on = {
        "changed": filters["changed"],
        "mine": me is not None and filters["assigned_to_id"] == me,
        "unassigned": filters["unassigned"],
        "critical": filters["severity"] == "critical",
        "closed": filters["status"] == "closed",
    }
    return [{"key": key, "label": label, "count": count(counts.get(key)), "on": on[key]} for key, label in CHIPS]


def inbox_view(payload: object, activity: Optional[dict], counts: Optional[dict], filters: Filters, user, offset: int, mode: str, q: Optional[str] = None) -> InboxView:
    records = rows(payload, "cases")
    if records is not None and not all(isinstance(row, dict) for row in records):
        records = None
    now = utc_now()
    me = count(getattr(user, "id", None))
    total = count(payload.get("total")) if isinstance(payload, dict) else None
    more = payload.get("has_more") if isinstance(payload, dict) else None
    shown = offset + len(records) if records is not None else None
    activity = activity or {}
    return {
        "state": "failed" if records is None else "data" if records else "empty",
        "rows": [inbox_row(row, activity.get(row.get("id")), now) for row in records] if records is not None else None,
        "cache": [{key: row.get(key) for key in _CACHE_KEYS} for row in records] if records is not None else None,
        "total": total,
        "shown": min(shown, total) if shown is not None and total is not None else shown,
        "offset": offset,
        "next_offset": shown,
        "has_more": more if isinstance(more, bool) and records is not None else None,
        "attention": attention_items(records, now) if records is not None else None,
        "chips": chips_view(counts, filters, me),
        "filtered": bool(q and q.strip()) or any(filters[key] for key in ("status", "severity", "assigned_to_id", "unassigned", "changed")),
        "me": me,
        "can_update": user.has_permission("case:update"),
        "alerts_sort_gap": mode == "alerts",
    }


def read_inbox(session: Session, *, filters: Filters, q: Optional[str], mode: str, limit: int, offset: int, user_id: Optional[int], now: datetime) -> tuple[Any, Any, Any]:
    """The page, its rows' activity and the chip counts. Each part fails on
    its own, so a failed count does not blank the list."""
    sort, order = SORTS[mode]
    since = (now - CHANGED_WINDOW).replace(tzinfo=None)
    try:
        payload = cq.list_cases_page(
            session, status=filters["status"], severity=filters["severity"], assigned_to_id=filters["assigned_to_id"],
            unassigned=filters["unassigned"], q=q, active_since=since if filters["changed"] else None,
            sort=sort, order=order, limit=limit, offset=offset,
        )
    except Exception:
        logger.exception("Case inbox could not read its page")
        return None, None, None
    ids = [row["id"] for row in payload["cases"] if isinstance(row.get("id"), int)]
    try:
        activity = cq.case_activity(session, ids)
    except Exception:
        logger.exception("Case inbox could not read its rows' activity")
        activity = None
    counts = None
    if offset == 0:
        try:
            counts = cq.inbox_counts(session, user_id=user_id, active_since=since)
        except Exception:
            logger.exception("Case inbox could not count its chips")
    return payload, activity, counts


@router.get("/cases/board", response_class=HTMLResponse)
async def board(
    request: Request,
    status: Optional[Literal["open", "acknowledged", "closed"]] = None,
    severity: Optional[Literal["critical", "high", "medium", "low", "info"]] = None,
    assigned_to_id: Optional[int] = None,
    unassigned: bool = False,
    mine: bool = False,
    changed: bool = False,
    q: Optional[str] = None,
    mode: Literal["activity", "newest", "oldest", "severity", "alerts"] = "activity",
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(READ),
    session: Session = Depends(get_db_session),
):
    me = count(getattr(user, "id", None))
    owner = None if unassigned else me if mine else assigned_to_id
    filters: Filters = {"status": status, "severity": severity, "assigned_to_id": owner, "unassigned": unassigned, "changed": changed}
    payload, activity, counts = await asyncio.to_thread(
        read_inbox, session, filters=filters, q=q, mode=mode, limit=limit, offset=offset, user_id=me, now=utc_now()
    )
    return render_view(request, "_fragments/cases_board.html", inbox_view(payload, activity, counts, filters, user, offset, mode, q))


# ── The preview pane ─────────────────────────────────────────────────────


class PreviewEvent(TypedDict):
    kind: str
    title: Optional[str]
    detail: Optional[str]
    when: Optional[str]


class PreviewView(TypedDict):
    state: Literal["failed", "data"]
    id: int
    number: Optional[str]
    title: Optional[str]
    host: Optional[str]
    severity: str
    status: str
    closure: Optional[str]
    counts: dict[str, Optional[int]]
    blockers: Optional[list[dict]]
    alert_ids: list[str]
    activity: Optional[list[PreviewEvent]]
    owner: Optional[str]
    owner_initials: str
    owner_hue: Optional[int]
    assigned_to_id: Optional[int]
    opened: Optional[str]
    opened_age: Optional[str]
    kibana: Literal["linked", "pending", "none"]
    kibana_url: Optional[str]
    iris_id: Optional[int]
    iris_url: Optional[str]
    can_update: bool
    me: Optional[int]


#: How many of the timeline's newest entries the preview shows.
PREVIEW_EVENTS = 4

#: How many alert documents the page reads for the key-field line.
PREVIEW_ALERT_DOCS = 3


def preview_events(timeline: object) -> Optional[list[PreviewEvent]]:
    events = rows(timeline, "events")
    if events is None:
        return None
    # The retention marker is not an alert (see _cases_window.case_alerts).
    dated = [e for e in events if isinstance(e, dict) and parse_instant(e.get("ts")) is not None
             and not (e.get("source_type") == "alert" and str(e.get("source_id") or "").startswith(RETENTION_MARKER))]
    dated.sort(key=lambda e: parse_instant(e["ts"]), reverse=True)
    return [
        {
            "kind": text(e.get("kind")) or "system",
            "title": text(e.get("title")),
            "detail": one_line(e.get("detail"), 160),
            "when": instant_label(e.get("ts")),
        }
        for e in dated[:PREVIEW_EVENTS]
    ]


def preview_view(case_id: int, detail: object, timeline: object, user, now: datetime) -> PreviewView:
    can_update = user.has_permission("case:update")
    me = count(getattr(user, "id", None))
    if not isinstance(detail, dict):
        return {
            "state": "failed", "id": case_id, "number": None, "title": None, "host": None, "severity": "unknown",
            "status": "unknown", "closure": None, "counts": {"alerts": None, "observables": None, "notes": None},
            "blockers": None, "alert_ids": [], "activity": preview_events(timeline), "owner": None, "owner_initials": "?", "owner_hue": None,
            "assigned_to_id": None, "opened": None, "opened_age": None, "kibana": "none", "kibana_url": None,
            "iris_id": None, "iris_url": None, "can_update": can_update, "me": me,
        }
    alerts = case_alerts(detail.get("alerts"))
    alert_rows = [a for a in alerts if isinstance(a, dict)] if isinstance(alerts, list) else []
    # Open alerts first: their fields are what the next action is about.
    alert_rows.sort(key=lambda a: str(a.get("status") or "open").lower() == "closed")
    severity, status = text(detail.get("severity")), text(detail.get("status"))
    severity = severity.lower() if severity else None
    hosts = detail.get("affected_hosts")
    owner = text(detail.get("assigned_to"))
    iris_id = count(detail.get("dfir_iris_case_id"))
    return {
        "state": "data",
        "id": count(detail.get("id")) or case_id,
        "number": text(detail.get("case_number")),
        "title": text(detail.get("title")) or "Untitled case",
        "host": distinct_host(next((h for h in hosts if isinstance(h, str) and h), None) if isinstance(hosts, list) else None, detail.get("title")),
        "severity": severity if severity in SEVERITIES else "unknown",
        "status": status if status in STATUSES else "unknown",
        "closure": closure_short(detail.get("closure_reason")),
        "counts": {
            "alerts": len(alerts) if isinstance(alerts, list) else None,
            "observables": count(detail.get("observables")),
            "notes": count(detail.get("notes")),
        },
        "blockers": blockers(alerts, detail.get("assigned_to_id"), detail.get("dfir_iris_case_id"),
                             detail.get("dfir_iris_url"),
                             alert_verdicts(detail.get("notes"))) if status != "closed" else [],
        "alert_ids": [a["es_alert_id"] for a in alert_rows if text(a.get("es_alert_id"))][:PREVIEW_ALERT_DOCS],
        "activity": preview_events(timeline),
        "owner": owner,
        "owner_initials": initials(owner),
        "owner_hue": hue(owner),
        "assigned_to_id": count(detail.get("assigned_to_id")),
        "opened": instant_label(detail.get("created_at")),
        "opened_age": age_label(detail.get("created_at"), now),
        "kibana": "pending" if detail.get("kibana_sync_pending") else "linked" if text(detail.get("kibana_case_id")) else "none",
        "kibana_url": text(detail.get("kibana_url")),
        "iris_id": iris_id,
        "iris_url": text(detail.get("dfir_iris_url")),
        "can_update": can_update,
        "me": me,
    }


@router.get("/cases/{case_id}/preview", response_class=HTMLResponse)
async def preview(request: Request, case_id: int, user=Depends(READ), session: Session = Depends(get_db_session)):
    try:
        detail = await case_lifecycle_api.get_case_detail(case_id=case_id, current_user=user, session=session)
    except Exception:
        logger.exception("Case preview could not read case %s", case_id)
        detail = None
    try:
        timeline = await asyncio.to_thread(case_lifecycle_api.get_case_timeline, case_id=case_id, current_user=user, session=session)
    except Exception:
        logger.exception("Case preview could not read the timeline of case %s", case_id)
        timeline = None
    return render_view(request, "_fragments/cases_preview.html", preview_view(case_id, detail, timeline, user, utc_now()))


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
