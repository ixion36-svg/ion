"""The submitted-bug-reports list, as one fragment."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()


def _fmt_dt(iso: Optional[str]) -> str:
    """"YYYY-MM-DD HH:MM" from an ISO timestamp, or the raw value.

    The JavaScript this replaces did
    `new Date(iso).toISOString().replace('T',' ').slice(0,16)` inside a
    try/catch that fell back to the raw string. Same shape and same
    fallback: a value that will not parse is shown as-is, because a visible
    oddity beats a blank cell that reads as "never".
    """
    if not iso:
        return ""
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return str(iso)


def _plain(value: object) -> object:
    """An enum member's value, or the value unchanged.

    `severity` and `status` are SQLEnum columns, so a row read through the
    ORM carries the enum member. The JSON endpoint got the string for free
    because FastAPI serialises a str-mixin enum by value; a template does
    not. On Python 3.11+ `str(BugReportSeverity.HIGH)` is
    "BugReportSeverity.HIGH", which is what the pill would have printed.
    Value equality still works, so the colour lookup kept working and only
    the visible text was wrong, which is the kind of thing that ships.
    """
    return getattr(value, "value", value)


def _rows(reports: list[dict]) -> list[dict]:
    """The report dicts with their display-only fields added."""
    out = []
    for r in reports:
        row = dict(r)
        row["severity"] = _plain(r.get("severity"))
        row["status"] = _plain(r.get("status"))
        row["created_display"] = _fmt_dt(r.get("created_at"))
        out.append(row)
    return out


@router.get("/bug-reports", response_class=HTMLResponse)
def bug_reports_fragment(
    request: Request,
    status: str = Query("all"),
    mine: bool = Query(False),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The submitted-reports card: filters, table and all.

    Replaces three innerHTML sites in bug_reports.html (the loaded table,
    the empty state and the load-failure message), 64 lines of inline JS
    including a hand-rolled `esc()` and a date formatter.

    It calls bug_report_api.bug_reports_payload, the same function
    GET /api/bug-reports calls, rather than repeating the query. What sits
    inline there is an object-level privacy gate: only system:settings sees
    everyone's reports. One copy of that, not two.

    The dependency is `get_current_user`, which is exactly what the JSON
    endpoint requires: filing a bug needs no named permission, so there is
    no `require_permission(...)` to mirror and a named one here would be a
    fragment stricter than its API rather than a match. Unauthenticated
    still gets 401, not the /login redirect a page dependency would give,
    because htmx must never swap a login form into a dashboard.
    """
    from ion.web.bug_report_api import bug_reports_payload

    context: dict[str, Any] = {"status": status, "mine": mine}
    try:
        payload = bug_reports_payload(status, mine, current_user, session)
    except Exception:
        logger.exception("Bug reports fragment could not be rendered")
        # A failed read is not an empty queue. The filters and Refresh stay
        # on screen in this branch so the panel is not stranded.
        context.update({"reports": None, "failed": True})
        return templates.TemplateResponse(
            request=request,
            name="_fragments/bug_reports.html",
            context=context,
        )

    context.update({"reports": _rows(payload["bug_reports"]), "failed": False})
    return templates.TemplateResponse(
        request=request,
        name="_fragments/bug_reports.html",
        context=context,
    )
