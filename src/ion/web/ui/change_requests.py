"""The change-request (CAB) table, rows and action buttons together."""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web.change_request_api import _PERM
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

#: Label and button class per workflow action. Only the presentation lives
#: here; which actions are legal from a given status comes from the service's
#: own transition table, so this cannot offer a button the server will 409.
_ACTION_CHROME: dict[str, tuple[str, str]] = {
    "submit": ("Submit", "ion-btn-primary"),
    "approve": ("Approve", "ion-btn-primary"),
    "reject": ("Reject", "ion-btn-danger"),
    "schedule": ("Schedule", "ion-btn-primary"),
    "implement": ("Implement", "ion-btn-primary"),
    "close": ("Close", "ion-btn-primary"),
    "cancel": ("Cancel", "ion-btn-ghost"),
}

_RISK_COLOUR = {"low": "ion-c-green", "medium": "ion-c-amber", "high": "ion-c-red"}
_STATUS_COLOUR = {
    "draft": "ion-c-muted",
    "submitted": "ion-c-cyan",
    "approved": "ion-c-green",
    "scheduled": "ion-c-cyan",
    "implemented": "ion-c-green",
    "closed": "ion-c-muted",
    "rejected": "ion-c-red",
    "cancelled": "ion-c-muted",
}


def _created_display(raw: object) -> str:
    """`2026-10-12T08:30:11.123456` as `2026-10-12 08:30`.

    The JavaScript did `new Date(iso).toISOString()`, which parses a naive
    stamp as local time and then converts it to UTC, so the column was off by
    the browser's offset. These timestamps are already naive UTC (see
    service_desk_service._now), so the stored value is the honest one and
    this only trims it.
    """
    if not raw:
        return ""
    return str(raw)[:16].replace("T", " ")


def _as_text(raw: object) -> str:
    """A SQLEnum column's value as a plain string.

    ui._shared.plain does the unwrapping, shared with the other
    conversions that hit the same trap. The str() is local, because the
    transition table and the colour maps here are keyed by string and a
    comparison against an enum member would silently match nothing.
    """
    return str(plain(raw))


def _next_actions(status: object) -> list[dict[str, str]]:
    """The transitions legal from `status`, in the service's own order.

    Imported from the service rather than restated: the JavaScript carried a
    NEXT_ACTIONS map that was a second copy of this state machine, and a
    second copy of a rule keeps offering what the first one has stopped
    allowing. `_TRANSITIONS` is private, which is the cost of there being no
    public accessor for it yet.
    """
    from ion.services.service_desk_service import _TRANSITIONS

    current = _as_text(status)
    out: list[dict[str, str]] = []
    for action, (allowed_from, _new) in _TRANSITIONS.items():
        if current not in allowed_from:
            continue
        label, css = _ACTION_CHROME.get(action, (action.title(), "ion-btn-ghost"))
        out.append({"action": action, "label": label, "css": css})
    return out


def _row_view(cr: dict[str, Any]) -> dict[str, Any]:
    """One change request with the derived fields the table needs."""
    row = dict(cr)
    status = _as_text(cr.get("status"))
    risk = _as_text(cr.get("risk_level"))
    row["status"] = status
    row["risk_level"] = risk
    row["status_css"] = _STATUS_COLOUR.get(status, "ion-c-muted")
    row["risk_css"] = _RISK_COLOUR.get(risk, "ion-c-muted")
    row["created_display"] = _created_display(cr.get("created_at"))
    row["actions"] = _next_actions(status)
    return row


@router.get(
    "/change-requests",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(_PERM))],
)
def change_requests_fragment(
    request: Request,
    status: Optional[str] = Query("all"),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The filtered change-request table as one fragment.

    Replaces three innerHTML writes in change_requests.html: the rows, the
    empty row and the failure row. The permission is imported from
    change_request_api rather than spelled again, so the fragment cannot
    become a softer way in than /api/change-requests.
    """
    from ion.web.change_request_api import change_requests_payload

    try:
        payload = change_requests_payload(status, session)
        rows = [_row_view(c) for c in payload["change_requests"]]
    except Exception:
        logger.exception("Change-request fragment could not be rendered")
        # A failed read is not an empty CAB queue. Rendering an empty table
        # for it would say there is nothing to approve.
        return templates.TemplateResponse(
            request=request,
            name="_fragments/change_requests.html",
            context={"rows": None, "status": status, "failed": True},
        )

    return templates.TemplateResponse(
        request=request,
        name="_fragments/change_requests.html",
        context={"rows": rows, "status": status, "failed": False},
    )
