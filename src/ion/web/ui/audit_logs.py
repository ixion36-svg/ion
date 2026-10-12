"""The audit log table, rendered on the server.

audit_logs.html built every row with a template literal, including a
secret-hiding filter over the details object. That filter ran in the
browser, which means the values were already in the response body and the
filter only kept them out of the table. Rendering here moves it to where
the data is assembled, so a key named like a secret never reaches the
page at all.

The JSON endpoint still has no redaction of its own. No audit producer in
the tree writes such a key today, so nothing leaks, and changing a JSON
contract other consumers may read is not this conversion's business. It is
logged as its own piece of work.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()

# Lifted verbatim from the page's ACTION_BADGE object. Unmapped actions take
# badge-ghost, which is the neutral one: a new action type must not inherit
# the colour of a security event it has nothing to do with.
ACTION_BADGE = {
    "login": "badge-success",
    "logout": "badge-ghost",
    "login_failed": "badge-error",
    "password_changed": "badge-info",
    "password_reset": "badge-info",
    "user_created": "badge-warning",
    "user_updated": "badge-warning",
    "user_deleted": "badge-warning",
    "user_roles_updated": "badge-warning",
}

# A details key containing any of these is not rendered. Substring match, as
# the JavaScript did, so `password_hash` and `new_password` are both caught.
SECRET_KEY_MARKERS = ("password", "token", "hash", "secret", "api_key")


def format_action(action: str | None) -> str:
    """`login_failed` to `Login Failed`, as the page's formatAction did."""
    if not action:
        return "-"
    return action.replace("_", " ").title()


def visible_details(details: Any) -> list[tuple[str, str]] | str | None:
    """The details object with anything named like a secret dropped.

    Returns a list of label/value pairs for an object, the string itself for
    a legacy bare-string row, and None for an empty one. Those are three
    different things on the page and collapsing them loses information: a
    row with no details and a row whose details were all redacted would
    otherwise look identical.

    The filter is a substring match on the key, the same rule the browser
    applied, widened to `secret` and `api_key`. It is deliberately not a
    match on the value: a redactor that guesses from values hides real
    audit content and misses a secret stored under an innocent name.
    """
    if not details:
        return None
    if not isinstance(details, dict):
        # Some historical producers stored a bare string, e.g. an IP range.
        return str(details)

    out: list[tuple[str, str]] = []
    for key, value in details.items():
        lowered = str(key).lower()
        if any(marker in lowered for marker in SECRET_KEY_MARKERS):
            continue
        if isinstance(value, (dict, list, tuple)):
            import json

            shown = json.dumps(value)
        else:
            shown = str(value)
        out.append((str(key).replace("_", " "), shown))
    return out


@router.get(
    "/audit-logs",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("system:audit_view"))],
)
def audit_logs_fragment(
    request: Request,
    offset: int = Query(0, ge=0),
    page_size: int = Query(50, ge=1, le=200),
    action: str | None = Query(None),
    resource_type: str | None = Query(None),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """One page of the audit trail, rows and pager together.

    `system:audit_view` matches /api/audit-logs exactly. A fragment must not
    be a softer way in than the API it mirrors, and this one reads the
    journal that records who did what.

    It asks the repository for one row more than it shows, so "there is a
    next page" is measured rather than guessed. The page inferred it from
    `logs.length === pageSize`, which enables Next on the last page whenever
    the total is an exact multiple of the page size, and then shows an empty
    table to a user who followed it.
    """
    from ion.web.api import _parse_audit_details
    from ion.storage.auth_repository import AuditLogRepository

    try:
        rows = AuditLogRepository(session).list_all(
            limit=page_size + 1,
            offset=offset,
            action=action or None,
            resource_type=resource_type or None,
        )
        has_next = len(rows) > page_size
        logs = [
            {
                "username": r.user.username if r.user else None,
                "action": r.action,
                "action_label": format_action(r.action),
                "badge": ACTION_BADGE.get(r.action or "", "badge-ghost"),
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "details": visible_details(_parse_audit_details(r.details)),
                "ip_address": r.ip_address,
                "timestamp": r.timestamp,
            }
            for r in rows[:page_size]
        ]
    except Exception:
        logger.exception("Audit log fragment could not be rendered")
        # An unreadable journal is not an empty one. "No audit logs" would
        # read as "nothing has happened", which on this page is the single
        # most misleading thing it could say.
        return templates.TemplateResponse(
            request=request,
            name="_fragments/audit_logs.html",
            context={"logs": None, "failed": True, "offset": 0,
                     "page_size": page_size, "has_next": False},
        )

    return templates.TemplateResponse(
        request=request,
        name="_fragments/audit_logs.html",
        context={"logs": logs, "failed": False, "offset": offset,
                 "page_size": page_size, "has_next": has_next},
    )
