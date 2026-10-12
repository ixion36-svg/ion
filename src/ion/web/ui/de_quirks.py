"""The System Quirks table, rows and action buttons together.

Replaces four innerHTML writes in de_quirks.html (the loading placeholder,
the load-failure alert, the empty state and the table) plus the hand-rolled
`qkEsc()` they needed.

This is the first fragment on a licence-gated page, so it carries both of
the gates its JSON counterpart carries and in the same order:

  * ``require_de_module`` first, because /api/de/quirks gets it from
    ``include_router(de_router, ..., dependencies=[Depends(require_de_module)])``
    and router dependencies run before route dependencies. With the module
    off it answers 404 before authentication is considered, which is the
    point of a 404 rather than a 403: a licence-gated deployment is
    indistinguishable from one where the endpoint does not exist.
  * ``require_permission("de:read")`` second, the same permission the JSON
    endpoint names. Not ``require_page_permission``: that redirects to
    /login, and htmx would swap a login form into the middle of the page.

Three outcomes, three different renders, because they lead to different
actions:

  module off   404, no fragment at all. static/js/htmx-errors.js says it is
               no longer available. Nothing about the quirk store leaks.
  read failed  200 with a fragment that says the read failed. Never 0 rows,
               because "no quirks are recorded" and "we could not look" are
               opposite findings for an advisory-suppression surface.
  no quirks    200 with the empty state the JavaScript had.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.licensing.gating import require_de_module
from ion.models.system_quirk import SystemQuirkStatus
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

#: The permission /api/de/quirks names. Spelled once so the fragment cannot
#: drift into being a softer way in than the endpoint it mirrors.
PERMISSION = "de:read"

_STATUS_CSS = {
    SystemQuirkStatus.PENDING.value: "badge-warning",
    SystemQuirkStatus.ACTIVE.value: "badge-success",
    SystemQuirkStatus.REVERTED.value: "badge-error",
}

#: Which lifecycle actions a row may offer, keyed by status.
#:
#: A table rather than the two-branch `if` the JavaScript had, because the
#: rule it encodes lives in de_quirk_service and the branch was a second
#: copy of it: `verify_quirk` rejects anything that is not PENDING, and
#: `revert_quirk` rejects anything already REVERTED. Keying it by the enum's
#: own values means a new state added to SystemQuirkStatus shows up as a
#: missing key here, which is a test failure rather than a row that silently
#: offers nothing.
_VERIFY = {"action": "qkVerify", "label": "Verify", "css": "btn-ghost"}
_REVERT = {"action": "qkRevert", "label": "Revert", "css": "btn-ghost btn-error"}
_ACTIONS: dict[str, list[dict[str, str]]] = {
    SystemQuirkStatus.PENDING.value: [_VERIFY, _REVERT],
    SystemQuirkStatus.ACTIVE.value: [_REVERT],
    SystemQuirkStatus.REVERTED.value: [],
}

_SCOPE_PREFIXES = (
    ("rule", "scope_rules"),
    ("host", "scope_hosts"),
    ("user", "scope_users"),
    ("ip", "scope_ips"),
)


def _scope_chips(q: dict[str, Any]) -> list[str]:
    """Every scope value as a prefixed chip label, in the JavaScript's order.

    Labels, not markup: the badge is a Jinja loop in the fragment, so a
    scope value containing `<script>` is escaped by the template rather than
    by a hand-rolled `qkEsc`.
    """
    chips: list[str] = []
    for prefix, key in _SCOPE_PREFIXES:
        for value in q.get(key) or []:
            chips.append(f"{prefix}:{value}")
    for obs in q.get("scope_observables") or []:
        if not isinstance(obs, dict):
            continue
        chips.append(f"{obs.get('type') or ''}:{obs.get('value') or ''}")
    return chips


def _as_dt(raw: object) -> Optional[datetime]:
    """An ISO timestamp from `SystemQuirk.to_dict()` back as a datetime.

    `to_dict` isoformats the column for JSON, and the `ts` macro wants the
    value: handed a naive ISO *string* it can only echo the string, so the
    Review column would read "2026-11-01T00:00:00". A datetime renders as
    "2026-11-01 00:00" with a title saying whose clock that is.

    The time of day is kept rather than trimmed to a date the way
    `(q.review_date||'').slice(0,10)` did, because `quirk_match` compares
    against the instant: a quirk goes inert at that time of day, not at the
    end of that date.
    """
    if not raw:
        return None
    if isinstance(raw, datetime):
        return raw
    try:
        return datetime.fromisoformat(str(raw).replace("Z", ""))
    except (TypeError, ValueError):
        return None


def _row(q: dict[str, Any]) -> dict[str, Any]:
    """One quirk with the fields the table needs derived."""
    row = dict(q)
    status = plain(q.get("status"))
    status = None if status is None else str(status)
    row["status"] = status
    row["status_css"] = _STATUS_CSS.get(status, "badge-ghost")
    # Three states, kept at three. `expired` is True, False, or absent when
    # a caller hands over a row that never computed it, and an absent value
    # must not render the "expired" pill: a quirk whose expiry is unknown is
    # not a quirk known to have lapsed. Only `active` shows it at all,
    # because a reverted quirk is already inert.
    row["expired_badge"] = status == SystemQuirkStatus.ACTIVE.value and (
        q.get("expired") is True
    )
    row["scope_chips"] = _scope_chips(q)
    row["review_date"] = _as_dt(q.get("review_date"))
    row["actions"] = _ACTIONS.get(status, [])
    return row


@router.get(
    "/de-quirks",
    response_class=HTMLResponse,
    dependencies=[
        Depends(require_de_module),
        Depends(require_permission(PERMISSION)),
    ],
)
def de_quirks_fragment(
    request: Request,
    status: str = Query("all", description="pending | active | reverted | all"),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The filtered quirk table as one fragment.

    Calls `de_quirk_service.list_quirks`, which is the whole body of
    GET /api/de/quirks, so the two cannot answer differently. Nothing was
    extracted into a `*_payload()` helper because there is nothing inline in
    that route to share: it is one call and a dict wrapper.
    """
    from ion.services.de_quirk_service import list_quirks

    context: dict[str, Any] = {"status": status}
    try:
        quirks = [_row(q) for q in list_quirks(session, status=status)]
    except Exception:
        logger.exception("System quirks fragment could not be rendered")
        context.update({"quirks": None, "failed": True})
        return templates.TemplateResponse(
            request=request, name="_fragments/de_quirks.html", context=context
        )

    context.update({"quirks": quirks, "failed": False})
    return templates.TemplateResponse(
        request=request, name="_fragments/de_quirks.html", context=context
    )
