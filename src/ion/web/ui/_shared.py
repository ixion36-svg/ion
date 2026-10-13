"""The one Jinja environment every /ui fragment renders through, and the
helpers more than one page needs.

make_templates() builds a fresh Jinja2Templates on each call, so a module
per page calling it would stand up one environment, and one bytecode cache
handle, per page. There are 35 pages left to convert. This is the single
instance they share.

Importing server.templates instead would loop: server imports this router.

A function earns a place here once a second page needs it. `rows` arrived
that way and is the clearest case: the alerts conversion and the
threat_intel conversion wrote it independently, with the same name and the
same reasoning in the docstring, without either knowing about the other.
Two copies of one decision is the drift this module exists to stop.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Optional

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from ion.web.templating import make_templates

templates = make_templates()


def wants_json(request: Request) -> bool:
    """Whether this caller asked for the view model rather than the markup.

    Strict on purpose. JSON is served only when the Accept header names it
    and does not name HTML, so htmx, which sends
    `text/html, */*; q=0.01`, and a browser address bar, which sends
    `text/html,...`, both keep getting markup. A client that sends `*/*`,
    or no Accept at all, gets markup too: HTML is what these routes are
    for, and JSON is the deliberate ask.
    """
    accept = request.headers.get("accept") or ""
    return "application/json" in accept and "text/html" not in accept


def render_view(
    request: Request,
    name: str,
    view: Mapping[str, Any],
    *,
    status_code: int = 200,
) -> Response:
    """Render one view model, as this page's fragment or as JSON.

    The point is that there is one object. A route that assembles its
    template context inline has no name for the thing it renders, so there
    is nothing a different front end could be built against and nothing a
    type checker can hold. A route that hands its whole context to this
    helper has published its contract by construction.

    Nothing new is exposed. The JSON is the same object the template reads,
    reached through the same route with the same permission dependency, so
    a caller who may not see the markup cannot see the model either.
    """
    if wants_json(request):
        return JSONResponse(dict(view), status_code=status_code)
    return templates.TemplateResponse(
        request=request, name=name, context=dict(view), status_code=status_code,
    )


def plain(value: object) -> object:
    """An enum member's value, or the value unchanged.

    ION's status, severity and risk columns are `SQLEnum`, so a row read
    through the ORM carries the enum member rather than its string. The JSON
    endpoints got the string for free, because FastAPI serialises a
    str-mixin enum by value. A template does not: on Python 3.12
    `str(ChangeRequestStatus.SUBMITTED)` is "ChangeRequestStatus.SUBMITTED",
    which is what a pill renders.

    Value equality still holds, so a colour map keyed by the string keeps
    working and only the visible text is wrong. That is why it survives a
    glance and why it is worth one shared definition: two conversions in the
    same batch hit it independently and each wrote this function.

    None passes through, because a missing status is not the string "None".
    """
    if isinstance(value, Enum):
        return value.value
    return value


def rows(payload: Any, key: str) -> Optional[list]:
    """The list under `key`, or None when the payload is not that shape.

    None is the third outcome and the whole point. `data.cases || []` and
    `d.actors || []` turned a refusal, a validation error and a genuinely
    empty collection into the same empty list, and all three then rendered
    the same sentence: "No cases", "No threat actors found", "No active
    watches". A caller that gets None here has to say the read failed; it
    cannot accidentally say "none found".
    """
    if not isinstance(payload, dict):
        return None
    found = payload.get(key)
    if not isinstance(found, list):
        return None
    return found


#: Closure reasons in the words a reader sees. ION stores the enum value.
CLOSURE_LABELS: dict[str, str] = {
    "true_positive": "True Positive",
    "false_positive": "False Positive",
    "benign_true_positive": "Benign True Positive",
    "duplicate": "Duplicate",
    "insufficient_data": "Insufficient Data",
    "not_applicable": "Not Applicable",
}

#: The short form a badge carries where there is no room for the words.
CLOSURE_SHORT: dict[str, str] = {
    "true_positive": "TP",
    "false_positive": "FP",
    "benign_true_positive": "BTP",
    "duplicate": "DUP",
    "insufficient_data": "N/D",
    "not_applicable": "N/A",
}


def closure_label(reason: Any) -> Optional[str]:
    """The words for a closure reason, the raw value for one these maps do
    not know, None for no reason at all.

    A reason nobody recorded and a reason this map has not caught up with
    are different, and only the first means the case was closed without
    saying why.
    """
    value = plain(reason)
    if not value:
        return None
    return CLOSURE_LABELS.get(str(value), str(value))


def closure_short(reason: Any) -> Optional[str]:
    """`closure_label`'s badge form."""
    value = plain(reason)
    if not value:
        return None
    return CLOSURE_SHORT.get(str(value), str(value))


def active_total(facets: Any) -> Optional[int]:
    """Open plus acknowledged, or None when the facets are not readable.

    A status missing from `by_status` is a true zero: the service builds
    that dict from a GROUP BY, which omits empty groups. That is different
    from the facets read failing, which is None here and was the size of
    the fetched page in the JavaScript, so a capped page of 50 reported
    "50 active cases" however many there really were.
    """
    if not isinstance(facets, dict):
        return None
    by_status = facets.get("by_status")
    if not isinstance(by_status, dict):
        return None
    total = 0
    for key in ("open", "acknowledged"):
        count = by_status.get(key, 0)
        if isinstance(count, bool) or not isinstance(count, int):
            return None
        total += count
    return total


def parse_instant(value: Any) -> Optional[datetime]:
    """An aware datetime from what the case reads emit, or None.

    Those rows are `isoformat()` of a naive column. A naive value is read
    as UTC, which is what SQLite's func.now() stores and what a Postgres
    whose session timezone is UTC stores. The JavaScript did `new Date(iso)`,
    which parses a zoneless string as the viewer's local time, so every age
    it showed was wrong by the viewer's offset.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def age_label(created_at: Any, now: Optional[datetime] = None) -> Optional[str]:
    """"3d", "5h" or "12m", or None when there is no usable timestamp.

    None, not zero. The JavaScript initialised its elapsed milliseconds to
    0 for a missing created_at and rendered "0m old", a confident age for a
    case whose creation time it did not have.
    """
    created = parse_instant(created_at)
    if created is None:
        return None
    now = now or datetime.now(timezone.utc)
    seconds = max(0.0, (now - created).total_seconds())
    if seconds > 86400:
        return f"{int(seconds // 86400)}d"
    if seconds > 3600:
        return f"{int(seconds // 3600)}h"
    return f"{int(seconds // 60)}m"
