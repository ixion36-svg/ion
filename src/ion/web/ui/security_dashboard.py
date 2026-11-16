"""The security dashboard, as server-rendered fragments.

Replaces the thirteen innerHTML writes in security_dashboard.html: the
threat-banner figures, the threat-type list, the top-source-IP list, the
events table (its loading row, its empty row, its data rows and its error
row), the blocked-IP list, and the event-detail modal body.

The nineteen ``escapeHtml()`` calls those needed go with them, but there is
no hand-rolled ``esc()`` on this page to delete: the page called the shared
``escapeHtml`` in ``static/js/app.js``, which nine other templates still
use and which stays exactly where it is. The contract's hand-rolled-esc
rule was written for ``service_accounts``, where the function was local.
What this conversion removes here is one caller, and what replaces it is
Jinja's autoescaping, which has its own test feeding ``<script>``.

The page is ``/security`` and its permission is ``security:read``.
``tools/fragment_plan.py`` reads the live gates, and every GET the script
fetches is ``require_permission('security:read')`` (plus the
``get_current_user`` that factory already depends on):

  * GET /api/security/threat-summary
  * GET /api/security/statistics
  * GET /api/security/events
  * GET /api/security/events/{event_id}
  * GET /api/security/blocked-ips

None of those routes carries ``require_de_module``, and neither does the
mount in server.py (``include_router(security_router, prefix="/api/security")``
with no dependencies). This module does not add the gate. A
detection-engineering licence check would answer 404 on a deployment that
is not licensed for that module, and the security dashboard is the posture
page, not a DE page: the API would still be serving it. A fragment must
not be a softer way in than the API it mirrors, and it must not pretend a
page the API serves does not exist.

``require_page_permission`` is the page's own gate and redirects to
/login, which htmx would swap into the middle of the dashboard.

The three writes the page can make are gated harder than the reads:

  * POST   /api/security/blocked-ips                security:manage
  * DELETE /api/security/blocked-ips/{ip_address}   security:manage
  * PATCH  /api/security/events/{event_id}/status   security:manage

``security:read`` is therefore enough to read this dashboard and not
enough to act on it, so every action control is withheld from a viewer
who holds only the read. The old page rendered Block, Unblock and the
status select for everyone and let the 403 teach the rule, which made
clicking the only way to learn it. ``can_manage`` is read off the user the
read dependency already resolved, so it cannot drift from the gate the
API enforces.

No write on this page refuses by record state, which was measured rather
than assumed. ``BlockedIPRepository.unblock`` matches any row by address
and every row the list renders exists, so a listed Unblock cannot 404.
The status select is built from ``SecurityEventStatus``, so the 400 on an
unknown status is unreachable, and the status 404 is for an event the
detail read just found. Nothing here is withheld on record state, because
a control withheld for a rule the server does not enforce is the same
defect the other way round.

One write is state-dependent without refusing. ``BlockedIPRepository.block``
upserts, so a quick block of an address already on the list overwrites its
reason, its expiry and its permanent flag with "60 minutes, not
permanent". On a permanent block that is a button marked "Block IP"
silently shortening live security state. The control stays, because the
server allows it, and it names what it would do instead.

Two fragments, one template. The dashboard is one swap because the banner,
the cards and the three lists are one paint, and Refresh has one
definition. The event detail is a second route because it is a second
request, made when a row is opened, and it must not re-send the table's
severity and hours.

Each read is caught on its own. The threat summary, the 24-hour
statistics, the event window and the block list are four queries, and one
of them throwing must not be worded as an empty list: "nothing in this
window" and "we could not look" lead to opposite actions on a posture
page.

What the old page did wrong here was not cross-contamination. It already
had four independent try/catch blocks, so a throw in one loader never
zeroed another panel. It left the other panels in their *loading* state
instead, forever: a failed threat-summary read kept the server-rendered
"Loading threat assessment..." banner and left both side lists spinning,
and a non-ok statistics response hit ``if (!response.ok) return;`` with no
log and no toast, leaving four dashes identical to the pre-load markup.
"Still loading" and "could not be read" were the same picture, and on the
statistics card nothing anywhere recorded the failure. That is the state
these branches replace.

The stat cards stay the 24-hour statistics. The events filter has its own
window, and the JavaScript asked ``/api/security/statistics?hours=24``
regardless of which window the table was on. A one-hour filter must not
turn the 24-hour total into a one-hour total.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Literal, Optional
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.security import (
    SecurityEventSeverity,
    SecurityEventStatus,
)
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

#: The permission the GET endpoints name. Spelled once so neither fragment
#: can drift into being a softer way in than the API it mirrors, and so
#: neither can drift the other way into ``security:manage``, which is the
#: gate on block, unblock and status and would lock a read behind a write.
PERMISSION = "security:read"

#: The permission POST /blocked-ips, DELETE /blocked-ips/{ip} and PATCH
#: /events/{id}/status all name. It gates the controls, never the fragment:
#: requiring it to render would lock the read behind the write.
MANAGE_PERMISSION = "security:manage"

#: What the page sent and what GET /api/security/events defaults to.
_EVENT_LIMIT = 100

#: decodeURIComponent throws on a % that is not two hex digits. unquote does
#: not, so this is the check that keeps the raw string, which is what the
#: table showed when the payload was not valid percent-encoding.
#:
#: It is only half of what decodeURIComponent refuses. The other half is a
#: well-formed escape whose bytes are not valid UTF-8, and that one is
#: handled by decoding strictly in :func:`_decode_query` rather than by a
#: pattern, because no regex over the percent escapes can decide it.
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")

_LEVELS = {"critical", "high", "medium", "low", "normal"}

#: The status select. Built from the enum so a status added to
#: SecurityEventStatus shows up here instead of being a value the API will
#: accept and the modal cannot set.
STATUSES: list[tuple[str, str]] = [
    (status.value, status.value.replace("_", " ").title())
    for status in SecurityEventStatus
]


def _count(value: object) -> Optional[int]:
    """A real count, or None.

    ``bool`` is an ``int`` subclass, so ``isinstance(True, int)`` is true
    and a bare type check would publish a flag as the count 1. Zero is a
    measurement and comes back as zero.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value == value and value.is_integer():
        return int(value)
    return None


def _severity_count(by_severity: object, name: str) -> Optional[int]:
    """One severity's count out of a statistics payload that was read.

    ``get_statistics`` groups only the severities that occurred, so a
    severity it does not mention was counted and came to nothing: that is
    zero. A map that is not there was not counted, and a value that is not
    a number was not a count. Neither of those is zero.
    """
    if not isinstance(by_severity, dict):
        return None
    if name not in by_severity:
        return 0
    return _count(by_severity[name])


def _words(value: object) -> Optional[str]:
    """``sql_injection`` -> ``Sql Injection``, the JavaScript's formatting.

    ``plain`` first, because a SQLEnum member stringifies as
    ``SecurityEventType.SQL_INJECTION`` on Python 3.12 and title-casing
    that renders the repr.
    """
    text = plain(value)
    if text is None:
        return None
    raw = str(text)
    if raw == "":
        return None
    return raw.replace("_", " ").title()


def _badge(kind: str, value: Optional[str]) -> str:
    """``severity-badge severity-critical`` / ``status-badge status-false-positive``.

    The status class uses hyphens because the stylesheet keys
    ``.status-false-positive`` and the enum value uses an underscore.
    """
    base = f"{kind}-badge"
    if not value:
        return base
    return base + " " + kind + "-" + value.replace("_", "-")


def _blank(value: object) -> Optional[str]:
    """A display string, or None when nothing was recorded.

    Empty and missing are the same claim for these columns: the JavaScript
    showed ``-`` for both. The string ``"0"`` is a value and is kept.
    """
    if value is None:
        return None
    text = str(plain(value))
    return text if text != "" else None


def _decode_query(raw: str) -> str:
    """``decodeURIComponent``, including both of its throws.

    ``+`` is left as ``+``. ``unquote_plus`` would turn it into a space,
    which is a different payload from the one that was sent.

    ``errors="strict"`` is the load-bearing argument. ``decodeURIComponent``
    throws on a well-formed escape whose bytes are not valid UTF-8, and the
    JavaScript caught that and showed the raw string. unquote's default is
    ``errors="replace"``, which turns ``%C0%80`` and ``%FF`` into U+FFFD.
    Those are exactly the overlong and invalid UTF-8 sequences a WAF bypass
    is built out of, so replacing them destroys the evidence the cell exists
    to show, and does it silently: the analyst sees a replacement glyph and
    has no way to tell it apart from one the attacker really sent.
    """
    if _BAD_PERCENT.search(raw):
        return raw
    try:
        return unquote(raw, errors="strict")
    except UnicodeDecodeError:
        return raw


def _clip(text: str, *, always_ellipsis: bool) -> str:
    """The table cell, as the JavaScript clipped it.

    A query string is clipped only past 100 characters. A body always
    grows an ellipsis, including when it is shorter than that, because
    that is what ``substring(0, 100) + '...'`` did. ``matched_content`` is
    not clipped at all; the stylesheet ellipsises the cell.
    """
    if len(text) > 100:
        return text[:100] + "..."
    if always_ellipsis:
        return text + "..."
    return text


def _present(raw: object, key: str) -> Optional[str]:
    """A raw_data field that was recorded, including ``""`` and ``0``.

    Absence is ``None``. A present value is used even when it is empty or
    the number 0: the JavaScript's truthiness test skipped 0 and fell
    through to the next field, which is a different payload.
    """
    if not isinstance(raw, dict) or key not in raw or raw[key] is None:
        return None
    return str(raw[key])


def matched_preview(raw: object) -> dict[str, str]:
    """The matched-content cell: visible text, and the full value for the title.

    Precedence is the JavaScript's: matched content, then the query
    string, then the body.

    The title is a deliberate divergence, not a port. The JavaScript put
    the already-clipped string in the tooltip, so on both clipped branches
    hovering showed the visible cell text again, ellipsis included, and
    gained the analyst nothing. The unclipped value goes there instead,
    because the cell is ellipsised by the stylesheet and the payload is the
    evidence. It is unbounded, where the old tooltip was capped near 103
    characters, and ``raw_data`` is a free-form JSON column: a hundred-row
    table can carry a hundred full request bodies in title attributes.
    """
    content = _present(raw, "matched_content")
    if content is not None:
        return {"text": content, "title": content}
    query = _present(raw, "query_string")
    if query is not None:
        decoded = _decode_query(query)
        return {"text": _clip(decoded, always_ellipsis=False), "title": decoded}
    body = _present(raw, "body")
    if body is not None:
        return {"text": _clip(body, always_ellipsis=True), "title": body}
    return {"text": "-", "title": "-"}


def payload_sections(raw: object) -> list[dict[str, str]]:
    """The modal's payload blocks, in the JavaScript's order, unclipped.

    A section is omitted only when its field was not recorded. An empty
    string and the number 0 were recorded and are shown.
    """
    if not isinstance(raw, dict):
        return []
    specs = (
        ("matched_content", "MATCHED MALICIOUS CONTENT:",
         "bg-error/10 text-error border border-error"),
        ("query_string", "Query String:", "bg-base-100"),
        ("body", "Request Body:", "bg-base-100"),
        ("path", "Request Path:", "bg-base-100"),
    )
    sections = []
    for key, label, css in specs:
        text = _present(raw, key)
        if text is None:
            continue
        if key == "query_string":
            text = _decode_query(text)
        sections.append({"label": label, "text": text, "css": css})
    return sections


def _patterns(value: object) -> list[Any]:
    if not isinstance(value, list):
        return []
    found = []
    for item in value:
        if item is None:
            continue
        found.append(item if isinstance(item, str) else str(plain(item)))
    return found


def event_view(event: Any) -> dict[str, Any]:
    """One security event with the fields the table and the modal share.

    Takes the ORM row ``get_recent_events`` and ``get_by_id`` return, not
    the pydantic response. FastAPI unwrapped the SQLEnum columns on the way
    to JSON; the template does not, so ``plain`` does it here.
    """
    severity = _blank(getattr(event, "severity", None))
    status = _blank(getattr(event, "status", None))
    event_type = _blank(getattr(event, "event_type", None))
    raw = getattr(event, "raw_data", None)
    return {
        "id": getattr(event, "id", None),
        "title": _blank(getattr(event, "title", None)),
        "description": _blank(getattr(event, "description", None)),
        "source_ip": _blank(getattr(event, "source_ip", None)),
        "severity": severity,
        "severity_class": _badge("severity", severity),
        "status": status,
        "status_label": _words(status),
        "status_class": _badge("status", status),
        "type_label": _words(event_type),
        "created_at": getattr(event, "created_at", None),
        "first_seen": getattr(event, "first_seen", None),
        "last_seen": getattr(event, "last_seen", None),
        "event_count": _count(getattr(event, "event_count", None)),
        "confidence_score": _count(getattr(event, "confidence_score", None)),
        "username": _blank(getattr(event, "username", None)),
        "request_path": _blank(getattr(event, "request_path", None)),
        "request_method": _blank(getattr(event, "request_method", None)),
        "user_agent": _blank(getattr(event, "user_agent", None)),
        "matched": matched_preview(raw),
        "payload": payload_sections(raw),
        "patterns": _patterns(getattr(event, "matched_patterns", None)),
    }


def stats_view(data: object) -> dict[str, Optional[int]]:
    """The four cards. Hours are not an argument: the cards are 24h.

    A missing ``by_severity`` is not four zeros. The query that produced an
    empty map still counted, and :func:`_severity_count` turns the missing
    keys into zero. A payload that has no map did not count.
    """
    if not isinstance(data, dict):
        raise ValueError("security statistics were not a dict")
    by_severity = data.get("by_severity") if "by_severity" in data else None
    return {
        "total": _count(data["total_events"]) if "total_events" in data else None,
        "critical": _severity_count(by_severity, "critical"),
        "high": _severity_count(by_severity, "high"),
        "blocked": _count(data["blocked_count"]) if "blocked_count" in data else None,
    }


def _pair_list(data: dict, key: str, label_key: str, *, words: bool) -> Optional[list]:
    """A ``[{label, count}]`` list, or None when the summary did not carry it.

    None is not ``[]``. An empty list means the summary looked and found
    nothing. A missing key means this fragment does not know.
    """
    if key not in data or data[key] is None or not isinstance(data[key], list):
        return None
    rows = []
    for row in data[key]:
        if not isinstance(row, dict) or label_key not in row or row[label_key] is None:
            continue
        label = str(plain(row[label_key]))
        rows.append({
            "label": label,
            "text": _words(label) if words else label,
            "count": _count(row["count"]) if "count" in row else None,
        })
    return rows


def summary_view(data: object) -> dict[str, Any]:
    """The banner and the two lists, from ``get_threat_summary``'s dict.

    The threat level is that function's. It is not recomputed here, so the
    banner cannot disagree with GET /api/security/threat-summary about
    whether the estate is critical.
    """
    if not isinstance(data, dict):
        raise ValueError("threat summary was not a dict")
    level = plain(data.get("threat_level")) if "threat_level" in data else None
    level = None if level is None else str(level)
    last_hour = data.get("last_hour") if isinstance(data.get("last_hour"), dict) else {}
    return {
        "threat_level": level,
        "level_class": level if level in _LEVELS else "",
        "active_blocks": (
            _count(data["active_blocks"]) if "active_blocks" in data else None
        ),
        "last_hour_total": (
            _count(last_hour["total"]) if "total" in last_hour else None
        ),
        "top_threats": _pair_list(data, "top_threats", "type", words=True),
        "top_attackers": _pair_list(data, "top_attackers", "ip", words=False),
    }


def blocked_view(row: Any) -> dict[str, Any]:
    """One block, with ``permanent`` kept as a real boolean or as unknown.

    Anything that is not ``True`` or ``False`` stays ``None``. Folding it
    into either branch would call a block permanent, or call it indefinite,
    when the flag was never a flag.

    The third state is defensive rather than observed. ``BlockedIP.permanent``
    is ``Boolean, nullable=False, default=False``, and these rows come out
    of ``get_all_active()``, so SQLAlchemy hands back a real ``bool``. The
    unmeasured case needs an unflushed instance or a migration that makes
    the column nullable. It is kept because it costs a branch and the
    alternative is a template that states a block's duration from a flag it
    did not read. ``is true`` / ``is false`` is safe here precisely because
    the value arrives through the ORM: a raw row handing back ``1`` would
    land in the third branch, which says "unknown" rather than guessing.
    """
    flag = getattr(row, "permanent", None)
    if flag is not True and flag is not False:
        flag = None
    return {
        "ip_address": _blank(getattr(row, "ip_address", None)),
        "permanent": flag,
        "blocked_until": getattr(row, "blocked_until", None),
    }


def _attempt(label: str, fn: Any) -> tuple[Any, bool]:
    """``(value, failed)``. A throw is a failed read, logged, not a zero."""
    try:
        return fn(), False
    except Exception:
        logger.exception("Security dashboard %s could not be read", label)
        return None, True


def _raw_summary(session: Session) -> dict:
    """``GET /api/security/threat-summary``'s own function.

    The threat-level maths lives inline in that route. Calling it is the
    reuse: a second copy here would keep announcing a level after the
    thresholds moved.
    """
    from ion.web.security_api import get_threat_summary

    return get_threat_summary(session=session, current_user=None)


def _raw_stats(session: Session) -> dict:
    from ion.services.security_service import SecurityDetectionService

    return SecurityDetectionService(session).get_statistics(hours=24)


def _raw_events(session: Session, hours: int, severity: str) -> list[dict]:
    from ion.services.security_service import SecurityDetectionService

    wanted = SecurityEventSeverity(severity) if severity else None
    rows = SecurityDetectionService(session).get_recent_events(
        hours=hours, severity=wanted, limit=_EVENT_LIMIT,
    )
    return [event_view(row) for row in rows]


def _raw_blocked(session: Session) -> list[dict]:
    from ion.services.security_service import SecurityDetectionService

    return [
        blocked_view(row)
        for row in SecurityDetectionService(session).get_blocked_ips()
    ]


def _blocked_addresses(rows: Optional[list[dict]]) -> Optional[set[str]]:
    """The addresses on the active block list, or None when it was not read.

    Three states, not two. ``None`` is "we do not know whether this address
    is blocked", and the quick-block control is offered in that case rather
    than being withheld on a guess: the server would accept the click.
    """
    if rows is None:
        return None
    return {
        row["ip_address"] for row in rows if row.get("ip_address") is not None
    }


def _render(request: Request, context: dict[str, Any]) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="_fragments/security_dashboard.html",
        context=context,
    )


@router.get("/security-dashboard", response_class=HTMLResponse)
def security_dashboard_fragment(
    request: Request,
    # Empty is the select's "All Severities". The members are the enum's,
    # so a value the service cannot parse is a 422 rather than a caught
    # exception worded as "the read failed".
    severity: Literal["", "critical", "high", "medium", "low", "info"] = Query(
        "", description="critical | high | medium | low | info | empty for all"
    ),
    # The same bounds as GET /api/security/events. 720 is the export
    # window, not this one; accepting it would show events the JSON
    # endpoint refuses.
    hours: int = Query(24, ge=1, le=168, description="Time period in hours"),
    user: User = Depends(require_permission(PERMISSION)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """Banner, 24h cards, the filtered event table and the three lists.

    ``user`` is used rather than ignored. Which controls a viewer may see
    depends on whether they hold the write permission, so the fragment
    cannot be rendered without knowing who is looking.
    """
    # Resolved before the reads, so a permission lookup that throws can
    # never be reported as a security read that failed.
    can_manage = user.has_permission(MANAGE_PERMISSION)

    summary, summary_failed = _attempt(
        "threat summary", lambda: summary_view(_raw_summary(session))
    )
    stats, stats_failed = _attempt(
        "statistics", lambda: stats_view(_raw_stats(session))
    )
    events, events_failed = _attempt(
        "events", lambda: _raw_events(session, hours, severity)
    )
    blocked, blocked_failed = _attempt(
        "blocked ips", lambda: _raw_blocked(session)
    )
    return _render(request, {
        "panel": "dashboard",
        "hours": hours,
        "severity": severity,
        "summary": summary,
        "summary_failed": summary_failed,
        "stats": stats,
        "stats_failed": stats_failed,
        "events": events,
        "events_failed": events_failed,
        "blocked": blocked,
        "blocked_failed": blocked_failed,
        "blocked_addresses": _blocked_addresses(blocked),
        "can_manage": can_manage,
        "statuses": STATUSES,
    })


@router.get(
    "/security-dashboard/events/{event_id}",
    response_class=HTMLResponse,
)
def security_event_fragment(
    request: Request,
    event_id: int,
    user: User = Depends(require_permission(PERMISSION)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The modal body for one event.

    Missing is 404, which is what ``GET /api/security/events/{event_id}``
    answers, and htmx-errors.js words a 404. A read that throws is a 200
    that says so: htmx does not swap a 500, and the modal would otherwise
    keep whatever it was showing and look like the truth.

    The status select is a write at ``security:manage``, so a viewer with
    only the read gets the record and no select.
    """
    from ion.storage.security_repository import SecurityEventRepository

    can_manage = user.has_permission(MANAGE_PERMISSION)
    try:
        event = SecurityEventRepository(session).get_by_id(event_id)
    except Exception:
        logger.exception("Security event %s could not be read", event_id)
        return _render(request, {
            "panel": "event", "failed": True, "event": None,
            "can_manage": can_manage, "statuses": STATUSES,
        })
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return _render(request, {
        "panel": "event",
        "failed": False,
        "event": event_view(event),
        "can_manage": can_manage,
        "statuses": STATUSES,
    })
