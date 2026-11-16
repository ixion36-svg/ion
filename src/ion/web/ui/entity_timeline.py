"""The cross-source entity timeline, rendered on the server.

entity_timeline.html assembled the whole result from template literals: the
entity header, the source filter pills, every event row, its severity badge
and its meta tags. Four innerHTML writes and a hand-rolled `esc()`.

The source filter was the interesting one. It was a `display:none` sweep
over rows the browser already held, so "filter to the audit source" never
narrowed the request, only the view. Here it narrows what is rendered, and
the pill that clears it is rendered with the rest, so the control and the
thing it controls have one definition.

The search itself still runs through
ion.services.entity_timeline_service.get_entity_timeline, the same function
/api/entity-timeline/search calls. Nothing about the query, the lookback
window, the 200-event cap or the dedupe is reimplemented here. This module
decides only how the result is presented.

Every timestamp on this page comes from a naive `DateTime` column
defaulting to the database's `func.now()`: AlertCase.created_at,
AlertTriage.updated_at, Observable.last_seen/first_seen/created_at,
ObservableEnrichment.enriched_at and AuditLog.timestamp. So all five
sources are on one clock and the page labels the whole timeline server
time, rather than localising some rows and not others. A timeline that
mixed a localised stamp with a server-time stamp would present two clocks
as one sequence, which is worse than either alone.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/entity_timeline.html"

# Lifted from the page's inline ternary. Only these three got a badge; low,
# info and unknown got none. `sev-low` and `sev-info` do exist in
# frontend/ion-legacy.css, so showing a badge for every severity is possible,
# but this page's `severity` is a union of four vocabularies (case severity,
# triage priority, observable threat level and a literal "info"), so which of
# them deserves a pill is a visual decision, not a port.
SEVERITY_CLASS = {
    "critical": "sev-critical",
    "high": "sev-high",
    "medium": "sev-medium",
}

# renderMeta showed at most five tags. Kept, because the cap is what stops a
# case with thirty meta keys from burying the event title.
META_TAG_LIMIT = 5


def event_timestamp(raw: object) -> datetime | str | None:
    """The event's instant, as a datetime where one can be recovered.

    get_entity_timeline serialises every timestamp with `.isoformat()`
    because its other consumer is a JSON endpoint. `ts` renders a real
    datetime in ION's house format and a bare string as itself, so parsing
    the string back is the difference between `2026-10-05 14:22` and
    `2026-10-05T14:22:31.481920`.

    `fromisoformat` is the exact inverse of `isoformat`, and crucially it
    preserves the one distinction that matters here: a naive string parses
    to a naive datetime, which `_ts_parts` refuses to localise, and an
    offset-bearing string parses to an aware one, which it does localise. So
    this does not decide the zone question, it hands the same question to
    the one place that answers it.

    Anything that will not parse is returned unchanged rather than dropped.
    A timestamp we cannot read is still evidence of when something happened.
    """
    if raw is None or raw == "":
        return None
    if isinstance(raw, datetime):
        return raw
    try:
        return datetime.fromisoformat(str(raw))
    except (TypeError, ValueError):
        return str(raw)


def visible_meta(meta: object) -> list[tuple[str, str]]:
    """The meta object's renderable pairs, capped, in insertion order.

    `v is not None and v != ""` rather than a truthiness test, because
    `sighting_count: 0` is a measurement. An observable seen zero times is a
    fact about the observable; dropping the tag claims the field was never
    there. The JavaScript got this right with `v != null && v !== ''`, so a
    truthiness port here would be a regression rather than a port.
    """
    if not isinstance(meta, dict):
        return []
    out: list[tuple[str, str]] = []
    for key, value in meta.items():
        value = plain(value)
        if value is None or value == "":
            continue
        out.append((str(key), str(value)))
        if len(out) == META_TAG_LIMIT:
            break
    return out


def present_event(raw: dict[str, Any]) -> dict[str, Any]:
    """One service event in the shape the template renders.

    `plain` on severity and status because Observable.threat_level is
    `SQLEnum(ThreatLevel)` and the service passes the ORM value straight
    through. The JSON endpoint got the string for free, since FastAPI
    serialises a str-mixin enum by value; a template renders
    `ThreatLevel.HIGH` instead, and the colour map still matches because
    value equality holds, so only the visible text is wrong.
    """
    severity = plain(raw.get("severity"))
    severity_text = str(severity) if severity is not None else None
    return {
        "source": str(raw.get("source") or "unknown"),
        "severity": severity_text,
        "severity_class": SEVERITY_CLASS.get((severity_text or "").lower()),
        "status": plain(raw.get("status")),
        "title": raw.get("title"),
        "detail": raw.get("detail"),
        "timestamp": event_timestamp(raw.get("timestamp")),
        "meta": visible_meta(raw.get("meta")),
    }


def parse_sources(raw: str | None) -> list[str]:
    """The active source filter, as a comma-separated list.

    One parameter holding a list rather than a repeated one, so each pill's
    href is a single value and the template never concatenates a literal `&`
    beside an escaped one.
    """
    if not raw:
        return []
    seen: list[str] = []
    for part in raw.split(","):
        name = part.strip()
        if name and name not in seen:
            seen.append(name)
    return seen


def source_pills(
    events: list[dict[str, Any]], active: list[str]
) -> list[dict[str, Any]]:
    """One pill per source present, most frequent first, each with the URL
    that toggles it.

    The pills live in the fragment because only the fragment knows which
    sources the result contains. They are therefore re-rendered with their
    own state on every swap, and the All pill is rendered whenever there are
    any events at all, including when the active filter matches none of
    them. A filter that can hide every row has to keep the control that
    clears it.
    """
    counts: dict[str, int] = {}
    for event in events:
        counts[event["source"]] = counts.get(event["source"], 0) + 1

    pills = []
    for source, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        if source in active:
            toggled = [s for s in active if s != source]
        else:
            toggled = active + [source]
        pills.append({
            "source": source,
            "count": count,
            "active": source in active,
            "url": "/ui/entity-timeline?sources=" + ",".join(toggled),
        })
    return pills


@router.get(
    "/entity-timeline",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("alert:read"))],
)
def entity_timeline_fragment(
    request: Request,
    q: str = Query("", max_length=500),
    type: str = Query("auto"),
    hours: int = Query(168, ge=1, le=8760),
    sources: str = Query(""),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The timeline for one entity, header, filters and events together.

    `alert:read` matches /api/entity-timeline/search exactly. A fragment
    must not be a softer way in than the API it mirrors, and this one reads
    case descriptions, analyst notes and audit details.

    `q` is optional here where the JSON endpoint requires it, because the
    unsearched page is a state this fragment renders. The page shell asks
    for the fragment on load whichever way, so the prompt, the results, the
    empty result and the failed read are all one render path with one
    definition each.
    """
    active = parse_sources(sources)
    context: dict[str, Any] = {
        "q": q.strip(),
        "entity_type": type,
        "hours": hours,
        "active_sources": active,
        "events": [],
        "pills": [],
        "total_events": None,
        "sources_count": None,
        "shown_count": 0,
    }

    if not q.strip():
        context["state"] = "prompt"
        return templates.TemplateResponse(
            request=request, name=FRAGMENT, context=context
        )

    # The same function /api/entity-timeline/search calls. That endpoint is a
    # single delegation with no query logic, pagination maths, privacy scope
    # or feature gate of its own, so there was nothing inline to lift into a
    # shared `*_payload()` helper: calling the service is already the one
    # definition both routes share.
    from ion.services.entity_timeline_service import get_entity_timeline

    try:
        payload = get_entity_timeline(
            session, entity_value=q.strip(), entity_type=type, hours=hours
        )
    except Exception:
        logger.exception("Entity timeline fragment could not be rendered")
        # An unreadable timeline is not an empty one. "No events found"
        # would tell an analyst that nothing happened to this host, which on
        # a page whose whole job is reconstructing what happened is the one
        # claim it must never make by accident.
        context["state"] = "failed"
        return templates.TemplateResponse(
            request=request, name=FRAGMENT, context=context
        )

    presented = [present_event(e) for e in payload.get("events") or []]
    context["state"] = "ok"
    context["entity_type"] = payload.get("entity_type") or type
    context["total_events"] = payload.get("total_events")
    context["sources_count"] = len(payload.get("sources") or [])
    context["shown_count"] = len(presented)
    context["pills"] = source_pills(presented, active)
    context["events"] = (
        [e for e in presented if e["source"] in active] if active else presented
    )
    return templates.TemplateResponse(
        request=request, name=FRAGMENT, context=context
    )
