"""Cases: the eight stat tiles and the Management Analytics panel.

Stage one of cases.html. The page has 64 DOM write sites in 3,610 lines of
script, measured with tools/ui_redesign_status.py, and this takes the region
that aggregates over the case list rather than listing it: the stat bar at
the top and the analytics panel at the bottom. Nine of the writes are
innerHTML (renderDonutChart 2, renderClosureDonut 1, renderWorkloadBars 2,
renderOpenCaseAges 2, renderRecentClosures 2); nine more are textContent
into the tiles (renderStats 5, renderRow2Stats 4), which the tool does not
count and which carried the same defects. The board, its filters and the
attention banner are a later stage: they are per-case rows with client-side
sort, page and dismissal state, which is a different kind of work.

What the JavaScript did, measured by reading it, and why each is not a
cosmetic port:

  * renderAnalyticsPanel began `if (!casesLoaded || !teamMetricsCache)
    return;`. loadTeamMetrics set the cache to null when the read failed. So
    a failed team-metrics read left every analytics card as the empty div
    the shell ships with, for ever, and loadAllCases's catch set `allCases =
    []` and carried on, so a failed case read rendered "No active cases",
    "No closed cases" and 0 in every tile. A failed read and an empty estate
    were the same picture.

  * renderSummaryStrip wrote `strip.replaceChildren() + '<div ...'`. That is
    a method call returning undefined, then a string concatenation whose
    result is discarded. The summary strip has rendered nothing since that
    line was written, so the four chips it describes (critical/high active,
    unassigned, oldest active, closed today) have never been on the page.

  * Every figure the panel drew came from the loaded array, which
    loadAllCases caps at 2,000 rows. The closure donut, the status donut
    and the age buckets therefore counted the most recent 2,000 cases and
    presented the result as the estate. The tiles had the same cap. The
    aggregates here are GROUP BYs and windowed counts over the table.

  * `sev.critical || 0`, `(tm.created_7d || 0)`, `d.open_count` with no
    guard. The services behind these emit integers from `scalar() or 0`, so
    the `|| 0` hid nothing today, but each one is a place where a payload
    that stopped carrying the key would print a confident zero. Numbers here
    are guarded with `is not none` and an int check, not truthiness.

  * ageLabel did `new Date(dateStr)` on `isoformat()` of a naive UTC column,
    which JavaScript parses as the viewer's local time, so every age on the
    panel was wrong by the viewer's offset. `_shared.age_label` reads a
    zoneless value as UTC, which is what the column stores.

  * getCaseAgeColor(NaN) fell through every `<` comparison to `sla-red`, so
    a case whose created_at was missing was painted as the oldest band. It
    is counted here as "age unknown" instead.

Three outcomes per card, never conflated: the read failed, the read found
nothing, and data. "No closed cases" and "we could not count your closed
cases" lead to opposite decisions.

Permissions, read off the live route table rather than assumed from the
page:

  * GET /api/cases and GET /api/cases/facets carry `case:read`, the page's
    own permission, so the route is gated on it and everything derived from
    the case table (tiles 1 to 4 and 8, the status and closure donuts, the
    age panel, the summary strip) renders for any viewer who can open the
    page.
  * GET /api/dashboard/team-metrics carries `alert:read`. Every built-in
    role that grants case:read also grants alert:read, measured by reading
    the role table in ion/auth/service.py, but a custom role need not. The
    team-metrics read is attempted only when the viewer holds alert:read,
    and the six things it feeds (MTTR, closure rate, created/closed 7d, the
    severity donut, workload bars, recent closures) say the account cannot
    read them otherwise. The fragment is never a softer way into that
    endpoint's data and never hides case:read data behind alert:read.

One route, two swap targets. The tiles are the primary target and the panel
body lands out of band, because both come from the same four reads and the
JavaScript made one team-metrics request for both. Two routes would run the
eight team-metrics queries twice per page load. The retry control is a
third out-of-band element that sits outside both targets, so a failed
render cannot remove the thing that retries it.
"""
from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import Any, Optional, TypedDict

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._cases_board import router as board_router
from ion.web.ui._shared import (
    age_label,
    closure_label,
    closure_short,
    parse_instant,
    plain,
    render_view,
)
from ion.web.ui._shared import (
    rows as _rows,
)

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/cases_summary.html"

#: What GET /api/cases and GET /api/cases/facets require, and what the page
#: route itself is gated on. Spelled once so the fragment cannot drift into
#: being a softer way in than the endpoints it mirrors.
PERMISSION = "case:read"

#: What GET /api/dashboard/team-metrics requires. Not PERMISSION: the route
#: is gated on case:read and this only decides whether the team-metrics read
#: is attempted, so the six figures it feeds are withheld, not faked, for a
#: viewer who cannot call that endpoint.
METRICS_PERMISSION = "alert:read"

#: The lower bound handed to case_metrics for the all-time figures. The
#: JavaScript computed the closure donut and the average resolution over
#: every loaded case; the service's window is on closed_at, so this is
#: "every case that has ever closed".
EPOCH = datetime(1970, 1, 1)

#: Every status that is not closed. The JavaScript tested `open` and
#: `acknowledged` by name; this is the same set derived from the enum so a
#: status added later cannot fall between the two pictures.
ACTIVE_STATUSES = tuple(
    m for m in AlertCaseStatus if m is not AlertCaseStatus.CLOSED
)

#: Rows the open-case-age panel lists, from the page's `.slice(0, 8)`.
OLDEST_SHOWN = 8

#: Rows the recent-closures card lists, from the page's `.slice(0, 5)`. The
#: endpoint returns ten.
CLOSURES_SHOWN = 5

#: Age bands in hours, highest bound first match. The class is the one the
#: page's stylesheet already paints (`sla-*` by name, because the hashed
#: class map references them; the heading says these are fixed thresholds
#: and not an SLA). The label is what the legend reads. None is "no upper
#: bound".
AGE_BANDS: tuple[tuple[Optional[float], str, str], ...] = (
    (24.0, "sla-green", "<24h"),
    (72.0, "sla-yellow", "1-3d"),
    (168.0, "sla-orange", "3-7d"),
    (None, "sla-red", ">7d"),
)

#: The oldest-active chip's dot, from the page's
#: `oldestDays > 7 ? danger : oldestDays > 3 ? warning : success`.
OLDEST_WARN_DAYS = 3
OLDEST_DANGER_DAYS = 7

#: Donut geometry, from renderDonutChart. Arithmetic plus markup, not a
#: layout computation: nothing is measured from the DOM, so the server
#: produces identical geometry.
DONUT_SIZE = 120
DONUT_RADIUS = 45
DONUT_STROKE = 14
DONUT_CIRCUMFERENCE = 2 * math.pi * DONUT_RADIUS

#: Segment order, label and colour for the two fixed-key donuts, from the
#: arrays the page passed to renderDonutChart.
SEVERITY_SEGMENTS: tuple[tuple[str, str], ...] = (
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
)
STATUS_SEGMENTS: tuple[tuple[str, str], ...] = (
    ("open", "Open"),
    ("acknowledged", "Acknowledged"),
    ("closed", "Closed"),
)

#: The closure reasons the summary donut paints. A reason not in here is
#: drawn in the fallback, which is what the page did. The colours are in
#: static/css/cases-page.css, keyed by these names: which colour means
#: "true positive" is the stylesheet's answer, and a model carrying it
#: makes every reader of /ui/cases/summary inherit ION's palette.
CLOSURE_KEYS: tuple[str, ...] = (
    "true_positive", "false_positive", "benign_true_positive",
    "duplicate", "insufficient_data", "not_applicable",
)
CLOSURE_FALLBACK_KEY = "other"

#: How many workload bar colours the stylesheet cycles through. The row's
#: index modulo this is the class it gets.
BAR_COLOUR_COUNT = 8

#: Severities the "critical/high active" chip counts, lower-cased.
URGENT_SEVERITIES = ("critical", "high")


def _count(value: Any) -> Optional[int]:
    """An int, or None for anything that is not one.

    bool is excluded on purpose: True is an int in Python and a payload
    carrying a flag where a count was expected must not render as 1.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _number(value: Any) -> Optional[float]:
    """A real number, or None. Same bool rule as `_count`."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _figure(value: Any) -> Any:
    """A real number with 12.0 shown as 12, or None for anything else.

    JSON handed the page a JavaScript 12 for a Python 12.0 and the tile read
    "12h"; Jinja would render "12.0h". The port is meant to be invisible.
    """
    number = _number(value)
    if number is None:
        return None
    return int(number) if float(number) == int(number) else number


def donut(segments: Optional[list[tuple[str, Any, str]]]) -> Optional[dict]:
    """The arcs and legend for one donut, or None when there is nothing to
    draw from.

    Three outcomes. None in means the source could not be read and None
    comes out, so the template says so. A total of zero is a measurement:
    every segment was counted and every count was zero. Anything else is
    arcs.

    A segment whose value is not a count is left out of the drawing and
    reported in `unreadable`, rather than treated as zero: a key the service
    stopped emitting is not a category with no cases in it.
    """
    if segments is None:
        return None
    counted: list[tuple[str, int, str]] = []
    unreadable: list[str] = []
    for label, value, key in segments:
        count = _count(value)
        if count is None:
            unreadable.append(label)
        else:
            counted.append((label, count, key))
    total = sum(v for _, v, _ in counted)
    arcs: list[dict] = []
    legend: list[dict] = []
    offset = 0.0
    for label, value, key in counted:
        if value == 0:
            continue
        share = value / total
        dash = DONUT_CIRCUMFERENCE * share
        arcs.append({
            "key": key,
            "dash": round(dash, 2),
            "gap": round(DONUT_CIRCUMFERENCE - dash, 2),
            "offset": round(-offset, 2),
        })
        legend.append({
            "label": label,
            "value": value,
            "pct": round(share * 100),
            "key": key,
        })
        offset += dash
    return {
        "total": total,
        "arcs": arcs,
        "legend": legend,
        "unreadable": unreadable,
    }


def severity_donut(metrics: Any) -> Optional[dict]:
    """Active cases by severity, from team-metrics' `cases_by_severity`.

    The service pre-seeds all four keys from a GROUP BY, so a missing key is
    a true zero there. A `cases_by_severity` that is not a mapping is a
    payload this panel cannot read.
    """
    if not isinstance(metrics, dict):
        return None
    by_severity = metrics.get("cases_by_severity")
    if not isinstance(by_severity, dict):
        return None
    return donut([
        (label, by_severity.get(key, 0), key)
        for key, label in SEVERITY_SEGMENTS
    ])


def status_donut(facets: Any) -> Optional[dict]:
    """All cases by status, from the facets' `by_status`.

    A status missing from `by_status` is a true zero: the service builds the
    dict from a GROUP BY, which omits empty groups. The JavaScript counted
    the loaded array, which stops at 2,000 rows.
    """
    if not isinstance(facets, dict):
        return None
    by_status = facets.get("by_status")
    if not isinstance(by_status, dict):
        return None
    return donut([
        (label, by_status.get(key, 0), key)
        for key, label in STATUS_SEGMENTS
    ])


def closure_donut(closed: Any) -> Optional[dict]:
    """Closed cases by closure reason, from case_metrics' `closure_reasons`.

    The service keys a closed case with no recorded reason as "unspecified",
    which the JavaScript dropped (`if (c.closure_reason)`), so a case closed
    without saying why was missing from the donut and from its total. It is
    a segment here, because a closure with no reason is a finding about how
    cases are being closed.
    """
    if not isinstance(closed, dict):
        return None
    reasons = closed.get("closure_reasons")
    if not isinstance(reasons, dict):
        return None
    segments = []
    for reason, count in reasons.items():
        key = str(plain(reason))
        label = closure_label(key) if key != "unspecified" else "No reason recorded"
        segments.append((
            label or key, count,
            key if key in CLOSURE_KEYS else CLOSURE_FALLBACK_KEY,
        ))
    return donut(segments)


def workload_bars(metrics: Any) -> Optional[list[dict]]:
    """One bar per assignee from team-metrics' `cases_by_assignee`.

    Width is the share of the busiest assignee, from
    `(d.open_count / max) * 100` with `max` floored at 1. A row whose count
    is not a number keeps its name and draws no bar, rather than a bar of
    zero width that reads as an analyst with nothing open.
    """
    if not isinstance(metrics, dict):
        return None
    rows = metrics.get("cases_by_assignee")
    if not isinstance(rows, list):
        return None
    counts = [_count(r.get("open_count")) for r in rows if isinstance(r, dict)]
    peak = max([c for c in counts if c is not None] + [1])
    bars = []
    for index, row in enumerate(r for r in rows if isinstance(r, dict)):
        count = _count(row.get("open_count"))
        bars.append({
            "name": row.get("display_name") or row.get("username") or "Unknown",
            "open_count": count,
            "pct": None if count is None else round(count / peak * 100, 1),
            "colour_index": index % BAR_COLOUR_COUNT,
        })
    return bars


def recent_closures(metrics: Any, now: datetime) -> Optional[list[dict]]:
    """The first CLOSURES_SHOWN of team-metrics' `recent_closures`."""
    if not isinstance(metrics, dict):
        return None
    rows = metrics.get("recent_closures")
    if not isinstance(rows, list):
        return None
    out = []
    for row in rows[:CLOSURES_SHOWN]:
        if not isinstance(row, dict):
            continue
        reason = plain(row.get("closure_reason"))
        severity = plain(row.get("severity"))
        out.append({
            "id": row.get("id"),
            "case_number": row.get("case_number"),
            "title": row.get("title"),
            "severity": str(severity).lower() if severity else None,
            "reason_short": closure_short(reason),
            "reason_label": closure_label(reason),
            "reason_class": f"reason-{reason}" if reason else "",
            "closed_by": row.get("closed_by"),
            # None when the row has no closed_at, which the template words
            # rather than printing "None ago".
            "ago": age_label(row.get("closed_at"), now),
        })
    return out


def active_cases(session: Session) -> list[dict]:
    """Every case that is not closed, oldest first, as light rows.

    Six columns and no relationships. This is the one read the age panel,
    the critical/unassigned tiles and the summary strip share, and it has no
    JSON endpoint of its own: the page derived all of them from the paged
    list, which is capped at 2,000 rows and shipped every column of each.
    list_cases_page cannot express `status IN (open, acknowledged)` in one
    call and caps at 500, so it is not the right tool for a count over every
    active case. An age-bucket aggregate belongs in case_facets eventually;
    that module is not this stage's file.

    NULL created_at sorts last so the oldest-eight list is cases whose age
    is known.
    """
    stmt = (
        select(
            AlertCase.id,
            AlertCase.case_number,
            AlertCase.title,
            AlertCase.severity,
            AlertCase.status,
            AlertCase.assigned_to_id,
            AlertCase.created_at,
        )
        .where(AlertCase.status.in_(ACTIVE_STATUSES))
        .order_by(
            AlertCase.created_at.is_(None),
            AlertCase.created_at.asc(),
            AlertCase.id.asc(),
        )
    )
    return [
        {
            "id": row.id,
            "case_number": row.case_number,
            "title": row.title,
            "severity": (str(row.severity).lower() if row.severity else None),
            "status": plain(row.status),
            "assigned_to_id": row.assigned_to_id,
            "created_at": row.created_at,
        }
        for row in session.execute(stmt).all()
    ]


def age_band(hours: float) -> tuple[str, str]:
    """The class and label for an age in hours."""
    for bound, cls, label in AGE_BANDS:
        if bound is None or hours < bound:
            return cls, label
    return AGE_BANDS[-1][1], AGE_BANDS[-1][2]


def ages_view(rows: Optional[list[dict]], now: datetime) -> Optional[dict]:
    """The age bar, its legend, and the oldest OLDEST_SHOWN active cases.

    `unknown` counts active cases with no usable created_at. The JavaScript
    painted those red: `new Date(undefined)` is NaN, every `<` on NaN is
    false, and the function fell through to its last return. Not knowing
    how old a case is and knowing it is over a week old are different
    findings.

    `oldest_days` is None when no active case has a known age, which the
    summary strip words. The JavaScript's reduce started at 0 and rendered
    "0d" for an estate with no active cases at all.
    """
    if rows is None:
        return None
    buckets = [
        {"cls": cls, "label": label, "count": 0} for _, cls, label in AGE_BANDS
    ]
    by_cls = {b["cls"]: b for b in buckets}
    unknown = 0
    oldest_hours: Optional[float] = None
    aged: list[dict] = []
    for row in rows:
        created = parse_instant(row.get("created_at"))
        if created is None:
            unknown += 1
            continue
        hours = max(0.0, (now - created).total_seconds() / 3600.0)
        cls, _ = age_band(hours)
        by_cls[cls]["count"] += 1
        if oldest_hours is None or hours > oldest_hours:
            oldest_hours = hours
        if len(aged) < OLDEST_SHOWN:
            aged.append({
                "id": row.get("id"),
                "case_number": row.get("case_number"),
                "title": row.get("title"),
                "severity": row.get("severity"),
                "cls": cls,
                "age": age_label(created, now),
            })
    return {
        "total": len(rows),
        "unknown": unknown,
        "buckets": buckets,
        "oldest": aged,
        "oldest_days": None if oldest_hours is None else int(oldest_hours // 24),
    }


def oldest_class(days: Optional[int]) -> Optional[str]:
    """The dot class on the oldest-active chip, or None with no measurement."""
    if days is None:
        return None
    if days > OLDEST_DANGER_DAYS:
        return "sla-red"
    if days > OLDEST_WARN_DAYS:
        return "sla-yellow"
    return "sla-green"


def resolution_text(hours: Any) -> Optional[str]:
    """"7h" or "3d" from an average in hours, the way renderStats printed it.

    None for no figure. The JavaScript printed "-" for that, which is the
    same glyph the tiles show while loading, so "no case has ever closed"
    and "still loading" were one picture.
    """
    value = _number(hours)
    if value is None:
        return None
    if value < 24:
        return f"{round(value)}h"
    return f"{round(value / 24)}d"


def tiles_view(facets: Any, active: Optional[list[dict]], closed: Any,
               metrics: Any) -> dict:
    """The eight figures, each None where its source could not be read.

    Which source feeds which tile is the whole reason this is one function:
    open and acknowledged are GROUP BY counts from the facets; critical
    active and unassigned are counted over the active rows; average
    resolution is the all-time `avg_mttr_hours` from case_metrics; the three
    on the right are team-metrics figures that are None for specific,
    worded reasons and never zero.
    """
    by_status = facets.get("by_status") if isinstance(facets, dict) else None
    if not isinstance(by_status, dict):
        by_status = None

    critical = unassigned = None
    if active is not None:
        critical = sum(1 for r in active if r.get("severity") == "critical")
        unassigned = sum(1 for r in active if r.get("assigned_to_id") is None)

    resolution_hours = (
        _number(closed.get("avg_mttr_hours")) if isinstance(closed, dict) else None
    )
    tm = metrics if isinstance(metrics, dict) else {}
    return {
        "open": _count(by_status.get("open", 0)) if by_status is not None else None,
        "acknowledged": (
            _count(by_status.get("acknowledged", 0)) if by_status is not None else None
        ),
        "critical_active": critical,
        "resolution_hours": resolution_hours,
        "resolution_text": resolution_text(resolution_hours),
        "mttr_hours": _figure(tm.get("mttr_hours")),
        "closure_rate": _figure(tm.get("closure_rate_7d")),
        "created_7d": _count(tm.get("created_7d")),
        "closed_7d": _count(tm.get("closed_7d")),
        "unassigned": unassigned,
    }


def strip_view(active: Optional[list[dict]], ages: Optional[dict],
               closed_today: Optional[int]) -> dict:
    """The four summary chips the page described and never rendered."""
    urgent = unassigned = None
    if active is not None:
        urgent = sum(1 for r in active if r.get("severity") in URGENT_SEVERITIES)
        unassigned = sum(1 for r in active if r.get("assigned_to_id") is None)
    oldest_days = ages.get("oldest_days") if isinstance(ages, dict) else None
    return {
        "crit_high_active": urgent,
        "unassigned_active": unassigned,
        "oldest_days": oldest_days,
        "oldest_class": oldest_class(oldest_days),
        "closed_today": closed_today,
    }


def summary_context(session: Session, can_read_metrics: bool,
                    now: Optional[datetime] = None) -> dict:
    """Everything the fragment renders, from four independent reads.

    Each read has its own try, so a failure in one leaves the others'
    figures standing and says which one failed. They share one HTTP request
    because they share one database on one schedule; the dashboard_v2
    argument for separate requests (different stores, a slow aggregation
    must not blank a handover) does not apply here.

    The team-metrics read is skipped, not attempted and swallowed, when the
    viewer lacks alert:read. Attempting it would compute figures the viewer
    is not permitted to call for and then decide whether to show them,
    which is the wrong order.
    """
    from ion.services import case_query_service as cq
    from ion.services.case_metrics import case_metrics
    from ion.web.api import team_metrics_payload

    now = now or datetime.now(timezone.utc)
    failed = {"facets": False, "active": False, "closed": False, "metrics": False}

    facets: Any = None
    try:
        facets = cq.case_facets(session)
    except Exception:
        logger.exception("Case summary: facets could not be read")
        failed["facets"] = True

    active: Optional[list[dict]] = None
    try:
        active = active_cases(session)
    except Exception:
        logger.exception("Case summary: active cases could not be read")
        failed["active"] = True

    closed: Any = None
    closed_today: Optional[int] = None
    try:
        closed = case_metrics(session, since=EPOCH)
        # Naive UTC midnight, because closed_at is a naive column holding
        # UTC. The JavaScript compared `toDateString()` in the viewer's
        # zone, so "today" moved with whoever was looking.
        day_start = now.astimezone(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0, tzinfo=None
        )
        closed_today = _count(case_metrics(session, since=day_start).get("closed"))
    except Exception:
        logger.exception("Case summary: closure metrics could not be read")
        failed["closed"] = True
        closed = None
        closed_today = None

    metrics: Any = None
    if can_read_metrics:
        try:
            metrics = team_metrics_payload(session)
            if not isinstance(metrics, dict):
                raise TypeError(f"team metrics payload is {type(metrics).__name__}")
        except Exception:
            logger.exception("Case summary: team metrics could not be read")
            failed["metrics"] = True
            metrics = None

    ages = ages_view(active, now)
    return {
        "failed": failed,
        "any_failed": any(failed.values()),
        "metrics_withheld": not can_read_metrics,
        "tiles": tiles_view(facets, active, closed, metrics),
        "strip": strip_view(active, ages, closed_today),
        "severity_donut": severity_donut(metrics),
        "closure_donut": closure_donut(closed),
        "status_donut": status_donut(facets),
        "workload": workload_bars(metrics),
        "ages": ages,
        "closures": recent_closures(metrics, now),
        "oldest_shown": OLDEST_SHOWN,
        "closures_shown": CLOSURES_SHOWN,
        "donut_size": DONUT_SIZE,
        "donut_radius": DONUT_RADIUS,
        "donut_stroke": DONUT_STROKE,
    }


@router.get(
    "/cases/summary",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def cases_summary_fragment(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The eight tiles, with the analytics panel and retry control out of band.

    Synchronous on purpose: team_metrics_payload is eight-odd queries and
    the JSON route hands it to asyncio.to_thread for that reason. A sync def
    runs the whole body in one worker thread, which is also the one thread
    the session is open on.
    """
    can_read_metrics = bool(
        current_user and current_user.has_permission(METRICS_PERMISSION)
    )
    return render_view(request, FRAGMENT,
                       summary_context(session, can_read_metrics))


# ---------------------------------------------------------------------------
# Similar Closed Cases
# ---------------------------------------------------------------------------
#
# The panel the detail view loads beside a case, from the pgvector endpoint
# GET /api/cases/{id}/similar (case:read, no module gate). loadSimilarCases
# already told a failed request from an empty answer, so two of the three
# outcomes were distinct; `const items = data.similar || []` collapsed the
# third into the second, and a 200 whose body was not that shape read as
# "No similar closed cases yet".

SIMILAR_FRAGMENT = "_fragments/cases_similar.html"

#: What the sidebar asked the endpoint for.
SIMILAR_SHOWN = 5

#: How much of a title the card has room for, as the page sliced it.
SIMILAR_TITLE_CHARS = 120

#: The closure reasons the verdict badge has a colour for, in
#: static/css/cases-page.css. A reason outside this set is painted as
#: `other`, where the page fell back to the not_applicable grey. Which
#: colour means "true positive" is the stylesheet's answer: the view model
#: carried rgba() and var() literals, so the palette shipped in the page.
CLOSURE_BADGE_KEYS: tuple[str, ...] = (
    "true_positive",
    "false_positive",
    "benign_true_positive",
    "duplicate",
    "insufficient_data",
    "not_applicable",
)
CLOSURE_BADGE_FALLBACK = "other"


class SimilarCase(TypedDict):
    """One card. `similarity_pct` is None for a row that carried no score."""

    case_id: Any
    label: str
    title: Optional[str]
    closure_key: str
    closure_label: Optional[str]
    similarity_pct: Optional[int]


class SimilarView(TypedDict):
    """`cases` is None when the read failed or answered a shape we cannot
    read, [] when there are genuinely none, and a list otherwise. `reason`
    is the endpoint's own word for why it found nothing, which it sends for
    the common case of a case that has not been embedded yet."""

    cases: Optional[list[SimilarCase]]
    reason: Optional[str]


def similarity_pct(value: Any) -> Optional[int]:
    """A cosine similarity as whole percent, or None when there isn't one.

    `Math.round((s.similarity || 0) * 100)` printed 0% for a row that
    arrived without a score, and 0% is the one number that means the
    opposite of unknown. bool is excluded before the numeric check because
    True is an int in Python and 100% is not what it means.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if math.isnan(value) or math.isinf(value):
        return None
    return int(round(value * 100))


def similar_case(row: Any) -> Optional[SimilarCase]:
    """One row of the endpoint's `similar` list, or None for a row that is
    not a mapping at all. A list with one bad row still renders its others."""
    if not isinstance(row, dict):
        return None
    case_id = plain(row.get("case_id"))
    number = plain(row.get("case_number"))
    reason = plain(row.get("closure_reason"))
    key = str(reason) if reason in CLOSURE_BADGE_KEYS else CLOSURE_BADGE_FALLBACK
    title = plain(row.get("title"))
    return {
        "case_id": case_id,
        "label": str(number) if number else f"#{case_id}",
        "title": str(title)[:SIMILAR_TITLE_CHARS] if title else None,
        "closure_key": key,
        "closure_label": closure_label(reason),
        "similarity_pct": similarity_pct(plain(row.get("similarity"))),
    }


def similar_view(payload: Any) -> SimilarView:
    """The endpoint's body as the panel's model.

    A payload that is not a dict, or whose `similar` is not a list, is the
    failed outcome rather than the empty one: we did not read it, so we
    cannot say there are none.
    """
    found = _rows(payload, "similar")
    if found is None:
        return {"cases": None, "reason": None}
    cases = [card for card in (similar_case(row) for row in found)
             if card is not None]
    reason = plain(payload.get("reason")) if isinstance(payload, dict) else None
    return {"cases": cases, "reason": str(reason) if reason else None}


@router.get(
    "/cases/{case_id}/similar",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def cases_similar_fragment(
    request: Request,
    case_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The Similar Closed Cases panel.

    Reads through the endpoint's own handler so the card a reader sees is
    the row the JSON reports. The endpoint is pgvector, which SQLite cannot
    answer at all, so every failure mode lands in the one except: that is
    the unavailable outcome, and it is not the empty one.
    """
    from ion.web.case_lifecycle_api import get_similar_cases

    try:
        payload = get_similar_cases(
            case_id,
            limit=SIMILAR_SHOWN,
            current_user=current_user,
            session=session,
        )
    except Exception:
        logger.exception(
            "Cases similar fragment could not read similar cases for %s",
            case_id)
        payload = None

    return render_view(request, SIMILAR_FRAGMENT, similar_view(payload))


# ---------------------------------------------------------------------------
# Attack Story Timeline
# ---------------------------------------------------------------------------
#
# GET /api/cases/{id}/timeline (case:read) unions the case's lifecycle
# events, analyst notes and Bob investigations into one sorted feed, with a
# narrative header carrying Bob's latest verdict and its citations.
#
# loadCaseTimeline told a failed request from an empty one, so two of the
# three outcomes were distinct. The rest of this is defects:
#
#   * `data.counts || {}` then `counts.total || 0` four times. A payload
#     that stopped carrying counts printed four confident zeros, and the
#     `|| 0` could not tell a real zero from a missing key.
#   * `new Date(e.ts).toLocaleString()` on `isoformat()` of a naive UTC
#     column, which JavaScript reads in the viewer's zone. Every timestamp
#     on the timeline was wrong by the viewer's offset, and nothing on the
#     page said which zone it was claiming.
#   * `kindMeta[e.kind] || kindMeta.system` labelled an unrecognised event
#     SYSTEM, which is a claim about where it came from.
#   * `verdictColors[verdict] || verdictColors.inconclusive`. The server
#     derives the verdict by splitting a title on an arrow, so it is an
#     arbitrary string, and "inconclusive" is a verdict rather than the
#     absence of one.
#   * `(c.value || '').toString()` dropped a citation value of 0 or false,
#     and a count of zero is a finding.

TIMELINE_FRAGMENT = "_fragments/cases_timeline.html"

#: How much of an event's detail the card shows, as the page sliced it.
TIMELINE_DETAIL_CHARS = 220

#: How much of Bob's summary the narrative header shows.
TIMELINE_SUMMARY_CHARS = 600

#: How much of a citation's value fits on its line.
TIMELINE_CITATION_CHARS = 80

#: The event kinds the timeline has a lane for, from `kindMeta`. One
#: outside this set is `unknown`, which the page called `system`.
TIMELINE_KINDS: dict[str, str] = {
    "bob": "BOB",
    "analyst": "ANALYST",
    "system": "SYSTEM",
}
TIMELINE_KIND_FALLBACK = "unknown"

#: The verdicts the narrative badge has a colour for, from `verdictColors`.
#: The colours are in static/css/cases-page.css, keyed by these names.
TIMELINE_VERDICTS: tuple[str, ...] = (
    "true_positive",
    "false_positive",
    "benign_true_positive",
    "inconclusive",
)
TIMELINE_VERDICT_FALLBACK = "unknown"


class TimelineCitation(TypedDict):
    """One of Bob's citations. `value` is formatted rather than tested for
    truth, so a measured zero survives."""

    field: Optional[str]
    value: Optional[str]
    significance: Optional[str]


class TimelineNarrative(TypedDict):
    """`verdict_label` is None when the investigation recorded no verdict,
    which is different from a verdict this build does not recognise."""

    summary: Optional[str]
    verdict_key: Optional[str]
    verdict_label: Optional[str]
    citations: list[TimelineCitation]


class TimelineEvent(TypedDict):
    """`when` is None for a timestamp we could not read. The page rendered
    `new Date(undefined)` as an empty string, so this is the same picture
    arrived at honestly."""

    kind_key: str
    kind_label: str
    when: Optional[str]
    title: Optional[str]
    detail: Optional[str]
    truncated: bool


class TimelineCounts(TypedDict):
    """Each figure is None when the payload did not carry a readable one."""

    total: Optional[int]
    bob: Optional[int]
    analyst: Optional[int]
    system: Optional[int]


class TimelineView(TypedDict):
    events: Optional[list[TimelineEvent]]
    narrative: Optional[TimelineNarrative]
    counts: TimelineCounts


def instant_label(value: Any) -> Optional[str]:
    """An absolute timestamp as `2026-09-01 10:30 UTC`, or None.

    The zone is named because the column is naive UTC and the page was
    presenting it as local time. An aware value is converted rather than
    relabelled, so a row that does carry an offset still reads correctly.
    """
    parsed = parse_instant(value)
    if parsed is None:
        return None
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def citation(raw: Any) -> Optional[TimelineCitation]:
    """One citation, or None for an entry that is not a mapping.

    The page skipped a non-object entry too (`if (!c || typeof c !==
    'object') return;`), so a malformed entry has never been fatal here.
    """
    if not isinstance(raw, dict):
        return None
    field = plain(raw.get("field"))
    value = raw.get("value")
    significance = plain(raw.get("significance"))
    return {
        "field": str(field) if field is not None else None,
        # Formatted, not tested for truth: `(c.value || '')` dropped 0.
        "value": (None if value is None
                  else str(value)[:TIMELINE_CITATION_CHARS]),
        "significance": str(significance) if significance else None,
    }


def narrative_view(raw: Any) -> Optional[TimelineNarrative]:
    """Bob's latest verdict, or None when there is no narrative at all."""
    if not isinstance(raw, dict):
        return None
    verdict = plain(raw.get("verdict"))
    if verdict is None or str(verdict) == "":
        verdict_key, verdict_label = None, None
    elif str(verdict) in TIMELINE_VERDICTS:
        verdict_key = str(verdict)
        verdict_label = str(verdict).replace("_", " ")
    else:
        verdict_key = TIMELINE_VERDICT_FALLBACK
        verdict_label = str(verdict).replace("_", " ")
    summary = plain(raw.get("summary"))
    raw_citations = raw.get("citations")
    cited = raw_citations if isinstance(raw_citations, list) else []
    return {
        "summary": str(summary)[:TIMELINE_SUMMARY_CHARS] if summary else None,
        "verdict_key": verdict_key,
        "verdict_label": verdict_label,
        "citations": [c for c in (citation(r) for r in cited)
                      if c is not None],
    }


def timeline_event(raw: Any) -> Optional[TimelineEvent]:
    """One event of the feed, or None for a row that is not a mapping."""
    if not isinstance(raw, dict):
        return None
    kind = plain(raw.get("kind"))
    key = (str(kind) if isinstance(kind, str) and kind in TIMELINE_KINDS
           else TIMELINE_KIND_FALLBACK)
    detail = plain(raw.get("detail"))
    text = str(detail) if detail is not None else None
    title = plain(raw.get("title"))
    return {
        "kind_key": key,
        "kind_label": TIMELINE_KINDS.get(key, "UNKNOWN"),
        "when": instant_label(raw.get("ts")),
        "title": str(title) if title is not None else None,
        "detail": text[:TIMELINE_DETAIL_CHARS] if text else None,
        "truncated": bool(text) and len(text) > TIMELINE_DETAIL_CHARS,
    }


def timeline_counts(raw: Any) -> TimelineCounts:
    """The four figures of the counts strip, each None when unreadable."""
    source = raw if isinstance(raw, dict) else {}
    return {
        "total": _count(source.get("total")),
        "bob": _count(source.get("bob")),
        "analyst": _count(source.get("analyst")),
        "system": _count(source.get("system")),
    }


def timeline_view(payload: Any) -> TimelineView:
    """The endpoint's body as the panel's model.

    `events is None` is the failed outcome and covers both a read that
    raised and a body that is not this shape. The counts and the narrative
    are read independently, so a payload whose counts went missing still
    renders its events.
    """
    found = _rows(payload, "events")
    if found is None:
        return {"events": None, "narrative": None,
                "counts": timeline_counts(None)}
    raw = payload if isinstance(payload, dict) else {}
    return {
        "events": [e for e in (timeline_event(r) for r in found)
                   if e is not None],
        "narrative": narrative_view(raw.get("narrative")),
        "counts": timeline_counts(raw.get("counts")),
    }


@router.get(
    "/cases/{case_id}/timeline",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def cases_timeline_fragment(
    request: Request,
    case_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The Attack Story Timeline panel.

    Reads through the endpoint's own handler, which raises 404 for a case
    that is not there. That is the unavailable outcome and not the empty
    one: a case we could not read is not a case with no history.
    """
    from ion.web.case_lifecycle_api import get_case_timeline

    try:
        payload = get_case_timeline(
            case_id, current_user=current_user, session=session)
    except Exception:
        logger.exception(
            "Cases timeline fragment could not read the timeline for %s",
            case_id)
        payload = None

    return render_view(request, TIMELINE_FRAGMENT, timeline_view(payload))


# ---------------------------------------------------------------------------
# Cross-case observable sightings
# ---------------------------------------------------------------------------
#
# GET /api/cases/{id}/similar-observables (case:read) is the deterministic
# sibling of the pgvector panel above: other cases that share an exact
# (type, normalized_value) with one of this case's observables.
#
# loadSimilarObservables told a failed request from an empty one, and the
# rest was defects:
#
#   * `const o = row.observable;` then `o.tlp`, with no guard. One row
#     arriving without its observable threw into the function's single
#     catch, so the whole panel read "Cross-case lookup unavailable"
#     because of one bad row among good ones. A row we cannot read is
#     skipped here, and a panel where no row could be read is the failed
#     outcome rather than the empty one.
#   * `o.sighting_count || 1` printed "1x" for an observable whose count
#     was missing, and could not tell that from a genuine 1.
#   * `esc(o.value)` with no guard printed the word "undefined".
#   * data-args by interpolation, and a `javascript:` href this CSP blocks.
#
# On the TLP fallback: `tlpColors[o.tlp] || tlpColors.amber` looks like it
# invents a marking and it does not. Observable.tlp is nullable=False with
# default="amber", so amber is what the schema means by an unset TLP. What
# it could not do is tell amber from a value outside the five it knew,
# because the column is a plain String(8), and such a value was painted
# amber while its own text showed in the pill.

OBSERVABLES_FRAGMENT = "_fragments/cases_observables.html"

#: How many sightings each indicator lists before "N more".
SIGHTINGS_SHOWN = 6

#: How much of a sighting's case title fits on its card.
SIGHTING_TITLE_CHARS = 100

#: The TLP markings the pill has a colour for, from `tlpColors`. The
#: colours are in static/css/cases-page.css, keyed by these names.
TLP_KEYS: tuple[str, ...] = ("red", "amber", "green", "clear", "white")

#: What the column means by an unset TLP, per Observable.tlp's own default.
TLP_DEFAULT = "amber"

#: A TLP outside TLP_KEYS. Its own text is still shown, so the pill and its
#: colour agree about not knowing.
TLP_FALLBACK = "unknown"


class Sighting(TypedDict):
    case_id: Any
    label: str
    title: Optional[str]
    status: Optional[str]


class SharedObservable(TypedDict):
    """One indicator and the other cases carrying it.

    `sighting_count` is None when the payload had no readable one, where
    `|| 1` claimed a single sighting.
    """

    type: Optional[str]
    value: Optional[str]
    is_ioc: bool
    tlp_key: str
    tlp_label: str
    sighting_count: Optional[int]
    sightings: list[Sighting]
    hidden: int


class ObservablesView(TypedDict):
    rows: Optional[list[SharedObservable]]


def tlp_parts(value: Any) -> tuple[str, str]:
    """The stylesheet key and the pill's words for a TLP marking.

    An absent marking is the column's own default, so it reads AMBER and is
    painted amber. A marking outside the five keeps its own text under the
    `unknown` key, because a pill saying PURPLE in amber disagrees with
    itself.
    """
    marking = plain(value)
    if marking is None or str(marking) == "":
        return TLP_DEFAULT, TLP_DEFAULT.upper()
    text = str(marking)
    if text in TLP_KEYS:
        return text, text.upper()
    return TLP_FALLBACK, text.upper()


def sighting(raw: Any) -> Optional[Sighting]:
    """One other case carrying the indicator, or None for a bad entry."""
    if not isinstance(raw, dict):
        return None
    case_id = plain(raw.get("case_id"))
    number = plain(raw.get("case_number"))
    title = plain(raw.get("title"))
    status = plain(raw.get("status"))
    return {
        "case_id": case_id,
        "label": str(number) if number else f"#{case_id}",
        "title": str(title)[:SIGHTING_TITLE_CHARS] if title else None,
        "status": str(status) if status else None,
    }


def shared_observable(raw: Any) -> Optional[SharedObservable]:
    """One row of the endpoint's `shared` list, or None when it has no
    readable observable. The page let that throw and lost the whole panel."""
    if not isinstance(raw, dict):
        return None
    obs = raw.get("observable")
    if not isinstance(obs, dict):
        return None
    tlp_key, tlp_label = tlp_parts(obs.get("tlp"))
    raw_sightings = raw.get("sightings")
    entries = raw_sightings if isinstance(raw_sightings, list) else []
    seen = [s for s in (sighting(r) for r in entries) if s is not None]
    kind = plain(obs.get("type"))
    value = plain(obs.get("value"))
    return {
        "type": str(kind) if kind is not None else None,
        "value": str(value) if value is not None else None,
        "is_ioc": obs.get("is_ioc") is True,
        "tlp_key": tlp_key,
        "tlp_label": tlp_label,
        "sighting_count": _count(obs.get("sighting_count")),
        "sightings": seen[:SIGHTINGS_SHOWN],
        "hidden": max(0, len(seen) - SIGHTINGS_SHOWN),
    }


def observables_view(payload: Any) -> ObservablesView:
    """The endpoint's body as the panel's model.

    `rows is None` is the failed outcome. A list we were given but could
    read nothing from is also that outcome: we were told there were matches
    and could not read any of them, which is not the same as none.
    """
    found = _rows(payload, "shared")
    if found is None:
        return {"rows": None}
    rows = [r for r in (shared_observable(raw) for raw in found)
            if r is not None]
    if found and not rows:
        return {"rows": None}
    return {"rows": rows}


@router.get(
    "/cases/{case_id}/similar-observables",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def cases_observables_fragment(
    request: Request,
    case_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The cross-case observable sightings panel."""
    from ion.web.case_lifecycle_api import get_case_similar_observables

    try:
        payload = get_case_similar_observables(
            case_id, current_user=current_user, session=session)
    except Exception:
        logger.exception(
            "Cases observables fragment could not read sightings for %s",
            case_id)
        payload = None

    return render_view(request, OBSERVABLES_FRAGMENT,
                       observables_view(payload))

router.include_router(board_router)


# ---------------------------------------------------------------------------
# The workbench kanban and the playbook browser
# ---------------------------------------------------------------------------
#
# A FAILED PINS READ SHOWED AN EMPTY EVIDENCE WORKBENCH
#
#     const pins = pinsResp.ok ? (await pinsResp.json()).pins || [] : [];
#     renderWorkbenchKanban(caseId, pins);
#
# Three columns, each reading "no pins". The workbench is the case's
# evidence board and the ledger behind it is tamper-evident, so "nothing
# has been pinned" is a claim about an investigation, and it was being
# made on the strength of a read that returned 403 or 500.
#
# The verify banner beside it is already right: `if (!verify)` renders
# "verify unavailable" under wb-verify-unknown rather than claiming a
# valid chain. It stays in the page, untouched, and a test pins it there.
#
# A PLAYBOOK WITH NO NAME TOOK THE BROWSER DOWN
#
#     playbooks.filter(p => p.name.toLowerCase().includes(q)
#                           || (p.description || '').toLowerCase()...)
#
# `p.description` is guarded and `p.name` is not, so one nameless
# playbook threw inside the filter and the whole browser fell into the
# catch, which then blamed the load.
#
# A PLAYBOOK NAME WITH A DOUBLE QUOTE BROKE ITS ACTION ARGUMENTS
#
# `esc(p.name)` turns a double quote into &quot;, which is right for an
# attribute and wrong for JSON inside one: the parser decodes it back and
# the array ends early. `|tojson` is the escaping that holds.
#
# BOTH READS NEED A PERMISSION THIS PAGE DOES NOT HAVE
#
# GET /api/alert-cases/{id}/pins takes forensic:read and GET
# /api/playbooks takes playbook:read, where this page is case:read. The
# page reached them over HTTP, so FastAPI applied those dependencies and
# a reader without them got a 403 the catch turned into "Failed to load".
# A fragment calls the function directly, which runs the body with none of
# its Depends(...) applied, so each permission is checked here explicitly.
# tests/unit/test_ui_fragments_respect_called_permissions.py enforces that
# across the package, after I shipped exactly this bug on the pcap page.

WORKBENCH_FRAGMENT = "_fragments/cases_workbench.html"
PLAYBOOKS_FRAGMENT = "_fragments/cases_playbooks.html"

#: What the pins read requires, from forensic_workbench_api.
PINS_PERMISSION = "forensic:read"

#: What the playbook library read requires, from api.list_playbooks.
PLAYBOOKS_PERMISSION = "playbook:read"

#: The kanban's columns, from the page's WB_COLUMNS.
WB_COLUMNS: tuple[tuple[str, str], ...] = (
    ("triage", "Triage"),
    ("confirmed", "Confirmed"),
    ("reported", "Reported"),
)

#: How much of a pin summary and a playbook description the cards show,
#: from the page's slice(0, 200) and substring(0, 80).
PIN_SUMMARY = 200
PLAYBOOK_DESC = 80


def read_case_pins(case_id, current_user, session):
    """The pins read, in one place so a test can stand in for it.

    The permission is checked here and not only at the route. Calling the
    endpoint function directly runs its body with none of its
    Depends(...) applied, so the guarantee has to be local to whatever
    makes the call rather than resting on its one current caller.
    """
    from ion.web import forensic_workbench_api

    if not current_user.has_permission(PINS_PERMISSION):
        raise PermissionError(PINS_PERMISSION)
    return forensic_workbench_api.list_pins_endpoint(
        case_id=case_id, include_dismissed=False, user=current_user,
        session=session)


def read_playbooks(current_user=None, session=None):
    """The playbook library read, likewise, and guarded for the same
    reason."""
    from ion.web import api as playbook_api

    if current_user is None or not current_user.has_permission(
            PLAYBOOKS_PERMISSION):
        raise PermissionError(PLAYBOOKS_PERMISSION)
    return playbook_api.list_playbooks(
        active_only=False, current_user=current_user, session=session)


def _wb_text(value: Any) -> Optional[str]:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _wb_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


class PinCard(TypedDict):
    pin_id: Optional[int]
    severity: Optional[str]
    source_label: str
    title: str
    summary: Optional[str]
    truncated: bool
    pinned_by: str
    pinned_at: Optional[str]


class WorkbenchColumn(TypedDict):
    key: str
    label: str
    pins: list[PinCard]


class WorkbenchView(TypedDict):
    state: str
    case_id: int
    columns: list[WorkbenchColumn]
    visible: Optional[int]
    uncategorised: list[PinCard]


def pin_card(raw: Any) -> Optional[PinCard]:
    if not isinstance(raw, dict):
        return None
    summary = raw.get("summary")
    summary = summary if isinstance(summary, str) else None
    source = _wb_text(raw.get("source_type")) or "note"
    return {
        "pin_id": _wb_int(raw.get("id")),
        "severity": _wb_text(raw.get("severity")),
        "source_label": source.upper(),
        "title": _wb_text(raw.get("title")) or "(untitled)",
        "summary": (None if summary is None
                    else summary[:PIN_SUMMARY]),
        "truncated": bool(summary and len(summary) > PIN_SUMMARY),
        "pinned_by": _wb_text(raw.get("pinned_by_username")) or "unknown",
        "pinned_at": instant_label(raw.get("pinned_at")),
    }


def workbench_view(payload: Any, case_id: int) -> WorkbenchView:
    empty: WorkbenchView = {
        "state": "failed", "case_id": case_id,
        "columns": [{"key": k, "label": l, "pins": []}
                    for k, l in WB_COLUMNS],
        "visible": None, "uncategorised": [],
    }
    if not isinstance(payload, dict):
        return empty
    raw = payload.get("pins")
    if not isinstance(raw, list):
        return {**empty, "state": "unreadable"}

    cards: dict[str, list[PinCard]] = {k: [] for k, _ in WB_COLUMNS}
    other: list[PinCard] = []
    visible = 0
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        status = _wb_text(entry.get("finding_status"))
        if status == "dismissed":
            continue
        card = pin_card(entry)
        if card is None:
            continue
        visible += 1
        # A status outside the three columns belonged to no column, so
        # the pin vanished from a tamper-evident evidence board.
        if status in cards:
            cards[status].append(card)
        else:
            other.append(card)

    return {
        "state": "data",
        "case_id": case_id,
        "columns": [{"key": k, "label": l, "pins": cards[k]}
                    for k, l in WB_COLUMNS],
        "visible": visible,
        "uncategorised": other,
    }


class PlaybookItem(TypedDict):
    playbook_id: Optional[int]
    name: str
    description: Optional[str]
    truncated: bool
    steps: Optional[int]
    is_active: bool


class PlaybooksView(TypedDict):
    state: str
    case_id: int
    filter: str
    active: list[PlaybookItem]
    inactive: list[PlaybookItem]


def playbook_item(raw: Any) -> Optional[PlaybookItem]:
    if not isinstance(raw, dict):
        return None
    description = raw.get("description")
    description = description if isinstance(description, str) else None
    return {
        "playbook_id": _wb_int(raw.get("id")),
        # `p.name.toLowerCase()` threw on a nameless playbook, inside the
        # filter, so one bad row cost the whole browser.
        "name": _wb_text(raw.get("name")) or "unnamed playbook",
        "description": (None if description is None
                        else description[:PLAYBOOK_DESC]),
        "truncated": bool(description
                          and len(description) > PLAYBOOK_DESC),
        "steps": _wb_int(raw.get("step_count")),
        "is_active": raw.get("is_active") is True,
    }


def playbooks_view(payload: Any, case_id: int,
                   needle: str = "") -> PlaybooksView:
    empty: PlaybooksView = {
        "state": "failed", "case_id": case_id, "filter": needle,
        "active": [], "inactive": [],
    }
    if not isinstance(payload, dict):
        return empty
    raw = payload.get("playbooks")
    if not isinstance(raw, list):
        return {**empty, "state": "unreadable"}

    items = [i for i in (playbook_item(e) for e in raw) if i is not None]
    total = len(items)
    if needle:
        lowered = needle.lower()
        items = [i for i in items
                 if lowered in i["name"].lower()
                 or lowered in (i["description"] or "").lower()]

    if not total:
        state = "empty"
    elif not items:
        state = "no_match"
    else:
        state = "data"
    return {
        "state": state, "case_id": case_id, "filter": needle,
        "active": [i for i in items if i["is_active"]],
        "inactive": [i for i in items if not i["is_active"]],
    }


@router.get(
    "/cases/{case_id}/workbench",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def cases_workbench_fragment(
    request: Request,
    case_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The evidence kanban."""
    if not current_user.has_permission(PINS_PERMISSION):
        view = workbench_view(None, case_id)
        view["state"] = "withheld"
        return render_view(request, WORKBENCH_FRAGMENT, view)
    try:
        payload = read_case_pins(case_id, current_user, session)
    except Exception:
        logger.exception("Case workbench could not read its pins")
        payload = None
    return render_view(request, WORKBENCH_FRAGMENT,
                       workbench_view(payload, case_id))


@router.get(
    "/cases/{case_id}/playbooks",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def cases_playbooks_fragment(
    request: Request,
    case_id: int,
    filter: str = "",
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The playbook browser, filtered server side."""
    if not current_user.has_permission(PLAYBOOKS_PERMISSION):
        view = playbooks_view(None, case_id, filter)
        view["state"] = "withheld"
        return render_view(request, PLAYBOOKS_FRAGMENT, view)
    try:
        payload = read_playbooks(current_user=current_user,
                                 session=session)
    except Exception:
        logger.exception("Case playbook browser could not read the library")
        payload = None
    return render_view(request, PLAYBOOKS_FRAGMENT,
                       playbooks_view(payload, case_id, filter))


# ---------------------------------------------------------------------------
# The attack-path graph's lanes, stats and legend
# ---------------------------------------------------------------------------
#
# AN UNREADABLE PAYLOAD READ AS "NO ATTACK PATH DERIVED YET"
#
#     const nodes = data.nodes || [];
#     ...
#     if (nodes.length === 0) {
#         container.innerHTML = '... No attack path derived yet</div>';
#
# The HTTP failures were handled, unusually for this project: a non-ok
# response said "Attack path unavailable" and the catch said "Attack path
# failed to load". What was not handled is a 200 whose body is the wrong
# shape, which became an empty node list and then the sentence saying
# this case has no established chain of activity.
#
# The edge overlay stays in the page. drawAttackPathEdges places each
# curve from getBoundingClientRect and the graph's scroll offsets, so it
# needs a laid-out DOM, and it draws SVG with createElementNS rather than
# markup, so there is nothing in it for a stylesheet to reach. The
# fragment hands it the edges on the graph element instead of making it
# fetch again, and drops any edge missing an endpoint, which the overlay
# would refuse to draw anyway for the right reason: skip, never fabricate.

ATTACK_PATH_FRAGMENT = "_fragments/cases_attack_path.html"

#: The node glyphs, from the page's _APG_TYPE_GLYPH.
APG_GLYPHS: dict[str, str] = {
    "host": "H", "user": "U", "process": "P", "ip": "IP",
    "domain": "D", "file": "F", "hash": "#",
}

#: The four edge types and their legend labels, in the page's order.
APG_EDGES: tuple[tuple[str, str], ...] = (
    ("process_lineage", "Process lineage"),
    ("network_flow", "Network flow"),
    ("auth_presence", "Auth / presence"),
    ("shared_observable", "Shared observable"),
)

#: Threat levels the node card has a class for. One outside this set keeps
#: its text and takes no class, as elsewhere on this page.
APG_THREAT_LEVELS: tuple[str, ...] = (
    "critical", "high", "medium", "low", "unknown",
)


def tactic_label(slug: Any) -> str:
    """`initial-access` to `Initial Access`, and None to Unattributed."""
    text = _wb_text(slug)
    if text is None:
        return "Unattributed"
    return " ".join(w.capitalize() if w else w for w in text.split("-"))


class ApgNode(TypedDict):
    node_id: str
    kind: str
    glyph: str
    threat: str
    threat_class: Optional[str]
    label: str
    title: str


class ApgLane(TypedDict):
    tactic_label: str
    nodes: list[ApgNode]


class ApgStats(TypedDict):
    nodes: Optional[int]
    edges: Optional[int]
    alerts: Optional[int]
    tactics: Optional[list[str]]
    reaches_impact: bool


class AttackPathView(TypedDict):
    state: str
    lanes: list[ApgLane]
    stats: ApgStats
    legend: list[dict]
    edges: list[dict]
    edges_readable: bool


def apg_node(raw: Any) -> Optional[ApgNode]:
    if not isinstance(raw, dict):
        return None
    identifier = raw.get("id")
    if identifier is None:
        return None
    kind = (_wb_text(raw.get("type")) or "unknown").lower()
    threat = (_wb_text(raw.get("threat_level")) or "unknown").lower()
    label = (_wb_text(raw.get("label")) or _wb_text(raw.get("value"))
             or str(identifier))
    return {
        "node_id": str(identifier),
        "kind": kind,
        "glyph": APG_GLYPHS.get(kind, "?"),
        "threat": threat,
        # None when the stylesheet has no class for it.
        "threat_class": (threat if threat in APG_THREAT_LEVELS else None),
        "label": label,
        "title": "%s \u00b7 %s \u00b7 threat: %s" % (kind, label, threat),
    }


def apg_lanes(nodes: Any, phases: Any) -> Optional[list[ApgLane]]:
    """Nodes placed in the earliest phase that names them.

    A node named by no phase falls into a trailing Unattributed lane, so
    the graph still renders everything, which is the page's own rule.
    """
    if not isinstance(nodes, list) or not isinstance(phases, list):
        return None
    cards: list[ApgNode] = [c for c in (apg_node(n) for n in nodes)
                            if c is not None]

    lane_of: dict[str, int] = {}
    ordered: list[tuple[Optional[str], list[ApgNode]]] = []
    for index, phase in enumerate(phases):
        if not isinstance(phase, dict):
            ordered.append((None, []))
            continue
        ordered.append((phase.get("tactic"), []))
        ids = phase.get("node_ids")
        if isinstance(ids, list):
            for nid in ids:
                key = str(nid)
                if key not in lane_of:
                    lane_of[key] = index

    unattributed: list[ApgNode] = []
    for card in cards:
        index = lane_of.get(card["node_id"])
        if index is not None and 0 <= index < len(ordered):
            ordered[index][1].append(card)
        else:
            unattributed.append(card)

    lanes: list[ApgLane] = [
        {"tactic_label": tactic_label(tactic), "nodes": found}
        for tactic, found in ordered]
    if unattributed:
        lanes.append({"tactic_label": tactic_label(None),
                      "nodes": unattributed})
    return lanes


def apg_stats(raw: Any, nodes: Any, edges: Any) -> ApgStats:
    stats = raw if isinstance(raw, dict) else {}
    edge_stats = stats.get("edges")
    edge_stats = edge_stats if isinstance(edge_stats, dict) else {}
    tactics = stats.get("tactics_reached")
    return {
        # A missing count falls back to the list length, which the page
        # did and which is the better answer.
        "nodes": (_wb_int(stats.get("nodes"))
                  if _wb_int(stats.get("nodes")) is not None
                  else (len(nodes) if isinstance(nodes, list) else None)),
        "edges": (_wb_int(edge_stats.get("total"))
                  if _wb_int(edge_stats.get("total")) is not None
                  else (len(edges) if isinstance(edges, list) else None)),
        # `stats.alerts != null ? stats.alerts : 0` said no alerts fed
        # this path when the count was simply not recorded.
        "alerts": _wb_int(stats.get("alerts")),
        "tactics": (None if not isinstance(tactics, list) else
                    [tactic_label(t) for t in tactics]),
        "reaches_impact": stats.get("reaches_impact") is True,
    }


def apg_edges(raw: Any) -> tuple[list[dict], bool]:
    """The edges the overlay needs, and whether the list was readable.

    An edge missing an endpoint is dropped: the overlay refuses to draw
    one anyway, and its reason is the right one.
    """
    if not isinstance(raw, list):
        return [], False
    out = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        source = entry.get("source")
        target = entry.get("target")
        if source is None or target is None:
            continue
        kind = _wb_text(entry.get("type")) or "unknown"
        out.append({
            "source": str(source), "target": str(target), "type": kind,
            # The overlay used to look this up in its own _APG_EDGE_LABELS
            # table, which moved here with the legend. It already prefers
            # e.label, so resolving it once on the way out keeps the
            # labels in one place.
            "label": (_wb_text(entry.get("label"))
                      or dict(APG_EDGES).get(kind) or kind),
        })
    return out, True


def read_attack_path(case_id, current_user, session):
    """The attack-path read. case:read, which this page already holds."""
    from ion.web import case_lifecycle_api

    return case_lifecycle_api.get_case_attack_path(
        case_id=case_id, current_user=current_user, session=session)


def attack_path_view(payload: Any) -> AttackPathView:
    legend = [{"key": k, "label": l} for k, l in APG_EDGES]
    empty: AttackPathView = {
        "state": "failed", "lanes": [],
        "stats": apg_stats(None, None, None), "legend": legend,
        "edges": [], "edges_readable": True,
    }
    if not isinstance(payload, dict):
        return empty
    lanes = apg_lanes(payload.get("nodes"), payload.get("phases"))
    if lanes is None:
        return {**empty, "state": "unreadable"}
    edges, edges_readable = apg_edges(payload.get("edges"))
    if not any(lane["nodes"] for lane in lanes):
        return {**empty, "state": "empty"}
    return {
        "state": "data",
        "lanes": lanes,
        "stats": apg_stats(payload.get("stats"), payload.get("nodes"),
                           payload.get("edges")),
        "legend": legend,
        "edges": edges,
        "edges_readable": edges_readable,
    }


@router.get(
    "/cases/{case_id}/attack-path",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def cases_attack_path_fragment(
    request: Request,
    case_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The lanes, the stats strip and the legend."""
    try:
        result = read_attack_path(case_id, current_user, session)
        payload = await result if hasattr(result, "__await__") else result
    except Exception:
        logger.exception("Case attack path could not be read")
        payload = None
    return render_view(request, ATTACK_PATH_FRAGMENT,
                       attack_path_view(payload))


# ---------------------------------------------------------------------------
# The case detail panel
# ---------------------------------------------------------------------------
#
# renderPanelContent was 408 lines returning one string, assigned straight
# to body.innerHTML, and openCaseDetail wrapped the whole sequence in a
# single try. Its own comment admits what that cost:
#
#     // Name the failure. Everything above runs inside one try, so a
#     // throw in any of renderPanelContent / applyConfidenceMeters /
#     // switchPanelTab / selectCaseAlert lands here indistinguishably --
#     // and the request itself returns 200, so the server log is clean
#     // and the only evidence was the words "Failed to load case
#     // details".
#
# A render failure is a 500 with a traceback now.
#
# TWO COUPLINGS THAT HAD TO SURVIVE
#
# renderPanelContent sorted c.alerts *in place*, deliberately, because
# openCaseDetail then reads c.alerts[0] and passes index 0 to
# selectCaseAlert. Sorting a copy would have left the rail showing one
# alert selected while the detail column rendered another. The sort is
# here now, so the view states which alert is first and the page reads
# that rather than re-deriving it and disagreeing.
#
# _railAlerts[alertId] = a stashed each full alert so selecting a row
# could hand it to the shared alert-detail component without a refetch.
# That still happens in the page: openCaseDetail keeps its
# /api/cases/{id} read for the ten async loaders anyway, so it fills the
# cache from a payload it already had.
#
# AND ONE THING THAT CANNOT MOVE
#
# The notes render markdown, and ui/template_render.py records why that
# stays client-side: ION has no HTML sanitiser in its dependencies. So
# this sends each note's raw text and the page renders it, through
# DOMPurify's RETURN_DOM_FRAGMENT and replaceChildren rather than
# innerHTML, which keeps it off the runtime-write count.

PANEL_FRAGMENT = "_fragments/cases_panel.html"

#: The severity strip's icon per level, from the page's sevIcons.
PANEL_SEV_ICONS: dict[str, str] = {
    "critical": "icon-alert-octagon",
    "high": "icon-alert-triangle",
    "medium": "icon-info",
    "low": "icon-minus-circle",
}

#: The panel's tabs, in the page's order, with the default first.
PANEL_TABS: tuple[tuple[str, str], ...] = (
    ("alerts", "Alerts"),
    ("overview", "Overview"),
    ("observables", "Observables"),
    ("timeline", "Timeline"),
    ("attackpath", "Attack Path"),
    ("notes", "Notes"),
    ("actions", "Actions"),
)

#: The selectable values of the two metadata dropdowns.
PANEL_STATUSES: tuple[str, ...] = ("open", "acknowledged", "closed")
PANEL_SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")

#: Triage order for the alert rail. The page reused the board's _sevRank
#: rather than declaring a second scale, and so does this.
PANEL_SEV_RANK: dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

#: The alert status badge's classes. These were statusColors, a table of
#: an rgba and a var per status held in JavaScript and applied through
#: data-ion-style, so the palette sat where no stylesheet could reach it.
PANEL_STATUS_CLASSES: tuple[str, ...] = ("open", "acknowledged", "closed")


class PanelAlert(TypedDict):
    alert_id: str
    index: int
    name: str
    severity: str
    severity_class: Optional[str]
    status: Optional[str]
    status_class: Optional[str]
    bits: list[str]


class PanelNote(TypedDict):
    note_id: str
    user: Optional[str]
    when: Optional[str]
    raw: str


class PanelTag(TypedDict):
    kind: str
    label: str
    value: str


class KibanaPill(TypedDict):
    display: str


class PanelView(TypedDict):
    state: str
    case_id: int
    case_number: Optional[str]
    title: Optional[str]
    severity: str
    severity_icon: str
    alert_count: Optional[int]
    observable_count: Optional[int]
    age: Optional[str]
    tabs: list[dict]
    status: Optional[str]
    statuses: list[str]
    severities: list[str]
    assigned_to_id: Optional[int]
    users: Optional[list[dict]]
    users_withheld: bool
    kibana_pills: Optional[list[KibanaPill]]
    kibana_mismatch: bool
    created: Optional[str]
    tags: Optional[list[PanelTag]]
    description: Optional[str]
    observables: Optional[list[dict]]
    mitre: Optional[list[dict]]
    alerts: Optional[list[PanelAlert]]
    first_alert_id: Optional[str]
    notes: Optional[list[PanelNote]]
    note_count: Optional[int]
    kibana_case_id: Optional[str]
    kibana_url: Optional[str]
    escalated: bool


def _panel_text(value: Any) -> Optional[str]:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def observable_key(raw: Any) -> Optional[tuple[str, str]]:
    if not isinstance(raw, dict):
        return None
    return (str(raw.get("type") or ""), str(raw.get("value") or ""))


def panel_observables(case_obs: Any, alerts: Any) -> Optional[list[dict]]:
    """The case's observables merged with its alerts', duplicates removed.

    The page did this so a multi-alert case never shows the same IP twice
    and the count matches the list. None here when either list is not a
    list, because "no observables extracted yet" is a different answer
    from "I could not read them".
    """
    if not isinstance(case_obs, list):
        return None
    seen: dict[tuple[str, str], dict] = {}

    def take(entry: Any) -> None:
        key = observable_key(entry)
        if key is not None and key not in seen:
            threat = entry.get("threat_level")
            seen[key] = {
                "kind": _panel_text(entry.get("type")),
                "value": _panel_text(entry.get("value")),
                "threat_level": (threat if threat is not None
                                 else entry.get("priority")),
                "score": entry.get("score"),
                "source": _panel_text(entry.get("source")),
            }

    for entry in case_obs:
        take(entry)
    if isinstance(alerts, list):
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            nested = alert.get("observables")
            if isinstance(nested, list):
                for entry in nested:
                    take(entry)
    return [observable_chip(v) for v in seen.values()]


#: Observable types OpenCTI enrichment can score. Others get a plain
#: chip, which is what _enrichableObsTypes decided in the page.
ENRICHABLE_OBS: frozenset[str] = frozenset({
    "ip", "ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5",
    "hash", "email",
})

#: Where a chip's value is clipped, from the page's 44/41 pair.
OBS_CHIP_MAX = 44
OBS_CHIP_KEEP = 41


def observable_chip(raw: dict) -> dict:
    """One typed observable chip.

    Enrichable types carry a threat badge whose label is the score when
    there is one, `ok` for benign, `?` for unknown, and the level
    otherwise. The page's own resolution, kept.
    """
    kind = (raw.get("kind") or "unknown").lower()
    value = raw.get("value") or ""
    score = raw.get("score")
    has_score = score is not None and score != ""
    level = str(raw.get("threat_level") or "unknown").lower()
    label = None
    if kind in ENRICHABLE_OBS:
        if has_score:
            label = str(score)
        elif level == "benign":
            label = "ok"
        elif level == "unknown":
            label = "?"
        else:
            label = level
    tip = "Threat level: %s" % level
    if has_score:
        tip += " · score %s" % score
    source = raw.get("source")
    if source:
        tip += " · %s" % source
    return {
        "kind": kind,
        "value": value,
        "short": (value[:OBS_CHIP_KEEP] + "…"
                  if len(value) > OBS_CHIP_MAX else value),
        "level": level,
        "label": label,
        "tip": tip,
    }


def panel_tags(hosts: Any, users: Any, rules: Any) -> Optional[list[PanelTag]]:
    """The context strip. None when any of the three is not a list."""
    if not all(isinstance(v, list) for v in (hosts, users, rules)):
        return None
    tags: list[PanelTag] = []
    for values, kind, label in ((hosts, "host", "H"), (users, "user", "U"),
                                (rules, "rule", "R")):
        for value in values:
            text = _panel_text(value) if isinstance(value, str)                 else _panel_text(str(value))
            if text:
                tags.append({"kind": kind, "label": label, "value": text})
    return tags


def panel_mitre(alerts: Any) -> Optional[list[dict]]:
    """Techniques across the case's alerts, first mention winning.

    The page accepted either a string or an object per technique, and so
    does this.
    """
    if not isinstance(alerts, list):
        return None
    out: list[dict] = []
    seen: set[str] = set()
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        techniques = alert.get("mitre_techniques")
        if not isinstance(techniques, list):
            continue
        for entry in techniques:
            if isinstance(entry, str):
                identifier = _panel_text(entry)
                name = identifier
            elif isinstance(entry, dict):
                identifier = (_panel_text(entry.get("id"))
                              or _panel_text(entry.get("technique_id")))
                name = (_panel_text(entry.get("name"))
                        or _panel_text(entry.get("technique"))
                        or identifier)
            else:
                continue
            if identifier and identifier not in seen:
                seen.add(identifier)
                out.append({"id": identifier, "name": name})
    return out


def panel_alerts(alerts: Any, case_severity: str) -> Optional[list[PanelAlert]]:
    """The rail, ordered by severity then newest.

    The page sorted c.alerts in place because openCaseDetail read
    c.alerts[0] afterwards. The order is decided here instead and the
    view names the first one, so the rail and the detail column cannot
    disagree.
    """
    if not isinstance(alerts, list):
        return None
    entries = [a for a in alerts if isinstance(a, dict)]

    def severity_of(alert: dict) -> str:
        return (_panel_text(alert.get("priority"))
                or _panel_text(alert.get("severity"))
                or case_severity)

    # Two stable passes rather than one clever key: newest first, then by
    # severity, which leaves newest-first inside each severity because
    # Python's sort is stable. The page broke the tie the same way.
    entries.sort(key=lambda a: _panel_text(a.get("timestamp")) or "",
                 reverse=True)
    entries.sort(key=lambda a: PANEL_SEV_RANK.get(severity_of(a), 9))

    out: list[PanelAlert] = []
    for index, alert in enumerate(entries):
        identifier = _panel_text(alert.get("es_alert_id")) or "unknown"
        name = _panel_text(alert.get("rule_name")) or identifier[:24]
        severity = (_panel_text(alert.get("priority"))
                    or _panel_text(alert.get("severity"))
                    or case_severity)
        status = _panel_text(alert.get("status")) or "open"
        bits = []
        process = _panel_text(alert.get("process_name"))
        if process:
            bits.append(process)
        source = _panel_text(alert.get("source_ip"))
        if source:
            destination = _panel_text(alert.get("destination_ip"))
            bits.append("%s \u2192 %s" % (source, destination)
                        if destination else source)
        out.append({
            "alert_id": identifier,
            "index": index,
            "name": name,
            "severity": severity,
            "severity_class": (severity if severity in PANEL_SEV_RANK
                               else None),
            "status": status,
            # The badge's palette is a class now, not an rgba pair held
            # in a JavaScript table and applied through data-ion-style.
            "status_class": (status if status in PANEL_STATUS_CLASSES
                             else None),
            "bits": bits,
        })
    return out


def panel_notes(notes: Any) -> Optional[list[PanelNote]]:
    """The notes, raw. Markdown rendering stays client-side because ION
    has no HTML sanitiser, which ui/template_render.py records."""
    if not isinstance(notes, list):
        return None
    out: list[PanelNote] = []
    for index, entry in enumerate(notes):
        if not isinstance(entry, dict):
            continue
        identifier = entry.get("id")
        content = entry.get("content")
        out.append({
            "note_id": ("cnote-%s" % identifier if identifier is not None
                        else "cnote-i%d" % index),
            "user": _panel_text(entry.get("user")),
            "when": instant_label(entry.get("created_at")),
            "raw": content if isinstance(content, str) else "",
        })
    return out


def kibana_pills(raw: Any,
                 assigned_to_id: Any) -> tuple[Optional[list[KibanaPill]], bool]:
    """The linked Kibana case's assignees, and whether they disagree.

    A mismatch means someone edited the case in Kibana since ION last
    wrote to it.
    """
    if not isinstance(raw, list):
        return None, False
    pills: list[KibanaPill] = []
    ion_ids: list[Any] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        display = (_panel_text(entry.get("ion_display_name"))
                   or _panel_text(entry.get("ion_username"))
                   or _panel_text(entry.get("full_name"))
                   or _panel_text(entry.get("username"))
                   or _panel_text(entry.get("uid"))
                   or "unnamed")
        pills.append({"display": display})
        if entry.get("ion_user_id") is not None:
            ion_ids.append(entry.get("ion_user_id"))
    mismatch = bool(pills) and (assigned_to_id is None
                                or assigned_to_id not in ion_ids)
    return pills, mismatch


def read_case_detail(case_id, current_user, session):
    """One case with its alerts, observables and notes. case:read, which
    this page already holds."""
    from ion.web import case_lifecycle_api

    return case_lifecycle_api.get_case_detail(
        case_id=case_id, current_user=current_user, session=session)


def panel_view(payload: Any, users: Any,
               users_withheld: bool) -> PanelView:
    empty: PanelView = {
        "state": "failed", "case_id": 0, "case_number": None,
        "title": None, "severity": "medium",
        "severity_icon": PANEL_SEV_ICONS["medium"],
        "alert_count": None, "observable_count": None, "age": None,
        "tabs": [], "status": None,
        "statuses": list(PANEL_STATUSES),
        "severities": list(PANEL_SEVERITIES),
        "assigned_to_id": None, "users": users,
        "users_withheld": users_withheld,
        "kibana_pills": None, "kibana_mismatch": False, "created": None,
        "tags": None, "description": None, "observables": None,
        "mitre": None, "alerts": None, "first_alert_id": None,
        "notes": None, "note_count": None, "kibana_case_id": None,
        "kibana_url": None, "escalated": False,
    }
    if not isinstance(payload, dict):
        return empty

    severity = _panel_text(payload.get("severity")) or "medium"
    alerts = panel_alerts(payload.get("alerts"), severity)
    observables = panel_observables(payload.get("observables"),
                                   payload.get("alerts"))
    notes = panel_notes(payload.get("notes"))
    pills, mismatch = kibana_pills(payload.get("kibana_assignees"),
                                   payload.get("assigned_to_id"))
    counts = {"alerts": len(alerts) if alerts is not None else None,
              "observables": (len(observables) if observables is not None
                              else None)}
    return {
        "state": "data",
        "case_id": _wb_int(payload.get("id")) or 0,
        "case_number": _panel_text(payload.get("case_number")),
        "title": _panel_text(payload.get("title")),
        "severity": severity,
        "severity_icon": PANEL_SEV_ICONS.get(severity, "icon-info"),
        "alert_count": counts["alerts"],
        "observable_count": counts["observables"],
        "age": age_label(payload.get("created_at")),
        "tabs": [{"key": k, "label": l,
                  "count": counts.get(k)} for k, l in PANEL_TABS],
        "status": _panel_text(payload.get("status")),
        "statuses": list(PANEL_STATUSES),
        "severities": list(PANEL_SEVERITIES),
        "assigned_to_id": _wb_int(payload.get("assigned_to_id")),
        "users": users,
        "users_withheld": users_withheld,
        "kibana_pills": pills,
        "kibana_mismatch": mismatch,
        "created": instant_label(payload.get("created_at")),
        "tags": panel_tags(payload.get("affected_hosts"),
                           payload.get("affected_users"),
                           payload.get("triggered_rules")),
        "description": (_panel_text(payload.get("description"))
                        or _panel_text(payload.get("evidence_summary"))),
        "observables": observables,
        "mitre": panel_mitre(payload.get("alerts")),
        "alerts": alerts,
        "first_alert_id": (alerts[0]["alert_id"] if alerts else None),
        "notes": notes,
        "note_count": len(notes) if notes is not None else None,
        "kibana_case_id": _panel_text(payload.get("kibana_case_id")),
        "kibana_url": _panel_text(payload.get("kibana_url")),
        "escalated": payload.get("dfir_iris_case_id") is not None,
    }


@router.get(
    "/cases/{case_id}/panel",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def cases_panel_fragment(
    request: Request,
    case_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The panel's own markup. The ten lazy sections stay the page's."""
    from ion.web import api as assignable_api
    from ion.web.ui._cases_board import assignees_view

    try:
        result = read_case_detail(case_id, current_user, session)
        payload = await result if hasattr(result, "__await__") else result
    except Exception:
        logger.exception("Case panel could not read case %s", case_id)
        payload = None

    # The assignee list needs alert:read, which this page does not hold,
    # so it is withheld rather than fetched for a reader without it. Same
    # shape as the board's own assignee dropdown.
    permitted = current_user.has_permission("alert:read")
    users = None
    if permitted:
        try:
            users = (await assignable_api.list_assignable_users(
                session=session))
        except Exception:
            logger.exception("Case panel could not read the user list")
    view = panel_view(payload, assignees_view(users, permitted)["users"],
                      not permitted)
    return render_view(request, PANEL_FRAGMENT, view)
