"""The landing page at `/`: welcome row, alert feed, four KPIs, cases, handover.

dashboard_v2.html fetched four endpoints inside one `Promise.all`, each with a
`.catch(() => null)`, and built every data-driven part of the page out of
string concatenation at fourteen innerHTML sites behind a hand-rolled
`escHtml()`, two severity colour tables, a `relativeTime()`, an `hhmmss()` and
a `formatHoursMTTR()`. All of it is rendered here, and Jinja escapes.

Four regions, four fragment routes, because the four reads carry three
different permissions:

    /api/dashboard                      get_current_user, no named permission
    /api/dashboard/team-metrics         require_permission("alert:read")
    /api/cases?status=open              require_permission("case:read")
    /api/shift-handover/report?hours=8  require_permission("alert:read")

One route could only carry one gate. The loosest would make the open-case
list a softer way into `case:read` data than GET /api/cases, and the
strictest would hide the alert feed from a viewer who can read alerts but not
cases. Neither is the page.

So the permissions force three routes, not four: they say the overview, the
cases and the two alert:read regions cannot share one gate, and team-metrics
and the handover carry the same gate as each other. Splitting those two is the
fourth route, and the reason is the one de_workbench gives. Four `try` blocks
inside one route keep the regions independent of each other's exceptions but
not of the one HTTP request, so a timeout or a dropped connection blanks every
region sharing that request. The two read different stores on different
schedules, and a slow aggregation over thirty days of cases must not be able
to blank the handover an incoming shift lead is reading.

The page route itself is `require_page_auth` in server.py, which is any
logged-in user and therefore looser than three of these four. That is not
changed here and server.py is not this conversion's file: a viewer without
`case:read` reaches the page, the cases fragment answers 403, and
static/js/htmx-errors.js words it as "this account cannot read it". The panel
says that instead of saying the queue is empty, which is the whole point of
the split.

What the JavaScript got wrong, as opposed to merely built badly:

  * `total_alerts` is `len(alerts)` where the service was called with
    `limit=10`, so the headline "Open alerts · 24h" could never exceed 10 and
    `critical_count` and `high_count` were counted over those same ten rows.
    An estate with four thousand open alerts read "10", under a sparkline
    drawn from a real 24-hour aggregation whose peak was far above it. The
    number and the shape beside it disagreed, and the number was the wrong
    one. The 24-hour total is the sum of the histogram the same read already
    carries, so that is what the tile shows now; the severity counts stay
    what they are and the line says how many alerts they were counted over.
  * `es.critical_count || 0`, `|| 0`, `|| 0` again. Elasticsearch being
    switched off and Elasticsearch being unreachable both arrive as a payload
    of zeros, so "0 critical", "0 open alerts" and "No active alerts." were
    what the landing page said for a store it had never asked and for a store
    that had refused. Three states now, kept apart.
  * A failed `/api/dashboard` left `#alerts-feed` reading "Loading alerts…"
    for ever, because the feed was only ever written inside `if (es)`. The
    region that matters most on the page did not even reach the empty state
    it would have been wrong to show.
  * `casesResp?.cases && currentUsername` meant a `/api/dashboard` failure
    silently blanked the open-cases panel too: `casesResp` was a good payload
    so the `else if (casesResp === null)` branch did not fire either, and
    both the list and the KPI kept their placeholders. One dead service took
    out a region that had read fine.
  * "Cases unavailable (permission required)." was printed for every cases
    failure, including a 500. It asserted a cause it did not know.
  * `?status=open` is an exact match on AlertCaseStatus.OPEN, and the
    client-side `(c.status || '').toLowerCase() !== 'closed'` that followed
    it was dead code. So "My open cases" silently omitted every acknowledged
    case, while `open_cases` in team-metrics counts `status != CLOSED`: the
    same dashboard held two different definitions of open. The filter the
    JavaScript was reaching for is the one used here.
  * That page of cases was capped at `case_query_service.DEFAULT_LIMIT`, one
    hundred, newest first across the whole estate, and then filtered to the
    caller in the browser. Past a hundred open cases the analyst's own count
    silently fell. The filter is a WHERE clause now and the count is the
    query's own COUNT, so it is exact.
  * `if (c.observables_count != null)` could never fire. The list rows come
    from `case_query_service._summary`, which deliberately does not carry
    that column, so the observables chip was unreachable code.
  * "all clear" was printed both when the analyst had no open cases at all
    and when every one of them was low severity, because the breakdown only
    ever listed critical, high and medium. Two states, one word.
  * `h.cases?.opened ?? 0` and its two siblings turned a handover report
    missing a key into three confident zeros.
  * `${critical} critical and ${high} high alert${high === 1 ? '' : 's'}`
    pluralised on the wrong number, so one critical and one high read "1
    critical and 1 high alert pending triage".
  * The role switcher rendered one `<button>` per role with no handler and no
    `data-click-action`, so the control that looks like the way to change
    focus role did nothing. POST /api/auth/focus-mode is the endpoint it was
    presumably meant to call. Wiring it is a feature rather than a port, so
    the roles render as what they actually are here: the focus role, marked,
    beside the others held.
  * "Open alert queue" in the card footer was `href="#"`.
  * The Customize panel never opened. `toggleDashConfig` toggled
    `panel.style.display` on an element the markup hides with Tailwind's
    `hidden` class, so the first click set `display:none` on something
    already hidden and the second set it back to `''`, which `hidden`
    overrides. The remaining script drops the class the first time it touches
    the element and decides visibility by the inline declaration alone.

Each region sends its own summary tiles back as out-of-band swaps beside its
panel, so a figure and the rows it summarises come from one read. The
alternative was a fifth route re-reading all four stores to paint the tiles,
which doubles the work on the page every user lands on and lets a tile
disagree with the table under it.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.alert_triage import AlertCaseStatus
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

#: The permission GET /api/dashboard/team-metrics and GET
#: /api/shift-handover/report both name, read off the live routes rather than
#: their decorators. Spelled once so the two fragments mirroring them cannot
#: drift apart.
ALERT_PERMISSION = "alert:read"

#: The permission GET /api/cases names. That path is not declared anywhere:
#: server.py's _install_path_aliases copies the endpoint at
#: /api/elasticsearch/alerts/cases to it, with the same dependencies, so
#: grepping for the route the page fetched finds nothing and the gate has to
#: be read off the mounted app.
CASE_PERMISSION = "case:read"

_OVERVIEW_FRAGMENT = "_fragments/dashboard_v2_overview.html"
_METRICS_FRAGMENT = "_fragments/dashboard_v2_metrics.html"
_CASES_FRAGMENT = "_fragments/dashboard_v2_cases.html"
_HANDOVER_FRAGMENT = "_fragments/dashboard_v2_handover.html"

#: The window /api/shift-handover/report was fetched with. Not a control: the
#: page has never offered one, and inventing one in a port is a new feature
#: whose absence is not a defect. Nothing on this page is a filter, so no
#: fragment here declares `hx-include` and none of them can duplicate a
#: parameter into a nested request.
HANDOVER_HOURS = 8

#: How many alert rows the feed shows, from `.slice(0, 6)`.
ALERTS_SHOWN = 6

#: How many case rows the panel shows, from `.slice(0, 4)`.
CASES_SHOWN = 4

#: How many handover highlights the list shows, from `.slice(0, 5)`.
HIGHLIGHTS_SHOWN = 5

#: What "my open cases" means. The JavaScript asked for OPEN and then applied
#: a dead `!== 'closed'` filter on top, which says what it was reaching for.
#: Everything that is not closed, which is also how team-metrics counts the
#: estate's open cases, so the two figures on this page now agree.
MY_CASE_STATUSES = tuple(
    m.value for m in AlertCaseStatus if m is not AlertCaseStatus.CLOSED
)

#: The severities the breakdown bars list, highest first, from the old
#: `rows` table. Low and info are deliberately not listed: the breakdown is
#: about what needs attention. What the JavaScript then got wrong was saying
#: "all clear" when none of these three had a row, which is also what it said
#: when the analyst had no cases at all.
BREAKDOWN_SEVERITIES = ("critical", "high", "medium")

#: Widest and narrowest a breakdown bar may be drawn, from
#: `Math.max(8, Math.round(share * 32))`. Pixels rather than a percentage
#: because the bar sits in a fixed-width stat figure.
BAR_MAX_PX = 32
BAR_MIN_PX = 8

#: The sparkline's viewBox, matching the `viewBox="0 0 140 44"` the page
#: shell declares. The path is computed here rather than in the browser: the
#: old `renderSparkline()` measured nothing from the DOM, so the server can
#: produce the identical geometry, and computing it beside the count it sits
#: under is what keeps the shape and the number from coming out of different
#: reads. `preserveAspectRatio="none"` means these are viewBox units and the
#: CSS box scales them, so no viewer-specific measurement is involved.
SPARK_W = 140
SPARK_H = 44
SPARK_PAD = 2

#: Floor left under the line so a zero bucket does not sit on the bottom
#: edge, from the JavaScript's `- 4`.
SPARK_FLOOR = 4

#: Elasticsearch's three states, which the payload expresses as two booleans
#: and the old page collapsed into one. A string rather than the booleans so
#: no template can test one of them for truth and get the other state's
#: answer, and so the state the counts are meaningless in has a name.
ES_OFF = "off"
ES_UNREACHABLE = "unreachable"
ES_LIVE = "live"


def _now() -> datetime:
    """Timezone-aware UTC, which is what Elasticsearch timestamps carry."""
    return datetime.now(timezone.utc)


def _es_state(payload: dict[str, Any]) -> str:
    """Which of Elasticsearch's three states this payload describes.

    `enabled` false is "not configured" and `connected` false on top of
    `enabled` is "configured and did not answer". Only the third state's
    counts are measurements; in the other two they are the initialiser's
    zeros, which is what `|| 0` could not tell apart.
    """
    if not payload.get("enabled"):
        return ES_OFF
    if not payload.get("connected"):
        return ES_UNREACHABLE
    return ES_LIVE


def _number(value: object) -> Optional[int | float]:
    """A figure, or None when there is not one there.

    A bool is not a number even though `bool` is an `int`, so a `True` in a
    count column cannot render as one alert.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _as_dt(raw: object) -> Optional[datetime]:
    """An isoformatted timestamp back as an aware datetime, or None.

    Used only to measure a duration. The instant itself is handed to the `ts`
    macro as the raw value, never as this function's result, and the
    difference matters: a naive value gets a UTC offset stamped on it here,
    which is an assumption this function has to make because a duration cannot
    be computed without one. `ion.web.templating._ts_parts` makes the opposite
    and correct call for display, marking a zoneless value `data-ts-local="no"`
    and leaving it as stored, because JavaScript would otherwise read the
    digits as the viewer's own clock and convert out of a zone the value was
    never in. Passing an aware datetime built here would tell it the value is
    UTC on a Postgres deployment whose session timezone is not, and every row
    would be wrong by the server's offset while looking authoritative.

    The assumption survives in `age_text` alone, where it is bounded by the
    offset inside a relative phrase rather than presented as an instant.
    """
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _age_text(when: Optional[datetime], now: datetime) -> Optional[str]:
    """How long ago, or None when nobody recorded when.

    A duration carries no timezone, so the server's answer is the viewer's.
    None rather than a number for a missing timestamp: `relativeTime(null)`
    returned the empty string, which rendered as a blank line that read as a
    row with no age rather than a row with no timestamp.
    """
    if when is None:
        return None
    seconds = (now - when).total_seconds()
    if seconds < 0:
        # Stamped in the future, which is a clock problem and not an age.
        return None
    if seconds < 60:
        return f"{int(seconds)}s ago"
    if seconds < 3600:
        return f"{round(seconds / 60)}m ago"
    if seconds < 86400:
        return f"{round(seconds / 3600)}h ago"
    return f"{round(seconds / 86400)}d ago"


def _mttr_text(hours: object) -> str:
    """A mean time to resolve as text, from the old `formatHoursMTTR`.

    The None case is the one the JavaScript folded away: it printed the same
    em-dash for "no case closed in the last thirty days" as for a read that
    never came back. The first is a finding about a quiet month.
    """
    value = _number(hours)
    if value is None:
        return "no closures in 30d"
    if value < 1:
        return f"{round(value * 60)}m"
    if value < 24:
        return f"{int(value)}h {round((value % 1) * 60)}m"
    return f"{int(value // 24)}d {round(value % 24)}h"


def _spark_path(buckets: object) -> Optional[dict[str, str]]:
    """The sparkline's two path strings, or None when there is nothing to draw.

    None rather than a flat line for an empty or one-point histogram, which
    is the call the JavaScript also made: a flat line along the floor is a
    drawn zero, and the floor is where an unmeasured window would sit too.

    Every bucket has to carry a numeric count. `get_alerts_histogram`
    zero-fills its buckets with `extended_bounds` and returns an empty list on
    any failure, so a bucket without a count is a shape nobody produces, and
    substituting zero for it (which `b.count || 0` did) would draw a dip that
    no measurement supports.
    """
    if not isinstance(buckets, list) or len(buckets) < 2:
        return None
    counts: list[int | float] = []
    for bucket in buckets:
        value = _number(bucket.get("count")) if isinstance(bucket, dict) else None
        if value is None or value < 0:
            return None
        counts.append(value)

    peak = max(1, max(counts))
    span = SPARK_H - SPARK_PAD * 2 - SPARK_FLOOR
    step = (SPARK_W - SPARK_PAD * 2) / (len(counts) - 1)
    points = []
    for index, count in enumerate(counts):
        x = SPARK_PAD + index * step
        # Inverted so a higher count sits nearer the top of the viewBox.
        y = SPARK_H - SPARK_PAD - (count / peak) * span
        points.append(f"{'M' if index == 0 else 'L'}{x:.1f},{y:.1f}")
    line = " ".join(points)
    close = (
        f" L{SPARK_W - SPARK_PAD:.1f},{SPARK_H} L{SPARK_PAD:.1f},{SPARK_H} Z"
    )
    return {"line": line, "fill": line + close}


def _role_label(name: object) -> Optional[str]:
    """A role name as the switcher showed it, from the old `roleLabel`.

    None rather than the word "User" when there is no name: the JavaScript's
    fallback invented a role that nobody holds.
    """
    if name is None:
        return None
    text = str(name).replace("_", " ").strip()
    return " ".join(w[:1].upper() + w[1:] for w in text.split(" ")) or None


def _first_name(user: User) -> Optional[str]:
    """What to greet the viewer by, or None when the account carries neither.

    The JavaScript's `|| 'there'` put the word "there" where a name goes,
    which reads as a name on a page whose heading is "Welcome, there."
    """
    for candidate in (user.display_name, user.username):
        if candidate and str(candidate).strip():
            return str(candidate).strip().split(" ")[0]
    return None


def _alert_row(raw: object, now: datetime) -> Optional[dict[str, Any]]:
    """One alert as the feed needs it, or None when it is not a row.

    `severity` is carried through as the lowercased string the colour table
    in the template is keyed by, with None when the document has none, so an
    alert of unknown severity is not quietly filed as info.
    """
    if not isinstance(raw, dict):
        return None
    severity = plain(raw.get("severity"))
    severity = str(severity).strip().lower() if severity is not None else None
    when = _as_dt(raw.get("timestamp"))
    return {
        "id": raw.get("id"),
        "severity": severity,
        # The stored value, for the `ts` macro to judge. Elasticsearch stamps
        # an offset so this one is localisable in practice, but the macro is
        # the thing that decides that, not this module.
        "timestamp_raw": raw.get("timestamp"),
        # The JavaScript's `mitre_tactic_name || source || 'Alert'`.
        "tactic": raw.get("mitre_tactic_name") or raw.get("source") or "Alert",
        "technique": raw.get("mitre_technique_id"),
        "title": raw.get("title") or raw.get("message"),
        "host": raw.get("host"),
        "user": raw.get("user"),
        "rule_name": raw.get("rule_name"),
        "timestamp": when,
        "age_text": _age_text(when, now),
    }


def _viewer(user: User) -> dict[str, Any]:
    """What the welcome row shows about the caller.

    Built from the `get_current_user` dependency and nothing else, so it is
    available whether or not any store answered. The route computes it outside
    the try for that reason: the greeting and the roles held are not
    Elasticsearch's to lose, and a fragment claiming it could not read a role
    it is holding in its hand is the same dishonesty in the other direction.
    """
    focus = getattr(user, "_focus_role", None)
    focus_name = getattr(focus, "name", None)
    held = [r.name for r in (user.roles or ())]
    return {
        "name": _first_name(user),
        "roles": [
            {"label": _role_label(name), "active": name == focus_name}
            for name in held
            if _role_label(name) is not None
        ],
        # No role at all is its own state. The JavaScript rendered one pill
        # reading "User", which names a role ION does not define.
        "has_roles": bool(held),
    }


def _overview_view(payload: dict[str, Any]) -> dict[str, Any]:
    """The alert feed, the Elasticsearch state, the counts and the sparkline.

    `total_24h` is the sum of the histogram, not `total_alerts`. The latter is
    `len(alerts)` behind a `limit=10`, so it is a page of rows and never a
    total, and the tile above the feed claims to be a 24-hour count. The
    histogram is an aggregation over the same window in the same read, so it
    is the measurement that claim needs. It is None when the histogram is not
    usable, and the tile then says the total was not measured rather than
    reporting the row count as one.
    """
    state = _es_state(payload)
    rows = payload.get("alerts")
    rows = rows if isinstance(rows, list) else []
    now = _now()
    alerts = [r for r in (_alert_row(a, now) for a in rows[:ALERTS_SHOWN]) if r]

    live = state == ES_LIVE
    buckets = payload.get("alerts_histogram")
    spark = _spark_path(buckets) if live else None
    total_24h: Optional[int | float] = None
    if live and isinstance(buckets, list) and buckets:
        summed = [_number(b.get("count")) if isinstance(b, dict) else None
                  for b in buckets]
        if all(s is not None for s in summed):
            total_24h = sum(summed)

    counts = {
        "critical": _number(payload.get("critical_count")) if live else None,
        "high": _number(payload.get("high_count")) if live else None,
        "sampled": _number(payload.get("total_alerts")) if live else None,
    }
    if any(v is None for v in counts.values()):
        counts = {key: None for key in counts}

    return {
        "es_state": state,
        "cluster_name": payload.get("cluster_name"),
        "es_error": payload.get("error"),
        # Counts over the rows the read returned, which is all they ever were.
        # All three or none of them, so the hero line's `critical is not none`
        # is one gate over the whole sentence rather than three places a
        # missing figure could print the word "None" mid-prose.
        "critical": counts["critical"],
        "high": counts["high"],
        "sampled": counts["sampled"],
        "total_24h": total_24h,
        "alerts": alerts,
        "shown": len(alerts),
        "spark": spark,
    }


def _metrics_view(payload: dict[str, Any]) -> dict[str, Any]:
    """The mean-time-to-resolve and closure-rate tiles.

    Raw and text together for both figures. `_mttr_text(0)` is the string
    "0m" and a non-empty string is truthy, so a template gating on the text
    would survive being weakened to truthiness and its `is not none` would be
    decorative. The templates gate on the raw number and print the text.

    `bar_pct` is None when the rate is, so the progress bar is not drawn
    rather than drawn empty. The JavaScript left it at `w-[0%]`, which is a
    graphic zero for a measurement nobody took.
    """
    mttr = _number(payload.get("mttr_hours"))
    closure = _number(payload.get("closure_rate_7d"))
    return {
        "mttr_hours": mttr,
        "mttr_text": _mttr_text(payload.get("mttr_hours")),
        "closure_pct": closure,
        "closure_text": "—" if closure is None else str(round(closure)),
        # Rounded to a whole percent, which is the width a 1px-high bar can
        # express, and keeps the emitted declaration `width:42%` rather than
        # `width:42.0%`.
        "bar_pct": None if closure is None else round(max(0, min(100, closure))),
        # Why the rate can be absent, which is a finding rather than a gap.
        "created_7d": _number(payload.get("created_7d")),
    }


def _case_row(raw: dict[str, Any], now: datetime) -> dict[str, Any]:
    """One case as the panel's row.

    `plain` on both columns even though `_summary` already unwraps the status
    and `AlertCase.severity` is a `String`. Both feed a colour lookup and
    visible text at once, which is the pairing that makes an `SQLEnum` member
    survive a glance: value equality keeps the pill's colour right while the
    pill starts reading "AlertCaseStatus.OPEN".
    """
    severity = plain(raw.get("severity"))
    severity = str(severity).strip().lower() if severity is not None else None
    # The JavaScript's `updated_at || created_at`. A case that has never been
    # touched since it was raised still has a created_at, and the line says
    # "Updated", so without the fallback the oldest rows carried no date.
    # The raw value is kept beside the parsed one and is what the `ts` macro
    # is given: AlertCase stores both columns naive, so the macro has to see
    # the zoneless string to mark it as server time rather than be handed an
    # aware datetime claiming UTC.
    when_raw = raw.get("updated_at")
    when = _as_dt(when_raw)
    if when is None:
        when_raw = raw.get("created_at")
        when = _as_dt(when_raw)
    return {
        "id": raw.get("id"),
        # The JavaScript's `case_number || 'CASE-' + id`.
        "reference": raw.get("case_number") or (
            f"CASE-{raw['id']}" if raw.get("id") is not None else None
        ),
        "title": raw.get("title"),
        "severity": severity,
        "status": plain(raw.get("status")),
        # The stored value for the macro, and the parsed instant for ordering
        # and for the age. Two keys because they answer different questions
        # and one value cannot: sorting ISO strings compares text, which is
        # wrong the moment one row carries an offset and another does not.
        "updated_at": when_raw,
        "sort_at": when,
        "age_text": _age_text(when, now),
        "alert_count": _number(raw.get("alert_count")),
    }


def _cases_view(pages: list[dict[str, Any]]) -> dict[str, Any]:
    """My open cases, their exact count, and the severity breakdown.

    One page per status in MY_CASE_STATUSES, each already filtered to the
    caller by a WHERE clause, so `count` is the sum of the queries' own
    COUNTs rather than a length of whatever fitted in one page.

    The breakdown is computed over the rows that came back, so it is exact
    only while every matching row did. `breakdown_complete` says whether it
    did, and the template says so rather than showing part of a composition
    as if it were the whole one.
    """
    now = _now()
    count = sum(int(p.get("total") or 0) for p in pages)
    returned = sum(len(p.get("cases") or ()) for p in pages)
    rows: list[dict[str, Any]] = []
    for page in pages:
        for raw in page.get("cases") or ():
            if isinstance(raw, dict):
                rows.append(_case_row(raw, now))

    tally = {severity: 0 for severity in BREAKDOWN_SEVERITIES}
    for row in rows:
        if row["severity"] in tally:
            tally[row["severity"]] += 1

    # The denominator is the rows the breakdown was counted over, not the
    # total, so the bars are a composition of what was measured.
    scale = max(1, returned)
    bars = [
        {
            "severity": severity,
            "count": tally[severity],
            "width_px": max(
                BAR_MIN_PX, round(tally[severity] / scale * BAR_MAX_PX)
            ),
        }
        for severity in BREAKDOWN_SEVERITIES
        if tally[severity] > 0
    ]

    # Newest first by the instant, not by the text: "9h ago" and "10d ago" do
    # not compare as strings. A row with no readable date sorts last rather
    # than being dropped, because a case with no timestamp is still a case.
    dated = sorted(
        (r for r in rows if r["sort_at"] is not None),
        key=lambda r: r["sort_at"],
        reverse=True,
    )
    ordered = dated + [r for r in rows if r["sort_at"] is None]
    return {
        "count": count,
        "rows": ordered[:CASES_SHOWN],
        "bars": bars,
        "breakdown_complete": returned == count,
        "breakdown_over": returned,
        # None of the three listed severities present is not the same as no
        # cases at all, and the JavaScript said "all clear" for both.
        "any_cases": count > 0,
    }


def _handover_view(report: dict[str, Any], hours: int) -> dict[str, Any]:
    """The opened/closed/triaged strip and the shift's highlights.

    Every one of the three figures is None when the report did not carry it.
    `h.cases?.opened ?? 0` printed a zero for a missing key, and a shift
    reporting zero cases opened is a finding somebody acts on.
    """
    cases = report.get("cases")
    cases = cases if isinstance(cases, dict) else {}
    alerts = report.get("alerts")
    alerts = alerts if isinstance(alerts, dict) else {}
    highlights = report.get("highlights")
    highlights = highlights if isinstance(highlights, list) else []
    return {
        "hours": hours,
        "opened": _number(cases.get("opened")),
        "closed": _number(cases.get("closed")),
        "triaged": _number(alerts.get("total_triaged")),
        "highlights": [
            {
                "level": str(plain(h.get("level")) or "info"),
                "message": h.get("message"),
            }
            for h in highlights[:HIGHLIGHTS_SHOWN]
            if isinstance(h, dict) and h.get("message")
        ],
    }


def _render(request: Request, name: str, context: dict[str, Any]) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name=name, context=context)


@router.get("/dashboard-v2/overview", response_class=HTMLResponse)
async def dashboard_v2_overview_fragment(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    """The welcome row, the alert feed, the status pills and the alerts tile.

    Bare `get_current_user` and no named permission, because that is the gate
    GET /api/dashboard carries and a fragment must be neither softer nor
    stricter than the endpoint it mirrors. Confirmed off the live route
    rather than read off the decorator, and
    test_each_fragment_gate_matches_the_endpoint_it_mirrors reads both gates
    back off the live routes, so this cannot drift. The path is also listed in
    BARE_AUTH_FRAGMENTS, which is where the drop from a named permission has
    to be a claim somebody made on purpose rather than an omission.

    Worth saying out loud: /api/dashboard serves Elasticsearch alert
    documents under bare authentication while every other alert read in ION,
    GET /api/elasticsearch/alerts included, requires `alert:read`. Mirroring
    that is correct for this fragment and the discrepancy is not this
    conversion's to resolve. It is reported with the conversion.

    The user is resolved by the dependency, so the greeting and the roles
    cannot fail. Only the Elasticsearch read is inside the try, and a failure
    there leaves the welcome row intact and says the alerts could not be
    read. The JavaScript left the feed reading "Loading alerts…" for ever.
    """
    from ion.web.api import dashboard_elasticsearch_payload

    viewer = _viewer(current_user)
    try:
        view = _overview_view(await dashboard_elasticsearch_payload())
    except Exception:
        logger.exception("Dashboard overview could not be read")
        return _render(
            request,
            _OVERVIEW_FRAGMENT,
            {"failed": True, "view": None, "viewer": viewer},
        )
    return _render(
        request,
        _OVERVIEW_FRAGMENT,
        {"failed": False, "view": view, "viewer": viewer},
    )


@router.get("/dashboard-v2/team-metrics", response_class=HTMLResponse)
def dashboard_v2_team_metrics_fragment(
    request: Request,
    current_user: User = Depends(require_permission(ALERT_PERMISSION)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The mean-time-to-resolve and closure-rate tiles.

    Calls `team_metrics_payload`, which is now the whole body of GET
    /api/dashboard/team-metrics, so the two figures on the landing page are
    the ones the endpoint reports rather than a second computation of them.

    Synchronous, so FastAPI runs the whole body in one worker thread. The
    endpoint is `async def` and hands the same function to `asyncio.to_thread`
    for the same reason: eight-odd queries must not run on the event loop, and
    every statement touching the session must run in the one thread that has
    it open.
    """
    from ion.web.api import team_metrics_payload

    try:
        view = _metrics_view(team_metrics_payload(session))
    except Exception:
        logger.exception("Dashboard team metrics could not be read")
        return _render(request, _METRICS_FRAGMENT, {"failed": True, "view": None})
    return _render(request, _METRICS_FRAGMENT, {"failed": False, "view": view})


@router.get("/dashboard-v2/my-cases", response_class=HTMLResponse)
def dashboard_v2_my_cases_fragment(
    request: Request,
    current_user: User = Depends(require_permission(CASE_PERMISSION)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The caller's open cases, their count and the severity breakdown.

    Calls `case_query_service.list_cases_page`, which is the whole body of
    GET /api/cases, so the row shape and the filters have one definition. The
    arguments are the page's, not the endpoint's: `assigned_to_id` instead of
    filtering the caller's cases out of a hundred rows in the browser, and one
    call per non-closed status because the service filters on an exact status
    and the page means everything that is not closed.

    Synchronous for the reason the endpoint wraps its own call in a thread:
    the query and the serialisation both touch the session, so they have to
    run in the one thread that holds it.
    """
    from ion.services import case_query_service as cq

    try:
        view = _cases_view([
            cq.list_cases_page(
                session,
                status=status,
                assigned_to_id=current_user.id,
                sort="updated_at",
                order="desc",
            )
            for status in MY_CASE_STATUSES
        ])
    except Exception:
        logger.exception("Dashboard open cases could not be read")
        return _render(request, _CASES_FRAGMENT, {"failed": True, "view": None})
    return _render(request, _CASES_FRAGMENT, {"failed": False, "view": view})


@router.get("/dashboard-v2/handover", response_class=HTMLResponse)
def dashboard_v2_handover_fragment(
    request: Request,
    current_user: User = Depends(require_permission(ALERT_PERMISSION)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The shift's opened/closed/triaged strip and its highlights.

    Calls `generate_shift_report`, which is the whole body of GET
    /api/shift-handover/report, at the same 8-hour window the page has always
    fetched. The endpoint adds `generated_by` to the report and this does not,
    because nothing on this panel shows it.

    Synchronous like the endpoint it mirrors, which is also a plain `def`, so
    FastAPI runs both in a worker thread.
    """
    from ion.services.shift_handover_service import generate_shift_report

    try:
        view = _handover_view(
            generate_shift_report(session, hours=HANDOVER_HOURS), HANDOVER_HOURS
        )
    except Exception:
        logger.exception("Dashboard shift handover could not be read")
        return _render(
            request,
            _HANDOVER_FRAGMENT,
            {"failed": True, "view": None, "hours": HANDOVER_HOURS},
        )
    return _render(
        request,
        _HANDOVER_FRAGMENT,
        {"failed": False, "view": view, "hours": HANDOVER_HOURS},
    )
