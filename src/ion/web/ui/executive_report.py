"""The executive report, as two server-rendered fragments.

executive_report.html used to build its whole body with five `innerHTML`
writes fed by 188 lines of inline JavaScript: seven stat cards, a daily
trend chart, a closure-reason breakdown, a notable-incidents table and a
Team Performance table on the Summary tab, and an hourly activity chart
plus a nine-column per-analyst breakdown on the Team tab, with a
hand-rolled `esc()`. Two requests render all of it here, and Jinja escapes.

This page is a stakeholder brief. Its reader is above the SOC, acts on the
figures in a board pack and has no way to check them, which makes an
invented figure worse here than anywhere else in ION. So every number is
tested with `is not none`, no figure carries a `|| 0` or a `.get(k, 0)`
default, and a failed read says the figure could not be computed rather
than printing a zero or an empty chart. A metric measured at zero and a
metric nobody computed lead to opposite conclusions.

Six things the JavaScript collapsed and this does not:

  * `d.cases||{}` with `c.opened||0`, `c.closed||0`, `c.open_backlog||0`,
    `a.total_triaged||0` and `a.analysts_active||0`. A section the payload
    did not carry printed as five confident zeros and two dashes, which
    reads as a quiet week rather than as a read that did not happen. Every
    stat here is built from one table and carries its own measured flag.
  * A per-analyst FP rate of `0.0`, which analyst_efficiency_service emits
    when `tp + fp == 0`, printed as "0%". That made "made no
    threat/not-threat call" look identical to "made ten and got them all
    right". The payload still carries tp and fp, so the two are separable.
  * The Summary tab's FP Rate card, which is case_metrics'
    `fp_rate_of_closed`, shown under the same two words as the Team tab's
    dispositions-based rate with the explanatory note on the Team tab
    alone, and there only when the basis key read exactly "of_dispositions".
    Both cards now carry their denominator, and an absent basis is stated.
  * The reporting period, printed from the payload but never compared with
    the window the select asked for. The team lookback is clamped here into
    the range /api/analyst-efficiency/metrics accepts, so the two can
    genuinely differ, and period_view/team_window_view keep three states
    apart: the service measured what was asked, it measured something else,
    or it did not say.
  * Two bar charts floored at 2px per bar, so a day or an hour with nothing
    in it drew the same stub as one with a single case. A dead-quiet window
    read as a trickle of work. Zero is drawn at zero and said in words.
  * `AlertCase.status`, an SQLEnum column, which FastAPI serialised by
    value for the JSON endpoint and which a template renders as
    "AlertCaseStatus.CLOSED". Unwrapped with ui._shared.plain.

Nothing here is a second opinion about any figure. generate_executive_report
and get_analyst_efficiency decide every number, exactly as they do for
/api/executive-report/json and /api/analyst-efficiency/metrics. This module
only keeps apart the states those two already report and the view drops.

No `*_payload()` helper was extracted: both JSON routes are one line that
calls the service with the query parameter, so there is no inline query
logic, privacy scope or feature gate to share.

The `safe_url` filter has no site on this page. Neither payload carries a
stored URL: the only link is the PDF export, whose href the page builds
from its own constant and the day count. Said here rather than left as a
silent omission.
"""
from __future__ import annotations

import logging
from typing import Any, NamedTuple

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

SUMMARY_FRAGMENT = "_fragments/executive_report_summary.html"
TEAM_FRAGMENT = "_fragments/executive_report_team.html"

#: The tone of a figure nobody computed. Deliberately not among any spec's
#: bands or base tone: no value can select it, so it cannot be read as a
#: measurement, and the test asserts both directions.
UNMEASURED_TONE = "text-[var(--text-secondary)]"

#: The lookback /api/analyst-efficiency/metrics accepts (hours, ge=24 le=720).
#: The days select reaches 90, which is 2160 hours, so the conversion has to
#: clamp or it asks the service for a window its own API would reject.
TEAM_MIN_HOURS = 24
TEAM_MAX_HOURS = 720


class StatSpec(NamedTuple):
    """One stat card: where its figure lives and how it is presented.

    A table rather than seven hand-written cards, because the defect being
    removed was per-card: five of the seven carried a `|| 0` and two did
    not, and nothing in the JavaScript made that visible side by side. One
    spec list means one rule for what an absent figure does.
    """

    section: str
    key: str
    label: str
    unit: str
    #: What the figure is measured against, when that is not self-evident.
    #: Rendered on the card. Empty for a plain count.
    basis: str
    #: Lower bound and tone, highest first, compared with strict `>` because
    #: that is what the JavaScript used: exactly 50% is not critical.
    bands: tuple[tuple[float, str], ...]
    #: The tone of a measured figure that matched no band.
    base_tone: str


SUMMARY_STATS: tuple[StatSpec, ...] = (
    StatSpec("cases", "opened", "Cases Opened", "", "", (), "text-primary"),
    StatSpec("cases", "closed", "Cases Closed", "", "", (), "text-success"),
    StatSpec(
        "cases", "fp_rate", "FP Rate", "%",
        # The whole reason this page can show two different FP rates. See
        # services/case_metrics: this one dilutes with administrative
        # closures, the Team tab's excludes them, and they are not the same
        # number for the same window.
        "false positives as a share of all closures",
        ((50, "text-error"), (30, "text-warning")), "text-primary",
    ),
    StatSpec(
        "cases", "avg_mttr", "Avg MTTR", "h",
        "mean time from case creation to closure, over cases closed in the "
        "window", (), "text-primary",
    ),
    StatSpec(
        "cases", "open_backlog", "Open Backlog", "",
        # case_metrics computes this without the window on purpose.
        "every case not closed, at the moment of reading, not just this "
        "window", ((20, "text-warning"),), "text-primary",
    ),
    StatSpec("alerts", "total_triaged", "Alerts Triaged", "", "", (), "text-primary"),
    StatSpec("alerts", "analysts_active", "Analysts Active", "", "", (), "text-primary"),
)

#: Closure-reason key to the colour the breakdown paints its count in,
#: lifted from the JavaScript. Any other reason is neutral: a disposition
#: this page does not rank must not borrow a colour that ranks it.
CLOSURE_COLOURS: dict[str, str] = {
    "true_positive": "var(--mitre-covered)",
    "false_positive": "var(--sev-critical)",
}

#: case_metrics maps a NULL closure_reason to this key. The JavaScript's
#: `replace(/_/g,' ')` turned it into "Unspecified", which sits in the list
#: looking like a disposition somebody chose rather than the absence of one.
UNSPECIFIED_REASON = "unspecified"
UNSPECIFIED_LABEL = "closed with no reason recorded"

#: Severity to its badge, from erSevBadge. `badge-ghost` is the fallback and
#: also what a severity the row does not record gets, because an unrecorded
#: severity must not borrow a severity colour.
SEVERITY_BADGES: dict[str, str] = {
    "critical": "badge-error",
    "high": "badge-warning",
    "medium": "badge-info",
    "low": "badge-success",
}
UNKNOWN_SEVERITY_BADGE = "badge-ghost"

#: What each FP-rate denominator means, in the page's words. Keyed by
#: analyst_efficiency_service's own `fp_rate_basis`. A basis absent from
#: this table returns None and the fragment says the denominator was not
#: stated, rather than dropping the note the way the JavaScript did.
FP_BASIS_NOTES: dict[str, str] = {
    "of_dispositions": (
        "FP Rate here is measured against true-positive and false-positive "
        "dispositions only, so administrative closures such as duplicate or "
        "not applicable are excluded. The Summary tab measures it against "
        "all closures, which reads lower for the same window."
    ),
    "of_closed": (
        "FP Rate here is measured against all closures, which is the same "
        "denominator the Summary tab uses."
    ),
}


def stat_tone(spec: StatSpec, value: object) -> str:
    """The tone a stat is painted in, total over None.

    Returning a tone for None rather than making the template guard is the
    point: there is no branch here to forget, and the JavaScript's
    `c.fp_rate>50?'crit':c.fp_rate>30?'warn':''` fell through to the
    default for null, so an unmeasured false-positive rate was painted the
    same colour as a healthy one.
    """
    if value is None:
        return UNMEASURED_TONE
    for floor, tone in spec.bands:
        if value > floor:
            return tone
    return spec.base_tone


def stat_views(report: dict[str, Any]) -> list[dict[str, Any]]:
    """The seven stat cards, each knowing whether its figure was measured.

    A section the payload does not carry makes every figure in it
    unmeasured. That is the `d.cases||{}` defect: an absent section is not
    a section of zeros, and on this page the difference is the difference
    between a quiet week and a database that did not answer.
    """
    views: list[dict[str, Any]] = []
    for spec in SUMMARY_STATS:
        section = report.get(spec.section)
        value = section.get(spec.key) if isinstance(section, dict) else None
        views.append({
            "label": spec.label,
            "value": None if value is None else f"{value}{spec.unit}",
            "measured": value is not None,
            "tone": stat_tone(spec, value),
            "basis": spec.basis,
        })
    return views


def period_view(report: dict[str, Any], requested_days: int) -> dict[str, Any]:
    """The window the figures actually cover, against the one asked for.

    Three states, kept apart because they are three different things to a
    reader: the service measured the window the select asked for, it
    measured a different one, or it did not say which one it measured. The
    JavaScript printed `d.period_days` and compared nothing, so a service
    that clamped or rounded the window would have been invisible.
    """
    measured = report.get("period_days")
    return {
        "start": report.get("period_start"),
        "end": report.get("period_end"),
        "generated_at": report.get("generated_at"),
        "days": measured,
        "requested_days": requested_days,
        "stated": measured is not None,
        "matches": measured == requested_days,
    }


def trend_view(report: dict[str, Any]) -> dict[str, Any]:
    """The daily trend bars, with a real zero drawn at zero.

    The JavaScript floored every bar at 2px, so a day with nothing drew the
    same stub as a day with one case and a dead-quiet window looked like a
    trickle of work. `_compute_trends` always returns one bucket per day,
    which also made its `if(daily.length)` guard always true, so nothing on
    the page ever said a window was empty.

    `peak` is the denominator the bars are scaled against. It is None when
    no bucket could be read at all and 0 when every bucket read zero, and
    those render differently.
    """
    trends = report.get("trends")
    daily = trends.get("daily") if isinstance(trends, dict) else None
    if not isinstance(daily, list):
        return {"rows": [], "peak": None, "measured": False,
                "any_activity": False}

    rows: list[dict[str, Any]] = []
    for day in daily:
        opened = day.get("opened") if isinstance(day, dict) else None
        closed = day.get("closed") if isinstance(day, dict) else None
        rows.append({
            "date": day.get("date") if isinstance(day, dict) else None,
            "opened": opened,
            "closed": closed,
            "measured": opened is not None and closed is not None,
        })

    peak = max(
        (max(r["opened"], r["closed"]) for r in rows if r["measured"]),
        default=None,
    )
    for row in rows:
        if not row["measured"]:
            row["opened_pct"] = None
            row["closed_pct"] = None
        elif peak > 0:
            row["opened_pct"] = round(row["opened"] / peak * 100, 1)
            row["closed_pct"] = round(row["closed"] / peak * 100, 1)
        else:
            row["opened_pct"] = 0
            row["closed_pct"] = 0

    return {
        "rows": rows,
        "peak": peak,
        "measured": peak is not None,
        "any_activity": peak is not None and peak > 0,
    }


def closure_views(report: dict[str, Any]) -> list[dict[str, Any]]:
    """The closure-reason breakdown, largest share first."""
    cases = report.get("cases")
    reasons = cases.get("closure_reasons") if isinstance(cases, dict) else None
    if not isinstance(reasons, dict) or not reasons:
        return []

    counted = {k: v for k, v in reasons.items() if v is not None}
    total = sum(counted.values())
    views: list[dict[str, Any]] = []
    for reason, count in sorted(counted.items(), key=lambda kv: -kv[1]):
        views.append({
            "reason": (UNSPECIFIED_LABEL if reason == UNSPECIFIED_REASON
                       else str(reason).replace("_", " ")),
            "count": count,
            # A share of nothing is not 0%. Unreachable with real counts,
            # which are all at least 1, so this is a guard rather than a fix.
            "pct": round(count / total * 100) if total > 0 else None,
            "colour": CLOSURE_COLOURS.get(reason, "var(--text-secondary)"),
        })
    return views


def incident_views(report: dict[str, Any]) -> list[dict[str, Any]]:
    """The notable incidents table.

    `status` goes through `plain`: AlertCase.status is
    SQLEnum(AlertCaseStatus), so the row carries the member and a template
    renders "AlertCaseStatus.CLOSED". `severity` is a plain nullable String
    and needs no unwrapping, but it does need a badge that cannot colour an
    unrecorded severity as though it were a measured one.
    """
    views: list[dict[str, Any]] = []
    for incident in report.get("notable_incidents") or []:
        severity = plain(incident.get("severity"))
        key = str(severity).lower() if severity is not None else None
        views.append({
            "case_number": incident.get("case_number"),
            "title": incident.get("title"),
            "severity": severity,
            "badge": SEVERITY_BADGES.get(key, UNKNOWN_SEVERITY_BADGE),
            "status": plain(incident.get("status")),
            "created_at": incident.get("created_at"),
        })
    return views


def summary_team_views(report: dict[str, Any]) -> list[dict[str, Any]]:
    """The Summary tab's three-column Team Performance rows.

    `_team_metrics` keeps only analysts whose `total_actions > 0`, so this
    table is the active-in-the-audit-log subset of the team and not the
    team. The fragment says so: an analyst who closed cases and wrote
    nothing to the audit log is absent, and their closures with them.
    """
    team = report.get("team")
    analysts = team.get("analysts") if isinstance(team, dict) else None
    return [
        {
            "username": analyst.get("username"),
            "cases_closed": analyst.get("cases_closed"),
            "total_actions": analyst.get("total_actions"),
        }
        for analyst in (analysts or [])
    ]


def team_hours(days: int) -> int:
    """The days select, as a lookback /api/analyst-efficiency/metrics takes.

    That endpoint declares `hours` as ge=24 le=720 and the exec report's
    days parameter reaches 90, which is 2160 hours. Clamping here rather
    than passing it through is what keeps the fragment from asking the
    service for a window its own API would answer with a 422, and the
    clamp is visible to the reader because the window the fragment prints
    comes from the payload rather than from this call.
    """
    return max(TEAM_MIN_HOURS, min(TEAM_MAX_HOURS, days * 24))


def team_window_view(
    metrics: dict[str, Any], requested_hours: int
) -> dict[str, Any]:
    """The lookback the service measured, against the one asked for.

    Same three states as period_view, and here they are reachable: 90 days
    asks for 2160 hours and gets 720.
    """
    measured = metrics.get("period_hours")
    return {
        "hours": measured,
        "requested_hours": requested_hours,
        "stated": measured is not None,
        "matches": measured == requested_hours,
    }


def hourly_views(metrics: dict[str, Any]) -> dict[str, Any]:
    """The 24-hour activity bars.

    `_hourly_activity` ignores the lookback entirely and always reads the
    last 24 hours, so this chart and the table beside it cover different
    windows. The JavaScript labelled this one and not the table.

    An hour missing either count is unmeasured, not quiet: the JavaScript's
    `(h.cases_closed||0) + (h.alerts_triaged||0)` turned an absent count
    into a measured zero in a chart whose whole job is showing when work
    happened.
    """
    hourly = metrics.get("hourly_activity")
    if not isinstance(hourly, list):
        return {"rows": [], "peak": None, "measured": False,
                "any_activity": False}

    rows: list[dict[str, Any]] = []
    for hour in hourly:
        closed = hour.get("cases_closed") if isinstance(hour, dict) else None
        triaged = hour.get("alerts_triaged") if isinstance(hour, dict) else None
        measured = closed is not None and triaged is not None
        rows.append({
            "hour": hour.get("hour") if isinstance(hour, dict) else None,
            "closed": closed,
            "triaged": triaged,
            "total": (closed + triaged) if measured else None,
            "measured": measured,
        })

    peak = max((r["total"] for r in rows if r["measured"]), default=None)
    for row in rows:
        if not row["measured"]:
            row["pct"] = None
        elif peak > 0:
            row["pct"] = round(row["total"] / peak * 100, 1)
        else:
            row["pct"] = 0

    return {
        "rows": rows,
        "peak": peak,
        "measured": peak is not None,
        "any_activity": peak is not None and peak > 0,
    }


def analyst_views(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    """The nine-column per-analyst breakdown.

    `fp_measured` is the figure this page most needed and did not have.
    analyst_efficiency_service emits `fp_rate: 0.0` when `tp + fp == 0`,
    which is not a measurement of zero: the analyst made no
    threat/not-threat call at all. The JavaScript printed `a.fp_rate + '%'`
    unconditionally, so "0%" meant either a flawless record or no record,
    and to a reader above the SOC those two read the same and mean opposite
    things. tp and fp are both in the payload, so the denominator is
    recoverable without recomputing anything.
    """
    views: list[dict[str, Any]] = []
    for analyst in metrics.get("analysts") or []:
        true_positives = analyst.get("true_positives")
        false_positives = analyst.get("false_positives")
        dispositions = (
            true_positives + false_positives
            if true_positives is not None and false_positives is not None
            else None
        )
        fp_rate = analyst.get("fp_rate")
        views.append({
            "username": analyst.get("username"),
            "cases_closed": analyst.get("cases_closed"),
            "cases_opened": analyst.get("cases_opened"),
            "alerts_triaged": analyst.get("alerts_triaged"),
            "true_positives": true_positives,
            "false_positives": false_positives,
            "dispositions": dispositions,
            "fp_rate": fp_rate,
            "fp_measured": (
                dispositions is not None
                and dispositions > 0
                and fp_rate is not None
            ),
            "avg_mttr": analyst.get("avg_mttr_hours"),
            "total_actions": analyst.get("total_actions"),
        })
    return views


def fp_basis_note(metrics: dict[str, Any]) -> str | None:
    """What the per-analyst FP rate is measured against, in words.

    None when the payload names no basis or names one this page does not
    recognise, and the fragment says so. The JavaScript rendered its note
    only when the basis read exactly "of_dispositions", so a payload that
    stopped emitting the key dropped the explanation silently and left two
    different rates on two tabs under one heading.
    """
    summary = metrics.get("team_summary")
    basis = summary.get("fp_rate_basis") if isinstance(summary, dict) else None
    return FP_BASIS_NOTES.get(basis)  # type: ignore[arg-type]


@router.get(
    "/executive-report/summary",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("alert:read"))],
)
def executive_report_summary_fragment(
    request: Request,
    days: int = Query(7, ge=1, le=90),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The Summary tab's whole body, as one fragment.

    It calls generate_executive_report, the function
    /api/executive-report/json calls, with the same `days` bounds, so the
    page and the API cannot disagree about any figure. `alert:read` matches
    that endpoint exactly; a fragment must not be a softer way in than the
    API it mirrors.
    """
    from ion.services.executive_report_service import generate_executive_report

    try:
        report = generate_executive_report(session, days=days)
    except Exception:
        logger.exception(
            "Executive report summary fragment could not be rendered "
            "(days=%s)", days,
        )
        # A failed read is not a report of zeros. Every figure is dropped
        # rather than defaulted, because a board pack reader cannot tell a
        # printed zero from a read that did not happen, and the two lead to
        # opposite conclusions.
        return templates.TemplateResponse(
            request=request,
            name=SUMMARY_FRAGMENT,
            context={"failed": True, "requested_days": days, "period": None,
                     "stats": [], "trend": None, "closures": [],
                     "incidents": [], "team": []},
        )

    return templates.TemplateResponse(
        request=request,
        name=SUMMARY_FRAGMENT,
        context={
            "failed": False,
            "requested_days": days,
            "period": period_view(report, days),
            "stats": stat_views(report),
            "trend": trend_view(report),
            "closures": closure_views(report),
            "incidents": incident_views(report),
            "team": summary_team_views(report),
        },
    )


@router.get(
    "/executive-report/team",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("alert:read"))],
)
def executive_report_team_fragment(
    request: Request,
    days: int = Query(7, ge=1, le=90),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The Team tab's whole body, as one fragment.

    It calls get_analyst_efficiency, the function
    /api/analyst-efficiency/metrics calls, so this tab and that endpoint
    cannot disagree. `alert:read` matches it exactly.

    It takes `days` rather than `hours` so the page has one control for
    both tabs, which is what the JavaScript did with
    `parseInt(days) * 24`. The conversion to hours is clamped to the range
    that endpoint accepts, and the window the fragment prints comes from
    the payload, so a clamp is visible to the reader rather than silent.
    """
    from ion.services.analyst_efficiency_service import get_analyst_efficiency

    hours = team_hours(days)
    try:
        metrics = get_analyst_efficiency(session, hours=hours)
    except Exception:
        logger.exception(
            "Executive report team fragment could not be rendered "
            "(days=%s, hours=%s)", days, hours,
        )
        return templates.TemplateResponse(
            request=request,
            name=TEAM_FRAGMENT,
            context={"failed": True, "window": None, "hourly": None,
                     "analysts": [], "fp_basis": None},
        )

    return templates.TemplateResponse(
        request=request,
        name=TEAM_FRAGMENT,
        context={
            "failed": False,
            "window": team_window_view(metrics, hours),
            "hourly": hourly_views(metrics),
            "analysts": analyst_views(metrics),
            "fp_basis": fp_basis_note(metrics),
        },
    )
