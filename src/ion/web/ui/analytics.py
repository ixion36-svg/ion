"""Analytics: the job panels.

analytics.html draws eleven panels from one read. `GET /api/analytics/jobs`
returns every analytics job with its last stored result, and a
`renderX(job)` function turns each one into a table.

All eleven opened with the same line:

    if (!job || !job.result) { container.innerHTML =
        '<div class="empty-state">No data yet. Click "Run All Jobs" to
        generate.</div>'; return; }

which is three different situations wearing one sentence. The job type is
not registered at all; the job is registered and has never run; and the job
has run and stored a result this page cannot read. Only the second is
answered by clicking Run All Jobs.

Then each one collapsed the next outcome in the same way, `job.result.rules
|| []`, `|| offenders`, `|| entities`, `|| stale_cases`, and rendered a
reassurance for it. "No stale investigations found. All items have recent
activity" is a sentence an analyst stops reading on, and a payload we could
not parse produced it.

Smaller things the same read turned up:

  * `c.severity || 'medium'` paints an alert whose severity is missing as
    medium, in a severity badge.
  * `c.days_stale > 7 ? 'danger' : 'warn'` is false for undefined, so a
    case with no staleness figure was painted as the milder state and then
    labelled "undefinedd".
  * `timeAgo(iso)` is `Date.now() - new Date(iso).getTime()` over
    isoformat() of a naive UTC column, so every elapsed time on the page
    was out by the viewer's offset. Sixth page with that one, and the first
    where it skews a duration rather than a timestamp.

Permissions. Every analytics endpoint is bare authentication, with no named
permission, while the page route is gated on `alert:read` (server.py:1303).
So these fragments take the page's permission: stricter than the endpoint,
never softer. The two mutations in that module, PATCH /jobs/{job_type} and
POST /jobs/{job_type}/run, are bare auth as well, which means any
authenticated account can disable an analytics job or change its schedule.
That is an authorisation gap rather than a rendering one and is filed
separately; nothing here widens or narrows it.
"""
from __future__ import annotations

import logging
from typing import Any, Optional, TypedDict

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.analytics import AnalyticsJobType
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import age_label, instant_label, plain, render_view

logger = logging.getLogger(__name__)

router = APIRouter()

#: What the page route requires. The endpoints require only a session.
PERMISSION = "alert:read"

#: The severities the badge has a colour for. One outside this set keeps
#: its own text under `unknown`, where the page painted it as medium.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")

#: Days stale at which the figure is drawn as urgent rather than a warning.
#: From `c.days_stale > 7 ? 'danger' : 'warn'`.
STALE_DANGER_DAYS = 7


class JobState(TypedDict):
    """What happened to one analytics job, in the four answers it has.

    "missing"    no job of this type is registered
    "never_run"  registered, never run, so Run All Jobs is the answer
    "unreadable" it ran and stored something this page cannot read
    "ok"         it ran and the result is readable
    """

    state: str
    job_type: Optional[str]
    display_name: Optional[str]
    last_run: Optional[str]
    last_run_age: Optional[str]
    last_error: Optional[str]


def job_state(job: Any) -> JobState:
    """The job's own condition, separately from whatever it produced."""
    if not isinstance(job, dict):
        return {"state": "missing", "job_type": None, "display_name": None,
                "last_run": None, "last_run_age": None, "last_error": None}
    job_type = plain(job.get("job_type"))
    name = plain(job.get("display_name"))
    error = plain(job.get("last_error"))
    result = job.get("result")
    if result is None:
        state = "never_run"
    elif isinstance(result, dict):
        state = "ok"
    else:
        state = "unreadable"
    return {
        "state": state,
        "job_type": str(job_type) if job_type is not None else None,
        "display_name": str(name) if name is not None else None,
        "last_run": instant_label(job.get("last_run_at")),
        "last_run_age": age_label(job.get("last_run_at")),
        "last_error": str(error) if error else None,
    }


def result_rows(job: Any, key: str) -> Optional[list]:
    """The list under `key` of a job's result, or None when we cannot read
    it.

    None is the outcome every panel was missing. `job.result.rules || []`
    turned a result of the wrong shape into an empty list, and each panel
    then rendered a sentence saying there was nothing to report.
    """
    if not isinstance(job, dict):
        return None
    result = job.get("result")
    if not isinstance(result, dict):
        return None
    rows = result.get(key)
    if not isinstance(rows, list):
        return None
    return rows


def severity_key(value: Any) -> str:
    """The stylesheet's key for a severity, or `unknown`.

    `c.severity || 'medium'` put an alert with no severity in the middle of
    the scale, which is a claim about how urgent it is.
    """
    marking = plain(value)
    if marking is None or str(marking) == "":
        return "unknown"
    text = str(marking)
    return text if text in SEVERITIES else "unknown"


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _text(value: Any) -> Optional[str]:
    plainest = plain(value)
    return str(plainest) if plainest is not None else None


class StaleRow(TypedDict):
    """One stale case or alert.

    `days` is None when the figure is missing, where the page printed
    "undefinedd" and painted the row as the milder of its two states.
    """

    reference: Optional[str]
    title: Optional[str]
    severity_key: str
    severity_label: Optional[str]
    assigned: Optional[str]
    last_activity: Optional[str]
    days: Optional[int]
    urgent: Optional[bool]


class StaleView(TypedDict):
    job: JobState
    cases: Optional[list[StaleRow]]
    alerts: Optional[list[StaleRow]]


def stale_row(raw: Any, *, reference_key: str) -> Optional[StaleRow]:
    if not isinstance(raw, dict):
        return None
    days = _int(raw.get("days_stale"))
    severity = raw.get("severity")
    assigned = _text(raw.get("assigned_to"))
    return {
        "reference": _text(raw.get(reference_key)),
        "title": _text(raw.get("title")),
        "severity_key": severity_key(severity),
        "severity_label": _text(severity),
        # "Unassigned" is a fact about the row; a missing field is not.
        "assigned": assigned if assigned is not None else None,
        "last_activity": age_label(raw.get("last_activity")),
        "days": days,
        # None rather than False: `days > 7` was false for undefined, so a
        # row with no figure was drawn as the milder state.
        "urgent": None if days is None else days > STALE_DANGER_DAYS,
    }


def stale_view(job: Any) -> StaleView:
    cases = result_rows(job, "stale_cases")
    alerts = result_rows(job, "stale_alerts")
    return {
        "job": job_state(job),
        "cases": (None if cases is None else
                  [r for r in (stale_row(c, reference_key="case_number")
                               for c in cases) if r is not None]),
        "alerts": (None if alerts is None else
                   [r for r in (stale_row(a, reference_key="alert_id")
                                for a in alerts) if r is not None]),
    }


def _one_job(job_type: str, current_user: User, session: Session) -> Any:
    """One job and its stored result, from the endpoint's own handler.

    The page read every job in one request and handed each panel its own.
    A panel asking for its own job is the same data, and it lets a panel
    whose job is missing or unreadable say so without the other ten
    inheriting it.

    The handler raises 404 for a job type that is not registered, which is
    the `missing` state rather than an error: job_state(None) answers it.
    """
    from fastapi import HTTPException

    from ion.web.analytics_api import get_analytics_job

    try:
        return get_analytics_job(
            job_type, current_user=current_user, session=session)
    except HTTPException as refusal:
        if refusal.status_code == 404:
            return None
        raise


@router.get(
    "/analytics/stale",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def analytics_stale_fragment(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The stale investigations panel."""
    try:
        job = _one_job(
            AnalyticsJobType.STALE_INVESTIGATIONS.value, current_user, session)
    except Exception:
        logger.exception("Analytics stale fragment could not read its job")
        job = None
    return render_view(request, "_fragments/analytics_stale.html",
                       stale_view(job))


# ---------------------------------------------------------------------------
# Rule noise, repeat offenders, entity risk
# ---------------------------------------------------------------------------
#
# Three panels sharing the foundation above, and sharing one more defect
# between two of them: a missing figure falls through a chain of
# comparisons to the *most reassuring* end of the scale.
#
#   * `r.fp_ratio > 0.5 ? 'fp-high' : r.fp_ratio > 0.2 ? 'fp-med' :
#     'fp-low'`. Both comparisons are false for undefined, so a rule whose
#     false-positive ratio was missing was painted as a low-FP rule, which
#     is the one colour that says "leave this one alone".
#   * `e.risk_score >= 100 ? 'critical' : ... : 'low'`, the same shape, so
#     an entity with no risk score was drawn as low risk.
#
# And one that erases a whole panel rather than one row:
#
#   * `Math.max(...rules.map(r => r.alert_count), 1)`. One alert_count that
#     is not a number makes the maximum NaN, every percentage NaN, and
#     every bar width the string "NaN%", so the chart renders as nothing.
#     The same spread-into-Math.max appeared on the discover histogram.
#   * `entities[0]?.risk_score || 1` takes the scale from the first row, so
#     a first row with no score silently rescaled every bar to 100%.
#
# Smaller: `${o.count_7d}` and five more figures printed "undefined";
# `(o.rules || []).length` reported "0 rules" for a list that was missing
# rather than empty; and `<span class="entity-type-badge ${o.type}">` put a
# server value into a class attribute unescaped.
#
# The bars use `data-ion-style`, ION's dynamic-style hook, rather than the
# page's own `data-pct` plus an applyBarWidths() pass. The hook is applied
# by static/js/ion-dynamic-styles.js on a MutationObserver, so it lands
# after an htmx swap without the fragment having to ask.

RULE_NOISE_FRAGMENT = "_fragments/analytics_rule_noise.html"
OFFENDERS_FRAGMENT = "_fragments/analytics_offenders.html"
ENTITY_RISK_FRAGMENT = "_fragments/analytics_entity_risk.html"

#: False-positive ratio bands, from the page's own ternary chain.
FP_HIGH = 0.5
FP_MEDIUM = 0.2

#: Risk score bands, from the page's own chain.
RISK_BANDS: tuple[tuple[int, str], ...] = (
    (100, "critical"), (50, "high"), (20, "medium"), (0, "low"),
)

#: How many rule names a row lists before the rest go in the tooltip.
RULES_SHOWN = 2


def _num(value: Any) -> Optional[float]:
    """A real number, or None. bool is excluded: True is 1 in Python and a
    ratio of 1.0 is not what a boolean means."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value != value or value in (float("inf"), float("-inf")):
        return None
    return float(value)


def _names(value: Any) -> Optional[list[str]]:
    """A list of names, or None when the payload did not carry one.

    `(o.rules || []).length` reported "0 rules" for a missing list, which
    is a count of a thing we were not told about.
    """
    if not isinstance(value, list):
        return None
    return [str(v) for v in value]


def scale(values: list[Optional[float]]) -> Optional[float]:
    """The largest readable value, or None when none of them is readable.

    `Math.max(...xs)` over a list containing one non-number is NaN, and
    every percentage derived from it is NaN, so the whole chart vanishes.
    """
    readable = [v for v in values if v is not None]
    if not readable:
        return None
    top = max(readable)
    return top if top > 0 else None


class NoiseRow(TypedDict):
    """One rule. `fp_band` is None when the ratio is missing, so the
    template can draw it as unmeasured rather than as a low-FP rule."""

    name: Optional[str]
    alerts: Optional[int]
    width: Optional[float]
    fp_ratio_pct: Optional[int]
    fp_band: Optional[str]


class NoiseView(TypedDict):
    job: JobState
    rules: Optional[list[NoiseRow]]


def fp_band(ratio: Optional[float]) -> Optional[str]:
    if ratio is None:
        return None
    if ratio > FP_HIGH:
        return "fp-high"
    if ratio > FP_MEDIUM:
        return "fp-med"
    return "fp-low"


def noise_view(job: Any) -> NoiseView:
    rows = result_rows(job, "rules")
    if rows is None:
        return {"job": job_state(job), "rules": None}
    readable = [r for r in rows if isinstance(r, dict)]
    top = scale([_num(r.get("alert_count")) for r in readable])
    out: list[NoiseRow] = []
    for raw in readable:
        alerts = _num(raw.get("alert_count"))
        ratio = _num(raw.get("fp_ratio"))
        out.append({
            "name": _text(raw.get("rule_name")),
            "alerts": _int(raw.get("alert_count")),
            "width": (round(alerts / top * 100, 2)
                      if alerts is not None and top else None),
            "fp_ratio_pct": None if ratio is None else int(round(ratio * 100)),
            "fp_band": fp_band(ratio),
        })
    return {"job": job_state(job), "rules": out}


class OffenderRow(TypedDict):
    entity: Optional[str]
    kind: Optional[str]
    kind_key: str
    count_7d: Optional[int]
    count_30d: Optional[int]
    severity_key: str
    severity_label: Optional[str]
    rules: Optional[list[str]]


class OffendersView(TypedDict):
    job: JobState
    offenders: Optional[list[OffenderRow]]


def entity_kind(value: Any) -> tuple[str, Optional[str]]:
    """The class suffix and the words for an entity type.

    `<span class="entity-type-badge ${o.type}">` put the value straight
    into a class attribute. A type carrying a space becomes two classes and
    one carrying a quote ends the attribute, so the key is restricted to
    what a class can safely be and the words are rendered as text.
    """
    text = _text(value)
    if text is None or text == "":
        return "unknown", None
    safe = text if text.replace("_", "").replace("-", "").isalnum() else None
    return (safe or "unknown"), text


def offenders_view(job: Any) -> OffendersView:
    rows = result_rows(job, "offenders")
    if rows is None:
        return {"job": job_state(job), "offenders": None}
    out: list[OffenderRow] = []
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        key, label = entity_kind(raw.get("type"))
        severity = raw.get("top_severity")
        out.append({
            "entity": _text(raw.get("entity")),
            "kind": label,
            "kind_key": key,
            "count_7d": _int(raw.get("count_7d")),
            "count_30d": _int(raw.get("count_30d")),
            "severity_key": severity_key(severity),
            "severity_label": _text(severity),
            "rules": _names(raw.get("rules")),
        })
    return {"job": job_state(job), "offenders": out}


class RiskRow(TypedDict):
    """`band` is None for an entity with no readable score, where the
    page's chain of >= comparisons made it low risk."""

    entity: Optional[str]
    kind: Optional[str]
    kind_key: str
    score: Optional[int]
    width: Optional[float]
    band: Optional[str]
    alerts: Optional[int]
    open_cases: Optional[int]
    rules: Optional[list[str]]


class RiskView(TypedDict):
    job: JobState
    entities: Optional[list[RiskRow]]


def risk_band(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    for threshold, name in RISK_BANDS:
        if score >= threshold:
            return name
    return "low"


def risk_view(job: Any) -> RiskView:
    rows = result_rows(job, "entities")
    if rows is None:
        return {"job": job_state(job), "entities": None}
    readable = [r for r in rows if isinstance(r, dict)]
    # The page took the scale from entities[0], so a first row without a
    # score rescaled every bar. The largest readable score is the scale.
    top = scale([_num(r.get("risk_score")) for r in readable])
    out: list[RiskRow] = []
    for raw in readable:
        score = _num(raw.get("risk_score"))
        key, label = entity_kind(raw.get("type"))
        out.append({
            "entity": _text(raw.get("entity")),
            "kind": label,
            "kind_key": key,
            "score": _int(raw.get("risk_score")),
            "width": (min(100.0, round(score / top * 100, 2))
                      if score is not None and top else None),
            "band": risk_band(score),
            "alerts": _int(raw.get("alert_count")),
            "open_cases": _int(raw.get("open_cases")),
            "rules": _names(raw.get("rules")),
        })
    return {"job": job_state(job), "entities": out}


def _panel(job_type: str, fragment: str, build):
    """One panel route. The three differ only in job type and view."""

    def handler(
        request: Request,
        current_user: User = Depends(get_current_user),
        session: Session = Depends(get_db_session),
    ) -> Response:
        try:
            job = _one_job(job_type, current_user, session)
        except Exception:
            logger.exception(
                "Analytics fragment could not read the %s job", job_type)
            job = None
        return render_view(request, fragment, build(job))

    return handler


router.add_api_route(
    "/analytics/rule-noise",
    _panel(AnalyticsJobType.RULE_NOISE.value, RULE_NOISE_FRAGMENT,
           noise_view),
    methods=["GET"], response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))])

router.add_api_route(
    "/analytics/repeat-offenders",
    _panel(AnalyticsJobType.REPEAT_OFFENDERS.value, OFFENDERS_FRAGMENT,
           offenders_view),
    methods=["GET"], response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))])

router.add_api_route(
    "/analytics/entity-risk",
    _panel(AnalyticsJobType.ENTITY_RISK_SCORE.value, ENTITY_RISK_FRAGMENT,
           risk_view),
    methods=["GET"], response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))])


# ---------------------------------------------------------------------------
# Case metrics and observable velocity
# ---------------------------------------------------------------------------
#
# The last two job panels, and the last of the same handful of defects:
#
#   * `r.total_cases || 0`, `r.open_cases || 0`, `r.closed_cases || 0`.
#     Three confident zeros for figures the job did not record, on the
#     cards an analyst reads first.
#   * `Math.max(...trend.map(d => d.count), 1)` twice, so one unreadable
#     day flattened a whole sparkline.
#   * `Object.values(reasons).reduce((a, b) => a + b, 0) || 1`. One
#     non-numeric value makes the sum NaN, `|| 1` turns that into 1, and
#     every percentage is then the count itself times 100.
#   * `s.days_stale > 21 ? 'danger' : 'warn'`, the fall-through again, so
#     an indicator with no staleness figure was drawn as the milder state
#     and labelled "undefinedd".
#   * `severity-${s.threat_level}` and `cl-${reason}` put server values
#     into class attributes, and `<span class="entity-type-badge host">`
#     hard-coded `host` as the class whatever the type actually was.
#   * `title="${d.date}: ${d.count}"` interpolated into an attribute.
#   * `text-[#eab308]`, `text-[#22c55e]` and `bg-[#8b5cf6]` were arbitrary
#     Tailwind values in a JavaScript template string.

CASE_METRICS_FRAGMENT = "_fragments/analytics_case_metrics.html"
VELOCITY_FRAGMENT = "_fragments/analytics_velocity.html"

#: How tall a sparkline bar is at full scale, and its floor, from the
#: page's `Math.max(2, Math.round((count / max) * 56))`.
SPARK_HEIGHT = 56
SPARK_FLOOR = 2

#: Days stale at which a dormant indicator is urgent rather than a
#: warning, from `s.days_stale > 21`.
IOC_DANGER_DAYS = 21


class SparkBar(TypedDict):
    """One day. `height` is None for a day whose count is unreadable, so
    the bar is drawn as unmeasured rather than as the floor, which looks
    like a quiet day."""

    date: Optional[str]
    count: Optional[int]
    height: Optional[int]


def spark(points: Any) -> Optional[list[SparkBar]]:
    """A daily series, or None when the payload did not carry one."""
    if not isinstance(points, list):
        return None
    readable = [p for p in points if isinstance(p, dict)]
    top = scale([_num(p.get("count")) for p in readable])
    bars: list[SparkBar] = []
    for point in readable:
        count = _num(point.get("count"))
        bars.append({
            "date": _text(point.get("date")),
            "count": _int(point.get("count")),
            "height": (max(SPARK_FLOOR,
                           int(round(count / top * SPARK_HEIGHT)))
                       if count is not None and top else None),
        })
    return bars


class Share(TypedDict):
    """One slice of a distribution. `key` is safe for a class attribute;
    `label` is the words."""

    key: str
    label: str
    count: Optional[int]
    pct: Optional[int]


def shares(mapping: Any) -> Optional[list[Share]]:
    """A name-to-count mapping as sorted shares, or None.

    `Object.values(x).reduce((a, b) => a + b, 0) || 1` is NaN as soon as
    one value is not a number, and `|| 1` turns that into a denominator of
    one, so every percentage became the count times a hundred.
    """
    if not isinstance(mapping, dict):
        return None
    counts = {str(k): _num(v) for k, v in mapping.items()}
    total = sum(v for v in counts.values() if v is not None)
    out: list[Share] = []
    for name, value in counts.items():
        key, label = entity_kind(name)
        out.append({
            "key": key,
            "label": label or name,
            "count": None if value is None else int(value),
            "pct": (int(round(value / total * 100))
                    if value is not None and total > 0 else None),
        })
    out.sort(key=lambda s: (s["count"] is None, -(s["count"] or 0)))
    return out


class StaleIOC(TypedDict):
    value: Optional[str]
    kind: Optional[str]
    kind_key: str
    threat_key: str
    threat_label: Optional[str]
    days: Optional[int]
    urgent: Optional[bool]


#: The order the Cases by Severity table sorts into, from the page's own
#: list. A severity outside it sorted to index -1 and so to the top, ahead
#: of critical; it goes last here.
SEVERITY_ORDER: tuple[str, ...] = (
    "critical", "high", "medium", "low", "info",
)


def severity_breakdown(mapping: Any) -> Optional[list[SeverityRow]]:
    """The Cases by Severity table, or None when the payload is not a
    mapping.

    `data.open || 0`, `data.closed || 0` and `data.total || 0` printed a
    zero for each figure the job did not record.
    """
    if not isinstance(mapping, dict):
        return None
    rows: list[SeverityRow] = []
    for name, figures in mapping.items():
        counts = figures if isinstance(figures, dict) else {}
        label = str(name)
        rows.append({
            "key": severity_key(label),
            "label": label,
            "open": _int(counts.get("open")),
            "closed": _int(counts.get("closed")),
            "total": _int(counts.get("total")),
        })
    order = {name: i for i, name in enumerate(SEVERITY_ORDER)}
    rows.sort(key=lambda r: order.get(r["label"], len(order)))
    return rows

class SeverityRow(TypedDict):
    """One row of the Cases by Severity table. Each figure is None when
    the job did not record it, where `data.open || 0` printed a zero."""

    key: str
    label: str
    open: Optional[int]
    closed: Optional[int]
    total: Optional[int]


class CaseMetricsView(TypedDict):
    job: JobState
    mttr_hours: Optional[float]
    total_cases: Optional[int]
    open_cases: Optional[int]
    closed_cases: Optional[int]
    trend: Optional[list[SparkBar]]
    closure_reasons: Optional[list[Share]]
    by_severity: Optional[list[SeverityRow]]


#: The threat levels the distribution always lists, in this order. The
#: page iterated this fixed list rather than the payload's keys, so a
#: level with no observables showed as a zero row instead of vanishing.
#: Dropping that was a regression in my own first pass at this panel.
THREAT_LEVELS: tuple[str, ...] = (
    "critical", "high", "medium", "low", "benign", "unknown",
)


class ThreatRow(TypedDict):
    """One of the six levels. `count` is 0 for a level the payload does not
    mention, which is what `dist[level] || 0` meant, and None only when the
    distribution itself was unreadable."""

    level: str
    count: Optional[int]
    pct: Optional[int]


def threat_rows(mapping: Any) -> Optional[list[ThreatRow]]:
    """The six levels, or None when the distribution is not a mapping."""
    if not isinstance(mapping, dict):
        return None
    counts = {str(k): _num(v) for k, v in mapping.items()}
    total = sum(v for v in counts.values() if v is not None)
    rows: list[ThreatRow] = []
    for level in THREAT_LEVELS:
        if level in counts:
            value = counts[level]
        else:
            # Absent from the payload means none of them, which is what
            # the page's `dist[level] || 0` said.
            value = 0.0
        rows.append({
            "level": level,
            "count": None if value is None else int(value),
            "pct": (int(round(value / total * 100))
                    if value is not None and total > 0 else None),
        })
    return rows


class VelocityView(TypedDict):
    job: JobState
    daily: Optional[list[SparkBar]]
    threat_distribution: Optional[list[ThreatRow]]
    total_observables: Optional[int]
    total_watched: Optional[int]
    stale_iocs: Optional[list[StaleIOC]]


def case_metrics_view(job: Any) -> CaseMetricsView:
    state = job_state(job)
    result = job.get("result") if isinstance(job, dict) else None
    if not isinstance(result, dict):
        return {"job": state, "mttr_hours": None, "total_cases": None,
                "open_cases": None, "closed_cases": None, "trend": None,
                "closure_reasons": None, "by_severity": None}
    return {
        "job": state,
        "mttr_hours": _num(result.get("mttr_hours")),
        "total_cases": _int(result.get("total_cases")),
        "open_cases": _int(result.get("open_cases")),
        "closed_cases": _int(result.get("closed_cases")),
        "trend": spark(result.get("daily_trend")),
        "closure_reasons": shares(result.get("closure_reasons")),
        "by_severity": severity_breakdown(result.get("by_severity")),
    }


def stale_ioc(raw: Any) -> Optional[StaleIOC]:
    if not isinstance(raw, dict):
        return None
    days = _int(raw.get("days_stale"))
    kind_key, kind = entity_kind(raw.get("type"))
    threat = raw.get("threat_level")
    return {
        "value": _text(raw.get("value")),
        "kind": kind,
        "kind_key": kind_key,
        "threat_key": severity_key(threat),
        "threat_label": _text(threat),
        "days": days,
        "urgent": None if days is None else days > IOC_DANGER_DAYS,
    }


def velocity_view(job: Any) -> VelocityView:
    state = job_state(job)
    result = job.get("result") if isinstance(job, dict) else None
    if not isinstance(result, dict):
        return {"job": state, "daily": None, "threat_distribution": None,
                "total_observables": None, "total_watched": None,
                "stale_iocs": None}
    raw_iocs = result.get("stale_iocs")
    return {
        "job": state,
        "daily": spark(result.get("daily_counts")),
        "threat_distribution": threat_rows(
            result.get("threat_distribution")),
        "total_observables": _int(result.get("total_observables")),
        "total_watched": _int(result.get("total_watched")),
        "stale_iocs": (None if not isinstance(raw_iocs, list) else
                       [i for i in (stale_ioc(r) for r in raw_iocs)
                        if i is not None]),
    }


router.add_api_route(
    "/analytics/case-metrics",
    _panel(AnalyticsJobType.CASE_METRICS.value, CASE_METRICS_FRAGMENT,
           case_metrics_view),
    methods=["GET"], response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))])

router.add_api_route(
    "/analytics/observable-velocity",
    _panel(AnalyticsJobType.OBSERVABLE_VELOCITY.value, VELOCITY_FRAGMENT,
           velocity_view),
    methods=["GET"], response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))])


# ---------------------------------------------------------------------------
# System analytics
# ---------------------------------------------------------------------------
#
# One read, GET /api/analytics/system-overview?hours=N, feeding a stats
# bar, a per-system card grid, a timeline and an index breakdown.
#
# THE PAGE NEVER READ es_failed, AND THAT IS THE WHOLE POINT
#
# That endpoint merges two halves: the Elasticsearch alert figures, and the
# CyAB namespace mappings out of ION's own database. Its own comment says
# so, and says what the flag means:
#
#     # Whether the Elasticsearch half of this payload happened. The
#     # figures above that come from it are placeholders when this is
#     # true, not measurements of a quiet estate.
#
# The page rendered those placeholders as measurements:
# `(data.total_alerts || 0).toLocaleString()` and three more like it. So a
# deployment whose Elasticsearch was unreachable saw a clean estate: zero
# alerts, zero logs ingested, no severity anywhere. The flag was added to
# the endpoint to make that visible and nothing was ever taught to read it.
#
# So this view is split by provenance. The figures that come from the
# database are real whether or not Elasticsearch answered, and the ones
# that come from Elasticsearch are withheld when it did not.
#
# Three smaller defects in the same panel:
#
#   * `idx.count.toLocaleString()` throws on undefined, taking the index
#     breakdown down through the caller's catch, which then rendered the
#     exception message in place of the whole tab.
#   * `Math.max(...indices.map(i => i.count), 1)` is NaN if any one count
#     is not a number, so every bar width became "NaN%".
#   * The severity pills used `if (sev.critical)`, so a count of zero and a
#     count that was never recorded both drew nothing, and the fallback
#     sentence depended on `sys.alert_count > 0`, which is false for a
#     missing count as well as for a genuine zero.

SYSTEM_FRAGMENT = "_fragments/analytics_system.html"

#: The severity pills a system or index card shows, in this order, with the
#: single letter the page used.
SEVERITY_PILLS: tuple[tuple[str, str], ...] = (
    ("critical", "C"), ("high", "H"), ("medium", "M"), ("low", "L"),
)


class Pill(TypedDict):
    key: str
    letter: str
    count: int


def pills(mapping: Any) -> Optional[list[Pill]]:
    """The severity pills for one row, or None when there is no readable
    severity breakdown at all.

    `if (sev.critical)` drew nothing both for a recorded zero and for a
    severity that was never recorded. None here is the second case, and an
    empty list is the first.
    """
    if not isinstance(mapping, dict):
        return None
    out: list[Pill] = []
    for key, letter in SEVERITY_PILLS:
        count = _int(mapping.get(key))
        if count:
            out.append({"key": key, "letter": letter, "count": count})
    return out


class SystemCard(TypedDict):
    name: Optional[str]
    mapped: bool
    alert_count: Optional[int]
    pills: Optional[list[Pill]]
    coverage: Optional[int]


class IndexRow(TypedDict):
    name: Optional[str]
    count: Optional[int]
    width: Optional[float]
    pills: Optional[list[Pill]]


class SystemView(TypedDict):
    """`es_failed` decides whether the Elasticsearch-derived figures are
    figures at all. The database-derived ones are real either way, which is
    what the endpoint means by being able to answer with one half down."""

    es_failed: bool
    error: Optional[str]
    hours: Optional[int]
    # From Elasticsearch.
    total_alerts: Optional[int]
    total_logs: Optional[int]
    total_pills: Optional[list[Pill]]
    indices: Optional[list[IndexRow]]
    # From ION's own database. The systems list stays in the model because
    # the page still builds the card grid itself: buildSysCard is a hundred
    # lines of structure, with a per-namespace icon and colour, a
    # sparkline, a top-rules table, a TIDE coverage bar carrying its own
    # threshold colours, a CyAB readiness line and an unmapped badge. A
    # simplified card here would have dropped most of that, which is the
    # regression this project keeps catching in conversions. The grid is a
    # later pass, so renderSysCards stays a write site on purpose.
    total_systems: Optional[int]
    mapped_systems: Optional[int]
    avg_coverage: Optional[int]
    systems: Optional[list[SystemCard]]


def system_card(raw: Any, *, es_failed: bool) -> Optional[SystemCard]:
    if not isinstance(raw, dict):
        return None
    name = _text(raw.get("system"))
    return {
        "name": name,
        "mapped": raw.get("mapped") is True,
        # Withheld rather than zero when the half that counts them failed.
        "alert_count": (None if es_failed
                        else _int(raw.get("alert_count"))),
        "pills": None if es_failed else pills(raw.get("severity")),
        "coverage": _int(raw.get("tide_coverage")),
    }


def index_row(raw: Any, top: Optional[float]) -> Optional[IndexRow]:
    if not isinstance(raw, dict):
        return None
    count = _num(raw.get("count"))
    return {
        "name": _text(raw.get("index")),
        "count": _int(raw.get("count")),
        "width": (round(count / top * 100, 2)
                  if count is not None and top else None),
        "pills": pills(raw.get("severity")),
    }


def system_view(payload: Any) -> SystemView:
    if not isinstance(payload, dict):
        return {
            "es_failed": True,
            "error": "The system overview answered something this page "
                     "could not read.",
            "hours": None, "total_alerts": None, "total_logs": None,
            "total_pills": None, "indices": None, "total_systems": None,
            "mapped_systems": None, "avg_coverage": None, "systems": None,
        }
    es_failed = payload.get("es_failed") is True
    raw_systems = payload.get("systems")
    raw_indices = payload.get("indices")
    readable_indices = ([i for i in raw_indices if isinstance(i, dict)]
                        if isinstance(raw_indices, list) else [])
    top = scale([_num(i.get("count")) for i in readable_indices])
    return {
        "es_failed": es_failed,
        "error": _text(payload.get("error")),
        "hours": _int(payload.get("hours")),
        "total_alerts": None if es_failed else _int(
            payload.get("total_alerts")),
        "total_logs": None if es_failed else _int(
            payload.get("total_logs_ingested")),
        "total_pills": None if es_failed else pills(
            payload.get("total_severity")),
        "indices": (None if es_failed or not isinstance(raw_indices, list)
                    else [r for r in (index_row(i, top)
                                      for i in readable_indices)
                          if r is not None]),
        "total_systems": _int(payload.get("total_systems")),
        "mapped_systems": _int(payload.get("mapped_systems")),
        "avg_coverage": _int(payload.get("avg_tide_coverage")),
        "systems": (None if not isinstance(raw_systems, list) else
                    [c for c in (system_card(s, es_failed=es_failed)
                                 for s in raw_systems) if c is not None]),
    }


@router.get(
    "/analytics/system",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def analytics_system_fragment(
    request: Request,
    hours: int = 24,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The system analytics tab."""
    from fastapi import HTTPException

    from ion.web.analytics_api import get_system_overview

    try:
        payload = await get_system_overview(
            hours=hours, current_user=current_user, session=session)
    except HTTPException as refusal:
        view = system_view(None)
        view["error"] = (str(refusal.detail) if refusal.detail
                         else "The system overview was refused.")
    except Exception:
        logger.exception("Analytics system fragment could not read")
        view = system_view(None)
    else:
        view = system_view(payload)
    return render_view(request, SYSTEM_FRAGMENT, view)
