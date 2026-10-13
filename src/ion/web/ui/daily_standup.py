"""The duty check report at /daily-standup: the sweep, the rota, Arkime, intel.

daily_standup.html fetched six endpoints and built every data-driven part of
the page out of string concatenation at thirty-three innerHTML sites behind
its own `esc()`, with a `sevPill()`, a `statusPill()`, an `hoursClass()`, a
`fmtN()` and a `fmtBytes()` beside it. All of that renders here and Jinja
escapes it.

Seven routes, because the reads carry two different permissions and run on
two different schedules:

    GET  /api/daily-standup/checks                     alert:read
    GET  /api/daily-standup/duty                       alert:read
    GET  /api/daily-standup/arkime/high-risk-traffic   alert:read
    GET  /api/daily-standup/arkime/node-stats          alert:read
    GET  /api/threat-landscape/reports?limit=5         observable:read
    GET  /api/threat-landscape/reports/{id}            observable:read
    POST /api/threat-landscape/ai-summary              observable:read

Permissions read off the live routes rather than assumed. One route could
carry only one gate: the loosest would make the OpenCTI reports a softer way
in than GET /api/threat-landscape/reports, and the strictest would hide the
Elasticsearch sweep from a duty analyst who has alert:read and no intel
permission, which is most of the people this page is for.

Not require_page_permission anywhere: it redirects to /login, and htmx would
swap a login form into the middle of the report.

/checks is ONE route and renders seven regions, which is the opposite of the
split above and for the same reason. `daily_checks_payload` is a single
`asyncio.gather` over ten Elasticsearch and database checks; a route per
region would run that sweep seven times on one press of Run Checks. The
regions that are not contiguous in the page come back as htmx out-of-band
swaps beside the main one, so every figure and the table under it come from
one read and cannot disagree.

The rota is its own route because it is one local row and is most worth
knowing on the mornings when Elasticsearch is the thing that broke. That
reasoning is the API's own, in `standup_duty`'s docstring, and splitting the
fragments the same way is what keeps the page honouring it: the duty line
loads on its own and /checks refreshes it.

This is not a detection-engineering page, so no require_de_module. None of
the endpoints above is mounted under /api/de; the licence gate is for
modules named de_*, and putting it here would 404 the morning standup on a
deployment that simply is not licensed for detection engineering.

What the JavaScript got wrong, as opposed to merely built badly:

  * `alertData.critical_count ?? 0`, `caseData.count ?? cases.length`,
    `h.gap_hours ?? 0`, `h.avg_7d ?? 0`, `(h.count_24h ?? h.events_24h ?? 0)`,
    `(n.packets_24h || 0)`, `(n.bytes_24h)`, `(n.sessions_24h || 0)`,
    `f.failures ?? f.failure_count ?? 0`, `c.session_count || 0`,
    `(d.total_hits || 0)`, `(d.host_count || 0)` and `c.hours_open ?? 0`.
    Thirteen places where a figure nobody measured printed as a confident
    zero. A standup is the one page where "we could not look" and "there is
    nothing there" lead to opposite actions.
  * `alertData.alerts || []`, `caseData.cases || []`, `data.hosts || []`,
    `data.nodes || []`, `failData.rules || []` and `data.countries || []`.
    Six lists where a refused read rendered the empty state: "No critical
    alerts in last 24h", "No stale cases", "No rule failures detected". The
    page said the estate was quiet because it had failed to ask.
  * `{critical,high,medium,low}[s] || 'ds-sev-low'`. An alert with no
    severity was painted with the low pill, so an unclassified critical read
    as triaged and low.
  * `c.hours_open.toFixed(1)` on the `?? 0` above printed "0.0" hours open
    for a stale case whose creation time was missing, which is the one figure
    that decides whether it gets chased.
  * `(data.total_events_24h ?? data.total_events ?? '--').toLocaleString()`
    called toLocaleString on the string "--" when neither key was present.
    That is a TypeError, which aborted renderLogHealth before the host grid
    was written, so the DC panel sat on "Loading..." for ever with no error
    anywhere the reader could see.
  * `statusPill()` returned the OK pill for every status that was not
    exactly CRITICAL or WARNING, including a status that had not been read.
    It is dead code in the shipped page, and it is not reimplemented here.
  * The Store tile printed `es.store_size` raw, which is
    `indices.store.size_in_bytes`: an eleven-digit byte count under a label
    saying "Store". It is formatted here.
  * The per-host gap chip carried `class="text-[#ef4444]"`, a hex literal in
    a template string, which is why a restyle never reached it.
  * `fmtBytes` in renderArkimeNodes began `if (!b || b === 0) return '0 B'`,
    so a byte count nobody sent and an idle capture node both read "0 B".
  * `DS.checksData` was the JSON the browser had fetched, and the page POSTs
    it to /save, /pdf and /pptx as `checks_data`. The fragment carries the
    same object in a data attribute, so a sign-off still records the sweep
    the analyst read without a second sweep to go and fetch it again.
"""
from __future__ import annotations

import logging
import math
from typing import Any, Optional, TypedDict

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.web.daily_standup_api import (
    _duty_today as duty_today,
    arkime_node_stats,
    check_arkime_high_risk,
    daily_checks_payload,
)
from ion.web.threat_landscape_api import (
    ai_threat_summary,
    get_recent_reports,
    get_report_detail,
)
from ion.web.ui._shared import plain, render_view

logger = logging.getLogger(__name__)

router = APIRouter()

CHECKS_FRAGMENT = "_fragments/daily_standup_checks.html"
DUTY_FRAGMENT = "_fragments/daily_standup_duty.html"
COUNTRIES_FRAGMENT = "_fragments/daily_standup_countries.html"
NODES_FRAGMENT = "_fragments/daily_standup_nodes.html"
REPORTS_FRAGMENT = "_fragments/daily_standup_reports.html"
REPORT_FRAGMENT = "_fragments/daily_standup_report.html"
SUMMARY_FRAGMENT = "_fragments/daily_standup_summary.html"

#: The permission every /api/daily-standup route names.
STANDUP_PERMISSION = "alert:read"

#: The permission every /api/threat-landscape route names.
INTEL_PERMISSION = "observable:read"

#: What the alert table showed, and no further. The rest of the sweep is
#: still in the payload the save and export endpoints receive, so capping
#: the table does not cap what is written to the saved report.
ALERT_ROWS = 15

#: The reports list the page asked for. Passed as a value rather than left
#: to the endpoint's default of 15, because 5 is what the panel has room for.
REPORT_LIMIT = 5

#: Indicators shown on a report. The endpoint already caps its own list at
#: 20; this is the panel's cap, and the fragment says when it bites.
INDICATOR_ROWS = 10

#: The five countries the panel is about, in the order the page listed them.
#: Spelled here rather than read from the payload so a country Arkime
#: returned nothing for still gets a card: a card that vanished would be
#: indistinguishable from a country with no traffic.
HIGH_RISK = (
    ("RU", "Russia"),
    ("CN", "China"),
    ("IR", "Iran"),
    ("KP", "North Korea"),
    ("SY", "Syria"),
)

#: Hours a case has been open, as a state the stylesheet paints. The
#: thresholds are the JavaScript's `hoursClass`.
_HOURS_CRITICAL = 72
_HOURS_WARNING = 48

_KB = 1024
_MB = 1024 * 1024
_GB = 1024 * 1024 * 1024
_TB = 1024 * 1024 * 1024 * 1024


# ---------------------------------------------------------------------------
# Reading one value out of a payload
# ---------------------------------------------------------------------------


def _num(value: object) -> Optional[int | float]:
    """A measured figure, or None when there is not one.

    `bool` is a subclass of `int`, so a check that only rejects non-numbers
    turns True into 1. A NaN or an infinity is not a measurement either: it
    formats as "nan", which reads like a value.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return int(value) if value.is_integer() else value
    return None


def _first_num(payload: object, *keys: str) -> Optional[int | float]:
    """The first key that is present AND numeric, or None.

    Present-and-null is not "try the next key": the endpoint sent that key
    and said it had no value. The JavaScript's `a ?? b ?? 0` read the second
    field after a null first one and then printed zero for both, so a host
    whose 24-hour count was explicitly null was reported as having had no
    events.
    """
    if not isinstance(payload, dict):
        return None
    for key in keys:
        if key in payload:
            return _num(payload[key])
    return None


def _text(value: object) -> Optional[str]:
    """A display string, or None when there is nothing to show.

    `plain` first, because `str()` of a SQLEnum member on 3.12 is the repr,
    which is what a pill would otherwise read. "0" is a value and is kept.
    """
    if value is None or isinstance(value, bool):
        return None
    value = plain(value)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _ok(payload: object) -> bool:
    """Whether a region of the sweep is readable at all.

    `daily_checks_payload` gathers with `return_exceptions=True` and
    substitutes `{"error": str(exc)[:100]}` for a check that raised. That
    dict has exactly one key, which is what identifies it: a check that ran
    and found a problem also reports an `error`, alongside a `status` and
    whatever else it measured, and that is a result rather than a refusal.

    Testing for the key alone was the first version of this and it was
    wrong: `_check_log_source_health` returns `{"status": "error", "error":
    ..., "diag": ...}` on a query Elasticsearch refused, and the diag block
    is the only thing that tells the operator which index and which host
    field were asked for.
    """
    return isinstance(payload, dict) and set(payload) != {"error"}


def _rows(payload: object, key: str) -> Optional[list]:
    """The list under `key`, or None when the payload is not that shape.

    `ion.web.ui._shared.rows` with one addition this page needs: a region
    the sweep replaced with `{"error": ...}` after a check raised is a
    failed read whichever key is asked for, and so is a region that simply
    is not in the payload.
    """
    if not _ok(payload):
        return None
    assert isinstance(payload, dict)
    found = payload.get(key)
    if not isinstance(found, list):
        return None
    return found


def _error(payload: object) -> Optional[str]:
    if not isinstance(payload, dict):
        return None
    return _text(payload.get("error"))


# ---------------------------------------------------------------------------
# Formatting a measured figure. None in, None out, always.
# ---------------------------------------------------------------------------


def _fmt_n(value: object) -> Optional[str]:
    """The page's `fmtN`: thousands separated, or "12.3k" past ten thousand.

    Without its `if (n == null || isNaN(n)) return '—'` doing double duty as
    a zero: a measured zero comes back as "0" and an unmeasured figure comes
    back as None, so the template chooses the word for absence.
    """
    n = _num(value)
    if n is None:
        return None
    if n >= 10000:
        shown = f"{n / 1000:.1f}"
        if shown.endswith(".0"):
            shown = shown[:-2]
        return shown + "k"
    if isinstance(n, float):
        return f"{n:,.1f}"
    return f"{n:,}"


def _fmt_bytes(value: object) -> Optional[str]:
    """A size, or None when the field was not a number.

    Without the JavaScript's `if (!b || b === 0) return '0 B'`, which made a
    size nobody sent and an idle capture node read the same. Zero is a real
    idle node and comes back as "0 B".
    """
    n = _num(value)
    if n is None or n < 0:
        return None
    if n < _KB:
        return f"{int(n)} B"
    if n < _MB:
        return f"{n / _KB:.0f} KB"
    if n < _GB:
        return f"{n / _MB:.1f} MB"
    if n < _TB:
        return f"{n / _GB:.1f} GB"
    return f"{n / _TB:.1f} TB"


def _fmt_minutes(value: object) -> Optional[str]:
    n = _num(value)
    return None if n is None else f"{n:.1f}"


def _fmt_hours(value: object) -> Optional[str]:
    n = _num(value)
    return None if n is None else f"{n:.1f}"


# ---------------------------------------------------------------------------
# The view models
# ---------------------------------------------------------------------------


class ChecksPanel(TypedDict):
    """The whole duty sweep, as the one object the fragment renders.

    `failed` is the sweep itself refusing. Every region then carries its own
    readability, because `daily_checks_payload` catches a check's exception
    and substitutes `{"error": ...}`: nine of the ten checks can fail
    independently and the page has to say which.
    """
    failed: bool
    cluster: dict
    alerts: dict
    stale: dict
    log_health: list
    rules: dict
    alerts_24h: dict
    cases: dict
    triage: dict
    duty: dict
    raw: dict


class DutyPanel(TypedDict):
    """Three states, because each sends somebody somewhere different: a name
    (get on with it), nobody rostered (the rota has a hole this week), and
    unavailable (the lookup failed, which must not read as "nobody")."""
    available: bool
    assigned: Optional[bool]
    name: Optional[str]
    acknowledged: Optional[bool]


class CountriesPanel(TypedDict):
    failed: bool
    configured: Optional[bool]
    countries: list
    errors: list


class NodesPanel(TypedDict):
    failed: bool
    configured: Optional[bool]
    error: Optional[str]
    nodes: Optional[list]


class ReportsPanel(TypedDict):
    failed: bool
    reports: Optional[list]


class ReportPanel(TypedDict):
    failed: bool
    name: Optional[str]
    meta: list
    labels: list
    body: Optional[str]
    actors: list
    ttps: list
    malware: list
    vulns: list
    countries: list
    sectors: list
    indicators: list
    indicators_total: Optional[int]
    empty: bool


class SummaryPanel(TypedDict):
    failed: bool
    summary: Optional[str]


# ---------------------------------------------------------------------------
# Region views
# ---------------------------------------------------------------------------


_CLUSTER_STATES = {"green": "good", "yellow": "warning", "red": "critical"}


def _cluster_view(payload: object) -> dict:
    """The ES tile: a status word, a state the stylesheet paints, four stats.

    `state` is the semantic value, not a colour. The JavaScript appended one
    of three Tailwind class triples directly, which is why the badge could
    not be restyled with the rest of the page.

    A status this map has not caught up with is "unknown", not red. Red is a
    claim about the cluster; unknown is a claim about the read.
    """
    if not _ok(payload):
        return {"failed": True, "mode": "unread", "state": "unknown"}
    assert isinstance(payload, dict)
    status = _text(payload.get("status"))
    if status == "not_configured":
        return {"failed": False, "mode": "unconfigured", "status": status,
                "state": "unknown"}
    if status == "error":
        return {"failed": False, "mode": "error", "status": status,
                "state": "critical", "error": _error(payload)}
    key = status.lower() if status else None
    return {
        "failed": False,
        "mode": "ok",
        "status": status,
        "state": _CLUSTER_STATES.get(key or "", "unknown"),
        "nodes": _fmt_n(payload.get("number_of_nodes")),
        "shards": _fmt_n(payload.get("active_shards")),
        "indices": _fmt_n(payload.get("indices_count")),
        # Formatted, not raw. The tile is labelled "Store" and printed
        # `size_in_bytes` as a bare integer.
        "store": _fmt_bytes(payload.get("store_size")),
    }


def _severity(raw: object) -> str:
    """The pill's word. "unknown" for a severity nobody set.

    The JavaScript fell through to the low pill, so an alert that had never
    been classified looked like one classified as low. The word travels and
    the stylesheet paints it, which is why `.ds-sev-unknown` exists.
    """
    text = _text(raw)
    if text is None:
        return "unknown"
    key = text.lower()
    return key if key in ("critical", "high", "medium", "low", "info") else "unknown"


def _alert_row(raw: object) -> Optional[dict]:
    if not isinstance(raw, dict):
        return None
    # rule_name, then title, then "(rule unknown)". Never `a.id`: that is
    # the raw Elasticsearch document id, and analysts read a leaked UUID in
    # this column as the rule's name.
    label = _text(raw.get("rule_name")) or _text(raw.get("title"))
    when = raw.get("timestamp")
    if when == "":
        when = None
    return {
        "timestamp": when,
        "severity": _severity(raw.get("severity")),
        "severity_shown": _text(raw.get("severity")),
        "rule": label or "(rule unknown)",
        "host": _text(raw.get("host")),
        "status": _text(raw.get("status")),
    }


def _alerts_view(payload: object) -> dict:
    rows = _rows(payload, "alerts")
    if rows is None:
        return {"failed": True}
    assert isinstance(payload, dict)
    parsed = [row for row in (_alert_row(a) for a in rows) if row is not None]
    source = _text(payload.get("source"))
    return {
        "failed": False,
        # The count the endpoint computed, over the whole window rather than
        # over the rows the table has room for.
        "critical": _fmt_n(payload.get("critical_count")),
        "total": _fmt_n(payload.get("total")),
        "rows": parsed[:ALERT_ROWS],
        "hidden": max(0, len(parsed) - ALERT_ROWS),
        # Exact match. Any other source is not the ION-local fallback, and
        # the banner claims the alert source is degraded.
        "fallback": source == "ion_fallback",
        "fallback_reason": _text(payload.get("fallback_reason"))
        or "ES returned no critical-severity matches",
    }


def _hours_state(hours: Optional[int | float]) -> Optional[str]:
    if hours is None:
        return None
    if hours > _HOURS_CRITICAL:
        return "critical"
    if hours > _HOURS_WARNING:
        return "warning"
    return "elevated"


def _case_row(raw: object) -> Optional[dict]:
    if not isinstance(raw, dict):
        return None
    rules = raw.get("triggered_rules")
    shown: list[str] = []
    if isinstance(rules, list):
        shown = [text for text in (_text(r) for r in rules) if text]
    hours = _first_num(raw, "hours_open")
    return {
        "case_number": _text(raw.get("case_number")),
        "title": _text(raw.get("title")),
        "severity": _severity(raw.get("severity")),
        "severity_shown": _text(raw.get("severity")),
        "rules": shown[:2],
        # A list the row did not carry and a case built from no rules are
        # different. `rules_known` is False only for the first.
        "rules_known": isinstance(rules, list),
        "rules_hidden": max(0, len(shown) - 2),
        "assigned_to": _text(raw.get("assigned_to")),
        "hours": _fmt_hours(hours),
        "hours_state": _hours_state(hours),
    }


def _stale_view(payload: object) -> dict:
    rows = _rows(payload, "cases")
    if rows is None:
        return {"failed": True}
    assert isinstance(payload, dict)
    parsed = [row for row in (_case_row(c) for c in rows) if row is not None]
    # The query's own count, and only the query's own count. The JavaScript
    # fell back to the length of the page it had been sent, which is the
    # same number only while nothing is capped.
    return {"failed": False, "count": _fmt_n(payload.get("count")),
            "rows": parsed}


def _host_row(raw: object) -> Optional[dict]:
    if not isinstance(raw, dict):
        return None
    name = _text(raw.get("hostname")) or _text(raw.get("display_hostname"))
    status = _text(raw.get("status"))
    # One vocabulary for the host light and the panel light, so the two
    # cannot disagree about what "fine" is called. A status this does not
    # recognise, and a host with no status at all, are both unknown: the
    # JavaScript's `h.status || 'ok'` painted both of them green.
    state = {"ok": "good", "warning": "warning",
             "critical": "critical"}.get((status or "").lower(), "unknown")
    events = _first_num(raw, "count_24h", "events_24h")
    avg = _first_num(raw, "avg_7d")
    gaps = _first_num(raw, "gap_hours")
    below = raw.get("below_average")
    if below is None:
        below = raw.get("below_avg")
    return {
        "name": name or "(unnamed host)",
        "state": state,
        "events": _fmt_n(events),
        "avg": _fmt_n(avg),
        "gaps": _fmt_n(gaps),
        # `> 0` only on a number. The JavaScript's `gaps > 0` on the `?? 0`
        # above could never fire for a missing value, which is right, but it
        # also compared a string against 0 when the field was text.
        "gap_shown": gaps is not None and gaps > 0,
        "below_average": below is True,
    }


def _diag_view(raw: object) -> Optional[dict]:
    """What was queried, so the operator can fix ION_STANDUP_* rather than
    guess. Counts stay None when they were not sent."""
    if not isinstance(raw, dict):
        return None
    patterns = raw.get("patterns")
    return {
        "index": _text(raw.get("index")),
        "host_field": _text(raw.get("host_field")),
        "patterns": [p for p in (_text(x) for x in patterns) if p]
        if isinstance(patterns, list) else [],
        "total_hits": _fmt_n(raw.get("total_hits")),
        "host_count": _fmt_n(raw.get("host_count")),
    }


def _log_health_view(payload: object, prefix: str, title: str) -> dict:
    """One log-source panel. Five outcomes, and they are all different.

    read failed      the check raised inside the sweep
    error            Elasticsearch answered with an error, which the diag
                     block explains
    not_configured   nothing was ever asked
    zero hosts       the patterns matched nothing, which is a measured
                     result and not the same as a failed query
    hosts            the grid

    The overall light is the worst host, not the first: `hosts.some()` is
    what the JavaScript did and it is right. A read that failed leaves the
    light grey rather than green, because green is a claim.
    """
    base = {"prefix": prefix, "title": title}
    if not _ok(payload):
        return {**base, "failed": True, "state": "unknown"}
    assert isinstance(payload, dict)
    status = _text(payload.get("status"))
    diag = _diag_view(payload.get("diag"))
    if status == "error":
        return {**base, "failed": False, "mode": "error", "state": "critical",
                "error": _error(payload)
                or "Elasticsearch gave no reason.", "diag": diag}
    if status == "not_configured":
        return {**base, "failed": False, "mode": "not_configured",
                "state": "warning",
                "error": _error(payload)
                or "Set ION_ELASTICSEARCH_URL and the ION_STANDUP_* "
                   "variables.", "diag": diag}

    hosts = _rows(payload, "hosts")
    if hosts is None:
        return {**base, "failed": True, "state": "unknown"}
    rows = [row for row in (_host_row(h) for h in hosts) if row is not None]
    counters = {
        "total": _fmt_n(_first_num(payload, "total_events_24h",
                                   "total_events")),
        "gaps": _fmt_n(_first_num(payload, "hosts_with_gaps")),
        "below": _fmt_n(_first_num(payload, "hosts_below_average",
                                   "hosts_below_avg")),
    }
    if not rows:
        return {**base, "failed": False, "mode": "empty", "state": "warning",
                "diag": diag, **counters}

    if any(r["state"] == "critical" for r in rows):
        state = "critical"
    elif any(r["state"] == "warning" for r in rows):
        state = "warning"
    elif any(r["state"] == "unknown" for r in rows):
        state = "unknown"
    else:
        state = "good"
    return {**base, "failed": False, "mode": "hosts", "state": state,
            "hosts": rows, "diag": diag, **counters}


def _rule_row(raw: object) -> Optional[dict]:
    if not isinstance(raw, dict):
        return None
    # The API renamed rule_name -> name and failure_count -> failures. Both
    # shapes are read, for a cached payload or an older image mid-deploy.
    name = _text(raw.get("name")) or _text(raw.get("rule_name"))
    return {
        "name": name or "(unnamed)",
        "failures": _fmt_n(_first_num(raw, "failures", "failure_count")),
        "last_failure": raw.get("last_failure") or None,
    }


def _rules_view(payload: object) -> dict:
    rows = _rows(payload, "rules")
    if rows is None and isinstance(payload, list):
        rows = payload
    if rows is None:
        return {"failed": True}
    return {"failed": False,
            "rows": [r for r in (_rule_row(f) for f in rows) if r is not None]}


def _breakdown(raw: object, *keys: str) -> dict:
    """A `{name: formatted-or-None}` map over the keys the card has cells for.

    A key missing from a GROUP BY result is a true zero and a key the read
    never produced is not, so the lookup is `in` and the value goes through
    `_fmt_n`, which keeps a zero and refuses a non-number.
    """
    source = raw if isinstance(raw, dict) else {}
    return {key: _fmt_n(source[key]) if key in source else None
            for key in keys}


def _alerts_24h_view(payload: object) -> dict:
    if not _ok(payload):
        return {"failed": True}
    assert isinstance(payload, dict)
    source = _text(payload.get("source"))
    return {
        "failed": False,
        "total": _fmt_n(payload.get("total")),
        "severity": _breakdown(payload.get("by_severity"),
                               "critical", "high", "medium", "low"),
        "status": _breakdown(payload.get("by_status"),
                             "open", "acknowledged", "closed"),
        "fallback": source == "ion_fallback",
        # The source word, when the read said what it was. A read that did
        # not is not silently "ES".
        "source": source,
    }


def _cases_view(payload: object) -> dict:
    if not _ok(payload):
        return {"failed": True}
    assert isinstance(payload, dict)
    return {
        "failed": False,
        "intake": _fmt_n(payload.get("intake_24h")),
        "open": _fmt_n(payload.get("open")),
        "in_progress": _fmt_n(payload.get("in_progress")),
        "closed": _fmt_n(payload.get("closed_24h")),
        "severity": _breakdown(payload.get("by_severity_24h"),
                               "critical", "high", "medium", "low"),
    }


def _triage_view(payload: object) -> dict:
    if not _ok(payload):
        return {"failed": True}
    assert isinstance(payload, dict)
    return {
        "failed": False,
        "triaged": _fmt_n(payload.get("triaged_24h")),
        "avg": _fmt_minutes(payload.get("avg_mtta_minutes")),
        "p50": _fmt_minutes(payload.get("p50_mtta_minutes")),
        "p90": _fmt_minutes(payload.get("p90_mtta_minutes")),
    }


def _duty_view(payload: object) -> DutyPanel:
    """The rota line. `available` is False only when the lookup itself did
    not produce a row, which is not the same as the rota having a hole."""
    if not isinstance(payload, dict):
        return {"available": False, "assigned": None, "name": None,
                "acknowledged": None}
    assigned = payload.get("assigned")
    if assigned is not True and assigned is not False:
        return {"available": False, "assigned": None, "name": None,
                "acknowledged": None}
    person = payload.get("user")
    name = _text(person.get("name")) if isinstance(person, dict) else None
    return {
        "available": True,
        "assigned": assigned,
        "name": name,
        # An unacknowledged entry is a plan rather than a fact, and the
        # Monday somebody is off sick is exactly when that matters.
        "acknowledged": payload.get("acknowledged") is True,
    }


def _checks_view(payload: object) -> ChecksPanel:
    """Every region of the sweep, from the one payload the sweep produced."""
    if not isinstance(payload, dict):
        return {
            "failed": True, "cluster": {}, "alerts": {}, "stale": {},
            "log_health": [], "rules": {}, "alerts_24h": {}, "cases": {},
            "triage": {}, "duty": _duty_view(None), "raw": {},
        }
    return {
        "failed": False,
        "cluster": _cluster_view(payload.get("cluster_health")),
        "alerts": _alerts_view(payload.get("critical_alerts")),
        "stale": _stale_view(payload.get("stale_cases")),
        "log_health": [
            _log_health_view(payload.get("dc_log_health"), "dc",
                             "DC Log Health"),
            _log_health_view(payload.get("wef_log_health"), "wef",
                             "WEF Log Health"),
        ],
        "rules": _rules_view(payload.get("rule_failures")),
        "alerts_24h": _alerts_24h_view(payload.get("alerts_24h")),
        "cases": _cases_view(payload.get("case_status_counts")),
        "triage": _triage_view(payload.get("triage_throughput")),
        "duty": _duty_view(payload.get("duty")),
        # The payload itself, for the save, PDF and pptx endpoints that
        # already accept it. It is not re-derived from the regions above:
        # those are the reader's view and this is the record.
        "raw": payload,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/daily-standup/checks", response_class=HTMLResponse)
async def standup_checks(
    request: Request,
    _user: User = Depends(require_permission(STANDUP_PERMISSION)),
) -> Response:
    """The whole duty sweep, in one read.

    `daily_checks_payload` is the body of GET /api/daily-standup/checks
    without its no-store response wrapper; the header belongs to the HTTP
    answer and this one carries its own. An exception here is a 200 fragment
    that says the sweep failed, because htmx does not swap a 5xx and the
    reader would be left on the spinner.
    """
    try:
        payload = await daily_checks_payload()
    except Exception:
        logger.exception("daily standup checks fragment could not be rendered")
        view = _checks_view(None)
    else:
        view = _checks_view(payload)
    return render_view(request, CHECKS_FRAGMENT, view)


@router.get("/daily-standup/duty", response_class=HTMLResponse)
def standup_duty_line(
    request: Request,
    _user: User = Depends(require_permission(STANDUP_PERMISSION)),
) -> Response:
    """Who the rota has on duty this week.

    `_duty_today` is the whole body of GET /api/daily-standup/duty and does
    not raise by contract, so the try is for the contract being broken
    rather than for a failure mode it documents. Either way the answer is
    "unavailable", never "nobody".
    """
    try:
        payload = duty_today()
    except Exception:
        logger.exception("duty rota fragment could not be rendered")
        payload = None
    view = _duty_view(payload)
    return render_view(request, DUTY_FRAGMENT, view)


def _country_session(raw: object) -> Optional[dict]:
    if not isinstance(raw, dict):
        return None
    return {
        "src_ip": _text(raw.get("src_ip")) or "?",
        "dst_ip": _text(raw.get("dst_ip")) or "?",
        "protocol": _text(raw.get("protocol")) or "?",
        "bytes": _fmt_bytes(raw.get("bytes")),
    }


def _country_node(raw: object) -> Optional[dict]:
    if not isinstance(raw, dict):
        return None
    name = _text(raw.get("node"))
    if name is None:
        return None
    sessions = raw.get("sessions")
    count = _num(raw.get("session_count")) if "session_count" in raw else None
    return {
        "node": name,
        "count": _fmt_n(count),
        # The plural is on the number it describes, and only when there is
        # a number to describe.
        "plural": count != 1 if count is not None else None,
        "sessions": [s for s in (_country_session(x) for x in sessions)
                     if s is not None] if isinstance(sessions, list) else [],
    }


def _countries_view(payload: object) -> CountriesPanel:
    if not isinstance(payload, dict):
        return {"failed": True, "configured": None, "countries": [],
                "errors": []}
    if payload.get("configured") is False:
        return {"failed": False, "configured": False, "countries": [],
                "errors": []}
    found = payload.get("countries")
    if not isinstance(found, list):
        return {"failed": True, "configured": None, "countries": [],
                "errors": []}

    by_code: dict[str, dict] = {}
    errors: list[str] = []
    for item in found:
        if not isinstance(item, dict):
            continue
        code = _text(item.get("country_code"))
        if code:
            by_code[code.upper()] = item
        raw_errors = item.get("errors")
        if isinstance(raw_errors, list):
            errors.extend(e for e in (_text(x) for x in raw_errors) if e)

    cards = []
    for code, name in HIGH_RISK:
        item = by_code.get(code)
        count = _num(item.get("session_count")) if isinstance(item, dict) \
            and "session_count" in item else None
        nodes = item.get("nodes") if isinstance(item, dict) else None
        cards.append({
            "code": code,
            "name": name,
            "count": _fmt_n(count),
            # Highlighted on a measured count above zero. The JavaScript's
            # `c.session_count || 0` highlighted on a truthy value, so a
            # country Arkime had not been asked about looked clean.
            "active": count is not None and count > 0,
            # A country the payload did not mention at all. Arkime answered;
            # it just did not name this one.
            "measured": item is not None,
            "nodes": [n for n in (_country_node(x) for x in nodes)
                      if n is not None] if isinstance(nodes, list) else [],
        })
    return {"failed": False, "configured": True, "countries": cards,
            "errors": errors}


@router.get("/daily-standup/arkime/countries", response_class=HTMLResponse)
async def standup_arkime_countries(
    request: Request,
    current_user: User = Depends(require_permission(STANDUP_PERMISSION)),
) -> Response:
    """High-risk country traffic, from GET
    /api/daily-standup/arkime/high-risk-traffic.

    Its own route rather than one shared with the node stats. The old page
    fetched both in one `Promise.all` and discarded both on a single throw;
    these are two Arkime sweeps of different cost and one must not be able
    to blank the other.
    """
    try:
        payload = await check_arkime_high_risk(current_user)
        view = _countries_view(payload)
    except Exception:
        logger.exception(
            "standup Arkime country fragment could not be rendered")
        view = _countries_view(None)
    return render_view(request, COUNTRIES_FRAGMENT, view)


def _node_row(raw: object) -> Optional[dict]:
    if not isinstance(raw, dict):
        return None
    dropped = _first_num(raw, "dropped")
    es_dropped = _first_num(raw, "es_dropped")
    overload = _first_num(raw, "overload_dropped")
    measured = [d for d in (dropped, es_dropped, overload) if d is not None]
    return {
        "name": _text(raw.get("name")) or "(unnamed node)",
        "cpu": _fmt_n(raw.get("cpu")),
        "packets": _fmt_n(_first_num(raw, "packets_24h")),
        "bytes": _fmt_bytes(_first_num(raw, "bytes_24h")),
        "sessions": _fmt_n(_first_num(raw, "sessions_24h")),
        "packets_per_sec": _fmt_n(_first_num(raw, "packets_per_sec")),
        "bytes_per_sec": _fmt_bytes(_first_num(raw, "bytes_per_sec")),
        "sessions_per_sec": _fmt_n(_first_num(raw, "sessions_per_sec")),
        "dropped": _fmt_n(dropped),
        "es_dropped": _fmt_n(es_dropped),
        "overload_dropped": _fmt_n(overload),
        # Dropping on a measured total above zero. A node whose drop
        # counters were not sent is not a clean node, so the drop row is
        # shown whenever any of the three was measured.
        "dropping": bool(measured) and sum(measured) > 0,
        "drops_known": bool(measured),
    }


def _nodes_view(payload: object) -> NodesPanel:
    if not isinstance(payload, dict):
        return {"failed": True, "configured": None, "error": None,
                "nodes": None}
    if payload.get("configured") is False:
        return {"failed": False, "configured": False, "error": None,
                "nodes": None}
    error = _error(payload)
    if error:
        return {"failed": False, "configured": True, "error": error,
                "nodes": None}
    found = payload.get("nodes")
    if not isinstance(found, list):
        return {"failed": True, "configured": None, "error": None,
                "nodes": None}
    return {
        "failed": False, "configured": True, "error": None,
        "nodes": [n for n in (_node_row(x) for x in found) if n is not None],
    }


@router.get("/daily-standup/arkime/nodes", response_class=HTMLResponse)
async def standup_arkime_nodes(
    request: Request,
    current_user: User = Depends(require_permission(STANDUP_PERMISSION)),
) -> Response:
    """Capture-node stats, from GET /api/daily-standup/arkime/node-stats."""
    try:
        payload = await arkime_node_stats(current_user)
        view = _nodes_view(payload)
    except Exception:
        logger.exception("standup Arkime node fragment could not be rendered")
        view = _nodes_view(None)
    return render_view(request, NODES_FRAGMENT, view)


def _report_row(raw: object) -> Optional[dict]:
    if not isinstance(raw, dict):
        return None
    report_id = _text(raw.get("id"))
    if report_id is None:
        return None
    when = raw.get("published") or raw.get("created_at") or None
    return {
        "id": report_id,
        "title": _text(raw.get("title")) or _text(raw.get("name"))
        or "Untitled",
        "published": when,
    }


def _reports_view(payload: object) -> ReportsPanel:
    rows = payload if isinstance(payload, list) else _rows(payload, "reports")
    if rows is None:
        return {"failed": True, "reports": None}
    return {"failed": False,
            "reports": [r for r in (_report_row(x) for x in rows)
                        if r is not None]}


@router.get("/daily-standup/reports", response_class=HTMLResponse)
async def standup_reports(
    request: Request,
    current_user: User = Depends(require_permission(INTEL_PERMISSION)),
) -> Response:
    """Reports of interest, from GET /api/threat-landscape/reports.

    limit is passed rather than left to the endpoint's default of 15,
    because 5 is what the panel has room for and the page asked for 5.
    """
    try:
        payload = await get_recent_reports(limit=REPORT_LIMIT,
                                          user=current_user)
        view = _reports_view(payload)
    except Exception:
        logger.exception("standup reports fragment could not be rendered")
        view = _reports_view(None)
    return render_view(request, REPORTS_FRAGMENT, view)


def _names(raw: object, key: str = "name") -> list[str]:
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        text = _text(item.get(key)) if isinstance(item, dict) else _text(item)
        if text:
            out.append(text)
    return out


def _actor_rows(raw: object) -> list[dict]:
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = _text(item.get("name"))
        if not name:
            continue
        out.append({"name": name, "aliases": _names(item.get("aliases"))})
    return out


def _ttp_rows(raw: object) -> list[dict]:
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = _text(item.get("name"))
        if not name:
            continue
        out.append({"name": name, "mitre_id": _text(item.get("mitre_id"))})
    return out


def _report_view(payload: object) -> ReportPanel:
    """One report's slide-over. `empty` is a report with nothing in it, which
    is not the same as a read that refused."""
    blank: ReportPanel = {
        "failed": True, "name": None, "meta": [], "labels": [], "body": None,
        "actors": [], "ttps": [], "malware": [], "vulns": [], "countries": [],
        "sectors": [], "indicators": [], "indicators_total": None,
        "empty": False,
    }
    if not isinstance(payload, dict):
        return blank

    meta: list[dict] = []
    published = payload.get("published")
    if published:
        meta.append({"kind": "published", "value": published})
    types = _names(payload.get("types"))
    if types:
        meta.append({"kind": "text", "value": ", ".join(types)})
    source = _text(payload.get("source"))
    if source:
        meta.append({"kind": "text", "value": source})
    # `is not none`, not truthiness. A confidence of 0 is a measurement and
    # the JavaScript's `!= null` had this right; it is spelled out because
    # the obvious rewrite to `if confidence:` loses it.
    confidence = _num(payload.get("confidence"))
    if confidence is not None:
        meta.append({"kind": "text", "value": f"Confidence {confidence}%"})

    shown = _names(payload.get("related_indicators"), "pattern")

    view: ReportPanel = {
        "failed": False,
        "name": _text(payload.get("name")) or "Report",
        "meta": meta,
        "labels": _names(payload.get("labels"), "value"),
        "body": _text(payload.get("body")),
        "actors": _actor_rows(payload.get("related_actors")),
        "ttps": _ttp_rows(payload.get("related_ttps")),
        "malware": _names(payload.get("related_malware")),
        "vulns": _names(payload.get("related_vulns")),
        "countries": _names(payload.get("related_countries")),
        "sectors": _names(payload.get("related_sectors")),
        "indicators": shown[:INDICATOR_ROWS],
        "indicators_total": len(shown),
        "empty": False,
    }
    view["empty"] = not any((
        view["meta"], view["labels"], view["body"], view["actors"],
        view["ttps"], view["malware"], view["vulns"], view["countries"],
        view["sectors"], view["indicators"],
    ))
    return view


@router.get("/daily-standup/reports/{report_id}", response_class=HTMLResponse)
async def standup_report(
    report_id: str,
    request: Request,
    current_user: User = Depends(require_permission(INTEL_PERMISSION)),
) -> Response:
    """One report, from GET /api/threat-landscape/reports/{report_id}."""
    try:
        payload = await get_report_detail(report_id, user=current_user)
        view = _report_view(payload)
    except Exception:
        logger.exception(
            "standup report fragment could not be rendered for %s", report_id)
        view = _report_view(None)
    return render_view(request, REPORT_FRAGMENT, view)


def _summary_view(payload: object) -> SummaryPanel:
    if not isinstance(payload, dict):
        return {"failed": True, "summary": None}
    text = _text(payload.get("summary")) or _text(payload.get("content"))
    # An AI service that answered with nothing is not an AI service that
    # could not be reached, and only the second is worth retrying.
    return {"failed": False, "summary": text}


@router.post("/daily-standup/threat-summary", response_class=HTMLResponse)
async def standup_threat_summary(
    request: Request,
    current_user: User = Depends(require_permission(INTEL_PERMISSION)),
) -> Response:
    """The threat-landscape briefing, from POST
    /api/threat-landscape/ai-summary.

    The text is handed to the page as text, inside a hidden textarea, for
    the browser's own `safeMarkdown` (marked plus DOMPurify) to paint. ION
    ships no HTML sanitiser, so rendering model output here and marking it
    safe would be a scripting hole; template_render made the same call for
    the same reason.
    """
    try:
        payload = await ai_threat_summary(user=current_user)
        view = _summary_view(payload)
    except Exception:
        logger.exception("standup threat summary could not be rendered")
        view = _summary_view(None)
    return render_view(request, SUMMARY_FRAGMENT, view)
