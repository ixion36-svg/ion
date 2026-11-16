"""The wallboard, one fragment for the whole board.

Replaces the innerHTML and insertAdjacentHTML writes in wallboard.html:
the topology graph, the alert and case status lines and their bars, Bob's
totals, the rule-posture line and its bars, and the threat-landscape
paragraph. The hand-rolled ``escHtml()`` those needed goes with them.

The JSON counterpart is ``GET /api/wallboard/snapshot``, which calls
``wallboard_service.get_snapshot`` and is gated on ``alert:read`` (plus
the ``get_current_user`` that ``require_permission`` already depends on).
The fragment calls that same function and names that same permission.
``require_page_permission`` is the page's gate and redirects to /login,
which htmx would swap into the middle of the board.

It does not carry ``require_de_module``. The live route does not either:
wallboard is mounted from its own router with no licence dependency, and
``tools/fragment_plan.py`` reads the gate off the running app as
``require_permission('alert:read')``. Adding the detection-engineering
gate would answer 404 on a deployment that is not licensed for that
module, and the wallboard is the SOC display, not a DE page. A fragment
must not be a softer way in than the API it mirrors; it also must not
pretend a page the API serves does not exist.

Three outcomes, and they are not interchangeable:

  read failed   200 with a fragment that says so. Never a board of zeros.
                "Nothing is open" and "we could not look" are opposite
                findings on a wall nobody is standing in front of to check.
  panel failed  that panel says so. The service isolates a broken
                collector as ``{"error": ...}`` with zeroed defaults, and
                those defaults are not the numbers.
  measured      including a measured zero. A quiet estate is a quiet
                estate.
"""
from __future__ import annotations

import logging
import math
import re
from typing import Any, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

#: The permission GET /api/wallboard/snapshot names. Spelled once so the
#: fragment cannot drift into being a softer way in than the endpoint it
#: mirrors.
PERMISSION = "alert:read"

_VERDICTS = (
    ("true_positive", "true positive", "bg-ion-coral"),
    ("false_positive", "false positive", "bg-ion-lime"),
    ("benign_true_positive", "benign TP", "bg-ion-amber"),
    ("inconclusive", "inconclusive", "bg-slate-500"),
)

_SEVERITIES = (
    ("critical", "bg-ion-coral"),
    ("high", "bg-ion-amber"),
    ("medium", "bg-ion-cyan"),
    ("low", "bg-slate-500"),
)

# The topology colours are the ones the JavaScript painted. They are keyed
# by the status string, so a SQLEnum member has to be unwrapped before the
# lookup or every node falls through to "off" and a healthy service reads
# as not configured.
_STROKE = {
    "up": "rgb(134,240,160)",
    "down": "rgb(255,108,108)",
    "off": "rgba(255,255,255,0.18)",
}
_FILL = {
    "up": "rgb(134,240,160)",
    "down": "rgb(255,108,108)",
    "off": "rgb(100,116,139)",
}

_CX, _CY = 230.0, 140.0
_RX, _RY = 175.0, 105.0


def _num(value: object) -> Optional[float]:
    """A real number, or None.

    ``bool`` is an ``int`` subclass, so ``isinstance(True, int)`` is true
    and a bare type check would publish a boolean as the count 1. NaN is
    not a measurement either. Zero is, and it comes back as zero.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        if isinstance(value, float) and value != value:
            return None
        return value
    return None


def _field(data: object, key: str) -> Optional[float]:
    """``data[key]`` as a number.

    A missing key is None, not zero: the collector that measured a quiet
    hour wrote the key with a 0. A key that is not there was not measured.
    """
    if not isinstance(data, dict) or key not in data:
        return None
    return _num(data.get(key))


def fmt_n(value: object) -> str:
    """The thousands shorthand the JavaScript's ``fmtN`` used.

    None, a boolean and anything that is not a number render as an em dash.
    Zero renders as ``0``. The two are different claims.
    """
    n = _num(value)
    if n is None:
        return "—"
    if n >= 1000:
        scaled = f"{n / 1000:.1f}"
        if scaled.endswith(".0"):
            scaled = scaled[:-2]
        return scaled + "k"
    if isinstance(n, float) and n.is_integer():
        return str(int(n))
    return str(int(n)) if isinstance(n, int) else str(n)


def _digits(value: object) -> Optional[str]:
    """The number with no thousands suffix, or None when it is not one."""
    n = _num(value)
    if n is None:
        return None
    if isinstance(n, float) and n.is_integer():
        return str(int(n))
    return str(int(n)) if isinstance(n, int) else str(n)


def fmt_age(seconds: object) -> Optional[str]:
    """How long ago the snapshot was computed, or None if nobody said.

    A missing age is not "just now". The JavaScript treated ``null`` as
    just now, which on a wall reads as a fresh measurement. Zero seconds
    is a fresh measurement and renders as ``0s ago``.
    """
    n = _num(seconds)
    if n is None:
        return None
    if n < 0:
        return "just now"
    if n < 60:
        return f"{int(n)}s ago"
    if n < 3600:
        return f"{round(n / 60)}m ago"
    return f"{round(n / 3600)}h ago"


def _delta(curr: Optional[float], prev: Optional[float], *, good_down: bool) -> dict:
    """A change against the previous 24h.

    Either side missing means the change was not measured. Subtracting zero
    for that side invents a direction, and a wall will believe it.
    """
    if curr is None or prev is None:
        return {"kind": "unknown"}
    diff = curr - prev
    if diff == 0:
        return {"kind": "flat"}
    up = diff > 0
    good = (not up) if good_down else up
    amount = abs(diff)
    if isinstance(amount, float) and amount.is_integer():
        amount = int(amount)
    return {"kind": "move", "up": up, "good": good, "amount": amount}


def _indexed(dist: dict) -> dict[str, object]:
    """Distribution keyed by the unwrapped, case-folded label.

    Status and severity travel as SQLEnum members when they have not been
    through FastAPI's JSON encoder. ``str()`` on Python 3.12 renders the
    member as ``Status.OPEN``, which matches neither ``open`` nor the
    colour, so the bar for a status that has rows draws as zero.
    """
    out: dict[str, object] = {}
    for key, value in dist.items():
        label = plain(key)
        if label is None:
            continue
        out[str(label).casefold()] = value
    return out


def _named_count(by_status: object, *names: str) -> Optional[float]:
    """One status's count out of a by-status map.

    An empty map was not counted. A map that counts other statuses and
    simply has no row for this one did count it, at zero.
    """
    if not isinstance(by_status, dict) or not by_status:
        return None
    wanted = {n.casefold() for n in names}
    indexed = _indexed(by_status)
    if not any(name in indexed for name in wanted):
        return 0
    total = 0.0
    for name in wanted:
        if name not in indexed:
            continue
        n = _num(indexed[name])
        if n is None:
            return None
        total += n
    return total


def sparkline_paths(buckets: object) -> Optional[dict[str, str]]:
    """Line and fill for the histogram sparkline, or None when it cannot be drawn.

    Fewer than two buckets, or a bucket whose count was not a number, is
    not a flat line of zeros. A count of zero is a real bucket and stays
    in the path: a quiet hour is the bottom of the line, not a gap.
    """
    if not isinstance(buckets, list) or len(buckets) < 2:
        return None
    counts: list[float] = []
    for bucket in buckets:
        if not isinstance(bucket, dict) or "count" not in bucket:
            return None
        n = _num(bucket.get("count"))
        if n is None:
            return None
        counts.append(n)
    width, height, pad = 160.0, 50.0, 2.0
    peak = max([1.0, *counts])
    step = (width - pad * 2) / (len(counts) - 1)
    span = height - pad * 2 - 4
    points = []
    for i, count in enumerate(counts):
        x = pad + i * step
        y = height - pad - (count / peak) * span
        points.append((x, y))
    line = " ".join(
        f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}" for i, (x, y) in enumerate(points)
    )
    fill = f"{line} L{width - pad:.1f},{int(height)} L{pad:.1f},{int(height)} Z"
    return {"line": line, "fill": fill}


def _count_bars(dist: object, order: tuple) -> dict:
    """One bar per known key of a ``{label: count}`` distribution.

    ``empty`` was read and had no rows. ``unknown`` was not a distribution,
    or a row it does contain is not a number. A label the distribution does
    not mention, while it mentions others, is a measured zero of that label.
    """
    if not isinstance(dist, dict):
        return {"state": "unknown"}
    if len(dist) == 0:
        return {"state": "empty"}
    indexed = _indexed(dist)
    measured: list[float] = []
    for value in indexed.values():
        n = _num(value)
        if n is None:
            return {"state": "unknown"}
        measured.append(n)
    peak = max([1.0, *measured]) if measured else 1.0
    rows = []
    for key, label, cls in order:
        n = _num(indexed[key]) if key in indexed else 0
        if n is None:
            return {"state": "unknown"}
        rows.append({
            "label": label,
            "cls": cls,
            "text": fmt_n(n),
            "pct": round(n / peak * 100),
        })
    return {"state": "bars", "rows": rows}


def _severity_pair(value: object) -> Optional[tuple[float, float]]:
    """``(total, enabled)`` for one severity, or None if it is not a pair.

    A missing severity is handled by the caller as a measured zero. A
    severity that is present but has no numeric total was not counted,
    and that is not a zero.
    """
    if not isinstance(value, dict) or "total" not in value:
        return None
    total = _num(value.get("total"))
    if total is None:
        return None
    if "enabled" not in value:
        return total, 0.0
    enabled = _num(value.get("enabled"))
    if enabled is None:
        return None
    return total, enabled


def _severity_bars(dist: object) -> dict:
    """The rule-severity bars: a dim total and a bright enabled overlay.

    Same empty-versus-unknown split as the count bars. The overlay width
    is the share of the row that is enabled, scaled to the longest row,
    which is what the JavaScript drew.
    """
    if not isinstance(dist, dict):
        return {"state": "unknown"}
    if len(dist) == 0:
        return {"state": "empty"}
    indexed = _indexed(dist)
    measured: list[float] = []
    for value in indexed.values():
        pair = _severity_pair(value)
        if pair is None:
            return {"state": "unknown"}
        measured.append(pair[0])
    peak = max([1.0, *measured]) if measured else 1.0
    rows = []
    for key, cls in _SEVERITIES:
        pair = _severity_pair(indexed[key]) if key in indexed else (0.0, 0.0)
        if pair is None:
            return {"state": "unknown"}
        total, enabled = pair
        total_pct = round(total / peak * 100)
        enabled_share = round(enabled / total * 100) if total else 0
        rows.append({
            "label": key,
            "cls": cls,
            "text": fmt_n(total),
            "total_pct": total_pct,
            "overlay_pct": round(total_pct * enabled_share / 100),
        })
    return {"state": "bars", "rows": rows}


def _panel(snapshot: dict, key: str) -> Optional[dict]:
    """A collector's dict, or None when that collector failed.

    The service's failure shape is the zeroed default plus ``error``. The
    zeros are there so a careless reader does not crash. They are not a
    result, so a panel that carries ``error`` is a failed panel.
    """
    panel = snapshot.get(key)
    if not isinstance(panel, dict) or panel.get("error"):
        return None
    return panel


def _topology(panel: Optional[dict]) -> dict:
    if panel is None:
        return {"failed": True}
    counts = panel.get("counts")
    header = {
        "up": _field(counts, "up"),
        "down": _field(counts, "down"),
        "off": _field(counts, "off"),
    }
    raw_nodes = panel.get("nodes")
    if not isinstance(raw_nodes, list):
        return {"failed": True, "header": header}
    nodes = []
    total = len(raw_nodes)
    for i, node in enumerate(raw_nodes):
        if not isinstance(node, dict):
            continue
        status = plain(node.get("status"))
        status = str(status) if status is not None else "off"
        if status not in _STROKE:
            status = "off"
        angle = (-math.pi / 2) + (i * 2 * math.pi / total) if total else 0
        x = _CX + _RX * math.cos(angle)
        y = _CY + _RY * math.sin(angle)
        if x > _CX:
            label_dx = 14
        elif x < _CX:
            label_dx = -14
        else:
            label_dx = 0
        if x > _CX + 5:
            anchor = "start"
        elif x < _CX - 5:
            anchor = "end"
        else:
            anchor = "middle"
        details = node.get("details")
        if details is None or details == "":
            details = status
        label = node.get("label")
        nodes.append({
            "key": "" if plain(node.get("key")) is None else str(plain(node.get("key"))),
            "label": "" if label is None else str(label),
            "status": status,
            "stroke": _STROKE[status],
            "fill": _FILL[status],
            "dash": status == "down",
            "width": 1.4 if status == "up" else 1,
            "opacity": 0.55 if status == "up" else 0.35,
            "pulse": status == "down",
            "x": f"{x:.1f}",
            "y": f"{y:.1f}",
            "label_x": f"{x + label_dx:.1f}",
            "label_y": f"{y + 4:.1f}",
            "anchor": anchor,
            "details": "" if details is None else str(details),
        })
    return {"failed": False, "header": header, "nodes": nodes}


def _rules(panel: Optional[dict]) -> dict:
    """Rule posture, with TIDE-unconfigured kept apart from a failed read.

    The collector's exception default sets ``tide_unavailable`` as well as
    ``error``, because the zeroed default already had that flag. Checking
    the flag first would tell the wall TIDE is not configured when the
    truth is that the read threw. ``error`` wins.

    ``tide_unavailable`` is three states. True means TIDE said it is not
    there. False means it answered. Anything else, including a missing
    flag, means this fragment does not know which, and it must not pick
    the number that happens to be sitting next to the flag.
    """
    if panel is None:
        return {"state": "failed"}
    flag = panel.get("tide_unavailable") if "tide_unavailable" in panel else None
    if "tide_unavailable" not in panel or flag is None:
        return {"state": "unknown"}
    if flag is True:
        return {"state": "unconfigured"}
    if flag is not False:
        return {"state": "unknown"}

    enabled = _field(panel, "enabled_rules")
    total = _field(panel, "total_rules")
    covered = _field(panel, "covered_techniques")
    techniques = _field(panel, "total_techniques")
    quality = panel.get("quality") if isinstance(panel.get("quality"), dict) else None
    if quality is None or "avg_quality" not in quality:
        avg = None
    else:
        avg = _digits(quality.get("avg_quality"))
    have_total = techniques is not None and techniques > 0 and covered is not None
    pct = round(covered / techniques * 100) if have_total else None
    bars = _severity_bars(panel.get("severity"))
    return {
        "state": "ready",
        "enabled": None if enabled is None else fmt_n(enabled),
        "total": None if total is None else fmt_n(total),
        "covered": None if covered is None else _digits(covered),
        "techniques": None if techniques is None else _digits(techniques),
        "have_total": have_total,
        "pct": pct,
        "avg": avg,
        "bars": bars,
    }


def _split_summary(text: object) -> Optional[dict]:
    """The paragraph and the bullets the model was asked to write.

    Whitespace-only is not a summary. The JavaScript checked ``trim()``
    and fell through to the stats sentence; so does this.
    """
    if not isinstance(text, str) or not text.strip():
        return None
    lines = [part.strip() for part in re.split(r"\r?\n", text) if part.strip()]
    bullet = re.compile(r"^[-•]\s+")
    bullets = [bullet.sub("", line) for line in lines if bullet.match(line)]
    paragraph = " ".join(line for line in lines if not bullet.match(line))
    return {"paragraph": paragraph, "bullets": bullets}


def _landscape(panel: Optional[dict]) -> dict:
    if panel is None:
        return {"state": "failed"}
    kind = panel.get("summary_kind")
    if kind == "ai":
        mode = "ai"
    elif kind == "stats":
        mode = "stats"
    else:
        mode = "unknown"
    summary = _split_summary(panel.get("summary"))
    stats = panel.get("stats") if isinstance(panel.get("stats"), dict) else None
    if stats is None:
        figures: dict[str, Any] = {"state": "unknown"}
    else:
        alerts = _field(stats, "alerts_24h_total")
        severity = stats.get("severity_24h") if "severity_24h" in stats else None
        if not isinstance(severity, dict):
            sev_text = None
            sev_known = False
        elif len(severity) == 0:
            sev_text = "no alerts"
            sev_known = True
        else:
            parts = []
            sev_known = True
            sev_text = None
            for key, value in severity.items():
                n = _num(value)
                if n is None:
                    sev_known = False
                    break
                label = plain(key)
                parts.append(f"{_digits(n)} {'' if label is None else label}")
            if sev_known:
                sev_text = ", ".join(parts)
        verdict = stats.get("verdict_7d") if "verdict_7d" in stats else None
        rate: Optional[str]
        if not isinstance(verdict, dict):
            rate = None
        elif len(verdict) == 0:
            # No verdicts is not a true-positive rate of zero.
            rate = None
        else:
            total = 0.0
            tp = 0.0
            rate = None
            ok = True
            for key, value in verdict.items():
                n = _num(value)
                if n is None:
                    ok = False
                    break
                total += n
                label = plain(key)
                if str(label).casefold() in ("true_positive", "malicious"):
                    tp += n
            if ok and total == 0:
                rate = None
            elif ok:
                rate = f"{round(tp / total * 100)}%"
        backlog = stats.get("open_backlog_sev") if "open_backlog_sev" in stats else None
        if not isinstance(backlog, dict):
            backlog_text = None
        elif len(backlog) == 0:
            backlog_text = "0"
        else:
            running = 0.0
            backlog_text = None
            ok = True
            for value in backlog.values():
                n = _num(value)
                if n is None:
                    ok = False
                    break
                running += n
            if ok:
                backlog_text = fmt_n(running)
        closures = stats.get("top_closures_7d") if "top_closures_7d" in stats else None
        closure_rows = None
        if isinstance(closures, list):
            closure_rows = []
            for row in closures:
                if not isinstance(row, dict):
                    continue
                reason = row.get("reason")
                count = _digits(row.get("count")) if "count" in row else None
                if reason is None or count is None:
                    continue
                closure_rows.append({"reason": str(reason), "count": count})
        figures = {
            "state": "ready",
            "alerts": None if alerts is None else fmt_n(alerts),
            "severity": sev_text,
            "severity_known": sev_known,
            "rate": rate,
            "backlog": backlog_text,
            "closures": closure_rows,
        }
    return {"state": "ready", "mode": mode, "summary": summary, "figures": figures}


def _attention(panel: Optional[dict], *, alerts_failed: bool, cases_failed: bool) -> dict:
    """The banner, without letting a failed constituent read say all clear.

    ``_compute_attention`` runs on whatever the collectors returned, and a
    collector that threw returned zeros. An all-clear computed from those
    zeros means the cases that would have turned it red were not counted.
    A warning or a critical the service did derive is kept: that is a
    positive finding, not the absence of one.
    """
    if panel is None:
        return {"state": "unknown", "why": "attention"}
    level = plain(panel.get("level"))
    level = str(level) if level is not None else ""
    if level not in ("ok", "warning", "critical"):
        return {"state": "unknown", "why": "attention"}
    if level == "ok" and (alerts_failed or cases_failed):
        why = "cases" if cases_failed else "alerts"
        if alerts_failed and cases_failed:
            why = "cases and alerts"
        return {"state": "unknown", "why": why}
    crit = _field(panel, "open_critical")
    high = _field(panel, "open_high")
    backlog = _field(panel, "open_alert_backlog")
    emphasis = None
    if not cases_failed:
        if crit is not None and crit > 0:
            emphasis = "critical"
        elif high is not None and high > 0:
            emphasis = "warning"
    headline = panel.get("headline")
    if not isinstance(headline, str) or not headline.strip():
        headline = "All clear" if level == "ok" else ""
    return {
        "state": level,
        "headline": headline,
        # Numbers, not pre-formatted strings. The template has to use
        # `is not none`: a string "0" is truthy, so it would hide the bug
        # where `{% if open_critical %}` drops a measured zero.
        "open_critical": crit,
        "open_high": high,
        "open_alert_backlog": backlog,
        "emphasis": emphasis,
    }


def _org(panel: Optional[dict]) -> dict:
    if panel is None:
        return {"state": "failed"}
    duty = panel.get("duty") if isinstance(panel.get("duty"), dict) else None
    assigned = duty.get("assigned") if duty and "assigned" in duty else None
    user = duty.get("user") if duty and isinstance(duty.get("user"), dict) else None
    name = user.get("name") if user else None
    if isinstance(name, str):
        name = name.strip() or None
    else:
        name = None
    if assigned is True and name:
        duty_state = "on"
        ack = duty.get("acknowledged") if duty and "acknowledged" in duty else None
    elif assigned is False:
        duty_state = "nobody"
        ack = None
    else:
        duty_state = "unknown"
        ack = None
    measured = panel.get("pillars_measured") if "pillars_measured" in panel else None
    worst = []
    for row in (panel.get("worst") or [])[:2]:
        if not isinstance(row, dict):
            continue
        gap = _digits(row.get("gap")) if "gap" in row else None
        role = row.get("role")
        if gap is None or role is None:
            continue
        worst.append({"role": str(role), "gap": gap})
    headline = panel.get("headline") if isinstance(panel.get("headline"), str) else None
    return {
        "state": "ready",
        "headline": headline,
        "duty_state": duty_state,
        "duty_name": name,
        "ack": ack,
        "leads": _field(panel, "leads_gapped"),
        "measured": measured,
        "uncovered": _field(panel, "pillars_uncovered"),
        "pillars_total": _field(panel, "pillars_total"),
        "self_rated": _field(panel, "pillars_self_rated"),
        "unfilled": _field(panel, "duty_unfilled_weeks"),
        "next_unfilled": panel.get("duty_next_unfilled"),
        "worst": worst,
    }


def _alerts(panel: Optional[dict]) -> dict:
    if panel is None:
        return {"failed": True}
    total = _field(panel, "last_24h_total")
    prev = _field(panel, "prev_24h_total")
    by_status = panel.get("by_status")

    def _shown(n: Optional[float]) -> Optional[str]:
        return None if n is None else fmt_n(n)

    return {
        "failed": False,
        "total": _shown(total),
        "open": _shown(_named_count(by_status, "open")),
        "ack": _shown(_named_count(by_status, "acknowledged")),
        "closed": _shown(_named_count(by_status, "closed")),
        "delta": _delta(total, prev, good_down=True),
        "spark": sparkline_paths(panel.get("histogram_24h")),
        "bars": _count_bars(panel.get("verdict_distribution_7d"), _VERDICTS),
    }


def _cases(panel: Optional[dict]) -> dict:
    if panel is None:
        return {"failed": True}
    by_status = panel.get("by_status")
    open_n = _named_count(by_status, "open")
    ack_n = _named_count(by_status, "acknowledged")
    if open_n is None or ack_n is None:
        open_total = None
    else:
        open_total = open_n + ack_n
    closures = _field(panel, "closures_24h_total")
    prev = _field(panel, "closures_prev_24h_total")
    return {
        "failed": False,
        "open": None if open_total is None else fmt_n(open_total),
        "closures": None if closures is None else fmt_n(closures),
        "delta": _delta(closures, prev, good_down=False),
        "spark": sparkline_paths(panel.get("closures_history_7d")),
        "bars": _count_bars(
            panel.get("open_by_severity"),
            tuple((key, key, cls) for key, cls in _SEVERITIES),
        ),
    }


def _bob(panel: Optional[dict]) -> dict:
    if panel is None:
        return {"failed": True}
    recent = _field(panel, "investigations_24h")
    prev = _field(panel, "investigations_prev_24h")
    pct = panel.get("agreement_pct") if "agreement_pct" in panel else None
    pct_n = _num(pct) if pct is not None else None
    if pct_n is None:
        agreement = "— / —"
        width = 0
    else:
        count = _field(panel, "agreement_count")
        total = _field(panel, "agreement_total")
        agreement = (
            f"{'—' if count is None else fmt_n(count)} / "
            f"{'—' if total is None else fmt_n(total)} ({fmt_n(pct_n)}%)"
        )
        width = max(0, min(100, int(round(pct_n))))
    investigated = _field(panel, "investigations_total")
    feedback = _field(panel, "feedback_7d_total")
    return {
        "failed": False,
        "recent": None if recent is None else fmt_n(recent),
        "investigated": None if investigated is None else fmt_n(investigated),
        "feedback": None if feedback is None else fmt_n(feedback),
        "delta": _delta(recent, prev, good_down=False),
        "spark": sparkline_paths(panel.get("history_7d")),
        "agreement": agreement,
        "agreement_width": width,
    }


def present_snapshot(snapshot: object) -> dict[str, Any]:
    """The snapshot as the template's context.

    A top-level ``error`` is the gather itself failing with nothing cached.
    There are no panels on that object. Rendering the missing ones as zero
    would publish a calm estate at the moment ION could not read one.
    """
    if not isinstance(snapshot, dict) or snapshot.get("error"):
        return {
            "failed": True,
            "stale": False,
            "age": None,
            "topology": {"failed": True},
        }
    alerts_panel = _panel(snapshot, "alerts")
    cases_panel = _panel(snapshot, "cases")
    topology = _topology(_panel(snapshot, "topology"))
    age = fmt_age(snapshot.get("cache_age_seconds")) if "cache_age_seconds" in snapshot else None
    return {
        "failed": False,
        "stale": bool(snapshot.get("stale_due_to_error")),
        "age": age,
        "attention": _attention(
            _panel(snapshot, "attention"),
            alerts_failed=alerts_panel is None,
            cases_failed=cases_panel is None,
        ),
        "alerts": _alerts(alerts_panel),
        "cases": _cases(cases_panel),
        "bob": _bob(_panel(snapshot, "bob")),
        "rules": _rules(_panel(snapshot, "rules")),
        "topology": topology,
        "landscape": _landscape(_panel(snapshot, "threat_landscape")),
        "org": _org(_panel(snapshot, "org")),
    }


@router.get(
    "/wallboard",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def wallboard_fragment(
    request: Request,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The board as one fragment.

    Calls ``get_snapshot`` with no ``force``. The JSON GET does the same,
    so a wall that polls this every five minutes hits the cache instead of
    starting a second gather. ``POST /api/wallboard/refresh`` is the force.
    """
    from ion.services.wallboard_service import get_snapshot

    try:
        # force stays false. The page used to poll the cached GET, and a
        # fragment that forced would recompute on every wall on every tick.
        snapshot = get_snapshot(session)
    except Exception:
        logger.exception("Wallboard fragment could not be rendered")
        snapshot = {"error": "unreadable"}
    return templates.TemplateResponse(
        request=request,
        name="_fragments/wallboard.html",
        context=present_snapshot(snapshot),
    )
