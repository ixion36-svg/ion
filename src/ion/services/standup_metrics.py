"""Seven-day SOC metrics for the daily standup.

Alert volume and response times come from Elasticsearch; case throughput,
outcomes and the per-analyst table come from ION's own tables. Every figure
is "this week" (the last 7 days) beside "last week" (the 7 days before), so
the standup reads change rather than a bare number.

The arithmetic is in pure functions at the top so it can be tested without
a cluster; the two readers at the bottom only fetch.

Definitions, so the standup and anyone auditing it agree:
  MTTA (alerts)  alert @timestamp -> kibana.alert.workflow_status_updated_at,
                 for alerts that left "open". That field holds the latest
                 status change, so an alert acknowledged and later closed
                 counts its close time: MTTA is an upper bound.
  MTTR (alerts)  the same span, for alerts now closed.
  MTTR (cases)   case created_at -> closed_at.
  Spike          a day of the last 7 with at least SPIKE_MIN alerts and at
                 least SPIKE_RATIO x the median of the 7 days before it.
  FP rate        false-positive closures / all verdict closures (TP, benign
                 TP, FP) of cases closed in the window.
  Escalation     alerts placed in cases created in the window / alerts
                 raised in the window.
"""

from __future__ import annotations

import logging
import re
import statistics
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

SEVERITIES = ("critical", "high", "medium", "low")
SPIKE_MIN = 5
SPIKE_RATIO = 2.0
TOP_N = 5
# The standup runs every check at once; these three reads must not lose
# to the cluster being busy with the others.
ES_TIMEOUT_S = 60
VERDICT_REASONS = ("true_positive", "benign_true_positive", "false_positive")

# Kibana alerts and ION's own alert index name these differently.
_SEV_FIELDS = ("kibana.alert.severity", "severity", "event.severity")
_RULE_FIELDS = ("kibana.alert.rule.name", "rule.name")
_STATUS_FIELDS = ("kibana.alert.workflow_status", "status")
_CLOSED_AS = re.compile(r"\A\*\*Alert closed as (?P<label>[^*\n]+)\*\*")
_NOTE_VERDICT = {"escalated": "true_positive", "benign": "benign_true_positive",
                 "false positive": "false_positive"}


# ── pure arithmetic ─────────────────────────────────────────────────────────

def change(this: Optional[float], last: Optional[float]) -> Dict[str, Any]:
    """This week beside last week, with the difference and the percentage."""
    if this is None or last is None:
        return {"this": this, "last": last, "delta": None, "pct": None}
    delta = this - last
    pct = round(delta / last * 100, 1) if last else None
    return {"this": this, "last": last, "delta": round(delta, 2), "pct": pct}


def spread(values: Iterable[float]) -> Dict[str, Optional[float]]:
    """Mean, median and p90 of a list, None when it is empty."""
    v = sorted(x for x in values if x is not None and x >= 0)
    if not v:
        return {"n": 0, "mean": None, "median": None, "p90": None}
    return {
        "n": len(v),
        "mean": round(sum(v) / len(v), 1),
        "median": round(statistics.median(v), 1),
        "p90": round(v[min(len(v) - 1, int(len(v) * 0.9))], 1),
    }


def find_spikes(daily: List[Dict[str, Any]], days: int = 7) -> List[Dict[str, Any]]:
    """Days of the last `days` well above the median of the week before each.

    `daily` is oldest -> newest, one row per day with a `total`.
    """
    out = []
    for i in range(max(days, len(daily) - days), len(daily)):
        before = [d["total"] for d in daily[max(0, i - 7):i]]
        if len(before) < 3:
            continue
        base = statistics.median(before)
        count = daily[i]["total"]
        if count >= SPIKE_MIN and count >= SPIKE_RATIO * max(base, 1):
            out.append({"date": daily[i]["date"], "count": count, "baseline": base,
                        "ratio": round(count / max(base, 1), 1)})
    return out


def movers(this: Dict[str, int], last: Dict[str, int], n: int = TOP_N) -> Dict[str, List[dict]]:
    """Top names this week, the biggest risers, and names new this week."""
    top = sorted(this.items(), key=lambda kv: (-kv[1], kv[0]))[:n]
    rising = sorted(((k, v - last.get(k, 0)) for k, v in this.items()),
                    key=lambda kv: (-kv[1], kv[0]))
    return {
        "top": [{"name": k, "count": v, "last": last.get(k, 0)} for k, v in top],
        "rising": [{"name": k, "count": this[k], "last": last.get(k, 0), "delta": d}
                   for k, d in rising if d > 0][:n],
        "new": sorted(k for k in this if k not in last)[:n],
    }


def daily_rows(buckets: List[dict], today: date) -> List[Dict[str, Any]]:
    """ES day buckets -> 14 rows oldest -> newest, zero-filled."""
    by_day: Dict[str, dict] = {}
    for b in buckets:
        key = str(b.get("key_as_string", ""))[:10]
        sev = {s: int(((b.get("sev") or {}).get("buckets") or {}).get(s, {}).get("doc_count", 0))
               for s in SEVERITIES}
        by_day[key] = {"total": int(b.get("doc_count", 0)), "severity": sev}
    rows = []
    for back in range(13, -1, -1):
        d = (today - timedelta(days=back)).isoformat()
        row = by_day.get(d, {"total": 0, "severity": {s: 0 for s in SEVERITIES}})
        rows.append({"date": d, **row})
    return rows


def _hours(start: Any, end: Any) -> Optional[float]:
    if not start or not end:
        return None
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    h = (end - start).total_seconds() / 3600
    return h if h >= 0 else None


# Minutes from an alert being raised to its last status change. Computed in
# Elasticsearch so every alert counts, not a page of hits.
RT_SCRIPT = (
    "def u = 'kibana.alert.workflow_status_updated_at';"
    "if (doc.containsKey(u) && doc[u].size() > 0 && doc['@timestamp'].size() > 0) {"
    " long d = doc[u].value.toInstant().toEpochMilli() - doc['@timestamp'].value.toInstant().toEpochMilli();"
    " if (d >= 0) { emit(d / 60000.0); } }"
)
_RT_STATS = {
    "n": {"value_count": {"field": "rt_minutes"}},
    "mean": {"avg": {"field": "rt_minutes"}},
    "pct": {"percentiles": {"field": "rt_minutes", "percents": [50, 90]}},
}


def rt_stats(agg: Any) -> Dict[str, Optional[float]]:
    """A {n, mean, median, p90} from one response-time sub-aggregation."""
    agg = agg if isinstance(agg, dict) else {}
    n = int(((agg.get("n") or {}).get("value")) or 0)
    if not n:
        return {"n": 0, "mean": None, "median": None, "p90": None}
    pct = ((agg.get("pct") or {}).get("values")) or {}

    def r(v):
        return None if v is None else round(float(v), 1)
    return {"n": n, "mean": r((agg.get("mean") or {}).get("value")),
            "median": r(pct.get("50.0")), "p90": r(pct.get("90.0"))}


# ── Elasticsearch ───────────────────────────────────────────────────────────

def _any_term(field_values: Iterable[tuple]) -> dict:
    return {"bool": {"should": [{"term": {f: v}} for f, v in field_values], "minimum_should_match": 1}}


def _sev_filters() -> dict:
    return {"filters": {"filters": {s: _any_term((f, s) for f in _SEV_FIELDS) for s in SEVERITIES}}}


def _week_aggs() -> dict:
    aggs = {"sev": _sev_filters(), "host": {"terms": {"field": "host.name", "size": 50}}}
    for i, f in enumerate(_RULE_FIELDS):
        aggs[f"rule{i}"] = {"terms": {"field": f, "size": 100}}
    return aggs


def _terms(agg: dict) -> Dict[str, int]:
    return {str(b["key"]): int(b["doc_count"]) for b in (agg or {}).get("buckets", [])}


async def read_alert_metrics(es: Any, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Volume, trend, spikes, movers, backlog and response times, from ES."""
    now = now or datetime.now(timezone.utc)
    not_bb = [{"exists": {"field": "kibana.alert.building_block_type"}}]
    closed = _any_term((f, "closed") for f in _STATUS_FIELDS)
    body = {
        "size": 0,
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": "now-14d/d", "lte": "now"}}}],
                           "must_not": not_bb}},
        "aggs": {
            "daily": {
                "date_histogram": {"field": "@timestamp", "calendar_interval": "day",
                                   "format": "yyyy-MM-dd", "min_doc_count": 0},
                "aggs": {"sev": _sev_filters()},
            },
            "weeks": {
                "range": {"field": "@timestamp", "ranges": [
                    {"key": "last", "from": "now-14d", "to": "now-7d"},
                    {"key": "this", "from": "now-7d", "to": "now"}]},
                "aggs": _week_aggs(),
            },
        },
    }
    result = await es._request("POST", f"/{es.alert_index}/_search", json=body, timeout=ES_TIMEOUT_S)
    aggs = result.get("aggregations") or {}
    daily = daily_rows((aggs.get("daily") or {}).get("buckets", []), now.date())

    weeks = {b["key"]: b for b in (aggs.get("weeks") or {}).get("buckets", [])}
    week = {}
    for key in ("this", "last"):
        b = weeks.get(key, {})
        rules: Counter = Counter()
        for i in range(len(_RULE_FIELDS)):
            rules.update(_terms(b.get(f"rule{i}")))
        week[key] = {
            "total": int(b.get("doc_count", 0)),
            "severity": {s: int(((b.get("sev") or {}).get("buckets") or {}).get(s, {}).get("doc_count", 0))
                         for s in SEVERITIES},
            "rules": dict(rules),
            "hosts": _terms(b.get("host")),
        }

    backlog_body = {
        "size": 0,
        "query": {"bool": {"must_not": not_bb + [closed] + [_any_term((f, "acknowledged") for f in _STATUS_FIELDS)],
                           "filter": [{"range": {"@timestamp": {"gte": "now-90d"}}}]}},
        "aggs": {"age": {"range": {"field": "@timestamp", "ranges": [
            {"key": "under_24h", "from": "now-24h"},
            {"key": "1_7d", "from": "now-7d", "to": "now-24h"},
            {"key": "over_7d", "to": "now-7d"}]}}},
    }
    backlog = await es._request("POST", f"/{es.alert_index}/_search", json=backlog_body, timeout=ES_TIMEOUT_S)
    ages = {b["key"]: int(b["doc_count"]) for b in ((backlog.get("aggregations") or {}).get("age") or {}).get("buckets", [])}

    rt_body = {
        "size": 0,
        "runtime_mappings": {"rt_minutes": {"type": "double", "script": {"source": RT_SCRIPT}}},
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": "now-14d"}}}],
                           "must_not": not_bb + [{"term": {"kibana.alert.workflow_status": "open"}}]}},
        "aggs": {"weeks": {
            "range": {"field": "@timestamp", "ranges": [
                {"key": "last", "from": "now-14d", "to": "now-7d"}, {"key": "this", "from": "now-7d"}]},
            "aggs": {"ack": {"filter": {"match_all": {}}, "aggs": _RT_STATS},
                     "closed": {"filter": {"term": {"kibana.alert.workflow_status": "closed"}},
                                "aggs": _RT_STATS}},
        }},
    }
    rt = await es._request("POST", f"/{es.alert_index}/_search", json=rt_body, timeout=ES_TIMEOUT_S)
    rt_weeks = {b["key"]: b for b in ((rt.get("aggregations") or {}).get("weeks") or {}).get("buckets", [])}
    this_rt = {"mtta": rt_stats(rt_weeks.get("this", {}).get("ack")),
               "mttr": rt_stats(rt_weeks.get("this", {}).get("closed"))}
    last_rt = {"mtta": rt_stats(rt_weeks.get("last", {}).get("ack")),
               "mttr": rt_stats(rt_weeks.get("last", {}).get("closed"))}

    return {
        "daily": daily[-7:],
        "total": change(week["this"]["total"], week["last"]["total"]),
        "severity": {s: change(week["this"]["severity"][s], week["last"]["severity"][s]) for s in SEVERITIES},
        "daily_avg": change(round(week["this"]["total"] / 7, 1), round(week["last"]["total"] / 7, 1)),
        "peak": max(daily[-7:], key=lambda d: d["total"]) if daily else None,
        "spikes": find_spikes(daily),
        "rules": movers(week["this"]["rules"], week["last"]["rules"]),
        "hosts": movers(week["this"]["hosts"], week["last"]["hosts"]),
        "backlog": {"total": sum(ages.values()), **ages},
        "mtta_minutes": {k: change(this_rt["mtta"][k], last_rt["mtta"][k]) for k in ("median", "mean", "p90")},
        "mttr_minutes": {k: change(this_rt["mttr"][k], last_rt["mttr"][k]) for k in ("median", "mean", "p90")},
        "responded": change(this_rt["mtta"]["n"], last_rt["mtta"]["n"]),
        "_week_totals": {"this": week["this"]["total"], "last": week["last"]["total"]},
    }


# ── ION's tables ────────────────────────────────────────────────────────────

def _verdict_mix(reasons: Iterable[Optional[str]]) -> Dict[str, Any]:
    c = Counter(r for r in reasons if r)
    verdicts = sum(c[r] for r in VERDICT_REASONS)
    return {
        "counts": dict(c),
        "verdicts": verdicts,
        "tp_rate": round(c["true_positive"] / verdicts * 100, 1) if verdicts else None,
        "btp_rate": round(c["benign_true_positive"] / verdicts * 100, 1) if verdicts else None,
        "fp_rate": round(c["false_positive"] / verdicts * 100, 1) if verdicts else None,
    }


def read_case_and_analyst_metrics(session: Any, alerts_this_week: Optional[int] = None,
                                  alerts_last_week: Optional[int] = None,
                                  now: Optional[datetime] = None) -> Dict[str, Any]:
    """Case throughput, outcomes, escalation and the per-analyst table."""
    from ion.models.alert_triage import AlertCase, AlertCaseStatus, Note, NoteEntityType
    from ion.models.user import User

    now = (now or datetime.now(timezone.utc)).replace(tzinfo=None)
    this_from, last_from = now - timedelta(days=7), now - timedelta(days=14)

    recent = session.query(AlertCase).filter(
        (AlertCase.created_at >= last_from) | (AlertCase.closed_at >= last_from)).all()
    open_now = session.query(AlertCase).filter(AlertCase.status != AlertCaseStatus.CLOSED).all()

    def opened(lo, hi):
        return [c for c in recent if c.created_at and lo <= c.created_at < hi]

    def closed_in(lo, hi):
        return [c for c in recent if c.closed_at and lo <= c.closed_at < hi]

    weeks = {"this": (this_from, now + timedelta(seconds=1)), "last": (last_from, this_from)}
    per_week = {}
    for key, (lo, hi) in weeks.items():
        made, done = opened(lo, hi), closed_in(lo, hi)
        per_week[key] = {
            "opened": len(made),
            "closed": len(done),
            "mttr": spread(_hours(c.created_at, c.closed_at) for c in done),
            "mix": _verdict_mix(c.closure_reason for c in done),
            "escalated_alerts": sum(len(c.source_alert_ids or []) for c in made),
        }

    def escalation(key, alerts):
        if not alerts:
            return None
        return round(per_week[key]["escalated_alerts"] / alerts * 100, 1)

    # Per analyst, this week.
    names = {u.id: (u.display_name or u.username) for u in session.query(User).all()}
    rows: Dict[int, Dict[str, Any]] = defaultdict(lambda: {
        "cases_closed": 0, "cases_opened": 0, "open_assigned": 0, "alert_verdicts": Counter(),
        "case_verdicts": Counter(), "_mttr": []})
    for c in opened(this_from, now + timedelta(seconds=1)):
        if c.created_by_id:
            rows[c.created_by_id]["cases_opened"] += 1
    for c in closed_in(this_from, now + timedelta(seconds=1)):
        who = c.closed_by_id or c.assigned_to_id
        if not who:
            continue
        rows[who]["cases_closed"] += 1
        if c.closure_reason:
            rows[who]["case_verdicts"][c.closure_reason] += 1
        h = _hours(c.created_at, c.closed_at)
        if h is not None:
            rows[who]["_mttr"].append(h)
    for c in open_now:
        if c.assigned_to_id:
            rows[c.assigned_to_id]["open_assigned"] += 1
    notes = session.query(Note.user_id, Note.content).filter(
        Note.entity_type == NoteEntityType.CASE, Note.created_at >= this_from).all()
    for uid, content in notes:
        m = _CLOSED_AS.match(content or "")
        if uid and m:
            verdict = _NOTE_VERDICT.get(m.group("label").strip().lower())
            if verdict:
                rows[uid]["alert_verdicts"][verdict] += 1

    analysts = []
    for uid, r in rows.items():
        name = names.get(uid)
        if not name:
            continue
        alerts_marked = sum(r["alert_verdicts"].values())
        mix = _verdict_mix(list(r["case_verdicts"].elements()) + list(r["alert_verdicts"].elements()))
        analysts.append({
            "name": name,
            "cases_closed": r["cases_closed"],
            "cases_opened": r["cases_opened"],
            "open_assigned": r["open_assigned"],
            "alerts_marked": alerts_marked,
            "mttr_hours": spread(r["_mttr"])["median"],
            "tp_rate": mix["tp_rate"],
            "fp_rate": mix["fp_rate"],
        })
    analysts.sort(key=lambda a: (-(a["cases_closed"] + a["alerts_marked"]), -a["open_assigned"], a["name"]))

    unassigned = sum(1 for c in open_now if not c.assigned_to_id)
    ages = [_hours(c.created_at, now) for c in open_now]
    return {
        "opened": change(per_week["this"]["opened"], per_week["last"]["opened"]),
        "closed": change(per_week["this"]["closed"], per_week["last"]["closed"]),
        "mttr_hours": {k: change(per_week["this"]["mttr"][k], per_week["last"]["mttr"][k])
                       for k in ("median", "mean", "p90")},
        "outcomes": per_week["this"]["mix"],
        "fp_rate": change(per_week["this"]["mix"]["fp_rate"], per_week["last"]["mix"]["fp_rate"]),
        "tp_rate": change(per_week["this"]["mix"]["tp_rate"], per_week["last"]["mix"]["tp_rate"]),
        "escalation_rate": change(escalation("this", alerts_this_week), escalation("last", alerts_last_week)),
        "open_now": len(open_now),
        "unassigned_now": unassigned,
        "open_over_7d": sum(1 for a in ages if a is not None and a > 24 * 7),
        "analysts": analysts,
    }
