"""Daily SOC Standup API — aggregates health checks, alerts, cases, and log monitoring."""

import asyncio
import logging
import json
import os
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/daily-standup", tags=["daily-standup"])


# ── Log-source health config (v0.10.18) ───────────────────────────────────
#
# The DC/WEF checks were originally hard-coded to query winlogbeat-* for
# host.hostname.keyword matching the literal substrings DCS / WEF. Real
# deployments name their hosts differently (e.g. `corp-dc-01`, `evtfwd-prd`)
# AND store events in different indices (`logs-windows.*-`, `filebeat-*`,
# custom data streams). These four env vars let operators point the checks
# at their actual data without code edits.
#
# All defaults preserve v0.10.17 behaviour exactly.

def _parse_patterns(raw: str) -> List[str]:
    """Split comma- or whitespace-separated patterns, drop blanks."""
    if not raw:
        return []
    parts: List[str] = []
    for chunk in raw.replace(";", ",").split(","):
        for sub in chunk.strip().split():
            s = sub.strip()
            if s:
                parts.append(s)
    return parts


def _standup_log_index() -> str:
    return os.environ.get("ION_STANDUP_LOG_INDEX", "winlogbeat-*").strip() or "winlogbeat-*"


def _standup_host_field() -> str:
    return (
        os.environ.get("ION_STANDUP_HOST_FIELD", "host.hostname.keyword").strip()
        or "host.hostname.keyword"
    )


def _standup_dcs_patterns() -> List[str]:
    return _parse_patterns(os.environ.get("ION_STANDUP_DCS_HOSTS", "*DCS*"))


def _standup_wef_patterns() -> List[str]:
    return _parse_patterns(os.environ.get("ION_STANDUP_WEF_HOSTS", "*WEF*"))


# ── Internal check helpers ────────────────────────────────────────────────


async def _check_cluster_health() -> Dict[str, Any]:
    """ES cluster health + stats."""
    from ion.services.elasticsearch_service import ElasticsearchService
    import httpx

    es = ElasticsearchService()
    if not es.is_configured:
        return {"status": "not_configured"}
    try:
        # Use a dedicated client to avoid event-loop-closed errors from shared pool
        result = await es._request("GET", "/_cluster/health")
        try:
            stats = await es._request("GET", "/_cluster/stats")
        except Exception:
            stats = {"indices": {}}
        return {
            "status": result.get("status"),  # green/yellow/red
            "number_of_nodes": result.get("number_of_nodes"),
            "active_shards": result.get("active_shards"),
            "relocating_shards": result.get("relocating_shards"),
            "unassigned_shards": result.get("unassigned_shards"),
            "indices_count": stats.get("indices", {}).get("count", 0),
            "docs_count": stats.get("indices", {}).get("docs", {}).get("count", 0),
            "store_size": stats.get("indices", {}).get("store", {}).get("size_in_bytes", 0),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)[:100]}


async def _check_critical_alerts() -> Dict[str, Any]:
    """Critical + high alerts in the last 24 h."""
    from ion.services.elasticsearch_service import ElasticsearchService

    es = ElasticsearchService()
    if not es.is_configured:
        return {"total": 0, "alerts": []}
    try:
        alerts = await es.get_alerts(hours=24, severity="critical", limit=50)
        high_alerts = await es.get_alerts(hours=24, severity="high", limit=50)
        all_alerts = alerts + high_alerts
        return {
            "critical_count": len(alerts),
            "high_count": len(high_alerts),
            "total": len(all_alerts),
            "alerts": [
                {
                    "id": a.id,
                    "title": a.title,
                    "severity": a.severity,
                    "status": a.status,
                    "host": a.host,
                    "timestamp": a.timestamp.isoformat(),
                    "rule_name": a.rule_name,
                }
                for a in sorted(all_alerts, key=lambda x: x.timestamp, reverse=True)[:20]
            ],
        }
    except Exception as e:
        return {"total": 0, "error": str(e)[:100]}


async def _check_stale_cases() -> Dict[str, Any]:
    """Open / acknowledged cases older than 24 h."""
    from ion.core.config import get_config
    from ion.storage.database import get_engine, get_session_factory
    from ion.models.alert_triage import AlertCase, AlertCaseStatus

    config = get_config()
    engine = get_engine(config.db_path)
    factory = get_session_factory(engine)
    session = factory()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        # Strip timezone for comparison with naive DB timestamps
        cutoff_naive = cutoff.replace(tzinfo=None)
        stale = (
            session.query(AlertCase)
            .filter(
                AlertCase.status.in_([AlertCaseStatus.OPEN, AlertCaseStatus.ACKNOWLEDGED]),
                AlertCase.created_at < cutoff_naive,
            )
            .order_by(AlertCase.created_at.asc())
            .limit(20)
            .all()
        )
        return {
            "count": len(stale),
            "cases": [
                {
                    "id": c.id,
                    "case_number": c.case_number,
                    "title": c.title,
                    "severity": c.severity,
                    "status": c.status.value if hasattr(c.status, "value") else str(c.status),
                    "created_at": c.created_at.isoformat() if c.created_at else None,
                    "assigned_to": (
                        (c.assigned_to.display_name or c.assigned_to.username)
                        if c.assigned_to
                        else "Unassigned"
                    ),
                    "hours_open": (
                        round((datetime.utcnow() - c.created_at).total_seconds() / 3600)
                        if c.created_at
                        else 0
                    ),
                }
                for c in stale
            ],
        }
    finally:
        session.close()


async def _check_log_source_health(
    patterns: List[str],
    label: str,
    *,
    index: Optional[str] = None,
    host_field: Optional[str] = None,
) -> Dict[str, Any]:
    """Check `index` for hosts matching any of `patterns`, compare to 7-day average, find gaps.

    v0.10.18: ``patterns`` is now a list (multiple wildcards OR'd together)
    and ``index`` + ``host_field`` are configurable. Returns a ``diag``
    block in the response so the UI can show ``Queried X for Y → N hosts``
    when nothing comes back — the v0.10.17 silent-empty masked field-name
    and index mismatches.
    """
    from ion.services.elasticsearch_service import ElasticsearchService

    index = index or _standup_log_index()
    host_field = host_field or _standup_host_field()
    diag: Dict[str, Any] = {
        "index": index,
        "host_field": host_field,
        "patterns": list(patterns),
        "total_hits": 0,
        "host_count": 0,
    }

    es = ElasticsearchService()
    if not es.is_configured:
        return {"label": label, "status": "not_configured", "diag": diag}

    if not patterns:
        return {
            "label": label,
            "status": "not_configured",
            "error": f"No host patterns configured (set ION_STANDUP_DCS_HOSTS / ION_STANDUP_WEF_HOSTS)",
            "diag": diag,
        }

    # Build a `should`-clause across all supplied patterns. minimum_should_match=1
    # means ANY pattern hit qualifies — operators can safely list "*DCS*", "*DC*"
    # without one swallowing the other.
    should_clauses = [{"wildcard": {host_field: p}} for p in patterns]

    try:
        # Last 24 h event count per host matching pattern
        # v0.15.1: terms.size dropped 500→100. WEF estates rarely have
        # >100 forwarders in scope, and the 500-host fan-out (×24 hourly
        # buckets) was the dominant cost causing timeouts on busy estates.
        # Operators with more hosts than that can override via
        # ION_STANDUP_TERMS_SIZE.
        try:
            terms_size = int(os.environ.get("ION_STANDUP_TERMS_SIZE", "100"))
        except Exception:
            terms_size = 100
        # v0.15.1: heavy aggregations get a 60 s per-request timeout
        # (vs the 30 s ION_ES_TIMEOUT default). Without this override the
        # WEF check on a busy estate raced the global default and timed
        # out before ES could finish the rollup.
        body_24h = {
            "size": 0,
            "query": {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1,
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
                    ],
                }
            },
            "aggs": {
                "hosts": {
                    "terms": {"field": host_field, "size": terms_size},
                    "aggs": {
                        "hourly": {
                            "date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}
                        }
                    },
                }
            },
        }
        result_24h = await es._request(
            "POST", f"/{index}/_search?ignore_unavailable=true",
            json=body_24h, timeout=60.0,
        )

        # 7-day average for comparison
        body_7d = {
            "size": 0,
            "query": {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1,
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-7d", "lte": "now"}}},
                    ],
                }
            },
            "aggs": {
                "hosts": {
                    "terms": {"field": host_field, "size": terms_size},
                }
            },
        }
        result_7d = await es._request(
            "POST", f"/{index}/_search?ignore_unavailable=true",
            json=body_7d, timeout=60.0,
        )

        hosts_24h: Dict[str, Dict[str, Any]] = {}
        gaps: List[Dict[str, Any]] = []
        for bucket in result_24h.get("aggregations", {}).get("hosts", {}).get("buckets", []):
            hostname = bucket["key"]
            count = bucket["doc_count"]
            hourly = bucket.get("hourly", {}).get("buckets", [])
            gap_hours = [h["key_as_string"] for h in hourly if h["doc_count"] == 0]
            hosts_24h[hostname] = {"count_24h": count, "gap_hours": gap_hours}
            if gap_hours:
                gaps.append({"host": hostname, "gap_count": len(gap_hours), "gaps": gap_hours[:5]})

        # 7-day daily averages
        hosts_7d: Dict[str, float] = {}
        for bucket in result_7d.get("aggregations", {}).get("hosts", {}).get("buckets", []):
            hosts_7d[bucket["key"]] = bucket["doc_count"] / 7

        # Per-host summary
        host_summaries: List[Dict[str, Any]] = []
        for hostname, data in sorted(hosts_24h.items()):
            avg_7d = hosts_7d.get(hostname, 0)
            count_24h = data["count_24h"]
            below_avg = count_24h < (avg_7d * 0.7) if avg_7d > 0 else False
            host_summaries.append(
                {
                    "hostname": hostname,
                    "count_24h": count_24h,
                    "avg_7d": round(avg_7d),
                    "below_average": below_avg,
                    "gap_hours": len(data["gap_hours"]),
                    "status": (
                        "critical"
                        if len(data["gap_hours"]) > 4
                        else "warning"
                        if len(data["gap_hours"]) > 0 or below_avg
                        else "ok"
                    ),
                }
            )

        total_24h = result_24h.get("hits", {}).get("total", {}).get("value", 0)
        diag["total_hits"] = total_24h
        diag["host_count"] = len(hosts_24h)
        return {
            "label": label,
            "status": "ok",
            "total_events_24h": total_24h,
            "host_count": len(hosts_24h),
            "hosts_with_gaps": len(gaps),
            "hosts_below_average": sum(1 for h in host_summaries if h["below_average"]),
            "hosts": sorted(host_summaries, key=lambda h: h["status"] != "ok", reverse=True),
            "gaps": gaps,
            "diag": diag,
        }
    except Exception as e:
        # type(e).__name__ in the message so connection-vs-auth-vs-query
        # failures are distinguishable in the UI banner.
        return {
            "label": label,
            "status": "error",
            "error": f"{type(e).__name__}: {str(e)[:180]}",
            "diag": diag,
        }


async def _check_rule_failures() -> Dict[str, Any]:
    """Detection rules that failed execution in the last 24 h.

    Tries multiple index patterns since Kibana versions store execution
    logs differently:
    - .kibana-event-log-* (older Kibana)
    - .internal.alerts-* with execution status fields
    - .kibana-alerting-* (some 8.x versions)
    """
    from ion.services.elasticsearch_service import ElasticsearchService

    es = ElasticsearchService()
    if not es.is_configured:
        return {"count": 0, "rules": []}

    # Try multiple approaches for rule failure detection
    rules: List[Dict[str, Any]] = []

    # Approach 1: Kibana event log
    indices_to_try = [
        ".kibana-event-log-*",
        ".internal.kibana-event-log-*",
    ]
    fields_to_try = [
        "kibana.alert.rule.execution.metrics.execution_status",
        "event.outcome",
    ]

    for index in indices_to_try:
        if rules:
            break
        for status_field in fields_to_try:
            if rules:
                break
            try:
                body = {
                    "size": 0,
                    "query": {
                        "bool": {
                            "must": [
                                {"range": {"@timestamp": {"gte": "now-24h"}}},
                                {"term": {status_field: "failure"}},
                            ]
                        }
                    },
                    "aggs": {
                        "rules": {
                            "terms": {
                                "field": "rule.name",
                                "size": 20,
                                "missing": "unknown",
                            },
                            "aggs": {
                                "last_failure": {"max": {"field": "@timestamp"}},
                            },
                        }
                    },
                }
                result = await es._request(
                    "POST", f"/{index}/_search?ignore_unavailable=true", json=body
                )
                for bucket in result.get("aggregations", {}).get("rules", {}).get("buckets", []):
                    rules.append({
                        "rule_name": bucket["key"],
                        "failure_count": bucket["doc_count"],
                        "last_failure": bucket.get("last_failure", {}).get("value_as_string"),
                    })
            except Exception:
                continue

    return {"count": len(rules), "rules": rules}


# ── Endpoints ─────────────────────────────────────────────────────────────


@router.get("/checks")
async def get_daily_checks(
    current_user: User = Depends(require_permission("alert:read")),
):
    """Aggregate all daily SOC duty checks in a single call."""
    cluster, alerts, cases, dc_health, wef_health, rule_failures = await asyncio.gather(
        _check_cluster_health(),
        _check_critical_alerts(),
        _check_stale_cases(),
        _check_log_source_health(_standup_dcs_patterns(), "Domain Controllers"),
        _check_log_source_health(_standup_wef_patterns(), "Windows Event Forwarding"),
        _check_rule_failures(),
        return_exceptions=True,
    )

    def _safe(val: Any) -> Any:
        if isinstance(val, Exception):
            return {"error": str(val)[:100]}
        return val

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cluster_health": _safe(cluster),
        "critical_alerts": _safe(alerts),
        "stale_cases": _safe(cases),
        "dc_log_health": _safe(dc_health),
        "wef_log_health": _safe(wef_health),
        "rule_failures": _safe(rule_failures),
    }


# ── Save standup ──────────────────────────────────────────────────────────


class StandupSaveRequest(BaseModel):
    servicenow_notes: str = ""
    meeting_notes: str = ""
    additional_notes: str = ""
    analyst_name: str = ""
    signed_off: bool = False
    checks_data: dict = Field(default_factory=dict)
    ai_summary: str = ""
    reports_of_interest: list = Field(default_factory=list)


@router.post("/save")
async def save_daily_standup(
    data: StandupSaveRequest,
    current_user: User = Depends(require_permission("alert:read")),
):
    """Save the daily standup report as a document."""
    from ion.core.config import get_config
    from ion.storage.database import get_engine, get_session_factory
    from ion.models.document import Document

    config = get_config()
    engine = get_engine(config.db_path)
    factory = get_session_factory(engine)
    session = factory()

    try:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        doc = Document(
            name=f"Daily Standup \u2014 {today}",
            rendered_content=json.dumps(
                {
                    "date": today,
                    "analyst": data.analyst_name or current_user.display_name or current_user.username,
                    "signed_off": data.signed_off,
                    "servicenow_notes": data.servicenow_notes,
                    "meeting_notes": data.meeting_notes,
                    "additional_notes": data.additional_notes,
                    "checks_data": data.checks_data,
                    "ai_summary": data.ai_summary,
                    "reports_of_interest": data.reports_of_interest,
                },
                default=str,
            ),
            status="active",
            output_format="json",
        )
        session.add(doc)
        session.commit()
        return {"ok": True, "document_id": doc.id, "name": doc.name}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


# ── PDF export ────────────────────────────────────────────────────────────


@router.post("/pdf")
async def export_standup_pdf(
    data: StandupSaveRequest,
    current_user: User = Depends(require_permission("alert:read")),
):
    """Export the daily standup report as a PDF (falls back to HTML without WeasyPrint)."""
    today = datetime.now(timezone.utc).strftime("%d %b %Y")
    analyst = data.analyst_name or current_user.display_name or current_user.username
    checks = data.checks_data or {}

    html = (
        "<html><head><style>"
        "body { font-family: Helvetica, sans-serif; color: #1a1a2e; padding: 30px;"
        " font-size: 11px; line-height: 1.5; }"
        "h1 { color: #0f172a; font-size: 22px; border-bottom: 2px solid #6de4ff;"
        " padding-bottom: 6px; }"
        "h2 { color: #334155; font-size: 14px; margin-top: 20px; background: #f1f5f9;"
        " padding: 6px 12px; border-radius: 4px; }"
        ".meta { color: #64748b; font-size: 10px; margin-bottom: 16px; }"
        "table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 10px; }"
        "th { text-align: left; padding: 4px 8px; background: #f1f5f9;"
        " border: 1px solid #e2e8f0; font-size: 9px; text-transform: uppercase;"
        " color: #64748b; }"
        "td { padding: 4px 8px; border: 1px solid #e2e8f0; }"
        ".status-ok { color: #16a34a; font-weight: bold; }"
        ".status-warning { color: #d97706; font-weight: bold; }"
        ".status-critical { color: #dc2626; font-weight: bold; }"
        ".status-green { color: #16a34a; }"
        ".status-yellow { color: #d97706; }"
        ".status-red { color: #dc2626; }"
        ".section-notes { background: #f8fafc; border: 1px solid #e2e8f0;"
        " border-radius: 4px; padding: 8px 12px; margin: 8px 0; white-space: pre-wrap; }"
        ".signoff { margin-top: 30px; padding: 16px; border: 2px solid #e2e8f0;"
        " border-radius: 8px; }"
        ".footer { margin-top: 30px; border-top: 1px solid #e2e8f0; padding-top: 8px;"
        " color: #94a3b8; font-size: 9px; text-align: center; }"
        "</style></head><body>"
    )

    html += f"<h1>Daily SOC Standup Report</h1>"
    signed = "Yes" if data.signed_off else "No"
    html += (
        f'<div class="meta">Date: {today} &nbsp;|&nbsp; '
        f"Duty Analyst: {analyst} &nbsp;|&nbsp; Signed Off: {signed}</div>"
    )

    # -- Cluster Health --------------------------------------------------------
    cluster = checks.get("cluster_health", {})
    if cluster:
        status = cluster.get("status", "unknown")
        status_class = f"status-{status}" if status in ("green", "yellow", "red") else ""
        html += "<h2>Elasticsearch Cluster Health</h2>"
        html += (
            "<table><tr><th>Status</th><th>Nodes</th><th>Indices</th>"
            "<th>Shards</th><th>Unassigned</th></tr>"
        )
        html += (
            f'<tr><td class="{status_class}">{status.upper()}</td>'
            f'<td>{cluster.get("number_of_nodes", "?")}</td>'
            f'<td>{cluster.get("indices_count", "?")}</td>'
            f'<td>{cluster.get("active_shards", "?")}</td>'
            f'<td>{cluster.get("unassigned_shards", "?")}</td></tr></table>'
        )

    # -- Critical Alerts -------------------------------------------------------
    alerts = checks.get("critical_alerts", {})
    if alerts:
        html += (
            f'<h2>Critical/High Alerts (Last 24h) &mdash; '
            f'{alerts.get("critical_count", 0)} Critical, '
            f'{alerts.get("high_count", 0)} High</h2>'
        )
        alert_list = alerts.get("alerts", [])
        if alert_list:
            html += (
                "<table><tr><th>Time</th><th>Severity</th><th>Rule</th>"
                "<th>Host</th><th>Status</th></tr>"
            )
            for a in alert_list[:15]:
                ts = a.get("timestamp", "")[:16].replace("T", " ")
                html += (
                    f'<tr><td>{ts}</td><td>{a.get("severity", "")}</td>'
                    f'<td>{a.get("rule_name", "")[:50]}</td>'
                    f'<td>{a.get("host", "")}</td>'
                    f'<td>{a.get("status", "")}</td></tr>'
                )
            html += "</table>"
        else:
            html += "<p>No critical/high alerts in the last 24 hours.</p>"

    # -- Stale Cases -----------------------------------------------------------
    stale = checks.get("stale_cases", {})
    if stale:
        html += f'<h2>Stale Cases (Open &gt; 24h) &mdash; {stale.get("count", 0)}</h2>'
        case_list = stale.get("cases", [])
        if case_list:
            html += (
                "<table><tr><th>Case</th><th>Title</th><th>Severity</th>"
                "<th>Assigned</th><th>Hours Open</th></tr>"
            )
            for c in case_list:
                html += (
                    f'<tr><td>{c.get("case_number", "")}</td>'
                    f'<td>{c.get("title", "")[:40]}</td>'
                    f'<td>{c.get("severity", "")}</td>'
                    f'<td>{c.get("assigned_to", "")}</td>'
                    f'<td>{c.get("hours_open", 0)}</td></tr>'
                )
            html += "</table>"
        else:
            html += "<p>No stale cases.</p>"

    # -- DC / WEF Log Health ---------------------------------------------------
    for key, title in [
        ("dc_log_health", "Domain Controller Log Health"),
        ("wef_log_health", "WEF Log Health"),
    ]:
        lh = checks.get(key, {})
        if lh and lh.get("hosts"):
            html += (
                f"<h2>{title} &mdash; {lh.get('total_events_24h', 0):,} events, "
                f"{lh.get('hosts_with_gaps', 0)} hosts with gaps</h2>"
            )
            html += (
                "<table><tr><th>Host</th><th>Events (24h)</th><th>7-Day Avg</th>"
                "<th>Below Avg</th><th>Gap Hours</th><th>Status</th></tr>"
            )
            for h in lh.get("hosts", []):
                sc = (
                    "status-critical"
                    if h["status"] == "critical"
                    else "status-warning"
                    if h["status"] == "warning"
                    else "status-ok"
                )
                html += (
                    f'<tr><td>{h["hostname"]}</td>'
                    f'<td>{h["count_24h"]:,}</td>'
                    f'<td>{h["avg_7d"]:,}</td>'
                    f'<td>{"Yes" if h["below_average"] else "No"}</td>'
                    f'<td>{h["gap_hours"]}</td>'
                    f'<td class="{sc}">{h["status"].upper()}</td></tr>'
                )
            html += "</table>"

    # -- Rule Failures ---------------------------------------------------------
    rf = checks.get("rule_failures", {})
    if rf and rf.get("rules"):
        html += f'<h2>Rule Failures &mdash; {rf.get("count", 0)} rules</h2>'
        html += "<table><tr><th>Rule</th><th>Failures</th><th>Last Failure</th></tr>"
        for r in rf.get("rules", []):
            html += (
                f'<tr><td>{r.get("rule_name", "")[:50]}</td>'
                f'<td>{r.get("failure_count", 0)}</td>'
                f'<td>{(r.get("last_failure") or "")[:16]}</td></tr>'
            )
        html += "</table>"

    # -- Free-text sections ----------------------------------------------------
    if data.servicenow_notes:
        html += f'<h2>ServiceNow Incidents</h2><div class="section-notes">{data.servicenow_notes}</div>'
    if data.ai_summary:
        html += f'<h2>Threat Landscape Summary</h2><div class="section-notes">{data.ai_summary}</div>'
    if data.meeting_notes:
        html += f'<h2>Daily Meeting Notes</h2><div class="section-notes">{data.meeting_notes}</div>'
    if data.additional_notes:
        html += f'<h2>Additional Notes</h2><div class="section-notes">{data.additional_notes}</div>'

    # -- Sign-off --------------------------------------------------------------
    html += (
        f'<div class="signoff"><strong>Duty Analyst:</strong> {analyst}<br>'
        f'<strong>Signed Off:</strong> {"Yes" if data.signed_off else "No"}<br>'
        f"<strong>Date:</strong> {today}</div>"
    )
    html += (
        f'<div class="footer">Generated by ION &middot; '
        f"Intelligent Operating Network &middot; {today}</div>"
    )
    html += "</body></html>"

    try:
        from weasyprint import HTML as WeasyHTML

        pdf_bytes = WeasyHTML(string=html).write_pdf()
        filename = f"Daily-Standup-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except (ImportError, OSError):
        from fastapi.responses import HTMLResponse

        return HTMLResponse(content=html)


# ── Arkime high-risk traffic ──────────────────────────────────────────────


@router.get("/arkime/high-risk-traffic")
async def check_arkime_high_risk(
    current_user: User = Depends(require_permission("alert:read")),
):
    """Check Arkime for ingress/egress traffic to high-risk countries."""
    from ion.services.arkime_service import get_arkime_service

    svc = get_arkime_service()
    if not svc.is_configured:
        return {"configured": False}

    countries = {
        "RU": "Russia",
        "CN": "China",
        "IR": "Iran",
        "KP": "North Korea",
        "SY": "Syria",
    }

    # First get the list of nodes
    headers = await svc._headers()
    client = await svc._client()
    nodes = []
    try:
        stats_resp = await client.get(
            f"{svc.url}/api/stats", auth=svc._auth(), headers=headers,
        )
        if stats_resp.status_code == 200:
            content_type = stats_resp.headers.get("content-type", "")
            if "json" in content_type:
                for n in stats_resp.json().get("data", []):
                    nodes.append(n.get("nodeName") or n.get("id") or "unknown")
    except Exception:
        pass
    if not nodes:
        nodes = ["default"]

    start_time = str(int((datetime.now(timezone.utc) - timedelta(hours=24)).timestamp()))
    stop_time = str(int(datetime.now(timezone.utc).timestamp()))

    results: List[Dict[str, Any]] = []
    for code, name in countries.items():
        country_result = {
            "country_code": code,
            "country": name,
            "session_count": 0,
            "nodes": [],
        }

        for node_name in nodes:
            try:
                resp = await client.get(
                    f"{svc.url}/api/sessions",
                    auth=svc._auth(),
                    headers=headers,
                    params={
                        "expression": f'country == {code} && node == "{node_name}"',
                        "startTime": start_time,
                        "stopTime": stop_time,
                        "length": "5",
                        "fields": "id,node,srcIp,dstIp,ipProtocol,protocol,bytes,packets,firstPacket,lastPacket",
                    },
                )
                if resp.status_code == 200:
                    content_type = resp.headers.get("content-type", "")
                    if "json" not in content_type:
                        continue
                    body = resp.json()
                    count = body.get("recordsFiltered", 0)
                    sessions = []
                    for s in (body.get("data") or [])[:5]:
                        sessions.append({
                            "src_ip": s.get("srcIp"),
                            "dst_ip": s.get("dstIp"),
                            "protocol": s.get("protocol") or s.get("ipProtocol"),
                            "bytes": s.get("bytes", 0),
                            "packets": s.get("packets", 0),
                            "first_packet": s.get("firstPacket"),
                            "last_packet": s.get("lastPacket"),
                        })
                    if count > 0:
                        country_result["nodes"].append({
                            "node": node_name,
                            "session_count": count,
                            "sessions": sessions,
                        })
                        country_result["session_count"] += count
            except Exception as e:
                country_result.setdefault("errors", []).append(f"{node_name}: {str(e)[:60]}")

        results.append(country_result)

    return {"countries": results, "total": sum(r["session_count"] for r in results)}


@router.get("/arkime/node-stats")
async def arkime_node_stats(
    current_user: User = Depends(require_permission("alert:read")),
):
    """Pull per-node capture stats from Arkime — packets, bytes, sessions, drops."""
    from ion.services.arkime_service import get_arkime_service

    svc = get_arkime_service()
    if not svc.is_configured:
        return {"configured": False}

    try:
        headers = await svc._headers()
        client = await svc._client()

        # Node stats
        resp = await client.get(
            f"{svc.url}/api/stats",
            auth=svc._auth(),
            headers=headers,
        )
        if resp.status_code != 200:
            return {"configured": True, "error": f"HTTP {resp.status_code}"}

        content_type = resp.headers.get("content-type", "")
        if "json" not in content_type:
            return {"configured": True, "error": "Non-JSON response from Arkime"}

        data = resp.json()
        nodes = []
        for node in data.get("data", []):
            nodes.append({
                "name": node.get("nodeName", "?"),
                "id": node.get("id", "?"),
                "cpu": node.get("cpu", 0),
                "memory": node.get("memory", 0),
                "packets_24h": node.get("deltaPackets", 0),
                "bytes_24h": node.get("deltaBytes", 0),
                "sessions_24h": node.get("deltaSessions", 0),
                "dropped": node.get("deltaDropped", 0),
                "es_dropped": node.get("deltaESDropped", 0),
                "overload_dropped": node.get("deltaOverloadDropped", 0),
                "packets_per_sec": node.get("deltaPacketsPerSec", 0),
                "bytes_per_sec": node.get("deltaBytesPerSec", 0),
                "sessions_per_sec": node.get("deltaSessionsPerSec", 0),
                "disk_queue": node.get("diskQueue", 0),
                "close_queue": node.get("closeQueue", 0),
                "free_space_g": node.get("freeSpaceG", 0),
                "current_time": node.get("currentTime", 0),
            })

        # Also grab ES health through Arkime
        es_health = {}
        try:
            es_resp = await client.get(
                f"{svc.url}/api/eshealth",
                auth=svc._auth(),
                headers=headers,
            )
            if es_resp.status_code == 200 and "json" in es_resp.headers.get("content-type", ""):
                es_health = es_resp.json()
        except Exception:
            pass

        return {
            "configured": True,
            "node_count": len(nodes),
            "nodes": nodes,
            "es_health": {
                "status": es_health.get("status", "unknown"),
                "nodes": es_health.get("number_of_nodes", 0),
                "shards": es_health.get("active_shards", 0),
                "unassigned": es_health.get("unassigned_shards", 0),
            },
        }
    except Exception as e:
        return {"configured": True, "error": str(e)[:100]}
