"""Daily SOC Standup API — aggregates health checks, alerts, cases, and log monitoring."""

import asyncio
import logging
import json
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


# ── Internal check helpers ────────────────────────────────────────────────


async def _check_cluster_health() -> Dict[str, Any]:
    """ES cluster health + stats."""
    from ion.services.elasticsearch_service import ElasticsearchService

    es = ElasticsearchService()
    if not es.is_configured:
        return {"status": "not_configured"}
    try:
        result = await es._request("GET", "/_cluster/health")
        stats = await es._request("GET", "/_cluster/stats")
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


async def _check_log_source_health(host_pattern: str, label: str) -> Dict[str, Any]:
    """Check winlogbeat-* for a host pattern, compare to 7-day average, find gaps."""
    from ion.services.elasticsearch_service import ElasticsearchService

    es = ElasticsearchService()
    if not es.is_configured:
        return {"label": label, "status": "not_configured"}
    try:
        # Last 24 h event count per host matching pattern
        body_24h = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"host.hostname": host_pattern}},
                        {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
                    ]
                }
            },
            "aggs": {
                "hosts": {
                    "terms": {"field": "host.hostname", "size": 100},
                    "aggs": {
                        "hourly": {
                            "date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}
                        }
                    },
                }
            },
        }
        result_24h = await es._request(
            "POST", "/winlogbeat-*/_search?ignore_unavailable=true", json=body_24h
        )

        # 7-day average for comparison
        body_7d = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"host.hostname": host_pattern}},
                        {"range": {"@timestamp": {"gte": "now-7d", "lte": "now"}}},
                    ]
                }
            },
            "aggs": {
                "hosts": {
                    "terms": {"field": "host.hostname", "size": 100},
                }
            },
        }
        result_7d = await es._request(
            "POST", "/winlogbeat-*/_search?ignore_unavailable=true", json=body_7d
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
        return {
            "label": label,
            "total_events_24h": total_24h,
            "host_count": len(hosts_24h),
            "hosts_with_gaps": len(gaps),
            "hosts_below_average": sum(1 for h in host_summaries if h["below_average"]),
            "hosts": sorted(host_summaries, key=lambda h: h["status"] != "ok", reverse=True),
            "gaps": gaps,
        }
    except Exception as e:
        return {"label": label, "status": "error", "error": str(e)[:200]}


async def _check_rule_failures() -> Dict[str, Any]:
    """Detection rules that failed execution in the last 24 h."""
    from ion.services.elasticsearch_service import ElasticsearchService

    es = ElasticsearchService()
    if not es.is_configured:
        return {"count": 0}
    try:
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": "now-24h"}}},
                        {
                            "term": {
                                "kibana.alert.rule.execution.metrics.execution_status": "failed"
                            }
                        },
                    ]
                }
            },
            "aggs": {
                "rules": {
                    "terms": {"field": "kibana.alert.rule.name", "size": 20},
                    "aggs": {
                        "last_failure": {"max": {"field": "@timestamp"}},
                    },
                }
            },
        }
        try:
            result = await es._request(
                "POST", "/.kibana-event-log-*/_search?ignore_unavailable=true", json=body
            )
        except Exception:
            return {"count": 0, "rules": []}

        rules: List[Dict[str, Any]] = []
        for bucket in result.get("aggregations", {}).get("rules", {}).get("buckets", []):
            rules.append(
                {
                    "rule_name": bucket["key"],
                    "failure_count": bucket["doc_count"],
                    "last_failure": bucket.get("last_failure", {}).get("value_as_string"),
                }
            )
        return {"count": len(rules), "rules": rules}
    except Exception as e:
        return {"count": 0, "error": str(e)[:100]}


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
        _check_log_source_health("*DCS*", "Domain Controllers"),
        _check_log_source_health("*WEF*", "Windows Event Forwarding"),
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
    results: List[Dict[str, Any]] = []

    for code, name in countries.items():
        try:
            headers = await svc._headers()
            client = await svc._client()
            resp = await client.get(
                f"{svc.url}/api/sessions",
                auth=svc._auth(),
                headers=headers,
                params={
                    "expression": f"country == {code}",
                    "startTime": str(
                        int((datetime.now(timezone.utc) - timedelta(hours=24)).timestamp())
                    ),
                    "stopTime": str(int(datetime.now(timezone.utc).timestamp())),
                    "length": "0",  # just want the count
                },
            )
            if resp.status_code == 200:
                body = resp.json()
                total = body.get("recordsFiltered", 0)
                results.append({"country_code": code, "country": name, "session_count": total})
            else:
                results.append(
                    {
                        "country_code": code,
                        "country": name,
                        "session_count": 0,
                        "error": f"HTTP {resp.status_code}",
                    }
                )
        except Exception as e:
            results.append(
                {"country_code": code, "country": name, "session_count": 0, "error": str(e)[:80]}
            )

    return {"countries": results, "total": sum(r["session_count"] for r in results)}
