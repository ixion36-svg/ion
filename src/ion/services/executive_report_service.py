"""Executive Weekly Report service — auto-generated PDF/HTML summary.

Pulls from all ION data sources to create a comprehensive executive report:
cases, MTTR, coverage, team metrics, notable incidents.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertTriage, AlertCase, AlertTriageStatus
from ion.models.user import User, AuditLog

logger = logging.getLogger(__name__)


def generate_executive_report(
    session: Session,
    days: int = 7,
) -> dict[str, Any]:
    """Generate an executive summary report for the last N days."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)

    report = {
        "generated_at": now.isoformat(),
        "period_start": cutoff.isoformat(),
        "period_end": now.isoformat(),
        "period_days": days,
        "cases": _case_metrics(session, cutoff),
        "alerts": _alert_metrics(session, cutoff),
        "team": _team_metrics(session, cutoff),
        "notable_incidents": _notable_incidents(session, cutoff),
        "trends": _compute_trends(session, cutoff, days),
    }

    return report


def generate_executive_html(report: dict) -> str:
    """Render the executive report as standalone HTML (for PDF conversion)."""
    d = report
    c = d["cases"]
    a = d["alerts"]
    t = d["team"]

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>ION Executive Report</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;color:#c9d1d9;background:#0d1117;padding:40px;font-size:14px;line-height:1.6}}
h1{{color:#58a6ff;border-bottom:2px solid #30363d;padding-bottom:8px}}
h2{{color:#c9d1d9;margin-top:24px;font-size:1.1rem;border-bottom:1px solid #21262d;padding-bottom:4px}}
.meta{{color:#8b949e;font-size:.85rem;margin-bottom:24px}}
.stats{{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0}}
.stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;min-width:120px;text-align:center}}
.stat-val{{font-size:1.5rem;font-weight:700;color:#58a6ff}}
.stat-val.crit{{color:#f85149}}.stat-val.green{{color:#3fb950}}.stat-val.warn{{color:#d29922}}
.stat-label{{font-size:.72rem;color:#8b949e;text-transform:uppercase;margin-top:4px}}
table{{width:100%;border-collapse:collapse;margin:12px 0;font-size:.85rem}}
th{{text-align:left;padding:8px;color:#8b949e;border-bottom:1px solid #30363d;font-size:.72rem;text-transform:uppercase}}
td{{padding:8px;border-bottom:1px solid #21262d}}
.sev-critical{{color:#f85149}}.sev-high{{color:#f0883e}}.sev-medium{{color:#d29922}}.sev-low{{color:#8b949e}}
.footer{{margin-top:32px;padding-top:12px;border-top:1px solid #30363d;color:#8b949e;font-size:.78rem;text-align:center}}
@media print{{body{{background:#fff;color:#333}}h1{{color:#0969da}}
.stat{{border-color:#d0d7de}}.stat-val{{color:#0969da}}.stat-val.crit{{color:#cf222e}}.stat-val.green{{color:#1a7f37}}
th{{color:#57606a;border-color:#d0d7de}}td{{border-color:#d0d7de}}.footer{{color:#57606a}}}}
</style></head><body>
<h1>ION Executive Report</h1>
<div class="meta">Period: {_esc(_fmt(d['period_start']))} — {_esc(_fmt(d['period_end']))} ({_esc(d['period_days'])} days) | Generated: {_esc(_fmt(d['generated_at']))}</div>

<h2>Case Metrics</h2>
<div class="stats">
<div class="stat"><div class="stat-val">{_esc(c['opened'])}</div><div class="stat-label">Cases Opened</div></div>
<div class="stat"><div class="stat-val green">{_esc(c['closed'])}</div><div class="stat-label">Cases Closed</div></div>
<div class="stat"><div class="stat-val{' crit' if c['fp_rate'] and c['fp_rate'] > 50 else ''}">{_esc(c['fp_rate'] or 0)}%</div><div class="stat-label">FP Rate</div></div>
<div class="stat"><div class="stat-val">{_esc(c['avg_mttr'] or '-')}</div><div class="stat-label">Avg MTTR (hrs)</div></div>
<div class="stat"><div class="stat-val{' warn' if c['open_backlog'] > 20 else ''}">{_esc(c['open_backlog'])}</div><div class="stat-label">Open Backlog</div></div>
</div>
"""

    # Closure reasons
    if c["closure_reasons"]:
        html += "<h2>Closure Reasons</h2><table><tr><th>Reason</th><th>Count</th><th>%</th></tr>"
        total = sum(c["closure_reasons"].values())
        for reason, count in sorted(c["closure_reasons"].items(), key=lambda x: -x[1]):
            pct = round(count / total * 100) if total else 0
            html += f"<tr><td>{_esc(reason.replace('_', ' ').title())}</td><td>{_esc(count)}</td><td>{_esc(pct)}%</td></tr>"
        html += "</table>"

    # Severity breakdown
    if c["by_severity"]:
        html += "<h2>Cases by Severity</h2><table><tr><th>Severity</th><th>Opened</th></tr>"
        for sev in ["critical", "high", "medium", "low"]:
            cnt = c["by_severity"].get(sev, 0)
            if cnt:
                html += f'<tr><td class="sev-{_esc(sev)}">{_esc(sev.title())}</td><td>{_esc(cnt)}</td></tr>'
        html += "</table>"

    # Alert metrics
    html += f"""<h2>Alert Metrics</h2>
<div class="stats">
<div class="stat"><div class="stat-val">{_esc(a['total_triaged'])}</div><div class="stat-label">Alerts Triaged</div></div>
<div class="stat"><div class="stat-val">{_esc(a['analysts_active'])}</div><div class="stat-label">Analysts Active</div></div>
</div>"""

    # Team
    if t["analysts"]:
        html += "<h2>Team Performance</h2><table><tr><th>Analyst</th><th>Cases Closed</th><th>Actions</th></tr>"
        for analyst in t["analysts"][:10]:
            html += f"<tr><td>{_esc(analyst['username'])}</td><td>{_esc(analyst['cases_closed'])}</td><td>{_esc(analyst['total_actions'])}</td></tr>"
        html += "</table>"

    # Notable incidents
    incidents = d.get("notable_incidents", [])
    if incidents:
        html += "<h2>Notable Incidents</h2><table><tr><th>Case</th><th>Title</th><th>Severity</th><th>Status</th></tr>"
        for inc in incidents[:10]:
            html += f'<tr><td>{_esc(inc["case_number"])}</td><td>{_esc(inc["title"])}</td><td class="sev-{_esc(inc["severity"])}">{_esc(inc["severity"])}</td><td>{_esc(inc["status"])}</td></tr>'
        html += "</table>"

    # Trends
    trends = d.get("trends", {})
    if trends.get("daily"):
        html += "<h2>Daily Activity Trend</h2><table><tr><th>Date</th><th>Opened</th><th>Closed</th></tr>"
        for day in trends["daily"]:
            html += f"<tr><td>{_esc(day['date'])}</td><td>{_esc(day['opened'])}</td><td>{_esc(day['closed'])}</td></tr>"
        html += "</table>"

    html += '<div class="footer">Generated by ION — Intelligent Operating Network</div></body></html>'
    return html


def generate_executive_pdf(report: dict) -> Optional[bytes]:
    """Generate PDF from executive report. Returns None if WeasyPrint unavailable."""
    try:
        from weasyprint import HTML
        html_content = generate_executive_html(report)
        return HTML(string=html_content).write_pdf()
    except (ImportError, OSError):
        return None


def _case_metrics(session: Session, cutoff: datetime) -> dict:
    opened = session.execute(
        select(AlertCase).where(AlertCase.created_at >= cutoff)
    ).scalars().all()

    closed = [c for c in opened if c.status == "closed"]
    all_closed = session.execute(
        select(AlertCase).where(
            and_(AlertCase.closed_at.isnot(None), AlertCase.closed_at >= cutoff)
        )
    ).scalars().all()

    closure_reasons = {}
    mttr_values = []
    for c in all_closed:
        reason = c.closure_reason or "unspecified"
        closure_reasons[reason] = closure_reasons.get(reason, 0) + 1
        if c.created_at and c.closed_at:
            mttr_values.append((c.closed_at - c.created_at).total_seconds() / 3600)

    fp = closure_reasons.get("false_positive", 0)
    total_closed = len(all_closed)

    by_severity = {}
    for c in opened:
        sev = c.severity or "unknown"
        by_severity[sev] = by_severity.get(sev, 0) + 1

    open_backlog = session.execute(
        select(func.count(AlertCase.id)).where(AlertCase.status != "closed")
    ).scalar() or 0

    return {
        "opened": len(opened),
        "closed": total_closed,
        "closure_reasons": closure_reasons,
        "fp_rate": round(fp / total_closed * 100, 1) if total_closed else None,
        "avg_mttr": round(sum(mttr_values) / len(mttr_values), 1) if mttr_values else None,
        "by_severity": by_severity,
        "open_backlog": open_backlog,
    }


def _alert_metrics(session: Session, cutoff: datetime) -> dict:
    triaged = session.execute(
        select(func.count(AlertTriage.id)).where(AlertTriage.updated_at >= cutoff)
    ).scalar() or 0

    analysts = session.execute(
        select(func.count(func.distinct(AlertTriage.assigned_to_id))).where(
            and_(AlertTriage.updated_at >= cutoff, AlertTriage.assigned_to_id.isnot(None))
        )
    ).scalar() or 0

    return {"total_triaged": triaged, "analysts_active": analysts}


def _team_metrics(session: Session, cutoff: datetime) -> dict:
    activity = (
        select(
            User.username,
            func.count(AuditLog.id).label("total_actions"),
        )
        .outerjoin(AuditLog, and_(AuditLog.user_id == User.id, AuditLog.timestamp >= cutoff))
        .where(User.is_active == True)
        .group_by(User.username)
        .order_by(func.count(AuditLog.id).desc())
    )

    analysts = []
    for username, total_actions in session.execute(activity).all():
        cases_closed = session.execute(
            select(func.count(AlertCase.id)).where(
                and_(
                    AlertCase.closed_at >= cutoff,
                    AlertCase.closed_by_id == select(User.id).where(User.username == username).scalar_subquery(),
                )
            )
        ).scalar() or 0

        analysts.append({
            "username": username,
            "cases_closed": cases_closed,
            "total_actions": total_actions or 0,
        })

    return {"analysts": [a for a in analysts if a["total_actions"] > 0]}


def _notable_incidents(session: Session, cutoff: datetime) -> list[dict]:
    cases = session.execute(
        select(AlertCase).where(
            and_(
                AlertCase.created_at >= cutoff,
                AlertCase.severity.in_(["critical", "high"]),
            )
        ).order_by(AlertCase.created_at.desc()).limit(15)
    ).scalars().all()

    return [
        {
            "case_number": c.case_number,
            "title": c.title,
            "severity": c.severity,
            "status": c.status,
            "created_at": c.created_at.isoformat() if c.created_at else None,
        }
        for c in cases
    ]


def _compute_trends(session: Session, cutoff: datetime, days: int) -> dict:
    daily = []
    for i in range(days):
        day_start = cutoff + timedelta(days=i)
        day_end = day_start + timedelta(days=1)

        opened = session.execute(
            select(func.count(AlertCase.id)).where(
                and_(AlertCase.created_at >= day_start, AlertCase.created_at < day_end)
            )
        ).scalar() or 0

        closed = session.execute(
            select(func.count(AlertCase.id)).where(
                and_(AlertCase.closed_at >= day_start, AlertCase.closed_at < day_end)
            )
        ).scalar() or 0

        daily.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "opened": opened,
            "closed": closed,
        })

    return {"daily": daily}


def _fmt(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%d %b %Y %H:%M")
    except (ValueError, TypeError):
        return str(iso)


def _esc(s) -> str:
    """HTML-escape a value for safe interpolation into report HTML.

    Accepts any type, coerces to string. Escapes the five XML/HTML special
    characters so the output is safe in element bodies AND attribute values.
    """
    if s is None:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
