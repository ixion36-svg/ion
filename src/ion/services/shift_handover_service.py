"""Shift Handover Report service — generates end-of-shift summaries.

Pulls data from AlertTriage, AlertCase, AuditLog, ThreatIntelWatch,
and Elasticsearch to produce a comprehensive handover document.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select, func, and_, desc
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertTriage, AlertCase, AlertTriageStatus, AlertCaseStatus
from ion.models.user import User, AuditLog
from ion.models.threat_intel import ThreatIntelWatch

logger = logging.getLogger(__name__)


def generate_shift_report(
    session: Session,
    hours: int = 8,
    analyst_id: Optional[int] = None,
) -> dict[str, Any]:
    """Generate a shift handover report covering the last `hours` hours.

    Args:
        session: Database session
        hours: Shift duration to report on (default 8)
        analyst_id: Optional — scope to a single analyst's activity

    Returns:
        Comprehensive shift report dict.
    """
    now = datetime.now(timezone.utc)
    shift_start = now - timedelta(hours=hours)

    report = {
        "generated_at": now.isoformat(),
        "shift_start": shift_start.isoformat(),
        "shift_end": now.isoformat(),
        "shift_hours": hours,
        "alerts": _get_alert_summary(session, shift_start, analyst_id),
        "cases": _get_case_summary(session, shift_start, analyst_id),
        "pending": _get_pending_items(session),
        "activity": _get_analyst_activity(session, shift_start),
        "watches": _get_active_watches(session),
        "highlights": [],
    }

    # Build highlights (noteworthy events for the incoming shift)
    report["highlights"] = _build_highlights(report)

    return report


def _get_alert_summary(
    session: Session, shift_start: datetime, analyst_id: Optional[int]
) -> dict:
    """Alerts triaged during this shift."""
    base = select(AlertTriage).where(AlertTriage.updated_at >= shift_start)
    if analyst_id:
        base = base.where(AlertTriage.assigned_to_id == analyst_id)

    triaged = session.execute(base).scalars().all()

    # Group by status
    by_status = {"open": 0, "acknowledged": 0, "closed": 0}
    by_priority = {}
    analysts_active = set()

    for t in triaged:
        by_status[t.status] = by_status.get(t.status, 0) + 1
        if t.priority:
            by_priority[t.priority] = by_priority.get(t.priority, 0) + 1
        if t.assigned_to_id:
            analysts_active.add(t.assigned_to_id)

    # Recent triage entries with analyst names
    recent_q = (
        select(AlertTriage, User.username)
        .outerjoin(User, AlertTriage.assigned_to_id == User.id)
        .where(AlertTriage.updated_at >= shift_start)
        .order_by(desc(AlertTriage.updated_at))
        .limit(20)
    )
    if analyst_id:
        recent_q = recent_q.where(AlertTriage.assigned_to_id == analyst_id)

    recent_rows = session.execute(recent_q).all()
    recent = []
    for triage, username in recent_rows:
        recent.append({
            "es_alert_id": triage.es_alert_id,
            "status": triage.status,
            "priority": triage.priority,
            "analyst": username or "Unassigned",
            "notes": (triage.analyst_notes or "")[:200],
            "updated_at": triage.updated_at.isoformat() if triage.updated_at else None,
        })

    return {
        "total_triaged": len(triaged),
        "by_status": by_status,
        "by_priority": by_priority,
        "analysts_active": len(analysts_active),
        "recent": recent,
    }


def _get_case_summary(
    session: Session, shift_start: datetime, analyst_id: Optional[int]
) -> dict:
    """Cases opened, closed, and worked during this shift."""
    # Cases created during shift
    created_q = select(AlertCase).where(AlertCase.created_at >= shift_start)
    if analyst_id:
        created_q = created_q.where(AlertCase.created_by_id == analyst_id)
    created = session.execute(created_q).scalars().all()

    # Cases closed during shift
    closed_q = select(AlertCase).where(
        and_(AlertCase.closed_at.isnot(None), AlertCase.closed_at >= shift_start)
    )
    if analyst_id:
        closed_q = closed_q.where(AlertCase.closed_by_id == analyst_id)
    closed = session.execute(closed_q).scalars().all()

    # Closure reason breakdown
    closure_reasons = {}
    for c in closed:
        reason = c.closure_reason or "unspecified"
        closure_reasons[reason] = closure_reasons.get(reason, 0) + 1

    # MTTR for cases closed this shift (created_at → closed_at)
    mttr_values = []
    for c in closed:
        if c.created_at and c.closed_at:
            delta = (c.closed_at - c.created_at).total_seconds() / 3600
            mttr_values.append(delta)
    avg_mttr = round(sum(mttr_values) / len(mttr_values), 1) if mttr_values else None

    # Severity breakdown of opened cases
    severity_opened = {}
    for c in created:
        sev = c.severity or "unknown"
        severity_opened[sev] = severity_opened.get(sev, 0) + 1

    # Cases created with details
    cases_opened = []
    for c in created:
        cases_opened.append({
            "id": c.id,
            "case_number": c.case_number,
            "title": c.title,
            "severity": c.severity,
            "status": c.status,
            "assigned_to_id": c.assigned_to_id,
        })

    cases_closed = []
    for c in closed:
        cases_closed.append({
            "id": c.id,
            "case_number": c.case_number,
            "title": c.title,
            "severity": c.severity,
            "closure_reason": c.closure_reason,
        })

    return {
        "opened": len(created),
        "closed": len(closed),
        "closure_reasons": closure_reasons,
        "avg_mttr_hours": avg_mttr,
        "severity_opened": severity_opened,
        "cases_opened": cases_opened[:10],
        "cases_closed": cases_closed[:10],
    }


def _get_pending_items(session: Session) -> dict:
    """Items the incoming shift needs to pick up."""
    # Open cases not yet assigned
    unassigned = session.execute(
        select(func.count(AlertCase.id)).where(
            and_(
                AlertCase.status != AlertCaseStatus.CLOSED.value,
                AlertCase.assigned_to_id.is_(None),
            )
        )
    ).scalar() or 0

    # Open cases by severity
    open_cases_q = (
        select(AlertCase.severity, func.count(AlertCase.id))
        .where(AlertCase.status != AlertCaseStatus.CLOSED.value)
        .group_by(AlertCase.severity)
    )
    open_by_severity = {}
    for sev, cnt in session.execute(open_cases_q).all():
        open_by_severity[sev or "unknown"] = cnt

    # Total open cases
    total_open = session.execute(
        select(func.count(AlertCase.id)).where(
            AlertCase.status != AlertCaseStatus.CLOSED.value
        )
    ).scalar() or 0

    # Open alerts (not yet triaged / still open)
    open_alerts = session.execute(
        select(func.count(AlertTriage.id)).where(
            AlertTriage.status == AlertTriageStatus.OPEN.value
        )
    ).scalar() or 0

    # Acknowledged but not closed (in progress)
    in_progress = session.execute(
        select(func.count(AlertTriage.id)).where(
            AlertTriage.status == AlertTriageStatus.ACKNOWLEDGED.value
        )
    ).scalar() or 0

    return {
        "open_cases": total_open,
        "unassigned_cases": unassigned,
        "open_cases_by_severity": open_by_severity,
        "open_alerts": open_alerts,
        "in_progress_alerts": in_progress,
    }


def _get_analyst_activity(session: Session, shift_start: datetime) -> list[dict]:
    """Per-analyst activity summary from the audit log."""
    activity_q = (
        select(
            AuditLog.user_id,
            User.username,
            AuditLog.action,
            func.count(AuditLog.id).label("count"),
        )
        .outerjoin(User, AuditLog.user_id == User.id)
        .where(AuditLog.timestamp >= shift_start)
        .group_by(AuditLog.user_id, User.username, AuditLog.action)
        .order_by(User.username, desc("count"))
    )

    rows = session.execute(activity_q).all()

    # Group by analyst
    by_analyst: dict[str, dict] = {}
    for user_id, username, action, count in rows:
        name = username or f"user_{user_id}"
        if name not in by_analyst:
            by_analyst[name] = {"user_id": user_id, "username": name, "actions": {}, "total": 0}
        by_analyst[name]["actions"][action] = count
        by_analyst[name]["total"] += count

    result = sorted(by_analyst.values(), key=lambda a: a["total"], reverse=True)
    return result


def _get_active_watches(session: Session) -> dict:
    """Current threat intel watches and recent matches."""
    watches = session.execute(
        select(ThreatIntelWatch).where(ThreatIntelWatch.is_active == True)
    ).scalars().all()

    watch_list = []
    total_matches = 0
    for w in watches:
        watch_list.append({
            "name": w.name,
            "entity_type": w.entity_type,
            "match_count": w.match_count,
            "watched_by": w.watched_by,
            "last_seen_at": w.last_seen_at.isoformat() if w.last_seen_at else None,
        })
        total_matches += w.match_count

    return {
        "active_count": len(watches),
        "total_matches": total_matches,
        "watches": watch_list[:20],
    }


def _build_highlights(report: dict) -> list[dict]:
    """Build a list of noteworthy items for the incoming shift."""
    highlights = []

    # Critical/high cases opened
    sev = report["cases"].get("severity_opened", {})
    crit = sev.get("critical", 0)
    high = sev.get("high", 0)
    if crit > 0:
        highlights.append({
            "level": "critical",
            "message": f"{crit} critical case(s) opened during this shift",
        })
    if high > 0:
        highlights.append({
            "level": "high",
            "message": f"{high} high-severity case(s) opened during this shift",
        })

    # Unassigned cases
    unassigned = report["pending"].get("unassigned_cases", 0)
    if unassigned > 0:
        highlights.append({
            "level": "warning",
            "message": f"{unassigned} case(s) unassigned — need assignment",
        })

    # Large open alert backlog
    open_alerts = report["pending"].get("open_alerts", 0)
    if open_alerts > 50:
        highlights.append({
            "level": "warning",
            "message": f"{open_alerts} alerts still in open queue",
        })

    # High FP rate this shift
    closure = report["cases"].get("closure_reasons", {})
    total_closed = report["cases"].get("closed", 0)
    fp_count = closure.get("false_positive", 0)
    if total_closed >= 3 and fp_count / total_closed > 0.5:
        highlights.append({
            "level": "info",
            "message": f"High FP rate: {fp_count}/{total_closed} cases closed as false positive — check rule tuning",
        })

    # Threat intel watch with recent activity
    watches = report["watches"]
    if watches.get("total_matches", 0) > 0:
        highlights.append({
            "level": "info",
            "message": f"{watches['total_matches']} threat intel match(es) across {watches['active_count']} active watches",
        })

    # No activity at all
    if report["alerts"]["total_triaged"] == 0 and report["cases"]["opened"] == 0:
        highlights.append({
            "level": "info",
            "message": "Quiet shift — no alerts triaged or cases opened",
        })

    return highlights
