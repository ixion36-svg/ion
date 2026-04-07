"""Analyst Efficiency Service for ION.

Computes per-analyst and team-wide efficiency metrics by cross-referencing
alert triage records, investigation cases, and the audit log over a
configurable lookback window.
"""

import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, desc, func, select
from sqlalchemy.orm import Session

from ion.models.alert_triage import (
    AlertCase,
    AlertCaseStatus,
    AlertTriage,
    AlertTriageStatus,
)
from ion.models.user import AuditLog, User

logger = logging.getLogger(__name__)


def _time_window(hours: int) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=hours)
    return now, cutoff


def _build_user_lookup(session: Session) -> Dict[int, str]:
    rows = session.execute(select(User.id, User.username).where(User.is_active == True)).all()  # noqa: E712
    return {uid: uname for uid, uname in rows}


def _cases_closed_per_analyst(session: Session, cutoff: datetime) -> Dict[int, List[AlertCase]]:
    stmt = (
        select(AlertCase)
        .where(
            and_(
                AlertCase.status == AlertCaseStatus.CLOSED,
                AlertCase.closed_at >= cutoff,
                AlertCase.closed_by_id.isnot(None),
            )
        )
    )
    cases = session.execute(stmt).scalars().all()
    by_analyst: Dict[int, List[AlertCase]] = defaultdict(list)
    for c in cases:
        by_analyst[c.closed_by_id].append(c)
    return by_analyst


def _cases_opened_per_analyst(session: Session, cutoff: datetime) -> Dict[int, int]:
    stmt = (
        select(AlertCase.created_by_id, func.count(AlertCase.id))
        .where(AlertCase.created_at >= cutoff)
        .group_by(AlertCase.created_by_id)
    )
    rows = session.execute(stmt).all()
    return {uid: cnt for uid, cnt in rows}


def _alerts_triaged_per_analyst(session: Session, cutoff: datetime) -> Dict[int, int]:
    stmt = (
        select(AlertTriage.assigned_to_id, func.count(AlertTriage.id))
        .where(
            and_(
                AlertTriage.status == AlertTriageStatus.CLOSED,
                AlertTriage.updated_at >= cutoff,
                AlertTriage.assigned_to_id.isnot(None),
            )
        )
        .group_by(AlertTriage.assigned_to_id)
    )
    rows = session.execute(stmt).all()
    return {uid: cnt for uid, cnt in rows}


def _closure_reason_counts(cases: List[AlertCase]) -> tuple[int, int]:
    tp = sum(1 for c in cases if c.closure_reason == "true_positive")
    fp = sum(1 for c in cases if c.closure_reason == "false_positive")
    return tp, fp


def _avg_mttr(cases: List[AlertCase]) -> Optional[float]:
    mttrs: List[float] = []
    for c in cases:
        if c.closed_at and c.created_at:
            closed = c.closed_at if c.closed_at.tzinfo else c.closed_at.replace(tzinfo=timezone.utc)
            created = c.created_at if c.created_at.tzinfo else c.created_at.replace(tzinfo=timezone.utc)
            delta_hours = (closed - created).total_seconds() / 3600
            if delta_hours >= 0:
                mttrs.append(delta_hours)
    if not mttrs:
        return None
    return round(sum(mttrs) / len(mttrs), 2)


def _audit_actions_per_analyst(
    session: Session, cutoff: datetime
) -> Dict[int, Dict[str, Any]]:
    stmt = (
        select(AuditLog.user_id, AuditLog.action)
        .where(
            and_(
                AuditLog.timestamp >= cutoff,
                AuditLog.user_id.isnot(None),
            )
        )
    )
    rows = session.execute(stmt).all()

    result: Dict[int, Dict[str, Any]] = defaultdict(lambda: {"total": 0, "counter": Counter()})
    for uid, action in rows:
        result[uid]["total"] += 1
        result[uid]["counter"][action] += 1
    return result


def _hourly_activity(session: Session, now: datetime) -> List[Dict[str, Any]]:
    cutoff_24h = now - timedelta(hours=24)

    closed_cases = session.execute(
        select(AlertCase.closed_at)
        .where(
            and_(
                AlertCase.status == AlertCaseStatus.CLOSED,
                AlertCase.closed_at >= cutoff_24h,
                AlertCase.closed_at.isnot(None),
            )
        )
    ).scalars().all()

    triaged_alerts = session.execute(
        select(AlertTriage.updated_at)
        .where(
            and_(
                AlertTriage.status == AlertTriageStatus.CLOSED,
                AlertTriage.updated_at >= cutoff_24h,
            )
        )
    ).scalars().all()

    # Build hour buckets
    buckets: Dict[str, Dict[str, int]] = {}
    for h in range(24):
        hour_dt = (cutoff_24h + timedelta(hours=h)).replace(minute=0, second=0, microsecond=0)
        key = hour_dt.strftime("%Y-%m-%dT%H:%M:%S")
        buckets[key] = {"cases_closed": 0, "alerts_triaged": 0}

    def _bucket_key(dt: datetime) -> str:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M:%S")

    for ts in closed_cases:
        key = _bucket_key(ts)
        if key in buckets:
            buckets[key]["cases_closed"] += 1

    for ts in triaged_alerts:
        key = _bucket_key(ts)
        if key in buckets:
            buckets[key]["alerts_triaged"] += 1

    return [
        {"hour": hour, **counts}
        for hour, counts in sorted(buckets.items())
    ]


def get_analyst_efficiency(session: Session, hours: int = 168) -> dict:
    """Compute analyst efficiency metrics over the given lookback window.

    Args:
        session: SQLAlchemy database session.
        hours: Lookback period in hours (default 168 = 7 days).

    Returns:
        Dictionary with per-analyst metrics, team summary, and hourly
        activity breakdown for the last 24 hours.
    """
    now, cutoff = _time_window(hours)
    user_lookup = _build_user_lookup(session)

    closed_by_analyst = _cases_closed_per_analyst(session, cutoff)
    opened_by_analyst = _cases_opened_per_analyst(session, cutoff)
    triaged_by_analyst = _alerts_triaged_per_analyst(session, cutoff)
    audit_by_analyst = _audit_actions_per_analyst(session, cutoff)

    # Collect all analyst IDs that had any activity
    active_ids = (
        set(closed_by_analyst.keys())
        | set(opened_by_analyst.keys())
        | set(triaged_by_analyst.keys())
        | set(audit_by_analyst.keys())
    )

    analysts: List[Dict[str, Any]] = []
    total_tp = 0
    total_fp = 0
    all_mttrs: List[float] = []
    busiest_analyst = ("", 0)
    most_efficient: tuple[str, float] = ("", float("inf"))

    for uid in sorted(active_ids):
        username = user_lookup.get(uid, f"user_{uid}")
        closed_cases = closed_by_analyst.get(uid, [])
        cases_closed = len(closed_cases)
        cases_opened = opened_by_analyst.get(uid, 0)
        alerts_triaged = triaged_by_analyst.get(uid, 0)

        tp, fp = _closure_reason_counts(closed_cases)
        total_tp += tp
        total_fp += fp

        total_dispositions = tp + fp
        fp_rate = round((fp / total_dispositions) * 100, 1) if total_dispositions > 0 else 0.0

        avg_mttr = _avg_mttr(closed_cases)

        # Collect individual MTTRs for team average
        for c in closed_cases:
            if c.closed_at and c.created_at:
                closed_ts = c.closed_at if c.closed_at.tzinfo else c.closed_at.replace(tzinfo=timezone.utc)
                created_ts = c.created_at if c.created_at.tzinfo else c.created_at.replace(tzinfo=timezone.utc)
                delta = (closed_ts - created_ts).total_seconds() / 3600
                if delta >= 0:
                    all_mttrs.append(delta)

        audit_data = audit_by_analyst.get(uid, {"total": 0, "counter": Counter()})
        total_actions = audit_data["total"]
        top_actions = dict(audit_data["counter"].most_common(10))

        # Track busiest analyst (by total actions)
        if total_actions > busiest_analyst[1]:
            busiest_analyst = (username, total_actions)

        # Track most efficient (lowest avg MTTR with >= 3 closures)
        if cases_closed >= 3 and avg_mttr is not None and avg_mttr < most_efficient[1]:
            most_efficient = (username, avg_mttr)

        analysts.append({
            "user_id": uid,
            "username": username,
            "cases_closed": cases_closed,
            "cases_opened": cases_opened,
            "alerts_triaged": alerts_triaged,
            "true_positives": tp,
            "false_positives": fp,
            "fp_rate": fp_rate,
            "avg_mttr_hours": avg_mttr,
            "total_actions": total_actions,
            "top_actions": top_actions,
        })

    # Team summary
    total_cases_closed = sum(a["cases_closed"] for a in analysts)
    total_cases_opened = sum(a["cases_opened"] for a in analysts)
    total_alerts_triaged = sum(a["alerts_triaged"] for a in analysts)

    total_dispositions = total_tp + total_fp
    overall_fp_rate = round((total_fp / total_dispositions) * 100, 1) if total_dispositions > 0 else 0.0
    team_avg_mttr = round(sum(all_mttrs) / len(all_mttrs), 2) if all_mttrs else None

    team_summary = {
        "total_cases_closed": total_cases_closed,
        "total_cases_opened": total_cases_opened,
        "total_alerts_triaged": total_alerts_triaged,
        "overall_fp_rate": overall_fp_rate,
        "avg_mttr_hours": team_avg_mttr,
        "busiest_analyst": busiest_analyst[0] or None,
        "most_efficient": most_efficient[0] if most_efficient[1] != float("inf") else None,
    }

    hourly = _hourly_activity(session, now)

    return {
        "period_hours": hours,
        "analysts": analysts,
        "team_summary": team_summary,
        "hourly_activity": hourly,
    }
