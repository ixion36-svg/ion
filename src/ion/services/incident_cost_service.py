"""Incident cost calculator — estimates analyst labour and downtime costs per case."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, and_
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.models.user import User

logger = logging.getLogger(__name__)


def _case_cost(case: AlertCase, hourly_rate: float, downtime_cost_per_hour: float) -> dict:
    if not case.created_at or not case.closed_at:
        return {"analyst_hours": 0, "analyst_cost": 0, "downtime_cost": 0, "total_cost": 0}

    analyst_hours = (case.closed_at - case.created_at).total_seconds() / 3600
    analyst_cost = analyst_hours * hourly_rate
    affected_systems = len(case.affected_hosts or [])
    downtime_cost = affected_systems * analyst_hours * downtime_cost_per_hour / 24
    total_cost = analyst_cost + downtime_cost

    return {
        "analyst_hours": round(analyst_hours, 2),
        "analyst_cost": round(analyst_cost, 2),
        "downtime_cost": round(downtime_cost, 2),
        "total_cost": round(total_cost, 2),
    }


def calculate_incident_cost(
    session: Session,
    case_id: Optional[int] = None,
    hourly_rate: float = 75.0,
    downtime_cost_per_hour: float = 5000.0,
) -> dict:
    if case_id:
        case = session.get(AlertCase, case_id)
        if not case:
            return {"error": "Case not found"}
        costs = _case_cost(case, hourly_rate, downtime_cost_per_hour)
        return {
            "case_id": case.id,
            "period_days": None,
            "cases_analyzed": 1,
            "total_cost": costs["total_cost"],
            "breakdown": {
                "analyst_cost": costs["analyst_cost"],
                "downtime_cost": costs["downtime_cost"],
            },
            "avg_cost_per_incident": costs["total_cost"],
            "by_severity": {
                (case.severity or "unknown"): {"count": 1, "avg_cost": costs["total_cost"]}
            },
            "by_closure_reason": {
                (case.closure_reason or "unspecified"): {"count": 1, "avg_cost": costs["total_cost"]}
            },
            "top_expensive_cases": [{
                "case_number": case.case_number,
                "title": case.title,
                "cost": costs["total_cost"],
                "hours": costs["analyst_hours"],
            }],
        }

    now = datetime.now(timezone.utc)
    period_start = now - timedelta(days=30)

    query = select(AlertCase).where(
        and_(
            AlertCase.status == AlertCaseStatus.CLOSED.value,
            AlertCase.closed_at.isnot(None),
            AlertCase.closed_at >= period_start,
        )
    )
    cases = session.execute(query).scalars().all()

    if not cases:
        return {
            "case_id": None,
            "period_days": 30,
            "cases_analyzed": 0,
            "total_cost": 0,
            "breakdown": {"analyst_cost": 0, "downtime_cost": 0},
            "avg_cost_per_incident": 0,
            "by_severity": {},
            "by_closure_reason": {},
            "top_expensive_cases": [],
        }

    total_analyst_cost = 0.0
    total_downtime_cost = 0.0
    by_severity: dict[str, dict] = {}
    by_closure_reason: dict[str, dict] = {}
    case_costs: list[dict] = []

    for case in cases:
        costs = _case_cost(case, hourly_rate, downtime_cost_per_hour)
        total_analyst_cost += costs["analyst_cost"]
        total_downtime_cost += costs["downtime_cost"]

        case_costs.append({
            "case_number": case.case_number,
            "title": case.title,
            "cost": costs["total_cost"],
            "hours": costs["analyst_hours"],
        })

        sev = case.severity or "unknown"
        if sev not in by_severity:
            by_severity[sev] = {"count": 0, "_total_cost": 0.0}
        by_severity[sev]["count"] += 1
        by_severity[sev]["_total_cost"] += costs["total_cost"]

        reason = case.closure_reason or "unspecified"
        if reason not in by_closure_reason:
            by_closure_reason[reason] = {"count": 0, "_total_cost": 0.0}
        by_closure_reason[reason]["count"] += 1
        by_closure_reason[reason]["_total_cost"] += costs["total_cost"]

    total_cost = round(total_analyst_cost + total_downtime_cost, 2)

    for bucket in by_severity.values():
        bucket["avg_cost"] = round(bucket.pop("_total_cost") / bucket["count"], 2)
    for bucket in by_closure_reason.values():
        bucket["avg_cost"] = round(bucket.pop("_total_cost") / bucket["count"], 2)

    case_costs.sort(key=lambda x: x["cost"], reverse=True)

    return {
        "case_id": None,
        "period_days": 30,
        "cases_analyzed": len(cases),
        "total_cost": total_cost,
        "breakdown": {
            "analyst_cost": round(total_analyst_cost, 2),
            "downtime_cost": round(total_downtime_cost, 2),
        },
        "avg_cost_per_incident": round(total_cost / len(cases), 2),
        "by_severity": by_severity,
        "by_closure_reason": by_closure_reason,
        "top_expensive_cases": case_costs[:10],
    }
