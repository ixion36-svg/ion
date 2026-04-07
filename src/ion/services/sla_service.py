"""SLA Management service -- policy CRUD, compliance checking, and breach logging."""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session

from ion.models.sla import SLAPolicy, SLABreachLog
from ion.models.alert_triage import AlertCase, AlertTriage, AlertCaseStatus, AlertTriageStatus

logger = logging.getLogger(__name__)

DEFAULT_POLICIES = [
    {"severity": "critical", "acknowledge_minutes": 15, "resolve_minutes": 240, "description": "Critical severity -- 15 min ack, 4 hr resolve"},
    {"severity": "high", "acknowledge_minutes": 60, "resolve_minutes": 480, "description": "High severity -- 1 hr ack, 8 hr resolve"},
    {"severity": "medium", "acknowledge_minutes": 240, "resolve_minutes": 1440, "description": "Medium severity -- 4 hr ack, 24 hr resolve"},
    {"severity": "low", "acknowledge_minutes": 480, "resolve_minutes": 2880, "description": "Low severity -- 8 hr ack, 48 hr resolve"},
]

AT_RISK_THRESHOLD = 0.80  # 80 % of resolve target consumed


def get_sla_policies(session: Session) -> list[dict]:
    """Return all SLA policies ordered by acknowledge_minutes ascending."""
    stmt = select(SLAPolicy).order_by(SLAPolicy.acknowledge_minutes)
    policies = session.execute(stmt).scalars().all()
    return [
        {
            "id": p.id,
            "severity": p.severity,
            "acknowledge_minutes": p.acknowledge_minutes,
            "resolve_minutes": p.resolve_minutes,
            "is_active": p.is_active,
            "description": p.description,
        }
        for p in policies
    ]


def set_sla_policy(
    session: Session,
    severity: str,
    acknowledge_minutes: int,
    resolve_minutes: int,
    description: str = None,
) -> dict:
    """Create or update an SLA policy for the given severity (upsert)."""
    severity = severity.lower().strip()

    stmt = select(SLAPolicy).where(SLAPolicy.severity == severity)
    policy = session.execute(stmt).scalar_one_or_none()

    if policy is None:
        policy = SLAPolicy(
            severity=severity,
            acknowledge_minutes=acknowledge_minutes,
            resolve_minutes=resolve_minutes,
            description=description,
            is_active=True,
        )
        session.add(policy)
    else:
        policy.acknowledge_minutes = acknowledge_minutes
        policy.resolve_minutes = resolve_minutes
        if description is not None:
            policy.description = description

    session.commit()
    return {
        "id": policy.id,
        "severity": policy.severity,
        "acknowledge_minutes": policy.acknowledge_minutes,
        "resolve_minutes": policy.resolve_minutes,
        "is_active": policy.is_active,
        "description": policy.description,
    }


def seed_default_policies(session: Session) -> None:
    """Insert default SLA policies if the table is empty."""
    count = session.execute(select(func.count(SLAPolicy.id))).scalar() or 0
    if count > 0:
        return

    for p in DEFAULT_POLICIES:
        session.add(SLAPolicy(is_active=True, **p))
    session.commit()
    logger.info("Seeded %d default SLA policies", len(DEFAULT_POLICIES))


def _load_active_policies(session: Session) -> dict[str, SLAPolicy]:
    """Return a dict mapping severity -> active SLAPolicy."""
    stmt = select(SLAPolicy).where(SLAPolicy.is_active == True)  # noqa: E712
    policies = session.execute(stmt).scalars().all()
    return {p.severity: p for p in policies}


def _minutes_between(start: datetime, end: datetime) -> float:
    """Compute minutes between two datetimes (timezone-naive safe)."""
    delta = end - start
    return delta.total_seconds() / 60.0


def _acknowledge_time_minutes(session: Session, case: AlertCase) -> float | None:
    """Compute minutes from case creation to first acknowledgement.

    Uses the case's own status -- if it ever moved to acknowledged or closed
    we look at the triage entries' updated_at for the earliest ack timestamp.
    Falls back to None if no ack signal is found.
    """
    # Find the earliest triage entry for this case that has status acknowledged or closed
    stmt = (
        select(func.min(AlertTriage.updated_at))
        .where(
            and_(
                AlertTriage.case_id == case.id,
                AlertTriage.status.in_([AlertTriageStatus.ACKNOWLEDGED, AlertTriageStatus.CLOSED]),
            )
        )
    )
    first_ack = session.execute(stmt).scalar_one_or_none()

    if first_ack is not None:
        return _minutes_between(case.created_at, first_ack)

    # If the case itself is acknowledged/closed, use its updated_at as a proxy
    if case.status in (AlertCaseStatus.ACKNOWLEDGED, AlertCaseStatus.CLOSED):
        return _minutes_between(case.created_at, case.updated_at)

    return None


def _already_logged(session: Session, case_id: int, breach_type: str) -> bool:
    """Check if a breach for this case + breach_type was already logged."""
    stmt = select(func.count(SLABreachLog.id)).where(
        and_(
            SLABreachLog.case_id == case_id,
            SLABreachLog.breach_type == breach_type,
        )
    )
    return (session.execute(stmt).scalar() or 0) > 0


def check_sla_compliance(session: Session, hours: int = 168) -> dict:
    """Evaluate SLA compliance for cases closed in the last *hours* hours.

    Returns a summary dict with overall stats, per-severity breakdown,
    recent breach details, and currently open at-risk cases.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=hours)
    policies = _load_active_policies(session)

    if not policies:
        return {
            "period_hours": hours,
            "total_cases": 0,
            "compliant": 0,
            "breached": 0,
            "compliance_rate": 0.0,
            "by_severity": {},
            "recent_breaches": [],
            "at_risk": [],
        }

    # ---- Closed cases in the window ----
    stmt = (
        select(AlertCase)
        .where(
            and_(
                AlertCase.status == AlertCaseStatus.CLOSED,
                AlertCase.closed_at >= cutoff,
            )
        )
    )
    closed_cases = session.execute(stmt).scalars().all()

    total = 0
    compliant = 0
    breached = 0
    recent_breaches: list[dict] = []

    by_severity: dict[str, dict] = {}
    for sev, pol in policies.items():
        by_severity[sev] = {
            "total": 0,
            "compliant": 0,
            "breached": 0,
            "ack_minutes_sum": 0.0,
            "resolve_minutes_sum": 0.0,
            "target_ack": pol.acknowledge_minutes,
            "target_resolve": pol.resolve_minutes,
        }

    for case in closed_cases:
        sev = (case.severity or "medium").lower()
        if sev not in policies:
            continue

        pol = policies[sev]
        bucket = by_severity[sev]
        bucket["total"] += 1
        total += 1

        ack_min = _acknowledge_time_minutes(session, case)
        resolve_min = _minutes_between(case.created_at, case.closed_at) if case.closed_at else None

        if ack_min is not None:
            bucket["ack_minutes_sum"] += ack_min
        if resolve_min is not None:
            bucket["resolve_minutes_sum"] += resolve_min

        case_breached = False

        # Check acknowledge breach
        if ack_min is not None and ack_min > pol.acknowledge_minutes:
            case_breached = True
            exceeded = ack_min - pol.acknowledge_minutes
            recent_breaches.append({
                "case_number": case.case_number,
                "severity": sev,
                "breach_type": "acknowledge",
                "target": pol.acknowledge_minutes,
                "actual": round(ack_min, 1),
                "exceeded_by": round(exceeded, 1),
            })
            if not _already_logged(session, case.id, "acknowledge"):
                session.add(SLABreachLog(
                    case_id=case.id,
                    severity=sev,
                    breach_type="acknowledge",
                    target_minutes=pol.acknowledge_minutes,
                    actual_minutes=round(ack_min, 1),
                    exceeded_by_minutes=round(exceeded, 1),
                ))

        # Check resolve breach
        if resolve_min is not None and resolve_min > pol.resolve_minutes:
            case_breached = True
            exceeded = resolve_min - pol.resolve_minutes
            recent_breaches.append({
                "case_number": case.case_number,
                "severity": sev,
                "breach_type": "resolve",
                "target": pol.resolve_minutes,
                "actual": round(resolve_min, 1),
                "exceeded_by": round(exceeded, 1),
            })
            if not _already_logged(session, case.id, "resolve"):
                session.add(SLABreachLog(
                    case_id=case.id,
                    severity=sev,
                    breach_type="resolve",
                    target_minutes=pol.resolve_minutes,
                    actual_minutes=round(resolve_min, 1),
                    exceeded_by_minutes=round(exceeded, 1),
                ))

        if case_breached:
            breached += 1
            bucket["breached"] += 1
        else:
            compliant += 1
            bucket["compliant"] += 1

    session.commit()

    # Build per-severity response with averages
    by_severity_out: dict[str, dict] = {}
    for sev, bucket in by_severity.items():
        cnt = bucket["total"] or 1
        by_severity_out[sev] = {
            "total": bucket["total"],
            "compliant": bucket["compliant"],
            "breached": bucket["breached"],
            "avg_acknowledge_min": round(bucket["ack_minutes_sum"] / cnt, 1) if bucket["total"] else 0.0,
            "avg_resolve_min": round(bucket["resolve_minutes_sum"] / cnt, 1) if bucket["total"] else 0.0,
            "target_ack": bucket["target_ack"],
            "target_resolve": bucket["target_resolve"],
        }

    # ---- At-risk: open cases approaching SLA breach ----
    stmt = select(AlertCase).where(
        AlertCase.status.in_([AlertCaseStatus.OPEN, AlertCaseStatus.ACKNOWLEDGED])
    )
    open_cases = session.execute(stmt).scalars().all()

    at_risk: list[dict] = []
    for case in open_cases:
        sev = (case.severity or "medium").lower()
        if sev not in policies:
            continue

        pol = policies[sev]
        minutes_open = _minutes_between(case.created_at, now)
        pct = (minutes_open / pol.resolve_minutes) if pol.resolve_minutes else 0.0

        if pct >= AT_RISK_THRESHOLD:
            at_risk.append({
                "case_number": case.case_number,
                "severity": sev,
                "minutes_open": round(minutes_open, 1),
                "target_minutes": pol.resolve_minutes,
                "pct_consumed": round(pct * 100, 1),
            })

    at_risk.sort(key=lambda x: x["pct_consumed"], reverse=True)

    compliance_rate = round((compliant / total) * 100, 1) if total else 0.0

    return {
        "period_hours": hours,
        "total_cases": total,
        "compliant": compliant,
        "breached": breached,
        "compliance_rate": compliance_rate,
        "by_severity": by_severity_out,
        "recent_breaches": recent_breaches,
        "at_risk": at_risk,
    }
