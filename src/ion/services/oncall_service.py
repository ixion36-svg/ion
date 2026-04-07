"""On-Call roster and escalation management service."""

import logging
from datetime import date, datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, and_, func
from sqlalchemy.orm import Session

from ion.models.oncall import OnCallRoster, EscalationPolicy, EscalationLog
from ion.models.user import User, Role, user_roles

logger = logging.getLogger(__name__)

ROLE_TYPES = ("duty_im", "primary_analyst", "secondary_analyst", "engineer_oncall")


def get_current_oncall(session: Session) -> dict:
    """Return who is on call RIGHT NOW for each role_type.

    Queries OnCallRoster where date = today, joins with User, and
    returns a dict keyed by role_type with user details or None.
    """
    today = date.today()

    stmt = (
        select(OnCallRoster, User)
        .join(User, OnCallRoster.user_id == User.id)
        .where(OnCallRoster.date == today)
    )
    rows = session.execute(stmt).all()

    roster: dict[str, Optional[dict]] = {rt: None for rt in ROLE_TYPES}
    for entry, user in rows:
        if entry.role_type in roster:
            roster[entry.role_type] = {
                "user_id": user.id,
                "username": user.username,
                "display_name": user.display_name,
                "contact_phone": entry.contact_phone,
                "contact_alt": entry.contact_alt,
                "shift": entry.shift,
                "notes": entry.notes,
            }

    return {"date": today.isoformat(), "roster": roster}


def get_roster_week(session: Session, start_date: date = None) -> list[dict]:
    """Return 7 days of roster entries starting from *start_date* (default: today).

    Each element represents one day with all role_type entries.
    """
    if start_date is None:
        start_date = date.today()

    end_date = start_date + timedelta(days=6)

    stmt = (
        select(OnCallRoster, User)
        .join(User, OnCallRoster.user_id == User.id)
        .where(
            and_(
                OnCallRoster.date >= start_date,
                OnCallRoster.date <= end_date,
            )
        )
        .order_by(OnCallRoster.date, OnCallRoster.role_type)
    )
    rows = session.execute(stmt).all()

    # Index entries by date
    by_date: dict[date, dict] = {}
    for entry, user in rows:
        day_key = entry.date
        if day_key not in by_date:
            by_date[day_key] = {rt: None for rt in ROLE_TYPES}
        by_date[day_key][entry.role_type] = {
            "user_id": user.id,
            "username": user.username,
            "display_name": user.display_name,
            "contact_phone": entry.contact_phone,
            "contact_alt": entry.contact_alt,
            "shift": entry.shift,
            "notes": entry.notes,
        }

    week = []
    for i in range(7):
        d = start_date + timedelta(days=i)
        week.append({
            "date": d.isoformat(),
            "roster": by_date.get(d, {rt: None for rt in ROLE_TYPES}),
        })

    return week


def set_oncall(
    session: Session,
    user_id: int,
    roster_date: date,
    role_type: str,
    shift: str = "day",
    contact_phone: str = None,
    contact_alt: str = None,
    notes: str = None,
) -> dict:
    """Create or update an on-call entry (upsert by user_id + date + role_type)."""
    stmt = select(OnCallRoster).where(
        and_(
            OnCallRoster.user_id == user_id,
            OnCallRoster.date == roster_date,
            OnCallRoster.role_type == role_type,
        )
    )
    entry = session.execute(stmt).scalar_one_or_none()

    if entry is None:
        entry = OnCallRoster(
            user_id=user_id,
            date=roster_date,
            role_type=role_type,
            shift=shift,
            contact_phone=contact_phone,
            contact_alt=contact_alt,
            notes=notes,
        )
        session.add(entry)
    else:
        entry.shift = shift
        if contact_phone is not None:
            entry.contact_phone = contact_phone
        if contact_alt is not None:
            entry.contact_alt = contact_alt
        if notes is not None:
            entry.notes = notes

    session.commit()

    user = session.get(User, user_id)
    return {
        "id": entry.id,
        "user_id": user_id,
        "username": user.username if user else None,
        "display_name": user.display_name if user else None,
        "date": roster_date.isoformat(),
        "role_type": role_type,
        "shift": entry.shift,
        "contact_phone": entry.contact_phone,
        "contact_alt": entry.contact_alt,
        "notes": entry.notes,
    }


def get_escalation_policies(session: Session) -> list[dict]:
    """Return all active escalation policies."""
    stmt = (
        select(EscalationPolicy)
        .where(EscalationPolicy.is_active == True)
        .order_by(EscalationPolicy.name)
    )
    policies = session.execute(stmt).scalars().all()

    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "severity_threshold": p.severity_threshold,
            "auto_escalate_minutes": p.auto_escalate_minutes,
            "escalate_to_role": p.escalate_to_role,
            "notify_method": p.notify_method,
            "conditions": p.conditions,
        }
        for p in policies
    ]


def _find_duty_im_user_id(session: Session) -> Optional[int]:
    """Find today's duty IM from the on-call roster.

    Falls back to any active lead or admin user if no duty IM is scheduled.
    """
    today = date.today()

    # Primary: today's duty_im
    stmt = select(OnCallRoster.user_id).where(
        and_(
            OnCallRoster.date == today,
            OnCallRoster.role_type == "duty_im",
        )
    )
    duty_im_id = session.execute(stmt).scalar_one_or_none()
    if duty_im_id is not None:
        return duty_im_id

    # Fallback: find any active user with lead or admin role
    stmt = (
        select(User.id)
        .join(user_roles, user_roles.c.user_id == User.id)
        .join(Role, Role.id == user_roles.c.role_id)
        .where(
            and_(
                User.is_active == True,
                Role.name.in_(["lead", "admin"]),
            )
        )
        .limit(1)
    )
    fallback_id = session.execute(stmt).scalar_one_or_none()
    return fallback_id


def escalate_to_duty_im(
    session: Session,
    escalated_by_id: int,
    severity: str,
    reason: str,
    case_id: int = None,
    alert_id: str = None,
) -> dict:
    """Create an escalation log entry and notify the duty IM.

    Finds today's duty IM from the on-call roster. If none is scheduled,
    falls back to any lead/admin user. Creates a notification for the
    target user.
    """
    duty_im_user_id = _find_duty_im_user_id(session)
    if duty_im_user_id is None:
        raise ValueError("No duty IM or lead/admin user available for escalation")

    entry = EscalationLog(
        case_id=case_id,
        alert_id=alert_id,
        escalated_by_id=escalated_by_id,
        escalated_to_id=duty_im_user_id,
        severity=severity,
        reason=reason,
        status="pending",
    )
    session.add(entry)
    session.flush()

    # Build notification
    escalated_by = session.get(User, escalated_by_id)
    by_name = escalated_by.display_name or escalated_by.username if escalated_by else "Unknown"
    title = f"Escalation ({severity.upper()})"
    message = f"{by_name} escalated: {reason}"

    from ion.web.notification_api import create_notification

    create_notification(
        session,
        user_id=duty_im_user_id,
        source="escalation",
        title=title,
        body=message,
        url="/cases",
        source_id=str(entry.id),
    )
    session.commit()

    escalated_to = session.get(User, duty_im_user_id)
    return {
        "id": entry.id,
        "case_id": entry.case_id,
        "alert_id": entry.alert_id,
        "escalated_by": by_name,
        "escalated_to": escalated_to.display_name or escalated_to.username if escalated_to else None,
        "escalated_to_id": duty_im_user_id,
        "severity": entry.severity,
        "reason": entry.reason,
        "status": entry.status,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


def get_escalation_log(session: Session, limit: int = 50) -> list[dict]:
    """Return recent escalation log entries with user details."""
    stmt = (
        select(EscalationLog)
        .order_by(EscalationLog.created_at.desc())
        .limit(limit)
    )
    entries = session.execute(stmt).scalars().all()

    results = []
    for e in entries:
        by_user = session.get(User, e.escalated_by_id)
        to_user = session.get(User, e.escalated_to_id)
        results.append({
            "id": e.id,
            "case_id": e.case_id,
            "alert_id": e.alert_id,
            "escalated_by": {
                "user_id": e.escalated_by_id,
                "username": by_user.username if by_user else None,
                "display_name": by_user.display_name if by_user else None,
            },
            "escalated_to": {
                "user_id": e.escalated_to_id,
                "username": to_user.username if to_user else None,
                "display_name": to_user.display_name if to_user else None,
            },
            "severity": e.severity,
            "reason": e.reason,
            "status": e.status,
            "acknowledged_at": e.acknowledged_at.isoformat() if e.acknowledged_at else None,
            "resolved_at": e.resolved_at.isoformat() if e.resolved_at else None,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        })

    return results


def acknowledge_escalation(session: Session, escalation_id: int, user_id: int) -> dict:
    """Mark an escalation as acknowledged with a timestamp."""
    entry = session.get(EscalationLog, escalation_id)
    if entry is None:
        raise ValueError(f"Escalation {escalation_id} not found")

    entry.status = "acknowledged"
    entry.acknowledged_at = datetime.now(timezone.utc)
    session.commit()

    by_user = session.get(User, entry.escalated_by_id)
    to_user = session.get(User, entry.escalated_to_id)
    return {
        "id": entry.id,
        "case_id": entry.case_id,
        "alert_id": entry.alert_id,
        "escalated_by": by_user.display_name or by_user.username if by_user else None,
        "escalated_to": to_user.display_name or to_user.username if to_user else None,
        "severity": entry.severity,
        "reason": entry.reason,
        "status": entry.status,
        "acknowledged_at": entry.acknowledged_at.isoformat() if entry.acknowledged_at else None,
        "resolved_at": entry.resolved_at.isoformat() if entry.resolved_at else None,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }
