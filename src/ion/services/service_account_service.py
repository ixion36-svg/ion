"""Service account lifecycle tracker — password rotation, staleness, and risk assessment."""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session

from ion.models.oncall import ServiceAccount
from ion.models.user import User

logger = logging.getLogger(__name__)


def _parse_json(raw: Optional[str]) -> list | dict | None:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def _account_to_dict(acct: ServiceAccount) -> dict:
    return {
        "id": acct.id,
        "account_name": acct.account_name,
        "display_name": acct.display_name,
        "description": acct.description,
        "owner_id": acct.owner_id,
        "owner_username": acct.owner.username if acct.owner else None,
        "department": acct.department,
        "account_type": acct.account_type,
        "status": acct.status,
        "password_last_set": acct.password_last_set.isoformat() if acct.password_last_set else None,
        "password_expires": acct.password_expires.isoformat() if acct.password_expires else None,
        "password_never_expires": acct.password_never_expires,
        "rotation_days": acct.rotation_days,
        "last_logon": acct.last_logon.isoformat() if acct.last_logon else None,
        "systems": _parse_json(acct.systems),
        "permissions": _parse_json(acct.permissions),
        "spn": acct.spn,
        "risk_level": acct.risk_level,
        "review_date": acct.review_date.isoformat() if acct.review_date else None,
        "notes": acct.notes,
        "created_at": acct.created_at.isoformat() if acct.created_at else None,
        "updated_at": acct.updated_at.isoformat() if acct.updated_at else None,
    }


def get_service_accounts(
    session: Session,
    status: Optional[str] = None,
    risk_level: Optional[str] = None,
) -> list[dict]:
    query = select(ServiceAccount).order_by(ServiceAccount.account_name)
    if status:
        query = query.where(ServiceAccount.status == status)
    if risk_level:
        query = query.where(ServiceAccount.risk_level == risk_level)
    accounts = session.execute(query).scalars().all()
    return [_account_to_dict(a) for a in accounts]


def get_service_account(session: Session, account_id: int) -> dict:
    acct = session.get(ServiceAccount, account_id)
    if not acct:
        return {}
    return _account_to_dict(acct)


def create_service_account(session: Session, **kwargs) -> dict:
    for field in ("systems", "permissions"):
        if field in kwargs and isinstance(kwargs[field], (list, dict)):
            kwargs[field] = json.dumps(kwargs[field])
    acct = ServiceAccount(**kwargs)
    session.add(acct)
    session.flush()
    session.refresh(acct)
    return _account_to_dict(acct)


def update_service_account(session: Session, account_id: int, **kwargs) -> dict:
    acct = session.get(ServiceAccount, account_id)
    if not acct:
        return {}
    for field in ("systems", "permissions"):
        if field in kwargs and isinstance(kwargs[field], (list, dict)):
            kwargs[field] = json.dumps(kwargs[field])
    for key, value in kwargs.items():
        if hasattr(acct, key):
            setattr(acct, key, value)
    session.flush()
    session.refresh(acct)
    return _account_to_dict(acct)


def get_stale_accounts(session: Session, stale_days: int = 90) -> list[dict]:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=stale_days)

    query = (
        select(ServiceAccount)
        .where(
            and_(
                ServiceAccount.status.in_(["active", "pending_review"]),
                (ServiceAccount.password_last_set < cutoff)
                | (ServiceAccount.password_last_set.is_(None)),
            )
        )
    )
    accounts = session.execute(query).scalars().all()

    results = []
    for acct in accounts:
        d = _account_to_dict(acct)
        if acct.password_last_set:
            pwd_aware = acct.password_last_set.replace(tzinfo=timezone.utc) if acct.password_last_set.tzinfo is None else acct.password_last_set
            d["days_since_rotation"] = (now - pwd_aware).days
        else:
            d["days_since_rotation"] = None
        results.append(d)

    results.sort(key=lambda x: x["days_since_rotation"] if x["days_since_rotation"] is not None else 999999, reverse=True)
    return results


def get_account_risk_summary(session: Session) -> dict:
    risk_q = (
        select(ServiceAccount.risk_level, func.count(ServiceAccount.id))
        .where(ServiceAccount.status.in_(["active", "pending_review"]))
        .group_by(ServiceAccount.risk_level)
    )
    by_risk = {}
    for level, count in session.execute(risk_q).all():
        by_risk[level] = count

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=90)
    stale_count = session.execute(
        select(func.count(ServiceAccount.id)).where(
            and_(
                ServiceAccount.status.in_(["active", "pending_review"]),
                (ServiceAccount.password_last_set < cutoff)
                | (ServiceAccount.password_last_set.is_(None)),
            )
        )
    ).scalar() or 0

    never_expires_count = session.execute(
        select(func.count(ServiceAccount.id)).where(
            and_(
                ServiceAccount.status.in_(["active", "pending_review"]),
                ServiceAccount.password_never_expires == True,
            )
        )
    ).scalar() or 0

    total_active = session.execute(
        select(func.count(ServiceAccount.id)).where(
            ServiceAccount.status.in_(["active", "pending_review"])
        )
    ).scalar() or 0

    return {
        "total_active": total_active,
        "by_risk_level": by_risk,
        "stale_count": stale_count,
        "never_expires_count": never_expires_count,
    }
