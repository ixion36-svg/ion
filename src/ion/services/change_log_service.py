"""Change management log — tracks configuration, rule, and system changes with approval workflow."""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session

from ion.models.oncall import ChangeLogEntry
from ion.models.user import User

logger = logging.getLogger(__name__)


def _parse_json(raw: Optional[str]) -> list | dict | None:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def _entry_to_dict(entry: ChangeLogEntry) -> dict:
    return {
        "id": entry.id,
        "change_type": entry.change_type,
        "title": entry.title,
        "description": entry.description,
        "changed_by_id": entry.changed_by_id,
        "changed_by_username": entry.changed_by.username if entry.changed_by else None,
        "approved_by_id": entry.approved_by_id,
        "approved_by_username": entry.approved_by.username if entry.approved_by else None,
        "status": entry.status,
        "rollback_notes": entry.rollback_notes,
        "affected_systems": _parse_json(entry.affected_systems),
        "risk_level": entry.risk_level,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
        "updated_at": entry.updated_at.isoformat() if entry.updated_at else None,
    }


def get_change_log(
    session: Session,
    change_type: Optional[str] = None,
    limit: int = 50,
) -> list[dict]:
    query = select(ChangeLogEntry).order_by(ChangeLogEntry.created_at.desc()).limit(limit)
    if change_type:
        query = query.where(ChangeLogEntry.change_type == change_type)
    entries = session.execute(query).scalars().all()
    return [_entry_to_dict(e) for e in entries]


def create_change(
    session: Session,
    changed_by_id: int,
    change_type: str,
    title: str,
    description: Optional[str] = None,
    affected_systems: Optional[list | str] = None,
    risk_level: str = "low",
) -> dict:
    if isinstance(affected_systems, list):
        affected_systems = json.dumps(affected_systems)
    entry = ChangeLogEntry(
        changed_by_id=changed_by_id,
        change_type=change_type,
        title=title,
        description=description,
        affected_systems=affected_systems,
        risk_level=risk_level,
        status="applied",
    )
    session.add(entry)
    session.flush()
    session.refresh(entry)
    return _entry_to_dict(entry)


def approve_change(session: Session, change_id: int, approved_by_id: int) -> dict:
    entry = session.get(ChangeLogEntry, change_id)
    if not entry:
        return {}
    entry.approved_by_id = approved_by_id
    entry.status = "approved"
    session.flush()
    session.refresh(entry)
    return _entry_to_dict(entry)


def rollback_change(session: Session, change_id: int, rollback_notes: str) -> dict:
    entry = session.get(ChangeLogEntry, change_id)
    if not entry:
        return {}
    entry.status = "rolled_back"
    entry.rollback_notes = rollback_notes
    session.flush()
    session.refresh(entry)
    return _entry_to_dict(entry)


def get_change_summary(session: Session, days: int = 30) -> dict:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    recent_query = select(ChangeLogEntry).where(
        ChangeLogEntry.created_at >= cutoff
    )
    recent = session.execute(recent_query).scalars().all()

    by_type: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    by_status: dict[str, int] = {}

    for entry in recent:
        by_type[entry.change_type] = by_type.get(entry.change_type, 0) + 1
        by_risk[entry.risk_level] = by_risk.get(entry.risk_level, 0) + 1
        by_status[entry.status] = by_status.get(entry.status, 0) + 1

    recent_entries = sorted(recent, key=lambda e: e.created_at, reverse=True)[:10]

    return {
        "period_days": days,
        "total_changes": len(recent),
        "by_type": by_type,
        "by_risk_level": by_risk,
        "by_status": by_status,
        "recent_changes": [_entry_to_dict(e) for e in recent_entries],
    }
