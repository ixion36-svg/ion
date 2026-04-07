"""Threat hunting workbench -- hypothesis tracking, query logging, and findings."""

import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session

from ion.models.sla import ThreatHunt
from ion.models.user import User

logger = logging.getLogger(__name__)

VALID_STATUSES = ("active", "confirmed", "refuted", "inconclusive")
VALID_PRIORITIES = ("critical", "high", "medium", "low")


def _safe_json_loads(raw: str | None, fallback=None):
    """Parse a JSON string, returning *fallback* on failure."""
    if not raw:
        return fallback if fallback is not None else []
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return fallback if fallback is not None else []


def _hunt_to_dict(hunt: ThreatHunt) -> dict:
    """Serialise a ThreatHunt row to a plain dict."""
    created_by = hunt.created_by
    assigned_to = hunt.assigned_to

    return {
        "id": hunt.id,
        "title": hunt.title,
        "hypothesis": hunt.hypothesis,
        "status": hunt.status,
        "priority": hunt.priority,
        "created_by": {
            "user_id": hunt.created_by_id,
            "username": created_by.username if created_by else None,
            "display_name": created_by.display_name if created_by else None,
        },
        "assigned_to": {
            "user_id": hunt.assigned_to_id,
            "username": assigned_to.username if assigned_to else None,
            "display_name": assigned_to.display_name if assigned_to else None,
        } if hunt.assigned_to_id else None,
        "threat_actor": hunt.threat_actor,
        "mitre_techniques": _safe_json_loads(hunt.mitre_techniques),
        "data_sources": _safe_json_loads(hunt.data_sources),
        "queries": _safe_json_loads(hunt.queries),
        "findings": hunt.findings,
        "conclusion": hunt.conclusion,
        "iocs_found": _safe_json_loads(hunt.iocs_found),
        "closed_at": hunt.closed_at.isoformat() if hunt.closed_at else None,
        "created_at": hunt.created_at.isoformat() if hunt.created_at else None,
        "updated_at": hunt.updated_at.isoformat() if hunt.updated_at else None,
    }


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def get_hunts(session: Session, status: str = None, limit: int = 50) -> list[dict]:
    """Return threat hunts, optionally filtered by status."""
    stmt = select(ThreatHunt).order_by(ThreatHunt.created_at.desc()).limit(limit)
    if status is not None:
        stmt = stmt.where(ThreatHunt.status == status)
    hunts = session.execute(stmt).scalars().all()
    return [_hunt_to_dict(h) for h in hunts]


def get_hunt(session: Session, hunt_id: int) -> dict:
    """Return a single threat hunt by ID, or raise ValueError."""
    hunt = session.get(ThreatHunt, hunt_id)
    if hunt is None:
        raise ValueError(f"Threat hunt {hunt_id} not found")
    return _hunt_to_dict(hunt)


def create_hunt(
    session: Session,
    created_by_id: int,
    title: str,
    hypothesis: str,
    priority: str = "medium",
    threat_actor: str = None,
    mitre_techniques: list = None,
    data_sources: list = None,
) -> dict:
    """Create a new threat hunt."""
    priority = priority.lower().strip()
    if priority not in VALID_PRIORITIES:
        priority = "medium"

    hunt = ThreatHunt(
        title=title,
        hypothesis=hypothesis,
        status="active",
        priority=priority,
        created_by_id=created_by_id,
        threat_actor=threat_actor,
        mitre_techniques=json.dumps(mitre_techniques or []),
        data_sources=json.dumps(data_sources or []),
        queries=json.dumps([]),
        findings=None,
        iocs_found=json.dumps([]),
    )
    session.add(hunt)
    session.commit()
    logger.info("Created threat hunt #%d: %s", hunt.id, title)
    return _hunt_to_dict(hunt)


def update_hunt(session: Session, hunt_id: int, **kwargs) -> dict:
    """Update arbitrary fields on a threat hunt."""
    hunt = session.get(ThreatHunt, hunt_id)
    if hunt is None:
        raise ValueError(f"Threat hunt {hunt_id} not found")

    json_fields = {"mitre_techniques", "data_sources", "queries", "iocs_found"}

    for key, value in kwargs.items():
        if not hasattr(hunt, key) or key in ("id", "created_at", "created_by_id"):
            continue
        if key in json_fields and isinstance(value, (list, dict)):
            value = json.dumps(value)
        setattr(hunt, key, value)

    session.commit()
    return _hunt_to_dict(hunt)


# ---------------------------------------------------------------------------
# Queries & Findings
# ---------------------------------------------------------------------------

def add_query(
    session: Session,
    hunt_id: int,
    query: str,
    description: str = "",
    result_count: int = 0,
) -> dict:
    """Append a query entry to the hunt's queries JSON list."""
    hunt = session.get(ThreatHunt, hunt_id)
    if hunt is None:
        raise ValueError(f"Threat hunt {hunt_id} not found")

    queries = _safe_json_loads(hunt.queries)
    queries.append({
        "query": query,
        "description": description,
        "result_count": result_count,
        "added_at": datetime.now(timezone.utc).isoformat(),
    })
    hunt.queries = json.dumps(queries)
    session.commit()
    return _hunt_to_dict(hunt)


def add_finding(session: Session, hunt_id: int, finding_text: str) -> dict:
    """Append a finding paragraph to the hunt's findings markdown field."""
    hunt = session.get(ThreatHunt, hunt_id)
    if hunt is None:
        raise ValueError(f"Threat hunt {hunt_id} not found")

    existing = hunt.findings or ""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    entry = f"\n\n**[{timestamp}]** {finding_text}" if existing else f"**[{timestamp}]** {finding_text}"
    hunt.findings = existing + entry
    session.commit()
    return _hunt_to_dict(hunt)


def close_hunt(
    session: Session,
    hunt_id: int,
    status: str,
    conclusion: str,
    iocs_found: list = None,
) -> dict:
    """Close a threat hunt with a final status and conclusion."""
    hunt = session.get(ThreatHunt, hunt_id)
    if hunt is None:
        raise ValueError(f"Threat hunt {hunt_id} not found")

    status = status.lower().strip()
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Must be one of: {', '.join(VALID_STATUSES)}")

    hunt.status = status
    hunt.conclusion = conclusion
    hunt.closed_at = datetime.now(timezone.utc)

    if iocs_found is not None:
        hunt.iocs_found = json.dumps(iocs_found)

    session.commit()
    logger.info("Closed threat hunt #%d as %s", hunt.id, status)
    return _hunt_to_dict(hunt)


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def get_hunt_stats(session: Session) -> dict:
    """Return aggregate statistics for all threat hunts."""
    total = session.execute(select(func.count(ThreatHunt.id))).scalar() or 0

    # By status
    status_rows = session.execute(
        select(ThreatHunt.status, func.count(ThreatHunt.id))
        .group_by(ThreatHunt.status)
    ).all()
    by_status = {status: count for status, count in status_rows}

    # By priority
    priority_rows = session.execute(
        select(ThreatHunt.priority, func.count(ThreatHunt.id))
        .group_by(ThreatHunt.priority)
    ).all()
    by_priority = {priority: count for priority, count in priority_rows}

    # Average duration (for closed hunts)
    stmt = (
        select(ThreatHunt.created_at, ThreatHunt.closed_at)
        .where(ThreatHunt.closed_at.isnot(None))
    )
    closed_hunts = session.execute(stmt).all()

    avg_duration_hours = 0.0
    if closed_hunts:
        durations = []
        for created_at, closed_at in closed_hunts:
            delta = closed_at - created_at
            durations.append(delta.total_seconds() / 3600.0)
        avg_duration_hours = round(sum(durations) / len(durations), 1) if durations else 0.0

    return {
        "total": total,
        "by_status": by_status,
        "by_priority": by_priority,
        "avg_duration_hours": avg_duration_hours,
    }
