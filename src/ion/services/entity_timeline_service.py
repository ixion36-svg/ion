"""Entity Timeline service — unified cross-source timeline for any host, IP, or user.

Pulls events from:
- AlertTriage / AlertCase (ION case data)
- Observable enrichments
- Forensic case entries
- AI chat analysis
- AuditLog (analyst actions)
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select, or_, and_, desc, func
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertTriage, AlertCase
from ion.models.user import AuditLog, User
from ion.models.observable import Observable, ObservableEnrichment

logger = logging.getLogger(__name__)


def get_entity_timeline(
    session: Session,
    entity_value: str,
    entity_type: str = "auto",
    hours: int = 168,
    limit: int = 200,
) -> dict[str, Any]:
    """Build a unified timeline for an entity (host, IP, user, domain, hash).

    Args:
        session: DB session
        entity_value: The entity to search for (IP, hostname, username, domain, etc.)
        entity_type: "ip", "host", "user", "domain", "hash", or "auto" to detect
        hours: Lookback window
        limit: Max events to return

    Returns:
        Timeline with events from all sources, sorted chronologically.
    """
    if entity_type == "auto":
        entity_type = _detect_type(entity_value)

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    events: list[dict] = []

    # 1. Cases mentioning this entity
    events.extend(_search_cases(session, entity_value, cutoff))

    # 2. Alert triage entries
    events.extend(_search_triage(session, entity_value, cutoff))

    # 3. Observables
    events.extend(_search_observables(session, entity_value, cutoff))

    # 4. Audit log (analyst actions mentioning this entity)
    events.extend(_search_audit(session, entity_value, cutoff))

    # Sort by timestamp descending
    events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)

    # Deduplicate by (source, id)
    seen = set()
    deduped = []
    for e in events:
        key = (e.get("source"), e.get("source_id"))
        if key not in seen:
            seen.add(key)
            deduped.append(e)

    return {
        "entity_value": entity_value,
        "entity_type": entity_type,
        "hours": hours,
        "total_events": len(deduped),
        "events": deduped[:limit],
        "sources": list({e["source"] for e in deduped}),
    }


def _detect_type(value: str) -> str:
    """Auto-detect entity type from the value."""
    import re
    v = value.strip()
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", v):
        return "ip"
    if re.match(r"^[0-9a-fA-F]{32,64}$", v):
        return "hash"
    if "." in v and not v.startswith("/") and "@" not in v:
        return "domain"
    if "@" in v:
        return "email"
    return "host"


def _search_cases(session: Session, entity: str, cutoff: datetime) -> list[dict]:
    """Search AlertCase for mentions in affected_hosts, affected_users, title, description."""
    events = []
    like_pattern = f"%{entity}%"

    cases = session.execute(
        select(AlertCase).where(
            and_(
                AlertCase.created_at >= cutoff,
                or_(
                    AlertCase.title.ilike(like_pattern),
                    AlertCase.description.ilike(like_pattern),
                    AlertCase.evidence_summary.ilike(like_pattern),
                )
            )
        ).order_by(desc(AlertCase.created_at)).limit(50)
    ).scalars().all()

    for c in cases:
        events.append({
            "timestamp": c.created_at.isoformat() if c.created_at else None,
            "source": "case",
            "source_id": str(c.id),
            "title": f"Case {c.case_number}: {c.title}",
            "severity": c.severity or "unknown",
            "status": c.status,
            "detail": (c.description or "")[:300],
            "meta": {
                "case_number": c.case_number,
                "closure_reason": c.closure_reason,
                "assigned_to_id": c.assigned_to_id,
            },
        })

    # Also check JSON fields for entity match
    all_cases = session.execute(
        select(AlertCase).where(AlertCase.created_at >= cutoff)
    ).scalars().all()

    for c in all_cases:
        if c.id in {int(e["source_id"]) for e in events if e["source"] == "case"}:
            continue
        hosts = c.affected_hosts or []
        users = c.affected_users or []
        if isinstance(hosts, str):
            try: hosts = json.loads(hosts)
            except: hosts = []
        if isinstance(users, str):
            try: users = json.loads(users)
            except: users = []

        entity_lower = entity.lower()
        matched = any(entity_lower in str(h).lower() for h in hosts) or \
                  any(entity_lower in str(u).lower() for u in users)
        if matched:
            events.append({
                "timestamp": c.created_at.isoformat() if c.created_at else None,
                "source": "case",
                "source_id": str(c.id),
                "title": f"Case {c.case_number}: {c.title}",
                "severity": c.severity or "unknown",
                "status": c.status,
                "detail": f"Entity found in affected hosts/users",
                "meta": {"case_number": c.case_number},
            })

    return events


def _search_triage(session: Session, entity: str, cutoff: datetime) -> list[dict]:
    """Search AlertTriage for mentions in notes or observables."""
    events = []
    like_pattern = f"%{entity}%"

    triages = session.execute(
        select(AlertTriage).where(
            and_(
                AlertTriage.updated_at >= cutoff,
                or_(
                    AlertTriage.analyst_notes.ilike(like_pattern),
                    AlertTriage.es_alert_id.ilike(like_pattern),
                )
            )
        ).order_by(desc(AlertTriage.updated_at)).limit(30)
    ).scalars().all()

    for t in triages:
        events.append({
            "timestamp": t.updated_at.isoformat() if t.updated_at else None,
            "source": "triage",
            "source_id": str(t.id),
            "title": f"Alert Triage: {t.es_alert_id[:40]}...",
            "severity": t.priority or "unknown",
            "status": t.status,
            "detail": (t.analyst_notes or "")[:200],
            "meta": {"es_alert_id": t.es_alert_id},
        })

    return events


def _search_observables(session: Session, entity: str, cutoff: datetime) -> list[dict]:
    """Search observables matching the entity value."""
    events = []

    observables = session.execute(
        select(Observable).where(
            Observable.value.ilike(f"%{entity}%")
        ).order_by(desc(Observable.last_seen)).limit(20)
    ).scalars().all()

    for o in observables:
        ts = o.last_seen or o.first_seen or o.created_at
        events.append({
            "timestamp": ts.isoformat() if ts else None,
            "source": "observable",
            "source_id": str(o.id),
            "title": f"Observable: {o.value}",
            "severity": o.threat_level or "unknown",
            "status": "active" if not o.is_whitelisted else "whitelisted",
            "detail": f"Type: {o.type.value if o.type else 'unknown'}, Sightings: {o.sighting_count or 0}",
            "meta": {
                "type": o.type.value if o.type else None,
                "threat_level": o.threat_level,
                "sighting_count": o.sighting_count,
                "first_seen": o.first_seen.isoformat() if o.first_seen else None,
            },
        })

    # Get enrichments for matched observables
    for o in observables:
        enrichments = session.execute(
            select(ObservableEnrichment).where(
                ObservableEnrichment.observable_id == o.id
            ).order_by(desc(ObservableEnrichment.enriched_at)).limit(5)
        ).scalars().all()

        for e in enrichments:
            events.append({
                "timestamp": e.enriched_at.isoformat() if e.enriched_at else None,
                "source": "enrichment",
                "source_id": f"enrich-{e.id}",
                "title": f"Enrichment: {o.value} via {e.source}",
                "severity": "info",
                "status": "enriched",
                "detail": f"Source: {e.source}",
                "meta": {"observable_value": o.value, "enrichment_source": e.source},
            })

    return events


def _search_audit(session: Session, entity: str, cutoff: datetime) -> list[dict]:
    """Search audit log for analyst actions mentioning this entity."""
    events = []
    like_pattern = f"%{entity}%"

    audits = session.execute(
        select(AuditLog, User.username)
        .outerjoin(User, AuditLog.user_id == User.id)
        .where(
            and_(
                AuditLog.timestamp >= cutoff,
                AuditLog.details.ilike(like_pattern),
            )
        )
        .order_by(desc(AuditLog.timestamp))
        .limit(30)
    ).all()

    for audit, username in audits:
        events.append({
            "timestamp": audit.timestamp.isoformat() if audit.timestamp else None,
            "source": "audit",
            "source_id": str(audit.id),
            "title": f"{username or 'system'}: {audit.action}",
            "severity": "info",
            "status": audit.action,
            "detail": (audit.details or "")[:200],
            "meta": {
                "action": audit.action,
                "resource_type": audit.resource_type,
                "resource_id": audit.resource_id,
                "analyst": username,
            },
        })

    return events
