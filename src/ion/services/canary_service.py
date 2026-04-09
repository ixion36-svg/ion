"""Canary / Deception Tracker service.

Two responsibilities:

1. CRUD over the canary registry (planted decoys).
2. Periodic scanning of recent ES alerts to find any that mention an active
   canary's value, and recording each match as a ``CanaryHit`` for the audit
   trail.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.canary import Canary, CanaryHit, CanaryStatus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def list_canaries(
    session: Session,
    status: Optional[str] = None,
    canary_type: Optional[str] = None,
) -> List[dict]:
    stmt = select(Canary).order_by(Canary.created_at.desc())
    if status:
        stmt = stmt.where(Canary.status == status)
    if canary_type:
        stmt = stmt.where(Canary.canary_type == canary_type)
    rows = session.execute(stmt).scalars().all()
    return [c.to_dict() for c in rows]


def get_canary(session: Session, canary_id: int) -> Optional[Canary]:
    return session.get(Canary, canary_id)


def create_canary(
    session: Session,
    *,
    name: str,
    canary_type: str,
    value: str,
    description: Optional[str],
    location: Optional[str],
    tags: Optional[list],
    high_confidence: bool,
    created_by_id: int,
) -> Canary:
    c = Canary(
        name=name.strip(),
        canary_type=canary_type,
        value=value.strip(),
        description=description,
        location=location,
        tags=tags or [],
        high_confidence=high_confidence,
        status=CanaryStatus.ACTIVE.value,
        created_by_id=created_by_id,
    )
    session.add(c)
    session.commit()
    session.refresh(c)
    return c


def update_canary(
    session: Session,
    canary_id: int,
    **fields,
) -> Optional[Canary]:
    c = session.get(Canary, canary_id)
    if not c:
        return None
    allowed = {
        "name", "canary_type", "value", "description", "status",
        "location", "tags", "high_confidence",
    }
    for k, v in fields.items():
        if k in allowed and v is not None:
            setattr(c, k, v)
    session.commit()
    session.refresh(c)
    return c


def delete_canary(session: Session, canary_id: int) -> bool:
    c = session.get(Canary, canary_id)
    if not c:
        return False
    session.delete(c)
    session.commit()
    return True


def list_hits(session: Session, canary_id: Optional[int] = None, limit: int = 100) -> List[dict]:
    stmt = select(CanaryHit).order_by(CanaryHit.detected_at.desc()).limit(limit)
    if canary_id:
        stmt = stmt.where(CanaryHit.canary_id == canary_id)
    rows = session.execute(stmt).scalars().all()
    return [h.to_dict() for h in rows]


# ---------------------------------------------------------------------------
# Scanner — finds canary mentions in recent ES alerts
# ---------------------------------------------------------------------------

def _alert_text_blob(alert: dict) -> str:
    """Concatenate fields most likely to mention a canary value into one string."""
    parts = []
    for k in (
        "rule_name", "title", "message", "description",
        "host", "user", "source_ip", "destination_ip",
        "process", "file", "url", "command_line",
    ):
        v = alert.get(k)
        if v:
            parts.append(str(v))
    # Walk shallow nested fields too
    for k in ("event", "process", "file", "user", "host", "source", "destination", "url"):
        v = alert.get(k)
        if isinstance(v, dict):
            for vv in v.values():
                if isinstance(vv, (str, int)):
                    parts.append(str(vv))
    return "\n".join(parts).lower()


async def scan_recent_alerts(session: Session, hours: int = 24, limit: int = 500) -> dict:
    """Pull recent ES alerts and record any new canary hits.

    Returns a summary dict so the API can show what just happened.
    """
    from ion.services.elasticsearch_service import ElasticsearchService

    canaries = session.execute(
        select(Canary).where(Canary.status == CanaryStatus.ACTIVE.value)
    ).scalars().all()
    if not canaries:
        return {"scanned": 0, "matched": 0, "new_hits": 0, "canaries_active": 0}

    # Build a quick lookup keyed by lowercased value for substring search.
    canary_index = [(c, (c.value or "").strip().lower()) for c in canaries]

    es = ElasticsearchService()
    if not es.is_configured:
        return {
            "scanned": 0,
            "matched": 0,
            "new_hits": 0,
            "canaries_active": len(canaries),
            "error": "Elasticsearch not configured",
        }

    try:
        alerts = await es.get_alerts(hours=hours, limit=limit)
    except Exception as e:
        logger.warning("Canary scan: ES query failed: %s", e)
        return {
            "scanned": 0,
            "matched": 0,
            "new_hits": 0,
            "canaries_active": len(canaries),
            "error": "ES query failed",
        }

    scanned = 0
    matched = 0
    new_hits = 0

    for alert in alerts:
        scanned += 1
        if hasattr(alert, "to_dict"):
            data = alert.to_dict()
        elif isinstance(alert, dict):
            data = alert
        else:
            continue
        blob = _alert_text_blob(data)
        if not blob:
            continue
        for canary, value_lc in canary_index:
            if not value_lc or value_lc not in blob:
                continue
            matched += 1
            alert_id = str(data.get("id") or data.get("alert_id") or "")
            # Skip if we already have a hit for this canary+alert pair
            if alert_id:
                existing = session.execute(
                    select(CanaryHit).where(
                        CanaryHit.canary_id == canary.id,
                        CanaryHit.source_alert_id == alert_id,
                    )
                ).scalar_one_or_none()
                if existing:
                    continue
            hit = CanaryHit(
                canary_id=canary.id,
                source="elasticsearch",
                source_alert_id=alert_id or None,
                actor=str(data.get("user") or "")[:255] or None,
                host=str(data.get("host") or "")[:255] or None,
                snippet=(data.get("message") or data.get("rule_name") or "")[:500] or None,
                raw=None,
            )
            session.add(hit)
            canary.hit_count = (canary.hit_count or 0) + 1
            canary.last_hit_at = datetime.utcnow()
            new_hits += 1

    if new_hits:
        session.commit()

    return {
        "scanned": scanned,
        "matched": matched,
        "new_hits": new_hits,
        "canaries_active": len(canaries),
    }


def stats(session: Session) -> dict:
    """Compute summary stats for the dashboard."""
    total = session.execute(select(Canary)).scalars().all()
    active = [c for c in total if c.status == CanaryStatus.ACTIVE.value]
    burned = [c for c in total if c.status == CanaryStatus.BURNED.value]
    fired = [c for c in active if c.hit_count and c.hit_count > 0]
    last_24h_hits = session.execute(
        select(CanaryHit).where(CanaryHit.detected_at >= datetime.utcnow() - timedelta(hours=24))
    ).scalars().all()

    return {
        "total": len(total),
        "active": len(active),
        "burned": len(burned),
        "fired": len(fired),
        "hits_24h": len(last_24h_hits),
    }
