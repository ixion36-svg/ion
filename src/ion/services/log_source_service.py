"""Log Source Health service.

Manages the registry of expected log sources and computes per-source health
by querying Elasticsearch for the most recent matching event.

A source is in one of these states:

- ``healthy``  — last event is within the expected interval window
- ``stale``    — last event is older than the window but younger than 3x
- ``silent``   — no event in 3x the expected window
- ``never``    — never seen an event
- ``error``    — query failed (ES unreachable, bad query, etc.)
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.log_source import LogSource

logger = logging.getLogger(__name__)


# A starter set of common log sources we suggest seeding when the table is empty.
DEFAULT_SUGGESTIONS = [
    {
        "name": "Sysmon (Windows endpoints)",
        "category": "endpoint",
        "description": "Sysmon process / file / network events from Windows hosts.",
        "query": {"match_field": "event.module", "match_value": "sysmon"},
        "expected_interval_minutes": 15,
        "criticality": "high",
    },
    {
        "name": "Windows Security Event Log",
        "category": "os",
        "description": "Windows Security channel via WinlogBeat / Winlogbeat.",
        "query": {"match_field": "event.module", "match_value": "security"},
        "expected_interval_minutes": 30,
        "criticality": "high",
    },
    {
        "name": "Linux auditd",
        "category": "os",
        "description": "Linux auditd via Filebeat / Auditbeat.",
        "query": {"match_field": "event.module", "match_value": "auditd"},
        "expected_interval_minutes": 30,
        "criticality": "medium",
    },
    {
        "name": "Firewall syslog",
        "category": "network",
        "description": "Perimeter firewall traffic and policy events.",
        "query": {"match_field": "event.category", "match_value": "network"},
        "expected_interval_minutes": 10,
        "criticality": "high",
    },
    {
        "name": "DNS query logs",
        "category": "network",
        "description": "DNS resolver query logs.",
        "query": {"match_field": "event.dataset", "match_value": "dns"},
        "expected_interval_minutes": 15,
        "criticality": "medium",
    },
    {
        "name": "Active Directory authentication",
        "category": "identity",
        "description": "AD authentication and Kerberos events.",
        "query": {"match_field": "event.category", "match_value": "authentication"},
        "expected_interval_minutes": 30,
        "criticality": "high",
    },
    {
        "name": "AWS CloudTrail",
        "category": "cloud",
        "description": "AWS API audit log.",
        "query": {"match_field": "event.module", "match_value": "aws"},
        "expected_interval_minutes": 30,
        "criticality": "high",
    },
    {
        "name": "Web proxy",
        "category": "network",
        "description": "HTTP/S proxy logs.",
        "query": {"match_field": "event.category", "match_value": "web"},
        "expected_interval_minutes": 30,
        "criticality": "medium",
    },
]


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def list_sources(session: Session) -> List[dict]:
    rows = session.execute(
        select(LogSource).order_by(LogSource.criticality.desc(), LogSource.name.asc())
    ).scalars().all()
    return [r.to_dict() for r in rows]


def get_source(session: Session, source_id: int) -> Optional[LogSource]:
    return session.get(LogSource, source_id)


def create_source(
    session: Session,
    *,
    name: str,
    category: str,
    description: Optional[str],
    query: dict,
    index_pattern: Optional[str],
    expected_interval_minutes: int,
    criticality: str,
    enabled: bool,
    owner: Optional[str],
    tags: Optional[list],
    created_by_id: Optional[int],
) -> LogSource:
    ls = LogSource(
        name=name.strip(),
        category=category,
        description=description,
        query=query or {},
        index_pattern=index_pattern,
        expected_interval_minutes=max(1, int(expected_interval_minutes or 60)),
        criticality=criticality or "medium",
        enabled=enabled,
        owner=owner,
        tags=tags or [],
        created_by_id=created_by_id,
    )
    session.add(ls)
    session.commit()
    session.refresh(ls)
    return ls


def update_source(session: Session, source_id: int, **fields) -> Optional[LogSource]:
    ls = session.get(LogSource, source_id)
    if not ls:
        return None
    allowed = {
        "name", "category", "description", "query", "index_pattern",
        "expected_interval_minutes", "criticality", "enabled", "owner", "tags",
    }
    for k, v in fields.items():
        if k in allowed and v is not None:
            setattr(ls, k, v)
    session.commit()
    session.refresh(ls)
    return ls


def delete_source(session: Session, source_id: int) -> bool:
    ls = session.get(LogSource, source_id)
    if not ls:
        return False
    session.delete(ls)
    session.commit()
    return True


def seed_defaults(session: Session, created_by_id: Optional[int]) -> int:
    """Insert the DEFAULT_SUGGESTIONS into an empty table. Returns count added."""
    existing = session.execute(select(LogSource)).scalars().all()
    if existing:
        return 0
    added = 0
    for s in DEFAULT_SUGGESTIONS:
        create_source(
            session,
            name=s["name"],
            category=s["category"],
            description=s["description"],
            query=s["query"],
            index_pattern=None,
            expected_interval_minutes=s["expected_interval_minutes"],
            criticality=s["criticality"],
            enabled=True,
            owner=None,
            tags=[],
            created_by_id=created_by_id,
        )
        added += 1
    return added


# ---------------------------------------------------------------------------
# Health checks
# ---------------------------------------------------------------------------

def _build_query(source_query: dict) -> dict:
    """Convert a stored ``query`` blob into an Elasticsearch ``query`` clause."""
    if not source_query:
        return {"match_all": {}}
    if "raw" in source_query and isinstance(source_query["raw"], dict):
        return source_query["raw"]
    field = source_query.get("match_field")
    value = source_query.get("match_value")
    if field and value:
        return {"term": {field: value}}
    return {"match_all": {}}


def _classify(last_event: Optional[datetime], expected_minutes: int) -> str:
    if last_event is None:
        return "never"
    age = (datetime.utcnow().replace(tzinfo=timezone.utc) - last_event).total_seconds() / 60
    window = expected_minutes
    if age <= window:
        return "healthy"
    if age <= window * 3:
        return "stale"
    return "silent"


async def _check_source(svc, source: LogSource) -> dict:
    """Run an aggregation against ES for one source. Returns a result dict."""
    query = _build_query(source.query or {})
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": query,
        "aggs": {
            "last_seen": {"max": {"field": "@timestamp"}},
            "last_24h": {
                "filter": {
                    "range": {
                        "@timestamp": {
                            "gte": "now-24h",
                        }
                    }
                }
            },
        },
    }
    index = source.index_pattern or "*"
    try:
        result = await svc._request(
            "POST",
            f"/{index}/_search",
            json=body,
        )
    except Exception as e:
        return {
            "id": source.id,
            "name": source.name,
            "status": "error",
            "error": type(e).__name__,
            "last_event_at": None,
            "event_count_24h": 0,
            "expected_interval_minutes": source.expected_interval_minutes,
            "criticality": source.criticality,
            "category": source.category,
            "owner": source.owner,
        }

    hits_total = (result.get("hits") or {}).get("total") or {}
    if isinstance(hits_total, dict):
        total = hits_total.get("value", 0)
    else:
        total = hits_total or 0

    aggs = result.get("aggregations") or {}
    last_seen_raw = (aggs.get("last_seen") or {}).get("value_as_string")
    last_event_at: Optional[datetime] = None
    if last_seen_raw:
        try:
            last_event_at = datetime.fromisoformat(last_seen_raw.replace("Z", "+00:00"))
        except Exception:
            last_event_at = None

    last_24h_count = ((aggs.get("last_24h") or {}).get("doc_count")) or 0

    status = _classify(last_event_at, source.expected_interval_minutes)
    return {
        "id": source.id,
        "name": source.name,
        "status": status,
        "last_event_at": last_event_at.isoformat() if last_event_at else None,
        "total_events": total,
        "event_count_24h": last_24h_count,
        "expected_interval_minutes": source.expected_interval_minutes,
        "criticality": source.criticality,
        "category": source.category,
        "owner": source.owner,
    }


async def check_all(session: Session) -> dict:
    """Check every enabled source against ES and update the cached snapshot."""
    from ion.services.elasticsearch_service import ElasticsearchService

    sources = session.execute(
        select(LogSource).where(LogSource.enabled == True)  # noqa: E712
    ).scalars().all()
    if not sources:
        return {"sources": [], "summary": {"total": 0}, "es_configured": False}

    svc = ElasticsearchService()
    if not svc.is_configured:
        # Return cached state for the UI but flag the failure
        cached = []
        for s in sources:
            cached.append({
                "id": s.id,
                "name": s.name,
                "status": s.last_status or "never",
                "last_event_at": s.last_event_at.isoformat() if s.last_event_at else None,
                "total_events": None,
                "event_count_24h": s.last_event_count,
                "expected_interval_minutes": s.expected_interval_minutes,
                "criticality": s.criticality,
                "category": s.category,
                "owner": s.owner,
                "cached": True,
            })
        return {
            "sources": cached,
            "summary": _summarize(cached),
            "es_configured": False,
        }

    results = []
    now = datetime.utcnow()
    for source in sources:
        r = await _check_source(svc, source)
        results.append(r)

        # Update the cached fields on the source row
        source.last_checked_at = now
        source.last_status = r.get("status")
        source.last_event_count = r.get("event_count_24h")
        last_iso = r.get("last_event_at")
        if last_iso:
            try:
                source.last_event_at = datetime.fromisoformat(last_iso.replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                pass
    session.commit()

    return {
        "sources": results,
        "summary": _summarize(results),
        "es_configured": True,
    }


def _summarize(results: List[dict]) -> dict:
    total = len(results)
    by_status = {"healthy": 0, "stale": 0, "silent": 0, "never": 0, "error": 0}
    for r in results:
        s = r.get("status") or "never"
        by_status[s] = by_status.get(s, 0) + 1
    blind = by_status["silent"] + by_status["never"]
    pct = round(((total - blind) / total) * 100) if total else 0
    return {
        "total": total,
        "healthy_pct": pct,
        **{f"{k}_count": v for k, v in by_status.items()},
    }
