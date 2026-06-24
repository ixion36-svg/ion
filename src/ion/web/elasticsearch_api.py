"""Elasticsearch infrastructure + alert-read API.

Extracted from web/api.py (god-module split, increment 2 — finding #14).
Mounted at the /api prefix in server.py, preserving the original
/api/elasticsearch/* paths. Covers ES config/test, alert read (list, raw,
sequence, systems, mitre-stats, diagnostic, related, stats), discover,
indices, and IOC hunt. Case lifecycle and alert triage remain in api.py
(future increments 3 and 4).
"""
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.core.config import get_config, get_elasticsearch_config
from ion.core.safe_errors import safe_error
from ion.models.user import User
from ion.services.elasticsearch_service import (
    ElasticsearchError,
    ElasticsearchService,
    build_process_tree,
)
from ion.storage.database import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter()


def get_elasticsearch_service() -> ElasticsearchService:
    """Get configured Elasticsearch service instance."""
    return ElasticsearchService()


# Request models for discover / field-stats / IOC-hunt routes (moved from api.py).
class DiscoverSearchRequest(BaseModel):
    """Request model for discover search."""
    index_pattern: str = "logs-*"
    query: str = "*"
    time_field: str = "@timestamp"
    time_from: Optional[str] = "now-24h"
    time_to: Optional[str] = "now"
    size: int = 100
    sort_field: Optional[str] = None
    sort_order: str = "desc"
    fields: Optional[List[str]] = None


class DiscoverHistogramRequest(BaseModel):
    """Request model for discover histogram."""
    index_pattern: str = "logs-*"
    query: str = "*"
    time_field: str = "@timestamp"
    time_from: str = "now-24h"
    time_to: str = "now"
    interval: str = "1h"


class FieldStatsRequest(BaseModel):
    """Request model for field statistics."""
    index_pattern: str
    field: str
    size: int = 10
    time_field: Optional[str] = "@timestamp"
    time_from: Optional[str] = "now-24h"
    time_to: Optional[str] = "now"


class IOCHuntRequest(BaseModel):
    """Request model for IOC hunt."""
    ioc_value: str
    ioc_type: Optional[str] = None  # ip, hash, domain, url, email (auto-detected if not provided)
    index_pattern: str = "*,-.*"
    time_field: str = "@timestamp"
    time_from: Optional[str] = "now-30d"
    time_to: Optional[str] = "now"
    size: int = 100


class IOCHuntBulkRequest(BaseModel):
    """Request model for bulk IOC hunt."""
    ioc_values: List[str]
    index_pattern: str = "*,-.*"
    time_from: Optional[str] = "now-30d"
    time_to: Optional[str] = "now"


@router.get("/elasticsearch/config")
async def get_es_config_status(
    current_user: User = Depends(get_current_user),
):
    """Get Elasticsearch configuration status (not sensitive data)."""
    config = get_elasticsearch_config()
    return {
        "enabled": config.get("enabled", False),
        "url": config.get("url", "")[:50] + "..." if len(config.get("url", "")) > 50 else config.get("url", ""),
        "has_credentials": bool(config.get("api_key") or (config.get("username") and config.get("password"))),
        "alert_index": config.get("alert_index", ""),
    }

@router.get("/elasticsearch/test")
async def test_es_connection(
    current_user: User = Depends(get_current_user),
):
    """Test Elasticsearch connection."""
    service = get_elasticsearch_service()
    result = await service.test_connection()
    return result

def _fixture_alert_dicts(
    session: Session,
    *,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    include_closed: bool = False,
) -> list[dict]:
    """Return lab-fixture alert dicts shaped like the ES alert list payload.

    v0.30.0: lab fixtures have no backing ES document by design — the
    seeder writes them straight to `alert_triage` so the lab system stays
    functional in air-gapped dev environments where ES isn't available.
    This helper is called from every return path of `get_es_alerts` so
    fixtures surface whether ES is disabled, unconfigured, unreachable,
    or fully up.

    The `system` filter is intentionally NOT honoured here — lab fixtures
    have no CyAB-system attribution and should always be visible to a
    learner running the lab regardless of system selection.
    """
    from datetime import datetime as _datetime
    from datetime import timezone as _tz

    from ion.models.alert_triage import AlertTriage as _AlertTriage
    from ion.models.alert_triage import AlertTriageStatus as _AlertTriageStatus

    fixture_q = session.query(_AlertTriage).filter(
        _AlertTriage.es_alert_id.like("lab-fixture-%")
    )
    if status:
        # `status` comes in as the lowercase enum value (open/acknowledged/closed).
        # AlertTriage.status is SQLEnum stored as the enum NAME, so we must hand
        # the bind processor an enum instance, not the raw string.
        try:
            fixture_q = fixture_q.filter(_AlertTriage.status == _AlertTriageStatus(status))
        except ValueError:
            # Unknown status value — no fixture rows can match
            fixture_q = fixture_q.filter(False)
    elif not include_closed:
        fixture_q = fixture_q.filter(_AlertTriage.status != _AlertTriageStatus.CLOSED)
    # `severity` query param maps to AlertTriage.priority (the seed-payload
    # field that semantically aligns with ES alert severity; AlertTriage
    # has no `severity` column).
    if severity:
        fixture_q = fixture_q.filter(_AlertTriage.priority == severity)

    # Override the hardcoded 2026-01-01 seed timestamp with "now" so
    # fixtures survive the client-side time-window filter on /alerts. The
    # underlying DB row keeps its deterministic timestamp (air-gap
    # reproducibility).
    now_iso = _datetime.now(_tz.utc).isoformat()
    return [
        {
            "id": t.es_alert_id,
            "severity": t.priority or "medium",
            "title": t.rule_name or t.es_alert_id,
            "rule_name": t.rule_name,
            "host": None,
            "user": None,
            "source_system": t.source_system or "elastic",
            "status": t.status,
            "timestamp": now_iso,
            "mitre_techniques": t.mitre_techniques or [],
            "mitre_technique_id": (t.mitre_techniques or [None])[0] if t.mitre_techniques else None,
            "is_lab_fixture": True,
        }
        for t in fixture_q.all()
    ]

@router.get("/elasticsearch/alerts")
async def get_es_alerts(
    hours: int = 24,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 500,
    include_closed: bool = False,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    system: Optional[str] = None,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Fetch alerts from Elasticsearch.

    v0.30.0: lab-fixture AlertTriage rows are always merged into the
    response (regardless of ES state) so graded labs work in dev
    environments where ES isn't running. See `_fixture_alert_dicts`.

    Args:
        hours: Number of hours to look back (default 24, ignored if time_from set)
        severity: Filter by severity (critical, high, medium, low, info)
        status: Filter by status (open, acknowledged, closed)
        limit: Maximum number of alerts (default 500)
        include_closed: Include closed/resolved alerts (default False)
        time_from: Absolute start time (ISO 8601). Overrides hours.
        time_to: Absolute end time (ISO 8601). Defaults to now.
    """
    fixture_dicts = _fixture_alert_dicts(
        session, severity=severity, status=status, include_closed=include_closed
    )

    config = get_elasticsearch_config()
    if not config.get("enabled"):
        return {
            "alerts": fixture_dicts,
            "total": len(fixture_dicts),
            "enabled": False,
            "message": "Elasticsearch integration is not enabled",
        }

    service = get_elasticsearch_service()
    if not service.is_configured:
        return {
            "alerts": fixture_dicts,
            "total": len(fixture_dicts),
            "enabled": True,
            "configured": False,
            "message": "Elasticsearch is not configured",
        }

    try:
        alerts = await service.get_alerts(
            hours=hours,
            severity=severity,
            status=status,
            limit=limit,
            include_closed=include_closed,
            time_from=time_from,
            time_to=time_to,
            system=system,
        )
        # Bulk-resolve every alert's namespace → CyAB + TIDE identity in one
        # cache build instead of one lookup per alert.
        from ion.services.system_resolver_service import bulk_resolve
        ns_map = bulk_resolve(session, (a.source_system for a in alerts))
        out_alerts = []
        for a in alerts:
            # Exclude raw_data from list view — saves ~65% of payload.
            # Frontend fetches raw_data on demand via GET /alerts/{id}/raw.
            d = a.to_dict(include_raw=False)
            res = ns_map.get(a.source_system) if a.source_system else None
            if res:
                d["cyab_system_id"] = res.get("cyab_system_id")
                d["cyab_system_name"] = res.get("cyab_system_name")
                d["cyab_data_source_name"] = res.get("cyab_data_source_name")
                d["tide_system_id"] = res.get("tide_system_id")
                d["tide_system_name"] = res.get("tide_system_name")
            out_alerts.append(d)

        out_alerts.extend(fixture_dicts)

        return {
            "alerts": out_alerts,
            "total": len(out_alerts),
            "hours": hours,
            "enabled": True,
            "configured": True,
            "arkime_enabled": get_config().arkime_enabled,
        }
    except ElasticsearchError as e:
        logger.warning("Elasticsearch connection error fetching alerts: %s", e)
        return {
            "alerts": fixture_dicts,
            "total": len(fixture_dicts),
            "hours": hours,
            "enabled": True,
            "configured": True,
            "connection_error": True,
            "message": safe_error(e),
        }

@router.get("/elasticsearch/alerts/{alert_id}/raw")
async def get_alert_raw_data(
    alert_id: str,
    current_user: User = Depends(require_permission("alert:read")),
):
    """Fetch raw_data for a single alert — called on demand when the detail panel opens."""
    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="Elasticsearch is not configured")
    alerts = await service.get_alerts_by_ids([alert_id])
    if not alerts:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"raw_data": alerts[0].raw_data}

@router.get("/elasticsearch/alerts/{alert_id}/sequence")
async def get_alert_sequence(
    alert_id: str,
    current_user: User = Depends(require_permission("alert:read")),
):
    """Fetch building block events for an EQL sequence/correlation alert.

    Returns the individual events that make up the correlation — each with
    full process, file, network context that the parent alert lacks.
    """
    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="Elasticsearch is not configured")
    blocks = await service.get_building_blocks(alert_id)
    return {"events": blocks, "count": len(blocks)}

@router.get("/elasticsearch/alerts/{alert_id}/process-tree")
async def get_alert_process_tree(
    alert_id: str,
    current_user: User = Depends(require_permission("alert:read")),
):
    """Build the alert-local process hierarchy (process explorer) for one alert.

    Returns an ordered root→leaf chain (grandparent → parent → the alert's own
    process, flagged ``is_alert``) derived from the alert ``_source``, plus an
    ``ancestry_depth`` / ``truncated_ancestors`` count from
    ``process.Ext.ancestry`` so the UI can show how many earlier ancestors exist
    that aren't named in the alert document.
    """
    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="Elasticsearch is not configured")
    alerts = await service.get_alerts_by_ids([alert_id])
    if not alerts:
        raise HTTPException(status_code=404, detail="Alert not found")
    return build_process_tree(alerts[0].raw_data)

@router.get("/elasticsearch/alerts/systems")
async def get_alert_systems(
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Return the list of CyAB-registered systems for the alerts filter dropdown.

    Each entry: {namespace, display_name, cyab_system_id, cyab_system_name,
    tide_system_id, tide_system_name}. Driven by the in-process resolver
    cache so this endpoint is essentially free.
    """
    from ion.services.system_resolver_service import list_known_systems
    return {"systems": list_known_systems(session)}

@router.get("/elasticsearch/alerts/mitre-stats")
async def get_mitre_stats(
    hours: int = 24,
    current_user: User = Depends(require_permission("alert:read")),
):
    """Get MITRE ATT&CK technique/tactic statistics from alerts.

    Args:
        hours: Number of hours to look back (default 24)

    Returns:
        Dict with technique counts, tactic counts, and total alerts with MITRE data.
    """
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        return {"techniques": {}, "tactics": {}, "total_alerts_with_mitre": 0, "time_range_hours": hours}

    service = get_elasticsearch_service()
    if not service.is_configured:
        return {"techniques": {}, "tactics": {}, "total_alerts_with_mitre": 0, "time_range_hours": hours}

    try:
        # Fetch alerts and aggregate MITRE data
        alerts = await service.get_alerts(hours=hours, limit=1000)

        techniques = {}
        tactics = {}
        total_with_mitre = 0

        for alert in alerts:
            if alert.mitre_technique_id:
                total_with_mitre += 1
                tech_id = alert.mitre_technique_id
                if tech_id not in techniques:
                    techniques[tech_id] = {
                        "name": alert.mitre_technique_name or "",
                        "tactic": alert.mitre_tactic_name or "",
                        "count": 0,
                    }
                techniques[tech_id]["count"] += 1

                if alert.mitre_tactic_name:
                    tactic = alert.mitre_tactic_name
                    tactics[tactic] = tactics.get(tactic, 0) + 1

        return {
            "techniques": techniques,
            "tactics": tactics,
            "total_alerts_with_mitre": total_with_mitre,
            "time_range_hours": hours,
        }
    except ElasticsearchError as e:
        logger.warning("Elasticsearch connection error fetching MITRE stats: %s", e)
        return {
            "techniques": {},
            "tactics": {},
            "total_alerts_with_mitre": 0,
            "time_range_hours": hours,
            "connection_error": True,
            "message": safe_error(e),
        }

@router.get("/elasticsearch/alerts/diagnostic")
async def diagnostic_alert_fields(
    limit: int = 3,
    current_user: User = Depends(require_permission("alert:read")),
):
    """Diagnostic: show raw _source field structure of recent alerts.

    Helps debug MITRE parsing issues by revealing exactly which keys
    the alert documents use (nested vs dot-notation, array vs scalar, etc.).
    """
    service = get_elasticsearch_service()
    if not service.is_configured:
        return JSONResponse(
            status_code=503, content={"error": "Elasticsearch not configured"}
        )

    try:
        result = await service._request(
            "POST",
            f"/{service.alert_index}/_search",
            json={
                "size": min(limit, 10),
                "sort": [{"@timestamp": {"order": "desc"}}],
                "_source": True,
            },
        )
    except Exception as e:
        return JSONResponse(
            status_code=502, content={"error": safe_error(e, "diagnostic")}
        )

    alerts = []
    for hit in result.get("hits", {}).get("hits", []):
        source = hit.get("_source", {})
        # Extract all threat-related keys
        threat_keys = {k: v for k, v in source.items() if "threat" in k.lower() or "mitre" in k.lower() or "tactic" in k.lower() or "technique" in k.lower()}
        # Also get the nested threat object if it exists
        threat_obj = source.get("threat")
        # Get parsed result
        parsed = service._parse_alert(hit["_id"], source)
        alerts.append({
            "id": hit["_id"],
            "index": hit.get("_index"),
            "rule_name": (
                source.get("kibana.alert.rule.name")
                or (source.get("kibana", {}) or {}).get("alert", {}).get("rule", {}).get("name")
                or source.get("rule_name")
                or "?"
            ),
            "threat_related_keys": threat_keys,
            "nested_threat_object": threat_obj,
            "parsed_mitre": {
                "technique_id": parsed.mitre_technique_id if parsed else None,
                "technique_name": parsed.mitre_technique_name if parsed else None,
                "tactic_name": parsed.mitre_tactic_name if parsed else None,
            },
            "all_keys": sorted(source.keys()),
        })

    return {
        "total_in_index": result.get("hits", {}).get("total", {}).get("value", 0),
        "alerts_checked": len(alerts),
        "alerts": alerts,
    }

@router.get("/elasticsearch/alerts/{alert_id}/related")
async def get_es_related_alerts(
    alert_id: str,
    host: Optional[str] = None,
    user: Optional[str] = None,
    rule_name: Optional[str] = None,
    hours: int = 72,
    current_user: User = Depends(require_permission("alert:read")),
):
    """Get alerts related to a specific alert by host, user, or rule."""
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch not configured")

    try:
        related = await service.get_related_alerts(
            alert_id=alert_id,
            host=host,
            user=user,
            rule_name=rule_name,
            hours=hours,
        )
        return {
            "alert_id": alert_id,
            "related": {
                key: [a.to_dict() for a in alerts]
                for key, alerts in related.items()
            },
        }
    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=safe_error(e))

@router.get("/elasticsearch/alerts/stats")
async def get_es_alert_stats(
    hours: int = 24,
    current_user: User = Depends(require_permission("alert:read")),
):
    """Get alert statistics from Elasticsearch."""
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        return {"enabled": False}

    service = get_elasticsearch_service()
    if not service.is_configured:
        return {"enabled": True, "configured": False}

    try:
        stats = await service.get_alert_stats(hours=hours)
        return {
            "enabled": True,
            "configured": True,
            **stats,
        }
    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=safe_error(e))

_DISCOVER_BLOCKED_PREFIXES = (".kibana", ".security", ".internal", ".tasks", ".apm", ".fleet")

def _validate_index_pattern(pattern: str) -> str:
    """Block access to system/internal ES indices via discover."""
    lower = pattern.lower().strip()
    for prefix in _DISCOVER_BLOCKED_PREFIXES:
        if lower.startswith(prefix):
            raise ValueError(f"Access to system index '{pattern}' is not permitted")
    return pattern

@router.post("/elasticsearch/discover/search")
async def discover_search(
    request: DiscoverSearchRequest,
    current_user: User = Depends(get_current_user),
):
    """Execute a discover-style search across Elasticsearch indices.

    Supports Lucene/KQL query syntax for flexible searching.
    """
    try:
        _validate_index_pattern(request.index_pattern)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=safe_error(e))

    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        result = await service.discover_search(
            index_pattern=request.index_pattern,
            query=request.query,
            time_field=request.time_field,
            time_from=request.time_from,
            time_to=request.time_to,
            size=request.size,
            sort_field=request.sort_field,
            sort_order=request.sort_order,
            fields=request.fields,
        )

        if "error" in result and result["error"]:
            raise HTTPException(status_code=500, detail=result["error"])

        return result

    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=safe_error(e))

@router.post("/elasticsearch/discover/histogram")
async def discover_histogram(
    request: DiscoverHistogramRequest,
    current_user: User = Depends(get_current_user),
):
    """Get a time histogram for discover visualization."""
    try:
        _validate_index_pattern(request.index_pattern)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=safe_error(e))

    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        result = await service.discover_histogram(
            index_pattern=request.index_pattern,
            query=request.query,
            time_field=request.time_field,
            time_from=request.time_from,
            time_to=request.time_to,
            interval=request.interval,
        )

        if "error" in result and result["error"]:
            raise HTTPException(status_code=500, detail=result["error"])

        return result

    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=safe_error(e))

@router.get("/elasticsearch/indices")
async def list_indices(
    pattern: str = "*",
    include_system: bool = False,
    include_stats: bool = True,
    current_user: User = Depends(get_current_user),
):
    """List available Elasticsearch indices.

    Args:
        pattern: Index pattern to filter (e.g., "logs-*")
        include_system: Include system indices (starting with .)
        include_stats: Include document count and size stats
    """
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        result = await service.list_indices(
            pattern=pattern,
            include_system=include_system,
            include_stats=include_stats,
        )

        if "error" in result and result["error"]:
            raise HTTPException(status_code=500, detail=result["error"])

        return result

    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=safe_error(e))

@router.get("/elasticsearch/indices/{index_pattern}/mappings")
async def get_index_mappings(
    index_pattern: str,
    current_user: User = Depends(get_current_user),
):
    """Get field mappings for an index pattern.

    Returns field names, types, and whether they are searchable/aggregatable.
    """
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        result = await service.get_index_mappings(index_pattern=index_pattern)

        if "error" in result and result["error"]:
            raise HTTPException(status_code=500, detail=result["error"])

        return result

    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=safe_error(e))

@router.post("/elasticsearch/indices/field-stats")
async def get_field_stats(
    request: FieldStatsRequest,
    current_user: User = Depends(get_current_user),
):
    """Get statistics and top values for a specific field.

    Returns cardinality, top values, and counts.
    """
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        result = await service.get_field_stats(
            index_pattern=request.index_pattern,
            field=request.field,
            size=request.size,
            time_field=request.time_field,
            time_from=request.time_from,
            time_to=request.time_to,
        )

        if "error" in result and result["error"]:
            raise HTTPException(status_code=500, detail=result["error"])

        return result

    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=safe_error(e))

@router.post("/elasticsearch/ioc-hunt")
async def ioc_hunt(
    request: IOCHuntRequest,
    current_user: User = Depends(get_current_user),
):
    """Hunt for an IOC (Indicator of Compromise) across all Elasticsearch indices.

    Automatically detects IOC type (IP, hash, domain, URL, email) and searches
    relevant fields. Returns matching documents and index statistics.
    """
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        result = await service.ioc_hunt(
            ioc_value=request.ioc_value,
            ioc_type=request.ioc_type,
            index_pattern=request.index_pattern,
            time_field=request.time_field,
            time_from=request.time_from,
            time_to=request.time_to,
            size=request.size,
        )

        if "error" in result and result["error"]:
            raise HTTPException(status_code=500, detail=result["error"])

        return result

    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=safe_error(e))

@router.post("/elasticsearch/ioc-hunt/bulk")
async def ioc_hunt_bulk(
    request: IOCHuntBulkRequest,
    current_user: User = Depends(get_current_user),
):
    """Hunt for multiple IOCs at once.

    Searches for up to 100 IOCs and returns a summary of which were found
    and in which indices.
    """
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        result = await service.ioc_hunt_bulk(
            ioc_values=request.ioc_values,
            index_pattern=request.index_pattern,
            time_from=request.time_from,
            time_to=request.time_to,
        )

        if "error" in result and result["error"]:
            raise HTTPException(status_code=500, detail=result["error"])

        return result

    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=safe_error(e))
