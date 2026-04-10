"""Engineering Analytics API router for ION.

Per-system alert metrics from Elasticsearch using data_stream.namespace
and index name patterns.
"""

from typing import Optional

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from ion.models.user import User
from ion.auth.dependencies import get_current_user
from ion.core.config import get_elasticsearch_config
from ion.services.elasticsearch_service import ElasticsearchService, ElasticsearchError
from ion.web.api import get_db_session
from ion.core.safe_errors import safe_error

router = APIRouter(tags=["engineering-analytics"])

# Cache service instance
_es_service: Optional[ElasticsearchService] = None


def _get_es_service() -> ElasticsearchService:
    global _es_service
    if _es_service is None:
        _es_service = ElasticsearchService()
    return _es_service


@router.get("/systems")
async def get_system_analytics(
    hours: int = 24,
    index_pattern: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    """Get per-system alert analytics from Elasticsearch.

    Aggregates by data_stream.namespace with severity, status, top rules,
    and time histograms per system.
    """
    config = get_elasticsearch_config()
    if not config.get("url"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    service = _get_es_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        result = await service.get_system_analytics(
            hours=hours,
            index_pattern=index_pattern,
        )
        if result.get("error"):
            raise HTTPException(status_code=500, detail="Elasticsearch query failed")
        return result
    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=safe_error(e, "engineering_analytics"))


@router.get("/indices")
async def get_index_breakdown(
    hours: int = 24,
    pattern: str = "logs-*",
    current_user: User = Depends(get_current_user),
):
    """Get alert counts broken down by index name.

    Useful for seeing which log indices (logs-*-systemname) are generating alerts.
    """
    config = get_elasticsearch_config()
    if not config.get("url"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    service = _get_es_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        result = await service.get_system_analytics(
            hours=hours,
            index_pattern=pattern,
        )
        if result.get("error"):
            raise HTTPException(status_code=500, detail="Elasticsearch query failed")
        return {
            "indices": result.get("indices", []),
            "total": result.get("total", 0),
            "hours": hours,
        }
    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=safe_error(e, "engineering_analytics"))


@router.get("/log-systems")
async def get_log_systems(
    hours: int = 24,
    current_user: User = Depends(get_current_user),
):
    """Discover systems from log indices (logs-*) by data_stream.namespace.

    Unlike /systems which aggregates from .alerts-*, this endpoint queries
    the actual log data streams (logs-*-systemname) to find all systems
    that are actively shipping logs — even if they haven't generated alerts.
    """
    service = _get_es_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        interval = "1h" if hours <= 48 else "6h" if hours <= 168 else "1d"
        systems = await service._discover_systems_from_logs(hours, interval)
        return {"systems": systems, "total": len(systems), "hours": hours}
    except Exception as e:
        raise HTTPException(status_code=500, detail=safe_error(e, "log_systems"))
