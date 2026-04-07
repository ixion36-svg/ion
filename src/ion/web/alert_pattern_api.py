"""Alert Pattern Detection API."""

import logging
from fastapi import APIRouter, Depends, Query
from ion.auth.dependencies import require_permission
from ion.services.elasticsearch_service import ElasticsearchService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alert-patterns", tags=["alert-patterns"])


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
async def get_alert_patterns(
    hours: int = Query(168, ge=24, le=720),
    min_occurrences: int = Query(3, ge=2, le=50),
):
    """Detect recurring alert patterns."""
    from ion.services.alert_pattern_service import detect_alert_patterns
    es = ElasticsearchService()
    if not es:
        return {"enabled": False, "error": "Elasticsearch not configured"}
    try:
        alerts = await es.get_alerts(hours=hours, limit=1000)
        alert_dicts = [a.to_dict() for a in alerts]
        return detect_alert_patterns(alert_dicts, min_occurrences=min_occurrences)
    except Exception as e:
        logger.error("Alert patterns failed: %s", e)
        return {"enabled": False, "error": str(e)}
