"""Attack Story API — alert correlation into attack narratives."""

import logging
from fastapi import APIRouter, Depends, Query
from ion.auth.dependencies import require_permission
from ion.services.elasticsearch_service import ElasticsearchService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/attack-stories", tags=["attack-stories"])


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
async def get_attack_stories(
    hours: int = Query(24, ge=1, le=168),
    min_alerts: int = Query(2, ge=2, le=20),
):
    """Build attack stories from correlated alerts."""
    from ion.services.attack_story_service import build_attack_stories
    es = ElasticsearchService()
    if not es:
        return {"enabled": False, "error": "Elasticsearch not configured"}
    try:
        alerts = await es.get_alerts(hours=hours, limit=500)
        alert_dicts = [a.to_dict() for a in alerts]
        return build_attack_stories(alert_dicts, min_alerts=min_alerts, time_window_hours=hours)
    except Exception as e:
        logger.error("Attack stories failed: %s", e)
        return {"enabled": False, "error": str(e)}
