"""Attack Story API — alert correlation into attack narratives."""

import logging

from fastapi import APIRouter, Depends, Query

from ion.auth.dependencies import require_permission
from ion.core.safe_errors import safe_error
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
    # `es.is_configured`, not `not es`. ElasticsearchService defines neither
    # __bool__ nor __len__, so an instance is always truthy and this guard
    # never fired once: an unconfigured deployment fell through to
    # get_alerts, raised, and answered {"enabled": false, "error":
    # "ElasticsearchError"} from the handler below, where the intent here
    # was to name the actual cause. Measured on a deployment where
    # bool(ElasticsearchService()) is True and .is_configured is False.
    # is_configured is a property, so it is read rather than called.
    if not es.is_configured:
        return {"enabled": False, "error": "Elasticsearch not configured"}
    try:
        alerts = await es.get_alerts(hours=hours, limit=500)
        alert_dicts = [a.to_dict() for a in alerts]
        return build_attack_stories(alert_dicts, min_alerts=min_alerts, time_window_hours=hours)
    except Exception as e:
        return {"enabled": False, "error": safe_error(e, "attack_stories")}
