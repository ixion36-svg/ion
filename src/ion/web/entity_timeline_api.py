"""Entity Timeline API — unified cross-source timeline for any entity."""

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.services.entity_timeline_service import get_entity_timeline
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/entity-timeline", tags=["entity-timeline"])


@router.get(
    "/search",
    dependencies=[Depends(require_permission("alert:read"))],
)
def search_entity_timeline(
    q: str = Query(..., min_length=1, max_length=500, description="Entity value (IP, host, user, domain, hash)"),
    type: str = Query("auto", description="Entity type: auto, ip, host, user, domain, hash, email"),
    hours: int = Query(168, ge=1, le=8760, description="Lookback hours"),
    session: Session = Depends(get_db_session),
):
    """Search for an entity across all ION data sources and return a unified timeline."""
    return get_entity_timeline(session, entity_value=q, entity_type=type, hours=hours)
