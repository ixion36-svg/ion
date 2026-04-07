"""IOC Staleness Tracker API."""

import logging
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ioc-staleness", tags=["ioc-staleness"])


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
def get_stale_iocs(
    stale_days: int = Query(30, ge=1, le=365),
    limit: int = Query(100, ge=1, le=500),
    session: Session = Depends(get_db_session),
):
    """Get stale IOCs that need re-enrichment."""
    from ion.services.ioc_staleness_service import get_stale_iocs
    return get_stale_iocs(session, stale_days=stale_days, limit=limit)
