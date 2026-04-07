"""Analyst Efficiency Dashboard API."""

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/analyst-efficiency", tags=["analyst-efficiency"])


@router.get(
    "/metrics",
    dependencies=[Depends(require_permission("alert:read"))],
)
def get_efficiency_metrics(
    hours: int = Query(168, ge=24, le=720, description="Lookback hours"),
    session: Session = Depends(get_db_session),
):
    """Get analyst efficiency metrics."""
    from ion.services.analyst_efficiency_service import get_analyst_efficiency
    return get_analyst_efficiency(session, hours=hours)
