"""Incident Cost Calculator API."""

import logging
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/incident-cost", tags=["incident-cost"])


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
def get_cost(
    case_id: int = Query(None),
    hourly_rate: float = Query(75.0, ge=0),
    downtime_cost_per_hour: float = Query(5000.0, ge=0),
    session: Session = Depends(get_db_session),
):
    from ion.services.incident_cost_service import calculate_incident_cost
    return calculate_incident_cost(
        session, case_id=case_id,
        hourly_rate=hourly_rate, downtime_cost_per_hour=downtime_cost_per_hour,
    )
