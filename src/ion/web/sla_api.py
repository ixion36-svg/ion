"""SLA Management API."""

import logging
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/sla", tags=["sla"])


class SLAPolicySet(BaseModel):
    severity: str
    acknowledge_minutes: int
    resolve_minutes: int
    description: Optional[str] = None


@router.get("/policies", dependencies=[Depends(require_permission("alert:read"))])
def list_policies(session: Session = Depends(get_db_session)):
    from ion.services.sla_service import get_sla_policies
    return {"policies": get_sla_policies(session)}


@router.post("/policies", dependencies=[Depends(require_permission("system:settings"))])
def set_policy(data: SLAPolicySet, session: Session = Depends(get_db_session)):
    from ion.services.sla_service import set_sla_policy
    return set_sla_policy(session, data.severity, data.acknowledge_minutes, data.resolve_minutes, data.description)


@router.get("/compliance", dependencies=[Depends(require_permission("alert:read"))])
def check_compliance(hours: int = Query(168, ge=24, le=720), session: Session = Depends(get_db_session)):
    from ion.services.sla_service import check_sla_compliance
    return check_sla_compliance(session, hours=hours)
