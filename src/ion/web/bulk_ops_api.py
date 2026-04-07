"""Bulk Operations API for alerts."""

import logging
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission, get_current_user
from ion.models.user import User
from ion.web.api import get_db_session, limiter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/bulk", tags=["bulk-operations"])


class BulkAlertRequest(BaseModel):
    alert_ids: list[str]


class BulkCloseRequest(BaseModel):
    alert_ids: list[str]
    closure_reason: str = "false_positive"


@router.post("/acknowledge", dependencies=[Depends(require_permission("alert:triage"))])
@limiter.limit("20/minute")
def bulk_acknowledge(request: Request, data: BulkAlertRequest, current_user: User = Depends(get_current_user), session: Session = Depends(get_db_session)):
    from ion.services.bulk_operations_service import bulk_acknowledge_alerts
    return bulk_acknowledge_alerts(session, data.alert_ids, current_user.id)


@router.post("/assign", dependencies=[Depends(require_permission("alert:triage"))])
@limiter.limit("20/minute")
def bulk_assign(request: Request, data: BulkAlertRequest, current_user: User = Depends(get_current_user), session: Session = Depends(get_db_session)):
    from ion.services.bulk_operations_service import bulk_assign_alerts
    return bulk_assign_alerts(session, data.alert_ids, current_user.id)


@router.post("/close", dependencies=[Depends(require_permission("alert:triage"))])
@limiter.limit("20/minute")
def bulk_close(request: Request, data: BulkCloseRequest, current_user: User = Depends(get_current_user), session: Session = Depends(get_db_session)):
    from ion.services.bulk_operations_service import bulk_close_alerts
    return bulk_close_alerts(session, data.alert_ids, current_user.id, data.closure_reason)
