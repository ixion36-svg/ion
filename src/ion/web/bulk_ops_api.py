"""Bulk Operations API for alerts."""

import logging
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission, get_current_user
from ion.models.user import User
from ion.web.api import get_db_session, limiter
from ion.core.safe_errors import safe_error

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/bulk", tags=["bulk-operations"])


class BulkAlertRequest(BaseModel):
    alert_ids: list[str]


class BulkCloseRequest(BaseModel):
    alert_ids: list[str]
    closure_reason: str = "false_positive"


def _sanitize_result(result):
    """Strip raw exception messages from a service result before returning it.

    The bulk-operations service may put exception text into a top-level
    ``error`` field; replace it with a sanitized count + flag so we never
    leak stack frames or paths through the API response.
    """
    if not isinstance(result, dict):
        return {"result": "ok"}
    safe = {k: v for k, v in result.items() if k != "error"}
    if result.get("error"):
        safe["has_error"] = True
    return safe


@router.post("/acknowledge", dependencies=[Depends(require_permission("alert:triage"))])
def bulk_acknowledge(request: Request, data: BulkAlertRequest, current_user: User = Depends(get_current_user), session: Session = Depends(get_db_session)):
    from ion.services.bulk_operations_service import bulk_acknowledge_alerts
    try:
        return _sanitize_result(bulk_acknowledge_alerts(session, data.alert_ids, current_user.id))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk acknowledge failed: {safe_error(e, 'bulk_ack')}")


@router.post("/assign", dependencies=[Depends(require_permission("alert:triage"))])
def bulk_assign(request: Request, data: BulkAlertRequest, current_user: User = Depends(get_current_user), session: Session = Depends(get_db_session)):
    from ion.services.bulk_operations_service import bulk_assign_alerts
    try:
        return _sanitize_result(bulk_assign_alerts(session, data.alert_ids, current_user.id))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk assign failed: {safe_error(e, 'bulk_assign')}")


@router.post("/close", dependencies=[Depends(require_permission("alert:triage"))])
def bulk_close(request: Request, data: BulkCloseRequest, current_user: User = Depends(get_current_user), session: Session = Depends(get_db_session)):
    from ion.services.bulk_operations_service import bulk_close_alerts
    try:
        return _sanitize_result(bulk_close_alerts(session, data.alert_ids, current_user.id, data.closure_reason))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk close failed: {safe_error(e, 'bulk_close')}")
