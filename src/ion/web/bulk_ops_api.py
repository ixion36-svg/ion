"""Bulk Operations API for alerts."""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.core.safe_errors import safe_error
from ion.models.user import User
from ion.web.api import get_db_session

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
        result = bulk_close_alerts(session, data.alert_ids, current_user.id, data.closure_reason)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk close failed: {safe_error(e, 'bulk_close')}")
    _close_alerts_in_es(data.alert_ids)
    return _sanitize_result(result)


def _close_alerts_in_es(alert_ids: list[str]) -> None:
    """Mirror a bulk close onto the alerts' Elasticsearch status. Best-effort.

    Left open there, the alerts page sent that "open" back on its next load
    and reopened the alerts in ION. This handler runs in the threadpool, so
    the async client gets a throwaway loop, which its pool supports.
    """
    try:
        import asyncio

        from ion.services.elasticsearch_service import ElasticsearchService
        es = ElasticsearchService()
        if es.is_configured and alert_ids:
            asyncio.run(es.update_alert_workflow_status(list(alert_ids), "closed"))
    except Exception as e:  # noqa: BLE001 — the ION-side close already stands
        logger.warning("Bulk close: alert status not mirrored to Elasticsearch: %s", e)
