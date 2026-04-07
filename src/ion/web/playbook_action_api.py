"""Automated Playbook Actions API."""

import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission, get_current_user
from ion.models.user import User
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/playbook-actions", tags=["playbook-actions"])


class ActionRequest(BaseModel):
    action_id: int
    target: str
    case_id: Optional[int] = None


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
def list_actions(session: Session = Depends(get_db_session)):
    from ion.services.playbook_action_service import get_available_actions
    return {"actions": get_available_actions(session)}


@router.post("/request", dependencies=[Depends(require_permission("alert:triage"))])
def request_action(data: ActionRequest, current_user: User = Depends(get_current_user), session: Session = Depends(get_db_session)):
    from ion.services.playbook_action_service import request_action
    return request_action(session, data.action_id, current_user.id, data.target, data.case_id)


@router.post("/log/{log_id}/approve", dependencies=[Depends(require_permission("alert:triage"))])
def approve(log_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_db_session)):
    from ion.services.playbook_action_service import approve_action
    result = approve_action(session, log_id, current_user.id)
    if not result:
        raise HTTPException(status_code=404, detail="Action log not found")
    return result


@router.post("/log/{log_id}/reject", dependencies=[Depends(require_permission("alert:triage"))])
def reject(log_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_db_session)):
    from ion.services.playbook_action_service import reject_action
    result = reject_action(session, log_id, current_user.id)
    if not result:
        raise HTTPException(status_code=404, detail="Action log not found")
    return result


@router.post("/log/{log_id}/execute", dependencies=[Depends(require_permission("system:settings"))])
def execute(log_id: int, session: Session = Depends(get_db_session)):
    from ion.services.playbook_action_service import execute_action
    result = execute_action(session, log_id)
    if not result:
        raise HTTPException(status_code=404, detail="Action log not found")
    return result


@router.get("/log", dependencies=[Depends(require_permission("alert:read"))])
def get_log(case_id: int = Query(None), limit: int = Query(50), session: Session = Depends(get_db_session)):
    from ion.services.playbook_action_service import get_action_log
    return {"log": get_action_log(session, case_id=case_id, limit=limit)}
