"""Change Log API — change management tracking."""

import logging
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission, get_current_user
from ion.models.user import User
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/change-log", tags=["change-log"])


class ChangeCreate(BaseModel):
    change_type: str
    title: str
    description: Optional[str] = None
    affected_systems: Optional[list] = None
    risk_level: str = "low"


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
def list_changes(
    change_type: str = Query(None),
    limit: int = Query(50, ge=1, le=500),
    session: Session = Depends(get_db_session),
):
    from ion.services.change_log_service import get_change_log
    return {"changes": get_change_log(session, change_type=change_type, limit=limit)}


@router.get("/summary", dependencies=[Depends(require_permission("alert:read"))])
def get_summary(days: int = Query(30, ge=1), session: Session = Depends(get_db_session)):
    from ion.services.change_log_service import get_change_summary
    return get_change_summary(session, days=days)


@router.post("", dependencies=[Depends(require_permission("alert:read"))])
def create_change(
    data: ChangeCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    import json
    from ion.services.change_log_service import create_change
    return create_change(
        session, changed_by_id=current_user.id, change_type=data.change_type,
        title=data.title, description=data.description,
        affected_systems=json.dumps(data.affected_systems) if data.affected_systems else None,
        risk_level=data.risk_level,
    )


@router.post("/{change_id}/approve", dependencies=[Depends(require_permission("system:settings"))])
def approve(change_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_db_session)):
    from ion.services.change_log_service import approve_change
    return approve_change(session, change_id, current_user.id)


@router.post("/{change_id}/rollback", dependencies=[Depends(require_permission("system:settings"))])
def rollback(change_id: int, notes: str = Query(""), session: Session = Depends(get_db_session)):
    from ion.services.change_log_service import rollback_change
    return rollback_change(session, change_id, notes)
