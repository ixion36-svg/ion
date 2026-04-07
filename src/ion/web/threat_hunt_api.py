"""Threat Hunting Workbench API."""

import logging
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission, get_current_user
from ion.models.user import User
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/threat-hunts", tags=["threat-hunting"])


class HuntCreate(BaseModel):
    title: str
    hypothesis: str
    priority: str = "medium"
    threat_actor: Optional[str] = None
    mitre_techniques: Optional[list] = None
    data_sources: Optional[list] = None


class HuntUpdate(BaseModel):
    title: Optional[str] = None
    hypothesis: Optional[str] = None
    priority: Optional[str] = None
    assigned_to_id: Optional[int] = None
    findings: Optional[str] = None


class HuntClose(BaseModel):
    status: str  # confirmed, refuted, inconclusive
    conclusion: str
    iocs_found: Optional[list] = None


class QueryAdd(BaseModel):
    query: str
    description: str = ""
    result_count: int = 0


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
def list_hunts(status: str = Query(None), limit: int = Query(50), session: Session = Depends(get_db_session)):
    from ion.services.threat_hunt_service import get_hunts
    return {"hunts": get_hunts(session, status=status, limit=limit)}


@router.get("/stats", dependencies=[Depends(require_permission("alert:read"))])
def hunt_stats(session: Session = Depends(get_db_session)):
    from ion.services.threat_hunt_service import get_hunt_stats
    return get_hunt_stats(session)


@router.get("/{hunt_id}", dependencies=[Depends(require_permission("alert:read"))])
def get_hunt(hunt_id: int, session: Session = Depends(get_db_session)):
    from ion.services.threat_hunt_service import get_hunt
    result = get_hunt(session, hunt_id)
    if not result:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return result


@router.post("", dependencies=[Depends(require_permission("alert:read"))])
def create_hunt(data: HuntCreate, current_user: User = Depends(get_current_user), session: Session = Depends(get_db_session)):
    import json
    from ion.services.threat_hunt_service import create_hunt
    return create_hunt(
        session, created_by_id=current_user.id, title=data.title,
        hypothesis=data.hypothesis, priority=data.priority,
        threat_actor=data.threat_actor,
        mitre_techniques=json.dumps(data.mitre_techniques) if data.mitre_techniques else None,
        data_sources=json.dumps(data.data_sources) if data.data_sources else None,
    )


@router.put("/{hunt_id}", dependencies=[Depends(require_permission("alert:read"))])
def update_hunt(hunt_id: int, data: HuntUpdate, session: Session = Depends(get_db_session)):
    from ion.services.threat_hunt_service import update_hunt
    kwargs = {k: v for k, v in data.model_dump().items() if v is not None}
    return update_hunt(session, hunt_id, **kwargs)


@router.post("/{hunt_id}/queries", dependencies=[Depends(require_permission("alert:read"))])
def add_query(hunt_id: int, data: QueryAdd, session: Session = Depends(get_db_session)):
    from ion.services.threat_hunt_service import add_query
    return add_query(session, hunt_id, data.query, data.description, data.result_count)


@router.post("/{hunt_id}/close", dependencies=[Depends(require_permission("alert:read"))])
def close_hunt(hunt_id: int, data: HuntClose, session: Session = Depends(get_db_session)):
    from ion.services.threat_hunt_service import close_hunt
    return close_hunt(session, hunt_id, data.status, data.conclusion, data.iocs_found)
