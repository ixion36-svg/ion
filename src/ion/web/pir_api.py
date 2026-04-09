"""Post-Incident Review API."""

from datetime import date
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.core.safe_errors import safe_error
from ion.models.pir import PIRActionStatus, PIRStatus
from ion.models.user import User
from ion.services import pir_service
from ion.web.api import get_db_session

router = APIRouter(prefix="/pirs", tags=["pirs"])


class PIRCreate(BaseModel):
    case_id: int


class PIRUpdate(BaseModel):
    status: Optional[str] = None
    summary: Optional[str] = None
    timeline: Optional[str] = None
    what_worked: Optional[str] = None
    what_didnt: Optional[str] = None
    root_cause: Optional[str] = None
    detection_gaps: Optional[str] = None
    response_gaps: Optional[str] = None
    metrics: Optional[dict] = None


class ActionCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=300)
    description: Optional[str] = None
    category: Optional[str] = None
    priority: str = "medium"
    owner_id: Optional[int] = None
    due_date: Optional[date] = None


class ActionUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=300)
    description: Optional[str] = None
    category: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    owner_id: Optional[int] = None
    due_date: Optional[date] = None


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
def list_endpoint(status: Optional[str] = None, session: Session = Depends(get_db_session)):
    return {"pirs": pir_service.list_pirs(session, status=status)}


@router.get("/backlog", dependencies=[Depends(require_permission("alert:read"))])
def backlog_endpoint(session: Session = Depends(get_db_session)):
    """Open action items across the org."""
    return {"actions": pir_service.backlog(session)}


@router.get("/by-case/{case_id}", dependencies=[Depends(require_permission("alert:read"))])
def by_case_endpoint(case_id: int, session: Session = Depends(get_db_session)):
    pir = pir_service.get_pir_by_case(session, case_id)
    if not pir:
        return {"pir": None}
    return {"pir": pir.to_dict()}


@router.post("", dependencies=[Depends(require_permission("alert:triage"))])
def create_endpoint(
    data: PIRCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    try:
        pir = pir_service.create_pir(session, case_id=data.case_id, created_by_id=current_user.id)
        return pir.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=safe_error(e, "pir_create"))


@router.get("/{pir_id}", dependencies=[Depends(require_permission("alert:read"))])
def get_endpoint(pir_id: int, session: Session = Depends(get_db_session)):
    pir = pir_service.get_pir(session, pir_id)
    if not pir:
        raise HTTPException(status_code=404, detail="PIR not found")
    return pir.to_dict()


@router.patch("/{pir_id}", dependencies=[Depends(require_permission("alert:triage"))])
def update_endpoint(
    pir_id: int,
    data: PIRUpdate,
    session: Session = Depends(get_db_session),
):
    fields = data.model_dump(exclude_none=True)
    if "status" in fields and fields["status"] not in {s.value for s in PIRStatus}:
        raise HTTPException(status_code=400, detail="Invalid PIR status")
    pir = pir_service.update_pir(session, pir_id, **fields)
    if not pir:
        raise HTTPException(status_code=404, detail="PIR not found")
    return pir.to_dict()


@router.delete("/{pir_id}", dependencies=[Depends(require_permission("alert:triage"))])
def delete_endpoint(pir_id: int, session: Session = Depends(get_db_session)):
    if not pir_service.delete_pir(session, pir_id):
        raise HTTPException(status_code=404, detail="PIR not found")
    return {"ok": True}


@router.post("/{pir_id}/suggest", dependencies=[Depends(require_permission("alert:triage"))])
async def suggest_endpoint(pir_id: int, session: Session = Depends(get_db_session)):
    """Ask Ollama for improvement bullets for this PIR."""
    try:
        text = await pir_service.suggest_improvements(session, pir_id)
        if text is None:
            return {"suggestions": None, "reason": "Ollama disabled or PIR not found"}
        return {"suggestions": text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=safe_error(e, "pir_suggest"))


# Action items
@router.post("/{pir_id}/actions", dependencies=[Depends(require_permission("alert:triage"))])
def add_action_endpoint(
    pir_id: int,
    data: ActionCreate,
    session: Session = Depends(get_db_session),
):
    try:
        a = pir_service.add_action(
            session, pir_id,
            title=data.title,
            description=data.description,
            category=data.category,
            priority=data.priority,
            owner_id=data.owner_id,
            due_date=data.due_date,
        )
        return a.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.patch("/actions/{action_id}", dependencies=[Depends(require_permission("alert:triage"))])
def update_action_endpoint(
    action_id: int,
    data: ActionUpdate,
    session: Session = Depends(get_db_session),
):
    fields = data.model_dump(exclude_none=True)
    if "status" in fields and fields["status"] not in {s.value for s in PIRActionStatus}:
        raise HTTPException(status_code=400, detail="Invalid action status")
    a = pir_service.update_action(session, action_id, **fields)
    if not a:
        raise HTTPException(status_code=404, detail="Action item not found")
    return a.to_dict()


@router.delete("/actions/{action_id}", dependencies=[Depends(require_permission("alert:triage"))])
def delete_action_endpoint(action_id: int, session: Session = Depends(get_db_session)):
    if not pir_service.delete_action(session, action_id):
        raise HTTPException(status_code=404, detail="Action item not found")
    return {"ok": True}
