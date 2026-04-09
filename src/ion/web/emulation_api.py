"""Adversary Emulation Plans API."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.core.safe_errors import safe_error
from ion.models.emulation import EmulationPlanStatus, StepResult
from ion.models.user import User
from ion.services import emulation_service
from ion.web.api import get_db_session

router = APIRouter(prefix="/emulation", tags=["emulation"])


class PlanCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    actor_name: Optional[str] = None
    actor_id: Optional[str] = None
    target_systems: Optional[list[str]] = None
    tags: Optional[list[str]] = None


class PlanUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    actor_name: Optional[str] = None
    actor_id: Optional[str] = None
    status: Optional[str] = None
    target_systems: Optional[list[str]] = None
    tags: Optional[list[str]] = None


class StepCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=300)
    description: Optional[str] = None
    mitre_techniques: Optional[list[str]] = None
    procedure: Optional[str] = None
    expected_rules: Optional[list[str]] = None


class StepUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=300)
    description: Optional[str] = None
    mitre_techniques: Optional[list[str]] = None
    procedure: Optional[str] = None
    expected_rules: Optional[list[str]] = None
    result: Optional[str] = None
    notes: Optional[str] = None
    order_index: Optional[int] = None


@router.get("/plans", dependencies=[Depends(require_permission("alert:read"))])
def list_plans_endpoint(status: Optional[str] = None, session: Session = Depends(get_db_session)):
    return {"plans": emulation_service.list_plans(session, status=status)}


@router.post("/plans", dependencies=[Depends(require_permission("alert:triage"))])
def create_plan_endpoint(
    data: PlanCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    try:
        p = emulation_service.create_plan(
            session,
            name=data.name,
            description=data.description,
            actor_name=data.actor_name,
            actor_id=data.actor_id,
            target_systems=data.target_systems,
            tags=data.tags,
            created_by_id=current_user.id,
        )
        return p.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=safe_error(e, "emulation_create_plan"))


@router.get("/plans/{plan_id}", dependencies=[Depends(require_permission("alert:read"))])
def get_plan_endpoint(plan_id: int, session: Session = Depends(get_db_session)):
    p = emulation_service.get_plan(session, plan_id)
    if not p:
        raise HTTPException(status_code=404, detail="Plan not found")
    return p.to_dict()


@router.patch("/plans/{plan_id}", dependencies=[Depends(require_permission("alert:triage"))])
def update_plan_endpoint(
    plan_id: int,
    data: PlanUpdate,
    session: Session = Depends(get_db_session),
):
    fields = data.model_dump(exclude_none=True)
    if "status" in fields and fields["status"] not in {s.value for s in EmulationPlanStatus}:
        raise HTTPException(status_code=400, detail="Invalid plan status")
    p = emulation_service.update_plan(session, plan_id, **fields)
    if not p:
        raise HTTPException(status_code=404, detail="Plan not found")
    return p.to_dict()


@router.delete("/plans/{plan_id}", dependencies=[Depends(require_permission("alert:triage"))])
def delete_plan_endpoint(plan_id: int, session: Session = Depends(get_db_session)):
    if not emulation_service.delete_plan(session, plan_id):
        raise HTTPException(status_code=404, detail="Plan not found")
    return {"ok": True}


@router.post("/plans/{plan_id}/steps", dependencies=[Depends(require_permission("alert:triage"))])
def add_step_endpoint(
    plan_id: int,
    data: StepCreate,
    session: Session = Depends(get_db_session),
):
    try:
        s = emulation_service.add_step(
            session, plan_id,
            title=data.title,
            description=data.description,
            mitre_techniques=data.mitre_techniques,
            procedure=data.procedure,
            expected_rules=data.expected_rules,
        )
        return s.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.patch("/steps/{step_id}", dependencies=[Depends(require_permission("alert:triage"))])
def update_step_endpoint(
    step_id: int,
    data: StepUpdate,
    session: Session = Depends(get_db_session),
):
    fields = data.model_dump(exclude_none=True)
    if "result" in fields and fields["result"] not in {s.value for s in StepResult}:
        raise HTTPException(status_code=400, detail="Invalid step result")
    s = emulation_service.update_step(session, step_id, **fields)
    if not s:
        raise HTTPException(status_code=404, detail="Step not found")
    return s.to_dict()


@router.delete("/steps/{step_id}", dependencies=[Depends(require_permission("alert:triage"))])
def delete_step_endpoint(step_id: int, session: Session = Depends(get_db_session)):
    if not emulation_service.delete_step(session, step_id):
        raise HTTPException(status_code=404, detail="Step not found")
    return {"ok": True}


@router.post("/steps/{step_id}/execute", dependencies=[Depends(require_permission("alert:triage"))])
def execute_step_endpoint(step_id: int, session: Session = Depends(get_db_session)):
    """Mark a step as executed at the current time. Operator runs the actual TTP outside ION."""
    s = emulation_service.mark_executed(session, step_id)
    if not s:
        raise HTTPException(status_code=404, detail="Step not found")
    return s.to_dict()


@router.post("/steps/{step_id}/verify", dependencies=[Depends(require_permission("alert:triage"))])
async def verify_step_endpoint(
    step_id: int,
    lookback_hours: int = Query(4, ge=1, le=168),
    session: Session = Depends(get_db_session),
):
    """Query Elasticsearch for matching alerts and update the step result."""
    try:
        return await emulation_service.verify_step(session, step_id, lookback_hours=lookback_hours)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=safe_error(e, "emulation_verify"))
