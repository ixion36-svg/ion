"""SOC Maturity Assessment API."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.services import maturity_service
from ion.web.api import get_db_session

router = APIRouter(prefix="/maturity", tags=["maturity"])


class AssessmentSubmit(BaseModel):
    title: Optional[str] = None
    responses: dict
    notes: Optional[str] = None


@router.get("/questionnaire", dependencies=[Depends(require_permission("alert:read"))])
def questionnaire_endpoint():
    return maturity_service.get_questionnaire()


@router.get("/assessments", dependencies=[Depends(require_permission("alert:read"))])
def list_endpoint(session: Session = Depends(get_db_session)):
    return {"assessments": maturity_service.list_assessments(session)}


@router.post("/assessments", dependencies=[Depends(require_permission("alert:triage"))])
def submit_endpoint(
    data: AssessmentSubmit,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    a = maturity_service.submit_assessment(
        session,
        title=data.title or "SOC Maturity Assessment",
        responses=data.responses,
        notes=data.notes,
        created_by_id=current_user.id,
    )
    return a.to_dict()


@router.get("/assessments/{assessment_id}", dependencies=[Depends(require_permission("alert:read"))])
def get_endpoint(assessment_id: int, session: Session = Depends(get_db_session)):
    a = maturity_service.get_assessment(session, assessment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return a


@router.delete("/assessments/{assessment_id}", dependencies=[Depends(require_permission("alert:triage"))])
def delete_endpoint(assessment_id: int, session: Session = Depends(get_db_session)):
    if not maturity_service.delete_assessment(session, assessment_id):
        raise HTTPException(status_code=404, detail="Assessment not found")
    return {"ok": True}
