"""Role-based skills questionnaire API."""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.services import role_skills_service
from ion.web.api import get_db_session

router = APIRouter(prefix="/skills/role-match", tags=["role-match"])


class RoleAssessmentSubmit(BaseModel):
    role_id: str
    responses: Dict[str, Any]
    notes: Optional[str] = None
    set_as_target: bool = True


@router.get(
    "/definitions",
    dependencies=[Depends(require_permission("alert:read"))],
)
def get_definitions():
    """Return all role definitions + questionnaires + the rating scale.

    Drives the picker UI on /training → Role Match tab.
    """
    return role_skills_service.get_role_definitions()


@router.post(
    "/submit",
    dependencies=[Depends(require_permission("alert:read"))],
)
async def submit_assessment(
    data: RoleAssessmentSubmit,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Score, persist, and return a role-match assessment.

    Side effect: when set_as_target=True (default) updates the user's
    UserCareerGoal.target_role so the existing /training tabs see the choice.
    """
    try:
        assessment = await role_skills_service.submit_assessment(
            session,
            user_id=current_user.id,
            role_id=data.role_id,
            responses=data.responses,
            notes=data.notes,
            set_as_target=data.set_as_target,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return role_skills_service._to_dict(assessment)


@router.get(
    "/me",
    dependencies=[Depends(require_permission("alert:read"))],
)
def get_my_latest(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Return the current user's most recent role assessment, or empty if none yet."""
    latest = role_skills_service.get_latest_for_user(session, current_user.id)
    return {"assessment": latest}


@router.get(
    "/history",
    dependencies=[Depends(require_permission("alert:read"))],
)
def get_my_history(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Return all of the current user's past role assessments, newest first."""
    return {"assessments": role_skills_service.list_history_for_user(session, current_user.id)}
