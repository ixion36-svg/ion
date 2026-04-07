"""Communication Templates API."""

import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission, get_current_user
from ion.models.user import User
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/comm-templates", tags=["comm-templates"])


class TemplateCreate(BaseModel):
    name: str
    category: str
    subject_template: str
    body_template: str
    audience: str = "internal"


class RenderRequest(BaseModel):
    variables: dict


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
def list_templates(category: str = Query(None), session: Session = Depends(get_db_session)):
    from ion.services.comm_template_service import get_templates
    return {"templates": get_templates(session, category=category)}


@router.get("/{template_id}", dependencies=[Depends(require_permission("alert:read"))])
def get_template(template_id: int, session: Session = Depends(get_db_session)):
    from ion.services.comm_template_service import get_template
    result = get_template(session, template_id)
    if not result:
        raise HTTPException(status_code=404, detail="Template not found")
    return result


@router.post("", dependencies=[Depends(require_permission("alert:read"))])
def create_template(
    data: TemplateCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    from ion.services.comm_template_service import create_template
    return create_template(
        session, name=data.name, category=data.category,
        subject_template=data.subject_template, body_template=data.body_template,
        audience=data.audience, created_by_id=current_user.id,
    )


@router.post("/{template_id}/render", dependencies=[Depends(require_permission("alert:read"))])
def render_template(template_id: int, data: RenderRequest, session: Session = Depends(get_db_session)):
    from ion.services.comm_template_service import render_template
    result = render_template(session, template_id, data.variables)
    if not result:
        raise HTTPException(status_code=404, detail="Template not found")
    return result
