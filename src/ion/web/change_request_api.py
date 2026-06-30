"""Change-request (CAB) API + page.

A change request captures the full CAB dataset for an ION version upgrade and
runs a reviewed status workflow. Gated by ``system:settings`` — the same
permission that governs the rest of the admin/operations surface. Optionally
mirrors the request to a linked GitLab issue.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.auth.dependencies import (
    get_current_user,
    require_page_permission,
    require_permission,
)
from ion.models.service_desk import ChangeRequest
from ion.models.user import User
from ion.services import service_desk_service as svc
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["change-requests"])

from ion.web.templating import make_templates  # noqa: E402

_templates = make_templates()

_PERM = "system:settings"
_RISKS = {"low", "medium", "high"}


class ChangeRequestCreate(BaseModel):
    title: Optional[str] = None
    change_type: str = "ION version upgrade"
    target_version: Optional[str] = None
    justification: Optional[str] = None
    changes: Optional[str] = None
    risk_level: str = "medium"
    impact: Optional[str] = None
    affected_systems: Optional[str] = None
    implementation_plan: Optional[str] = None
    backout_plan: Optional[str] = None
    test_plan: Optional[str] = None
    scheduled_start: Optional[str] = None
    scheduled_end: Optional[str] = None
    create_gitlab: bool = True


class TransitionRequest(BaseModel):
    action: str
    notes: Optional[str] = None
    scheduled_start: Optional[str] = None
    scheduled_end: Optional[str] = None


@router.get("/api/change-requests", dependencies=[Depends(require_permission(_PERM))])
def list_change_requests(
    status: Optional[str] = None,
    session: Session = Depends(get_db_session),
):
    stmt = select(ChangeRequest)
    if status and status != "all":
        stmt = stmt.where(ChangeRequest.status == status)
    stmt = stmt.order_by(ChangeRequest.created_at.desc()).limit(500)
    rows = session.execute(stmt).scalars().all()
    return {"change_requests": [r.to_dict() for r in rows], "count": len(rows)}


@router.get("/api/change-requests/changelog", dependencies=[Depends(require_permission(_PERM))])
def preview_changelog(target: Optional[str] = None):
    """Preview the CHANGELOG delta the form will pre-fill for current→target."""
    current = svc._ion_version()
    return {
        "current_version": current,
        "target_version": target,
        "changes": svc.changelog_between(current, target) if target else "",
        "backout_plan": svc.default_backout_plan(current),
    }


@router.post("/api/change-requests", status_code=201, dependencies=[Depends(require_permission(_PERM))])
async def create_change_request(
    body: ChangeRequestCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    data = body.model_dump()
    if data.get("risk_level") not in _RISKS:
        data["risk_level"] = "medium"
    cr = await svc.create_change_request(
        session, current_user.id, data, create_gitlab=bool(body.create_gitlab)
    )
    return cr.to_dict()


@router.get("/api/change-requests/{cr_id}", dependencies=[Depends(require_permission(_PERM))])
def get_change_request(cr_id: int, session: Session = Depends(get_db_session)):
    cr = session.get(ChangeRequest, cr_id)
    if not cr:
        raise HTTPException(status_code=404, detail="Change request not found")
    return cr.to_dict()


@router.post("/api/change-requests/{cr_id}/transition", dependencies=[Depends(require_permission(_PERM))])
def transition_change_request(
    cr_id: int,
    body: TransitionRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    cr = session.get(ChangeRequest, cr_id)
    if not cr:
        raise HTTPException(status_code=404, detail="Change request not found")
    try:
        cr = svc.transition_change_request(
            session, cr, body.action, current_user.id, body.notes,
            scheduled_start=body.scheduled_start, scheduled_end=body.scheduled_end,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return cr.to_dict()


@router.get("/api/change-requests/{cr_id}/export", dependencies=[Depends(require_permission(_PERM))])
def export_change_request(cr_id: int, session: Session = Depends(get_db_session)):
    """Download the full CAB submission as a Markdown document."""
    cr = session.get(ChangeRequest, cr_id)
    if not cr:
        raise HTTPException(status_code=404, detail="Change request not found")
    md = svc.cab_markdown(cr)
    return PlainTextResponse(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="CAB-{cr.reference}.md"'},
    )


@router.get("/change-requests", response_class=HTMLResponse)
def change_requests_page(
    request: Request, _user: User = Depends(require_page_permission(_PERM))
):
    return _templates.TemplateResponse(request=request, name="change_requests.html")
