"""Bug-report API + page.

Any authenticated user can file a bug; ION opens a linked GitLab issue
(best-effort) and tracks its open/closed state back into the local record.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_page_auth
from ion.models.service_desk import BugReport
from ion.models.user import User
from ion.services import service_desk_service as svc
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["bug-reports"])

from ion.web.templating import make_templates  # noqa: E402

_templates = make_templates()

_SEVERITIES = {"low", "medium", "high", "critical"}


class BugReportCreate(BaseModel):
    title: str
    description: str
    steps_to_reproduce: Optional[str] = None
    component: Optional[str] = None
    severity: str = "medium"
    page_url: Optional[str] = None


@router.post("/api/bug-reports", status_code=201)
async def create_bug_report(
    body: BugReportCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    if not body.title.strip() or not body.description.strip():
        raise HTTPException(status_code=400, detail="title and description are required")
    severity = body.severity if body.severity in _SEVERITIES else "medium"
    br = await svc.create_bug_report(
        session,
        current_user.id,
        {
            "title": body.title,
            "description": body.description,
            "steps_to_reproduce": body.steps_to_reproduce,
            "component": body.component,
            "severity": severity,
            "page_url": body.page_url,
        },
    )
    return br.to_dict()


@router.get("/api/bug-reports")
def list_bug_reports(
    status: Optional[str] = None,
    mine: bool = False,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    # object-level scoping. Anyone can file a bug, but only a
    # privileged user (system:settings — the CAB/admin surface) may see
    # everyone's; a normal analyst is scoped to their own submissions.
    can_see_all = current_user.has_permission("system:settings")
    stmt = select(BugReport)
    if status and status != "all":
        stmt = stmt.where(BugReport.status == status)
    if mine or not can_see_all:
        stmt = stmt.where(BugReport.reported_by_id == current_user.id)
    stmt = stmt.order_by(BugReport.created_at.desc()).limit(500)
    rows = session.execute(stmt).scalars().all()
    return {"bug_reports": [r.to_dict() for r in rows], "count": len(rows)}


@router.get("/api/bug-reports/{report_id}")
def get_bug_report(
    report_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    br = session.get(BugReport, report_id)
    if not br:
        raise HTTPException(status_code=404, detail="Bug report not found")
    # Owner or privileged only; 404 (not 403) for others — no existence oracle.
    if br.reported_by_id != current_user.id and not current_user.has_permission("system:settings"):
        raise HTTPException(status_code=404, detail="Bug report not found")
    return br.to_dict()


@router.post("/api/bug-reports/{report_id}/sync")
async def sync_bug_report(
    report_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    br = session.get(BugReport, report_id)
    if not br:
        raise HTTPException(status_code=404, detail="Bug report not found")
    if br.reported_by_id != current_user.id and not current_user.has_permission("system:settings"):
        raise HTTPException(status_code=404, detail="Bug report not found")
    if not br.gitlab_issue_iid:
        raise HTTPException(status_code=409, detail="No linked GitLab issue to sync")
    br = await svc.sync_bug_report(session, br)
    return br.to_dict()


@router.get("/bug-reports", response_class=HTMLResponse)
def bug_reports_page(request: Request, _user: User = Depends(require_page_auth)):
    return _templates.TemplateResponse(
        request=request,
        name="bug_reports.html",
        # Needed by the sibling tab strip: the Change Requests tab is only
        # rendered for users who can actually open that page (system:settings).
        context={"current_user": _user},
    )
