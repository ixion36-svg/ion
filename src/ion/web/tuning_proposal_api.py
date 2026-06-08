"""Tuning proposals API + page — detection-engineering review of Bob's FP
verdicts that suggested a concrete rule tuning."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.auth.dependencies import (
    get_current_user,
    require_any_permission,
    require_page_auth,
)
from ion.models.tuning_proposal import TuningProposal, TuningProposalStatus
from ion.models.user import User
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["tuning-proposals"])

from ion.web.templating import make_templates  # noqa: E402

_templates = make_templates()

_READ = ["tuning:read"]
_REVIEW = ["tuning:review"]


class ReviewRequest(BaseModel):
    review_notes: Optional[str] = None


@router.get(
    "/api/tuning-proposals",
    dependencies=[Depends(require_any_permission(_READ))],
)
def list_tuning_proposals(
    status: Optional[str] = "pending",
    session: Session = Depends(get_db_session),
):
    """List tuning proposals. Defaults to pending — pass status=all to include closed ones."""
    stmt = select(TuningProposal)
    if status and status != "all":
        stmt = stmt.where(TuningProposal.status == status)
    stmt = stmt.order_by(TuningProposal.created_at.desc())
    rows = session.execute(stmt).scalars().all()
    return {"proposals": [r.to_dict() for r in rows], "count": len(rows)}


@router.get(
    "/api/tuning-proposals/{proposal_id}",
    dependencies=[Depends(require_any_permission(_READ))],
)
def get_tuning_proposal(
    proposal_id: int,
    session: Session = Depends(get_db_session),
):
    p = session.get(TuningProposal, proposal_id)
    if not p:
        raise HTTPException(status_code=404, detail="Tuning proposal not found")
    return p.to_dict()


def _review(
    proposal_id: int,
    new_status: TuningProposalStatus,
    payload: ReviewRequest,
    user: User,
    session: Session,
):
    p = session.get(TuningProposal, proposal_id)
    if not p:
        raise HTTPException(status_code=404, detail="Tuning proposal not found")
    if p.status != TuningProposalStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail=f"Already reviewed (status={p.status})",
        )
    p.status = new_status
    p.reviewed_by_id = user.id
    p.reviewed_at = datetime.now(timezone.utc)
    p.review_notes = payload.review_notes
    session.commit()
    return p.to_dict()


@router.post(
    "/api/tuning-proposals/{proposal_id}/accept",
    dependencies=[Depends(require_any_permission(_REVIEW))],
)
def accept_tuning_proposal(
    proposal_id: int,
    payload: ReviewRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    return _review(proposal_id, TuningProposalStatus.ACCEPTED, payload, current_user, session)


@router.post(
    "/api/tuning-proposals/{proposal_id}/reject",
    dependencies=[Depends(require_any_permission(_REVIEW))],
)
def reject_tuning_proposal(
    proposal_id: int,
    payload: ReviewRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    return _review(proposal_id, TuningProposalStatus.REJECTED, payload, current_user, session)


@router.post(
    "/api/tuning-proposals/{proposal_id}/duplicate",
    dependencies=[Depends(require_any_permission(_REVIEW))],
)
def mark_tuning_proposal_duplicate(
    proposal_id: int,
    payload: ReviewRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    return _review(proposal_id, TuningProposalStatus.DUPLICATE, payload, current_user, session)


@router.get("/tuning-proposals", response_class=HTMLResponse)
def tuning_proposals_page(
    request: Request,
    _user: User = Depends(require_page_auth),
):
    return _templates.TemplateResponse(
        request=request,
        name="tuning_proposals.html",
    )
