"""Detection Health dashboard API (v0.47.0).

Per-rule performance analytics over the AIFeedback ledger + closure verdicts,
plus a one-click action to file a `TuningProposal` against a flagged rule.

Read views gated `security:read` (lead / detection-engineer audience — a step
up from the `alert:read` used by the other reporting pages). The proposal-create
mutation is gated `tuning:review`, matching `tuning_proposal_api`.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_any_permission, require_permission
from ion.models.tuning_proposal import TuningProposal, TuningProposalStatus
from ion.models.user import User
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/detection-health", tags=["detection-health"])


@router.get("/metrics", dependencies=[Depends(require_permission("security:read"))])
def detection_health_metrics(
    days: int = Query(90, ge=1, le=365, description="Lookback window in days"),
    session: Session = Depends(get_db_session),
):
    """Per-rule detection-health metrics."""
    from ion.services.detection_health_service import get_detection_health

    return get_detection_health(session, days=days)


@router.get(
    "/rules/{rule_name}/disagreements",
    dependencies=[Depends(require_permission("security:read"))],
)
def detection_health_disagreements(
    rule_name: str,
    days: int = Query(90, ge=1, le=365),
    session: Session = Depends(get_db_session),
):
    """Bob-vs-analyst disagreements for a single rule (drill-down)."""
    from ion.services.detection_health_service import get_rule_disagreements

    return get_rule_disagreements(session, rule_name, days=days)


class TuningProposalCreate(BaseModel):
    rule_name: str
    suggested_change: str
    rationale: Optional[str] = None
    alert_id: Optional[str] = None


@router.post(
    "/tuning-proposal",
    dependencies=[Depends(require_any_permission(["tuning:review"]))],
)
def create_tuning_proposal(
    payload: TuningProposalCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """File a tuning proposal against a rule flagged on the dashboard.

    Net-new create path (the existing tuning-proposal API only reviews
    Bob-generated proposals). Validation + attribution run here before commit.
    """
    rule = (payload.rule_name or "").strip()
    change = (payload.suggested_change or "").strip()
    if not rule:
        raise HTTPException(status_code=400, detail="rule_name is required")
    if not change:
        raise HTTPException(status_code=400, detail="suggested_change is required")

    proposal = TuningProposal(
        rule_id=rule,
        alert_id=(payload.alert_id or None),
        suggested_change=change,
        rationale=(payload.rationale or None),
        status=TuningProposalStatus.PENDING,
        created_by_id=current_user.id,
    )
    session.add(proposal)
    session.commit()
    session.refresh(proposal)
    logger.info("Detection-health tuning proposal %d filed for rule %r by user %s",
                proposal.id, rule, current_user.id)
    return proposal.to_dict()
