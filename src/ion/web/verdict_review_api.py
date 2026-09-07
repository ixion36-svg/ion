"""Verdict Review API — list + resolve Bob's pending per-alert verdicts.

Gated by ``verdict:review`` (seeded to the triage-capable roles). Resolving a
verdict stamps the AIFeedback ledger (agreement computed) and is audit-logged.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.core.client_ip import get_client_ip
from ion.models.user import User
from ion.services import verdict_review_service as vr
from ion.storage.auth_repository import AuditLogRepository
from ion.storage.database import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/verdict-review", tags=["verdict-review"])


class ResolveBody(BaseModel):
    human_verdict: str
    delta_reason: Optional[str] = None


@router.get("/pending")
def pending(
    limit: int = 100,
    _user: User = Depends(require_permission("verdict:review")),
    session: Session = Depends(get_db_session),
):
    """Bob's verdicts awaiting a human decision (latest per alert)."""
    return {"pending": vr.list_pending_verdicts(session, limit=limit)}


@router.get("/metrics")
def metrics(
    _user: User = Depends(require_permission("verdict:review")),
    session: Session = Depends(get_db_session),
):
    """Queue depth + Bob↔human agreement rate."""
    return vr.verdict_metrics(session)


@router.post("/{feedback_id}/resolve")
def resolve(
    feedback_id: int,
    body: ResolveBody,
    request: Request,
    user: User = Depends(require_permission("verdict:review")),
    session: Session = Depends(get_db_session),
):
    """Accept Bob's verdict or override it; stamps the ledger + agreement."""
    result = vr.resolve_verdict(
        session,
        feedback_id=feedback_id,
        human_verdict=body.human_verdict,
        reviewer_id=user.id,
        delta_reason=body.delta_reason,
    )
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result["error"])
    AuditLogRepository(session).create(
        user_id=user.id,
        action="verdict_resolved",
        resource_type="ai_feedback",
        resource_id=feedback_id,
        details={"human_verdict": body.human_verdict, "agreement": result.get("agreement")},
        ip_address=get_client_ip(request),
    )
    session.commit()
    return result
