"""On-Call and Escalation Management API."""

import logging
from datetime import date
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from ion.web.api import limiter
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission, get_current_user
from ion.models.user import User
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/oncall", tags=["oncall"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SetOnCallRequest(BaseModel):
    user_id: int
    date: str = Field(..., description="ISO date, e.g. 2026-04-07")
    role_type: str = Field(..., description="duty_im | primary_analyst | secondary_analyst | engineer_oncall")
    shift: str = "day"
    contact_phone: Optional[str] = None
    contact_alt: Optional[str] = None
    notes: Optional[str] = None


class EscalateRequest(BaseModel):
    severity: str = Field(..., description="critical | high | medium | low")
    reason: str
    case_id: Optional[int] = None
    alert_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/current",
    dependencies=[Depends(require_permission("alert:read"))],
)
def current_oncall(
    session: Session = Depends(get_db_session),
):
    """Get who is on call right now for each role type."""
    from ion.services.oncall_service import get_current_oncall

    return get_current_oncall(session)


@router.get(
    "/roster",
    dependencies=[Depends(require_permission("alert:read"))],
)
def roster_week(
    start_date: Optional[str] = Query(None, description="ISO date, e.g. 2026-04-07"),
    session: Session = Depends(get_db_session),
):
    """Get 7 days of on-call roster starting from start_date (default: today)."""
    from ion.services.oncall_service import get_roster_week

    sd = None
    if start_date:
        try:
            sd = date.fromisoformat(start_date)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format — use YYYY-MM-DD")

    return get_roster_week(session, start_date=sd)


@router.post(
    "/roster",
    dependencies=[Depends(require_permission("user:manage"))],
)
def set_roster_entry(
    body: SetOnCallRequest,
    session: Session = Depends(get_db_session),
):
    """Create or update an on-call roster entry."""
    from ion.services.oncall_service import set_oncall

    try:
        roster_date = date.fromisoformat(body.date)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format — use YYYY-MM-DD")

    valid_roles = ("duty_im", "primary_analyst", "secondary_analyst", "engineer_oncall")
    if body.role_type not in valid_roles:
        raise HTTPException(status_code=400, detail=f"role_type must be one of {valid_roles}")

    valid_shifts = ("day", "night", "24h")
    if body.shift not in valid_shifts:
        raise HTTPException(status_code=400, detail=f"shift must be one of {valid_shifts}")

    return set_oncall(
        session,
        user_id=body.user_id,
        roster_date=roster_date,
        role_type=body.role_type,
        shift=body.shift,
        contact_phone=body.contact_phone,
        contact_alt=body.contact_alt,
        notes=body.notes,
    )


@router.get(
    "/policies",
    dependencies=[Depends(require_permission("alert:read"))],
)
def list_policies(
    session: Session = Depends(get_db_session),
):
    """Get all active escalation policies."""
    from ion.services.oncall_service import get_escalation_policies

    return get_escalation_policies(session)


@router.post(
    "/escalate",
    dependencies=[Depends(require_permission("alert:read"))],
)
def escalate(
    request: Request,
    body: EscalateRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Escalate an alert or case to the current duty IM."""
    from ion.services.oncall_service import escalate_to_duty_im

    valid_severities = ("critical", "high", "medium", "low")
    if body.severity not in valid_severities:
        raise HTTPException(status_code=400, detail=f"severity must be one of {valid_severities}")

    try:
        return escalate_to_duty_im(
            session,
            escalated_by_id=current_user.id,
            severity=body.severity,
            reason=body.reason,
            case_id=body.case_id,
            alert_id=body.alert_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.get(
    "/escalations",
    dependencies=[Depends(require_permission("alert:read"))],
)
def list_escalations(
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_db_session),
):
    """Get recent escalation log entries."""
    from ion.services.oncall_service import get_escalation_log

    return get_escalation_log(session, limit=limit)


@router.post(
    "/escalations/{escalation_id}/acknowledge",
    dependencies=[Depends(require_permission("alert:read"))],
)
def ack_escalation(
    escalation_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Acknowledge an escalation."""
    from ion.services.oncall_service import acknowledge_escalation

    try:
        return acknowledge_escalation(session, escalation_id, current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
