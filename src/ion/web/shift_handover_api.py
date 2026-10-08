"""Shift Handover API — the live report, plus accountable persisted transfers.

``GET /shift-handover/report`` is unchanged: the live view of the last N
hours. Everything under ``/shift-handover/handovers`` is the record the
2026-10-08 review asked for — a frozen snapshot, two named leads, owned
actions with deadlines, and an acceptance by someone other than the person
handing over. See ``ion.services.shift_handover_record_service``.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.core.safe_errors import safe_error
from ion.models.user import User
from ion.services import shift_handover_record_service as handovers
from ion.services.shift_handover_record_service import HandoverError
from ion.services.shift_handover_service import generate_shift_report
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/shift-handover", tags=["shift-handover"])


@router.get(
    "/report",
    dependencies=[Depends(require_permission("alert:read"))],
)
def get_shift_report(
    hours: int = Query(8, ge=1, le=24, description="Shift duration in hours"),
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_permission("alert:read")),
):
    """Generate a shift handover report for the last N hours.

    A live view, recomputed per call. ``POST /handovers`` freezes one of
    these into an accountable record.
    """
    report = generate_shift_report(session, hours=hours)
    report["generated_by"] = current_user.username
    return report


# ---------------------------------------------------------------------------
# Persisted transfers
# ---------------------------------------------------------------------------


class HandoverCreate(BaseModel):
    incoming_lead_id: Optional[int] = Field(
        None, description="Required before the handover can be submitted"
    )
    hours: int = Field(8, ge=1, le=24)
    summary: Optional[str] = None


class HandoverReject(BaseModel):
    reason: str = Field(..., min_length=1)


class HandoverIncomingLead(BaseModel):
    incoming_lead_id: int


class HandoverActionCreate(BaseModel):
    description: str = Field(..., min_length=1)
    owner_id: Optional[int] = None
    due_at: Optional[str] = Field(None, description="ISO-8601 deadline")
    case_id: Optional[int] = None


class HandoverActionResolve(BaseModel):
    note: Optional[str] = None


def _parse_ts(raw: Optional[str], field: str) -> Optional[datetime]:
    """Parse an ISO-8601 string, accepting the trailing ``Z`` browsers send."""
    if raw is None or not str(raw).strip():
        return None
    text = str(raw).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail=f"{field} is not a valid ISO-8601 timestamp"
        ) from exc


def _refused(exc: HandoverError) -> HTTPException:
    return HTTPException(status_code=400, detail=safe_error(exc))


@router.get(
    "/handovers",
    dependencies=[Depends(require_permission("alert:read"))],
)
def list_handovers_endpoint(
    limit: int = Query(25, ge=1, le=200),
    session: Session = Depends(get_db_session),
):
    """Recent transfers, newest first."""
    return {"handovers": handovers.list_handovers(session, limit=limit)}


# Declared before "/handovers/{handover_id}" on purpose: FastAPI matches in
# declaration order, so the other way round "metrics" is parsed as an id and
# the request 422s on int conversion.
@router.get(
    "/handovers/metrics",
    dependencies=[Depends(require_permission("alert:read"))],
)
def handover_metrics_endpoint(
    session: Session = Depends(get_db_session),
):
    """Unaccepted handovers and overdue transferred actions."""
    return handovers.handover_metrics(session)


@router.get(
    "/handovers/{handover_id}",
    dependencies=[Depends(require_permission("alert:read"))],
)
def get_handover_endpoint(
    handover_id: int,
    session: Session = Depends(get_db_session),
):
    """One transfer with its frozen snapshot, actions and baseline comparison."""
    try:
        return handovers.get_handover(session, handover_id)
    except HandoverError as exc:
        raise HTTPException(status_code=404, detail=safe_error(exc)) from exc


@router.post(
    "/handovers",
    dependencies=[Depends(require_permission("case:update"))],
)
def create_handover_endpoint(
    body: HandoverCreate,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Raise a draft transfer, freezing the shift snapshot as it stands now.

    The caller is the outgoing lead: handing over on someone else's behalf
    would put a name on the record that did not agree to it.
    """
    try:
        handover = handovers.create_handover(
            session,
            outgoing_lead_id=user.id,
            incoming_lead_id=body.incoming_lead_id,
            hours=body.hours,
            summary=body.summary,
        )
    except HandoverError as exc:
        raise _refused(exc) from exc
    return {"handover": handovers.get_handover(session, handover.id)}


@router.patch(
    "/handovers/{handover_id}/incoming-lead",
    dependencies=[Depends(require_permission("case:update"))],
)
def set_incoming_lead_endpoint(
    handover_id: int,
    body: HandoverIncomingLead,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Name the incoming lead on a draft."""
    try:
        handovers.set_incoming_lead(
            session, handover_id=handover_id,
            incoming_lead_id=body.incoming_lead_id, actor_id=user.id,
        )
    except HandoverError as exc:
        raise _refused(exc) from exc
    return {"handover": handovers.get_handover(session, handover_id)}


@router.post(
    "/handovers/{handover_id}/submit",
    dependencies=[Depends(require_permission("case:update"))],
)
def submit_handover_endpoint(
    handover_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Offer the transfer to the incoming shift."""
    try:
        handovers.submit_handover(session, handover_id=handover_id, actor_id=user.id)
    except HandoverError as exc:
        raise _refused(exc) from exc
    return {"handover": handovers.get_handover(session, handover_id)}


@router.post(
    "/handovers/{handover_id}/accept",
    dependencies=[Depends(require_permission("case:update"))],
)
def accept_handover_endpoint(
    handover_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Take the transfer. Refused for the outgoing lead."""
    try:
        handovers.accept_handover(session, handover_id=handover_id, actor_id=user.id)
    except HandoverError as exc:
        raise _refused(exc) from exc
    return {"handover": handovers.get_handover(session, handover_id)}


@router.post(
    "/handovers/{handover_id}/reject",
    dependencies=[Depends(require_permission("case:update"))],
)
def reject_handover_endpoint(
    handover_id: int,
    body: HandoverReject,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Send the transfer back with a reason the outgoing lead can act on."""
    try:
        handovers.reject_handover(
            session, handover_id=handover_id, actor_id=user.id, reason=body.reason
        )
    except HandoverError as exc:
        raise _refused(exc) from exc
    return {"handover": handovers.get_handover(session, handover_id)}


@router.post(
    "/handovers/{handover_id}/actions",
    dependencies=[Depends(require_permission("case:update"))],
)
def add_handover_action_endpoint(
    handover_id: int,
    body: HandoverActionCreate,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Add work crossing the boundary, with an owner and a deadline."""
    try:
        handovers.add_action(
            session,
            handover_id=handover_id,
            actor_id=user.id,
            description=body.description,
            owner_id=body.owner_id,
            due_at=_parse_ts(body.due_at, "due_at"),
            case_id=body.case_id,
        )
    except HandoverError as exc:
        raise _refused(exc) from exc
    return {"handover": handovers.get_handover(session, handover_id)}


@router.post(
    "/handovers/{handover_id}/actions/{action_id}/complete",
    dependencies=[Depends(require_permission("case:update"))],
)
def complete_handover_action_endpoint(
    handover_id: int,
    action_id: int,
    body: HandoverActionResolve = Body(default_factory=HandoverActionResolve),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Mark an action done, so it stops carrying into the next shift."""
    try:
        handovers.complete_action(
            session, action_id=action_id, actor_id=user.id, note=body.note
        )
    except HandoverError as exc:
        raise _refused(exc) from exc
    return {"handover": handovers.get_handover(session, handover_id)}


@router.post(
    "/handovers/{handover_id}/actions/{action_id}/cancel",
    dependencies=[Depends(require_permission("case:update"))],
)
def cancel_handover_action_endpoint(
    handover_id: int,
    action_id: int,
    body: HandoverReject,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Drop an action. The reason is mandatory — silent disappearance is the
    failure mode this record exists to prevent."""
    try:
        handovers.cancel_action(
            session, action_id=action_id, actor_id=user.id, reason=body.reason
        )
    except HandoverError as exc:
        raise _refused(exc) from exc
    return {"handover": handovers.get_handover(session, handover_id)}
