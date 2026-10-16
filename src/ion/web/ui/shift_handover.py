"""Live shift report and accountable transfer fragments."""
import logging

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.services import shift_handover_record_service as handovers
from ion.storage.database import get_db_session
from ion.web.api import list_assignable_users
from ion.web.shift_handover_api import get_shift_report
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)
router = APIRouter()


def normalize(value):
    if isinstance(value, dict):
        return {plain(k): normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return plain(value)


@router.get("/shift-handover/controls", response_class=HTMLResponse)
def controls(request: Request, user: User = Depends(require_permission("alert:read"))):
    return templates.TemplateResponse(request=request, name="_fragments/shift_handover_controls.html",
                                      context={"can_write": user.has_permission("case:update")})


@router.get("/shift-handover/report", response_class=HTMLResponse)
def report(request: Request, hours: int = Query(8, ge=1, le=24),
           user: User = Depends(require_permission("alert:read")),
           session: Session = Depends(get_db_session)):
    data = None
    try:
        data = normalize(get_shift_report(hours=hours, session=session, current_user=user))
    except Exception:
        logger.exception("Shift report could not be read")
    return templates.TemplateResponse(request=request, name="_fragments/shift_handover_report.html",
                                      context={"data": data}, headers={"Cache-Control": "no-store"})


@router.get("/shift-handover/transfers", response_class=HTMLResponse,
            dependencies=[Depends(require_permission("alert:read"))])
def transfers(request: Request, session: Session = Depends(get_db_session)):
    rows = metrics = None
    try:
        rows = normalize(handovers.list_handovers(session, limit=10))
    except Exception:
        logger.exception("Shift transfers could not be read")
        session.rollback()
    try:
        metrics = handovers.handover_metrics(session)
    except Exception:
        logger.exception("Shift transfer metrics could not be read")
    return templates.TemplateResponse(request=request, name="_fragments/shift_handover_transfers.html",
                                      context={"rows": rows, "metrics": metrics},
                                      headers={"Cache-Control": "no-store"})


@router.get("/shift-handover/leads", response_class=HTMLResponse)
async def leads(request: Request, user: User = Depends(require_permission("alert:read")),
                session: Session = Depends(get_db_session)):
    users = None
    try:
        users = (await list_assignable_users(session=session))["users"]
        users = [u for u in users if u["id"] != user.id]
    except Exception:
        logger.exception("Incoming leads could not be read")
    return templates.TemplateResponse(request=request, name="_fragments/shift_handover_leads.html",
                                      context={"users": users, "can_write": user.has_permission("case:update")})


@router.get("/shift-handover/transfers/{handover_id}", response_class=HTMLResponse)
async def detail(request: Request, handover_id: int,
                 user: User = Depends(require_permission("alert:read")),
                 session: Session = Depends(get_db_session)):
    data = users = None
    capabilities = {}
    try:
        data = normalize(handovers.get_handover(session, handover_id))
        if user.has_permission("case:update"):
            capabilities = handovers.handover_capabilities(data["status"], data["outgoing_lead_id"],
                                                         data.get("incoming_lead_id"), user.id)
        for action in data.get("actions") or []:
            action["can_resolve"] = (user.has_permission("case:update") and
                                     action.get("status") in handovers.RESOLVABLE_ACTION_STATUSES)
    except Exception:
        logger.exception("Shift transfer %s could not be read", handover_id)
        data = None
    if data is not None and (capabilities.get("set_incoming") or capabilities.get("add_action")):
        try:
            users = (await list_assignable_users(session=session))["users"]
        except Exception:
            logger.exception("Shift assignment choices could not be read")
    return templates.TemplateResponse(request=request, name="_fragments/shift_handover_detail.html",
                                      context={"h": data, "capabilities": capabilities, "users": users},
                                      headers={"Cache-Control": "no-store"})
