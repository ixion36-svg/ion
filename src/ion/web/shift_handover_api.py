"""Shift Handover API — generate and retrieve shift reports."""

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
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
    """Generate a shift handover report for the last N hours."""
    report = generate_shift_report(session, hours=hours)
    report["generated_by"] = current_user.username
    return report
