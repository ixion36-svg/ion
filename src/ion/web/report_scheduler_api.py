"""Reporting Scheduler API."""

import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission, get_current_user
from ion.models.user import User
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/report-scheduler", tags=["report-scheduler"])


class ReportCreate(BaseModel):
    name: str
    report_type: str  # executive, soc_health, shift_handover, compliance
    schedule: str  # daily, weekly, monthly
    time_utc: str = "08:00"
    day_of_week: Optional[int] = None
    day_of_month: Optional[int] = None
    recipients: Optional[list] = None
    config: Optional[dict] = None


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
def list_reports(session: Session = Depends(get_db_session)):
    from ion.services.report_scheduler_service import get_scheduled_reports
    return {"reports": get_scheduled_reports(session)}


@router.post("", dependencies=[Depends(require_permission("system:settings"))])
def create_report(data: ReportCreate, current_user: User = Depends(get_current_user), session: Session = Depends(get_db_session)):
    import json
    from ion.services.report_scheduler_service import create_scheduled_report
    return create_scheduled_report(
        session, name=data.name, report_type=data.report_type,
        schedule=data.schedule, created_by_id=current_user.id,
        time_utc=data.time_utc, day_of_week=data.day_of_week,
        day_of_month=data.day_of_month,
        recipients=json.dumps(data.recipients) if data.recipients else None,
        config=json.dumps(data.config) if data.config else None,
    )


@router.post("/{report_id}/run", dependencies=[Depends(require_permission("alert:read"))])
def run_now(report_id: int, session: Session = Depends(get_db_session)):
    from ion.services.report_scheduler_service import run_report_now
    result = run_report_now(session, report_id)
    if not result:
        raise HTTPException(status_code=404, detail="Report not found")
    # Strip any embedded raw exception text from the service result before
    # returning it (avoid leaking stack frames in HTTP responses).
    if isinstance(result, dict):
        safe = {k: v for k, v in result.items() if k != "error"}
        if result.get("error"):
            safe["has_error"] = True
        return safe
    return {"result": "ok"}


@router.delete("/{report_id}", dependencies=[Depends(require_permission("system:settings"))])
def delete_report(report_id: int, session: Session = Depends(get_db_session)):
    from ion.services.report_scheduler_service import delete_scheduled_report
    if not delete_scheduled_report(session, report_id):
        raise HTTPException(status_code=404, detail="Report not found")
    return {"ok": True}
