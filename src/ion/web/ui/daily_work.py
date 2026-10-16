"""Personal worklog, task controls and permission-separated team board."""
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.services import worklog_service
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates
from ion.web.worklog_api import _parse_day, get_my_day

logger = logging.getLogger(__name__)
router = APIRouter()
AUTO_COLORS = {"triaged": "red", "closed": "green", "playbook": "amber", "note": "purple", "shift": "muted"}


def day_view(payload, task_types):
    taxonomy = {t["key"]: t for t in task_types}
    rows = []
    hours = {h: [] for h in range(24)}
    for original in payload["items"]:
        row = dict(original)
        kind = plain(row.get("type"))
        row["type"] = kind
        row["label"] = taxonomy.get(kind, {}).get("label", kind)
        row["color"] = taxonomy.get(kind, {}).get("color") or AUTO_COLORS.get(kind, "muted")
        row["editable"] = row.get("source") == "logged" and row.get("id") is not None
        # Unknown times remain outside the hourly grid rather than claiming midnight.
        try:
            hour = datetime.strptime(row.get("time") or "", "%H:%M").hour
        except ValueError:
            hour = None
        if hour is not None:
            hours[hour].append(row)
        rows.append(row)
    for bucket in hours.values():
        bucket.sort(key=lambda r: r.get("time") or "")
    return dict(payload, items=rows, hours=hours)


@router.get("/daily-work/controls", response_class=HTMLResponse)
def controls(request: Request, user: User = Depends(require_permission("alert:read")),
             session: Session = Depends(get_db_session)):
    task_types = None
    try:
        task_types = worklog_service.get_task_types(session)
    except Exception:
        logger.exception("Worklog task types could not be read")
    return templates.TemplateResponse(request=request, name="_fragments/daily_work_controls.html",
                                      context={"task_types": task_types, "can_team": user.has_permission("security:read")})


@router.get("/daily-work", response_class=HTMLResponse)
def day(request: Request, date: str | None = None,
        user: User = Depends(require_permission("alert:read")),
        session: Session = Depends(get_db_session)):
    payload = None
    try:
        payload = day_view(get_my_day(date=date, current_user=user, session=session),
                           worklog_service.get_task_types(session))
    except Exception:
        logger.exception("Worklog day could not be read")
    return templates.TemplateResponse(request=request, name="_fragments/daily_work.html",
                                      context={"payload": payload})


@router.get("/daily-work/team", response_class=HTMLResponse)
def team(request: Request, date: str | None = None,
         user: User = Depends(require_permission("security:read")),
         session: Session = Depends(get_db_session)):
    rows = None
    try:
        rows = worklog_service.get_team_today(session, _parse_day(date))
    except Exception:
        logger.exception("Worklog team could not be read")
    return templates.TemplateResponse(request=request, name="_fragments/daily_work_team.html",
                                      context={"team": rows})
