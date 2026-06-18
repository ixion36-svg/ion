"""Daily-work tracking API.

Endpoints backing the My Day / Team Day pages:
  GET  /api/worklog/task-types   — quick-add task taxonomy (seeds defaults)
  GET  /api/worklog/day          — current user's hybrid timeline + summary
  POST /api/worklog/entry        — log a manual activity
  GET  /api/worklog/team         — team board (lead view)

Self views are gated ``alert:read`` (any analyst); the team board is gated
``security:read`` (lead), matching the Skills/Team-Schedule convention.
"""

from datetime import date, datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_db_session, require_permission
from ion.models.user import AuditLog, User
from ion.services import worklog_service

router = APIRouter(tags=["worklog"])


class WorkLogEntryCreate(BaseModel):
    task_type: str = Field(..., min_length=1, max_length=50)
    text: str = Field(..., min_length=1, max_length=2000)


def _parse_day(value: str | None) -> date:
    if value:
        try:
            return datetime.strptime(value, "%Y-%m-%d").date()
        except ValueError:
            pass
    return date.today()


@router.get("/task-types")
def list_task_types(
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    return {"task_types": worklog_service.get_task_types(session)}


@router.get("/day")
def get_my_day(
    date: str | None = Query(default=None, description="YYYY-MM-DD; defaults to today"),
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    day = _parse_day(date)
    data = worklog_service.get_day_activity(session, current_user.id, day)
    data["user"] = {
        "id": current_user.id,
        "name": getattr(current_user, "display_name", None) or current_user.username,
    }
    return data


@router.post("/entry")
def create_entry(
    payload: WorkLogEntryCreate,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    entry = worklog_service.add_entry(
        session, current_user.id, payload.task_type.strip(), payload.text.strip()
    )
    session.add(AuditLog(
        user_id=current_user.id,
        action="worklog_entry_created",
        resource_type="worklog",
        resource_id=entry.id,
        details=f"{payload.task_type}: {payload.text[:120]}",
    ))
    session.commit()
    return {"entry": entry.to_dict()}


@router.get("/team")
def get_team_day(
    date: str | None = Query(default=None, description="YYYY-MM-DD; defaults to today"),
    current_user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
):
    day = _parse_day(date)
    return {"date": day.isoformat(), "team": worklog_service.get_team_today(session, day)}
