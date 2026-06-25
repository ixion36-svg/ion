"""Daily-work tracking API.

Endpoints backing the My Day / Team Day pages:
  GET    /api/worklog/task-types     — quick-add task taxonomy (seeds defaults)
  GET    /api/worklog/day            — current user's hybrid timeline + summary
  POST   /api/worklog/entry          — log a manual activity (optional time)
  PATCH  /api/worklog/entry/{id}     — edit own entry's time / type / text
  DELETE /api/worklog/entry/{id}     — delete own entry
  GET    /api/worklog/team           — team board (lead view)

Self views are gated ``alert:read`` (any analyst); edit/delete are likewise
``alert:read`` but the worklog service owner-scopes every mutation to the
caller's own ``user_id`` BEFORE touching a row, so one analyst can never edit
another's log. The team board is gated ``security:read`` (lead), matching the
Skills/Team-Schedule convention.
"""

from datetime import date, datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_db_session, require_permission
from ion.models.user import AuditLog, User
from ion.services import worklog_service

router = APIRouter(tags=["worklog"])


class WorkLogEntryCreate(BaseModel):
    task_type: str = Field(..., min_length=1, max_length=50)
    text: str = Field(..., min_length=1, max_length=2000)
    # Optional explicit event time (day-calendar / time picker). Omitted →
    # the column server-default (now) applies.
    logged_at: Optional[datetime] = None


class WorkLogEntryUpdate(BaseModel):
    task_type: Optional[str] = Field(default=None, min_length=1, max_length=50)
    text: Optional[str] = Field(default=None, min_length=1, max_length=2000)
    logged_at: Optional[datetime] = None


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
        session, current_user.id, payload.task_type.strip(), payload.text.strip(),
        logged_at=payload.logged_at,
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


@router.patch("/entry/{entry_id}")
def edit_entry(
    payload: WorkLogEntryUpdate,
    entry_id: int = Path(..., ge=1),
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Edit one of the caller's own manual entries (time / type / text).

    Ownership is enforced inside the service before mutation; a 404 here means
    the entry doesn't exist OR isn't owned by the caller (no existence oracle).
    """
    entry = worklog_service.update_entry(
        session,
        current_user.id,
        entry_id,
        task_type=payload.task_type.strip() if payload.task_type else None,
        text=payload.text.strip() if payload.text else None,
        logged_at=payload.logged_at,
    )
    if entry is None:
        raise HTTPException(status_code=404, detail="Entry not found")
    session.add(AuditLog(
        user_id=current_user.id,
        action="worklog_entry_updated",
        resource_type="worklog",
        resource_id=entry.id,
        details=f"{entry.task_type}: {entry.text[:120]}",
    ))
    session.commit()
    return {"entry": entry.to_dict()}


@router.delete("/entry/{entry_id}")
def remove_entry(
    entry_id: int = Path(..., ge=1),
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Delete one of the caller's own manual entries. Owner-scoped in the
    service; 404 if it doesn't exist or isn't the caller's."""
    ok = worklog_service.delete_entry(session, current_user.id, entry_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Entry not found")
    session.add(AuditLog(
        user_id=current_user.id,
        action="worklog_entry_deleted",
        resource_type="worklog",
        resource_id=entry_id,
        details=f"deleted entry {entry_id}",
    ))
    session.commit()
    return {"deleted": entry_id}


@router.get("/team")
def get_team_day(
    date: str | None = Query(default=None, description="YYYY-MM-DD; defaults to today"),
    current_user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
):
    day = _parse_day(date)
    return {"date": day.isoformat(), "team": worklog_service.get_team_today(session, day)}
