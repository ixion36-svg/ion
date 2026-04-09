"""Canary / Deception Tracker API."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.core.safe_errors import safe_error
from ion.models.canary import CanaryStatus, CanaryType
from ion.models.user import User
from ion.services import canary_service
from ion.web.api import get_db_session

router = APIRouter(prefix="/canaries", tags=["canaries"])


class CanaryCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    canary_type: str = Field(..., description="One of canary type values")
    value: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    location: Optional[str] = Field(None, max_length=255)
    tags: Optional[list[str]] = None
    high_confidence: bool = True


class CanaryUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    canary_type: Optional[str] = None
    value: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    status: Optional[str] = None
    location: Optional[str] = Field(None, max_length=255)
    tags: Optional[list[str]] = None
    high_confidence: Optional[bool] = None


def _validate_type(t: str) -> str:
    if t not in {v.value for v in CanaryType}:
        raise HTTPException(status_code=400, detail=f"Invalid canary_type: {t}")
    return t


def _validate_status(s: str) -> str:
    if s not in {v.value for v in CanaryStatus}:
        raise HTTPException(status_code=400, detail=f"Invalid status: {s}")
    return s


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
def list_endpoint(
    status: Optional[str] = None,
    canary_type: Optional[str] = None,
    session: Session = Depends(get_db_session),
):
    return {"canaries": canary_service.list_canaries(session, status=status, canary_type=canary_type)}


@router.get("/stats", dependencies=[Depends(require_permission("alert:read"))])
def stats_endpoint(session: Session = Depends(get_db_session)):
    return canary_service.stats(session)


@router.get("/types")
def types_endpoint():
    """Static reference: enumerate canary types and statuses for the UI."""
    return {
        "types": [
            {"id": t.value, "label": t.value.replace("_", " ").title()}
            for t in CanaryType
        ],
        "statuses": [
            {"id": s.value, "label": s.value.title()} for s in CanaryStatus
        ],
    }


@router.get("/hits", dependencies=[Depends(require_permission("alert:read"))])
def hits_endpoint(
    canary_id: Optional[int] = None,
    limit: int = 100,
    session: Session = Depends(get_db_session),
):
    return {"hits": canary_service.list_hits(session, canary_id=canary_id, limit=min(max(limit, 1), 500))}


@router.post("", dependencies=[Depends(require_permission("alert:triage"))])
def create_endpoint(
    data: CanaryCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    _validate_type(data.canary_type)
    try:
        c = canary_service.create_canary(
            session,
            name=data.name,
            canary_type=data.canary_type,
            value=data.value,
            description=data.description,
            location=data.location,
            tags=data.tags,
            high_confidence=data.high_confidence,
            created_by_id=current_user.id,
        )
        return c.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=safe_error(e, "canary_create"))


@router.get("/{canary_id}", dependencies=[Depends(require_permission("alert:read"))])
def get_endpoint(canary_id: int, session: Session = Depends(get_db_session)):
    c = canary_service.get_canary(session, canary_id)
    if not c:
        raise HTTPException(status_code=404, detail="Canary not found")
    out = c.to_dict()
    out["recent_hits"] = canary_service.list_hits(session, canary_id=canary_id, limit=20)
    return out


@router.patch("/{canary_id}", dependencies=[Depends(require_permission("alert:triage"))])
def update_endpoint(
    canary_id: int,
    data: CanaryUpdate,
    session: Session = Depends(get_db_session),
):
    fields = data.model_dump(exclude_none=True)
    if "canary_type" in fields:
        _validate_type(fields["canary_type"])
    if "status" in fields:
        _validate_status(fields["status"])
    c = canary_service.update_canary(session, canary_id, **fields)
    if not c:
        raise HTTPException(status_code=404, detail="Canary not found")
    return c.to_dict()


@router.delete("/{canary_id}", dependencies=[Depends(require_permission("alert:triage"))])
def delete_endpoint(canary_id: int, session: Session = Depends(get_db_session)):
    if not canary_service.delete_canary(session, canary_id):
        raise HTTPException(status_code=404, detail="Canary not found")
    return {"ok": True}


@router.post("/scan", dependencies=[Depends(require_permission("alert:triage"))])
async def scan_endpoint(hours: int = 24, session: Session = Depends(get_db_session)):
    """Manually trigger a scan of recent ES alerts for canary mentions."""
    if hours < 1 or hours > 720:
        raise HTTPException(status_code=400, detail="hours must be between 1 and 720")
    try:
        return await canary_service.scan_recent_alerts(session, hours=hours)
    except Exception as e:
        raise HTTPException(status_code=500, detail=safe_error(e, "canary_scan"))
