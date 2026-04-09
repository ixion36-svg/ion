"""Log Source Health Monitor API."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.core.safe_errors import safe_error
from ion.models.log_source import LogSourceCategory
from ion.models.user import User
from ion.services import log_source_service
from ion.web.api import get_db_session

router = APIRouter(prefix="/log-sources", tags=["log-sources"])


class LogSourceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    category: str
    description: Optional[str] = None
    query: dict
    index_pattern: Optional[str] = Field(None, max_length=255)
    expected_interval_minutes: int = Field(60, ge=1, le=10080)
    criticality: str = "medium"
    enabled: bool = True
    owner: Optional[str] = Field(None, max_length=120)
    tags: Optional[list[str]] = None


class LogSourceUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    category: Optional[str] = None
    description: Optional[str] = None
    query: Optional[dict] = None
    index_pattern: Optional[str] = Field(None, max_length=255)
    expected_interval_minutes: Optional[int] = Field(None, ge=1, le=10080)
    criticality: Optional[str] = None
    enabled: Optional[bool] = None
    owner: Optional[str] = Field(None, max_length=120)
    tags: Optional[list[str]] = None


def _validate_category(c: str) -> str:
    if c not in {v.value for v in LogSourceCategory}:
        raise HTTPException(status_code=400, detail=f"Invalid category: {c}")
    return c


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
def list_endpoint(session: Session = Depends(get_db_session)):
    return {"sources": log_source_service.list_sources(session)}


@router.get("/categories")
def categories_endpoint():
    return {
        "categories": [
            {"id": c.value, "label": c.value.title()} for c in LogSourceCategory
        ],
        "criticalities": [
            {"id": "critical", "label": "Critical"},
            {"id": "high", "label": "High"},
            {"id": "medium", "label": "Medium"},
            {"id": "low", "label": "Low"},
        ],
    }


@router.get("/health", dependencies=[Depends(require_permission("alert:read"))])
async def health_endpoint(session: Session = Depends(get_db_session)):
    """Run a live ES check across every enabled source and return per-source health."""
    try:
        return await log_source_service.check_all(session)
    except Exception as e:
        raise HTTPException(status_code=500, detail=safe_error(e, "log_source_health"))


@router.post("/seed-defaults", dependencies=[Depends(require_permission("integration:manage"))])
def seed_endpoint(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Populate the table with a starter set of common log sources."""
    added = log_source_service.seed_defaults(session, current_user.id)
    return {"added": added}


@router.post("", dependencies=[Depends(require_permission("integration:manage"))])
def create_endpoint(
    data: LogSourceCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    _validate_category(data.category)
    try:
        ls = log_source_service.create_source(
            session,
            name=data.name,
            category=data.category,
            description=data.description,
            query=data.query,
            index_pattern=data.index_pattern,
            expected_interval_minutes=data.expected_interval_minutes,
            criticality=data.criticality,
            enabled=data.enabled,
            owner=data.owner,
            tags=data.tags,
            created_by_id=current_user.id,
        )
        return ls.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=safe_error(e, "log_source_create"))


@router.get("/{source_id}", dependencies=[Depends(require_permission("alert:read"))])
def get_endpoint(source_id: int, session: Session = Depends(get_db_session)):
    ls = log_source_service.get_source(session, source_id)
    if not ls:
        raise HTTPException(status_code=404, detail="Log source not found")
    return ls.to_dict()


@router.patch("/{source_id}", dependencies=[Depends(require_permission("integration:manage"))])
def update_endpoint(
    source_id: int,
    data: LogSourceUpdate,
    session: Session = Depends(get_db_session),
):
    fields = data.model_dump(exclude_none=True)
    if "category" in fields:
        _validate_category(fields["category"])
    ls = log_source_service.update_source(session, source_id, **fields)
    if not ls:
        raise HTTPException(status_code=404, detail="Log source not found")
    return ls.to_dict()


@router.delete("/{source_id}", dependencies=[Depends(require_permission("integration:manage"))])
def delete_endpoint(source_id: int, session: Session = Depends(get_db_session)):
    if not log_source_service.delete_source(session, source_id):
        raise HTTPException(status_code=404, detail="Log source not found")
    return {"ok": True}
