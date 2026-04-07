"""Saved Searches / Personal Workspace API."""

import logging
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission, get_current_user
from ion.models.user import User
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/saved-searches", tags=["saved-searches"])


class SearchCreate(BaseModel):
    name: str
    search_type: str
    query: str
    is_pinned: bool = False


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
def list_searches(
    search_type: str = Query(None),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    from ion.services.saved_search_service import get_saved_searches
    return {"searches": get_saved_searches(session, current_user.id, search_type=search_type)}


@router.post("", dependencies=[Depends(require_permission("alert:read"))])
def create_search(
    data: SearchCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    from ion.services.saved_search_service import create_saved_search
    return create_saved_search(
        session, user_id=current_user.id, name=data.name,
        search_type=data.search_type, query=data.query, is_pinned=data.is_pinned,
    )


@router.delete("/{search_id}", dependencies=[Depends(require_permission("alert:read"))])
def delete_search(
    search_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    from ion.services.saved_search_service import delete_saved_search
    if not delete_saved_search(session, search_id, current_user.id):
        raise HTTPException(status_code=404, detail="Search not found")
    return {"ok": True}


@router.post("/{search_id}/pin", dependencies=[Depends(require_permission("alert:read"))])
def toggle_pin(
    search_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    from ion.services.saved_search_service import toggle_pin
    result = toggle_pin(session, search_id, current_user.id)
    if not result:
        raise HTTPException(status_code=404, detail="Search not found")
    return result


@router.post("/{search_id}/use", dependencies=[Depends(require_permission("alert:read"))])
def use_search(
    search_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    from ion.services.saved_search_service import record_use
    record_use(session, search_id, current_user.id)
    return {"ok": True}
