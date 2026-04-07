"""Dashboard Widget Customization API."""

import logging
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission, get_current_user
from ion.models.user import User
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/dashboard-layout", tags=["dashboard-layout"])


class LayoutSave(BaseModel):
    widgets: list[dict]


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
def get_layout(current_user: User = Depends(get_current_user), session: Session = Depends(get_db_session)):
    from ion.services.dashboard_layout_service import get_layout
    roles = [r.name for r in current_user.roles] if hasattr(current_user, 'roles') else []
    return get_layout(session, current_user.id, user_roles=roles)


@router.post("", dependencies=[Depends(require_permission("alert:read"))])
def save_layout(data: LayoutSave, current_user: User = Depends(get_current_user), session: Session = Depends(get_db_session)):
    from ion.services.dashboard_layout_service import save_layout
    return save_layout(session, current_user.id, data.widgets)


@router.delete("", dependencies=[Depends(require_permission("alert:read"))])
def reset_layout(current_user: User = Depends(get_current_user), session: Session = Depends(get_db_session)):
    from ion.services.dashboard_layout_service import reset_layout
    return reset_layout(session, current_user.id)


@router.get("/widgets", dependencies=[Depends(require_permission("alert:read"))])
def list_widgets(current_user: User = Depends(get_current_user)):
    from ion.services.dashboard_layout_service import get_available_widgets
    roles = [r.name for r in current_user.roles] if hasattr(current_user, 'roles') else []
    return {"widgets": get_available_widgets(user_roles=roles)}
