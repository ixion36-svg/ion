"""Playbook Effectiveness Analytics API."""

import logging
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/playbook-analytics", tags=["playbook-analytics"])


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
def get_playbook_analytics(session: Session = Depends(get_db_session)):
    """Get playbook effectiveness analytics."""
    from ion.services.playbook_analytics_service import get_playbook_analytics
    return get_playbook_analytics(session)
