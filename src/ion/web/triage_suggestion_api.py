"""Triage Suggestion API — historical data-driven triage recommendations."""

import logging
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/triage-suggestions", tags=["triage-suggestions"])


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
def get_suggestion(
    rule_name: str = Query(..., min_length=1),
    host: str = Query(None),
    severity: str = Query(None),
    session: Session = Depends(get_db_session),
):
    """Get triage suggestion for a rule/host combination."""
    from ion.services.triage_suggestion_service import get_triage_suggestion
    return get_triage_suggestion(session, rule_name=rule_name, host=host, severity=severity)
