"""Rule Tuning Feedback Loop API — identifies FP-heavy, high-value, and silent rules."""

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.services.rule_tuning_service import get_rule_tuning_analysis
from ion.services.tide_service import get_tide_service
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/rule-tuning", tags=["rule-tuning"])


@router.get(
    "/analysis",
    dependencies=[Depends(require_permission("alert:read"))],
)
def get_rule_analysis(
    hours: int = Query(168, ge=24, le=720, description="Lookback window in hours"),
    session: Session = Depends(get_db_session),
):
    """Generate rule tuning analysis cross-referencing TIDE rules with case closure outcomes."""
    tide_svc = get_tide_service()
    return get_rule_tuning_analysis(session, tide_svc, es_service=None, hours=hours)
