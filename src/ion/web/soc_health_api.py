"""SOC Health Scorecard API."""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/soc-health", tags=["soc-health"])


@router.get(
    "/scorecard",
    dependencies=[Depends(require_permission("alert:read"))],
)
def get_scorecard(
    session: Session = Depends(get_db_session),
):
    """Get SOC health scorecard."""
    from ion.services.soc_health_service import get_soc_health_scorecard
    return get_soc_health_scorecard(session)
