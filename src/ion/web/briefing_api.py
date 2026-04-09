"""Morning Threat Briefing API."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.core.safe_errors import safe_error
from ion.services import briefing_service
from ion.web.api import get_db_session

router = APIRouter(prefix="/briefing", tags=["briefing"])


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
async def briefing_endpoint(
    hours: int = Query(12, ge=1, le=168),
    ai: bool = Query(False, description="If true, ask Ollama for a narrative summary"),
    session: Session = Depends(get_db_session),
):
    """Compose the morning threat briefing."""
    try:
        return await briefing_service.build_briefing(session, hours=hours, ai=ai)
    except Exception as e:
        raise HTTPException(status_code=500, detail=safe_error(e, "morning_briefing"))
