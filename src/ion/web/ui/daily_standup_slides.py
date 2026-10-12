"""The standup presentation uses the same check payload as its JSON API."""
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from ion.auth.dependencies import require_permission
from ion.web.daily_standup_api import daily_checks_payload
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/daily-standup/slides", response_class=HTMLResponse,
            dependencies=[Depends(require_permission("alert:read"))])
async def slides(request: Request):
    data = None
    try:
        data = await daily_checks_payload()
        for section in ("critical_alerts", "stale_cases", "rule_failures"):
            block = data.get(section) or {}
            for key in ("alerts", "cases", "rules"):
                for row in block.get(key) or []:
                    for field in ("severity", "last_status"):
                        if field in row:
                            row[field] = plain(row[field])
    except Exception:
        logger.exception("Standup slide checks could not be read")
        data = None
    return templates.TemplateResponse(request=request, name="_fragments/daily_standup_slides.html",
                                      context={"data": data}, headers={"Cache-Control": "no-store"})
