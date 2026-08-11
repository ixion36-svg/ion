"""Wallboard dashboard API + page (v0.14.0).

The wallboard is a single page intended for full-screen wall display.
Pulls from all aspects of ION (alerts, cases, Bob, detection, CYAB,
curriculum, ticker, service health) via the cached
``wallboard_service.get_snapshot()`` and renders one big multi-panel
layout that auto-refreshes every 5 minutes client-side.

Routes:

- ``GET /wallboard``                 — the wallboard page (HTML)
- ``GET /api/wallboard/snapshot``    — the JSON snapshot (cached 5 min)
- ``POST /api/wallboard/refresh``    — force-recompute the snapshot
                                        (admin / cron use)
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import (
    get_current_user,
    require_page_permission,
    require_permission,
)
from ion.models.user import User
from ion.services.wallboard_service import get_snapshot
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter()

from ion.web.templating import make_templates  # noqa: E402

_templates = make_templates()


@router.get("/wallboard", response_class=HTMLResponse)
def wallboard_page(
    request: Request,
    _user: User = Depends(require_page_permission("alert:read")),
):
    """Render the wallboard. The HTML page hydrates from the JSON API."""
    return _templates.TemplateResponse(
        request=request, name="wallboard.html",
    )


# gated on alert:read to match the wallboard page route. The
# JSON endpoints previously only required get_current_user, so a user
# whose role had been revoked (but session still valid) could still
# pull the wall data via the API.
@router.get("/api/wallboard/snapshot",
            dependencies=[Depends(require_permission("alert:read"))])
def wallboard_snapshot(
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Return the cached snapshot (recomputed at most once per 5 min)."""
    return get_snapshot(session)


@router.post("/api/wallboard/refresh",
             dependencies=[Depends(require_permission("alert:read"))])
def wallboard_refresh(
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Force-recompute the snapshot. Useful for admin triggers / a cron job."""
    return get_snapshot(session, force=True)
