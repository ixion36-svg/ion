"""Case grouper API — status card, manual run-now, HTML control panel.

Mounted at ``/api/case-grouper`` for JSON endpoints plus a top-level
``/case-grouper`` page. The router sets its own prefix; ``server.py``
should include it with ``prefix=""`` (same pattern as scheduler_api).

All endpoints require the ``alert:triage`` permission — triggering the
grouper attaches alerts to cases, which is a triage action.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_page_auth, require_permission
from ion.core.config import get_config
from ion.models.user import User
from ion.services.case_grouper_service import (
    count_auto_cases,
    get_last_run_info,
    run_grouper_once,
)
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["case-grouper"])

# Reuse the same templates dir — importing server.templates would loop.
_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=_TEMPLATES_DIR)


def _resolve_interval_s() -> int:
    """Environment takes precedence over the config file, matching the loop."""
    env_val = os.environ.get("ION_CASE_GROUPER_INTERVAL_S")
    if env_val:
        try:
            return int(env_val)
        except ValueError:
            pass
    try:
        return int(getattr(get_config(), "case_grouper_interval_s", 60))
    except Exception:
        return 60


def _resolve_window_minutes() -> int:
    env_val = os.environ.get("ION_CASE_GROUPER_WINDOW_MINUTES")
    if env_val:
        try:
            return int(env_val)
        except ValueError:
            pass
    try:
        return int(getattr(get_config(), "case_grouper_window_minutes", 15))
    except Exception:
        return 15


def _resolve_enabled() -> bool:
    env_val = os.environ.get("ION_CASE_GROUPER_ENABLED", "").lower()
    if env_val in ("false", "0", "no"):
        return False
    if env_val in ("true", "1", "yes"):
        return True
    try:
        return bool(getattr(get_config(), "case_grouper_enabled", True))
    except Exception:
        return True


# ---------------------------------------------------------------------------
# JSON endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/api/case-grouper/status",
    dependencies=[Depends(require_permission("alert:triage"))],
)
def status(session: Session = Depends(get_db_session)) -> Dict[str, Any]:
    """Summary card for the control panel.

    Returns the static config (enabled flag, interval, window), the
    last-run timestamp + summary dict, and a count of all auto-grouped
    cases currently in the DB.
    """
    last_at, last_result = get_last_run_info()
    return {
        "enabled": _resolve_enabled(),
        "interval_s": _resolve_interval_s(),
        "window_minutes": _resolve_window_minutes(),
        "push_to_kibana": os.environ.get(
            "ION_CASE_GROUPER_PUSH_TO_KIBANA", ""
        ).lower() not in ("false", "0", "no"),
        "auto_investigate": os.environ.get(
            "ION_CASE_GROUPER_AUTO_INVESTIGATE", ""
        ).lower() not in ("false", "0", "no"),
        "last_run_at": last_at.isoformat() if last_at else None,
        "last_result": last_result,
        "auto_cases_total": count_auto_cases(session),
    }


@router.post(
    "/api/case-grouper/run-now",
    dependencies=[Depends(require_permission("alert:triage"))],
)
def run_now(
    user: User = Depends(require_permission("alert:triage")),
    session: Session = Depends(get_db_session),
) -> Dict[str, Any]:
    """Trigger one synchronous grouping pass.

    This bypasses the background loop's advisory-lock protection on
    purpose — the user clicking the button explicitly asked for an
    immediate run. The underlying function is idempotent (it skips any
    alert already on a case) so concurrent runs are safe.
    """
    logger.info("Case grouper manual run requested by user=%s", user.username)
    summary = run_grouper_once(session)
    last_at, _ = get_last_run_info()
    return {
        "ok": True,
        "triggered_by": user.username,
        "last_run_at": last_at.isoformat() if last_at else None,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# HTML page
# ---------------------------------------------------------------------------


@router.get("/case-grouper", response_class=HTMLResponse)
async def case_grouper_page(
    request: Request,
    user: User = Depends(require_page_auth),
) -> HTMLResponse:
    """Render the case-grouper control panel."""
    return templates.TemplateResponse(
        request=request, name="case_grouper.html",
    )
