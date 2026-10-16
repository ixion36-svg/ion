"""The service-accounts risk summary and account table, as one fragment."""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()


def _systems_display(raw: object, limit: int = 3) -> str:
    """The first few system names from a JSON-encoded list.

    `systems` is stored as a JSON string. The JavaScript this replaces did
    `JSON.parse(a.systems||'[]').slice(0,3).join(', ')` inside a try/catch
    that fell back to the raw string, so a row with malformed JSON showed
    the raw value rather than breaking the table. Same behaviour here: a
    value that will not parse is shown as-is, because a visible oddity beats
    a blank cell that looks like "no systems".
    """
    if not raw:
        return ""
    if isinstance(raw, (list, tuple)):
        return ", ".join(str(x) for x in list(raw)[:limit])
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return str(raw)
    if isinstance(parsed, (list, tuple)):
        return ", ".join(str(x) for x in list(parsed)[:limit])
    return str(parsed)


@router.get(
    "/service-accounts",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("alert:read"))],
)
def service_accounts_fragment(
    request: Request,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The risk summary and the account table, as one fragment.

    service_accounts.html used to fetch /api/service-accounts and
    /api/service-accounts/risk-summary in parallel and build both with
    innerHTML, 55 lines of string concatenation including a hand-rolled
    `esc()`. One request renders both here, and Jinja escapes.
    """
    from ion.services.service_account_service import (
        get_account_risk_summary,
        get_service_accounts,
    )

    try:
        accounts = [dict(a) for a in get_service_accounts(session)]
        summary = get_account_risk_summary(session)
        for a in accounts:
            a["systems_display"] = _systems_display(a.get("systems"))
    except Exception:
        logger.exception("Service account fragment could not be rendered")
        # A failed read is not an empty estate. The fragment says which it
        # is, because "no service accounts" and "we could not look" lead to
        # opposite actions.
        return templates.TemplateResponse(
            request=request,
            name="_fragments/service_accounts.html",
            context={"accounts": None, "summary": None, "failed": True},
            status_code=200,
        )

    return templates.TemplateResponse(
        request=request,
        name="_fragments/service_accounts.html",
        context={"accounts": accounts, "summary": summary, "failed": False},
    )
