"""Network threat-correlation report API.

Correlates network-linked cases → observables → OpenCTI enrichment (threat
actors / score / labels) → netmon pipeline, as JSON or standalone HTML.
Mirrors the executive-report endpoints. Gated ``case:read``.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_db_session, require_permission
from ion.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/network-correlation-report", tags=["network-correlation-report"])

_REPORT_SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


@router.get("/json")
def correlation_json(
    days: int = Query(7, ge=1, le=90),
    user: User = Depends(require_permission("case:read")),
    session: Session = Depends(get_db_session),
) -> Dict[str, Any]:
    """Correlation report as JSON."""
    from ion.services.network_correlation_report_service import (
        generate_network_correlation_report,
    )
    return generate_network_correlation_report(session, days=days)


@router.get("/html", response_class=HTMLResponse)
def correlation_html(
    days: int = Query(7, ge=1, le=90),
    user: User = Depends(require_permission("case:read")),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """Correlation report as standalone, CSP-safe HTML."""
    from ion.services.network_correlation_report_service import (
        generate_network_correlation_html,
        generate_network_correlation_report,
    )
    report = generate_network_correlation_report(session, days=days)
    return HTMLResponse(
        content=generate_network_correlation_html(report),
        headers=_REPORT_SECURITY_HEADERS,
    )
