"""Executive Weekly Report API — PDF/HTML/JSON."""

import logging
from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/executive-report", tags=["executive-report"])


@router.get("/json", dependencies=[Depends(require_permission("alert:read"))])
def get_executive_json(
    days: int = Query(7, ge=1, le=90),
    session: Session = Depends(get_db_session),
):
    """Get executive report as JSON."""
    from ion.services.executive_report_service import generate_executive_report
    return generate_executive_report(session, days=days)


@router.get("/html", response_class=HTMLResponse, dependencies=[Depends(require_permission("alert:read"))])
def get_executive_html(
    days: int = Query(7, ge=1, le=90),
    session: Session = Depends(get_db_session),
):
    """Get executive report as standalone HTML."""
    from ion.services.executive_report_service import generate_executive_report, generate_executive_html
    report = generate_executive_report(session, days=days)
    return HTMLResponse(content=generate_executive_html(report))


@router.get("/pdf", dependencies=[Depends(require_permission("alert:read"))])
def get_executive_pdf(
    days: int = Query(7, ge=1, le=90),
    session: Session = Depends(get_db_session),
):
    """Get executive report as PDF (Docker only — WeasyPrint required)."""
    from ion.services.executive_report_service import generate_executive_report, generate_executive_pdf, generate_executive_html
    report = generate_executive_report(session, days=days)
    pdf_bytes = generate_executive_pdf(report)
    if pdf_bytes:
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="ion_executive_report.pdf"'},
        )
    return HTMLResponse(content=generate_executive_html(report))
