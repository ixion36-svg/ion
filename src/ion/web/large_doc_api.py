"""AI Document Analysis API + page — chunked map-reduce of a large PDF through
the internal LLM (Bob). Gated by ``ION_AI_LARGE_PDF_ENABLED`` (default off).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_page_auth, require_permission
from ion.models.user import User
from ion.services import large_doc_service as lds
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["document-analysis"])

from ion.web.templating import make_templates  # noqa: E402

_templates = make_templates()

_PERM = "ai:chat"


@router.get("/api/document-analysis/status", dependencies=[Depends(require_permission(_PERM))])
def analysis_status(session: Session = Depends(get_db_session)):
    return lds.status(session)


@router.post("/api/document-analysis", dependencies=[Depends(require_permission(_PERM))])
async def start_document_analysis(
    file: UploadFile = File(...),
    task: str = Form("checklist"),
    custom_prompt: str = Form(""),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    if not lds.is_enabled():
        raise HTTPException(
            status_code=503,
            detail="Large-PDF AI analysis is disabled. Set ION_AI_LARGE_PDF_ENABLED=true to enable it.",
        )
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")
    try:
        job_id = lds.start_analysis(
            session, current_user.id, file.filename or "document", content, task, custom_prompt or None
        )
    except ValueError as exc:
        code = 409 if "already running" in str(exc).lower() else 400
        raise HTTPException(status_code=code, detail=str(exc))
    return {"job_id": job_id}


@router.get("/api/document-analysis/jobs/{job_id}", dependencies=[Depends(require_permission(_PERM))])
def get_analysis_job(job_id: str, session: Session = Depends(get_db_session)):
    job = lds.get_job(session, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/document-analysis", response_class=HTMLResponse)
def document_analysis_page(request: Request, _user: User = Depends(require_page_auth)):
    return _templates.TemplateResponse(request=request, name="document_analysis.html")
