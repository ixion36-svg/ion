"""PCAP file upload and analysis API."""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.core.safe_errors import safe_error
from ion.models.user import User
from ion.storage.database import get_db_session

# Shared with the Arkime auto-case pipeline (pcap_analysis_service) — the
# canonical implementations live in services.pcap_enrichment_service.
from ion.services.pcap_enrichment_service import (
    enrich_pcap_observables as _enrich_pcap_observables,
)
from ion.services.pcap_enrichment_service import (
    ti_findings as _ti_findings,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["pcap"])

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


@router.post("/analyze")
async def analyze_pcap(
    file: UploadFile = File(...),
    user: User = Depends(require_permission("alert:read")),
):
    """Upload and analyze a PCAP file, then enrich external IPs/domains."""
    # Validate extension
    filename = file.filename or "upload.pcap"
    ext = ""
    for e in ALLOWED_EXTENSIONS:
        if filename.lower().endswith(e):
            ext = e
            break
    if not ext:
        raise HTTPException(400, f"Unsupported file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}")

    # Read file content.
    # was `await file.read()` followed by a post-hoc size
    # check, which buffered the entire upload (potentially multi-GB)
    # into memory before the 100 MB cap was evaluated. Stream-read
    # with a running cap so oversize uploads are rejected before the
    # allocation completes — returns 413 instead of 400 to match
    # standard semantics.
    from ion.core.uploads import read_upload_capped
    content = await read_upload_capped(file, MAX_FILE_SIZE)
    if len(content) == 0:
        raise HTTPException(400, "Empty file")

    # Parse
    try:
        from ion.services.pcap_service import _is_private, parse_pcap
        result = parse_pcap(content, filename)
    except ValueError as e:
        # Validation errors carry user-meaningful messages — return a class label.
        raise HTTPException(400, f"Invalid PCAP: {safe_error(e, 'pcap_parse')}")
    except Exception as e:
        raise HTTPException(500, f"Analysis failed: {safe_error(e, 'pcap_parse')}")

    response = result.to_dict()

    # Extract and enrich observables (non-blocking — failures don't break the response)
    try:
        enrichments = await _enrich_pcap_observables(result, _is_private)
        if enrichments:
            response["threat_intel"] = enrichments
            # Escalate: any pcap observable that threat intel flags as known-bad
            # becomes a finding, and the verdict is recomputed to reflect it.
            _apply_ti_findings(response, enrichments)
    except Exception as e:
        response["threat_intel"] = {"error": safe_error(e, "pcap_enrich"), "observables": []}

    return response


def _apply_ti_findings(response: dict, enrichments: dict) -> None:
    """Append TI-match findings and recompute the verdict to fold in IOC hits."""
    ti = _ti_findings(enrichments)
    if not ti:
        return
    response["findings"] = (response.get("findings") or []) + ti
    try:
        from ion.services.pcap_service import Finding, _attach_mitre, _build_mitre_summary, _compute_verdict
        fobjs = [Finding(category=f["category"], severity=f["severity"],
                         title=f.get("title", ""), detail=f.get("detail", ""),
                         mitre=f.get("mitre") or []) for f in response["findings"]]
        _attach_mitre(fobjs)
        response["verdict"] = _compute_verdict(fobjs)
        response["mitre_techniques"] = _build_mitre_summary(fobjs)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Durable jobs (review 2026-10-08 §13)
#
# /analyze above stays as the immediate, stateless parse. These endpoints
# record the analysis as a job, so a capture that took forty seconds to
# parse can be looked at again without re-uploading, two analysts can see
# each other's work, and a finding can reach the case without retyping.
# ---------------------------------------------------------------------------


@router.post("/jobs")
async def create_pcap_job(
    file: UploadFile = File(...),
    case_id: Optional[int] = Form(None),
    reuse: bool = Form(True),
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Upload a capture as a durable job and parse it.

    An identical capture already parsed by this parser version is served
    from the stored result rather than parsed again, and the response says
    which job it came from.
    """
    from ion.core.uploads import read_upload_capped
    from ion.services import pcap_job_service as pcap_jobs

    filename = file.filename or "upload.pcap"
    content = await read_upload_capped(file, MAX_FILE_SIZE)

    try:
        job = pcap_jobs.create_job(
            session,
            filename=filename,
            content=content,
            requested_by_id=user.id,
            case_id=case_id,
            reuse=reuse,
        )
    except pcap_jobs.PcapJobError as exc:
        raise HTTPException(400, str(exc)) from exc

    if job.status == "queued":
        from ion.services.pcap_service import parse_pcap

        def _parse(raw: bytes, name: str) -> dict:
            return parse_pcap(raw, name).to_dict()

        job = pcap_jobs.run_job(
            session, job_id=job.id, parse=_parse, content=content,
        )

    return {"job": job.to_dict()}


@router.get("/jobs")
def list_pcap_jobs(
    case_id: Optional[int] = None,
    limit: int = 50,
    _user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Analysis history, newest first, without the bulky parse results."""
    from ion.services import pcap_job_service as pcap_jobs

    return {
        "jobs": pcap_jobs.list_jobs(
            session, case_id=case_id, limit=max(1, min(limit, 200)),
        )
    }


@router.get("/jobs/{job_id}")
def get_pcap_job(
    job_id: int,
    _user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """One analysis with its stored result, reusable without re-uploading."""
    from ion.services import pcap_job_service as pcap_jobs

    try:
        return pcap_jobs.get_job(session, job_id)
    except pcap_jobs.PcapJobError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.post("/jobs/{job_id}/cancel")
def cancel_pcap_job(
    job_id: int,
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Ask a running analysis to stop.

    This records the request; the status becomes `cancelled` only when the
    runner actually notices, because until then the parse may still be going.
    """
    from ion.services import pcap_job_service as pcap_jobs

    try:
        job = pcap_jobs.request_cancel(session, job_id=job_id, actor_id=user.id)
    except pcap_jobs.PcapJobError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"job": job.summary()}


class PcapAttachRequest(BaseModel):
    case_id: int
    finding_indexes: List[int] = Field(..., min_length=1)


@router.post("/jobs/{job_id}/attach")
def attach_pcap_findings(
    job_id: int,
    body: PcapAttachRequest,
    user: User = Depends(require_permission("case:update")),
    session: Session = Depends(get_db_session),
):
    """Pin selected findings to a case, with their evidential basis.

    Writes to the case and its evidence ledger, so this takes case:update
    rather than the alert:read the rest of the PCAP surface uses.
    """
    from ion.services import pcap_job_service as pcap_jobs
    from ion.services.case_pin_service import CaseNotFoundError, PinError

    try:
        pins = pcap_jobs.attach_findings_to_case(
            session,
            job_id=job_id,
            case_id=body.case_id,
            finding_indexes=body.finding_indexes,
            actor_id=user.id,
        )
    except CaseNotFoundError as exc:
        raise HTTPException(404, safe_error(exc)) from exc
    except (pcap_jobs.PcapJobError, PinError) as exc:
        raise HTTPException(400, safe_error(exc)) from exc

    return {
        "attached": [p.to_dict() for p in pins],
        "attached_count": len(pins),
        # Zero created with no error means every selected finding was
        # already on the case, which is the desired end state, not a failure.
        "already_attached": len(body.finding_indexes) - len(pins),
    }
