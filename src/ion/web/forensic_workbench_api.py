"""ForensicCase Workbench REST API — pinned evidence + tamper-evident ledger (v0.20.1).

Mounted at /api/forensics in server.py (same prefix as forensics_router).
Route decorators use RELATIVE paths — the combined URL is:

  /api/forensics/cases/{id}/pins
  /api/forensics/cases/{id}/pins/{pin_id}
  /api/forensics/cases/{id}/ledger
  /api/forensics/cases/{id}/ledger/verify
  /api/forensics/cases/{case_id}/evidence/upload

Permission gate: ``forensic:read`` for GET, ``forensic:update`` for mutations,
``forensic:create`` for the upload. Matches existing forensics_api.py pattern.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_db_session, require_permission
from ion.core.safe_errors import safe_error
from ion.models.forensics import EvidenceType
from ion.models.user import User
from ion.services import forensic_ledger_service, forensic_pin_service
from ion.services.forensic_pin_service import (
    CaseNotFoundError,
    DuplicatePinError,
    PinError,
)
from ion.storage.forensic_repository import ForensicRepository

logger = logging.getLogger(__name__)

router = APIRouter(tags=["forensic-workbench"])

MAX_EVIDENCE_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class PinCreate(BaseModel):
    source_type: str = Field(..., description="alert | observable | es_event | note | file | host")
    source_ref: str = Field("", max_length=500)
    title: str = Field(..., min_length=1, max_length=500)
    summary: Optional[str] = None
    severity: Optional[str] = None
    mitre_techniques: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    metadata: Optional[dict[str, Any]] = None


class PinUpdate(BaseModel):
    finding_status: Optional[str] = None
    summary: Optional[str] = None
    severity: Optional[str] = None
    tags: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    title: Optional[str] = Field(None, max_length=500)


class PinDismiss(BaseModel):
    reason: Optional[str] = Field(None, max_length=500)


# ---------------------------------------------------------------------------
# Pin endpoints
# ---------------------------------------------------------------------------


@router.get("/cases/{case_id}/pins")
def list_pins_endpoint(
    case_id: int,
    include_dismissed: bool = False,
    user: User = Depends(require_permission("forensic:read")),
    session: Session = Depends(get_db_session),
):
    pins = forensic_pin_service.list_pins(
        session, case_id, include_dismissed=include_dismissed
    )
    return {"pins": [p.to_dict() for p in pins]}


@router.post("/cases/{case_id}/pins")
def create_pin_endpoint(
    case_id: int,
    body: PinCreate,
    user: User = Depends(require_permission("forensic:update")),
    session: Session = Depends(get_db_session),
):
    try:
        pin = forensic_pin_service.create_pin(
            session,
            forensic_case_id=case_id,
            source_type=body.source_type,
            source_ref=body.source_ref,
            title=body.title,
            summary=body.summary,
            severity=body.severity,
            mitre_techniques=body.mitre_techniques,
            tags=body.tags,
            metadata=body.metadata,
            actor_id=user.id,
        )
    except DuplicatePinError as exc:
        raise HTTPException(status_code=409, detail=safe_error(exc)) from exc
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=safe_error(exc)) from exc
    except PinError as exc:
        raise HTTPException(status_code=400, detail=safe_error(exc)) from exc
    return {"pin": pin.to_dict()}


@router.patch("/cases/{case_id}/pins/{pin_id}")
def update_pin_endpoint(
    case_id: int,
    pin_id: int,
    body: PinUpdate,
    user: User = Depends(require_permission("forensic:update")),
    session: Session = Depends(get_db_session),
):
    try:
        pin = forensic_pin_service.update_pin(
            session,
            pin_id,
            actor_id=user.id,
            finding_status=body.finding_status,
            summary=body.summary,
            severity=body.severity,
            tags=body.tags,
            mitre_techniques=body.mitre_techniques,
            title=body.title,
        )
    except PinError as exc:
        raise HTTPException(status_code=400, detail=safe_error(exc)) from exc
    if pin.forensic_case_id != case_id:
        raise HTTPException(status_code=404, detail="pin not in this case")
    return {"pin": pin.to_dict()}


@router.delete("/cases/{case_id}/pins/{pin_id}")
def dismiss_pin_endpoint(
    case_id: int,
    pin_id: int,
    body: PinDismiss = PinDismiss(),
    user: User = Depends(require_permission("forensic:update")),
    session: Session = Depends(get_db_session),
):
    try:
        pin = forensic_pin_service.dismiss_pin(
            session, pin_id, actor_id=user.id, reason=body.reason
        )
    except PinError as exc:
        raise HTTPException(status_code=400, detail=safe_error(exc)) from exc
    if pin.forensic_case_id != case_id:
        raise HTTPException(status_code=404, detail="pin not in this case")
    return {"pin": pin.to_dict()}


# ---------------------------------------------------------------------------
# Ledger endpoints
# ---------------------------------------------------------------------------


@router.get("/cases/{case_id}/ledger")
def list_ledger_endpoint(
    case_id: int,
    limit: int = 500,
    user: User = Depends(require_permission("forensic:read")),
    session: Session = Depends(get_db_session),
):
    safe_limit = max(1, min(int(limit or 500), 2000))
    return {
        "entries": forensic_ledger_service.list_entries(
            session, case_id, limit=safe_limit
        )
    }


@router.get("/cases/{case_id}/ledger/verify")
def verify_ledger_endpoint(
    case_id: int,
    user: User = Depends(require_permission("forensic:read")),
    session: Session = Depends(get_db_session),
):
    return forensic_ledger_service.verify_chain(session, case_id)


# ---------------------------------------------------------------------------
# Evidence file upload
# ---------------------------------------------------------------------------


@router.post("/cases/{case_id}/evidence/upload")
async def upload_evidence_file(
    case_id: int,
    file: UploadFile = File(...),
    user: User = Depends(require_permission("forensic:create")),
    session: Session = Depends(get_db_session),
):
    """Upload an evidence file (max 50 MB).

    Streams the upload via read_upload_capped (no OOM risk), computes sha256,
    creates an EvidenceItem row, and writes a ledger row: action='evidence_upload'.
    """
    from ion.core.uploads import read_upload_capped

    repo = ForensicRepository(session)
    case = repo.get_case_by_id(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Investigation not found")

    content = await read_upload_capped(file, MAX_EVIDENCE_FILE_SIZE)
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    sha256_hex = hashlib.sha256(content).hexdigest()
    filename = file.filename or "upload"

    evidence = repo.add_evidence(
        case,
        name=filename,
        evidence_type=EvidenceType.OTHER.value,
        collected_by_id=user.id,
        description=f"Uploaded via ION Workbench ({len(content)} bytes)",
        hash_sha256=sha256_hex,
        storage_location=None,
        metadata={"original_filename": filename, "size_bytes": len(content)},
    )
    session.flush()

    forensic_ledger_service.append(
        session,
        forensic_case_id=case_id,
        action="evidence_upload",
        payload={
            "evidence_id": evidence.id,
            "filename": filename,
            "size_bytes": len(content),
            "sha256": sha256_hex,
        },
        actor_id=user.id,
    )
    session.commit()

    return {
        "evidence": evidence.to_dict(),
        "sha256": sha256_hex,
        "size_bytes": len(content),
    }
