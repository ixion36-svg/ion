"""Investigation memory API endpoints.

Exposes the investigation / IOC-sighting / FP-signature store over
HTTP. All endpoints require the ``alert:read`` permission (ION's
canonical name — the spec said ``alerts:read`` but the rest of the
codebase uses the singular form, so we follow the existing convention).
If finer-grained permissions land later, swap the dependency on the
mutating routes.

The HTML page lives at ``/investigations`` and is rendered via
Jinja2 from ``web/templates/investigation_memory.html``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import (
    get_db_session,
    require_page_auth,
    require_permission,
)
from ion.models.investigation import (
    FalsePositiveSignature,
    Investigation,
    IOCSighting,
)
from ion.models.user import User
from ion.services import knowledge_review_service as knowledge_review
from ion.storage import investigation_memory_repository as repo

logger = logging.getLogger(__name__)

router = APIRouter(tags=["investigation-memory"])

# Shared Jinja env from the factory (bytecode cache + ion_version + csp_nonce);
# importing server.templates would create a circular import.
from ion.web.templating import make_templates  # noqa: E402

templates = make_templates()


# =========================================================================
# Response schemas
# =========================================================================

class InvestigationSummary(BaseModel):
    id: int
    alert_id_ref: str
    alert_signature: str
    host: Optional[str] = None
    source_ip: Optional[str] = None
    user_name: Optional[str] = None
    status: str
    verdict: Optional[str] = None
    severity_assessment: Optional[str] = None
    llm_model_used: Optional[str] = None
    tokens_used: Optional[int] = None
    duration_ms: Optional[int] = None
    created_at: Optional[str] = None
    completed_at: Optional[str] = None


class InvestigationDetail(InvestigationSummary):
    summary_text: Optional[str] = None
    recommended_actions: Optional[Any] = None
    ioc_snapshot: Optional[Any] = None
    prompt_template_id: Optional[int] = None
    created_by: Optional[int] = None
    # grounded evidence — list of {field, value, significance}
    key_observations: Optional[Any] = None
    # prompt + raw response snapshots for training-loop debugging.
    # Admin-only callers include these; standard callers get them elided.
    prompt_snapshot: Optional[str] = None
    raw_response: Optional[str] = None


class IOCSightingResponse(BaseModel):
    id: int
    ioc_type: str
    ioc_value: str
    seen_count: int
    first_seen_at: Optional[str] = None
    last_seen_at: Optional[str] = None
    last_investigation_id: Optional[int] = None
    is_known_bad: Optional[bool] = None
    is_known_good: Optional[bool] = None
    notes: Optional[str] = None
    reputation: Optional[Any] = None


class FPSignatureResponse(BaseModel):
    id: int
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    alert_signature: Optional[str] = None
    host_pattern: Optional[str] = None
    user_pattern: Optional[str] = None
    reason: str
    confidence: int
    recorded_by: Optional[int] = None
    recorded_at: Optional[str] = None
    hit_count: int
    last_matched_at: Optional[str] = None
    enabled: bool
    # Governance (review 2026-10-08 s8). `governance_state` is the one word
    # a caller should render; the rest is there to explain it.
    review_date: Optional[str] = None
    expired: bool = False
    governance_state: str = "ungoverned"
    verified_by_id: Optional[int] = None
    verified_at: Optional[str] = None
    verification_note: Optional[str] = None


class FPSignatureCreate(BaseModel):
    reason: str = Field(..., min_length=1, max_length=4000)
    confidence: int = Field(80, ge=0, le=100)
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    alert_signature: Optional[str] = None
    host_pattern: Optional[str] = None
    user_pattern: Optional[str] = None
    # Omitted means the default review window, not "never review".
    review_date: Optional[str] = Field(None, description="ISO-8601 review date")


def _parse_review_date(raw: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 review date, accepting the trailing Z browsers send."""
    if raw is None or not str(raw).strip():
        return None
    text = str(raw).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail="review_date is not a valid ISO-8601 date"
        ) from exc


# =========================================================================
# Converters
# =========================================================================

def _iso(v: Optional[datetime]) -> Optional[str]:
    return v.isoformat() if v else None


def _maybe_json(raw: Optional[str]) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw  # fall back to the raw string


def _inv_to_summary(inv: Investigation) -> InvestigationSummary:
    return InvestigationSummary(
        id=inv.id,
        alert_id_ref=inv.alert_id_ref,
        alert_signature=inv.alert_signature,
        host=inv.host,
        source_ip=inv.source_ip,
        user_name=inv.user_name,
        status=inv.status,
        verdict=inv.verdict,
        severity_assessment=inv.severity_assessment,
        llm_model_used=inv.llm_model_used,
        tokens_used=inv.tokens_used,
        duration_ms=inv.duration_ms,
        created_at=_iso(inv.created_at),
        completed_at=_iso(inv.completed_at),
    )


def _inv_to_detail(inv: Investigation) -> InvestigationDetail:
    base = _inv_to_summary(inv).model_dump()
    base.update(
        summary_text=inv.summary_text,
        recommended_actions=_maybe_json(inv.recommended_actions_json),
        ioc_snapshot=_maybe_json(inv.ioc_snapshot_json),
        prompt_template_id=inv.prompt_template_id,
        created_by=inv.created_by,
        key_observations=_maybe_json(inv.key_observations_json),
        prompt_snapshot=inv.prompt_snapshot,
        raw_response=inv.raw_response,
    )
    return InvestigationDetail(**base)


def _ioc_to_response(s: IOCSighting) -> IOCSightingResponse:
    return IOCSightingResponse(
        id=s.id,
        ioc_type=s.ioc_type,
        ioc_value=s.ioc_value,
        seen_count=s.seen_count,
        first_seen_at=_iso(s.first_seen_at),
        last_seen_at=_iso(s.last_seen_at),
        last_investigation_id=s.last_investigation_id,
        is_known_bad=s.is_known_bad,
        is_known_good=s.is_known_good,
        notes=s.notes,
        reputation=_maybe_json(s.reputation_snapshot_json),
    )


def _fp_to_response(fp: FalsePositiveSignature) -> FPSignatureResponse:
    return FPSignatureResponse(
        id=fp.id,
        rule_id=fp.rule_id,
        rule_name=fp.rule_name,
        alert_signature=fp.alert_signature,
        host_pattern=fp.host_pattern,
        user_pattern=fp.user_pattern,
        reason=fp.reason,
        confidence=fp.confidence,
        recorded_by=fp.recorded_by,
        recorded_at=_iso(fp.recorded_at),
        hit_count=fp.hit_count,
        last_matched_at=_iso(fp.last_matched_at),
        enabled=fp.enabled,
        review_date=_iso(fp.review_date),
        expired=fp.is_expired(),
        governance_state=fp.governance_state(),
        verified_by_id=fp.verified_by_id,
        verified_at=_iso(fp.verified_at),
        verification_note=fp.verification_note,
    )


# =========================================================================
# Investigations
# =========================================================================

@router.get("/api/investigations")
def list_investigations_endpoint(
    verdict: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    alert_signature: Optional[str] = Query(None),
    host: Optional[str] = Query(None),
    from_date: Optional[str] = Query(None, description="ISO8601 lower bound"),
    to_date: Optional[str] = Query(None, description="ISO8601 upper bound"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db_session),
    user: User = Depends(require_permission("alert:read")),
) -> dict:
    """List investigations with optional filters."""
    filters = {
        "verdict": verdict,
        "status": status,
        "alert_signature": alert_signature,
        "host": host,
        "from_date": from_date,
        "to_date": to_date,
    }
    rows = repo.list_investigations(filters, db, limit=limit, offset=offset)
    return {
        "investigations": [_inv_to_summary(r).model_dump() for r in rows],
        "limit": limit,
        "offset": offset,
        "count": len(rows),
    }


@router.get("/api/investigations/{inv_id}")
def get_investigation_endpoint(
    inv_id: int,
    db: Session = Depends(get_db_session),
    user: User = Depends(require_permission("alert:read")),
) -> InvestigationDetail:
    """Get a single investigation's full record."""
    inv = repo.get_investigation(inv_id, db)
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return _inv_to_detail(inv)


# =========================================================================
# IOC Sightings
# =========================================================================

@router.get("/api/iocs")
def list_iocs_endpoint(
    ioc_type: Optional[str] = Query(None),
    is_known_bad: Optional[bool] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db_session),
    user: User = Depends(require_permission("alert:read")),
) -> dict:
    """List IOC sightings with optional filters."""
    rows = repo.list_ioc_sightings(
        db,
        ioc_type=ioc_type,
        is_known_bad=is_known_bad,
        limit=limit,
        offset=offset,
    )
    return {
        "iocs": [_ioc_to_response(r).model_dump() for r in rows],
        "limit": limit,
        "offset": offset,
        "count": len(rows),
    }


@router.get("/api/iocs/{ioc_type}/{value:path}")
def get_ioc_endpoint(
    ioc_type: str,
    value: str,
    db: Session = Depends(get_db_session),
    user: User = Depends(require_permission("alert:read")),
) -> IOCSightingResponse:
    """Look up a single IOC sighting by type + value."""
    sighting = repo.lookup_ioc_history(ioc_type, value, db)
    if sighting is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    return _ioc_to_response(sighting)


# =========================================================================
# False Positive Signatures
# =========================================================================

@router.get("/api/fps")
def list_fps_endpoint(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db_session),
    user: User = Depends(require_permission("alert:read")),
) -> dict:
    """List FP signatures."""
    rows = repo.list_fps(db, limit=limit, offset=offset)
    return {
        "fps": [_fp_to_response(r).model_dump() for r in rows],
        "limit": limit,
        "offset": offset,
        "count": len(rows),
    }


@router.post("/api/fps", status_code=201)
def create_fp_endpoint(
    data: FPSignatureCreate,
    db: Session = Depends(get_db_session),
    user: User = Depends(require_permission("alert:read")),
) -> FPSignatureResponse:
    """Create a new FP signature.

    Requires at least one match key (rule_id / rule_name /
    alert_signature) otherwise the signature would match nothing.
    """
    if not (data.rule_id or data.rule_name or data.alert_signature):
        raise HTTPException(
            status_code=400,
            detail="Supply at least one of rule_id, rule_name, or alert_signature",
        )
    try:
        fp = repo.record_fp(
            db=db,
            reason=data.reason,
            confidence=data.confidence,
            recorded_by=user.id,
            rule_id=data.rule_id,
            rule_name=data.rule_name,
            alert_signature=data.alert_signature,
            host_pattern=data.host_pattern,
            user_pattern=data.user_pattern,
            review_date=_parse_review_date(data.review_date),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    return _fp_to_response(fp)


@router.delete("/api/fps/{fp_id}")
def delete_fp_endpoint(
    fp_id: int,
    db: Session = Depends(get_db_session),
    user: User = Depends(require_permission("alert:read")),
) -> dict:
    """Delete an FP signature."""
    if not repo.delete_fp(fp_id, db):
        raise HTTPException(status_code=404, detail="FP signature not found")
    db.commit()
    return {"deleted": True, "id": fp_id}


@router.patch("/api/fps/{fp_id}/toggle")
def toggle_fp_endpoint(
    fp_id: int,
    db: Session = Depends(get_db_session),
    user: User = Depends(require_permission("alert:read")),
) -> FPSignatureResponse:
    """Flip ``enabled`` on an FP signature."""
    fp = repo.toggle_fp(fp_id, db)
    if fp is None:
        raise HTTPException(status_code=404, detail="FP signature not found")
    db.commit()
    return _fp_to_response(fp)


class FPVerify(BaseModel):
    note: Optional[str] = Field(None, max_length=2000)


class FPReview(BaseModel):
    extend_days: int = Field(repo.FP_DEFAULT_REVIEW_DAYS, ge=1, le=3650)
    note: Optional[str] = Field(None, max_length=2000)


@router.get("/api/fps/needing-review")
def fps_needing_review_endpoint(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db_session),
    user: User = Depends(require_permission("alert:read")),
) -> dict:
    """FP signatures that need a human decision, worst first.

    Lapsed ones come before ungoverned, then unverified, then merely due
    soon: the first group has already stopped suppressing anything, so it is
    the group whose absence is changing what analysts see today.
    """
    rows = repo.list_fps_needing_review(db, limit=limit)
    return {"fps": rows, "count": len(rows)}


@router.post("/api/fps/{fp_id}/verify")
def verify_fp_endpoint(
    fp_id: int,
    data: FPVerify,
    db: Session = Depends(get_db_session),
    user: User = Depends(require_permission("alert:read")),
) -> FPSignatureResponse:
    """Record a second person's verification of an FP signature.

    Refused for the person who recorded it. That is a separation-of-duty
    check, not a permission check: holding the right permission does not
    make you a second pair of eyes.
    """
    try:
        fp = repo.verify_fp(db, fp_id, actor_id=user.id, note=data.note)
    except ValueError as exc:
        # "not found" and "cannot verify your own" are both ValueError from
        # the repo; the text distinguishes them for the caller.
        status = 404 if "not found" in str(exc) else 400
        raise HTTPException(status_code=status, detail=str(exc)) from exc
    db.commit()
    db.refresh(fp)
    return _fp_to_response(fp)


@router.post("/api/fps/{fp_id}/review")
def review_fp_endpoint(
    fp_id: int,
    data: FPReview,
    db: Session = Depends(get_db_session),
    user: User = Depends(require_permission("alert:read")),
) -> FPSignatureResponse:
    """Confirm a signature is still true and push its review date out.

    Measured from now, so reviewing a long-lapsed signature actually brings
    it back into date instead of leaving it lapsed.
    """
    try:
        fp = repo.review_fp(
            db, fp_id, actor_id=user.id,
            extend_days=data.extend_days, note=data.note,
        )
    except ValueError as exc:
        status = 404 if "not found" in str(exc) else 400
        raise HTTPException(status_code=status, detail=str(exc)) from exc
    db.commit()
    db.refresh(fp)
    return _fp_to_response(fp)


# =========================================================================
# Knowledge review inbox (review 2026-10-08 §8)
#
# Four kinds of decaying knowledge that nothing was surfacing as work:
# lapsed quirks, stale FP signatures, the same alert closed two different
# ways, and prompts Bob keeps abstaining on.
# =========================================================================

@router.get("/api/knowledge-review/summary")
def knowledge_review_summary_endpoint(
    window_days: int = Query(
        knowledge_review.DEFAULT_WINDOW_DAYS, ge=1, le=730),
    db: Session = Depends(get_db_session),
    user: User = Depends(require_permission("alert:read")),
) -> dict:
    """Counts only, for a dashboard tile. No item bodies."""
    return knowledge_review.review_summary(db, window_days=window_days)


@router.get("/api/knowledge-review")
def knowledge_review_endpoint(
    kind: Optional[str] = Query(
        None, description="Restrict to one kind; omit for all"),
    window_days: int = Query(
        knowledge_review.DEFAULT_WINDOW_DAYS, ge=1, le=730),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db_session),
    user: User = Depends(require_permission("alert:read")),
) -> dict:
    """Everything decaying that needs a human decision, worst first.

    `total` is the true backlog rather than the size of this page, so a
    capped response does not understate how much is waiting.
    """
    try:
        return knowledge_review.review_inbox(
            db,
            kinds=[kind] if kind else None,
            window_days=window_days,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# =========================================================================
# HTML page
# =========================================================================

@router.get("/investigation-memory", response_class=HTMLResponse)
async def investigations_page(
    request: Request,
    user: User = Depends(require_page_auth),
) -> HTMLResponse:
    """Render the investigation-memory HTMX page."""
    return templates.TemplateResponse(
        request=request, name="investigation_memory.html"
    )
