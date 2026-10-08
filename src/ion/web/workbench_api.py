"""Workbench REST API — pinned evidence + tamper-evident ledger (v0.20.0).

Mounted at /api in server.py; this router declares its own /alert-cases/{id}
prefix so URLs land at /api/alert-cases/{id}/pins, /ledger, /ledger/verify.

Permission gate is reused: ``case:read`` for GET, ``case:update`` for any
mutation. v0.20.1 will add a parallel set of endpoints under
/api/forensic-cases/{id}/pins for ForensicCase attachment.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.core.safe_errors import safe_error
from ion.models.case_evidence import CaseEvidencePin
from ion.models.user import User
from ion.services import (
    annotation_service,
    case_ledger_service,
    case_pin_service,
    query_evidence_service,
)
from ion.services.query_evidence_service import QueryEvidenceError
from ion.services.annotation_service import (
    AnnotationError,
    AnnotationForbiddenError,
)
from ion.services.case_pin_service import (
    CaseNotFoundError,
    DuplicatePinError,
    PinError,
)
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alert-cases", tags=["workbench"])


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
    finding_status: Optional[str] = None  # triage | confirmed | reported | dismissed
    summary: Optional[str] = None
    severity: Optional[str] = None
    tags: Optional[list[str]] = None
    mitre_techniques: Optional[list[str]] = None
    title: Optional[str] = Field(None, max_length=500)


class PinDismiss(BaseModel):
    reason: Optional[str] = Field(None, max_length=500)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/{case_id}/pins",
    dependencies=[Depends(require_permission("case:read"))],
)
def list_pins_endpoint(
    case_id: int,
    include_dismissed: bool = False,
    session: Session = Depends(get_db_session),
):
    pins = case_pin_service.list_pins(
        session, case_id, include_dismissed=include_dismissed
    )
    return {"pins": [p.to_dict() for p in pins]}


@router.post(
    "/{case_id}/pins",
    dependencies=[Depends(require_permission("case:update"))],
)
def create_pin_endpoint(
    case_id: int,
    body: PinCreate,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    try:
        pin = case_pin_service.create_pin(
            session,
            alert_case_id=case_id,
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


@router.patch(
    "/{case_id}/pins/{pin_id}",
    dependencies=[Depends(require_permission("case:update"))],
)
def update_pin_endpoint(
    case_id: int,
    pin_id: int,
    body: PinUpdate,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    try:
        pin = case_pin_service.update_pin(
            session,
            pin_id,
            alert_case_id=case_id,
            actor_id=user.id,
            finding_status=body.finding_status,
            summary=body.summary,
            severity=body.severity,
            tags=body.tags,
            mitre_techniques=body.mitre_techniques,
            title=body.title,
        )
    except PinError as exc:
        raise HTTPException(status_code=404, detail=safe_error(exc)) from exc
    return {"pin": pin.to_dict()}


@router.delete(
    "/{case_id}/pins/{pin_id}",
    dependencies=[Depends(require_permission("case:update"))],
)
def dismiss_pin_endpoint(
    case_id: int,
    pin_id: int,
    body: PinDismiss = PinDismiss(),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    try:
        pin = case_pin_service.dismiss_pin(
            session, pin_id, alert_case_id=case_id, actor_id=user.id, reason=body.reason
        )
    except PinError as exc:
        raise HTTPException(status_code=404, detail=safe_error(exc)) from exc
    return {"pin": pin.to_dict()}


# ---------------------------------------------------------------------------
# Query evidence
#
# A captured Discover search, stored as a `query` pin so it joins the same
# hash-chained ledger as every other piece of case evidence. See
# ion.services.query_evidence_service for why a rerun is a new pin rather
# than an update of the original.
# ---------------------------------------------------------------------------


class QueryEvidenceCreate(BaseModel):
    query: str = Field(..., min_length=1, description="The search text, exactly as it ran")
    index: str = Field(..., min_length=1, description="Index or index pattern searched")
    language: Optional[str] = Field(None, description="kql | lucene | dsl")
    time_from: Optional[str] = Field(None, description="ISO-8601 window start")
    time_to: Optional[str] = Field(None, description="ISO-8601 window end")
    time_expression: Optional[dict[str, Any]] = Field(
        None, description='The relative form picked, e.g. {"from": "now-24h", "to": "now"}'
    )
    executed_at: Optional[str] = Field(None, description="ISO-8601; when the search ran")
    duration_ms: Optional[int] = Field(None, ge=0)
    returned_count: int = Field(0, ge=0)
    total_hits: Optional[int] = Field(None, ge=0)
    truncated: Optional[bool] = None
    selected_results: Optional[list[Any]] = None
    title: Optional[str] = Field(None, max_length=500)
    note: Optional[str] = None
    severity: Optional[str] = None
    tags: Optional[list[str]] = None


class QueryEvidenceRerun(BaseModel):
    returned_count: int = Field(..., ge=0)
    total_hits: Optional[int] = Field(None, ge=0)
    truncated: Optional[bool] = None
    selected_results: Optional[list[Any]] = None
    duration_ms: Optional[int] = Field(None, ge=0)
    executed_at: Optional[str] = None
    time_from: Optional[str] = None
    time_to: Optional[str] = None
    note: Optional[str] = None


def _parse_ts(raw: Optional[str], field: str) -> Optional[datetime]:
    """Parse an ISO-8601 string, accepting the trailing ``Z`` browsers send."""
    if raw is None or not str(raw).strip():
        return None
    text = str(raw).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail=f"{field} is not a valid ISO-8601 timestamp"
        ) from exc


@router.get(
    "/{case_id}/query-evidence",
    dependencies=[Depends(require_permission("case:read"))],
)
def list_query_evidence_endpoint(
    case_id: int,
    limit: int = 100,
    session: Session = Depends(get_db_session),
):
    """Every captured search on this case, newest first."""
    return {
        "query_evidence": query_evidence_service.list_query_evidence(
            session, case_id, limit=max(1, min(limit, 500))
        )
    }


@router.post(
    "/{case_id}/query-evidence",
    dependencies=[Depends(require_permission("case:update"))],
)
def capture_query_evidence_endpoint(
    case_id: int,
    body: QueryEvidenceCreate,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Capture a search as case evidence with its full provenance."""
    try:
        pin = query_evidence_service.capture_query_evidence(
            session,
            alert_case_id=case_id,
            actor_id=user.id,
            query=body.query,
            index=body.index,
            language=body.language,
            time_from=_parse_ts(body.time_from, "time_from"),
            time_to=_parse_ts(body.time_to, "time_to"),
            time_expression=body.time_expression,
            executed_at=_parse_ts(body.executed_at, "executed_at"),
            duration_ms=body.duration_ms,
            returned_count=body.returned_count,
            total_hits=body.total_hits,
            truncated=body.truncated,
            selected_results=body.selected_results,
            title=body.title,
            note=body.note,
            severity=body.severity,
            tags=body.tags,
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=safe_error(exc)) from exc
    except (QueryEvidenceError, PinError) as exc:
        raise HTTPException(status_code=400, detail=safe_error(exc)) from exc
    return {"pin": pin.to_dict()}


@router.post(
    "/{case_id}/query-evidence/{pin_id}/rerun",
    dependencies=[Depends(require_permission("case:update"))],
)
def rerun_query_evidence_endpoint(
    case_id: int,
    pin_id: int,
    body: QueryEvidenceRerun,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Re-capture an earlier search as a *new* pin. The original is untouched."""
    original = session.get(CaseEvidencePin, pin_id)
    if original is None or original.alert_case_id != case_id:
        raise HTTPException(status_code=404, detail="query evidence not found on this case")
    try:
        pin = query_evidence_service.rerun_query_evidence(
            session,
            pin_id=pin_id,
            actor_id=user.id,
            returned_count=body.returned_count,
            total_hits=body.total_hits,
            truncated=body.truncated,
            selected_results=body.selected_results,
            duration_ms=body.duration_ms,
            executed_at=_parse_ts(body.executed_at, "executed_at"),
            time_from=_parse_ts(body.time_from, "time_from"),
            time_to=_parse_ts(body.time_to, "time_to"),
            note=body.note,
        )
    except (QueryEvidenceError, PinError) as exc:
        raise HTTPException(status_code=400, detail=safe_error(exc)) from exc
    return {"pin": pin.to_dict()}


# ---------------------------------------------------------------------------
# Annotation schemas
# ---------------------------------------------------------------------------


class AnnotationCreate(BaseModel):
    timeline_ts: str  # ISO-8601 datetime string, stored as UTC naive
    body: str = Field(..., min_length=1, max_length=2000)


class AnnotationUpdate(BaseModel):
    timeline_ts: Optional[str] = None
    body: Optional[str] = Field(None, min_length=1, max_length=2000)


def _parse_ts(ts_str: str):
    """Parse ISO-8601 datetime string to naive UTC datetime."""
    from datetime import datetime
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse datetime: {ts_str!r}")


def _annotation_response(ann, session) -> dict:
    """Build the API response shape (deleted_at never included)."""
    username = None
    if ann.created_by:
        username = getattr(ann.created_by, "username", None)
    return {
        "id": ann.id,
        "case_id": ann.alert_case_id,
        "timeline_ts": ann.timeline_ts.isoformat() if ann.timeline_ts else None,
        "body": ann.body,
        "created_by_id": ann.created_by_id,
        "created_by_username": username,
        "created_at": ann.created_at.isoformat() if ann.created_at else None,
        "updated_at": ann.updated_at.isoformat() if ann.updated_at else None,
    }


# ---------------------------------------------------------------------------
# Annotation endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/{case_id}/annotations",
    dependencies=[Depends(require_permission("case:read"))],
)
def list_annotations_endpoint(
    case_id: int,
    session: Session = Depends(get_db_session),
):
    annotations = annotation_service.list_active(session, case_id)
    return {"annotations": [_annotation_response(a, session) for a in annotations]}


@router.post(
    "/{case_id}/annotations",
    status_code=201,
)
def create_annotation_endpoint(
    case_id: int,
    body: AnnotationCreate,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("case:update")),
):
    try:
        ts = _parse_ts(body.timeline_ts)
        ann = annotation_service.create(
            session,
            alert_case_id=case_id,
            body=body.body,
            timeline_ts=ts,
            actor_id=user.id,
        )
    except AnnotationError as exc:
        raise HTTPException(status_code=404, detail=safe_error(exc)) from exc
    return _annotation_response(ann, session)


@router.patch(
    "/{case_id}/annotations/{ann_id}",
)
def update_annotation_endpoint(
    case_id: int,
    ann_id: int,
    body: AnnotationUpdate,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("case:update")),
):
    has_close = user.has_permission("case:close")
    try:
        ts = _parse_ts(body.timeline_ts) if body.timeline_ts else None
        ann = annotation_service.update(
            session,
            ann_id,
            alert_case_id=case_id,
            actor=user,
            has_case_close=has_close,
            body=body.body,
            timeline_ts=ts,
        )
    except AnnotationForbiddenError as exc:
        raise HTTPException(status_code=403, detail=safe_error(exc)) from exc
    except AnnotationError as exc:
        raise HTTPException(status_code=404, detail=safe_error(exc)) from exc
    return _annotation_response(ann, session)


@router.delete(
    "/{case_id}/annotations/{ann_id}",
)
def delete_annotation_endpoint(
    case_id: int,
    ann_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("case:update")),
):
    has_close = user.has_permission("case:close")
    try:
        ann = annotation_service.soft_delete(
            session,
            ann_id,
            alert_case_id=case_id,
            actor=user,
            has_case_close=has_close,
        )
    except AnnotationForbiddenError as exc:
        raise HTTPException(status_code=403, detail=safe_error(exc)) from exc
    except AnnotationError as exc:
        raise HTTPException(status_code=404, detail=safe_error(exc)) from exc
    return {"deleted": True, "id": ann.id}

@router.get(
    "/{case_id}/ledger",
    dependencies=[Depends(require_permission("case:read"))],
)
def list_ledger_endpoint(
    case_id: int,
    limit: int = 500,
    session: Session = Depends(get_db_session),
):
    # Cap at 2000 so a curious caller can't pull a 100k-row chain in one go.
    safe_limit = max(1, min(int(limit or 500), 2000))
    return {
        "entries": case_ledger_service.list_entries(
            session, case_id, limit=safe_limit
        )
    }


@router.get(
    "/{case_id}/ledger/verify",
    dependencies=[Depends(require_permission("case:read"))],
)
def verify_ledger_endpoint(
    case_id: int,
    session: Session = Depends(get_db_session),
):
    return case_ledger_service.verify_chain(session, case_id)
