"""Workbench REST API — pinned evidence + tamper-evident ledger (v0.20.0).

Mounted at /api in server.py; this router declares its own /alert-cases/{id}
prefix so URLs land at /api/alert-cases/{id}/pins, /ledger, /ledger/verify.

Permission gate is reused: ``case:read`` for GET, ``case:update`` for any
mutation. v0.20.1 will add a parallel set of endpoints under
/api/forensic-cases/{id}/pins for ForensicCase attachment.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.core.safe_errors import safe_error
from ion.models.user import User
from ion.services import annotation_service, case_ledger_service, case_pin_service
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
# Annotation schemas (v0.22.0)
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
# Annotation endpoints (v0.22.0)
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
