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
from ion.services import case_ledger_service, case_pin_service
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
    if pin.alert_case_id != case_id:
        raise HTTPException(status_code=404, detail="pin not in this case")
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
            session, pin_id, actor_id=user.id, reason=body.reason
        )
    except PinError as exc:
        raise HTTPException(status_code=400, detail=safe_error(exc)) from exc
    if pin.alert_case_id != case_id:
        raise HTTPException(status_code=404, detail="pin not in this case")
    return {"pin": pin.to_dict()}


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
