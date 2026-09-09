"""Analyst pinned-fields API (ION_ALERT_FIELD_PINS).

Per-user, per-rule (or global, rule_id='') field pins that surface in the
alert-detail Case-context panel. Every query is scoped to the authenticated
user's own rows, so a caller can only ever read or mutate their own pins —
ownership is enforced in-handler, before the mutation commits.
"""

import logging

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.analyst_pinned_field import AnalystPinnedField
from ion.models.user import User
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alerts/pinned-fields", tags=["pinned-fields"])


class PinRequest(BaseModel):
    field_name: str = Field(..., min_length=1, max_length=256)
    rule_id: str = Field("", max_length=512)  # '' = global (all rules)


@router.get("")
def list_pins(
    rule_id: str = Query("", max_length=512),
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Resolved pins for this user: global ('') plus the given rule's, if any."""
    q = session.query(AnalystPinnedField).filter(AnalystPinnedField.user_id == user.id)
    if rule_id:
        q = q.filter(AnalystPinnedField.rule_id.in_(["", rule_id]))
    rows = q.all()
    return {"fields": [r.field_name for r in rows], "pins": [r.to_dict() for r in rows]}


@router.post("")
def add_pin(
    body: PinRequest,
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Pin a field (idempotent). Only ever writes a row owned by this user."""
    field = body.field_name.strip()
    rule = (body.rule_id or "").strip()
    existing = (
        session.query(AnalystPinnedField)
        .filter(
            AnalystPinnedField.user_id == user.id,
            AnalystPinnedField.rule_id == rule,
            AnalystPinnedField.field_name == field,
        )
        .one_or_none()
    )
    if existing:
        return existing.to_dict()
    pin = AnalystPinnedField(user_id=user.id, rule_id=rule, field_name=field)
    session.add(pin)
    session.commit()
    session.refresh(pin)
    return pin.to_dict()


@router.delete("")
def remove_pin(
    field_name: str = Query(..., min_length=1, max_length=256),
    rule_id: str = Query("", max_length=512),
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Unpin a field. Only ever deletes the caller's own row."""
    session.query(AnalystPinnedField).filter(
        AnalystPinnedField.user_id == user.id,
        AnalystPinnedField.rule_id == (rule_id or "").strip(),
        AnalystPinnedField.field_name == field_name.strip(),
    ).delete()
    session.commit()
    return {"ok": True}
