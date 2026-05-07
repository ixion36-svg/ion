"""AlertCase timeline annotation CRUD (v0.22.0).

Annotations are a freestanding mutable surface — see spec §4.2 for the
mutability decision. A single ledger row is written on create; edits and
deletes do NOT write ledger rows.

TOCTOU rule: every mutation method verifies annotation ownership INSIDE
this service before any DB write. Cross-case attempts raise AnnotationError
which the API maps to 404 (spec §6.2 test #6/#7).
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertCase, AlertCaseAnnotation
from ion.models.user import User
from ion.services import case_ledger_service

logger = logging.getLogger(__name__)


class AnnotationError(ValueError):
    """Raised for validation/ownership failures; API maps to 404 or 403."""


class AnnotationForbiddenError(AnnotationError):
    """Raised when the caller lacks permission to mutate this annotation."""


def _ensure_case(session: Session, alert_case_id: int) -> AlertCase:
    case = session.get(AlertCase, alert_case_id)
    if case is None:
        raise AnnotationError(f"AlertCase {alert_case_id} not found")
    return case


def _get_annotation_or_raise(
    session: Session, ann_id: int, alert_case_id: int
) -> AlertCaseAnnotation:
    """Load annotation and enforce cross-case TOCTOU check.

    Raises AnnotationError (404) if the annotation doesn't exist OR belongs
    to a different case — prevents TOCTOU mutation via wrong case URL.
    """
    ann = session.get(AlertCaseAnnotation, ann_id)
    if ann is None or ann.deleted_at is not None:
        raise AnnotationError(f"annotation {ann_id} not found")
    # TOCTOU ownership check: annotation must belong to the URL's case_id
    if ann.alert_case_id != alert_case_id:
        raise AnnotationError(
            f"annotation {ann_id} does not belong to case {alert_case_id}"
        )
    return ann


def _check_edit_permission(
    ann: AlertCaseAnnotation, actor: User, has_case_close: bool
) -> None:
    """Verify caller may edit/delete this annotation.

    Rules (spec §4.5): author may always edit their own; case:close users
    may edit any. Others get 403.
    """
    if ann.created_by_id == actor.id:
        return
    if has_case_close:
        return
    raise AnnotationForbiddenError(
        "only the annotation author or a case:close user may modify this annotation"
    )


def create(
    session: Session,
    *,
    alert_case_id: int,
    body: str,
    timeline_ts: datetime,
    actor_id: int,
) -> AlertCaseAnnotation:
    """Insert annotation row, write ledger entry, commit atomically."""
    _ensure_case(session, alert_case_id)
    if not body or not body.strip():
        raise AnnotationError("body must not be empty")

    ann = AlertCaseAnnotation(
        alert_case_id=alert_case_id,
        created_by_id=actor_id,
        timeline_ts=timeline_ts,
        body=body,
    )
    session.add(ann)
    session.flush()  # obtain ann.id before ledger append

    case_ledger_service.append(
        session,
        alert_case_id=alert_case_id,
        action="annotation_created",
        payload={
            "annotation_id": ann.id,
            "timeline_ts": timeline_ts.isoformat(),
            "actor_id": actor_id,
        },
        actor_id=actor_id,
    )
    session.commit()
    return ann


def list_active(
    session: Session, alert_case_id: int
) -> list[AlertCaseAnnotation]:
    """Return all non-deleted annotations sorted by timeline_ts ascending."""
    rows = session.execute(
        select(AlertCaseAnnotation)
        .where(AlertCaseAnnotation.alert_case_id == alert_case_id)
        .where(AlertCaseAnnotation.deleted_at.is_(None))
        .order_by(AlertCaseAnnotation.timeline_ts.asc())
    ).scalars().all()
    return list(rows)


def update(
    session: Session,
    ann_id: int,
    *,
    alert_case_id: int,
    actor: User,
    has_case_close: bool,
    body: Optional[str] = None,
    timeline_ts: Optional[datetime] = None,
) -> AlertCaseAnnotation:
    """Update mutable fields. Does NOT write a ledger row (spec §4.2)."""
    ann = _get_annotation_or_raise(session, ann_id, alert_case_id)
    _check_edit_permission(ann, actor, has_case_close)

    if body is not None:
        if not body.strip():
            raise AnnotationError("body must not be empty")
        ann.body = body
    if timeline_ts is not None:
        ann.timeline_ts = timeline_ts

    session.commit()
    return ann


def soft_delete(
    session: Session,
    ann_id: int,
    *,
    alert_case_id: int,
    actor: User,
    has_case_close: bool,
) -> AlertCaseAnnotation:
    """Soft-delete by setting deleted_at. Does NOT write a ledger row."""
    ann = _get_annotation_or_raise(session, ann_id, alert_case_id)
    _check_edit_permission(ann, actor, has_case_close)

    ann.deleted_at = datetime.utcnow()
    session.commit()
    return ann
