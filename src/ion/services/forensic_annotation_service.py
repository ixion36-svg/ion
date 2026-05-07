"""ForensicCase timeline annotation CRUD (v0.22.0).

Mirrors annotation_service exactly but operates on forensic_case_annotations
and uses forensic_ledger_service (FCWL namespace) for the create ledger row.

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

from ion.models.forensics import ForensicCase, ForensicCaseAnnotation
from ion.models.user import User
from ion.services import forensic_ledger_service

logger = logging.getLogger(__name__)


class AnnotationError(ValueError):
    """Raised for validation/ownership failures; API maps to 404 or 403."""


class AnnotationForbiddenError(AnnotationError):
    """Raised when the caller lacks permission to mutate this annotation."""


def _ensure_case(session: Session, forensic_case_id: int) -> ForensicCase:
    case = session.get(ForensicCase, forensic_case_id)
    if case is None:
        raise AnnotationError(f"ForensicCase {forensic_case_id} not found")
    return case


def _get_annotation_or_raise(
    session: Session, ann_id: int, forensic_case_id: int
) -> ForensicCaseAnnotation:
    """Load annotation and enforce cross-case TOCTOU check.

    Raises AnnotationError (404) if the annotation doesn't exist OR belongs
    to a different case — prevents TOCTOU mutation via wrong case URL.
    """
    ann = session.get(ForensicCaseAnnotation, ann_id)
    if ann is None or ann.deleted_at is not None:
        raise AnnotationError(f"annotation {ann_id} not found")
    # TOCTOU ownership check: annotation must belong to the URL's case_id
    if ann.forensic_case_id != forensic_case_id:
        raise AnnotationError(
            f"annotation {ann_id} does not belong to forensic case {forensic_case_id}"
        )
    return ann


def _check_edit_permission(
    ann: ForensicCaseAnnotation, actor: User, has_forensic_close: bool
) -> None:
    """Verify caller may edit/delete this annotation.

    Rules mirror AlertCase (spec §4.5): author may edit own annotation;
    forensic:close users may edit any.
    """
    if ann.created_by_id == actor.id:
        return
    if has_forensic_close:
        return
    raise AnnotationForbiddenError(
        "only the annotation author or a forensic:close user may modify this annotation"
    )


def create(
    session: Session,
    *,
    forensic_case_id: int,
    body: str,
    timeline_ts: datetime,
    actor_id: int,
) -> ForensicCaseAnnotation:
    """Insert annotation row, write ledger entry, commit atomically."""
    _ensure_case(session, forensic_case_id)
    if not body or not body.strip():
        raise AnnotationError("body must not be empty")

    ann = ForensicCaseAnnotation(
        forensic_case_id=forensic_case_id,
        created_by_id=actor_id,
        timeline_ts=timeline_ts,
        body=body,
    )
    session.add(ann)
    session.flush()  # obtain ann.id before ledger append

    forensic_ledger_service.append(
        session,
        forensic_case_id=forensic_case_id,
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
    session: Session, forensic_case_id: int
) -> list[ForensicCaseAnnotation]:
    """Return all non-deleted annotations sorted by timeline_ts ascending."""
    rows = session.execute(
        select(ForensicCaseAnnotation)
        .where(ForensicCaseAnnotation.forensic_case_id == forensic_case_id)
        .where(ForensicCaseAnnotation.deleted_at.is_(None))
        .order_by(ForensicCaseAnnotation.timeline_ts.asc())
    ).scalars().all()
    return list(rows)


def update(
    session: Session,
    ann_id: int,
    *,
    forensic_case_id: int,
    actor: User,
    has_forensic_close: bool,
    body: Optional[str] = None,
    timeline_ts: Optional[datetime] = None,
) -> ForensicCaseAnnotation:
    """Update mutable fields. Does NOT write a ledger row (spec §4.2)."""
    ann = _get_annotation_or_raise(session, ann_id, forensic_case_id)
    _check_edit_permission(ann, actor, has_forensic_close)

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
    forensic_case_id: int,
    actor: User,
    has_forensic_close: bool,
) -> ForensicCaseAnnotation:
    """Soft-delete by setting deleted_at. Does NOT write a ledger row."""
    ann = _get_annotation_or_raise(session, ann_id, forensic_case_id)
    _check_edit_permission(ann, actor, has_forensic_close)

    ann.deleted_at = datetime.utcnow()
    session.commit()
    return ann
