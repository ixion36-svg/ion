"""ForensicCase Workbench pin CRUD (v0.20.1).

Mirrors ``case_pin_service`` exactly — every mutation emits a matching
ledger row through ``forensic_ledger_service.append``. Hard-deletes are
not exposed; soft-delete via finding_status='dismissed' keeps the chain
meaningful.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ion.models.forensics import ForensicCase
from ion.models.case_evidence import FindingStatus, PinSeverity, PinSourceType
from ion.models.forensic_workbench import ForensicCasePin
from ion.services import forensic_ledger_service

logger = logging.getLogger(__name__)


_VALID_STATUSES = {s.value for s in FindingStatus}
_VALID_SOURCE_TYPES = {s.value for s in PinSourceType}
_VALID_SEVERITIES = {s.value for s in PinSeverity}


class PinError(ValueError):
    """Raised for validation failures so the API can map to 400/409."""


class DuplicatePinError(PinError):
    """The (case, source_type, source_ref) tuple is already pinned."""


class CaseNotFoundError(PinError):
    """Pin requested on a forensic_case_id that doesn't exist."""


def _ensure_case(session: Session, forensic_case_id: int) -> ForensicCase:
    case = session.get(ForensicCase, forensic_case_id)
    if case is None:
        raise CaseNotFoundError(f"ForensicCase {forensic_case_id} not found")
    return case


def _validate_inputs(
    *, source_type: str, finding_status: Optional[str], severity: Optional[str]
) -> None:
    if source_type not in _VALID_SOURCE_TYPES:
        raise PinError(f"invalid source_type: {source_type}")
    if finding_status is not None and finding_status not in _VALID_STATUSES:
        raise PinError(f"invalid finding_status: {finding_status}")
    if severity is not None and severity not in _VALID_SEVERITIES:
        raise PinError(f"invalid severity: {severity}")


def create_pin(
    session: Session,
    *,
    forensic_case_id: int,
    source_type: str,
    source_ref: str,
    title: str,
    summary: Optional[str] = None,
    severity: Optional[str] = None,
    mitre_techniques: Optional[list[str]] = None,
    tags: Optional[list[str]] = None,
    metadata: Optional[dict[str, Any]] = None,
    actor_id: int,
) -> ForensicCasePin:
    """Create a pin and append a 'pin' action to the ledger atomically."""
    _ensure_case(session, forensic_case_id)
    _validate_inputs(source_type=source_type, finding_status=None, severity=severity)

    if not title or not title.strip():
        raise PinError("title is required")

    if source_type == PinSourceType.NOTE.value and not source_ref:
        source_ref = f"note:{uuid.uuid4().hex[:16]}"

    if not source_ref:
        raise PinError("source_ref is required for non-note source types")

    meta = dict(metadata) if metadata else {}

    pin = ForensicCasePin(
        forensic_case_id=forensic_case_id,
        source_type=source_type,
        source_ref=source_ref,
        title=title.strip()[:500],
        summary=(summary or None),
        finding_status=FindingStatus.TRIAGE.value,
        severity=severity,
        mitre_techniques=mitre_techniques or None,
        tags=tags or None,
        pinned_by_id=actor_id,
        pin_metadata=meta or None,
    )
    session.add(pin)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise DuplicatePinError(
            f"already pinned: {source_type}:{source_ref}"
        ) from exc

    forensic_ledger_service.append(
        session,
        forensic_case_id=forensic_case_id,
        action="pin",
        payload={
            "pin_id": pin.id,
            "source_type": pin.source_type,
            "source_ref": pin.source_ref,
            "title": pin.title,
            "severity": pin.severity,
            "tags": pin.tags or [],
            "mitre_techniques": pin.mitre_techniques or [],
        },
        actor_id=actor_id,
    )
    session.commit()
    return pin


def list_pins(
    session: Session,
    forensic_case_id: int,
    *,
    include_dismissed: bool = False,
) -> list[ForensicCasePin]:
    stmt = (
        select(ForensicCasePin)
        .where(ForensicCasePin.forensic_case_id == forensic_case_id)
        .order_by(ForensicCasePin.pinned_at.desc())
    )
    if not include_dismissed:
        stmt = stmt.where(
            ForensicCasePin.finding_status != FindingStatus.DISMISSED.value
        )
    return list(session.execute(stmt).scalars().all())


def update_pin(
    session: Session,
    pin_id: int,
    *,
    forensic_case_id: int,
    actor_id: int,
    finding_status: Optional[str] = None,
    summary: Optional[str] = None,
    severity: Optional[str] = None,
    tags: Optional[list[str]] = None,
    mitre_techniques: Optional[list[str]] = None,
    title: Optional[str] = None,
) -> ForensicCasePin:
    """Update mutable fields. Each kind of change emits a distinct ledger action."""
    pin = session.get(ForensicCasePin, pin_id)
    if pin is None:
        raise PinError(f"pin {pin_id} not found")
    if pin.forensic_case_id != forensic_case_id:
        raise PinError(f"pin {pin_id} not in this case")

    _validate_inputs(
        source_type=pin.source_type,
        finding_status=finding_status,
        severity=severity,
    )

    case_id = pin.forensic_case_id

    if finding_status is not None and finding_status != pin.finding_status:
        old = pin.finding_status
        pin.finding_status = finding_status
        forensic_ledger_service.append(
            session,
            forensic_case_id=case_id,
            action="status_change",
            payload={"pin_id": pin.id, "from": old, "to": finding_status},
            actor_id=actor_id,
        )

    if summary is not None and summary != (pin.summary or ""):
        pin.summary = summary or None
        forensic_ledger_service.append(
            session,
            forensic_case_id=case_id,
            action="summary_edit",
            payload={"pin_id": pin.id, "summary_len": len(summary or "")},
            actor_id=actor_id,
        )

    if severity is not None and severity != pin.severity:
        old = pin.severity
        pin.severity = severity
        forensic_ledger_service.append(
            session,
            forensic_case_id=case_id,
            action="severity_change",
            payload={"pin_id": pin.id, "from": old, "to": severity},
            actor_id=actor_id,
        )

    if tags is not None and tags != (pin.tags or []):
        pin.tags = tags or None
        forensic_ledger_service.append(
            session,
            forensic_case_id=case_id,
            action="tags_change",
            payload={"pin_id": pin.id, "tags": tags},
            actor_id=actor_id,
        )

    if mitre_techniques is not None and mitre_techniques != (pin.mitre_techniques or []):
        pin.mitre_techniques = mitre_techniques or None
        forensic_ledger_service.append(
            session,
            forensic_case_id=case_id,
            action="mitre_change",
            payload={"pin_id": pin.id, "techniques": mitre_techniques},
            actor_id=actor_id,
        )

    if title is not None and title.strip() and title.strip() != pin.title:
        old = pin.title
        pin.title = title.strip()[:500]
        forensic_ledger_service.append(
            session,
            forensic_case_id=case_id,
            action="title_change",
            payload={"pin_id": pin.id, "from": old, "to": pin.title},
            actor_id=actor_id,
        )

    session.commit()
    return pin


def dismiss_pin(
    session: Session,
    pin_id: int,
    *,
    forensic_case_id: int,
    actor_id: int,
    reason: Optional[str] = None,
) -> ForensicCasePin:
    """Soft-delete: status -> dismissed, ledger row records the reason."""
    pin = session.get(ForensicCasePin, pin_id)
    if pin is None:
        raise PinError(f"pin {pin_id} not found")
    if pin.forensic_case_id != forensic_case_id:
        raise PinError(f"pin {pin_id} not in this case")

    if pin.finding_status == FindingStatus.DISMISSED.value:
        return pin  # idempotent

    pin.finding_status = FindingStatus.DISMISSED.value
    forensic_ledger_service.append(
        session,
        forensic_case_id=pin.forensic_case_id,
        action="dismiss",
        payload={"pin_id": pin.id, "reason": reason or ""},
        actor_id=actor_id,
    )
    session.commit()
    return pin
