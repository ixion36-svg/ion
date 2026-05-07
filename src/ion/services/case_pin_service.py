"""Case Workbench pin CRUD (v0.20.0).

Every mutation (create, status change, summary edit, dismiss) emits a
matching ledger row through ``case_ledger_service.append``. Hard-deletes
are not exposed — soft-delete via finding_status='dismissed' keeps the
chain meaningful (a missing pin would stall any auditor walking the chain).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertCase
from ion.models.case_evidence import (
    CaseEvidencePin,
    FindingStatus,
    PinSeverity,
    PinSourceType,
)
from ion.services import case_ledger_service

logger = logging.getLogger(__name__)


_VALID_STATUSES = {s.value for s in FindingStatus}
_VALID_SOURCE_TYPES = {s.value for s in PinSourceType}
_VALID_SEVERITIES = {s.value for s in PinSeverity}


class PinError(ValueError):
    """Raised for validation failures so the API layer can map to 400/409."""


class DuplicatePinError(PinError):
    """The (case, source_type, source_ref) tuple is already pinned."""


class CaseNotFoundError(PinError):
    """Pin requested on an alert_case_id that doesn't exist."""


def _ensure_case(session: Session, alert_case_id: int) -> AlertCase:
    case = session.get(AlertCase, alert_case_id)
    if case is None:
        raise CaseNotFoundError(f"AlertCase {alert_case_id} not found")
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
    alert_case_id: int,
    source_type: str,
    source_ref: str,
    title: str,
    summary: Optional[str] = None,
    severity: Optional[str] = None,
    mitre_techniques: Optional[list[str]] = None,
    tags: Optional[list[str]] = None,
    metadata: Optional[dict[str, Any]] = None,
    actor_id: int,
) -> CaseEvidencePin:
    """Create a pin and append a 'pin' action to the ledger atomically."""
    _ensure_case(session, alert_case_id)
    _validate_inputs(source_type=source_type, finding_status=None, severity=severity)

    if not title or not title.strip():
        raise PinError("title is required")

    # Free-form notes have no external ref to dedupe on. Generate a uuid so
    # each note pin has a unique source_ref and the UNIQUE constraint allows
    # multiple notes per case.
    if source_type == PinSourceType.NOTE.value and not source_ref:
        source_ref = f"note:{uuid.uuid4().hex[:16]}"

    if not source_ref:
        raise PinError("source_ref is required for non-note source types")

    meta = dict(metadata) if metadata else {}

    pin = CaseEvidencePin(
        alert_case_id=alert_case_id,
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
        # Re-raise as our domain error so the API can return 409 cleanly.
        raise DuplicatePinError(
            f"already pinned: {source_type}:{source_ref}"
        ) from exc

    case_ledger_service.append(
        session,
        alert_case_id=alert_case_id,
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
    # ION's get_db_session() yields without auto-commit and rolls back on
    # close. The pin row + its 'pin' ledger row must land atomically — commit
    # here so both are durable in a single transaction.
    session.commit()
    return pin


def list_pins(
    session: Session,
    alert_case_id: int,
    *,
    include_dismissed: bool = False,
) -> list[CaseEvidencePin]:
    stmt = (
        select(CaseEvidencePin)
        .where(CaseEvidencePin.alert_case_id == alert_case_id)
        .order_by(CaseEvidencePin.pinned_at.desc())
    )
    if not include_dismissed:
        stmt = stmt.where(CaseEvidencePin.finding_status != FindingStatus.DISMISSED.value)
    return list(session.execute(stmt).scalars().all())


def update_pin(
    session: Session,
    pin_id: int,
    *,
    alert_case_id: int,
    actor_id: int,
    finding_status: Optional[str] = None,
    summary: Optional[str] = None,
    severity: Optional[str] = None,
    tags: Optional[list[str]] = None,
    mitre_techniques: Optional[list[str]] = None,
    title: Optional[str] = None,
) -> CaseEvidencePin:
    """Update mutable fields. Each kind of change emits a distinct ledger
    action so auditors can filter by action type."""
    pin = session.get(CaseEvidencePin, pin_id)
    if pin is None:
        raise PinError(f"pin {pin_id} not found")
    if pin.alert_case_id != alert_case_id:
        raise PinError(f"pin {pin_id} not in this case")

    _validate_inputs(
        source_type=pin.source_type,
        finding_status=finding_status,
        severity=severity,
    )

    case_id = pin.alert_case_id

    if finding_status is not None and finding_status != pin.finding_status:
        old = pin.finding_status
        pin.finding_status = finding_status
        case_ledger_service.append(
            session,
            alert_case_id=case_id,
            action="status_change",
            payload={"pin_id": pin.id, "from": old, "to": finding_status},
            actor_id=actor_id,
        )

    if summary is not None and summary != (pin.summary or ""):
        pin.summary = summary or None
        case_ledger_service.append(
            session,
            alert_case_id=case_id,
            action="summary_edit",
            payload={"pin_id": pin.id, "summary_len": len(summary or "")},
            actor_id=actor_id,
        )

    if severity is not None and severity != pin.severity:
        old = pin.severity
        pin.severity = severity
        case_ledger_service.append(
            session,
            alert_case_id=case_id,
            action="severity_change",
            payload={"pin_id": pin.id, "from": old, "to": severity},
            actor_id=actor_id,
        )

    if tags is not None and tags != (pin.tags or []):
        pin.tags = tags or None
        case_ledger_service.append(
            session,
            alert_case_id=case_id,
            action="tags_change",
            payload={"pin_id": pin.id, "tags": tags},
            actor_id=actor_id,
        )

    if mitre_techniques is not None and mitre_techniques != (pin.mitre_techniques or []):
        pin.mitre_techniques = mitre_techniques or None
        case_ledger_service.append(
            session,
            alert_case_id=case_id,
            action="mitre_change",
            payload={"pin_id": pin.id, "techniques": mitre_techniques},
            actor_id=actor_id,
        )

    if title is not None and title.strip() and title.strip() != pin.title:
        old = pin.title
        pin.title = title.strip()[:500]
        case_ledger_service.append(
            session,
            alert_case_id=case_id,
            action="title_change",
            payload={"pin_id": pin.id, "from": old, "to": pin.title},
            actor_id=actor_id,
        )

    # Commit any field changes + their ledger rows together. Safe even if
    # nothing changed (no-op commit).
    session.commit()
    return pin


def dismiss_pin(
    session: Session,
    pin_id: int,
    *,
    alert_case_id: int,
    actor_id: int,
    reason: Optional[str] = None,
) -> CaseEvidencePin:
    """Soft-delete: status -> dismissed, ledger row records the reason."""
    pin = session.get(CaseEvidencePin, pin_id)
    if pin is None:
        raise PinError(f"pin {pin_id} not found")
    if pin.alert_case_id != alert_case_id:
        raise PinError(f"pin {pin_id} not in this case")

    if pin.finding_status == FindingStatus.DISMISSED.value:
        return pin  # idempotent

    pin.finding_status = FindingStatus.DISMISSED.value
    case_ledger_service.append(
        session,
        alert_case_id=pin.alert_case_id,
        action="dismiss",
        payload={"pin_id": pin.id, "reason": reason or ""},
        actor_id=actor_id,
    )
    session.commit()
    return pin
