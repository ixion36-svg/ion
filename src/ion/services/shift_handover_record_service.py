"""Shift handover as an accountable transfer (review 2026-10-08 §17).

    "handover generates a report rather than persisting an accountable
    transfer with incoming acceptance and owned actions"

:func:`ion.services.shift_handover_service.generate_shift_report` stays as
the live view of the last N hours. This module turns one of those views into
a record: a frozen snapshot, two named leads, owned actions with deadlines,
and an acceptance by someone other than the person handing over.

Design notes worth keeping in view:

**The snapshot is frozen, not a query.** A report recomputed at read time
shows the estate as it is now, not as it was when the shift ended. The numbers
the outgoing lead signed off on are the accountable ones, so they are stored
with the timestamp they were taken at and never recalculated.

**Acceptance is atomic.** Two leads reaching for the same handover must
resolve to one, so the transition is a conditional ``UPDATE ... WHERE status
= :expected`` checked by rowcount — the same discipline stage 1 applied to
response actions, for the same reason: a read-then-write lets both callers
through.

**Open actions carry forward.** When the next handover is created, actions
still open on the last accepted one are copied with ``carried_from_id`` set
and ``carry_count`` incremented. A task that crossed three shifts then looks
like one task that crossed three shifts, rather than three unrelated tasks,
which is the signal worth seeing.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from ion.models.shift_handover import (
    HandoverActionStatus,
    HandoverStatus,
    ShiftHandover,
    ShiftHandoverAction,
)
from ion.models.user import User
from ion.services.shift_handover_service import generate_shift_report

logger = logging.getLogger(__name__)


class HandoverError(Exception):
    """A handover operation was refused."""


#: Snapshot counters compared against the previous accepted handover. Each is
#: a (name, path) pair into the snapshot dict. Deliberately a short list of
#: counts an incoming lead actually acts on, not everything in the report.
_CHANGE_METRICS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("open_cases", ("pending", "open_cases"), "Open cases"),
    ("unassigned_cases", ("pending", "unassigned_cases"), "Unassigned cases"),
    ("open_alerts", ("pending", "open_alerts"), "Open alerts"),
    ("in_progress_alerts", ("pending", "in_progress_alerts"), "Alerts in progress"),
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    """Treat a stored naive datetime as UTC rather than local time."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _dig(data: Any, path: tuple[str, ...]):
    for key in path:
        if not isinstance(data, dict) or key not in data:
            return None
        data = data[key]
    return data


def _claim_status(
    session: Session,
    handover_id: int,
    *,
    expected: tuple[str, ...],
    new: str,
    **fields,
) -> bool:
    """Conditional transition. Returns True only for the caller that won.

    The ``WHERE`` clause decides, so a second acceptance cannot also advance
    the row. Without it, two leads who both read ``submitted`` would both
    write ``accepted`` and the record would name whichever committed last.
    """
    result = session.execute(
        update(ShiftHandover)
        .where(
            ShiftHandover.id == handover_id,
            ShiftHandover.status.in_(expected),
        )
        .values(status=new, **fields)
    )
    won = result.rowcount == 1
    session.commit()
    if not won:
        session.expire_all()
    return won


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

def _snapshot(session: Session, hours: int) -> dict:
    """Freeze the shift report, annotated with where each number came from.

    The review asks for "a shared operational snapshot with source
    timestamps". Each source carries its own ``as_of`` because they are not
    all equally fresh: the database counts are current as at the snapshot,
    while anything cached or externally fetched may not be.
    """
    report = generate_shift_report(session, hours=hours)
    taken = _now()
    report["snapshot_taken_at"] = taken.isoformat()
    report["sources"] = [
        {
            "name": "ION database",
            "detail": "Alert, case and triage counts",
            "as_of": taken.isoformat(),
            "freshness": "live at snapshot",
        },
        {
            "name": "Shift report generator",
            "detail": f"Rolling {hours}h window ending at the snapshot",
            "as_of": report.get("generated_at") or taken.isoformat(),
            "freshness": "live at snapshot",
        },
    ]
    return report


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

def _last_accepted(session: Session) -> Optional[ShiftHandover]:
    return session.execute(
        select(ShiftHandover)
        .where(ShiftHandover.status == HandoverStatus.ACCEPTED.value)
        .order_by(ShiftHandover.id.desc())
        .limit(1)
    ).scalars().first()


def create_handover(
    session: Session,
    *,
    outgoing_lead_id: int,
    incoming_lead_id: Optional[int] = None,
    hours: int = 8,
    summary: Optional[str] = None,
) -> ShiftHandover:
    """Raise a draft handover with a frozen snapshot of the shift.

    Open actions from the last *accepted* handover are carried forward. A
    draft nobody accepted is not a baseline, so it is not the source.

    Args:
        session: Database session.
        outgoing_lead_id: The lead handing over.
        incoming_lead_id: The lead taking over, if already known. Required
            before the handover can be submitted.
        hours: Shift length the snapshot covers.
        summary: The outgoing lead's own words.

    Returns:
        The created draft.

    Raises:
        HandoverError: If the two leads are the same person.
    """
    if incoming_lead_id is not None and incoming_lead_id == outgoing_lead_id:
        raise HandoverError(
            "the outgoing and incoming lead cannot be the same person; a "
            "transfer to yourself is not a transfer"
        )
    if hours < 1 or hours > 24:
        raise HandoverError("shift length must be between 1 and 24 hours")

    snapshot = _snapshot(session, hours)
    taken = datetime.fromisoformat(snapshot["snapshot_taken_at"])
    previous = _last_accepted(session)

    handover = ShiftHandover(
        shift_start=datetime.fromisoformat(snapshot["shift_start"]),
        shift_end=datetime.fromisoformat(snapshot["shift_end"]),
        shift_hours=hours,
        outgoing_lead_id=outgoing_lead_id,
        incoming_lead_id=incoming_lead_id,
        status=HandoverStatus.DRAFT.value,
        summary=(summary.strip() if summary and summary.strip() else None),
        snapshot=snapshot,
        snapshot_taken_at=taken,
        previous_handover_id=previous.id if previous else None,
    )
    session.add(handover)
    session.flush()

    carried = 0
    if previous is not None:
        for action in previous.actions:
            if action.status != HandoverActionStatus.OPEN.value:
                continue
            session.add(
                ShiftHandoverAction(
                    handover_id=handover.id,
                    description=action.description,
                    owner_id=action.owner_id,
                    due_at=action.due_at,
                    case_id=action.case_id,
                    status=HandoverActionStatus.OPEN.value,
                    carried_from_id=action.id,
                    carry_count=action.carry_count + 1,
                    created_by_id=action.created_by_id,
                )
            )
            carried += 1

    session.commit()
    session.refresh(handover)
    logger.info(
        "Shift handover %s raised by user %s (previous=%s, carried %d action(s))",
        handover.id, outgoing_lead_id, handover.previous_handover_id, carried,
    )
    return handover


def set_incoming_lead(
    session: Session,
    *,
    handover_id: int,
    incoming_lead_id: int,
    actor_id: int,
) -> ShiftHandover:
    """Name the incoming lead on a draft."""
    handover = _require(session, handover_id)
    if handover.status != HandoverStatus.DRAFT.value:
        raise HandoverError(
            f"handover {handover_id} is '{handover.status}'; the incoming lead "
            "can only be changed on a draft"
        )
    if actor_id != handover.outgoing_lead_id:
        raise HandoverError("only the outgoing lead may edit their own draft")
    if incoming_lead_id == handover.outgoing_lead_id:
        raise HandoverError(
            "the outgoing and incoming lead cannot be the same person"
        )
    handover.incoming_lead_id = incoming_lead_id
    session.commit()
    session.refresh(handover)
    return handover


# ---------------------------------------------------------------------------
# Transitions
# ---------------------------------------------------------------------------

def _require(session: Session, handover_id: int) -> ShiftHandover:
    handover = session.get(ShiftHandover, handover_id)
    if handover is None:
        raise HandoverError(f"handover {handover_id} not found")
    return handover


def submit_handover(
    session: Session, *, handover_id: int, actor_id: int
) -> ShiftHandover:
    """Offer the handover to the incoming shift.

    A submitted handover nobody takes is what the "unaccepted handovers"
    measure counts, so submitting is the point at which the clock starts.
    """
    handover = _require(session, handover_id)
    if actor_id != handover.outgoing_lead_id:
        raise HandoverError("only the outgoing lead may submit their handover")
    if handover.incoming_lead_id is None:
        raise HandoverError(
            "name the incoming lead before submitting; a transfer needs "
            "someone on the other end"
        )

    if not _claim_status(
        session, handover_id,
        expected=(HandoverStatus.DRAFT.value, HandoverStatus.REJECTED.value),
        new=HandoverStatus.SUBMITTED.value,
        submitted_at=_now().replace(tzinfo=None),
        rejection_reason=None,
    ):
        current = session.get(ShiftHandover, handover_id)
        raise HandoverError(
            f"handover {handover_id} is '{current.status if current else 'missing'}' "
            "and cannot be submitted"
        )
    session.expire_all()
    return _require(session, handover_id)


def accept_handover(
    session: Session, *, handover_id: int, actor_id: int
) -> ShiftHandover:
    """Take the handover. Accountable, so not by the person handing over.

    The named incoming lead going off sick must not block the shift, so
    anyone else may accept — but the record keeps both names and flags that
    the acceptor was not the designated lead.
    """
    handover = _require(session, handover_id)
    if handover.status != HandoverStatus.SUBMITTED.value:
        raise HandoverError(
            f"handover {handover_id} is '{handover.status}'; only a submitted "
            "handover can be accepted"
        )
    if actor_id == handover.outgoing_lead_id:
        raise HandoverError(
            "the outgoing lead cannot accept their own handover; the record "
            "exists to show that someone else took it"
        )

    designated = actor_id == handover.incoming_lead_id

    if not _claim_status(
        session, handover_id,
        expected=(HandoverStatus.SUBMITTED.value,),
        new=HandoverStatus.ACCEPTED.value,
        accepted_at=_now().replace(tzinfo=None),
        accepted_by_id=actor_id,
        accepted_by_designated_lead=designated,
    ):
        current = session.get(ShiftHandover, handover_id)
        raise HandoverError(
            f"handover {handover_id} was already decided concurrently (now "
            f"'{current.status if current else 'missing'}')"
        )

    session.expire_all()
    logger.info(
        "Shift handover %s accepted by user %s (designated lead: %s)",
        handover_id, actor_id, designated,
    )
    return _require(session, handover_id)


def reject_handover(
    session: Session, *, handover_id: int, actor_id: int, reason: str
) -> ShiftHandover:
    """Send the handover back with a reason, which is mandatory."""
    if not reason or not reason.strip():
        raise HandoverError("a rejection needs a reason the outgoing lead can act on")

    handover = _require(session, handover_id)
    if handover.status != HandoverStatus.SUBMITTED.value:
        raise HandoverError(
            f"handover {handover_id} is '{handover.status}'; only a submitted "
            "handover can be rejected"
        )
    if actor_id == handover.outgoing_lead_id:
        raise HandoverError("the outgoing lead cannot reject their own handover")

    if not _claim_status(
        session, handover_id,
        expected=(HandoverStatus.SUBMITTED.value,),
        new=HandoverStatus.REJECTED.value,
        rejection_reason=reason.strip(),
    ):
        current = session.get(ShiftHandover, handover_id)
        raise HandoverError(
            f"handover {handover_id} was already decided concurrently (now "
            f"'{current.status if current else 'missing'}')"
        )
    session.expire_all()
    return _require(session, handover_id)


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

_EDITABLE = (HandoverStatus.DRAFT.value, HandoverStatus.SUBMITTED.value,
             HandoverStatus.REJECTED.value)


def add_action(
    session: Session,
    *,
    handover_id: int,
    actor_id: int,
    description: str,
    owner_id: Optional[int] = None,
    due_at: Optional[datetime] = None,
    case_id: Optional[int] = None,
) -> ShiftHandoverAction:
    """Add work crossing the boundary.

    ``owner_id`` may be ``None``: an unowned action is a real state and is
    surfaced as a gap, which is more useful than forcing a false owner.

    Accepted handovers are closed to edits — the accepted record is what both
    leads agreed to, so new work goes on the next handover.
    """
    if not description or not description.strip():
        raise HandoverError("an action needs a description")

    handover = _require(session, handover_id)
    if handover.status not in _EDITABLE:
        raise HandoverError(
            f"handover {handover_id} is '{handover.status}' and is closed to "
            "edits; raise the action on the next handover"
        )

    action = ShiftHandoverAction(
        handover_id=handover_id,
        description=description.strip(),
        owner_id=owner_id,
        due_at=(due_at.astimezone(timezone.utc).replace(tzinfo=None)
                if due_at and due_at.tzinfo else due_at),
        case_id=case_id,
        status=HandoverActionStatus.OPEN.value,
        carry_count=0,
        created_by_id=actor_id,
    )
    session.add(action)
    session.commit()
    session.refresh(action)
    return action


def _resolve_action(
    session: Session,
    *,
    action_id: int,
    actor_id: int,
    new_status: str,
    note: Optional[str],
) -> ShiftHandoverAction:
    """Conditional close of an open action, so it cannot be closed twice."""
    action = session.get(ShiftHandoverAction, action_id)
    if action is None:
        raise HandoverError(f"handover action {action_id} not found")
    if action.status != HandoverActionStatus.OPEN.value:
        raise HandoverError(
            f"action {action_id} is already '{action.status}'"
        )

    result = session.execute(
        update(ShiftHandoverAction)
        .where(
            ShiftHandoverAction.id == action_id,
            ShiftHandoverAction.status == HandoverActionStatus.OPEN.value,
        )
        .values(
            status=new_status,
            completed_at=_now().replace(tzinfo=None),
            completed_by_id=actor_id,
            resolution_note=note,
        )
    )
    session.commit()
    if result.rowcount != 1:
        session.expire_all()
        raise HandoverError(f"action {action_id} was already resolved concurrently")
    session.expire_all()
    return session.get(ShiftHandoverAction, action_id)


def complete_action(
    session: Session, *, action_id: int, actor_id: int, note: Optional[str] = None
) -> ShiftHandoverAction:
    """Mark an action done. It then stops carrying forward."""
    return _resolve_action(
        session, action_id=action_id, actor_id=actor_id,
        new_status=HandoverActionStatus.DONE.value,
        note=(note.strip() if note and note.strip() else None),
    )


def cancel_action(
    session: Session, *, action_id: int, actor_id: int, reason: str
) -> ShiftHandoverAction:
    """Drop an action. The reason is mandatory — silent disappearance is the
    failure mode this whole record exists to prevent."""
    if not reason or not reason.strip():
        raise HandoverError("cancelling an action needs a reason")
    return _resolve_action(
        session, action_id=action_id, actor_id=actor_id,
        new_status=HandoverActionStatus.CANCELLED.value, note=reason.strip(),
    )


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def _changes_since_previous(session: Session, handover: ShiftHandover) -> dict:
    """Compare this snapshot against the previous accepted one.

    A metric absent from the baseline — an older snapshot shape, or one
    edited — reports ``delta: None`` and direction ``unknown``. Treating a
    missing baseline as zero would invent a change that never happened.
    """
    if handover.previous_handover_id is None:
        return {"baseline": None, "baseline_taken_at": None, "metrics": []}

    previous = session.get(ShiftHandover, handover.previous_handover_id)
    if previous is None:
        return {"baseline": None, "baseline_taken_at": None, "metrics": []}

    metrics = []
    for name, path, label in _CHANGE_METRICS:
        current = _dig(handover.snapshot, path)
        baseline = _dig(previous.snapshot, path)

        if isinstance(current, (int, float)) and isinstance(baseline, (int, float)):
            delta = current - baseline
            direction = "up" if delta > 0 else ("down" if delta < 0 else "flat")
        else:
            delta = None
            direction = "unknown"

        metrics.append(
            {
                "name": name,
                "label": label,
                "current": current,
                "baseline": baseline,
                "delta": delta,
                "direction": direction,
            }
        )

    return {
        "baseline": previous.id,
        "baseline_taken_at": (
            previous.snapshot_taken_at.isoformat()
            if previous.snapshot_taken_at else None
        ),
        "metrics": metrics,
    }


def get_handover(session: Session, handover_id: int) -> dict:
    """One handover with its actions, counts and changes since the baseline."""
    handover = _require(session, handover_id)
    now = _now()
    actions = [a.to_dict(now=now) for a in handover.actions]
    open_actions = [a for a in actions if a["status"] == HandoverActionStatus.OPEN.value]

    payload = handover.to_dict()
    payload.update(
        {
            "actions": actions,
            "action_count": len(actions),
            "open_action_count": len(open_actions),
            "overdue_action_count": sum(1 for a in actions if a["overdue"]),
            "unowned_action_count": sum(
                1 for a in open_actions if a["owner_id"] is None
            ),
            "carried_action_count": sum(
                1 for a in actions if a["carried_from_id"] is not None
            ),
            "snapshot": handover.snapshot or {},
            "changes_since_previous": _changes_since_previous(session, handover),
        }
    )
    return payload


def list_handovers(session: Session, limit: int = 25) -> list[dict]:
    """Recent handovers, newest first, each with its open-action count."""
    rows = session.execute(
        select(ShiftHandover).order_by(ShiftHandover.id.desc()).limit(limit)
    ).scalars().all()

    now = _now()
    out = []
    for handover in rows:
        actions = [a.to_dict(now=now) for a in handover.actions]
        payload = handover.to_dict()
        payload.update(
            {
                "action_count": len(actions),
                "open_action_count": sum(
                    1 for a in actions
                    if a["status"] == HandoverActionStatus.OPEN.value
                ),
                "overdue_action_count": sum(1 for a in actions if a["overdue"]),
            }
        )
        out.append(payload)
    return out


def handover_metrics(session: Session, limit: int = 50) -> dict:
    """The measures the review asks for.

        "Measure: unaccepted handovers, overdue transferred actions."

    A draft is not counted as unaccepted: nobody was asked to take it, so
    nobody failed to. A rejected handover is, because it was offered and not
    taken, and the work is still sitting with the outgoing lead.
    """
    now = _now()

    unaccepted_rows = session.execute(
        select(ShiftHandover)
        .where(
            ShiftHandover.status.in_(
                (HandoverStatus.SUBMITTED.value, HandoverStatus.REJECTED.value)
            )
        )
        .order_by(ShiftHandover.id.desc())
        .limit(limit)
    ).scalars().all()

    unaccepted = []
    for handover in unaccepted_rows:
        submitted = _aware(handover.submitted_at)
        unaccepted.append(
            {
                "id": handover.id,
                "status": handover.status,
                "outgoing_lead": (
                    handover.outgoing_lead.username if handover.outgoing_lead else None
                ),
                "incoming_lead": (
                    handover.incoming_lead.username if handover.incoming_lead else None
                ),
                "submitted_at": submitted.isoformat() if submitted else None,
                "waiting_hours": (
                    round((now - submitted).total_seconds() / 3600.0, 2)
                    if submitted else None
                ),
                "rejection_reason": handover.rejection_reason,
            }
        )

    open_actions = session.execute(
        select(ShiftHandoverAction)
        .where(ShiftHandoverAction.status == HandoverActionStatus.OPEN.value)
    ).scalars().all()

    overdue_actions = []
    unowned = 0
    for action in open_actions:
        payload = action.to_dict(now=now)
        if payload["owner_id"] is None:
            unowned += 1
        if payload["overdue"]:
            overdue_actions.append(payload)

    overdue_actions.sort(key=lambda a: (-a["carry_count"], a["due_at"] or ""))

    return {
        "as_of": now.isoformat(),
        "unaccepted_count": len(unaccepted),
        "unaccepted": unaccepted,
        "overdue_action_count": len(overdue_actions),
        "overdue_actions": overdue_actions[:limit],
        "open_action_count": len(open_actions),
        "unowned_action_count": unowned,
        "accepted_count": session.execute(
            select(func.count(ShiftHandover.id)).where(
                ShiftHandover.status == HandoverStatus.ACCEPTED.value
            )
        ).scalar() or 0,
    }


__all__ = [
    "HandoverError",
    "create_handover",
    "set_incoming_lead",
    "submit_handover",
    "accept_handover",
    "reject_handover",
    "add_action",
    "complete_action",
    "cancel_action",
    "get_handover",
    "list_handovers",
    "handover_metrics",
]
