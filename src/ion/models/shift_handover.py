"""Persisted shift handovers: an accountable transfer, not a generated report.

From the 8 Oct 2026 feature review (§17):

    "Observed gap: handover generates a report rather than persisting an
    accountable transfer with incoming acceptance and owned actions."

``generate_shift_report`` recomputed a view of the last N hours on every
call. Nothing was stored, so there was no answer to "what did the night shift
hand us", no record that anyone took the handover, and no owner for the work
that crossed the boundary. Two shifts could each believe the other was
carrying a case.

Two tables:

``shift_handovers``
    One transfer. Holds a **frozen** snapshot of the shift report, with the
    timestamp it was taken at, because a report recomputed at read time shows
    the estate as it is now rather than as it was when the shift ended — and
    the numbers the outgoing lead signed off on are the accountable ones.
    ``previous_handover_id`` points at the last *accepted* handover, which is
    what "changes since the last accepted handover" is measured against.

``shift_handover_actions``
    Work crossing the boundary, with an owner, a deadline and a case. An
    action still open when the next handover is created is carried forward as
    a new row linked by ``carried_from_id``, with ``carry_count`` incremented,
    so a task that crossed three shifts looks like one rather than like three
    unrelated tasks.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from ion.models.user import User


def _iso_utc(value: Optional[datetime]) -> Optional[str]:
    """ISO-8601 with an explicit UTC offset.

    These columns store naive UTC. Emitting a bare "2026-10-07T21:20:00"
    makes ``new Date(...)`` in the browser read it as *local* time, so a
    shift recorded at 21:20 UTC renders as 21:20 in BST instead of 22:20 --
    an hour out, silently, and only visible beside another timestamp that
    was serialised correctly. Found by rendering the page next to the live
    shift report, which does carry an offset.
    """
    if value is None:
        return None
    aware = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return aware.isoformat()


class HandoverStatus(str, Enum):
    """Where a transfer has got to.

    ``DRAFT`` is editable by the outgoing lead. ``SUBMITTED`` is offered to
    the incoming shift and is the state that counts as *unaccepted* in the
    metrics. ``ACCEPTED`` is the accountable end state and is closed to
    edits. ``REJECTED`` goes back to the outgoing lead with a reason and can
    be resubmitted.
    """

    DRAFT = "draft"
    SUBMITTED = "submitted"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class HandoverActionStatus(str, Enum):
    OPEN = "open"
    DONE = "done"
    CANCELLED = "cancelled"


class ShiftHandover(Base, TimestampMixin):
    """One shift-to-shift transfer, with its frozen operational snapshot."""

    __tablename__ = "shift_handovers"
    __table_args__ = (
        Index("ix_shift_handovers_status", "status"),
        Index("ix_shift_handovers_shift_end", "shift_end"),
        Index("ix_shift_handovers_outgoing", "outgoing_lead_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    shift_start: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    shift_end: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    shift_hours: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    outgoing_lead_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    # Not known at draft time in every SOC, so nullable — but required before
    # the handover can be submitted. A transfer needs someone on the other end.
    incoming_lead_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=HandoverStatus.DRAFT.value
    )
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    #: The shift report as it stood when the handover was raised, including
    #: per-source `as_of` timestamps. Never recomputed.
    snapshot: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    snapshot_taken_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True
    )

    submitted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    accepted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    accepted_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    #: False when someone other than the named incoming lead accepted. The
    #: named lead going off sick must not block the shift, but the record has
    #: to say who actually took it — that is the accountable fact.
    accepted_by_designated_lead: Mapped[Optional[bool]] = mapped_column(
        Boolean, nullable=True
    )
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    #: The last *accepted* handover when this one was created. A draft nobody
    #: accepted is not a baseline.
    previous_handover_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("shift_handovers.id", ondelete="SET NULL"), nullable=True
    )

    outgoing_lead: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[outgoing_lead_id]
    )
    incoming_lead: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[incoming_lead_id]
    )
    accepted_by: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[accepted_by_id]
    )
    actions: Mapped[list["ShiftHandoverAction"]] = relationship(
        "ShiftHandoverAction",
        back_populates="handover",
        cascade="all, delete-orphan",
        order_by="ShiftHandoverAction.id",
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "status": self.status,
            "shift_start": _iso_utc(self.shift_start),
            "shift_end": _iso_utc(self.shift_end),
            "shift_hours": self.shift_hours,
            "outgoing_lead_id": self.outgoing_lead_id,
            "outgoing_lead": self.outgoing_lead.username if self.outgoing_lead else None,
            "incoming_lead_id": self.incoming_lead_id,
            "incoming_lead": self.incoming_lead.username if self.incoming_lead else None,
            "summary": self.summary,
            "snapshot_taken_at": _iso_utc(self.snapshot_taken_at),
            "submitted_at": _iso_utc(self.submitted_at),
            "accepted_at": _iso_utc(self.accepted_at),
            "accepted_by_id": self.accepted_by_id,
            "accepted_by": self.accepted_by.username if self.accepted_by else None,
            "accepted_by_designated_lead": self.accepted_by_designated_lead,
            "rejection_reason": self.rejection_reason,
            "previous_handover_id": self.previous_handover_id,
            "created_at": _iso_utc(self.created_at),
        }


class ShiftHandoverAction(Base, TimestampMixin):
    """A piece of work crossing the shift boundary, with an owner."""

    __tablename__ = "shift_handover_actions"
    __table_args__ = (
        Index("ix_shift_handover_actions_handover", "handover_id"),
        Index("ix_shift_handover_actions_status", "status"),
        Index("ix_shift_handover_actions_owner", "owner_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    handover_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("shift_handovers.id", ondelete="CASCADE"), nullable=False
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    # Nullable on purpose: an unowned action is a real state and worth
    # surfacing as a gap, rather than forcing a false owner at creation.
    owner_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    due_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    case_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("alert_cases.id", ondelete="SET NULL"), nullable=True
    )

    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=HandoverActionStatus.OPEN.value
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    resolution_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    #: The action row on the previous handover this was carried from.
    carried_from_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("shift_handover_actions.id", ondelete="SET NULL"),
        nullable=True,
    )
    #: How many shift boundaries this work has crossed. 0 on first creation.
    carry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    handover: Mapped["ShiftHandover"] = relationship(
        "ShiftHandover", back_populates="actions"
    )
    owner: Mapped[Optional["User"]] = relationship("User", foreign_keys=[owner_id])
    completed_by: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[completed_by_id]
    )

    def to_dict(self, *, now: Optional[datetime] = None) -> dict:
        from datetime import timezone as _tz

        reference = now or datetime.now(_tz.utc)
        due = self.due_at
        if due is not None and due.tzinfo is None:
            # Stored naive UTC. Comparing a naive value against an aware one
            # raises, and assuming local time would shift every deadline.
            due = due.replace(tzinfo=_tz.utc)

        # No deadline means no deadline, not an immediately breached one. A
        # done or cancelled action is not overdue whatever its deadline said.
        overdue = bool(
            due is not None
            and self.status == HandoverActionStatus.OPEN.value
            and due < reference
        )

        return {
            "id": self.id,
            "handover_id": self.handover_id,
            "description": self.description,
            "owner_id": self.owner_id,
            "owner": self.owner.username if self.owner else None,
            "due_at": due.isoformat() if due else None,
            "case_id": self.case_id,
            "status": self.status,
            "overdue": overdue,
            "completed_at": _iso_utc(self.completed_at),
            "completed_by_id": self.completed_by_id,
            "completed_by": self.completed_by.username if self.completed_by else None,
            "resolution_note": self.resolution_note,
            "carried_from_id": self.carried_from_id,
            "carry_count": self.carry_count,
            "created_by_id": self.created_by_id,
        }


__all__ = [
    "HandoverStatus",
    "HandoverActionStatus",
    "ShiftHandover",
    "ShiftHandoverAction",
]
