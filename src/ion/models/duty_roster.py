"""Who is on duty this week.

Distinct from the establishment and from the shift rota. A post says the
SOC needs an L2; a shift says who is working Tuesday night. A duty says
who carries a named responsibility for a week -- running the daily
standup, being the first name on a callout list -- regardless of which
posts they hold or which shifts they work.

Weekly, and anchored to a Monday. A duty that changes mid-week is a duty
nobody can be sure they hold, and "whoever is around" is how the standup
quietly stops happening.

One person per duty per week. A rota with two names against a week does
not mean redundancy, it means nobody knows which of them is doing it.
"""

from datetime import date, datetime
from typing import Optional

from sqlalchemy import (
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base, TimestampMixin

#: The duties a SOC rosters weekly. Deliberately a short list rather than
#: free text: a duty nobody recognises the name of is a duty nobody picks
#: up, and two spellings of the same one split the rota in half.
DUTY_ANALYST = "duty_analyst"
DUTIES = (DUTY_ANALYST,)

#: What each duty actually involves, shown next to the name so somebody
#: coming on duty does not have to ask.
DUTY_DESCRIPTIONS = {
    DUTY_ANALYST: (
        "Runs the daily standup, owns the queue's shape for the week, and "
        "is the first point of contact for anything that does not have an "
        "obvious owner."
    ),
}


class DutyAssignment(Base, TimestampMixin):
    """One person holding one duty for one week."""

    __tablename__ = "duty_assignments"
    __table_args__ = (
        # One holder per duty per week. Two names against a week is not
        # redundancy, it is nobody knowing which of them is doing it.
        UniqueConstraint("duty", "week_start", name="uq_duty_week"),
        Index("ix_duty_week", "week_start"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True,
                                    autoincrement=True)
    duty: Mapped[str] = mapped_column(String(32), nullable=False,
                                      default=DUTY_ANALYST)
    #: Always a Monday. Normalised on write, so a rota cannot end up with
    #: overlapping weeks that each look valid on their own.
    week_start: Mapped[date] = mapped_column(Date, nullable=False)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    assigned_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    #: When the holder confirmed they have picked it up. A rota entry
    #: nobody acknowledged is a plan, not a fact, and the difference
    #: matters on the Monday somebody is off sick.
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "duty": self.duty,
            "week_start": self.week_start.isoformat() if self.week_start else None,
            "user_id": self.user_id,
            "assigned_by_id": self.assigned_by_id,
            "notes": self.notes,
            "acknowledged_at": (
                self.acknowledged_at.isoformat() if self.acknowledged_at else None
            ),
        }
