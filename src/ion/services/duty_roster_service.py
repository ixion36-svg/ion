"""Assigning and reading the weekly duty rota.

The thing this has to get right is the empty week. A duty rota's failure
mode is not a wrong name against a week -- somebody notices that on the
Monday. It is a week with no name at all, which looks exactly like a week
nobody has scrolled to, and quietly becomes the week the standup did not
happen.

So every read returns the week whether or not anybody holds it, says so
in words a caller can put on a screen, and counts the unfilled ones.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta
from typing import List, Optional

from sqlalchemy.orm import Session

from ion.models.duty_roster import (
    DUTIES,
    DUTY_ANALYST,
    DUTY_DESCRIPTIONS,
    DutyAssignment,
)
from ion.models.user import AuditLog, User

logger = logging.getLogger(__name__)


class DutyError(ValueError):
    """A refused assignment. The message is shown to the operator."""


def week_of(day: date) -> date:
    """The Monday of ``day``'s week.

    Every week_start is normalised through here. Without it a rota ends up
    with overlapping weeks that each look valid on their own, and two
    people are both "this week".
    """
    return day - timedelta(days=day.weekday())


def _person(session: Session, user_id: Optional[int]) -> Optional[dict]:
    if not user_id:
        return None
    user = session.get(User, user_id)
    if user is None:
        return {"id": user_id, "name": f"user {user_id}", "username": None}
    return {
        "id": user.id,
        "name": user.display_name or user.username,
        "username": user.username,
    }


def for_week(session: Session, *, duty: str = DUTY_ANALYST,
             week_start: date) -> Optional[DutyAssignment]:
    """The assignment for a week, or None."""
    return (
        session.query(DutyAssignment)
        .filter(DutyAssignment.duty == duty,
                DutyAssignment.week_start == week_of(week_start))
        .one_or_none()
    )


def _week_view(session: Session, duty: str, week_start: date) -> dict:
    """One week, assigned or not.

    Returns a row either way. A caller that only ever sees assigned weeks
    cannot tell an unfilled week from one it has not loaded.
    """
    row = for_week(session, duty=duty, week_start=week_start)
    monday = week_of(week_start)
    if row is None:
        return {
            "duty": duty,
            "week_start": monday.isoformat(),
            "assigned": False,
            "user": None,
            "acknowledged": False,
            "summary": (
                f"Nobody is on {duty.replace('_', ' ')} duty for the week of "
                f"{monday:%d %b}."
            ),
        }
    return {
        "duty": duty,
        "week_start": monday.isoformat(),
        "assigned": True,
        "assignment_id": row.id,
        "user": _person(session, row.user_id),
        "acknowledged": row.acknowledged_at is not None,
        "notes": row.notes,
        "summary": (
            f"{(_person(session, row.user_id) or {}).get('name')} is on "
            f"{duty.replace('_', ' ')} duty for the week of {monday:%d %b}."
        ),
    }


def current(session: Session, *, duty: str = DUTY_ANALYST,
            today: Optional[date] = None) -> dict:
    """Who holds the duty this week.

    Scoped to this week only. Carrying a stale name forward is worse than
    showing nobody: it says somebody is covering when they think they
    finished on Friday.
    """
    return _week_view(session, duty, today or date.today())


def upcoming(session: Session, *, duty: str = DUTY_ANALYST, weeks: int = 6,
             today: Optional[date] = None) -> List[dict]:
    """This week and the next few, filled or not."""
    start = week_of(today or date.today())
    return [
        _week_view(session, duty, start + timedelta(days=7 * n))
        for n in range(max(1, weeks))
    ]


def rota_summary(session: Session, *, duty: str = DUTY_ANALYST,
                 weeks: int = 6, today: Optional[date] = None) -> dict:
    """The coming weeks, with how many have nobody against them."""
    rows = upcoming(session, duty=duty, weeks=weeks, today=today)
    unfilled = [r for r in rows if not r["assigned"]]
    return {
        "duty": duty,
        "description": DUTY_DESCRIPTIONS.get(duty, ""),
        "weeks": rows,
        "unfilled": len(unfilled),
        "next_unfilled": unfilled[0]["week_start"] if unfilled else None,
    }


def _same_person(a: str, b: str) -> bool:
    """Tolerant comparison of two typed names."""
    return " ".join((a or "").split()).casefold() == \
           " ".join((b or "").split()).casefold()


def standup_attribution(session: Session, *, signatory_name: str,
                        signatory_user_id: Optional[int] = None,
                        duty: str = DUTY_ANALYST,
                        today: Optional[date] = None) -> dict:
    """Who was on the rota for the standup, and who actually signed it.

    Reports rather than enforces. A duty holder off sick must not block
    the standup, so anybody may run it -- but the record names both
    people and says when they differ, because a rota nobody follows is
    not a rota, and writing it down each day is the only way anybody
    finds that out.

    ``matches_rota`` is deliberately three-valued:

    * ``None``  nobody is on the rota this week. Not a mismatch -- there
                is nothing to match against, and calling it a breach
                would blame whoever did step up.
    * ``True``  the person on the rota signed it.
    * ``False`` somebody else signed, or nobody did.

    Matching prefers the signed-in user id over the typed name, because
    the name is a free-text box and a typo in it is not a rota breach.
    """
    today = today or date.today()
    week = _week_view(session, duty, today)
    signed_by = (signatory_name or "").strip() or None

    holder = week.get("user") or {}
    label = duty.replace("_", " ")

    if not week["assigned"]:
        note = (
            f"Nobody was on {label} duty for the week of "
            f"{week['week_start']}"
            + (f"; {signed_by} signed the standup." if signed_by
               else ", and the standup is not signed.")
        )
        matches = None
    elif signed_by is None:
        # An empty signature box must not read as "the duty holder did
        # it" merely because nobody contradicted the rota.
        note = (
            f"{holder.get('name')} is on {label} duty, but the standup "
            f"is not signed."
        )
        matches = False
    else:
        matches = bool(
            (signatory_user_id is not None
             and signatory_user_id == holder.get("id"))
            or _same_person(signed_by, holder.get("name") or "")
        )
        note = (
            f"{holder.get('name')} is on {label} duty and signed the "
            f"standup."
            if matches else
            f"{signed_by} ran the standup; {holder.get('name')} is on "
            f"{label} duty this week."
        )

    return {
        "duty": week,
        "signed_by": signed_by,
        "signed_by_user_id": signatory_user_id,
        "matches_rota": matches,
        "note": note,
    }


def assign(session: Session, *, duty: str = DUTY_ANALYST, week_start: date,
           user: User, actor: User, notes: str = "") -> DutyAssignment:
    """Put somebody on duty for a week, replacing whoever was on it.

    Replaces rather than adds: two names against one week is not
    redundancy, it is nobody knowing which of them is doing it.
    """
    if not actor.has_permission("workforce:manage"):
        raise DutyError("Permission denied")
    if duty not in DUTIES:
        raise DutyError(
            f"{duty!r} is not a duty this SOC rosters. Known: "
            f"{', '.join(DUTIES)}."
        )
    if not getattr(user, "is_active", False):
        # Rostering somebody who has left reads as covered until the
        # Monday it is not.
        raise DutyError(
            f"{user.username} is not an active account, so cannot be put on "
            f"duty."
        )

    monday = week_of(week_start)
    row = for_week(session, duty=duty, week_start=monday)
    if row is None:
        row = DutyAssignment(duty=duty, week_start=monday, user_id=user.id)
        session.add(row)
    else:
        row.user_id = user.id
        # A replacement has not been acknowledged by the new holder, even
        # if the previous one had acknowledged it.
        row.acknowledged_at = None
    row.assigned_by_id = actor.id
    row.notes = notes.strip() or None
    session.flush()

    session.add(AuditLog(
        user_id=actor.id, action="duty_assigned",
        resource_type="duty_assignment", resource_id=row.id,
        details=f"{actor.username} put {user.username} on {duty} for the "
                f"week of {monday.isoformat()}",
    ))
    session.commit()
    return row


def acknowledge(session: Session, *, assignment_id: int,
                actor: User) -> DutyAssignment:
    """The holder confirms they have picked it up.

    Only the holder. A rota entry nobody acknowledged is a plan rather
    than a fact, and the difference matters on the Monday somebody is off
    sick -- a lead ticking it on their behalf erases exactly that signal.
    """
    row = session.get(DutyAssignment, assignment_id)
    if row is None:
        raise DutyError(f"No duty assignment {assignment_id}")
    if row.user_id != actor.id:
        raise DutyError(
            "Only the person on duty can acknowledge it. An entry nobody "
            "acknowledged is a plan, not a fact."
        )
    row.acknowledged_at = datetime.utcnow()
    session.commit()
    return row


def clear(session: Session, *, duty: str = DUTY_ANALYST, week_start: date,
          actor: User) -> bool:
    """Take somebody off duty for a week, leaving it visibly unfilled."""
    if not actor.has_permission("workforce:manage"):
        raise DutyError("Permission denied")
    row = for_week(session, duty=duty, week_start=week_start)
    if row is None:
        return False
    session.add(AuditLog(
        user_id=actor.id, action="duty_cleared",
        resource_type="duty_assignment", resource_id=row.id,
        details=f"{actor.username} cleared {duty} for the week of "
                f"{week_of(week_start).isoformat()}",
    ))
    session.delete(row)
    session.commit()
    return True
