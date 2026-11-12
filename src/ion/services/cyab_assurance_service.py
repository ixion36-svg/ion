"""Sign-off, review and accepted gaps for CyAB systems.

Every function takes the signed-in user, so a signature names who made it
rather than whatever was typed in a name box. Rules a caller can break
raise AssuranceError with a message fit to show that caller.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.cyab import CyabSystem
from ion.models.cyab_assurance import (
    ROLE_DEPARTMENT,
    ROLE_SOC,
    SIGNOFF_ROLES,
    CyabChecklistException,
    CyabSignoff,
)
from ion.models.cyab_doc_checklist import CyabDocChecklistItem
from ion.services import cyab_sal
from ion.services.cyab_readiness_service import compute

ROLE_REVIEW = "review"


class AssuranceError(ValueError):
    pass


def _who(user) -> str:
    return (getattr(user, "display_name", None) or getattr(user, "username", None) or "unknown").strip()


def sign(session: Session, system: CyabSystem, role: str, user, note: Optional[str] = None,
         today: Optional[date] = None) -> CyabSignoff:
    """Record one role's sign-off. Every step before sign-off must be complete."""
    today = today or date.today()
    if role not in SIGNOFF_ROLES:
        raise AssuranceError(f"Unknown sign-off role {role!r}")
    r = compute(session, system, today)
    blocking = [s for s in r.steps if s.key != "signoff" and not s.complete]
    if blocking:
        raise AssuranceError("Finish " + ", ".join(s.label.lower() for s in blocking) + " before signing off")

    name = _who(user)
    row = CyabSignoff(
        system_id=system.id, role=role, user_id=getattr(user, "id", None), signer_name=name,
        sal_tier=r.sal, readiness_pct=r.pct, note=(note or "").strip() or None,
    )
    session.add(row)
    if role == ROLE_DEPARTMENT:
        system.sign_dept_name, system.sign_dept_date = name, today
    elif role == ROLE_SOC:
        system.sign_soc_name, system.sign_soc_date = name, today

    signed = set(r.signed_roles) | {role}
    if signed >= set(SIGNOFF_ROLES):
        _start_review_cycle(system, r.sal, today)
        system.status = "ACTIVE"
    session.commit()
    return row


def mark_reviewed(session: Session, system: CyabSystem, user, note: Optional[str] = None,
                  today: Optional[date] = None) -> CyabSignoff:
    """Close a review: the system is still as signed off, until the next one."""
    today = today or date.today()
    r = compute(session, system, today)
    if r.stage not in ("signed", "review_due"):
        raise AssuranceError("Only a signed-off system can be marked reviewed")
    row = CyabSignoff(
        system_id=system.id, role=ROLE_REVIEW, user_id=getattr(user, "id", None),
        signer_name=_who(user), sal_tier=r.sal, readiness_pct=r.pct,
        note=(note or "").strip() or None,
    )
    session.add(row)
    _start_review_cycle(system, r.sal, today)
    session.commit()
    return row


def _start_review_cycle(system: CyabSystem, sal: str, today: date) -> None:
    days = cyab_sal.REVIEW_DAYS[sal]
    system.review_cadence_days = days
    system.last_reviewed_date = today
    system.next_review_date = today + timedelta(days=days)


def history(session: Session, system_id: int) -> List[CyabSignoff]:
    return list(session.scalars(
        select(CyabSignoff).where(CyabSignoff.system_id == system_id)
        .order_by(CyabSignoff.signed_at.desc(), CyabSignoff.id.desc())
    ))


def accept_gap(session: Session, item: CyabDocChecklistItem, reason: str, approver: str,
               until: date, user, today: Optional[date] = None) -> CyabChecklistException:
    """Accept a missing document for a stated reason until a date.

    The longest an acceptance may run is set by the system's SAL, as is the
    role expected to approve it (CyAB_SAL.md 12.2).
    """
    today = today or date.today()
    system = session.get(CyabSystem, item.system_id)
    sal = cyab_sal.normalise(system.sal_tier if system else None)
    reason, approver = (reason or "").strip(), (approver or "").strip()
    if not reason:
        raise AssuranceError("Give a reason for accepting the gap")
    if not approver:
        raise AssuranceError(f"Name the approver ({cyab_sal.APPROVER[sal]} at {sal})")
    if until <= today:
        raise AssuranceError("The acceptance must end after today")
    longest = cyab_sal.MAX_EXCEPTION_DAYS[sal]
    if until > today + timedelta(days=longest):
        raise AssuranceError(f"At {sal} a gap can be accepted for at most {longest} days")
    if active_exception(session, item.id, today) is not None:
        raise AssuranceError("This gap is already accepted; revoke that first")
    row = CyabChecklistException(
        item_id=item.id, system_id=item.system_id, reason=reason, approver=approver,
        accepted_by_id=getattr(user, "id", None), until=until,
    )
    session.add(row)
    session.commit()
    return row


def revoke_gap(session: Session, exc: CyabChecklistException) -> None:
    if exc.revoked_at is None:
        exc.revoked_at = datetime.utcnow()
        session.commit()


def active_exception(session: Session, item_id: int,
                     today: Optional[date] = None) -> Optional[CyabChecklistException]:
    today = today or date.today()
    return session.scalars(
        select(CyabChecklistException).where(
            CyabChecklistException.item_id == item_id,
            CyabChecklistException.revoked_at.is_(None),
            CyabChecklistException.until >= today,
        ).order_by(CyabChecklistException.id.desc())
    ).first()


def exceptions_for_system(session: Session, system_id: int) -> List[CyabChecklistException]:
    return list(session.scalars(
        select(CyabChecklistException).where(CyabChecklistException.system_id == system_id)
        .order_by(CyabChecklistException.id.desc())
    ))


def activity(session: Session, system_id: Optional[int] = None, limit: int = 50) -> List[dict]:
    """What people did to CyAB systems, newest first.

    Sign-offs, reviews, accepted and revoked gaps, checklist edits and new
    systems, each read with its own bounded query and merged.
    """
    from ion.models.user import User

    def scoped(stmt, col):
        return stmt.where(col == system_id) if system_id is not None else stmt

    events: List[dict] = []
    for row in session.scalars(scoped(select(CyabSignoff), CyabSignoff.system_id)
                               .order_by(CyabSignoff.signed_at.desc()).limit(limit)):
        text = "marked reviewed" if row.role == ROLE_REVIEW else (
            "signed off as " + ("department" if row.role == ROLE_DEPARTMENT else "SOC"))
        events.append({"at": row.signed_at, "user_id": row.user_id, "who": row.signer_name,
                       "system_id": row.system_id, "text": text, "kind": "signoff", "note": row.note})

    excs = list(session.scalars(scoped(select(CyabChecklistException), CyabChecklistException.system_id)
                                .order_by(CyabChecklistException.id.desc()).limit(limit)))
    labels = {}
    if excs:
        labels = dict(session.execute(
            select(CyabDocChecklistItem.id, CyabDocChecklistItem.label)
            .where(CyabDocChecklistItem.id.in_({e.item_id for e in excs}))
        ).all())
    for e in excs:
        label = labels.get(e.item_id, "a document")
        events.append({"at": e.created_at, "user_id": e.accepted_by_id, "who": None,
                       "system_id": e.system_id, "kind": "exception", "note": e.reason,
                       "text": f"accepted the {label} gap until {e.until:%d %b %Y} ({e.approver})"})
        if e.revoked_at:
            events.append({"at": e.revoked_at, "user_id": None, "who": None, "system_id": e.system_id,
                           "kind": "exception", "note": None, "text": f"revoked the {label} acceptance"})

    for item in session.scalars(scoped(select(CyabDocChecklistItem), CyabDocChecklistItem.system_id)
                                .where(CyabDocChecklistItem.updated_by_id.is_not(None))
                                .order_by(CyabDocChecklistItem.updated_at.desc()).limit(limit)):
        events.append({"at": item.updated_at, "user_id": item.updated_by_id, "who": None,
                       "system_id": item.system_id, "kind": "checklist", "note": None,
                       "text": f"set {item.label} to {item.status.replace('_', ' ')}"})

    for sys in session.scalars(scoped(select(CyabSystem), CyabSystem.id)
                               .order_by(CyabSystem.created_at.desc()).limit(limit)):
        events.append({"at": sys.created_at, "user_id": sys.created_by, "who": None,
                       "system_id": sys.id, "kind": "system", "note": None, "text": "onboarded the system"})

    events = [e for e in events if e["at"] is not None]
    events.sort(key=lambda e: e["at"], reverse=True)
    events = _collapse_checklist_runs(events)[:limit]

    user_ids = {e["user_id"] for e in events if e["user_id"] and not e["who"]}
    names = {}
    if user_ids:
        for u in session.scalars(select(User).where(User.id.in_(user_ids))):
            names[u.id] = u.display_name or u.username
    sys_ids = {e["system_id"] for e in events}
    systems = dict(session.execute(select(CyabSystem.id, CyabSystem.name).where(CyabSystem.id.in_(sys_ids))).all()) if sys_ids else {}
    for e in events:
        e["who"] = e["who"] or names.get(e["user_id"]) or "someone"
        e["system"] = systems.get(e["system_id"], f"#{e['system_id']}")
    return events


def _collapse_checklist_runs(events: List[dict], window: timedelta = timedelta(minutes=15)) -> List[dict]:
    """One line for a burst of document edits by one person on one system.

    Walking a checklist sets a dozen statuses in a few minutes, and a line
    each pushes everything else off the feed.
    """
    out: List[dict] = []
    for e in events:
        last = out[-1] if out else None
        if (last and e["kind"] == "checklist" and last["kind"] == "checklist"
                and last["system_id"] == e["system_id"] and last["user_id"] == e["user_id"]
                and last["run_start"] - e["at"] <= window):
            last["count"] += 1
            last["text"] = f"updated {last['count']} documents"
            continue
        out.append({**e, "run_start": e["at"], "count": 1})
    return out
