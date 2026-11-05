"""The lead's roster and verification queue, as one fragment.

The page stacked three unrelated jobs on one scroll: the queue of items
waiting on a verifier, a table of everyone, and an always-open form for
starting somebody's offboarding. Only the first is what a lead opens this
page to do, and it was the shortest thing on it.

So the three are tabs here, the queue first, and the numbers that say
whether the lead needs to act at all are above them. The roster also gained
a search box, because it was an unfiltered table of every active user and
stopped being readable somewhere around thirty people.

Nothing is re-queried by hand. The three reads call the same functions
/api/workforce/{verification-queue,people,leavers} call -- the endpoint
functions themselves, with the session and user passed in -- because the
roster's shape is assembled in the endpoint rather than in a service, and a
second copy of that assembly here is the drift this avoids. Permission is
enforced by this router's own dependencies, which mirror the JSON ones:
read and verify to look, manage to write.
"""
from __future__ import annotations

import logging
from datetime import date
from typing import Any, Callable, Optional

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.models.workforce import LeaverRecord
from ion.services import workforce_service as wf
from ion.storage.database import get_db_session
from ion.web.ui._shared import age_label, render_view

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/workforce_people.html"

TABS = ("queue", "everyone", "offboarding")

#: What each requirement status says on a LEAD's screen, and its tone.
#:
#: Deliberately not the joiner's wording from ui.workforce_journey: there,
#: a submitted item reads "Awaiting your lead", which on the lead's own
#: checklist would point at the wrong person.
ITEM_VIEW: dict[str, tuple[str, str]] = {
    "verified": ("Verified", "bg-success"),
    "waived": ("Waived", "bg-success"),
    "equivalent": ("Met by assessment", "bg-success"),
    "submitted": ("Waiting on you", "bg-warning"),
    "expired": ("Lapsed", "bg-error"),
    "pending": ("Not started", "bg-base-content/30"),
}

#: The journey stages a roster row shows, in the words a lead reads, with
#: the badge each one carries.
STAGE_VIEW: dict[str, tuple[str, str]] = {
    "pre_access": ("Pre-access", "badge-warning"),
    "role_training": ("Role training", "badge-info"),
    "operational": ("Operational", "badge-success"),
    "suspended": ("Suspended", "badge-error"),
    "withdrawn": ("Withdrawn", "badge-error"),
    "closed": ("Closed", "badge-ghost"),
}


def _matches(person: dict[str, Any], needle: str) -> bool:
    """Whether a roster row matches the search box.

    Name, username, the roles they hold and the roles they are onboarding
    into, because a lead searching "L2" means the role and a lead searching
    a surname means the person, and asking them which is which would be a
    filter nobody uses.
    """
    if not needle:
        return True
    hay = " ".join([
        str(person.get("name") or ""),
        str(person.get("username") or ""),
        str(person.get("target_role") or ""),
        " ".join(person.get("ion_roles") or []),
        " ".join(str(j.get("role") or "") for j in person.get("journeys") or []),
    ]).lower()
    return needle.lower() in hay


def _attach_checklists(session: Session, everyone: list[dict[str, Any]]) -> None:
    """Hang each journey's own items off it, as that person's checklist.

    The roster said "gate 1 of 3" and stopped, so a lead who wanted to know
    WHICH one of the three was outstanding had to go and ask. The counts
    answer "is this person behind"; only the items answer "on what".

    journey_summary does not carry the rows, so they are read here -- in one
    query over every journey on the page, not one per person, which is the
    rule the roster endpoint itself keeps. Journeys are keyed by the `id`
    that journey_summary already returns.
    """
    from ion.models.workforce import JourneyRequirement

    journeys = [j for p in everyone for j in (p.get("journeys") or [])]
    ids = [j["id"] for j in journeys if j.get("id") is not None]
    if not ids:
        return

    by_journey: dict[int, list[dict[str, Any]]] = {}
    rows = (
        session.query(JourneyRequirement)
        .filter(JourneyRequirement.journey_id.in_(ids))
        .all()
    )
    for r in rows:
        label, dot = ITEM_VIEW.get(r.status, ITEM_VIEW["pending"])
        by_journey.setdefault(r.journey_id, []).append({
            "id": r.id,
            "name": r.name,
            "kind": r.kind,
            "phase": r.phase,
            "status": r.status,
            "label": label,
            "dot": dot,
            "satisfied": r.satisfied,
        })

    # Gate before readiness, and within each the unfinished first: a lead
    # reading a checklist is looking for what is outstanding, so sorting
    # verified items to the bottom puts the answer at the top.
    # Keyed `checklist`, not `items`: Jinja resolves `j.items` on a dict to
    # the dict's own .items method, so the template silently iterated a
    # bound method and raised instead of listing anything.
    for j in journeys:
        rows_for = by_journey.get(j["id"], [])
        rows_for.sort(key=lambda r: (r["phase"] != "gate", r["satisfied"], r["name"]))
        j["checklist"] = rows_for


def _view(
    session: Session,
    user: User,
    tab: str = "queue",
    q: str = "",
    error: str = "",
) -> dict[str, Any]:
    """Everything the page shows, for whichever tab is open.

    All three reads happen whatever the tab, because the counts above the
    tabs come from all three and a lead who cannot see "4 waiting" until
    they click the right tab has not been told anything.
    """
    from ion.web.workforce_api import list_leavers, people, verification_queue

    if tab not in TABS:
        tab = "queue"

    try:
        queue = verification_queue(session=session, _user=user)
        roster = people(session=session, _user=user)
        leavers = list_leavers(session=session, _user=user)
    except Exception:
        logger.exception("Workforce people fragment could not be rendered")
        return {
            "failed": True, "error": "", "tab": tab, "q": q,
            "items": [], "people": [], "all_people": [], "leavers": [],
            "stage_view": STAGE_VIEW,
            "awaiting": 0, "blocked": 0, "overdue": 0, "operational": 0,
            "can_manage": False, "total_people": 0,
        }

    items = list(queue.get("items") or [])
    for i in items:
        # How long it has sat with the lead. A difference between two
        # instants, so unlike a clock time it carries no timezone claim and
        # is safe to render server-side.
        i["waiting"] = age_label(i.get("submitted_at"))

    everyone = list(roster.get("people") or [])
    _attach_checklists(session, everyone)

    blocked = sum(1 for p in everyone if p.get("has_access") is False)
    overdue = 0
    operational = 0
    for p in everyone:
        for j in p.get("journeys") or []:
            stage = j.get("stage")
            if stage == "operational":
                operational += 1
            # Only a running journey can be behind. A suspended one has a
            # lapsed item, which is a different problem with a different
            # remedy, and counting it here would put a number above the
            # tabs that the roster below does not show against any row.
            elif stage in ("pre_access", "role_training") and (
                j.get("days_elapsed", 0) > j.get("target_days", 0)
            ):
                overdue += 1

    return {
        "failed": False,
        "error": error,
        "tab": tab,
        "q": q,
        "items": items,
        "people": [p for p in everyone if _matches(p, q)],
        # Unfiltered, for the offboarding tab's person list. That select
        # must offer everybody whatever the roster search happens to hold,
        # or a search narrows who can be offboarded.
        "all_people": everyone,
        "total_people": len(everyone),
        "leavers": list(leavers.get("leavers") or []),
        "stage_view": STAGE_VIEW,
        "awaiting": queue.get("count") or 0,
        "blocked": blocked,
        "overdue": overdue,
        "operational": operational,
        "can_manage": user.has_permission("workforce:manage"),
    }


@router.get(
    "/workforce/people",
    dependencies=[Depends(require_permission("workforce:verify"))],
)
def people_fragment(
    request: Request,
    tab: str = "queue",
    q: str = "",
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """The queue, the roster and offboarding, with one of them open."""
    return render_view(request, FRAGMENT, _view(session, user, tab, q))


def _write(
    request: Request,
    session: Session,
    user: User,
    action: Callable[[], Any],
    tab: str,
    q: str = "",
):
    """Run one write, then re-render from the database.

    A verification can clear somebody's gate and grant them system access,
    which changes the roster and three of the four counts, so the whole
    fragment is re-read rather than the row patched. Refusals come back in
    the markup: the page reported them through `alert()`, which names no
    row and leaves the stale state on screen behind the dialog.
    """
    error = ""
    try:
        action()
    except wf.WorkforceError as exc:
        error = str(exc)
    except ValueError as exc:
        error = str(exc)
    return render_view(request, FRAGMENT, _view(session, user, tab, q, error))


def _requirement(session: Session, requirement_id: int):
    from ion.models.workforce import JourneyRequirement

    req = session.get(JourneyRequirement, requirement_id)
    if req is None:
        raise wf.WorkforceError("That item no longer exists. Reload the page.")
    return req


@router.post(
    "/workforce/requirements/{requirement_id}/verify",
    dependencies=[Depends(require_permission("workforce:verify"))],
)
def verify(
    request: Request,
    requirement_id: int,
    evidence_ref: str = Form(""),
    tab: str = Form("queue"),
    q: str = Form(""),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Accept one submitted item.

    `tab` and `q` come back from the form because the same button exists in
    two places: the queue, and a person's checklist on the roster. Sending
    the roster's caller back to the queue would throw away the search they
    were part-way through.
    """
    def run():
        req = _requirement(session, requirement_id)
        wf.verify_requirement(
            session, requirement=req, verifier=user,
            evidence_ref=evidence_ref or (req.evidence_ref or ""),
            expires_on=None,
        )

    return _write(request, session, user, run, tab, q)


@router.post(
    "/workforce/requirements/{requirement_id}/send-back",
    dependencies=[Depends(require_permission("workforce:verify"))],
)
def send_back(
    request: Request,
    requirement_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Put one item back to the person who submitted it.

    The same withdraw the submitter has. Named for what it is from this
    side of the queue, because "withdraw" on a lead's screen reads as the
    lead retracting something of their own.
    """
    def run():
        wf.withdraw_submission(
            session, requirement=_requirement(session, requirement_id), actor=user,
        )

    return _write(request, session, user, run, "queue")


@router.post(
    "/workforce/leavers",
    dependencies=[Depends(require_permission("workforce:manage"))],
)
def start_offboarding(
    request: Request,
    user_id: int = Form(...),
    last_working_day: str = Form(""),
    reason: str = Form(""),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Open an offboarding record and schedule the revocation."""
    def run():
        target = session.get(User, user_id)
        if target is None:
            raise wf.WorkforceError("That person no longer exists.")
        if not last_working_day:
            raise wf.WorkforceError("Give the last working day.")
        try:
            day = date.fromisoformat(last_working_day)
        except ValueError:
            raise wf.WorkforceError("That is not a date the calendar accepts.")
        wf.start_offboarding(
            session, user=target, raiser=user,
            last_working_day=day, reason=reason.strip(),
        )

    return _write(request, session, user, run, "offboarding")


@router.post(
    "/workforce/leavers/{record_id}/revoke",
    dependencies=[Depends(require_permission("workforce:manage"))],
)
def revoke(
    request: Request,
    record_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Close every journey and take back the roles, now rather than at 17:00."""
    def run():
        record = session.get(LeaverRecord, record_id)
        if record is None:
            raise wf.WorkforceError("That leaver record no longer exists.")
        wf.revoke_now(session, record, actor=user)

    return _write(request, session, user, run, "offboarding")


@router.post(
    "/workforce/leavers/{record_id}/checklist",
    dependencies=[Depends(require_permission("workforce:manage"))],
)
def tick(
    request: Request,
    record_id: int,
    index: int = Form(...),
    done: Optional[str] = Form(None),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Tick or clear one checklist line.

    An unchecked box sends nothing, so `done` absent means false. Reading it
    as "unchanged" would make a box impossible to clear.
    """
    def run():
        record = session.get(LeaverRecord, record_id)
        if record is None:
            raise wf.WorkforceError("That leaver record no longer exists.")
        wf.set_checklist_item(
            session, record=record, index=index,
            done=done is not None, actor=user,
        )

    return _write(request, session, user, run, "offboarding")
