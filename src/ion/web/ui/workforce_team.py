"""The Team tab: what is waiting on a verifier, and the team two ways.

This is the merge of what were /workforce/people and /workforce/orbat. The
chart answers "which posts exist and who holds them"; the roster answers
"who do we have and where are they up to", and includes the people holding
no post at all, who are invisible on a chart of posts and are often the
ones mid-onboarding. Two views of one team is a toggle, not two pages.

The counts are read from every source whichever view is showing, because
they are what tells a lead whether the page needs opening, and a count
only visible after clicking the right view has told them nothing.

Reads reuse the endpoint functions behind /api/workforce/{verification-
queue,people}: the roster's shape is assembled in the endpoint rather than
in a service, and a second copy of that assembly here is the drift this
avoids. Writes reuse the service functions, which is where the permission
and ownership rules live.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.services import workforce_service as wf
from ion.storage.database import get_db_session
from ion.web.ui._shared import age_label, render_view
from ion.web.ui.workforce_orbat import POST_STATE, STAGE_LABEL
from ion.web.workforce_api import require_workforce_module

logger = logging.getLogger(__name__)

# The module gate belongs on the router, not on each route: with the
# workforce feature off the page 404s, and a fragment that still
# answered would be reachable directly even though nothing links to it.
router = APIRouter(dependencies=[Depends(require_workforce_module)])

FRAGMENT = "_fragments/workforce_team.html"

VIEWS = ("chart", "list")

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

#: The journey stages a roster row shows, in a lead's words, with a badge.
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
    into, because a lead searching "L2" means the role and a lead
    searching a surname means the person, and asking them which is which
    would be a filter nobody uses.
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

    The roster said "gate 1 of 3" and stopped, so a lead who wanted to
    know WHICH of the three was outstanding had to go and ask. The counts
    answer "is this person behind"; only the items answer "on what".

    journey_summary does not carry the rows, so they are read here -- in
    one query over every journey on the page, not one per person, which is
    the rule the roster endpoint itself keeps.

    Keyed `checklist`, not `items`: Jinja resolves `j.items` on a dict to
    the dict's own .items method, so the template iterated a bound method
    and raised rather than listing anything.
    """
    from ion.models.workforce import JourneyRequirement

    journeys = [j for p in everyone for j in (p.get("journeys") or [])]
    ids = [j["id"] for j in journeys if j.get("id") is not None]
    if not ids:
        return

    by_journey: dict[int, list[dict[str, Any]]] = {}
    for r in (
        session.query(JourneyRequirement)
        .filter(JourneyRequirement.journey_id.in_(ids))
        .all()
    ):
        label, dot = ITEM_VIEW.get(r.status, ITEM_VIEW["pending"])
        by_journey.setdefault(r.journey_id, []).append({
            "id": r.id, "name": r.name, "kind": r.kind, "phase": r.phase,
            "status": r.status, "label": label, "dot": dot,
            "satisfied": r.satisfied,
        })

    # Gate before readiness, unfinished first: a lead reading a checklist
    # is looking for what is outstanding, so verified items sort to the
    # bottom and the answer is at the top.
    for j in journeys:
        rows = by_journey.get(j["id"], [])
        rows.sort(key=lambda r: (r["phase"] != "gate", r["satisfied"], r["name"]))
        j["checklist"] = rows


#: A pillar's coverage state, in the old ORBAT page's words, with its badge.
#:
#: `unmeasured` is ghost, not an error: nobody has filled the form in,
#: which is a different job from being short of people, and colouring it
#: like a gap would send a lead recruiting when they should be surveying.
PILLAR_STATE: dict[str, tuple[str, str]] = {
    "covered": ("covered", "badge-success"),
    "thin": ("thin", "badge-warning"),
    "partial": ("partial", "badge-warning"),
    "self_rated": ("self-rated", "badge-warning"),
    "uncovered": ("nobody owns it", "badge-error"),
    "unmeasured": ("unmeasured", "badge-ghost"),
}

#: How far ahead Expiring soon looks, and how many it lists.
EXPIRING_DAYS = 90
EXPIRING_SHOWN = 12


def _coverage(session: Session) -> dict[str, Any]:
    """Cover by role, day-to-day pillar coverage, and what lapses soon.

    These were the old ORBAT page's side panels and are the same three
    reads as /api/workforce/{orbat,coverage,expiring}, each declared
    workforce:read -- the gate this router holds -- so calling the services
    directly widens nothing.

    Kept out of the main read: they are supplementary, and a failure here
    should say "coverage could not be read" beside a working roster rather
    than take the whole tab down with it.
    """
    from ion.models.user import User as UserModel
    from ion.models.workforce import RoleProfile
    from ion.services import coverage_service

    cover = []
    for profile in session.query(RoleProfile).order_by(RoleProfile.name).all():
        c = wf.capability_cover(session, profile.name)
        # A role nobody holds, trains for or has been suspended from is a
        # line of zeros, and twenty of those bury the three that matter.
        if c["primary"] or c["cover"] or c["in_training"] or c["blocked"]:
            cover.append({"role": profile.name, **c})

    pillars = coverage_service.pillar_coverage(session)

    due = wf.expiring(session, within_days=EXPIRING_DAYS)
    shown = due[:EXPIRING_SHOWN]
    ids = {i.journey.user_id for i in shown}
    # One query for every name on the list, not one per row.
    names = {
        u.id: (u.display_name or u.username)
        for u in session.query(UserModel).filter(UserModel.id.in_(ids or [0])).all()
    }
    expiring = [
        {
            "name": names.get(i.journey.user_id, f"user {i.journey.user_id}"),
            "journey_id": i.journey.id,
            "requirement": i.requirement.name,
            "phase": i.requirement.phase,
            "expires_on": i.requirement.expires_on.isoformat(),
            "days_left": i.days_left,
        }
        for i in shown
    ]

    return {
        "cover": cover,
        "cover_weight": wf.COVER_WEIGHT,
        "pillars": pillars.get("pillars") or [],
        "measured": bool(pillars.get("measured")),
        "self_rated_pillars": pillars.get("self_rated_pillars") or 0,
        "unplaced": [u.get("name") for u in pillars.get("unplaced") or []],
        "weights": pillars.get("weights") or {},
        "expiring": expiring,
        "expiring_more": max(0, len(due) - len(shown)),
        "expiring_days": EXPIRING_DAYS,
    }


def _view(
    session: Session,
    user: User,
    view: str = "chart",
    q: str = "",
    error: str = "",
) -> dict[str, Any]:
    """Everything the Team tab shows, in whichever view is open."""
    from ion.web.workforce_api import people, verification_queue

    if view not in VIEWS:
        view = "chart"

    base: dict[str, Any] = {
        "failed": False, "error": error, "view": view, "q": q,
        "items": [], "people": [], "total_people": 0, "units": [],
        "stage_view": STAGE_VIEW, "post_state": POST_STATE,
        "stage_label": STAGE_LABEL,
        "awaiting": 0, "blocked": 0, "overdue": 0, "gaps": 0,
        "leads_gapped": 0,
        "can_verify": user.has_permission("workforce:verify"),
        "can_manage": user.has_permission("workforce:manage"),
        "pillar_state": PILLAR_STATE,
        "coverage": None, "coverage_failed": False,
    }

    # The queue is read only for a verifier, and that is load-bearing.
    #
    # These endpoint functions are called directly, so FastAPI's dependency
    # for each one does NOT run and their declared permission is not
    # applied here -- this router's own gate is the only one in force, and
    # it is workforce:read. /api/workforce/verification-queue is declared
    # workforce:verify, so loading it behind a read gate would show who
    # submitted what, with their evidence references, to everyone who can
    # read the roster. The tab hides the buttons from a non-verifier; that
    # is not a control, because the data would already be in the markup.
    #
    # The roster is a different case and stays: /api/workforce/people is
    # declared workforce:read, and /api/workforce/journeys/open returns
    # full requirement rows at workforce:read too, so the per-person
    # checklist below is the contract that already exists rather than a
    # widening of it.
    can_verify = base["can_verify"]
    try:
        queue = (
            verification_queue(session=session, _user=user) if can_verify
            else {"items": [], "count": 0}
        )
        roster = people(session=session, _user=user)
        tree = wf.org_tree(session)
    except Exception:
        logger.exception("Workforce team fragment could not be rendered")
        base["failed"] = True
        return base

    items = list(queue.get("items") or [])
    for i in items:
        # A difference between two instants, so unlike a clock time it
        # carries no timezone claim and is safe to render server-side.
        i["waiting"] = age_label(i.get("submitted_at"))

    everyone = list(roster.get("people") or [])
    _attach_checklists(session, everyone)

    overdue = 0
    for p in everyone:
        for j in p.get("journeys") or []:
            # Only a running journey can be behind. A suspended one has a
            # lapsed item, a different problem with a different remedy.
            if j.get("stage") in ("pre_access", "role_training") and (
                j.get("days_elapsed", 0) > j.get("target_days", 0)
            ):
                overdue += 1

    base.update({
        "items": items,
        "people": [p for p in everyone if _matches(p, q)],
        "total_people": len(everyone),
        "units": tree.get("units") or [],
        "awaiting": queue.get("count") or 0,
        "blocked": sum(1 for p in everyone if p.get("has_access") is False),
        "overdue": overdue,
        "gaps": tree.get("gaps") or 0,
        "leads_gapped": tree.get("leads_gapped") or 0,
    })

    try:
        base["coverage"] = _coverage(session)
    except Exception:
        logger.exception("Workforce coverage panels could not be rendered")
        base["coverage_failed"] = True
    return base


@router.get(
    "/workforce/team",
    dependencies=[Depends(require_permission("workforce:read"))],
    response_class=HTMLResponse,
)
def team_fragment(
    request: Request,
    view: str = "chart",
    q: str = "",
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """The queue, then the team as a chart or as a list."""
    return render_view(request, FRAGMENT, _view(session, user, view, q))


def _write(
    request: Request,
    session: Session,
    user: User,
    action: Callable[[], Any],
    view: str,
    q: str = "",
):
    """Run one write, then re-render the tab from the database.

    A verification can clear somebody's gate and grant them access, which
    moves the roster and three of the four counts, so the whole tab is
    re-read rather than the row patched. Refusals come back in the markup:
    the old page used alert(), which names no row and leaves the stale
    state on screen behind the dialog.
    """
    error = ""
    try:
        action()
    except wf.WorkforceError as exc:
        error = str(exc)
    return render_view(request, FRAGMENT, _view(session, user, view, q, error))


def _requirement(session: Session, requirement_id: int):
    from ion.models.workforce import JourneyRequirement

    req = session.get(JourneyRequirement, requirement_id)
    if req is None:
        raise wf.WorkforceError("That item no longer exists. Reload the page.")
    return req


@router.post(
    "/workforce/requirements/{requirement_id}/verify",
    dependencies=[Depends(require_permission("workforce:verify"))],
    response_class=HTMLResponse,
)
def verify(
    request: Request,
    requirement_id: int,
    evidence_ref: str = Form(""),
    tab: str = Form("chart"),
    q: str = Form(""),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Accept one submitted item.

    `tab` and `q` come back from the form because the same button exists
    in two places: the queue, and a person's checklist on the roster.
    Sending the roster's caller back to the chart would throw away the
    search they were part-way through.
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
    response_class=HTMLResponse,
)
def send_back(
    request: Request,
    requirement_id: int,
    tab: str = Form("chart"),
    q: str = Form(""),
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

    return _write(request, session, user, run, tab, q)
