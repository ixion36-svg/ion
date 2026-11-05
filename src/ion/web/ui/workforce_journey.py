"""A person's own onboarding, as one fragment.

Replaces the five-step wizard that workforce_journey.html drove from
JavaScript. The wizard's problem was not how it looked: of its five steps
only two carried an action. "Your role" was a paragraph, "Access" was a
badge and "Operational" was a badge, so three of five clicks moved the
joiner between screens that asked nothing of them. The two that mattered,
the access gate and role readiness, were never visible at the same time, so
the question a joiner actually has -- what is left for me to do -- could not
be answered without navigating.

Both lists are on the page here, the gate first because it is what holds
access, and each row carries its own form behind a `<details>`, so eight
outstanding items are eight lines rather than eight date pickers.

The data is assembled exactly as /api/workforce/journeys/me assembles it,
through the same service calls, so the fragment and the JSON cannot drift.
Writes go through the same service functions too, which is where the
ownership check lives: submit_requirement refuses a requirement whose
journey belongs to someone else, so this router does not re-implement that
rule and cannot disagree with it.
"""
from __future__ import annotations

import logging
from datetime import date
from typing import Any, Callable, Optional

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user
from ion.models.user import User
from ion.models.workforce import JourneyRequirement
from ion.services import workforce_service as wf
from ion.storage.database import get_db_session
from ion.web.ui._shared import render_view

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/workforce_journey.html"

#: What each requirement status says to the person, and the tone it carries.
#:
#: All six of workforce.STATUSES appear. The wizard's map held five and fell
#: through to "To do" for the sixth, STATUS_EQUIVALENT -- an item met by
#: assessed proficiency rather than by the named certificate.
#: JourneyRequirement.satisfied counts equivalent, and journey_summary builds
#: gate_done from satisfied, so the counter read "3 of 3 verified" while one
#: of those three rows said "To do" and offered a submit form.
STATUS_VIEW: dict[str, tuple[str, str]] = {
    "verified": ("Verified", "success"),
    "waived": ("Waived", "success"),
    "equivalent": ("Met by assessment", "success"),
    "submitted": ("Awaiting your lead", "warning"),
    "expired": ("Lapsed", "error"),
    "pending": ("To do", "todo"),
}

#: A joiner may put these forward. Anything satisfied is left alone: the
#: service would accept a resubmission of an equivalent item, but a row the
#: counter has already counted must not also read as outstanding.
ACTIONABLE = ("pending", "expired")


def _requirement_view(r: JourneyRequirement) -> dict[str, Any]:
    label, tone = STATUS_VIEW.get(r.status, STATUS_VIEW["pending"])
    return {
        "id": r.id,
        "name": r.name,
        "kind": r.kind,
        "phase": r.phase,
        "status": r.status,
        "label": label,
        "tone": tone,
        "actionable": r.status in ACTIONABLE,
        "withdrawable": r.status == "submitted",
        "expires_on": r.expires_on.isoformat() if r.expires_on else None,
        "completed_on": r.completed_on.isoformat() if r.completed_on else None,
        "evidence_ref": r.evidence_ref or "",
        "notes": r.notes or "",
    }


def _view(
    session: Session,
    user: User,
    journey_id: Optional[int] = None,
    error: str = "",
) -> dict[str, Any]:
    """The whole page's model, or `failed` when the read did not complete.

    `failed` is not an empty onboarding. "No role assigned yet" invites the
    joiner to wait for a lead; "your onboarding could not be read" asks them
    to retry. Showing the first when the second happened tells somebody with
    outstanding gate items that they have none.
    """
    try:
        journeys: list[dict[str, Any]] = []
        for journey in wf.live_journeys(session, user.id):
            wf.sync_course_requirements(session, journey)
            summary = wf.journey_summary(session, journey)
            summary["requirements"] = [
                _requirement_view(r) for r in journey.requirements
            ]
            journeys.append(summary)
        has_access = wf.has_system_access(session, user.id)
    except Exception:
        logger.exception("Onboarding fragment could not be rendered")
        return {
            "failed": True, "error": "", "journeys": [], "active": None,
            "gate": [], "readiness": [], "done": 0, "total": 0,
            "has_access": False, "overdue": False,
        }

    # Only the caller's own journeys are ever in this list, so an id that is
    # not theirs is simply not found and they get their first journey. The
    # selection cannot be used to read somebody else's onboarding.
    active: Optional[dict[str, Any]] = None
    if journey_id is not None:
        active = next((j for j in journeys if j["id"] == journey_id), None)
    if active is None and journeys:
        active = journeys[0]

    gate: list[dict[str, Any]] = []
    readiness: list[dict[str, Any]] = []
    done = total = 0
    if active:
        requirements = active["requirements"]
        gate = [r for r in requirements if r["phase"] == "gate"]
        readiness = [r for r in requirements if r["phase"] == "readiness"]
        total = len(requirements)
        done = sum(1 for r in requirements if r["tone"] == "success")

    return {
        "failed": False,
        "error": error,
        "journeys": journeys,
        "active": active,
        "gate": gate,
        "readiness": readiness,
        "done": done,
        "total": total,
        "has_access": has_access,
        # Past the target with the journey still open. Stated as a fact
        # rather than flagged as a fault: the date slipping is usually the
        # organisation's doing, and this page is read by the joiner.
        "overdue": bool(
            active
            and active["stage"] != "operational"
            and active["days_elapsed"] > active["target_days"]
        ),
    }


@router.get("/workforce/journey")
def journey_fragment(
    request: Request,
    journey: Optional[int] = None,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """The signed-in person's own onboarding.

    Signed in is the whole bar, matching the page route. /workforce is
    deliberately open to everyone: it tells somebody what they must complete
    before they are allowed to do anything, so gating it on a workforce
    permission hid it from exactly the people it is for.
    """
    return render_view(request, FRAGMENT, _view(session, user, journey))


def _write(
    request: Request,
    session: Session,
    user: User,
    requirement_id: int,
    action: Callable[[JourneyRequirement], Any],
    journey_id: Optional[int],
):
    """Run one write, then re-render the page from the database.

    Re-rendering rather than patching the row is the point: a write moves
    counters, can clear the gate and can grant system access, and a handler
    that updated only the row it touched left all three stale on screen. The
    error comes back inside the fragment for the same reason -- the wizard
    reported a refusal through `alert()`, which names no item and leaves the
    page still claiming the old state behind the dialog.
    """
    error = ""
    req = session.get(JourneyRequirement, requirement_id)
    if req is None:
        error = "That item no longer exists. Reload the page."
    else:
        if journey_id is None:
            journey_id = req.journey_id
        try:
            action(req)
        except wf.WorkforceError as exc:
            error = str(exc)
    return render_view(request, FRAGMENT, _view(session, user, journey_id, error))


@router.post("/workforce/requirements/{requirement_id}/submit")
def submit_requirement(
    request: Request,
    requirement_id: int,
    completed_on: str = Form(""),
    evidence_ref: str = Form(""),
    journey: Optional[int] = Form(None),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Put one item forward for a lead to verify."""
    try:
        when: Optional[date] = (
            date.fromisoformat(completed_on) if completed_on else None
        )
    except ValueError:
        # A value no date input could have produced. Treated as absent
        # rather than as today, so the service records its own default and
        # nobody is credited with a completion date they did not enter.
        when = None

    return _write(
        request, session, user, requirement_id,
        lambda req: wf.submit_requirement(
            session, requirement=req, submitter=user,
            completed_on=when, evidence_ref=evidence_ref.strip(),
        ),
        journey,
    )


@router.post("/workforce/requirements/{requirement_id}/withdraw")
def withdraw_requirement(
    request: Request,
    requirement_id: int,
    journey: Optional[int] = Form(None),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Take a submission back before a lead has verified it."""
    return _write(
        request, session, user, requirement_id,
        lambda req: wf.withdraw_submission(session, requirement=req, actor=user),
        journey,
    )
