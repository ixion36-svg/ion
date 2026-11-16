"""The order of battle: every post, who holds it, and how far along they are.

The roster answers "who is behind". This answers the question a lead asks
first, which is structural: which posts exist, who is in them, and which
are gapped or being filled by somebody not yet operational. org_tree
already computes exactly that -- a post with no operational occupant is a
gap, and one held by somebody still in training is reported as `filling`
rather than quietly counted as covered.

Clicking a post opens that person's detail beside the tree: the full state
of their onboarding, gate and readiness, and the training objectives still
outstanding. Those objectives are the unsatisfied readiness certs and
courses on the journey itself, which is the same set
_sync_training_artifacts mirrors into the TrainingPlan the /training page
shows. Read from the journey here so there is one source on this page
rather than two that can disagree.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.workforce import UserJourney
from ion.services import workforce_service as wf
from ion.storage.database import get_db_session
from ion.web.ui._shared import render_view
from ion.web.workforce_api import require_workforce_module

logger = logging.getLogger(__name__)

# The module gate belongs on the router, not on each route: with the
# workforce feature off the page 404s, and a fragment that still
# answered would be reachable directly even though nothing links to it.
router = APIRouter(dependencies=[Depends(require_workforce_module)])

PERSON_FRAGMENT = "_fragments/workforce_orbat_person.html"

#: A post's state, in the words the page uses, with the tone it carries.
#: `filling` is deliberately not success: the post has a name against it
#: but nobody who can do the job yet, and a page that showed it as covered
#: would be the exact misreading org_tree refuses to make.
POST_STATE: dict[str, tuple[str, str, str]] = {
    "filled": ("Operational", "badge-success", "border-base-300"),
    "filling": ("Filling", "badge-warning", "border-warning/40"),
    "gapped": ("Gapped", "badge-error", "border-error/40"),
}

#: The stage an occupant is at, for the badge on their post.
STAGE_LABEL: dict[str, str] = {
    "pre_access": "Pre-access",
    "role_training": "Role training",
    "operational": "Operational",
    "suspended": "Suspended",
    "withdrawn": "Withdrawn",
}

ITEM_TONE: dict[str, tuple[str, str]] = {
    "verified": ("Verified", "bg-success"),
    "waived": ("Waived", "bg-success"),
    "equivalent": ("Met by assessment", "bg-success"),
    "submitted": ("Awaiting verification", "bg-warning"),
    "expired": ("Lapsed", "bg-error"),
    "pending": ("Not started", "bg-base-content/30"),
}


@router.get(
    "/workforce/orbat/closed",
    dependencies=[Depends(require_permission("workforce:read"))],
    response_class=HTMLResponse,
)
def closed_fragment() -> HTMLResponse:
    """Nothing, swapped into the post panel to close it.

    The panel hides itself when it is empty, so closing is an ordinary
    swap. ION serves no inline script and no unsafe-eval, which rules out
    doing this with hx-on.
    """
    return HTMLResponse("")


@router.get(
    "/workforce/orbat/person/{journey_id}",
    dependencies=[Depends(require_permission("workforce:read"))],
    response_class=HTMLResponse,
)
def person_fragment(
    request: Request,
    journey_id: int,
    session: Session = Depends(get_db_session),
):
    """One occupant's onboarding in full, plus what training is left.

    Gated the same as the tree that links to it. Everyone with
    workforce:read already sees who holds which post and what stage they
    are at; this is the detail behind a row on that same page, so a softer
    or harder gate here would be inconsistent with the link that reaches it.
    """
    view: dict[str, Any] = {
        "failed": False, "found": False, "journey": None, "person": "",
        "gate": [], "readiness": [], "objectives": [], "spend": 0.0,
        "committed": 0.0, "item_tone": ITEM_TONE, "stage_label": STAGE_LABEL,
    }

    try:
        journey: Optional[UserJourney] = session.get(UserJourney, journey_id)
        if journey is None:
            return render_view(request, PERSON_FRAGMENT, view)

        summary = wf.journey_summary(session, journey)
        from ion.models.user import User

        who = session.get(User, journey.user_id)
        rows = []
        for r in journey.requirements:
            label, dot = ITEM_TONE.get(r.status, ITEM_TONE["pending"])
            rows.append({
                "id": r.id, "name": r.name, "kind": r.kind, "phase": r.phase,
                "status": r.status, "label": label, "dot": dot,
                "satisfied": r.satisfied, "cost": r.cost or 0.0,
                "expires_on": r.expires_on.isoformat() if r.expires_on else None,
                "notes": r.notes or "",
            })
    except Exception:
        logger.exception("ORBAT person detail could not be rendered")
        view["failed"] = True
        return render_view(request, PERSON_FRAGMENT, view)

    # Outstanding first within each list, so the panel opens on what is
    # left rather than on what is already done.
    rows.sort(key=lambda r: (r["satisfied"], r["name"]))

    view.update({
        "found": True,
        "journey": summary,
        "person": (who.display_name or who.username) if who else f"user {journey.user_id}",
        "gate": [r for r in rows if r["phase"] == "gate"],
        "readiness": [r for r in rows if r["phase"] == "readiness"],
        # The training objectives: readiness certs and courses not yet met.
        # Same set _sync_training_artifacts puts on the "Onboarding: <role>"
        # plan, so the figure here and the one on /training agree.
        "objectives": [
            r for r in rows
            if r["phase"] == "readiness"
            and r["kind"] in ("cert", "course")
            and not r["satisfied"]
        ],
        "plan_name": f"Onboarding: {summary['role']}",
    })
    return render_view(request, PERSON_FRAGMENT, view)
