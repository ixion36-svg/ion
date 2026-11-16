"""The Setup tab: role profiles, the establishment, and who is leaving.

Configuration a lead touches occasionally, kept off the Team tab so the
daily queue is not sharing a scroll with a form for ending somebody's
employment -- which is how /workforce/people read.

This absorbed /workforce/profiles, the last of the four workforce pages.
The schema and the establishment belong together: one says what a role
requires, the other says how many of that role the SOC is supposed to
have, and editing either without seeing the other was the reason they
were two screens with a ghost button between them.

Every read here calls the function behind its /api counterpart rather
than going through HTTP, so FastAPI does not resolve that endpoint's own
dependency and its declared permission does not run. That is safe only
because this whole router is gated on workforce:manage, which is at least
as strict as every endpoint it calls (`list_profiles` is workforce:read;
the rest are workforce:manage). A route added here on a looser gate would
silently widen all of them, which is exactly what happened once on the
Team tab with the verification queue.

The establishment is shown per role rather than per post, because "how
many L2s should we have, how many do we have, and how short are we" is
the question a lead asks, and org_tree's shape does not answer it.
`filling` stays separate from `filled` throughout: a post held by
somebody still in training is a gap in cover tonight just as much as an
empty one, and merging them is how a rota looks staffed while nobody on
it can take the queue.
"""
from __future__ import annotations

import logging
from datetime import date
from typing import Any, Callable, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.models.workforce import LeaverRecord
from ion.services import workforce_service as wf
from ion.storage.database import get_db_session
from ion.web.ui._shared import render_view
from ion.web.ui.workforce_orbat import POST_STATE, STAGE_LABEL
from ion.web.workforce_api import require_workforce_module

logger = logging.getLogger(__name__)

# The module gate belongs on the router, not on each route: with the
# workforce feature off the page 404s, and a fragment that still
# answered would be reachable directly even though nothing links to it.
router = APIRouter(dependencies=[Depends(require_workforce_module)])

FRAGMENT = "_fragments/workforce_setup.html"


def _draft_for(session: Session, user: User, profile_id: Optional[int]):
    """The open draft of one profile, or None when none is selected.

    Returns None rather than raising for a profile that has gone: Setup
    re-renders after every write, and a stale id in a form field should
    put the reader back on the list, not on an error page.
    """
    if profile_id is None:
        return None
    from ion.web.workforce_api import get_draft

    try:
        return get_draft(profile_id=profile_id, session=session, _user=user)
    except Exception:
        logger.info("No draft for profile %s", profile_id)
        return None


#: Journeys in these stages cannot be seated: fill_post refuses them, so
#: offering them in the list would only produce a refusal.
UNSEATABLE_STAGES = ("closed", "withdrawn")


def _structure(
    units: list[dict[str, Any]],
    everyone: list[dict[str, Any]],
    profiles: list[dict[str, Any]],
) -> dict[str, Any]:
    """What the structure editor needs beyond the tree itself.

    `unit_paths` is every unit as "SOC / Detection", for the parent picker:
    two teams can both be called "Tier 2" under different parents, and a
    flat list of bare names would not say which one a new unit goes under.

    `seatable` is every live journey not already in a post. A journey can
    hold one post at a time (fill_post refuses a second), so listing seated
    ones would offer a choice that always fails. The template narrows it
    per post to the post's own role profile, which fill_post also enforces.
    """
    paths: list[dict[str, Any]] = []
    seated: set[int] = set()

    def walk(nodes: list[dict[str, Any]], prefix: str) -> None:
        for u in nodes:
            path = f"{prefix} / {u['name']}" if prefix else u["name"]
            paths.append({"id": u["id"], "path": path})
            for p in (u.get("leads") or []) + (u.get("posts") or []):
                if p.get("occupant"):
                    seated.add(p["occupant"]["journey_id"])
            walk(u.get("children") or [], path)

    walk(units, "")

    seatable = [
        {
            "journey_id": j["id"], "name": p["name"], "role": j.get("role") or "?",
            "is_cover": bool(j.get("is_cover")), "profile_id": j.get("profile_id"),
        }
        for p in everyone
        for j in p.get("journeys") or []
        if j["id"] not in seated and j.get("stage") not in UNSEATABLE_STAGES
    ]
    seatable.sort(key=lambda s: (s["name"].lower(), s["is_cover"]))

    return {
        "units": units,
        "unit_paths": paths,
        "seatable": seatable,
        "profile_names": {p["id"]: p["name"] for p in profiles},
    }


def _view(
    session: Session,
    user: User,
    profile_id: Optional[int] = None,
    error: str = "",
    notice: str = "",
) -> dict[str, Any]:
    """The schema, the establishment, the leavers, and who could leave."""
    from ion.models.workforce import KINDS, PHASES
    from ion.web.workforce_api import ion_roles, list_leavers, list_profiles, people

    base: dict[str, Any] = {
        "failed": False, "error": error, "notice": notice,
        "roles": [], "note": "",
        "established": 0, "filled": 0, "filling": 0, "gap": 0,
        "leavers": [], "all_people": [],
        "units": [], "unit_paths": [], "seatable": [], "profile_names": {},
        "post_state": POST_STATE, "stage_label": STAGE_LABEL,
        "profiles": [], "profile_id": profile_id, "draft": None,
        "ion_roles": [], "kinds": list(KINDS), "phases": list(PHASES),
        "can_manage": user.has_permission("workforce:manage"),
    }

    try:
        est = wf.establishment_summary(session)
        leavers = list_leavers(session=session, _user=user)
        roster = people(session=session, _user=user)
        profiles = list_profiles(session=session, _user=user)
        roles_available = ion_roles(session=session, _user=user)
        draft = _draft_for(session, user, profile_id)
        tree = wf.org_tree(session)
    except Exception:
        logger.exception("Workforce setup fragment could not be rendered")
        base["failed"] = True
        return base

    units = tree.get("units") or []
    everyone = list(roster.get("people") or [])
    base.update(_structure(units, everyone, profiles.get("profiles") or []))
    base.update({
        "roles": est.get("roles") or [],
        # Present when no posts exist at all. Reporting zero gaps there
        # would read as fully staffed rather than as undefined.
        "note": est.get("note") or "",
        "established": est.get("established") or 0,
        "filled": est.get("filled") or 0,
        "filling": est.get("filling") or 0,
        "gap": est.get("gap") or 0,
        "leavers": list(leavers.get("leavers") or []),
        "all_people": list(roster.get("people") or []),
        "profiles": list(profiles.get("profiles") or []),
        "ion_roles": list(roles_available.get("roles") or []),
        "draft": draft,
    })
    return base


@router.get(
    "/workforce/setup",
    dependencies=[Depends(require_permission("workforce:manage"))],
    response_class=HTMLResponse,
)
def setup_fragment(
    request: Request,
    profile: Optional[int] = None,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """The schema, the establishment and offboarding."""
    return render_view(request, FRAGMENT, _view(session, user, profile))


def _write(
    request: Request,
    session: Session,
    user: User,
    action: Callable[[], Any],
    profile_id: Optional[int] = None,
    notice: str = "",
):
    """Run one write, then re-render the tab from the database.

    A pydantic ValidationError is caught alongside WorkforceError because
    the form posts strings: a name the model rejects is a thing the reader
    typed, and it belongs on the page next to the field rather than as a
    500. HTTPException is caught because the structure writes call the
    /api handlers, which refuse a missing unit or profile that way.
    """
    error = ""
    try:
        action()
    except wf.WorkforceError as exc:
        error = str(exc)
    except HTTPException as exc:
        error = str(exc.detail)
    except ValidationError as exc:
        first = exc.errors()[0] if exc.errors() else {}
        error = str(first.get("msg") or "That value was not accepted.")
    except ValueError as exc:
        error = str(exc)
    return render_view(
        request, FRAGMENT,
        _view(session, user, profile_id, error, "" if error else notice),
    )


# --- the schema -------------------------------------------------------------


@router.post(
    "/workforce/profiles",
    dependencies=[Depends(require_permission("workforce:manage"))],
    response_class=HTMLResponse,
)
def create_profile(
    request: Request,
    name: str = Form(""),
    nice_work_role: str = Form(""),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Add a role profile. It starts as a draft with no requirements."""
    created: dict[str, Any] = {}

    def run():
        from ion.web.workforce_api import ProfileIn
        from ion.web.workforce_api import create_profile as api_create

        if not name.strip():
            raise wf.WorkforceError("Give the role a name.")
        out = api_create(
            payload=ProfileIn(name=name.strip(),
                              nice_work_role=nice_work_role.strip()),
            session=session, _user=user,
        )
        created.update(out)

    response = _write(request, session, user, run, None,
                      "Profile created. Add its requirements, then publish.")
    # Select what was just made, so the reader lands in its editor rather
    # than having to find it in the list they just grew.
    if created.get("id"):
        return render_view(
            request, FRAGMENT,
            _view(session, user, created["id"], "",
                  "Profile created. Add its requirements, then publish."),
        )
    return response


@router.post(
    "/workforce/profiles/{profile_id}/grants",
    dependencies=[Depends(require_permission("workforce:manage"))],
    response_class=HTMLResponse,
)
def set_grants(
    request: Request,
    profile_id: int,
    role_id: str = Form(""),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Map a profile to the ION role its cleared gate confers.

    Calls the API's own handler, which also re-syncs everybody who has
    already cleared the gate -- they gain or lose the role now, because
    nothing else about their journey will change to trigger it.
    """
    def run():
        from ion.web.workforce_api import GrantsIn
        from ion.web.workforce_api import set_grants as api_set

        api_set(
            profile_id=profile_id,
            payload=GrantsIn(role_id=int(role_id) if role_id else None),
            session=session, _user=user,
        )

    return _write(request, session, user, run, profile_id,
                  "Saved. The gate now controls that role.")


@router.post(
    "/workforce/versions/{version_id}/requirements",
    dependencies=[Depends(require_permission("workforce:manage"))],
    response_class=HTMLResponse,
)
def add_requirement(
    request: Request,
    version_id: int,
    profile: int = Form(...),
    name: str = Form(""),
    kind: str = Form("document"),
    phase: str = Form("gate"),
    validity_months: str = Form(""),
    cost: str = Form("0"),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Add one requirement to the open draft."""
    def run():
        from ion.web.workforce_api import RequirementIn
        from ion.web.workforce_api import add_requirement as api_add

        if not name.strip():
            raise wf.WorkforceError("Give the requirement a name.")
        api_add(
            version_id=version_id,
            payload=RequirementIn(
                name=name.strip(), kind=kind, phase=phase,
                validity_months=int(validity_months) if validity_months else None,
                cost=float(cost or 0),
            ),
            session=session, _user=user,
        )

    return _write(request, session, user, run, profile)


@router.post(
    "/workforce/profile-requirements/{requirement_id}/remove",
    dependencies=[Depends(require_permission("workforce:manage"))],
    response_class=HTMLResponse,
)
def remove_requirement(
    request: Request,
    requirement_id: int,
    profile: int = Form(...),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Take one requirement off the open draft.

    Named profile-requirements, not requirements: the journey routes on
    the Me and Team tabs already own /workforce/requirements/{id}/..., and
    those act on a JourneyRequirement -- somebody's copy of an item -- not
    on the ProfileRequirement the schema is made of. Two different things
    behind one path is how a delete lands on the wrong row.
    """
    def run():
        from ion.web.workforce_api import delete_requirement

        delete_requirement(requirement_id=requirement_id, session=session, _user=user)

    return _write(request, session, user, run, profile)


@router.post(
    "/workforce/versions/{version_id}/publish",
    dependencies=[Depends(require_permission("workforce:manage"))],
    response_class=HTMLResponse,
)
def publish(
    request: Request,
    version_id: int,
    profile: int = Form(...),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Publish the draft. It applies to new assignments only."""
    def run():
        from ion.web.workforce_api import publish as api_publish

        api_publish(version_id=version_id, session=session, user=user)

    return _write(request, session, user, run, profile,
                  "Published. Existing journeys keep the version they "
                  "started on; this applies to new assignments.")


@router.post(
    "/workforce/establishment/{profile_id}",
    dependencies=[Depends(require_permission("workforce:manage"))],
    response_class=HTMLResponse,
)
def set_establishment(
    request: Request,
    profile_id: int,
    count: str = Form(""),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Set how many posts a role has.

    `count` is taken as a string and parsed here so a typo comes back as
    a sentence on the page. Declared as an int, FastAPI would reject the
    request with a 422 before this route ran, and htmx would swap
    nothing in -- the form would simply appear not to work.

    The rules about what may be removed live in the service, not here:
    an occupied post is never deleted to satisfy a number going down,
    and nor is a lead post, because a vacant one is the ORBAT saying
    nobody answers for that unit.
    """
    def run():
        from ion.models.workforce import RoleProfile

        try:
            wanted = int(count.strip())
        except (TypeError, ValueError):
            raise wf.WorkforceError(f"{count!r} is not a number of posts.")
        profile = session.get(RoleProfile, profile_id)
        if profile is None:
            raise wf.WorkforceError("That role profile no longer exists.")
        wf.set_establishment(session, profile=profile, count=wanted, actor=user)

    return _write(request, session, user, run)


# --- the structure ----------------------------------------------------------
#
# Units and posts: the tree the Team tab's chart draws. These were on the
# /workforce/orbat page and went missing when it was folded into Team,
# which left no way to build a structure except the catalogue's one-shot
# establishment. Each write calls its /api handler, so the rules -- a post
# needs a real unit, a seat needs a matching profile -- live in one place.


def _optional_id(raw: str) -> Optional[int]:
    """A select's value as an id, with "" meaning none.

    Parsed here rather than declared Optional[int] on the form, because an
    empty option posts "" and FastAPI would answer that with a 422 that
    htmx swaps nowhere -- the control would just seem dead.
    """
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        raise wf.WorkforceError("That choice was not recognised. Reload the page.")


@router.post(
    "/workforce/org/units",
    dependencies=[Depends(require_permission("workforce:manage"))],
    response_class=HTMLResponse,
)
def create_unit(
    request: Request,
    name: str = Form(""),
    parent_id: str = Form(""),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Add a unit, at the top or under another."""
    def run():
        from ion.web.workforce_api import OrgUnitIn
        from ion.web.workforce_api import create_unit as api_create

        if not name.strip():
            raise wf.WorkforceError("Give the unit a name.")
        api_create(
            payload=OrgUnitIn(name=name.strip(), parent_id=_optional_id(parent_id)),
            session=session, _user=user,
        )

    return _write(request, session, user, run, None, "Unit added.")


@router.post(
    "/workforce/org/units/{unit_id}/delete",
    dependencies=[Depends(require_permission("workforce:manage"))],
    response_class=HTMLResponse,
)
def delete_unit(
    request: Request,
    unit_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Remove a unit and everything under it. The button confirms first."""
    def run():
        from ion.web.workforce_api import delete_unit as api_delete

        api_delete(unit_id=unit_id, session=session, _user=user)

    return _write(request, session, user, run, None, "Unit removed.")


@router.post(
    "/workforce/org/posts",
    dependencies=[Depends(require_permission("workforce:manage"))],
    response_class=HTMLResponse,
)
def create_post(
    request: Request,
    unit_id: int = Form(...),
    title: str = Form(""),
    profile_id: str = Form(""),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Add a post to a unit, for one role or for any."""
    def run():
        from ion.web.workforce_api import OrgPostIn
        from ion.web.workforce_api import create_post as api_create

        if not title.strip():
            raise wf.WorkforceError("Give the post a title.")
        api_create(
            payload=OrgPostIn(unit_id=unit_id, title=title.strip(),
                              profile_id=_optional_id(profile_id)),
            session=session, _user=user,
        )

    return _write(request, session, user, run, None, "Post added.")


@router.post(
    "/workforce/org/posts/{post_id}/delete",
    dependencies=[Depends(require_permission("workforce:manage"))],
    response_class=HTMLResponse,
)
def delete_post(
    request: Request,
    post_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Remove one post. Its occupant keeps their journey; only the seat goes."""
    def run():
        from ion.web.workforce_api import delete_post as api_delete

        api_delete(post_id=post_id, session=session, _user=user)

    return _write(request, session, user, run, None, "Post removed.")


@router.post(
    "/workforce/org/posts/{post_id}/fill",
    dependencies=[Depends(require_permission("workforce:manage"))],
    response_class=HTMLResponse,
)
def fill_post(
    request: Request,
    post_id: int,
    journey_id: str = Form(""),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Seat a journey in a post, or empty it when `journey_id` is blank.

    The seat select and the Unseat button both post here. fill_post
    refuses a closed journey, one from a different role profile, and one
    already seated elsewhere, and those refusals come back on the page.
    """
    def run():
        from ion.web.workforce_api import FillIn
        from ion.web.workforce_api import fill as api_fill

        api_fill(
            post_id=post_id, payload=FillIn(journey_id=_optional_id(journey_id)),
            session=session, user=user,
        )

    return _write(request, session, user, run)


# --- offboarding ------------------------------------------------------------


@router.post(
    "/workforce/leavers",
    dependencies=[Depends(require_permission("workforce:manage"))],
    response_class=HTMLResponse,
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

    return _write(request, session, user, run)


@router.post(
    "/workforce/leavers/{record_id}/revoke",
    dependencies=[Depends(require_permission("workforce:manage"))],
    response_class=HTMLResponse,
)
def revoke(
    request: Request,
    record_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Close every journey and take the roles back, now rather than at 17:00."""
    def run():
        record = session.get(LeaverRecord, record_id)
        if record is None:
            raise wf.WorkforceError("That leaver record no longer exists.")
        wf.revoke_now(session, record, actor=user)

    return _write(request, session, user, run)


@router.post(
    "/workforce/leavers/{record_id}/checklist",
    dependencies=[Depends(require_permission("workforce:manage"))],
    response_class=HTMLResponse,
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

    An unchecked box sends nothing, so `done` absent means false. Reading
    it as "unchanged" would make a box impossible to clear.
    """
    def run():
        record = session.get(LeaverRecord, record_id)
        if record is None:
            raise wf.WorkforceError("That leaver record no longer exists.")
        wf.set_checklist_item(
            session, record=record, index=index,
            done=done is not None, actor=user,
        )

    return _write(request, session, user, run)
