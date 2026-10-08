"""Workforce lifecycle endpoints.

404, not 403, when the module is off: a deployment that does not run this
should be indistinguishable from one where it does not exist, matching the
DE-module and SOAR gating.
"""

from __future__ import annotations

import logging
from datetime import date
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.core.config import get_config
from ion.models.user import User
from ion.models.workforce import (
    KINDS,
    PHASES,
    STATUS_VERIFIED,
    STATUS_WAIVED,
    JourneyRequirement,
    LeaverRecord,
    OrgPost,
    OrgUnit,
    ProfileRequirement,
    RoleProfile,
    RoleProfileVersion,
    UserJourney,
)
from ion.services import coverage_service
from ion.services import workforce_service as wf
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/workforce", tags=["workforce"])


def require_workforce_module() -> None:
    """404 when the lifecycle is not enabled for this deployment."""
    if not get_config().workforce_enabled:
        raise HTTPException(status_code=404, detail="Not found")


def _err(exc: wf.WorkforceError) -> HTTPException:
    """Lifecycle rule violations are the caller's problem, not a 500."""
    message = str(exc)
    return HTTPException(status_code=403 if "Permission denied" in message else 400,
                         detail=message)


# --- schemas ----------------------------------------------------------------


class ProfileIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=150)
    description: str = ""
    nice_work_role: str = ""
    is_baseline: bool = False
    # The career role whose skills questionnaire applies, e.g.
    # "l2_soc_analyst". Lets a lead recording an equivalence find the
    # right assessment without having to know the slug.
    skills_role_id: Optional[str] = None


class RequirementIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    kind: str = Field("document", pattern="^(document|vetting|access|course|cert|signoff)$")
    phase: str = Field("gate", pattern="^(gate|readiness)$")
    description: str = ""
    validity_months: Optional[int] = Field(None, ge=1, le=120)
    course_id: Optional[int] = None
    cost: float = Field(0.0, ge=0)
    funding_type: str = Field("company", pattern="^(company|self|split|tbd)$")


class AssignIn(BaseModel):
    user_id: int
    version_id: int
    is_cover: bool = False
    sponsor_id: Optional[int] = None
    # Roll an existing journey for the same role onto this version. Off by
    # default so closing somebody's journey is always something the lead
    # asked for, never a side effect of pressing assign.
    supersede: bool = False


class VerifyIn(BaseModel):
    evidence_ref: str = ""
    expires_on: Optional[date] = None


class EquivalenceIn(BaseModel):
    """Satisfy a requirement by assessed proficiency instead of the item."""

    # Required, with a minimum length, so an equivalence cannot be recorded
    # as a bare tick. The whole value of this path is that somebody had to
    # write down what they assessed and how.
    basis: str = Field(..., min_length=1, max_length=2000)
    expires_on: Optional[date] = None
    # A RoleAssessment to cite as supporting evidence. Evidence, not the
    # decision: the assessment is self-rated, so a score can never clear a
    # requirement on its own and the basis above stays mandatory.
    assessment_id: Optional[int] = None


class SubmitIn(BaseModel):
    completed_on: Optional[date] = None
    evidence_ref: str = Field("", max_length=500)


class GrantsIn(BaseModel):
    role_id: Optional[int] = None


class OrgUnitIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=150)
    parent_id: Optional[int] = None


class OrgPostIn(BaseModel):
    unit_id: int
    title: str = Field(..., min_length=1, max_length=150)
    profile_id: Optional[int] = None


class ChecklistIn(BaseModel):
    index: int = Field(..., ge=0, le=50)
    done: bool


class FillIn(BaseModel):
    journey_id: Optional[int] = None


class OffboardIn(BaseModel):
    user_id: int
    last_working_day: date
    reason: str = ""


# --- profiles ---------------------------------------------------------------


@router.get("/catalogue", dependencies=[Depends(require_workforce_module)])
def role_catalogue(
    _user: User = Depends(require_permission("workforce:read")),
) -> dict:
    """Roles a SOC might have, for a lead to pick from.

    Reference data, not configuration. Nothing here exists until it is
    adopted, and ``adopted`` says which ones this SOC already has so the
    page can show the difference between "we have this" and "we could".
    """
    from ion.data.soc_role_catalogue import CATEGORIES, by_category

    return {
        "categories": list(CATEGORIES),
        "roles": by_category(),
        "note": (
            "Certificates listed are what each role is usually advertised "
            "with, not what somebody needs to do the job. Any requirement "
            "can be met by assessed proficiency instead. Establishment "
            "numbers are a starting shape for a mid-sized 24/7 SOC, not a "
            "recommendation for yours."
        ),
    }


@router.post("/catalogue/{role_id}/adopt",
             dependencies=[Depends(require_workforce_module)],
             status_code=201)
def adopt_role(
    role_id: str,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("workforce:manage")),
) -> dict:
    """Build a role profile from a catalogue entry, as an editable draft."""
    try:
        profile = wf.adopt_catalogue_role(session, role_id, adopter=user)
    except wf.WorkforceError as exc:
        raise _err(exc) from exc
    version = wf.draft_version(session, profile)
    return {
        "profile": {
            "id": profile.id, "name": profile.name,
            "skills_role_id": profile.skills_role_id,
        },
        "draft_version_id": version.id,
        "requirements": len(version.requirements),
        "next": (
            "Review the suggested requirements, add the mandatory items "
            "this SOC requires, then publish."
        ),
    }


@router.get("/profiles", dependencies=[Depends(require_workforce_module)])
def list_profiles(
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:read")),
):
    out = []
    for p in session.query(RoleProfile).order_by(RoleProfile.name).all():
        published = wf.latest_published(session, p.id)
        out.append({
            "id": p.id, "name": p.name, "description": p.description,
            "nice_work_role": p.nice_work_role, "is_baseline": p.is_baseline,
            "skills_role_id": p.skills_role_id,
            "published_version": published.version if published else None,
            "people_on_version": wf.people_on_version(session, published.id) if published else 0,
        })
    return {"profiles": out, "kinds": list(KINDS), "phases": list(PHASES)}


@router.post("/profiles", dependencies=[Depends(require_workforce_module)], status_code=201)
def create_profile(
    payload: ProfileIn,
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:manage")),
):
    try:
        profile = wf.create_profile(
            session, name=payload.name, description=payload.description,
            nice_work_role=payload.nice_work_role, is_baseline=payload.is_baseline,
            skills_role_id=payload.skills_role_id,
        )
    except wf.WorkforceError as exc:
        raise _err(exc) from exc
    return {"id": profile.id, "name": profile.name}


@router.get("/profiles/{profile_id}/draft", dependencies=[Depends(require_workforce_module)])
def get_draft(
    profile_id: int,
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:manage")),
):
    profile = session.get(RoleProfile, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    draft = wf.draft_version(session, profile)
    session.commit()
    published = wf.latest_published(session, profile_id)
    return {
        "profile": {"id": profile.id, "name": profile.name,
                    "grants_role_id": profile.grants_role_id},
        "version": draft.version,
        "version_id": draft.id,
        "live_version": published.version if published else None,
        "people_on_live": wf.people_on_version(session, published.id) if published else 0,
        "requirements": [_req_out(r) for r in draft.requirements],
    }


def _req_out(r: ProfileRequirement) -> dict:
    return {
        "id": r.id, "name": r.name, "kind": r.kind, "phase": r.phase,
        "validity_months": r.validity_months, "cost": r.cost,
        "funding_type": r.funding_type, "course_id": r.course_id,
    }


@router.post("/versions/{version_id}/requirements",
             dependencies=[Depends(require_workforce_module)], status_code=201)
def add_requirement(
    version_id: int,
    payload: RequirementIn,
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:manage")),
):
    version = session.get(RoleProfileVersion, version_id)
    if version is None:
        raise HTTPException(status_code=404, detail="Version not found")
    try:
        req = wf.add_requirement(session, version, **payload.model_dump())
    except wf.WorkforceError as exc:
        raise _err(exc) from exc
    return _req_out(req)


@router.delete("/requirements/{requirement_id}", dependencies=[Depends(require_workforce_module)])
def delete_requirement(
    requirement_id: int,
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:manage")),
):
    req = session.get(ProfileRequirement, requirement_id)
    if req is None:
        raise HTTPException(status_code=404, detail="Requirement not found")
    try:
        wf.remove_requirement(session, req)
    except wf.WorkforceError as exc:
        raise _err(exc) from exc
    return {"status": "deleted"}


@router.post("/versions/{version_id}/inherit-gate",
             dependencies=[Depends(require_workforce_module)])
def inherit_baseline_gate(
    version_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("workforce:manage")),
) -> dict:
    """Copy the baseline's mandatory items into this draft.

    Asked for rather than applied automatically: which mandatory items a
    role carries is a decision, and a profile that quietly acquired
    requirements would be worse than one that has none.
    """
    version = session.get(RoleProfileVersion, version_id)
    if version is None:
        raise HTTPException(status_code=404, detail="Version not found")
    try:
        added = wf.apply_baseline_gate(session, version, actor=user)
    except wf.WorkforceError as exc:
        raise _err(exc) from exc
    return {"added": added, "version_id": version_id,
            "requirements": len(version.requirements)}


@router.post("/versions/{version_id}/publish", dependencies=[Depends(require_workforce_module)])
def publish(
    version_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("workforce:manage")),
):
    version = session.get(RoleProfileVersion, version_id)
    if version is None:
        raise HTTPException(status_code=404, detail="Version not found")
    try:
        wf.publish_version(session, version, user)
    except wf.WorkforceError as exc:
        raise _err(exc) from exc
    return {"version": version.version, "published_at": version.published_at}


# --- journeys ---------------------------------------------------------------


@router.post("/journeys", dependencies=[Depends(require_workforce_module)], status_code=201)
def assign(
    payload: AssignIn,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("workforce:manage")),
):
    target = session.get(User, payload.user_id)
    version = session.get(RoleProfileVersion, payload.version_id)
    if target is None or version is None:
        raise HTTPException(status_code=404, detail="User or version not found")
    sponsor = session.get(User, payload.sponsor_id) if payload.sponsor_id else None
    try:
        journey = wf.assign_profile(session, user=target, version=version, assigner=user,
                                    is_cover=payload.is_cover, sponsor=sponsor,
                                    supersede=payload.supersede)
    except wf.WorkforceError as exc:
        raise _err(exc) from exc
    return wf.journey_summary(session, journey)


@router.get("/journeys/me", dependencies=[Depends(require_workforce_module)])
def my_journeys(
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    out = []
    for journey in wf.live_journeys(session, user.id):
        wf.sync_course_requirements(session, journey)
        summary = wf.journey_summary(session, journey)
        summary["requirements"] = [_jreq_out(r) for r in journey.requirements]
        out.append(summary)
    return {"journeys": out, "has_access": wf.has_system_access(session, user.id)}


def _jreq_out(r: JourneyRequirement) -> dict:
    return {
        "id": r.id, "name": r.name, "kind": r.kind, "phase": r.phase,
        "status": r.status, "cost": r.cost,
        "expires_on": r.expires_on.isoformat() if r.expires_on else None,
        "verified_at": r.verified_at.isoformat() if r.verified_at else None,
        "completed_on": r.completed_on.isoformat() if r.completed_on else None,
        "submitted_at": r.submitted_at.isoformat() if r.submitted_at else None,
        "evidence_ref": r.evidence_ref,
        "notes": r.notes,
    }


@router.get("/journeys/open", dependencies=[Depends(require_workforce_module)])
def open_queue(
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:read")),
):
    """The lead's queue: who is waiting, and on what.

    Names are resolved in one query; a per-row lookup would be an N+1 over the
    whole workforce.
    """
    journeys = wf.open_journeys(session)
    names = {
        u.id: (u.display_name or u.username)
        for u in session.query(User)
        .filter(User.id.in_([j.user_id for j in journeys] or [0]))
        .all()
    }
    out = []
    for journey in journeys:
        summary = wf.journey_summary(session, journey)
        summary["user"] = names.get(journey.user_id, f"user {journey.user_id}")
        summary["outstanding"] = [
            _jreq_out(r) for r in journey.requirements
            if r.status not in (STATUS_VERIFIED, STATUS_WAIVED)
        ]
        out.append(summary)
    return {"journeys": out}


@router.post("/requirements/{requirement_id}/verify",
             dependencies=[Depends(require_workforce_module)])
def verify(
    requirement_id: int,
    payload: VerifyIn,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    req = session.get(JourneyRequirement, requirement_id)
    if req is None:
        raise HTTPException(status_code=404, detail="Requirement not found")
    try:
        wf.verify_requirement(session, requirement=req, verifier=user,
                              evidence_ref=payload.evidence_ref,
                              expires_on=payload.expires_on)
    except wf.WorkforceError as exc:
        raise _err(exc) from exc
    return _jreq_out(req)


@router.post("/requirements/{requirement_id}/equivalent",
             dependencies=[Depends(require_workforce_module)])
def record_equivalent(
    requirement_id: int,
    payload: EquivalenceIn,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Mark a requirement met by assessed proficiency rather than the item.

    Deliberately a separate endpoint from verify, not a flag on it. The two
    record different facts -- "they hold this" and "they do not hold this,
    and here is what was assessed instead" -- and collapsing them into one
    call with a boolean is how the distinction gets lost at the call site.
    """
    req = session.get(JourneyRequirement, requirement_id)
    if req is None:
        raise HTTPException(status_code=404, detail="Requirement not found")
    try:
        wf.record_equivalence(session, requirement=req, assessor=user,
                              basis=payload.basis,
                              expires_on=payload.expires_on,
                              assessment_id=payload.assessment_id)
    except wf.WorkforceError as exc:
        raise _err(exc) from exc
    return _jreq_out(req)


# --- currency ---------------------------------------------------------------


@router.get("/expiring", dependencies=[Depends(require_workforce_module)])
def expiring(
    within_days: int = 90,
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:read")),
):
    items = wf.expiring(session, within_days=max(1, min(within_days, 730)))
    return {"items": [
        {"user_id": i.journey.user_id, "journey_id": i.journey.id,
         "requirement": i.requirement.name, "phase": i.requirement.phase,
         "kind": i.requirement.kind, "status": i.requirement.status,
         "expires_on": i.requirement.expires_on.isoformat(),
         "days_left": i.days_left, "threshold": i.threshold}
        for i in items
    ]}


@router.post("/sweep", dependencies=[Depends(require_workforce_module)])
def sweep(
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:manage")),
):
    """Run the expiry sweep now. Also runs on a schedule."""
    return wf.sweep_expiries(session)


@router.get("/orbat", dependencies=[Depends(require_workforce_module)])
def orbat(
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:read")),
):
    journeys = (
        session.query(UserJourney)
        .filter(UserJourney.stage != "closed")
        .order_by(UserJourney.is_cover.asc())
        .all()
    )
    people: dict = {}
    for j in journeys:
        summary = wf.journey_summary(session, j)
        entry = people.setdefault(j.user_id, {"user_id": j.user_id, "primary": None,
                                              "cover": [], "stage": j.stage})
        if j.is_cover:
            entry["cover"].append(summary)
        else:
            entry["primary"] = summary
            entry["stage"] = j.stage

    names = {u.id: (u.display_name or u.username)
             for u in session.query(User).filter(User.id.in_(list(people))).all()}
    for uid, entry in people.items():
        entry["name"] = names.get(uid, f"user {uid}")

    profiles = [p.name for p in session.query(RoleProfile).order_by(RoleProfile.name).all()]
    return {
        "people": list(people.values()),
        "cover": {name: wf.capability_cover(session, name) for name in profiles},
        "cover_weight": wf.COVER_WEIGHT,
    }


# --- offboarding ------------------------------------------------------------


@router.post("/leavers", dependencies=[Depends(require_workforce_module)], status_code=201)
def start_offboarding(
    payload: OffboardIn,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("workforce:manage")),
):
    target = session.get(User, payload.user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        record = wf.start_offboarding(session, user=target, raiser=user,
                                      last_working_day=payload.last_working_day,
                                      reason=payload.reason)
    except wf.WorkforceError as exc:
        raise _err(exc) from exc
    return {"id": record.id, "revoke_at": record.revoke_at, "checklist": record.checklist}


@router.post("/leavers/{record_id}/revoke", dependencies=[Depends(require_workforce_module)])
def revoke(
    record_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("workforce:manage")),
):
    record = session.get(LeaverRecord, record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Leaver record not found")
    try:
        closed = wf.revoke_now(session, record, actor=user)
    except wf.WorkforceError as exc:
        raise _err(exc) from exc
    return {"roles_closed": closed, "revoked_at": record.revoked_at}


@router.get("/leavers", dependencies=[Depends(require_workforce_module)])
def list_leavers(
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:read")),
) -> dict:
    import json as _json

    rows: List[LeaverRecord] = (
        session.query(LeaverRecord).order_by(LeaverRecord.last_working_day.desc()).limit(100).all()
    )
    names = {u.id: (u.display_name or u.username)
             for u in session.query(User)
             .filter(User.id.in_([r.user_id for r in rows] or [0])).all()}

    def _list(raw):
        try:
            return _json.loads(raw or "[]")
        except ValueError:
            return []

    return {"leavers": [
        {"id": r.id, "user_id": r.user_id,
         "name": names.get(r.user_id, f"user {r.user_id}"),
         "last_working_day": r.last_working_day.isoformat(),
         "revoke_at": r.revoke_at.isoformat() if r.revoke_at else None,
         "reason": r.reason,
         "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
         "checklist": _list(r.checklist)}
        for r in rows
    ]}


@router.put("/leavers/{record_id}/checklist",
            dependencies=[Depends(require_workforce_module)])
def tick_checklist(
    record_id: int,
    payload: ChecklistIn,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("workforce:manage")),
):
    record = session.get(LeaverRecord, record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Leaver record not found")
    try:
        items = wf.set_checklist_item(session, record=record, index=payload.index,
                                      done=payload.done, actor=user)
    except wf.WorkforceError as exc:
        raise _err(exc) from exc
    return {"id": record.id, "checklist": items}


@router.post("/requirements/{requirement_id}/submit",
             dependencies=[Depends(require_workforce_module)])
def submit_item(
    requirement_id: int,
    payload: SubmitIn,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """The joiner's one write: claim completion and queue it for a verifier."""
    req = session.get(JourneyRequirement, requirement_id)
    if req is None:
        raise HTTPException(status_code=404, detail="Requirement not found")
    try:
        wf.submit_requirement(session, requirement=req, submitter=user,
                              completed_on=payload.completed_on,
                              evidence_ref=payload.evidence_ref)
    except wf.WorkforceError as exc:
        raise _err(exc) from exc
    return _jreq_out(req)


@router.post("/requirements/{requirement_id}/withdraw",
             dependencies=[Depends(require_workforce_module)])
def withdraw_item(
    requirement_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    req = session.get(JourneyRequirement, requirement_id)
    if req is None:
        raise HTTPException(status_code=404, detail="Requirement not found")
    try:
        wf.withdraw_submission(session, requirement=req, actor=user)
    except wf.WorkforceError as exc:
        raise _err(exc) from exc
    return _jreq_out(req)


@router.get("/verification-queue", dependencies=[Depends(require_workforce_module)])
def verification_queue(
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:verify")),
):
    """Submitted items awaiting a verifier, oldest first."""
    items = wf.awaiting_verification(session)
    journeys = {r.journey_id for r in items}
    ctx = {j.id: j for j in session.query(UserJourney)
           .filter(UserJourney.id.in_(list(journeys) or [0])).all()}
    names = {u.id: (u.display_name or u.username)
             for u in session.query(User)
             .filter(User.id.in_([j.user_id for j in ctx.values()] or [0])).all()}
    out = []
    for r in items:
        j = ctx.get(r.journey_id)
        entry = _jreq_out(r)
        entry["user"] = names.get(j.user_id, f"user {j.user_id}") if j else "?"
        entry["user_id"] = j.user_id if j else None
        entry["role"] = j.version.profile.name if j and j.version else "?"
        out.append(entry)
    return {"items": out, "count": len(out)}


@router.get("/ion-roles", dependencies=[Depends(require_workforce_module)])
def ion_roles(
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:manage")),
):
    """The ION roles a profile can grant, for the schema editor's dropdown."""
    from ion.models.user import Role

    rows = session.query(Role).order_by(Role.name).all()
    return {"roles": [
        {"id": r.id, "name": r.name, "permissions": len(r.permissions)}
        for r in rows
    ]}


@router.put("/profiles/{profile_id}/grants",
            dependencies=[Depends(require_workforce_module)])
def set_grants(
    profile_id: int,
    payload: GrantsIn,
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:manage")),
):
    """Map a profile to the ION role its cleared gate confers."""
    from ion.models.user import Role

    profile = session.get(RoleProfile, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    if payload.role_id is not None and session.get(Role, payload.role_id) is None:
        raise HTTPException(status_code=400, detail="No such ION role")
    profile.grants_role_id = payload.role_id
    session.flush()

    # People who already cleared the gate must gain (or lose) the role NOW --
    # nothing else about their journey will change to trigger the sync.
    holders = (
        session.query(User)
        .join(UserJourney, UserJourney.user_id == User.id)
        .join(RoleProfileVersion, UserJourney.version_id == RoleProfileVersion.id)
        .filter(RoleProfileVersion.profile_id == profile.id)
        .distinct()
        .all()
    )
    for holder in holders:
        wf.sync_granted_roles(session, holder)
    session.commit()
    return {"id": profile.id, "grants_role_id": profile.grants_role_id,
            "resynced": len(holders)}


@router.get("/people", dependencies=[Depends(require_workforce_module)])
def people(
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:read")),
):
    """The lead's roster: everyone, their journeys, their target role.

    Batched lookups throughout -- one query per table, never per person.
    """
    from ion.models.skills import UserCareerGoal

    users = session.query(User).filter(User.is_active.is_(True)).order_by(User.username).all()
    journeys = (
        session.query(UserJourney)
        .filter(UserJourney.stage != "closed")
        .order_by(UserJourney.is_cover.asc(), UserJourney.started_at.asc())
        .all()
    )
    by_user: dict = {}
    for j in journeys:
        by_user.setdefault(j.user_id, []).append(j)
    goals = {g.user_id: g.target_role for g in session.query(UserCareerGoal).all()}

    out = []
    for u in users:
        js = by_user.get(u.id, [])
        out.append({
            "user_id": u.id,
            "name": u.display_name or u.username,
            "username": u.username,
            "ion_roles": sorted(r.name for r in u.roles),
            "target_role": goals.get(u.id),
            "has_access": wf.has_system_access(session, u.id) if js else None,
            "journeys": [wf.journey_summary(session, j) | {
                "role": j.version.profile.name if j.version else "?",
                "profile_id": j.version.profile_id if j.version else None,
                "awaiting_verification": sum(
                    1 for r in j.requirements if r.status == "submitted"),
            } for j in js],
        })
    return {"people": out}


# --- org structure ----------------------------------------------------------


class DutyIn(BaseModel):
    user_id: int
    week_start: date
    duty: str = "duty_analyst"
    notes: str = ""


@router.get("/duty", dependencies=[Depends(require_workforce_module)])
def duty_rota(
    weeks: int = Query(6, ge=1, le=52),
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:read")),
) -> dict:
    """Who is on duty, and which coming weeks have nobody.

    Unfilled weeks come back as rows rather than being absent: a caller
    that only ever sees assigned weeks cannot tell an empty one from a
    week it has not loaded, and that is how the standup quietly stops
    happening.
    """
    from ion.services import duty_roster_service as duty

    return duty.rota_summary(session, weeks=weeks)


@router.post("/duty", dependencies=[Depends(require_workforce_module)],
             status_code=201)
def set_duty(
    body: DutyIn,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("workforce:manage")),
) -> dict:
    """Put somebody on duty for a week, replacing whoever held it."""
    from ion.services import duty_roster_service as duty

    target = session.get(User, body.user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        row = duty.assign(session, duty=body.duty, week_start=body.week_start,
                          user=target, actor=user, notes=body.notes)
    except duty.DutyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return row.to_dict()


@router.post("/duty/{assignment_id}/acknowledge",
             dependencies=[Depends(require_workforce_module)])
def acknowledge_duty(
    assignment_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """The holder confirms they have picked it up.

    Only the holder: an entry nobody acknowledged is a plan rather than a
    fact, and a lead ticking it for them erases that signal.
    """
    from ion.services import duty_roster_service as duty

    try:
        row = duty.acknowledge(session, assignment_id=assignment_id,
                               actor=user)
    except duty.DutyError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    return row.to_dict()


@router.get("/establishment", dependencies=[Depends(require_workforce_module)])
def establishment(
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:read")),
) -> dict:
    """Per role: how many posts, how many held, how short.

    Deliberately separate from /org, which is the org-chart shape. This
    answers the question a lead actually asks, and keeps "filling" apart
    from "filled" because somebody still in training is a gap in cover
    tonight just as much as an empty post is.
    """
    return wf.establishment_summary(session)


@router.get("/coverage", dependencies=[Depends(require_workforce_module)])
def coverage(
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:read")),
) -> dict:
    """Who could cover each day-to-day pillar, and on what evidence.

    Separate from /establishment, which counts posts. This counts
    capability, a different question: a fully established SOC can still
    have nobody who can do forensics, and six filled L1 posts do not
    cover threat intelligence.

    The three bases stay in separate fields on purpose. Collapsing them
    into one number turns "three analysts who rated themselves 4 out of
    5" into "three forensics analysts", and the people reading this
    screen will believe it.
    """
    return coverage_service.pillar_coverage(session)


@router.post("/establishment/from-catalogue",
             dependencies=[Depends(require_workforce_module)],
             status_code=201)
def establish(
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("workforce:manage")),
) -> dict:
    """Create posts for adopted roles at the catalogue's suggested strength.

    Only adds, never removes: a lead who has already trimmed the
    establishment must not have it reset by running this again.
    """
    try:
        return wf.establish_from_catalogue(session, actor=user)
    except wf.WorkforceError as exc:
        raise _err(exc) from exc


@router.get("/org", dependencies=[Depends(require_workforce_module)])
def org(
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:read")),
):
    return wf.org_tree(session)


@router.post("/org/units", dependencies=[Depends(require_workforce_module)],
             status_code=201)
def create_unit(
    payload: OrgUnitIn,
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:manage")),
):
    if payload.parent_id is not None and session.get(OrgUnit, payload.parent_id) is None:
        raise HTTPException(status_code=400, detail="No such parent unit")
    unit = OrgUnit(name=payload.name, parent_id=payload.parent_id)
    session.add(unit)
    session.commit()
    return {"id": unit.id, "name": unit.name, "parent_id": unit.parent_id}


@router.delete("/org/units/{unit_id}", dependencies=[Depends(require_workforce_module)])
def delete_unit(
    unit_id: int,
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:manage")),
):
    unit = session.get(OrgUnit, unit_id)
    if unit is None:
        raise HTTPException(status_code=404, detail="Unit not found")
    session.delete(unit)
    session.commit()
    return {"deleted": unit_id}


@router.post("/org/posts", dependencies=[Depends(require_workforce_module)],
             status_code=201)
def create_post(
    payload: OrgPostIn,
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:manage")),
):
    if session.get(OrgUnit, payload.unit_id) is None:
        raise HTTPException(status_code=400, detail="No such unit")
    if payload.profile_id is not None and session.get(RoleProfile, payload.profile_id) is None:
        raise HTTPException(status_code=400, detail="No such role profile")
    post = OrgPost(unit_id=payload.unit_id, title=payload.title,
                   profile_id=payload.profile_id)
    session.add(post)
    session.commit()
    return {"id": post.id, "unit_id": post.unit_id, "title": post.title}


@router.delete("/org/posts/{post_id}", dependencies=[Depends(require_workforce_module)])
def delete_post(
    post_id: int,
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission("workforce:manage")),
):
    post = session.get(OrgPost, post_id)
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    session.delete(post)
    session.commit()
    return {"deleted": post_id}


@router.put("/org/posts/{post_id}/fill", dependencies=[Depends(require_workforce_module)])
def fill(
    post_id: int,
    payload: FillIn,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("workforce:manage")),
):
    post = session.get(OrgPost, post_id)
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    try:
        wf.fill_post(session, post=post, journey_id=payload.journey_id, actor=user)
    except wf.WorkforceError as exc:
        raise _err(exc) from exc
    return {"id": post.id, "filled_by_journey_id": post.filled_by_journey_id}
