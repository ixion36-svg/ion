"""Workforce lifecycle logic.

The rules that matter, in one place:

* A profile version is immutable once published. Assigning it COPIES its
  requirements onto the journey, so a later edit to the role cannot change
  what someone was required to hold.
* Gate requirements are person-level. They are satisfied once, are not
  repeated when a cover role is added, and a lapse suspends every role.
* Readiness requirements are role-level. A lapse withdraws that role only.
* Authorisation is checked INSIDE this service before any mutation, never by
  the caller afterwards (the v0.20.1 TOCTOU lesson).
"""

from __future__ import annotations

import calendar
import json
import logging
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import List, Optional, Sequence

from sqlalchemy.orm import Session

from ion.models.user import AuditLog, User
from ion.models.workforce import (
    KIND_CERT,
    KIND_COURSE,
    PHASE_GATE,
    PHASE_READINESS,
    STAGE_CLOSED,
    STAGE_OPERATIONAL,
    STAGE_PRE_ACCESS,
    STAGE_SUSPENDED,
    STAGE_TRAINING,
    STAGE_WITHDRAWN,
    STATUS_EXPIRED,
    STATUS_PENDING,
    STATUS_SUBMITTED,
    STATUS_VERIFIED,
    STATUS_WAIVED,
    JourneyRequirement,
    LeaverRecord,
    OrgPost,
    OrgUnit,
    ProfileRequirement,
    RoleProfile,
    RoleProfileVersion,
    UserEnrolment,
    UserJourney,
)

logger = logging.getLogger(__name__)

# Days before expiry at which the person and their lead are reminded.
REMINDER_DAYS = (90, 60, 30, 7)

# A cover holder counts for less than someone whose day job it is, so depth
# cannot disguise a thin rota.
COVER_WEIGHT = 0.5


class WorkforceError(Exception):
    """A lifecycle rule was violated. Carries a caller-safe message."""


# --- profiles ---------------------------------------------------------------


def create_profile(session: Session, *, name: str, description: str = "",
                   nice_work_role: str = "", is_baseline: bool = False) -> RoleProfile:
    existing = session.query(RoleProfile).filter(RoleProfile.name == name).one_or_none()
    if existing is not None:
        raise WorkforceError(f"A role profile named {name!r} already exists")
    profile = RoleProfile(
        name=name, description=description or None,
        nice_work_role=nice_work_role or None, is_baseline=is_baseline,
    )
    session.add(profile)
    session.flush()
    draft_version(session, profile)
    session.commit()
    return profile


def draft_version(session: Session, profile: RoleProfile) -> RoleProfileVersion:
    """Return the open draft for ``profile``, creating one if needed.

    A new draft starts as a copy of the latest published version, so editing a
    live role means adjusting it rather than retyping it.
    """
    open_draft = (
        session.query(RoleProfileVersion)
        .filter(RoleProfileVersion.profile_id == profile.id,
                RoleProfileVersion.published_at.is_(None))
        .order_by(RoleProfileVersion.version.desc())
        .first()
    )
    if open_draft is not None:
        return open_draft

    latest = latest_published(session, profile.id)
    number = (latest.version + 1) if latest else 1
    version = RoleProfileVersion(profile_id=profile.id, version=number)
    session.add(version)
    session.flush()

    if latest is not None:
        for src in latest.requirements:
            session.add(_copy_profile_requirement(src, version.id))
        session.flush()
    return version


def _copy_profile_requirement(src: ProfileRequirement, version_id: int) -> ProfileRequirement:
    return ProfileRequirement(
        version_id=version_id, name=src.name, kind=src.kind, phase=src.phase,
        description=src.description, validity_months=src.validity_months,
        course_id=src.course_id, cost=src.cost, funding_type=src.funding_type,
        ordering=src.ordering,
    )


def latest_published(session: Session, profile_id: int) -> Optional[RoleProfileVersion]:
    return (
        session.query(RoleProfileVersion)
        .filter(RoleProfileVersion.profile_id == profile_id,
                RoleProfileVersion.published_at.isnot(None))
        .order_by(RoleProfileVersion.version.desc())
        .first()
    )


def add_requirement(session: Session, version: RoleProfileVersion, **fields) -> ProfileRequirement:
    if version.is_published:
        raise WorkforceError("This version is published and cannot be edited; start a new draft")
    ordering = fields.pop("ordering", None)
    if ordering is None:
        ordering = len(version.requirements)
    req = ProfileRequirement(version_id=version.id, ordering=ordering, **fields)
    session.add(req)
    session.commit()
    return req


def remove_requirement(session: Session, requirement: ProfileRequirement) -> None:
    version = session.get(RoleProfileVersion, requirement.version_id)
    if version is not None and version.is_published:
        raise WorkforceError("This version is published and cannot be edited; start a new draft")
    session.delete(requirement)
    session.commit()


def publish_version(session: Session, version: RoleProfileVersion, publisher: User) -> RoleProfileVersion:
    if version.is_published:
        raise WorkforceError("Already published")
    if not version.requirements:
        raise WorkforceError("A version needs at least one requirement before it can be published")
    version.published_at = datetime.utcnow()
    version.published_by_id = publisher.id
    session.commit()
    return version


def people_on_version(session: Session, version_id: int) -> int:
    """How many live journeys still reference this version."""
    return (
        session.query(UserJourney)
        .filter(UserJourney.version_id == version_id,
                UserJourney.stage.notin_([STAGE_CLOSED, STAGE_WITHDRAWN]))
        .count()
    )


# --- assignment -------------------------------------------------------------


def verified_gate_names(session: Session, user_id: int) -> set:
    """Gate requirements this person already holds, by name.

    Gate items are person-level: a cover role does not re-run the clearance
    someone already has.
    """
    rows = (
        session.query(JourneyRequirement)
        .join(UserJourney, JourneyRequirement.journey_id == UserJourney.id)
        .filter(UserJourney.user_id == user_id,
                UserJourney.stage != STAGE_CLOSED,
                JourneyRequirement.phase == PHASE_GATE,
                JourneyRequirement.status.in_([STATUS_VERIFIED, STATUS_WAIVED]))
        .all()
    )
    return {r.name for r in rows}


def _baseline_version(session: Session) -> Optional[RoleProfileVersion]:
    """The published version of the baseline profile, or None.

    Deterministic when a deployment has misconfigured two baselines:
    lowest profile id wins. Two baselines is a mistake either way, but one
    that enrols one starter on induction A and the next on induction B is
    the hardest kind to notice.
    """
    profile = (
        session.query(RoleProfile)
        .filter(RoleProfile.is_baseline.is_(True),
                RoleProfile.is_active.is_(True))
        .order_by(RoleProfile.id.asc())
        .first()
    )
    if profile is None:
        return None
    # Latest published, not the first: a deployment that has revised its
    # induction should put new starters on the current one. A draft is
    # somebody still writing it, and enrolling people onto a half-written
    # mandatory list is worse than enrolling them onto none, because it
    # looks deliberate.
    return latest_published(session, profile.id)


def enrol_on_baseline(session: Session,
                      user: User) -> Optional[UserJourney]:
    """Open the mandatory journey for a newly created account.

    The workflow this serves: somebody gets a local account, the account is
    gated behind permissions until they pass the mandatory training, and
    passing it is what confers their role and its permissions.

    ``is_baseline`` and ``grants_role_id`` already described that, and
    nothing opened the journey, so it only applied to people a lead had
    remembered to enrol by hand -- when the person nobody remembered is
    exactly the one who should be gated.

    Unlike ``assign_profile`` this takes no assigner and checks no
    permission. It runs when an account is created, which may be a
    bootstrap or an SSO first login with no human in the loop. It cannot
    grant anything: the journey opens at pre_access with everything
    pending, and ``sync_granted_roles`` still decides what a cleared gate
    confers.

    Returns None rather than raising, always. A deployment that cannot add
    users because the workforce module has a problem is a worse failure
    than one with no journeys.
    """
    try:
        version = _baseline_version(session)
        if version is None:
            logger.debug(
                "No published baseline profile; %s enrolled on nothing",
                user.username,
            )
            return None

        existing = _live_journey_for_profile(
            session, user.id, version.profile_id)
        if existing is not None:
            # A re-run bootstrap or a repeated SSO callback must not
            # duplicate somebody's mandatory list.
            return existing

        journey = UserJourney(
            user_id=user.id, version_id=version.id, is_cover=False,
            stage=STAGE_PRE_ACCESS,
        )
        session.add(journey)
        session.flush()

        already = verified_gate_names(session, user.id)
        now = datetime.utcnow()
        for src in version.requirements:
            carried = src.phase == PHASE_GATE and src.name in already
            session.add(JourneyRequirement(
                journey_id=journey.id,
                source_requirement_id=src.id,
                name=src.name, kind=src.kind, phase=src.phase,
                validity_months=src.validity_months, course_id=src.course_id,
                cost=src.cost, ordering=src.ordering,
                status=STATUS_VERIFIED if carried else STATUS_PENDING,
                verified_at=now if carried else None,
                notes=("Carried from an existing verified gate item"
                       if carried else None),
                expires_on=(_expiry_for(src.validity_months, now)
                            if carried else None),
            ))
        session.flush()
        _sync_training_artifacts(session, journey)
        _recompute_stage(session, journey)
        session.add(AuditLog(
            user_id=user.id, action="workforce_baseline_enrolled",
            resource_type="user_journey", resource_id=journey.id,
            details=f"{user.username} enrolled on "
                    f"{version.profile.name} v{version.version} at account "
                    f"creation",
        ))
        session.commit()
        logger.info("Enrolled %s on baseline %s v%s",
                    user.username, version.profile.name, version.version)
        return journey
    except Exception:  # noqa: BLE001
        logger.exception(
            "Baseline enrolment failed for %s; the account still exists",
            getattr(user, "username", "?"),
        )
        try:
            session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return None


def _live_journey_for_profile(session: Session, user_id: int,
                              profile_id: int) -> Optional[UserJourney]:
    """This person's open journey for a role, whatever version it is on."""
    return (
        session.query(UserJourney)
        .join(RoleProfileVersion,
              UserJourney.version_id == RoleProfileVersion.id)
        .filter(UserJourney.user_id == user_id,
                RoleProfileVersion.profile_id == profile_id,
                UserJourney.stage.notin_([STAGE_CLOSED, STAGE_WITHDRAWN]))
        .first()
    )


def _carryable(journey: UserJourney, today: Optional[date] = None) -> dict:
    """Items on ``journey`` that a superseding journey may inherit.

    Keyed by name, both phases. Gate items are person-level and already
    handled by ``verified_gate_names``; readiness items were earned for
    THIS role, so reissuing them on a version bump is pure rework -- the
    person is asked again for a sign-off they already hold.

    Expired items are excluded. Carrying one across would launder a lapse
    into a clean record, which is the one thing this must never do.
    """
    day = today or date.today()
    out = {}
    for req in journey.requirements:
        if req.status not in (STATUS_VERIFIED, STATUS_WAIVED):
            continue
        if req.expires_on and req.expires_on < day:
            continue
        out[req.name] = req
    return out


def assign_profile(session: Session, *, user: User, version: RoleProfileVersion,
                   assigner: User, is_cover: bool = False,
                   sponsor: Optional[User] = None,
                   supersede: bool = False) -> UserJourney:
    """Start a journey for ``user`` against ``version``.

    Requirements are copied, not referenced. Gate items the person has already
    satisfied elsewhere are carried across as verified rather than reissued.

    ``supersede`` rolls an existing journey for the same role onto this
    version: the old one closes and items already verified and still in date
    come across by name.

    Without it, someone already on v1 of a role is refused v2. The guard is
    per PROFILE rather than per version because two live journeys for one
    role duplicate that person's requirements, list every expiry twice, and
    make capability cover count them twice. The last one matters most: that
    number answers "are we covered tonight", and it was over-reporting.
    """
    if not assigner.has_permission("workforce:manage"):
        raise WorkforceError("Permission denied")
    if not version.is_published:
        raise WorkforceError("Only a published version can be assigned")
    # A self-sponsor could verify their own gate and grant themselves the
    # profile's role -- the exact bypass the submit/verify split exists for.
    if sponsor is not None and sponsor.id == user.id:
        raise WorkforceError("A person cannot sponsor their own journey")

    open_same = _live_journey_for_profile(session, user.id, version.profile_id)
    if open_same is not None and not supersede:
        held = session.get(RoleProfileVersion, open_same.version_id)
        raise WorkforceError(
            f"This person already holds an open journey for that role "
            f"(journey {open_same.id}, version {held.version if held else '?'}). "
            f"Supersede it to move them onto this version: that closes the "
            f"old journey and carries across what they already hold."
        )

    superseded = open_same if (open_same is not None and supersede) else None
    inherited = _carryable(superseded) if superseded is not None else {}

    journey = UserJourney(
        user_id=user.id, version_id=version.id, is_cover=is_cover,
        stage=STAGE_PRE_ACCESS, sponsor_id=sponsor.id if sponsor else None,
    )
    session.add(journey)
    session.flush()

    already = verified_gate_names(session, user.id)
    now = datetime.utcnow()

    for src in version.requirements:
        prior = inherited.get(src.name)
        if prior is not None:
            # From the journey being superseded: keep its status, when it was
            # verified, and its ORIGINAL expiry. Recalculating the expiry
            # would let a change to the role's wording extend every clearance
            # in the SOC by its full validity period.
            session.add(JourneyRequirement(
                journey_id=journey.id,
                source_requirement_id=src.id,
                name=src.name, kind=src.kind, phase=src.phase,
                validity_months=src.validity_months, course_id=src.course_id,
                cost=src.cost, ordering=src.ordering,
                status=prior.status,
                verified_at=prior.verified_at,
                completed_on=prior.completed_on,
                evidence_ref=prior.evidence_ref,
                expires_on=prior.expires_on,
                notes=f"Carried from journey {superseded.id} on supersede",
            ))
            continue
        carried = src.phase == PHASE_GATE and src.name in already
        session.add(JourneyRequirement(
            journey_id=journey.id,
            source_requirement_id=src.id,
            name=src.name, kind=src.kind, phase=src.phase,
            validity_months=src.validity_months, course_id=src.course_id,
            cost=src.cost, ordering=src.ordering,
            status=STATUS_VERIFIED if carried else STATUS_PENDING,
            verified_at=now if carried else None,
            notes="Carried from an existing verified gate item" if carried else None,
            expires_on=_expiry_for(src.validity_months, now) if carried else None,
        ))

    if superseded is not None:
        superseded.stage = STAGE_CLOSED
        session.add(AuditLog(
            user_id=assigner.id, action="workforce_journey_superseded",
            resource_type="user_journey", resource_id=superseded.id,
            details=f"user {user.username}: journey {superseded.id} closed, "
                    f"replaced by journey {journey.id} on "
                    f"{version.profile.name} v{version.version}; "
                    f"{len(inherited)} item(s) carried across",
        ))

    session.flush()
    _sync_training_artifacts(session, journey)
    _recompute_stage(session, journey)
    session.add(AuditLog(
        user_id=assigner.id, action="workforce_profile_assigned",
        resource_type="user_journey", resource_id=journey.id,
        details=f"user {user.username}: {version.profile.name} v{version.version}"
                f"{' (cover)' if is_cover else ''}",
    ))
    session.commit()
    return journey


def _expiry_for(validity_months: Optional[int], when: datetime) -> Optional[date]:
    """The same day of the month, ``validity_months`` on.

    Calendar months, not 30-day blocks: a certificate expires on the
    anniversary printed on it, and a reminder that fires three weeks early
    teaches people to ignore reminders. Short months clamp to their last day.
    """
    if not validity_months:
        return None
    start = when.date() if isinstance(when, datetime) else when
    year, month = divmod(start.month - 1 + validity_months, 12)
    year, month = start.year + year, month + 1
    return date(year, month, min(start.day, calendar.monthrange(year, month)[1]))


def _sync_training_artifacts(session: Session, journey: UserJourney) -> None:
    """Readiness certs and courses become TrainingPlanItem rows.

    The /training page's plans, cost roll-ups and forecast already exist;
    tracking the same spend a second time here is how two figures drift.
    The journey requirement keeps its copied cost only as the audit snapshot
    of what was expected at assignment.
    """
    from ion.models.skills import TrainingPlan, TrainingPlanItem

    profile = journey.version.profile if journey.version else None
    if profile is None:
        return
    plan_name = f"Onboarding: {profile.name}"
    plan = (
        session.query(TrainingPlan)
        .filter(TrainingPlan.user_id == journey.user_id,
                TrainingPlan.name == plan_name)
        .one_or_none()
    )
    if plan is None:
        plan = TrainingPlan(user_id=journey.user_id, name=plan_name,
                            target_role=profile.name, status="active")
        session.add(plan)
        session.flush()

    existing = {
        i.cert_name for i in
        session.query(TrainingPlanItem).filter(TrainingPlanItem.plan_id == plan.id)
    }
    for req in journey.requirements:
        if req.phase != PHASE_READINESS or req.kind not in (KIND_CERT, KIND_COURSE):
            continue
        if req.name in existing or req.satisfied:
            continue
        src = (session.get(ProfileRequirement, req.source_requirement_id)
               if req.source_requirement_id else None)
        session.add(TrainingPlanItem(
            plan_id=plan.id, cert_name=req.name, price=req.cost or 0.0,
            funding_type=getattr(src, "funding_type", None) or "company",
            status="planned", priority=req.ordering,
        ))
    session.flush()


def _record_verified_training(session: Session, journey: UserJourney,
                              requirement: JourneyRequirement) -> None:
    """A verified cert lands in TeamCertification; its plan item completes.

    Both stores predate this module and feed the /training page -- write to
    them rather than growing a third copy of the same fact.
    """
    from ion.models.skills import TeamCertification, TrainingPlan, TrainingPlanItem

    now = datetime.utcnow()
    if requirement.kind == KIND_CERT:
        cert = (
            session.query(TeamCertification)
            .filter(TeamCertification.user_id == journey.user_id,
                    TeamCertification.cert_name == requirement.name)
            .one_or_none()
        )
        if cert is None:
            cert = TeamCertification(user_id=journey.user_id,
                                     cert_name=requirement.name)
            session.add(cert)
        cert.obtained_date = requirement.completed_on or now.date()
        cert.expiry_date = requirement.expires_on
        cert.status = "active"

    if requirement.phase == PHASE_READINESS and requirement.kind in (KIND_CERT, KIND_COURSE):
        item = (
            session.query(TrainingPlanItem)
            .join(TrainingPlan, TrainingPlanItem.plan_id == TrainingPlan.id)
            .filter(TrainingPlan.user_id == journey.user_id,
                    TrainingPlanItem.cert_name == requirement.name,
                    TrainingPlanItem.status != "completed")
            .first()
        )
        if item is not None:
            item.status = "completed"
            item.completed_at = now
    session.flush()


# --- verification -----------------------------------------------------------


def verify_requirement(session: Session, *, requirement: JourneyRequirement,
                       verifier: User, evidence_ref: str = "",
                       expires_on: Optional[date] = None) -> JourneyRequirement:
    """Mark one requirement verified.

    The authorisation check runs here, before the mutation, because the caller
    cannot be trusted to have done it against the row we are about to write.
    """
    journey = session.get(UserJourney, requirement.journey_id)
    if journey is None:
        raise WorkforceError("Journey not found")
    if not _may_verify(verifier, journey):
        raise WorkforceError("Permission denied")
    if requirement.status in (STATUS_VERIFIED, STATUS_WAIVED):
        return requirement

    now = datetime.utcnow()
    requirement.status = STATUS_VERIFIED
    requirement.verified_by_id = verifier.id
    requirement.verified_at = now
    requirement.evidence_ref = evidence_ref or requirement.evidence_ref
    requirement.expires_on = expires_on or _expiry_for(requirement.validity_months, now)
    requirement.last_reminder_days = None

    _record_verified_training(session, journey, requirement)
    session.flush()
    _recompute_stage(session, journey)
    session.add(AuditLog(
        user_id=verifier.id, action="workforce_requirement_verified",
        resource_type="journey_requirement", resource_id=requirement.id,
        details=f"{requirement.name} for user_id {journey.user_id}",
    ))
    session.commit()
    return requirement


def _may_verify(verifier: User, journey: UserJourney) -> bool:
    if verifier.has_permission("workforce:verify"):
        return True
    # A sponsor may verify their own people without the global permission.
    return journey.sponsor_id is not None and journey.sponsor_id == verifier.id


def sync_course_requirements(session: Session, journey: UserJourney) -> int:
    """Resolve COURSE requirements from enrolment rather than a manual tick."""
    pending = [r for r in journey.requirements
               if r.kind == KIND_COURSE and r.course_id and not r.satisfied]
    if not pending:
        return 0

    done = {
        e.course_id for e in session.query(UserEnrolment)
        .filter(UserEnrolment.user_id == journey.user_id,
                UserEnrolment.course_id.in_([r.course_id for r in pending]),
                UserEnrolment.completed_at.isnot(None))
        .all()
    }
    changed = 0
    now = datetime.utcnow()
    for req in pending:
        if req.course_id in done:
            req.status = STATUS_VERIFIED
            req.verified_at = now
            req.notes = "Completed in ION training"
            req.expires_on = _expiry_for(req.validity_months, now)
            changed += 1
    if changed:
        session.flush()
        _recompute_stage(session, journey)
        session.commit()
    return changed


def submit_requirement(session: Session, *, requirement: JourneyRequirement,
                       submitter: User, completed_on: Optional[date] = None,
                       evidence_ref: str = "") -> JourneyRequirement:
    """The person puts a requirement forward for verification.

    This is deliberately the only write a joiner can make. It records what
    they claim and moves the item to SUBMITTED; it never reaches VERIFIED,
    so nobody can clear their own gate and grant themselves the role.
    """
    journey = session.get(UserJourney, requirement.journey_id)
    if journey is None:
        raise WorkforceError("Journey not found")
    if journey.user_id != submitter.id and not _may_verify(submitter, journey):
        raise WorkforceError("Permission denied")
    if requirement.status in (STATUS_VERIFIED, STATUS_WAIVED):
        raise WorkforceError("This item is already verified")

    requirement.completed_on = completed_on or date.today()
    requirement.evidence_ref = evidence_ref or requirement.evidence_ref
    requirement.submitted_at = datetime.utcnow()
    requirement.status = STATUS_SUBMITTED
    session.commit()
    return requirement


def withdraw_submission(session: Session, *, requirement: JourneyRequirement,
                        actor: User) -> JourneyRequirement:
    """Take a submission back before it is verified."""
    journey = session.get(UserJourney, requirement.journey_id)
    if journey is None:
        raise WorkforceError("Journey not found")
    if journey.user_id != actor.id and not _may_verify(actor, journey):
        raise WorkforceError("Permission denied")
    if requirement.status != STATUS_SUBMITTED:
        raise WorkforceError("Only a submitted item can be withdrawn")
    requirement.status = STATUS_PENDING
    requirement.submitted_at = None
    session.commit()
    return requirement


def awaiting_verification(session: Session) -> List[JourneyRequirement]:
    """Everything a lead has been asked to verify, oldest submission first."""
    return (
        session.query(JourneyRequirement)
        .join(UserJourney, JourneyRequirement.journey_id == UserJourney.id)
        .filter(JourneyRequirement.status == STATUS_SUBMITTED,
                UserJourney.stage.notin_([STAGE_CLOSED, STAGE_WITHDRAWN]))
        .order_by(JourneyRequirement.submitted_at.asc())
        .all()
    )


# --- granted permissions ----------------------------------------------------


def confers_role(journey: UserJourney, now: Optional[datetime] = None) -> bool:
    """Whether this journey should currently confer its profile's ION role.

    The gate is the condition. A suspended journey keeps conferring until its
    grace expires, so a certificate lapsing overnight does not strip access
    from someone on shift before anyone has seen the alert.
    """
    now = now or datetime.utcnow()
    if journey.stage in (STAGE_CLOSED, STAGE_WITHDRAWN):
        return False
    # A journey that never cleared the gate confers nothing, whatever its stage.
    if journey.gate_cleared_at is None:
        return False
    # Suspension is only ever caused by a lapsed gate item, so this has to be
    # asked BEFORE gate_cleared() -- which is already False by definition here.
    if journey.stage == STAGE_SUSPENDED:
        return journey.grace_until is not None and now < journey.grace_until
    return gate_cleared(journey)


def sync_granted_roles(session: Session, user: User,
                       now: Optional[datetime] = None) -> dict:
    """Reconcile the ION roles this person holds against their journeys.

    Only roles some journey of theirs grants are touched, so a role an admin
    assigned by hand is never silently removed.
    """
    from ion.models.user import Role

    now = now or datetime.utcnow()
    earned: set = set()
    withheld: set = set()
    # EVERY journey, not just the live ones: a closed journey grants nothing,
    # and if it were filtered out here its role could never be handed back.
    journeys = (
        session.query(UserJourney)
        .filter(UserJourney.user_id == user.id)
        .all()
    )
    for journey in journeys:
        profile = journey.version.profile if journey.version else None
        role_id = getattr(profile, "grants_role_id", None)
        if role_id is None:
            continue
        (earned if confers_role(journey, now) else withheld).add(role_id)

    # One journey earning a role beats another withholding it.
    withheld -= earned

    held = {r.id: r for r in user.roles}
    added, removed = [], []
    for role_id in earned - set(held):
        role = session.get(Role, role_id)
        if role is not None:
            user.roles.append(role)
            added.append(role.name)
    for role_id in withheld & set(held):
        user.roles.remove(held[role_id])
        removed.append(held[role_id].name)

    if added or removed:
        for name in added:
            session.add(AuditLog(
                user_id=user.id, action="workforce_role_granted",
                resource_type="user", resource_id=user.id, details=name,
            ))
        for name in removed:
            session.add(AuditLog(
                user_id=user.id, action="workforce_role_revoked",
                resource_type="user", resource_id=user.id, details=name,
            ))
        session.commit()
        logger.info("Workforce roles for %s: +%s -%s", user.username, added, removed)
    return {"granted": added, "revoked": removed}


# --- state ------------------------------------------------------------------


def _gate_items(journey: UserJourney) -> List[JourneyRequirement]:
    return [r for r in journey.requirements if r.phase == PHASE_GATE]


def _readiness_items(journey: UserJourney) -> List[JourneyRequirement]:
    return [r for r in journey.requirements if r.phase == PHASE_READINESS]


def gate_cleared(journey: UserJourney) -> bool:
    items = _gate_items(journey)
    return bool(items) and all(r.satisfied for r in items)


def readiness_complete(journey: UserJourney) -> bool:
    items = _readiness_items(journey)
    return all(r.satisfied for r in items)


def _recompute_stage(session: Session, journey: UserJourney) -> str:
    """Derive the stage from the requirements. Never set stage by hand.

    Grace and ION role membership are applied here rather than at the call
    sites: this is the one funnel every stage change passes through, and a
    limb hung off the callers gets missed the next time one is added.
    """
    if journey.stage in (STAGE_CLOSED, STAGE_WITHDRAWN):
        _sync_roles_for(session, journey)
        return journey.stage

    was = journey.stage

    gate_lapsed = any(r.phase == PHASE_GATE and r.status == STATUS_EXPIRED
                      for r in journey.requirements)
    role_lapsed = any(r.phase == PHASE_READINESS and r.status == STATUS_EXPIRED
                      for r in journey.requirements)

    if gate_lapsed:
        journey.stage = STAGE_SUSPENDED
    elif not gate_cleared(journey):
        journey.stage = STAGE_PRE_ACCESS
    elif role_lapsed:
        journey.stage = STAGE_WITHDRAWN if journey.is_cover else STAGE_TRAINING
    elif readiness_complete(journey):
        journey.stage = STAGE_OPERATIONAL
        journey.operational_at = journey.operational_at or datetime.utcnow()
    else:
        journey.stage = STAGE_TRAINING

    if journey.stage != STAGE_PRE_ACCESS and journey.gate_cleared_at is None and gate_cleared(journey):
        journey.gate_cleared_at = datetime.utcnow()

    if journey.stage == STAGE_SUSPENDED and was != STAGE_SUSPENDED:
        journey.grace_until = datetime.utcnow() + timedelta(days=_grace_days())
    elif journey.stage != STAGE_SUSPENDED:
        journey.grace_until = None

    session.flush()
    _sync_roles_for(session, journey)
    return journey.stage


def _grace_days() -> int:
    """How long granted permissions outlive a lapse. 0 revokes immediately."""
    from ion.core.config import get_config

    return max(0, int(getattr(get_config(), "workforce_lapse_grace_days", 7)))


def _sync_roles_for(session: Session, journey: UserJourney) -> None:
    owner = session.get(User, journey.user_id)
    if owner is not None:
        sync_granted_roles(session, owner)


def has_system_access(session: Session, user_id: int) -> bool:
    """Access is person-level: every gate item on every live journey holds."""
    journeys = live_journeys(session, user_id)
    if not journeys:
        return False
    if any(j.stage == STAGE_SUSPENDED for j in journeys):
        return False
    return all(gate_cleared(j) for j in journeys if not j.is_cover) and bool(
        [j for j in journeys if not j.is_cover]
    )


def live_journeys(session: Session, user_id: int) -> List[UserJourney]:
    return (
        session.query(UserJourney)
        .filter(UserJourney.user_id == user_id, UserJourney.stage != STAGE_CLOSED)
        .order_by(UserJourney.is_cover.asc(), UserJourney.id.asc())
        .all()
    )


def suspend_for_lapsed_gate(session: Session, user_id: int) -> int:
    """A lapsed gate item withdraws access, so every role goes with it."""
    journeys = live_journeys(session, user_id)
    lapsed = any(
        r.status == STATUS_EXPIRED and r.phase == PHASE_GATE
        for j in journeys for r in j.requirements
    )
    if not lapsed:
        return 0
    changed = 0
    for j in journeys:
        if j.stage != STAGE_SUSPENDED:
            j.stage = STAGE_SUSPENDED
            changed += 1
    if changed:
        session.commit()
    return changed


# --- expiry -----------------------------------------------------------------


@dataclass
class ExpiringItem:
    requirement: JourneyRequirement
    journey: UserJourney
    days_left: int
    threshold: Optional[int]


def expiring(session: Session, *, within_days: int = 90,
             today: Optional[date] = None) -> List[ExpiringItem]:
    """Requirements due to lapse, soonest first. Includes already-lapsed."""
    today = today or date.today()
    horizon = today + timedelta(days=within_days)
    rows = (
        session.query(JourneyRequirement, UserJourney)
        .join(UserJourney, JourneyRequirement.journey_id == UserJourney.id)
        .filter(UserJourney.stage != STAGE_CLOSED,
                JourneyRequirement.expires_on.isnot(None),
                JourneyRequirement.expires_on <= horizon)
        .order_by(JourneyRequirement.expires_on.asc())
        .all()
    )
    out = []
    for req, journey in rows:
        days = (req.expires_on - today).days
        out.append(ExpiringItem(req, journey, days, _threshold_for(days)))
    return out


def _threshold_for(days_left: int) -> Optional[int]:
    """The tightest reminder band this day count has entered.

    20 days out is inside 90, 60 and 30, so the band is 30. Beyond the widest
    band nothing is due yet.
    """
    entered = [t for t in REMINDER_DAYS if days_left <= t]
    return min(entered) if entered else None


def sweep_expiries(session: Session, *, today: Optional[date] = None) -> dict:
    """Mark lapsed items expired and suspend anyone whose gate item went.

    Returns a summary for the caller to notify from; sending is the caller's
    job so this stays testable without SMTP.
    """
    today = today or date.today()
    newly_expired: List[JourneyRequirement] = []

    rows = (
        session.query(JourneyRequirement, UserJourney)
        .join(UserJourney, JourneyRequirement.journey_id == UserJourney.id)
        .filter(UserJourney.stage != STAGE_CLOSED,
                JourneyRequirement.expires_on.isnot(None),
                JourneyRequirement.expires_on < today,
                JourneyRequirement.status.in_([STATUS_VERIFIED, STATUS_WAIVED]))
        .all()
    )
    from ion.models.skills import TeamCertification

    affected_users = set()
    for req, journey in rows:
        req.status = STATUS_EXPIRED
        newly_expired.append(req)
        affected_users.add(journey.user_id)
        if req.kind == KIND_CERT:
            (session.query(TeamCertification)
             .filter(TeamCertification.user_id == journey.user_id,
                     TeamCertification.cert_name == req.name,
                     TeamCertification.status == "active")
             .update({TeamCertification.status: "expired"}))

    if newly_expired:
        session.flush()

    for user_id in affected_users:
        for journey in live_journeys(session, user_id):
            _recompute_stage(session, journey)
        suspend_for_lapsed_gate(session, user_id)

    due = [i for i in expiring(session, within_days=REMINDER_DAYS[0], today=today)
           if i.days_left >= 0 and _reminder_due(i)]
    for item in due:
        item.requirement.last_reminder_days = item.threshold

    session.commit()
    return {
        "expired": len(newly_expired),
        "suspended_users": len(affected_users),
        "reminders": [
            {"user_id": i.journey.user_id, "requirement": i.requirement.name,
             "days_left": i.days_left, "threshold": i.threshold}
            for i in due
        ],
    }


def _reminder_due(item: ExpiringItem) -> bool:
    if item.threshold is None:
        return False
    sent = item.requirement.last_reminder_days
    return sent is None or item.threshold < sent


# --- cover / ORBAT ----------------------------------------------------------


def capability_cover(session: Session, profile_name: str) -> dict:
    """Primary and cover headcount for a role, weighted.

    A cover holder counts at ``COVER_WEIGHT``: three people who *can* cover is
    not three whose day job it is. Only operational people count at all, so
    ``in_training`` and ``blocked`` are reported alongside — a zero with two
    people in training is a different problem from a zero with nobody.
    """
    journeys = (
        session.query(UserJourney)
        .join(RoleProfileVersion, UserJourney.version_id == RoleProfileVersion.id)
        .join(RoleProfile, RoleProfileVersion.profile_id == RoleProfile.id)
        .filter(RoleProfile.name == profile_name,
                UserJourney.stage != STAGE_CLOSED)
        .all()
    )
    ready = [j for j in journeys if j.stage == STAGE_OPERATIONAL]
    primary = [j for j in ready if not j.is_cover]
    cover = [j for j in ready if j.is_cover]
    blocked = [j for j in journeys
               if j.stage in (STAGE_SUSPENDED, STAGE_WITHDRAWN)]
    return {
        "primary": len(primary),
        "cover": len(cover),
        "weighted": len(primary) + COVER_WEIGHT * len(cover),
        "in_training": len(journeys) - len(ready) - len(blocked),
        "blocked": len(blocked),
    }


# --- org structure / ORBAT ---------------------------------------------------


def fill_post(session: Session, *, post: OrgPost, journey_id: Optional[int],
              actor: User) -> OrgPost:
    """Seat a journey in a post, or empty it with ``journey_id=None``.

    A post established for one profile refuses a journey from another --
    seating an IR Lead in an L1 post is a data error, not flexibility.
    """
    if not actor.has_permission("workforce:manage"):
        raise WorkforceError("Permission denied")
    if journey_id is None:
        post.filled_by_journey_id = None
        session.commit()
        return post

    journey = session.get(UserJourney, journey_id)
    if journey is None or journey.stage in (STAGE_CLOSED, STAGE_WITHDRAWN):
        raise WorkforceError("That journey cannot fill a post")
    if post.profile_id is not None and journey.version is not None             and journey.version.profile_id != post.profile_id:
        raise WorkforceError("This post is established for a different role profile")
    taken = (
        session.query(OrgPost)
        .filter(OrgPost.filled_by_journey_id == journey_id, OrgPost.id != post.id)
        .first()
    )
    if taken is not None:
        raise WorkforceError("That journey already fills another post")
    post.filled_by_journey_id = journey_id
    session.commit()
    return post


def org_tree(session: Session) -> dict:
    """The whole structure in three queries, nested for the page.

    A post with no operational occupant is a gap; one being filled by someone
    still in training is reported as such, not hidden.
    """
    units = session.query(OrgUnit).order_by(OrgUnit.ordering, OrgUnit.id).all()
    posts = session.query(OrgPost).order_by(OrgPost.ordering, OrgPost.id).all()

    journey_ids = [p.filled_by_journey_id for p in posts if p.filled_by_journey_id]
    journeys = {j.id: j for j in session.query(UserJourney)
                .filter(UserJourney.id.in_(journey_ids or [0])).all()}
    names = {u.id: (u.display_name or u.username)
             for u in session.query(User)
             .filter(User.id.in_([j.user_id for j in journeys.values()] or [0])).all()}

    gaps = 0
    filling = 0
    by_unit: dict = {}
    for post in posts:
        journey = journeys.get(post.filled_by_journey_id)
        occupant = None
        state = "gapped"
        if journey is not None:
            occupant = {
                "journey_id": journey.id,
                "user_id": journey.user_id,
                "name": names.get(journey.user_id, f"user {journey.user_id}"),
                "stage": journey.stage,
                "is_cover": journey.is_cover,
            }
            state = "filled" if journey.stage == STAGE_OPERATIONAL else "filling"
        if state == "gapped":
            gaps += 1
        elif state == "filling":
            filling += 1
        by_unit.setdefault(post.unit_id, []).append({
            "id": post.id, "title": post.title, "profile_id": post.profile_id,
            "state": state, "occupant": occupant,
        })

    def node(unit: OrgUnit) -> dict:
        return {
            "id": unit.id, "name": unit.name,
            "posts": by_unit.get(unit.id, []),
            "children": [node(c) for c in units if c.parent_id == unit.id],
        }

    roots = [node(u) for u in units if u.parent_id is None]
    return {"units": roots, "posts_total": len(posts), "gaps": gaps,
            "filling": filling}


# --- offboarding ------------------------------------------------------------

DEFAULT_LEAVER_CHECKLIST = [
    {"name": "Privileged credentials rotated", "owner": "SOC manager", "done": False},
    {"name": "Open cases reassigned", "owner": "Shift lead", "done": False},
    {"name": "Sole-owner knowledge handed over", "owner": "Leaver", "done": False},
    {"name": "Hardware returned", "owner": "Facilities", "done": False},
    {"name": "Continuing obligations acknowledged", "owner": "HR", "done": False},
]


def start_offboarding(session: Session, *, user: User, raiser: User,
                      last_working_day: date, reason: str = "") -> LeaverRecord:
    if not raiser.has_permission("workforce:manage"):
        raise WorkforceError("Permission denied")
    existing = (
        session.query(LeaverRecord)
        .filter(LeaverRecord.user_id == user.id, LeaverRecord.revoked_at.is_(None))
        .first()
    )
    if existing is not None:
        raise WorkforceError("An open leaver record already exists for this person")

    record = LeaverRecord(
        user_id=user.id, last_working_day=last_working_day, reason=reason or None,
        raised_by_id=raiser.id,
        revoke_at=datetime.combine(last_working_day, datetime.min.time()) + timedelta(hours=17),
        checklist=json.dumps(DEFAULT_LEAVER_CHECKLIST),
    )
    session.add(record)
    session.flush()
    session.add(AuditLog(
        user_id=raiser.id, action="workforce_offboarding_started",
        resource_type="leaver_record", resource_id=record.id,
        details=f"user {user.username}, last day {last_working_day.isoformat()}",
    ))
    session.commit()
    return record


def revoke_now(session: Session, record: LeaverRecord, *, actor: User) -> int:
    """Close every journey. Runs on the last working day regardless of the list.

    The permission check lives HERE, not only at the route: this function
    revokes ION roles, and any future internal caller (a scheduler, a bulk
    script) must hit the same gate. The v0.20.1 rule.
    """
    if not actor.has_permission("workforce:manage"):
        raise WorkforceError("Permission denied")
    closed = 0
    for journey in live_journeys(session, record.user_id):
        journey.stage = STAGE_CLOSED
        journey.closed_at = datetime.utcnow()
        closed += 1
    record.revoked_at = datetime.utcnow()
    session.flush()

    # This path sets the stage directly, so it has to hand the roles back
    # itself -- _recompute_stage is not on the way out.
    leaver = session.get(User, record.user_id)
    if leaver is not None:
        sync_granted_roles(session, leaver)
    session.add(AuditLog(
        user_id=actor.id, action="workforce_access_revoked",
        resource_type="leaver_record", resource_id=record.id,
        details=f"closed {closed} journeys for user_id {record.user_id}",
    ))
    session.commit()
    return closed


def set_checklist_item(session: Session, *, record: LeaverRecord, index: int,
                       done: bool, actor: User) -> list:
    """Tick or untick one leaver checklist item.

    Outstanding items are chased, never a reason to delay revocation, so this
    changes bookkeeping only.
    """
    if not actor.has_permission("workforce:manage"):
        raise WorkforceError("Permission denied")
    try:
        items = json.loads(record.checklist or "[]")
    except ValueError:
        items = []
    if not 0 <= index < len(items):
        raise WorkforceError("No such checklist item")
    items[index]["done"] = bool(done)
    record.checklist = json.dumps(items)
    session.commit()
    return items


def due_revocations(session: Session, *, now: Optional[datetime] = None) -> Sequence[LeaverRecord]:
    now = now or datetime.utcnow()
    return (
        session.query(LeaverRecord)
        .filter(LeaverRecord.revoked_at.is_(None), LeaverRecord.revoke_at <= now)
        .all()
    )


# --- read models for the pages ---------------------------------------------


def journey_summary(session: Session, journey: UserJourney) -> dict:
    gate = _gate_items(journey)
    readiness = _readiness_items(journey)
    version = session.get(RoleProfileVersion, journey.version_id)
    profile = session.get(RoleProfile, version.profile_id) if version else None
    return {
        "id": journey.id,
        "user_id": journey.user_id,
        "role": profile.name if profile else "(unknown)",
        "version": version.version if version else 0,
        "is_cover": journey.is_cover,
        "stage": journey.stage,
        "gate_total": len(gate),
        "gate_done": sum(1 for r in gate if r.satisfied),
        "gate_cleared": gate_cleared(journey),
        "readiness_total": len(readiness),
        "readiness_done": sum(1 for r in readiness if r.satisfied),
        "spend": sum(r.cost for r in journey.requirements if r.satisfied),
        "committed": sum(r.cost for r in journey.requirements if not r.satisfied),
        "days_elapsed": (datetime.utcnow() - journey.started_at).days,
        "target_days": journey.target_days,
    }


def open_journeys(session: Session, *, limit: int = 200) -> List[UserJourney]:
    return (
        session.query(UserJourney)
        .filter(UserJourney.stage.notin_([STAGE_CLOSED, STAGE_OPERATIONAL]))
        .order_by(UserJourney.started_at.asc())
        .limit(limit)
        .all()
    )
