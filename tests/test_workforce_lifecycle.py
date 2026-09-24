"""Workforce lifecycle contracts.

The rules these pin are the ones the design turns on, and each has a failure
mode that is invisible until an audit: a profile edit that retrospectively
marks people non-compliant, a cover role that inherits its way out of the
training it exists to require, and a lapsed clearance that only withdraws half
of someone's roles.
"""

from datetime import date, datetime, timedelta

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from ion.models.base import Base
from ion.models.course import Course, CourseLevel, UserEnrolment
from ion.models.user import Permission, Role, User
from ion.models.workforce import (
    KIND_CERT,
    KIND_COURSE,
    KIND_DOCUMENT,
    PHASE_GATE,
    PHASE_READINESS,
    STAGE_CLOSED,
    STAGE_OPERATIONAL,
    STAGE_PRE_ACCESS,
    STAGE_SUSPENDED,
    STAGE_TRAINING,
    STAGE_WITHDRAWN,
    STATUS_EXPIRED,
    STATUS_VERIFIED,
)
from ion.services import workforce_service as wf


@pytest.fixture(scope="module")
def _engine(tmp_path_factory):
    """create_all raises ION's whole schema; build it once for the module."""
    path = tmp_path_factory.mktemp("wf") / "wf.db"
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def db(_engine):
    maker = sessionmaker(bind=_engine)
    s = maker()
    # Association tables first: a bulk delete() does not clear them, and their
    # stale rows collide on the next insert.
    for table in ("role_permissions", "user_roles", "audit_logs"):
        s.execute(text(f"DELETE FROM {table}"))
    for model in (wf.JourneyRequirement, wf.UserJourney, wf.ProfileRequirement,
                  wf.RoleProfileVersion, wf.RoleProfile, wf.LeaverRecord,
                  UserEnrolment, Course, User, Role, Permission):
        s.query(model).delete()
    s.commit()
    yield s
    s.close()


def _user(db, username, perms=()):
    role = Role(name=f"role_{username}", description="test")
    for p in perms:
        role.permissions.append(Permission(name=p, resource=p.split(":")[0], action=p.split(":")[1]))
    u = User(username=username, email=f"{username}@x.y", password_hash="x", display_name=username)
    u.roles.append(role)
    db.add(u)
    db.commit()
    return u


def _profile_with(db, name, reqs):
    p = wf.create_profile(db, name=name)
    v = wf.draft_version(db, p)
    for r in reqs:
        wf.add_requirement(db, v, **r)
    db.refresh(v)
    return p, v


GATE_DOC = {"name": "Confidentiality agreement", "kind": KIND_DOCUMENT, "phase": PHASE_GATE}
GATE_CLR = {"name": "Security clearance", "kind": KIND_DOCUMENT, "phase": PHASE_GATE,
            "validity_months": 12}
READY_CERT = {"name": "Security+", "kind": KIND_CERT, "phase": PHASE_READINESS, "cost": 369.0}


# --- versioning -------------------------------------------------------------


def test_a_published_version_cannot_be_edited(db):
    admin = _user(db, "admin", ["workforce:manage"])
    _, v = _profile_with(db, "L1 Analyst", [GATE_DOC])
    wf.publish_version(db, v, admin)

    with pytest.raises(wf.WorkforceError):
        wf.add_requirement(db, v, name="Sneaked in", kind=KIND_DOCUMENT, phase=PHASE_GATE)


def test_a_new_draft_starts_from_the_published_version(db):
    admin = _user(db, "admin", ["workforce:manage"])
    p, v1 = _profile_with(db, "L1 Analyst", [GATE_DOC, READY_CERT])
    wf.publish_version(db, v1, admin)

    v2 = wf.draft_version(db, p)
    assert v2.version == 2
    assert v2.published_at is None
    assert sorted(r.name for r in v2.requirements) == sorted(r.name for r in v1.requirements)


def test_editing_the_role_later_cannot_change_an_existing_journey(db):
    """The whole reason requirements are copied rather than referenced."""
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    joiner = _user(db, "joiner")
    p, v1 = _profile_with(db, "L1 Analyst", [GATE_DOC])
    wf.publish_version(db, v1, admin)
    journey = wf.assign_profile(db, user=joiner, version=v1, assigner=admin)
    assert len(journey.requirements) == 1

    v2 = wf.draft_version(db, p)
    wf.add_requirement(db, v2, name="New mandatory thing", kind=KIND_DOCUMENT, phase=PHASE_GATE)
    wf.publish_version(db, v2, admin)

    db.refresh(journey)
    assert [r.name for r in journey.requirements] == ["Confidentiality agreement"], \
        "a later profile edit must not reach back into a live journey"


# --- the gate ---------------------------------------------------------------


def test_the_gate_blocks_until_every_item_is_verified(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    joiner = _user(db, "joiner")
    _, v = _profile_with(db, "L1 Analyst", [GATE_DOC, GATE_CLR, READY_CERT])
    wf.publish_version(db, v, admin)
    j = wf.assign_profile(db, user=joiner, version=v, assigner=admin)

    assert j.stage == STAGE_PRE_ACCESS
    assert wf.gate_cleared(j) is False

    gate = [r for r in j.requirements if r.phase == PHASE_GATE]
    wf.verify_requirement(db, requirement=gate[0], verifier=admin)
    db.refresh(j)
    assert j.stage == STAGE_PRE_ACCESS, "one item short is still blocked"

    wf.verify_requirement(db, requirement=gate[1], verifier=admin)
    db.refresh(j)
    assert wf.gate_cleared(j) is True
    assert j.stage == STAGE_TRAINING
    assert j.gate_cleared_at is not None


def test_completing_readiness_makes_the_journey_operational(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    joiner = _user(db, "joiner")
    _, v = _profile_with(db, "L1 Analyst", [GATE_DOC, READY_CERT])
    wf.publish_version(db, v, admin)
    j = wf.assign_profile(db, user=joiner, version=v, assigner=admin)

    for r in list(j.requirements):
        wf.verify_requirement(db, requirement=r, verifier=admin)
    db.refresh(j)
    assert j.stage == STAGE_OPERATIONAL
    assert j.operational_at is not None


# --- cover roles ------------------------------------------------------------


def test_a_cover_role_carries_gate_items_but_adds_its_own_training(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "analyst")

    _, v1 = _profile_with(db, "L2 Analyst", [GATE_DOC, GATE_CLR, READY_CERT])
    wf.publish_version(db, v1, admin)
    primary = wf.assign_profile(db, user=person, version=v1, assigner=admin)
    for r in list(primary.requirements):
        wf.verify_requirement(db, requirement=r, verifier=admin)

    _, v2 = _profile_with(db, "Incident Response", [
        GATE_DOC, GATE_CLR,
        {"name": "GCIH", "kind": KIND_CERT, "phase": PHASE_READINESS, "cost": 1150.0},
    ])
    wf.publish_version(db, v2, admin)
    cover = wf.assign_profile(db, user=person, version=v2, assigner=admin, is_cover=True)

    gate = [r for r in cover.requirements if r.phase == PHASE_GATE]
    ready = [r for r in cover.requirements if r.phase == PHASE_READINESS]

    assert all(r.status == STATUS_VERIFIED for r in gate), \
        "person-level gate items must not be reissued for a cover role"
    assert [r.name for r in ready] == ["GCIH"]
    assert all(not r.satisfied for r in ready), "the extra training is genuinely outstanding"
    assert cover.stage == STAGE_TRAINING


def test_cover_counts_for_less_than_a_primary_holder(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    _, v = _profile_with(db, "Incident Response", [GATE_DOC])
    wf.publish_version(db, v, admin)

    for i, is_cover in enumerate([False, True, True]):
        person = _user(db, f"p{i}")
        j = wf.assign_profile(db, user=person, version=v, assigner=admin, is_cover=is_cover)
        for r in list(j.requirements):
            wf.verify_requirement(db, requirement=r, verifier=admin)

    cover = wf.capability_cover(db, "Incident Response")
    assert cover == {"primary": 1, "cover": 2, "weighted": 2.0,
                     "in_training": 0, "blocked": 0}, \
        "three able bodies must not read as three primaries"


def test_cover_depth_separates_nobody_from_not_yet(db):
    """Zero operational with people in training is not zero with nobody.

    Both render as 0 depth; a lead has to be able to tell a hiring problem
    from a training-backlog problem without leaving the page.
    """
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    _, v = _profile_with(db, "Threat Hunter", [GATE_DOC])
    wf.publish_version(db, v, admin)

    empty = wf.capability_cover(db, "Threat Hunter")
    assert empty["weighted"] == 0 and empty["in_training"] == 0

    wf.assign_profile(db, user=_user(db, "trainee"), version=v, assigner=admin)
    waiting = wf.capability_cover(db, "Threat Hunter")
    assert waiting["weighted"] == 0, "not operational, so not rota depth"
    assert waiting["in_training"] == 1, "but the page must not read as empty"


# --- the two suspension scopes ---------------------------------------------


def _lapse(db, requirement):
    requirement.expires_on = date.today() - timedelta(days=1)
    db.commit()


def test_a_lapsed_gate_item_suspends_every_role(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "analyst")

    _, v1 = _profile_with(db, "L2 Analyst", [GATE_CLR])
    wf.publish_version(db, v1, admin)
    primary = wf.assign_profile(db, user=person, version=v1, assigner=admin)
    wf.verify_requirement(db, requirement=primary.requirements[0], verifier=admin)

    _, v2 = _profile_with(db, "Incident Response", [GATE_CLR])
    wf.publish_version(db, v2, admin)
    cover = wf.assign_profile(db, user=person, version=v2, assigner=admin, is_cover=True)

    _lapse(db, primary.requirements[0])
    wf.sweep_expiries(db)

    db.refresh(primary)
    db.refresh(cover)
    assert primary.stage == STAGE_SUSPENDED
    assert cover.stage == STAGE_SUSPENDED, "access is person-level; both roles go"
    assert wf.has_system_access(db, person.id) is False


def test_a_lapsed_cover_item_withdraws_only_that_role(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "analyst")

    _, v1 = _profile_with(db, "L2 Analyst", [GATE_DOC])
    wf.publish_version(db, v1, admin)
    primary = wf.assign_profile(db, user=person, version=v1, assigner=admin)
    wf.verify_requirement(db, requirement=primary.requirements[0], verifier=admin)

    _, v2 = _profile_with(db, "Incident Response", [
        GATE_DOC,
        {"name": "GCIH", "kind": KIND_CERT, "phase": PHASE_READINESS, "validity_months": 1},
    ])
    wf.publish_version(db, v2, admin)
    cover = wf.assign_profile(db, user=person, version=v2, assigner=admin, is_cover=True)
    gcih = [r for r in cover.requirements if r.name == "GCIH"][0]
    wf.verify_requirement(db, requirement=gcih, verifier=admin)

    _lapse(db, gcih)
    wf.sweep_expiries(db)

    db.refresh(primary)
    db.refresh(cover)
    assert cover.stage == STAGE_WITHDRAWN, "the cover role goes"
    assert primary.stage == STAGE_OPERATIONAL, "the primary is untouched"


# --- courses ----------------------------------------------------------------


def test_a_course_requirement_resolves_from_enrolment_not_a_manual_tick(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    joiner = _user(db, "joiner")
    course = Course(title="Induction", slug="induction", level=CourseLevel.L1, description_md="")
    db.add(course)
    db.commit()

    _, v = _profile_with(db, "L1 Analyst", [
        {"name": "Induction", "kind": KIND_COURSE, "phase": PHASE_GATE, "course_id": course.id},
    ])
    wf.publish_version(db, v, admin)
    j = wf.assign_profile(db, user=joiner, version=v, assigner=admin)

    assert wf.sync_course_requirements(db, j) == 0, "not enrolled yet"

    db.add(UserEnrolment(user_id=joiner.id, course_id=course.id, completed_at=datetime.utcnow()))
    db.commit()

    assert wf.sync_course_requirements(db, j) == 1
    db.refresh(j)
    assert j.requirements[0].status == STATUS_VERIFIED


# --- authorisation ----------------------------------------------------------


def test_assigning_a_profile_requires_the_manage_permission(db):
    admin = _user(db, "admin", ["workforce:manage"])
    nobody = _user(db, "nobody")
    joiner = _user(db, "joiner")
    _, v = _profile_with(db, "L1 Analyst", [GATE_DOC])
    wf.publish_version(db, v, admin)

    with pytest.raises(wf.WorkforceError, match="Permission denied"):
        wf.assign_profile(db, user=joiner, version=v, assigner=nobody)


def test_verification_is_refused_without_permission_or_sponsorship(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    lead = _user(db, "lead")
    bystander = _user(db, "bystander")
    joiner = _user(db, "joiner")

    _, v = _profile_with(db, "L1 Analyst", [GATE_DOC])
    wf.publish_version(db, v, admin)
    j = wf.assign_profile(db, user=joiner, version=v, assigner=admin, sponsor=lead)
    req = j.requirements[0]

    with pytest.raises(wf.WorkforceError, match="Permission denied"):
        wf.verify_requirement(db, requirement=req, verifier=bystander)

    # The sponsoring lead may verify their own person without the global grant.
    wf.verify_requirement(db, requirement=req, verifier=lead)
    assert req.status == STATUS_VERIFIED


def test_an_unpublished_version_cannot_be_assigned(db):
    admin = _user(db, "admin", ["workforce:manage"])
    joiner = _user(db, "joiner")
    _, v = _profile_with(db, "L1 Analyst", [GATE_DOC])

    with pytest.raises(wf.WorkforceError, match="published"):
        wf.assign_profile(db, user=joiner, version=v, assigner=admin)


# --- expiry -----------------------------------------------------------------


def test_validity_runs_in_calendar_months_not_30_day_blocks():
    """A certificate expires on its printed anniversary.

    30-day months drift ~5 days a year, so a 4-year cert would read three
    weeks early and every reminder band would fire against the wrong date.
    """
    issued = datetime(2026, 9, 24, 9, 0)
    assert wf._expiry_for(12, issued) == date(2027, 9, 24)
    assert wf._expiry_for(36, issued) == date(2029, 9, 24)
    assert wf._expiry_for(48, issued) == date(2030, 9, 24)
    assert wf._expiry_for(60, issued) == date(2031, 9, 24)
    assert wf._expiry_for(None, issued) is None
    assert wf._expiry_for(0, issued) is None


def test_validity_clamps_when_the_target_month_is_shorter():
    """31 January plus a month is the 28th, not the 3rd of March."""
    assert wf._expiry_for(1, datetime(2027, 1, 31)) == date(2027, 2, 28)
    assert wf._expiry_for(1, datetime(2028, 1, 31)) == date(2028, 2, 29)
    assert wf._expiry_for(12, datetime(2028, 2, 29)) == date(2029, 2, 28)


def test_the_sweep_marks_lapsed_items_and_reports_reminders(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "analyst")
    _, v = _profile_with(db, "L1 Analyst", [GATE_CLR, READY_CERT])
    wf.publish_version(db, v, admin)
    j = wf.assign_profile(db, user=person, version=v, assigner=admin)

    clearance = [r for r in j.requirements if r.name == "Security clearance"][0]
    plus = [r for r in j.requirements if r.name == "Security+"][0]
    wf.verify_requirement(db, requirement=clearance, verifier=admin)
    wf.verify_requirement(db, requirement=plus, verifier=admin,
                          expires_on=date.today() + timedelta(days=20))

    _lapse(db, clearance)
    result = wf.sweep_expiries(db)

    assert result["expired"] == 1
    db.refresh(clearance)
    assert clearance.status == STATUS_EXPIRED
    names = [r["requirement"] for r in result["reminders"]]
    assert "Security+" in names, "an item 20 days out falls in the 30-day band"


def test_expiring_lists_soonest_first_and_includes_lapsed(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "analyst")
    _, v = _profile_with(db, "L1 Analyst", [GATE_CLR, READY_CERT])
    wf.publish_version(db, v, admin)
    j = wf.assign_profile(db, user=person, version=v, assigner=admin)

    a, b = j.requirements[0], j.requirements[1]
    wf.verify_requirement(db, requirement=a, verifier=admin,
                          expires_on=date.today() + timedelta(days=45))
    wf.verify_requirement(db, requirement=b, verifier=admin,
                          expires_on=date.today() + timedelta(days=5))

    items = wf.expiring(db, within_days=90)
    assert [i.days_left for i in items] == [5, 45]


# --- offboarding ------------------------------------------------------------


def test_offboarding_closes_every_role_and_keeps_the_record(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "leaver")
    _, v = _profile_with(db, "L1 Analyst", [GATE_DOC])
    wf.publish_version(db, v, admin)
    j = wf.assign_profile(db, user=person, version=v, assigner=admin)
    wf.verify_requirement(db, requirement=j.requirements[0], verifier=admin)

    record = wf.start_offboarding(db, user=person, raiser=admin,
                                  last_working_day=date.today(), reason="Resignation")
    assert record.revoke_at.hour == 17, "revocation is scheduled, not immediate"
    assert wf.revoke_now(db, record, actor=admin) == 1

    db.refresh(j)
    assert j.stage == STAGE_CLOSED
    assert j.closed_at is not None
    assert record.revoked_at is not None
    assert db.get(wf.LeaverRecord, record.id) is not None, "the record outlives the access"


def test_offboarding_requires_permission_and_refuses_duplicates(db):
    admin = _user(db, "admin", ["workforce:manage"])
    nobody = _user(db, "nobody")
    person = _user(db, "leaver")

    with pytest.raises(wf.WorkforceError, match="Permission denied"):
        wf.start_offboarding(db, user=person, raiser=nobody, last_working_day=date.today())

    wf.start_offboarding(db, user=person, raiser=admin, last_working_day=date.today())
    with pytest.raises(wf.WorkforceError, match="already exists"):
        wf.start_offboarding(db, user=person, raiser=admin, last_working_day=date.today())
