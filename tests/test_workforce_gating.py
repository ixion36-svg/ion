"""The mandatory list is what holds the ION permissions back.

The failure this pins is silent and serious: someone assigned a role gets its
permissions before the clearance is verified, or keeps them after it lapses.
Neither shows up in the journey UI, which would still read "suspended".
"""

from datetime import date, datetime, timedelta

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from ion.models.base import Base
from ion.models.course import Course, UserEnrolment
from ion.models.user import Permission, Role, User
from ion.models.workforce import (
    KIND_CERT,
    KIND_DOCUMENT,
    PHASE_GATE,
    PHASE_READINESS,
    STATUS_SUBMITTED,
    STATUS_VERIFIED,
)
from ion.services import workforce_service as wf


@pytest.fixture(scope="module")
def _engine(tmp_path_factory):
    engine = create_engine(f"sqlite:///{tmp_path_factory.mktemp('wfg') / 'wfg.db'}")
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def db(_engine):
    s = sessionmaker(bind=_engine)()
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
        role.permissions.append(
            Permission(name=p, resource=p.split(":")[0], action=p.split(":")[1]))
    u = User(username=username, email=f"{username}@x.y", password_hash="x",
             display_name=username)
    u.roles.append(role)
    db.add(u)
    db.commit()
    return u


def _granted_role(db, name="analyst", perms=("alert:read", "case:write")):
    role = Role(name=name, description="granted by the profile")
    for p in perms:
        role.permissions.append(
            Permission(name=p, resource=p.split(":")[0], action=p.split(":")[1]))
    db.add(role)
    db.commit()
    return role


GATE = {"name": "Security clearance", "kind": KIND_DOCUMENT, "phase": PHASE_GATE,
        "validity_months": 12}
GATE2 = {"name": "Acceptable use policy", "kind": KIND_DOCUMENT, "phase": PHASE_GATE}
READY = {"name": "GCIH", "kind": KIND_CERT, "phase": PHASE_READINESS, "cost": 1200.0}


def _assign(db, admin, person, role, reqs=(GATE, GATE2, READY)):
    profile = wf.create_profile(db, name="L1 SOC Analyst")
    profile.grants_role_id = role.id
    version = wf.draft_version(db, profile)
    for r in reqs:
        wf.add_requirement(db, version, **r)
    db.refresh(version)
    wf.publish_version(db, version, admin)
    return wf.assign_profile(db, user=person, version=version, assigner=admin)


def _clear_gate(db, journey, admin):
    for r in [r for r in journey.requirements if r.phase == PHASE_GATE]:
        wf.verify_requirement(db, requirement=r, verifier=admin)


def test_assigning_a_role_does_not_hand_over_its_permissions(db):
    """The whole point: assignment starts a journey, it does not grant access."""
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    role = _granted_role(db)
    _assign(db, admin, person, role)

    db.refresh(person)
    assert role not in person.roles, "permissions arrived before the gate was cleared"
    assert not person.has_permission("alert:read")


def test_clearing_the_gate_grants_the_role(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    role = _granted_role(db)
    journey = _assign(db, admin, person, role)

    gate = [r for r in journey.requirements if r.phase == PHASE_GATE]
    wf.verify_requirement(db, requirement=gate[0], verifier=admin)
    db.refresh(person)
    assert role not in person.roles, "a partial gate must not grant anything"

    wf.verify_requirement(db, requirement=gate[1], verifier=admin)
    db.refresh(person)
    assert role in person.roles
    assert person.has_permission("alert:read"), "readiness is not a precondition for access"


def test_a_lapse_suspends_at_once_but_permissions_survive_the_grace(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    role = _granted_role(db)
    journey = _assign(db, admin, person, role)
    _clear_gate(db, journey, admin)

    lapsed = next(r for r in journey.requirements if r.name == "Security clearance")
    lapsed.expires_on = date.today() - timedelta(days=1)
    db.commit()
    wf.sweep_expiries(db)

    db.refresh(journey)
    db.refresh(person)
    assert journey.stage == "suspended", "the lapse must be visible immediately"
    assert journey.grace_until is not None
    assert role in person.roles, "access must not vanish from under someone on shift"


def test_when_the_grace_runs_out_the_permissions_go(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    role = _granted_role(db)
    journey = _assign(db, admin, person, role)
    _clear_gate(db, journey, admin)

    lapsed = next(r for r in journey.requirements if r.name == "Security clearance")
    lapsed.expires_on = date.today() - timedelta(days=1)
    db.commit()
    wf.sweep_expiries(db)

    journey.grace_until = datetime.utcnow() - timedelta(minutes=1)
    db.commit()
    wf.sync_granted_roles(db, person)

    db.refresh(person)
    assert role not in person.roles, "an expired grace must not leave access standing"
    assert not person.has_permission("alert:read")


def test_re_verifying_after_a_lapse_restores_the_role(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    role = _granted_role(db)
    journey = _assign(db, admin, person, role)
    _clear_gate(db, journey, admin)

    lapsed = next(r for r in journey.requirements if r.name == "Security clearance")
    lapsed.expires_on = date.today() - timedelta(days=1)
    db.commit()
    wf.sweep_expiries(db)
    journey.grace_until = datetime.utcnow() - timedelta(minutes=1)
    db.commit()
    wf.sync_granted_roles(db, person)

    wf.verify_requirement(db, requirement=lapsed, verifier=admin,
                          expires_on=date.today() + timedelta(days=365))
    db.refresh(person)
    db.refresh(journey)
    assert journey.grace_until is None, "a cleared journey carries no grace"
    assert role in person.roles


def test_offboarding_takes_the_permissions_back(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "leaver")
    role = _granted_role(db)
    journey = _assign(db, admin, person, role)
    _clear_gate(db, journey, admin)
    db.refresh(person)
    assert role in person.roles

    record = wf.start_offboarding(db, user=person, raiser=admin,
                                  last_working_day=date.today())
    wf.revoke_now(db, record, actor=admin)
    db.refresh(person)
    assert role not in person.roles, "a leaver must not keep the role's permissions"


def test_a_hand_assigned_role_is_never_stripped(db):
    """Only roles a journey of theirs grants are touched."""
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    role = _granted_role(db)
    unrelated = _granted_role(db, name="forensic", perms=("case:read",))
    person.roles.append(unrelated)
    db.commit()

    _assign(db, admin, person, role)
    db.refresh(person)
    assert unrelated in person.roles, "an admin's own grant is not ours to remove"


def test_a_profile_granting_nothing_changes_no_permissions(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    before = {r.name for r in person.roles}

    profile = wf.create_profile(db, name="Unmapped role")
    version = wf.draft_version(db, profile)
    wf.add_requirement(db, version, **GATE2)
    db.refresh(version)
    wf.publish_version(db, version, admin)
    journey = wf.assign_profile(db, user=person, version=version, assigner=admin)
    wf.verify_requirement(db, requirement=journey.requirements[0], verifier=admin)

    db.refresh(person)
    assert {r.name for r in person.roles} == before


# --- what the joiner may do -------------------------------------------------


def test_a_joiner_submits_but_cannot_verify_themselves(db):
    """Self-service stops at SUBMITTED, or the gate grants its own clearance."""
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    role = _granted_role(db)
    journey = _assign(db, admin, person, role)
    item = journey.requirements[0]

    wf.submit_requirement(db, requirement=item, submitter=person,
                          completed_on=date.today(), evidence_ref="cert.pdf")
    assert item.status == STATUS_SUBMITTED
    assert item.completed_on == date.today()
    assert item.submitted_at is not None

    db.refresh(person)
    assert role not in person.roles, "submitting must not confer anything"

    with pytest.raises(wf.WorkforceError, match="Permission denied"):
        wf.verify_requirement(db, requirement=item, verifier=person)


def test_one_person_cannot_submit_against_another(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    bystander = _user(db, "bystander")
    role = _granted_role(db)
    journey = _assign(db, admin, person, role)

    with pytest.raises(wf.WorkforceError, match="Permission denied"):
        wf.submit_requirement(db, requirement=journey.requirements[0],
                              submitter=bystander)


def test_a_submitted_item_reaches_the_lead_queue_then_leaves_it(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    role = _granted_role(db)
    journey = _assign(db, admin, person, role)
    item = journey.requirements[0]

    assert wf.awaiting_verification(db) == []
    wf.submit_requirement(db, requirement=item, submitter=person)
    assert [r.id for r in wf.awaiting_verification(db)] == [item.id]

    wf.verify_requirement(db, requirement=item, verifier=admin)
    assert wf.awaiting_verification(db) == []
    assert item.status == STATUS_VERIFIED


def test_a_verified_item_cannot_be_re_submitted(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    role = _granted_role(db)
    journey = _assign(db, admin, person, role)
    item = journey.requirements[0]
    wf.verify_requirement(db, requirement=item, verifier=admin)

    with pytest.raises(wf.WorkforceError, match="already verified"):
        wf.submit_requirement(db, requirement=item, submitter=person)


def test_nobody_can_sponsor_their_own_journey(db):
    """A self-sponsor could verify their own gate: the bypass must be refused."""
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    role = _granted_role(db)
    profile = wf.create_profile(db, name="L1 SOC Analyst")
    profile.grants_role_id = role.id
    version = wf.draft_version(db, profile)
    wf.add_requirement(db, version, **GATE)
    db.refresh(version)
    wf.publish_version(db, version, admin)

    with pytest.raises(wf.WorkforceError, match="sponsor their own"):
        wf.assign_profile(db, user=person, version=version, assigner=admin,
                          sponsor=person)


def test_revoke_now_checks_permission_inside_the_service(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "leaver")
    role = _granted_role(db)
    journey = _assign(db, admin, person, role)
    _clear_gate(db, journey, admin)
    record = wf.start_offboarding(db, user=person, raiser=admin,
                                  last_working_day=date.today())

    with pytest.raises(wf.WorkforceError, match="Permission denied"):
        wf.revoke_now(db, record, actor=person)
    db.refresh(person)
    assert role in person.roles, "the refused call must not have revoked anything"


def test_role_changes_leave_an_audit_trail(db):
    from ion.models.user import AuditLog

    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    person = _user(db, "joiner")
    role = _granted_role(db)
    journey = _assign(db, admin, person, role)
    _clear_gate(db, journey, admin)

    actions = [a.action for a in db.query(AuditLog).all()]
    assert "workforce_profile_assigned" in actions
    assert "workforce_requirement_verified" in actions
    assert "workforce_role_granted" in actions, \
        "a role grant with no audit row is invisible to forensics"

    record = wf.start_offboarding(db, user=person, raiser=admin,
                                  last_working_day=date.today())
    wf.revoke_now(db, record, actor=admin)
    actions = [a.action for a in db.query(AuditLog).all()]
    assert "workforce_offboarding_started" in actions
    assert "workforce_access_revoked" in actions
    assert "workforce_role_revoked" in actions

