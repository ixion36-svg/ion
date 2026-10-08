"""The role is chosen when the account is made, not weeks later.

The workflow: an admin creates the account and says which role the person
is being onboarded into. The person then works their training while the
vetting and paperwork run in parallel, and the permissions arrive when the
mandatory items are verified.

Before this, ``create_user`` opened only the baseline induction. The role
had to be assigned separately, by a lead, at some later point -- so until
somebody did that, "Role readiness" on the joiner's own page was empty and
they had no way to know what they were training for.

Two things this had to get right.

**A role profile with no gate items can never confer its role.**
``gate_cleared`` is ``bool(items) and all(satisfied)``, so an empty gate is
False, not vacuously True. That is the safe direction -- a role is never
granted by having no requirements -- but it means a profile carrying
``grants_role_id`` and only readiness items is permanently inert: the
person completes everything asked of them and nothing is ever conferred,
with nothing on screen to say why. Publishing one is now refused.

**Assigning a role up front must not grant anything up front.** The
journey opens at pre_access with every item pending. What the admin is
choosing is which training to issue, not which permissions to hand over.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.models.base import Base
from ion.models.user import Permission, Role, User
from ion.models.workforce import (
    PHASE_GATE,
    PHASE_READINESS,
    STAGE_PRE_ACCESS,
    STATUS_VERIFIED,
    UserJourney,
)
from ion.services import workforce_service as wf

GATE = dict(name="Security induction", kind="course", phase=PHASE_GATE,
            validity_months=12)
AGREEMENT = dict(name="Acceptable use", kind="document", phase=PHASE_GATE,
                 validity_months=12)
TRAINING = dict(name="ION platform training", kind="course",
                phase=PHASE_READINESS, validity_months=24)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


@pytest.fixture
def admin(db):
    role = Role(name="admin")
    role.permissions = [
        Permission(name="workforce:manage", resource="workforce", action="manage"),
        Permission(name="workforce:verify", resource="workforce", action="verify"),
    ]
    u = User(username="admin", email="a@x", password_hash="x", is_active=True)
    u.roles = [role]
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def analyst_role(db):
    r = Role(name="analyst")
    db.add(r)
    db.commit()
    return r


def role_profile(db, admin, analyst_role, *, name="SOC Analyst L1",
                 requirements=(GATE, AGREEMENT, TRAINING), grants=True,
                 publish=True):
    profile = wf.create_profile(db, name=name)
    if grants:
        profile.grants_role_id = analyst_role.id
    version = wf.draft_version(db, profile)
    for req in requirements:
        wf.add_requirement(db, version, **req)
    db.commit()
    if publish:
        wf.publish_version(db, version, admin)
        db.commit()
    return profile, version


# -- Publishing a profile that could never confer its role ----------------


class TestAnInertProfileIsRefused:
    def test_granting_a_role_with_no_gate_items_is_refused(
        self, db, admin, analyst_role
    ):
        """The person would complete everything asked of them and never be
        granted anything, with nothing on screen to say why."""
        profile, version = role_profile(
            db, admin, analyst_role,
            requirements=(TRAINING,), publish=False)
        with pytest.raises(wf.WorkforceError) as exc:
            wf.publish_version(db, version, admin)
        assert "gate" in str(exc.value).lower()

    def test_the_refusal_explains_the_consequence(self, db, admin, analyst_role):
        profile, version = role_profile(
            db, admin, analyst_role,
            requirements=(TRAINING,), publish=False)
        with pytest.raises(wf.WorkforceError) as exc:
            wf.publish_version(db, version, admin)
        message = str(exc.value).lower()
        assert "never" in message or "cannot" in message

    def test_a_profile_that_grants_nothing_may_have_no_gate(
        self, db, admin, analyst_role
    ):
        """A pure training track confers no role, so an empty gate is not a
        trap -- it is the whole point."""
        profile, version = role_profile(
            db, admin, analyst_role, name="Optional CPD",
            requirements=(TRAINING,), grants=False, publish=False)
        wf.publish_version(db, version, admin)
        assert version.is_published

    def test_a_profile_with_a_gate_publishes_normally(
        self, db, admin, analyst_role
    ):
        _, version = role_profile(db, admin, analyst_role)
        assert version.is_published


# -- Assigning the role when the account is made --------------------------


class TestRoleAtCreation:
    def test_the_journey_opens_for_the_named_role(self, db, admin, analyst_role):
        profile, version = role_profile(db, admin, analyst_role)
        joiner = User(username="j", email="j@x", password_hash="x",
                      is_active=True)
        db.add(joiner)
        db.commit()

        journey = wf.enrol_on_role(db, joiner, profile_id=profile.id,
                                   assigner=admin)
        assert journey is not None
        assert journey.version_id == version.id

    def test_it_grants_nothing_yet(self, db, admin, analyst_role):
        """Choosing the role is choosing which training to issue, not which
        permissions to hand over."""
        profile, _ = role_profile(db, admin, analyst_role)
        joiner = User(username="j", email="j@x", password_hash="x",
                      is_active=True)
        db.add(joiner)
        db.commit()

        wf.enrol_on_role(db, joiner, profile_id=profile.id, assigner=admin)
        db.refresh(joiner)
        assert [r.name for r in joiner.roles] == []
        assert wf.has_system_access(db, joiner.id) is False

    def test_the_journey_starts_before_access(self, db, admin, analyst_role):
        profile, _ = role_profile(db, admin, analyst_role)
        joiner = User(username="j", email="j@x", password_hash="x",
                      is_active=True)
        db.add(joiner)
        db.commit()
        journey = wf.enrol_on_role(db, joiner, profile_id=profile.id,
                                   assigner=admin)
        assert journey.stage == STAGE_PRE_ACCESS
        assert all(r.status == "pending" for r in journey.requirements)

    def test_both_the_mandatory_and_the_role_items_are_issued(
        self, db, admin, analyst_role
    ):
        """The training and the paperwork run in parallel, so the person
        can see all of it from day one."""
        profile, _ = role_profile(db, admin, analyst_role)
        joiner = User(username="j", email="j@x", password_hash="x",
                      is_active=True)
        db.add(joiner)
        db.commit()
        journey = wf.enrol_on_role(db, joiner, profile_id=profile.id,
                                   assigner=admin)
        phases = {r.phase for r in journey.requirements}
        assert phases == {PHASE_GATE, PHASE_READINESS}

    def test_an_unknown_profile_returns_none(self, db, admin):
        joiner = User(username="j", email="j@x", password_hash="x",
                      is_active=True)
        db.add(joiner)
        db.commit()
        assert wf.enrol_on_role(db, joiner, profile_id=9999,
                                assigner=admin) is None

    def test_an_unpublished_profile_returns_none(self, db, admin, analyst_role):
        profile, _ = role_profile(db, admin, analyst_role, publish=False)
        joiner = User(username="j", email="j@x", password_hash="x",
                      is_active=True)
        db.add(joiner)
        db.commit()
        assert wf.enrol_on_role(db, joiner, profile_id=profile.id,
                                assigner=admin) is None

    def test_it_never_raises(self, db, admin, analyst_role, monkeypatch):
        """Same contract as enrol_on_baseline: creating an account must not
        fail because the workforce module has a problem."""
        profile, _ = role_profile(db, admin, analyst_role)
        joiner = User(username="j", email="j@x", password_hash="x",
                      is_active=True)
        db.add(joiner)
        db.commit()

        def boom(*a, **k):
            raise RuntimeError("broken")

        monkeypatch.setattr(wf, "assign_profile", boom)
        assert wf.enrol_on_role(db, joiner, profile_id=profile.id,
                                assigner=admin) is None

    def test_a_verified_gate_item_carries_across(self, db, admin, analyst_role):
        """Somebody who already cleared the induction on the baseline is
        not asked for it again when their role is assigned."""
        base = wf.create_profile(db, name="Mandatory Induction",
                                 is_baseline=True)
        bv = wf.draft_version(db, base)
        wf.add_requirement(db, bv, **GATE)
        wf.add_requirement(db, bv, **AGREEMENT)
        wf.publish_version(db, bv, admin)
        db.commit()

        joiner = User(username="j", email="j@x", password_hash="x",
                      is_active=True)
        db.add(joiner)
        db.commit()
        baseline_journey = wf.enrol_on_baseline(db, joiner)
        for req in baseline_journey.requirements:
            wf.verify_requirement(db, requirement=req, verifier=admin)
        db.commit()

        profile, _ = role_profile(db, admin, analyst_role)
        journey = wf.enrol_on_role(db, joiner, profile_id=profile.id,
                                   assigner=admin)
        gate = {r.name: r for r in journey.requirements
                if r.phase == PHASE_GATE}
        assert gate["Security induction"].status == STATUS_VERIFIED
        assert gate["Acceptable use"].status == STATUS_VERIFIED


# -- Wired into account creation ------------------------------------------


class TestWiredIntoAccountCreation:
    def test_create_user_accepts_a_role_profile(self):
        source = (_SRC / "ion" / "auth" / "service.py").read_text(
            encoding="utf-8")
        assert "role_profile_id" in source
        assert "enrol_on_role" in source

    def test_the_api_accepts_it_too(self):
        source = (_SRC / "ion" / "web" / "api.py").read_text(encoding="utf-8")
        block = source.split("class UserCreate(BaseModel):")[1][:900]
        assert "role_profile_id" in block
