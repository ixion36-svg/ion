"""One person, one live journey per role.

Found by walking onboarding against the running estate, 8 October 2026.
``assign_profile`` refuses a second journey for the same *version*:

    UserJourney.version_id == version.id

but a role profile is versioned, so publishing v2 and assigning it to
someone already on v1 passes that check and opens a second journey. The
person then holds two live journeys for one role, and:

* their requirements are duplicated, so they are asked for the same
  evidence twice and can satisfy a role by completing either copy;
* the expiry report lists every item twice, which is how it was noticed --
  the same "Acceptable use and monitoring agreement" under journey 1 and
  journey 2;
* capability cover and the ORBAT count them twice for one role, so a team
  of one reads as a team of two. That is the dangerous one: the number
  exists to answer "are we covered tonight", and it over-reports.

Rolling a role profile forward is a normal thing to do -- it is why
versions exist -- so refusing outright would leave leads unable to move
anyone onto a new version without hand-closing the old journey first.

So: the guard moves to the profile, and supersede becomes explicit.
Superseding closes the prior journey and carries across items that are
already verified and still in date, by name, in both phases. A person who
has held a clearance and a Security+ for two years should not be asked to
produce them again because the role's wording changed.
"""

from __future__ import annotations

import sys
from datetime import date, datetime, timedelta
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
    STAGE_CLOSED,
    STATUS_VERIFIED,
    UserJourney,
)
from ion.services import workforce_service as wf


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


@pytest.fixture
def lead(db):
    role = Role(name="lead")
    # Both: assign_profile needs workforce:manage, verify_requirement needs
    # workforce:verify. A lead doing a supersede does both.
    role.permissions = [
        Permission(name="workforce:manage", resource="workforce", action="manage"),
        Permission(name="workforce:verify", resource="workforce", action="verify"),
    ]
    u = User(username="lead", email="lead@x", password_hash="x",
             display_name="Lead", is_active=True)
    u.roles = [role]
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def joiner(db):
    u = User(username="joiner", email="j@x", password_hash="x",
             display_name="Joiner", is_active=True)
    db.add(u)
    db.commit()
    return u


def published_version(db, lead, profile=None, *, requirements):
    """A published version of a profile, with the given requirements."""
    if profile is None:
        profile = wf.create_profile(db, name="SOC Analyst")
    version = wf.draft_version(db, profile)
    for r in requirements:
        wf.add_requirement(db, version, **r)
    wf.publish_version(db, version, lead)
    db.commit()
    return profile, version


GATE = dict(name="BPSS", kind="vetting", phase=PHASE_GATE, validity_months=36)
CERT = dict(name="Security+", kind="cert", phase=PHASE_READINESS,
            validity_months=36)
SIGNOFF = dict(name="Triage sign-off", kind="signoff", phase=PHASE_READINESS,
               validity_months=12)


# -- The defect -----------------------------------------------------------


class TestOneLiveJourneyPerRole:
    def test_a_second_version_of_the_same_role_is_refused(self, db, lead, joiner):
        profile, v1 = published_version(db, lead, requirements=[GATE, CERT])
        wf.assign_profile(db, user=joiner, version=v1, assigner=lead)

        v2 = wf.draft_version(db, profile)
        wf.add_requirement(db, v2, **GATE)
        wf.publish_version(db, v2, lead)
        db.commit()

        with pytest.raises(wf.WorkforceError) as exc:
            wf.assign_profile(db, user=joiner, version=v2, assigner=lead)
        assert "already" in str(exc.value).lower()

    def test_the_refusal_names_the_existing_journey(self, db, lead, joiner):
        """"Already holds one" without saying which leaves the lead
        hunting. The point of refusing is to send them to the right place."""
        profile, v1 = published_version(db, lead, requirements=[GATE])
        journey = wf.assign_profile(db, user=joiner, version=v1, assigner=lead)

        v2 = wf.draft_version(db, profile)
        wf.add_requirement(db, v2, **GATE)
        wf.publish_version(db, v2, lead)
        db.commit()

        with pytest.raises(wf.WorkforceError) as exc:
            wf.assign_profile(db, user=joiner, version=v2, assigner=lead)
        message = str(exc.value)
        assert str(journey.id) in message
        assert "supersede" in message.lower()

    def test_the_same_version_is_still_refused(self, db, lead, joiner):
        """The original guard's case must keep working."""
        _, v1 = published_version(db, lead, requirements=[GATE])
        wf.assign_profile(db, user=joiner, version=v1, assigner=lead)
        with pytest.raises(wf.WorkforceError):
            wf.assign_profile(db, user=joiner, version=v1, assigner=lead)

    def test_a_different_role_is_unaffected(self, db, lead, joiner):
        """The guard is per profile, not per person: holding two different
        roles is normal, and a cover role is the whole point."""
        _, v1 = published_version(db, lead, requirements=[GATE])
        other = wf.create_profile(db, name="Incident Responder")
        _, v_other = published_version(db, lead, other, requirements=[GATE])

        wf.assign_profile(db, user=joiner, version=v1, assigner=lead)
        second = wf.assign_profile(db, user=joiner, version=v_other,
                                   assigner=lead, is_cover=True)
        assert second.id is not None

    def test_a_closed_journey_does_not_block_a_new_one(self, db, lead, joiner):
        """Someone who left the role and came back starts cleanly."""
        profile, v1 = published_version(db, lead, requirements=[GATE])
        journey = wf.assign_profile(db, user=joiner, version=v1, assigner=lead)
        journey.stage = STAGE_CLOSED
        db.commit()

        v2 = wf.draft_version(db, profile)
        wf.add_requirement(db, v2, **GATE)
        wf.publish_version(db, v2, lead)
        db.commit()
        again = wf.assign_profile(db, user=joiner, version=v2, assigner=lead)
        assert again.id != journey.id


# -- Superseding ----------------------------------------------------------


class TestSupersede:
    def _two_versions(self, db, lead, joiner):
        profile, v1 = published_version(
            db, lead, requirements=[GATE, CERT, SIGNOFF])
        journey = wf.assign_profile(db, user=joiner, version=v1, assigner=lead)
        # Verify everything on the old journey.
        for req in journey.requirements:
            wf.verify_requirement(db, requirement=req, verifier=lead)
        db.commit()

        v2 = wf.draft_version(db, profile)
        for r in (GATE, CERT, SIGNOFF):
            wf.add_requirement(db, v2, **r)
        wf.publish_version(db, v2, lead)
        db.commit()
        return profile, journey, v2

    def test_superseding_closes_the_old_journey(self, db, lead, joiner):
        _, old, v2 = self._two_versions(db, lead, joiner)
        wf.assign_profile(db, user=joiner, version=v2, assigner=lead,
                          supersede=True)
        db.refresh(old)
        assert old.stage == STAGE_CLOSED

    def test_only_one_live_journey_remains(self, db, lead, joiner):
        _, old, v2 = self._two_versions(db, lead, joiner)
        wf.assign_profile(db, user=joiner, version=v2, assigner=lead,
                          supersede=True)
        live = [
            j for j in db.query(UserJourney).filter_by(user_id=joiner.id).all()
            if j.stage not in (STAGE_CLOSED, "withdrawn")
        ]
        assert len(live) == 1
        assert live[0].version_id == v2.id

    def test_a_verified_in_date_item_carries_across(self, db, lead, joiner):
        """Someone who has held a clearance for two years should not be
        asked to produce it again because the role's wording changed."""
        _, _, v2 = self._two_versions(db, lead, joiner)
        new = wf.assign_profile(db, user=joiner, version=v2, assigner=lead,
                                supersede=True)
        carried = {r.name: r for r in new.requirements}
        assert carried["BPSS"].status == STATUS_VERIFIED
        assert carried["Security+"].status == STATUS_VERIFIED

    def test_readiness_carries_too_not_just_the_gate(self, db, lead, joiner):
        """assign_profile already carried gate items across from elsewhere.
        On a supersede the readiness items were earned for THIS role, so
        reissuing them is pure rework."""
        _, _, v2 = self._two_versions(db, lead, joiner)
        new = wf.assign_profile(db, user=joiner, version=v2, assigner=lead,
                                supersede=True)
        signoff = next(r for r in new.requirements if r.name == "Triage sign-off")
        assert signoff.status == STATUS_VERIFIED
        assert signoff.phase == PHASE_READINESS

    def test_an_expired_item_does_not_carry(self, db, lead, joiner):
        """Carrying an expired item across would launder a lapse into a
        clean record -- the one thing this must never do."""
        _, old, v2 = self._two_versions(db, lead, joiner)
        stale = next(r for r in old.requirements if r.name == "Security+")
        stale.expires_on = date.today() - timedelta(days=1)
        db.commit()

        new = wf.assign_profile(db, user=joiner, version=v2, assigner=lead,
                                supersede=True)
        carried = next(r for r in new.requirements if r.name == "Security+")
        assert carried.status != STATUS_VERIFIED

    def test_a_new_requirement_starts_pending(self, db, lead, joiner):
        profile, old, _ = self._two_versions(db, lead, joiner)
        v3 = wf.draft_version(db, profile)
        for r in (GATE, CERT, SIGNOFF):
            wf.add_requirement(db, v3, **r)
        wf.add_requirement(db, v3, name="New thing", kind="document",
                           phase=PHASE_READINESS)
        wf.publish_version(db, v3, lead)
        db.commit()

        new = wf.assign_profile(db, user=joiner, version=v3, assigner=lead,
                                supersede=True)
        added = next(r for r in new.requirements if r.name == "New thing")
        assert added.status == "pending"

    def test_the_carried_expiry_is_the_original_not_a_fresh_one(
        self, db, lead, joiner
    ):
        """Resetting the clock on supersede would let a role edit extend
        every clearance in the SOC by three years."""
        _, old, v2 = self._two_versions(db, lead, joiner)
        original = next(r for r in old.requirements if r.name == "BPSS")
        original.expires_on = date.today() + timedelta(days=30)
        db.commit()

        new = wf.assign_profile(db, user=joiner, version=v2, assigner=lead,
                                supersede=True)
        carried = next(r for r in new.requirements if r.name == "BPSS")
        assert carried.expires_on == date.today() + timedelta(days=30)

    def test_superseding_is_audited(self, db, lead, joiner):
        from ion.models.user import AuditLog

        _, old, v2 = self._two_versions(db, lead, joiner)
        wf.assign_profile(db, user=joiner, version=v2, assigner=lead,
                          supersede=True)
        actions = [a.action for a in db.query(AuditLog).all()]
        assert "workforce_journey_superseded" in actions

    def test_supersede_with_nothing_to_supersede_is_a_normal_assignment(
        self, db, lead, joiner
    ):
        """A lead who ticks supersede on a first assignment should get a
        journey, not an error about a journey that does not exist."""
        _, v1 = published_version(db, lead, requirements=[GATE])
        journey = wf.assign_profile(db, user=joiner, version=v1,
                                    assigner=lead, supersede=True)
        assert journey.id is not None
