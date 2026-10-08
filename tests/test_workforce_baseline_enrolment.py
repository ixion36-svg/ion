"""A new account is enrolled on the baseline journey automatically.

The workflow is: somebody gets a local account, that account is gated
behind permissions until they pass the mandatory training, and passing it
is what confers the role and with it the role's permissions.

The pieces for that existed and were not connected. ``RoleProfile`` has
carried ``is_baseline`` with the comment "a baseline applies to every
role", and ``grants_role_id`` with "membership is withheld until the gate
is verified ... so the mandatory list is what actually holds the
permissions back, not a separate manual step". Both were true of the
mechanism and false in practice, because nothing opened the journey: a
lead had to assign one by hand, per person, before any of it applied.

So an account created and forgotten had no journey, no mandatory list,
nothing withheld and nothing tracked. The gate held back permissions only
for people somebody had remembered to enrol, which is the wrong way round
-- the person nobody remembered is exactly the one you want gated.

Enrolment happens at account creation, so:

* the mandatory list exists from the moment the account does;
* the person sees what they have to do the first time they log in,
  without waiting on a lead;
* ``sync_granted_roles`` has something to reconcile against, so the gate
  genuinely holds the permissions back rather than describing a policy
  nobody applied.

It is deliberately not retroactive and deliberately quiet about failure:
creating an account must not fail because the workforce module is off, or
because no baseline has been defined yet.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.models.base import Base
from ion.models.user import User
from ion.models.workforce import (
    PHASE_GATE,
    PHASE_READINESS,
    STAGE_PRE_ACCESS,
    UserJourney,
)
from ion.services import workforce_service as wf
from ion.services.workforce_service import enrol_on_baseline


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


@pytest.fixture
def joiner(db):
    u = User(username="newstarter", email="n@x", password_hash="x",
             display_name="New Starter", is_active=True)
    db.add(u)
    db.commit()
    return u


def baseline_profile(db, name="Mandatory induction"):
    """A published baseline profile with gate and readiness items."""
    profile = wf.create_profile(db, name=name, is_baseline=True)
    version = wf.draft_version(db, profile)
    wf.add_requirement(db, version, name="Security induction", kind="course",
                       phase=PHASE_GATE, validity_months=12)
    wf.add_requirement(db, version, name="Acceptable use", kind="document",
                       phase=PHASE_GATE, validity_months=12)
    wf.add_requirement(db, version, name="Tooling walkthrough", kind="course",
                       phase=PHASE_READINESS, validity_months=24)
    # is_published is derived from published_at, which has no setter.
    version.published_at = datetime.utcnow()
    db.commit()
    return profile, version


# -- The enrolment --------------------------------------------------------


class TestEnrolment:
    def test_a_new_account_gets_the_baseline_journey(self, db, joiner):
        _, version = baseline_profile(db)
        journey = enrol_on_baseline(db, joiner)
        assert journey is not None
        assert journey.user_id == joiner.id
        assert journey.version_id == version.id

    def test_the_journey_starts_before_access(self, db, joiner):
        baseline_profile(db)
        journey = enrol_on_baseline(db, joiner)
        assert journey.stage == STAGE_PRE_ACCESS

    def test_the_mandatory_list_is_there_from_the_start(self, db, joiner):
        """The point of enrolling at creation: the person can see what they
        have to do the first time they log in, without waiting on a lead."""
        baseline_profile(db)
        journey = enrol_on_baseline(db, joiner)
        names = {r.name for r in journey.requirements}
        assert names == {"Security induction", "Acceptable use",
                         "Tooling walkthrough"}

    def test_nothing_is_verified_on_day_one(self, db, joiner):
        baseline_profile(db)
        journey = enrol_on_baseline(db, joiner)
        assert all(r.status == "pending" for r in journey.requirements)

    def test_the_person_has_no_access_yet(self, db, joiner):
        baseline_profile(db)
        enrol_on_baseline(db, joiner)
        assert wf.has_system_access(db, joiner.id) is False

    def test_it_does_not_need_a_lead_to_be_present(self, db, joiner):
        """assign_profile requires an assigner holding workforce:manage.
        Enrolment happens when an account is created, which may be a
        bootstrap or an SSO first login with no human in the loop."""
        baseline_profile(db)
        assert enrol_on_baseline(db, joiner) is not None


# -- It must never break account creation ---------------------------------


class TestItNeverBreaksAccountCreation:
    def test_no_baseline_defined_returns_none_rather_than_raising(
        self, db, joiner
    ):
        """A fresh deployment has no profiles at all. Creating the first
        account must not fail because nobody has written an induction yet."""
        assert enrol_on_baseline(db, joiner) is None

    def test_an_unpublished_baseline_is_not_used(self, db, joiner):
        """A draft is somebody still writing it. Enrolling people onto a
        half-written mandatory list is worse than enrolling them onto
        none, because it looks like it was intended."""
        profile = wf.create_profile(db, name="Draft induction", is_baseline=True)
        version = wf.draft_version(db, profile)
        wf.add_requirement(db, version, name="Half-written", kind="document",
                           phase=PHASE_GATE)
        db.commit()
        assert enrol_on_baseline(db, joiner) is None

    def test_an_inactive_baseline_is_not_used(self, db, joiner):
        profile, _ = baseline_profile(db)
        profile.is_active = False
        db.commit()
        assert enrol_on_baseline(db, joiner) is None

    def test_enrolling_twice_does_not_make_a_second_journey(self, db, joiner):
        """Re-running a bootstrap, or an SSO callback firing twice, must
        not duplicate somebody's mandatory list."""
        baseline_profile(db)
        first = enrol_on_baseline(db, joiner)
        second = enrol_on_baseline(db, joiner)
        assert second is not None
        assert second.id == first.id
        assert db.query(UserJourney).filter_by(user_id=joiner.id).count() == 1

    def test_a_broken_baseline_does_not_raise(self, db, joiner, monkeypatch):
        """Whatever goes wrong in here, the account still gets created.
        A deployment that cannot add users because the workforce module
        has a problem is a worse failure than one with no journeys."""
        def boom(*a, **k):
            raise RuntimeError("something in workforce broke")

        baseline_profile(db)
        monkeypatch.setattr(wf, "_baseline_version", boom)
        assert enrol_on_baseline(db, joiner) is None


# -- Choosing the baseline ------------------------------------------------


class TestChoosingTheBaseline:
    def test_a_non_baseline_profile_is_ignored(self, db, joiner):
        """Only is_baseline profiles auto-enrol. A role profile is assigned
        deliberately, by a lead, to a named person."""
        profile = wf.create_profile(db, name="L2 Analyst", is_baseline=False)
        version = wf.draft_version(db, profile)
        wf.add_requirement(db, version, name="Something", kind="document",
                           phase=PHASE_GATE)
        version.published_at = datetime.utcnow()
        db.commit()
        assert enrol_on_baseline(db, joiner) is None

    def test_the_latest_published_version_is_used(self, db, joiner):
        """Not the first: a deployment that has revised its induction twice
        should put new starters on the current one."""
        profile, v1 = baseline_profile(db)
        v2 = wf.draft_version(db, profile)
        wf.add_requirement(db, v2, name="Newer item", kind="document",
                           phase=PHASE_GATE)
        v2.published_at = datetime.utcnow()
        db.commit()

        journey = enrol_on_baseline(db, joiner)
        assert journey.version_id == v2.id

    def test_with_two_baselines_the_choice_is_deterministic(self, db, joiner):
        """Two baselines is a misconfiguration, but it must not produce a
        different answer depending on row order -- one person enrolled on
        one induction and the next on another is the hardest kind of
        inconsistency to notice."""
        baseline_profile(db, name="Induction A")
        baseline_profile(db, name="Induction B")
        first = enrol_on_baseline(db, joiner)

        other = User(username="second", email="s@x", password_hash="x",
                     is_active=True)
        db.add(other)
        db.commit()
        second = enrol_on_baseline(db, other)
        assert first.version_id == second.version_id


# -- Wired into account creation ------------------------------------------


class TestWiredIntoAccountCreation:
    def test_create_user_calls_it(self):
        """A test on the call site, because the value of enrolling at
        creation is entirely that nobody has to remember to do it."""
        source = (_SRC / "ion" / "auth" / "service.py").read_text(encoding="utf-8")
        assert "enrol_on_baseline" in source
