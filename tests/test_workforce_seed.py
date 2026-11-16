"""A fresh install is given an induction and starter roles to onboard into.

The defect: every Workforce tab was empty on a new deployment, and the
induction the Me tab is built around could not be created from any page.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ion.models.base import Base
from ion.models.user import Permission, Role, User
from ion.models.workforce import PHASE_GATE, RoleProfile, UserJourney
from ion.services import workforce_service as wf
from ion.services.workforce_seed import map_existing_accounts, seed_workforce_defaults


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
    ]
    u = User(username="admin", email="a@x", password_hash="x", is_active=True)
    u.roles = [role]
    db.add(u)
    db.commit()
    return u


def test_a_new_account_is_put_on_the_seeded_induction(db, admin):
    assert seed_workforce_defaults(db) is True

    joiner = User(username="joiner", email="j@x", password_hash="x", is_active=True)
    db.add(joiner)
    db.commit()
    journey = wf.enrol_on_baseline(db, joiner)

    assert journey is not None
    assert len(journey.requirements) == 4
    assert {r.phase for r in journey.requirements} == {PHASE_GATE}


def _account(db, username, *role_names):
    roles = [db.query(Role).filter_by(name=n).one_or_none() or Role(name=n)
             for n in role_names]
    u = User(username=username, email=f"{username}@x", password_hash="x",
             is_active=True)
    u.roles = roles
    db.add(u)
    db.commit()
    return u


def _journeys(db, user):
    return {j.version.profile.name: j
            for j in db.query(UserJourney).filter_by(user_id=user.id)}


def test_accounts_are_put_on_the_roles_they_already_hold_and_keep_them(db, admin):
    veteran = _account(db, "veteran", "senior_analyst", "forensic")
    seed_workforce_defaults(db)

    opened = map_existing_accounts(db)

    journeys = _journeys(db, veteran)
    assert opened == 2
    assert sorted(journeys) == ["DFIR / Forensic Analyst", "SOC Analyst (L2)"]
    assert all(j.role_already_held for j in journeys.values())
    assert sorted(r.name for r in veteran.roles) == ["forensic", "senior_analyst"]


def test_mapped_accounts_are_seated_on_the_order_of_battle(db, admin):
    from ion.models.workforce import OrgPost

    veteran = _account(db, "veteran", "senior_analyst")
    seed_workforce_defaults(db)
    map_existing_accounts(db)

    journey = db.query(UserJourney).filter_by(user_id=veteran.id).one()
    post = db.query(OrgPost).filter_by(filled_by_journey_id=journey.id).one()
    assert post.profile_id == journey.version.profile_id


def test_one_more_post_is_added_when_every_post_for_the_role_is_filled(db, admin):
    from ion.models.workforce import OrgPost

    leads = [_account(db, f"lead{i}", "lead") for i in range(3)]
    seed_workforce_defaults(db)
    lead_profile = db.query(RoleProfile).filter_by(name="SOC Lead").one()
    established = db.query(OrgPost).filter_by(profile_id=lead_profile.id).count()

    map_existing_accounts(db)

    posts = db.query(OrgPost).filter_by(profile_id=lead_profile.id).all()
    assert established < 3
    assert len(posts) == 3
    seated = {p.filled_by_journey_id for p in posts}
    assert seated == {j.id for j in db.query(UserJourney)
                      if j.user_id in {u.id for u in leads}}


def test_a_held_role_survives_later_syncs_with_its_gate_unverified(db, admin):
    veteran = _account(db, "veteran", "analyst")
    seed_workforce_defaults(db)
    map_existing_accounts(db)

    result = wf.sync_granted_roles(db, veteran)

    assert result == {"granted": [], "revoked": []}
    assert [r.name for r in veteran.roles] == ["analyst"]


def test_a_role_still_to_be_earned_is_held_back(db, admin):
    _account(db, "placeholder", "analyst")
    seed_workforce_defaults(db)
    joiner = _account(db, "joiner")
    l1 = db.query(RoleProfile).filter_by(name="SOC Analyst (L1)").one()

    journey = wf.enrol_on_role(db, joiner, profile_id=l1.id, assigner=admin)

    assert journey.role_already_held is False
    assert joiner.roles == []


def test_a_journey_closed_on_purpose_is_not_reopened(db, admin):
    from ion.models.workforce import STAGE_CLOSED

    veteran = _account(db, "veteran", "analyst")
    seed_workforce_defaults(db)
    map_existing_accounts(db)
    journey = db.query(UserJourney).filter_by(user_id=veteran.id).one()
    journey.stage = STAGE_CLOSED
    db.commit()

    assert map_existing_accounts(db) == 0
    assert db.query(UserJourney).filter_by(user_id=veteran.id).count() == 1


def test_accounts_with_no_mapped_role_get_no_journey(db, admin):
    _account(db, "service", "metis")
    seed_workforce_defaults(db)

    assert map_existing_accounts(db) == 0


def test_a_deployment_with_its_own_profiles_is_left_alone(db, admin):
    wf.create_profile(db, name="Our Own Role")

    assert seed_workforce_defaults(db) is False
    assert [p.name for p in db.query(RoleProfile)] == ["Our Own Role"]


def test_a_second_start_adds_nothing(db, admin):
    seed_workforce_defaults(db)
    before = db.query(RoleProfile).count()

    assert seed_workforce_defaults(db) is False
    assert db.query(RoleProfile).count() == before


def test_it_waits_when_nobody_can_manage_workforce(db):
    assert seed_workforce_defaults(db) is False
    assert db.query(RoleProfile).count() == 0
    assert db.query(UserJourney).count() == 0
