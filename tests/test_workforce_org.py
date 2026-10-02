"""ORBAT structure rules.

An empty post IS the signal — the tree must count it as a gap, and seating
rules must stop the two quiet ways a gap gets papered over: filling a post
with the wrong role, and one person appearing to fill two posts.
"""

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from ion.models.base import Base
from ion.models.user import Permission, Role, User
from ion.models.workforce import (
    KIND_DOCUMENT,
    PHASE_GATE,
    Course,
    OrgPost,
    OrgUnit,
    UserEnrolment,
)
from ion.services import workforce_service as wf


@pytest.fixture(scope="module")
def _engine(tmp_path_factory):
    engine = create_engine(f"sqlite:///{tmp_path_factory.mktemp('wfo') / 'wfo.db'}")
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def db(_engine):
    s = sessionmaker(bind=_engine)()
    for table in ("role_permissions", "user_roles", "audit_logs"):
        s.execute(text(f"DELETE FROM {table}"))
    for model in (OrgPost, OrgUnit, wf.JourneyRequirement, wf.UserJourney,
                  wf.ProfileRequirement, wf.RoleProfileVersion, wf.RoleProfile,
                  wf.LeaverRecord, UserEnrolment, Course, User, Role, Permission):
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


def _published(db, admin, name):
    profile = wf.create_profile(db, name=name)
    version = wf.draft_version(db, profile)
    wf.add_requirement(db, version, name="AUP", kind=KIND_DOCUMENT, phase=PHASE_GATE)
    db.refresh(version)
    wf.publish_version(db, version, admin)
    return profile, version


def _structure(db, l1_profile):
    soc = OrgUnit(name="SOC")
    db.add(soc)
    db.flush()
    triage = OrgUnit(name="Triage", parent_id=soc.id)
    db.add(triage)
    db.flush()
    posts = [OrgPost(unit_id=triage.id, title=f"L1 Analyst {i}",
                     profile_id=l1_profile.id) for i in (1, 2)]
    db.add_all(posts)
    db.commit()
    return soc, triage, posts


def test_the_tree_counts_an_unfilled_post_as_a_gap(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    profile, version = _published(db, admin, "L1 SOC Analyst")
    _structure(db, profile)

    tree = wf.org_tree(db)
    assert tree["posts_total"] == 2 and tree["gaps"] == 2
    triage = tree["units"][0]["children"][0]
    assert [p["state"] for p in triage["posts"]] == ["gapped", "gapped"]


def test_someone_still_in_training_reads_as_filling_not_filled(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    profile, version = _published(db, admin, "L1 SOC Analyst")
    _, _, posts = _structure(db, profile)

    person = _user(db, "joiner")
    journey = wf.assign_profile(db, user=person, version=version, assigner=admin)
    wf.fill_post(db, post=posts[0], journey_id=journey.id, actor=admin)

    tree = wf.org_tree(db)
    triage = tree["units"][0]["children"][0]
    seated = next(p for p in triage["posts"] if p["id"] == posts[0].id)
    assert seated["state"] == "filling", "pre-access is not presence"
    assert seated["occupant"]["name"] == "joiner"
    assert tree["gaps"] == 1 and tree["filling"] == 1


def test_a_post_refuses_a_journey_from_another_profile(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    l1, _ = _published(db, admin, "L1 SOC Analyst")
    _, ir_version = _published(db, admin, "IR Lead")
    _, _, posts = _structure(db, l1)

    person = _user(db, "responder")
    journey = wf.assign_profile(db, user=person, version=ir_version, assigner=admin)
    with pytest.raises(wf.WorkforceError, match="different role profile"):
        wf.fill_post(db, post=posts[0], journey_id=journey.id, actor=admin)


def test_one_journey_cannot_fill_two_posts(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    profile, version = _published(db, admin, "L1 SOC Analyst")
    _, _, posts = _structure(db, profile)

    person = _user(db, "joiner")
    journey = wf.assign_profile(db, user=person, version=version, assigner=admin)
    wf.fill_post(db, post=posts[0], journey_id=journey.id, actor=admin)
    with pytest.raises(wf.WorkforceError, match="already fills"):
        wf.fill_post(db, post=posts[1], journey_id=journey.id, actor=admin)

    wf.fill_post(db, post=posts[0], journey_id=None, actor=admin)
    wf.fill_post(db, post=posts[1], journey_id=journey.id, actor=admin)


def test_filling_a_post_needs_the_manage_permission(db):
    admin = _user(db, "admin", ["workforce:manage", "workforce:verify"])
    profile, version = _published(db, admin, "L1 SOC Analyst")
    _, _, posts = _structure(db, profile)
    person = _user(db, "joiner")
    journey = wf.assign_profile(db, user=person, version=version, assigner=admin)

    with pytest.raises(wf.WorkforceError, match="Permission denied"):
        wf.fill_post(db, post=posts[0], journey_id=journey.id, actor=person)
