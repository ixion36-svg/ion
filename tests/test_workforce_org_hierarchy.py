"""The ORBAT has to say who answers for each function.

The first establishment rendered as six flat columns of posts, which told
a lead how many of each role existed and nothing about who they report
to. A SOC has a shape: a manager, functional leads under them, and the
teams under those. A list of posts is not an order of battle.

``OrgPost.is_lead`` marks the post that heads its unit, so it renders
above the members rather than beside them. The catalogue's ``leads`` field
says which roles those are.

Two things the hierarchy must not quietly break.

A unit with no lead post is normal, not an error -- a small SOC may have
one manager and no functional leads, and reporting that as a fault would
be noise. But a unit whose lead post is EMPTY is worth seeing, because
"nobody answers for detection engineering tonight" is exactly the kind of
gap the ORBAT exists to surface, and it is invisible if the lead is just
another row in a list.

The manager sits at the root rather than inside a function. Putting the
SOC Manager under Operations would say they lead analysis, which is not
the same job.
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

from ion.data.soc_role_catalogue import get_role
from ion.models.base import Base
from ion.models.user import Permission, Role, User
from ion.models.workforce import PHASE_GATE, OrgPost, OrgUnit
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
    role.permissions = [
        Permission(name="workforce:manage", resource="workforce",
                   action="manage"),
        Permission(name="workforce:verify", resource="workforce",
                   action="verify"),
    ]
    u = User(username="lead", email="l@x", password_hash="x", is_active=True)
    u.roles = [role]
    db.add(u)
    db.commit()
    return u


def find_unit(tree, name):
    """Walk the nested tree. Units are no longer all at the root: that is
    the point of the hierarchy."""
    def walk(nodes):
        for node in nodes:
            if node["name"] == name:
                return node
            found = walk(node.get("children", []))
            if found is not None:
                return found
        return None
    return walk(tree["units"])


def adopt(db, lead, *role_ids):
    analyst = db.query(Role).filter_by(name="analyst").first()
    if analyst is None:
        analyst = Role(name="analyst")
        db.add(analyst)
        db.commit()
    out = {}
    for role_id in role_ids:
        profile = wf.adopt_catalogue_role(db, role_id, adopter=lead)
        version = wf.draft_version(db, profile)
        wf.add_requirement(db, version, name="Right to work", kind="vetting",
                           phase=PHASE_GATE)
        profile.grants_role_id = analyst.id
        db.commit()
        wf.publish_version(db, version, lead)
        db.commit()
        out[role_id] = profile
    return out


class TestTheLeadPost:
    def test_a_lead_role_is_marked_as_one(self, db, lead):
        adopt(db, lead, "lead_analyst", "l1_soc_analyst")
        wf.establish_from_catalogue(db, actor=lead)
        leads = [p for p in db.query(OrgPost).all() if p.is_lead]
        assert len(leads) == 1
        assert "Lead Analyst" in leads[0].title

    def test_an_ordinary_role_is_not(self, db, lead):
        adopt(db, lead, "l1_soc_analyst")
        wf.establish_from_catalogue(db, actor=lead)
        assert all(not p.is_lead for p in db.query(OrgPost).all())

    def test_the_lead_sits_in_the_unit_it_leads(self, db, lead):
        adopt(db, lead, "lead_engineer", "detection_engineer")
        wf.establish_from_catalogue(db, actor=lead)
        unit = db.query(OrgUnit).filter_by(name="Detection Engineering").one()
        titles = {p.title for p in db.query(OrgPost)
                  .filter_by(unit_id=unit.id)}
        assert any("Lead Engineer" in t for t in titles)


class TestTheTree:
    def test_the_lead_is_reported_apart_from_the_members(self, db, lead):
        """So the page can render them above rather than in the list."""
        adopt(db, lead, "lead_analyst", "l1_soc_analyst")
        wf.establish_from_catalogue(db, actor=lead)
        tree = wf.org_tree(db)
        ops = find_unit(tree, "Operations")
        assert ops is not None
        assert ops["lead"] is not None
        assert "Lead Analyst" in ops["lead"]["title"]
        assert all("Lead Analyst" not in p["title"] for p in ops["posts"])

    def test_a_unit_with_no_lead_is_not_an_error(self, db, lead):
        """A small SOC may have one manager and no functional leads."""
        adopt(db, lead, "l1_soc_analyst")
        wf.establish_from_catalogue(db, actor=lead)
        ops = find_unit(wf.org_tree(db), "Operations")
        assert ops is not None
        assert ops["lead"] is None
        assert ops["posts"]

    def test_an_empty_lead_post_is_counted_as_a_gap(self, db, lead):
        """"Nobody answers for detection engineering tonight" is exactly
        what the ORBAT is for, and it disappears if the lead is just
        another row."""
        adopt(db, lead, "lead_engineer", "detection_engineer")
        wf.establish_from_catalogue(db, actor=lead)
        tree = wf.org_tree(db)
        assert tree["leads_gapped"] == 1

    def test_a_filled_lead_post_is_not(self, db, lead):
        profiles = adopt(db, lead, "lead_engineer", "detection_engineer")
        person = User(username="e", email="e@x", password_hash="x",
                      is_active=True)
        db.add(person)
        db.commit()
        version = wf.latest_published(db, profiles["lead_engineer"].id)
        journey = wf.assign_profile(db, user=person, version=version,
                                    assigner=lead)
        wf.establish_from_catalogue(db, actor=lead)
        post = next(p for p in db.query(OrgPost).all() if p.is_lead)
        wf.fill_post(db, post=post, journey_id=journey.id, actor=lead)
        assert wf.org_tree(db)["leads_gapped"] == 0

    def test_the_gap_total_still_counts_every_post(self, db, lead):
        """Separating the lead out must not drop it from the headline."""
        adopt(db, lead, "lead_analyst", "l1_soc_analyst")
        wf.establish_from_catalogue(db, actor=lead)
        tree = wf.org_tree(db)
        expected = get_role("l1_soc_analyst")["typical_establishment"] + 1
        assert tree["posts_total"] == expected
        assert tree["gaps"] == expected


class TestTheManager:
    def test_the_manager_is_not_inside_a_function(self, db, lead):
        """Putting the SOC Manager under Operations would say they lead
        analysis, which is a different job."""
        adopt(db, lead, "soc_manager", "l1_soc_analyst")
        wf.establish_from_catalogue(db, actor=lead)
        unit = db.query(OrgUnit).filter_by(name="Operations").one()
        titles = {p.title for p in db.query(OrgPost).filter_by(unit_id=unit.id)}
        assert not any("SOC Manager" in t for t in titles)

    def test_the_manager_heads_the_whole_thing(self, db, lead):
        adopt(db, lead, "soc_manager", "l1_soc_analyst")
        wf.establish_from_catalogue(db, actor=lead)
        tree = wf.org_tree(db)
        root = find_unit(tree, "SOC")
        assert root is not None
        assert root["lead"] is not None
        assert "SOC Manager" in root["lead"]["title"]

    def test_the_functions_sit_under_it(self, db, lead):
        adopt(db, lead, "soc_manager", "lead_analyst", "l1_soc_analyst")
        wf.establish_from_catalogue(db, actor=lead)
        tree = wf.org_tree(db)
        root = find_unit(tree, "SOC")
        assert {c["name"] for c in root["children"]} >= {"Operations"}


class TestTheNewRoles:
    @pytest.mark.parametrize("role_id,expected_tier", [
        ("operations_analyst", "T3"),
        ("technical_analyst", "T3"),
    ])
    def test_they_are_in_the_catalogue_at_tier_three(self, role_id,
                                                     expected_tier):
        role = get_role(role_id)
        assert role is not None
        assert role["tier"] == expected_tier

    def test_they_sit_in_operations(self):
        for role_id in ("operations_analyst", "technical_analyst"):
            assert get_role(role_id)["category"] == "operations"

    def test_they_can_be_adopted_and_established(self, db, lead):
        adopt(db, lead, "operations_analyst", "technical_analyst")
        wf.establish_from_catalogue(db, actor=lead)
        titles = {p.title for p in db.query(OrgPost).all()}
        assert "Operations Analyst" in titles
        assert "Technical Analyst" in titles
