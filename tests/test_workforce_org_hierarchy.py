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
        assert len(ops["leads"]) == 1
        assert "Lead Analyst" in ops["leads"][0]["title"]
        assert all("Lead Analyst" not in p["title"] for p in ops["posts"])

    def test_a_unit_with_no_lead_is_not_an_error(self, db, lead):
        """A small SOC may have one manager and no functional leads."""
        adopt(db, lead, "l1_soc_analyst")
        wf.establish_from_catalogue(db, actor=lead)
        ops = find_unit(wf.org_tree(db), "Operations")
        assert ops is not None
        assert ops["leads"] == []
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
        assert [p["title"] for p in root["leads"]] == ["SOC Manager"]

    def test_the_functions_sit_under_it(self, db, lead):
        adopt(db, lead, "soc_manager", "lead_analyst", "l1_soc_analyst")
        wf.establish_from_catalogue(db, actor=lead)
        tree = wf.org_tree(db)
        root = find_unit(tree, "SOC")
        assert {c["name"] for c in root["children"]} >= {"Operations"}


class TestTheSOCLeadAndTheManager:
    """Both head the SOC, and they are not the same job.

    The manager is accountable for the service: cover, capability, budget,
    the people. The SOC Lead runs it day to day, and the functional leads
    answer to them. A SOC can have one, the other, or both.

    They sit on the same unit, which the tree used to handle by keeping
    one lead post per unit in a dict keyed on unit id -- so the second
    silently replaced the first and vanished from the page and from the
    gap count. A head nobody can see is worse than no head at all.
    """

    def test_both_sit_at_the_root(self, db, lead):
        adopt(db, lead, "soc_manager", "soc_lead", "l1_soc_analyst")
        wf.establish_from_catalogue(db, actor=lead)
        root = find_unit(wf.org_tree(db), "SOC")
        assert sorted(p["title"] for p in root["leads"]) == [
            "SOC Lead", "SOC Manager"]

    def test_neither_is_dropped_from_the_gap_count(self, db, lead):
        """The silent-overwrite bug showed up here as one gap, not two."""
        adopt(db, lead, "soc_manager", "soc_lead")
        wf.establish_from_catalogue(db, actor=lead)
        assert wf.org_tree(db)["leads_gapped"] == 2

    def test_the_functional_leads_are_below_them(self, db, lead):
        adopt(db, lead, "soc_lead", "lead_analyst", "l1_soc_analyst")
        wf.establish_from_catalogue(db, actor=lead)
        tree = wf.org_tree(db)
        assert [p["title"] for p in find_unit(tree, "SOC")["leads"]] == \
            ["SOC Lead"]
        assert [p["title"] for p in find_unit(tree, "Operations")["leads"]] == \
            ["Lead Analyst"]

    def test_the_soc_lead_is_not_inside_a_function(self, db, lead):
        """Under Operations they would be the analysis lead, which is the
        Lead Analyst's job."""
        adopt(db, lead, "soc_lead", "l1_soc_analyst")
        wf.establish_from_catalogue(db, actor=lead)
        unit = db.query(OrgUnit).filter_by(name="Operations").one()
        titles = {p.title for p in db.query(OrgPost).filter_by(unit_id=unit.id)}
        assert not any("SOC Lead" in t for t in titles)


class TestTheFunctionsWithoutLeads:
    """Incident response, threat intelligence and governance have no lead
    role in the catalogue, deliberately.

    They are small functions -- one or two people -- and inventing a lead
    post for each would put three permanent vacancies on the ORBAT that no
    SOC this size intends to fill. They answer to the SOC Lead directly.
    """

    @pytest.mark.parametrize("unit_name,role_id", [
        ("Incident Response", "incident_responder"),
        ("Threat Intelligence", "cti_analyst"),
        ("Governance", "grc_analyst"),
    ])
    def test_the_function_has_members_and_no_lead_post(self, db, lead,
                                                       unit_name, role_id):
        adopt(db, lead, role_id)
        wf.establish_from_catalogue(db, actor=lead)
        unit = find_unit(wf.org_tree(db), unit_name)
        assert unit is not None
        assert unit["posts"], unit_name
        assert unit["leads"] == [], unit_name

    def test_they_do_not_inflate_the_lead_gap_count(self, db, lead):
        adopt(db, lead, "incident_responder", "cti_analyst", "grc_analyst")
        wf.establish_from_catalogue(db, actor=lead)
        assert wf.org_tree(db)["leads_gapped"] == 0


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
