"""The establishment: what the SOC says it needs, against what it has.

``org_tree`` already reports each post as filled, filling or gapped, but it
is organised by unit -- which is the right shape for an org chart and the
wrong one for the question a lead actually asks: "how many L2s should we
have, how many do we have, and how short are we".

Two pieces here.

``establish_from_catalogue`` turns the catalogue's suggested headcounts
into real posts, so the ORBAT is not empty on day one. The numbers are a
starting shape for a mid-sized 24/7 SOC, not a recommendation for anyone's
actual SOC, so this is something a lead asks for once and then edits.

``establishment_summary`` reports per role rather than per unit. The
distinction it keeps is between a post nobody holds and a post held by
somebody still in training: both are gaps in cover tonight, and conflating
them is how a rota looks staffed while nobody on it can take the queue.
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
from ion.models.workforce import (
    PHASE_GATE,
    PHASE_READINESS,
    STAGE_OPERATIONAL,
    OrgPost,
    OrgUnit,
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


@pytest.fixture
def adopted(db, lead):
    """Two adopted roles, published so they can be assigned."""
    analyst = Role(name="analyst")
    db.add(analyst)
    db.commit()
    out = {}
    for role_id in ("l1_soc_analyst", "l2_soc_analyst"):
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


# -- Building the establishment -------------------------------------------


class TestEstablishing:
    def test_it_creates_a_post_per_head(self, db, lead, adopted):
        wf.establish_from_catalogue(db, actor=lead)
        l1 = get_role("l1_soc_analyst")["typical_establishment"]
        posts = (db.query(OrgPost)
                 .filter(OrgPost.profile_id == adopted["l1_soc_analyst"].id)
                 .count())
        assert posts == l1

    def test_posts_are_grouped_into_units_by_category(self, db, lead, adopted):
        wf.establish_from_catalogue(db, actor=lead)
        names = {u.name for u in db.query(OrgUnit).all()}
        assert "Operations" in names

    def test_only_adopted_roles_are_established(self, db, lead, adopted):
        """The catalogue has nineteen roles. Creating posts for the ones
        this SOC has not adopted would invent an establishment nobody
        asked for."""
        wf.establish_from_catalogue(db, actor=lead)
        profile_ids = {p.profile_id for p in db.query(OrgPost).all()}
        assert profile_ids == {adopted["l1_soc_analyst"].id,
                               adopted["l2_soc_analyst"].id}

    def test_running_it_twice_does_not_double_the_establishment(
        self, db, lead, adopted
    ):
        wf.establish_from_catalogue(db, actor=lead)
        before = db.query(OrgPost).count()
        wf.establish_from_catalogue(db, actor=lead)
        assert db.query(OrgPost).count() == before

    def test_it_does_not_remove_posts_somebody_added(self, db, lead, adopted):
        """A lead who has already trimmed the establishment must not have
        it silently reset by running this again."""
        wf.establish_from_catalogue(db, actor=lead)
        unit = db.query(OrgUnit).first()
        db.add(OrgPost(unit_id=unit.id, title="Bespoke post",
                       profile_id=adopted["l1_soc_analyst"].id))
        db.commit()
        total = db.query(OrgPost).count()
        wf.establish_from_catalogue(db, actor=lead)
        assert db.query(OrgPost).count() == total

    def test_posts_are_numbered_so_they_can_be_told_apart(self, db, lead,
                                                          adopted):
        wf.establish_from_catalogue(db, actor=lead)
        titles = [p.title for p in db.query(OrgPost)
                  .filter(OrgPost.profile_id == adopted["l1_soc_analyst"].id)]
        assert len(set(titles)) == len(titles)

    def test_it_needs_permission(self, db, adopted):
        nobody = User(username="n", email="n@x", password_hash="x",
                      is_active=True)
        db.add(nobody)
        db.commit()
        with pytest.raises(wf.WorkforceError):
            wf.establish_from_catalogue(db, actor=nobody)

    def test_it_is_audited(self, db, lead, adopted):
        from ion.models.user import AuditLog

        wf.establish_from_catalogue(db, actor=lead)
        actions = [a.action for a in db.query(AuditLog).all()]
        assert "workforce_establishment_created" in actions


# -- Have against need ----------------------------------------------------


class TestTheSummary:
    def test_an_empty_establishment_reports_nothing_rather_than_zeroes(
        self, db, lead, adopted
    ):
        """No posts is "nobody has said what we need", which is not the
        same as "we need nothing". Reporting a gap of zero would read as
        fully staffed."""
        summary = wf.establishment_summary(db)
        assert summary["roles"] == []
        assert summary["established"] == 0

    def test_every_established_role_appears(self, db, lead, adopted):
        wf.establish_from_catalogue(db, actor=lead)
        summary = wf.establishment_summary(db)
        names = {r["role"] for r in summary["roles"]}
        assert names == {"SOC Analyst (L1)", "SOC Analyst (L2)"}

    def test_an_unfilled_establishment_is_all_gap(self, db, lead, adopted):
        wf.establish_from_catalogue(db, actor=lead)
        summary = wf.establishment_summary(db)
        row = next(r for r in summary["roles"] if r["role"] == "SOC Analyst (L1)")
        assert row["filled"] == 0
        assert row["gap"] == row["established"]

    def test_somebody_still_training_is_not_counted_as_filled(
        self, db, lead, adopted
    ):
        """Both are gaps in cover tonight. Conflating them is how a rota
        looks staffed while nobody on it can take the queue."""
        person = User(username="j", email="j@x", password_hash="x",
                      is_active=True)
        db.add(person)
        db.commit()
        version = wf.latest_published(db, adopted["l1_soc_analyst"].id)
        journey = wf.assign_profile(db, user=person, version=version,
                                    assigner=lead)
        wf.establish_from_catalogue(db, actor=lead)
        post = (db.query(OrgPost)
                .filter(OrgPost.profile_id == adopted["l1_soc_analyst"].id)
                .first())
        wf.fill_post(db, post=post, journey_id=journey.id, actor=lead)

        row = next(r for r in wf.establishment_summary(db)["roles"]
                   if r["role"] == "SOC Analyst (L1)")
        assert row["filling"] == 1
        assert row["filled"] == 0
        assert row["gap"] == row["established"] - 1

    def test_an_operational_occupant_counts_as_filled(self, db, lead, adopted):
        person = User(username="j", email="j@x", password_hash="x",
                      is_active=True)
        db.add(person)
        db.commit()
        version = wf.latest_published(db, adopted["l1_soc_analyst"].id)
        journey = wf.assign_profile(db, user=person, version=version,
                                    assigner=lead)
        for req in journey.requirements:
            wf.verify_requirement(db, requirement=req, verifier=lead)
        db.commit()
        assert journey.stage == STAGE_OPERATIONAL

        wf.establish_from_catalogue(db, actor=lead)
        post = (db.query(OrgPost)
                .filter(OrgPost.profile_id == adopted["l1_soc_analyst"].id)
                .first())
        wf.fill_post(db, post=post, journey_id=journey.id, actor=lead)

        row = next(r for r in wf.establishment_summary(db)["roles"]
                   if r["role"] == "SOC Analyst (L1)")
        assert row["filled"] == 1
        assert row["filling"] == 0

    def test_the_totals_add_up(self, db, lead, adopted):
        wf.establish_from_catalogue(db, actor=lead)
        summary = wf.establishment_summary(db)
        for row in summary["roles"]:
            assert row["filled"] + row["filling"] + row["gap"] == \
                row["established"]
        assert summary["established"] == sum(
            r["established"] for r in summary["roles"])

    def test_a_role_with_nobody_at_all_is_named(self, db, lead, adopted):
        """A role the SOC has established and never filled is the thing a
        lead most needs to see, and it is the one that disappears if the
        report only lists people."""
        wf.establish_from_catalogue(db, actor=lead)
        summary = wf.establishment_summary(db)
        unstaffed = [r["role"] for r in summary["roles"] if r["filled"] == 0]
        assert "SOC Analyst (L2)" in unstaffed
