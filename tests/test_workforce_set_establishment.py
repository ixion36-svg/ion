"""Setting how many posts a role has.

establish_from_catalogue seeds a starting shape and only ever adds, so
until now a lead could grow the establishment but never trim it: the
numbers came from the catalogue's idea of a mid-sized 24/7 SOC, and
correcting them downward meant deleting posts one at a time on the
ORBAT.

set_establishment is the editable version, and the interesting half is
what it refuses. A number going down must not remove somebody from
their post as a side effect, and it must not delete a vacant LEAD post
either -- that post is the ORBAT saying nobody answers for the unit,
and deleting it resolves the gap by hiding it.
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

from ion.models.base import Base  # noqa: E402
from ion.models.user import AuditLog, Permission, Role, User  # noqa: E402
from ion.models.workforce import (  # noqa: E402
    PHASE_GATE,
    OrgPost,
    OrgUnit,
)
from ion.services import workforce_service as wf  # noqa: E402


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
        Permission(name="workforce:manage", resource="workforce", action="manage"),
    ]
    u = User(username="lead", email="l@x", password_hash="x", is_active=True)
    u.roles = [role]
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def bystander(db):
    u = User(username="nobody", email="n@x", password_hash="x", is_active=True)
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def profile(db, lead):
    p = wf.adopt_catalogue_role(db, "l1_soc_analyst", adopter=lead)
    version = wf.draft_version(db, p)
    wf.add_requirement(db, version, name="Right to work", kind="vetting",
                       phase=PHASE_GATE)
    db.commit()
    wf.publish_version(db, version, lead)
    db.commit()
    return p


@pytest.fixture
def unit(db):
    u = OrgUnit(name="Operations", ordering=0)
    db.add(u)
    db.commit()
    return u


def _posts(db, profile):
    return (db.query(OrgPost)
            .filter(OrgPost.profile_id == profile.id)
            .order_by(OrgPost.ordering, OrgPost.id).all())


def _seed(db, profile, unit, n, lead_posts=0):
    for i in range(1, n + 1):
        db.add(OrgPost(unit_id=unit.id, title=f"{profile.name} #{i}",
                       profile_id=profile.id, ordering=i, is_lead=False))
    for i in range(lead_posts):
        db.add(OrgPost(unit_id=unit.id, title=f"{profile.name} Lead",
                       profile_id=profile.id, ordering=-1, is_lead=True))
    db.commit()


class TestGrowing:
    def test_it_creates_the_difference(self, db, lead, profile, unit):
        _seed(db, profile, unit, 2)
        out = wf.set_establishment(db, profile=profile, count=5, actor=lead)
        assert out["created"] == 3 and out["removed"] == 0
        assert len(_posts(db, profile)) == 5

    def test_new_posts_join_the_unit_the_role_already_occupies(
        self, db, lead, profile, unit
    ):
        """A role that scatters across the tree makes the chain of
        command unreadable, which is the thing the ORBAT is for."""
        elsewhere = OrgUnit(name="Engineering", ordering=1)
        db.add(elsewhere)
        db.commit()
        _seed(db, profile, unit, 3)
        db.add(OrgPost(unit_id=elsewhere.id, title="stray", profile_id=profile.id,
                       ordering=9, is_lead=False))
        db.commit()

        # Identified by what is new, not by ordering: the stray sits at
        # 9 and the created posts continue from the numbered titles, so
        # an ordering filter would quietly match nothing and pass.
        before = {post.id for post in _posts(db, profile)}
        wf.set_establishment(db, profile=profile, count=6, actor=lead)
        added = [post for post in _posts(db, profile) if post.id not in before]

        assert len(added) == 2
        assert all(post.unit_id == unit.id for post in added), (
            "new posts went somewhere other than the unit holding most of "
            "the role"
        )

    def test_numbering_continues_rather_than_restarting(
        self, db, lead, profile, unit
    ):
        """Two posts called '#2' cannot be told apart in the tree."""
        _seed(db, profile, unit, 3)
        wf.set_establishment(db, profile=profile, count=2, actor=lead)
        wf.set_establishment(db, profile=profile, count=4, actor=lead)
        titles = [p.title for p in _posts(db, profile)]
        assert len(titles) == len(set(titles)), titles

    def test_a_role_with_no_posts_is_refused_rather_than_guessed(
        self, db, lead, profile, unit
    ):
        """There is no unit to infer, and putting an analyst under the
        wrong function makes the chain of command wrong."""
        with pytest.raises(wf.WorkforceError) as exc:
            wf.set_establishment(db, profile=profile, count=3, actor=lead)
        assert "no unit" in str(exc.value).lower()


class TestShrinking:
    def test_it_removes_vacant_posts(self, db, lead, profile, unit):
        _seed(db, profile, unit, 5)
        out = wf.set_establishment(db, profile=profile, count=2, actor=lead)
        assert out["removed"] == 3
        assert len(_posts(db, profile)) == 2

    def test_it_removes_the_newest_first(self, db, lead, profile, unit):
        """A lead who overshoots gets back the posts they just added."""
        _seed(db, profile, unit, 4)
        wf.set_establishment(db, profile=profile, count=2, actor=lead)
        assert [p.ordering for p in _posts(db, profile)] == [1, 2]

    def test_an_occupied_post_is_never_removed(
        self, db, lead, profile, unit, bystander
    ):
        """The number going down must not take somebody out of their post
        as a side effect. Whoever wants that moves the person first."""
        _seed(db, profile, unit, 3)
        version = wf.latest_published(db, profile.id)
        journey = wf.assign_profile(db, user=bystander, version=version,
                                    assigner=lead)
        posts = _posts(db, profile)
        posts[0].filled_by_journey_id = journey.id
        db.commit()

        with pytest.raises(wf.WorkforceError) as exc:
            wf.set_establishment(db, profile=profile, count=0, actor=lead)
        assert "filled" in str(exc.value).lower()
        assert len(_posts(db, profile)) == 3, "posts were removed anyway"

    def test_it_says_how_far_down_the_role_can_go(
        self, db, lead, profile, unit, bystander
    ):
        """A refusal that does not say the limit makes the reader guess."""
        _seed(db, profile, unit, 3)
        version = wf.latest_published(db, profile.id)
        journey = wf.assign_profile(db, user=bystander, version=version,
                                    assigner=lead)
        _posts(db, profile)[0].filled_by_journey_id = journey.id
        db.commit()

        with pytest.raises(wf.WorkforceError) as exc:
            wf.set_establishment(db, profile=profile, count=0, actor=lead)
        assert "below 1" in str(exc.value)

    def test_a_lead_post_is_never_removed(self, db, lead, profile, unit):
        """A vacant lead post is the ORBAT saying nobody answers for the
        unit. Deleting it resolves that gap by hiding it."""
        _seed(db, profile, unit, 1, lead_posts=1)
        with pytest.raises(wf.WorkforceError):
            wf.set_establishment(db, profile=profile, count=0, actor=lead)
        assert any(p.is_lead for p in _posts(db, profile))

    def test_shrinking_to_the_lead_post_alone_is_allowed(
        self, db, lead, profile, unit
    ):
        _seed(db, profile, unit, 3, lead_posts=1)
        wf.set_establishment(db, profile=profile, count=1, actor=lead)
        remaining = _posts(db, profile)
        assert len(remaining) == 1 and remaining[0].is_lead


class TestRefusals:
    def test_a_negative_count(self, db, lead, profile, unit):
        _seed(db, profile, unit, 2)
        with pytest.raises(wf.WorkforceError):
            wf.set_establishment(db, profile=profile, count=-1, actor=lead)

    def test_an_absurd_count(self, db, lead, profile, unit):
        """Driven by a number typed into a form, so a fat finger must not
        create nine hundred posts to be deleted one at a time."""
        _seed(db, profile, unit, 2)
        with pytest.raises(wf.WorkforceError):
            wf.set_establishment(db, profile=profile,
                                 count=wf.MAX_ESTABLISHMENT + 1, actor=lead)

    def test_without_the_permission(self, db, bystander, profile, unit):
        _seed(db, profile, unit, 2)
        with pytest.raises(wf.WorkforceError) as exc:
            wf.set_establishment(db, profile=profile, count=5, actor=bystander)
        assert "permission" in str(exc.value).lower()
        assert len(_posts(db, profile)) == 2


class TestItLeavesARecord:
    def test_a_change_is_audited(self, db, lead, profile, unit):
        _seed(db, profile, unit, 2)
        wf.set_establishment(db, profile=profile, count=4, actor=lead)
        entries = (db.query(AuditLog)
                   .filter(AuditLog.action == "workforce_establishment_set")
                   .all())
        assert len(entries) == 1
        assert "4 post" in entries[0].details

    def test_setting_the_same_number_changes_and_records_nothing(
        self, db, lead, profile, unit
    ):
        _seed(db, profile, unit, 3)
        out = wf.set_establishment(db, profile=profile, count=3, actor=lead)
        assert out["created"] == 0 and out["removed"] == 0
        assert not (db.query(AuditLog)
                    .filter(AuditLog.action == "workforce_establishment_set")
                    .all())
