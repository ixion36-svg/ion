"""The ORBAT page's controls, restored after it was folded into Team.

Commit 785fefd3 deleted /workforce/orbat and moved its chart to the Team
tab. The chart came across; nothing else did. The page had also been the
only place to add and remove units and posts, to seat somebody in a post
or take them out of it, and to read three panels a lead plans from: cover
by role, day-to-day pillar coverage, and what is about to lapse. After the
fold a lead could look at a structure but not build one, and
set_establishment's own refusal sent them to a page that no longer
existed.

These tests drive the restored routes over HTTP, so the gate, the form
parsing and the rendered markup are all exercised together. A test that
called the handler would miss the 422 an empty select used to produce,
which is the failure that makes a control look dead rather than broken.
"""
from __future__ import annotations

import sys
from datetime import date, timedelta
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: E402,F401  -- every table, for create_all
from ion.models.base import Base  # noqa: E402
from ion.models.user import Permission, Role, User  # noqa: E402
from ion.models.workforce import PHASE_GATE, OrgPost, OrgUnit  # noqa: E402
from ion.services import workforce_service as wf  # noqa: E402


@pytest.fixture
def db():
    # StaticPool and no thread check: TestClient runs the app on another
    # thread, and an in-memory database is per connection.
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _permission(db, name):
    found = db.query(Permission).filter_by(name=name).one_or_none()
    return found or Permission(name=name, resource="workforce",
                               action=name.split(":")[1])


def _user(db, name, *perms):
    role = Role(name=f"{name}-role")
    role.permissions = [_permission(db, p) for p in perms]
    u = User(username=name, email=f"{name}@x", password_hash="x", is_active=True)
    u.roles = [role]
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def lead(db):
    return _user(db, "lead", "workforce:manage", "workforce:read")


@pytest.fixture
def reader(db):
    return _user(db, "reader", "workforce:read")


def _profile(db, lead, catalogue_id):
    p = wf.adopt_catalogue_role(db, catalogue_id, adopter=lead)
    version = wf.draft_version(db, p)
    wf.add_requirement(db, version, name="Right to work", kind="vetting",
                       phase=PHASE_GATE, validity_months=12)
    db.commit()
    wf.publish_version(db, version, lead)
    db.commit()
    return p, version


@pytest.fixture
def l1(db, lead):
    return _profile(db, lead, "l1_soc_analyst")


@pytest.fixture
def joiner(db, lead, l1):
    """Somebody on the L1 role, not yet seated anywhere."""
    _, version = l1
    person = User(username="ada", display_name="Ada Joiner", email="a@x",
                  password_hash="x", is_active=True)
    db.add(person)
    db.commit()
    journey = wf.assign_profile(db, user=person, version=version, assigner=lead)
    db.commit()
    return journey


def _client(db, as_user):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session
    from ion.web.ui import workforce_setup, workforce_team
    from ion.web.workforce_api import require_workforce_module

    app = FastAPI()
    app.include_router(workforce_setup.router, prefix="/ui")
    app.include_router(workforce_team.router, prefix="/ui")
    app.dependency_overrides[get_current_user] = lambda: as_user
    app.dependency_overrides[get_db_session] = lambda: db
    app.dependency_overrides[require_workforce_module] = lambda: None
    return TestClient(app)


@pytest.fixture
def as_lead(db, lead):
    with _client(db, lead) as c:
        yield c


class TestUnits:
    def test_an_empty_structure_says_how_to_start(self, as_lead):
        html = as_lead.get("/ui/workforce/setup").text
        assert "No structure yet" in html
        assert 'hx-post="/ui/workforce/org/units"' in html

    def test_a_unit_can_be_added_at_the_top_and_under_another(self, db, as_lead):
        r = as_lead.post("/ui/workforce/org/units", data={"name": "SOC", "parent_id": ""})
        assert r.status_code == 200
        soc = db.query(OrgUnit).filter_by(name="SOC").one()
        assert soc.parent_id is None

        r = as_lead.post("/ui/workforce/org/units",
                         data={"name": "Detection", "parent_id": str(soc.id)})
        child = db.query(OrgUnit).filter_by(name="Detection").one()
        assert child.parent_id == soc.id
        # The parent picker names a unit by its path, so two teams with
        # one name under different parents can be told apart.
        assert "SOC / Detection" in r.text

    def test_a_blank_name_is_a_sentence_not_a_422(self, db, as_lead):
        r = as_lead.post("/ui/workforce/org/units", data={"name": "  ", "parent_id": ""})
        assert r.status_code == 200
        assert "Give the unit a name." in r.text
        assert db.query(OrgUnit).count() == 0

    def test_a_missing_parent_is_refused_on_the_page(self, db, as_lead):
        r = as_lead.post("/ui/workforce/org/units", data={"name": "X", "parent_id": "999"})
        assert r.status_code == 200
        assert "No such parent unit" in r.text
        assert db.query(OrgUnit).count() == 0

    def test_removing_a_unit_takes_everything_under_it(self, db, as_lead):
        soc = OrgUnit(name="SOC")
        db.add(soc)
        db.commit()
        team = OrgUnit(name="Tier 2", parent_id=soc.id)
        db.add(team)
        db.commit()
        db.add(OrgPost(unit_id=team.id, title="Analyst"))
        db.commit()

        html = as_lead.get("/ui/workforce/setup").text
        assert "Remove SOC and everything under it?" in html

        as_lead.post(f"/ui/workforce/org/units/{soc.id}/delete")
        db.expire_all()
        assert db.query(OrgUnit).count() == 0
        assert db.query(OrgPost).count() == 0


class TestPosts:
    @pytest.fixture
    def soc(self, db):
        u = OrgUnit(name="SOC")
        db.add(u)
        db.commit()
        return u

    def test_a_post_can_be_added_for_a_role_or_for_any(self, db, as_lead, soc, l1):
        profile, _ = l1
        as_lead.post("/ui/workforce/org/posts",
                     data={"unit_id": soc.id, "title": "L1 #1",
                           "profile_id": str(profile.id)})
        as_lead.post("/ui/workforce/org/posts",
                     data={"unit_id": soc.id, "title": "Floater", "profile_id": ""})
        posts = {p.title: p for p in db.query(OrgPost).all()}
        assert posts["L1 #1"].profile_id == profile.id
        assert posts["Floater"].profile_id is None

    def test_a_blank_title_is_refused_on_the_page(self, db, as_lead, soc):
        r = as_lead.post("/ui/workforce/org/posts",
                         data={"unit_id": soc.id, "title": "", "profile_id": ""})
        assert "Give the post a title." in r.text
        assert db.query(OrgPost).count() == 0

    def test_a_post_can_be_removed(self, db, as_lead, soc):
        post = OrgPost(unit_id=soc.id, title="Spare")
        db.add(post)
        db.commit()
        as_lead.post(f"/ui/workforce/org/posts/{post.id}/delete")
        db.expire_all()
        assert db.query(OrgPost).count() == 0


class TestSeating:
    @pytest.fixture
    def post(self, db, l1):
        profile, _ = l1
        unit = OrgUnit(name="SOC")
        db.add(unit)
        db.commit()
        p = OrgPost(unit_id=unit.id, title="L1 #1", profile_id=profile.id)
        db.add(p)
        db.commit()
        return p

    def test_a_gapped_post_offers_the_free_journeys_of_its_role(
        self, as_lead, post, joiner
    ):
        html = as_lead.get("/ui/workforce/setup").text
        assert f'hx-post="/ui/workforce/org/posts/{post.id}/fill"' in html
        assert f'<option value="{joiner.id}">Ada Joiner · ' in html

    def test_seating_and_unseating(self, db, as_lead, post, joiner):
        as_lead.post(f"/ui/workforce/org/posts/{post.id}/fill",
                     data={"journey_id": str(joiner.id)})
        db.expire_all()
        assert db.get(OrgPost, post.id).filled_by_journey_id == joiner.id

        # Seated now, so the seat list no longer offers them anywhere,
        # and the post offers Unseat instead.
        html = as_lead.get("/ui/workforce/setup").text
        assert "Ada Joiner · " not in html
        assert "Unseat" in html

        as_lead.post(f"/ui/workforce/org/posts/{post.id}/fill", data={"journey_id": ""})
        db.expire_all()
        assert db.get(OrgPost, post.id).filled_by_journey_id is None

    def test_a_post_for_another_role_does_not_list_them(
        self, db, as_lead, lead, post, joiner
    ):
        other, _ = _profile(db, lead, "l2_soc_analyst")
        wrong = OrgPost(unit_id=post.unit_id, title="L2 #1", profile_id=other.id)
        db.add(wrong)
        db.commit()
        html = as_lead.get("/ui/workforce/setup").text
        # The L2 post's own row, from its title to the end of its <li>.
        row = html.split('>L2 #1</span>')[1].split("</li>")[0]
        assert "Ada Joiner" not in row
        assert "nobody free for this role" in row

    def test_a_mismatched_seat_is_refused_on_the_page(
        self, db, as_lead, lead, post, joiner
    ):
        other, _ = _profile(db, lead, "l2_soc_analyst")
        wrong = OrgPost(unit_id=post.unit_id, title="L2 #1", profile_id=other.id)
        db.add(wrong)
        db.commit()
        r = as_lead.post(f"/ui/workforce/org/posts/{wrong.id}/fill",
                         data={"journey_id": str(joiner.id)})
        assert r.status_code == 200
        assert "different role profile" in r.text
        db.expire_all()
        assert db.get(OrgPost, wrong.id).filled_by_journey_id is None


class TestTheWritesNeedManage:
    @pytest.mark.parametrize("path", [
        "/ui/workforce/org/units",
        "/ui/workforce/org/units/1/delete",
        "/ui/workforce/org/posts",
        "/ui/workforce/org/posts/1/delete",
        "/ui/workforce/org/posts/1/fill",
    ])
    def test_a_reader_cannot_change_the_structure(self, db, reader, path):
        with _client(db, reader) as c:
            r = c.post(path, data={"name": "X", "unit_id": "1", "title": "X"})
        assert r.status_code == 403


class TestCoverageOnTeam:
    def test_the_three_panels_render(self, as_lead, joiner):
        html = as_lead.get("/ui/workforce/team").text
        assert "Cover by role" in html
        assert "Day-to-day coverage" in html
        assert "Expiring soon" in html
        # The joiner is in training, not cover: counted apart, never added.
        assert "0p + 0c = 0" in html
        assert "1 in training" in html

    def test_expiring_names_the_person(self, db, as_lead, joiner):
        item = next(r for r in joiner.requirements if r.phase == PHASE_GATE)
        item.expires_on = date.today() + timedelta(days=10)
        db.commit()
        html = as_lead.get("/ui/workforce/team").text
        block = html.split("Expiring soon")[1]
        assert item.name in block
        assert "Ada Joiner" in block
        assert "10d" in block
        assert "GATE" in block

    def test_nothing_due_says_so(self, as_lead):
        html = as_lead.get("/ui/workforce/team").text
        assert "Nothing due in the next 90 days." in html

    def test_a_coverage_failure_leaves_the_team_readable(
        self, as_lead, joiner, monkeypatch
    ):
        from ion.services import coverage_service

        def boom(_session):
            raise RuntimeError("matrix unavailable")

        monkeypatch.setattr(coverage_service, "pillar_coverage", boom)
        r = as_lead.get("/ui/workforce/team?view=list")
        assert r.status_code == 200
        assert "Coverage could not be read" in r.text
        assert "Ada Joiner" in r.text
        assert "The team could not be read" not in r.text

    def test_unmeasured_is_not_drawn_as_a_gap(self):
        from ion.web.ui.workforce_team import PILLAR_STATE

        assert PILLAR_STATE["unmeasured"][1] == "badge-ghost"
        assert PILLAR_STATE["uncovered"][1] == "badge-error"

    def test_a_manager_is_pointed_at_the_editor(self, db, as_lead, reader):
        assert "/workforce?tab=setup#structure" in as_lead.get("/ui/workforce/team").text
        with _client(db, reader) as c:
            assert "/workforce?tab=setup#structure" not in c.get("/ui/workforce/team").text


def test_set_establishment_points_at_the_editor_that_exists(db, lead, l1):
    """It used to send the reader to the order of battle, a deleted page."""
    profile, _ = l1
    with pytest.raises(wf.WorkforceError) as exc:
        wf.set_establishment(db, profile=profile, count=2, actor=lead)
    assert "Structure" in str(exc.value)
    assert "order of battle" not in str(exc.value)
