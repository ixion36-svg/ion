"""The workforce fragments over HTTP: Me, the ORBAT detail, Team and Setup.

Each route is driven through a real FastAPI app so the permission gate, the
form parsing and the rendered markup are exercised together. The refusals
matter as much as the successes: every write here reports its failure inside
the fragment, and a refusal that escaped as a 422 or 500 would leave htmx
swapping nothing and the control looking dead.
"""
from __future__ import annotations

import sys
from datetime import timedelta
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
from ion.models.workforce import (  # noqa: E402
    PHASE_GATE,
    PHASE_READINESS,
    JourneyRequirement,
    LeaverRecord,
    ProfileRequirement,
    RoleProfile,
    UserJourney,
)
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
    resource, action = name.split(":")
    return found or Permission(name=name, resource=resource, action=action)


def _user(db, name, *perms, display_name=None):
    role = Role(name=f"{name}-role")
    role.permissions = [_permission(db, p) for p in perms]
    u = User(username=name, display_name=display_name, email=f"{name}@x",
             password_hash="x", is_active=True)
    u.roles = [role]
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def lead(db):
    return _user(db, "lead", "workforce:manage", "workforce:read",
                 "workforce:verify", "alert:read")


@pytest.fixture
def profile(db, lead):
    """L1 with one gate item and one readiness certificate."""
    p = wf.adopt_catalogue_role(db, "l1_soc_analyst", adopter=lead)
    version = wf.draft_version(db, p)
    for r in list(version.requirements):
        db.delete(r)
    db.commit()
    wf.add_requirement(db, version, name="Right to work", kind="vetting",
                       phase=PHASE_GATE, validity_months=12)
    wf.add_requirement(db, version, name="Security+", kind="cert",
                       phase=PHASE_READINESS, cost=300.0)
    db.commit()
    wf.publish_version(db, version, lead)
    db.commit()
    return p, version


@pytest.fixture
def joiner_user(db):
    return _user(db, "ada", display_name="Ada Joiner")


@pytest.fixture
def journey(db, lead, profile, joiner_user):
    _, version = profile
    j = wf.assign_profile(db, user=joiner_user, version=version, assigner=lead)
    db.commit()
    return j


def _gate(journey):
    return next(r for r in journey.requirements if r.phase == PHASE_GATE)


def _client(db, as_user):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session
    from ion.web.ui import (
        skills_certifications,
        workforce_journey,
        workforce_orbat,
        workforce_setup,
        workforce_team,
    )
    from ion.web.workforce_api import require_workforce_module

    app = FastAPI()
    for module in (workforce_journey, workforce_orbat, workforce_setup,
                   workforce_team, skills_certifications):
        app.include_router(module.router, prefix="/ui")
    app.dependency_overrides[get_current_user] = lambda: as_user
    app.dependency_overrides[get_db_session] = lambda: db
    app.dependency_overrides[require_workforce_module] = lambda: None
    return TestClient(app)


@pytest.fixture
def as_lead(db, lead):
    with _client(db, lead) as c:
        yield c


@pytest.fixture
def as_joiner(db, joiner_user):
    with _client(db, joiner_user) as c:
        yield c


def _boom(*_a, **_k):
    raise RuntimeError("database went away")


# --- Me: the joiner's own onboarding -----------------------------------------


class TestMe:
    def test_nobody_assigned_is_told_to_wait(self, as_joiner):
        html = as_joiner.get("/ui/workforce/me").text
        assert "No role assigned yet" in html

    def test_both_lists_render_with_their_forms(self, as_joiner, journey):
        html = as_joiner.get("/ui/workforce/me").text
        gate = _gate(journey)
        assert "Right to work" in html
        assert "Security+" in html
        assert f"/ui/workforce/requirements/{gate.id}/submit" in html

    def test_a_failed_read_is_not_an_empty_onboarding(
        self, as_joiner, journey, monkeypatch
    ):
        monkeypatch.setattr(wf, "live_journeys", _boom)
        r = as_joiner.get("/ui/workforce/me")
        assert r.status_code == 200
        assert "the query failed" in r.text
        assert "No role assigned yet" not in r.text

    def test_an_unknown_journey_falls_back_to_their_first(self, as_joiner, journey):
        html = as_joiner.get("/ui/workforce/me?journey=99999").text
        assert "Right to work" in html

    def test_past_the_target_says_so(self, db, as_joiner, journey):
        journey.started_at -= timedelta(days=journey.target_days + 5)
        db.commit()
        html = as_joiner.get(f"/ui/workforce/me?journey={journey.id}").text
        assert "past the target" in html

    def test_submit_then_withdraw(self, db, as_joiner, journey):
        gate = _gate(journey)
        r = as_joiner.post(
            f"/ui/workforce/requirements/{gate.id}/submit",
            data={"completed_on": "2026-11-01", "evidence_ref": "  HR-12  "},
        )
        assert r.status_code == 200
        db.expire_all()
        row = db.get(JourneyRequirement, gate.id)
        assert row.status == "submitted"
        assert row.evidence_ref == "HR-12"
        assert row.completed_on.isoformat() == "2026-11-01"
        assert "Awaiting your lead" in r.text

        r = as_joiner.post(f"/ui/workforce/requirements/{gate.id}/withdraw",
                           data={"journey": str(journey.id)})
        db.expire_all()
        assert db.get(JourneyRequirement, gate.id).status == "pending"

    def test_a_malformed_date_is_not_credited(self, db, as_joiner, journey):
        gate = _gate(journey)
        as_joiner.post(f"/ui/workforce/requirements/{gate.id}/submit",
                       data={"completed_on": "not-a-date"})
        db.expire_all()
        # The service's own default, not a parse of the junk.
        assert db.get(JourneyRequirement, gate.id).completed_on is not None
        assert db.get(JourneyRequirement, gate.id).status == "submitted"

    def test_a_missing_item_is_a_sentence(self, as_joiner, journey):
        r = as_joiner.post("/ui/workforce/requirements/99999/submit", data={})
        assert r.status_code == 200
        assert "That item no longer exists" in r.text

    def test_a_refusal_comes_back_in_the_fragment(self, as_joiner, journey):
        gate = _gate(journey)
        r = as_joiner.post(f"/ui/workforce/requirements/{gate.id}/withdraw", data={})
        assert r.status_code == 200
        assert "Only a submitted item can be withdrawn" in r.text

    def test_somebody_elses_item_is_refused(self, db, lead, profile, journey):
        other = _user(db, "mallory")
        wf.assign_profile(db, user=other, version=profile[1], assigner=lead)
        db.commit()
        gate = _gate(journey)
        with _client(db, other) as c:
            r = c.post(f"/ui/workforce/requirements/{gate.id}/submit", data={})
        assert "Permission denied" in r.text
        db.expire_all()
        assert db.get(JourneyRequirement, gate.id).status == "pending"


# --- the ORBAT person detail ---------------------------------------------------


class TestOrbatPerson:
    def test_it_lists_the_outstanding_training(self, as_lead, journey):
        html = as_lead.get(f"/ui/workforce/orbat/person/{journey.id}").text
        assert "Ada Joiner" in html
        assert "Current training objectives" in html
        assert "Security+" in html

    def test_a_missing_journey_is_not_found(self, as_lead):
        r = as_lead.get("/ui/workforce/orbat/person/99999")
        assert r.status_code == 200
        assert "Ada Joiner" not in r.text

    def test_a_deleted_user_is_named_by_id(self, db, as_lead, journey):
        uid = journey.user_id
        db.query(User).filter(User.id == uid).delete()
        db.commit()
        html = as_lead.get(f"/ui/workforce/orbat/person/{journey.id}").text
        assert f"user {uid}" in html

    def test_a_failed_read_says_so(self, as_lead, journey, monkeypatch):
        monkeypatch.setattr(wf, "journey_summary", _boom)
        html = as_lead.get(f"/ui/workforce/orbat/person/{journey.id}").text
        assert "could not be read" in html

    def test_it_needs_read(self, db, journey, joiner_user):
        with _client(db, joiner_user) as c:
            assert c.get(f"/ui/workforce/orbat/person/{journey.id}").status_code == 403


# --- suggested certificates ----------------------------------------------------


class TestSuggestedCertificates:
    def test_no_goal_asks_for_one(self, as_lead):
        html = as_lead.get("/ui/skills/suggested-certifications").text
        assert "Set the role you are in" in html

    def test_a_goal_lists_both_roles(self, db, as_lead, lead):
        from ion.models.skills import UserCareerGoal

        db.add(UserCareerGoal(user_id=lead.id, current_role="l1-analyst",
                              target_role="l2-analyst"))
        db.commit()
        html = as_lead.get("/ui/skills/suggested-certifications").text
        assert "Where you are now" in html
        assert "Where you are heading" in html
        assert "l2-analyst" in html

    def test_a_failure_is_not_an_empty_list(self, as_lead, monkeypatch):
        from ion.services import role_skills_service

        monkeypatch.setattr(role_skills_service, "suggested_certifications", _boom)
        html = as_lead.get("/ui/skills/suggested-certifications").text
        assert "could not be read" in html


# --- Team: queue, roster, verify and send back --------------------------------


class TestTeam:
    def test_an_unknown_view_falls_back_to_the_chart(self, as_lead, journey):
        assert as_lead.get("/ui/workforce/team?view=bogus").status_code == 200

    def test_search_narrows_the_roster(self, as_lead, journey):
        hit = as_lead.get("/ui/workforce/team?view=list&q=ada").text
        miss = as_lead.get("/ui/workforce/team?view=list&q=zzzz").text
        assert "Ada Joiner" in hit
        assert "Ada Joiner" not in miss

    def test_search_matches_the_role_they_are_onboarding_into(self, as_lead, journey):
        html = as_lead.get("/ui/workforce/team?view=list&q=l1").text
        assert "Ada Joiner" in html

    def test_a_failed_read_says_so(self, as_lead, monkeypatch):
        monkeypatch.setattr(wf, "org_tree", _boom)
        html = as_lead.get("/ui/workforce/team").text
        assert "could not be read" in html

    def test_a_submission_is_queued_and_verified(self, db, as_lead, journey, joiner_user):
        gate = _gate(journey)
        wf.submit_requirement(db, requirement=gate, submitter=joiner_user,
                              evidence_ref="HR-1")
        html = as_lead.get("/ui/workforce/team").text
        assert f"/ui/workforce/requirements/{gate.id}/verify" in html

        r = as_lead.post(f"/ui/workforce/requirements/{gate.id}/verify",
                         data={"tab": "list", "q": "ada"})
        assert r.status_code == 200
        db.expire_all()
        row = db.get(JourneyRequirement, gate.id)
        assert row.status == "verified"
        # No reference typed, so the submitter's own is kept.
        assert row.evidence_ref == "HR-1"

    def test_send_back(self, db, as_lead, journey, joiner_user):
        gate = _gate(journey)
        wf.submit_requirement(db, requirement=gate, submitter=joiner_user)
        as_lead.post(f"/ui/workforce/requirements/{gate.id}/send-back",
                     data={"tab": "chart"})
        db.expire_all()
        assert db.get(JourneyRequirement, gate.id).status == "pending"

    def test_a_missing_item_is_a_sentence(self, as_lead):
        r = as_lead.post("/ui/workforce/requirements/99999/verify", data={})
        assert r.status_code == 200
        assert "That item no longer exists" in r.text

    def test_a_refused_send_back_is_on_the_page(self, as_lead, journey):
        gate = _gate(journey)
        r = as_lead.post(f"/ui/workforce/requirements/{gate.id}/send-back", data={})
        assert "Only a submitted item can be withdrawn" in r.text

    def test_an_overdue_journey_is_counted(self, db, as_lead, journey):
        from ion.web.ui.workforce_team import _view

        journey.started_at -= timedelta(days=journey.target_days + 5)
        db.commit()
        lead = db.query(User).filter_by(username="lead").one()
        assert _view(db, lead)["overdue"] == 1


# --- Setup: the schema, the establishment, offboarding --------------------------


class TestSetupSchema:
    def test_a_failed_read_says_so(self, as_lead, monkeypatch):
        monkeypatch.setattr(wf, "establishment_summary", _boom)
        html = as_lead.get("/ui/workforce/setup").text
        assert "Setup could not be read" in html

    def test_selecting_a_profile_opens_its_draft(self, as_lead, profile):
        p, _ = profile
        r = as_lead.get(f"/ui/workforce/setup?profile={p.id}")
        assert r.status_code == 200
        assert "Right to work" in r.text

    def test_a_vanished_profile_puts_the_reader_back_on_the_list(self, as_lead):
        r = as_lead.get("/ui/workforce/setup?profile=99999")
        assert r.status_code == 200
        assert "Setup could not be read" not in r.text

    def test_create_profile_lands_in_its_editor(self, db, as_lead):
        r = as_lead.post("/ui/workforce/profiles", data={"name": " Hunter ",
                                                         "nice_work_role": ""})
        assert r.status_code == 200
        assert "Profile created." in r.text
        assert db.query(RoleProfile).filter_by(name="Hunter").count() == 1

    def test_closing_the_post_panel_swaps_in_nothing(self, as_lead):
        r = as_lead.get("/ui/workforce/orbat/closed")
        assert r.status_code == 200
        assert r.text == ""

    def test_an_empty_setup_offers_the_catalogue_and_the_induction(self, as_lead):
        r = as_lead.get("/ui/workforce/setup")
        assert 'hx-post="/ui/workforce/catalogue/adopt"' in r.text
        assert 'name="is_baseline"' in r.text

    def test_adopting_a_catalogue_role_creates_its_draft(self, db, as_lead):
        from ion.data.soc_role_catalogue import SOC_ROLE_CATALOGUE

        entry = SOC_ROLE_CATALOGUE[0]
        r = as_lead.post("/ui/workforce/catalogue/adopt",
                         data={"role_id": entry["id"]})
        assert "Adopted as a draft." in r.text
        assert db.query(RoleProfile).filter_by(name=entry["name"]).count() == 1
        assert f'<option value="{entry["id"]}">' not in r.text

    def test_adopting_nothing_is_refused(self, db, as_lead):
        r = as_lead.post("/ui/workforce/catalogue/adopt", data={"role_id": ""})
        assert "Choose a role to adopt." in r.text
        assert db.query(RoleProfile).count() == 0

    def test_a_profile_can_be_made_the_induction_once(self, db, as_lead):
        r = as_lead.post("/ui/workforce/profiles",
                         data={"name": "Induction", "is_baseline": "1"})
        assert db.query(RoleProfile).filter_by(name="Induction").one().is_baseline
        assert 'name="is_baseline"' not in r.text

    def test_a_profile_is_not_the_induction_unless_ticked(self, db, as_lead):
        as_lead.post("/ui/workforce/profiles", data={"name": "Hunter"})
        assert not db.query(RoleProfile).filter_by(name="Hunter").one().is_baseline

    def test_a_blank_profile_name_is_refused(self, db, as_lead):
        r = as_lead.post("/ui/workforce/profiles", data={"name": "  "})
        assert "Give the role a name." in r.text
        assert db.query(RoleProfile).count() == 0

    def test_grants_set_and_clear(self, db, as_lead, profile, lead):
        p, _ = profile
        role_id = lead.roles[0].id
        r = as_lead.post(f"/ui/workforce/profiles/{p.id}/grants",
                         data={"role_id": str(role_id)})
        assert "The gate now controls that role." in r.text
        db.expire_all()
        assert db.get(RoleProfile, p.id).grants_role_id == role_id

        as_lead.post(f"/ui/workforce/profiles/{p.id}/grants", data={"role_id": ""})
        db.expire_all()
        assert db.get(RoleProfile, p.id).grants_role_id is None

    def test_an_unknown_grant_is_the_apis_refusal(self, as_lead, profile):
        p, _ = profile
        r = as_lead.post(f"/ui/workforce/profiles/{p.id}/grants",
                         data={"role_id": "99999"})
        assert r.status_code == 200
        assert "No such ION role" in r.text

    def _draft_id(self, db, p):
        draft = wf.draft_version(db, p)
        db.commit()
        return draft.id

    def test_add_remove_and_publish_a_requirement(self, db, as_lead, profile):
        p, _ = profile
        vid = self._draft_id(db, p)
        r = as_lead.post(f"/ui/workforce/versions/{vid}/requirements",
                         data={"profile": p.id, "name": "Vetting", "kind": "vetting",
                               "phase": "gate", "validity_months": "6", "cost": ""})
        assert r.status_code == 200
        added = db.query(ProfileRequirement).filter_by(version_id=vid, name="Vetting").one()
        assert added.validity_months == 6

        as_lead.post(f"/ui/workforce/profile-requirements/{added.id}/remove",
                     data={"profile": p.id})
        db.expire_all()
        assert db.get(ProfileRequirement, added.id) is None

        r = as_lead.post(f"/ui/workforce/versions/{vid}/publish", data={"profile": p.id})
        assert "Published." in r.text

    def test_a_blank_requirement_name_is_refused(self, db, as_lead, profile):
        p, _ = profile
        vid = self._draft_id(db, p)
        r = as_lead.post(f"/ui/workforce/versions/{vid}/requirements",
                         data={"profile": p.id, "name": " "})
        assert "Give the requirement a name." in r.text

    def test_a_kind_the_model_rejects_is_on_the_page(self, db, as_lead, profile):
        p, _ = profile
        vid = self._draft_id(db, p)
        r = as_lead.post(f"/ui/workforce/versions/{vid}/requirements",
                         data={"profile": p.id, "name": "X", "kind": "bogus"})
        assert r.status_code == 200
        assert "should match pattern" in r.text

    def test_a_non_numeric_validity_is_on_the_page(self, db, as_lead, profile):
        p, _ = profile
        vid = self._draft_id(db, p)
        r = as_lead.post(f"/ui/workforce/versions/{vid}/requirements",
                         data={"profile": p.id, "name": "X", "validity_months": "abc"})
        assert r.status_code == 200
        assert "invalid literal" in r.text

    def test_a_missing_requirement_is_the_apis_404(self, as_lead, profile):
        p, _ = profile
        r = as_lead.post("/ui/workforce/profile-requirements/99999/remove",
                         data={"profile": p.id})
        assert "Requirement not found" in r.text


class TestSetupEstablishment:
    def test_a_typo_is_a_sentence(self, as_lead, profile):
        p, _ = profile
        r = as_lead.post(f"/ui/workforce/establishment/{p.id}", data={"count": "two"})
        assert r.status_code == 200
        assert "is not a number of posts." in r.text

    def test_a_vanished_profile_is_a_sentence(self, as_lead):
        r = as_lead.post("/ui/workforce/establishment/99999", data={"count": "2"})
        assert "That role profile no longer exists." in r.text

    def test_the_service_refusal_is_on_the_page(self, as_lead, profile):
        p, _ = profile
        r = as_lead.post(f"/ui/workforce/establishment/{p.id}", data={"count": "2"})
        assert r.status_code == 200
        assert "Structure" in r.text

    def test_an_unparseable_select_value_is_a_sentence(self, as_lead):
        r = as_lead.post("/ui/workforce/org/units", data={"name": "SOC", "parent_id": "x"})
        assert "That choice was not recognised." in r.text


class TestSetupOffboarding:
    def test_start_tick_and_revoke(self, db, as_lead, journey, joiner_user):
        r = as_lead.post("/ui/workforce/leavers",
                         data={"user_id": joiner_user.id,
                               "last_working_day": "2026-12-01", "reason": " moving "})
        assert r.status_code == 200
        record = db.query(LeaverRecord).filter_by(user_id=joiner_user.id).one()
        assert record.reason == "moving"

        as_lead.post(f"/ui/workforce/leavers/{record.id}/checklist",
                     data={"index": 0, "done": "on"})
        db.expire_all()
        assert '"done": true' in db.get(LeaverRecord, record.id).checklist

        # An unchecked box posts no `done`, which clears it.
        as_lead.post(f"/ui/workforce/leavers/{record.id}/checklist", data={"index": 0})
        db.expire_all()
        assert '"done": true' not in db.get(LeaverRecord, record.id).checklist

        as_lead.post(f"/ui/workforce/leavers/{record.id}/revoke")
        db.expire_all()
        assert db.get(LeaverRecord, record.id).revoked_at is not None
        assert db.get(UserJourney, journey.id).stage == "closed"

    @pytest.mark.parametrize("data, message", [
        ({"user_id": 99999, "last_working_day": "2026-12-01"},
         "That person no longer exists."),
        ({"last_working_day": ""}, "Give the last working day."),
        ({"last_working_day": "31/12/2026"}, "not a date the calendar accepts"),
    ])
    def test_offboarding_refusals(self, db, as_lead, joiner_user, data, message):
        payload = {"user_id": joiner_user.id, **data}
        r = as_lead.post("/ui/workforce/leavers", data=payload)
        assert r.status_code == 200
        assert message in r.text
        assert db.query(LeaverRecord).count() == 0

    @pytest.mark.parametrize("path, data", [
        ("/ui/workforce/leavers/99999/revoke", {}),
        ("/ui/workforce/leavers/99999/checklist", {"index": 0}),
    ])
    def test_a_vanished_record_is_a_sentence(self, as_lead, path, data):
        r = as_lead.post(path, data=data)
        assert r.status_code == 200
        assert "That leaver record no longer exists." in r.text
