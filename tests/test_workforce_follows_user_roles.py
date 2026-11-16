"""The Users page can say which role an account is being onboarded into.

The defect: a person's Workforce page said no role had been assigned, and
nothing an administrator could click would assign one. The only thing that
opened a role journey was an API no page called.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ion.models.base import Base
from ion.models.user import Permission, Role, User
from ion.models.workforce import PHASE_GATE, UserJourney
from ion.services import workforce_service as wf
from ion.web import api

GATE = dict(name="Security induction", kind="course", phase=PHASE_GATE,
            validity_months=12)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _user(db, username, roles=()):
    u = User(username=username, email=f"{username}@x", password_hash="x",
             is_active=True)
    u.roles = list(roles)
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def admin(db):
    role = Role(name="admin")
    role.permissions = [
        Permission(name="workforce:manage", resource="workforce", action="manage"),
    ]
    return _user(db, "admin", [role])


@pytest.fixture
def analyst_role(db):
    r = Role(name="analyst")
    db.add(r)
    db.commit()
    return r


def _profile(db, admin, name, *, grants=None, publish=True):
    profile = wf.create_profile(db, name=name)
    if grants is not None:
        profile.grants_role_id = grants.id
    version = wf.draft_version(db, profile)
    wf.add_requirement(db, version, **GATE)
    db.commit()
    if publish:
        wf.publish_version(db, version, admin)
        db.commit()
    return profile


def _open_profiles(db, user):
    return sorted(
        j.version.profile.name
        for j in db.query(UserJourney).filter_by(user_id=user.id)
    )


def _save_roles(db, editor, target, roles, role_profile_id=None):
    from starlette.requests import Request

    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 1)})
    return api.update_user_roles(
        user_id=target.id,
        roles_update=api.UserRolesUpdate(roles=roles, role_profile_id=role_profile_id),
        request=request, current_user=editor, session=db)


def test_the_picked_profile_is_opened_beside_the_ticked_role(db, admin, analyst_role):
    picked = _profile(db, admin, "Detection Engineer")
    _profile(db, admin, "SOC Analyst L1", grants=analyst_role)
    joiner = _user(db, "joiner")

    _save_roles(db, admin, joiner, ["analyst"], role_profile_id=picked.id)

    assert _open_profiles(db, joiner) == ["Detection Engineer", "SOC Analyst L1"]
    held = {j.version.profile.name: j.role_already_held
            for j in db.query(UserJourney).filter_by(user_id=joiner.id)}
    assert held == {"Detection Engineer": False, "SOC Analyst L1": True}
    assert [r.name for r in joiner.roles] == ["analyst"]


def test_ticking_a_role_opens_its_profile_and_the_role_is_kept(db, admin, analyst_role):
    _profile(db, admin, "SOC Analyst L1", grants=analyst_role)
    joiner = _user(db, "joiner")

    _save_roles(db, admin, joiner, ["analyst"])

    assert _open_profiles(db, joiner) == ["SOC Analyst L1"]
    assert [r.name for r in joiner.roles] == ["analyst"]


def test_ticking_a_role_and_picking_its_profile_still_keeps_the_role(
        db, admin, analyst_role):
    l1 = _profile(db, admin, "SOC Analyst L1", grants=analyst_role)
    joiner = _user(db, "joiner")

    _save_roles(db, admin, joiner, ["analyst"], role_profile_id=l1.id)

    assert db.query(UserJourney).filter_by(user_id=joiner.id).count() == 1
    assert [r.name for r in joiner.roles] == ["analyst"]


def test_a_role_with_no_profile_opens_nothing(db, admin, analyst_role):
    joiner = _user(db, "joiner")

    _save_roles(db, admin, joiner, ["analyst"])

    assert _open_profiles(db, joiner) == []
    assert [r.name for r in joiner.roles] == ["analyst"]


def test_saving_the_same_profile_again_keeps_one_journey(db, admin):
    picked = _profile(db, admin, "Detection Engineer")
    joiner = _user(db, "joiner")

    _save_roles(db, admin, joiner, [], role_profile_id=picked.id)
    _save_roles(db, admin, joiner, [], role_profile_id=picked.id)

    assert db.query(UserJourney).filter_by(user_id=joiner.id).count() == 1


def test_the_role_change_stands_when_the_editor_cannot_manage_workforce(
        db, admin, analyst_role):
    _profile(db, admin, "SOC Analyst (L1)", grants=analyst_role)
    editor = _user(db, "editor", [Role(name="user_admin")])
    joiner = _user(db, "joiner")

    _save_roles(db, editor, joiner, ["analyst"])

    db.expire_all()
    assert [r.name for r in joiner.roles] == ["analyst"]
    assert _open_profiles(db, joiner) == []


def test_picking_a_profile_without_the_right_to_is_refused_before_anything_changes(
        db, admin, analyst_role):
    from fastapi import HTTPException

    picked = _profile(db, admin, "Detection Engineer")
    editor = _user(db, "editor", [Role(name="user_admin")])
    joiner = _user(db, "joiner")

    with pytest.raises(HTTPException) as refused:
        _save_roles(db, editor, joiner, ["analyst"], role_profile_id=picked.id)

    assert refused.value.status_code == 403
    db.expire_all()
    assert joiner.roles == []
    assert _open_profiles(db, joiner) == []


def test_offboarding_takes_back_a_role_that_was_already_held(db, admin, analyst_role):
    from datetime import date

    _profile(db, admin, "SOC Analyst (L1)", grants=analyst_role)
    leaver = _user(db, "leaver")
    _save_roles(db, admin, leaver, ["analyst"])
    assert [r.name for r in leaver.roles] == ["analyst"]

    record = wf.start_offboarding(db, user=leaver, raiser=admin,
                                  last_working_day=date.today())
    wf.revoke_now(db, record, actor=admin)

    db.refresh(leaver)
    assert leaver.roles == []


def test_a_lapsed_mandatory_item_suspends_a_role_that_was_already_held(
        db, admin, analyst_role):
    from datetime import datetime, timedelta

    from ion.models.workforce import STAGE_SUSPENDED

    _profile(db, admin, "SOC Analyst (L1)", grants=analyst_role)
    holder = _user(db, "holder")
    _save_roles(db, admin, holder, ["analyst"])
    journey = db.query(UserJourney).filter_by(user_id=holder.id).one()
    journey.stage = STAGE_SUSPENDED
    journey.grace_until = datetime.utcnow() - timedelta(days=1)
    db.commit()

    wf.sync_granted_roles(db, holder)

    assert holder.roles == []


def test_only_published_non_baseline_profiles_are_offered(db, admin, analyst_role):
    _profile(db, admin, "SOC Analyst L1", grants=analyst_role)
    _profile(db, admin, "Still A Draft", publish=False)
    baseline = _profile(db, admin, "Induction")
    baseline.is_baseline = True
    retired = _profile(db, admin, "Retired Role")
    retired.is_active = False
    db.commit()

    assert [p.name for p in wf.assignable_profiles(db)] == ["SOC Analyst L1"]


def test_the_general_role_is_chosen_when_two_profiles_grant_one_role(
        db, admin, analyst_role):
    specialism = _profile(db, admin, "Vulnerability Management Analyst",
                          grants=analyst_role)
    specialism.catalogue_id = "vuln_analyst"
    general = _profile(db, admin, "SOC Analyst (L1)", grants=analyst_role)
    general.catalogue_id = "l1_soc_analyst"
    db.commit()
    joiner = _user(db, "joiner")

    _save_roles(db, admin, joiner, ["analyst"])

    assert _open_profiles(db, joiner) == ["SOC Analyst (L1)"]


def test_an_account_created_with_a_role_starts_on_its_profile_holding_it(
        db, admin, analyst_role):
    from ion.auth.service import AuthService

    _profile(db, admin, "SOC Analyst (L1)", grants=analyst_role)

    created, error = AuthService(db).create_user(
        "newstarter", "newstarter@x", "Str0ng-Passw0rd-For-Tests-91",
        role_names=["analyst"], admin_user_id=admin.id)
    db.commit()

    assert error is None
    journey = db.query(UserJourney).filter_by(user_id=created.id).one()
    assert journey.role_already_held is True
    assert [r.name for r in created.roles] == ["analyst"]


def test_relinking_a_profile_does_not_strip_a_role_somebody_already_held(
        db, admin, analyst_role):
    from ion.web import workforce_api

    profile = _profile(db, admin, "SOC Analyst (L1)", grants=analyst_role)
    veteran = _user(db, "veteran")
    _save_roles(db, admin, veteran, ["analyst"])

    workforce_api.set_grants(
        profile_id=profile.id,
        payload=workforce_api.GrantsIn(role_id=analyst_role.id),
        session=db, _user=admin)

    assert [r.name for r in veteran.roles] == ["analyst"]


def test_an_existing_database_gains_the_already_held_column(tmp_path):
    from sqlalchemy import inspect, text

    from ion.storage.database import _run_migrations

    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE user_journeys DROP COLUMN role_already_held"))

    _run_migrations(engine)

    columns = {c["name"]: c for c in inspect(engine).get_columns("user_journeys")}
    assert "role_already_held" in columns
    assert columns["role_already_held"]["nullable"] is False


def _picker(db, viewer, group="edit"):
    from starlette.requests import Request

    from ion.web.ui import users as users_ui

    request = Request({
        "type": "http", "method": "GET", "path": "/ui/users/profile-options",
        "headers": [], "query_string": b"", "scheme": "http",
        "server": ("testserver", 80), "root_path": "",
    })
    return users_ui.users_profile_options_fragment(
        request=request, group=group, user=viewer, session=db).body.decode()


def test_the_picker_offers_the_assignable_profiles_to_a_workforce_manager(
        db, admin, analyst_role):
    picked = _profile(db, admin, "Detection Engineer")

    html = _picker(db, admin)

    assert 'id="edit-user-profile"' in html
    assert f'<option value="{picked.id}">Detection Engineer</option>' in html


def test_the_picker_gives_no_control_to_somebody_who_could_not_use_it(
        db, admin, analyst_role):
    _profile(db, admin, "Detection Engineer")
    editor = _user(db, "editor", [Role(name="user_admin")])

    html = _picker(db, editor)

    assert "<select" not in html
    assert "Detection Engineer" not in html
