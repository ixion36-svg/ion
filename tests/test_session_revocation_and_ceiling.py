"""Session lifecycle: revocation on credential change, and a bound on renewal.

Three gaps that only make sense read together, on the estate ION is actually
deployed into. ION authenticates analysts through Keycloak: the only
local-password account is admin, and OIDC users are created with
``password_hash=""`` (``ion.auth.oidc``). So ``must_change_password`` -- the
flag the auth layer otherwise treats as the brake after a credential event --
is an admin-account control and nothing more. Deleting the session rows is the
only thing ION can do to an attacker who already holds a cookie.

* Revocation on both password paths, sparing the changer's own tab.
* An absolute ceiling, so the sliding window cannot renew a session for ever
  and revocation is not racing something unbounded.
* The admin reset refused outright for an account ION holds no password for,
  because setting one issues a credential Keycloak never sees AND strands the
  user behind a flag they cannot clear.
"""

import json
from datetime import datetime, timedelta

import pytest

from ion.auth.service import AuthService
from ion.core import config as cfg_mod
from ion.core.config import Config, set_config
from ion.models.user import AuditLog, User, UserSession

GOOD_PW = "Str0ng-Passw0rd-42!"
NEW_PW = "An0ther-Str0ng-Pw-77!"


@pytest.fixture
def svc(session):
    User.metadata.create_all(session.get_bind())
    service = AuthService(session)
    service.seed_permissions()
    service.seed_roles()
    session.commit()
    return service


@pytest.fixture
def cfg():
    """Install a default Config for the duration of a test, then restore."""
    saved = cfg_mod._config
    config = Config()
    set_config(config)
    try:
        yield config
    finally:
        set_config(saved)


def _human(svc, username="alice"):
    user, err = svc.create_user(
        username=username, email=f"{username}@corp.test", password=GOOD_PW
    )
    assert err is None, err
    svc.db_session.commit()
    return user


def _session_for(svc, user, expires_in=timedelta(hours=24)):
    token = svc._generate_session_token()
    svc.session_repo.create(
        user_id=user.id,
        session_token=token,
        expires_at=datetime.utcnow() + expires_in,
    )
    svc.db_session.commit()
    return token


def _audit(svc, action):
    return svc.db_session.query(AuditLog).filter_by(action=action).all()


# ---------------------------------------------------------------------------
# R1 -- a credential change kills the other sessions
# ---------------------------------------------------------------------------

def test_password_change_kills_the_other_session(svc, cfg):
    """The attacker's cookie stops working the moment the user remediates.

    This is the whole point: "I think I was compromised so I changed my
    password" used to leave the stolen session valid.
    """
    user = _human(svc)
    stolen = _session_for(svc, user)
    mine = _session_for(svc, user)

    ok, err = svc.change_password(user, GOOD_PW, NEW_PW, current_session_token=mine)
    svc.db_session.commit()

    assert (ok, err) == (True, None)
    assert svc.validate_session(stolen) is None


def test_password_change_keeps_the_changers_own_session(svc, cfg):
    """Remediating must not look like a failure. The tab you are in survives."""
    user = _human(svc)
    _session_for(svc, user)
    mine = _session_for(svc, user)

    svc.change_password(user, GOOD_PW, NEW_PW, current_session_token=mine)
    svc.db_session.commit()

    assert svc.validate_session(mine) is not None


def test_password_change_without_a_token_revokes_everything(svc, cfg):
    """No token to spare means nothing is spared -- fail closed, not open."""
    user = _human(svc)
    a, b = _session_for(svc, user), _session_for(svc, user)

    svc.change_password(user, GOOD_PW, NEW_PW)
    svc.db_session.commit()

    assert svc.validate_session(a) is None
    assert svc.validate_session(b) is None


def test_a_failed_password_change_revokes_nothing(svc, cfg):
    """Wrong current password: no credential event, so no session event."""
    user = _human(svc)
    other = _session_for(svc, user)

    ok, err = svc.change_password(user, "not-the-password", NEW_PW)
    svc.db_session.commit()

    assert ok is False and err
    assert svc.validate_session(other) is not None


def test_revocation_is_audited_with_a_count(svc, cfg):
    user = _human(svc)
    _session_for(svc, user)
    _session_for(svc, user)
    mine = _session_for(svc, user)

    svc.change_password(user, GOOD_PW, NEW_PW, current_session_token=mine)
    svc.db_session.commit()

    entries = _audit(svc, "sessions_revoked")
    assert len(entries) == 1
    details = json.loads(entries[0].details)
    assert details["reason"] == "password_changed"
    assert details["sessions_revoked"] == 2
    assert details["kept_current_session"] is True


def test_revocation_does_not_touch_another_users_sessions(svc, cfg):
    alice, bob = _human(svc, "alice"), _human(svc, "bob")
    bobs = _session_for(svc, bob)

    svc.change_password(alice, GOOD_PW, NEW_PW)
    svc.db_session.commit()

    assert svc.validate_session(bobs) is not None


def test_admin_reset_revokes_every_session(svc, cfg):
    """An admin reset reacts to compromise or departure. A surviving cookie
    makes it cosmetic -- its holder never needs the password again."""
    admin = _human(svc, "admin_user")
    target = _human(svc, "target")
    a, b = _session_for(svc, target), _session_for(svc, target)

    svc.reset_password(target, NEW_PW, must_change=True, admin_user_id=admin.id)
    svc.db_session.commit()

    assert svc.validate_session(a) is None
    assert svc.validate_session(b) is None
    details = json.loads(_audit(svc, "sessions_revoked")[0].details)
    assert details["reason"] == "password_reset"
    assert details["kept_current_session"] is False


# ---------------------------------------------------------------------------
# R2 -- the sliding window gets a fixed point
# ---------------------------------------------------------------------------

def test_renewal_cannot_push_expiry_past_the_ceiling(svc, cfg):
    """A session renewed continuously still dies at created_at + ceiling."""
    cfg.session_absolute_lifetime_hours = 168
    user = _human(svc)
    token = _session_for(svc, user, expires_in=timedelta(hours=1))

    # Backdate creation to just inside the ceiling. The renewal branch wants
    # to grant a fresh 24h; only 2h of ceiling are left.
    row = svc.session_repo.get_by_token(token)
    created = datetime.utcnow() - timedelta(hours=166)
    row.created_at = created
    svc.db_session.commit()

    assert svc.validate_session(token) is not None
    renewed = svc.session_repo.get_by_token(token).expires_at
    assert renewed == created + timedelta(hours=168)
    assert renewed < datetime.utcnow() + timedelta(hours=3)


def test_a_session_past_its_ceiling_stops_validating(svc, cfg):
    """Not merely 'stops renewing' -- the clamp pulls expiry back to the
    ceiling, so the next request is refused rather than riding out another
    half-window."""
    cfg.session_absolute_lifetime_hours = 168
    user = _human(svc)
    token = _session_for(svc, user, expires_in=timedelta(hours=1))

    row = svc.session_repo.get_by_token(token)
    row.created_at = datetime.utcnow() - timedelta(hours=200)
    svc.db_session.commit()

    svc.validate_session(token)          # the request that trips the clamp
    svc.db_session.expire_all()
    assert svc.validate_session(token) is None


def test_an_ordinary_session_still_slides(svc, cfg):
    """The ceiling must not break the sliding window it bounds."""
    cfg.session_absolute_lifetime_hours = 168
    user = _human(svc)
    token = _session_for(svc, user, expires_in=timedelta(hours=1))
    before = svc.session_repo.get_by_token(token).expires_at

    assert svc.validate_session(token) is not None
    after = svc.session_repo.get_by_token(token).expires_at
    assert after - before > timedelta(hours=20)


def test_ceiling_of_zero_disables_the_bound(svc, cfg):
    """The escape hatch, for an estate that wants the old behaviour."""
    cfg.session_absolute_lifetime_hours = 0
    user = _human(svc)
    token = _session_for(svc, user, expires_in=timedelta(hours=1))

    row = svc.session_repo.get_by_token(token)
    row.created_at = datetime.utcnow() - timedelta(days=400)
    svc.db_session.commit()

    assert svc.validate_session(token) is not None
    extended = svc.session_repo.get_by_token(token).expires_at
    assert extended > datetime.utcnow() + timedelta(hours=20)


def test_service_account_token_still_expires_exactly_at_its_ttl(svc, cfg):
    """Regression guard on the exclusion that already existed. Service
    accounts are outside the renewal branch entirely, so the ceiling must not
    become a new way to move their minted --ttl-days bound in either
    direction."""
    cfg.session_absolute_lifetime_hours = 168
    svc.seed_metis_user()
    svc.db_session.commit()
    metis = svc.user_repo.get_by_username("metis")

    token = svc.mint_service_account_token(metis.id, ttl_days=365)
    svc.db_session.commit()
    minted = svc.session_repo.get_by_token(token).expires_at
    assert minted > datetime.utcnow() + timedelta(days=360)

    # Drag it inside the renewal threshold and well past the human ceiling.
    row = svc.session_repo.get_by_token(token)
    row.expires_at = datetime.utcnow() + timedelta(hours=1)
    row.created_at = datetime.utcnow() - timedelta(days=300)
    svc.db_session.commit()
    pinned = svc.session_repo.get_by_token(token).expires_at

    assert svc.validate_session(token) is not None
    assert svc.session_repo.get_by_token(token).expires_at == pinned


# ---------------------------------------------------------------------------
# R8 -- an account ION holds no password for is not given one
# ---------------------------------------------------------------------------

def _oidc_user(svc, username="keycloak_user"):
    """How ion.auth.oidc creates a user: no local hash, flag off."""
    user = svc.user_repo.create(
        username=username,
        email=f"{username}@corp.test",
        password_hash="",
        display_name="Keycloak User",
        is_active=True,
        must_change_password=False,
    )
    svc.db_session.commit()
    return user


def test_admin_reset_is_refused_for_an_oidc_account(svc, cfg):
    admin = _human(svc, "admin_user")
    user = _oidc_user(svc)

    with pytest.raises(ValueError) as exc:
        svc.reset_password(user, NEW_PW, must_change=True, admin_user_id=admin.id)

    assert "identity provider" in str(exc.value)


def test_a_refused_reset_leaves_no_lockout_and_no_local_credential(svc, cfg):
    """The harm was never the refusal, it was the flag: checked on every
    request regardless of how the user authenticated, so the next Keycloak
    login lands in password_change_blocks with no ION-local password to
    change."""
    admin = _human(svc, "admin_user")
    _oidc_user(svc)

    with pytest.raises(ValueError):
        svc.reset_password(
            svc.user_repo.get_by_username("keycloak_user"),
            NEW_PW,
            must_change=True,
            admin_user_id=admin.id,
        )
    svc.db_session.rollback()

    user = svc.user_repo.get_by_username("keycloak_user")
    assert user.must_change_password is False
    assert user.password_hash == ""


def test_admin_reset_is_refused_for_a_service_account(svc, cfg):
    """Same rule, other kind of account with no login path. A reset would
    overwrite the no-login sentinel with a real bcrypt hash."""
    admin = _human(svc, "admin_user")
    svc.seed_metis_user()
    svc.db_session.commit()
    metis = svc.user_repo.get_by_username("metis")

    with pytest.raises(ValueError):
        svc.reset_password(metis, NEW_PW, must_change=True, admin_user_id=admin.id)

    assert metis.password_hash == AuthService._SERVICE_ACCOUNT_HASH_SENTINEL


def test_reset_still_works_for_a_local_password_account(svc, cfg):
    """admin is the one account that genuinely has an ION-local password."""
    admin = _human(svc, "admin_user")
    target = _human(svc, "target")

    svc.reset_password(target, NEW_PW, must_change=True, admin_user_id=admin.id)
    svc.db_session.commit()

    assert target.must_change_password is True
    _user, token, err = svc.login("target", NEW_PW)
    assert err is None and token


def test_deactivation_revokes_sessions_for_an_oidc_account(svc, cfg):
    """With the reset refused, deactivation is the admin's lever on an OIDC
    account -- and it must delete the rows, not just fail the is_active check,
    or reactivating hands a stolen cookie its access back."""
    admin = _human(svc, "admin_user")
    user = _oidc_user(svc)
    stolen = _session_for(svc, user)

    user.is_active = False
    svc.revoke_sessions(user, reason="account_deactivated", actor_user_id=admin.id)
    user.is_active = True
    svc.db_session.commit()

    assert svc.db_session.query(UserSession).filter_by(user_id=user.id).count() == 0
    assert svc.validate_session(stolen) is None


# ---------------------------------------------------------------------------
# The routes, not just the service. Three of these fixes live in the wiring.
# ---------------------------------------------------------------------------

@pytest.fixture
def admin_client(session, svc, cfg):
    """TestClient authenticated as a real admin row in the test database."""
    from fastapi.testclient import TestClient

    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session
    from ion.web.server import app

    admin = _human(svc, "route_admin")
    admin.roles = [svc.role_repo.get_by_name("admin")]
    session.commit()

    app.dependency_overrides[get_current_user] = lambda: admin
    app.dependency_overrides[get_db_session] = lambda: session
    try:
        yield TestClient(app), admin
    finally:
        app.dependency_overrides.clear()


def test_route_refuses_to_reset_an_oidc_account(admin_client, svc):
    client, _admin = admin_client
    user = _oidc_user(svc)

    resp = client.post(
        f"/api/users/{user.id}/reset-password",
        json={"new_password": NEW_PW, "must_change": True},
    )

    assert resp.status_code == 400
    assert "identity provider" in resp.json()["detail"]
    assert svc.user_repo.get_by_id(user.id).must_change_password is False


def test_route_deactivation_revokes_the_accounts_sessions(admin_client, svc):
    """The lever that has to work on an OIDC estate, exercised through the
    route rather than the service, because the wiring is where it was
    missing."""
    client, _admin = admin_client
    user = _oidc_user(svc)
    stolen = _session_for(svc, user)

    resp = client.put(f"/api/users/{user.id}", json={"is_active": False})

    assert resp.status_code == 200
    svc.db_session.expire_all()
    assert svc.db_session.query(UserSession).filter_by(user_id=user.id).count() == 0
    assert svc.validate_session(stolen) is None


def test_an_update_that_does_not_deactivate_leaves_sessions_alone(admin_client, svc):
    client, _admin = admin_client
    user = _oidc_user(svc)
    live = _session_for(svc, user)

    resp = client.put(f"/api/users/{user.id}", json={"display_name": "Renamed"})

    assert resp.status_code == 200
    assert svc.validate_session(live) is not None


def test_the_admin_revoke_endpoint_actually_deletes_sessions(svc, cfg, monkeypatch):
    """It used to write a log line saying a session had been "marked for
    revocation" and delete nothing, while telling the admin the user would
    have to authenticate again."""
    import asyncio

    from ion.models.integration import IntegrationLog  # noqa: F401  (table)
    from ion.storage import database as db_mod
    from ion.web import admin_api

    User.metadata.create_all(svc.db_session.get_bind())

    admin = _human(svc, "revoking_admin")
    victim = _human(svc, "victim")
    stolen = _session_for(svc, victim)
    another = _session_for(svc, victim)

    monkeypatch.setattr(db_mod, "get_engine", lambda *a, **k: svc.db_session.get_bind())
    monkeypatch.setattr(db_mod, "get_session", lambda engine: iter([svc.db_session]))

    result = asyncio.run(
        admin_api.revoke_user_session(user_id=victim.id, current_user=admin)
    )

    assert result["sessions_revoked"] == 2
    assert svc.validate_session(stolen) is None
    assert svc.validate_session(another) is None
