"""v0.78.0 — AEGIS service account: scoped role + bearer-token minting.

AEGIS is a companion threat-modelling app that calls ION's API. It
authenticates over the *existing* session mechanism — `mint_service_account_token`
mints a UserSession exactly like the OIDC callback does, just without a
browser round-trip. No new auth primitive, no new token model.

Role is deliberately least-privilege (SECURE_BY_DESIGN P6): alert:read,
de:read, de:propose, case:read. NOT de:verify (system-quirk revert) or
de:approve (Bob-tuning apply) — those stay reserved for human reviewers.
"""

import hashlib

import pytest

from ion.auth.service import AuthService
from ion.models.user import Role, User, UserSession

AEGIS_PERMS = {"alert:read", "de:read", "de:propose", "case:read"}


def _seeded(session) -> AuthService:
    User.metadata.create_all(session.get_bind())
    svc = AuthService(session)
    svc.seed_permissions()
    svc.seed_roles()
    svc.seed_aegis_user()
    session.commit()
    return svc


def test_seeding_is_idempotent(session):
    svc = _seeded(session)

    # Re-run the full seed sequence — must not error or duplicate rows.
    svc.seed_permissions()
    svc.seed_roles()
    user = svc.seed_aegis_user()
    session.commit()

    assert user.username == "aegis"
    assert session.query(User).filter_by(username="aegis").count() == 1
    assert session.query(Role).filter_by(name="aegis").count() == 1


def test_aegis_user_is_flagged_service_account(session):
    svc = _seeded(session)
    user = svc.user_repo.get_by_username("aegis")

    assert user is not None
    assert user.is_service_account is True
    assert user.is_active is True
    assert user.has_role("aegis")


def test_aegis_role_has_exactly_four_permissions(session):
    svc = _seeded(session)
    role = svc.role_repo.get_by_name("aegis")

    assert role is not None
    perm_names = {p.name for p in role.permissions}
    assert perm_names == AEGIS_PERMS


def test_aegis_role_excludes_verify_and_approve(session):
    """Least privilege (P6): AEGIS proposes but never verifies or approves."""
    svc = _seeded(session)
    role = svc.role_repo.get_by_name("aegis")
    perm_names = {p.name for p in role.permissions}

    assert "de:verify" not in perm_names
    assert "de:approve" not in perm_names


def test_aegis_interactive_login_is_refused(session):
    svc = _seeded(session)
    user, token, err = svc.login("aegis", "whatever-password")

    assert user is None
    assert token is None
    assert err == "This account cannot be used for interactive login"


def test_mint_token_is_accepted_by_validate_session_and_maps_to_aegis(session):
    svc = _seeded(session)
    aegis = svc.user_repo.get_by_username("aegis")

    token = svc.mint_service_account_token(aegis.id, ttl_days=365)
    assert isinstance(token, str)
    assert len(token) > 20

    validated = svc.validate_session(token)
    assert validated is not None
    assert validated.username == "aegis"


def test_mint_token_refused_for_non_service_account(session):
    svc = _seeded(session)
    human, err = svc.create_user(
        username="alice", email="alice@x.test", password="Str0ngPassw0rd!42"
    )
    assert err is None

    with pytest.raises(ValueError):
        svc.mint_service_account_token(human.id, ttl_days=365)


def test_mint_token_stores_hash_not_plaintext(session):
    svc = _seeded(session)
    aegis = svc.user_repo.get_by_username("aegis")

    token = svc.mint_service_account_token(aegis.id, ttl_days=365)
    session.commit()

    row = session.query(UserSession).filter_by(user_id=aegis.id).one()
    assert row.session_token_hash != token
    assert row.session_token_hash == hashlib.sha256(token.encode("utf-8")).hexdigest()
