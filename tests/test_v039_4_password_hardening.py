"""v0.39.4 — password hardening (F4 must-change gate + F6 policy), all OPT-IN.

Both controls ship disabled by default (a v0.39.4 image changes no behaviour
until an operator sets ION_ENFORCE_PASSWORD_CHANGE / ION_PASSWORD_MIN_LENGTH).
In ION's deployment `admin` is the only local account; everyone else is OIDC.
"""

import pytest
from fastapi import HTTPException

from ion.auth import dependencies as deps
from ion.auth.password import validate_password_policy
from ion.auth.service import AuthService
from ion.core.config import Config, get_config
from ion.models.user import User


# --- fakes for the get_current_user dependency (no DB needed) ---------------
class _Url:
    def __init__(self, path):
        self.path = path


class _Req:
    def __init__(self, path):
        self.url = _Url(path)


class _FakeAuth:
    def __init__(self, user):
        self._user = user

    def validate_session(self, token):
        return self._user


def _must_change_user():
    return User(
        id=1, username="admin", email="admin@localhost",
        password_hash="x", must_change_password=True, is_active=True,
    )


# ---------------------------------------------------------------------------
# F6 — password policy validator
# ---------------------------------------------------------------------------
def test_policy_disabled_accepts_anything():
    assert validate_password_policy("x", 0) is None
    assert validate_password_policy("short", -1) is None


def test_policy_rejects_too_short():
    assert validate_password_policy("abc123", 12) is not None


def test_policy_rejects_common_password():
    # 'password123' is in the denylist and long enough to pass the length gate
    assert validate_password_policy("password123", 8) is not None


def test_policy_accepts_strong_password():
    assert validate_password_policy("Tr0ub4dour&3xtraLong", 12) is None


def test_password_flags_default_off():
    c = Config()
    assert c.enforce_password_change is False
    assert c.password_min_length == 0


# ---------------------------------------------------------------------------
# F4 — must_change_password gate in get_current_user
# ---------------------------------------------------------------------------
def test_f4_blocks_must_change_user_when_enabled(monkeypatch):
    monkeypatch.setattr(get_config(), "enforce_password_change", True)
    with pytest.raises(HTTPException) as ei:
        deps.get_current_user(
            request=_Req("/api/elasticsearch/alerts"),
            session_token="t",
            auth_service=_FakeAuth(_must_change_user()),
        )
    assert ei.value.status_code == 403


def test_f4_allows_change_password_endpoint(monkeypatch):
    monkeypatch.setattr(get_config(), "enforce_password_change", True)
    user = _must_change_user()
    got = deps.get_current_user(
        request=_Req("/api/auth/change-password"),
        session_token="t",
        auth_service=_FakeAuth(user),
    )
    assert got is user


def test_f4_noop_when_disabled(monkeypatch):
    monkeypatch.setattr(get_config(), "enforce_password_change", False)
    user = _must_change_user()
    got = deps.get_current_user(
        request=_Req("/api/elasticsearch/alerts"),
        session_token="t",
        auth_service=_FakeAuth(user),
    )
    assert got is user  # flag is advisory when enforcement is off


# ---------------------------------------------------------------------------
# F6 — enforcement wired into the service layer (create_user)
# ---------------------------------------------------------------------------
def test_create_user_rejects_weak_when_policy_on(session, monkeypatch):
    User.metadata.create_all(session.get_bind())
    monkeypatch.setattr(get_config(), "password_min_length", 12)
    user, err = AuthService(session).create_user(
        username="bob", email="bob@x.test", password="short"
    )
    assert user is None
    assert err is not None


def test_create_user_ok_when_policy_off(session, monkeypatch):
    User.metadata.create_all(session.get_bind())
    monkeypatch.setattr(get_config(), "password_min_length", 0)
    user, err = AuthService(session).create_user(
        username="bob2", email="bob2@x.test", password="short"
    )
    assert err is None
    assert user is not None
