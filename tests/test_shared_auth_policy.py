"""A validated session is not an authenticated caller: policy applies everywhere.

The password-change gate and tenant resolution lived inside the REST dependency
rather than beside session validation, so any entry point that called
validate_session() directly inherited neither. MCP did: a user flagged
must_change_password could list alerts and write case notes, and a tenant-bound
user's tools ran unbound — which the ES/Kibana overlay reads as the default
estate.

These pin the shared policy at each entry point, and pin the remediation path
that gating pages would otherwise close: /profile hosts the change-password
form, so a flagged user must still reach it.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

import ion.web.mcp_api as mcp_mod
from ion.auth.dependencies import (
    _authenticate,
    _authenticate_page,
    apply_post_session_policy,
    password_change_blocks,
)


def _request(path: str) -> Request:
    return Request({"type": "http", "method": "POST", "path": path, "headers": [],
                    "query_string": b""})


def _flagged(**kw):
    return SimpleNamespace(
        id=1, username="admin", email="a@x.y", must_change_password=True,
        has_permission=lambda p: True, tenant_id=None, **kw,
    )


def _clear(**kw):
    return SimpleNamespace(
        id=1, username="analyst", email="n@x.y", must_change_password=False,
        has_permission=lambda p: True, tenant_id=None, **kw,
    )


def _auth_service(user):
    svc = MagicMock()
    svc.validate_session.return_value = user
    return svc


def _enforced(on=True):
    return patch("ion.auth.dependencies.get_config",
                 return_value=SimpleNamespace(enforce_password_change=on))


# ── the gate itself ─────────────────────────────────────────────────────────

def test_gate_blocks_arbitrary_path():
    with _enforced():
        assert password_change_blocks(_request("/api/cases"), _flagged()) is True


def test_gate_permits_the_change_endpoint():
    with _enforced():
        assert password_change_blocks(
            _request("/api/auth/change-password"), _flagged()) is False


def test_gate_ignores_unflagged_user():
    with _enforced():
        assert password_change_blocks(_request("/api/cases"), _clear()) is False


def test_gate_off_when_disabled():
    with _enforced(on=False):
        assert password_change_blocks(_request("/api/cases"), _flagged()) is False


# ── pages: gated, but the remediation page stays reachable ─────────────────

def test_page_gate_redirects_flagged_user_to_profile():
    with _enforced():
        with pytest.raises(HTTPException) as caught:
            _authenticate_page(_request("/cases"), "tok", _auth_service(_flagged()))
    assert caught.value.status_code == 307
    assert caught.value.headers["Location"] == "/profile?change_password=1"


def test_page_gate_allows_profile_so_the_user_can_remediate():
    """A flagged user locked out of /profile could never change the password."""
    with _enforced():
        user, _ = _authenticate_page(
            _request("/profile"), "tok", _auth_service(_flagged()))
    assert user.username == "admin"


def test_page_gate_allows_static_assets():
    with _enforced():
        user, _ = _authenticate_page(
            _request("/static/app.css"), "tok", _auth_service(_flagged()))
    assert user is not None


def test_page_permission_still_enforced():
    user = _clear()
    user.has_permission = lambda p: False
    with _enforced():
        with pytest.raises(HTTPException) as caught:
            _authenticate_page(_request("/cases"), "tok", _auth_service(user), "case:read")
    assert caught.value.status_code == 403


def test_page_unauthenticated_redirects_to_login():
    with pytest.raises(HTTPException) as caught:
        _authenticate_page(_request("/cases"), None, _auth_service(None))
    assert caught.value.status_code == 307
    assert "/login" in caught.value.headers["Location"]


# ── REST keeps its 403 ─────────────────────────────────────────────────────

def test_rest_rejects_flagged_user():
    with _enforced():
        with pytest.raises(HTTPException) as caught:
            _authenticate(_request("/api/cases"), "tok", _auth_service(_flagged()))
    assert caught.value.status_code == 403


def test_rest_allows_unflagged_user():
    with _enforced():
        user, _ = _authenticate(_request("/api/cases"), "tok", _auth_service(_clear()))
    assert user.username == "analyst"


# ── MCP now inherits the same policy ───────────────────────────────────────

def _mcp_client():
    app = FastAPI()
    app.include_router(mcp_mod.router)
    return TestClient(app)


def _call_add_note():
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "add_case_note",
                       "arguments": {"case_id": 1, "content": "x"}}}


def test_mcp_rejects_flagged_user_before_dispatch(monkeypatch):
    monkeypatch.setenv("ION_MCP_ENABLED", "true")
    factory = MagicMock()
    monkeypatch.setattr(mcp_mod, "get_session_factory", lambda: factory)
    monkeypatch.setattr(mcp_mod, "AuthService", lambda s: _auth_service(_flagged()))
    dispatched = []
    monkeypatch.setattr(mcp_mod, "_handle_message",
                        lambda *a: dispatched.append(a) or {})
    with _enforced():
        r = _mcp_client().post("/api/mcp", json=_call_add_note(),
                               headers={"Authorization": "Bearer tok"})
    assert r.status_code == 403, r.text
    assert dispatched == [], "the tool ran despite a pending password change"


def test_mcp_allows_unflagged_user(monkeypatch):
    monkeypatch.setenv("ION_MCP_ENABLED", "true")
    factory = MagicMock()
    monkeypatch.setattr(mcp_mod, "get_session_factory", lambda: factory)
    monkeypatch.setattr(mcp_mod, "AuthService", lambda s: _auth_service(_clear()))
    monkeypatch.setattr(mcp_mod, "_handle_message",
                        lambda msg, user: {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})
    with _enforced():
        r = _mcp_client().post("/api/mcp", json=_call_add_note(),
                               headers={"Authorization": "Bearer tok"})
    assert r.status_code == 200, r.text
    assert r.json()["result"] == {"ok": True}


def test_mcp_still_401s_without_a_session(monkeypatch):
    monkeypatch.setenv("ION_MCP_ENABLED", "true")
    r = _mcp_client().post("/api/mcp", json=_call_add_note())
    assert r.status_code == 401


# ── the policy resolves a tenant, so MCP cannot run unbound ────────────────

def test_policy_returns_tenant_binding():
    svc = _auth_service(_clear())
    with _enforced():
        with patch("ion.auth.dependencies._resolve_tenant_binding",
                   return_value=(7, {"es": {"url": "https://t7"}})) as resolve:
            _, binding = _authenticate(_request("/api/cases"), "tok", svc)
    assert resolve.called, "policy did not resolve a tenant"
    assert binding == (7, {"es": {"url": "https://t7"}})


def test_mcp_authenticate_applies_the_shared_policy():
    """Pins the wiring, not just the behaviour: MCP must call the shared policy."""
    import inspect
    src = inspect.getsource(mcp_mod._authenticate)
    assert "apply_post_session_policy" in src
    assert "validate_session" in src


def test_policy_is_the_only_password_gate():
    """No entry point should re-implement the gate inline."""
    import inspect
    src = inspect.getsource(apply_post_session_policy)
    assert "password_change_blocks" in src


# ── the allowlist must not widen past the one page ─────────────────────────

@pytest.mark.parametrize("path", ["/profileXYZ", "/profiles", "/profile-settings",
                                  "/profile/cases", "/cases"])
def test_page_gate_does_not_exempt_lookalike_paths(path):
    """Exact match, not prefix: a future /profile* route must not be exempt."""
    with _enforced():
        assert password_change_blocks(_request(path), _flagged(), pages=True) is True


def test_page_gate_tolerates_a_trailing_slash():
    with _enforced():
        assert password_change_blocks(_request("/profile/"), _flagged(), pages=True) is False


def test_api_caller_gets_no_page_exemption():
    """/profile is a page allowance only; an API caller is still refused."""
    with _enforced():
        assert password_change_blocks(_request("/profile"), _flagged()) is True


# ── the SSE stream is an entry point too ───────────────────────────────────

def test_events_stream_refuses_a_flagged_user(monkeypatch):
    import ion.web.events_api as events

    monkeypatch.setattr(events, "get_session_factory", lambda: MagicMock())
    monkeypatch.setattr(events, "AuthService", lambda s: _auth_service(_flagged()))
    req = Request({"type": "http", "method": "GET", "path": "/api/events/stream",
                   "headers": [(b"authorization", b"Bearer tok")], "query_string": b""})
    with _enforced():
        with pytest.raises(HTTPException) as caught:
            events._authenticate(req)
    assert caught.value.status_code == 403


def test_events_stream_allows_an_unflagged_user(monkeypatch):
    import ion.web.events_api as events

    monkeypatch.setattr(events, "get_session_factory", lambda: MagicMock())
    monkeypatch.setattr(events, "AuthService", lambda s: _auth_service(_clear()))
    req = Request({"type": "http", "method": "GET", "path": "/api/events/stream",
                   "headers": [(b"authorization", b"Bearer tok")], "query_string": b""})
    with _enforced():
        assert events._authenticate(req) is True


# ── binding semantics ──────────────────────────────────────────────────────

def test_install_tolerates_an_unbound_request():
    """binding None means tenancy is off; the default estate is intended."""
    from ion.auth.dependencies import install_tenant_binding

    install_tenant_binding(None)  # must not raise


def test_install_accepts_a_platform_user_with_no_tenant():
    from ion.auth.dependencies import install_tenant_binding
    from ion.core.tenant_context import current_tenant_id

    install_tenant_binding((None, None))
    assert current_tenant_id() is None
