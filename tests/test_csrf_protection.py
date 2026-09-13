"""CSRF middleware: token check, Origin check, and the exemption rules.

Exercised against a minimal app carrying only CSRFMiddleware, so these test the
control itself rather than ION's routing and database.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.core.csrf import derive_token
from ion.web.csrf_middleware import CSRF_HEADER, CSRFMiddleware, is_exempt

SESSION = "test-session-token"
OTHER_SESSION = "someone-elses-session"
HOST = "ion.test"
ORIGIN = f"http://{HOST}"


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(CSRFMiddleware)

    @app.post("/api/things")
    async def create_thing():
        return {"ok": True}

    @app.get("/api/things")
    async def list_things():
        return {"ok": True}

    @app.post("/api/auth/login")
    async def login():
        return {"ok": True}

    @app.post("/api/integrations/webhooks/receive/{token}")
    async def receive(token: str):
        return {"ok": True}

    return app


@pytest.fixture
def client():
    return TestClient(_app(), base_url=ORIGIN, raise_server_exceptions=False)


def _cookie(client):
    client.cookies.set("ion_session", SESSION)
    return client


# --- Token check -------------------------------------------------------------

def test_cookie_post_without_token_is_rejected(client):
    r = _cookie(client).post("/api/things")
    assert r.status_code == 403
    assert r.json()["code"] == "csrf_invalid"


def test_cookie_post_with_valid_token_succeeds(client):
    r = _cookie(client).post("/api/things", headers={CSRF_HEADER: derive_token(SESSION)})
    assert r.status_code == 200


def test_cookie_post_with_another_sessions_token_is_rejected(client):
    r = _cookie(client).post("/api/things", headers={CSRF_HEADER: derive_token(OTHER_SESSION)})
    assert r.status_code == 403
    assert r.json()["code"] == "csrf_invalid"


def test_bearer_header_does_not_exempt_cookie_request(client):
    """The bypass this whole control lives or dies on.

    Keyed on Bearer PRESENCE instead of cookie ABSENCE, an attacker appends a
    junk Authorization header, the middleware waves the request through, and the
    cookie still authenticates it because get_session_token() reads the cookie
    first. Must stay 403.
    """
    r = _cookie(client).post(
        "/api/things",
        headers={"Authorization": "Bearer junk"},
    )
    assert r.status_code == 403
    assert r.json()["code"] == "csrf_invalid"


def test_bearer_without_cookie_is_exempt(client):
    r = client.post("/api/things", headers={"Authorization": "Bearer real-api-token"})
    assert r.status_code == 200


def test_anonymous_post_without_cookie_is_not_challenged(client):
    r = client.post("/api/things")
    assert r.status_code == 200


# --- Method gate -------------------------------------------------------------

def test_get_is_never_challenged(client):
    assert _cookie(client).get("/api/things").status_code == 200


def test_options_is_never_challenged(client):
    assert _cookie(client).options("/api/things").status_code in (200, 405)


# --- Exemptions --------------------------------------------------------------

def test_login_is_exempt(client):
    assert _cookie(client).post("/api/auth/login").status_code == 200


def test_webhook_receive_is_exempt(client):
    assert _cookie(client).post("/api/integrations/webhooks/receive/abc123").status_code == 200


def test_is_exempt_matches_login_exactly():
    assert is_exempt("/api/auth/login") is True
    assert is_exempt("/api/auth/login/extra") is False


def test_is_exempt_matches_webhook_prefix():
    assert is_exempt("/api/integrations/webhooks/receive/tok") is True
    assert is_exempt("/api/integrations/webhooks") is False


def test_ordinary_paths_are_not_exempt():
    assert is_exempt("/api/things") is False
    assert is_exempt("/api/response/actions/1/approve") is False


# --- Origin check ------------------------------------------------------------

def test_foreign_origin_is_rejected(client):
    r = _cookie(client).post(
        "/api/things",
        headers={CSRF_HEADER: derive_token(SESSION), "Origin": "https://evil.example"},
    )
    assert r.status_code == 403
    assert r.json()["code"] == "origin_invalid"


def test_matching_origin_succeeds(client):
    r = _cookie(client).post(
        "/api/things",
        headers={CSRF_HEADER: derive_token(SESSION), "Origin": ORIGIN},
    )
    assert r.status_code == 200


def test_absent_origin_and_referer_is_allowed(client):
    """curl and CI send neither. Must keep working."""
    r = client.post("/api/things", headers={"Authorization": "Bearer t"})
    assert r.status_code == 200


def test_foreign_referer_is_rejected_when_origin_absent(client):
    r = _cookie(client).post(
        "/api/things",
        headers={CSRF_HEADER: derive_token(SESSION), "Referer": "https://evil.example/x"},
    )
    assert r.status_code == 403
    assert r.json()["code"] == "origin_invalid"


def test_origin_is_checked_for_bearer_requests_too(client):
    """Origin validation is orthogonal to auth method, unlike the token."""
    r = client.post(
        "/api/things",
        headers={"Authorization": "Bearer t", "Origin": "https://evil.example"},
    )
    assert r.status_code == 403
    assert r.json()["code"] == "origin_invalid"


def test_origin_is_checked_before_the_token(client):
    """A foreign origin is reported as such even with no token, so logs name the
    real reason rather than blaming a missing token."""
    r = _cookie(client).post("/api/things", headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert r.json()["code"] == "origin_invalid"


# --- Kill switch -------------------------------------------------------------

def test_disabling_the_flag_turns_both_checks_off(client, monkeypatch):
    from ion.core import config as config_module

    cfg = config_module.get_config()
    monkeypatch.setattr(cfg, "csrf_enabled", False)
    r = _cookie(client).post("/api/things", headers={"Origin": "https://evil.example"})
    assert r.status_code == 200


# --- Context var -------------------------------------------------------------

def test_token_is_published_to_the_context_var_for_templates(client):
    from ion.web._csrf_token import _csrf_token_var

    seen = {}

    app = FastAPI()
    app.add_middleware(CSRFMiddleware)

    @app.get("/peek")
    async def peek():
        seen["token"] = _csrf_token_var.get()
        return {"ok": True}

    c = TestClient(app, base_url=ORIGIN)
    c.cookies.set("ion_session", SESSION)
    c.get("/peek")
    assert seen["token"] == derive_token(SESSION)
