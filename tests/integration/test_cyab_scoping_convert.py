"""Integration tests for the Convert-to-system flow.

Plan literal references inline ``admin_session`` fixture that POSTs to
``/api/auth/login``. Per task adjustments we use the project-wide ``client``
fixture from ``conftest.py`` (it injects an admin user via dependency
overrides, so no real login flow is needed). For the unauth-check we
construct a separate TestClient that does NOT inherit those overrides.
"""

import pytest


def test_convert_requires_auth(temp_db, monkeypatch):
    """Anonymous can't convert — that creates state on the server."""
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from ion.storage.database import reset_engine
    reset_engine()
    from fastapi.testclient import TestClient
    from ion.web.server import app
    raw_client = TestClient(app)
    try:
        r = raw_client.post(
            "/api/cyab/scoping/convert",
            data={"org_sector": "finance"},
            follow_redirects=False,
        )
        # 401 / 403 (depending on auth wiring), or redirect-to-login (302/303).
        assert r.status_code in (302, 303, 401, 403)
    finally:
        reset_engine()


def test_convert_authenticated_redirects_to_wizard(client):
    r = client.post(
        "/api/cyab/scoping/convert",
        data={"org_sector": "finance", "concern_top": "ransomware"},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303)
    location = r.headers["location"]
    assert location.startswith("/cyab/onboard"), f"unexpected redirect target: {location}"


def test_convert_passes_answers_via_query_string_or_session(client):
    """Either query string carries the payload, or the wizard page (next GET)
    receives it via session — at minimum the redirect target must let the
    wizard access the answers."""
    r = client.post(
        "/api/cyab/scoping/convert",
        data={"org_sector": "tech", "concern_top": "supply_chain"},
        follow_redirects=False,
    )
    location = r.headers["location"]
    if "?" in location:
        # Query-string fallback is acceptable
        assert "org_sector" in location or "from_scoping=1" in location
    else:
        # Session-stored — landing page should reveal the prefilled marker
        landing = client.get(location)
        assert landing.status_code == 200
        assert "scoping" in landing.text.lower() or "prefilled" in landing.text.lower()
