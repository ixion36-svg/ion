"""v0.38.1 — /briefings is path-traversal safe (CodeQL py/path-injection).

The deck slide directory is resolved through a fixed lookup table, so a
caller-supplied ``deck`` query value can never influence the filesystem path.
This pins that invariant: any unknown / malicious ``deck`` falls back to the
"executive" deck and no rendered asset URL ever contains a traversal segment.
"""
import pytest

from ion.auth.dependencies import require_page_auth
from ion.models.user import User
from ion.web.server import app


@pytest.fixture
def authed_client(client):
    """The shared integration `client`, plus an override for require_page_auth
    (the page-auth dependency the /briefings route uses)."""
    app.dependency_overrides[require_page_auth] = lambda: User(
        id=1, username="admin", email="admin@localhost",
        password_hash="x", display_name="Administrator", is_active=True,
    )
    yield client
    # base `client` fixture clears overrides on teardown


def test_valid_deck_renders_its_slides(authed_client):
    r = authed_client.get("/briefings", params={"deck": "secure-by-design"})
    assert r.status_code == 200
    assert "/static/briefings/secure-by-design/slide-" in r.text


@pytest.mark.parametrize("evil", [
    "../../../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "secure-by-design/../../overview",
    "....//....//etc",
    "/etc/passwd",
    "overview\x00",
])
def test_malicious_deck_falls_back_and_never_traverses(authed_client, evil):
    r = authed_client.get("/briefings", params={"deck": evil})
    assert r.status_code == 200
    # Falls back to the executive deck...
    assert "/static/briefings/executive/slide-" in r.text
    # ...and no rendered asset path escapes the briefings tree.
    assert "/static/briefings/../" not in r.text
    assert "etc/passwd" not in r.text
