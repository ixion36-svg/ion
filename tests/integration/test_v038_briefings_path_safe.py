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


def test_ai_airgap_deck_renders_svg_slides(authed_client):
    # v0.51.x: the AI air-gap lessons-learned deck (12 authored SVGs).
    r = authed_client.get("/briefings", params={"deck": "ai-airgap"})
    assert r.status_code == 200
    assert "/static/briefings/ai-airgap/slide-01.svg" in r.text
    assert "/static/briefings/ai-airgap/slide-12.svg" in r.text
    # The PDF download is the full HLD deliverable.
    assert "/static/briefings/AI_Airgap_Best_Practices_HLD.pdf" in r.text


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


@pytest.mark.parametrize("deck", ["executive", "overview", "secure-by-design"])
def test_refreshed_decks_serve_authored_svgs(authed_client, deck):
    # The three product decks were re-authored as in-repo SVGs (the PNG decks'
    # PowerPoint sources were never in the repo, so they froze at v0.39.8).
    # First slide asserted by name, no exact-count pin: the deck should be able
    # to grow at release time without touching this test.
    r = authed_client.get("/briefings", params={"deck": deck})
    assert r.status_code == 200
    assert f"/static/briefings/{deck}/slide-01.svg" in r.text
    assert f"/static/briefings/{deck}/slide-1.png" not in r.text
    assert f"/static/briefings/{deck}/slide-01.png" not in r.text
    # Their v0.39-era PDF/PPTX downloads are gone with their source decks.
    assert "ION_Overview" not in r.text
    assert "ION_Executive_Brief" not in r.text


def test_every_deck_in_the_dict_gets_a_tab(authed_client):
    # The strip is rendered from the decks dict. Hardcoding it is how the
    # ai-airgap deck shipped unreachable from the UI.
    r = authed_client.get("/briefings")
    for key in ("executive", "overview", "secure-by-design",
                "ad-attacks", "ad-advanced", "ai-airgap"):
        assert f"/about?deck={key}" in r.text, key
