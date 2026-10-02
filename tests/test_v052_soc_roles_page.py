"""v0.52.0 — /soc-roles training-section reference page.

A server-rendered "SOC roles & daily duties" page in the briefing-deck
visual style: one card per role (11 roles since v0.54.1), pure-CSS hover
expansion carrying
mission / shift timeline / standing duties / "what good looks like", and a
Training path section joined live to the published-course catalogue by the
role's declared CourseLevel. URL is /soc-roles — /roles stays reserved for
the planned RBAC admin surface.
"""

import pytest
from fastapi.testclient import TestClient

from ion.auth.dependencies import require_page_auth
from ion.models.user import User
from ion.web.api import get_db_session
from ion.web.server import app

# +3 engineering seats (Security Platform Engineer, Automation
# Engineer (SOAR), Network Security Engineer) grouped with Detection
# Engineer under the "Engineering" tier.
ROLE_NAMES = [
    "L1 Triage Analyst", "L2 Investigation Analyst", "L3 / Incident Lead",
    "Detection Engineer", "Security Platform Engineer",
    "Automation Engineer (SOAR)", "Network Security Engineer",
    "Threat Hunter", "Threat Intel Analyst",
    "DFIR Specialist", "SOC Manager",
]


@pytest.fixture
def client(session):
    fake_user = User(
        id=7, username="analyst", email="analyst@localhost",
        password_hash="x", display_name="Analyst", is_active=True,
    )
    app.dependency_overrides[require_page_auth] = lambda: fake_user
    app.dependency_overrides[get_db_session] = lambda: session
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_page_renders_all_roles(client):
    r = client.get("/soc-roles")
    assert r.status_code == 200
    for name in ROLE_NAMES:
        assert name in r.text
    # Deck styling: per-role colour classes + the CSS hover-expansion hook.
    for color in ("cyan", "green", "amber", "violet", "coral", "pink", "teal",
                  "ice", "steel", "lime", "rose"):
        assert f"sr-c-{color}" in r.text
    assert ".sr-role:hover .sr-detail" in r.text
    # CSP: page styles ship in a nonced style block, no inline style attrs
    # in the roles markup.
    assert "<style nonce=" in r.text


def test_day_in_the_life_content_present(client):
    r = client.get("/soc-roles")
    assert "A shift in this seat" in r.text
    assert "Standing duties" in r.text
    assert "WHAT GOOD LOOKS LIKE" in r.text
    assert "Queue triage block" in r.text          # L1 timeline entry
    assert "Hypothesis discipline" in r.text        # Hunter duty


def test_nav_carries_soc_roles_link(client):
    r = client.get("/soc-roles")
    assert 'href="/soc-roles"' in r.text
    assert "SOC Roles" in r.text


def test_unauthenticated_is_rejected(session):
    app.dependency_overrides[get_db_session] = lambda: session
    try:
        c = TestClient(app, follow_redirects=False)
        r = c.get("/soc-roles")
        assert r.status_code in (302, 303, 307, 401, 403)
    finally:
        app.dependency_overrides.clear()
