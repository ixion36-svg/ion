"""The settings page must ship the source-badge code.

This is a render-level guard, not a browser test: it catches the template
losing the hook during a rewrite, which is the realistic regression.
"""
import pytest
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.models.user import Permission, Role, User
from ion.web.server import app


@pytest.fixture
def admin_client():
    """TestClient authenticated as a user holding system:settings.

    Same pattern as tests/test_config_sources_api.py: override
    get_current_user with an in-memory user, so no DB or login flow is needed.
    The /settings page route is guarded by a require_page_permission closure
    (session cookie, not get_current_user), so that one dependency is
    overridden too, on the /settings route only.
    """
    perm = Permission(name="system:settings", resource="system", action="settings")
    role = Role(name="admin")
    role.permissions = [perm]
    user = User(
        id=1, username="admin", email="admin@localhost", password_hash="x",
        display_name="Administrator", is_active=True,
    )
    user.roles = [role]
    app.dependency_overrides[get_current_user] = lambda: user
    for route in app.router.routes:
        if getattr(route, "path", None) == "/settings":
            for dep in route.dependant.dependencies:
                if getattr(dep.call, "__name__", "") == "dependency":
                    app.dependency_overrides[dep.call] = lambda: user
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_settings_page_defines_source_badge_helper(admin_client):
    resp = admin_client.get("/settings")
    assert resp.status_code == 200
    html = resp.text
    assert "applyConfigSources" in html


def test_settings_page_has_badge_markup(admin_client):
    resp = admin_client.get("/settings")
    assert resp.status_code == 200
    html = resp.text
    assert "set by environment" in html.lower()
