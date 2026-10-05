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


def test_settings_page_calls_helper_after_config_fetch(admin_client):
    """Defining the helper is not enough: loadAllSettings must invoke it."""
    html = admin_client.get("/settings").text
    call = "applyConfigSources(currentConfig.sources, currentConfig.source_env_names)"
    assert call in html
    assert html.index("populateForms(currentConfig);") < html.index(call)


def test_the_badge_tooltip_does_not_derive_the_variable_name(admin_client):
    """It must name the key the server sent, not one built from the field.

    field.toUpperCase() drops the ION_ prefix on every field and is simply
    wrong for gitlab_sudo_enabled (ION_GITLAB_SUDO), so the tooltip told the
    operator to remove a variable that does not exist.
    """
    html = admin_client.get("/settings").text
    assert "field.toUpperCase()" not in html
    assert "envNames[field]" in html


def test_save_settings_drops_locked_fields(admin_client):
    """saveSettings must not PUT env-held (disabled) fields back to config.json.

    A disabled input still exposes .value, so without this filter the
    environment's value is copied into the file on every section save.
    """
    html = admin_client.get("/settings").text
    save = html[html.index("async function saveSettings("):]
    save = save[: save.index("async function testConnection(")]
    filter_at = save.index("if (el && el.disabled) delete data[k];")
    assert "form.elements[k]" in save
    # The filter must run after the payload is built and before it is sent.
    assert save.index("data.oidc_verify_ssl") < filter_at < save.index("JSON.stringify(data)")
