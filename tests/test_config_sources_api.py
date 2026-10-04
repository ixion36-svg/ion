"""GET /config must say which fields the environment is holding."""
import json

import pytest
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.models.user import Permission, Role, User
from ion.web.server import app


@pytest.fixture
def admin_client():
    """TestClient authenticated as a user holding system:settings.

    Same style as the other API tests: override get_current_user with an
    in-memory user, so no DB or login flow is needed.
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
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_config_response_includes_sources(admin_client, monkeypatch):
    monkeypatch.setenv("ION_ELASTICSEARCH_URL", "http://es.example:9200")

    resp = admin_client.get("/api/admin/config")

    assert resp.status_code == 200
    body = resp.json()
    assert "sources" in body
    assert body["sources"]["elasticsearch_url"] == "environment"


def test_sources_does_not_leak_secret_values(admin_client, monkeypatch):
    """Sources report provenance only. The value stays masked."""
    monkeypatch.setenv("ION_GITLAB_TOKEN", "env-secret")

    body = admin_client.get("/api/admin/config").json()

    assert body["sources"]["gitlab_token"] == "environment"
    assert "env-secret" not in json.dumps(body)


def test_existing_sections_unchanged(admin_client):
    body = admin_client.get("/api/admin/config").json()
    for section in ("general", "gitlab", "opencti", "elasticsearch"):
        assert section in body
