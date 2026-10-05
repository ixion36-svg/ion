"""A write must not persist a field the environment is holding.

The settings page renders those fields read-only and drops them from the save
payload, but that is one caller. `curl`, a script, the setup wizard and
`/wizard/save-all` reach the same handlers, and a value stored there loses to
the environment on the next load — a save that reports success and changes
nothing, which is the failure v0.99.7 exists to close.
"""
import json

import pytest
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.core import config as config_mod
from ion.models.user import Permission, Role, User
from ion.web.server import app


@pytest.fixture
def admin_client(tmp_path, monkeypatch):
    """Authenticated as a user holding both config permissions.

    ION_DATA_DIR points at tmp_path so the handlers' to_file() writes a
    throwaway config.json that the test can read back.
    """
    monkeypatch.setenv("ION_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config_mod, "_config", None, raising=False)
    perms = [
        Permission(name="system:settings", resource="system", action="settings"),
        Permission(name="integration:manage", resource="integration", action="manage"),
    ]
    role = Role(name="admin")
    role.permissions = perms
    user = User(
        id=1, username="admin", email="admin@localhost", password_hash="x",
        display_name="Administrator", is_active=True,
    )
    user.roles = [role]
    app.dependency_overrides[get_current_user] = lambda: user
    yield TestClient(app)
    app.dependency_overrides.clear()
    monkeypatch.setattr(config_mod, "_config", None, raising=False)


def _stored(tmp_path):
    path = tmp_path / ".ion" / "config.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def test_section_put_does_not_store_an_env_held_field(
    admin_client, tmp_path, monkeypatch
):
    monkeypatch.setenv("ION_ELASTICSEARCH_URL", "http://from-env:9200")
    monkeypatch.setattr(config_mod, "_config", None, raising=False)

    resp = admin_client.put(
        "/api/admin/config/elasticsearch",
        json={"elasticsearch_url": "http://from-the-api:9200"},
    )

    assert resp.status_code == 200
    stored = _stored(tmp_path)
    # What must never appear is the submitted value.
    assert stored.get("elasticsearch_url") != "http://from-the-api:9200"
    # But the key IS present, holding the environment's value: to_file
    # serialises the whole env-merged object, which is what keeps
    # scripts/migrate-env-to-settings.ps1 working — it exists to get effective
    # values into config.json before .env is pruned, and every field it cares
    # about is env-held by definition at that moment. The guard rejects the
    # submitted value without stopping the env value being persisted.
    assert stored.get("elasticsearch_url") == "http://from-env:9200"


def test_a_section_put_still_stores_a_field_the_environment_is_not_holding(
    admin_client, tmp_path, monkeypatch
):
    """The guard must be narrow. Everything else still saves."""
    monkeypatch.delenv("ION_ELASTICSEARCH_ALERT_INDEX", raising=False)
    monkeypatch.setattr(config_mod, "_config", None, raising=False)

    resp = admin_client.put(
        "/api/admin/config/elasticsearch",
        json={"elasticsearch_alert_index": "my-alerts-*"},
    )

    assert resp.status_code == 200
    assert _stored(tmp_path)["elasticsearch_alert_index"] == "my-alerts-*"


def test_the_wizard_does_not_store_an_env_held_field(
    admin_client, tmp_path, monkeypatch
):
    """The wizard's payload is generically named, so it needs its own guard.

    It is also a lower bar to reach: `integration:manage`, not
    `system:settings`.
    """
    monkeypatch.setenv("ION_GITLAB_URL", "https://gitlab.from-env.internal")
    monkeypatch.setattr(config_mod, "_config", None, raising=False)

    resp = admin_client.put(
        "/api/admin/wizard/save/gitlab",
        json={"url": "https://gitlab.from-the-wizard.internal", "enabled": True},
    )

    assert resp.status_code == 200
    stored = _stored(tmp_path)
    assert stored.get("gitlab_url") != "https://gitlab.from-the-wizard.internal"
    # gitlab_enabled is not env-held, so the rest of the payload still landed.
    assert stored.get("gitlab_enabled") is True


def test_wizard_save_all_does_not_store_an_env_held_field(
    admin_client, tmp_path, monkeypatch
):
    monkeypatch.setenv("ION_OPENCTI_URL", "https://opencti.from-env.internal")
    monkeypatch.setattr(config_mod, "_config", None, raising=False)

    resp = admin_client.post(
        "/api/admin/wizard/save-all",
        json={
            "integrations": {
                "opencti": {
                    "url": "https://opencti.from-the-wizard.internal",
                    "enabled": True,
                }
            }
        },
    )

    assert resp.status_code == 200
    assert _stored(tmp_path).get("opencti_url") != (
        "https://opencti.from-the-wizard.internal"
    )


def test_the_effective_value_is_still_the_environments(
    admin_client, tmp_path, monkeypatch
):
    """The point of the guard, stated as the user-visible outcome."""
    monkeypatch.setenv("ION_ELASTICSEARCH_URL", "http://from-env:9200")
    monkeypatch.setattr(config_mod, "_config", None, raising=False)

    admin_client.put(
        "/api/admin/config/elasticsearch",
        json={"elasticsearch_url": "http://from-the-api:9200"},
    )
    monkeypatch.setattr(config_mod, "_config", None, raising=False)

    assert config_mod.get_config().elasticsearch_url == "http://from-env:9200"


def test_config_response_names_the_real_environment_variable(admin_client):
    """Fix 7's server half: the page cannot derive these names correctly."""
    body = admin_client.get("/api/admin/config").json()

    names = body["source_env_names"]
    assert names["elasticsearch_url"] == "ION_ELASTICSEARCH_URL"
    # The field whose key is not its name: derivation would say
    # ION_GITLAB_SUDO_ENABLED, which does not exist.
    assert names["gitlab_sudo_enabled"] == "ION_GITLAB_SUDO"
    assert set(names) == set(body["sources"])


def test_env_names_carry_no_values(admin_client, monkeypatch):
    monkeypatch.setenv("ION_GITLAB_TOKEN", "env-secret")

    body = admin_client.get("/api/admin/config").json()

    assert body["source_env_names"]["gitlab_token"] == "ION_GITLAB_TOKEN"
    assert "env-secret" not in json.dumps(body)
