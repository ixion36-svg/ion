"""Settings reads are exercised through the mounted fragment routes."""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.web import admin_api


@pytest.fixture
def client():
    from ion.web.ui import router

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=1,
        username="settings-reader",
        is_admin=True,
        has_permission=lambda permission: True,
    )
    return TestClient(app)


PANELS = {
    "sessions": ("get_active_sessions", "sessions"),
    "backups": ("list_database_backups", "backups"),
    "logs": ("get_system_logs", "logs"),
    "wizard": ("get_wizard_integrations", "integrations"),
}


@pytest.mark.parametrize("panel", PANELS)
@pytest.mark.parametrize(
    "payload,state", [(None, "failed"), ({}, "failed"), ("empty", "empty"), ("error", "failed")]
)
def test_list_states(client, monkeypatch, panel, payload, state):
    name, key = PANELS[panel]
    if payload == "empty":
        payload = {key: {} if panel == "wizard" else []}
    elif payload == "error":
        payload = {key: [], "error": "unavailable"}

    async def read(*args, **kwargs):
        return payload

    monkeypatch.setattr(admin_api, name, read)
    response = client.get(f"/ui/settings/{panel}", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["state"] == state


@pytest.mark.parametrize(
    "panel,name",
    [
        ("database", "get_database_stats"),
        ("recovery", "get_recovery_capability"),
        ("system", "get_system_info"),
        ("environment", "get_environment_variables"),
        ("inventory", "get_configuration"),
    ],
)
def test_unavailable_objects(client, monkeypatch, panel, name):
    async def read(*args, **kwargs):
        return {}

    monkeypatch.setattr(admin_api, name, read)
    response = client.get(f"/ui/settings/{panel}", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["state"] == "failed"


@pytest.mark.parametrize("value", [None, 0])
def test_database_numbers(client, monkeypatch, value):
    async def read(*args, **kwargs):
        return {"tables": [], "database_size_mb": value, "total_tables": value, "total_rows": value}

    monkeypatch.setattr(admin_api, "get_database_stats", read)
    response = client.get("/ui/settings/database")
    assert response.status_code == 200
    assert response.text.count("Unknown" if value is None else ">0") >= 3


def test_admin_dependency_refuses_settings_only(client, monkeypatch):
    client.app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=1,
        username="reader",
        is_admin=False,
        has_permission=lambda permission: permission == "system:settings",
    )
    for panel in ("sessions", "database", "recovery", "backups", "system", "environment", "logs"):
        assert client.get(f"/ui/settings/{panel}").status_code == 403
    assert client.get("/ui/settings/wizard").status_code == 403


def test_secret_inventory_never_publishes_source_value(client, monkeypatch):
    import secrets

    marker = secrets.token_urlsafe(24)

    async def read(*args, **kwargs):
        return {
            "inventory": [
                {
                    "field": "gitlab_token",
                    "kind": "secret",
                    "is_secret": True,
                    "value": marker,
                    "available": True,
                    "source": "environment",
                    "env_var": "ION_GITLAB_TOKEN",
                    "writable": False,
                    "write_blocked_by": "environment",
                }
            ]
        }

    monkeypatch.setattr(admin_api, "get_configuration", read)
    for headers in ({}, {"Accept": "application/json"}):
        response = client.get("/ui/settings/inventory", headers=headers)
        assert response.status_code == 200
        assert marker not in response.text
        assert marker[-4:] not in response.text
        assert (
            "set by environment" in response.text
            if not headers
            else response.json()["items"][0]["secret_set"] is True
        )


def test_environment_masks_credentials_again(client, monkeypatch):
    import secrets

    marker = secrets.token_urlsafe(24)

    async def read(*args, **kwargs):
        return {
            "variables": {
                "ION_DB_PASSWORD": marker,
                "ION_DATABASE_URL": f"postgresql://reader:{marker}@localhost/ion",
            }
        }

    monkeypatch.setattr(admin_api, "get_environment_variables", read)
    for headers in ({}, {"Accept": "application/json"}):
        response = client.get("/ui/settings/environment", headers=headers)
        assert response.status_code == 200
        assert marker not in response.text
        assert marker[-4:] not in response.text


@pytest.mark.parametrize("panel,name,key", [(panel, *spec) for panel, spec in PANELS.items()])
def test_malformed_nested_collection(client, monkeypatch, panel, name, key):
    async def read(*args, **kwargs):
        return {key: {"broken": "not a row"} if panel == "wizard" else ["not a row"]}

    monkeypatch.setattr(admin_api, name, read)
    assert (
        client.get(f"/ui/settings/{panel}", headers={"Accept": "application/json"}).json()["state"]
        == "failed"
    )


@pytest.mark.parametrize(
    "panel,name",
    [(panel, spec[0]) for panel, spec in PANELS.items()]
    + [
        ("inventory", "get_configuration"),
        ("database", "get_database_stats"),
        ("recovery", "get_recovery_capability"),
        ("system", "get_system_info"),
        ("environment", "get_environment_variables"),
    ],
)
def test_source_exception_never_leaks(client, monkeypatch, panel, name):
    import secrets

    marker = secrets.token_urlsafe(24)

    async def read(*args, **kwargs):
        raise RuntimeError(marker)

    monkeypatch.setattr(admin_api, name, read)
    for headers in ({}, {"Accept": "application/json"}):
        response = client.get(f"/ui/settings/{panel}", headers=headers)
        assert response.status_code == 200
        assert marker not in response.text
        if headers:
            assert response.json()["state"] == "failed"


@pytest.mark.parametrize("present", [True, False])
def test_session_fields_and_current_session(client, monkeypatch, present):
    import json
    from bs4 import BeautifulSoup

    item = (
        {
            "user_id": 2,
            "username": 'O\'Brien "reader"',
            "email": "reader@example.invalid",
            "last_login": "2026-10-14T10:00:00Z",
            "roles": ["Analyst"],
        }
        if present
        else {}
    )

    async def read(*args, **kwargs):
        return {"sessions": [item, {"user_id": 1, "username": "settings-reader", "roles": []}]}

    monkeypatch.setattr(admin_api, "get_active_sessions", read)
    soup = BeautifulSoup(client.get("/ui/settings/sessions").text, "html.parser")
    assert "(current)" in soup.get_text()
    if present:
        assert json.loads(soup.select_one('[data-click-action="revokeSession"]')["data-args"]) == [
            2,
            item["username"],
        ]
        for key in ("username", "email", "last_login"):
            assert item[key] in soup.get_text()
        assert "Analyst" in soup.get_text()
    else:
        assert soup.select_one('[data-click-action="revokeSession"]') is None
        assert "Unknown" in soup.get_text()
        assert "Roles unknown" in soup.get_text()


@pytest.mark.parametrize("present", [True, False])
def test_backup_fields_and_safe_arguments(client, monkeypatch, present):
    import json
    from bs4 import BeautifulSoup

    item = (
        {"filename": 'archive\'s "copy".db', "size_mb": 0, "created_at": "2026-10-14T10:00:00Z"}
        if present
        else {}
    )

    async def read(*args, **kwargs):
        return {"backups": [item]}

    monkeypatch.setattr(admin_api, "list_database_backups", read)
    soup = BeautifulSoup(client.get("/ui/settings/backups").text, "html.parser")
    if present:
        assert "0 MB" in soup.get_text()
        assert item["created_at"] in soup.get_text()
        for button in soup.select("button"):
            assert json.loads(button["data-args"]) == [item["filename"]]
    else:
        assert "Unknown MB" in soup.get_text()
        assert soup.select_one("button") is None


@pytest.mark.parametrize("configured", [True, False, None])
@pytest.mark.parametrize("enabled", [True, False, None])
def test_wizard_each_boolean_has_three_states(client, monkeypatch, configured, enabled):
    async def read(*args, **kwargs):
        return {
            "integrations": {
                "safe": {"name": "Connector", "configured": configured, "enabled": enabled}
            }
        }

    monkeypatch.setattr(admin_api, "get_wizard_integrations", read)
    text = client.get("/ui/settings/wizard").text
    assert {True: "Configured", False: "Not configured", None: "Configuration status unknown"}[
        configured
    ] in text
    assert ("(Enabled)" in text) == (enabled is True)
    assert ("Enablement unknown" in text) == (enabled is None)


@pytest.mark.parametrize("supported", [True, False, None])
@pytest.mark.parametrize("lists", [True, False])
def test_recovery_capability_branches(client, monkeypatch, supported, lists):
    async def read(*args, **kwargs):
        payload = {"file_copy_supported": supported, "backend": "SQLite", "target": "ion.db"}
        if lists:
            payload.update(guidance=["Take a copy"], not_covered=["Evidence files"])
        return payload

    monkeypatch.setattr(admin_api, "get_recovery_capability", read)
    text = client.get("/ui/settings/recovery").text
    assert ('data-backup-supported="true"' in text) == (supported is True)
    if supported is None:
        assert "Could not determine backup coverage" in text
    else:
        assert ("applies to this deployment" in text) == supported
        assert ("does not apply to this deployment" in text) != supported
        assert "SQLite" in text and "ion.db" in text
        assert ("Take a copy" in text) == lists
        assert ("Guidance unavailable" in text) != lists
        assert ("Evidence files" in text) == lists
        assert ("Coverage details unavailable" in text) != lists


@pytest.mark.parametrize("value", [True, False, 0, "", None])
def test_inventory_safe_values_and_filters(client, monkeypatch, value):
    async def read(*args, **kwargs):
        return {
            "inventory": [
                {
                    "field": "auto_save",
                    "kind": "bool",
                    "available": True,
                    "value": value,
                    "source": "default",
                    "writable": True,
                }
            ]
        }

    monkeypatch.setattr(admin_api, "get_configuration", read)
    model = client.get("/ui/settings/inventory", headers={"Accept": "application/json"}).json()
    assert model["items"][0]["value"] == value
    assert model["total"] == 1
    assert (
        client.get(
            "/ui/settings/inventory?non_default=true", headers={"Accept": "application/json"}
        ).json()["state"]
        == "empty"
    )
    assert (
        client.get(
            "/ui/settings/inventory?search=absent", headers={"Accept": "application/json"}
        ).json()["items"]
        == []
    )


@pytest.mark.parametrize(
    "value,available,expected",
    [("", True, False), (None, True, None), (None, False, None), (None, None, None)],
)
def test_secret_inventory_unset_and_unknown(client, monkeypatch, value, available, expected):
    async def read(*args, **kwargs):
        return {
            "inventory": [
                {
                    "field": "gitlab_token",
                    "kind": "secret",
                    "available": available,
                    "value": value,
                    "source": "file",
                    "writable": True,
                }
            ]
        }

    monkeypatch.setattr(admin_api, "get_configuration", read)
    model = client.get("/ui/settings/inventory", headers={"Accept": "application/json"}).json()
    assert model["items"][0]["secret_set"] is expected
    assert model["items"][0]["value"] is None


@pytest.mark.parametrize(
    "value,expected",
    [
        ("", "Not configured"),
        ("(not set)", "Not configured"),
        (None, "Configuration status unknown"),
    ],
)
def test_environment_unset_and_unknown(client, monkeypatch, value, expected):
    async def read(*args, **kwargs):
        return {"variables": {"ION_DB_PASSWORD": value}}

    monkeypatch.setattr(admin_api, "get_environment_variables", read)
    assert expected in client.get("/ui/settings/environment").text


def test_page_secret_template_is_rendered_outside_script():
    from ion.web.templating import make_templates
    from bs4 import BeautifulSoup

    page = (
        make_templates()
        .get_template("settings.html")
        .render(
            current_user=SimpleNamespace(is_admin=False, has_permission=lambda permission: False),
            request=SimpleNamespace(url=SimpleNamespace(path="/settings"), state=SimpleNamespace()),
        )
    )
    soup = BeautifulSoup(page, "html.parser")
    assert soup.select_one("template#settings-secret-status-template > span") is not None
    assert soup.select_one('[data-click-action="createBackup"]') is None
    assert soup.select_one('[data-click-action="cleanupDatabase"]') is None
    assert soup.select_one('[data-click-action="openIntegrationWizard"]') is None


def test_configuration_allowlists_fields_and_locks_redacted_url(client, monkeypatch):
    import secrets

    marker = secrets.token_urlsafe(24)

    async def read(*args, **kwargs):
        return {
            "gitlab": {
                "gitlab_url": f"https://reader:{marker}@git.example.invalid/project?token={marker}",
                "gitlab_token": marker,
                "gitlab_token_set": True,
                "extra": marker,
            },
            "general": {"max_versions_to_keep": 0},
            "sources": {"gitlab_token": "environment"},
            "source_env_names": {"gitlab_token": marker},
        }

    monkeypatch.setattr(admin_api, "get_configuration", read)
    for headers in ({}, {"Accept": "application/json"}):
        response = client.get("/ui/settings/configuration", headers=headers)
        assert response.status_code == 200
        assert marker not in response.text
        assert marker[-4:] not in response.text
        if headers:
            model = response.json()
            assert (
                model["configuration"]["gitlab"]["gitlab_url"]
                == "https://git.example.invalid/project"
            )
            assert "gitlab_url" in model["locked_fields"]
            assert "gitlab_token" not in model["configuration"]["gitlab"]
            assert model["configuration"]["gitlab"]["gitlab_token_set"] is True
            assert model["configuration"]["general"]["max_versions_to_keep"] == 0
            assert model["source_env_names"]["gitlab_token"] == "ION_GITLAB_TOKEN"


@pytest.mark.parametrize("value", [True, False, None, "yes", 1])
def test_configuration_secret_status_is_strict_boolean(client, monkeypatch, value):
    async def read(*args, **kwargs):
        return {"gitlab": {"gitlab_token_set": value}}

    monkeypatch.setattr(admin_api, "get_configuration", read)
    response = client.get("/ui/settings/configuration", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["configuration"]["gitlab"]["gitlab_token_set"] is (
        value if isinstance(value, bool) else None
    )


@pytest.mark.parametrize("present", [True, False])
def test_logs_fields_and_escaping(client, monkeypatch, present):
    from bs4 import BeautifulSoup

    item = (
        {
            "timestamp": "2026-10-14T10:00:00Z",
            "level": "ERROR",
            "message": "Read <failed>",
            "logger": "service.reader",
            "function": "read",
            "file": "service.py",
            "line": 0,
            "username": "reader",
            "client_ip": "127.0.0.1",
            "request_id": "abcdefgh123",
            "exception": "Failure <detail>",
        }
        if present
        else {}
    )

    async def read(*args, **kwargs):
        return {"logs": [item]}

    monkeypatch.setattr(admin_api, "get_system_logs", read)
    soup = BeautifulSoup(client.get("/ui/settings/logs").text, "html.parser")
    if present:
        for value in (
            "ERROR",
            "Read <failed>",
            "service.reader",
            "service.py:0",
            "reader",
            "127.0.0.1",
            "abcdefgh",
            "Failure <detail>",
        ):
            assert value in soup.get_text()
        assert soup.find("failed") is None
        assert soup.find("detail") is None
    else:
        assert "UNKNOWN" in soup.get_text()
        assert soup.select_one(".log-msg").get_text() == ""
        assert soup.select_one(".log-exception") is None


def test_logs_redact_configured_and_labelled_secrets(client, monkeypatch):
    import secrets
    from ion.web.ui import _integration_safety

    marker = secrets.token_urlsafe(24)
    unconfigured = secrets.token_urlsafe(24)
    monkeypatch.setattr(
        _integration_safety, "get_config", lambda: SimpleNamespace(gitlab_token=marker)
    )

    async def read(*args, **kwargs):
        return {
            "logs": [
                {
                    "level": "ERROR",
                    "message": f"Connection failed {marker} Authorization: Bearer {unconfigured}",
                    "exception": f"password={unconfigured} https://reader:{marker}@example.invalid/?token={unconfigured}",
                }
            ]
        }

    monkeypatch.setattr(admin_api, "get_system_logs", read)
    for headers in ({}, {"Accept": "application/json"}):
        response = client.get("/ui/settings/logs", headers=headers)
        assert response.status_code == 200
        assert marker not in response.text and unconfigured not in response.text
        assert "Connection failed" in response.text
        assert "[redacted]" in response.text


@pytest.mark.parametrize("panel", ["configuration", "inventory"])
def test_truncated_credential_addresses_are_withheld(client, monkeypatch, panel):
    import secrets

    marker = secrets.token_urlsafe(24)

    async def read(*args, **kwargs):
        return {
            "gitlab": {"gitlab_url": f"https://{marker}..."},
            "inventory": [
                {
                    "field": "gitlab_url",
                    "kind": "text",
                    "available": True,
                    "value": f"https://{marker}...",
                    "source": "file",
                    "writable": True,
                }
            ],
        }

    monkeypatch.setattr(admin_api, "get_configuration", read)
    for headers in ({}, {"Accept": "application/json"}):
        response = client.get(f"/ui/settings/{panel}", headers=headers)
        assert response.status_code == 200
        assert marker.lower() not in response.text.lower()
        if headers:
            model = response.json()
            assert (
                "gitlab_url" in model["locked_fields"]
                if panel == "configuration"
                else model["items"][0]["writable"] is False
            )
