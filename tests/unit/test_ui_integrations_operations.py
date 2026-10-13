"""Read fragments preserve unknown values, permissions and secret boundaries."""

import importlib
from types import SimpleNamespace

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.storage.database import get_db_session
from ion.web import integration_api as api


class User:
    def __init__(self, manage=True, read=True):
        self.manage = manage
        self.read = read

    def has_permission(self, permission):
        return self.manage if permission == "integration:manage" else self.read


@pytest.fixture
def client(monkeypatch):
    try:
        module = importlib.import_module("ion.web.ui._integrations_operations")
        router = module.router
    except ModuleNotFoundError:
        router = APIRouter()
    app = FastAPI()
    app.include_router(router, prefix="/ui")
    app.dependency_overrides[get_current_user] = lambda: User()
    app.dependency_overrides[get_db_session] = lambda: None
    with TestClient(app) as client:
        yield client


def stub(monkeypatch, panel, payload):
    def result(**kwargs):
        if isinstance(payload, Exception):
            raise payload
        return payload

    async def status(**kwargs):
        return result(**kwargs)

    if panel == "status":
        monkeypatch.setattr(api, "get_integration_status", status)
    elif panel == "webhooks":
        monkeypatch.setattr(api, "list_webhooks", result)
    elif panel == "webhooks/1/logs":
        monkeypatch.setattr(api, "get_webhook_logs", result)
    else:
        monkeypatch.setattr(api, "get_integration_log_service", lambda: SimpleNamespace(get_logs=result))


@pytest.mark.parametrize("panel", ["status", "webhooks", "webhooks/1/logs", "logs"])
@pytest.mark.parametrize("payload,state", [([], "empty"), (RuntimeError("private upstream detail"), "failed"), ({}, "failed")])
def test_outcomes(client, monkeypatch, panel, payload, state):
    stub(monkeypatch, panel, payload)
    response = client.get("/ui/integrations/" + panel, headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["state"] == state
    assert "private upstream detail" not in response.text


@pytest.mark.parametrize("panel", ["status", "webhooks", "webhooks/1/logs", "logs"])
def test_read_permission(client, panel):
    client.app.dependency_overrides[get_current_user] = lambda: User(read=False)
    assert client.get("/ui/integrations/" + panel).status_code == 403


def test_webhook_whitelist_zero_and_controls(client, monkeypatch):
    # Runtime sentinel rather than a credential fixture committed to the repo.
    sentinel = str(object())
    stub(monkeypatch, "webhooks", [{"id": 1, "name": "Hook <one>", "source_type": "custom", "is_active": True, "trigger_count": 0, "token": sentinel, "secret": sentinel}])
    response = client.get("/ui/integrations/webhooks")
    assert "Hook &lt;one&gt;" in response.text
    assert "0 triggers" in response.text
    assert "showEditWebhookModal" in response.text
    assert sentinel not in response.text
    assert sentinel not in client.get("/ui/integrations/webhooks", headers={"Accept": "application/json"}).text
    client.app.dependency_overrides[get_current_user] = lambda: User(manage=False)
    response = client.get("/ui/integrations/webhooks")
    assert "showWebhookLogs" in response.text
    assert "showEditWebhookModal" not in response.text
    assert "deleteWebhook" not in response.text


def test_status_missing_is_unknown_and_zero_is_measured(client, monkeypatch):
    stub(monkeypatch, "status", [{"type": "gitlab", "display_name": "GitLab", "response_time_ms": 0}])
    data = client.get("/ui/integrations/status", headers={"Accept": "application/json"}).json()
    assert data["items"][0]["status"] == "Unknown"
    assert data["items"][0]["enabled"] is None
    assert data["items"][0]["response_time_ms"] == 0
    assert "0ms" in client.get("/ui/integrations/status").text


@pytest.mark.parametrize("panel,time_key", [("webhooks/1/logs", "processing_time_ms"), ("logs", "timestamp")])
def test_logs_whitelist_and_missing_values(client, monkeypatch, panel, time_key):
    sentinel = str(object())
    stub(monkeypatch, panel, [{time_key: 0 if time_key == "processing_time_ms" else None, "payload": {"password": sentinel}, "headers": {"Authorization": sentinel}}])
    response = client.get("/ui/integrations/" + panel)
    assert "Unknown" in response.text
    if time_key == "processing_time_ms":
        assert "0.00ms" in response.text
    assert sentinel not in response.text


def test_log_filter_forwarding(client, monkeypatch):
    captured = {}

    def get_logs(**kwargs):
        captured.update(kwargs)
        return []

    monkeypatch.setattr(api, "get_integration_log_service", lambda: SimpleNamespace(get_logs=get_logs))
    assert client.get("/ui/integrations/logs?integration_type=gitlab&level=error").status_code == 200
    assert captured["integration_type"].value == "gitlab"
    assert captured["level"].value == "error"
    assert captured["limit"] == 100


def test_webhook_missing_is_unknown(client, monkeypatch):
    stub(monkeypatch, "webhooks", [{"id": 1}])
    data = client.get("/ui/integrations/webhooks", headers={"Accept": "application/json"}).json()
    assert data["items"][0]["active"] is None
    assert data["items"][0]["trigger_count"] is None


@pytest.mark.parametrize(
    "panel,source,expected",
    [
        (
            "status",
            {
                "type": "gitlab",
                "display_name": "Friendly",
                "status": "healthy",
                "is_configured": True,
                "is_enabled": False,
                "response_time_ms": 2.5,
                "metadata": {"version": "17.2", "version_compatibility": {"in_range": False}},
            },
            {"type": "gitlab", "name": "Friendly", "status": "healthy", "configured": True, "enabled": False, "response_time_ms": 2.5, "version": "17.2", "compatible": False},
        ),
        (
            "webhooks",
            {"id": 7, "name": "Example", "source_type": "custom", "is_active": False, "trigger_count": 13},
            {"id": 7, "name": "Example", "source_type": "custom", "active": False, "trigger_count": 13},
        ),
        (
            "webhooks/1/logs",
            {"created_at": "2026-01-01T01:02:03Z", "event_type": "push", "status": "success", "source_ip": "192.0.2.1", "processing_time_ms": 3.2},
            {"timestamp": "2026-01-01T01:02:03Z", "event_type": "push", "status": "success", "source_ip": "192.0.2.1", "processing_time_ms": 3.2},
        ),
        (
            "logs",
            {"created_at": "2026-01-01T01:02:03Z", "integration_type": "gitlab", "level": "warning", "action": "poll", "message": "Polling completed"},
            {"timestamp": "2026-01-01T01:02:03Z", "integration_type": "gitlab", "level": "warning", "action": "poll", "message": "Polling completed"},
        ),
    ],
)
def test_complete_data_contract(client, monkeypatch, panel, source, expected):
    stub(monkeypatch, panel, [source])
    response = client.get("/ui/integrations/" + panel, headers={"Accept": "application/json"})
    assert response.json()["state"] == "data"
    assert response.json()["items"] == [expected]


@pytest.mark.parametrize(
    "panel,expected",
    [
        ("status", {"type": "", "name": "Unknown", "status": "Unknown", "configured": None, "enabled": None, "response_time_ms": None, "version": None, "compatible": None}),
        ("webhooks", {"id": None, "name": "Unknown", "source_type": "Unknown", "active": None, "trigger_count": None}),
        ("webhooks/1/logs", {"timestamp": "Unknown", "event_type": "Unknown", "status": "Unknown", "source_ip": "Unknown", "processing_time_ms": None}),
        ("logs", {"timestamp": "Unknown", "integration_type": "Unknown", "level": "Unknown", "action": "Unknown", "message": "Unknown"}),
    ],
)
def test_complete_missing_contract(client, monkeypatch, panel, expected):
    stub(monkeypatch, panel, [{}])
    assert client.get("/ui/integrations/" + panel, headers={"Accept": "application/json"}).json()["items"] == [expected]


@pytest.mark.parametrize("value", [True, "0", [], {}])
def test_invalid_measurements_remain_unknown(client, monkeypatch, value):
    stub(monkeypatch, "status", [{"response_time_ms": value, "metadata": value}])
    item = client.get("/ui/integrations/status", headers={"Accept": "application/json"}).json()["items"][0]
    assert item["response_time_ms"] is None
    assert item["version"] is None


def test_viewer_status_has_no_test_control(client, monkeypatch):
    stub(monkeypatch, "status", [{"type": "gitlab", "display_name": "GitLab"}])
    client.app.dependency_overrides[get_current_user] = lambda: User(manage=False)
    assert 'data-click-action="testConnection"' not in client.get("/ui/integrations/status").text


@pytest.mark.parametrize("panel", ["status", "webhooks", "webhooks/1/logs", "logs"])
def test_failed_html_does_not_claim_empty(client, monkeypatch, panel):
    stub(monkeypatch, panel, RuntimeError("internal details"))
    response = client.get("/ui/integrations/" + panel)
    assert "unavailable" in response.text
    assert "No logs found" not in response.text
    assert "No webhooks configured" not in response.text
    assert "No integrations configured" not in response.text


def test_status_whitelists_nested_metadata(client, monkeypatch):
    sentinel = str(object())
    stub(monkeypatch, "status", [{"metadata": {"password": sentinel, "version_compatibility": {"message": sentinel}}, "error": sentinel, "reason": sentinel}])
    for headers in [{}, {"Accept": "application/json"}]:
        assert sentinel not in client.get("/ui/integrations/status", headers=headers).text
