import importlib
import json
from types import SimpleNamespace

import pytest
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.storage.database import get_db_session
from ion.web import integration_api, response_api


@pytest.fixture
def client(monkeypatch):
    try:
        ui = importlib.import_module("ion.web.ui._cases_detail_response")
    except ModuleNotFoundError as error:
        if error.name != "ion.web.ui._cases_detail_response":
            raise
        ui = SimpleNamespace(router=APIRouter())
    app = FastAPI()
    app.include_router(ui.router, prefix="/ui")
    user = SimpleNamespace(has_permission=lambda permission: True)
    for route in ui.router.routes:
        for dependency in route.dependant.dependencies:
            if dependency.call is not get_db_session:
                app.dependency_overrides[dependency.call] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: None
    monkeypatch.setattr(response_api, "response_actions_enabled", lambda: True)
    return TestClient(app), user


@pytest.mark.parametrize(
    "payload,state",
    [
        (None, "failed"),
        ({}, "failed"),
        ({"log": None}, "failed"),
        ({"log": []}, "empty"),
        ({"log": [{"status": "completed", "action_type": "block_ip", "target": "<unsafe>", "result": {"dry_run": True}}]}, "data"),
    ],
)
def test_log_outcomes(client, monkeypatch, payload, state):
    c, _ = client

    def read(**kwargs):
        assert kwargs["case_id"] == 7 and kwargs["limit"] == 100
        return payload

    monkeypatch.setattr(response_api, "response_action_log", read)
    result = c.get("/ui/cases/7/response-log", headers={"Accept": "application/json"})
    assert result.status_code == 200
    assert result.json()["state"] == state
    html = c.get("/ui/cases/7/response-log").text
    assert "<unsafe>" not in html
    assert ("No actions requested yet" in html) == (state == "empty")
    assert ("Could not load action log." in html) == (state == "failed")
    if state == "data":
        assert "(dry-run)" in html


@pytest.mark.parametrize("status", [403, 500])
def test_log_refusal_never_empty(client, monkeypatch, status):
    c, _ = client

    def read(**kwargs):
        raise HTTPException(status_code=status)

    monkeypatch.setattr(response_api, "response_action_log", read)
    html = c.get("/ui/cases/7/response-log").text
    assert "Could not load action log." in html
    assert "No actions requested yet" not in html


@pytest.mark.parametrize("missing", ["abandoned_count", "retrying_count", "unresolved", "has_problems"])
def test_sync_missing_fields_never_mild_warning(client, monkeypatch, missing):
    c, _ = client
    payload = {"has_problems": True, "abandoned_count": 1, "retrying_count": 0, "unresolved": []}
    del payload[missing]
    monkeypatch.setattr(integration_api, "get_case_sync_journal", lambda **kwargs: payload)
    result = c.get("/ui/cases/7/sync-status", headers={"Accept": "application/json"})
    assert result.status_code == 200
    assert result.json()["state"] == "failed"
    html = c.get("/ui/cases/7/sync-status").text
    assert "could not be read" in html
    assert "alert-warning" not in html


@pytest.mark.parametrize("abandoned,retrying,css", [(0, 1, "alert-warning"), (1, 0, "alert-error")])
def test_sync_known_severity_and_utc(client, monkeypatch, abandoned, retrying, css):
    c, _ = client
    payload = {
        "has_problems": True,
        "abandoned_count": abandoned,
        "retrying_count": retrying,
        "unresolved": [{"status": "failed", "target": "<unsafe>", "operation": "post_note", "last_error": "oops", "next_retry_at": "2026-10-14T12:00:00", "attempt_count": 0, "attempts_remaining": 5}],
    }
    monkeypatch.setattr(integration_api, "get_case_sync_journal", lambda **kwargs: payload)
    html = c.get("/ui/cases/7/sync-status").text
    assert css in html
    assert "<unsafe>" not in html
    assert "2026-10-14 12:00 UTC" in html
    assert "0 attempts" in html


def test_sync_genuine_empty(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(integration_api, "get_case_sync_journal", lambda **kwargs: {"has_problems": False, "abandoned_count": 0, "retrying_count": 0, "unresolved": []})
    result = c.get("/ui/cases/7/sync-status", headers={"Accept": "application/json"})
    assert result.status_code == 200 and result.json()["state"] == "empty"
    assert "alert-" not in c.get("/ui/cases/7/sync-status").text


@pytest.mark.parametrize(
    "catalogue,observables,state", [({}, [], "failed"), ({"actions": []}, None, "failed"), ({"actions": []}, [], "empty"), ({"actions": []}, [{"type": "unknown", "value": "x"}], "empty")]
)
def test_actions_shapes(client, monkeypatch, catalogue, observables, state):
    c, _ = client
    monkeypatch.setattr(response_api, "list_actions", lambda **kwargs: catalogue)
    result = c.post("/ui/cases/7/response-actions", data={"observables": json.dumps(observables)}, headers={"Accept": "application/json"})
    assert result.status_code == 200
    assert result.json()["state"] == state
    html = c.post("/ui/cases/7/response-actions", data={"observables": json.dumps(observables)}).text
    assert ("No actionable observables" in html) == (state == "empty")


def test_actions_deduplicate_and_encode_callback(client, monkeypatch):
    c, user = client
    monkeypatch.setattr(response_api, "list_actions", lambda **kwargs: {"actions": [{"id": 1, "action_type": "block_ip", "name": "Block IP", "requires_approval": True}]})
    body = {"observables": [{"type": "ip", "value": "<quoted ' target>"}] * 2}
    html = c.post("/ui/cases/7/response-actions", data={"observables": json.dumps(body["observables"])}).text
    assert html.count('data-click-action="requestResponseAction"') == 1
    assert "<quoted" not in html
    from bs4 import BeautifulSoup

    button = BeautifulSoup(html, "html.parser").select_one('[data-click-action="requestResponseAction"]')
    assert json.loads(button["data-args"]) == [1, "<quoted ' target>", 7]
    user.has_permission = lambda permission: permission != "playbook:execute"
    assert 'data-click-action="requestResponseAction"' not in c.post("/ui/cases/7/response-actions", data={"observables": json.dumps(body["observables"])}).text


def test_response_disabled_does_not_read(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(response_api, "response_actions_enabled", lambda: False)
    monkeypatch.setattr(response_api, "list_actions", lambda **kwargs: pytest.fail("disabled catalogue read"))
    result = c.post("/ui/cases/7/response-actions", data={"observables": "[]"}, headers={"Accept": "application/json"})
    assert result.status_code == 200 and result.json()["state"] == "disabled"


@pytest.mark.parametrize("path,method", [("/ui/cases/7/sync-status", "get"), ("/ui/cases/7/response-log", "get"), ("/ui/cases/7/response-actions", "post")])
def test_routes_keep_case_permission_dependency(path, method):
    from ion.web.ui import _cases_detail_response as ui

    app = FastAPI()
    app.include_router(ui.router, prefix="/ui")
    from ion.auth.dependencies import get_current_user

    user = SimpleNamespace(id=1, username="viewer", role_id=None, has_permission=lambda permission: permission != "case:read")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: None
    response = getattr(TestClient(app), method)(path, **({"json": {"observables": []}} if method == "post" else {}))
    assert response.status_code == 403


def test_callback_pattern_discriminates():
    import re

    pattern = re.compile(r"data-args='\{\{\s*\[action.id, item.value, case_id\]\|tojson\s*\}\}'")
    assert pattern.search("data-args='{{ [action.id, item.value, case_id]|tojson }}'")
    assert not pattern.search('data-args="{{ [action.id, item.value, case_id] }}"')
    from pathlib import Path

    fragment = Path("src/ion/web/templates/_fragments/cases_detail_response_actions.html").read_text(encoding="utf-8")
    assert pattern.search(fragment)


@pytest.mark.parametrize("observables", ["{broken", "{}", "null", '[{"type":"ip"}]'])
def test_action_form_unreadable_not_empty(client, monkeypatch, observables):
    c, _ = client
    monkeypatch.setattr(response_api, "list_actions", lambda **kwargs: {"actions": []})
    response = c.post("/ui/cases/7/response-actions", data={"observables": observables})
    assert response.status_code == 200
    assert "Could not load response actions." in response.text
    assert "No actionable observables" not in response.text


@pytest.mark.parametrize(
    "path,method,denied",
    [("/ui/cases/7/sync-status", "get", {"integration:read", "alert:read"}), ("/ui/cases/7/response-log", "get", {"playbook:read"}), ("/ui/cases/7/response-actions", "post", {"playbook:read"})],
)
def test_called_source_permission_denies_before_read(monkeypatch, path, method, denied):
    from ion.auth.dependencies import get_current_user
    from ion.web.ui import _cases_detail_response as ui

    app = FastAPI()
    app.include_router(ui.router, prefix="/ui")
    user = SimpleNamespace(id=1, username="viewer", role_id=None, has_permission=lambda permission: permission not in denied)
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: None
    monkeypatch.setattr(integration_api, "get_case_sync_journal", lambda **kwargs: pytest.fail("source called without integration access"))
    monkeypatch.setattr(response_api, "list_actions", lambda **kwargs: pytest.fail("catalogue called without permission"))
    monkeypatch.setattr(response_api, "response_action_log", lambda **kwargs: pytest.fail("log called without permission"))
    response = getattr(TestClient(app), method)(path, **({"data": {"observables": "[]"}} if method == "post" else {}))
    assert response.status_code == 403
