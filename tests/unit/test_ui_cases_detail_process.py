import importlib
import json
from types import SimpleNamespace

import pytest
from bs4 import BeautifulSoup
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.web import elasticsearch_api


@pytest.fixture
def client():
    try:
        ui = importlib.import_module("ion.web.ui._cases_detail_process")
    except ModuleNotFoundError as error:
        if error.name != "ion.web.ui._cases_detail_process":
            raise
        ui = SimpleNamespace(router=APIRouter())
    app = FastAPI()
    app.include_router(ui.router, prefix="/ui")
    user = SimpleNamespace(has_permission=lambda permission: permission in {"case:read", "alert:read", "case:update"})
    for route in ui.router.routes:
        for dependency in route.dependant.dependencies:
            app.dependency_overrides[dependency.call] = lambda: user
    return TestClient(app), user


@pytest.mark.parametrize(
    "payload,state",
    [
        (None, "failed"),
        ({}, "failed"),
        ({"available": False, "nodes": [], "children": [], "truncated_ancestors": 0}, "empty"),
        ({"available": True, "nodes": [{"name": "<unsafe>", "pid": 0}], "children": [], "truncated_ancestors": 0}, "data"),
        ({"available": True, "nodes": [], "children": []}, "failed"),
        ({"available": True, "nodes": [{"name": "one"}]}, "failed"),
    ],
)
def test_process_outcomes(client, monkeypatch, payload, state):
    c, _ = client

    async def read(**kwargs):
        assert kwargs["alert_id"] == "alert-1"
        return payload

    monkeypatch.setattr(elasticsearch_api, "get_alert_process_tree", read)
    response = c.get("/ui/cases/detail/process-tree/alert-1", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["state"] == state
    html = c.get("/ui/cases/detail/process-tree/alert-1").text
    assert "<unsafe>" not in html
    if state == "failed":
        assert "Failed to load process tree" in html
        assert "No process context" not in html


@pytest.mark.parametrize("status,message", [(503, "Process tree needs a live Elasticsearch connection."), (403, "Failed to load process tree"), (500, "Failed to load process tree")])
def test_process_http_failure(client, monkeypatch, status, message):
    c, _ = client

    async def read(**kwargs):
        raise HTTPException(status_code=status, detail="private backend data")

    monkeypatch.setattr(elasticsearch_api, "get_alert_process_tree", read)
    response = c.get("/ui/cases/detail/process-tree/a")
    assert response.status_code == 200
    assert message in response.text
    assert "private backend data" not in response.text
    assert "No process context" not in response.text


def test_process_commands_and_pin_arguments(client, monkeypatch):
    c, _ = client
    command = 'echo "quoted" && </template><script>evil()</script>'

    async def read(**kwargs):
        return {"available": True, "nodes": [{"name": "a\"b'c", "pid": 0, "command_line": command, "is_alert": True}], "children": [{"name": "child", "role": "child"}], "truncated_ancestors": 2}

    monkeypatch.setattr(elasticsearch_api, "get_alert_process_tree", read)
    response = c.get("/ui/cases/detail/process-tree/a?case_id=7")
    soup = BeautifulSoup(response.text, "html.parser")
    assert soup.select_one(".cpanel-proc-meta").text == "PID 0"
    assert soup.select_one(".cpanel-proc-cmd").text == command
    import json

    assert json.loads(soup.select_one('[data-click-action="pinProcessToCase"]')["data-args"]) == [7, "Process: a\"b'c (PID 0)"]
    assert soup.select_one(".cpanel-proc-node.is-child")
    assert "<script>evil()" not in response.text


@pytest.mark.parametrize("route,method", [("/ui/cases/detail/process-tree/a", "get"), ("/ui/cases/detail/rule-guide", "post")])
def test_case_reader_without_alert_permission_cannot_read(client, monkeypatch, route, method):
    c, user = client
    user.has_permission = lambda permission: permission == "case:read"

    async def forbidden(**kwargs):
        pytest.fail("source read must not happen")

    monkeypatch.setattr(elasticsearch_api, "get_alert_process_tree", forbidden)
    response = c.get(route) if method == "get" else c.post(route, data={"state": "data", "raw": json.dumps({"rule": {"note": "secret"}})})
    assert response.status_code == 403
    assert "secret" not in response.text


@pytest.mark.parametrize(
    "body,state,message",
    [
        ({"state": "failed"}, "failed", "Failed to load rule guide"),
        ({"state": "empty"}, "empty", "No raw data available for this alert."),
        ({"state": "data", "raw": {}}, "empty", "No rule description or investigation guide on this alert."),
        ({"state": "data", "raw": {"rule": {"description": "<script>evil()</script>", "note": "**Guide**"}}}, "data", "Investigation guide"),
        ({"state": "data", "raw": None}, "failed", "Failed to load rule guide"),
    ],
)
def test_rule_guide_outcomes_without_raw_refetch(client, monkeypatch, body, state, message):
    c, _ = client

    async def forbidden(**kwargs):
        pytest.fail("rule guide must use the coalesced raw document")

    monkeypatch.setattr(elasticsearch_api, "get_alert_raw_data", forbidden)
    response = c.post("/ui/cases/detail/rule-guide", data={"state": body["state"], **({"raw": json.dumps(body["raw"])} if "raw" in body else {})}, headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["state"] == state
    html = c.post("/ui/cases/detail/rule-guide", data={"state": body["state"], **({"raw": json.dumps(body["raw"])} if "raw" in body else {})}).text
    assert message in html
    assert "<script>evil()" not in html


def test_rule_guide_field_precedence_and_arrays(client):
    c, _ = client
    raw = {"kibana": {"alert": {"rule": {"description": ["primary", "description"], "parameters": {"note": "nested guide"}}}}, "signal.rule.description": "fallback"}
    response = c.post("/ui/cases/detail/rule-guide", data={"state": "data", "raw": json.dumps(raw)}, headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["description"] == "primary, description"
    assert response.json()["guide"] == "nested guide"


def test_process_pin_requires_update(client, monkeypatch):
    c, user = client
    user.has_permission = lambda permission: permission in {"case:read", "alert:read"}

    async def read(**kwargs):
        return {"available": True, "nodes": [{"name": "one", "command_line": "cmd"}], "children": [], "truncated_ancestors": 0}

    monkeypatch.setattr(elasticsearch_api, "get_alert_process_tree", read)
    html = c.get("/ui/cases/detail/process-tree/a?case_id=7").text
    assert "copyProcCmd" in html
    assert "pinProcessToCase" not in html


def test_rule_markdown_carrier_cannot_break_out(client):
    c, _ = client
    guide = "</textarea><img src=x onerror=evil()>\n**guide**"
    response = c.post("/ui/cases/detail/rule-guide", data={"state": "data", "raw": json.dumps({"rule.note": guide})})
    assert response.status_code == 200
    soup = BeautifulSoup(response.text, "html.parser")
    assert soup.select_one("textarea[data-case-rule-markdown]").text == guide
    assert not soup.select("img, script")


@pytest.mark.parametrize("raw", ["{broken", "null", "[]", ""])
def test_rule_guide_invalid_form_raw_is_failed(client, raw):
    c, _ = client
    response = c.post("/ui/cases/detail/rule-guide", data={"state": "data", "raw": raw}, headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["state"] == "failed"
