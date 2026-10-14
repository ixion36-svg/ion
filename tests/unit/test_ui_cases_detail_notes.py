import importlib
import json
import re
from types import SimpleNamespace

import pytest
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.storage.database import get_db_session
from ion.web import kibana_api, translator_api, workbench_api


@pytest.fixture
def client():
    try:
        ui = importlib.import_module("ion.web.ui._cases_detail_notes")
    except ModuleNotFoundError as error:
        if error.name != "ion.web.ui._cases_detail_notes":
            raise
        ui = SimpleNamespace(router=APIRouter())
    app = FastAPI()
    app.include_router(ui.router, prefix="/ui")
    user = SimpleNamespace(has_permission=lambda permission: permission in {"case:read", "case:update", "alert:read"})
    for route in ui.router.routes:
        for dependency in route.dependant.dependencies:
            app.dependency_overrides[dependency.call] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: None
    return TestClient(app), user


@pytest.mark.parametrize("kind", ["comments", "annotations"])
@pytest.mark.parametrize(
    "payload,state",
    [
        (None, "failed"),
        ({}, "failed"),
        ({"KEY": None}, "failed"),
        ({"KEY": []}, "empty"),
        ({"KEY": [{"id": 3, "body": "<script>bad</script>", "comment": "<script>bad</script>", "timeline_ts": "2026-10-14T12:00:00", "created_at": "2026-10-14T13:00:00+01:00"}]}, "data"),
    ],
)
def test_read_outcomes(client, monkeypatch, kind, payload, state):
    c, _ = client
    payload = {kind: payload["KEY"]} if isinstance(payload, dict) and "KEY" in payload else payload
    calls = []
    if kind == "comments":

        async def read(**kwargs):
            calls.append(kwargs)
            return payload

        monkeypatch.setattr(kibana_api, "get_kibana_case", read)
        url = "/ui/cases/kibana/external-1/comments"
    else:

        def read(**kwargs):
            calls.append(kwargs)
            return payload

        monkeypatch.setattr(workbench_api, "list_annotations_endpoint", read)
        url = "/ui/cases/12/annotations"
    response = c.get(url, headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["state"] == state
    assert calls[0]["case_id"] == ("external-1" if kind == "comments" else 12)
    html = c.get(url).text
    assert "<script>bad</script>" not in html
    if state == "failed":
        assert ("Could not load Kibana comments" if kind == "comments" else "Failed to load annotations") in html
        assert "No comments in Kibana" not in html
    if state == "data":
        assert "2026-10-14 12:00 UTC" in html
    if kind == "comments":
        assert 'id="kibana-comment-count"' in html
    else:
        assert 'id="annotations-count-12"' in html


@pytest.mark.parametrize("kind", ["comments", "annotations"])
def test_read_exceptions_are_failed(client, monkeypatch, kind):
    c, _ = client
    if kind == "comments":

        async def read(**kwargs):
            raise HTTPException(403, "Denied")

        monkeypatch.setattr(kibana_api, "get_kibana_case", read)
        url = "/ui/cases/kibana/x/comments"
    else:

        def read(**kwargs):
            raise HTTPException(500, "Failure")

        monkeypatch.setattr(workbench_api, "list_annotations_endpoint", read)
        url = "/ui/cases/12/annotations"
    response = c.get(url, headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["state"] == "failed"


def test_annotation_callback_args_and_readonly(client, monkeypatch):
    c, user = client
    monkeypatch.setattr(workbench_api, "list_annotations_endpoint", lambda **kwargs: {"annotations": [{"id": 3, "body": "words", "timeline_ts": None}]})
    html = c.get("/ui/cases/12/annotations").text
    pattern = re.compile(r"data-args='([^']*)'")
    assert pattern.search("data-args='[12, 3]'")
    assert not pattern.search('data-args="[12, 3]"')
    args = [json.loads(match) for match in pattern.findall(html)]
    assert [12, 3] in args
    assert 'id="ann-card-12-3"' in html
    assert 'id="ann-body-12"' in html
    user.has_permission = lambda permission: permission == "case:read"
    html = c.get("/ui/cases/12/annotations").text
    assert "editAnnotation" not in html
    assert "submitAnnotation" not in html


@pytest.mark.parametrize("payload,state", [(None, "failed"), ({}, "failed"), ({"translation": None}, "failed"), ({"translation": ""}, "empty"), ({"translation": "<unsafe>"}, "data")])
def test_translation_contract(client, monkeypatch, payload, state):
    c, _ = client
    calls = []

    def read(**kwargs):
        calls.append(kwargs)
        return payload

    monkeypatch.setattr(translator_api, "translate", read)
    body = {"text": "bonjour", "source": "auto", "target": "en"}
    response = c.post("/ui/cases/note-translation", data=body, headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["state"] == state
    assert calls[0]["body"].model_dump() == body
    html = c.post("/ui/cases/note-translation", data=body).text
    assert "<unsafe>" not in html
    assert "data-note-translation" in html


def test_translation_refusal_does_not_call_model(client, monkeypatch):
    c, user = client
    calls = []
    monkeypatch.setattr(translator_api, "translate", lambda **kwargs: calls.append(kwargs))
    user.has_permission = lambda permission: permission == "case:read"
    response = c.post("/ui/cases/note-translation", data={"text": "words"})
    assert response.status_code == 403
    assert calls == []


def test_translation_error_remains_visible(client, monkeypatch):
    c, _ = client

    def read(**kwargs):
        raise HTTPException(502, "Translator unavailable")

    monkeypatch.setattr(translator_api, "translate", read)
    response = c.post("/ui/cases/note-translation", data={"text": "words"})
    assert response.status_code == 200
    assert "[translation failed: Translator unavailable]" in response.text


@pytest.mark.parametrize("url,method", [("/ui/cases/kibana/x/comments", "get"), ("/ui/cases/12/annotations", "get"), ("/ui/cases/note-translation", "post")])
def test_case_permission_runs_before_source_read(monkeypatch, url, method):
    ui = importlib.import_module("ion.web.ui._cases_detail_notes")
    app = FastAPI()
    app.include_router(ui.router, prefix="/ui")
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(has_permission=lambda permission: False)
    app.dependency_overrides[get_db_session] = lambda: None
    calls = []
    monkeypatch.setattr(kibana_api, "get_kibana_case", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setattr(workbench_api, "list_annotations_endpoint", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setattr(translator_api, "translate", lambda **kwargs: calls.append(kwargs))
    c = TestClient(app)
    response = c.post(url, data={"text": "words"}) if method == "post" else c.get(url)
    assert response.status_code == 403
    assert calls == []


@pytest.mark.parametrize("body", [{}, {"text": ""}, {"text": "x" * 200001}])
def test_translation_body_validation_before_model(client, monkeypatch, body):
    c, _ = client
    calls = []
    monkeypatch.setattr(translator_api, "translate", lambda **kwargs: calls.append(kwargs))
    response = c.post("/ui/cases/note-translation", data=body)
    assert response.status_code == 422
    assert calls == []


@pytest.mark.parametrize("kind", ["comments", "annotations"])
def test_malformed_list_child_is_failure(client, monkeypatch, kind):
    c, _ = client
    if kind == "comments":

        async def read(**kwargs):
            return {"comments": [None]}

        monkeypatch.setattr(kibana_api, "get_kibana_case", read)
        url = "/ui/cases/kibana/x/comments"
    else:
        monkeypatch.setattr(workbench_api, "list_annotations_endpoint", lambda **kwargs: {"annotations": [None]})
        url = "/ui/cases/12/annotations"
    response = c.get(url, headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["state"] == "failed"
    assert response.json()["count"] is None
