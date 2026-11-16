import importlib
from types import SimpleNamespace
import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from ion.storage.database import get_db_session
from ion.web import observable_api as api


@pytest.fixture
def client():
    try:
        ui = importlib.import_module("ion.web.ui._observables_core")
    except ModuleNotFoundError as error:
        if error.name != "ion.web.ui._observables_core":
            raise
        ui = SimpleNamespace(router=APIRouter())
    app = FastAPI()
    app.include_router(ui.router, prefix="/ui")
    for route in ui.router.routes:
        for dependency in route.dependant.dependencies:
            if dependency.call is not get_db_session:
                app.dependency_overrides[dependency.call] = lambda: SimpleNamespace(has_permission=lambda p: p == "observable:read")
    app.dependency_overrides[get_db_session] = lambda: None
    return TestClient(app)


@pytest.mark.parametrize("route,handler,key", [("list", "search_observables", "observables"), ("watchlist", "get_watchlist", "items"), ("watchlist/alerts", "get_watchlist_alerts", "items")])
@pytest.mark.parametrize("payload,state", [(None, "failed"), ({}, "failed"), ("empty", "empty"), ("data", "data")])
def test_collection_outcomes(client, monkeypatch, route, handler, key, payload, state):
    if payload == "empty":
        payload = {key: [], "total": 0}
    if payload == "data":
        payload = {key: [{"id": 7, "value": "<unsafe>", "observable_value": "<unsafe>", "is_read": False}], "total": 1}
    monkeypatch.setattr(api, handler, lambda **kw: payload)
    response = client.get("/ui/observables/" + route)
    assert response.status_code == 200
    model = client.get("/ui/observables/" + route, headers={"Accept": "application/json"}).json()
    assert model["state"] == state
    assert "<unsafe>" not in response.text
    assert "removeFromWatchlist" not in response.text
    assert "markAlertRead" not in response.text
    assert "enrichObservable" not in response.text


@pytest.mark.parametrize("field", ["total", "enriched"])
@pytest.mark.parametrize("value", [None, 0, 8])
def test_stats_unknown_and_zero(client, monkeypatch, field, value):
    monkeypatch.setattr(api, "get_observable_stats", lambda **kw: {field: value})
    response = client.get("/ui/observables/stats", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["figures"][field] == value


@pytest.mark.parametrize("key", ["alerts", "cases", "co_occurring"])
@pytest.mark.parametrize("present", [False, True])
def test_detail_secondary_keys(client, monkeypatch, key, present):
    monkeypatch.setattr(api, "get_observable", lambda **kw: {"id": 7, "value": "quoted", "tags": ['a"b']})
    for name, k in [("get_observable_alerts", "alerts"), ("get_observable_cases", "cases"), ("get_co_occurring_observables", "co_occurring")]:
        monkeypatch.setattr(api, name, lambda k=k, **kw: {k: []} if present or k != key else {})
    response = client.get("/ui/observables/7/detail", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()[key] == ([] if present else None)
    html = client.get("/ui/observables/7/detail").text
    assert "saveNotes" not in html and "removeTag" not in html and "enrichObservable" not in html


@pytest.mark.parametrize("name,method,key", [("list", "search_observables", "observables"), ("watchlist", "get_watchlist", "items"), ("watchlist/alerts", "get_watchlist_alerts", "items")])
def test_failure_is_not_empty(client, monkeypatch, name, method, key):
    def failed(**kw):
        raise RuntimeError("private service failure")

    monkeypatch.setattr(api, method, failed)
    response = client.get("/ui/observables/" + name)
    assert response.status_code == 200 and "Failed to load" in response.text
    assert "private service failure" not in response.text


@pytest.mark.parametrize("endpoint,method", [("watched-count", "get_watchlist"), ("watchlist/banner", "get_watchlist_alerts")])
@pytest.mark.parametrize("payload,state,total", [(None, "failed", None), ({}, "failed", None), ({"total": 0}, "empty", 0), ({"total": 3}, "data", 3)])
def test_count_outcomes(client, monkeypatch, endpoint, method, payload, state, total):
    monkeypatch.setattr(api, method, lambda **kw: payload)
    response = client.get("/ui/observables/" + endpoint, headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json() == {"state": state, "total": total}


@pytest.mark.parametrize("name,group,keys", [("ips", "by_type", ("ipv4", "ipv6")), ("domains", "by_type", ("domain", "hostname")), ("critical", "by_threat_level", ("critical", "high"))])
@pytest.mark.parametrize("missing", [True, False])
def test_stats_missing_bucket_is_unknown(client, monkeypatch, name, group, keys, missing):
    payload = {group: {key: 0 for key in keys}}
    if missing:
        del payload[group][keys[0]]
    monkeypatch.setattr(api, "get_observable_stats", lambda **kw: payload)
    result = client.get("/ui/observables/stats", headers={"Accept": "application/json"})
    assert result.status_code == 200
    assert result.json()["figures"][name] == (None if missing else 0)


@pytest.mark.parametrize("permission,action", [("observable:update", "toggleWatchlist"), ("observable:enrich", "enrichObservable")])
def test_list_mutation_controls_follow_exact_permission(client, monkeypatch, permission, action):
    from ion.web.ui import _observables_core as ui

    client.app.dependency_overrides[ui.PERMISSION] = lambda: SimpleNamespace(has_permission=lambda p: p in ["observable:read", permission])
    monkeypatch.setattr(api, "search_observables", lambda **kw: {"observables": [{"id": 7, "value": "test", "is_watched": False, "is_ignored": False}], "total": 1})
    html = client.get("/ui/observables/list").text
    assert action in html
    assert ("enrichObservable" in html) == (permission == "observable:enrich")
    assert ("toggleWatchlist" in html) == (permission == "observable:update")


@pytest.mark.parametrize("key", ["alerts", "cases", "co_occurring"])
def test_detail_secondary_exception_is_visible(client, monkeypatch, key):
    monkeypatch.setattr(api, "get_observable", lambda **kw: {"id": 7, "value": "quoted"})

    def failed(**kw):
        raise RuntimeError("private")

    for name, k in [("get_observable_alerts", "alerts"), ("get_observable_cases", "cases"), ("get_co_occurring_observables", "co_occurring")]:
        monkeypatch.setattr(api, name, failed if k == key else lambda k=k, **kw: {k: []})
    html = client.get("/ui/observables/7/detail").text
    assert "unavailable" in html and "private" not in html


@pytest.mark.parametrize("score", [None, 0, 90])
def test_detail_enrichment_score_and_escaped_tags(client, monkeypatch, score):
    from bs4 import BeautifulSoup
    import json
    from ion.web.ui import _observables_core as ui

    client.app.dependency_overrides[ui.PERMISSION] = lambda: SimpleNamespace(has_permission=lambda p: True)
    obs = {
        "id": 7,
        "value": "<bad>",
        "tags": ["a\"b'c"],
        "enrichment": {"source": "<source>", "score": score, "is_malicious": None, "labels": ["<label>"], "threat_actors": [{"name": "<actor>"}], "indicators": [{}]},
    }
    monkeypatch.setattr(api, "get_observable", lambda **kw: obs)
    for name, k in [("get_observable_alerts", "alerts"), ("get_observable_cases", "cases"), ("get_co_occurring_observables", "co_occurring")]:
        monkeypatch.setattr(api, name, lambda k=k, **kw: {k: []})
    response = client.get("/ui/observables/7/detail")
    assert response.status_code == 200
    soup = BeautifulSoup(response.text, "html.parser")
    assert soup.find("bad") is None and soup.find("actor") is None
    assert json.loads(soup.select_one('[data-click-action="removeTag"]')["data-args"]) == [7, "a\"b'c"]
    assert ("Score: Unknown" if score is None else "Score: " + str(score) + "/100") in response.text


@pytest.mark.parametrize("endpoint", ["list", "stats", "watched-count", "watchlist", "watchlist/alerts", "watchlist/banner", "7/detail"])
def test_core_requires_observable_read(client, endpoint):
    from fastapi import HTTPException
    from ion.web.ui import _observables_core as ui

    def denied():
        raise HTTPException(403, "Forbidden")

    client.app.dependency_overrides[ui.PERMISSION] = denied
    response = client.get("/ui/observables/" + endpoint)
    assert response.status_code == 403


@pytest.mark.parametrize(
    "key,method,row,text",
    [
        ("alerts", "get_observable_alerts", {"id": 1, "es_alert_id": "quoted-alert", "context": "source_ip", "priority": "high", "created_at": "today"}, "Source Ip"),
        ("cases", "get_observable_cases", {"id": 2, "case_number": "CASE-123", "title": "<private>", "severity": "low"}, "CASE-123"),
        ("co_occurring", "get_co_occurring_observables", {"id": 3, "value": "related.example", "type": "domain", "co_occurrence_count": 0}, "related.example"),
    ],
)
def test_detail_related_data(client, monkeypatch, key, method, row, text):
    monkeypatch.setattr(api, "get_observable", lambda **kw: {"id": 7, "value": "primary"})
    for name, k in [("get_observable_alerts", "alerts"), ("get_observable_cases", "cases"), ("get_co_occurring_observables", "co_occurring")]:
        monkeypatch.setattr(api, name, lambda k=k, **kw: {k: []})
    monkeypatch.setattr(api, method, lambda **kw: {key: [row]})
    response = client.get("/ui/observables/7/detail")
    assert response.status_code == 200
    assert text in response.text and "<private>" not in response.text


@pytest.mark.parametrize("payload", [None, {}, {"id": None}])
def test_failed_primary_detail_does_not_claim_empty_related(client, monkeypatch, payload):
    monkeypatch.setattr(api, "get_observable", lambda **kw: payload)
    response = client.get("/ui/observables/7/detail")
    assert response.status_code == 200
    assert "Failed to load observable details" in response.text
    assert "No related cases" not in response.text


def test_list_passes_filter_and_page_parameters(client, monkeypatch):
    captured = {}

    def search(**kw):
        captured.update(kw)
        return {"observables": [], "total": 150}

    monkeypatch.setattr(api, "search_observables", search)
    response = client.get(
        "/ui/observables/list?query=example&type=domain&threat_level=high&is_whitelisted=false&is_enriched=true&only_ignored=true&limit=50&offset=50", headers={"Accept": "application/json"}
    )
    assert response.status_code == 200
    assert captured["query"] == "example" and captured["type"] == "domain"
    assert captured["is_whitelisted"] is False and captured["is_enriched"] is True
    assert captured["only_ignored"] is True and captured["offset"] == 50
    assert response.json()["page"] == 2 and response.json()["pages"] == 3


@pytest.mark.parametrize("state", ["empty", "data", "failed"])
def test_real_list_api_with_stubbed_service(client, monkeypatch, state):
    from datetime import datetime

    row = SimpleNamespace(
        id=7,
        type="domain",
        value="service.example",
        normalized_value="service.example",
        first_seen=datetime(2026, 10, 1),
        last_seen=datetime(2026, 10, 2),
        sighting_count=0,
        threat_level="unknown",
        is_whitelisted=False,
        tags=[],
        notes=None,
        latest_enrichment=None,
        is_watched=False,
        watch_reason=None,
        watched_by=None,
        watched_at=None,
        auto_enrich=False,
    )

    class Service:
        def __init__(self, session):
            pass

        def search(self, **kw):
            if state == "failed":
                raise RuntimeError("secret")
            return ([row], 1) if state == "data" else ([], 0)

    monkeypatch.setattr(api, "ObservableService", Service)
    response = client.get("/ui/observables/list", headers={"Accept": "application/json"})
    assert response.status_code == 200 and response.json()["state"] == state
    if state == "data":
        assert response.json()["items"][0]["sighting_count"] == 0


def test_real_stats_api_with_stubbed_service(client, monkeypatch):
    class Service:
        def __init__(self, session):
            pass

        def get_stats(self):
            return {"total": 0, "enriched": 0, "whitelisted": 0, "by_type": {"ipv4": 0, "ipv6": 0, "domain": 0, "hostname": 0}, "by_threat_level": {"critical": 0, "high": 0}}

    monkeypatch.setattr(api, "ObservableService", Service)
    response = client.get("/ui/observables/stats", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["figures"] == {"total": 0, "enriched": 0, "ips": 0, "domains": 0, "critical": 0}
