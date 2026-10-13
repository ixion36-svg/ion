"""Integration metric fragments preserve refusals and unknown measurements."""
from types import SimpleNamespace
import importlib

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

ROUTES = {
    "server": "get_server_metrics",
    "elasticsearch": "get_elasticsearch_metrics",
    "server-logs": "get_server_log_metrics",
    "data-flows": "get_data_flow_metrics",
}

@pytest.fixture
def client(monkeypatch):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session
    from ion.web import integration_api
    try:
        ui = importlib.import_module("ion.web.ui._integrations_metrics")
        router = ui.router
    except ModuleNotFoundError:
        router = APIRouter()
    app = FastAPI()
    app.include_router(router, prefix="/ui")
    user = SimpleNamespace(id=1, username="reader", has_permission=lambda permission: permission == "alert:read")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: None
    payloads = {}
    for key, method in ROUTES.items():
        async def read(_key=key, **kwargs):
            value = payloads.get(_key)
            if isinstance(value, Exception):
                raise value
            return value
        monkeypatch.setattr(integration_api, method, read)
    return TestClient(app), payloads, user

@pytest.mark.parametrize("panel", ROUTES)
@pytest.mark.parametrize("payload", [None, {}, {"error": "Unavailable"}, RuntimeError("Unavailable")])
def test_failed_reads_are_not_empty(client, panel, payload):
    c, payloads, _ = client
    payloads[panel] = payload
    response = c.get(f"/ui/integrations/metrics/{panel}", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["state"] == "failed"
    html = c.get(f"/ui/integrations/metrics/{panel}").text
    assert "unavailable" in html.lower()
    assert "No logs" not in html

@pytest.mark.parametrize("panel", ROUTES)
def test_alert_read_is_required(client, panel):
    c, _, user = client
    user.has_permission = lambda permission: False
    assert c.get(f"/ui/integrations/metrics/{panel}").status_code == 403

@pytest.mark.parametrize("number", [None, 0, 81.5])
def test_server_numbers(client, number):
    c, payloads, _ = client
    payloads["server"] = {"cpu": {"percent": number}, "memory": {}, "disk": {}, "process": {}}
    result = c.get("/ui/integrations/metrics/server", headers={"Accept": "application/json"}).json()
    assert result["state"] == "data"
    assert result["metrics"][0]["value"] == number
    html = c.get("/ui/integrations/metrics/server").text
    assert "Unknown" in html
    if number is not None:
        assert f"{number:.1f}%" in html
    else:
        assert 'data-ion-style="width:' not in html

@pytest.mark.parametrize("configured,state", [(None, "failed"), (False, "empty"), (True, "data")])
def test_elasticsearch_configuration(client, configured, state):
    c, payloads, _ = client
    payloads["elasticsearch"] = {"configured": configured, "cluster": {}, "indices": {}}
    response = c.get("/ui/integrations/metrics/elasticsearch", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["state"] == state
    html = c.get("/ui/integrations/metrics/elasticsearch").text
    assert ("Not configured" in html) == (configured is False)

@pytest.mark.parametrize("field", ["number_of_nodes", "active_shards", "total_docs", "total_size_mb", "index_total", "search_total"])
@pytest.mark.parametrize("number", [None, 0])
def test_elasticsearch_missing_and_zero(client, field, number):
    c, payloads, _ = client
    section = "cluster" if field in ("number_of_nodes", "active_shards") else "indices"
    payloads["elasticsearch"] = {"configured": True, "cluster": {}, "indices": {}}
    payloads["elasticsearch"][section][field] = number
    result = c.get("/ui/integrations/metrics/elasticsearch", headers={"Accept": "application/json"}).json()
    metrics = result[section]["metrics"]
    metric = next(row for row in metrics if row["key"] == field)
    assert metric["value"] == number
    html = c.get("/ui/integrations/metrics/elasticsearch").text
    assert "Unknown" in html
    if number == 0:
        assert '>0' in html

@pytest.mark.parametrize("failed_section", ["cluster", "indices"])
def test_elasticsearch_panel_failure_independent(client, failed_section):
    c, payloads, _ = client
    payloads["elasticsearch"] = {"configured": True, "cluster": {"status": "green"}, "indices": {"total_docs": 0}}
    payloads["elasticsearch"][failed_section] = {"error": "Unavailable"}
    result = c.get("/ui/integrations/metrics/elasticsearch", headers={"Accept": "application/json"}).json()
    assert result[failed_section]["state"] == "failed"
    assert result["indices" if failed_section == "cluster" else "cluster"]["state"] == "data"

@pytest.mark.parametrize("counts,expected", [(None, None), ({}, 0), ({"200": 0, "500": 0}, 0), ({"200": 8, "404": 1, "500": 1}, 8), ({"200": "bad"}, None)])
def test_log_request_counts(client, counts, expected):
    c, payloads, _ = client
    payloads["server-logs"] = {"configured": True, "total": 0, "by_level": {}, "by_status": counts}
    result = c.get("/ui/integrations/metrics/server-logs", headers={"Accept": "application/json"}).json()
    assert result["state"] == "empty"
    assert next(row["value"] for row in result["metrics"] if row["key"] == "success_count") == expected
    html = c.get("/ui/integrations/metrics/server-logs").text
    assert "No logs in this window" in html
    assert "None%" not in html

@pytest.mark.parametrize("field", ["total", "error", "active_webhooks", "total_webhooks", "total_triggers"])
@pytest.mark.parametrize("number", [None, 0])
def test_flow_missing_and_zero(client, field, number):
    c, payloads, _ = client
    payload = {"integration_activity": {"by_level": {}}, "webhooks": {}}
    if field == "total":
        payload["integration_activity"][field] = number
    elif field == "error":
        payload["integration_activity"]["by_level"][field] = number
    else:
        payload["webhooks"][field] = number
    payloads["data-flows"] = payload
    result = c.get("/ui/integrations/metrics/data-flows", headers={"Accept": "application/json"}).json()
    assert next(row["value"] for row in result["metrics"] if row["key"] == field) == number

@pytest.mark.parametrize("panel", ROUTES)
def test_metadata_not_published(client, panel):
    c, payloads, _ = client
    payloads[panel] = {"configured": True, "cpu": {}, "cluster": {}, "indices": {}, "integration_activity": {}, "webhooks": {}, "metadata": "UNEXPECTED_METADATA"}
    for accept in ("application/json", "text/html"):
        response = c.get(f"/ui/integrations/metrics/{panel}", headers={"Accept": accept})
        assert response.status_code == 200
        assert "UNEXPECTED_METADATA" not in response.text

@pytest.mark.parametrize("section,field,key", [("cpu", "percent", "cpu"), ("memory", "used_percent", "memory"), ("disk", "used_percent", "disk"), ("process", "memory_mb", "process_memory"), ("process", "threads", "threads")])
@pytest.mark.parametrize("number", [None, 0, 5])
def test_every_server_measurement(client, section, field, key, number):
    c, payloads, _ = client
    payloads["server"] = {section: {field: number}}
    result = c.get("/ui/integrations/metrics/server", headers={"Accept": "application/json"}).json()
    assert next(row["value"] for row in result["metrics"] if row["key"] == key) == number

@pytest.mark.parametrize("number", [-1, True, "0", 101])
def test_invalid_server_percentage_is_unknown(client, number):
    c, payloads, _ = client
    payloads["server"] = {"cpu": {"percent": number}}
    result = c.get("/ui/integrations/metrics/server", headers={"Accept": "application/json"}).json()
    assert result["metrics"][0]["value"] is None
    assert 'data-ion-style="width:' not in c.get("/ui/integrations/metrics/server").text

@pytest.mark.parametrize("section,key", [("integration_activity", "total"), ("webhooks", "total_webhooks")])
def test_partial_flow_failure_withholds_stale_counts(client, section, key):
    c, payloads, _ = client
    payloads["data-flows"] = {"integration_activity": {}, "webhooks": {}}
    payloads["data-flows"][section] = {"error": "Unavailable", key: 10}
    result = c.get("/ui/integrations/metrics/data-flows", headers={"Accept": "application/json"}).json()
    assert next(row["value"] for row in result["metrics"] if row["key"] == key) is None

@pytest.mark.parametrize("configured,error,state", [(False, True, "empty"), (None, False, "failed"), (True, True, "failed"), (True, False, "data")])
def test_log_configuration_and_failure(client, configured, error, state):
    c, payloads, _ = client
    payloads["server-logs"] = {"configured": configured}
    if error:
        payloads["server-logs"]["error"] = "Unavailable"
    result = c.get("/ui/integrations/metrics/server-logs", headers={"Accept": "application/json"}).json()
    assert result["state"] == state
    html = c.get("/ui/integrations/metrics/server-logs").text
    assert ("Elasticsearch not configured" in html) == (configured is False)
    if state == "data":
        assert "Unknown" in html
        assert "No logs in this window" not in html

@pytest.mark.parametrize("number", [None, 0, 10])
def test_log_total_and_error_counts(client, number):
    c, payloads, _ = client
    payloads["server-logs"] = {"configured": True, "total": number, "by_level": {"error": number}}
    result = c.get("/ui/integrations/metrics/server-logs", headers={"Accept": "application/json"}).json()
    assert result["state"] == ("empty" if number == 0 else "data")
    assert result["metrics"][0]["value"] == number
    assert result["metrics"][2]["value"] == number


def test_log_rate_and_http_buckets(client):
    c, payloads, _ = client
    payloads["server-logs"] = {"configured": True, "total": 10, "by_status": {"200": 7, "301": 1, "404": 1, "503": 1}}
    result = c.get("/ui/integrations/metrics/server-logs", headers={"Accept": "application/json"}).json()
    values = {row["key"]: row["value"] for row in result["metrics"]}
    assert values["success_rate"] == 80
    assert values["success_count"] == 8
    assert values["client_errors"] == 1
    assert values["server_errors"] == 1
    assert "80.0%" in c.get("/ui/integrations/metrics/server-logs").text


def test_cluster_strings_are_escaped_and_status_allowlisted(client):
    c, payloads, _ = client
    payloads["elasticsearch"] = {"configured": True, "cluster": {"status": "invalid-class", "cluster_name": "<Cluster>"}, "indices": {}}
    result = c.get("/ui/integrations/metrics/elasticsearch", headers={"Accept": "application/json"}).json()
    assert result["cluster"]["status"] is None
    assert result["cluster"]["name"] == "<Cluster>"
    html = c.get("/ui/integrations/metrics/elasticsearch").text
    assert "&lt;Cluster&gt;" in html
    assert "invalid-class" not in html
    assert 'id="es-ingest-metrics-content"' in html
    assert 'hx-swap-oob="innerHTML"' in html

@pytest.mark.parametrize("panel,payload", [
    ("server", {"cpu": {"error": "Unavailable", "percent": 10}}),
    ("elasticsearch", {"configured": True, "cluster": {"error": "Unavailable"}, "indices": {"error": "Unavailable"}}),
    ("data-flows", {"integration_activity": {"error": "Unavailable"}, "webhooks": {"error": "Unavailable"}}),
])
def test_all_components_failed_is_not_data(client, panel, payload):
    c, payloads, _ = client
    payloads[panel] = payload
    result = c.get(f"/ui/integrations/metrics/{panel}", headers={"Accept": "application/json"}).json()
    assert result["state"] == "failed"


def test_partial_server_failure_withholds_stale_percent(client):
    c, payloads, _ = client
    payloads["server"] = {"cpu": {"error": "Unavailable", "percent": 10}, "memory": {"used_percent": 20}}
    result = c.get("/ui/integrations/metrics/server", headers={"Accept": "application/json"}).json()
    assert result["state"] == "data"
    assert result["metrics"][0]["value"] is None
    assert result["metrics"][1]["value"] == 20
