"""Prometheus /metrics endpoint — opt-in gating, token, and exposition content.

The endpoint is mounted always but 404s unless ION_METRICS_ENABLED. Tested in
isolation on a minimal app (the full ION app is heavy and the metrics are
module-global singletons).
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.metrics_api import router as metrics_router


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(metrics_router)
    return TestClient(app, raise_server_exceptions=False)


def test_metrics_404_when_disabled(monkeypatch):
    monkeypatch.delenv("ION_METRICS_ENABLED", raising=False)
    assert _client().get("/metrics").status_code == 404


def test_metrics_200_and_content_when_enabled(monkeypatch):
    monkeypatch.setenv("ION_METRICS_ENABLED", "true")
    monkeypatch.delenv("ION_METRICS_TOKEN", raising=False)
    r = _client().get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    body = r.text
    assert "ion_build_info" in body
    # circuit breakers are module-global (created at import of circuit_breaker.py)
    assert "ion_circuit_breaker_state" in body
    assert "ion_http_request_duration_seconds" in body  # histogram registered


def test_metrics_token_gate(monkeypatch):
    monkeypatch.setenv("ION_METRICS_ENABLED", "true")
    monkeypatch.setenv("ION_METRICS_TOKEN", "s3cret")
    c = _client()
    assert c.get("/metrics").status_code == 401
    assert c.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/metrics", headers={"Authorization": "Bearer s3cret"}).status_code == 200


def test_middleware_records_request(monkeypatch):
    monkeypatch.setenv("ION_METRICS_ENABLED", "true")
    monkeypatch.delenv("ION_METRICS_TOKEN", raising=False)
    from ion.web.metrics_api import PrometheusMiddleware

    app = FastAPI()
    app.add_middleware(PrometheusMiddleware)
    app.include_router(metrics_router)

    @app.get("/ping")
    def ping():
        return {"ok": True}

    c = TestClient(app, raise_server_exceptions=False)
    c.get("/ping")
    body = c.get("/metrics").text
    # labelled by the route TEMPLATE (bounded cardinality), not the raw path
    assert 'route="/ping"' in body and "ion_http_requests_total" in body


if __name__ == "__main__":
    import sys

    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
