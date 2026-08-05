"""v0.76.0 — `/api/integrations/status` no longer 500s the whole page.

Reported from a live v0.50.2 deployment: the `/integrations` page showed
"Error: Failed to load integrations", with the browser console recording a **500
on `integrations:1389`** — which is exactly the `fetch('/api/integrations/status')`
line in that build's served HTML — followed by
`net::ERR_INCOMPLETE_CHUNKED_ENCODING` on the document itself (an in-flight
response on the same connection getting cut when the worker unwound).

`git diff v0.50.2..HEAD` over `integration_api.py`, `services/connectors/`,
`integration_log_service.py` and `models/integration.py` is **empty** — the
reporting deployment runs identical code to today, so this was never a version
problem and upgrading alone would not have fixed it. It is data- and
environment-dependent, which is why it did not reproduce on a clean database.

Two independent faults, both of which take down the entire endpoint:

1. **The metadata merge assumed a mapping.** `check_metadata` is the `details`
   JSON column, annotated `Optional[dict]` but shared by every IntegrationEvent
   kind, with nothing at the DB level constraining it to an object. Any
   non-mapping JSON value there made `{**meta}` raise
   `TypeError: 'X' object is not a mapping`.

2. **No per-connector isolation.** The endpoint aggregates 6+ independent
   integrations and backs the whole page. One connector raising inside
   `get_status_info()` — the kind of thing a half-configured service does —
   killed the response for all of them. So a single misconfigured integration
   blanked the page whose entire job is to tell you which integration is
   misconfigured.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from ion.models.integration import (
    IntegrationEvent,
    IntegrationEventType,
    IntegrationStatus,
    IntegrationType,
)
from ion.models.user import User
from ion.services.connectors import get_connector_registry
from ion.storage.database import get_session_factory
from ion.web.integration_api import require_integration_access
from ion.web.server import app


@pytest.fixture
def client():
    user = User(id=1, username="admin", email="a@b", password_hash="x",
                display_name="Admin", is_active=True)
    app.dependency_overrides[require_integration_access] = lambda: user
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.clear()


def _seed_health_check(details) -> None:
    """Replace all health-check events with one carrying `details`."""
    session = get_session_factory()()
    try:
        session.query(IntegrationEvent).filter(
            IntegrationEvent.event_type == IntegrationEventType.HEALTH_CHECK
        ).delete()
        session.add(IntegrationEvent(
            event_type=IntegrationEventType.HEALTH_CHECK,
            integration_type=IntegrationType.ELASTICSEARCH,
            health_status=IntegrationStatus.HEALTHY,
            response_time_ms=10.0,
            details=details,
        ))
        session.commit()
    finally:
        session.close()


# ── fault 1: non-mapping details ─────────────────────────────────────────


@pytest.mark.parametrize("details", [
    pytest.param([{"connected": True}], id="list"),
    pytest.param("connected", id="string"),
    pytest.param(42, id="number"),
    pytest.param(True, id="bool"),
])
def test_non_mapping_details_does_not_500(client, details):
    """Each of these raised `TypeError: 'X' object is not a mapping` out of the
    `**` unpack and surfaced as a bare 500 on the endpoint backing the page."""
    _seed_health_check(details)
    resp = client.get("/api/integrations/status")
    assert resp.status_code == 200, resp.text


@pytest.mark.parametrize("details", [
    pytest.param([{"connected": True}], id="list"),
    pytest.param("connected", id="string"),
    pytest.param(42, id="number"),
])
def test_non_mapping_details_is_surfaced_not_swallowed(client, details):
    """A non-object payload means something wrote the column wrong. Silently
    dropping it would hide that; it goes under `raw_details`."""
    _seed_health_check(details)
    rows = client.get("/api/integrations/status").json()
    es = next(r for r in rows if r["type"] == "elasticsearch")
    assert es["metadata"]["raw_details"] == details


def test_mapping_details_still_merges_normally(client):
    """The fix must not change the behaviour of the normal path — a dict is
    still flattened into metadata, not nested under raw_details."""
    _seed_health_check({"connected": True, "version": "8.12.0"})
    rows = client.get("/api/integrations/status").json()
    es = next(r for r in rows if r["type"] == "elasticsearch")
    assert es["metadata"]["version"] == "8.12.0"
    assert "raw_details" not in es["metadata"]
    assert es["status"] == "healthy"


def test_absent_health_check_leaves_status_unset(client):
    """No health check yet is not an error — the card renders as un-checked."""
    session = get_session_factory()()
    try:
        session.query(IntegrationEvent).filter(
            IntegrationEvent.event_type == IntegrationEventType.HEALTH_CHECK
        ).delete()
        session.commit()
    finally:
        session.close()

    rows = client.get("/api/integrations/status").json()
    es = next(r for r in rows if r["type"] == "elasticsearch")
    assert es["status"] is None
    assert es["last_check"] is None


# ── fault 2: one connector must not sink the rest ────────────────────────


def test_one_broken_connector_does_not_break_the_page(client):
    """The page exists to report which integration is unhealthy. A connector
    that cannot describe itself must become one broken card, not a blank page."""
    registry = get_connector_registry()
    connectors = registry.get_all()
    victim = connectors[0]
    original = victim.get_status_info

    def boom():
        # The shape of a real half-configured service.
        raise AttributeError("'NoneType' object has no attribute '_running'")

    victim.get_status_info = boom
    try:
        resp = client.get("/api/integrations/status")
        assert resp.status_code == 200, resp.text
        rows = resp.json()
        assert len(rows) == len(connectors), "every connector still gets a row"

        broken = next(r for r in rows if r["type"] == victim.CONNECTOR_TYPE)
        assert broken["status"] == IntegrationStatus.ERROR.value
        assert "Status unavailable" in broken["error"]

        healthy = [r for r in rows if r["type"] != victim.CONNECTOR_TYPE]
        assert all(r["error"] is None for r in healthy), \
            "a fault in one connector must not mark the others errored"
    finally:
        victim.get_status_info = original


def test_broken_connector_error_does_not_leak_internals(client):
    """The error reaches an authenticated analyst's screen, so it goes through
    safe_error() — no file paths, library internals, or stack frames."""
    registry = get_connector_registry()
    victim = registry.get_all()[0]
    original = victim.get_status_info

    def boom():
        raise RuntimeError(r"failed opening C:\Users\svc\secrets\es-ca.pem line 42")

    victim.get_status_info = boom
    try:
        rows = client.get("/api/integrations/status").json()
        broken = next(r for r in rows if r["type"] == victim.CONNECTOR_TYPE)
        assert "secrets" not in broken["error"]
        assert ".pem" not in broken["error"]
    finally:
        victim.get_status_info = original
