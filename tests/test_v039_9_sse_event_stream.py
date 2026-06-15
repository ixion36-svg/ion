"""Tests for the v0.39.9 SSE change-notification channel.

Covers:
- env flag / cadence parsing (`sse_enabled`, `_env_int`)
- topic registry validation
- the investigations *signature* function reacts to state changes
- SSE frame formatting
- the async `event_generator` primes a connect with retry + refresh
- the HTTP endpoint's status-code contract (503 disabled / 401 unauth /
  404 unknown topic) — chosen so the browser EventSource goes CLOSED and the
  client helper falls back to polling.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import ion.services.event_stream as es
from ion.models.investigation import Investigation  # registers table on Base.metadata
from ion.web.events_api import router as events_router

# ---------------------------------------------------------------------------
# Env flag + cadence parsing
# ---------------------------------------------------------------------------


class TestEnvParsing:
    def test_sse_enabled_default_on(self, monkeypatch):
        monkeypatch.delenv("ION_SSE_ENABLED", raising=False)
        assert es.sse_enabled() is True

    @pytest.mark.parametrize("val", ["false", "0", "no", "off", "FALSE", "Off"])
    def test_sse_disabled_values(self, monkeypatch, val):
        monkeypatch.setenv("ION_SSE_ENABLED", val)
        assert es.sse_enabled() is False

    def test_sse_enabled_truthy_values(self, monkeypatch):
        monkeypatch.setenv("ION_SSE_ENABLED", "true")
        assert es.sse_enabled() is True

    def test_env_int_override(self, monkeypatch):
        monkeypatch.setenv("ION_SSE_POLL_INTERVAL", "9")
        assert es._sig_poll_secs() == 9

    def test_env_int_junk_falls_back(self, monkeypatch):
        monkeypatch.setenv("ION_SSE_POLL_INTERVAL", "not-a-number")
        assert es._sig_poll_secs() == 4

    def test_env_int_rejects_nonpositive(self, monkeypatch):
        monkeypatch.setenv("ION_SSE_HEARTBEAT", "0")
        assert es._heartbeat_secs() == 25
        monkeypatch.setenv("ION_SSE_HEARTBEAT", "-5")
        assert es._heartbeat_secs() == 25


# ---------------------------------------------------------------------------
# Topic registry
# ---------------------------------------------------------------------------


class TestTopicRegistry:
    @pytest.mark.parametrize(
        "name", ["investigations", "alerts", "dashboard", "integrations"]
    )
    def test_known_topics(self, name):
        assert es.is_valid_topic(name) is True

    def test_unknown_topic(self):
        assert es.is_valid_topic("nope") is False
        assert es.is_valid_topic("") is False

    def test_investigations_is_signature_topic(self):
        assert es._topics()["investigations"].signature_fn is not None

    def test_dashboard_is_interval_topic(self):
        assert es._topics()["dashboard"].signature_fn is None

    def test_interval_env_override(self, monkeypatch):
        monkeypatch.setenv("ION_SSE_DASHBOARD_INTERVAL", "12")
        assert es._topics()["dashboard"].interval == 12


# ---------------------------------------------------------------------------
# Signature function
# ---------------------------------------------------------------------------


class TestInvestigationSignature:
    def _mk(self, status="pending"):
        return Investigation(
            alert_id_ref="es-alert-1",
            alert_signature="Suspicious login",
            status=status,
        )

    def test_empty_table_signature_is_stable(self, session):
        assert es._sig_investigations(session) == es._sig_investigations(session)

    def test_new_investigation_changes_signature(self, session):
        before = es._sig_investigations(session)
        session.add(self._mk())
        session.commit()
        after = es._sig_investigations(session)
        assert before != after

    def test_status_transition_changes_signature(self, session):
        inv = self._mk(status="pending")
        session.add(inv)
        session.commit()
        sig_pending = es._sig_investigations(session)

        inv.status = "completed"
        inv.completed_at = datetime.now(timezone.utc)
        session.commit()
        sig_completed = es._sig_investigations(session)
        assert sig_pending != sig_completed

    def test_signature_is_stable_without_changes(self, session):
        session.add(self._mk())
        session.commit()
        assert es._sig_investigations(session) == es._sig_investigations(session)


# ---------------------------------------------------------------------------
# SSE frame formatting + generator priming
# ---------------------------------------------------------------------------


class TestSseFraming:
    def test_sse_frame_format(self):
        frame = es._sse("refresh", "change")
        assert frame == b"event: refresh\ndata: change\n\n"

    def test_heartbeat_is_comment(self):
        assert es._HEARTBEAT_FRAME.startswith(b":")
        assert es._HEARTBEAT_FRAME.endswith(b"\n\n")


class _FakeRequest:
    """Minimal stand-in for starlette Request in the generator."""

    def __init__(self, disconnected=False):
        self._disconnected = disconnected

    async def is_disconnected(self):
        return self._disconnected


class TestEventGenerator:
    def test_generator_primes_retry_and_refresh(self):
        """First two frames on connect: retry directive + an initial refresh.

        Uses an interval topic ('dashboard') so no DB session is opened, and
        closes the generator before its first sleep so the test is instant.
        """

        async def drive():
            gen = es.event_generator(_FakeRequest(), "dashboard")
            first = await gen.__anext__()
            second = await gen.__anext__()
            await gen.aclose()
            return first, second

        first, second = asyncio.run(drive())
        assert first == b"retry: 5000\n\n"
        assert second == es._sse("refresh", "init")


# ---------------------------------------------------------------------------
# HTTP endpoint status-code contract
# ---------------------------------------------------------------------------


def _app():
    app = FastAPI()
    app.include_router(events_router)
    return app


class TestEndpointContract:
    def test_503_when_disabled(self, monkeypatch):
        monkeypatch.setattr(es, "sse_enabled", lambda: False)
        client = TestClient(_app())
        resp = client.get("/api/events/stream?topic=dashboard")
        assert resp.status_code == 503

    def test_401_when_unauthenticated(self, monkeypatch):
        monkeypatch.setattr(es, "sse_enabled", lambda: True)
        # No session cookie / bearer -> _authenticate returns False.
        client = TestClient(_app())
        resp = client.get("/api/events/stream?topic=dashboard")
        assert resp.status_code == 401

    def test_404_unknown_topic_when_authed(self, monkeypatch):
        import ion.web.events_api as events_api

        monkeypatch.setattr(es, "sse_enabled", lambda: True)
        monkeypatch.setattr(events_api, "_authenticate", lambda request: True)
        client = TestClient(_app())
        resp = client.get("/api/events/stream?topic=bogus")
        assert resp.status_code == 404

    def test_missing_topic_param_is_422(self, monkeypatch):
        monkeypatch.setattr(es, "sse_enabled", lambda: True)
        client = TestClient(_app())
        resp = client.get("/api/events/stream")
        assert resp.status_code == 422
