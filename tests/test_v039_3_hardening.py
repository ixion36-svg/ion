"""v0.39.3 external-pentest hardening — regression tests.

Covers the new controls, all of which ship OPT-IN (default off):
  F1/F2  unified, trusted-proxy-aware client-IP derivation
  F3     ION_WEBHOOK_REQUIRE_SIGNATURE gate
  F5     ION_IP_BLOCKING_ENABLED + config plumbing
  F7     generic Server header

The defaults are themselves part of the contract: a v0.39.3 image must not
change behaviour until an operator opts in.
"""

import asyncio
import ipaddress

from ion.core import client_ip as cip
from ion.core.config import Config
from ion.storage.database import reset_engine


# ---------------------------------------------------------------------------
# Fake request — client_ip only touches request.client.host + request.headers
# ---------------------------------------------------------------------------
class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeReq:
    def __init__(self, peer, headers=None):
        self.client = _FakeClient(peer) if peer is not None else None
        self.headers = headers or {}


def _nets(*cidrs):
    return [ipaddress.ip_network(c, strict=False) for c in cidrs]


# ---------------------------------------------------------------------------
# F1/F2 — client-IP derivation
# ---------------------------------------------------------------------------
def test_untrusted_peer_ignores_forwarded_header(monkeypatch):
    """The whole point: an external client cannot spoof its source IP."""
    monkeypatch.setattr(cip, "_TRUSTED_PROXIES", [])  # no proxies trusted
    req = _FakeReq("203.0.113.9", {"X-Forwarded-For": "127.0.0.1, 10.1.2.3"})
    assert cip.get_client_ip(req) == "203.0.113.9"  # peer, not the spoofed XFF


def test_trusted_peer_returns_real_client_behind_proxy(monkeypatch):
    """When the peer IS the ingress, walk XFF right-to-left to the real client."""
    monkeypatch.setattr(cip, "_TRUSTED_PROXIES", _nets("10.0.0.0/8"))
    req = _FakeReq("10.0.0.5", {"X-Forwarded-For": "198.51.100.7, 10.0.0.9"})
    assert cip.get_client_ip(req) == "198.51.100.7"


def test_trusted_peer_falls_back_to_x_real_ip(monkeypatch):
    monkeypatch.setattr(cip, "_TRUSTED_PROXIES", _nets("10.0.0.0/8"))
    req = _FakeReq("10.0.0.5", {"X-Real-IP": "198.51.100.42"})
    assert cip.get_client_ip(req) == "198.51.100.42"


def test_is_trusted_proxy_handles_garbage(monkeypatch):
    monkeypatch.setattr(cip, "_TRUSTED_PROXIES", _nets("10.0.0.0/8"))
    assert cip.is_trusted_proxy("10.0.0.1") is True
    assert cip.is_trusted_proxy("8.8.8.8") is False
    assert cip.is_trusted_proxy("not-an-ip") is False


def test_auth_layer_get_client_ip_is_the_shared_one():
    """dependencies.get_client_ip must be the canonical implementation."""
    from ion.auth.dependencies import get_client_ip as dep_get
    assert dep_get is cip.get_client_ip


# ---------------------------------------------------------------------------
# Config — opt-in defaults (the "disabled by default" contract)
# ---------------------------------------------------------------------------
def test_new_security_flags_default_off():
    c = Config()
    assert c.ip_blocking_enabled is False
    assert c.webhook_require_signature is False


def test_flags_are_settable_fields():
    c = Config(ip_blocking_enabled=True, webhook_require_signature=True)
    assert c.ip_blocking_enabled is True
    assert c.webhook_require_signature is True


# ---------------------------------------------------------------------------
# F7 — Server header no longer discloses uvicorn
# ---------------------------------------------------------------------------
def test_server_header_is_generic(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *a, **k: temp_db)
    reset_engine()
    from fastapi.testclient import TestClient

    from ion.web.server import app

    resp = TestClient(app).get("/api/health")
    assert resp.headers.get("server") == "ION"
    reset_engine()


# ---------------------------------------------------------------------------
# F3 — webhook signature requirement (opt-in)
# ---------------------------------------------------------------------------
def _seed_secretless_webhook(temp_db, token):
    from sqlalchemy.orm import sessionmaker

    from ion.models.integration import Webhook

    Webhook.metadata.create_all(temp_db)  # ensure webhooks + event tables exist
    Session = sessionmaker(bind=temp_db)
    s = Session()
    s.add(Webhook(name="t", token=token, secret=None, is_active=True))
    s.commit()
    s.close()


def _run_webhook(token):
    from ion.services.webhook_service import get_webhook_service

    svc = get_webhook_service()
    return asyncio.run(
        svc.process_webhook(
            token=token,
            event_type="ping",
            payload={},
            headers={},
            source_ip="203.0.113.1",
            signature=None,
            raw_payload=b"{}",
        )
    )


def test_secretless_webhook_allowed_when_flag_off(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *a, **k: temp_db)
    reset_engine()
    from ion.core.config import get_config

    monkeypatch.setattr(get_config(), "webhook_require_signature", False)
    _seed_secretless_webhook(temp_db, "tok-off")
    result = _run_webhook("tok-off")
    # Not rejected for a missing secret (may fail later for no handler — that's fine).
    assert result.get("status") != "invalid_signature"
    reset_engine()


def test_secretless_webhook_rejected_when_flag_on(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *a, **k: temp_db)
    reset_engine()
    from ion.core.config import get_config

    monkeypatch.setattr(get_config(), "webhook_require_signature", True)
    _seed_secretless_webhook(temp_db, "tok-on")
    result = _run_webhook("tok-on")
    assert result["success"] is False
    assert result["status"] == "invalid_signature"
    reset_engine()
