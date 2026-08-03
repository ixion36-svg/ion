"""v0.65.0 — Arkime Traffic Analytics: noise-IP filtering, spigraph country
aggregation, and the Real-Time Monitor (RTMON) summary endpoint.

Covers:
- ArkimeService._is_noise_ip drops IPv6 link-local / loopback / unspecified +
  IPv4 link-local, keeps public + RFC-1918 addresses,
- get_top_talkers excludes noise endpoints from the ranking,
- get_top_countries uses /api/spigraph server-side buckets and falls back to the
  legacy session-sampling method on error,
- the /rtmon-summary endpoint returns the per-detector / per-severity / daily
  shape from arkime-rtmon cases, an empty-but-valid shape when RTMON never ran,
  and is gated behind alert:read.
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage
from ion.models.user import User
from ion.services.arkime_service import ArkimeError, ArkimeService
from ion.web.api import get_db_session
from ion.web.arkime_traffic_analytics_api import _rtmon_detector
from ion.web.server import app

_NAIVE_NOW = datetime.now(timezone.utc).replace(tzinfo=None)


# ── helpers ──────────────────────────────────────────────────────────────


def _make_service(url="http://ark:8005", user="admin", pwd="pass"):
    svc = ArkimeService.__new__(ArkimeService)
    svc.url = url
    svc.username = user
    svc.password = pwd
    svc.verify_ssl = False
    return svc


def _mock_resp(payload: dict, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"content-type": "application/json"}
    resp.json.return_value = payload
    resp.text = json.dumps(payload)
    return resp


def _mock_client(responses):
    """AsyncClient whose .get returns each response in turn (side_effect)."""
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.get = AsyncMock(side_effect=list(responses))
    return client


def _run(coro):
    return asyncio.run(coro)


# ── #4  _is_noise_ip ─────────────────────────────────────────────────────


def test_is_noise_ip_drops_link_local_loopback_unspecified():
    assert ArkimeService._is_noise_ip("fe80::1") is True      # IPv6 link-local
    assert ArkimeService._is_noise_ip("::1") is True          # IPv6 loopback
    assert ArkimeService._is_noise_ip("::") is True           # unspecified
    assert ArkimeService._is_noise_ip("169.254.1.1") is True  # IPv4 link-local
    assert ArkimeService._is_noise_ip("127.0.0.1") is True    # IPv4 loopback


def test_is_noise_ip_keeps_public_and_rfc1918():
    assert ArkimeService._is_noise_ip("8.8.8.8") is False
    assert ArkimeService._is_noise_ip("203.0.113.5") is False
    assert ArkimeService._is_noise_ip("10.0.0.5") is False
    assert ArkimeService._is_noise_ip("192.168.1.1") is False


def test_is_noise_ip_bad_input_is_not_noise():
    assert ArkimeService._is_noise_ip("not-an-ip") is False
    assert ArkimeService._is_noise_ip("") is False


# ── #4  get_top_talkers excludes noise endpoints ─────────────────────────


def test_top_talkers_excludes_noise_ips():
    payload = {"data": [
        {"srcIp": "203.0.113.5", "dstIp": "8.8.8.8", "totBytes": 1000},
        {"srcIp": "fe80::1",     "dstIp": "8.8.8.8", "totBytes": 500},   # src is noise
        {"srcIp": "9.9.9.9",     "dstIp": "::1",     "totBytes": 700},   # dst is noise
        {"srcIp": "169.254.1.1", "dstIp": "1.1.1.1", "totBytes": 300},   # src is noise
    ]}
    svc = _make_service()
    client = _mock_client([_mock_resp(payload)])
    with patch.object(svc, "_client", return_value=client):
        result = _run(svc.get_top_talkers(0, 86400, limit=10))

    src_ips = {r["ip"] for r in result["by_src"]}
    dst_ips = {r["ip"] for r in result["by_dst"]}
    assert src_ips == {"203.0.113.5", "9.9.9.9"}   # fe80::1 + 169.254.1.1 dropped
    assert dst_ips == {"8.8.8.8", "1.1.1.1"}        # ::1 dropped
    # 8.8.8.8 still aggregates the byte/session totals from the two real flows.
    dst_8888 = next(r for r in result["by_dst"] if r["ip"] == "8.8.8.8")
    assert dst_8888["bytes"] == 1500 and dst_8888["sessions"] == 2


# ── #2  get_top_countries via spigraph + fallback ────────────────────────


def test_top_countries_spigraph_parses_buckets():
    src_payload = {"items": [
        {"name": "us", "count": 10, "size": 5000},
        {"name": "de", "count": 4, "size": 2000},
    ]}
    dst_payload = {"items": [{"name": "cn", "count": 6, "size": 3000}]}
    svc = _make_service()
    client = _mock_client([_mock_resp(src_payload), _mock_resp(dst_payload)])
    with patch.object(svc, "_client", return_value=client):
        result = _run(svc.get_top_countries(0, 86400, limit=15))

    assert result["by_src"] == [
        {"country": "US", "bytes": 5000, "sessions": 10},
        {"country": "DE", "bytes": 2000, "sessions": 4},
    ]
    assert result["by_dst"] == [{"country": "CN", "bytes": 3000, "sessions": 6}]


def test_top_countries_falls_back_on_spigraph_error():
    # First (spigraph country.src) request 404s → fall back to session sampling.
    err = _mock_resp({}, status_code=404)
    sessions = _mock_resp({"data": [
        {"srcGEO": "us", "dstGEO": "de", "totBytes": 1234},
    ]})
    svc = _make_service()
    client = _mock_client([err, sessions])
    with patch.object(svc, "_client", return_value=client):
        result = _run(svc.get_top_countries(0, 86400, limit=15))

    assert result["by_src"] == [{"country": "US", "bytes": 1234, "sessions": 1}]
    assert result["by_dst"] == [{"country": "DE", "bytes": 1234, "sessions": 1}]


def test_top_countries_not_configured_raises():
    svc = _make_service(url="")
    with pytest.raises(ArkimeError):
        _run(svc.get_top_countries(0, 86400))


# ── #3  RTMON detector parsing ───────────────────────────────────────────


def test_rtmon_detector_parse():
    assert _rtmon_detector("rtmon:c2_beacon_shape:node:cid") == "c2_beacon_shape"
    assert _rtmon_detector("rtmon:beacon:10.0.0.5:45.77.198.50:443") == "beacon"
    assert _rtmon_detector("rtmon:cleartext_credentials:cap01:1:abc=") == "cleartext_credentials"
    assert _rtmon_detector("garbage") == "other"
    assert _rtmon_detector("") == "other"
    assert _rtmon_detector(None) == "other"


# ── #3  RTMON summary endpoint ───────────────────────────────────────────


def _rtmon_case(session, num, marker, *, severity, days_ago, source="arkime-rtmon"):
    c = AlertCase(
        case_number=num, title=f"rtmon {num}", created_by_id=1,
        status=AlertCaseStatus.OPEN, severity=severity,
    )
    session.add(c)
    session.flush()
    c.created_at = _NAIVE_NOW - timedelta(days=days_ago)
    session.add(AlertTriage(es_alert_id=marker, case_id=c.id, source_system=source))
    session.flush()
    return c


def _client(session, perms):
    user = User(id=1, username="analyst", email="a@x", password_hash="x",
                display_name="Analyst", is_active=True)
    user.has_permission = lambda p: p in perms  # type: ignore[method-assign]
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: session
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.clear()


def test_rtmon_summary_requires_alert_read(session):
    r = _client(session, perms=set()).get("/api/arkime/traffic/rtmon-summary")
    assert r.status_code == 403


def test_rtmon_summary_empty_shape(session):
    r = _client(session, perms={"alert:read"}).get("/api/arkime/traffic/rtmon-summary?days=7")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 0
    assert body["by_detector"] == []
    assert body["by_severity"] == []
    assert body["enabled"] is False
    assert isinstance(body["daily"], list) and len(body["daily"]) == 7
    assert all(d["count"] == 0 for d in body["daily"])


def test_rtmon_summary_aggregates(session):
    _rtmon_case(session, "R-1", "rtmon:c2_beacon_shape:n:c1", severity="high", days_ago=1)
    _rtmon_case(session, "R-2", "rtmon:c2_beacon_shape:n:c2", severity="high", days_ago=2)
    _rtmon_case(session, "R-3", "rtmon:cleartext_credentials:n:c3", severity="critical", days_ago=1)
    _rtmon_case(session, "R-4", "rtmon:beacon:10.0.0.5:1.2.3.4:443", severity="medium", days_ago=3)
    _rtmon_case(session, "R-5", "garbage-marker", severity="high", days_ago=2)
    # Outside the window (excluded when days=7):
    _rtmon_case(session, "R-old", "rtmon:ioc_ip:n:c9", severity="high", days_ago=40)
    # Non-RTMON case (excluded by source_system filter):
    _rtmon_case(session, "R-other", "es-alert-1", severity="high", days_ago=1, source="elastic")
    session.commit()

    r = _client(session, perms={"alert:read"}).get("/api/arkime/traffic/rtmon-summary?days=7")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 5
    assert body["enabled"] is True

    detectors = {d["detector"]: d["count"] for d in body["by_detector"]}
    assert detectors == {
        "c2_beacon_shape": 2,
        "cleartext_credentials": 1,
        "beacon": 1,
        "other": 1,  # 'garbage-marker' collapses to other
    }
    severities = {s["severity"]: s["count"] for s in body["by_severity"]}
    assert severities == {"high": 3, "critical": 1, "medium": 1}

    assert len(body["daily"]) == 7
    assert sum(d["count"] for d in body["daily"]) == 5
