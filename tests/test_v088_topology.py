"""v0.88.0 — Network Topology (NSE view), Phases 0+1.

Covers:
- get_conversations: /api/connections primary (index + inline link shapes,
  zero-byte borrow from the enrichment sample), session-sample fallback,
  noise/garbage endpoint drops,
- _pair_edges: dominant protocol/port by byte share, throughput from the
  observed packet span (None when the span is unknown — never faked),
- topology_metrics_service: /24-/64 subnet assignment, CMDB asset join by
  exact IP, Observable threat join (whitelist/ignore respected, case counts),
- GET /api/arkime/traffic/topology: perms, invalid range, unconfigured 503,
  the 60s per-worker response cache.
"""

import asyncio
import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.models.network_asset import NetworkAsset, NetworkAssetIP
from ion.models.observable import (
    Observable,
    ObservableLink,
    ObservableLinkType,
    ObservableType,
    ThreatLevel,
)
from ion.models.user import User
from ion.services import topology_metrics_service as tms
from ion.services.arkime_service import ArkimeService
from ion.web.api import get_db_session
from ion.web.server import app


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
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.get = AsyncMock(side_effect=list(responses))
    return client


def _run(coro):
    return asyncio.run(coro)


def _session_doc(src, dst, tot=1000, port=443, proto=6, first=1000_000, last=1010_000, packets=10):
    return {
        "srcIp": src, "dstIp": dst, "totBytes": tot, "dstPort": port,
        "ipProtocol": proto, "firstPacket": first, "lastPacket": last,
        "packets": packets,
    }


# ── get_conversations ─────────────────────────────────────────────────────


def test_conversations_connections_primary_with_enrichment():
    sample = {"data": [
        _session_doc("10.0.0.5", "1.2.3.4", tot=5000, port=443, proto=6,
                     first=1_744_689_000_000, last=1_744_689_100_000),  # ms → 100s span
    ]}
    connections = {"nodes": [{"id": "10.0.0.5"}, {"id": "1.2.3.4"}],
                   "links": [{"source": 0, "target": 1, "value": 9, "by": 90_000}]}
    svc = _make_service()
    # get_conversations fetches the enrichment sample first, then connections.
    client = _mock_client([_mock_resp(sample), _mock_resp(connections)])
    with patch.object(svc, "_client", return_value=client):
        out = _run(svc.get_conversations(0, 86400))

    assert out["method"] == "connections"
    assert len(out["edges"]) == 1
    e = out["edges"][0]
    assert (e["src"], e["dst"]) == ("10.0.0.5", "1.2.3.4")
    assert e["bytes"] == 90_000            # connections weight wins
    assert e["sessions"] == 9
    assert e["protocol"] == "tcp"          # enrichment from the sample
    assert e["port"] == 443
    assert e["throughput_bps"] == 50.0     # 5000 bytes / 100 s
    ips = {n["ip"] for n in out["nodes"]}
    assert ips == {"10.0.0.5", "1.2.3.4"}


def test_conversations_inline_link_values_and_byte_borrow():
    # Some builds inline the endpoint value in links and omit byte sizes —
    # the sampled figure fills in so node/edge sizing still works.
    sample = {"data": [_session_doc("10.0.0.5", "1.2.3.4", tot=7777)]}
    connections = {"nodes": [],
                   "links": [{"source": "10.0.0.5", "target": "1.2.3.4", "value": 3}]}
    svc = _make_service()
    client = _mock_client([_mock_resp(sample), _mock_resp(connections)])
    with patch.object(svc, "_client", return_value=client):
        out = _run(svc.get_conversations(0, 86400))
    assert out["method"] == "connections"
    assert out["edges"][0]["bytes"] == 7777


def test_conversations_falls_back_to_sample():
    sample = {"data": [
        _session_doc("10.0.0.5", "1.2.3.4", tot=5000),
        _session_doc("10.0.0.5", "1.2.3.4", tot=3000),
        _session_doc("10.0.0.6", "1.2.3.4", tot=100, port=53, proto=17),
    ]}
    svc = _make_service()
    client = _mock_client([_mock_resp(sample), _mock_resp({}, status_code=500)])
    with patch.object(svc, "_client", return_value=client):
        out = _run(svc.get_conversations(0, 86400))

    assert out["method"] == "sample"
    assert len(out["edges"]) == 2
    top = out["edges"][0]
    assert (top["src"], top["dst"], top["bytes"], top["sessions"]) == (
        "10.0.0.5", "1.2.3.4", 8000, 2)
    assert out["edges"][1]["protocol"] == "udp"


def test_conversations_drops_noise_and_garbage_endpoints():
    sample = {"data": [
        _session_doc("fe80::1", "1.2.3.4"),        # link-local noise
        _session_doc("not-an-ip", "1.2.3.4"),      # unparseable
        _session_doc("10.0.0.5", "10.0.0.5"),      # self-loop
        _session_doc("10.0.0.5", "1.2.3.4"),
    ]}
    svc = _make_service()
    client = _mock_client([_mock_resp(sample), _mock_resp({}, status_code=404)])
    with patch.object(svc, "_client", return_value=client):
        out = _run(svc.get_conversations(0, 86400))
    assert [(e["src"], e["dst"]) for e in out["edges"]] == [("10.0.0.5", "1.2.3.4")]


def test_pair_edges_dominant_and_unknown_span():
    pairs = {
        ("a", "b"): {
            "bytes": 100, "sessions": 2, "packets": 5,
            "protocols": {"tcp": 80, "udp": 20}, "ports": {443: 80, 53: 20},
            "first": None, "last": None,
        },
    }
    (edge,) = ArkimeService._pair_edges(pairs)
    assert edge["protocol"] == "tcp"
    assert edge["port"] == 443
    assert edge["throughput_bps"] is None  # unknown span → no faked rate


# ── metrics service joins ─────────────────────────────────────────────────


def test_subnet_of():
    assert tms._subnet_of("10.50.12.17") == "10.50.12.0/24"
    assert tms._subnet_of("2001:db8::1") == "2001:db8::/64"
    assert tms._subnet_of("garbage") == ""


def test_asset_and_threat_joins(session):
    asset = NetworkAsset(hostname="fs01", display_hostname="FS01",
                         criticality="high", environment="prod",
                         first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    session.add(asset)
    session.flush()
    session.add(NetworkAssetIP(asset_id=asset.id, ip="10.50.20.5",
                               first_seen=datetime.utcnow(), last_seen=datetime.utcnow()))
    obs = Observable(type=ObservableType.IPV4, value="185.220.101.78",
                     normalized_value="185.220.101.78",
                     threat_level=ThreatLevel.HIGH, is_ioc=True)
    ignored = Observable(type=ObservableType.IPV4, value="10.50.20.5",
                         normalized_value="10.50.20.5",
                         threat_level=ThreatLevel.CRITICAL, is_ignored=True)
    session.add_all([obs, ignored])
    session.flush()
    session.add_all([
        ObservableLink(observable_id=obs.id, link_type=ObservableLinkType.CASE,
                       entity_id=1, context="src_ip"),
        ObservableLink(observable_id=obs.id, link_type=ObservableLinkType.CASE,
                       entity_id=2, context="src_ip"),
        ObservableLink(observable_id=obs.id, link_type=ObservableLinkType.ALERT,
                       entity_id=9, context="src_ip"),
    ])
    session.commit()

    ips = ["10.50.20.5", "185.220.101.78", "8.8.8.8"]
    assets = tms._assets_by_ip(session, ips)
    assert assets == {"10.50.20.5": {
        "asset_id": asset.id, "hostname": "FS01",
        "criticality": "high", "environment": "prod",
    }}
    threats = tms._threat_by_ip(session, ips)
    # The ignored observable must not surface; alert links don't count as cases.
    assert set(threats) == {"185.220.101.78"}
    t = threats["185.220.101.78"]
    assert t["malicious"] is True and t["level"] == "high"
    assert t["is_ioc"] is True and t["case_count"] == 2


def test_build_topology_shapes_payload(session, monkeypatch):
    class _Fake:
        async def get_conversations(self, *a, **k):
            return {
                "nodes": [
                    {"ip": "10.50.12.17", "bytes": 500, "sessions": 3},
                    {"ip": "185.220.101.78", "bytes": 500, "sessions": 3},
                ],
                "edges": [{
                    "src": "10.50.12.17", "dst": "185.220.101.78",
                    "bytes": 500, "sessions": 3, "packets": 40,
                    "protocol": "tcp", "port": 443, "throughput_bps": 12.5,
                }],
                "method": "connections",
            }

    monkeypatch.setattr(tms, "get_arkime_service", lambda: _Fake())
    out = _run(tms.build_topology(session, 0, 86400))

    n = {x["ip"]: x for x in out["nodes"]}
    assert n["10.50.12.17"]["subnet"] == "10.50.12.0/24"
    assert n["10.50.12.17"]["private"] is True
    assert n["185.220.101.78"]["private"] is False
    assert out["edges"][0]["arkime_url"] == ""  # Arkime unconfigured in tests
    assert out["metrics"]["active_conversations"] == 1
    assert out["metrics"]["port_distribution"] == [{"port": 443, "bytes": 500}]
    assert {u["metric"] for u in out["unavailable"]} >= {"RTT / latency", "Packet loss"}


# ── API endpoint ──────────────────────────────────────────────────────────


def _api_client(session, perms):
    user = User(id=1, username="analyst", email="a@x", password_hash="x",
                display_name="Analyst", is_active=True)
    user.has_permission = lambda p: p in perms  # type: ignore[method-assign]
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: session
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clear_state():
    yield
    app.dependency_overrides.clear()
    from ion.web import arkime_traffic_analytics_api as api
    api._topology_cache.clear()


def test_topology_requires_alert_read(session):
    r = _api_client(session, perms=set()).get("/api/arkime/traffic/topology")
    assert r.status_code == 403


def test_topology_invalid_range(session, monkeypatch):
    monkeypatch.setattr(
        "ion.web.arkime_traffic_analytics_api.get_arkime_service",
        lambda: MagicMock(is_configured=True),
    )
    r = _api_client(session, perms={"alert:read"}).get(
        "/api/arkime/traffic/topology?range=90d")
    assert r.status_code == 400


def test_topology_unconfigured_503(session, monkeypatch):
    monkeypatch.setattr(
        "ion.web.arkime_traffic_analytics_api.get_arkime_service",
        lambda: MagicMock(is_configured=False),
    )
    r = _api_client(session, perms={"alert:read"}).get("/api/arkime/traffic/topology")
    assert r.status_code == 503


def test_topology_happy_path_and_cache(session, monkeypatch):
    svc = MagicMock(is_configured=True)
    svc.build_exclusion_expression.return_value = ""
    svc._RFC1918_EXPR = ArkimeService._RFC1918_EXPR
    monkeypatch.setattr(
        "ion.web.arkime_traffic_analytics_api.get_arkime_service", lambda: svc)

    calls = {"n": 0}

    async def _fake_build(session_, start_ts, stop_ts, expression=None, limit=200):
        calls["n"] += 1
        return {"nodes": [], "edges": [], "metrics": {"active_conversations": 0,
                "hosts": 0, "port_distribution": [], "method": "sample"},
                "unavailable": tms.UNAVAILABLE_METRICS}

    monkeypatch.setattr(tms, "build_topology", _fake_build)
    client = _api_client(session, perms={"alert:read"})
    r1 = client.get("/api/arkime/traffic/topology?range=24h")
    assert r1.status_code == 200, r1.text
    assert r1.json()["range"] == "24h"
    r2 = client.get("/api/arkime/traffic/topology?range=24h")
    assert r2.status_code == 200
    assert calls["n"] == 1  # second hit served from the 60s cache
    # A different (range, exclude_private) key computes fresh.
    r3 = client.get("/api/arkime/traffic/topology?range=24h&exclude_private=true")
    assert r3.status_code == 200
    assert calls["n"] == 2
