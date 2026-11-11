"""ION reads Arkime 5 sessions through the real client.

Arkime 3+ names session fields after ECS (source.ip, network.community_id)
and passes `fields=` straight to Elasticsearch, so the Moloch-era names ION
asked for came back empty and every RTMON detector dropped every session.
These tests drive ArkimeService against a mocked viewer that answers the way
Arkime 5.4 does, in both the dotted (flatten=1) and nested shapes.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

import ion.services.arkime_realtime_monitor_service as rtmon
from ion.services import arkime_service as ark

FTP_DOTTED = {
    "id": "260101-abc", "node": "sensor1", "network.community_id": "1:ftpflow=",
    "source.ip": "10.20.4.17", "destination.ip": "10.20.9.31", "source.port": 51515,
    "destination.port": 21, "network.bytes": 4200, "firstPacket": 1_800_000_000_000,
    "protocol": ["ftp", "tcp"], "user": ["svc-backup"],
}
FTP_NESTED = {
    "id": "260101-def", "node": "sensor1", "network": {"community_id": "1:nested=", "bytes": 900},
    "source": {"ip": "10.20.4.18", "port": 51516}, "destination": {"ip": "10.20.9.31", "port": 21},
    "protocol": ["ftp", "tcp"], "user": ["svc-ops"],
}


def _service(monkeypatch, payload, seen):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.url.params))
        return httpx.Response(200, json=payload)

    svc = ark.ArkimeService(url="http://arkime.test", username="u", password="p", verify_ssl=False)

    async def _client():
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(svc, "_client", _client)
    return svc


@pytest.mark.parametrize("session", [FTP_DOTTED, FTP_NESTED], ids=["flatten", "nested"])
def test_an_arkime5_session_reaches_the_cleartext_detector(monkeypatch, session):
    seen: list = []
    svc = _service(monkeypatch, {"data": [session], "recordsFiltered": 1}, seen)
    for k in ("COMMAND", "BEACON", "DNS", "JA4"):
        monkeypatch.setenv(f"ION_ARKIME_RTMON_{k}_ENABLED", "false")
    monkeypatch.delenv("ION_ARKIME_RTMON_CLEARTEXT_ENABLED", raising=False)

    cands = asyncio.run(rtmon._gather_candidates(svc))

    assert [c["detector"] for c in cands] == ["cleartext_credentials"]
    c = cands[0]
    assert c["community_id"] == ark.normalize_session(session)["communityId"]
    assert c["src"].startswith("10.20.4.") and c["dst_port"] == 21
    params = seen[0]
    assert params["flatten"] == "1"
    fields = params["fields"].split(",")
    assert {"network.community_id", "source.ip", "destination.port", "network.bytes"} <= set(fields)
    assert not {"communityId", "srcIp", "dstPort", "totBytes"} & set(fields)


def test_a_refused_query_is_an_error_not_quiet_traffic(monkeypatch):
    seen: list = []
    svc = _service(monkeypatch, {"bsqErr": "Unknown field tls.ja4", "data": []}, seen)
    with pytest.raises(ark.ArkimeError, match="tls.ja4"):
        asyncio.run(svc.find_recent_sessions_by_expression("protocols == dns"))


def test_a_failed_sweep_is_counted_and_logged(monkeypatch, caplog):
    seen: list = []
    svc = _service(monkeypatch, {"bsqErr": "bad expression", "data": []}, seen)
    for k in ("COMMAND", "BEACON", "CLEARTEXT", "JA4"):
        monkeypatch.setenv(f"ION_ARKIME_RTMON_{k}_ENABLED", "false")
    monkeypatch.delenv("ION_ARKIME_RTMON_DNS_ENABLED", raising=False)
    with caplog.at_level("WARNING"):
        assert asyncio.run(rtmon._gather_candidates(svc)) == []
    assert rtmon._last_pass["failed"] == 1
    assert "bad expression" in caplog.text


def test_legacy_keys_already_present_are_kept():
    s = ark.normalize_session({"srcIp": "1.1.1.1", "source": {"ip": "2.2.2.2"}, "totBytes": 7})
    assert s["srcIp"] == "1.1.1.1" and s["totBytes"] == 7 and s["source"] == {"ip": "2.2.2.2"}


def test_regular_dns_to_an_external_resolver_is_not_a_beacon():
    """Every host querying 8.8.8.8 is regular by design; it scored 1.0."""
    t0 = 1_800_000_000_000
    sessions = [ark.normalize_session({
        "id": f"d{i}", "node": "sensor1", "network.community_id": f"1:dns{i}=",
        "source.ip": "10.20.4.17", "destination.ip": "8.8.8.8", "destination.port": 53,
        "network.bytes": 120, "firstPacket": t0 + i * 60_000, "protocol": ["dns", "udp"],
    }) for i in range(12)]
    assert rtmon._detect_beacon_shape(sessions) == []


def test_an_html_error_in_place_of_a_pcap_names_arkimes_reason(monkeypatch):
    msg = b"Error talking to node 'sensor1' using host 'cap1:8005' check viewer logs"
    svc = ark.ArkimeService(url="http://arkime.test", username="u", password="p", verify_ssl=False)

    async def _client():
        return httpx.AsyncClient(transport=httpx.MockTransport(
            lambda r: httpx.Response(200, content=msg, headers={"content-type": "text/html; charset=utf-8"})))

    monkeypatch.setattr(svc, "_pcap_client", _client)
    with pytest.raises(ark.ArkimeError, match="Error talking to node"):
        asyncio.run(svc.download_pcap("sensor1", "3@abc"))
