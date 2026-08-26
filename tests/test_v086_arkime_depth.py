"""v0.86.0 — Arkime depth: connector hygiene, spigraph aggregations, extended
SPI fields, retention helpers, hunts, WISE feed, geo/AS-org alert parsing.

Covers:
- ArkimeConnector.get_status_info works against the Basic-only service (the
  pre-v0.86 version read removed Keycloak/API-key attributes → AttributeError),
- the connector config schema advertises only fields the service implements,
- get_per_node_traffic and the traffic-overview protocol mix use spigraph
  server-side buckets with session-sample fallback,
- the extended SPI field list degrades to the base list after one HTTP 400
  (and stays degraded for the service instance),
- retention horizons + the retention-loop flow-recovery helpers,
- alert geo parsing: country_iso_code fallback via the static ISO map + AS org
  from {prefix}.as.full / ECS as.organization.name,
- the RTMON ja4_blocklist detector: env parsing, flat/nested session matching,
  and the empty-blocklist no-op,
- the hunts API (lead-gated submit, DB row lifecycle) and the WISE IOC feed
  (404 while unset, 401 on bad token, typed payloads).
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.models.user import User
from ion.services.arkime_realtime_monitor_service import (
    _detect_ja4_blocklist,
    _ja4_blocklist,
)
from ion.services.arkime_service import ArkimeService
from ion.services.connectors.arkime_connector import ArkimeConnector
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


# ── connector hygiene ─────────────────────────────────────────────────────


def _make_connector(svc) -> ArkimeConnector:
    conn = ArkimeConnector.__new__(ArkimeConnector)
    conn._service = svc
    return conn


def test_connector_status_info_configured_basic():
    conn = _make_connector(_make_service())
    info = conn.get_status_info()
    assert info["is_configured"] is True
    assert info["url"] == "http://ark:8005"
    assert info["auth_mode"] == "basic"


def test_connector_status_info_unconfigured():
    conn = _make_connector(_make_service(url=""))
    info = conn.get_status_info()
    assert info["is_configured"] is False
    assert "auth_mode" not in info


def test_connector_schema_matches_service_surface():
    schema = _make_connector(_make_service()).get_config_schema()
    assert set(schema["properties"]) == {"url", "username", "password", "verify_ssl"}
    assert set(schema["required"]) == {"url", "username", "password"}


# ── spigraph aggregations ─────────────────────────────────────────────────


def test_per_node_spigraph_buckets():
    payload = {"items": [
        {"name": "cap-edge-01", "count": 12, "size": 9000},
        {"name": "cap-core-01", "count": 30, "size": 4000},
    ]}
    svc = _make_service()
    client = _mock_client([_mock_resp(payload)])
    with patch.object(svc, "_client", return_value=client):
        result = _run(svc.get_per_node_traffic(0, 86400))

    assert result["method"] == "spigraph"
    assert result["nodes"] == [
        {"node": "cap-edge-01", "bytes": 9000, "sessions": 12},
        {"node": "cap-core-01", "bytes": 4000, "sessions": 30},
    ]


def test_per_node_falls_back_on_spigraph_error():
    err = _mock_resp({}, status_code=404)
    sessions = _mock_resp({"data": [
        {"node": "cap-edge-01", "totBytes": 500},
        {"node": "cap-edge-01", "totBytes": 300},
    ]})
    svc = _make_service()
    client = _mock_client([err, sessions])
    with patch.object(svc, "_client", return_value=client):
        result = _run(svc.get_per_node_traffic(0, 86400))

    assert result["method"] == "sample"
    assert result["nodes"] == [{"node": "cap-edge-01", "bytes": 800, "sessions": 2}]


def test_overview_protocol_mix_via_spigraph():
    # Facets payload with no graph.protocols → spigraph supplies the mix.
    facets = _mock_resp({"graph": {}, "recordsFiltered": 7})
    spigraph = _mock_resp({"items": [
        {"name": "tls", "count": 5},
        {"name": "dns", "count": 2},
    ]})
    svc = _make_service()
    client = _mock_client([facets, spigraph])
    with patch.object(svc, "_client", return_value=client):
        result = _run(svc.get_traffic_overview(0, 86400))

    assert result["protocols"] == {"tls": 5, "dns": 2}
    assert result["protocols_method"] == "spigraph"
    assert result["total_sessions"] == 7


def test_overview_protocol_mix_facets_short_circuits():
    facets = _mock_resp({"graph": {"protocols": {"tcp": 3}}, "recordsFiltered": 3})
    svc = _make_service()
    client = _mock_client([facets])
    with patch.object(svc, "_client", return_value=client):
        result = _run(svc.get_traffic_overview(0, 86400))

    assert result["protocols"] == {"tcp": 3}
    assert result["protocols_method"] == "facets"
    assert client.get.await_count == 1


# ── extended SPI field degrade ────────────────────────────────────────────


def test_depth_fields_requested_then_degraded_on_400():
    svc = _make_service()
    bad = _mock_resp({}, status_code=400)
    ok = _mock_resp({"data": [{"id": "s1", "node": "n1"}]})
    client = _mock_client([bad, ok])
    with patch.object(svc, "_client", return_value=client):
        sessions = _run(svc.find_sessions_by_community_id("n1", "1:abc="))

    assert sessions == [{"id": "s1", "node": "n1"}]
    assert svc._depth_fields_ok is False
    # Two calls: extended-field attempt (400) then base-field retry. The mock
    # records a reference to the mutated params dict, so only the retry value
    # is inspectable here; the extended first attempt is covered by
    # test_depth_fields_kept_when_accepted.
    assert client.get.await_count == 2
    retry_fields = client.get.await_args_list[1].kwargs["params"]["fields"]
    assert retry_fields == ArkimeService._SESSION_FIELDS

    # Once latched, later searches go straight to base fields — no retry.
    client2 = _mock_client([ok])
    with patch.object(svc, "_client", return_value=client2):
        _run(svc.find_sessions_by_community_id("n1", "1:abc="))
    assert (
        client2.get.await_args_list[0].kwargs["params"]["fields"]
        == ArkimeService._SESSION_FIELDS
    )


def test_depth_fields_kept_when_accepted():
    svc = _make_service()
    ok = _mock_resp({"data": []})
    client = _mock_client([ok])
    with patch.object(svc, "_client", return_value=client):
        _run(svc.find_sessions_by_community_id("n1", "1:abc="))
    fields = client.get.await_args_list[0].kwargs["params"]["fields"]
    assert "tls.ja4" in fields and "http.useragent" in fields
    assert client.get.await_count == 1


# ── alert geo: ISO-code fallback + AS org ─────────────────────────────────


def _parse_alert(source):
    from ion.services.elasticsearch_service import ElasticsearchService
    return ElasticsearchService()._parse_alert("alert-1", source)


def test_geo_from_country_iso_code_nested():
    a = _parse_alert({
        "source": {
            "geo": {"country_iso_code": "US"},
            "as": {"full": "AS15169 Google LLC"},
        },
        "destination": {"geo": {"country_iso_code": "de", "city_name": "Berlin"}},
    })
    assert a.geo_data["source_country"] == "United States"
    assert a.geo_data["source_country_iso_code"] == "US"
    assert a.geo_data["source_as_org"] == "AS15169 Google LLC"
    assert a.geo_data["destination_country"] == "Germany"
    assert a.geo_data["destination_city"] == "Berlin"


def test_geo_from_flat_dotted_keys():
    a = _parse_alert({
        "source.geo.country_iso_code": "GB",
        "source.as.full": "AS2856 BT",
    })
    assert a.geo_data["source_country"] == "United Kingdom"
    assert a.geo_data["source_as_org"] == "AS2856 BT"


def test_geo_country_name_wins_over_iso_code():
    a = _parse_alert({
        "source": {"geo": {"country_name": "Deutschland", "country_iso_code": "DE"}},
    })
    assert a.geo_data["source_country"] == "Deutschland"
    assert a.geo_data["source_country_iso_code"] == "DE"


def test_geo_ecs_as_organization_name():
    a = _parse_alert({
        "destination": {"as": {"organization": {"name": "Cloudflare, Inc."}}},
    })
    assert a.geo_data["destination_as_org"] == "Cloudflare, Inc."


def test_country_mapper_full_iso_set():
    from ion.services.country_mapper import get_country_name

    assert get_country_name("NL") == "Netherlands"
    assert get_country_name("nl") == "Netherlands"
    # Threat-actor display names still win (Russia, not Russian Federation).
    assert get_country_name("ru") == "Russia"
    assert get_country_name("ZZ") == "ZZ"  # unknown code passes through
    assert get_country_name("") == ""


# ── RTMON ja4_blocklist detector ──────────────────────────────────────────


def test_ja4_blocklist_env_parsing(monkeypatch):
    monkeypatch.setenv(
        "ION_ARKIME_RTMON_JA4_BLOCKLIST",
        "t13d1516h2_aaaa_bbbb=Sliver C2, t12d0000_cccc_dddd ,,",
    )
    bl = _ja4_blocklist()
    assert bl["t13d1516h2_aaaa_bbbb"] == "Sliver C2"
    assert bl["t12d0000_cccc_dddd"] == "blocklisted"


def test_ja4_blocklist_rejects_non_ja4_charset(monkeypatch):
    # Fingerprints are interpolated into an Arkime expression — anything
    # outside the JA4 charset is dropped, not queried.
    monkeypatch.setenv(
        "ION_ARKIME_RTMON_JA4_BLOCKLIST",
        'good_fp=ok, bad"fp || ip == 1.2.3.4=evil',
    )
    bl = _ja4_blocklist()
    assert bl == {"good_fp": "ok"}


def test_escape_arkime_quoted_blocks_expression_breakout():
    from ion.services.arkime_service import escape_arkime_quoted

    hostile = '1:x=" || ip == 1.2.3.4 || communityId == "'
    escaped = escape_arkime_quoted(hostile)
    assert '"' not in escaped.replace('\\"', "")
    assert escape_arkime_quoted("1:normal=") == "1:normal="


def test_note_cids_charset_rejects_expression_chars():
    from ion.services.arkime_retention_service import note_cids

    hostile = (
        '### [network] PCAP auto-analysis — `community_id` = '
        '`1:x" || ip == 1.2.3.4` \n\nfindings…'
    )
    # The quote/space/pipe payload fails the charset capture — no cid recovered.
    assert note_cids([hostile]) == {}


def test_ja4_blocklist_empty_by_default(monkeypatch):
    monkeypatch.delenv("ION_ARKIME_RTMON_JA4_BLOCKLIST", raising=False)
    # _KNOWN_BAD_JA4 ships empty, so the merged set is empty → detector no-op.
    assert _ja4_blocklist() == {}


def test_retention_horizons_cluster_and_per_node():
    oldest_cluster = _mock_resp({"data": [{"node": "cap-a", "firstPacket": 1_700_000_000_000}]})
    node_buckets = _mock_resp({"items": [{"name": "cap-a", "count": 5}]})
    oldest_node = _mock_resp({"data": [{"node": "cap-a", "firstPacket": 1_700_000_050_000}]})
    svc = _make_service()
    client = _mock_client([oldest_cluster, node_buckets, oldest_node])
    with patch.object(svc, "_client", return_value=client):
        horizons = _run(svc.get_retention_horizons())

    assert horizons == {"*": 1_700_000_000, "cap-a": 1_700_000_050}


def test_retention_horizons_empty_when_unreachable():
    err = _mock_resp({}, status_code=502)
    svc = _make_service()
    client = _mock_client([err, err, err])
    with patch.object(svc, "_client", return_value=client):
        horizons = _run(svc.get_retention_horizons())
    assert horizons == {}


# ── retention-loop helpers ────────────────────────────────────────────────


def test_parse_rtmon_marker_flow():
    from ion.services.arkime_retention_service import parse_rtmon_marker_flow

    flow = parse_rtmon_marker_flow("rtmon:cleartext_credentials:cap01:1:abc=")
    assert flow == {"node": "cap01", "community_id": "1:abc="}
    # Beacon markers carry no communityId — never parsed as a flow.
    assert parse_rtmon_marker_flow("rtmon:beacon:10.0.0.5:1.2.3.4:443") is None
    assert parse_rtmon_marker_flow("es-alert-123") is None
    assert parse_rtmon_marker_flow("") is None


def test_note_cids_completed_vs_failed():
    from ion.services.arkime_retention_service import note_cids

    completed = "### [network] PCAP auto-analysis — `community_id` = `1:aa=`\n\nfindings…"
    failed = (
        "### [network] PCAP auto-analysis — `community_id` = `1:bb=`\n\n"
        "_PCAP download failed:_ `timeout`"
    )
    unrelated = "analyst comment, no analysis heading, `community_id` = `1:zz=`"
    state = note_cids([completed, failed, unrelated])
    assert state == {"1:aa=": True, "1:bb=": False}
    # A later clean analysis note for the failed cid wins.
    retried = "### [network] PCAP auto-analysis — `community_id` = `1:bb=`\n\nok"
    assert note_cids([failed, retried])["1:bb="] is True


# ── hunts API + WISE feed ─────────────────────────────────────────────────


def _api_client(session, perms):
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


class _FakeArkime:
    def __init__(self, configured=True, hunt_id="h-42", fail=None):
        self.is_configured = configured
        self._hunt_id = hunt_id
        self._fail = fail
        self.submitted = []

    async def create_hunt(self, **kwargs):
        from ion.services.arkime_service import ArkimeError

        if self._fail:
            raise ArkimeError("refused", status_code=self._fail)
        self.submitted.append(kwargs)
        return {"id": self._hunt_id, "raw": {}}

    async def list_hunts(self):
        return [{"id": self._hunt_id, "status": "finished", "matchedSessions": 7}]


def test_hunt_submit_requires_lead(session):
    r = _api_client(session, perms={"alert:read"}).post(
        "/api/arkime/hunts", json={"name": "n", "search": "evil"}
    )
    assert r.status_code == 403


def test_hunt_submit_creates_row_and_tracks(session, monkeypatch):
    fake = _FakeArkime()
    monkeypatch.setattr("ion.web.arkime_api.get_arkime_service", lambda: fake)
    client = _api_client(session, perms={"security:read", "alert:read"})
    r = client.post("/api/arkime/hunts", json={
        "name": "UA sweep", "search": "Mozilla/4.0", "search_type": "ascii",
        "hours": 24,
    })
    assert r.status_code == 200, r.text
    hunt = r.json()["hunt"]
    assert hunt["arkime_hunt_id"] == "h-42"
    assert hunt["status"] == "running"
    assert fake.submitted and fake.submitted[0]["search"] == "Mozilla/4.0"

    # Listing refreshes from the viewer: finished + matched count land in DB.
    r2 = client.get("/api/arkime/hunts")
    assert r2.status_code == 200
    row = r2.json()["hunts"][0]
    assert row["status"] == "finished"
    assert row["matched_sessions"] == 7


def test_hunt_submit_403_marks_failed(session, monkeypatch):
    fake = _FakeArkime(fail=403)
    monkeypatch.setattr("ion.web.arkime_api.get_arkime_service", lambda: fake)
    client = _api_client(session, perms={"security:read"})
    r = client.post("/api/arkime/hunts", json={"name": "n", "search": "x"})
    assert r.status_code == 403
    from ion.models.arkime_hunt import ArkimeHunt
    row = session.query(ArkimeHunt).first()
    assert row is not None and row.status == "failed"


def test_wise_feed_404_when_token_unset(session, monkeypatch):
    monkeypatch.delenv("ION_WISE_TOKEN", raising=False)
    r = _api_client(session, set()).get("/api/wise/ion-iocs?type=ip")
    assert r.status_code == 404


def test_wise_feed_auth_and_payload(session, monkeypatch):
    import ion.web.wise_api as wise_api
    from ion.models.observable import Observable, ObservableType, ThreatLevel

    monkeypatch.setenv("ION_WISE_TOKEN", "sekrit")
    monkeypatch.setattr(wise_api, "_cache", {})
    # The endpoint opens its own DB session via the global factory — the
    # conftest temp_db engine is already the process default here.
    session.add(Observable(
        type=ObservableType.IPV4, value="203.0.113.9", normalized_value="203.0.113.9",
        is_ioc=True, threat_level=ThreatLevel.HIGH,
    ))
    session.commit()

    client = _api_client(session, set())
    assert client.get("/api/wise/ion-iocs?type=ip").status_code == 401
    assert client.get(
        "/api/wise/ion-iocs?type=ip", headers={"x-ion-token": "wrong"}
    ).status_code == 401
    r = client.get("/api/wise/ion-iocs?type=ip", headers={"x-ion-token": "sekrit"})
    assert r.status_code == 200, r.text
    values = {row["value"]: row for row in r.json()}
    assert "203.0.113.9" in values
    assert values["203.0.113.9"]["label"] == "ioc"
    assert values["203.0.113.9"]["threat_level"] == "high"
    # Unknown type is a 400, not a silent empty list.
    assert client.get(
        "/api/wise/ion-iocs?type=sha1", headers={"x-ion-token": "sekrit"}
    ).status_code == 400


def test_detect_ja4_blocklist_flat_and_nested():
    bl = {"t13d1516h2_aaaa_bbbb": "Sliver C2"}
    sessions = [
        {"communityId": "1:a=", "node": "n1", "srcIp": "10.0.0.5",
         "dstIp": "45.77.1.2", "dstPort": 443, "tls.ja4": "t13d1516h2_aaaa_bbbb"},
        {"communityId": "1:b=", "node": "n1", "srcIp": "10.0.0.6",
         "dstIp": "45.77.1.3", "tls": {"ja4": ["t13d1516h2_aaaa_bbbb"]}},
        {"communityId": "1:c=", "node": "n1", "srcIp": "10.0.0.7",
         "dstIp": "45.77.1.4", "tls.ja4": "benign_fingerprint"},
        {"communityId": "", "node": "n1", "tls.ja4": "t13d1516h2_aaaa_bbbb"},
    ]
    hits = _detect_ja4_blocklist(sessions, bl)
    assert len(hits) == 2
    assert all(h["detector"] == "ja4_blocklist" for h in hits)
    assert all(h["severity"] == "high" for h in hits)
    assert all(not h["confirm_first"] for h in hits)
    assert {h["marker"] for h in hits} == {"rtmon:ja4:n1:1:a=", "rtmon:ja4:n1:1:b="}
    assert "Sliver C2" in hits[0]["title"]
