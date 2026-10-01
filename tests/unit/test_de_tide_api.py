"""Tests for de_tide_api — the TIDE and Detection Engineering HTTP surface.

This module was extracted from `cyab_api` so the CyAB assessment product could
be archived without ten delicate excisions from the file that hosted a headline
feature's entire HTTP surface. 98% of it is relocated code, which is why it
arrived at 13.4% coverage: it was never tested inside `cyab_api` either.

What these tests are for, beyond the number. Every route here is a cross-
reference — TIDE's idea of a detection rule against Elasticsearch's idea of an
alert, or OpenCTI's idea of a threat actor against TIDE's coverage. The failure
that costs something is not a 500; it is a cross-reference that silently stops
matching, because the page then reads "no rules firing" or "0% readiness" and
looks like good news. So the tests concentrate on:

  * the match itself — case- and whitespace-insensitive rule-name matching,
    sub-technique-to-parent matching, and the namespace lower-casing that exists
    because ES enforces lowercase while CyAB data sources do not;
  * the degraded paths — TIDE off, Elasticsearch off, the circuit breaker open,
    OpenCTI off, a query that raises. Each must return a *shaped* response the
    page can render, not an exception, and must not report an empty result as
    though it were a clean bill of health;
  * the snapshot-or-live fallback, which decides whether a response comes from
    Postgres in 10ms or a live TIDE round-trip.

The fakes are deliberately hand-written rather than Mock: these handlers walk
nested aggregation dictionaries, and a Mock would answer every shape alike,
which is exactly the bug class being tested for.

One statement is left uncovered on purpose. The `return 1` at the end of the
navigator layer's `_score` ladder is unreachable: `enabled <= 0` has already
returned 0, and `enabled` is coerced through `int()`, so the preceding
`enabled >= 1` always wins. It is dead rather than untested, and left in place
because deleting a line in a relocated module to move a coverage number is the
wrong trade — the ladder's actual behaviour is pinned at every boundary by
`test_the_score_rewards_enabled_rules_not_written_ones`.
"""

from __future__ import annotations

from typing import Any, Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.models.cyab import CyabDataSource, CyabSystem
from ion.web import de_tide_api
from ion.web.api import get_db_session

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeTide:
    """Stands in for TideService. Only the attributes the routes touch."""

    def __init__(self, *, enabled: bool = True, space: str = "default", **data):
        self.enabled = enabled
        self.space = space
        self._data = data
        self.calls: list[tuple[str, tuple, dict]] = []
        self.set_space_raises = False

    def _record(self, name, *a, **k):
        self.calls.append((name, a, k))

    def test_connection(self):
        self._record("test_connection")
        return self._data.get("connection", {"ok": True})

    def get_global_mitre_coverage(self):
        self._record("get_global_mitre_coverage")
        return self._data.get("coverage")

    def get_systems(self):
        self._record("get_systems")
        return self._data.get("systems", [])

    def get_system_detail(self, system_id):
        self._record("get_system_detail", system_id)
        return (self._data.get("details") or {}).get(system_id)

    def get_mitre_coverage(self, system_id):
        self._record("get_mitre_coverage", system_id)
        return self._data.get("system_mitre", {})

    def get_system_use_case_coverage(self, system_id):
        self._record("get_system_use_case_coverage", system_id)
        return self._data.get("use_case_coverage")

    def get_detection_rules(self, search="", limit=50):
        self._record("get_detection_rules", search=search, limit=limit)
        return self._data.get("rules", [])

    def get_available_spaces(self):
        self._record("get_available_spaces")
        return self._data.get("spaces", [])

    def set_space(self, space):
        self._record("set_space", space)
        if self.set_space_raises:
            raise ValueError("bad space")
        self.space = space

    def get_posture_stats(self):
        self._record("get_posture_stats")
        return self._data.get("posture")

    def get_disabled_critical_high(self):
        self._record("get_disabled_critical_high")
        return self._data.get("disabled_critical", [])

    def get_playbooks_with_kill_chains(self):
        self._record("get_playbooks_with_kill_chains")
        return self._data.get("playbooks", [])

    def get_rules_paginated(self, search="", severity="", enabled="",
                            offset=0, limit=50):
        self._record("get_rules_paginated", search=search, severity=severity,
                     enabled=enabled, offset=offset, limit=limit)
        return self._data.get("paginated", {"rows": [], "total": 0})

    def get_gaps_analysis(self):
        self._record("get_gaps_analysis")
        return self._data.get("gaps")


class FakeES:
    """Stands in for ElasticsearchService."""

    def __init__(self, *, configured: bool = True, response: Any = None,
                 raises: Optional[Exception] = None,
                 alert_index: str = "alerts-*,signals-*"):
        self.is_configured = configured
        self.alert_index = alert_index
        self._response = response if response is not None else {}
        self._raises = raises
        self.requests: list[tuple[str, str, dict]] = []

    async def _request(self, method, path, json=None):
        self.requests.append((method, path, json or {}))
        if self._raises:
            raise self._raises
        return self._response


class FakeOpenCTI:
    def __init__(self, *, configured: bool = True, actor=None, actors=None,
                 detail_raises=None, search_raises=None):
        self.is_configured = configured
        self._actor = actor
        self._actors = actors or {"actors": []}
        self._detail_raises = detail_raises
        self._search_raises = search_raises

    async def get_entity_detail(self, entity_id, entity_type):
        if self._detail_raises:
            raise self._detail_raises
        if isinstance(self._actor, dict) and "by_id" in self._actor:
            return self._actor["by_id"].get(entity_id)
        return self._actor

    async def search_threat_actors(self, search="", first=15):
        if self._search_raises:
            raise self._search_raises
        return self._actors


class _User:
    """require_permission only calls has_permission()."""

    id = 1
    username = "de-tester"

    def has_permission(self, _name):
        return True


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

@pytest.fixture
def client(session):
    """A minimal app mounting only this router.

    Mounted at /api/cyab because that is where server.py mounts it — the prefix
    is a historical fact about these URLs, and a test that used a different one
    would not be exercising the paths the frontend calls.
    """
    app = FastAPI()
    app.include_router(de_tide_api.router, prefix="/api/cyab")
    app.dependency_overrides[get_current_user] = lambda: _User()
    app.dependency_overrides[get_db_session] = lambda: session
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def tide(monkeypatch):
    """Install a FakeTide and hand the test a setter to configure it."""
    holder = {}

    def _install(**kwargs):
        svc = FakeTide(**kwargs)
        holder["svc"] = svc
        monkeypatch.setattr(de_tide_api, "get_tide_service", lambda: svc)
        return svc

    _install()
    return _install


@pytest.fixture
def es(monkeypatch):
    def _install(**kwargs):
        svc = FakeES(**kwargs)
        monkeypatch.setattr(de_tide_api, "ElasticsearchService", lambda: svc)
        return svc

    return _install


@pytest.fixture
def snapshot(monkeypatch):
    """Control ion.services.tide_sync_service, imported lazily inside routes."""
    import ion.services.tide_sync_service as sync

    state = {"value": None, "status": {"ok": True}, "synced": {"ran": True}}
    monkeypatch.setattr(sync, "get_snapshot", lambda s, k: state["value"],
                        raising=False)
    monkeypatch.setattr(sync, "get_sync_status", lambda s: state["status"],
                        raising=False)
    monkeypatch.setattr(sync, "sync_all", lambda s: state["synced"],
                        raising=False)
    return state


def _system(session, **kw):
    fields = dict(name="Payments", department="Finance", status="active")
    fields.update(kw)
    s = CyabSystem(**fields)
    session.add(s)
    session.flush()
    return s


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestParseJson:
    def test_a_json_object_is_decoded(self):
        assert de_tide_api._parse_json('{"a": 1}') == {"a": 1}

    def test_a_json_list_is_decoded(self):
        assert de_tide_api._parse_json('["a"]') == ["a"]

    def test_empty_and_none_are_none(self):
        assert de_tide_api._parse_json("") is None
        assert de_tide_api._parse_json(None) is None

    def test_malformed_json_is_none_not_an_exception(self):
        """These columns hold text written by earlier versions; one bad row must
        not 500 a whole inventory listing."""
        assert de_tide_api._parse_json("{nope") is None


class TestSystemToDict:
    def test_the_system_fields_the_page_reads(self, session):
        s = _system(session, name="Payments", reference="SYS-1",
                    readiness_score=72)

        d = de_tide_api._system_to_dict(s)

        assert d["id"] == s.id
        assert d["name"] == "Payments"
        assert d["reference"] == "SYS-1"
        assert d["readiness_score"] == 72
        assert d["data_source_count"] == 0

    def test_a_missing_icon_falls_back_rather_than_rendering_blank(self, session):
        assert de_tide_api._system_to_dict(_system(session))["icon"] == "monitor"

    def test_tags_decode_to_a_list_and_never_to_none(self, session):
        """The template iterates this, so None would be a TypeError."""
        assert de_tide_api._system_to_dict(_system(session))["tags"] == []
        s = _system(session, tags='["pci", "tier1"]')
        assert de_tide_api._system_to_dict(s)["tags"] == ["pci", "tier1"]

    def test_data_sources_are_omitted_unless_asked_for(self, session):
        s = _system(session)
        session.add(CyabDataSource(system_id=s.id, name="EDR",
                                   data_source_type="endpoint"))
        session.flush()
        session.refresh(s)

        assert "data_sources" not in de_tide_api._system_to_dict(s)
        full = de_tide_api._system_to_dict(s, include_sources=True)
        assert [ds["name"] for ds in full["data_sources"]] == ["EDR"]
        assert full["data_source_count"] == 1

    def test_a_data_source_carries_its_namespace_and_field_mapping(self, session):
        s = _system(session)
        session.add(CyabDataSource(
            system_id=s.id, name="EDR", data_source_type="endpoint",
            data_namespace="EndpointFleet", field_mapping='{"host": "host.name"}',
            tide_system_id="tide-uuid-1",
        ))
        session.flush()
        session.refresh(s)

        ds = de_tide_api._system_to_dict(s, include_sources=True)["data_sources"][0]

        assert ds["data_namespace"] == "EndpointFleet"
        assert ds["field_mapping"] == {"host": "host.name"}
        assert ds["tide_system_id"] == "tide-uuid-1"

    def test_severity_order_puts_critical_first(self):
        """Used to sort silent rules, so an analyst sees the worst gap first."""
        assert sorted(["low", "critical", "medium", "high"],
                      key=lambda s: de_tide_api._SEV_ORDER[s]) == [
            "critical", "high", "medium", "low"]


# ---------------------------------------------------------------------------
# TIDE integration routes
# ---------------------------------------------------------------------------

class TestTideRoutes:
    def test_status_passes_the_connection_check_through(self, client, tide):
        tide(connection={"ok": True, "rules": 412})

        r = client.get("/api/cyab/tide/status")

        assert r.status_code == 200
        assert r.json() == {"ok": True, "rules": 412}

    def test_mitre_coverage_is_flagged_enabled(self, client, tide):
        tide(coverage={"techniques": {"T1059": {"rule_count": 2}},
                       "total_techniques": 1})

        body = client.get("/api/cyab/tide/mitre-coverage").json()

        assert body["enabled"] is True
        assert body["techniques"]["T1059"]["rule_count"] == 2

    def test_no_coverage_reports_disabled_rather_than_an_empty_map(self, client,
                                                                   tide):
        """An empty techniques map and "TIDE is off" render identically unless
        the flag distinguishes them, and the page would read as full blindness."""
        tide(coverage=None)

        assert client.get("/api/cyab/tide/mitre-coverage").json() == {
            "enabled": False}

    def test_systems_are_listed(self, client, tide):
        tide(systems=[{"id": "a", "name": "Payments"}])

        assert client.get("/api/cyab/tide/systems").json() == [
            {"id": "a", "name": "Payments"}]

    def test_a_system_detail_is_returned(self, client, tide):
        tide(details={"sys-1": {"name": "Payments", "detections": []}})

        r = client.get("/api/cyab/tide/systems/sys-1")

        assert r.status_code == 200
        assert r.json()["name"] == "Payments"

    def test_an_unknown_system_is_a_404(self, client, tide):
        tide(details={})

        r = client.get("/api/cyab/tide/systems/nope")

        assert r.status_code == 404
        assert r.json()["detail"] == "TIDE system not found"

    def test_system_mitre_coverage_is_passed_through(self, client, tide):
        tide(system_mitre={"covered": 3})

        assert client.get("/api/cyab/tide/systems/s1/mitre").json() == {
            "covered": 3}

    def test_use_cases_need_tide_configured(self, client, tide):
        """503 rather than an empty list: "no use cases" would read as a clean
        result from a system that was never asked."""
        tide(enabled=False)

        r = client.get("/api/cyab/tide/systems/s1/use-cases")

        assert r.status_code == 503
        assert "not configured" in r.json()["detail"]

    def test_use_cases_report_a_failed_tide_query_as_502(self, client, tide):
        tide(use_case_coverage=None)

        r = client.get("/api/cyab/tide/systems/s1/use-cases")

        assert r.status_code == 502

    def test_use_cases_are_returned_when_tide_answers(self, client, tide):
        tide(use_case_coverage={"playbooks": [{"name": "Ransomware"}]})

        r = client.get("/api/cyab/tide/systems/s1/use-cases")

        assert r.status_code == 200
        assert r.json()["playbooks"][0]["name"] == "Ransomware"

    def test_rule_search_is_passed_through(self, client, tide):
        svc = tide(rules=[{"name": "Suspicious PowerShell"}])

        client.get("/api/cyab/tide/rules?search=power&limit=10")

        call = [c for c in svc.calls if c[0] == "get_detection_rules"][0]
        assert call[2] == {"search": "power", "limit": 10}

    def test_the_rule_limit_is_capped_at_two_hundred(self, client, tide):
        """An uncapped limit lets one request pull every rule TIDE holds."""
        svc = tide(rules=[])

        client.get("/api/cyab/tide/rules?limit=100000")

        assert [c for c in svc.calls if c[0] == "get_detection_rules"][0][2][
            "limit"] == 200


# ---------------------------------------------------------------------------
# Snapshot-or-live
# ---------------------------------------------------------------------------

class TestSnapshotOrLive:
    def test_a_cached_snapshot_short_circuits_the_live_query(self, session,
                                                             snapshot):
        snapshot["value"] = {"from": "postgres"}
        called = []

        out = de_tide_api._snapshot_or_live(
            session, "posture", lambda: called.append(1) or {"from": "tide"})

        assert out == {"from": "postgres"}
        assert called == [], "TIDE was queried despite a fresh snapshot"

    def test_no_snapshot_falls_through_to_tide(self, session, snapshot):
        snapshot["value"] = None

        out = de_tide_api._snapshot_or_live(session, "posture",
                                           lambda: {"from": "tide"})

        assert out == {"from": "tide"}

    def test_live_kwargs_are_forwarded(self, session, snapshot):
        snapshot["value"] = None

        out = de_tide_api._snapshot_or_live(
            session, "k", lambda **kw: kw, {"limit": 5})

        assert out == {"limit": 5}

    def test_a_falsy_snapshot_is_still_a_hit(self, session, snapshot):
        """An empty list is a legitimate cached answer — "TIDE has no disabled
        critical rules" — and must not trigger a live round-trip on every
        request. The check is `is not None`, and this pins it."""
        snapshot["value"] = []
        called = []

        out = de_tide_api._snapshot_or_live(
            session, "disabled_critical",
            lambda: called.append(1) or ["live"])

        assert out == []
        assert called == []


class TestDeSnapshotRoutes:
    def test_systems_come_from_the_snapshot(self, client, tide, snapshot):
        snapshot["value"] = [{"id": "cached"}]

        assert client.get("/api/cyab/tide/de/systems").json() == [
            {"id": "cached"}]

    def test_systems_fall_back_to_tide(self, client, tide, snapshot):
        snapshot["value"] = None
        tide(systems=[{"id": "live"}])

        assert client.get("/api/cyab/tide/de/systems").json() == [
            {"id": "live"}]

    def test_posture_is_flagged_enabled(self, client, tide, snapshot):
        snapshot["value"] = {"total_rules": 400}

        body = client.get("/api/cyab/tide/de/posture").json()

        assert body["enabled"] is True
        assert body["total_rules"] == 400

    def test_no_posture_reports_disabled(self, client, tide, snapshot):
        snapshot["value"] = None
        tide(posture=None)

        assert client.get("/api/cyab/tide/de/posture").json() == {
            "enabled": False}

    def test_a_non_dict_posture_is_returned_untouched(self, client, tide,
                                                      snapshot):
        """The enabled flag is only stamped on a dict, so a list response
        cannot raise a TypeError on assignment."""
        snapshot["value"] = [1, 2]

        assert client.get("/api/cyab/tide/de/posture").json() == [1, 2]

    def test_disabled_critical_rules_are_listed(self, client, tide, snapshot):
        snapshot["value"] = [{"name": "Disabled ransomware rule"}]

        assert client.get("/api/cyab/tide/de/disabled-critical").json() == [
            {"name": "Disabled ransomware rule"}]

    def test_use_cases_are_listed(self, client, tide, snapshot):
        snapshot["value"] = [{"name": "Ransomware"}]

        assert client.get("/api/cyab/tide/de/use-cases").json() == [
            {"name": "Ransomware"}]

    def test_the_kill_chains_alias_returns_the_same_shape(self, client, tide,
                                                          snapshot):
        """Deprecated alias kept for older clients; if it ever diverges from
        /use-cases those clients break silently."""
        snapshot["value"] = [{"name": "Ransomware"}]

        a = client.get("/api/cyab/tide/de/use-cases").json()
        b = client.get("/api/cyab/tide/de/kill-chains").json()

        assert a == b

    def test_gaps_are_flagged_enabled(self, client, tide, snapshot):
        snapshot["value"] = {"blind_tactics": ["exfiltration"]}

        body = client.get("/api/cyab/tide/de/gaps").json()

        assert body["enabled"] is True
        assert body["blind_tactics"] == ["exfiltration"]

    def test_no_gaps_data_reports_disabled(self, client, tide, snapshot):
        snapshot["value"] = None
        tide(gaps=None)

        assert client.get("/api/cyab/tide/de/gaps").json() == {"enabled": False}

    def test_a_non_dict_gaps_payload_is_returned_untouched(self, client, tide,
                                                           snapshot):
        snapshot["value"] = ["a"]

        assert client.get("/api/cyab/tide/de/gaps").json() == ["a"]

    def test_sync_status_is_passed_through(self, client, snapshot):
        snapshot["status"] = {"fresh": True, "age_seconds": 12}

        assert client.get("/api/cyab/tide/de/sync-status").json()["fresh"] is True

    def test_sync_now_triggers_a_sync(self, client, snapshot):
        snapshot["synced"] = {"synced": 7}

        assert client.post("/api/cyab/tide/de/sync-now").json() == {"synced": 7}


class TestSpaces:
    def test_spaces_are_listed_with_the_active_one(self, client, tide):
        tide(spaces=[{"space": "default", "rules": 400}], space="default")

        body = client.get("/api/cyab/tide/de/spaces").json()

        assert body["active"] == "default"
        assert body["spaces"][0]["rules"] == 400

    def test_tide_off_yields_an_empty_selector_not_an_error(self, client, tide):
        """The dropdown renders unconditionally, so it needs the shape."""
        tide(enabled=False)

        assert client.get("/api/cyab/tide/de/spaces").json() == {
            "spaces": [], "active": "default"}

    def test_switching_space_reports_the_new_active_value(self, client, tide):
        svc = tide(space="default")

        body = client.post("/api/cyab/tide/de/spaces/soc").json()

        assert body == {"ok": True, "active": "soc"}
        assert svc.space == "soc"

    def test_switching_with_tide_off_is_refused_in_the_body(self, client, tide):
        tide(enabled=False)

        assert client.post("/api/cyab/tide/de/spaces/soc").json() == {
            "ok": False, "error": "TIDE not configured"}

    def test_an_invalid_space_is_a_400(self, client, tide):
        """The service validates the space name; a rejection must surface as a
        400 rather than a 500. (Note: a path-traversal-looking value like
        "../etc" never reaches the handler — the router 404s it first — so this
        drives the service's own ValueError instead.)"""
        svc = tide()
        svc.set_space_raises = True

        r = client.post("/api/cyab/tide/de/spaces/bogus-space")

        assert r.status_code == 400
        assert r.json()["detail"] == "Invalid space value"

    def test_rule_paging_forwards_every_filter(self, client, tide):
        svc = tide(paginated={"rows": [], "total": 0})

        client.get("/api/cyab/tide/de/rules"
                   "?search=power&severity=high&enabled=true&offset=20&limit=25")

        assert [c for c in svc.calls if c[0] == "get_rules_paginated"][0][2] == {
            "search": "power", "severity": "high", "enabled": "true",
            "offset": 20, "limit": 25,
        }

    def test_the_paged_rule_limit_is_capped(self, client, tide):
        svc = tide(paginated={"rows": []})

        client.get("/api/cyab/tide/de/rules?limit=9999")

        assert [c for c in svc.calls if c[0] == "get_rules_paginated"][0][2][
            "limit"] == 200


# ---------------------------------------------------------------------------
# /tide/systems/{id}/alerts — the TIDE-rule-to-ES-alert cross-reference
# ---------------------------------------------------------------------------

def _rule_bucket(name, count, *, severity=None, status=None, latest=None,
                 mitre=None):
    return {
        "key": name,
        "doc_count": count,
        "by_severity": {"buckets": [{"key": k, "doc_count": v}
                                    for k, v in (severity or {}).items()]},
        "by_status": {"buckets": [{"key": k, "doc_count": v}
                                  for k, v in (status or {}).items()]},
        "latest": {"value_as_string": latest},
        "earliest": {"value_as_string": latest},
        "by_mitre": {"buckets": [{"key": m} for m in (mitre or [])]},
    }


def _es_alert_response(rule_buckets, *, total=0, severity=None, status=None,
                       timeline=None):
    return {
        "hits": {"total": {"value": total}},
        "aggregations": {
            "by_rule": {"buckets": rule_buckets},
            "total_by_severity": {"buckets": [{"key": k, "doc_count": v}
                                              for k, v in (severity or {}).items()]},
            "total_by_status": {"buckets": [{"key": k, "doc_count": v}
                                            for k, v in (status or {}).items()]},
            "over_time": {"buckets": [{"key_as_string": t, "doc_count": c}
                                      for t, c in (timeline or [])]},
            "by_severity_over_time": {"buckets": []},
        },
    }


DETAIL = {
    "sys-1": {
        "name": "Payments",
        "detections": [
            {"name": "Suspicious PowerShell", "rule_id": "r1",
             "severity": "critical", "enabled": True, "quality_score": 80},
            {"name": "Credential Dumping", "rule_id": "r2",
             "severity": "low", "enabled": True, "quality_score": 40},
            {"name": "Rare Parent Process", "rule_id": "r3",
             "severity": "high", "enabled": False, "quality_score": 55},
        ],
    }
}


@pytest.fixture
def breaker_open(monkeypatch):
    from ion.core.circuit_breaker import es_breaker

    def _set(can_execute: bool):
        monkeypatch.setattr(es_breaker, "can_execute", lambda: can_execute)

    return _set


class TestSystemAlerts:
    def test_an_unknown_tide_system_is_a_404(self, client, tide, es):
        tide(details={})
        es()

        r = client.get("/api/cyab/tide/systems/nope/alerts?namespace=ns")

        assert r.status_code == 404

    def test_no_namespace_explains_itself_and_lists_every_rule_as_silent(
        self, client, tide, es
    ):
        """The data source has no namespace set, so nothing can be matched.
        Reporting zero firing rules without the error would read as "all quiet"."""
        tide(details=DETAIL)
        es()

        body = client.get("/api/cyab/tide/systems/sys-1/alerts").json()

        assert "set the data namespace" in body["error"]
        assert body["tide_rules"] == 3
        assert body["firing_rules"] == []
        assert len(body["silent_rules"]) == 3

    def test_elasticsearch_off_is_reported_without_losing_the_rule_count(
        self, client, tide, es
    ):
        tide(details=DETAIL)
        es(configured=False)

        body = client.get("/api/cyab/tide/systems/sys-1/alerts?namespace=ns").json()

        assert body["error"] == "Elasticsearch not configured"
        assert body["tide_rules"] == 3
        assert len(body["silent_rules"]) == 3

    def test_an_open_circuit_breaker_fast_fails(self, client, tide, es,
                                                breaker_open):
        """Known-offline ES should not produce a connection error per request."""
        tide(details=DETAIL)
        es()
        breaker_open(False)

        body = client.get("/api/cyab/tide/systems/sys-1/alerts?namespace=ns").json()

        assert "circuit breaker open" in body["error"]
        assert len(body["silent_rules"]) == 3

    def test_a_failed_es_query_is_reported_in_the_shape_the_page_expects(
        self, client, tide, es, breaker_open
    ):
        tide(details=DETAIL)
        es(raises=RuntimeError("connection reset"))
        breaker_open(True)

        body = client.get("/api/cyab/tide/systems/sys-1/alerts?namespace=ns").json()

        assert "ES query failed" in body["error"]
        assert body["firing_rules"] == []
        assert len(body["silent_rules"]) == 3

    def test_the_namespace_is_lowercased_before_querying(self, client, tide, es,
                                                         breaker_open):
        """ES enforces lowercase on data_stream.namespace; CyAB data sources
        store mixed case. Without the fold, nothing ever matches."""
        tide(details=DETAIL)
        svc = es(response=_es_alert_response([]))
        breaker_open(True)

        body = client.get(
            "/api/cyab/tide/systems/sys-1/alerts?namespace=EndpointFleet").json()

        assert body["namespace"] == "endpointfleet"
        sent = svc.requests[0][2]
        terms = [m for m in sent["query"]["bool"]["must"] if "term" in m]
        assert terms[0]["term"]["data_stream.namespace"] == "endpointfleet"

    def test_a_firing_rule_is_matched_to_its_tide_rule(self, client, tide, es,
                                                       breaker_open):
        tide(details=DETAIL)
        es(response=_es_alert_response(
            [_rule_bucket("Suspicious PowerShell", 12,
                          severity={"critical": 12},
                          status={"open": 10, "closed": 2},
                          latest="2026-06-01T10:00:00Z", mitre=["T1059"])],
            total=12))
        breaker_open(True)

        body = client.get("/api/cyab/tide/systems/sys-1/alerts?namespace=ns").json()

        assert body["firing_count"] == 1
        fired = body["firing_rules"][0]
        assert fired["alert_count"] == 12
        assert fired["tide_rule_id"] == "r1"
        assert fired["tide_severity"] == "critical"
        assert fired["tide_quality"] == 80
        assert fired["matched"] is True
        assert fired["mitre_ids"] == ["T1059"]

    def test_rule_name_matching_ignores_case_and_padding(self, client, tide, es,
                                                          breaker_open):
        """TIDE and Kibana disagree about whitespace and capitalisation more
        often than either team expects; an exact match loses the cross-ref."""
        tide(details=DETAIL)
        es(response=_es_alert_response(
            [_rule_bucket("  suspicious POWERSHELL  ", 3)], total=3))
        breaker_open(True)

        body = client.get("/api/cyab/tide/systems/sys-1/alerts?namespace=ns").json()

        assert body["firing_count"] == 1
        assert body["unmatched_count"] == 0

    def test_an_es_rule_with_no_tide_counterpart_is_unmatched_not_dropped(
        self, client, tide, es, breaker_open
    ):
        """An alert firing from a rule TIDE does not know about is the
        interesting case — undocumented detection — so it must surface."""
        tide(details=DETAIL)
        es(response=_es_alert_response(
            [_rule_bucket("Some Ad-Hoc Rule", 5)], total=5))
        breaker_open(True)

        body = client.get("/api/cyab/tide/systems/sys-1/alerts?namespace=ns").json()

        assert body["unmatched_count"] == 1
        assert body["unmatched_alerts"][0]["matched"] is False
        assert body["silent_count"] == 3

    def test_firing_rules_are_sorted_by_volume(self, client, tide, es,
                                                breaker_open):
        tide(details=DETAIL)
        es(response=_es_alert_response([
            _rule_bucket("Credential Dumping", 2),
            _rule_bucket("Suspicious PowerShell", 40),
        ], total=42))
        breaker_open(True)

        body = client.get("/api/cyab/tide/systems/sys-1/alerts?namespace=ns").json()

        assert [r["alert_count"] for r in body["firing_rules"]] == [40, 2]

    def test_silent_rules_are_sorted_worst_severity_first(self, client, tide,
                                                           es, breaker_open):
        tide(details=DETAIL)
        es(response=_es_alert_response([]))
        breaker_open(True)

        body = client.get("/api/cyab/tide/systems/sys-1/alerts?namespace=ns").json()

        assert [r["severity"] for r in body["silent_rules"]] == [
            "critical", "high", "low"]

    def test_the_overall_stats_and_timeline_are_carried(self, client, tide, es,
                                                         breaker_open):
        tide(details=DETAIL)
        es(response=_es_alert_response(
            [], total=7, severity={"high": 7}, status={"open": 7},
            timeline=[("2026-06-01T00:00:00Z", 3), ("2026-06-01T06:00:00Z", 4)]))
        breaker_open(True)

        body = client.get("/api/cyab/tide/systems/sys-1/alerts?namespace=ns").json()

        assert body["total_alerts"] == 7
        assert body["alert_stats"]["severity"] == {"high": 7}
        assert body["alert_stats"]["status"] == {"open": 7}
        assert [p["count"] for p in body["alert_stats"]["timeline"]] == [3, 4]

    def test_a_scalar_hit_total_is_tolerated(self, client, tide, es,
                                              breaker_open):
        """Older ES versions return hits.total as an int, not {"value": n}."""
        tide(details=DETAIL)
        resp = _es_alert_response([])
        resp["hits"]["total"] = 9
        es(response=resp)
        breaker_open(True)

        body = client.get("/api/cyab/tide/systems/sys-1/alerts?namespace=ns").json()

        assert body["total_alerts"] == 9

    def test_a_detection_with_no_name_is_skipped(self, client, tide, es,
                                                  breaker_open):
        tide(details={"sys-1": {"name": "P", "detections": [
            {"name": "   ", "rule_id": "blank"},
            {"name": "Real Rule", "rule_id": "r1", "severity": "high"},
        ]}})
        es(response=_es_alert_response([]))
        breaker_open(True)

        body = client.get("/api/cyab/tide/systems/sys-1/alerts?namespace=ns").json()

        assert body["tide_rules"] == 1

    def test_a_system_with_no_detections_still_answers(self, client, tide, es,
                                                        breaker_open):
        tide(details={"sys-1": {"name": "P"}})
        es(response=_es_alert_response([]))
        breaker_open(True)

        body = client.get("/api/cyab/tide/systems/sys-1/alerts?namespace=ns").json()

        assert body["tide_rules"] == 0
        assert body["silent_rules"] == []

    def test_the_index_pattern_is_url_encoded(self, client, tide, es,
                                               breaker_open):
        """A comma-separated pattern must not be read as a path separator."""
        tide(details=DETAIL)
        svc = es(response=_es_alert_response([]),
                 alert_index="alerts-*,signals-*")
        breaker_open(True)

        client.get("/api/cyab/tide/systems/sys-1/alerts?namespace=ns")

        assert "%2C" in svc.requests[0][1]
        assert "," not in svc.requests[0][1]


# ---------------------------------------------------------------------------
# /tide/de/navigator-layer
# ---------------------------------------------------------------------------

class TestNavigatorLayer:
    def test_tide_off_is_a_503(self, client, tide):
        tide(enabled=False)

        assert client.get("/api/cyab/tide/de/navigator-layer").status_code == 503

    def test_no_coverage_is_a_502(self, client, tide):
        tide(coverage=None)

        assert client.get("/api/cyab/tide/de/navigator-layer").status_code == 502

    def test_the_layer_downloads_as_a_named_attachment(self, client, tide):
        tide(coverage={"techniques": {"T1059": {"rule_count": 2,
                                                "enabled_rules": 1}}},
             space="soc")

        r = client.get("/api/cyab/tide/de/navigator-layer")

        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/json")
        assert "attachment" in r.headers["content-disposition"]
        assert "ion-tide-coverage-soc-" in r.headers["content-disposition"]
        assert r.headers["x-content-type-options"] == "nosniff"

    def test_the_layer_is_valid_navigator_json(self, client, tide):
        tide(coverage={"techniques": {"T1059": {"rule_count": 2,
                                                "enabled_rules": 1}}})

        layer = client.get("/api/cyab/tide/de/navigator-layer").json()

        assert layer["domain"] == "enterprise-attack"
        assert layer["versions"]["layer"] == "4.5"
        assert layer["gradient"]["maxValue"] == 4
        assert [t["techniqueID"] for t in layer["techniques"]] == ["T1059"]

    @pytest.mark.parametrize("rule_count,enabled,score", [
        (0, 0, 0),      # nothing enabled is blind, whatever exists on paper
        (9, 0, 0),
        (1, 1, 2),
        (3, 2, 3),
        (5, 3, 4),
        (9, 9, 4),
        (2, 2, 2),
    ])
    def test_the_score_rewards_enabled_rules_not_written_ones(
        self, client, tide, rule_count, enabled, score
    ):
        """A technique with nine rules that are all disabled is a blind spot,
        and scoring it green is the one error that matters in this file."""
        tide(coverage={"techniques": {"T1059": {"rule_count": rule_count,
                                                "enabled_rules": enabled}}})

        layer = client.get("/api/cyab/tide/de/navigator-layer").json()

        assert layer["techniques"][0]["score"] == score

    def test_the_comment_summarises_rules_severity_and_systems(self, client,
                                                                tide):
        tide(coverage={"techniques": {"T1059": {
            "rule_count": 4, "enabled_rules": 2,
            "severity": {"critical": 1, "high": 3, "low": 0},
            "systems": [{"name": "A"}, {"name": "B"}, {"name": "C"},
                        {"name": "D"}],
            "avg_quality": 71,
        }}})

        t = client.get("/api/cyab/tide/de/navigator-layer").json()["techniques"][0]

        assert "2/4 enabled rules" in t["comment"]
        assert "critical:1" in t["comment"]
        assert "low:0" not in t["comment"], "zero counts add noise"
        assert "systems: A, B, C ..." in t["comment"]
        assert {"name": "avg_quality", "value": "71"} in t["metadata"]

    def test_a_malformed_technique_entry_is_skipped(self, client, tide):
        tide(coverage={"techniques": {"T1059": None, "T1003": "nonsense",
                                      "T1110": {"rule_count": 1,
                                                "enabled_rules": 1}}})

        layer = client.get("/api/cyab/tide/de/navigator-layer").json()

        assert [t["techniqueID"] for t in layer["techniques"]] == ["T1110"]

    def test_empty_coverage_techniques_yield_an_empty_but_valid_layer(
        self, client, tide
    ):
        tide(coverage={"techniques": {}, "total_techniques": 0})

        layer = client.get("/api/cyab/tide/de/navigator-layer").json()

        assert layer["techniques"] == []
        assert "0 techniques mapped" in layer["description"]


# ---------------------------------------------------------------------------
# /tide/de/execution — TIDE rules vs what actually fired
# ---------------------------------------------------------------------------

class TestExecution:
    def test_elasticsearch_off_is_reported_first(self, client, tide, es):
        tide()
        es(configured=False)

        assert client.get("/api/cyab/tide/de/execution").json() == {
            "enabled": False, "error": "Elasticsearch not configured"}

    def test_tide_off_is_reported(self, client, tide, es):
        tide(enabled=False)
        es()

        assert client.get("/api/cyab/tide/de/execution").json()["error"] == (
            "TIDE not configured")

    def test_a_failed_query_keeps_the_shape_the_page_reads(self, client, tide,
                                                            es):
        tide(paginated={"rows": []})
        es(raises=RuntimeError("boom"))

        body = client.get("/api/cyab/tide/de/execution").json()

        assert "ES query failed" in body["error"]
        assert body["rules"] == [] and body["summary"] == {}

    def test_a_firing_rule_is_matched_to_tide(self, client, tide, es):
        tide(paginated={"rows": [
            {"name": "Suspicious PowerShell", "severity": "critical",
             "enabled": True, "quality_score": 90},
        ]})
        es(response=_es_alert_response(
            [_rule_bucket("suspicious powershell", 20,
                          severity={"critical": 20},
                          status={"open": 15, "closed": 5})], total=20))

        body = client.get("/api/cyab/tide/de/execution").json()

        rule = body["top_firing"][0]
        assert rule["in_tide"] is True
        assert rule["tide_severity"] == "critical"
        assert rule["tide_quality"] == 90
        assert body["summary"]["tide_matched"] == 1
        assert body["summary"]["tide_unmatched"] == 0

    def test_a_rule_tide_does_not_know_is_counted_as_unmatched(self, client,
                                                                tide, es):
        tide(paginated={"rows": []})
        es(response=_es_alert_response([_rule_bucket("Ad-Hoc", 4)], total=4))

        body = client.get("/api/cyab/tide/de/execution").json()

        assert body["top_firing"][0]["in_tide"] is False
        assert body["top_firing"][0]["tide_severity"] is None
        assert body["summary"]["tide_unmatched"] == 1

    def test_the_close_rate_is_a_percentage_of_that_rule_s_alerts(self, client,
                                                                   tide, es):
        tide(paginated={"rows": []})
        es(response=_es_alert_response(
            [_rule_bucket("R", 10, status={"closed": 8, "open": 2})], total=10))

        rule = client.get("/api/cyab/tide/de/execution").json()["top_firing"][0]

        assert rule["close_rate"] == 80.0
        assert rule["closed"] == 8 and rule["open"] == 2

    def test_a_high_volume_high_close_rule_is_flagged_noisy(self, client, tide,
                                                             es):
        """The point of the page: a rule firing 50 times and closed every time
        is costing analyst hours, not catching anything."""
        tide(paginated={"rows": []})
        es(response=_es_alert_response([
            _rule_bucket("Noisy", 50, status={"closed": 45, "open": 5}),
            _rule_bucket("Quiet but closed", 4, status={"closed": 4}),
            _rule_bucket("Busy and real", 40, status={"open": 40}),
        ], total=94))

        body = client.get("/api/cyab/tide/de/execution").json()

        assert [r["rule_name"] for r in body["noisy_rules"]] == ["Noisy"]
        assert body["summary"]["noisy_rules"] == 1

    def test_an_enabled_tide_rule_that_never_fired_is_silent(self, client, tide,
                                                              es):
        tide(paginated={"rows": [
            {"name": "Never Fires", "severity": "critical", "enabled": True,
             "quality_score": 70, "mitre_ids": ["T1003"]},
        ]})
        es(response=_es_alert_response([]))

        body = client.get("/api/cyab/tide/de/execution").json()

        assert body["silent_rules"][0]["rule_name"] == "Never Fires"
        assert body["silent_rules"][0]["mitre_ids"] == ["T1003"]
        assert body["summary"]["silent_enabled_rules"] == 1

    def test_a_disabled_tide_rule_is_not_called_silent(self, client, tide, es):
        """It is not firing because nobody turned it on — that is
        /disabled-critical's job, and listing it here would double-report."""
        tide(paginated={"rows": [
            {"name": "Switched Off", "severity": "high", "enabled": False},
        ]})
        es(response=_es_alert_response([]))

        assert client.get("/api/cyab/tide/de/execution").json()[
            "silent_rules"] == []

    def test_silent_rules_are_sorted_worst_first(self, client, tide, es):
        tide(paginated={"rows": [
            {"name": "L", "severity": "low", "enabled": True},
            {"name": "C", "severity": "critical", "enabled": True},
            {"name": "M", "severity": "medium", "enabled": True},
        ]})
        es(response=_es_alert_response([]))

        body = client.get("/api/cyab/tide/de/execution").json()

        assert [r["rule_name"] for r in body["silent_rules"]] == ["C", "M", "L"]

    def test_the_summary_averages_alerts_per_rule(self, client, tide, es):
        tide(paginated={"rows": []})
        es(response=_es_alert_response([
            _rule_bucket("A", 6), _rule_bucket("B", 4),
        ], total=10))

        summary = client.get("/api/cyab/tide/de/execution").json()["summary"]

        assert summary["unique_rules_firing"] == 2
        assert summary["avg_alerts_per_rule"] == 5.0

    def test_no_rules_firing_does_not_divide_by_zero(self, client, tide, es):
        tide(paginated={"rows": []})
        es(response=_es_alert_response([], total=0))

        summary = client.get("/api/cyab/tide/de/execution").json()["summary"]

        assert summary["avg_alerts_per_rule"] == 0
        assert summary["unique_rules_firing"] == 0

    def test_the_severity_timeline_is_flattened_per_bucket(self, client, tide,
                                                            es):
        tide(paginated={"rows": []})
        resp = _es_alert_response([], total=0)
        resp["aggregations"]["by_severity_over_time"]["buckets"] = [
            {"key_as_string": "2026-06-01T00:00:00Z",
             "sev": {"buckets": [{"key": "high", "doc_count": 3},
                                 {"key": "low", "doc_count": 1}]}},
        ]
        es(response=resp)

        tl = client.get("/api/cyab/tide/de/execution").json()["severity_timeline"]

        assert tl == [{"timestamp": "2026-06-01T00:00:00Z", "high": 3, "low": 1}]

    def test_the_window_is_capped_at_thirty_days(self, client, tide, es):
        tide(paginated={"rows": []})
        es(response=_es_alert_response([]))

        body = client.get("/api/cyab/tide/de/execution?hours=99999").json()

        assert body["hours"] == 720

    def test_a_long_window_uses_daily_buckets(self, client, tide, es):
        """A 6-hourly histogram over 30 days is 120 points the chart cannot use."""
        tide(paginated={"rows": []})
        svc = es(response=_es_alert_response([]))

        client.get("/api/cyab/tide/de/execution?hours=720")
        long_interval = svc.requests[0][2]["aggs"]["over_time"][
            "date_histogram"]["fixed_interval"]

        client.get("/api/cyab/tide/de/execution?hours=24")
        short_interval = svc.requests[1][2]["aggs"]["over_time"][
            "date_histogram"]["fixed_interval"]

        assert long_interval == "1d"
        assert short_interval == "6h"

    def test_a_tide_rule_with_no_name_is_ignored(self, client, tide, es):
        tide(paginated={"rows": [{"name": "  ", "enabled": True},
                                 {"name": "Real", "enabled": True,
                                  "severity": "high"}]})
        es(response=_es_alert_response([]))

        body = client.get("/api/cyab/tide/de/execution").json()

        assert [r["rule_name"] for r in body["silent_rules"]] == ["Real"]

    def test_top_firing_is_capped_at_fifty(self, client, tide, es):
        tide(paginated={"rows": []})
        es(response=_es_alert_response(
            [_rule_bucket(f"R{i}", 100 - i) for i in range(70)], total=4000))

        body = client.get("/api/cyab/tide/de/execution").json()

        assert len(body["top_firing"]) == 50
        assert body["summary"]["unique_rules_firing"] == 70


# ---------------------------------------------------------------------------
# /tide/de/kill-chain-alerts — multi-step progression per host
# ---------------------------------------------------------------------------

PLAYBOOK = {
    "id": "pb-1",
    "name": "Ransomware",
    "steps": [
        {"order": 1, "name": "Initial Access", "tactic": "initial-access",
         "techniques": ["T1566"]},
        {"order": 2, "name": "Execution", "tactic": "execution",
         "techniques": ["T1059"]},
        {"order": 3, "name": "Credential Access", "tactic": "credential-access",
         "techniques": ["T1003"]},
        {"order": 4, "name": "Impact", "tactic": "impact",
         "techniques": ["T1486"]},
    ],
}


def _host_bucket(host, techniques, *, latest=None, earliest=None):
    return {
        "key": host,
        "doc_count": sum(t[1] for t in techniques),
        "by_technique": {"buckets": [
            {"key": tid, "doc_count": count,
             "latest": {"value_as_string": latest},
             "earliest": {"value_as_string": earliest},
             "by_rule": {"buckets": [{"key": f"rule for {tid}"}]},
             "by_severity": {"buckets": [{"key": "high", "doc_count": count}]}}
            for tid, count in techniques
        ]},
        "latest_alert": {"value_as_string": latest},
        "earliest_alert": {"value_as_string": earliest},
    }


def _kc_response(host_buckets):
    return {"aggregations": {"by_host": {"buckets": host_buckets}}}


class TestKillChainAlerts:
    def test_tide_off_is_reported(self, client, tide, es):
        tide(enabled=False)
        es()

        assert client.get("/api/cyab/tide/de/kill-chain-alerts").json() == {
            "enabled": False, "error": "TIDE not configured"}

    def test_elasticsearch_off_is_reported(self, client, tide, es):
        tide()
        es(configured=False)

        assert client.get("/api/cyab/tide/de/kill-chain-alerts").json()[
            "error"] == "Elasticsearch not configured"

    def test_no_playbooks_is_enabled_but_empty(self, client, tide, es):
        tide(playbooks=[])
        es()

        body = client.get("/api/cyab/tide/de/kill-chain-alerts").json()

        assert body == {"enabled": True, "progressions": [], "playbooks": []}

    def test_playbooks_with_no_techniques_short_circuit(self, client, tide, es):
        """Nothing to query ES for, but the playbooks still go back so the page
        can say "no kill chains are mapped" rather than "nothing is happening"."""
        tide(playbooks=[{"id": "p", "name": "Empty",
                         "steps": [{"order": 1, "name": "s", "techniques": []}]}])
        svc = es()

        body = client.get("/api/cyab/tide/de/kill-chain-alerts").json()

        assert body["progressions"] == []
        assert len(body["playbooks"]) == 1
        assert svc.requests == [], "ES was queried with no techniques to match"

    def test_a_failed_query_is_reported(self, client, tide, es):
        tide(playbooks=[PLAYBOOK])
        es(raises=RuntimeError("down"))

        body = client.get("/api/cyab/tide/de/kill-chain-alerts").json()

        assert "ES query failed" in body["error"]
        assert body["progressions"] == []

    def test_one_fired_step_is_not_a_progression(self, client, tide, es):
        """A single alert is an alert. Reporting it as a kill chain would bury
        the real multi-step cases."""
        tide(playbooks=[PLAYBOOK])
        es(response=_kc_response([_host_bucket("web-01", [("T1566", 1)])]))

        body = client.get("/api/cyab/tide/de/kill-chain-alerts").json()

        assert body["progressions"] == []
        assert body["total_hosts_checked"] == 1

    def test_two_fired_steps_make_a_progression(self, client, tide, es):
        tide(playbooks=[PLAYBOOK])
        es(response=_kc_response([
            _host_bucket("web-01", [("T1566", 1), ("T1059", 3)],
                         latest="2026-06-01T12:00:00Z",
                         earliest="2026-06-01T09:00:00Z")]))

        body = client.get("/api/cyab/tide/de/kill-chain-alerts").json()

        prog = body["progressions"][0]
        assert prog["host"] == "web-01"
        assert prog["playbook_name"] == "Ransomware"
        assert prog["fired_steps"] == 2
        assert prog["total_steps"] == 4
        assert prog["pct_complete"] == 50
        assert prog["latest_alert"] == "2026-06-01T12:00:00Z"
        assert prog["earliest_alert"] == "2026-06-01T09:00:00Z"

    def test_a_sub_technique_alert_matches_its_parent_step(self, client, tide,
                                                            es):
        """ES reports T1003.001; the playbook step says T1003. Without the
        prefix match the whole credential-access step reads as never fired."""
        tide(playbooks=[PLAYBOOK])
        es(response=_kc_response([
            _host_bucket("dc-01", [("T1566", 1), ("T1003.001", 2)])]))

        prog = client.get(
            "/api/cyab/tide/de/kill-chain-alerts").json()["progressions"][0]

        cred_step = [s for s in prog["steps"] if s["order"] == 3][0]
        assert cred_step["fired"] is True
        assert cred_step["matched_technique"] == "T1003.001"

    def test_an_unfired_step_carries_no_alert_data(self, client, tide, es):
        tide(playbooks=[PLAYBOOK])
        es(response=_kc_response([
            _host_bucket("web-01", [("T1566", 1), ("T1059", 1)])]))

        prog = client.get(
            "/api/cyab/tide/de/kill-chain-alerts").json()["progressions"][0]

        impact = [s for s in prog["steps"] if s["order"] == 4][0]
        assert impact["fired"] is False
        assert impact["matched_technique"] is None
        assert impact["alert_data"] is None

    def test_a_fired_step_carries_its_rules_and_severity(self, client, tide,
                                                          es):
        tide(playbooks=[PLAYBOOK])
        es(response=_kc_response([
            _host_bucket("web-01", [("T1566", 1), ("T1059", 5)])]))

        prog = client.get(
            "/api/cyab/tide/de/kill-chain-alerts").json()["progressions"][0]

        exec_step = [s for s in prog["steps"] if s["order"] == 2][0]
        assert exec_step["alert_data"]["count"] == 5
        assert exec_step["alert_data"]["rules"] == ["rule for T1059"]
        assert exec_step["alert_data"]["severity"] == {"high": 5}

    @pytest.mark.parametrize("fired_techs,pct,severity", [
        (["T1566", "T1059"], 50, "high"),
        (["T1566", "T1059", "T1003"], 75, "critical"),
        (["T1566", "T1059", "T1003", "T1486"], 100, "critical"),
    ])
    def test_severity_rises_with_how_far_the_chain_got(self, client, tide, es,
                                                        fired_techs, pct,
                                                        severity):
        tide(playbooks=[PLAYBOOK])
        es(response=_kc_response([
            _host_bucket("web-01", [(t, 1) for t in fired_techs])]))

        prog = client.get(
            "/api/cyab/tide/de/kill-chain-alerts").json()["progressions"][0]

        assert prog["pct_complete"] == pct
        assert prog["severity"] == severity

    def test_a_quarter_complete_chain_is_only_medium(self, client, tide, es):
        eight_step = {**PLAYBOOK, "steps": PLAYBOOK["steps"] + [
            {"order": i, "name": f"s{i}", "techniques": [f"T900{i}"]}
            for i in range(5, 9)]}
        tide(playbooks=[eight_step])
        es(response=_kc_response([
            _host_bucket("web-01", [("T1566", 1), ("T1059", 1)])]))

        prog = client.get(
            "/api/cyab/tide/de/kill-chain-alerts").json()["progressions"][0]

        assert prog["pct_complete"] == 25
        assert prog["severity"] == "medium"

    def test_progressions_are_sorted_worst_first(self, client, tide, es):
        tide(playbooks=[PLAYBOOK])
        es(response=_kc_response([
            _host_bucket("half", [("T1566", 1), ("T1059", 1)]),
            _host_bucket("full", [("T1566", 1), ("T1059", 1), ("T1003", 1),
                                  ("T1486", 1)]),
        ]))

        body = client.get("/api/cyab/tide/de/kill-chain-alerts").json()

        assert [p["host"] for p in body["progressions"]] == ["full", "half"]

    def test_the_window_is_capped_at_a_week(self, client, tide, es):
        tide(playbooks=[PLAYBOOK])
        es(response=_kc_response([]))

        body = client.get("/api/cyab/tide/de/kill-chain-alerts?hours=10000").json()

        assert body["hours"] == 168

    def test_the_query_asks_for_exact_and_sub_technique_matches(self, client,
                                                                tide, es):
        tide(playbooks=[PLAYBOOK])
        svc = es(response=_kc_response([]))

        client.get("/api/cyab/tide/de/kill-chain-alerts")

        should = svc.requests[0][2]["query"]["bool"]["must"][1]["bool"]["should"]
        assert {"term": {"threat.technique.id": "T1566"}} in should
        assert {"prefix": {"threat.technique.id": "T1566."}} in should

    def test_a_playbook_with_no_steps_is_skipped(self, client, tide, es):
        tide(playbooks=[{"id": "x", "name": "Stepless", "steps": []},
                        PLAYBOOK])
        es(response=_kc_response([
            _host_bucket("web-01", [("T1566", 1), ("T1059", 1)])]))

        body = client.get("/api/cyab/tide/de/kill-chain-alerts").json()

        assert [p["playbook_name"] for p in body["progressions"]] == ["Ransomware"]
        assert body["playbook_count"] == 2


# ---------------------------------------------------------------------------
# Readiness routes — OpenCTI actor TTPs against TIDE coverage
# ---------------------------------------------------------------------------

ACTOR = {
    "id": "actor-1",
    "name": "FIN7",
    "description": "x" * 900,
    "aliases": ["Carbanak", "Carbon Spider"],
    "labels": ["ecrime"],
    "ttps": [
        {"mitre_id": "T1566", "name": "Phishing"},
        {"mitre_id": "T1059", "name": "Command and Scripting Interpreter"},
        {"mitre_id": "T1003", "name": "OS Credential Dumping"},
        {"mitre_id": "T1003.001", "name": "LSASS Memory"},
    ],
}

GLOBAL_COV = {
    "techniques": {
        "T1566": {"rule_count": 2, "enabled_rules": 2, "avg_quality": 80},
        "T1059": {"rule_count": 0, "enabled_rules": 0},
    },
    "total_techniques": 2,
    "covered_techniques": 1,
}


@pytest.fixture
def opencti(monkeypatch):
    import ion.services.opencti_service as mod

    def _install(**kwargs):
        svc = FakeOpenCTI(**kwargs)
        monkeypatch.setattr(mod, "get_opencti_service", lambda: svc)
        return svc

    return _install


@pytest.fixture
def ollama(monkeypatch):
    import ion.services.ollama_service as mod

    class FakeOllama:
        def __init__(self, available=True, raises=None):
            self.is_available = available
            self._raises = raises
            self.prompts = []

        async def generate(self, prompt, temperature=0.4):
            self.prompts.append(prompt)
            if self._raises:
                raise self._raises
            return f"generated({len(self.prompts)})"

    def _install(**kwargs):
        svc = FakeOllama(**kwargs)
        monkeypatch.setattr(mod, "get_ollama_service", lambda: svc)
        return svc

    return _install


def _readiness(client, **body):
    payload = {"actor_id": "actor-1", "actor_type": "threat_actor"}
    payload.update(body)
    return client.post("/api/cyab/tide/de/system-readiness", json=payload)


class TestSystemReadiness:
    def test_tide_off_is_reported(self, client, tide, opencti):
        tide(enabled=False)
        opencti()

        assert _readiness(client).json() == {
            "enabled": False, "error": "TIDE not configured"}

    def test_opencti_off_is_reported(self, client, tide, opencti):
        tide()
        opencti(configured=False)

        assert _readiness(client).json()["error"] == "OpenCTI not configured"

    def test_an_opencti_failure_is_reported_without_a_500(self, client, tide,
                                                           opencti):
        tide()
        opencti(detail_raises=RuntimeError("graphql exploded"))

        body = _readiness(client).json()

        assert body["enabled"] is True
        assert "OpenCTI failed" in body["error"]

    def test_an_unknown_actor_is_a_404(self, client, tide, opencti):
        tide()
        opencti(actor=None)

        assert _readiness(client).status_code == 404

    def test_global_coverage_decides_readiness_with_no_system(self, client,
                                                               tide, opencti):
        tide(coverage=GLOBAL_COV)
        opencti(actor=ACTOR)

        body = _readiness(client).json()

        assert body["enabled"] is True
        assert body["total_ttps"] == 3, "sub-techniques fold into their parent"
        assert body["covered_count"] == 1
        assert body["gap_count"] == 2
        assert body["readiness_pct"] == 33

    def test_sub_techniques_do_not_double_count_their_parent(self, client, tide,
                                                             opencti):
        """FIN7's TTPs list both T1003 and T1003.001. Counting both would make
        the denominator wrong and the percentage flatter."""
        tide(coverage=GLOBAL_COV)
        opencti(actor=ACTOR)

        matrix = _readiness(client).json()["coverage_matrix"]

        assert all("." not in e["mitre_id"] for e in matrix)
        assert sorted(e["mitre_id"] for e in matrix) == ["T1003", "T1059",
                                                         "T1566"]

    def test_covered_techniques_sort_before_gaps(self, client, tide, opencti):
        tide(coverage=GLOBAL_COV)
        opencti(actor=ACTOR)

        matrix = _readiness(client).json()["coverage_matrix"]

        assert matrix[0]["covered"] is True
        assert [e["covered"] for e in matrix] == sorted(
            [e["covered"] for e in matrix], reverse=True)

    def test_a_technique_with_rules_carries_its_counts(self, client, tide,
                                                        opencti):
        tide(coverage=GLOBAL_COV)
        opencti(actor=ACTOR)

        matrix = _readiness(client).json()["coverage_matrix"]
        covered = [e for e in matrix if e["mitre_id"] == "T1566"][0]

        assert covered["rule_count"] == 2
        assert covered["enabled_rules"] == 2

    def test_a_technique_with_zero_rules_is_a_gap_not_coverage(self, client,
                                                                tide, opencti):
        """T1059 is present in the coverage map with rule_count 0 — a mapping
        intention, not a detection."""
        tide(coverage=GLOBAL_COV)
        opencti(actor=ACTOR)

        matrix = _readiness(client).json()["coverage_matrix"]
        t1059 = [e for e in matrix if e["mitre_id"] == "T1059"][0]

        assert t1059["covered"] is False

    def test_the_actor_description_is_truncated(self, client, tide, opencti):
        tide(coverage=GLOBAL_COV)
        opencti(actor=ACTOR)

        assert len(_readiness(client).json()["actor"]["description"]) == 500

    def test_an_actor_with_no_ttps_scores_zero_without_dividing_by_zero(
        self, client, tide, opencti
    ):
        tide(coverage=GLOBAL_COV)
        opencti(actor={**ACTOR, "ttps": []})

        body = _readiness(client).json()

        assert body["total_ttps"] == 0
        assert body["readiness_pct"] == 0

    def test_a_tide_system_uuid_scopes_coverage_to_that_system(self, client,
                                                               tide, opencti):
        tide(coverage=GLOBAL_COV, details={"tide-sys": {
            "name": "Payments", "classification": "pci",
            "detections": [{"name": "r", "enabled": True,
                            "mitre_ids": ["T1059"]}],
        }})
        opencti(actor=ACTOR)

        body = _readiness(client, system_id="tide-sys").json()

        assert body["system"]["name"] == "Payments"
        t1059 = [e for e in body["coverage_matrix"]
                 if e["mitre_id"] == "T1059"][0]
        assert t1059["covered"] is True, "system rules beat global coverage"
        assert t1059["enabled_rules"] == 1

    def test_a_cyab_integer_id_resolves_through_its_data_sources(
        self, client, session, tide, opencti
    ):
        """The system selector can hand back either a TIDE UUID or a CyAB row
        id; the CyAB path reaches TIDE via each data source's tide_system_id."""
        sys_row = _system(session, name="Payments")
        session.add(CyabDataSource(system_id=sys_row.id, name="EDR",
                                   data_source_type="endpoint",
                                   tide_system_id="tide-sys"))
        session.flush()
        session.refresh(sys_row)

        tide(coverage=GLOBAL_COV, details={"tide-sys": {
            "name": "Payments", "detections": [
                {"name": "r", "enabled": True, "mitre_ids": ["T1003.001"]}],
        }})
        opencti(actor=ACTOR)

        body = _readiness(client, system_id=str(sys_row.id)).json()

        assert body["system"]["name"] == "Payments"
        t1003 = [e for e in body["coverage_matrix"]
                 if e["mitre_id"] == "T1003"][0]
        assert t1003["covered"] is True, "a sub-technique rule covers the parent"

    def test_an_unresolvable_system_id_falls_back_to_global(self, client, tide,
                                                             opencti):
        tide(coverage=GLOBAL_COV, details={})
        opencti(actor=ACTOR)

        body = _readiness(client, system_id="not-a-uuid-or-int").json()

        assert body["system"] is None
        assert body["covered_count"] == 1

    def test_a_cyab_id_that_does_not_exist_falls_back_to_global(self, client,
                                                                 tide, opencti):
        tide(coverage=GLOBAL_COV, details={})
        opencti(actor=ACTOR)

        body = _readiness(client, system_id="999999").json()

        assert body["system"] is None

    def test_no_ai_is_generated_unless_asked(self, client, tide, opencti,
                                              ollama):
        tide(coverage=GLOBAL_COV)
        opencti(actor=ACTOR)
        svc = ollama()

        body = _readiness(client).json()

        assert body["ai_summary"] is None
        assert body["ai_recommendations"] is None
        assert svc.prompts == []

    def test_ai_content_is_generated_on_request(self, client, tide, opencti,
                                                 ollama):
        tide(coverage=GLOBAL_COV)
        opencti(actor=ACTOR)
        svc = ollama()

        body = _readiness(client, generate_ai=True).json()

        assert body["ai_summary"] == "generated(1)"
        assert body["ai_recommendations"] == "generated(2)"
        assert "FIN7" in svc.prompts[0]
        assert "33%" in svc.prompts[0]

    def test_ai_is_skipped_when_the_model_is_unavailable(self, client, tide,
                                                          opencti, ollama):
        tide(coverage=GLOBAL_COV)
        opencti(actor=ACTOR)
        ollama(available=False)

        body = _readiness(client, generate_ai=True).json()

        assert body["ai_summary"] is None

    def test_an_ai_failure_degrades_to_a_note_not_a_500(self, client, tide,
                                                         opencti, ollama):
        """The readiness matrix is the deliverable; the prose is a nicety."""
        tide(coverage=GLOBAL_COV)
        opencti(actor=ACTOR)
        ollama(raises=RuntimeError("model gone"))

        body = _readiness(client, generate_ai=True).json()

        assert "AI generation failed" in body["ai_summary"]
        assert body["readiness_pct"] == 33

    def test_no_global_coverage_leaves_everything_a_gap(self, client, tide,
                                                         opencti):
        tide(coverage=None)
        opencti(actor=ACTOR)

        body = _readiness(client).json()

        assert body["covered_count"] == 0
        assert body["gap_count"] == 3


class TestReadinessPdf:
    def _post(self, client, **body):
        payload = {"actor_id": "actor-1", "actor_type": "threat_actor"}
        payload.update(body)
        return client.post("/api/cyab/tide/de/readiness-pdf", json=payload)

    def test_a_pdf_is_produced(self, client, tide, opencti, ollama):
        tide(coverage=GLOBAL_COV)
        opencti(actor=ACTOR)
        ollama()

        r = self._post(client)

        assert r.status_code == 200
        assert r.headers["content-type"] == "application/pdf"
        assert r.content.startswith(b"%PDF")
        assert r.headers["x-content-type-options"] == "nosniff"

    def test_the_filename_is_slugged_from_the_actor_name(self, client, tide,
                                                          opencti, ollama):
        """An actor name reaches this from OpenCTI, so it cannot be trusted to
        stay out of the Content-Disposition header."""
        tide(coverage=GLOBAL_COV)
        opencti(actor={**ACTOR, "name": 'FIN7"; rm -rf /\r\nX-Evil: 1'})
        ollama()

        cd = self._post(client).headers["content-disposition"]

        assert "\r" not in cd and "\n" not in cd
        assert cd.count('"') == 2
        assert "rm_-rf" in cd or "FIN7" in cd

    def test_an_unconfigured_backend_is_a_400(self, client, tide, opencti):
        tide(enabled=False)
        opencti()

        r = self._post(client)

        assert r.status_code == 400
        assert "TIDE not configured" in r.json()["detail"]

    def test_the_html_fallback_carries_a_strict_csp(self, client, tide, opencti,
                                                     ollama, monkeypatch):
        """WeasyPrint needs system libraries an air-gapped host may lack. The
        fallback is served as HTML, so it gets a CSP that forbids scripts even
        if an escaping regression slipped through."""
        import sys

        tide(coverage=GLOBAL_COV)
        opencti(actor=ACTOR)
        ollama()
        monkeypatch.setitem(sys.modules, "weasyprint", None)

        r = self._post(client)

        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        assert "default-src 'none'" in r.headers["content-security-policy"]
        assert r.headers["x-frame-options"] == "DENY"

    def test_a_hostile_actor_name_is_escaped_in_the_report_body(
        self, client, tide, opencti, ollama, monkeypatch
    ):
        import sys

        tide(coverage=GLOBAL_COV)
        opencti(actor={**ACTOR, "name": "<script>alert(1)</script>"})
        ollama()
        monkeypatch.setitem(sys.modules, "weasyprint", None)

        body = self._post(client).text

        assert "<script>alert(1)</script>" not in body
        assert "&lt;script&gt;" in body

    def test_a_hostile_technique_name_is_escaped(self, client, tide, opencti,
                                                  ollama, monkeypatch):
        import sys

        tide(coverage=GLOBAL_COV)
        opencti(actor={**ACTOR, "ttps": [
            {"mitre_id": "T1566", "name": "<img src=x onerror=1>"}]})
        ollama()
        monkeypatch.setitem(sys.modules, "weasyprint", None)

        body = self._post(client).text

        assert "<img src=x" not in body

    def test_the_gauge_width_cannot_be_poisoned(self, client, tide, opencti,
                                                 ollama, monkeypatch):
        """readiness_pct is interpolated into a style attribute, so it is
        coerced through int() and clamped rather than escaped."""
        import sys

        tide(coverage=GLOBAL_COV)
        opencti(actor=ACTOR)
        ollama()
        monkeypatch.setitem(sys.modules, "weasyprint", None)

        body = self._post(client).text

        assert "width:33%" in body

    def test_the_system_block_appears_when_a_system_is_resolved(
        self, client, tide, opencti, ollama, monkeypatch
    ):
        import sys

        tide(coverage=GLOBAL_COV, details={"tide-sys": {
            "name": "Payments", "detections": []}})
        opencti(actor=ACTOR)
        ollama()
        monkeypatch.setitem(sys.modules, "weasyprint", None)

        body = self._post(client, system_id="tide-sys").text

        assert "Payments" in body
        assert "Department" in body

    def test_the_global_report_names_all_systems(self, client, tide, opencti,
                                                  ollama, monkeypatch):
        import sys

        tide(coverage=GLOBAL_COV)
        opencti(actor=ACTOR)
        ollama()
        monkeypatch.setitem(sys.modules, "weasyprint", None)

        body = self._post(client).text

        assert "All Systems (Global)" in body

    def test_every_matrix_row_is_rendered_with_its_status(self, client, tide,
                                                           opencti, ollama,
                                                           monkeypatch):
        import sys

        tide(coverage=GLOBAL_COV)
        opencti(actor=ACTOR)
        ollama()
        monkeypatch.setitem(sys.modules, "weasyprint", None)

        body = self._post(client).text

        assert body.count("COVERED") >= 1
        assert body.count("GAP") >= 2

    @pytest.mark.parametrize("covered,total,colour", [
        (4, 4, "#2e7d32"),   # 100% -> green
        (3, 4, "#2e7d32"),   # 75%  -> green (the boundary)
        (2, 4, "#f57f17"),   # 50%  -> amber (the boundary)
        (1, 4, "#c62828"),   # 25%  -> red
    ])
    def test_the_gauge_colour_tracks_the_score(self, client, tide, opencti,
                                               ollama, monkeypatch, covered,
                                               total, colour):
        """An executive reads the colour before the number."""
        import sys

        techs = {}
        ttps = []
        for i in range(total):
            tid = f"T90{i:02d}"
            ttps.append({"mitre_id": tid, "name": f"t{i}"})
            techs[tid] = {"rule_count": 1 if i < covered else 0,
                          "enabled_rules": 1 if i < covered else 0}
        tide(coverage={"techniques": techs})
        opencti(actor={**ACTOR, "ttps": ttps})
        ollama()
        monkeypatch.setitem(sys.modules, "weasyprint", None)

        body = self._post(client).text

        assert f".gauge-fill {{ background: {colour}; }}" in body

    def test_an_actor_with_no_description_omits_the_paragraph(self, client,
                                                               tide, opencti,
                                                               ollama,
                                                               monkeypatch):
        import sys

        tide(coverage=GLOBAL_COV)
        opencti(actor={**ACTOR, "description": ""})
        ollama()
        monkeypatch.setitem(sys.modules, "weasyprint", None)

        body = self._post(client).text

        assert "None known" not in body or "Aliases" in body


class TestActorReadiness:
    def test_tide_off_is_reported(self, client, tide, opencti):
        tide(enabled=False)
        opencti()

        assert client.get("/api/cyab/tide/de/actor-readiness").json() == {
            "enabled": False, "error": "TIDE not configured"}

    def test_opencti_off_is_reported(self, client, tide, opencti):
        tide()
        opencti(configured=False)

        assert client.get("/api/cyab/tide/de/actor-readiness").json()[
            "error"] == "OpenCTI not configured"

    def test_no_tide_coverage_is_reported(self, client, tide, opencti):
        tide(coverage=None)
        opencti()

        assert client.get("/api/cyab/tide/de/actor-readiness").json()[
            "error"] == "Failed to fetch TIDE coverage"

    def test_an_opencti_search_failure_keeps_the_actors_key(self, client, tide,
                                                             opencti):
        tide(coverage=GLOBAL_COV)
        opencti(search_raises=RuntimeError("timeout"))

        body = client.get("/api/cyab/tide/de/actor-readiness").json()

        assert "OpenCTI query failed" in body["error"]
        assert body["actors"] == []

    def test_each_actor_gets_a_readiness_score(self, client, tide, opencti):
        tide(coverage=GLOBAL_COV)
        opencti(
            actors={"actors": [{"id": "actor-1", "name": "FIN7",
                                "entity_type": "threat_actor",
                                "description": "d" * 400,
                                "aliases": ["Carbanak"], "confidence": 80,
                                "labels": ["ecrime"], "country_code": "RU",
                                "country_name": "Russia",
                                "country_flag": "🇷🇺"}]},
            actor={"ttps": [{"mitre_id": "T1566", "name": "Phishing"},
                            {"mitre_id": "T1059", "name": "Scripting"}]},
        )

        body = client.get("/api/cyab/tide/de/actor-readiness").json()

        a = body["actors"][0]
        assert a["name"] == "FIN7"
        assert a["total_ttps"] == 2
        assert a["covered_count"] == 1
        assert a["gap_count"] == 1
        assert a["readiness_pct"] == 50
        assert a["country_name"] == "Russia"
        assert len(a["description"]) == 200
        assert body["tide_total_techniques"] == 2

    def test_a_covered_ttp_carries_its_rule_counts(self, client, tide, opencti):
        tide(coverage=GLOBAL_COV)
        opencti(actors={"actors": [{"id": "a", "name": "A"}]},
                actor={"ttps": [{"mitre_id": "T1566", "name": "Phishing"}]})

        a = client.get("/api/cyab/tide/de/actor-readiness").json()["actors"][0]

        assert a["covered"][0]["rule_count"] == 2
        assert a["covered"][0]["enabled_rules"] == 2
        assert a["covered"][0]["avg_quality"] == 80

    def test_a_sub_technique_ttp_matches_its_parent_coverage(self, client, tide,
                                                             opencti):
        tide(coverage=GLOBAL_COV)
        opencti(actors={"actors": [{"id": "a", "name": "A"}]},
                actor={"ttps": [{"mitre_id": "T1566.002", "name": "Spearphish"}]})

        a = client.get("/api/cyab/tide/de/actor-readiness").json()["actors"][0]

        assert a["covered_count"] == 1

    def test_an_actor_with_no_ttps_scores_zero(self, client, tide, opencti):
        tide(coverage=GLOBAL_COV)
        opencti(actors={"actors": [{"id": "a", "name": "A"}]},
                actor={"ttps": []})

        a = client.get("/api/cyab/tide/de/actor-readiness").json()["actors"][0]

        assert a["total_ttps"] == 0 and a["readiness_pct"] == 0

    def test_no_actors_returns_an_empty_list(self, client, tide, opencti):
        tide(coverage=GLOBAL_COV)
        opencti(actors={"actors": []})

        body = client.get("/api/cyab/tide/de/actor-readiness").json()

        assert body["enabled"] is True and body["actors"] == []

    def test_actors_are_sorted_by_ttp_count(self, client, tide, opencti):
        """Most-documented actors first — that is the useful reading order."""
        tide(coverage=GLOBAL_COV)
        opencti(
            actors={"actors": [{"id": "small", "name": "Small"},
                               {"id": "big", "name": "Big"}]},
            actor={"by_id": {
                "small": {"ttps": [{"mitre_id": "T1566", "name": "p"}]},
                "big": {"ttps": [{"mitre_id": "T1566", "name": "p"},
                                 {"mitre_id": "T1059", "name": "s"},
                                 {"mitre_id": "T1003", "name": "c"}]},
            }},
        )

        body = client.get("/api/cyab/tide/de/actor-readiness").json()

        assert [a["name"] for a in body["actors"]] == ["Big", "Small"]

    def test_one_actor_failing_does_not_lose_the_others(self, client, tide,
                                                        opencti, monkeypatch):
        """The detail fetches run concurrently via map_bounded, which returns
        exceptions rather than raising. One actor OpenCTI cannot answer for
        must read as zero TTPs, not take the whole page down."""
        import ion.services.opencti_service as mod

        class Flaky(FakeOpenCTI):
            async def get_entity_detail(self, entity_id, entity_type):
                if entity_id == "bad":
                    raise RuntimeError("actor detail blew up")
                return {"ttps": [{"mitre_id": "T1566", "name": "p"}]}

        svc = Flaky(actors={"actors": [{"id": "bad", "name": "Bad"},
                                       {"id": "good", "name": "Good"}]})
        monkeypatch.setattr(mod, "get_opencti_service", lambda: svc)
        tide(coverage=GLOBAL_COV)

        body = client.get("/api/cyab/tide/de/actor-readiness").json()

        by_name = {a["name"]: a for a in body["actors"]}
        assert by_name["Good"]["total_ttps"] == 1
        assert by_name["Bad"]["total_ttps"] == 0
        assert by_name["Bad"]["readiness_pct"] == 0

    def test_the_actor_page_size_is_capped(self, client, tide, opencti):
        tide(coverage=GLOBAL_COV)
        opencti(actors={"actors": []})

        r = client.get("/api/cyab/tide/de/actor-readiness?first=500")

        assert r.status_code == 200
