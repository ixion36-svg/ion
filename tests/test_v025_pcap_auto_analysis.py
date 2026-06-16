"""Tests for the v0.25.x PCAP auto-analysis multi-alert wiring.

Covers the four changes layered on top of the v0.16.0 pipeline:

1. ``_extract_community_and_node`` handles ECS nested, flattened, and
   missing forms uniformly — and recovers the top-level ``arkime_node``
   even when no nested ``arkime`` dict is present (v0.16.0 bug).
2. ``_build_pcap_flows`` reads from ``ctx.raw_data`` when available.
3. ``_build_pcap_flows`` falls back to ``ElasticsearchService.
   get_alerts_by_ids`` when contexts arrive without raw_data — the
   multi-select case-create path on the alerts list page.
4. ``enqueue_pcap_analysis_for_case`` dedups by ``community_id`` while
   preserving order, accepts the new ``flows`` shape, AND accepts the
   legacy ``community_ids`` + ``alert_node_hint`` kwargs (back-compat).

No external Arkime / ES traffic — the ES service is monkeypatched and
the PCAP service is observed via ``unique_flows_consumed`` rather than
fired.
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


class TestAutoCaseEsFactoryImport:
    """v0.39.1 regression guard for the bug that made the Arkime auto-case loop
    create ZERO cases from v0.34.0 to v0.39.0: ``arkime_auto_case_service._run_pass``
    imported ``get_elasticsearch_service`` from ``ion.services.elasticsearch_service``,
    but the factory was refactored into ``connectors.elasticsearch_connector``. The
    ImportError was swallowed by the pass's try/except ("import failed") so the loop
    silently returned every pass."""

    def test_factory_lives_in_connector(self):
        from ion.services.connectors.elasticsearch_connector import (
            get_elasticsearch_service,
        )
        assert callable(get_elasticsearch_service)

    def test_run_pass_imports_from_correct_module(self):
        import ion.services.arkime_auto_case_service as aac
        src = inspect.getsource(aac._run_pass)
        assert "connectors.elasticsearch_connector import" in src, (
            "auto-case loop must import get_elasticsearch_service from the connector"
        )
        assert "from ion.services.elasticsearch_service import get_elasticsearch_service" not in src, (
            "the broken import is back — the auto-case loop will create no cases"
        )


# ── _extract_community_and_node ──────────────────────────────────────────


class TestExtractCommunityAndNode:
    def test_ecs_nested_form(self):
        from ion.web.case_lifecycle_api import _extract_community_and_node
        cid, node = _extract_community_and_node({
            "network": {"community_id": "1:abc123"},
            "arkime_node": "cap-01",
        })
        assert cid == "1:abc123"
        assert node == "cap-01"

    def test_flattened_dotted_key(self):
        from ion.web.case_lifecycle_api import _extract_community_and_node
        cid, _ = _extract_community_and_node({"network.community_id": "1:flat"})
        assert cid == "1:flat"

    def test_bare_community_id_key(self):
        from ion.web.case_lifecycle_api import _extract_community_and_node
        cid, _ = _extract_community_and_node({"community_id": "1:bare"})
        assert cid == "1:bare"

    def test_node_hint_top_level_without_nested_arkime_dict(self):
        """Regression for the v0.16.0 ``or x if isinstance else None`` bug.

        Previously: when raw_data has ``arkime_node`` at top level but
        no nested ``arkime`` dict, the precedence on the original
        expression evaluated to None and the top-level value was lost.
        """
        from ion.web.case_lifecycle_api import _extract_community_and_node
        _, node = _extract_community_and_node({
            "network": {"community_id": "1:n"},
            "arkime_node": "cap-02",
            # No nested "arkime" key.
        })
        assert node == "cap-02"

    def test_node_hint_nested_form(self):
        from ion.web.case_lifecycle_api import _extract_community_and_node
        _, node = _extract_community_and_node({
            "network": {"community_id": "1:n"},
            "arkime": {"node": "cap-03"},
        })
        assert node == "cap-03"

    def test_no_community_id(self):
        from ion.web.case_lifecycle_api import _extract_community_and_node
        cid, node = _extract_community_and_node({"network": {"src_ip": "10.0.0.1"}})
        assert cid is None
        assert node is None

    def test_non_dict_input(self):
        from ion.web.case_lifecycle_api import _extract_community_and_node
        assert _extract_community_and_node(None) == (None, None)
        assert _extract_community_and_node("not a dict") == (None, None)


class TestParseAlertArkimeLinkage:
    """v0.39.1: the AUTO-CASE path reads ElasticsearchAlert.network_community_id
    and .arkime_node populated by ElasticsearchService._parse_alert (distinct
    from ion.web.api._extract_community_and_node above). The node extraction was
    broadened so common schemas (nested node, ECS observer.hostname) qualify —
    previously a `source.get("node")` flat-key-only check missed them, so the
    `community_id AND arkime_node` filter dropped every alert and no auto-cases
    were created."""

    def _parse(self, source):
        from ion.services.elasticsearch_service import ElasticsearchService
        return ElasticsearchService()._parse_alert("alert-1", source)

    def test_observer_hostname(self):
        a = self._parse({"network": {"community_id": "1:abc"}, "observer": {"hostname": "cap-host"}})
        assert a.network_community_id == "1:abc"
        assert a.arkime_node == "cap-host"

    def test_observer_name(self):
        a = self._parse({"network.community_id": "1:flat", "observer": {"name": "cap-name"}})
        assert a.arkime_node == "cap-name"

    def test_nested_node_dict(self):
        a = self._parse({"network": {"community_id": "1:n"}, "node": {"name": "cap-nested"}})
        assert a.arkime_node == "cap-nested"

    def test_arkime_node_dotted(self):
        a = self._parse({"network": {"community_id": "1:n"}, "arkime": {"node": "cap-ark"}})
        assert a.arkime_node == "cap-ark"

    def test_community_without_node_yields_no_node(self):
        # community_id present but no recognised node field → arkime_node None,
        # so the auto-case filter correctly skips it (and the diagnostic logs why).
        a = self._parse({"network": {"community_id": "1:n"}})
        assert a.network_community_id == "1:n"
        assert a.arkime_node is None


# ── _build_pcap_flows ────────────────────────────────────────────────────


def _make_ctx(alert_id: str, raw_data: Any) -> Any:
    """Cheap stand-in for the AlertContext pydantic model."""
    return SimpleNamespace(alert_id=alert_id, raw_data=raw_data, host=None, user=None)


class TestBuildPcapFlows:
    def test_contexts_with_raw_data_skip_es(self, monkeypatch):
        """When every alert has raw_data in context, no ES round trip fires."""
        import asyncio

        from ion.web import case_lifecycle_api as api

        called = {"es_calls": 0}

        class FakeES:
            async def get_alerts_by_ids(self, ids):
                called["es_calls"] += 1
                return []

        monkeypatch.setattr(api, "get_elasticsearch_service", lambda: FakeES())

        flows = asyncio.run(api._build_pcap_flows(
            alert_ids=["a1", "a2"],
            alert_contexts=[
                _make_ctx("a1", {"network": {"community_id": "1:flow-a"}, "arkime_node": "n1"}),
                _make_ctx("a2", {"network": {"community_id": "1:flow-b"}, "arkime_node": "n2"}),
            ],
        ))

        assert called["es_calls"] == 0
        assert flows == [
            {"community_id": "1:flow-a", "node_hint": "n1", "alert_id": "a1",
             "source_ip": None, "destination_ip": None, "alert_timestamp": None},
            {"community_id": "1:flow-b", "node_hint": "n2", "alert_id": "a2",
             "source_ip": None, "destination_ip": None, "alert_timestamp": None},
        ]

    def test_falls_back_to_es_when_raw_data_missing(self, monkeypatch):
        """Multi-select case-create gap: contexts without raw_data → ES fetch."""
        import asyncio

        from ion.web import case_lifecycle_api as api

        observed: Dict[str, Any] = {}

        class FakeES:
            async def get_alerts_by_ids(self, ids):
                observed["requested_ids"] = list(ids)
                return [
                    SimpleNamespace(
                        id="a-multi-1",
                        raw_data={"network": {"community_id": "1:fetched"}, "arkime_node": "cap-9"},
                    ),
                    SimpleNamespace(
                        id="a-multi-2",
                        raw_data={"network": {"community_id": "1:other"}, "arkime_node": "cap-9"},
                    ),
                ]

        monkeypatch.setattr(api, "get_elasticsearch_service", lambda: FakeES())

        flows = asyncio.run(api._build_pcap_flows(
            alert_ids=["a-multi-1", "a-multi-2"],
            alert_contexts=[
                _make_ctx("a-multi-1", None),
                _make_ctx("a-multi-2", None),
            ],
        ))

        assert observed["requested_ids"] == ["a-multi-1", "a-multi-2"]
        assert flows == [
            {"community_id": "1:fetched", "node_hint": "cap-9", "alert_id": "a-multi-1",
             "source_ip": None, "destination_ip": None, "alert_timestamp": None},
            {"community_id": "1:other", "node_hint": "cap-9", "alert_id": "a-multi-2",
             "source_ip": None, "destination_ip": None, "alert_timestamp": None},
        ]

    def test_hybrid_context_some_ids_via_es(self, monkeypatch):
        """One alert via context, one via ES — both flows surface."""
        import asyncio

        from ion.web import case_lifecycle_api as api

        class FakeES:
            async def get_alerts_by_ids(self, ids):
                assert ids == ["a-multi"]
                return [
                    SimpleNamespace(
                        id="a-multi",
                        raw_data={"network": {"community_id": "1:from-es"}},
                    ),
                ]

        monkeypatch.setattr(api, "get_elasticsearch_service", lambda: FakeES())

        flows = asyncio.run(api._build_pcap_flows(
            alert_ids=["a-single", "a-multi"],
            alert_contexts=[
                _make_ctx("a-single", {"network": {"community_id": "1:from-ctx"}}),
                _make_ctx("a-multi", None),
            ],
        ))

        # Context-bearing alert processed first (matches alert_ids order).
        assert flows[0]["alert_id"] == "a-single"
        assert flows[0]["community_id"] == "1:from-ctx"
        assert flows[1]["alert_id"] == "a-multi"
        assert flows[1]["community_id"] == "1:from-es"

    def test_es_failure_is_non_fatal(self, monkeypatch):
        """If ES raises, the helper returns whatever flows it already has."""
        import asyncio

        from ion.web import case_lifecycle_api as api

        class BoomES:
            async def get_alerts_by_ids(self, ids):
                raise RuntimeError("ES unreachable")

        monkeypatch.setattr(api, "get_elasticsearch_service", lambda: BoomES())

        flows = asyncio.run(api._build_pcap_flows(
            alert_ids=["a-ctx", "a-missing"],
            alert_contexts=[
                _make_ctx("a-ctx", {"network": {"community_id": "1:still-here"}}),
                _make_ctx("a-missing", None),
            ],
        ))
        assert flows == [
            {"community_id": "1:still-here", "node_hint": None, "alert_id": "a-ctx",
             "source_ip": None, "destination_ip": None, "alert_timestamp": None},
        ]

    def test_alerts_without_community_id_are_dropped(self, monkeypatch):
        import asyncio

        from ion.web import case_lifecycle_api as api

        class FakeES:
            async def get_alerts_by_ids(self, ids):
                return []

        monkeypatch.setattr(api, "get_elasticsearch_service", lambda: FakeES())

        flows = asyncio.run(api._build_pcap_flows(
            alert_ids=["a1", "a2"],
            alert_contexts=[
                _make_ctx("a1", {"network": {"src_ip": "10.0.0.1"}}),  # no community_id
                _make_ctx("a2", {"network": {"community_id": "1:keep"}}),
            ],
        ))
        assert flows == [
            {"community_id": "1:keep", "node_hint": None, "alert_id": "a2",
             "source_ip": None, "destination_ip": None, "alert_timestamp": None},
        ]


# ── enqueue_pcap_analysis_for_case dedup + back-compat ───────────────────


class TestEnqueueDedup:
    def test_dedup_by_community_id_preserves_first(self, monkeypatch):
        """Two alerts sharing a flow hash → one note, attributed to the
        FIRST alert; the node_hint from the first occurrence wins."""
        from ion.services import pcap_analysis_service as svc

        consumed: List[List[Dict]] = []

        async def fake_runner(case_id, flows):
            consumed.append(flows)

        monkeypatch.setattr(svc, "_runner", fake_runner)

        # Force the daemon-thread path so we can assert against consumed
        # synchronously after a short join. asyncio.get_running_loop()
        # will raise inside a sync test which falls back to the bg
        # thread.
        svc.enqueue_pcap_analysis_for_case(
            case_id=42,
            flows=[
                {"community_id": "1:shared", "node_hint": "cap-A", "alert_id": "a1"},
                {"community_id": "1:other", "node_hint": "cap-B", "alert_id": "a2"},
                {"community_id": "1:shared", "node_hint": "cap-A-dup", "alert_id": "a3"},
            ],
        )

        # The bg thread runs asyncio.run synchronously and is daemonic.
        # Join briefly to allow completion.
        import threading
        for t in threading.enumerate():
            if t.name == "ion-pcap-42":
                t.join(timeout=2.0)
                break

        assert len(consumed) == 1
        cids = [f["community_id"] for f in consumed[0]]
        assert cids == ["1:shared", "1:other"]
        # First-wins for node_hint and alert_id.
        assert consumed[0][0]["node_hint"] == "cap-A"
        assert consumed[0][0]["alert_id"] == "a1"

    def test_dedup_preserves_ip_and_timestamp_fields(self, monkeypatch):
        """v0.39.1 regression: dedup must carry source_ip / destination_ip /
        alert_timestamp through to _runner. Dropping them silently disabled
        _analyze_one's IP-fallback (used when Arkime's community_id index
        misses), so auto-cases got empty PCAP notes."""
        from ion.services import pcap_analysis_service as svc

        consumed: List[List[Dict]] = []

        async def fake_runner(case_id, flows):
            consumed.append(flows)

        monkeypatch.setattr(svc, "_runner", fake_runner)

        svc.enqueue_pcap_analysis_for_case(
            case_id=45,
            flows=[{
                "community_id": "1:flow", "node_hint": "cap-A", "alert_id": "a1",
                "source_ip": "10.0.0.5", "destination_ip": "8.8.8.8",
                "alert_timestamp": "2026-06-02T00:00:00+00:00",
            }],
        )

        import threading
        for t in threading.enumerate():
            if t.name == "ion-pcap-45":
                t.join(timeout=2.0)
                break

        assert len(consumed) == 1
        f = consumed[0][0]
        assert f["source_ip"] == "10.0.0.5"
        assert f["destination_ip"] == "8.8.8.8"
        assert f["alert_timestamp"] == "2026-06-02T00:00:00+00:00"

    def test_legacy_kwargs_still_work(self, monkeypatch):
        """Older callers passing community_ids + alert_node_hint don't
        break; the kwargs are translated into the flow shape."""
        from ion.services import pcap_analysis_service as svc

        consumed: List[List[Dict]] = []

        async def fake_runner(case_id, flows):
            consumed.append(flows)

        monkeypatch.setattr(svc, "_runner", fake_runner)

        svc.enqueue_pcap_analysis_for_case(
            case_id=43,
            community_ids=["1:legacy-a", "1:legacy-b"],
            alert_node_hint="cap-legacy",
        )

        import threading
        for t in threading.enumerate():
            if t.name == "ion-pcap-43":
                t.join(timeout=2.0)
                break

        assert len(consumed) == 1
        assert [f["community_id"] for f in consumed[0]] == ["1:legacy-a", "1:legacy-b"]
        assert all(f["node_hint"] == "cap-legacy" for f in consumed[0])

    def test_empty_input_is_a_no_op(self, monkeypatch):
        from ion.services import pcap_analysis_service as svc

        called = {"runner": 0}

        async def fake_runner(case_id, flows):
            called["runner"] += 1

        monkeypatch.setattr(svc, "_runner", fake_runner)
        svc.enqueue_pcap_analysis_for_case(case_id=44, flows=[])
        svc.enqueue_pcap_analysis_for_case(case_id=44, community_ids=[])
        # No thread should have been spawned for these.
        import threading
        for t in threading.enumerate():
            assert not t.name.startswith("ion-pcap-44")
        assert called["runner"] == 0
