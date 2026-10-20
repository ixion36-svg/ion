"""Flow Topology fragments around the Arkime conversation graph.

The node layout stays in the page, because it is computed from measured
geometry. Everything that used to be written into the DOM as a message or a
detail panel is a fragment. An unreachable Arkime (HTTP 503) is a different
outcome from an empty window: the first was never read, the second was read
and had no sessions.

The canvas messages are templates filled with textContent. The tests that
cover them read the page. The panels are driven through TestClient with the
topology handler monkeypatched.
"""
from __future__ import annotations

import json
import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/network_topology.html"
#: The page sheet was retired into the one build; its rules are nested
#: under body[data-page="network_topology"] in frontend/ion-pages.css, and
#: tests/test_retired_page_sheets.py is what pins them there.
CSS = ROOT / "frontend/ion-pages.css"

BOARD = "/ui/network-topology/board"
NODE = "/ui/network-topology/node"
EDGE = "/ui/network-topology/edge"


def _src(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(?<![:'\"\\])//[^\n]*", "", text)
    return text


def _page_script() -> str:
    return "\n".join(
        re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", _src(PAGE), flags=re.S)
    )


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


class _User:
    id = 1
    username = "topology-tester"

    def __init__(self, *permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions

    def has_any_permission(self, names):
        return any(self.has_permission(n) for n in names)


def _client(user, monkeypatch, topology):
    import ion.web.ui.network_topology as mod
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    async def fake(range="24h", exclude_private=False, user=None, session=None):
        fake.calls.append({"range": range, "exclude_private": exclude_private})
        outcome = topology()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    fake.calls = []
    monkeypatch.setattr(mod, "traffic_topology", fake)
    application = FastAPI()
    application.include_router(mod.router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: user
    application.dependency_overrides[get_db_session] = lambda: object()
    application.calls = fake.calls

    class _Calling(TestClient):
        """Starlette's client does not forward arbitrary app attributes."""

        @property
        def calls(self):
            return self.app.calls

    return _Calling(application)


def _get(monkeypatch, url, *permissions, topology):
    with _client(_User(*permissions), monkeypatch, topology) as client:
        response = client.get(url)
        response.calls = client.calls
        return response


def _graph():
    return {
        "nodes": [
            {
                "ip": "10.0.0.5", "bytes": 2048, "sessions": 3, "subnet": "10.0.0.0/24",
                "private": True,
                "asset": {"hostname": "db-1", "criticality": "high", "environment": "prod"},
                "threat": {"level": "critical", "malicious": True, "is_ioc": True, "case_count": 2},
            },
            {
                "ip": "8.8.8.8", "bytes": 512, "sessions": 1, "subnet": "8.8.8.0/24",
                "private": False, "asset": None, "threat": None,
            },
        ],
        "edges": [
            {
                "src": "10.0.0.5", "dst": "8.8.8.8", "bytes": 2048, "sessions": 3,
                "packets": 40, "protocol": "tcp", "port": 443, "throughput_bps": 1024,
                "arkime_url": "https://arkime.example/sessions?expression=1",
                "arkime_pcap_url": "https://arkime.example/pcap?expression=1",
                "threat": {"level": "critical", "malicious": True, "is_ioc": True, "rank": 4},
            },
        ],
        "metrics": {
            "active_conversations": 1,
            "hosts": 2,
            "port_distribution": [{"port": 443, "bytes": 2048}, {"port": 53, "bytes": 512}],
            "method": "connections",
        },
        "unavailable": [
            {"metric": "RTT / latency", "requires": "Packetbeat"},
        ],
    }


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def test_the_page_script_no_longer_assigns_inner_html():
    script = _page_script()
    assert script.strip()
    assert not re.search(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", script)


def test_the_page_keeps_the_layout_in_javascript_and_the_three_canvas_messages():
    script = _page_script()
    page = PAGE.read_text(encoding="utf-8")
    assert "function ntLoad(" in script
    assert "cytoscape(" in script
    assert "function ntShowNode(" in script
    assert "function ntShowEdge(" in script
    assert "nt-canvas-loading" in page
    assert "nt-canvas-message" in page
    assert "No capture source." in page
    assert "Nothing to graph" in page
    assert "textContent" in script
    # The layout call stays. The messages are templates, not strings assigned
    # into the canvas.
    assert "Building graph" in page


def test_the_page_has_no_inline_style_block_except_the_cytoscape_suppressor():
    """Cytoscape injects a nonce-less style unless an element with this id
    already exists. The element has to stay. It must be empty, or the styled
    column still fails."""
    text = PAGE.read_text(encoding="utf-8")
    blocks = re.findall(r"<style[^>]*>(.*?)</style>", text, flags=re.S)
    assert blocks == [""] or blocks == ["\n"] or all(not b.strip() for b in blocks)
    assert "__________cytoscape_stylesheet" in text
    # The sheet is retired; the rules moved into the one build under
    # body[data-page="network_topology"], which this block is what selects.
    assert "network-topology-page.css" not in text
    assert "{% block page_id %}network_topology{% endblock %}" in text


def test_unconfigured_and_empty_are_different_sentences_on_the_page():
    page = PAGE.read_text(encoding="utf-8")
    assert "No capture source." in page
    assert "Nothing to graph" in page
    assert page.index("No capture source.") != page.index("Nothing to graph")


# ---------------------------------------------------------------------------
# Board
# ---------------------------------------------------------------------------


def test_the_board_requires_alert_read(monkeypatch):
    res = _get(monkeypatch, BOARD, "playbook:read", topology=lambda: _graph())
    assert res.status_code == 403
    assert "10.0.0.5" not in res.text


def test_the_board_renders_counts_ports_and_the_unavailable_list(monkeypatch):
    res = _get(monkeypatch, BOARD + "?range=7d&exclude_private=true", "alert:read", topology=lambda: _graph())
    assert res.status_code == 200
    assert res.calls == [{"range": "7d", "exclude_private": True}]
    body = flat(res.text)
    assert "2" in body and "hosts" in body
    assert "1" in body and "conversations" in body
    assert "whole-window" in body
    assert "443" in body
    assert "RTT / latency" in body
    assert "Packetbeat" in body
    assert "unavailable" in body
    assert "Nothing to graph" not in body
    assert "not configured" not in body.lower()
    assert "javascript:" not in res.text
    assert ' style="' not in res.text
    # The legend names a category. The colour lives in the stylesheet.
    assert "nt-cat-threat" in res.text
    assert "nt-cat-asset" in res.text
    assert "#" not in res.text
    widths = re.findall(r'data-ion-style="width:(\d+)px"', res.text)
    assert widths, "the port bars did not render"
    assert all(int(w) >= 2 for w in widths)


def test_a_zero_byte_host_count_is_zero_and_a_missing_one_is_not(monkeypatch):
    payload = _graph()
    payload["metrics"]["hosts"] = 0
    payload["metrics"]["active_conversations"] = 0
    zero = _get(monkeypatch, BOARD, "alert:read", topology=lambda: payload)
    assert ">0<" in zero.text
    assert "unknown" not in flat(zero.text)

    missing = _graph()
    missing["metrics"] = {"port_distribution": [], "method": None}
    res = _get(monkeypatch, BOARD, "alert:read", topology=lambda: missing)
    body = flat(res.text)
    assert "unknown" in body
    assert "top-volume sample" not in body
    assert "0 hosts" not in body and ">0<" not in res.text.split("unknown", 1)[0]


def test_an_empty_graph_is_not_an_unreachable_arkime(monkeypatch):
    payload = {
        "nodes": [], "edges": [],
        "metrics": {"active_conversations": 0, "hosts": 0, "port_distribution": [], "method": "sample"},
        "unavailable": [{"metric": "Packet loss", "requires": "Packetbeat"}],
    }
    res = _get(monkeypatch, BOARD, "alert:read", topology=lambda: payload)
    body = flat(res.text)
    assert "No conversations" in body or "Nothing to graph" in body or "no Arkime sessions" in body
    assert "not configured" not in body.lower()
    assert "No capture source" not in body
    assert "Packet loss" in body
    assert "No port data" in body
    assert ">0<" in res.text


def test_an_unconfigured_arkime_is_not_rendered_as_no_traffic(monkeypatch):
    def topology():
        return HTTPException(status_code=503, detail="Arkime is not configured")
    res = _get(monkeypatch, BOARD, "alert:read", topology=topology)
    assert res.status_code == 200
    body = flat(res.text)
    assert "not configured" in body.lower()
    assert "No conversations" not in body
    assert "Nothing to graph" not in body
    assert "No port data" not in body
    assert ">0<" not in res.text
    assert "Packet loss" not in body


def test_a_raised_topology_read_is_not_an_empty_graph(monkeypatch):
    res = _get(monkeypatch, BOARD, "alert:read", topology=lambda: RuntimeError("arkime down"))
    body = flat(res.text)
    assert "could not be read" in body
    assert "No conversations" not in body
    assert "not configured" not in body.lower()
    assert ">0<" not in res.text


def test_a_payload_that_is_not_a_graph_is_not_an_empty_one(monkeypatch):
    res = _get(monkeypatch, BOARD, "alert:read", topology=lambda: {"nodes": "nope"})
    body = flat(res.text)
    assert "could not be read" in body
    assert "No conversations" not in body
    assert "No port data" not in body


def test_ports_of_the_wrong_shape_are_not_no_port_data(monkeypatch):
    payload = _graph()
    payload["metrics"]["port_distribution"] = {"443": 10}
    res = _get(monkeypatch, BOARD, "alert:read", topology=lambda: payload)
    body = flat(res.text)
    assert "could not be read" in body
    assert "No port data" not in body


def test_a_missing_unavailable_list_is_not_silence(monkeypatch):
    payload = _graph()
    del payload["unavailable"]
    res = _get(monkeypatch, BOARD, "alert:read", topology=lambda: payload)
    body = flat(res.text)
    assert "could not be read" in body
    # The hosts we did read are still there. One bad key does not blank the graph.
    assert "hosts" in body


def test_a_port_with_no_byte_count_does_not_draw_a_zero_bar(monkeypatch):
    payload = _graph()
    payload["metrics"]["port_distribution"] = [{"port": 22, "bytes": None}, {"port": 80, "bytes": 100}]
    res = _get(monkeypatch, BOARD, "alert:read", topology=lambda: payload)
    body = flat(res.text)
    assert "22" in body
    assert "unknown" in body
    # 80 has a real width. 22 must not be given one built from a fake zero.
    assert body.count("unknown") >= 1


def test_the_board_answers_json_when_asked(monkeypatch):
    with _client(_User("alert:read"), monkeypatch, lambda: _graph()) as client:
        res = client.get(BOARD, headers={"accept": "application/json"})
    assert res.headers["content-type"].startswith("application/json")
    body = res.json()
    assert body["state"] == "data"
    assert body["hosts"] == 2
    assert body["method"] == "connections"


# ---------------------------------------------------------------------------
# Node and edge details
# ---------------------------------------------------------------------------


def test_a_host_detail_renders_the_asset_and_the_threat_and_not_a_colour(monkeypatch):
    res = _get(
        monkeypatch,
        NODE + "?node=h:10.0.0.5&range=24h&grouped=true",
        "alert:read",
        topology=lambda: _graph(),
    )
    assert res.status_code == 200
    body = flat(res.text)
    assert "10.0.0.5" in body
    assert "db-1" in body
    assert "critical" in body
    assert "prod" in body
    assert "IOC" in body
    assert "2" in body
    assert "internal" in body
    assert "Not in CMDB" not in body
    assert "/observables?search=10.0.0.5" in res.text
    assert "/network-map?search=10.0.0.5" in res.text
    assert "javascript:" not in res.text
    assert ' style="' not in res.text
    assert "nt-detail" in res.text
    assert "empty" not in res.text.split("nt-detail", 1)[1][:80]


def test_a_host_with_no_asset_and_no_threat_says_so_rather_than_leaving_a_blank(monkeypatch):
    res = _get(
        monkeypatch, NODE + "?node=h:8.8.8.8", "alert:read", topology=lambda: _graph(),
    )
    body = flat(res.text)
    assert "8.8.8.8" in body
    assert "Not in CMDB" in body
    assert "No observable-ledger hits" in body
    assert "external" in body
    assert "/network-map" not in res.text
    assert "/observables?search=8.8.8.8" in res.text


def test_a_byte_count_that_did_not_arrive_is_not_zero_bytes(monkeypatch):
    payload = _graph()
    payload["nodes"][1]["bytes"] = None
    payload["nodes"][1]["sessions"] = None
    res = _get(monkeypatch, NODE + "?node=h:8.8.8.8", "alert:read", topology=lambda: payload)
    body = flat(res.text)
    assert "unknown" in body
    assert "0 B" not in body
    assert "0 sessions" not in body


def test_a_subnet_detail_sums_its_members_and_offers_drill(monkeypatch):
    res = _get(
        monkeypatch, NODE + "?node=s:10.0.0.0/24&grouped=true",
        "alert:read", topology=lambda: _graph(),
    )
    body = flat(res.text)
    assert "10.0.0.0/24" in body
    assert "1 host" in body
    assert "Drill into subnet" in body
    args = json.loads(re.search(r"data-args='([^']*)'", res.text).group(1))
    assert args == ["10.0.0.0/24"]


def test_a_node_that_is_not_in_the_graph_is_not_an_empty_estate(monkeypatch):
    res = _get(monkeypatch, NODE + "?node=h:1.2.3.4", "alert:read", topology=lambda: _graph())
    body = flat(res.text)
    assert "not in this graph" in body
    assert "No conversations" not in body
    assert "0 B" not in body


def test_a_node_detail_against_an_unconfigured_arkime_does_not_say_no_traffic(monkeypatch):
    res = _get(
        monkeypatch, NODE + "?node=h:10.0.0.5", "alert:read",
        topology=lambda: HTTPException(status_code=503, detail="Arkime is not configured"),
    )
    body = flat(res.text)
    assert "not configured" in body.lower()
    assert "not in this graph" not in body
    assert "No conversations" not in body


def test_a_node_detail_when_the_read_raises_does_not_say_the_host_is_absent(monkeypatch):
    res = _get(
        monkeypatch, NODE + "?node=h:10.0.0.5", "alert:read",
        topology=lambda: RuntimeError("down"),
    )
    body = flat(res.text)
    assert "could not be read" in body
    assert "not in this graph" not in body


def test_an_edge_detail_renders_the_sample_and_only_http_links(monkeypatch):
    res = _get(
        monkeypatch,
        EDGE + "?src=h:10.0.0.5&dst=h:8.8.8.8&grouped=false",
        "alert:read",
        topology=lambda: _graph(),
    )
    body = flat(res.text)
    assert "10.0.0.5" in body and "8.8.8.8" in body
    assert "tcp:443" in body
    assert "malicious" in body
    assert "IOC" in body
    assert "https://arkime.example/sessions?expression=1" in res.text
    assert "https://arkime.example/pcap?expression=1" in res.text
    assert 'target="_blank"' in res.text
    assert "noopener" in res.text
    assert "javascript:" not in res.text


def test_a_javascript_url_on_an_edge_is_dropped(monkeypatch):
    payload = _graph()
    payload["edges"][0]["arkime_url"] = "javascript:alert(1)"
    payload["edges"][0]["arkime_pcap_url"] = "javascript:alert(2)"
    res = _get(
        monkeypatch, EDGE + "?src=h:10.0.0.5&dst=h:8.8.8.8&grouped=false",
        "alert:read", topology=lambda: payload,
    )
    assert "javascript:" not in res.text
    assert "Open in Arkime" not in res.text
    assert "10.0.0.5" in flat(res.text)


def test_an_edge_with_no_protocol_sample_does_not_invent_one(monkeypatch):
    payload = _graph()
    payload["edges"][0]["protocol"] = ""
    payload["edges"][0]["port"] = None
    payload["edges"][0]["throughput_bps"] = None
    payload["edges"][0]["packets"] = None
    res = _get(
        monkeypatch, EDGE + "?src=h:10.0.0.5&dst=h:8.8.8.8&grouped=false",
        "alert:read", topology=lambda: payload,
    )
    body = flat(res.text)
    assert "Protocol detail needs the session sample" in body
    assert "tcp" not in body


def test_a_grouped_edge_uses_the_subnet_key_the_graph_drew(monkeypatch):
    """With grouping on and the subnet not expanded, both hosts collapse and
    there is no host-to-host edge. Asking for the host key must not invent
    one, and asking for the subnet key must find the rolled-up conversation."""
    missing = _get(
        monkeypatch, EDGE + "?src=h:10.0.0.5&dst=h:8.8.8.8&grouped=true",
        "alert:read", topology=lambda: _graph(),
    )
    assert "not in this graph" in flat(missing.text)
    found = _get(
        monkeypatch, EDGE + "?src=s:10.0.0.0/24&dst=s:8.8.8.0/24&grouped=true",
        "alert:read", topology=lambda: _graph(),
    )
    body = flat(found.text)
    assert "10.0.0.0/24" in body
    assert "8.8.8.0/24" in body
    assert "not in this graph" not in body


def test_expanding_a_subnet_splits_the_edge_back_into_hosts(monkeypatch):
    res = _get(
        monkeypatch,
        EDGE + "?src=h:10.0.0.5&dst=h:8.8.8.8&grouped=true&expanded=10.0.0.0/24,8.8.8.0/24",
        "alert:read",
        topology=lambda: _graph(),
    )
    assert "not in this graph" not in flat(res.text)
    assert "10.0.0.5" in flat(res.text)


def test_fragments_carry_no_colour_literals():
    frag_dir = ROOT / "src/ion/web/templates/_fragments"
    for name in ("network_topology_board.html", "network_topology_node.html", "network_topology_edge.html"):
        text = (frag_dir / name).read_text(encoding="utf-8")
        assert "<script" not in text, name
        assert ' style="' not in text, name
        assert "javascript:" not in text, name
        assert not re.search(r"#[0-9a-fA-F]{3,8}\b", text), name
        assert "var(--" not in text, name
