"""v0.98.0 — Network Topology phase 2: threat edge overlay + per-edge PCAP link.

Edges now inherit their endpoints' threat (so a suspicious conversation stands
out) and carry a deep-link to the representative flow's PCAP in Arkime when a
community_id was sampled.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import ion.services.topology_metrics_service as tm


def _build(convo, threats):
    svc = MagicMock()
    svc.get_conversations = AsyncMock(return_value=convo)
    with patch.object(tm, "get_arkime_service", return_value=svc), \
         patch.object(tm, "_assets_by_ip", return_value={}), \
         patch.object(tm, "_threat_by_ip", return_value=threats), \
         patch.object(tm, "arkime_sessions_link",
                      side_effect=lambda expr: "http://arkime/sessions?expression=" + expr):
        return asyncio.run(tm.build_topology(MagicMock(), 0, 100))


def _convo(cid=None):
    return {
        "nodes": [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}],
        "edges": [{"src": "10.0.0.1", "dst": "10.0.0.2", "bytes": 100,
                   "sessions": 1, "community_id": cid}],
        "method": "sample",
    }


def test_edge_inherits_malicious_endpoint():
    threats = {"10.0.0.2": {"level": "critical", "malicious": True, "is_ioc": True, "case_count": 2}}
    e = _build(_convo(), threats)["edges"][0]
    assert e["threat"]["malicious"] is True and e["threat"]["level"] == "critical"


def test_edge_pcap_deeplink_when_community_id_present():
    e = _build(_convo(cid="1:AAAABBBBCCCC="), {})["edges"][0]
    assert "communityId" in e["arkime_pcap_url"]


def test_plain_edge_has_no_threat_or_pcap_link_but_keeps_base_link():
    e = _build(_convo(cid=None), {})["edges"][0]
    assert "threat" not in e and "arkime_pcap_url" not in e
    assert e["arkime_url"]  # the src/dst sessions link is still there


def test_edge_threat_picks_worst_endpoint_level():
    et = tm._edge_threat({"level": "low", "malicious": False},
                         {"level": "high", "malicious": True})
    assert et["level"] == "high" and et["malicious"] is True


def test_edge_threat_none_without_ledgered_endpoints():
    assert tm._edge_threat(None, None) is None
