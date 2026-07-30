"""v0.60.0 — Attack Path (Bob Pathfinding) Phase 0.

Pins the deterministic, compute-on-read path-graph contract:
- node dedup across alerts + stable ids;
- each of the 4 edge types (process lineage, network flow, user→host presence,
  shared-observable cross-alert linkage) derived correctly;
- tactic lanes ordered by kill-chain rank, within-lane by timestamp;
- ``reaches_impact`` true iff an impactful tactic is present;
- air-gap safety (no observables/enrichment → valid graph, null threat levels);
- empty case → valid empty-ish graph.

Everything here exercises the pure builder ``build_attack_path_from_alerts``
(no I/O) plus a monkeypatched fetch for the async ``build_attack_path`` wrapper.
"""
import asyncio

from ion.services.attack_path_service import (
    build_attack_path,
    build_attack_path_from_alerts,
)

_GEN = "2026-07-30T00:00:00+00:00"


def _alert(aid, **kw):
    """Craft an alert dict in the ElasticsearchAlert.to_dict shape."""
    a = {
        "id": aid,
        "timestamp": kw.pop("timestamp", "2026-07-30T12:00:00+00:00"),
        "host": None,
        "user": None,
        "process_name": None,
        "parent_process_name": None,
        "source_ip": None,
        "destination_ip": None,
        "file_hash": None,
        "mitre_technique_id": None,
        "mitre_tactic_name": None,
        "observables": [],
    }
    a.update(kw)
    return a


def _by_type(edges):
    out = {}
    for e in edges:
        out.setdefault(e["type"], []).append(e)
    return out


# ── node dedup + ids ─────────────────────────────────────────────────────────


def test_node_dedup_across_alerts():
    alerts = [
        _alert("a1", host="WKSTN-4471", user="alice", process_name="powershell.exe"),
        _alert("a2", host="WKSTN-4471", user="alice", process_name="cmd.exe"),
    ]
    g = build_attack_path_from_alerts(7, alerts, generated_at=_GEN)

    assert g["case_id"] == 7
    ids = {n["id"] for n in g["nodes"]}
    # host + user deduped to one node each; two distinct processes.
    assert "host:WKSTN-4471" in ids
    assert "user:alice" in ids
    assert "proc:powershell.exe" in ids
    assert "proc:cmd.exe" in ids
    assert sum(1 for n in g["nodes"] if n["id"] == "host:WKSTN-4471") == 1
    assert g["stats"]["nodes"] == len(g["nodes"])
    # ids are unique.
    assert len(ids) == len(g["nodes"])


# ── the four edge types ────────────────────────────────────────────────────


def test_process_lineage_edge():
    g = build_attack_path_from_alerts(
        1,
        [_alert("a1", parent_process_name="explorer.exe", process_name="powershell.exe")],
        generated_at=_GEN,
    )
    lineage = _by_type(g["edges"]).get("process_lineage", [])
    assert len(lineage) == 1
    e = lineage[0]
    assert e["source"] == "proc:explorer.exe"
    assert e["target"] == "proc:powershell.exe"
    assert e["alert_ids"] == ["a1"]


def test_network_flow_edge():
    g = build_attack_path_from_alerts(
        1,
        [_alert("a1", source_ip="10.0.0.5", destination_ip="34.216.114.9")],
        generated_at=_GEN,
    )
    flow = _by_type(g["edges"]).get("network_flow", [])
    assert len(flow) == 1
    assert flow[0]["source"] == "ip:10.0.0.5"
    assert flow[0]["target"] == "ip:34.216.114.9"


def test_auth_presence_edge():
    g = build_attack_path_from_alerts(
        1,
        [_alert("a1", user="alice", host="WKSTN-4471")],
        generated_at=_GEN,
    )
    auth = _by_type(g["edges"]).get("auth_presence", [])
    assert len(auth) == 1
    assert auth[0]["source"] == "user:alice"
    assert auth[0]["target"] == "host:WKSTN-4471"


def test_shared_observable_links_two_alerts():
    shared = {"type": "ip", "value": "34.216.114.9", "threat_level": "high",
              "score": 90, "source": "opencti"}
    alerts = [
        _alert("a1", host="HOST-A", timestamp="2026-07-30T12:00:00+00:00",
               observables=[shared]),
        _alert("a2", host="HOST-B", timestamp="2026-07-30T12:05:00+00:00",
               observables=[dict(shared)]),
    ]
    g = build_attack_path_from_alerts(1, alerts, generated_at=_GEN)

    shared_edges = _by_type(g["edges"]).get("shared_observable", [])
    assert len(shared_edges) == 1
    e = shared_edges[0]
    # Anchored on each alert's host, ordered by timestamp.
    assert e["source"] == "host:HOST-A"
    assert e["target"] == "host:HOST-B"
    assert set(e["alert_ids"]) == {"a1", "a2"}
    # The shared observable is a single deduped node carrying its threat level.
    ip_nodes = [n for n in g["nodes"] if n["id"] == "ip:34.216.114.9"]
    assert len(ip_nodes) == 1
    assert ip_nodes[0]["threat_level"] == "high"


def test_edge_dedup_merges_alert_ids():
    # Same network flow reported by two alerts -> one edge, both ids.
    alerts = [
        _alert("a1", source_ip="1.1.1.1", destination_ip="2.2.2.2"),
        _alert("a2", source_ip="1.1.1.1", destination_ip="2.2.2.2"),
    ]
    g = build_attack_path_from_alerts(1, alerts, generated_at=_GEN)
    flow = _by_type(g["edges"]).get("network_flow", [])
    assert len(flow) == 1
    assert set(flow[0]["alert_ids"]) == {"a1", "a2"}


# ── tactic lanes ─────────────────────────────────────────────────────────────


def test_tactic_lanes_ordered_by_kill_chain():
    # Deliberately out of kill-chain order; expect rank-sorted phases.
    alerts = [
        _alert("a_imp", mitre_tactic_name="Impact", host="H1",
               timestamp="2026-07-30T09:00:00+00:00"),
        _alert("a_init", mitre_tactic_name="Initial Access", host="H2",
               timestamp="2026-07-30T08:00:00+00:00"),
        _alert("a_exec", mitre_tactic_name="Execution", host="H3",
               timestamp="2026-07-30T08:30:00+00:00"),
    ]
    g = build_attack_path_from_alerts(1, alerts, generated_at=_GEN)

    tactics = [p["tactic"] for p in g["phases"]]
    assert tactics == ["initial-access", "execution", "impact"]
    ranks = [p["rank"] for p in g["phases"]]
    assert ranks == sorted(ranks)
    # Each lane carries its alert.
    lane = {p["tactic"]: p for p in g["phases"]}
    assert lane["initial-access"]["alert_ids"] == ["a_init"]
    assert "host:H2" in lane["initial-access"]["node_ids"]
    assert g["stats"]["tactics_reached"] == ["initial-access", "execution", "impact"]


def test_within_lane_ordered_by_timestamp():
    alerts = [
        _alert("late", mitre_tactic_name="Execution", host="H_late",
               timestamp="2026-07-30T10:00:00+00:00"),
        _alert("early", mitre_tactic_name="Execution", host="H_early",
               timestamp="2026-07-30T08:00:00+00:00"),
    ]
    g = build_attack_path_from_alerts(1, alerts, generated_at=_GEN)
    exec_lane = next(p for p in g["phases"] if p["tactic"] == "execution")
    assert exec_lane["alert_ids"] == ["early", "late"]


def test_unmapped_tactic_lands_in_last_lane():
    alerts = [
        _alert("a1", mitre_tactic_name="Initial Access", host="H1"),
        _alert("a2", mitre_tactic_name=None, host="H2"),
    ]
    g = build_attack_path_from_alerts(1, alerts, generated_at=_GEN)
    last = g["phases"][-1]
    assert last["tactic"] == "unknown"
    assert last["rank"] == 99
    assert last["alert_ids"] == ["a2"]
    # unknown excluded from tactics_reached.
    assert "unknown" not in g["stats"]["tactics_reached"]


# ── reachability ─────────────────────────────────────────────────────────────


def test_reaches_impact_true_when_impact_present():
    g = build_attack_path_from_alerts(
        1, [_alert("a1", mitre_tactic_name="Impact", host="H1")], generated_at=_GEN
    )
    assert g["stats"]["reaches_impact"] is True


def test_reaches_impact_true_for_exfiltration():
    g = build_attack_path_from_alerts(
        1, [_alert("a1", mitre_tactic_name="Exfiltration", host="H1")], generated_at=_GEN
    )
    assert g["stats"]["reaches_impact"] is True


def test_reaches_impact_false_otherwise():
    g = build_attack_path_from_alerts(
        1, [_alert("a1", mitre_tactic_name="Execution", host="H1")], generated_at=_GEN
    )
    assert g["stats"]["reaches_impact"] is False


# ── air-gap safety + robustness ──────────────────────────────────────────────


def test_air_gap_no_observables_null_threat():
    # No observables at all (OpenCTI/ES enrichment unavailable) — nodes still
    # build, and observable-backed threat levels stay null.
    g = build_attack_path_from_alerts(
        1,
        [_alert("a1", source_ip="9.9.9.9", destination_ip="8.8.8.8", host="H1")],
        generated_at=_GEN,
    )
    assert g["stats"]["nodes"] >= 3
    ip_node = next(n for n in g["nodes"] if n["id"] == "ip:9.9.9.9")
    assert ip_node["threat_level"] is None
    # A network flow still derived from the common fields.
    assert _by_type(g["edges"]).get("network_flow")


def test_empty_case_returns_valid_graph():
    g = build_attack_path_from_alerts(42, [], generated_at=_GEN)
    assert g["case_id"] == 42
    assert g["nodes"] == []
    assert g["edges"] == []
    assert g["phases"] == []
    assert g["stats"]["nodes"] == 0
    assert g["stats"]["edges"]["total"] == 0
    assert g["stats"]["alerts"] == 0
    assert g["stats"]["tactics_reached"] == []
    assert g["stats"]["reaches_impact"] is False


def test_single_alert_returns_valid_graph():
    g = build_attack_path_from_alerts(
        1, [_alert("a1", host="solo")], generated_at=_GEN
    )
    assert g["stats"]["nodes"] == 1
    assert g["nodes"][0]["id"] == "host:solo"


def test_malformed_alert_is_skipped_not_fatal():
    alerts = [
        None,                     # not a dict
        {"observables": "nope"},  # observables not a list
        _alert("good", host="H1"),
    ]
    # Should not raise; the good alert still contributes.
    g = build_attack_path_from_alerts(1, [a for a in alerts if a is not None], generated_at=_GEN)
    assert any(n["id"] == "host:H1" for n in g["nodes"])


def test_schema_keys_present():
    g = build_attack_path_from_alerts(
        1, [_alert("a1", host="H1", user="u1")], generated_at=_GEN
    )
    assert set(g.keys()) == {"case_id", "generated_at", "nodes", "edges", "phases", "stats"}
    for n in g["nodes"]:
        assert set(n.keys()) == {"id", "type", "value", "label", "threat_level"}
    for e in g["edges"]:
        assert set(e.keys()) == {"source", "target", "type", "label", "alert_ids"}
    for p in g["phases"]:
        assert set(p.keys()) == {"tactic", "rank", "node_ids", "alert_ids"}
    assert set(g["stats"].keys()) == {
        "nodes", "edges", "alerts", "tactics_reached", "reaches_impact"
    }
    assert set(g["stats"]["edges"].keys()) == {
        "total", "process_lineage", "network_flow", "auth_presence", "shared_observable"
    }


# ── async wrapper (fetch monkeypatched) ──────────────────────────────────────


def test_build_attack_path_wrapper(monkeypatch):
    crafted = [
        _alert("a1", host="HOST-A", user="alice", parent_process_name="explorer.exe",
               process_name="powershell.exe", mitre_tactic_name="Execution"),
    ]

    async def _fake_fetch(session, case_id):
        assert case_id == 5
        return crafted

    monkeypatch.setattr(
        "ion.services.attack_path_service._fetch_case_alert_dicts", _fake_fetch
    )

    g = asyncio.run(build_attack_path(None, 5))
    assert g["case_id"] == 5
    assert any(n["id"] == "host:HOST-A" for n in g["nodes"])
    assert _by_type(g["edges"]).get("process_lineage")


def test_build_attack_path_wrapper_missing_case(monkeypatch):
    async def _fake_fetch(session, case_id):
        return None  # case not found

    monkeypatch.setattr(
        "ion.services.attack_path_service._fetch_case_alert_dicts", _fake_fetch
    )
    g = asyncio.run(build_attack_path(None, 999))
    # Still a valid empty graph (endpoint enforces the 404 separately).
    assert g["case_id"] == 999
    assert g["nodes"] == []
