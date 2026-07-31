"""v0.62.0 — Attack Path (Bob Pathfinding) Phase 2.

Pins the Phase-2 additions on top of the Phase-0 deterministic graph:

* ``score_reachability`` — Fork D MITRE-tactic-reached heuristic:
  - an impact-reaching path scores in the critical/high band;
  - a reconnaissance-only path scores ``low``;
  - a high/critical threat node applies a boost;
  - pure + deterministic (same input → same output).
* the async ``build_attack_path`` wrapper now folds ``stats.reachability`` in
  (the pure Phase-0 builder keeps its stable schema — asserted in test_v060).
* the Bob path→prompt helper ``_build_attack_path_prompt_block`` renders the
  expected compact structured kill-chain for a small path and is a safe
  no-op / fallback on an empty path (tested WITHOUT invoking the LLM).
"""
import asyncio

from ion.services.attack_path_service import (
    build_attack_path,
    build_attack_path_from_alerts,
    score_reachability,
)
from ion.web.bob_analysis_api import _build_attack_path_prompt_block

_GEN = "2026-07-30T00:00:00+00:00"


def _alert(aid, **kw):
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


# ── score_reachability — bands ───────────────────────────────────────────────


def test_impact_path_scores_critical_or_high_band():
    path = build_attack_path_from_alerts(
        1,
        [
            _alert("a_init", mitre_tactic_name="Initial Access", host="H1",
                   timestamp="2026-07-30T08:00:00+00:00"),
            _alert("a_exec", mitre_tactic_name="Execution", host="H1",
                   timestamp="2026-07-30T08:30:00+00:00"),
            _alert("a_imp", mitre_tactic_name="Impact", host="H1",
                   timestamp="2026-07-30T09:00:00+00:00"),
        ],
        generated_at=_GEN,
    )
    r = score_reachability(path)
    assert r["band"] in ("high", "critical")
    assert r["score"] >= 60
    assert "impact" in r["impact_tactics"]
    assert isinstance(r["rationale"], str) and r["rationale"]


def test_recon_only_path_scores_low():
    path = build_attack_path_from_alerts(
        1,
        [_alert("a1", mitre_tactic_name="Reconnaissance", host="H1")],
        generated_at=_GEN,
    )
    r = score_reachability(path)
    assert r["band"] == "low"
    assert r["score"] < 35
    assert r["impact_tactics"] == []


def test_threat_level_boost_applies():
    # Same tactic set; one path has a critical-scored observable node.
    plain = build_attack_path_from_alerts(
        1,
        [_alert("a1", mitre_tactic_name="Execution", host="H1",
                destination_ip="9.9.9.9")],
        generated_at=_GEN,
    )
    boosted = build_attack_path_from_alerts(
        1,
        [_alert("a1", mitre_tactic_name="Execution", host="H1",
                destination_ip="9.9.9.9",
                observables=[{"type": "ip", "value": "9.9.9.9",
                              "threat_level": "critical", "score": 95,
                              "source": "opencti"}])],
        generated_at=_GEN,
    )
    r_plain = score_reachability(plain)
    r_boost = score_reachability(boosted)
    assert r_boost["score"] > r_plain["score"]
    assert any(n["threat_level"] == "critical" for n in r_boost["top_threat_nodes"])


def test_score_reachability_is_deterministic():
    path = build_attack_path_from_alerts(
        1,
        [
            _alert("a1", mitre_tactic_name="Lateral Movement", host="H1",
                   destination_ip="8.8.8.8"),
            _alert("a2", mitre_tactic_name="Exfiltration", host="H2"),
        ],
        generated_at=_GEN,
    )
    r1 = score_reachability(path)
    r2 = score_reachability(path)
    assert r1 == r2


def test_score_reachability_empty_path_is_safe():
    empty = build_attack_path_from_alerts(1, [], generated_at=_GEN)
    r = score_reachability(empty)
    assert r["score"] == 0
    assert r["band"] == "low"
    assert r["impact_tactics"] == []
    assert r["top_threat_nodes"] == []
    # Robust on a bare/malformed dict too.
    assert score_reachability({})["score"] == 0
    assert score_reachability(None)["score"] == 0


def test_reachability_schema_keys():
    path = build_attack_path_from_alerts(
        1, [_alert("a1", mitre_tactic_name="Impact", host="H1")], generated_at=_GEN
    )
    r = score_reachability(path)
    assert set(r.keys()) == {
        "score", "band", "rationale", "impact_tactics", "top_threat_nodes"
    }


# ── build_attack_path (async wrapper) now carries stats.reachability ─────────


def test_build_attack_path_carries_reachability(monkeypatch):
    crafted = [
        _alert("a1", mitre_tactic_name="Impact", host="HOST-A",
               destination_ip="34.216.114.9",
               observables=[{"type": "ip", "value": "34.216.114.9",
                             "threat_level": "high", "score": 90,
                             "source": "opencti"}]),
    ]

    async def _fake_fetch(session, case_id):
        return crafted

    monkeypatch.setattr(
        "ion.services.attack_path_service._fetch_case_alert_dicts", _fake_fetch
    )
    g = asyncio.run(build_attack_path(None, 3))
    assert "reachability" in g["stats"]
    reach = g["stats"]["reachability"]
    assert reach["band"] in ("high", "critical")
    assert reach["score"] >= 60
    # Backward-compatible: the Phase-0 stats keys are still all present.
    for k in ("nodes", "edges", "alerts", "tactics_reached", "reaches_impact"):
        assert k in g["stats"]


# ── Bob path→prompt helper ───────────────────────────────────────────────────


def test_prompt_block_renders_compact_structured_path():
    path = build_attack_path_from_alerts(
        7,
        [
            _alert("a1", host="HOST-A", user="alice",
                   parent_process_name="explorer.exe", process_name="powershell.exe",
                   mitre_tactic_name="Execution",
                   timestamp="2026-07-30T08:00:00+00:00"),
            _alert("a2", host="HOST-A", source_ip="10.0.0.5",
                   destination_ip="34.216.114.9", mitre_tactic_name="Impact",
                   timestamp="2026-07-30T09:00:00+00:00",
                   observables=[{"type": "ip", "value": "34.216.114.9",
                                 "threat_level": "critical", "score": 99,
                                 "source": "opencti"}]),
        ],
        generated_at=_GEN,
    )
    # Attach reachability the way the async wrapper does before rendering.
    path["stats"]["reachability"] = score_reachability(path)

    block = _build_attack_path_prompt_block(path)
    assert block  # non-empty
    # Header + reachability line.
    assert "Attack path" in block
    assert "Reachability:" in block
    # Kill-chain lanes present + a specific node id rendered.
    assert "Kill-chain lanes" in block
    assert "`proc:powershell.exe`" in block
    # A specific edge rendered with its type + backing alert id.
    assert "process_lineage" in block
    assert "`proc:explorer.exe` --process_lineage--> `proc:powershell.exe`" in block
    # The critical observable node surfaces its threat level.
    assert "threat=critical" in block
    # Alert ids are cited so Bob can reference them.
    assert "a1" in block and "a2" in block


def test_prompt_block_is_noop_on_empty_path():
    empty = build_attack_path_from_alerts(1, [], generated_at=_GEN)
    assert _build_attack_path_prompt_block(empty) == ""
    assert _build_attack_path_prompt_block(None) == ""
    assert _build_attack_path_prompt_block({}) == ""
    # A graph with no nodes (defensive) also renders nothing.
    assert _build_attack_path_prompt_block({"nodes": [], "edges": [], "phases": []}) == ""


def test_prompt_block_caps_are_noted():
    # Build a wide graph well over the node cap; expect a truncation note.
    alerts = [
        _alert(f"a{i}", mitre_tactic_name="Execution", host=f"H{i}")
        for i in range(60)
    ]
    path = build_attack_path_from_alerts(1, alerts, generated_at=_GEN)
    path["stats"]["reachability"] = score_reachability(path)
    block = _build_attack_path_prompt_block(path)
    assert "truncated" in block
