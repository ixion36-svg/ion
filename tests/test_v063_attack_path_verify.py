"""v0.63.0 — Attack Path (Bob Pathfinding) Phase 3.

Pins the Phase-3 additions:

* the adversarial **verifier** — pure prompt builder, Fork-E gating
  (``should_verify``), verdict/confidence extraction, and the air-gap /
  gated-out no-op behaviour (all tested WITHOUT a real LLM; the run path uses a
  fake Ollama);
* the **path signature** — deterministic, same-shape → same-signature; and
  ``find_recurring_path`` counting same-signature cases + the advisory
  ``suggests_detection_proposal`` hint past threshold (alert fetch + recent-case
  enumeration monkeypatched, as the Phase-0 tests do).

Phase-0/Phase-2 contracts stay green (see test_v060 / test_v062).
"""
import asyncio

import ion.services.attack_path_service as aps
from ion.services.attack_path_service import (
    _collect_technique_ids,
    build_attack_path_from_alerts,
    find_recurring_path,
    path_signature,
    score_reachability,
)
from ion.services.bob_verifier_service import (
    build_verifier_user_prompt,
    extract_confidence_band,
    extract_verdict,
    render_verification_block,
    should_verify,
    verify_analysis,
)

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


def _small_path():
    path = build_attack_path_from_alerts(
        7,
        [
            _alert("a1", host="HOST-A", user="alice",
                   parent_process_name="explorer.exe", process_name="powershell.exe",
                   mitre_tactic_name="Execution", mitre_technique_id="T1059",
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
    path["stats"]["reachability"] = score_reachability(path)
    return path


# ── verifier: pure prompt builder ────────────────────────────────────────────


def test_verifier_prompt_builder_is_adversarial_and_cites_the_graph():
    path = _small_path()
    prompt = build_verifier_user_prompt(
        analysis_text="Verdict: true_positive (confidence: medium). PowerShell ran.",
        verdict="true_positive",
        confidence_band="medium",
        path_dict=path,
    )
    assert prompt  # non-empty
    # The verdict under review is surfaced.
    assert "Verdict under review" in prompt
    assert "`true_positive`" in prompt
    assert "`medium`" in prompt
    # It renders the SAME structured attack path Bob reasoned over.
    assert "Attack path" in prompt
    assert "`proc:powershell.exe`" in prompt
    # Adversarial framing + unsupported-claim ask.
    assert "Adversarially check" in prompt
    assert "NOT present in the graph" in prompt
    assert "recommend a downgrade" in prompt
    # Pinned JSON output contract.
    assert '"supported"' in prompt
    assert '"unsupported_claims"' in prompt
    assert '"recommended_band"' in prompt


def test_verifier_prompt_builder_tolerates_empty_path():
    # No graph -> still builds a prompt (with a placeholder), never raises.
    prompt = build_verifier_user_prompt("some analysis", "false_positive", "medium", {})
    assert prompt
    assert "No attack-path graph available" in prompt


# ── Fork E gating ────────────────────────────────────────────────────────────


def test_should_verify_medium_decisive_runs():
    assert should_verify("medium", "true_positive") is True
    assert should_verify("medium", "false_positive") is True
    assert should_verify("medium", "benign_true_positive") is True


def test_should_verify_skips_high_and_low_confidence():
    assert should_verify("high", "true_positive") is False
    assert should_verify("low", "true_positive") is False


def test_should_verify_skips_abstentions_and_unknowns():
    assert should_verify("medium", "inconclusive") is False
    assert should_verify("medium", None) is False
    assert should_verify(None, "true_positive") is False


# ── verdict / confidence extraction ──────────────────────────────────────────


def test_extract_verdict_prefers_benign_over_substring():
    assert extract_verdict("**Verdict:** benign_true_positive — expected admin tool") \
        == "benign_true_positive"
    assert extract_verdict("Verdict: true_positive, confidence medium") == "true_positive"
    assert extract_verdict("no verdict token here") is None


def test_extract_confidence_band():
    assert extract_confidence_band("confidence: medium") == "medium"
    assert extract_confidence_band("I have high confidence in this") == "high"
    assert extract_confidence_band("nothing stated") is None


def test_render_verification_block_empty_when_skipped():
    assert render_verification_block({"skipped": True, "supported": None}) == ""
    assert render_verification_block(None) == ""
    block = render_verification_block(
        {"skipped": False, "supported": False,
         "unsupported_claims": ["cites host:H9 not in graph"],
         "recommended_band": "low", "notes": "verdict overstates reach"}
    )
    assert "Verification (advisory)" in block
    assert "NO — consider a downgrade" in block
    assert "host:H9" in block
    assert "low" in block


# ── verify_analysis: gated-out + air-gap no-op (no real LLM) ──────────────────


def test_verify_analysis_skips_when_gated_out():
    # High confidence -> Fork E gates it out; Ollama never touched.
    r = asyncio.run(verify_analysis("x", "true_positive", "high", _small_path()))
    assert r["skipped"] is True
    assert r["supported"] is None
    assert r["reason"] == "not-medium-decisive"


def test_verify_analysis_noop_when_ollama_disabled():
    class _DisabledOllama:
        enabled = False

    r = asyncio.run(
        verify_analysis("x", "true_positive", "medium", _small_path(),
                        ollama=_DisabledOllama())
    )
    assert r["skipped"] is True
    assert r["supported"] is None
    assert r["reason"] == "ollama-disabled"


def test_verify_analysis_noop_when_path_empty():
    empty = build_attack_path_from_alerts(1, [], generated_at=_GEN)
    r = asyncio.run(verify_analysis("x", "true_positive", "medium", empty))
    assert r["skipped"] is True
    assert r["reason"] == "no-attack-path"


def test_verify_analysis_noop_when_llm_raises():
    class _BoomOllama:
        enabled = True

        async def chat(self, **kw):
            raise RuntimeError("circuit breaker open")

    r = asyncio.run(
        verify_analysis("x", "true_positive", "medium", _small_path(),
                        ollama=_BoomOllama())
    )
    assert r["skipped"] is True
    assert r["reason"] == "ollama-unavailable"


def test_verify_analysis_runs_with_fake_ollama():
    class _FakeOllama:
        enabled = True

        def __init__(self):
            self.calls = []

        async def chat(self, **kw):
            self.calls.append(kw)
            return {"content": '{"supported": false, '
                    '"unsupported_claims": ["references ip:1.2.3.4 absent from graph"], '
                    '"recommended_band": "medium", "notes": "verdict overstates reach"}'}

    ollama = _FakeOllama()
    r = asyncio.run(
        verify_analysis("Verdict: true_positive (confidence: medium).",
                        "true_positive", "medium", _small_path(), ollama=ollama)
    )
    assert r["skipped"] is False
    assert r["supported"] is False
    assert r["recommended_band"] == "medium"
    assert r["unsupported_claims"] == ["references ip:1.2.3.4 absent from graph"]
    # Adversarial verifier is a temp-0 JSON call.
    assert ollama.calls and ollama.calls[0]["temperature"] == 0.0
    assert ollama.calls[0]["response_format"] == "json"
    # And it renders a non-empty advisory block.
    assert "Verification (advisory)" in render_verification_block(r)


# ── path signature ───────────────────────────────────────────────────────────


def _shape(case_id, alerts):
    path = build_attack_path_from_alerts(case_id, alerts, generated_at=_GEN)
    path["stats"]["techniques"] = _collect_technique_ids(alerts)
    return path


def test_path_signature_is_deterministic():
    p = _shape(1, [_alert("a1", mitre_tactic_name="Impact",
                          mitre_technique_id="T1486", host="H1")])
    assert path_signature(p) == path_signature(p)


def test_same_shape_same_signature_regardless_of_incidentals():
    # Same tactics + same technique ids, but different hosts/timestamps/order.
    a = _shape(1, [
        _alert("x", mitre_tactic_name="Execution", mitre_technique_id="T1059",
               host="H1", timestamp="2026-07-30T08:00:00+00:00"),
        _alert("y", mitre_tactic_name="Impact", mitre_technique_id="T1486",
               host="H2", timestamp="2026-07-30T09:00:00+00:00"),
    ])
    b = _shape(99, [
        _alert("q", mitre_tactic_name="Impact", mitre_technique_id="T1486",
               host="OTHER", timestamp="2026-07-30T22:00:00+00:00"),
        _alert("z", mitre_tactic_name="Execution", mitre_technique_id="T1059",
               host="DIFF", timestamp="2026-07-30T21:00:00+00:00"),
    ])
    assert path_signature(a) == path_signature(b)


def test_different_shape_different_signature():
    a = _shape(1, [_alert("a1", mitre_tactic_name="Execution",
                          mitre_technique_id="T1059", host="H1")])
    b = _shape(1, [_alert("a1", mitre_tactic_name="Reconnaissance",
                          mitre_technique_id="T1595", host="H1")])
    assert path_signature(a) != path_signature(b)


def test_signature_safe_on_empty():
    assert isinstance(path_signature({}), str)
    assert isinstance(path_signature(None), str)


# ── find_recurring_path ──────────────────────────────────────────────────────

# Two cases share the target's shape (Execution+Impact / T1059+T1486); one does
# not (Reconnaissance).
_CASE_ALERTS = {
    1: [_alert("a", mitre_tactic_name="Execution", mitre_technique_id="T1059", host="H1"),
        _alert("b", mitre_tactic_name="Impact", mitre_technique_id="T1486", host="H1")],
    2: [_alert("c", mitre_tactic_name="Impact", mitre_technique_id="T1486", host="H2"),
        _alert("d", mitre_tactic_name="Execution", mitre_technique_id="T1059", host="H2")],
    3: [_alert("e", mitre_tactic_name="Execution", mitre_technique_id="T1059", host="H3"),
        _alert("f", mitre_tactic_name="Impact", mitre_technique_id="T1486", host="H3")],
    4: [_alert("g", mitre_tactic_name="Reconnaissance", mitre_technique_id="T1595", host="H4")],
}


def _install_recurrence_fixtures(monkeypatch, case_alerts):
    async def _fake_fetch(session, case_id):
        return case_alerts.get(case_id)

    def _fake_recent(session, exclude_case_id, days, limit):
        return [cid for cid in case_alerts if cid != exclude_case_id][:limit]

    monkeypatch.setattr(aps, "_fetch_case_alert_dicts", _fake_fetch)
    monkeypatch.setattr(aps, "_recent_case_ids", _fake_recent)


def test_find_recurring_path_counts_shared_signature_cases(monkeypatch):
    _install_recurrence_fixtures(monkeypatch, _CASE_ALERTS)
    r = asyncio.run(find_recurring_path(None, 1, days=30))
    # Cases 2 and 3 share case 1's shape; case 4 does not.
    assert set(r["case_ids"]) == {2, 3}
    assert r["recurrence_count"] == 2
    assert r["signature"] and r["signature"].startswith("ap1:")
    # Past the default threshold (2) -> advisory proposal hint set.
    assert r["suggests_detection_proposal"] is True


def test_find_recurring_path_below_threshold_no_hint(monkeypatch):
    # Only one other case shares the shape -> below threshold (2) -> no hint.
    only_one = {1: _CASE_ALERTS[1], 2: _CASE_ALERTS[2], 4: _CASE_ALERTS[4]}
    _install_recurrence_fixtures(monkeypatch, only_one)
    r = asyncio.run(find_recurring_path(None, 1, days=30))
    assert r["case_ids"] == [2]
    assert r["recurrence_count"] == 1
    assert r["suggests_detection_proposal"] is False


def test_find_recurring_path_trivial_shape_is_noop(monkeypatch):
    # Air-gap analogue: no tactics/techniques -> null signature, no scan.
    trivial = {1: [_alert("a", host="H1")], 2: [_alert("b", host="H2")]}
    _install_recurrence_fixtures(monkeypatch, trivial)
    r = asyncio.run(find_recurring_path(None, 1, days=30))
    assert r["signature"] is None
    assert r["recurrence_count"] == 0
    assert r["case_ids"] == []
    assert r["suggests_detection_proposal"] is False


def test_find_recurring_path_no_alerts_is_safe(monkeypatch):
    async def _fake_fetch(session, case_id):
        return None  # case not found / no alerts

    monkeypatch.setattr(aps, "_fetch_case_alert_dicts", _fake_fetch)
    r = asyncio.run(find_recurring_path(None, 999, days=30))
    assert r["recurrence_count"] == 0
    assert r["suggests_detection_proposal"] is False
