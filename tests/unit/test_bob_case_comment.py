"""Bob runs per-case (at case creation), not per-alert.

Two pure seams:
- ``should_run_per_alert_sweep`` — the standalone per-alert background sweep is
  OFF when the case grouper is the active investigator; a fallback when it isn't.
- ``_render_bob_case_note`` — the case comment Bob posts on case creation, worded
  to distinguish a single-alert case from a multi-alert cluster.
"""
from ion.services.investigation_service import (
    _render_bob_case_note,
    should_run_per_alert_sweep,
)


class _Cfg:
    def __init__(self, loop=True, grouper=True, grouper_ai=True):
        self.investigation_loop_enabled = loop
        self.case_grouper_enabled = grouper
        self.case_grouper_auto_investigate = grouper_ai


# ── sweep gating ──────────────────────────────────────────────────────────────

def test_sweep_off_when_grouper_actively_investigating():
    assert should_run_per_alert_sweep(_Cfg(loop=True, grouper=True, grouper_ai=True)) is False


def test_sweep_on_when_grouper_disabled_and_loop_enabled():
    assert should_run_per_alert_sweep(_Cfg(loop=True, grouper=False, grouper_ai=True)) is True


def test_sweep_on_when_grouper_enabled_but_not_investigating():
    # Grouper groups but doesn't investigate → per-alert sweep is the investigator.
    assert should_run_per_alert_sweep(_Cfg(loop=True, grouper=True, grouper_ai=False)) is True


def test_sweep_off_when_loop_disabled():
    assert should_run_per_alert_sweep(_Cfg(loop=False, grouper=False, grouper_ai=False)) is False


# ── case comment renderer ─────────────────────────────────────────────────────

_PARSED = {
    "verdict": "true_positive",
    "severity": "high",
    "summary": "Encoded PowerShell download cradle executed from WINWORD.EXE.",
    "recommended_actions": ["Isolate the host", "Retrieve and analyse a.ps1"],
    "mitre": {"techniques": ["T1059.001", "T1105"]},
}


def test_case_note_single_alert_wording():
    body = _render_bob_case_note(_PARSED, cluster_size=1)
    assert "1 alert" in body and "alerts" not in body.split("1 alert")[0][-8:]
    assert "true_positive" in body
    assert "Encoded PowerShell" in body


def test_case_note_multi_alert_wording():
    body = _render_bob_case_note(_PARSED, cluster_size=3)
    assert "3 alerts" in body


def test_case_note_lists_actions_and_attack():
    body = _render_bob_case_note(_PARSED, cluster_size=2)
    assert "Isolate the host" in body
    assert "T1059.001" in body


def test_case_note_handles_missing_fields():
    body = _render_bob_case_note({"verdict": "inconclusive"}, cluster_size=1)
    assert "inconclusive" in body  # never raises on sparse envelopes
