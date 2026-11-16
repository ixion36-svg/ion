"""The case comment Bob posts on case creation.

``_render_bob_case_note`` words a single-alert case differently from a
multi-alert cluster.
"""
from ion.services.investigation_service import _render_bob_case_note


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
