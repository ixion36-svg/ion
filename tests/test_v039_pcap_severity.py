"""v0.39.0 — PCAP verdict → case severity mapping (two-way auto).

Pins the deterministic mapping in ``pcap_analysis_service.pcap_case_severity``
so the same capture always yields the same case severity.
"""
from types import SimpleNamespace

import pytest

from ion.services.pcap_analysis_service import pcap_case_severity, severity_rank


def _result(findings_sev, score=0, label="Needs Investigation"):
    return SimpleNamespace(
        findings=[{"severity": s} for s in findings_sev],
        verdict={"score": score, "label": label} if (score or label) else {},
    )


def test_severity_rank_order():
    assert severity_rank("low") < severity_rank("medium") < severity_rank("high") < severity_rank("critical")
    assert severity_rank(None) == 0
    assert severity_rank("bogus") == 0


def test_none_and_empty():
    assert pcap_case_severity(None) is None
    # no findings, no verdict → hold (None)
    assert pcap_case_severity(SimpleNamespace(findings=[], verdict={})) is None
    # benign verdict, zero findings → low
    assert pcap_case_severity(SimpleNamespace(findings=[], verdict={"label": "Likely Benign"})) == "low"


@pytest.mark.parametrize("sevs,expected", [
    (["low"], "low"),
    (["low", "medium"], "medium"),
    (["medium", "high", "low"], "high"),
    (["critical", "high"], "critical"),
])
def test_highest_finding_wins(sevs, expected):
    assert pcap_case_severity(_result(sevs, score=0)) == expected


def test_score_floor_escalates():
    # a pile of lows with a high cumulative score → medium
    assert pcap_case_severity(_result(["low", "low", "low"], score=60)) == "medium"
    # mediums with a very high score → high
    assert pcap_case_severity(_result(["medium", "medium"], score=120)) == "high"
    # but a real critical finding is never downgraded by a low score
    assert pcap_case_severity(_result(["critical"], score=0)) == "critical"
