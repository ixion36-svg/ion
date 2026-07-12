"""Threat-intel IOC cross-referencing for PCAP observables (pcap_api).

The analyze endpoint already extracts external IPs/domains and enriches them via
the observable/OpenCTI subsystem; these tests cover turning a known-bad hit into
a finding and recomputing the verdict. Pure logic — no TI backend required.
"""
from ion.web.pcap_api import _apply_ti_findings, _ti_findings


def _enrichment(malicious=True, score=90):
    return {
        "observables": [
            {"type": "ipv4", "value": "185.56.137.138", "enrichment": {
                "source": "opencti", "is_malicious": malicious, "score": score,
                "labels": ["c2"], "threat_actors": ["APT-X"]}},
            {"type": "domain", "value": "benign.example.com", "enrichment": {
                "is_malicious": False, "score": 3}},
        ]
    }


def test_malicious_observable_becomes_critical_finding():
    findings = _ti_findings(_enrichment(malicious=True))
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["category"] == "Threat Intel Match"
    assert "185.56.137.138" in findings[0]["title"]


def test_high_score_without_malicious_flag_still_flags():
    findings = _ti_findings(_enrichment(malicious=False, score=80))
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_benign_observables_produce_no_findings():
    enr = {"observables": [
        {"type": "ipv4", "value": "8.8.8.8", "enrichment": {"is_malicious": False, "score": 0}}]}
    assert _ti_findings(enr) == []


def test_apply_ti_findings_escalates_verdict():
    resp = {
        "findings": [{"category": "DNS Anomaly", "severity": "medium", "title": "x", "detail": "y"}],
        "verdict": {"label": "Likely Benign"},
    }
    _apply_ti_findings(resp, _enrichment(malicious=True))
    assert len(resp["findings"]) == 2
    assert resp["verdict"]["label"] == "Needs Investigation"


def test_apply_ti_findings_noop_when_clean():
    resp = {"findings": [], "verdict": {"label": "Likely Benign"}}
    _apply_ti_findings(resp, _enrichment(malicious=False, score=10))
    assert resp["findings"] == []
    assert resp["verdict"]["label"] == "Likely Benign"
