"""v0.97.0 — PCAP case notes carry the extracted protocol evidence (the 'why').

The auto-analysis verdict was already sound; these pin that the supporting
evidence now reaches the note so an analyst can see WHY:
- IKE/IPsec (ISAKMP) sessions, including auth-failure error notifications,
- cleartext/weak-auth credentials observed (never the secret itself),
- each finding's supporting detail, not just its title.
"""

from ion.services.pcap_analysis_service import _render_pcap_markdown
from ion.services.pcap_service import PcapResult


def _render(**over):
    r = PcapResult(packet_count=100, file_size=2048, capture_duration=5.0)
    for k, v in over.items():
        setattr(r, k, v)
    return _render_pcap_markdown("cid-1", [], r)


def test_ike_sessions_and_auth_failure_rendered():
    md = _render(isakmp_sessions=[{
        "initiator": "10.0.0.1", "responder": "10.0.0.2", "ike_version": 2,
        "exchanges": ["IKE_SA_INIT", "IKE_AUTH"], "status": "Failed",
        "retransmits": 3, "errors": ["AUTHENTICATION_FAILED"],
    }])
    assert "IKE / IPsec (ISAKMP) sessions" in md
    assert "10.0.0.1" in md and "10.0.0.2" in md
    assert "IKE_AUTH" in md and "Failed" in md
    assert "AUTHENTICATION_FAILED" in md  # the auth-failure evidence


def test_credentials_rendered_without_the_secret():
    md = _render(credential_captures=[{
        "protocol": "http_basic", "username": "admin",
        "credential": "SUPERSECRET", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9",
    }])
    assert "Credentials observed" in md
    assert "http_basic" in md and "admin" in md
    assert "SUPERSECRET" not in md  # the captured secret must never reach the note


def test_finding_detail_is_shown():
    md = _render(findings=[{
        "severity": "high", "title": "DNS tunneling suspected",
        "detail": "42 TXT queries to r4nd0m.evil.example in 60s",
        "mitre": ["T1071.004"],
    }])
    assert "DNS tunneling suspected" in md
    assert "42 TXT queries to r4nd0m.evil.example in 60s" in md  # the why
    assert "T1071.004" in md


def test_finding_detail_not_duplicated_when_same_as_title():
    md = _render(findings=[{"severity": "low", "title": "same text", "detail": "same text"}])
    assert md.count("same text") == 1  # no duplicated 'why' line
