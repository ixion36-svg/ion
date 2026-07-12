"""Regression corpus for the PCAP analyser, built from REAL packet captures.

Ground-truth policy: every capture here is a genuine capture from an external
source (Wireshark SampleCaptures wiki, etc.) — never synthetic/self-generated.
Synthetic captures gave false confidence in the past (ION's own test_pcaps/
seeds were mislabeled: 'malicious_portscan' held no scan, just a DCE/RPC
endpoint-mapper lookup). Real traffic is the only trustworthy signal that a
detection actually fires.

Assertions target EVIDENCE SURFACED (finding categories/severities, MITRE
techniques), not verdict labels — labels are downstream of evidence and
borderline captures shouldn't be forced to a specific verdict.

Captures live in test_pcaps/real/. Each test skips if its capture is absent so
the suite stays green on a fresh checkout before the corpus is fetched.
"""
from pathlib import Path

import pytest

from ion.services.pcap_service import parse_pcap

CORPUS = Path(__file__).parent.parent.parent / "test_pcaps" / "real"


def _load(name):
    f = CORPUS / name
    if not f.exists():
        pytest.skip(f"real corpus capture {name} not present")
    return parse_pcap(f.read_bytes(), name)


def _categories(result):
    return {f["category"] for f in result.findings}


def _by_category(result, category):
    return [f for f in result.findings if f["category"] == category]


class TestRealCorpusParsesCleanly:
    """Every real capture must parse without raising and yield packets."""

    @pytest.mark.parametrize("name", [
        "smbtorture.cap",
        "smb-on-windows-10.pcapng",
        "smb3-aes-128-ccm.pcap",
        "arp-storm.pcap",
        "kpasswd_tcp.cap",
        "dns-remoteshell.pcap",
        "slammer.pcap",
        "krb-816.cap",
    ])
    def test_parses(self, name):
        r = _load(name)
        assert r.packet_count > 0
        assert isinstance(r.verdict, dict) and r.verdict.get("label")


class TestSmbEvidence:
    """SMB1 hygiene must surface, and the carver must not emit phantom files."""

    def test_smbtorture_flags_smb1_and_no_phantom_files(self):
        r = _load("smbtorture.cap")
        assert "Legacy SMB Protocol" in _categories(r)
        # Carver false-positive guard: this benign capture yielded 50 phantom
        # 'files' before structural validation; it must now carve none.
        assert len(r.extracted_files) == 0

    def test_smb_windows10_flags_smb1(self):
        r = _load("smb-on-windows-10.pcapng")
        assert "Legacy SMB Protocol" in _categories(r)

    def test_smb_windows10_extracts_create_filename(self):
        """SMB2 CREATE requests carry the target path — parse it instead of leaving
        filename=''. This real capture opens the \\srvsvc named pipe."""
        r = _load("smb-on-windows-10.pcapng")
        creates = [t for t in r.smb_transfers if t["command"] == "SMB2_CREATE"]
        assert creates, "no SMB2_CREATE transfers parsed"
        assert any(t["filename"] for t in creates), \
            f"filename not extracted; got {[t['filename'] for t in creates]}"
        assert any("srvsvc" in t["filename"] for t in creates)


class TestDcerpcEvidence:
    """Real SMB sessions bind low-risk recon interfaces — surfaced as context."""

    def test_smb_windows10_surfaces_dcerpc_context(self):
        r = _load("smb-on-windows-10.pcapng")
        rpc = _by_category(r, "DCE/RPC Activity")
        assert rpc, "expected DCE/RPC context finding on a real SMB3 session"
        assert all(f["severity"] == "low" for f in rpc)


class TestArpEvidence:
    """A real ARP storm (one MAC claiming many IPs) must produce a finding —
    the anomaly was detected but never wired into findings/verdict."""

    def test_arp_storm_flags_spoofing(self):
        r = _load("arp-storm.pcap")
        arp = _by_category(r, "ARP Spoofing")
        assert arp, f"ARP storm produced no finding; categories={_categories(r)}"
        assert arp[0]["severity"] == "high"
        assert any(t["id"] == "T1557.002" for t in r.mitre_techniques)


class TestCleartextEvidence:
    """dns-remoteshell rides cleartext services — those must be flagged."""

    def test_dns_remoteshell_flags_cleartext(self):
        r = _load("dns-remoteshell.pcap")
        assert "Suspicious Port" in _categories(r) or "Cleartext Protocol" in _categories(r)
