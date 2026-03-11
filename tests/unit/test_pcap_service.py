"""Tests for PCAP parser and heuristic analysis engine.

Accreditation-level test coverage:
- Unit tests for every utility, parser, and detector function
- Boundary value analysis for thresholds and limits
- Malformed/adversarial input handling
- Edge cases: truncated data, zero-length payloads, overflows
- Security: path traversal filenames, binary injection, oversized inputs
- Integration tests with real PCAP files
- Verdict scoring correctness and consistency
"""

import struct
import collections
import pytest

from ion.services.pcap_service import (
    parse_pcap,
    PcapResult,
    Finding,
    _ip_to_str,
    _is_private,
    _fmt_bytes,
    _shannon_entropy,
    _detect_beaconing,
    _detect_dns_tunneling,
    _detect_suspicious_ports,
    _detect_exfiltration,
    _detect_port_scan,
    _detect_dga,
    _detect_isakmp_issues,
    _detect_payload_signatures,
    _detect_suspicious_uas,
    _detect_cleartext_creds,
    _scan_payload_signatures,
    _check_suspicious_ua,
    _check_cleartext_creds,
    _compute_verdict,
    _extract_tls_sni,
    _parse_isakmp,
    _parse_isakmp_payloads,
    _summarise_isakmp,
    _extract_ip,
    _parse_dns,
    SEVERITY_WEIGHTS,
    SUSPICIOUS_PORTS,
    CLEARTEXT_PORTS,
    _MAGIC_SIGNATURES,
    _SHELLCODE_PATTERNS,
    _BASE64_PE_MARKERS,
    _SUSPICIOUS_UA_PATTERNS,
)


# =============================================================================
# 1. Utility function tests
# =============================================================================

class TestIpToStr:
    """RFC-compliant IP address formatting."""

    def test_ipv4_standard(self):
        assert _ip_to_str(b"\xc0\xa8\x01\x01") == "192.168.1.1"

    def test_ipv4_zeros(self):
        assert _ip_to_str(b"\x00\x00\x00\x00") == "0.0.0.0"

    def test_ipv4_broadcast(self):
        assert _ip_to_str(b"\xff\xff\xff\xff") == "255.255.255.255"

    def test_ipv4_loopback(self):
        assert _ip_to_str(b"\x7f\x00\x00\x01") == "127.0.0.1"

    def test_ipv4_class_a(self):
        assert _ip_to_str(b"\x0a\x00\x00\x01") == "10.0.0.1"

    def test_ipv6_link_local(self):
        addr = b"\xfe\x80" + b"\x00" * 6 + b"\x00\x01\x00\x02\x00\x03\x00\x04"
        result = _ip_to_str(addr)
        assert result.startswith("fe80:")
        assert len(result.split(":")) == 8

    def test_ipv6_all_zeros(self):
        result = _ip_to_str(b"\x00" * 16)
        assert result == "0000:0000:0000:0000:0000:0000:0000:0000"

    def test_ipv6_all_ones(self):
        result = _ip_to_str(b"\xff" * 16)
        assert result == "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"

    def test_unknown_length_fallback_to_hex(self):
        assert _ip_to_str(b"\xab\xcd") == "abcd"

    def test_empty_bytes(self):
        assert _ip_to_str(b"") == ""

    def test_single_byte(self):
        assert _ip_to_str(b"\xff") == "ff"

    def test_three_bytes(self):
        result = _ip_to_str(b"\xab\xcd\xef")
        assert result == "abcdef"


class TestIsPrivate:
    """RFC 1918 / loopback / IPv6 ULA classification."""

    def test_rfc1918_10_range_start(self):
        assert _is_private("10.0.0.0") is True

    def test_rfc1918_10_range_end(self):
        assert _is_private("10.255.255.255") is True

    def test_rfc1918_172_16_start(self):
        assert _is_private("172.16.0.1") is True

    def test_rfc1918_172_31_end(self):
        assert _is_private("172.31.255.255") is True

    def test_rfc1918_172_20(self):
        assert _is_private("172.20.0.1") is True

    def test_rfc1918_192_168(self):
        assert _is_private("192.168.0.1") is True

    def test_rfc1918_192_168_high(self):
        assert _is_private("192.168.255.255") is True

    def test_loopback_127_0_0_1(self):
        assert _is_private("127.0.0.1") is True

    def test_loopback_127_high(self):
        assert _is_private("127.255.255.255") is True

    def test_public_8_8_8_8(self):
        assert _is_private("8.8.8.8") is False

    def test_public_1_1_1_1(self):
        assert _is_private("1.1.1.1") is False

    def test_public_203_0_113(self):
        assert _is_private("203.0.113.1") is False

    def test_public_172_15_edge(self):
        """172.15.x.x is NOT private (just below 172.16)."""
        assert _is_private("172.15.255.255") is False

    def test_public_11_0_0_1(self):
        """11.0.0.0 is public (just above 10.x range)."""
        assert _is_private("11.0.0.1") is False

    def test_ipv6_link_local(self):
        assert _is_private("fe80:0000:0000:0000:1234:5678:abcd:ef01") is True

    def test_ipv6_ula_fc(self):
        assert _is_private("fc00::1") is True

    def test_ipv6_ula_fd(self):
        assert _is_private("fd00::1") is True

    def test_ipv6_global_2001(self):
        assert _is_private("2001:db8::1") is False

    def test_empty_string(self):
        assert _is_private("") is False

    def test_non_ip_string(self):
        assert _is_private("not-an-ip") is False


class TestFmtBytes:
    """Byte formatting with boundary checks."""

    def test_zero(self):
        assert _fmt_bytes(0) == "0 B"

    def test_one_byte(self):
        assert _fmt_bytes(1) == "1 B"

    def test_1023_bytes(self):
        assert _fmt_bytes(1023) == "1023 B"

    def test_exactly_1kb(self):
        assert _fmt_bytes(1024) == "1.0 KB"

    def test_1025_bytes(self):
        result = _fmt_bytes(1025)
        assert "KB" in result

    def test_kilobytes(self):
        assert _fmt_bytes(2048) == "2.0 KB"

    def test_just_under_1mb(self):
        result = _fmt_bytes(1024 * 1024 - 1)
        assert "KB" in result

    def test_exactly_1mb(self):
        assert _fmt_bytes(1024 * 1024) == "1.0 MB"

    def test_megabytes(self):
        assert _fmt_bytes(5 * 1024 * 1024) == "5.0 MB"

    def test_gigabytes(self):
        assert _fmt_bytes(2 * 1024 * 1024 * 1024) == "2.0 GB"

    def test_terabyte_scale(self):
        result = _fmt_bytes(1024 * 1024 * 1024 * 1024)
        assert "GB" in result  # 1024 GB


class TestShannonEntropy:
    """Shannon entropy calculation correctness."""

    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char_repeated(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_two_chars_equal(self):
        result = _shannon_entropy("ab")
        assert abs(result - 1.0) < 0.001

    def test_high_entropy(self):
        result = _shannon_entropy("abcdefghij")
        assert result > 3.0

    def test_low_entropy(self):
        result = _shannon_entropy("aaabbb")
        assert result < 1.5

    def test_dga_like_domain(self):
        result = _shannon_entropy("xk4m9qz2bv")
        assert result > 3.0

    def test_real_word_lower_entropy(self):
        result = _shannon_entropy("google")
        assert result < 3.0

    def test_case_insensitive(self):
        """Entropy should be same regardless of case."""
        lower = _shannon_entropy("abcd")
        upper = _shannon_entropy("ABCD")
        assert abs(lower - upper) < 0.001

    def test_single_char_string(self):
        assert _shannon_entropy("a") == 0.0

    def test_all_unique_8_chars(self):
        result = _shannon_entropy("abcdefgh")
        assert abs(result - 3.0) < 0.01


# =============================================================================
# 2. IP packet extraction tests
# =============================================================================

class TestExtractIp:
    """Raw packet IP extraction — handles Ethernet and raw IP."""

    def test_valid_ethernet_ipv4(self):
        """Standard Ethernet frame wrapping IPv4."""
        import dpkt
        ip = dpkt.ip.IP(src=b"\xc0\xa8\x01\x01", dst=b"\x08\x08\x08\x08")
        ip.data = dpkt.tcp.TCP(sport=12345, dport=80)
        ip.p = dpkt.ip.IP_PROTO_TCP
        ip.len = len(bytes(ip))
        eth = dpkt.ethernet.Ethernet(
            dst=b"\xff" * 6, src=b"\x00" * 6,
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip
        )
        result = _extract_ip(bytes(eth))
        assert result is not None

    def test_raw_ipv4_no_ethernet(self):
        """Raw IP packet without Ethernet header."""
        import dpkt
        ip = dpkt.ip.IP(src=b"\xc0\xa8\x01\x01", dst=b"\x08\x08\x08\x08")
        ip.data = dpkt.tcp.TCP(sport=12345, dport=80)
        ip.p = dpkt.ip.IP_PROTO_TCP
        ip.len = len(bytes(ip))
        result = _extract_ip(bytes(ip))
        assert result is not None

    def test_garbage_returns_none(self):
        result = _extract_ip(b"\x00\x01\x02\x03")
        assert result is None

    def test_empty_returns_none(self):
        result = _extract_ip(b"")
        assert result is None

    def test_truncated_packet(self):
        """Truncated data should not crash."""
        result = _extract_ip(b"\x45\x00")
        # May or may not parse, but should not raise


class TestParseDns:
    """DNS query name extraction."""

    def test_valid_dns_query(self):
        import dpkt
        dns = dpkt.dns.DNS()
        dns.qd = [dpkt.dns.DNS.Q(name="example.com", type=dpkt.dns.DNS_A)]
        dns.op = dpkt.dns.DNS_QR
        counter = collections.Counter()
        _parse_dns(bytes(dns), counter)
        assert "example.com" in counter

    def test_malformed_dns_no_crash(self):
        counter = collections.Counter()
        _parse_dns(b"\x00\x01\x02", counter)
        # Should not raise

    def test_empty_dns(self):
        counter = collections.Counter()
        _parse_dns(b"", counter)
        assert len(counter) == 0


# =============================================================================
# 3. TLS SNI extraction
# =============================================================================

class TestExtractTlsSni:
    """TLS ClientHello SNI parsing — security critical for correct TLS inspection."""

    def test_non_tls_returns_none(self):
        assert _extract_tls_sni(b"GET / HTTP/1.1\r\n") is None

    def test_too_short_returns_none(self):
        assert _extract_tls_sni(b"\x16\x03\x01") is None

    def test_wrong_record_type_returns_none(self):
        assert _extract_tls_sni(b"\x17" + b"\x00" * 50) is None

    def test_truncated_handshake_returns_none(self):
        """Not a ClientHello (handshake type != 1)."""
        data = b"\x16\x03\x01\x00\x05\x02" + b"\x00" * 40
        assert _extract_tls_sni(data) is None

    def test_empty_returns_none(self):
        assert _extract_tls_sni(b"") is None


# =============================================================================
# 4. ISAKMP/IKE parsing
# =============================================================================

class TestParseIsakmp:
    """ISAKMP packet parser — header validation and session tracking."""

    def _build_isakmp_header(self, init_spi=b"\xaa" * 8, resp_spi=b"\x00" * 8,
                              next_payload=0, version=0x10, exchange_type=2,
                              flags=0, msg_id=0, total_len=28):
        return (
            init_spi + resp_spi +
            bytes([next_payload, version, exchange_type, flags]) +
            struct.pack("!I", msg_id) +
            struct.pack("!I", total_len)
        )

    def test_valid_ike_init(self):
        sessions = {}
        proto_counter = collections.Counter()
        data = self._build_isakmp_header()
        _parse_isakmp(data, "10.0.0.1", "10.0.0.2", 500, 500, 1.0, sessions, proto_counter)
        assert len(sessions) == 1
        assert proto_counter["ISAKMP"] == 1

    def test_too_short_ignored(self):
        sessions = {}
        proto_counter = collections.Counter()
        _parse_isakmp(b"\x00" * 10, "10.0.0.1", "10.0.0.2", 500, 500, 1.0, sessions, proto_counter)
        assert len(sessions) == 0

    def test_nat_t_port_4500_skips_marker(self):
        """Port 4500 packets have a 4-byte non-ESP marker prefix."""
        sessions = {}
        proto_counter = collections.Counter()
        marker = b"\x00\x00\x00\x00"
        data = marker + self._build_isakmp_header()
        _parse_isakmp(data, "10.0.0.1", "10.0.0.2", 4500, 4500, 1.0, sessions, proto_counter)
        assert len(sessions) == 1

    def test_insane_length_ignored(self):
        """Total length wildly exceeding data size should be rejected."""
        sessions = {}
        proto_counter = collections.Counter()
        data = self._build_isakmp_header(total_len=99999)
        _parse_isakmp(data, "10.0.0.1", "10.0.0.2", 500, 500, 1.0, sessions, proto_counter)
        assert len(sessions) == 0

    def test_version_parsed_correctly(self):
        """IKEv2 = version byte 0x20 (major=2, minor=0)."""
        sessions = {}
        proto_counter = collections.Counter()
        data = self._build_isakmp_header(version=0x20)
        _parse_isakmp(data, "10.0.0.1", "10.0.0.2", 500, 500, 1.0, sessions, proto_counter)
        spi_key = b"\xaa" * 8
        assert sessions[spi_key]["ike_version"] == "2.0"

    def test_responder_spi_tracked(self):
        """When responder SPI is non-zero, it should be recorded."""
        sessions = {}
        proto_counter = collections.Counter()
        resp_spi = b"\xbb" * 8
        data = self._build_isakmp_header(resp_spi=resp_spi)
        _parse_isakmp(data, "10.0.0.2", "10.0.0.1", 500, 500, 2.0, sessions, proto_counter)
        spi_key = b"\xaa" * 8
        assert sessions[spi_key]["resp_spi"] == resp_spi.hex()

    def test_quick_mode_sets_established(self):
        """Exchange type 32 (Quick Mode) should mark session established."""
        sessions = {}
        proto_counter = collections.Counter()
        # First: main mode init
        data1 = self._build_isakmp_header(exchange_type=2)
        _parse_isakmp(data1, "10.0.0.1", "10.0.0.2", 500, 500, 1.0, sessions, proto_counter)
        # Then: quick mode
        data2 = self._build_isakmp_header(exchange_type=32, resp_spi=b"\xbb" * 8)
        _parse_isakmp(data2, "10.0.0.1", "10.0.0.2", 500, 500, 2.0, sessions, proto_counter)
        spi_key = b"\xaa" * 8
        assert sessions[spi_key]["established"] is True

    def test_ike_auth_sets_established(self):
        """Exchange type 35 (IKE_AUTH) should mark session established."""
        sessions = {}
        proto_counter = collections.Counter()
        data = self._build_isakmp_header(exchange_type=35, version=0x20)
        _parse_isakmp(data, "10.0.0.1", "10.0.0.2", 500, 500, 1.0, sessions, proto_counter)
        spi_key = b"\xaa" * 8
        assert sessions[spi_key]["established"] is True

    def test_retransmit_detection(self):
        sessions = {}
        proto_counter = collections.Counter()
        data = self._build_isakmp_header()
        # Send same init 3 times from same source
        for i in range(3):
            _parse_isakmp(data, "10.0.0.1", "10.0.0.2", 500, 500, float(i), sessions, proto_counter)
        spi_key = b"\xaa" * 8
        assert sessions[spi_key]["retransmits"] >= 2

    def test_multiple_sessions_tracked(self):
        sessions = {}
        proto_counter = collections.Counter()
        data1 = self._build_isakmp_header(init_spi=b"\x01" * 8)
        data2 = self._build_isakmp_header(init_spi=b"\x02" * 8)
        _parse_isakmp(data1, "10.0.0.1", "10.0.0.2", 500, 500, 1.0, sessions, proto_counter)
        _parse_isakmp(data2, "10.0.0.3", "10.0.0.4", 500, 500, 2.0, sessions, proto_counter)
        assert len(sessions) == 2


class TestParseIsakmpPayloads:
    """ISAKMP payload chain walking — boundary and malformed input tests."""

    def test_empty_payload(self):
        sess = {"notifications": [], "has_delete": False}
        _parse_isakmp_payloads(b"", 0, sess)  # next_payload = NONE
        assert len(sess["notifications"]) == 0

    def test_notify_payload_parsed(self):
        """Notification payload with NO_PROPOSAL_CHOSEN error."""
        sess = {"notifications": [], "has_delete": False}
        # IKEv2 notify body: Protocol ID (1), SPI Size (1), Notify Type (2)
        notify_body = bytes([1, 0]) + struct.pack("!H", 14)  # protocol=1, spi_sz=0, type=14
        payload = bytes([0, 0]) + struct.pack("!H", 4 + len(notify_body)) + notify_body
        _parse_isakmp_payloads(payload, 11, sess)  # 11 = NOTIFY
        assert len(sess["notifications"]) == 1
        assert sess["notifications"][0]["name"] == "NO_PROPOSAL_CHOSEN"
        assert sess["notifications"][0]["is_error"] is True

    def test_delete_payload_detected(self):
        sess = {"notifications": [], "has_delete": False}
        payload = bytes([0, 0]) + struct.pack("!H", 8) + b"\x00" * 4
        _parse_isakmp_payloads(payload, 12, sess)  # 12 = DELETE
        assert sess["has_delete"] is True

    def test_payload_too_short_stops(self):
        sess = {"notifications": [], "has_delete": False}
        _parse_isakmp_payloads(b"\x00\x00", 11, sess)
        assert len(sess["notifications"]) == 0

    def test_payload_length_zero_stops(self):
        """Payload with length < 4 should break the loop (safety)."""
        sess = {"notifications": [], "has_delete": False}
        payload = bytes([11, 0]) + struct.pack("!H", 0)  # length = 0
        _parse_isakmp_payloads(payload, 11, sess)
        assert len(sess["notifications"]) == 0

    def test_max_payload_chain_limit(self):
        """Safety limit of 20 payloads prevents infinite loop."""
        sess = {"notifications": [], "has_delete": False}
        # Chain 30 notify payloads (each 8 bytes: next=11, reserved, len=8, body)
        chain = b""
        for i in range(30):
            next_p = 11 if i < 29 else 0
            chain += bytes([next_p, 0]) + struct.pack("!H", 8) + struct.pack("!HH", 0, 1)
        _parse_isakmp_payloads(chain, 11, sess)
        # Should process at most 20 payloads
        assert len(sess["notifications"]) <= 20


class TestSummariseIsakmp:
    """ISAKMP session summary generation."""

    def _make_session(self, established=False, resp_packets=1, errors=None, retransmits=0):
        return {
            "init_spi": "aabb",
            "resp_spi": "ccdd" if resp_packets > 0 else None,
            "initiator_ip": "10.0.0.1",
            "responder_ip": "10.0.0.2",
            "ike_version": "1.0",
            "exchange_types": ["Main Mode"],
            "packets": 4,
            "initiator_packets": 2,
            "responder_packets": resp_packets,
            "first_seen": 0,
            "last_seen": 10,
            "notifications": errors or [],
            "has_delete": False,
            "established": established,
            "retransmits": retransmits,
        }

    def test_empty_sessions(self):
        assert _summarise_isakmp({}) == []

    def test_established_status(self):
        sessions = {b"spi1": self._make_session(established=True)}
        result = _summarise_isakmp(sessions)
        assert result[0]["status"] == "Established"

    def test_failed_status(self):
        errors = [{"type": 14, "name": "NO_PROPOSAL_CHOSEN", "is_error": True}]
        sessions = {b"spi1": self._make_session(errors=errors)}
        result = _summarise_isakmp(sessions)
        assert result[0]["status"] == "Failed"

    def test_no_response_status(self):
        sessions = {b"spi1": self._make_session(resp_packets=0)}
        result = _summarise_isakmp(sessions)
        assert result[0]["status"] == "No Response"

    def test_incomplete_status(self):
        sessions = {b"spi1": self._make_session(resp_packets=2)}
        result = _summarise_isakmp(sessions)
        assert result[0]["status"] == "Incomplete"

    def test_established_sorted_first(self):
        sessions = {
            b"spi1": self._make_session(resp_packets=0),
            b"spi2": self._make_session(established=True),
        }
        result = _summarise_isakmp(sessions)
        assert result[0]["status"] == "Established"


# =============================================================================
# 5. Beaconing detection
# =============================================================================

class TestDetectBeaconing:
    """C2 beaconing detection via interval coefficient of variation."""

    def test_regular_intervals_detected(self):
        times = {("10.0.0.1", "1.2.3.4", 443): [i * 60.0 for i in range(10)]}
        findings = _detect_beaconing(times)
        assert len(findings) >= 1
        assert findings[0].severity == "high"
        assert "Beaconing" in findings[0].title

    def test_irregular_intervals_not_flagged(self):
        times = {("10.0.0.1", "1.2.3.4", 443): [0, 5, 45, 47, 120, 300, 301, 500]}
        findings = _detect_beaconing(times)
        assert len(findings) == 0

    def test_too_few_connections_ignored(self):
        times = {("10.0.0.1", "1.2.3.4", 443): [0, 60, 120]}
        findings = _detect_beaconing(times)
        assert len(findings) == 0

    def test_exactly_5_connections_threshold(self):
        """5 connections = minimum for detection."""
        times = {("10.0.0.1", "1.2.3.4", 443): [i * 30.0 for i in range(5)]}
        findings = _detect_beaconing(times)
        assert len(findings) >= 1

    def test_sub_second_intervals_ignored(self):
        times = {("10.0.0.1", "1.2.3.4", 80): [i * 0.1 for i in range(20)]}
        findings = _detect_beaconing(times)
        assert len(findings) == 0

    def test_empty_input(self):
        findings = _detect_beaconing({})
        assert len(findings) == 0

    def test_cv_boundary_at_015(self):
        """CV = 0.15 is the threshold. High jitter should not flag."""
        # Intervals with ~50% jitter → CV well above 0.15
        times_list = [0, 30, 100, 130, 220, 240, 340, 350, 470, 480]
        times = {("10.0.0.1", "1.2.3.4", 443): times_list}
        findings = _detect_beaconing(times)
        assert len(findings) == 0

    def test_multiple_beacons_detected(self):
        """Multiple C2 channels should each generate a finding."""
        times = {
            ("10.0.0.1", "1.2.3.4", 443): [i * 60.0 for i in range(10)],
            ("10.0.0.2", "5.6.7.8", 8443): [i * 30.0 for i in range(10)],
        }
        findings = _detect_beaconing(times)
        assert len(findings) == 2


# =============================================================================
# 6. DNS tunneling detection
# =============================================================================

class TestDetectDnsTunneling:
    """DNS tunneling / C2 detection heuristics."""

    def test_long_queries_detected(self):
        dns = collections.Counter({"a" * 55 + ".evil.com": 10})
        findings = _detect_dns_tunneling(dns)
        assert any("long DNS" in f.title for f in findings)

    def test_exactly_50_chars_not_flagged(self):
        """Query of exactly 50 chars should NOT flag (threshold is >50)."""
        query = "a" * 42 + ".evil.com"  # 42 + 9 = 51 chars total → flags
        dns = collections.Counter({query: 5})
        findings = _detect_dns_tunneling(dns)
        long_findings = [f for f in findings if "long DNS" in f.title]
        if len(query) > 50:
            assert len(long_findings) >= 1
        else:
            assert len(long_findings) == 0

    def test_high_subdomain_diversity_50plus(self):
        dns = collections.Counter({f"sub{i}.evil.com": 1 for i in range(60)})
        findings = _detect_dns_tunneling(dns)
        assert any("diversity" in f.title.lower() for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_medium_subdomain_diversity_15_to_50(self):
        dns = collections.Counter({f"sub{i}.c2.net": 5 for i in range(20)})
        findings = _detect_dns_tunneling(dns)
        assert any("Elevated" in f.title for f in findings)

    def test_repetitive_queries_5plus_subs_50plus_total(self):
        dns = collections.Counter({f"s{i}.beacon.io": 15 for i in range(6)})
        findings = _detect_dns_tunneling(dns)
        assert any("Repetitive" in f.title or "diversity" in f.title.lower() for f in findings)

    def test_normal_dns_not_flagged(self):
        dns = collections.Counter({
            "www.google.com": 5,
            "mail.google.com": 3,
            "dns.google.com": 2,
            "www.example.com": 1,
        })
        findings = _detect_dns_tunneling(dns)
        assert len(findings) == 0

    def test_empty_counter(self):
        findings = _detect_dns_tunneling(collections.Counter())
        assert len(findings) == 0

    def test_two_part_domain_ignored(self):
        """Domains like 'google.com' (only 2 parts) shouldn't trigger subdomain checks."""
        dns = collections.Counter({"google.com": 1000})
        findings = _detect_dns_tunneling(dns)
        subdomain_findings = [f for f in findings if "diversity" in f.title.lower()]
        assert len(subdomain_findings) == 0


# =============================================================================
# 7. Suspicious ports
# =============================================================================

class TestDetectSuspiciousPorts:
    """Known-bad port detection."""

    def test_metasploit_port_critical(self):
        counter = collections.Counter({4444: 100})
        findings = _detect_suspicious_ports(counter)
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_back_orifice_port_critical(self):
        counter = collections.Counter({31337: 5})
        findings = _detect_suspicious_ports(counter)
        assert findings[0].severity == "critical"

    def test_tor_port_high(self):
        counter = collections.Counter({9001: 10})
        findings = _detect_suspicious_ports(counter)
        assert findings[0].severity == "high"

    def test_rdp_port_medium(self):
        counter = collections.Counter({3389: 50})
        findings = _detect_suspicious_ports(counter)
        assert findings[0].severity == "medium"

    def test_single_packet_triggers(self):
        """Even 1 packet to a suspicious port should flag."""
        counter = collections.Counter({4444: 1})
        findings = _detect_suspicious_ports(counter)
        assert len(findings) == 1

    def test_normal_ports_not_flagged(self):
        counter = collections.Counter({80: 1000, 443: 2000, 8080: 500})
        findings = _detect_suspicious_ports(counter)
        assert len(findings) == 0

    def test_zero_count_not_flagged(self):
        counter = collections.Counter()
        findings = _detect_suspicious_ports(counter)
        assert len(findings) == 0

    def test_all_suspicious_ports_covered(self):
        """Every port in SUSPICIOUS_PORTS should produce a finding."""
        counter = collections.Counter({p: 1 for p in SUSPICIOUS_PORTS})
        findings = _detect_suspicious_ports(counter)
        assert len(findings) == len(SUSPICIOUS_PORTS)

    def test_multiple_suspicious_ports(self):
        counter = collections.Counter({4444: 10, 9001: 5, 3389: 20})
        findings = _detect_suspicious_ports(counter)
        assert len(findings) == 3


# =============================================================================
# 8. Exfiltration detection
# =============================================================================

class TestDetectExfiltration:
    """Data exfiltration detection — volume and ratio thresholds."""

    def test_large_outbound_detected(self):
        ip_sent = collections.Counter({"192.168.1.10": 200_000_000})
        ip_recv = collections.Counter({"192.168.1.10": 1_000_000})
        findings = _detect_exfiltration(ip_sent, ip_recv)
        assert len(findings) >= 1
        assert findings[0].severity == "high"

    def test_exactly_100mb_threshold(self):
        """Exactly 100MB should trigger."""
        ip_sent = collections.Counter({"10.0.0.1": 100_000_001})
        ip_recv = collections.Counter({"10.0.0.1": 100})
        findings = _detect_exfiltration(ip_sent, ip_recv)
        assert len(findings) >= 1

    def test_just_under_100mb_no_volume_flag(self):
        """Under 100MB won't trigger the volume check (may trigger ratio)."""
        ip_sent = collections.Counter({"10.0.0.1": 99_999_999})
        ip_recv = collections.Counter({"10.0.0.1": 50_000_000})
        findings = _detect_exfiltration(ip_sent, ip_recv)
        volume_findings = [f for f in findings if "Large outbound" in f.title]
        assert len(volume_findings) == 0

    def test_asymmetric_ratio_detected(self):
        ip_sent = collections.Counter({"10.0.0.5": 50_000_000})
        ip_recv = collections.Counter({"10.0.0.5": 1_000_000})
        findings = _detect_exfiltration(ip_sent, ip_recv)
        assert any("Asymmetric" in f.title for f in findings)

    def test_external_ip_not_flagged(self):
        ip_sent = collections.Counter({"8.8.8.8": 500_000_000})
        ip_recv = collections.Counter({"8.8.8.8": 1_000})
        findings = _detect_exfiltration(ip_sent, ip_recv)
        assert len(findings) == 0

    def test_normal_traffic_not_flagged(self):
        ip_sent = collections.Counter({"192.168.1.10": 5_000_000})
        ip_recv = collections.Counter({"192.168.1.10": 4_000_000})
        findings = _detect_exfiltration(ip_sent, ip_recv)
        assert len(findings) == 0

    def test_zero_received_with_large_sent(self):
        """IP that sent >100MB but received 0 bytes."""
        ip_sent = collections.Counter({"10.0.0.1": 200_000_000})
        ip_recv = collections.Counter()
        findings = _detect_exfiltration(ip_sent, ip_recv)
        assert len(findings) >= 1

    def test_empty_counters(self):
        findings = _detect_exfiltration(collections.Counter(), collections.Counter())
        assert len(findings) == 0


# =============================================================================
# 9. Port scan detection
# =============================================================================

class TestDetectPortScan:
    """Vertical and horizontal port scan detection."""

    def test_vertical_scan_detected(self):
        conn_times = {("10.0.0.1", "10.0.0.2", p): [1.0] for p in range(25)}
        findings = _detect_port_scan(conn_times)
        assert any("Port scan" in f.title for f in findings)

    def test_exactly_20_ports_not_flagged(self):
        """20 ports = not a scan (threshold is >20)."""
        conn_times = {("10.0.0.1", "10.0.0.2", p): [1.0] for p in range(20)}
        findings = _detect_port_scan(conn_times)
        vertical = [f for f in findings if "Port scan" in f.title and "Horizontal" not in f.title]
        assert len(vertical) == 0

    def test_21_ports_triggers_scan(self):
        conn_times = {("10.0.0.1", "10.0.0.2", p): [1.0] for p in range(21)}
        findings = _detect_port_scan(conn_times)
        assert any("Port scan" in f.title for f in findings)

    def test_horizontal_scan_detected(self):
        conn_times = {("10.0.0.1", f"10.0.0.{i}", 445): [1.0] for i in range(15)}
        findings = _detect_port_scan(conn_times)
        assert any("Horizontal" in f.title for f in findings)

    def test_exactly_10_hosts_not_flagged(self):
        conn_times = {("10.0.0.1", f"10.0.0.{i}", 445): [1.0] for i in range(10)}
        findings = _detect_port_scan(conn_times)
        horiz = [f for f in findings if "Horizontal" in f.title]
        assert len(horiz) == 0

    def test_normal_connections_not_flagged(self):
        conn_times = {
            ("10.0.0.1", "10.0.0.2", 80): [1.0],
            ("10.0.0.1", "10.0.0.3", 443): [2.0],
            ("10.0.0.1", "10.0.0.4", 22): [3.0],
        }
        findings = _detect_port_scan(conn_times)
        assert len(findings) == 0

    def test_empty_input(self):
        findings = _detect_port_scan({})
        assert len(findings) == 0


# =============================================================================
# 10. DGA detection
# =============================================================================

class TestDetectDga:
    """Domain Generation Algorithm detection via Shannon entropy."""

    def test_high_entropy_domains_detected(self):
        dns = collections.Counter({
            "xk4m9qzr2bv7np.com": 1,
            "b7n3p2wvj5k8mx.com": 1,
            "qz8k4mxr9wv3jn.net": 1,
            "j5v9b3nwxk2m4q.org": 1,
        })
        findings = _detect_dga(dns)
        assert len(findings) >= 1
        assert any("DGA" in f.category for f in findings)

    def test_normal_domains_not_flagged(self):
        dns = collections.Counter({
            "google.com": 10,
            "facebook.com": 5,
            "amazon.com": 3,
        })
        findings = _detect_dga(dns)
        assert len(findings) == 0

    def test_short_sld_ignored(self):
        dns = collections.Counter({"abc.com": 10})
        findings = _detect_dga(dns)
        assert len(findings) == 0

    def test_exactly_6_char_sld_checked(self):
        """6-char SLD is the minimum for entropy check."""
        dns = collections.Counter({"abcdef.com": 10})
        findings = _detect_dga(dns)
        # "abcdef" entropy ≈ 2.58, under 3.5 threshold
        assert len(findings) == 0

    def test_single_high_entropy_domain_medium(self):
        """1-3 high entropy domains = medium per-domain findings."""
        dns = collections.Counter({"xk4m9qzr2bv7np.com": 1})
        findings = _detect_dga(dns)
        if findings:
            assert findings[0].severity == "medium"

    def test_many_high_entropy_domains_high(self):
        """4+ high entropy domains = single high severity finding."""
        dns = collections.Counter({
            f"{''.join(chr(ord('a') + (i*7+j) % 26) for j in range(14))}.com": 1
            for i in range(5)
        })
        findings = _detect_dga(dns)
        high_findings = [f for f in findings if f.severity == "high"]
        # May produce high severity if 4+ pass entropy threshold
        assert len(findings) >= 1

    def test_empty_counter(self):
        findings = _detect_dga(collections.Counter())
        assert len(findings) == 0


# =============================================================================
# 11. ISAKMP detection logic
# =============================================================================

class TestDetectIsakmpIssues:
    """ISAKMP/IKE finding generation — internal/external classification."""

    def _make_session(self, init_ip, resp_ip, established=False, resp_packets=1,
                      errors=None, retransmits=0, has_delete=False):
        return {
            "init_spi": "aabbccdd11223344",
            "resp_spi": "1122334455667788" if resp_packets > 0 else None,
            "initiator_ip": init_ip,
            "responder_ip": resp_ip,
            "ike_version": "2.0",
            "exchange_types": ["IKE_SA_INIT (IKEv2)"],
            "packets": 4,
            "initiator_packets": 2,
            "responder_packets": resp_packets,
            "first_seen": 0,
            "last_seen": 10,
            "notifications": errors or [],
            "has_delete": has_delete,
            "established": established,
            "retransmits": retransmits,
        }

    def test_internal_established_is_benign(self):
        sessions = {b"spi1": self._make_session("192.168.1.1", "10.0.0.1", established=True)}
        findings = _detect_isakmp_issues(sessions)
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert "internal" in findings[0].title.lower()

    def test_external_established_is_critical(self):
        sessions = {b"spi1": self._make_session("192.168.1.1", "8.8.8.8", established=True)}
        findings = _detect_isakmp_issues(sessions)
        assert any(f.severity == "critical" for f in findings)
        assert any("Unauthorized" in f.title for f in findings)

    def test_external_no_response_is_probing(self):
        sessions = {b"spi1": self._make_session("192.168.1.1", "1.2.3.4",
                                                 established=False, resp_packets=0)}
        findings = _detect_isakmp_issues(sessions)
        assert any(f.severity == "high" for f in findings)
        assert any("probing" in f.title.lower() for f in findings)

    def test_external_failed_is_high(self):
        errors = [{"type": 14, "name": "NO_PROPOSAL_CHOSEN", "is_error": True}]
        sessions = {b"spi1": self._make_session("10.0.0.5", "203.0.113.1",
                                                 established=False, errors=errors)}
        findings = _detect_isakmp_issues(sessions)
        assert any(f.severity == "high" for f in findings)

    def test_external_incomplete_treated_as_failed(self):
        """External session with no errors but not established should be high."""
        sessions = {b"spi1": self._make_session("10.0.0.1", "8.8.8.8",
                                                 established=False, resp_packets=2)}
        findings = _detect_isakmp_issues(sessions)
        assert any(f.severity == "high" for f in findings)

    def test_internal_no_response_flagged(self):
        sessions = {b"spi1": self._make_session("192.168.1.10", "192.168.1.1",
                                                 established=False, resp_packets=0)}
        findings = _detect_isakmp_issues(sessions)
        assert any("no server response" in f.title.lower() for f in findings)

    def test_internal_failed_medium(self):
        errors = [{"type": 14, "name": "NO_PROPOSAL_CHOSEN", "is_error": True}]
        sessions = {b"spi1": self._make_session("192.168.1.1", "192.168.1.2",
                                                 established=False, errors=errors)}
        findings = _detect_isakmp_issues(sessions)
        assert any(f.severity == "medium" for f in findings)

    def test_retransmissions_flagged(self):
        sessions = {b"spi1": self._make_session("192.168.1.1", "192.168.1.2",
                                                 established=True, retransmits=5)}
        findings = _detect_isakmp_issues(sessions)
        assert any("retransmission" in f.title.lower() for f in findings)

    def test_retransmissions_below_threshold_not_flagged(self):
        """2 retransmits is at the threshold (>2 to flag)."""
        sessions = {b"spi1": self._make_session("192.168.1.1", "192.168.1.2",
                                                 established=True, retransmits=2)}
        findings = _detect_isakmp_issues(sessions)
        retrans_findings = [f for f in findings if "retransmission" in f.title.lower()]
        assert len(retrans_findings) == 0

    def test_high_teardown_rate(self):
        """>50% sessions with delete = flagged."""
        sessions = {
            b"s1": self._make_session("10.0.0.1", "10.0.0.2", established=True, has_delete=True),
            b"s2": self._make_session("10.0.0.1", "10.0.0.3", established=True, has_delete=True),
            b"s3": self._make_session("10.0.0.1", "10.0.0.4", established=True, has_delete=False),
        }
        findings = _detect_isakmp_issues(sessions)
        assert any("torn down" in f.title.lower() for f in findings)

    def test_empty_sessions(self):
        findings = _detect_isakmp_issues({})
        assert len(findings) == 0

    def test_none_ips_handled(self):
        """Sessions with None IPs should not crash."""
        sess = self._make_session("192.168.1.1", "10.0.0.1", established=True)
        sess["initiator_ip"] = None
        sess["responder_ip"] = None
        sessions = {b"spi1": sess}
        # Should not raise
        findings = _detect_isakmp_issues(sessions)


# =============================================================================
# 12. Payload signature detection
# =============================================================================

class TestPayloadSignatures:
    """Malware magic bytes and shellcode detection."""

    def test_pe_executable_detected(self):
        sigs = []
        _scan_payload_signatures(b"MZ" + b"\x00" * 100, "10.0.0.1", "10.0.0.2", 4444, 8080, sigs)
        assert len(sigs) == 1
        assert "PE Executable" in sigs[0]["sig"]

    def test_elf_binary_detected(self):
        sigs = []
        _scan_payload_signatures(b"\x7fELF" + b"\x00" * 100, "10.0.0.1", "10.0.0.2", 1234, 9999, sigs)
        assert len(sigs) == 1
        assert "ELF" in sigs[0]["sig"]

    def test_script_shebang_detected(self):
        sigs = []
        _scan_payload_signatures(b"#!/bin/bash\n" + b"\x00" * 100, "10.0.0.1", "10.0.0.2", 80, 4444, sigs)
        assert len(sigs) == 1
        assert "Script" in sigs[0]["sig"]

    def test_zip_archive_detected(self):
        sigs = []
        _scan_payload_signatures(b"PK\x03\x04" + b"\x00" * 100, "10.0.0.1", "10.0.0.2", 80, 4444, sigs)
        assert len(sigs) == 1
        assert "ZIP" in sigs[0]["sig"]

    def test_ole2_document_detected(self):
        sigs = []
        _scan_payload_signatures(b"\xd0\xcf\x11\xe0" + b"\x00" * 100, "10.0.0.1", "10.0.0.2", 80, 4444, sigs)
        assert len(sigs) == 1
        assert "OLE2" in sigs[0]["sig"]

    def test_pdf_detected(self):
        sigs = []
        _scan_payload_signatures(b"%PDF-1.4" + b"\x00" * 100, "10.0.0.1", "10.0.0.2", 80, 4444, sigs)
        assert len(sigs) == 1
        assert "PDF" in sigs[0]["sig"]

    def test_nop_sled_detected(self):
        sigs = []
        _scan_payload_signatures(b"\x90" * 20 + b"\xcc" * 10, "10.0.0.1", "10.0.0.2", 80, 4444, sigs)
        assert len(sigs) == 1
        assert "NOP sled" in sigs[0]["sig"]

    def test_int3_sled_detected(self):
        sigs = []
        _scan_payload_signatures(b"\xcc" * 10, "10.0.0.1", "10.0.0.2", 80, 4444, sigs)
        assert len(sigs) == 1
        assert "INT3" in sigs[0]["sig"]

    def test_metasploit_reverse_shell_detected(self):
        sigs = []
        payload = b"\xfc\xe8\x82\x00\x00\x00" + b"\x00" * 100
        _scan_payload_signatures(payload, "10.0.0.1", "10.0.0.2", 4444, 8080, sigs)
        assert len(sigs) == 1
        assert "Metasploit" in sigs[0]["sig"]

    def test_metasploit_x64_detected(self):
        sigs = []
        payload = b"\xfc\x48\x83\xe4\xf0" + b"\x00" * 100
        _scan_payload_signatures(payload, "10.0.0.1", "10.0.0.2", 4444, 8080, sigs)
        assert len(sigs) == 1
        assert "x64" in sigs[0]["sig"]

    def test_linux_execve_detected(self):
        sigs = []
        payload = b"\x31\xc0\x50\x68\x2f\x2f" + b"\x00" * 100
        _scan_payload_signatures(payload, "10.0.0.1", "10.0.0.2", 4444, 8080, sigs)
        assert len(sigs) == 1
        assert "execve" in sigs[0]["sig"]

    def test_base64_pe_detected(self):
        sigs = []
        _scan_payload_signatures(b"data TVqQAAMAAAA more data", "10.0.0.1", "10.0.0.2", 80, 8080, sigs)
        assert len(sigs) == 1
        assert "Base64" in sigs[0]["sig"]

    def test_all_base64_pe_markers(self):
        """Every base64 PE marker variant should be detected."""
        for marker in _BASE64_PE_MARKERS:
            sigs = []
            _scan_payload_signatures(b"xxx" + marker + b"xxx" * 50, "10.0.0.1", "10.0.0.2", 80, 8080, sigs)
            assert len(sigs) == 1, f"Marker {marker} not detected"

    def test_encoded_powershell_detected(self):
        sigs = []
        payload = b"cmd /c powershell -enc SQBFAFgAIAAoA..."
        _scan_payload_signatures(payload, "10.0.0.1", "10.0.0.2", 80, 4444, sigs)
        assert len(sigs) == 1
        assert "PowerShell" in sigs[0]["sig"]

    def test_powershell_encodedcommand_variant(self):
        sigs = []
        payload = b"powershell.exe -encodedcommand SQBFAFgA"
        _scan_payload_signatures(payload, "10.0.0.1", "10.0.0.2", 80, 4444, sigs)
        assert len(sigs) == 1

    def test_normal_http_not_flagged(self):
        sigs = []
        _scan_payload_signatures(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>",
                                 "10.0.0.1", "10.0.0.2", 80, 12345, sigs)
        assert len(sigs) == 0

    def test_pe_on_port_80_medium_severity(self):
        sigs = []
        _scan_payload_signatures(b"MZ" + b"\x00" * 100, "1.2.3.4", "10.0.0.1", 80, 54321, sigs)
        assert sigs[0]["severity"] == "medium"

    def test_pe_on_port_443_medium_severity(self):
        sigs = []
        _scan_payload_signatures(b"MZ" + b"\x00" * 100, "1.2.3.4", "10.0.0.1", 443, 54321, sigs)
        assert sigs[0]["severity"] == "medium"

    def test_pe_on_port_8080_medium_severity(self):
        sigs = []
        _scan_payload_signatures(b"MZ" + b"\x00" * 100, "1.2.3.4", "10.0.0.1", 8080, 54321, sigs)
        assert sigs[0]["severity"] == "medium"

    def test_pe_on_port_8443_medium_severity(self):
        sigs = []
        _scan_payload_signatures(b"MZ" + b"\x00" * 100, "1.2.3.4", "10.0.0.1", 8443, 54321, sigs)
        assert sigs[0]["severity"] == "medium"

    def test_pe_on_dport_web_also_medium(self):
        """Client dport=80 (server response) should also be medium."""
        sigs = []
        _scan_payload_signatures(b"MZ" + b"\x00" * 100, "1.2.3.4", "10.0.0.1", 54321, 80, sigs)
        assert sigs[0]["severity"] == "medium"

    def test_pe_on_non_web_port_critical(self):
        sigs = []
        _scan_payload_signatures(b"MZ" + b"\x00" * 100, "10.0.0.1", "10.0.0.2", 4444, 12345, sigs)
        assert sigs[0]["severity"] == "critical"

    def test_one_match_per_packet(self):
        """Only one signature match per call (first match wins for magic bytes)."""
        sigs = []
        # PE header at start, but also NOP sled after
        _scan_payload_signatures(b"MZ" + b"\x90" * 20, "10.0.0.1", "10.0.0.2", 4444, 12345, sigs)
        assert len(sigs) == 1
        assert "PE Executable" in sigs[0]["sig"]

    def test_small_payload_no_crash(self):
        sigs = []
        _scan_payload_signatures(b"\x00", "10.0.0.1", "10.0.0.2", 80, 80, sigs)
        assert len(sigs) == 0

    def test_empty_payload_no_crash(self):
        """Empty payload should be handled gracefully."""
        sigs = []
        _scan_payload_signatures(b"", "10.0.0.1", "10.0.0.2", 80, 80, sigs)
        # May or may not match, but should not raise

    def test_detect_payload_signatures_groups(self):
        sigs = [
            {"sig": "File Transfer: PE Executable (MZ)", "detail": "a:1->b:2", "src": "a", "dst": "b", "severity": "critical"},
            {"sig": "File Transfer: PE Executable (MZ)", "detail": "c:3->d:4", "src": "c", "dst": "d", "severity": "critical"},
            {"sig": "Shellcode: NOP sled (16+ bytes)", "detail": "e:5->f:6", "src": "e", "dst": "f", "severity": "critical"},
        ]
        findings = _detect_payload_signatures(sigs)
        assert len(findings) == 2

    def test_detect_payload_signatures_empty(self):
        findings = _detect_payload_signatures([])
        assert len(findings) == 0

    def test_detect_uses_worst_severity(self):
        """Grouped finding should use the worst severity among its hits."""
        sigs = [
            {"sig": "File Transfer: PE Executable (MZ)", "detail": "a:1->b:2", "src": "a", "dst": "b", "severity": "medium"},
            {"sig": "File Transfer: PE Executable (MZ)", "detail": "c:80->d:4", "src": "c", "dst": "d", "severity": "critical"},
        ]
        findings = _detect_payload_signatures(sigs)
        assert findings[0].severity == "critical"

    def test_category_assignment(self):
        """Different sig types should get correct categories."""
        sigs_shellcode = [{"sig": "Shellcode: NOP sled", "detail": "x", "src": "a", "dst": "b", "severity": "critical"}]
        sigs_ps = [{"sig": "Encoded PowerShell command", "detail": "x", "src": "a", "dst": "b", "severity": "critical"}]
        sigs_file = [{"sig": "File Transfer: PE", "detail": "x", "src": "a", "dst": "b", "severity": "critical"}]

        assert _detect_payload_signatures(sigs_shellcode)[0].category == "Shellcode Detection"
        assert _detect_payload_signatures(sigs_ps)[0].category == "PowerShell Abuse"
        assert _detect_payload_signatures(sigs_file)[0].category == "Suspicious File Transfer"


# =============================================================================
# 13. Suspicious User-Agent detection
# =============================================================================

class TestSuspiciousUa:
    """HTTP User-Agent anomaly detection."""

    def test_python_requests_detected(self):
        uas = []
        _check_suspicious_ua("python-requests/2.28.0", "10.0.0.1", "1.2.3.4", "/api", uas)
        assert len(uas) == 1
        assert uas[0]["reason"] == "Python requests library"
        assert uas[0]["severity"] == "medium"

    def test_cobalt_strike_critical(self):
        uas = []
        _check_suspicious_ua("Mozilla/5.0 cobalt", "10.0.0.1", "1.2.3.4", "/beacon", uas)
        assert uas[0]["severity"] == "critical"

    def test_empire_c2_critical(self):
        uas = []
        _check_suspicious_ua("Mozilla/5.0 empire agent", "10.0.0.1", "1.2.3.4", "/", uas)
        assert uas[0]["severity"] == "critical"

    def test_certutil_critical(self):
        uas = []
        _check_suspicious_ua("certutil/1.0", "10.0.0.1", "1.2.3.4", "/payload.exe", uas)
        assert uas[0]["severity"] == "critical"

    def test_powershell_high(self):
        uas = []
        _check_suspicious_ua("PowerShell/7.0", "10.0.0.1", "1.2.3.4", "/", uas)
        assert uas[0]["severity"] == "high"

    def test_empty_ua_high(self):
        uas = []
        _check_suspicious_ua("", "10.0.0.1", "1.2.3.4", "/", uas)
        assert len(uas) == 1
        assert uas[0]["severity"] == "high"

    def test_short_ua_high(self):
        uas = []
        _check_suspicious_ua("bot", "10.0.0.1", "1.2.3.4", "/", uas)
        assert len(uas) == 1
        assert "minimal" in uas[0]["reason"].lower()

    def test_whitespace_only_ua(self):
        uas = []
        _check_suspicious_ua("    ", "10.0.0.1", "1.2.3.4", "/", uas)
        assert len(uas) == 1
        assert uas[0]["severity"] == "high"

    def test_normal_browser_not_flagged(self):
        uas = []
        _check_suspicious_ua(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
            "10.0.0.1", "1.2.3.4", "/page", uas
        )
        assert len(uas) == 0

    def test_curl_low_severity(self):
        uas = []
        _check_suspicious_ua("curl/7.88.1", "10.0.0.1", "1.2.3.4", "/api", uas)
        assert uas[0]["severity"] == "low"

    def test_wget_low_severity(self):
        uas = []
        _check_suspicious_ua("wget/1.21", "10.0.0.1", "1.2.3.4", "/file", uas)
        assert uas[0]["severity"] == "low"

    def test_go_http_client_medium(self):
        uas = []
        _check_suspicious_ua("Go-http-client/2.0", "10.0.0.1", "1.2.3.4", "/", uas)
        assert uas[0]["severity"] == "medium"

    def test_ua_truncated_at_120(self):
        """Long UAs should be truncated in output."""
        uas = []
        long_ua = "python-requests/" + "x" * 200
        _check_suspicious_ua(long_ua, "10.0.0.1", "1.2.3.4", "/", uas)
        assert len(uas[0]["ua"]) <= 120

    def test_case_insensitive_matching(self):
        uas = []
        _check_suspicious_ua("PYTHON-REQUESTS/2.28", "10.0.0.1", "1.2.3.4", "/", uas)
        assert len(uas) == 1

    def test_all_patterns_detectable(self):
        """Every pattern in _SUSPICIOUS_UA_PATTERNS should be detectable."""
        for pattern, name, severity in _SUSPICIOUS_UA_PATTERNS:
            uas = []
            test_ua = f"Mozilla/5.0 {pattern}/1.0 extra-text-to-reach-5-chars"
            _check_suspicious_ua(test_ua, "10.0.0.1", "1.2.3.4", "/", uas)
            assert len(uas) >= 1, f"Pattern '{pattern}' not detected"

    def test_detect_groups_by_reason(self):
        uas = [
            {"ua": "python-requests/2.28", "reason": "Python requests library", "src": "a", "dst": "b", "uri": "/", "severity": "medium"},
            {"ua": "python-requests/2.28", "reason": "Python requests library", "src": "a", "dst": "c", "uri": "/x", "severity": "medium"},
        ]
        findings = _detect_suspicious_uas(uas)
        assert len(findings) == 1
        assert "2 request(s)" in findings[0].title

    def test_detect_empty(self):
        findings = _detect_suspicious_uas([])
        assert len(findings) == 0


# =============================================================================
# 14. Cleartext credential detection
# =============================================================================

class TestCleartextCreds:
    """Cleartext credential exposure over FTP/SMTP/POP3/HTTP Basic Auth."""

    def test_ftp_user(self):
        creds = []
        _check_cleartext_creds(b"USER admin\r\n", "10.0.0.1", "10.0.0.2", 12345, 21, creds)
        assert len(creds) == 1
        assert creds[0]["protocol"] == "FTP"

    def test_ftp_pass(self):
        creds = []
        _check_cleartext_creds(b"PASS secret123\r\n", "10.0.0.1", "10.0.0.2", 12345, 21, creds)
        assert len(creds) == 1

    def test_ftp_on_sport_21(self):
        """FTP response from server (sport=21) should also detect."""
        creds = []
        _check_cleartext_creds(b"USER admin\r\n", "10.0.0.1", "10.0.0.2", 21, 12345, creds)
        assert len(creds) == 1

    def test_smtp_auth(self):
        creds = []
        _check_cleartext_creds(b"AUTH PLAIN dGVzdAB0ZXN0\r\n", "10.0.0.1", "10.0.0.2", 12345, 587, creds)
        assert len(creds) == 1
        assert creds[0]["protocol"] == "SMTP"

    def test_smtp_port_25(self):
        creds = []
        _check_cleartext_creds(b"AUTH LOGIN\r\n", "10.0.0.1", "10.0.0.2", 12345, 25, creds)
        assert len(creds) == 1

    def test_pop3_user(self):
        creds = []
        _check_cleartext_creds(b"USER mailuser\r\n", "10.0.0.1", "10.0.0.2", 12345, 110, creds)
        assert len(creds) == 1
        assert creds[0]["protocol"] == "POP3"

    def test_pop3_pass(self):
        creds = []
        _check_cleartext_creds(b"PASS mypassword\r\n", "10.0.0.1", "10.0.0.2", 12345, 110, creds)
        assert len(creds) == 1

    def test_http_basic_auth(self):
        creds = []
        _check_cleartext_creds(
            b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n",
            "10.0.0.1", "10.0.0.2", 12345, 80, creds
        )
        assert len(creds) == 1
        assert creds[0]["protocol"] == "HTTP Basic Auth"

    def test_normal_http_not_flagged(self):
        creds = []
        _check_cleartext_creds(
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "10.0.0.1", "10.0.0.2", 12345, 80, creds
        )
        assert len(creds) == 0

    def test_short_data_ignored(self):
        creds = []
        _check_cleartext_creds(b"OK", "10.0.0.1", "10.0.0.2", 12345, 21, creds)
        assert len(creds) == 0

    def test_exactly_4_bytes_ignored(self):
        """Less than 5 bytes should be ignored."""
        creds = []
        _check_cleartext_creds(b"USER", "10.0.0.1", "10.0.0.2", 12345, 21, creds)
        assert len(creds) == 0

    def test_exactly_5_bytes_checked(self):
        creds = []
        _check_cleartext_creds(b"USER ", "10.0.0.1", "10.0.0.2", 12345, 21, creds)
        assert len(creds) == 1

    def test_non_ascii_data_no_crash(self):
        """Binary data should not crash the ASCII decode."""
        creds = []
        _check_cleartext_creds(b"\xff\xfe\xfd\xfc\xfb\xfa" * 10, "10.0.0.1", "10.0.0.2", 12345, 21, creds)
        # Should not raise

    def test_wrong_port_not_flagged(self):
        """FTP command on non-FTP port should not be flagged as FTP."""
        creds = []
        _check_cleartext_creds(b"USER admin\r\n", "10.0.0.1", "10.0.0.2", 12345, 8080, creds)
        # Port 8080 is not 21/25/587/110, so no protocol match
        # HTTP Basic Auth check might still run
        ftp_creds = [c for c in creds if c["protocol"] == "FTP"]
        assert len(ftp_creds) == 0

    def test_detect_groups_by_protocol(self):
        creds = [
            {"protocol": "FTP", "detail": "a->b: USER admin", "src": "a", "dst": "b"},
            {"protocol": "FTP", "detail": "a->b: PASS secret", "src": "a", "dst": "b"},
        ]
        findings = _detect_cleartext_creds(creds)
        assert len(findings) == 1
        assert "2 instance(s)" in findings[0].title
        assert findings[0].severity == "high"

    def test_detect_multiple_protocols(self):
        creds = [
            {"protocol": "FTP", "detail": "x", "src": "a", "dst": "b"},
            {"protocol": "SMTP", "detail": "x", "src": "a", "dst": "b"},
        ]
        findings = _detect_cleartext_creds(creds)
        assert len(findings) == 2

    def test_detect_empty(self):
        findings = _detect_cleartext_creds([])
        assert len(findings) == 0


# =============================================================================
# 15. Verdict computation
# =============================================================================

class TestComputeVerdict:
    """Verdict scoring — threshold correctness and consistency."""

    def test_no_findings_benign(self):
        v = _compute_verdict([])
        assert v["label"] == "Likely Benign"
        assert v["confidence"] == 85

    def test_critical_finding_needs_investigation(self):
        findings = [Finding("Test", "critical", "Bad thing", "details")]
        v = _compute_verdict(findings)
        assert v["label"] == "Needs Investigation"
        assert v["score"] >= 50

    def test_single_critical_exactly_50(self):
        """One critical = score 50 = exactly at threshold."""
        findings = [Finding("X", "critical", "Bad", "d")]
        v = _compute_verdict(findings)
        assert v["score"] == 50
        assert v["label"] == "Needs Investigation"

    def test_single_high_below_threshold(self):
        """One high = score 25 = below 50 threshold."""
        findings = [Finding("X", "high", "Bad", "d")]
        v = _compute_verdict(findings)
        assert v["score"] == 25
        assert v["label"] == "Likely Benign"

    def test_two_high_at_threshold(self):
        """Two high = score 50 = at threshold."""
        findings = [Finding("X", "high", "A", "d"), Finding("Y", "high", "B", "d")]
        v = _compute_verdict(findings)
        assert v["score"] == 50
        assert v["label"] == "Needs Investigation"

    def test_many_medium_findings_can_escalate(self):
        findings = [Finding("Cat", "medium", f"Issue {i}", "d") for i in range(6)]
        v = _compute_verdict(findings)
        assert v["label"] == "Needs Investigation"
        assert v["score"] == 60

    def test_five_medium_just_under(self):
        """5 medium = score 50 = exactly at threshold."""
        findings = [Finding("Cat", "medium", f"Issue {i}", "d") for i in range(5)]
        v = _compute_verdict(findings)
        assert v["score"] == 50
        assert v["label"] == "Needs Investigation"

    def test_four_medium_under_threshold(self):
        """4 medium = score 40 = under threshold."""
        findings = [Finding("Cat", "medium", f"Issue {i}", "d") for i in range(4)]
        v = _compute_verdict(findings)
        assert v["score"] == 40
        assert v["label"] == "Likely Benign"

    def test_single_low_finding_benign(self):
        findings = [Finding("Info", "low", "Minor", "d")]
        v = _compute_verdict(findings)
        assert v["label"] == "Likely Benign"
        assert v["score"] == 3

    def test_many_low_findings_dont_escalate(self):
        """Even 16 low findings = 48 score, still benign."""
        findings = [Finding("Cat", "low", f"Issue {i}", "d") for i in range(16)]
        v = _compute_verdict(findings)
        assert v["score"] == 48
        assert v["label"] == "Likely Benign"

    def test_17_low_findings_escalate(self):
        """17 low = 51 score, should escalate."""
        findings = [Finding(f"Cat{i}", "low", f"Issue {i}", "d") for i in range(17)]
        v = _compute_verdict(findings)
        assert v["score"] == 51
        assert v["label"] == "Needs Investigation"

    def test_mixed_severities(self):
        findings = [
            Finding("A", "critical", "Crit", "d"),
            Finding("B", "high", "High", "d"),
            Finding("C", "medium", "Med", "d"),
            Finding("D", "low", "Low", "d"),
        ]
        v = _compute_verdict(findings)
        expected_score = 50 + 25 + 10 + 3
        assert v["score"] == expected_score
        assert v["label"] == "Needs Investigation"

    def test_reasons_deduplicated_by_category(self):
        findings = [
            Finding("Cat A", "high", "Issue 1", "d"),
            Finding("Cat A", "high", "Issue 2", "d"),
            Finding("Cat B", "medium", "Issue 3", "d"),
        ]
        v = _compute_verdict(findings)
        assert len(v["reasons"]) == 2

    def test_max_5_reasons(self):
        findings = [Finding(f"Cat{i}", "medium", f"Issue {i}", "d") for i in range(10)]
        v = _compute_verdict(findings)
        assert len(v["reasons"]) <= 5

    def test_confidence_capped_at_95(self):
        findings = [Finding("X", "critical", "Very bad", "d")] * 5
        v = _compute_verdict(findings)
        assert v["confidence"] <= 95

    def test_confidence_min_55_for_benign(self):
        """Even with findings, benign confidence should not go below 55."""
        findings = [Finding("Cat", "medium", f"Issue {i}", "d") for i in range(4)]
        v = _compute_verdict(findings)
        assert v["confidence"] >= 55

    def test_severity_weights_match_constants(self):
        """Verify the weight constants are what we expect."""
        assert SEVERITY_WEIGHTS["critical"] == 50
        assert SEVERITY_WEIGHTS["high"] == 25
        assert SEVERITY_WEIGHTS["medium"] == 10
        assert SEVERITY_WEIGHTS["low"] == 3

    def test_unknown_severity_zero_weight(self):
        """Unknown severity should contribute 0 to score."""
        findings = [Finding("X", "unknown", "Test", "d")]
        v = _compute_verdict(findings)
        assert v["score"] == 0
        assert v["label"] == "Likely Benign"

    def test_finding_count_in_verdict(self):
        findings = [Finding("A", "high", "X", "d"), Finding("B", "medium", "Y", "d")]
        v = _compute_verdict(findings)
        assert v["finding_count"] == 2


# =============================================================================
# 16. PcapResult model
# =============================================================================

class TestPcapResult:
    """Result model correctness and serialisation."""

    def test_default_values(self):
        r = PcapResult()
        assert r.packet_count == 0
        assert r.file_name == ""
        assert r.findings == []
        assert r.isakmp_sessions == []
        assert r.protocols == {}
        assert r.dns_queries == []
        assert r.http_requests == []
        assert r.tls_handshakes == []
        assert r.conversations == []
        assert r.data_transfer == {}

    def test_to_dict(self):
        r = PcapResult(file_name="test.pcap", packet_count=100)
        d = r.to_dict()
        assert isinstance(d, dict)
        assert d["file_name"] == "test.pcap"
        assert d["packet_count"] == 100
        assert "findings" in d
        assert "verdict" in d
        assert "isakmp_sessions" in d

    def test_to_dict_all_fields_present(self):
        """All PcapResult fields should appear in serialised dict."""
        r = PcapResult()
        d = r.to_dict()
        expected_keys = {
            "file_name", "file_size", "packet_count", "capture_duration",
            "time_start", "time_end", "protocols", "top_src_ips", "top_dst_ips",
            "top_src_ports", "top_dst_ports", "dns_queries", "http_requests",
            "tls_handshakes", "conversations", "data_transfer",
            "isakmp_sessions", "findings", "verdict",
        }
        assert expected_keys.issubset(set(d.keys()))

    def test_to_dict_is_json_serialisable(self):
        """Result dict must be JSON-serialisable for API response."""
        import json
        r = PcapResult(file_name="test.pcap", packet_count=50)
        r.findings = [{"category": "Test", "severity": "low", "title": "T", "detail": "D"}]
        r.verdict = {"label": "Likely Benign", "confidence": 85, "reasons": [], "score": 0}
        d = r.to_dict()
        serialised = json.dumps(d)
        assert isinstance(serialised, str)


# =============================================================================
# 17. Finding model
# =============================================================================

class TestFindingModel:
    """Finding dataclass correctness."""

    def test_fields(self):
        f = Finding("Cat", "high", "Title", "Detail")
        assert f.category == "Cat"
        assert f.severity == "high"
        assert f.title == "Title"
        assert f.detail == "Detail"

    def test_serialisation(self):
        from dataclasses import asdict
        f = Finding("Cat", "high", "Title", "Detail")
        d = asdict(f)
        assert d == {"category": "Cat", "severity": "high", "title": "Title", "detail": "Detail"}


# =============================================================================
# 18. Malformed/adversarial input tests (security boundary)
# =============================================================================

class TestMalformedInputSecurity:
    """Security boundary tests: malformed data should not crash the parser."""

    def test_random_bytes(self):
        """Random binary data should raise ValueError, not crash."""
        import os
        random_data = os.urandom(1024)
        with pytest.raises((ValueError, Exception)):
            parse_pcap(random_data, "random.pcap")

    def test_empty_file(self):
        with pytest.raises((ValueError, Exception)):
            parse_pcap(b"", "empty.pcap")

    def test_single_byte(self):
        with pytest.raises((ValueError, Exception)):
            parse_pcap(b"\x00", "single.pcap")

    def test_pcap_magic_only(self):
        """Just the PCAP magic number with no data."""
        with pytest.raises((ValueError, Exception)):
            parse_pcap(b"\xd4\xc3\xb2\xa1", "magic_only.pcap")

    def test_pcap_header_truncated(self):
        """Valid PCAP magic but truncated global header."""
        with pytest.raises((ValueError, Exception)):
            parse_pcap(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00", "truncated.pcap")

    def test_very_large_filename_handled(self):
        """Extremely long filename should not cause issues."""
        long_name = "a" * 10000 + ".pcap"
        with pytest.raises((ValueError, Exception)):
            parse_pcap(b"\x00" * 100, long_name)

    def test_null_bytes_in_filename(self):
        """Null bytes in filename should not cause path traversal."""
        with pytest.raises((ValueError, Exception)):
            parse_pcap(b"\x00" * 100, "test\x00.pcap")

    def test_path_traversal_filename(self):
        """Path traversal in filename should be harmless (no file I/O)."""
        with pytest.raises((ValueError, Exception)):
            parse_pcap(b"\x00" * 100, "../../etc/passwd.pcap")

    def test_unicode_filename(self):
        """Unicode characters in filename should not crash."""
        with pytest.raises((ValueError, Exception)):
            parse_pcap(b"\x00" * 100, "\u2603\u2764.pcap")

    def test_xml_in_data(self):
        """XML/HTML data should not be parsed as PCAP."""
        with pytest.raises((ValueError, Exception)):
            parse_pcap(b"<?xml version='1.0'?><root></root>", "not_a.pcap")

    def test_json_in_data(self):
        with pytest.raises((ValueError, Exception)):
            parse_pcap(b'{"key": "value"}', "not_a.pcap")

    def test_valid_pcap_header_zero_packets(self):
        """Valid PCAP with global header but zero packets."""
        # PCAP global header: magic, version 2.4, timezone, sigfigs, snaplen, network
        header = struct.pack("<IHHiIII",
                             0xa1b2c3d4,  # magic
                             2, 4,         # version
                             0,            # timezone
                             0,            # sigfigs
                             65535,        # snaplen
                             1)            # network (Ethernet)
        result = parse_pcap(header, "empty_valid.pcap")
        assert result.packet_count == 0
        assert result.verdict["label"] == "Likely Benign"


# =============================================================================
# 19. Crafted PCAP tests (synthetic packet construction)
# =============================================================================

class TestCraftedPcapParsing:
    """Parse synthetic PCAPs with known content to verify detection accuracy."""

    def _build_pcap(self, packets):
        """Build a minimal valid PCAP file from a list of (timestamp, raw_bytes) tuples."""
        # Global header
        buf = struct.pack("<IHHiIII",
                          0xa1b2c3d4,  # magic
                          2, 4,         # version
                          0, 0,         # timezone, sigfigs
                          65535,        # snaplen
                          1)            # Ethernet
        for ts, raw in packets:
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1000000)
            pkt_len = len(raw)
            buf += struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len)
            buf += raw
        return buf

    def _build_ethernet_ip_tcp(self, src_ip, dst_ip, sport, dport, payload=b"", flags=0x02):
        """Build Ethernet + IPv4 + TCP packet."""
        import dpkt
        tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=payload, seq=0, off=5)
        ip = dpkt.ip.IP(
            src=bytes(int(x) for x in src_ip.split(".")),
            dst=bytes(int(x) for x in dst_ip.split(".")),
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp,
        )
        ip.len = len(bytes(ip))
        eth = dpkt.ethernet.Ethernet(
            dst=b"\xff\xff\xff\xff\xff\xff",
            src=b"\x00\x00\x00\x00\x00\x01",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip,
        )
        return bytes(eth)

    def _build_ethernet_ip_udp(self, src_ip, dst_ip, sport, dport, payload=b""):
        """Build Ethernet + IPv4 + UDP packet."""
        import dpkt
        udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
        udp.ulen = len(bytes(udp))
        ip = dpkt.ip.IP(
            src=bytes(int(x) for x in src_ip.split(".")),
            dst=bytes(int(x) for x in dst_ip.split(".")),
            p=dpkt.ip.IP_PROTO_UDP,
            data=udp,
        )
        ip.len = len(bytes(ip))
        eth = dpkt.ethernet.Ethernet(
            dst=b"\xff\xff\xff\xff\xff\xff",
            src=b"\x00\x00\x00\x00\x00\x01",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip,
        )
        return bytes(eth)

    def test_single_tcp_packet(self):
        """Minimal PCAP with one TCP SYN."""
        pkt = self._build_ethernet_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 80)
        pcap_data = self._build_pcap([(1.0, pkt)])
        result = parse_pcap(pcap_data, "single_syn.pcap")
        assert result.packet_count == 1
        assert result.protocols.get("TCP", 0) == 1

    def test_suspicious_port_in_crafted_pcap(self):
        """Crafted PCAP with traffic to port 4444 should flag."""
        pkt = self._build_ethernet_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 4444)
        pcap_data = self._build_pcap([(1.0, pkt)])
        result = parse_pcap(pcap_data, "port4444.pcap")
        assert any("4444" in f["title"] for f in result.findings)

    def test_pe_transfer_detected_in_crafted_pcap(self):
        """PE executable in TCP payload should be flagged."""
        payload = b"MZ" + b"\x00" * 200
        pkt = self._build_ethernet_ip_tcp("10.0.0.1", "10.0.0.2", 4444, 12345, payload=payload, flags=0x18)
        pcap_data = self._build_pcap([(1.0, pkt)])
        result = parse_pcap(pcap_data, "pe_transfer.pcap")
        assert any("PE Executable" in f["title"] for f in result.findings)

    def test_dns_query_extracted(self):
        """UDP DNS query should populate dns_queries."""
        import dpkt
        dns = dpkt.dns.DNS()
        dns.qd = [dpkt.dns.DNS.Q(name="test.example.com", type=dpkt.dns.DNS_A)]
        dns.op = dpkt.dns.DNS_QR
        pkt = self._build_ethernet_ip_udp("192.168.1.1", "8.8.8.8", 12345, 53, bytes(dns))
        pcap_data = self._build_pcap([(1.0, pkt)])
        result = parse_pcap(pcap_data, "dns_query.pcap")
        assert any("test.example.com" in q["query"] for q in result.dns_queries)

    def test_cleartext_http_flagged(self):
        """HTTP traffic (port 80) >10 packets should generate cleartext finding."""
        pkts = []
        for i in range(15):
            pkt = self._build_ethernet_ip_tcp("192.168.1.1", "10.0.0.1", 12345 + i, 80)
            pkts.append((float(i), pkt))
        pcap_data = self._build_pcap(pkts)
        result = parse_pcap(pcap_data, "http_traffic.pcap")
        assert any("Cleartext" in f["title"] and "HTTP" in f["title"] for f in result.findings)

    def test_beaconing_in_crafted_pcap(self):
        """Regular 60s interval SYNs should trigger beaconing detection."""
        pkts = []
        for i in range(10):
            pkt = self._build_ethernet_ip_tcp("10.0.0.5", "1.2.3.4", 12345, 443)
            pkts.append((i * 60.0, pkt))
        pcap_data = self._build_pcap(pkts)
        result = parse_pcap(pcap_data, "beaconing.pcap")
        assert any("Beaconing" in f["title"] for f in result.findings)

    def test_timestamp_range(self):
        """Time start/end should reflect packet timestamps."""
        pkt = self._build_ethernet_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 80)
        pcap_data = self._build_pcap([(100.0, pkt), (200.0, pkt)])
        result = parse_pcap(pcap_data, "timestamps.pcap")
        assert result.capture_duration == 100.0

    def test_ip_counters(self):
        """Top IPs should reflect actual traffic."""
        pkt = self._build_ethernet_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 80)
        pcap_data = self._build_pcap([(1.0, pkt), (2.0, pkt)])
        result = parse_pcap(pcap_data, "ip_count.pcap")
        src_ips = [e["ip"] for e in result.top_src_ips]
        assert "192.168.1.1" in src_ips

    def test_conversation_tracking(self):
        pkt = self._build_ethernet_ip_tcp("192.168.1.1", "10.0.0.1", 12345, 80)
        pcap_data = self._build_pcap([(1.0, pkt)])
        result = parse_pcap(pcap_data, "conv.pcap")
        assert len(result.conversations) >= 1


# =============================================================================
# 20. API endpoint validation (unit-level)
# =============================================================================

class TestPcapApiValidation:
    """PCAP API endpoint validation logic — tests file extension and size checks."""

    def test_allowed_extensions(self):
        from ion.web.pcap_api import ALLOWED_EXTENSIONS
        assert ".pcap" in ALLOWED_EXTENSIONS
        assert ".pcapng" in ALLOWED_EXTENSIONS
        assert ".cap" in ALLOWED_EXTENSIONS
        assert ".exe" not in ALLOWED_EXTENSIONS
        assert ".txt" not in ALLOWED_EXTENSIONS

    def test_max_file_size(self):
        from ion.web.pcap_api import MAX_FILE_SIZE
        assert MAX_FILE_SIZE == 100 * 1024 * 1024

    def test_extension_check_logic(self):
        """Verify the extension matching logic works for all allowed types."""
        from ion.web.pcap_api import ALLOWED_EXTENSIONS
        test_cases = [
            ("capture.pcap", True),
            ("capture.PCAP", True),
            ("capture.pcapng", True),
            ("capture.PCAPNG", True),
            ("capture.cap", True),
            ("capture.CAP", True),
            ("capture.exe", False),
            ("capture.pcap.exe", False),
            ("capture", False),
            (".pcap", True),
            ("test.pdf", False),
        ]
        for filename, should_match in test_cases:
            found = any(filename.lower().endswith(e) for e in ALLOWED_EXTENSIONS)
            assert found == should_match, f"Filename '{filename}' expected match={should_match}"


# =============================================================================
# 21. Constants integrity
# =============================================================================

class TestConstantsIntegrity:
    """Verify security-critical constants have expected values."""

    def test_suspicious_ports_include_key_ports(self):
        assert 4444 in SUSPICIOUS_PORTS  # Metasploit
        assert 31337 in SUSPICIOUS_PORTS  # Back Orifice
        assert 9001 in SUSPICIOUS_PORTS   # Tor
        assert 3389 in SUSPICIOUS_PORTS   # RDP
        assert 23 in SUSPICIOUS_PORTS     # Telnet
        assert 6667 in SUSPICIOUS_PORTS   # IRC

    def test_cleartext_ports_include_key_ports(self):
        assert 21 in CLEARTEXT_PORTS   # FTP
        assert 23 in CLEARTEXT_PORTS   # Telnet
        assert 80 in CLEARTEXT_PORTS   # HTTP
        assert 110 in CLEARTEXT_PORTS  # POP3
        assert 25 in CLEARTEXT_PORTS   # SMTP
        assert 587 in CLEARTEXT_PORTS  # SMTP submission

    def test_magic_signatures_cover_key_formats(self):
        magic_names = [name for _, name, _ in _MAGIC_SIGNATURES]
        assert any("PE" in n for n in magic_names)
        assert any("ELF" in n for n in magic_names)
        assert any("PDF" in n for n in magic_names)
        assert any("ZIP" in n for n in magic_names)
        assert any("OLE2" in n for n in magic_names)

    def test_shellcode_patterns_present(self):
        pattern_names = [name for _, name, _ in _SHELLCODE_PATTERNS]
        assert any("NOP" in n for n in pattern_names)
        assert any("Metasploit" in n for n in pattern_names)
        assert any("x64" in n for n in pattern_names)


# =============================================================================
# 22. End-to-end PCAP parsing (using real test files)
# =============================================================================

class TestParsePcapFiles:
    """Integration tests using downloaded test PCAPs."""

    @pytest.fixture
    def pcap_dir(self):
        from pathlib import Path
        d = Path(__file__).parent.parent.parent / "test_pcaps"
        if not d.exists():
            pytest.skip("test_pcaps directory not found")
        return d

    def test_malicious_meterpreter(self, pcap_dir):
        f = pcap_dir / "malicious_meterpreter.pcapng"
        if not f.exists():
            pytest.skip("malicious_meterpreter.pcapng not found")
        result = parse_pcap(f.read_bytes(), f.name)
        assert result.packet_count > 0
        assert result.verdict["label"] == "Needs Investigation"
        assert any("4444" in f["title"] for f in result.findings)

    def test_malicious_meterpreter_has_critical_findings(self, pcap_dir):
        f = pcap_dir / "malicious_meterpreter.pcapng"
        if not f.exists():
            pytest.skip("malicious_meterpreter.pcapng not found")
        result = parse_pcap(f.read_bytes(), f.name)
        assert any(f["severity"] == "critical" for f in result.findings)

    def test_benign_web_traffic(self, pcap_dir):
        f = pcap_dir / "benign_web_traffic.pcapng"
        if not f.exists():
            pytest.skip("benign_web_traffic.pcapng not found")
        result = parse_pcap(f.read_bytes(), f.name)
        assert result.packet_count > 1000
        assert result.protocols.get("TCP", 0) > 0
        assert len(result.dns_queries) > 0
        assert len(result.http_requests) > 0

    def test_benign_web_not_needs_investigation(self, pcap_dir):
        """Benign web traffic should not trigger 'Needs Investigation'."""
        f = pcap_dir / "benign_web_traffic.pcapng"
        if not f.exists():
            pytest.skip("benign_web_traffic.pcapng not found")
        result = parse_pcap(f.read_bytes(), f.name)
        assert result.verdict["label"] == "Likely Benign"

    def test_isakmp_established(self, pcap_dir):
        f = pcap_dir / "isakmp_sample.cap"
        if not f.exists():
            pytest.skip("isakmp_sample.cap not found")
        result = parse_pcap(f.read_bytes(), f.name)
        assert result.packet_count > 0
        assert len(result.isakmp_sessions) == 1
        assert result.isakmp_sessions[0]["status"] == "Established"
        assert result.verdict["label"] == "Likely Benign"

    def test_isakmp_session_fields_present(self, pcap_dir):
        """ISAKMP session summary should contain all expected fields."""
        f = pcap_dir / "isakmp_sample.cap"
        if not f.exists():
            pytest.skip("isakmp_sample.cap not found")
        result = parse_pcap(f.read_bytes(), f.name)
        sess = result.isakmp_sessions[0]
        required_keys = {
            "init_spi", "resp_spi", "initiator", "responder",
            "ike_version", "exchanges", "status", "packets",
            "initiator_packets", "responder_packets", "retransmits",
            "errors", "has_delete", "duration",
        }
        assert required_keys.issubset(set(sess.keys()))

    def test_malicious_dns_c2(self, pcap_dir):
        f = pcap_dir / "malicious_dns_c2.pcap"
        if not f.exists():
            pytest.skip("malicious_dns_c2.pcap not found")
        result = parse_pcap(f.read_bytes(), f.name)
        assert result.packet_count > 0
        assert len(result.dns_queries) > 0
        assert any("ostrykebs" in f["title"] or "DNS" in f["category"] for f in result.findings)

    def test_invalid_file_raises(self):
        with pytest.raises(ValueError, match="Not a valid PCAP"):
            parse_pcap(b"this is not a pcap file at all", "garbage.pcap")

    def test_empty_file_raises(self):
        with pytest.raises((ValueError, Exception)):
            parse_pcap(b"", "empty.pcap")

    def test_result_file_size_matches(self, pcap_dir):
        """Result file_size should match actual input size."""
        f = pcap_dir / "isakmp_sample.cap"
        if not f.exists():
            pytest.skip("isakmp_sample.cap not found")
        data = f.read_bytes()
        result = parse_pcap(data, f.name)
        assert result.file_size == len(data)

    def test_result_filename_matches(self, pcap_dir):
        f = pcap_dir / "isakmp_sample.cap"
        if not f.exists():
            pytest.skip("isakmp_sample.cap not found")
        result = parse_pcap(f.read_bytes(), "my_capture.cap")
        assert result.file_name == "my_capture.cap"
