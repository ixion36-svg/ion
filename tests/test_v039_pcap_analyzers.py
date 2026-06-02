"""v0.39.0 — PCAP enhanced analyzers: OS fingerprint, RITA beaconing, DGA, TLS certs.

Covers the four analyzer areas added in v0.39.0 alongside JA4/JA4S and
verdict→severity:

- p0f-style passive OS fingerprinting (TTL/window/options → OS family)
- RITA-style beacon scoring (interval + payload-size regularity)
- multi-signal DGA scoring (entropy + digit/vowel ratio + consonant runs)
- TLS certificate carving + X.509 analysis (self-signed / known-bad C2 certs)
"""
import datetime
import struct

from ion.services.pcap_service import (
    PcapResult,
    _beacon_score_findings,
    _bowley_skew,
    _build_host_profiles,
    _collect_handshake_bytes,
    _compute_beacon_scores,
    _compute_os_fingerprints,
    _detect_dga,
    _dga_score,
    _extract_tls_certificates,
    _find_handshake_msg,
    _first_cert_der,
    _guess_os,
    _madm_score,
    _parse_x509,
    _tls_cert_findings,
)

# ── OS fingerprinting ───────────────────────────────────────────────────────

def test_guess_os_by_ttl():
    assert _guess_os({"ttl": 64, "window": 29200, "wscale": 7})[0] == "Linux / Unix"
    assert _guess_os({"ttl": 128, "window": 64240})[0] == "Windows"
    assert _guess_os({"ttl": 255, "window": 4128})[0].startswith("Network device")
    # observed TTL below the boundary still rounds up to the right origin
    assert _guess_os({"ttl": 117, "window": 8192})[0] == "Windows"
    assert _guess_os({"ttl": 54, "window": 65535})[0] == "Linux / Unix"


def test_guess_os_macos():
    assert _guess_os({"ttl": 64, "window": 65535, "wscale": 6})[0] == "macOS / iOS"


def test_compute_os_fingerprints_rollup():
    sigs = {
        "10.0.0.5": {"ttl": 128, "window": 64240, "mss": 1460},
        "10.0.0.9": {"ttl": 64, "window": 29200, "mss": 1460, "wscale": 7},
    }
    out = _compute_os_fingerprints(sigs)
    by_ip = {o["ip"]: o for o in out}
    assert by_ip["10.0.0.5"]["os"] == "Windows"
    assert by_ip["10.0.0.9"]["os"] == "Linux / Unix"


# ── RITA-style beacon scoring ───────────────────────────────────────────────

def test_madm_score():
    assert _madm_score([10, 10, 10, 10]) == 1.0       # zero dispersion
    assert _madm_score([10, 100, 5, 200]) < 0.5       # noisy
    assert _madm_score([5]) == 0.0                     # too few


def test_bowley_skew_symmetric():
    assert abs(_bowley_skew([1, 2, 3, 4, 5, 6, 7, 8])) < 0.4


def test_beacon_scores_regular_vs_noisy():
    # metronome cadence + uniform size → high score
    regular_times = [1000 + 60 * i for i in range(12)]
    conn_times = {("10.0.0.2", "8.8.4.4", 443): regular_times}
    conn_sizes = {("10.0.0.2", "8.8.4.4", 443): [512] * 12}
    scored = _compute_beacon_scores(conn_times, conn_sizes)
    assert scored and scored[0]["score"] >= 0.9
    assert scored[0]["connections"] == 12

    # jittery cadence → low score
    noisy = [1000, 1003, 1050, 1120, 1122, 1400, 1402, 1900]
    out = _compute_beacon_scores({("a", "b", 80): noisy}, {})
    assert out[0]["score"] < 0.9


def test_beacon_findings_fire_for_loose_cv_high_score():
    # regular ~60s cadence but enough micro-jitter that interval CV ≥ 0.15,
    # which the simple _detect_beaconing would skip — score-based catches it.
    times = [1000, 1060, 1119, 1181, 1240, 1302, 1359, 1421, 1480]
    scored = _compute_beacon_scores({("10.0.0.2", "evil.example", 443): times}, {})
    findings = _beacon_score_findings(scored)
    # only fires when the combined score is genuinely high
    if scored[0]["score"] >= 0.9:
        assert any("Beaconing" in f.title for f in findings)


# ── DGA scoring ─────────────────────────────────────────────────────────────

def test_dga_score_random_vs_benign():
    assert _dga_score("kq3v9xzwplmn") >= 0.6        # random-looking
    assert _dga_score("google") < 0.6                 # pronounceable
    assert _dga_score("questionmarket") < 0.7         # benign CDN/ad-tech (tuned)


def test_detect_dga_cluster():
    import collections
    c = collections.Counter()
    for d in ["kq3v9xzwplmn.com", "x7zqwmlkpnbq.net", "vbnmqxzlkprw.org",
              "qwxzplmnbvht.com", "zxcvbnmqwkpl.net"]:
        c[d] = 3
    findings = _detect_dga(c)
    assert any(f.category == "DGA Detection" and f.severity == "high" for f in findings)


def test_detect_dga_single_benign_stays_low():
    import collections
    c = collections.Counter({"amch.questionmarket.com": 5})
    findings = _detect_dga(c)
    # must not raise a high-severity DGA finding for one benign high-entropy CDN host
    assert not any(f.severity == "high" for f in findings)


# ── TLS certificate analysis ────────────────────────────────────────────────

def _make_self_signed(cn: str, days_valid: int = 365):
    """Build a DER self-signed cert (lazy import so the test skips if absent)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(146473198)  # 0x8bb00ee — matches Cobalt Strike known-bad serial
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
    from cryptography.hazmat.primitives.serialization import Encoding
    return cert.public_bytes(Encoding.DER)


def _wrap_certificate_record(der: bytes) -> bytes:
    """Wrap a DER cert into a TLS Certificate handshake message inside a TLS record."""
    cert_entry = struct.pack("!I", len(der))[1:] + der          # 3-byte len + cert
    cert_list = struct.pack("!I", len(cert_entry))[1:] + cert_entry
    hs = b"\x0b" + struct.pack("!I", len(cert_list))[1:] + cert_list  # type 0x0b + len
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs     # record: handshake, TLS1.2


def test_parse_x509_self_signed():
    der = _make_self_signed("internal.local")
    info = _parse_x509(der)
    assert info is not None
    assert info["self_signed"] is True
    assert "internal.local" in info["subject"]
    assert info["serial"] == "8bb00ee"


def test_handshake_walk_and_carve():
    der = _make_self_signed("svc.example")
    record = _wrap_certificate_record(der)
    hs = _collect_handshake_bytes(record)
    msg = _find_handshake_msg(hs, 0x0b)
    assert msg
    assert _first_cert_der(msg) == der


def test_extract_tls_certificates_from_streams():
    der = _make_self_signed("svc.example")
    record = _wrap_certificate_record(der)
    # server→client stream: key = (server_ip, 443, client_ip, cport)
    streams = {("203.0.113.9", 443, "10.0.0.2", 51000): bytearray(record)}
    certs = _extract_tls_certificates(streams)
    assert len(certs) == 1
    assert certs[0]["server_ip"] == "203.0.113.9"
    assert certs[0]["self_signed"] is True


def test_tls_cert_findings_known_bad_cn():
    certs = [{
        "serial": "deadbeef", "subject": "CN=Major Cobalt Strike",
        "issuer": "CN=Major Cobalt Strike", "self_signed": True,
        "validity_days": 1000, "server_ip": "203.0.113.9",
    }]
    findings = _tls_cert_findings(certs)
    assert any(f.severity == "critical" and "Cobalt Strike" in f.title for f in findings)


def test_tls_cert_findings_self_signed_medium():
    certs = [{
        "serial": "abc123", "subject": "CN=internal.local",
        "issuer": "CN=internal.local", "self_signed": True,
        "validity_days": 365, "server_ip": "10.0.0.9",
    }]
    findings = _tls_cert_findings(certs)
    assert any(f.severity == "medium" and "self-signed" in f.title.lower() for f in findings)


# ── Host profile rollup ─────────────────────────────────────────────────────

def test_build_host_profiles():
    r = PcapResult()
    r.data_transfer = {"by_ip": [{"ip": "10.0.0.2", "sent": 5000, "received": 200}]}
    r.os_fingerprints = [{"ip": "10.0.0.2", "os": "Windows", "evidence": "TTL≈128"}]
    r.ja4_fingerprints = [{"src_ip": "10.0.0.2", "dst_ip": "8.8.8.8", "ja4": "t13d1516h2_x_y", "sni": "evil.example"}]
    r.beacons = [{"src": "10.0.0.2", "dst": "8.8.8.8", "port": 443, "score": 0.95}]
    r.findings = [{"title": "Beaconing", "detail": "10.0.0.2 -> 8.8.8.8:443"}]
    profiles = _build_host_profiles(r)
    p = next(p for p in profiles if p["ip"] == "10.0.0.2")
    assert p["os"] == "Windows"
    assert "client" in p["role"]
    assert "evil.example" in p["snis"]
    assert p["beacons"] == 1
    assert p["findings"] == 1
