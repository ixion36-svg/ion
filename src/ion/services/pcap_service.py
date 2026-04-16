"""PCAP file parser and network traffic analyzer."""

import hashlib
import io
import math
import re
import socket
import struct
import collections
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, Any

import dpkt


@dataclass
class Finding:
    category: str
    severity: str  # low, medium, high, critical
    title: str
    detail: str


@dataclass
class ExtractedFile:
    """A file carved from a TCP stream."""
    filename: str
    mime_type: str
    size: int
    md5: str
    sha256: str
    src_ip: str = ""
    dst_ip: str = ""
    stream_index: int = 0

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class JA3Fingerprint:
    """A TLS ClientHello fingerprint."""
    ja3_hash: str
    ja3_str: str
    src_ip: str
    dst_ip: str
    dst_port: int
    sni: str = ""
    known_malware: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class JA3SFingerprint:
    """A TLS ServerHello fingerprint (JA3S)."""
    ja3s_hash: str
    ja3s_str: str
    src_ip: str
    dst_ip: str
    src_port: int
    known_malware: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class HASSHFingerprint:
    """An SSH client/server fingerprint (HASSH)."""
    hassh_hash: str
    hassh_str: str
    src_ip: str
    dst_ip: str
    direction: str = "client"  # "client" or "server"
    ssh_version: str = ""
    known_malware: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class SMBTransfer:
    """An SMB file operation detected in the capture."""
    src_ip: str
    dst_ip: str
    command: str  # e.g. "SMB2_CREATE", "SMB2_WRITE", "SMB1_TRANS2"
    filename: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class KerberosTicket:
    """A Kerberos ticket extracted from traffic."""
    msg_type: str  # AS-REQ, AS-REP, TGS-REQ, TGS-REP
    src_ip: str
    dst_ip: str
    realm: str = ""
    principal: str = ""
    cipher: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class CredentialCapture:
    """An extracted credential or auth hash from cleartext/NTLM/HTTP."""
    protocol: str  # http_basic, http_digest, ntlm, ftp, smtp, pop3, imap
    username: str
    credential: str  # password or hash
    src_ip: str = ""
    dst_ip: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class PcapResult:
    file_name: str = ""
    file_size: int = 0
    packet_count: int = 0
    capture_duration: float = 0.0
    time_start: str = ""
    time_end: str = ""
    protocols: dict = field(default_factory=dict)
    top_src_ips: list = field(default_factory=list)
    top_dst_ips: list = field(default_factory=list)
    top_src_ports: list = field(default_factory=list)
    top_dst_ports: list = field(default_factory=list)
    dns_queries: list = field(default_factory=list)
    http_requests: list = field(default_factory=list)
    tls_handshakes: list = field(default_factory=list)
    conversations: list = field(default_factory=list)
    data_transfer: dict = field(default_factory=dict)
    isakmp_sessions: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    verdict: dict = field(default_factory=dict)
    # Enhanced analyzers
    extracted_files: list = field(default_factory=list)
    ja3_fingerprints: list = field(default_factory=list)
    ja3s_fingerprints: list = field(default_factory=list)
    hassh_fingerprints: list = field(default_factory=list)
    credential_captures: list = field(default_factory=list)
    smb_transfers: list = field(default_factory=list)
    kerberos_tickets: list = field(default_factory=list)
    http_files: list = field(default_factory=list)
    arp_anomalies: list = field(default_factory=list)
    base64_payloads: list = field(default_factory=list)
    network_graph: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# Ports commonly associated with malicious activity
SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    5555: "Common RAT",
    1234: "Common backdoor",
    31337: "Back Orifice / elite",
    8888: "Common C2",
    6666: "IRC / backdoor",
    6667: "IRC",
    6697: "IRC over TLS",
    9001: "Tor ORPort",
    9050: "Tor SOCKS",
    9150: "Tor Browser SOCKS",
    3333: "Mining pool",
    14444: "Mining pool (Monero)",
    3389: "RDP (external exposure risk)",
    23: "Telnet (cleartext)",
    21: "FTP (cleartext)",
}

CLEARTEXT_PORTS = {21, 23, 80, 110, 143, 161, 25, 587}


def parse_pcap(file_bytes: bytes, filename: str) -> PcapResult:
    """Parse a PCAP/PCAPNG file and return analysis results."""
    buf = io.BytesIO(file_bytes)

    pcap_reader_cls = dpkt.pcap.Reader
    try:
        reader = dpkt.pcap.Reader(buf)
    except (ValueError, dpkt.UnpackError):
        buf.seek(0)
        pcap_reader_cls = dpkt.pcapng.Reader
        try:
            reader = dpkt.pcapng.Reader(buf)
        except Exception as e:
            raise ValueError(f"Not a valid PCAP or PCAPNG file: {e}")

    # Counters
    proto_counter = collections.Counter()
    src_ip_counter = collections.Counter()
    dst_ip_counter = collections.Counter()
    src_port_counter = collections.Counter()
    dst_port_counter = collections.Counter()
    dns_counter = collections.Counter()
    http_counter = collections.Counter()
    tls_sni_counter = collections.Counter()
    conv_bytes = collections.Counter()  # (src, dst) -> bytes
    ip_sent = collections.Counter()
    ip_recv = collections.Counter()
    conn_times: dict[tuple, list] = {}  # (src, dst, port) -> [timestamps]
    isakmp_sessions: dict[bytes, dict] = {}  # initiator_spi -> session info
    payload_sigs: list[dict] = []  # malware signature hits
    suspicious_uas: list[dict] = []  # suspicious HTTP User-Agents
    cleartext_creds: list[dict] = []  # cleartext credential leaks

    timestamps = []
    packet_count = 0
    arp_table: dict[str, set[str]] = {}  # MAC → set of IPs (for ARP spoofing detection)

    for ts, raw in reader:
        packet_count += 1
        timestamps.append(ts)

        # ARP detection (link layer, before IP extraction)
        try:
            eth = dpkt.ethernet.Ethernet(raw)
            if eth.type == dpkt.ethernet.ETH_TYPE_ARP and isinstance(eth.data, dpkt.arp.ARP):
                arp = eth.data
                if arp.op in (1, 2):  # REQUEST or REPLY
                    sender_mac = ":".join(f"{b:02x}" for b in arp.sha)
                    sender_ip = socket.inet_ntoa(arp.spa)
                    arp_table.setdefault(sender_mac, set()).add(sender_ip)
        except Exception:
            pass

        ip_pkt = _extract_ip(raw)
        if ip_pkt is None:
            proto_counter["Other"] += 1
            continue

        src_ip = _ip_to_str(ip_pkt.src)
        dst_ip = _ip_to_str(ip_pkt.dst)
        pkt_len = len(raw)

        src_ip_counter[src_ip] += 1
        dst_ip_counter[dst_ip] += 1
        ip_sent[src_ip] += pkt_len
        ip_recv[dst_ip] += pkt_len

        conv_key = tuple(sorted([src_ip, dst_ip]))
        conv_bytes[conv_key] += pkt_len

        if isinstance(ip_pkt.data, dpkt.tcp.TCP):
            tcp = ip_pkt.data
            proto_counter["TCP"] += 1
            src_port_counter[tcp.sport] += 1
            dst_port_counter[tcp.dport] += 1

            # Track connection times for beaconing detection
            if tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):
                key = (src_ip, dst_ip, tcp.dport)
                conn_times.setdefault(key, []).append(ts)

            _parse_tcp_payload(tcp, src_ip, dst_ip, dns_counter, http_counter,
                               tls_sni_counter, payload_sigs, suspicious_uas, cleartext_creds)

        elif isinstance(ip_pkt.data, dpkt.udp.UDP):
            udp = ip_pkt.data
            proto_counter["UDP"] += 1
            src_port_counter[udp.sport] += 1
            dst_port_counter[udp.dport] += 1

            if udp.sport == 53 or udp.dport == 53:
                _parse_dns(udp.data, dns_counter)

            # ISAKMP/IKE on UDP 500 or NAT-T on UDP 4500
            if udp.dport in (500, 4500) or udp.sport in (500, 4500):
                _parse_isakmp(bytes(udp.data), src_ip, dst_ip, udp.sport, udp.dport,
                              ts, isakmp_sessions, proto_counter)

        elif isinstance(ip_pkt.data, dpkt.icmp.ICMP):
            proto_counter["ICMP"] += 1
        else:
            proto_counter["Other"] += 1

    # Build result
    result = PcapResult(
        file_name=filename,
        file_size=len(file_bytes),
        packet_count=packet_count,
    )

    if timestamps:
        t_start = min(timestamps)
        t_end = max(timestamps)
        result.time_start = datetime.fromtimestamp(t_start, tz=timezone.utc).isoformat()
        result.time_end = datetime.fromtimestamp(t_end, tz=timezone.utc).isoformat()
        result.capture_duration = round(t_end - t_start, 2)

    result.protocols = dict(proto_counter.most_common())
    result.top_src_ips = [{"ip": ip, "count": c} for ip, c in src_ip_counter.most_common(20)]
    result.top_dst_ips = [{"ip": ip, "count": c} for ip, c in dst_ip_counter.most_common(20)]
    result.top_src_ports = [{"port": p, "count": c} for p, c in src_port_counter.most_common(20)]
    result.top_dst_ports = [{"port": p, "count": c} for p, c in dst_port_counter.most_common(20)]

    result.dns_queries = [
        {"query": q, "count": c} for q, c in dns_counter.most_common(50)
    ]
    result.http_requests = [
        {"request": r, "count": c} for r, c in http_counter.most_common(50)
    ]
    result.tls_handshakes = [
        {"sni": s, "count": c} for s, c in tls_sni_counter.most_common(50)
    ]
    result.conversations = [
        {"pair": f"{k[0]} <-> {k[1]}", "bytes": v}
        for k, v in conv_bytes.most_common(20)
    ]

    total_bytes = sum(ip_sent.values())
    top_talkers = sorted(
        set(list(ip_sent.keys()) + list(ip_recv.keys())),
        key=lambda ip: ip_sent[ip] + ip_recv[ip],
        reverse=True,
    )[:20]
    result.data_transfer = {
        "total_bytes": total_bytes,
        "by_ip": [
            {"ip": ip, "sent": ip_sent[ip], "received": ip_recv[ip]}
            for ip in top_talkers
        ],
    }

    # Summarise ISAKMP sessions for the results
    result.isakmp_sessions = _summarise_isakmp(isakmp_sessions)

    # ARP spoofing detection: a MAC claiming multiple IPs
    for mac, ips in arp_table.items():
        if len(ips) > 1:
            result.arp_anomalies.append({
                "mac": mac,
                "ips": sorted(ips),
                "severity": "high" if len(ips) > 2 else "medium",
                "detail": f"MAC {mac} is claiming {len(ips)} different IPs — possible ARP spoofing",
            })

    # ── Enhanced analyzers ──
    try:
        buf.seek(0)
        streams, tls_hellos, tls_server_hellos, ssh_pkts = _reassemble_tcp_streams(buf, pcap_reader_cls)
        result.extracted_files = [f.to_dict() for f in _extract_files_from_streams(streams)]
        result.ja3_fingerprints = [j.to_dict() for j in _compute_ja3(tls_hellos)]
        result.ja3s_fingerprints = [j.to_dict() for j in _compute_ja3s(tls_server_hellos)]
        result.hassh_fingerprints = [h.to_dict() for h in _compute_hassh(ssh_pkts)]
        result.credential_captures = [c.to_dict() for c in _extract_credentials(streams)]
        result.smb_transfers = [s.to_dict() for s in _detect_smb(streams)]
        result.kerberos_tickets = _detect_kerberos(streams)
        result.http_files = _extract_http_files(streams)
        result.base64_payloads = _detect_base64_payloads(streams)
    except Exception:
        pass  # Non-fatal

    # Build network graph from conversations
    try:
        result.network_graph = _build_network_graph(result)
    except Exception:
        result.network_graph = {"nodes": [], "edges": []}

    # Run heuristic analysis
    findings = _analyze(
        result, conn_times, dns_counter, src_ip_counter, dst_ip_counter,
        src_port_counter, dst_port_counter, ip_sent, ip_recv, proto_counter,
        isakmp_sessions, payload_sigs, suspicious_uas, cleartext_creds,
    )

    # Add findings from enhanced analyzers
    if result.extracted_files:
        findings.append(Finding(
            category="file_extraction",
            severity="medium",
            title=f"{len(result.extracted_files)} file(s) extracted from traffic",
            detail=", ".join(f.get("filename", "?") for f in result.extracted_files[:5]),
        ))
    if any(j.get("known_malware") for j in result.ja3_fingerprints):
        bad = [j for j in result.ja3_fingerprints if j.get("known_malware")]
        findings.append(Finding(
            category="tls_fingerprint",
            severity="high",
            title=f"{len(bad)} known-malware JA3 fingerprint(s) detected",
            detail=", ".join(f'{j["ja3_hash"][:12]}... ({j["known_malware"]})' for j in bad[:3]),
        ))
    if result.credential_captures:
        findings.append(Finding(
            category="credential_capture",
            severity="critical",
            title=f"{len(result.credential_captures)} credential(s) captured from traffic",
            detail=", ".join(f'{c.get("protocol")}:{c.get("username","")}' for c in result.credential_captures[:5]),
        ))

    result.findings = [asdict(f) for f in findings]
    result.verdict = _compute_verdict(findings)

    return result


# ---------------------------------------------------------------------------
# TCP stream reassembly (shared by file extraction + credential extraction)
# ---------------------------------------------------------------------------

def _reassemble_tcp_streams(buf: io.BytesIO, reader_cls):
    """Two-pass: reassemble TCP streams and collect TLS + SSH handshakes."""
    streams: dict[tuple, bytearray] = {}
    tls_hellos: list[dict] = []      # ClientHello (type 0x01)
    tls_server_hellos: list[dict] = []  # ServerHello (type 0x02)
    ssh_packets: list[dict] = []     # SSH KEX_INIT messages

    try:
        reader = reader_cls(buf)
    except Exception:
        return streams, tls_hellos, tls_server_hellos, ssh_packets

    for ts, raw in reader:
        ip = _extract_ip(raw)
        if ip is None:
            continue
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue
        tcp = ip.data
        if not tcp.data:
            continue

        try:
            src_ip = socket.inet_ntoa(ip.src) if len(ip.src) == 4 else socket.inet_ntop(socket.AF_INET6, ip.src)
            dst_ip = socket.inet_ntoa(ip.dst) if len(ip.dst) == 4 else socket.inet_ntop(socket.AF_INET6, ip.dst)
        except Exception:
            continue

        key = (src_ip, tcp.sport, dst_ip, tcp.dport)
        if key not in streams:
            streams[key] = bytearray()
        if len(streams[key]) < 10 * 1024 * 1024:
            streams[key].extend(tcp.data)

        data = bytes(tcp.data)

        # TLS handshakes (content type 0x16)
        if len(data) > 5 and data[0] == 0x16:
            hs_type = data[5]
            if hs_type == 0x01:  # ClientHello
                tls_hellos.append({
                    "src_ip": src_ip, "dst_ip": dst_ip,
                    "src_port": tcp.sport, "dst_port": tcp.dport,
                    "data": data,
                })
            elif hs_type == 0x02:  # ServerHello
                tls_server_hellos.append({
                    "src_ip": src_ip, "dst_ip": dst_ip,
                    "src_port": tcp.sport, "dst_port": tcp.dport,
                    "data": data,
                })

        # SSH KEX_INIT (SSH-2.0 protocol, message code 20 = SSH_MSG_KEXINIT)
        if (tcp.sport == 22 or tcp.dport == 22) and len(data) > 6:
            # SSH binary packet: packet_length(4) + padding_length(1) + msg_type(1)
            # Also capture SSH version banner ("SSH-2.0-...")
            if data[:4] == b"SSH-":
                ssh_packets.append({
                    "src_ip": src_ip, "dst_ip": dst_ip,
                    "src_port": tcp.sport, "dst_port": tcp.dport,
                    "type": "banner",
                    "data": data,
                })
            elif len(data) > 5:
                try:
                    pkt_len = struct.unpack("!I", data[:4])[0]
                    if 4 < pkt_len < len(data) and data[5] == 20:  # SSH_MSG_KEXINIT
                        ssh_packets.append({
                            "src_ip": src_ip, "dst_ip": dst_ip,
                            "src_port": tcp.sport, "dst_port": tcp.dport,
                            "type": "kexinit",
                            "data": data,
                        })
                except Exception:
                    pass

    return streams, tls_hellos, tls_server_hellos, ssh_packets


# ---------------------------------------------------------------------------
# 1. File extraction from TCP streams
# ---------------------------------------------------------------------------

# Magic bytes → (extension, MIME type)
_FILE_SIGNATURES = [
    (b'\x50\x4b\x03\x04', "zip", "application/zip"),
    (b'\x50\x4b\x05\x06', "zip", "application/zip"),
    (b'\x25\x50\x44\x46', "pdf", "application/pdf"),
    (b'\xd0\xcf\x11\xe0', "doc", "application/msword"),
    (b'\x50\x4b\x03\x04\x14\x00\x06\x00', "docx", "application/vnd.openxmlformats"),
    (b'\x4d\x5a', "exe", "application/x-dosexec"),
    (b'\x7f\x45\x4c\x46', "elf", "application/x-elf"),
    (b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a', "png", "image/png"),
    (b'\xff\xd8\xff', "jpg", "image/jpeg"),
    (b'\x47\x49\x46\x38', "gif", "image/gif"),
    (b'\x52\x61\x72\x21', "rar", "application/x-rar"),
    (b'\x1f\x8b\x08', "gz", "application/gzip"),
    (b'\x42\x5a\x68', "bz2", "application/x-bzip2"),
    (b'\xca\xfe\xba\xbe', "class", "application/java"),
    (b'\x23\x21', "script", "text/x-script"),
]


def _extract_files_from_streams(streams: dict) -> list[ExtractedFile]:
    """Scan reassembled TCP streams for file signatures and carve them out."""
    extracted: list[ExtractedFile] = []
    seen_hashes: set[str] = set()

    for (src_ip, sport, dst_ip, dport), payload in streams.items():
        if len(payload) < 8:
            continue
        data = bytes(payload)

        for magic, ext, mime in _FILE_SIGNATURES:
            offset = 0
            while True:
                pos = data.find(magic, offset)
                if pos == -1 or pos > len(data) - 16:
                    break
                # Carve: take up to 5 MB from the signature start
                carved = data[pos:pos + 5 * 1024 * 1024]
                if len(carved) < 32:
                    offset = pos + 1
                    continue

                md5 = hashlib.md5(carved).hexdigest()
                if md5 in seen_hashes:
                    offset = pos + len(magic)
                    continue
                seen_hashes.add(md5)

                sha256 = hashlib.sha256(carved).hexdigest()
                extracted.append(ExtractedFile(
                    filename=f"extracted_{len(extracted)+1}.{ext}",
                    mime_type=mime,
                    size=len(carved),
                    md5=md5,
                    sha256=sha256,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    stream_index=len(extracted),
                ))
                offset = pos + len(magic)
                if len(extracted) >= 50:  # Cap
                    break
            if len(extracted) >= 50:
                break
        if len(extracted) >= 50:
            break

    return extracted


# ---------------------------------------------------------------------------
# 2. JA3 TLS fingerprinting
# ---------------------------------------------------------------------------

# Known malware JA3 hashes (curated subset — extend as needed)
_KNOWN_BAD_JA3: dict[str, str] = {
    "51c64c77e60f3980eea90869b68c58a8": "Cobalt Strike",
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike (4.x)",
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike (HTTPS)",
    "7dd50e112cd23734a310b90f6f44a7cd": "Metasploit Meterpreter",
    "e7d705a3286e19ea42f587b344ee6865": "Emotet",
    "4d7a28d6f2263ed61de88ca66eb2e89a": "TrickBot",
    "6734f37431670b3ab4292b8f60f29984": "Dridex",
    "3b5074b1b5d032e5620f69f9f700ff0e": "Tofsee",
    "36f7277af969a6947a61ae0b815907a1": "IcedID",
    "19e29534fd49dd27d09234e639c4057e": "QakBot",
    "c12f54a3f91dc7bafd92b15ef9a5b6b9": "AsyncRAT",
    "e35df3e00ca4ef31d42b34bebaa2f86e": "SocGholish",
}


def _compute_ja3(tls_hellos: list[dict]) -> list[JA3Fingerprint]:
    """Compute JA3 fingerprints from collected TLS ClientHello messages."""
    fingerprints: list[JA3Fingerprint] = []
    seen: set[str] = set()

    for hello in tls_hellos:
        data = hello["data"]
        try:
            ja3_str, ja3_hash = _parse_client_hello_ja3(data)
        except Exception:
            continue

        if not ja3_hash:
            continue
        dedup_key = f'{hello["src_ip"]}:{hello["dst_ip"]}:{ja3_hash}'
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        # Try to extract SNI
        sni = ""
        try:
            sni = _extract_tls_sni(data) or ""
        except Exception:
            pass

        fingerprints.append(JA3Fingerprint(
            ja3_hash=ja3_hash,
            ja3_str=ja3_str,
            src_ip=hello["src_ip"],
            dst_ip=hello["dst_ip"],
            dst_port=hello["dst_port"],
            sni=sni,
            known_malware=_KNOWN_BAD_JA3.get(ja3_hash, ""),
        ))

    return fingerprints


def _parse_client_hello_ja3(data: bytes) -> tuple[str, str]:
    """Parse a TLS ClientHello and compute the JA3 fingerprint.

    JA3 = md5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
    """
    if len(data) < 44:
        return "", ""

    # TLS record: type(1) + version(2) + length(2) + handshake
    # Handshake: type(1) + length(3) + client_version(2) + random(32) + ...
    content_type = data[0]
    if content_type != 0x16:  # Handshake
        return "", ""

    handshake_type = data[5]
    if handshake_type != 0x01:  # ClientHello
        return "", ""

    # Client version at offset 9-10
    tls_version = struct.unpack("!H", data[9:11])[0]

    # Skip random (32 bytes) starting at offset 11
    offset = 43  # 11 + 32

    # Session ID
    if offset >= len(data):
        return "", ""
    session_id_len = data[offset]
    offset += 1 + session_id_len

    # Cipher suites
    if offset + 2 > len(data):
        return "", ""
    cipher_len = struct.unpack("!H", data[offset:offset+2])[0]
    offset += 2
    ciphers = []
    for i in range(0, cipher_len, 2):
        if offset + i + 2 > len(data):
            break
        c = struct.unpack("!H", data[offset+i:offset+i+2])[0]
        # Skip GREASE values
        if (c & 0x0f0f) == 0x0a0a:
            continue
        ciphers.append(str(c))
    offset += cipher_len

    # Compression methods
    if offset >= len(data):
        return "", ""
    comp_len = data[offset]
    offset += 1 + comp_len

    # Extensions
    extensions = []
    elliptic_curves = []
    ec_point_formats = []

    if offset + 2 <= len(data):
        ext_total_len = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2
        ext_end = offset + ext_total_len

        while offset + 4 <= ext_end and offset + 4 <= len(data):
            ext_type = struct.unpack("!H", data[offset:offset+2])[0]
            ext_len = struct.unpack("!H", data[offset+2:offset+4])[0]
            offset += 4

            # Skip GREASE
            if (ext_type & 0x0f0f) == 0x0a0a:
                offset += ext_len
                continue

            extensions.append(str(ext_type))

            ext_data = data[offset:offset+ext_len]

            # Supported Groups (0x000a)
            if ext_type == 0x000a and len(ext_data) >= 2:
                groups_len = struct.unpack("!H", ext_data[0:2])[0]
                for i in range(2, min(2 + groups_len, len(ext_data)), 2):
                    if i + 2 > len(ext_data):
                        break
                    g = struct.unpack("!H", ext_data[i:i+2])[0]
                    if (g & 0x0f0f) != 0x0a0a:
                        elliptic_curves.append(str(g))

            # EC Point Formats (0x000b)
            elif ext_type == 0x000b and len(ext_data) >= 1:
                fmt_len = ext_data[0]
                for i in range(1, min(1 + fmt_len, len(ext_data))):
                    ec_point_formats.append(str(ext_data[i]))

            offset += ext_len

    ja3_str = ",".join([
        str(tls_version),
        "-".join(ciphers),
        "-".join(extensions),
        "-".join(elliptic_curves),
        "-".join(ec_point_formats),
    ])
    ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()

    return ja3_str, ja3_hash


# ---------------------------------------------------------------------------
# 3. Credential extraction from TCP streams
# ---------------------------------------------------------------------------

def _extract_credentials(streams: dict) -> list[CredentialCapture]:
    """Scan reassembled TCP streams for credentials and auth hashes."""
    creds: list[CredentialCapture] = []
    seen: set[str] = set()

    for (src_ip, sport, dst_ip, dport), payload in streams.items():
        data = bytes(payload[:50000])  # Only scan first 50KB of each stream
        text = ""
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            continue

        # HTTP Basic Auth (Authorization: Basic base64)
        for m in re.finditer(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', text, re.IGNORECASE):
            try:
                import base64
                decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
                if ":" in decoded:
                    user, pwd = decoded.split(":", 1)
                    key = f"basic:{user}:{dst_ip}"
                    if key not in seen:
                        seen.add(key)
                        creds.append(CredentialCapture(
                            protocol="http_basic", username=user, credential=pwd,
                            src_ip=src_ip, dst_ip=dst_ip,
                            detail=f"HTTP Basic auth to {dst_ip}:{dport}",
                        ))
            except Exception:
                pass

        # HTTP Digest Auth
        for m in re.finditer(r'Authorization:\s*Digest\s+(.+?)(?:\r?\n)', text, re.IGNORECASE):
            digest_str = m.group(1)
            user_m = re.search(r'username="([^"]+)"', digest_str)
            if user_m:
                key = f"digest:{user_m.group(1)}:{dst_ip}"
                if key not in seen:
                    seen.add(key)
                    creds.append(CredentialCapture(
                        protocol="http_digest", username=user_m.group(1),
                        credential=digest_str[:200],
                        src_ip=src_ip, dst_ip=dst_ip,
                        detail=f"HTTP Digest auth to {dst_ip}:{dport}",
                    ))

        # NTLM challenge/response (Type 3 message in HTTP)
        for m in re.finditer(r'Authorization:\s*(?:NTLM|Negotiate)\s+([A-Za-z0-9+/=]+)', text, re.IGNORECASE):
            try:
                import base64
                ntlm_bytes = base64.b64decode(m.group(1))
                if len(ntlm_bytes) > 8 and ntlm_bytes[0:7] == b'NTLMSSP':
                    msg_type = struct.unpack("<I", ntlm_bytes[8:12])[0]
                    if msg_type == 3:  # Type 3 = authenticate
                        key = f"ntlm:{src_ip}:{dst_ip}"
                        if key not in seen:
                            seen.add(key)
                            creds.append(CredentialCapture(
                                protocol="ntlm", username="(see hash)",
                                credential=m.group(1)[:100] + "...",
                                src_ip=src_ip, dst_ip=dst_ip,
                                detail=f"NTLM Type 3 (authenticate) to {dst_ip}:{dport}",
                            ))
            except Exception:
                pass

        # FTP USER/PASS
        for m in re.finditer(r'USER\s+(\S+)\r?\n.*?PASS\s+(\S+)', text, re.IGNORECASE | re.DOTALL):
            key = f"ftp:{m.group(1)}:{dst_ip}"
            if key not in seen:
                seen.add(key)
                creds.append(CredentialCapture(
                    protocol="ftp", username=m.group(1), credential=m.group(2),
                    src_ip=src_ip, dst_ip=dst_ip,
                    detail=f"FTP login to {dst_ip}:{dport}",
                ))

        # SMTP AUTH PLAIN/LOGIN
        for m in re.finditer(r'AUTH\s+(?:PLAIN|LOGIN)\s+([A-Za-z0-9+/=]+)', text, re.IGNORECASE):
            try:
                import base64
                decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
                parts = decoded.split("\x00")
                if len(parts) >= 2:
                    user = parts[-2] or parts[0]
                    pwd = parts[-1]
                    key = f"smtp:{user}:{dst_ip}"
                    if key not in seen:
                        seen.add(key)
                        creds.append(CredentialCapture(
                            protocol="smtp", username=user, credential=pwd,
                            src_ip=src_ip, dst_ip=dst_ip,
                            detail=f"SMTP auth to {dst_ip}:{dport}",
                        ))
            except Exception:
                pass

        # POP3 USER/PASS
        for m in re.finditer(r'USER\s+(\S+)\r?\n.*?PASS\s+(\S+)', text, re.IGNORECASE | re.DOTALL):
            if dport in (110, 995):
                key = f"pop3:{m.group(1)}:{dst_ip}"
                if key not in seen:
                    seen.add(key)
                    creds.append(CredentialCapture(
                        protocol="pop3", username=m.group(1), credential=m.group(2),
                        src_ip=src_ip, dst_ip=dst_ip,
                        detail=f"POP3 login to {dst_ip}:{dport}",
                    ))

        if len(creds) >= 100:
            break

    return creds


# ---------------------------------------------------------------------------
# 4. Network graph builder (for vis-network visualisation)
# ---------------------------------------------------------------------------

def _build_network_graph(result: PcapResult) -> dict:
    """Build a vis-network compatible graph from the parsed PCAP conversations."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    edge_set: set[str] = set()

    conversations = result.conversations or []
    findings_ips: set[str] = set()

    # Collect IPs mentioned in findings for highlighting
    for f in (result.findings or []):
        detail = f.get("detail", "") if isinstance(f, dict) else (f.detail if hasattr(f, "detail") else "")
        for part in detail.replace(",", " ").split():
            part = part.strip("()")
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', part):
                findings_ips.add(part)

    for conv in conversations:
        src = conv.get("src", "")
        dst = conv.get("dst", "")
        if not src or not dst:
            continue

        # Parse "ip:port" format
        src_ip = src.rsplit(":", 1)[0] if ":" in src else src
        dst_ip = dst.rsplit(":", 1)[0] if ":" in dst else dst

        is_private_src = _is_private(src_ip) if src_ip else False
        is_private_dst = _is_private(dst_ip) if dst_ip else False

        for ip, is_priv in [(src_ip, is_private_src), (dst_ip, is_private_dst)]:
            if ip and ip not in nodes:
                is_suspicious = ip in findings_ips
                nodes[ip] = {
                    "id": ip,
                    "label": ip,
                    "color": {
                        "background": "#f85149" if is_suspicious else ("#58a6ff" if is_priv else "#3fb950"),
                        "border": "#a40e26" if is_suspicious else ("#1f6feb" if is_priv else "#1a7f37"),
                    },
                    "shape": "dot",
                    "title": f"{'SUSPICIOUS ' if is_suspicious else ''}{'Internal' if is_priv else 'External'}: {ip}",
                    "size": 12 if is_suspicious else 8,
                }

        edge_key = f"{src_ip}-{dst_ip}"
        if edge_key not in edge_set:
            edge_set.add(edge_key)
            proto = conv.get("proto", "")
            packet_count = conv.get("packets", 0)
            byte_count = conv.get("bytes", 0)
            label = proto
            if byte_count > 1024 * 1024:
                label += f" ({byte_count // (1024*1024)}MB)"
            elif byte_count > 1024:
                label += f" ({byte_count // 1024}KB)"
            edges.append({
                "from": src_ip,
                "to": dst_ip,
                "label": label,
                "title": f"{src} → {dst}: {packet_count} pkts, {byte_count} bytes",
                "width": min(max(1, packet_count // 10), 6),
                "color": {"color": "#484f58"},
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.5}},
            })

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "internal_nodes": sum(1 for n in nodes.values() if "Internal" in n.get("title", "")),
            "external_nodes": sum(1 for n in nodes.values() if "External" in n.get("title", "")),
            "suspicious_nodes": sum(1 for n in nodes.values() if "SUSPICIOUS" in n.get("title", "")),
        },
    }


# ---------------------------------------------------------------------------
# Packet parsing helpers
# ---------------------------------------------------------------------------

def _extract_ip(raw: bytes) -> Optional[Any]:
    """Extract IP packet from raw bytes (handles Ethernet + raw IP)."""
    try:
        eth = dpkt.ethernet.Ethernet(raw)
        if isinstance(eth.data, dpkt.ip.IP):
            return eth.data
        if isinstance(eth.data, dpkt.ip6.IP6):
            return eth.data
    except (dpkt.UnpackError, dpkt.NeedData):
        pass
    # Try raw IP
    try:
        ip = dpkt.ip.IP(raw)
        if ip.v == 4:
            return ip
    except (dpkt.UnpackError, dpkt.NeedData):
        pass
    return None


def _ip_to_str(addr: bytes) -> str:
    """Convert packed IP bytes to string."""
    if len(addr) == 4:
        return ".".join(str(b) for b in addr)
    if len(addr) == 16:
        # IPv6
        parts = []
        for i in range(0, 16, 2):
            parts.append(f"{addr[i]:02x}{addr[i+1]:02x}")
        return ":".join(parts)
    return addr.hex()


def _parse_tcp_payload(tcp, src_ip, dst_ip, dns_counter, http_counter,
                       tls_sni_counter, payload_sigs, suspicious_uas, cleartext_creds):
    """Parse TCP payload for HTTP, TLS, DNS-over-TCP, and malware signatures."""
    data = bytes(tcp.data)
    if not data:
        return

    # DNS over TCP (port 53)
    if tcp.sport == 53 or tcp.dport == 53:
        if len(data) > 2:
            _parse_dns(data[2:], dns_counter)  # skip 2-byte length prefix
        return

    # TLS ClientHello detection
    if len(data) > 5 and data[0] == 0x16:
        sni = _extract_tls_sni(data)
        if sni:
            tls_sni_counter[sni] += 1
        return

    # Scan payloads for magic bytes and signatures (limit to avoid performance issues)
    if len(data) >= 2 and len(payload_sigs) < 200:
        _scan_payload_signatures(data, src_ip, dst_ip, tcp.sport, tcp.dport, payload_sigs)

    # HTTP detection
    is_http = tcp.dport == 80 or tcp.sport == 80
    if is_http or data[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI"):
        try:
            if data[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI"):
                req = dpkt.http.Request(data)
                host = req.headers.get("host", dst_ip)
                key = f"{req.method} {host}{req.uri[:80]}"
                http_counter[key] += 1

                # Check for suspicious User-Agents
                ua = req.headers.get("user-agent", "")
                if ua and len(suspicious_uas) < 50:
                    _check_suspicious_ua(ua, src_ip, dst_ip, req.uri[:80], suspicious_uas)

                # Check for PowerShell download cradles in URIs
                uri_lower = req.uri.lower()
                if len(payload_sigs) < 200:
                    for pattern in _POWERSHELL_URI_PATTERNS:
                        if pattern in uri_lower:
                            payload_sigs.append({
                                "sig": "PowerShell Download Cradle",
                                "detail": f"{req.method} {host}{req.uri[:100]}",
                                "src": src_ip, "dst": dst_ip,
                                "severity": "critical",
                            })
                            break

        except (dpkt.UnpackError, dpkt.NeedData):
            pass

    # Cleartext credential detection (FTP, SMTP, POP3, IMAP)
    if len(cleartext_creds) < 50:
        _check_cleartext_creds(data, src_ip, dst_ip, tcp.sport, tcp.dport, cleartext_creds)


def _parse_dns(data: bytes, dns_counter):
    """Parse DNS packet and collect query names."""
    try:
        dns = dpkt.dns.DNS(data)
        for q in dns.qd:
            name = q.name
            if name:
                dns_counter[name] += 1
    except (dpkt.UnpackError, dpkt.NeedData):
        pass


# ---------------------------------------------------------------------------
# Payload signature scanning
# ---------------------------------------------------------------------------

# Magic bytes for executable/malware file transfers
_MAGIC_SIGNATURES = [
    (b"MZ", "PE Executable (MZ)", "critical"),
    (b"\x7fELF", "ELF Binary", "critical"),
    (b"#!/", "Script (shebang)", "medium"),
    (b"PK\x03\x04", "ZIP/JAR/Office Archive", "low"),
    (b"\xd0\xcf\x11\xe0", "OLE2 (Legacy Office doc)", "medium"),
    (b"%PDF", "PDF Document", "low"),
]

# Shellcode / exploit patterns (longer patterns to reduce false positives)
_SHELLCODE_PATTERNS = [
    (b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90", "NOP sled (16+ bytes)", "critical"),
    (b"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc", "INT3 breakpoint sled (8+ bytes)", "high"),
    (b"\xfc\xe8\x82\x00\x00\x00", "Metasploit reverse shell prologue", "critical"),
    (b"\xfc\xe8\x89\x00\x00\x00", "Metasploit bind shell prologue", "critical"),
    (b"\xfc\x48\x83\xe4\xf0", "Metasploit x64 shellcode prologue", "critical"),
    (b"\x31\xc0\x50\x68\x2f\x2f", "Linux execve shellcode (/bin/sh)", "critical"),
]

# Base64-encoded PE header variants
_BASE64_PE_MARKERS = [b"TVqQ", b"TVpQ", b"TVoA", b"TVpB", b"TVpA"]

# PowerShell download patterns in HTTP URIs
_POWERSHELL_URI_PATTERNS = [
    "powershell", "invoke-expression", "iex(", "downloadstring",
    "downloadfile", "invoke-webrequest", "bitstransfer",
    "start-bitstransfer", "certutil", "mshta",
]

# Suspicious HTTP User-Agents (common in malware/tools)
_SUSPICIOUS_UA_PATTERNS = [
    ("python-requests", "Python requests library", "medium"),
    ("python-urllib", "Python urllib", "medium"),
    ("curl/", "curl", "low"),
    ("wget/", "wget", "low"),
    ("powershell", "PowerShell", "high"),
    ("certutil", "CertUtil", "critical"),
    ("mshta", "MSHTA", "critical"),
    ("bitsadmin", "BITSAdmin", "high"),
    ("winhttp", "WinHTTP raw", "medium"),
    ("go-http-client", "Go HTTP client", "medium"),
    ("cobalt", "Cobalt Strike", "critical"),
    ("empire", "Empire C2", "critical"),
    ("metasploit", "Metasploit", "critical"),
    ("havoc", "Havoc C2", "critical"),
    ("sliver", "Sliver C2", "critical"),
    ("mozilla/4.0 (compatible;)", "Bare compat UA (common in malware)", "high"),
    ("java/", "Java HTTP client", "medium"),
]


def _scan_payload_signatures(data: bytes, src_ip: str, dst_ip: str,
                             sport: int, dport: int, payload_sigs: list):
    """Scan TCP payload for magic bytes, shellcode, and encoded PE markers."""
    # Only scan first 512 bytes for magic bytes (file headers at start of transfer)
    head = data[:512]

    for magic, name, severity in _MAGIC_SIGNATURES:
        if head.startswith(magic):
            # PE/ELF over standard web ports is less unusual (could be legitimate download)
            web_ports = (80, 443, 8080, 8443)
            if severity == "critical" and (dport in web_ports or sport in web_ports):
                severity = "medium"
            # PE/ELF over non-web port is highly suspicious
            elif severity != "critical" and name in ("PE Executable (MZ)", "ELF Binary") \
                    and dport not in web_ports and sport not in web_ports and dport != 21:
                severity = "critical"
            payload_sigs.append({
                "sig": f"File Transfer: {name}",
                "detail": f"{src_ip}:{sport} -> {dst_ip}:{dport}",
                "src": src_ip, "dst": dst_ip,
                "severity": severity,
            })
            return  # one match per packet

    # Shellcode patterns (scan first 2048 bytes)
    scan_region = data[:2048]
    for pattern, name, severity in _SHELLCODE_PATTERNS:
        if pattern in scan_region:
            payload_sigs.append({
                "sig": f"Shellcode: {name}",
                "detail": f"{src_ip}:{sport} -> {dst_ip}:{dport}",
                "src": src_ip, "dst": dst_ip,
                "severity": severity,
            })
            return

    # Base64-encoded PE in payload (e.g., PowerShell encoded payloads)
    for marker in _BASE64_PE_MARKERS:
        if marker in head:
            payload_sigs.append({
                "sig": "Base64-encoded PE executable",
                "detail": f"{src_ip}:{sport} -> {dst_ip}:{dport} (marker: {marker.decode()})",
                "src": src_ip, "dst": dst_ip,
                "severity": "critical",
            })
            return

    # Encoded PowerShell commands in payload
    lower_head = head.lower()
    if b"powershell" in lower_head and (b"-enc" in lower_head or b"-e " in lower_head
                                         or b"encodedcommand" in lower_head):
        payload_sigs.append({
            "sig": "Encoded PowerShell command",
            "detail": f"{src_ip}:{sport} -> {dst_ip}:{dport}",
            "src": src_ip, "dst": dst_ip,
            "severity": "critical",
        })


def _check_suspicious_ua(ua: str, src_ip: str, dst_ip: str, uri: str, suspicious_uas: list):
    """Check HTTP User-Agent against known suspicious patterns."""
    ua_lower = ua.lower()

    # Empty or very short UA
    if len(ua.strip()) < 5:
        suspicious_uas.append({
            "ua": ua or "(empty)",
            "reason": "Missing/minimal User-Agent",
            "src": src_ip, "dst": dst_ip, "uri": uri,
            "severity": "high",
        })
        return

    for pattern, name, severity in _SUSPICIOUS_UA_PATTERNS:
        if pattern in ua_lower:
            suspicious_uas.append({
                "ua": ua[:120],
                "reason": name,
                "src": src_ip, "dst": dst_ip, "uri": uri,
                "severity": severity,
            })
            return


def _check_cleartext_creds(data: bytes, src_ip: str, dst_ip: str,
                           sport: int, dport: int, cleartext_creds: list):
    """Detect cleartext credentials in FTP, SMTP, POP3, IMAP, HTTP Basic Auth."""
    if len(data) < 5:
        return

    try:
        text = data[:256].decode("ascii", errors="ignore")
    except Exception:
        return

    text_upper = text.upper()

    # FTP credentials (port 21)
    if dport == 21 or sport == 21:
        if text_upper.startswith("USER ") or text_upper.startswith("PASS "):
            cmd = text.split("\r")[0].split("\n")[0]
            cleartext_creds.append({
                "protocol": "FTP",
                "detail": f"{src_ip} -> {dst_ip}: {cmd[:60]}",
                "src": src_ip, "dst": dst_ip,
            })
            return

    # SMTP AUTH (ports 25, 587)
    if dport in (25, 587) or sport in (25, 587):
        if text_upper.startswith("AUTH ") or text_upper.startswith("EHLO "):
            cmd = text.split("\r")[0].split("\n")[0]
            cleartext_creds.append({
                "protocol": "SMTP",
                "detail": f"{src_ip} -> {dst_ip}: {cmd[:60]}",
                "src": src_ip, "dst": dst_ip,
            })
            return

    # POP3 credentials (port 110)
    if dport == 110 or sport == 110:
        if text_upper.startswith("USER ") or text_upper.startswith("PASS "):
            cmd = text.split("\r")[0].split("\n")[0]
            cleartext_creds.append({
                "protocol": "POP3",
                "detail": f"{src_ip} -> {dst_ip}: {cmd[:60]}",
                "src": src_ip, "dst": dst_ip,
            })
            return

    # HTTP Basic Auth (base64-encoded but trivially decoded)
    if b"Authorization: Basic " in data[:256]:
        cleartext_creds.append({
            "protocol": "HTTP Basic Auth",
            "detail": f"{src_ip} -> {dst_ip}:{dport}",
            "src": src_ip, "dst": dst_ip,
        })


# ---------------------------------------------------------------------------
# ISAKMP / IKE parsing
# ---------------------------------------------------------------------------

# ISAKMP exchange types
_ISAKMP_EXCHANGE = {
    0: "None",
    1: "Base",
    2: "Identity Protection (Main Mode)",
    4: "Aggressive",
    5: "Informational",
    32: "Quick Mode",
    33: "New Group Mode",
    34: "IKE_SA_INIT (IKEv2)",
    35: "IKE_AUTH (IKEv2)",
    36: "CREATE_CHILD_SA (IKEv2)",
    37: "INFORMATIONAL (IKEv2)",
}

# ISAKMP notification types that indicate errors (1-16383 are error types)
_ISAKMP_NOTIFY_ERRORS = {
    1: "INVALID_PAYLOAD_TYPE",
    2: "DOI_NOT_SUPPORTED",
    3: "SITUATION_NOT_SUPPORTED",
    4: "INVALID_COOKIE",
    5: "INVALID_MAJOR_VERSION",
    6: "INVALID_MINOR_VERSION",
    7: "INVALID_EXCHANGE_TYPE",
    8: "INVALID_FLAGS",
    9: "INVALID_MESSAGE_ID",
    10: "INVALID_PROTOCOL_ID",
    11: "INVALID_SPI",
    12: "INVALID_TRANSFORM_ID",
    13: "ATTRIBUTES_NOT_SUPPORTED",
    14: "NO_PROPOSAL_CHOSEN",
    24: "AUTHENTICATION_FAILED",
    34: "INVALID_KE_PAYLOAD",
    43: "INVALID_SYNTAX",
}

# ISAKMP next-payload types we care about
_PAYLOAD_SA = 1
_PAYLOAD_NOTIFY = 11
_PAYLOAD_DELETE = 12
_PAYLOAD_NONE = 0


def _parse_isakmp(data: bytes, src_ip: str, dst_ip: str, sport: int, dport: int,
                  ts: float, sessions: dict, proto_counter: collections.Counter):
    """Parse an ISAKMP/IKE packet header and track session state."""
    # NAT-T (port 4500): skip 4-byte non-ESP marker
    if (sport == 4500 or dport == 4500) and len(data) >= 4:
        marker = struct.unpack("!I", data[:4])[0]
        if marker == 0:
            data = data[4:]

    # ISAKMP header is 28 bytes minimum
    if len(data) < 28:
        return

    try:
        init_spi = data[0:8]
        resp_spi = data[8:16]
        next_payload = data[16]
        version = data[17]
        exchange_type = data[18]
        flags = data[19]
        msg_id = struct.unpack("!I", data[20:24])[0]
        total_len = struct.unpack("!I", data[24:28])[0]
    except (struct.error, IndexError):
        return

    # Sanity check: length should be at least 28 and not wildly larger than data
    if total_len < 28 or total_len > len(data) + 100:
        return

    ike_major = (version >> 4) & 0x0F
    ike_minor = version & 0x0F
    is_response = bool(flags & 0x20)  # R flag (IKEv2) or similar
    is_initiator = not is_response

    proto_counter["ISAKMP"] += 1

    spi_key = init_spi
    if spi_key not in sessions:
        sessions[spi_key] = {
            "init_spi": init_spi.hex(),
            "resp_spi": None,
            "initiator_ip": None,
            "responder_ip": None,
            "ike_version": f"{ike_major}.{ike_minor}",
            "exchange_types": [],
            "packets": 0,
            "initiator_packets": 0,
            "responder_packets": 0,
            "first_seen": ts,
            "last_seen": ts,
            "notifications": [],
            "has_delete": False,
            "established": False,
            "retransmits": 0,
        }

    sess = sessions[spi_key]
    sess["packets"] += 1
    sess["last_seen"] = ts

    exchange_name = _ISAKMP_EXCHANGE.get(exchange_type, f"Unknown({exchange_type})")
    if exchange_name not in sess["exchange_types"]:
        sess["exchange_types"].append(exchange_name)

    # Determine who is initiator vs responder
    resp_is_zero = (resp_spi == b'\x00' * 8)
    if resp_is_zero or sess["initiator_ip"] is None:
        # First packet or responder hasn't replied yet
        if sess["initiator_ip"] is None:
            sess["initiator_ip"] = src_ip
            sess["responder_ip"] = dst_ip
    if not resp_is_zero:
        sess["resp_spi"] = resp_spi.hex()

    # Count directional packets
    if src_ip == sess["initiator_ip"]:
        sess["initiator_packets"] += 1
    else:
        sess["responder_packets"] += 1

    # Detect retransmissions: same initiator SPI, same exchange type from same source
    # with responder SPI still zero after first packet
    if resp_is_zero and sess["packets"] > 1 and src_ip == sess["initiator_ip"]:
        sess["retransmits"] += 1

    # Check if session reached established state (IKEv1: Quick Mode seen, IKEv2: IKE_AUTH seen)
    if exchange_type in (32, 35):  # Quick Mode or IKE_AUTH
        sess["established"] = True

    # Parse notification payloads (walk the payload chain)
    _parse_isakmp_payloads(data[28:], next_payload, sess)


def _parse_isakmp_payloads(data: bytes, next_payload: int, sess: dict):
    """Walk ISAKMP payload chain looking for Notification and Delete payloads."""
    offset = 0
    max_payloads = 20  # safety limit
    count = 0

    while next_payload != _PAYLOAD_NONE and offset + 4 <= len(data) and count < max_payloads:
        count += 1
        current_type = next_payload
        next_payload = data[offset]
        payload_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]
        if payload_len < 4:
            break

        payload_body = data[offset + 4:offset + payload_len] if offset + payload_len <= len(data) else b""

        if current_type == _PAYLOAD_NOTIFY and len(payload_body) >= 4:
            # Notification payload: DOI(4), protocol(1), SPI size(1), notify type(2)
            try:
                notify_type = struct.unpack("!H", payload_body[2:4])[0]
                name = _ISAKMP_NOTIFY_ERRORS.get(notify_type, f"Type {notify_type}")
                is_error = notify_type < 16384
                sess["notifications"].append({
                    "type": notify_type,
                    "name": name,
                    "is_error": is_error,
                })
            except struct.error:
                pass

        if current_type == _PAYLOAD_DELETE:
            sess["has_delete"] = True

        offset += payload_len


def _summarise_isakmp(sessions: dict) -> list:
    """Build a summary list of ISAKMP sessions for the result output."""
    if not sessions:
        return []
    result = []
    for spi_key, sess in sessions.items():
        errors = [n for n in sess["notifications"] if n.get("is_error")]
        status = "Established" if sess["established"] else (
            "Failed" if errors else (
                "No Response" if sess["responder_packets"] == 0 else "Incomplete"
            )
        )
        result.append({
            "init_spi": sess["init_spi"],
            "resp_spi": sess["resp_spi"],
            "initiator": sess["initiator_ip"],
            "responder": sess["responder_ip"],
            "ike_version": sess["ike_version"],
            "exchanges": sess["exchange_types"],
            "status": status,
            "packets": sess["packets"],
            "initiator_packets": sess["initiator_packets"],
            "responder_packets": sess["responder_packets"],
            "retransmits": sess["retransmits"],
            "errors": [n["name"] for n in errors],
            "has_delete": sess["has_delete"],
            "duration": round(sess["last_seen"] - sess["first_seen"], 2),
        })
    return sorted(result, key=lambda s: s["status"] != "Established")


def _detect_isakmp_issues(sessions: dict) -> list[Finding]:
    """Detect ISAKMP/IKE negotiation problems.

    Logic:
    - Internal-to-internal ISAKMP is expected (your VPN infrastructure).
    - External IP involved + established = unauthorized VPN tunnel (critical).
    - External IP involved + failed/no response = probing attempt (high).
    - Internal sessions: only flag failures/retransmits (operational health).
    """
    findings = []
    if not sessions:
        return findings

    total = len(sessions)
    ext_established = []
    ext_failed = []
    ext_probing = []
    int_no_response = []
    int_failed = []
    int_incomplete = []
    retransmit_sessions = []
    delete_sessions = []

    for spi_key, sess in sessions.items():
        errors = [n for n in sess["notifications"] if n.get("is_error")]
        init_ip = sess["initiator_ip"] or ""
        resp_ip = sess["responder_ip"] or ""
        label = f"{init_ip} -> {resp_ip}"
        both_internal = _is_private(init_ip) and _is_private(resp_ip)

        if not both_internal:
            # External IP involved — this is where we care most
            if sess["established"]:
                ext_established.append((label, sess))
            elif errors:
                ext_failed.append((label, sess, errors))
            elif sess["responder_packets"] == 0:
                ext_probing.append((label, sess))
            else:
                ext_failed.append((label, sess, errors))
        else:
            # Internal-to-internal — only flag operational issues
            if sess["responder_packets"] == 0:
                int_no_response.append((label, sess))
            elif errors:
                int_failed.append((label, sess, errors))
            elif not sess["established"]:
                int_incomplete.append((label, sess))

        if sess["retransmits"] > 2:
            retransmit_sessions.append((label, sess))

        if sess["has_delete"]:
            delete_sessions.append((label, sess))

    # === EXTERNAL IKE — high priority ===

    # 1. Established VPN tunnels with external IPs (unauthorized tunnel)
    if ext_established:
        details = "; ".join(
            f"{lbl} (v{s['ike_version']}, {s['packets']} pkts, "
            f"exchanges: {', '.join(s['exchange_types'])})"
            for lbl, s in ext_established[:5]
        )
        findings.append(Finding(
            category="ISAKMP/IKE",
            severity="critical",
            title=f"Unauthorized VPN: {len(ext_established)} IKE session(s) established with external IP(s)",
            detail=f"IKE/IPsec tunnels established with non-internal IP addresses. This may indicate "
                   f"an unauthorized VPN tunnel, rogue IPsec connection, or compromised endpoint "
                   f"phoning home via encrypted tunnel. Sessions: {details}",
        ))

    # 2. Failed external IKE (attempted unauthorized tunnel)
    if ext_failed:
        details = "; ".join(
            f"{lbl} ({', '.join(e['name'] for e in errs[:2]) if errs else 'incomplete'})"
            for lbl, s, errs in ext_failed[:5]
        )
        findings.append(Finding(
            category="ISAKMP/IKE",
            severity="high",
            title=f"External IKE negotiation attempts: {len(ext_failed)} failed session(s)",
            detail=f"IKE negotiations with external IPs failed. Someone may be attempting to "
                   f"establish an unauthorized VPN tunnel. Sessions: {details}",
        ))

    # 3. External probing (sent IKE init but got no response)
    if ext_probing:
        details = "; ".join(
            f"{lbl} ({s['initiator_packets']} pkts, {s['retransmits']} retransmits)"
            for lbl, s in ext_probing[:5]
        )
        findings.append(Finding(
            category="ISAKMP/IKE",
            severity="high",
            title=f"External IKE probing: {len(ext_probing)} unanswered session(s)",
            detail=f"IKE initiation attempts to/from external IPs with no response. This may indicate "
                   f"reconnaissance, a misconfigured VPN client, or an endpoint attempting to tunnel out. "
                   f"Sessions: {details}",
        ))

    # === INTERNAL IKE — operational health ===

    # 4. Internal sessions with no response (your VPN server not replying)
    if int_no_response:
        details = "; ".join(
            f"{lbl} ({s['initiator_packets']} pkts, {s['retransmits']} retransmits)"
            for lbl, s in int_no_response[:5]
        )
        findings.append(Finding(
            category="ISAKMP/IKE",
            severity="high",
            title=f"Internal IKE: {len(int_no_response)} session(s) received no server response",
            detail=f"Internal VPN server did not respond to IKE initiations. Check if the VPN "
                   f"service is running and UDP 500/4500 is not blocked. Sessions: {details}",
        ))

    # 5. Internal negotiation failures
    if int_failed:
        for lbl, sess, errors in int_failed[:3]:
            error_names = ", ".join(e["name"] for e in errors[:3]) if errors else "unknown"
            findings.append(Finding(
                category="ISAKMP/IKE",
                severity="medium",
                title=f"Internal IKE negotiation failed: {lbl}",
                detail=f"Error(s): {error_names}. IKE v{sess['ike_version']}, "
                       f"exchanges: {', '.join(sess['exchange_types'])}. "
                       f"Check proposal compatibility and credentials.",
            ))

    # 6. Internal incomplete negotiations
    if int_incomplete:
        details = "; ".join(
            f"{lbl} ({s['initiator_packets']}i/{s['responder_packets']}r pkts)"
            for lbl, s in int_incomplete[:5]
        )
        findings.append(Finding(
            category="ISAKMP/IKE",
            severity="medium",
            title=f"Internal IKE: {len(int_incomplete)} session(s) incomplete",
            detail=f"Phase 1 succeeded but never reached Phase 2 / IKE_AUTH. "
                   f"Check Phase 2 proposals and authentication. Sessions: {details}",
        ))

    # 7. Excessive retransmissions
    if retransmit_sessions:
        details = "; ".join(
            f"{lbl} ({s['retransmits']} retransmits)" for lbl, s in retransmit_sessions[:5]
        )
        findings.append(Finding(
            category="ISAKMP/IKE",
            severity="medium",
            title=f"IKE: {len(retransmit_sessions)} session(s) with excessive retransmissions",
            detail=f"Packets are being lost or peer is slow. Check network path, MTU, and "
                   f"firewall rules for UDP 500/4500. Sessions: {details}",
        ))

    # 8. High session teardown rate
    if delete_sessions and total >= 3:
        pct = len(delete_sessions) * 100 // total
        if pct > 50:
            findings.append(Finding(
                category="ISAKMP/IKE",
                severity="medium",
                title=f"IKE: {len(delete_sessions)}/{total} sessions torn down ({pct}%)",
                detail=f"High proportion of IKE sessions explicitly deleted. May indicate "
                       f"unstable VPN tunnels or DPD failures.",
            ))

    # Summary: all internal and healthy
    int_established = total - len(ext_established) - len(ext_failed) - len(ext_probing) \
        - len(int_no_response) - len(int_failed) - len(int_incomplete)
    if total > 0 and not findings:
        findings.append(Finding(
            category="ISAKMP/IKE",
            severity="low",
            title=f"IKE: {int_established}/{total} internal session(s) established normally",
            detail=f"All IKE/IPsec negotiations are between internal IPs and completed successfully. "
                   f"No unauthorized external tunnels detected.",
        ))

    return findings


def _extract_tls_sni(data: bytes) -> Optional[str]:
    """Extract SNI from TLS ClientHello."""
    try:
        if len(data) < 44:
            return None
        # TLS record: type(1) version(2) length(2) -> handshake
        if data[0] != 0x16:
            return None
        # Handshake type 1 = ClientHello at offset 5
        if data[5] != 0x01:
            return None

        # Skip to session_id
        offset = 43
        if offset >= len(data):
            return None
        session_id_len = data[offset]
        offset += 1 + session_id_len

        # Skip cipher suites
        if offset + 2 > len(data):
            return None
        cs_len = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2 + cs_len

        # Skip compression methods
        if offset >= len(data):
            return None
        cm_len = data[offset]
        offset += 1 + cm_len

        # Extensions
        if offset + 2 > len(data):
            return None
        ext_len = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2
        ext_end = offset + ext_len

        while offset + 4 <= ext_end and offset + 4 <= len(data):
            ext_type = struct.unpack("!H", data[offset:offset + 2])[0]
            ext_data_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4

            if ext_type == 0x0000:  # SNI extension
                if offset + 5 <= len(data):
                    sni_list_len = struct.unpack("!H", data[offset:offset + 2])[0]
                    sni_type = data[offset + 2]
                    sni_len = struct.unpack("!H", data[offset + 3:offset + 5])[0]
                    if sni_type == 0 and offset + 5 + sni_len <= len(data):
                        return data[offset + 5:offset + 5 + sni_len].decode("ascii", errors="ignore")
                return None

            offset += ext_data_len

    except (struct.error, IndexError):
        pass
    return None


# ---------------------------------------------------------------------------
# Heuristic analysis
# ---------------------------------------------------------------------------

def _analyze(
    result: PcapResult,
    conn_times: dict,
    dns_counter: collections.Counter,
    src_ip_counter: collections.Counter,
    dst_ip_counter: collections.Counter,
    src_port_counter: collections.Counter,
    dst_port_counter: collections.Counter,
    ip_sent: collections.Counter,
    ip_recv: collections.Counter,
    proto_counter: collections.Counter,
    isakmp_sessions: dict,
    payload_sigs: list,
    suspicious_uas: list,
    cleartext_creds: list,
) -> list[Finding]:
    findings = []

    # 1. Beaconing detection
    findings.extend(_detect_beaconing(conn_times))

    # 2. DNS tunneling
    findings.extend(_detect_dns_tunneling(dns_counter))

    # 3. Suspicious ports
    findings.extend(_detect_suspicious_ports(dst_port_counter))

    # 4. Large data exfiltration
    findings.extend(_detect_exfiltration(ip_sent, ip_recv))

    # 5. Port scanning
    findings.extend(_detect_port_scan(conn_times))

    # 6. DGA domains
    findings.extend(_detect_dga(dns_counter))

    # 7. ICMP anomaly (check if lots of ICMP)
    total_pkts = sum(proto_counter.values())
    icmp_count = proto_counter.get("ICMP", 0)
    if total_pkts > 100 and icmp_count > total_pkts * 0.2:
        findings.append(Finding(
            category="Network Anomaly",
            severity="medium",
            title=f"High ICMP traffic: {icmp_count} packets ({icmp_count * 100 // total_pkts}%)",
            detail="Elevated ICMP traffic may indicate ICMP tunneling, network reconnaissance, or a ping flood.",
        ))

    # 8. Cleartext sensitive protocols
    for port in CLEARTEXT_PORTS:
        count = dst_port_counter.get(port, 0)
        if count > 10:
            svc = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP",
                   161: "SNMP", 25: "SMTP", 587: "SMTP"}.get(port, str(port))
            findings.append(Finding(
                category="Cleartext Protocol",
                severity="low",
                title=f"Cleartext {svc} traffic detected ({count} packets to port {port})",
                detail=f"Unencrypted {svc} traffic may expose credentials or sensitive data.",
            ))

    # 9. ISAKMP/IKE health checks
    findings.extend(_detect_isakmp_issues(isakmp_sessions))

    # 10. Malware payload signatures (magic bytes, shellcode, encoded PE)
    findings.extend(_detect_payload_signatures(payload_sigs))

    # 11. Suspicious HTTP User-Agents
    findings.extend(_detect_suspicious_uas(suspicious_uas))

    # 12. Cleartext credential exposure
    findings.extend(_detect_cleartext_creds(cleartext_creds))

    return findings


def _detect_beaconing(conn_times: dict) -> list[Finding]:
    findings = []
    for (src, dst, port), times in conn_times.items():
        if len(times) < 5:
            continue
        times_sorted = sorted(times)
        intervals = [times_sorted[i + 1] - times_sorted[i] for i in range(len(times_sorted) - 1)]
        mean = sum(intervals) / len(intervals)
        if mean < 1:
            continue
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5
        cv = std_dev / mean if mean > 0 else float("inf")
        if cv < 0.15:
            findings.append(Finding(
                category="Command & Control",
                severity="high",
                title=f"Beaconing: {src} -> {dst}:{port}",
                detail=f"Regular connections every ~{mean:.1f}s (CV={cv:.3f}, {len(times)} connections). "
                       f"Low variance suggests automated C2 beaconing.",
            ))
    return findings


def _detect_dns_tunneling(dns_counter: collections.Counter) -> list[Finding]:
    findings = []
    # Check for long subdomain names
    long_queries = [q for q in dns_counter if len(q) > 50]
    if long_queries:
        findings.append(Finding(
            category="DNS Tunneling",
            severity="high",
            title=f"Unusually long DNS queries ({len(long_queries)} unique)",
            detail=f"DNS queries exceeding 50 chars may indicate DNS tunneling or data exfiltration. "
                   f"Examples: {', '.join(long_queries[:3])}",
        ))

    # Check for high subdomain diversity under one domain
    domain_subs: dict[str, set] = {}
    domain_query_count: dict[str, int] = {}
    for q, count in dns_counter.items():
        parts = q.split(".")
        if len(parts) >= 3:
            base = ".".join(parts[-2:])
            domain_subs.setdefault(base, set()).add(q)
            domain_query_count[base] = domain_query_count.get(base, 0) + count
    for base, subs in domain_subs.items():
        total_hits = domain_query_count.get(base, 0)
        if len(subs) > 50:
            findings.append(Finding(
                category="DNS Tunneling",
                severity="high",
                title=f"High subdomain diversity for {base} ({len(subs)} unique)",
                detail=f"Excessive unique subdomains under a single domain is a strong DNS tunneling indicator.",
            ))
        elif len(subs) > 15:
            findings.append(Finding(
                category="DNS Tunneling",
                severity="medium",
                title=f"Elevated subdomain diversity for {base} ({len(subs)} unique, {total_hits} queries)",
                detail=f"Multiple unique subdomains under {base} with high query volume may indicate DNS C2 or tunneling.",
            ))
        elif len(subs) >= 5 and total_hits > 50:
            findings.append(Finding(
                category="DNS Anomaly",
                severity="medium",
                title=f"Repetitive DNS queries to {base} ({total_hits} queries, {len(subs)} subdomains)",
                detail=f"High query volume to a single domain with multiple subdomains may indicate C2 beaconing over DNS.",
            ))

    return findings


def _detect_suspicious_ports(dst_port_counter: collections.Counter) -> list[Finding]:
    findings = []
    for port, label in SUSPICIOUS_PORTS.items():
        count = dst_port_counter.get(port, 0)
        if count > 0:
            sev = "critical" if port in (4444, 31337) else "high" if port in (6667, 9001, 9050, 3333) else "medium"
            findings.append(Finding(
                category="Suspicious Port",
                severity=sev,
                title=f"Traffic to port {port} ({label}): {count} packets",
                detail=f"Port {port} is associated with {label}. {count} packets observed.",
            ))
    return findings


def _detect_exfiltration(ip_sent: collections.Counter, ip_recv: collections.Counter) -> list[Finding]:
    findings = []
    for ip, sent in ip_sent.most_common(50):
        if _is_private(ip):
            recv = ip_recv.get(ip, 0)
            if sent > 100_000_000:  # >100MB sent from an internal IP
                findings.append(Finding(
                    category="Data Exfiltration",
                    severity="high",
                    title=f"Large outbound transfer from {ip}: {_fmt_bytes(sent)}",
                    detail=f"Internal IP {ip} sent {_fmt_bytes(sent)} (received {_fmt_bytes(recv)}). "
                           f"Ratio: {sent / max(recv, 1):.1f}:1",
                ))
            elif recv > 0 and sent / max(recv, 1) > 10 and sent > 10_000_000:
                findings.append(Finding(
                    category="Data Exfiltration",
                    severity="medium",
                    title=f"Asymmetric traffic from {ip}: {sent / max(recv, 1):.1f}:1 ratio",
                    detail=f"Internal IP {ip} sent {_fmt_bytes(sent)} but received only {_fmt_bytes(recv)}.",
                ))
    return findings


def _detect_port_scan(conn_times: dict) -> list[Finding]:
    findings = []
    # Vertical scan: one src -> one dst on many ports
    src_dst_ports: dict[tuple, set] = {}
    # Horizontal scan: one src -> many dsts on same port
    src_port_dsts: dict[tuple, set] = {}

    for (src, dst, port) in conn_times:
        src_dst_ports.setdefault((src, dst), set()).add(port)
        src_port_dsts.setdefault((src, port), set()).add(dst)

    for (src, dst), ports in src_dst_ports.items():
        if len(ports) > 20:
            findings.append(Finding(
                category="Reconnaissance",
                severity="high",
                title=f"Port scan: {src} -> {dst} ({len(ports)} ports)",
                detail=f"Source {src} connected to {len(ports)} unique ports on {dst}. "
                       f"Ports include: {', '.join(str(p) for p in sorted(ports)[:10])}...",
            ))

    for (src, port), dsts in src_port_dsts.items():
        if len(dsts) > 10:
            findings.append(Finding(
                category="Reconnaissance",
                severity="medium",
                title=f"Horizontal scan: {src} port {port} -> {len(dsts)} hosts",
                detail=f"Source {src} connected to {len(dsts)} unique hosts on port {port}.",
            ))

    return findings


def _detect_dga(dns_counter: collections.Counter) -> list[Finding]:
    findings = []
    high_entropy_domains = []
    for query in dns_counter:
        parts = query.split(".")
        if len(parts) >= 2:
            sld = parts[-2]  # second-level domain
            if len(sld) >= 6:
                entropy = _shannon_entropy(sld)
                if entropy > 3.5:
                    high_entropy_domains.append((query, round(entropy, 2)))

    if len(high_entropy_domains) > 3:
        examples = high_entropy_domains[:5]
        findings.append(Finding(
            category="DGA Detection",
            severity="high",
            title=f"Possible DGA: {len(high_entropy_domains)} high-entropy domains",
            detail=f"Multiple DNS queries with high randomness in the domain name suggest Domain Generation "
                   f"Algorithm activity. Examples: {', '.join(f'{d} (H={e})' for d, e in examples)}",
        ))
    elif high_entropy_domains:
        for domain, entropy in high_entropy_domains:
            findings.append(Finding(
                category="DGA Detection",
                severity="medium",
                title=f"High-entropy domain: {domain} (H={entropy})",
                detail=f"Domain name has unusually high randomness (Shannon entropy {entropy}), "
                       f"which may indicate DGA or algorithmically generated malware C2.",
            ))

    return findings


# ---------------------------------------------------------------------------
# Payload / UA / credential detections
# ---------------------------------------------------------------------------

def _detect_payload_signatures(payload_sigs: list) -> list[Finding]:
    """Generate findings from payload signature matches."""
    findings = []
    if not payload_sigs:
        return findings

    # Group by signature name and deduplicate
    sig_groups: dict[str, list] = {}
    for sig in payload_sigs:
        sig_groups.setdefault(sig["sig"], []).append(sig)

    for sig_name, hits in sig_groups.items():
        worst_sev = max(hits, key=lambda h: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(h["severity"], 0))
        severity = worst_sev["severity"]
        examples = "; ".join(h["detail"] for h in hits[:5])
        count = len(hits)

        category = "Malware Signature"
        if "Shellcode" in sig_name:
            category = "Shellcode Detection"
        elif "PowerShell" in sig_name:
            category = "PowerShell Abuse"
        elif "File Transfer" in sig_name:
            category = "Suspicious File Transfer"

        findings.append(Finding(
            category=category,
            severity=severity,
            title=f"{sig_name}: {count} occurrence(s)",
            detail=f"Detected in traffic: {examples}" +
                   (f" ... and {count - 5} more" if count > 5 else ""),
        ))

    return findings


def _detect_suspicious_uas(suspicious_uas: list) -> list[Finding]:
    """Generate findings from suspicious HTTP User-Agents."""
    findings = []
    if not suspicious_uas:
        return findings

    # Group by reason
    ua_groups: dict[str, list] = {}
    for ua in suspicious_uas:
        ua_groups.setdefault(ua["reason"], []).append(ua)

    for reason, hits in ua_groups.items():
        worst = max(hits, key=lambda h: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(h["severity"], 0))
        examples = "; ".join(f"{h['src']}->{h['dst']} UA=\"{h['ua'][:60]}\"" for h in hits[:3])
        findings.append(Finding(
            category="Suspicious User-Agent",
            severity=worst["severity"],
            title=f"Suspicious HTTP User-Agent: {reason} ({len(hits)} request(s))",
            detail=f"HTTP requests with tool/malware-associated User-Agent detected. {examples}",
        ))

    return findings


def _detect_cleartext_creds(cleartext_creds: list) -> list[Finding]:
    """Generate findings from cleartext credential exposure."""
    findings = []
    if not cleartext_creds:
        return findings

    # Group by protocol
    proto_groups: dict[str, list] = {}
    for cred in cleartext_creds:
        proto_groups.setdefault(cred["protocol"], []).append(cred)

    for protocol, hits in proto_groups.items():
        examples = "; ".join(h["detail"] for h in hits[:3])
        findings.append(Finding(
            category="Credential Exposure",
            severity="high",
            title=f"Cleartext {protocol} credentials: {len(hits)} instance(s)",
            detail=f"Authentication credentials sent in cleartext over {protocol}. "
                   f"These can be intercepted by any network observer. {examples}",
        ))

    return findings


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {"critical": 50, "high": 25, "medium": 10, "low": 3}


def _compute_verdict(findings: list[Finding]) -> dict:
    if not findings:
        return {
            "label": "Likely Benign",
            "confidence": 85,
            "reasons": ["No suspicious patterns detected in traffic analysis."],
        }

    score = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)

    # Deduplicate reasons by category
    reasons = []
    seen_cats = set()
    for f in sorted(findings, key=lambda x: SEVERITY_WEIGHTS.get(x.severity, 0), reverse=True):
        if f.category not in seen_cats and len(reasons) < 5:
            reasons.append(f.title)
            seen_cats.add(f.category)

    if score >= 50:
        return {
            "label": "Needs Investigation",
            "confidence": min(95, 50 + score),
            "reasons": reasons,
            "score": score,
            "finding_count": len(findings),
        }
    else:
        return {
            "label": "Likely Benign",
            "confidence": max(55, 100 - score * 2),
            "reasons": reasons if reasons else ["Minor anomalies detected but within normal parameters."],
            "score": score,
            "finding_count": len(findings),
        }


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _is_private(ip: str) -> bool:
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.")
        or ip.startswith("172.19.") or ip.startswith("172.2") or ip.startswith("172.3")
        or ip.startswith("127.")
        or ip.startswith("fe80")
        or ip.startswith("fc") or ip.startswith("fd")
    )


def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.1f} GB"


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = collections.Counter(s.lower())
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


# ---------------------------------------------------------------------------
# JA3S — TLS ServerHello fingerprinting
# ---------------------------------------------------------------------------

_KNOWN_BAD_JA3S: dict[str, str] = {
    "ae4edc6faf64d08308082ad26be60767": "Cobalt Strike",
    "fd4bc6cea4877646ccd62f0792ec0b62": "Cobalt Strike",
    "b742b407517bac9536a77a7b0fee28e9": "Cobalt Strike (4.x)",
    "15af977ce25de452b96affa2addb1036": "Cobalt Strike (HTTPS)",
    "ec74a5c51106f0419184d0dd08fb05bc": "Metasploit",
    "298c3ea8e9f786f2e5c3c08e0f93f708": "Trickbot C2",
    "4a55e90e5c823cc77d52d10e828dda2b": "Gozi/ISFB",
}


def _compute_ja3s(server_hellos: list[dict]) -> list[JA3SFingerprint]:
    """Compute JA3S fingerprints from TLS ServerHello messages."""
    fingerprints: list[JA3SFingerprint] = []
    seen: set[str] = set()

    for hello in server_hellos:
        data = hello["data"]
        try:
            ja3s_str, ja3s_hash = _parse_server_hello_ja3s(data)
        except Exception:
            continue
        if not ja3s_hash:
            continue
        dedup = f'{hello["src_ip"]}:{hello["dst_ip"]}:{ja3s_hash}'
        if dedup in seen:
            continue
        seen.add(dedup)
        fingerprints.append(JA3SFingerprint(
            ja3s_hash=ja3s_hash,
            ja3s_str=ja3s_str,
            src_ip=hello["src_ip"],
            dst_ip=hello["dst_ip"],
            src_port=hello["src_port"],
            known_malware=_KNOWN_BAD_JA3S.get(ja3s_hash, ""),
        ))
    return fingerprints


def _parse_server_hello_ja3s(data: bytes) -> tuple[str, str]:
    """Parse TLS ServerHello → JA3S = md5(TLSVersion,Cipher,Extensions)."""
    if len(data) < 44 or data[0] != 0x16 or data[5] != 0x02:
        return "", ""

    # Record header: type(1) + version(2) + length(2) = 5 bytes
    # Handshake header: type(1) + length(3) = 4 bytes → offset 9
    # ServerHello: server_version(2) + random(32) + session_id_length(1)
    offset = 9
    if offset + 2 > len(data):
        return "", ""
    tls_version = struct.unpack("!H", data[offset:offset + 2])[0]
    offset += 2 + 32  # skip random

    if offset >= len(data):
        return "", ""
    session_id_len = data[offset]
    offset += 1 + session_id_len

    if offset + 2 > len(data):
        return "", ""
    cipher = struct.unpack("!H", data[offset:offset + 2])[0]
    offset += 2

    # Skip compression method (1 byte)
    if offset >= len(data):
        return "", ""
    offset += 1

    # Extensions
    extensions = []
    if offset + 2 <= len(data):
        ext_len = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2
        ext_end = offset + ext_len
        while offset + 4 <= min(ext_end, len(data)):
            ext_type = struct.unpack("!H", data[offset:offset + 2])[0]
            ext_data_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            # Skip GREASE values
            if (ext_type & 0x0f0f) != 0x0a0a:
                extensions.append(str(ext_type))
            offset += 4 + ext_data_len

    ja3s_str = f"{tls_version},{cipher},{'-'.join(extensions)}"
    ja3s_hash = hashlib.md5(ja3s_str.encode()).hexdigest()
    return ja3s_str, ja3s_hash


# ---------------------------------------------------------------------------
# HASSH — SSH fingerprinting
# ---------------------------------------------------------------------------

_KNOWN_BAD_HASSH: dict[str, str] = {
    "ec7378c1a92f5a8dde7e8b7a1ddf33d1": "Cobalt Strike SSH",
    "06046964c022c6407d15a27b12a6f4fb": "Paramiko (Python SSH)",
}


def _compute_hassh(ssh_packets: list[dict]) -> list[HASSHFingerprint]:
    """Compute HASSH fingerprints from SSH KEX_INIT messages."""
    fingerprints: list[HASSHFingerprint] = []
    seen: set[str] = set()
    banners: dict[str, str] = {}  # ip → SSH banner

    for pkt in ssh_packets:
        if pkt["type"] == "banner":
            raw = pkt["data"]
            try:
                banner = raw[:raw.index(b"\r\n")].decode("ascii", errors="replace") if b"\r\n" in raw else raw[:64].decode("ascii", errors="replace")
            except Exception:
                banner = ""
            banners[pkt["src_ip"]] = banner
            continue

        if pkt["type"] != "kexinit":
            continue

        data = pkt["data"]
        try:
            hassh_str, hassh_hash = _parse_ssh_kexinit(data)
        except Exception:
            continue
        if not hassh_hash:
            continue

        direction = "server" if pkt["src_port"] == 22 else "client"
        dedup = f'{pkt["src_ip"]}:{pkt["dst_ip"]}:{hassh_hash}'
        if dedup in seen:
            continue
        seen.add(dedup)
        fingerprints.append(HASSHFingerprint(
            hassh_hash=hassh_hash,
            hassh_str=hassh_str,
            src_ip=pkt["src_ip"],
            dst_ip=pkt["dst_ip"],
            direction=direction,
            ssh_version=banners.get(pkt["src_ip"], ""),
            known_malware=_KNOWN_BAD_HASSH.get(hassh_hash, ""),
        ))
    return fingerprints


def _parse_ssh_kexinit(data: bytes) -> tuple[str, str]:
    """Parse SSH_MSG_KEXINIT → HASSH = md5(kex_algs,enc_algs,mac_algs,comp_algs).

    Binary packet: length(4) + padding_length(1) + msg_type(1=20) + cookie(16)
    Then name-lists: each is uint32 length + comma-separated string.
    """
    if len(data) < 26:
        return "", ""
    # Skip packet length(4) + padding_length(1) + msg_type(1) + cookie(16) = 22
    offset = 22
    name_lists = []
    # We need 4 name-lists for HASSH: kex_algorithms, encryption_algorithms_c2s,
    # mac_algorithms_c2s, compression_algorithms_c2s (indices 0, 2, 4, 6 of the
    # 10 name-lists in KEX_INIT).
    all_lists = []
    for i in range(10):
        if offset + 4 > len(data):
            break
        nl_len = struct.unpack("!I", data[offset:offset + 4])[0]
        offset += 4
        if offset + nl_len > len(data):
            break
        nl = data[offset:offset + nl_len].decode("ascii", errors="replace")
        all_lists.append(nl)
        offset += nl_len

    if len(all_lists) < 7:
        return "", ""

    # HASSH (client): kex[0], enc_c2s[2], mac_c2s[4], comp_c2s[6]
    hassh_str = ";".join([all_lists[0], all_lists[2], all_lists[4], all_lists[6]])
    hassh_hash = hashlib.md5(hassh_str.encode()).hexdigest()
    return hassh_str, hassh_hash


# ---------------------------------------------------------------------------
# SMB file transfer detection
# ---------------------------------------------------------------------------

def _detect_smb(streams: dict) -> list[SMBTransfer]:
    """Detect SMB/CIFS file operations in TCP streams on port 445/139."""
    results: list[SMBTransfer] = []
    seen: set[str] = set()

    for (src_ip, sport, dst_ip, dport), payload in streams.items():
        if dport not in (445, 139) and sport not in (445, 139):
            continue
        data = bytes(payload)
        if len(data) < 10:
            continue

        # SMB2 magic: \xFE\x53\x4D\x42
        offset = 0
        while offset < len(data) - 64:
            pos = data.find(b"\xfeSMB", offset)
            if pos == -1:
                break
            if pos + 16 > len(data):
                break
            try:
                cmd = struct.unpack("<H", data[pos + 12:pos + 14])[0]
            except Exception:
                offset = pos + 4
                continue
            cmd_names = {
                0x0005: "SMB2_CREATE",
                0x0006: "SMB2_CLOSE",
                0x0008: "SMB2_READ",
                0x0009: "SMB2_WRITE",
                0x000e: "SMB2_FIND",
            }
            cmd_name = cmd_names.get(cmd)
            if cmd_name:
                key = f"{src_ip}:{dst_ip}:{cmd_name}"
                if key not in seen:
                    seen.add(key)
                    results.append(SMBTransfer(
                        src_ip=src_ip, dst_ip=dst_ip,
                        command=cmd_name,
                        detail=f"SMB2 {cmd_name} detected on port {dport}",
                    ))
            offset = pos + 64
            if len(results) >= 50:
                break
        if len(results) >= 50:
            break

    # SMB1 fallback: \xFF\x53\x4D\x42
    if len(results) < 50:
        for (src_ip, sport, dst_ip, dport), payload in streams.items():
            if dport not in (445, 139) and sport not in (445, 139):
                continue
            data = bytes(payload)
            if data.find(b"\xffSMB") != -1:
                key = f"{src_ip}:{dst_ip}:SMB1"
                if key not in seen:
                    seen.add(key)
                    results.append(SMBTransfer(
                        src_ip=src_ip, dst_ip=dst_ip,
                        command="SMB1",
                        detail="Legacy SMB1 traffic detected",
                    ))
    return results


# ---------------------------------------------------------------------------
# Kerberos ticket detection
# ---------------------------------------------------------------------------

def _detect_kerberos(streams: dict) -> list[dict]:
    """Detect Kerberos AS-REQ/AS-REP/TGS-REQ/TGS-REP on port 88."""
    results: list[dict] = []

    for (src_ip, sport, dst_ip, dport), payload in streams.items():
        if dport != 88 and sport != 88:
            continue
        data = bytes(payload)
        if len(data) < 10:
            continue

        # Kerberos uses ASN.1 DER encoding. The application tags are:
        # AS-REQ: 0x6a (application 10), AS-REP: 0x6b (application 11)
        # TGS-REQ: 0x6c (application 12), TGS-REP: 0x6d (application 13)
        msg_types = {
            0x6a: "AS-REQ", 0x6b: "AS-REP",
            0x6c: "TGS-REQ", 0x6d: "TGS-REP",
        }
        for tag_byte, msg_type in msg_types.items():
            if tag_byte in data[:4]:
                results.append({
                    "msg_type": msg_type,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "detail": f"{msg_type} detected ({src_ip} → {dst_ip})",
                })
                break
        if len(results) >= 100:
            break
    return results


# ---------------------------------------------------------------------------
# HTTP file reassembly
# ---------------------------------------------------------------------------

def _extract_http_files(streams: dict) -> list[dict]:
    """Extract files from HTTP response bodies via Content-Type + Content-Disposition."""
    files: list[dict] = []
    seen: set[str] = set()

    for (src_ip, sport, dst_ip, dport), payload in streams.items():
        if sport not in (80, 8080, 8443, 443) and dport not in (80, 8080):
            continue
        data = bytes(payload)
        # Look for HTTP response headers
        idx = 0
        while idx < len(data) - 20:
            resp_start = data.find(b"HTTP/1.", idx)
            if resp_start == -1:
                break
            header_end = data.find(b"\r\n\r\n", resp_start)
            if header_end == -1:
                break
            headers_raw = data[resp_start:header_end].decode("ascii", errors="replace")
            body_start = header_end + 4

            # Parse Content-Type and Content-Length
            content_type = ""
            content_length = 0
            filename = ""
            for line in headers_raw.split("\r\n"):
                lower = line.lower()
                if lower.startswith("content-type:"):
                    content_type = line.split(":", 1)[1].strip().split(";")[0].strip()
                elif lower.startswith("content-length:"):
                    try:
                        content_length = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        pass
                elif lower.startswith("content-disposition:") and "filename=" in lower:
                    try:
                        fn_part = line.split("filename=")[1].strip().strip('"').strip("'")
                        filename = fn_part.split(";")[0].strip()
                    except Exception:
                        pass

            # Only care about non-text content types that indicate file transfers
            interesting_types = (
                "application/", "image/", "audio/", "video/",
                "font/", "model/",
            )
            if content_type and any(content_type.startswith(t) for t in interesting_types):
                body = data[body_start:body_start + min(content_length, 5 * 1024 * 1024)] if content_length else b""
                md5 = hashlib.md5(body).hexdigest() if body else ""
                if md5 and md5 not in seen:
                    seen.add(md5)
                    ext = content_type.split("/")[-1].split(";")[0][:10]
                    files.append({
                        "filename": filename or f"http_file_{len(files)+1}.{ext}",
                        "content_type": content_type,
                        "size": content_length or len(body),
                        "md5": md5,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                    })
            idx = body_start + max(content_length, 1)
            if len(files) >= 50:
                break
        if len(files) >= 50:
            break
    return files


# ---------------------------------------------------------------------------
# Base64 payload detection
# ---------------------------------------------------------------------------

import base64 as _b64
import re as _re

_B64_PATTERN = _re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")


def _detect_base64_payloads(streams: dict) -> list[dict]:
    """Scan HTTP bodies and DNS-adjacent streams for base64-encoded payloads."""
    results: list[dict] = []
    seen: set[str] = set()

    for (src_ip, sport, dst_ip, dport), payload in streams.items():
        # Focus on HTTP and high-port streams
        if dport not in (80, 443, 8080, 8443, 8000, 8888) and sport not in (80, 443, 8080):
            continue
        data = bytes(payload)
        if len(data) < 60:
            continue

        for m in _B64_PATTERN.finditer(data):
            candidate = m.group()
            if len(candidate) < 40:
                continue
            try:
                decoded = _b64.b64decode(candidate, validate=True)
            except Exception:
                continue
            if len(decoded) < 20:
                continue

            # Check if decoded content looks interesting (has printable + non-printable mix
            # suggesting encoded binary, or starts with known script patterns)
            printable_ratio = sum(1 for b in decoded[:200] if 32 <= b < 127) / min(len(decoded), 200)
            is_script = decoded[:20].lower().startswith((
                b"powershell", b"cmd /c", b"bash ", b"#!/", b"import ",
                b"<script", b"function ", b"var ", b"eval(",
            ))
            is_binary = printable_ratio < 0.7
            if not is_script and not is_binary:
                continue

            preview = decoded[:80].decode("ascii", errors="replace")
            key = hashlib.md5(candidate[:100]).hexdigest()
            if key in seen:
                continue
            seen.add(key)
            results.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "encoded_length": len(candidate),
                "decoded_length": len(decoded),
                "type": "script" if is_script else "binary",
                "preview": preview[:120],
                "port": dport,
            })
            if len(results) >= 20:
                break
        if len(results) >= 20:
            break
    return results
