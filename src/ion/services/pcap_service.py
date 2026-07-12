"""PCAP file parser and network traffic analyzer."""

import collections
import hashlib
import io
import math
import re
import socket
import struct
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import dpkt


@dataclass
class Finding:
    category: str
    severity: str  # low, medium, high, critical
    title: str
    detail: str
    mitre: list = field(default_factory=list)  # v0.39.0: mapped ATT&CK technique IDs


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
    sport: int = 0
    dport: int = 0

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
    ja4_fingerprints: list = field(default_factory=list)
    ja4s_fingerprints: list = field(default_factory=list)
    hassh_fingerprints: list = field(default_factory=list)
    credential_captures: list = field(default_factory=list)
    smb_transfers: list = field(default_factory=list)
    kerberos_tickets: list = field(default_factory=list)
    http_files: list = field(default_factory=list)
    arp_anomalies: list = field(default_factory=list)
    base64_payloads: list = field(default_factory=list)
    network_graph: dict = field(default_factory=dict)
    # v0.39.0 enhanced analyzers
    tls_certificates: list = field(default_factory=list)
    os_fingerprints: list = field(default_factory=list)
    beacons: list = field(default_factory=list)
    host_profiles: list = field(default_factory=list)
    mitre_techniques: list = field(default_factory=list)  # deduped ATT&CK rollup

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


# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping (v0.39.0)
#
# Each PCAP finding category maps to one or more ATT&CK technique IDs so network
# evidence lands in the same taxonomy as the rest of ION's triage. The mapping
# is intentionally conservative (network-observable techniques only) and every
# ID is validated against `data/attack_techniques.json` at load time — an
# unknown ID is dropped rather than surfaced, so a catalogue refresh can never
# leave a dangling technique reference. Title-level refinements (e.g. a
# known-malware fingerprint) layer extra techniques on top of the category map.
# ---------------------------------------------------------------------------

_FINDING_MITRE: dict[str, list[str]] = {
    "Command & Control": ["T1071", "T1571"],
    "DGA Detection": ["T1568.002"],
    "DNS Tunneling": ["T1071.004", "T1572"],
    "DNS Anomaly": ["T1071.004"],
    "Data Exfiltration": ["T1048", "T1030"],
    "Cleartext Protocol": ["T1040"],
    "Credential Exposure": ["T1040"],
    "credential_capture": ["T1040"],
    "Suspicious Port": ["T1571"],
    "Reconnaissance": ["T1046"],
    "Network Anomaly": ["T1095"],
    "Suspicious User-Agent": ["T1071.001"],
    "TLS Certificate": ["T1573"],
    "tls_fingerprint": ["T1573", "T1071.001"],
    "file_extraction": ["T1105"],
    "Malware Signature": ["T1105"],
    "Suspicious File Transfer": ["T1105"],
    "Legacy SMB Protocol": ["T1021.002"],
    "Lateral Tool Transfer": ["T1570", "T1021.002"],
    "DCE/RPC Lateral Movement": ["T1021.003"],
    "DCE/RPC Activity": ["T1021.003"],
    "Protocol Tunneling": ["T1572", "T1071.004"],
    "Shellcode Detection": ["T1055", "T1027"],
    "PowerShell Abuse": ["T1059.001"],
    "ARP Spoofing": ["T1557.002"],
}

_ATTACK_CATALOGUE: Optional[dict] = None


def _load_attack_catalogue() -> dict:
    """Lazily load the ATT&CK technique catalogue (id → {name, tactic_ids}); {} on failure."""
    global _ATTACK_CATALOGUE
    if _ATTACK_CATALOGUE is None:
        try:
            import json
            from pathlib import Path
            path = Path(__file__).resolve().parents[1] / "data" / "attack_techniques.json"
            with open(path, encoding="utf-8") as fh:
                _ATTACK_CATALOGUE = {
                    t["id"]: {"name": t.get("name", ""), "tactic_ids": t.get("tactic_ids", [])}
                    for t in json.load(fh)
                }
        except Exception:
            _ATTACK_CATALOGUE = {}
    return _ATTACK_CATALOGUE


def _attach_mitre(findings: list[Finding]) -> None:
    """Populate each finding's ``mitre`` list from the category map + title refinements.

    Mutates findings in place. Only catalogue-valid technique IDs are kept.
    """
    catalogue = _load_attack_catalogue()
    for f in findings:
        # Start from any technique the detector attached itself (e.g. DCE/RPC maps
        # a specific interface UUID to its technique), then layer the category map.
        ids = list(getattr(f, "mitre", []) or []) + list(_FINDING_MITRE.get(f.category, []))
        # Title-level refinements: known-malware fingerprints / C2 certs imply an
        # encrypted C2 channel over a standard web protocol on top of the base map.
        title_l = f.title.lower()
        if "known-malware" in title_l or "cobalt strike" in title_l:
            ids += ["T1071.001", "T1573.002"]
        # Keep only catalogue-valid IDs (drop silently if the catalogue lacks one),
        # preserving order and de-duplicating.
        seen: set[str] = set()
        valid: list[str] = []
        for tid in ids:
            if tid in seen:
                continue
            if not catalogue or tid in catalogue:
                seen.add(tid)
                valid.append(tid)
        f.mitre = valid


def _build_mitre_summary(findings: list[Finding]) -> list[dict]:
    """Deduped ATT&CK rollup across all findings → [{id, name, tactic_ids}], sorted by ID."""
    catalogue = _load_attack_catalogue()
    ids: set[str] = set()
    for f in findings:
        ids.update(getattr(f, "mitre", []) or [])
    out = []
    for tid in sorted(ids):
        info = catalogue.get(tid, {})
        out.append({
            "id": tid,
            "name": info.get("name", ""),
            "tactic_ids": info.get("tactic_ids", []),
        })
    return out


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
    kerberos_udp: list[tuple] = []  # (src, dst, payload) for UDP/88 Kerberos (TCP is handled via streams)

    timestamps = []
    packet_count = 0
    arp_table: dict[str, set[str]] = {}  # MAC → set of IPs (for ARP spoofing detection)
    syn_sigs: dict[str, dict] = {}  # src_ip → first SYN signature (p0f-style OS fingerprint)
    conn_sizes: dict[tuple, list] = {}  # (src, dst, dport) → payload sizes (RITA data-consistency)

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
                # OS fingerprint: first SYN signature per source host (p0f-style)
                if src_ip not in syn_sigs:
                    try:
                        syn_sigs[src_ip] = _syn_signature(ip_pkt, tcp)
                    except Exception:
                        pass

            # RITA-style data-size consistency: payload sizes per connection tuple (bounded)
            if tcp.data:
                fk = (src_ip, dst_ip, tcp.dport)
                if fk in conn_sizes:
                    if len(conn_sizes[fk]) < 5000:
                        conn_sizes[fk].append(len(tcp.data))
                elif len(conn_sizes) < 20000:
                    conn_sizes[fk] = [len(tcp.data)]

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

            # Kerberos on UDP/88 (the classic transport). The TCP-stream ticket
            # extractor never sees these, so collect them for _detect_kerberos_udp.
            if (udp.dport == 88 or udp.sport == 88) and udp.data and len(kerberos_udp) < 500:
                kerberos_udp.append((src_ip, dst_ip, bytes(udp.data)))

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
    dcerpc_findings: list = []  # needs raw streams; produced here, merged in assembly
    dns_port_findings: list = []  # non-DNS traffic on port 53 (needs raw streams)
    try:
        buf.seek(0)
        streams, tls_hellos, tls_server_hellos, ssh_pkts = _reassemble_tcp_streams(buf, pcap_reader_cls)
        result.extracted_files = [f.to_dict() for f in _extract_files_from_streams(streams)]
        result.ja3_fingerprints = [j.to_dict() for j in _compute_ja3(tls_hellos)]
        result.ja3s_fingerprints = [j.to_dict() for j in _compute_ja3s(tls_server_hellos)]
        result.ja4_fingerprints = _compute_ja4(tls_hellos)
        result.ja4s_fingerprints = _compute_ja4s(tls_server_hellos)
        result.hassh_fingerprints = [h.to_dict() for h in _compute_hassh(ssh_pkts)]
        result.credential_captures = [c.to_dict() for c in _extract_credentials(streams)]
        result.smb_transfers = [s.to_dict() for s in _detect_smb(streams)]
        dcerpc_findings = _detect_dcerpc(streams)
        dns_port_findings = _detect_dns_port_abuse(streams)
        result.kerberos_tickets = _detect_kerberos(streams) + _detect_kerberos_udp(kerberos_udp)
        result.http_files = _extract_http_files(streams)
        result.base64_payloads = _detect_base64_payloads(streams)
        result.tls_certificates = _extract_tls_certificates(streams)
    except Exception:
        pass  # Non-fatal

    # v0.39.0 — OS fingerprints + RITA-style beacon scoring (each independently fail-safe)
    try:
        result.os_fingerprints = _compute_os_fingerprints(syn_sigs)
    except Exception:
        result.os_fingerprints = []
    try:
        result.beacons = _compute_beacon_scores(conn_times, conn_sizes)
    except Exception:
        result.beacons = []

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
    # Filter out common web assets — every web page transfers dozens of these
    # legitimately, so flagging them as "files extracted from traffic" is noise.
    # Real interest: executables, archives, scripts, office docs.
    _WEB_ASSET_EXTS = {
        "html", "htm", "css", "js", "mjs", "json", "xml", "svg",
        "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp",
        "woff", "woff2", "ttf", "otf", "eot",
        "mp4", "webm", "mp3", "wav",
    }
    notable_files = [
        f for f in result.extracted_files
        if (f.get("filename", "").rsplit(".", 1)[-1].lower() if "." in f.get("filename", "") else "")
        not in _WEB_ASSET_EXTS
    ]
    if notable_files:
        findings.append(Finding(
            category="file_extraction",
            severity="medium",
            title=f"{len(notable_files)} non-web file(s) extracted from traffic",
            detail=", ".join(f.get("filename", "?") for f in notable_files[:5]),
        ))
    if any(j.get("known_malware") for j in result.ja3_fingerprints):
        bad = [j for j in result.ja3_fingerprints if j.get("known_malware")]
        findings.append(Finding(
            category="tls_fingerprint",
            severity="high",
            title=f"{len(bad)} known-malware JA3 fingerprint(s) detected",
            detail=", ".join(f'{j["ja3_hash"][:12]}... ({j["known_malware"]})' for j in bad[:3]),
        ))
    if any(j.get("known_malware") for j in result.ja4_fingerprints):
        bad = [j for j in result.ja4_fingerprints if j.get("known_malware")]
        findings.append(Finding(
            category="tls_fingerprint",
            severity="high",
            title=f"{len(bad)} known-malware JA4 fingerprint(s) detected",
            detail=", ".join(f'{j["ja4"]} ({j["known_malware"]})' for j in bad[:3]),
        ))
    if result.credential_captures:
        findings.append(Finding(
            category="credential_capture",
            severity="critical",
            title=f"{len(result.credential_captures)} credential(s) captured from traffic",
            detail=", ".join(f'{c.get("protocol")}:{c.get("username","")}' for c in result.credential_captures[:5]),
        ))
    # SMB lateral-movement findings (SMB1 hygiene + executable-over-SMB). Additive,
    # fail-safe: smb_transfers / extracted_files are already dict-shaped here.
    try:
        findings.extend(_smb_findings(result.smb_transfers, result.extracted_files))
    except Exception:
        pass
    try:
        findings.extend(_arp_findings(result.arp_anomalies))
    except Exception:
        pass
    # DCE/RPC (MSRPC) lateral-movement binds (svcctl/WMI/atsvc/drsuapi). Computed
    # above where the raw streams are available; merged here.
    findings.extend(dcerpc_findings)
    findings.extend(dns_port_findings)
    # v0.39.0 — TLS certificate + RITA beacon findings (additive, fail-safe)
    try:
        findings.extend(_tls_cert_findings(result.tls_certificates))
    except Exception:
        pass
    try:
        findings.extend(_beacon_score_findings(result.beacons))
    except Exception:
        pass

    # v0.39.0 — map findings to MITRE ATT&CK techniques (fail-safe)
    try:
        _attach_mitre(findings)
        result.mitre_techniques = _build_mitre_summary(findings)
    except Exception:
        result.mitre_techniques = []

    result.findings = [asdict(f) for f in findings]
    result.verdict = _compute_verdict(findings)

    # Per-host rollup (display-only; depends on result.findings being populated)
    try:
        result.host_profiles = _build_host_profiles(result)
    except Exception:
        result.host_profiles = []

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


def _looks_like_real_file(ext: str, data: bytes) -> bool:
    """Reject chance magic-byte matches (e.g. 'MZ' or '#!' landing mid-stream in
    binary data). Carving keys off short magic numbers, so without a structural
    check a busy binary stream yields dozens of phantom files — measured 50/50
    false positives on a benign SMB torture-test capture. Formats with weak
    (2-3 byte) magic get validated; longer, low-collision magics are trusted."""
    if ext == "exe":  # DOS/PE: 'MZ' + e_lfanew pointer to a 'PE\0\0' signature
        if len(data) < 0x40 or data[:2] != b"MZ":
            return False
        try:
            e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
        except struct.error:
            return False
        return 0 < e_lfanew <= len(data) - 4 and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"
    if ext == "elf":  # ELF: magic + valid class (32/64-bit) + valid endianness
        return len(data) > 20 and data[:4] == b"\x7fELF" and data[4] in (1, 2) and data[5] in (1, 2)
    if ext == "script":  # shebang: '#!' + a printable interpreter path containing '/'
        line = data[2:130].split(b"\n", 1)[0]
        return bool(line) and all(32 <= c < 127 for c in line) and b"/" in line
    if ext == "class":  # Java class: 0xCAFEBABE + a plausible major version (rejects Mach-O fat)
        if len(data) < 8 or data[:4] != b"\xca\xfe\xba\xbe":
            return False
        try:
            major = struct.unpack(">H", data[6:8])[0]
        except struct.error:
            return False
        return 45 <= major <= 100
    if ext == "gz":  # gzip: magic + a known compression method byte (0x08 = deflate)
        return len(data) > 3 and data[:3] == b"\x1f\x8b\x08"
    # zip/pdf/doc/png/jpg/gif/rar/bz2 magics are 3-8 bytes and low-collision: accept.
    return True


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

                # Reject chance magic-byte matches that aren't structurally the
                # claimed format (short magics like MZ/#! collide constantly).
                if not _looks_like_real_file(ext, carved):
                    offset = pos + len(magic)
                    continue

                # MD5 used as a content fingerprint for dedup, never for security.
                md5 = hashlib.md5(carved, usedforsecurity=False).hexdigest()
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
                    sport=sport,
                    dport=dport,
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

# Known-malware JA4 client fingerprints. Intentionally operator-extensible
# and shipped empty: ION is air-gapped, so it can't auto-pull a JA4 threat
# feed, and hardcoding unverified hashes would create false positives. Add
# vetted JA4 → label entries here (e.g. from abuse.ch/ThreatFox JA4 exports).
_KNOWN_BAD_JA4: dict[str, str] = {}


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
    # JA3 fingerprint is canonically an MD5 hash of the TLS-handshake string;
    # the algorithm is interoperability-defined, not a security boundary.
    ja3_hash = hashlib.md5(ja3_str.encode(), usedforsecurity=False).hexdigest()

    return ja3_str, ja3_hash


# ---------------------------------------------------------------------------
# 2b. JA4 / JA4S TLS fingerprinting (FoxIO JA4+ — successor to JA3)
# ---------------------------------------------------------------------------
#
# JA4 is resistant to the TLS-extension randomisation that defeats JA3
# (Chrome/modern malware shuffle extension order), because it *sorts* the
# cipher and extension lists before hashing and adds ALPN. Computed from the
# same ClientHello/ServerHello bytes JA3 already collects. Hashing validated
# against the FoxIO reference worked examples (sha256, lowercase 4-char hex,
# truncated to 12). JA4H (HTTP) is intentionally not implemented here — its
# authoritative algorithm wasn't available to verify, and shipping a
# non-interoperable fingerprint would defeat the purpose.

_JA4_TLS_VERSION = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3",
    0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3",
}


def _is_grease(v: int) -> bool:
    return (v & 0x0f0f) == 0x0a0a


def _ja4_alpn(first_value: str) -> str:
    """First+last alphanumeric char of the first ALPN value, per spec."""
    if not first_value:
        return "00"
    a0, a1 = first_value[0], first_value[-1]
    return (a0 + a1) if (a0.isalnum() and a1.isalnum()) else "99"


def _parse_client_hello_ja4(data: bytes) -> str:
    """Compute the JA4 (TLS client) fingerprint, or '' on parse failure."""
    if len(data) < 44 or data[0] != 0x16 or data[5] != 0x01:
        return ""
    try:
        legacy_version = struct.unpack("!H", data[9:11])[0]
        offset = 43  # 11 (header) + 32 (random)
        sid_len = data[offset]
        offset += 1 + sid_len
        if offset + 2 > len(data):
            return ""
        cipher_len = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2
        ciphers = []
        for i in range(0, cipher_len, 2):
            if offset + i + 2 > len(data):
                break
            c = struct.unpack("!H", data[offset + i:offset + i + 2])[0]
            if not _is_grease(c):
                ciphers.append(c)
        offset += cipher_len
        if offset >= len(data):
            return ""
        comp_len = data[offset]
        offset += 1 + comp_len

        extensions: list[int] = []
        sig_algs: list[int] = []
        sni_present = False
        alpn_first = ""
        supported_versions: list[int] = []
        if offset + 2 <= len(data):
            ext_total = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2
            ext_end = min(offset + ext_total, len(data))
            while offset + 4 <= ext_end:
                etype = struct.unpack("!H", data[offset:offset + 2])[0]
                elen = struct.unpack("!H", data[offset + 2:offset + 4])[0]
                offset += 4
                edata = data[offset:offset + elen]
                offset += elen
                if _is_grease(etype):
                    continue
                extensions.append(etype)
                if etype == 0x0000:
                    sni_present = True
                elif etype == 0x000d and len(edata) >= 2:  # signature_algorithms
                    sa_len = struct.unpack("!H", edata[0:2])[0]
                    for j in range(2, min(2 + sa_len, len(edata)), 2):
                        if j + 2 <= len(edata):
                            sig_algs.append(struct.unpack("!H", edata[j:j + 2])[0])
                elif etype == 0x0010 and len(edata) >= 3:  # ALPN
                    fl = edata[2]
                    val = edata[3:3 + fl]
                    if val:
                        alpn_first = val.decode("ascii", "ignore")
                elif etype == 0x002b and len(edata) >= 1:  # supported_versions
                    sv_len = edata[0]
                    for j in range(1, min(1 + sv_len, len(edata)), 2):
                        if j + 2 <= len(edata):
                            v = struct.unpack("!H", edata[j:j + 2])[0]
                            if not _is_grease(v):
                                supported_versions.append(v)

        ver = max(supported_versions) if supported_versions else legacy_version
        ver2 = _JA4_TLS_VERSION.get(ver, "00")
        sni_c = "d" if sni_present else "i"
        cc = "{:02d}".format(min(len(ciphers), 99))
        ec = "{:02d}".format(min(len(extensions), 99))
        alpn = _ja4_alpn(alpn_first)
        ja4_a = f"t{ver2}{sni_c}{cc}{ec}{alpn}"

        cipher_hex = sorted("{:04x}".format(c) for c in ciphers)
        ja4_b = hashlib.sha256(",".join(cipher_hex).encode()).hexdigest()[:12] if cipher_hex else "000000000000"

        # ja4_c: extensions sorted (excl SNI 0x0000 + ALPN 0x0010), then
        # signature algorithms in original packet order, separated by "_".
        ext_for_c = sorted("{:04x}".format(e) for e in extensions if e not in (0x0000, 0x0010))
        sig_hex = ["{:04x}".format(s) for s in sig_algs]
        ja4_c = hashlib.sha256((",".join(ext_for_c) + "_" + ",".join(sig_hex)).encode()).hexdigest()[:12]
        return f"{ja4_a}_{ja4_b}_{ja4_c}"
    except Exception:
        return ""


def _parse_server_hello_ja4s(data: bytes) -> str:
    """Compute the JA4S (TLS server) fingerprint, or '' on parse failure."""
    if len(data) < 44 or data[0] != 0x16 or data[5] != 0x02:
        return ""
    try:
        legacy_version = struct.unpack("!H", data[9:11])[0]
        offset = 43
        sid_len = data[offset]
        offset += 1 + sid_len
        if offset + 3 > len(data):
            return ""
        chosen_cipher = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2
        offset += 1  # compression method
        extensions: list[int] = []
        alpn_first = ""
        supported_versions: list[int] = []
        if offset + 2 <= len(data):
            ext_total = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2
            ext_end = min(offset + ext_total, len(data))
            while offset + 4 <= ext_end:
                etype = struct.unpack("!H", data[offset:offset + 2])[0]
                elen = struct.unpack("!H", data[offset + 2:offset + 4])[0]
                offset += 4
                edata = data[offset:offset + elen]
                offset += elen
                if _is_grease(etype):
                    continue
                extensions.append(etype)
                if etype == 0x0010 and len(edata) >= 3:
                    fl = edata[2]
                    val = edata[3:3 + fl]
                    if val:
                        alpn_first = val.decode("ascii", "ignore")
                elif etype == 0x002b and len(edata) >= 2:
                    v = struct.unpack("!H", edata[0:2])[0]
                    if not _is_grease(v):
                        supported_versions.append(v)
        ver = max(supported_versions) if supported_versions else legacy_version
        ver2 = _JA4_TLS_VERSION.get(ver, "00")
        ec = "{:02d}".format(min(len(extensions), 99))
        alpn = _ja4_alpn(alpn_first)
        ja4s_a = f"t{ver2}{ec}{alpn}"
        cipher = "{:04x}".format(chosen_cipher)
        # JA4S extension hash uses server order (not sorted).
        ext_hex = ["{:04x}".format(e) for e in extensions]
        ja4s_c = hashlib.sha256(",".join(ext_hex).encode()).hexdigest()[:12] if ext_hex else "000000000000"
        return f"{ja4s_a}_{cipher}_{ja4s_c}"
    except Exception:
        return ""


def _compute_ja4(tls_hellos: list[dict]) -> list[dict]:
    """JA4 client fingerprints from collected ClientHello messages (deduped)."""
    out: list[dict] = []
    seen: set[str] = set()
    for hello in tls_hellos:
        ja4 = _parse_client_hello_ja4(hello["data"])
        if not ja4:
            continue
        key = f'{hello["src_ip"]}:{hello["dst_ip"]}:{ja4}'
        if key in seen:
            continue
        seen.add(key)
        sni = ""
        try:
            sni = _extract_tls_sni(hello["data"]) or ""
        except Exception:
            pass
        out.append({
            "ja4": ja4, "src_ip": hello["src_ip"], "dst_ip": hello["dst_ip"],
            "dst_port": hello.get("dst_port"), "sni": sni,
            "known_malware": _KNOWN_BAD_JA4.get(ja4, ""),
        })
    return out


def _compute_ja4s(tls_server_hellos: list[dict]) -> list[dict]:
    """JA4S server fingerprints from collected ServerHello messages (deduped)."""
    out: list[dict] = []
    seen: set[str] = set()
    for hello in tls_server_hellos:
        ja4s = _parse_server_hello_ja4s(hello["data"])
        if not ja4s:
            continue
        key = f'{hello["src_ip"]}:{hello["dst_ip"]}:{ja4s}'
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "ja4s": ja4s, "src_ip": hello["src_ip"], "dst_ip": hello["dst_ip"],
            "src_port": hello.get("src_port"),
        })
    return out


# ---------------------------------------------------------------------------
# 2c. TLS certificate analysis (v0.39.0)
#
# The TLS Certificate handshake message (type 0x0b) is normally larger than one
# TCP segment, so it fragments across both TCP segments AND TLS records. We walk
# the *reassembled* server→client stream's record layer, concatenate handshake
# bytes across records, locate the Certificate message, carve the leaf DER, and
# parse it with `cryptography` (a project dependency, imported lazily so a build
# without it degrades gracefully rather than failing import).
# ---------------------------------------------------------------------------

# Cobalt Strike's default HTTPS beacon ships a self-signed cert with this exact
# serial / CN — a high-confidence C2 tell. Lowercased hex serial → label.
_KNOWN_BAD_CERT_SERIALS = {
    "8bb00ee": "Cobalt Strike default certificate",
}
_KNOWN_BAD_CERT_CN = {
    "major cobalt strike": "Cobalt Strike default certificate",
}


def _collect_handshake_bytes(data: bytes) -> bytes:
    """Concatenate the bodies of all TLS handshake records (type 0x16) in a stream.

    Handshake messages can span multiple TLS records, so we reassemble the
    handshake byte-stream independently of record framing.
    """
    out = bytearray()
    off = 0
    n = len(data)
    while off + 5 <= n:
        rec_type = data[off]
        rec_len = int.from_bytes(data[off + 3:off + 5], "big")
        if rec_len == 0 or rec_len > 0x4000 + 2048:  # max TLS record + slack
            break
        body = data[off + 5:off + 5 + rec_len]
        if len(body) < rec_len:
            out.extend(body)  # truncated final record — keep what we have
            break
        if rec_type == 0x16:  # handshake
            out.extend(body)
        elif rec_type not in (0x14, 0x16):  # ChangeCipherSpec(0x14) is interleaved; anything else = encrypted
            break
        off += 5 + rec_len
    return bytes(out)


def _find_handshake_msg(hs: bytes, msg_type: int) -> bytes:
    """Locate a handshake message of the given type in a handshake byte-stream."""
    p = 0
    n = len(hs)
    while p + 4 <= n:
        mtype = hs[p]
        mlen = int.from_bytes(hs[p + 1:p + 4], "big")
        if mtype == msg_type:
            return hs[p:p + 4 + mlen]
        p += 4 + mlen
    return b""


def _first_cert_der(cert_msg: bytes) -> bytes:
    """Extract the leaf (first) certificate DER from a Certificate handshake message."""
    body = cert_msg[4:]  # strip 1-byte type + 3-byte length

    def _try(b: bytes) -> bytes:
        # certificate_list: total_len(3) + [cert_len(3) + cert_der]...
        if len(b) < 6:
            return b""
        total = int.from_bytes(b[:3], "big")
        clen = int.from_bytes(b[3:6], "big")
        if 0 < clen <= len(b) - 6 and clen <= total:
            return b[6:6 + clen]
        return b""

    der = _try(body)
    if der:
        return der
    # TLS 1.3 Certificate prepends a certificate_request_context (1-byte length + context)
    if body:
        ctx_len = body[0]
        return _try(body[1 + ctx_len:])
    return b""


def _parse_x509(der: bytes) -> Optional[dict]:
    """Parse a DER certificate into a summary dict (None if cryptography is unavailable/parse fails)."""
    try:
        from cryptography import x509
    except Exception:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None

    def _name(n) -> str:
        try:
            return n.rfc4514_string()
        except Exception:
            return str(n)

    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        pass

    subject = _name(cert.subject)
    issuer = _name(cert.issuer)
    validity_days = max(0, (not_after - not_before).days)
    return {
        "subject": subject,
        "issuer": issuer,
        "self_signed": subject == issuer,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "validity_days": validity_days,
        "serial": format(cert.serial_number, "x"),
        "sans": sans[:10],
        "sig_algorithm": getattr(getattr(cert, "signature_algorithm_oid", None), "_name", ""),
    }


# Bounds for untrusted-PCAP TLS parsing: a leaf cert handshake fits easily in
# 64 KB, so scanning the full (up to 10 MB) stream just hands an attacker free
# CPU. Cap both the per-stream scan window and the total certs processed.
_MAX_TLS_CERTS = 50
_TLS_HANDSHAKE_SCAN_BYTES = 64 * 1024


def _extract_tls_certificates(streams: dict) -> list[dict]:
    """Carve and parse the leaf X.509 certificate from each TLS server stream (deduped by serial)."""
    certs: list[dict] = []
    seen: set[str] = set()
    for (src_ip, sport, dst_ip, dport), payload in streams.items():
        if len(certs) >= _MAX_TLS_CERTS:
            break
        data = bytes(payload[:_TLS_HANDSHAKE_SCAN_BYTES])
        if len(data) < 16 or data[0] != 0x16:
            continue
        try:
            hs = _collect_handshake_bytes(data)
            cert_msg = _find_handshake_msg(hs, 0x0b)
            if not cert_msg:
                continue
            der = _first_cert_der(cert_msg)
            if not der:
                continue
            info = _parse_x509(der)
        except Exception:
            continue
        if not info:
            continue
        if info["serial"] in seen:
            continue
        seen.add(info["serial"])
        info["server_ip"] = src_ip
        info["server_port"] = sport
        info["client_ip"] = dst_ip
        certs.append(info)
    return certs


def _tls_cert_findings(certs: list[dict]) -> list[Finding]:
    """Findings from parsed TLS certificates: known-bad C2 certs, self-signed, expired, long validity."""
    findings: list[Finding] = []
    self_signed = 0
    for c in certs:
        serial = (c.get("serial") or "").lower()
        subject_cn = (c.get("subject") or "").lower()
        issuer_cn = (c.get("issuer") or "").lower()
        label = _KNOWN_BAD_CERT_SERIALS.get(serial, "")
        if not label:
            for cn, lbl in _KNOWN_BAD_CERT_CN.items():
                if cn in subject_cn or cn in issuer_cn:
                    label = lbl
                    break
        if label:
            findings.append(Finding(
                category="TLS Certificate",
                severity="critical",
                title=f"Known-malicious TLS certificate: {label}",
                detail=f"Server {c.get('server_ip')} presented a certificate matching {label} "
                       f"(serial {serial}, subject {c.get('subject')}). Strong C2 indicator.",
            ))
            continue  # don't also flag it as merely self-signed
        if c.get("self_signed"):
            self_signed += 1
        # Suspiciously long validity (>5 years) is common for C2 / self-signed infra
        if c.get("validity_days", 0) > 365 * 5 and c.get("self_signed"):
            findings.append(Finding(
                category="TLS Certificate",
                severity="low",
                title=f"Self-signed certificate with {c['validity_days'] // 365}-year validity",
                detail=f"Server {c.get('server_ip')} ({c.get('subject')}) uses a long-lived self-signed cert.",
            ))
    if self_signed:
        findings.append(Finding(
            category="TLS Certificate",
            severity="medium",
            title=f"{self_signed} self-signed TLS certificate(s) observed",
            detail="Self-signed certificates on observed TLS servers can indicate internal services "
                   "or attacker-controlled C2 infrastructure not backed by a public CA.",
        ))
    return findings


# ---------------------------------------------------------------------------
# 2d. p0f-style passive OS fingerprinting (v0.39.0)
# ---------------------------------------------------------------------------

def _syn_signature(ip_pkt, tcp) -> dict:
    """Capture the OS-discriminating fields of a TCP SYN packet."""
    ttl = getattr(ip_pkt, "ttl", None)
    if ttl is None:
        ttl = getattr(ip_pkt, "hlim", 0)  # IPv6 hop limit
    mss = None
    wscale = None
    sack = False
    tsval = False
    opt_order: list[int] = []
    try:
        for otype, odata in dpkt.tcp.parse_opts(tcp.opts):
            opt_order.append(otype)
            if otype == dpkt.tcp.TCP_OPT_MSS and len(odata) == 2:
                mss = struct.unpack("!H", odata)[0]
            elif otype == dpkt.tcp.TCP_OPT_WSCALE and len(odata) >= 1:
                wscale = odata[0]
            elif otype == dpkt.tcp.TCP_OPT_SACKOK:
                sack = True
            elif otype == dpkt.tcp.TCP_OPT_TIMESTAMP:
                tsval = True
    except Exception:
        pass
    df = bool(getattr(ip_pkt, "df", 0))  # IP.df property (IP.off is deprecated in dpkt)
    return {
        "ttl": ttl, "window": getattr(tcp, "win", 0), "mss": mss,
        "wscale": wscale, "sack": sack, "tsval": tsval,
        "opt_order": opt_order, "df": df,
    }


def _guess_os(sig: dict) -> tuple[str, str]:
    """Map a SYN signature to an OS family guess + short evidence string."""
    ttl = sig.get("ttl") or 0
    win = sig.get("window") or 0
    wscale = sig.get("wscale")
    # Round observed TTL up to the nearest common initial TTL (hops only decrease it).
    init = next((t for t in (64, 128, 255) if ttl <= t), 0) if ttl else 0
    if init == 128:
        return "Windows", f"initial TTL≈128 (obs {ttl}), win={win}"
    if init == 64:
        if win == 65535 and wscale == 6:
            return "macOS / iOS", f"initial TTL≈64 (obs {ttl}), win=65535, wscale=6"
        ev = f"initial TTL≈64 (obs {ttl}), win={win}"
        if wscale is not None:
            ev += f", wscale={wscale}"
        return "Linux / Unix", ev
    if init == 255:
        return "Network device / BSD / Solaris", f"initial TTL≈255 (obs {ttl})"
    return "Unknown", f"TTL={ttl}, win={win}"


def _compute_os_fingerprints(syn_sigs: dict) -> list[dict]:
    """Produce a passive OS guess per source host from captured SYN signatures."""
    out: list[dict] = []
    for ip, sig in syn_sigs.items():
        os_name, evidence = _guess_os(sig)
        out.append({
            "ip": ip, "os": os_name, "evidence": evidence,
            "ttl": sig.get("ttl"), "window": sig.get("window"), "mss": sig.get("mss"),
        })
    out.sort(key=lambda o: o["ip"])
    return out


# ---------------------------------------------------------------------------
# 2e. RITA-style beacon scoring (v0.39.0)
#
# Beyond the simple coefficient-of-variation check in `_detect_beaconing`, this
# scores each connection tuple on the *dispersion* and *skew* of both its
# inter-arrival intervals and its payload sizes — the four signals RITA combines.
# A near-1.0 score means metronome-regular, uniform-sized connections: the
# hallmark of automated C2 even when individual intervals are long.
# ---------------------------------------------------------------------------

def _madm_score(values: list) -> float:
    """1.0 = zero dispersion (all equal); → 0 as the median absolute deviation grows."""
    if len(values) < 2:
        return 0.0
    s = sorted(values)
    median = s[len(s) // 2]
    if median == 0:
        return 0.0
    devs = sorted(abs(v - median) for v in values)
    madm = devs[len(devs) // 2]
    return max(0.0, 1.0 - (madm / median))


def _bowley_skew(values: list) -> float:
    """Quartile (Bowley) skewness in [-1, 1]; 0 = symmetric."""
    s = sorted(values)
    n = len(s)
    if n < 4:
        return 0.0
    q1 = s[n // 4]
    q2 = s[n // 2]
    q3 = s[(3 * n) // 4]
    denom = q3 - q1
    if denom == 0:
        return 0.0
    return (q1 + q3 - 2 * q2) / denom


def _compute_beacon_scores(conn_times: dict, conn_sizes: dict) -> list[dict]:
    """Score each connection tuple for beaconing using interval + size regularity."""
    out: list[dict] = []
    for (src, dst, port), times in conn_times.items():
        if len(times) < 5:
            continue
        ts = sorted(times)
        intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
        if not intervals:
            continue
        mean_int = sum(intervals) / len(intervals)
        variance = sum((x - mean_int) ** 2 for x in intervals) / len(intervals)
        cv = (variance ** 0.5 / mean_int) if mean_int > 0 else float("inf")
        i_score = (_madm_score(intervals) + (1.0 - abs(_bowley_skew(intervals)))) / 2

        sizes = conn_sizes.get((src, dst, port), [])
        if len(sizes) >= 3:
            s_score = (_madm_score(sizes) + (1.0 - abs(_bowley_skew(sizes)))) / 2
            score = round((i_score * 0.6) + (s_score * 0.4), 3)
        else:
            s_score = None
            score = round(i_score, 3)

        out.append({
            "src": src, "dst": dst, "port": port,
            "connections": len(times),
            "interval_s": round(mean_int, 1),
            "cv": round(cv, 3) if cv != float("inf") else None,
            "interval_score": round(i_score, 3),
            "size_score": round(s_score, 3) if s_score is not None else None,
            "score": score,
        })
    out.sort(key=lambda b: b["score"], reverse=True)
    return out


def _beacon_score_findings(beacons: list[dict]) -> list[Finding]:
    """Emit a finding for high-scoring beacons the simple CV detector would miss.

    `_detect_beaconing` already fires for very tight cadence (CV < 0.15); here we
    catch beacons whose *combined* interval+size regularity is high even though
    their raw interval CV is looser — without double-reporting the tight ones.
    """
    findings: list[Finding] = []
    for b in beacons:
        cv = b.get("cv")
        if b["score"] >= 0.9 and b["connections"] >= 6 and b["interval_s"] >= 1 \
                and (cv is None or cv >= 0.15):
            size_note = (f", size-regularity={b['size_score']}" if b.get("size_score") is not None else "")
            findings.append(Finding(
                category="Command & Control",
                severity="high",
                title=f"Beaconing (regularity score {b['score']}): {b['src']} -> {b['dst']}:{b['port']}",
                detail=f"{b['connections']} connections every ~{b['interval_s']}s with high combined "
                       f"interval+size regularity (score {b['score']}{size_note}). RITA-style scoring "
                       f"flags this as likely automated C2 even though the raw interval variance is moderate.",
            ))
    return findings


# ---------------------------------------------------------------------------
# 2f. Per-host profile rollup (v0.39.0, display-only)
# ---------------------------------------------------------------------------

def _build_host_profiles(result: PcapResult) -> list[dict]:
    """Aggregate per-IP intelligence (OS, role, fingerprints, SNIs, beacons, findings)."""
    profiles: dict[str, dict] = {}

    def prof(ip: str) -> dict:
        return profiles.setdefault(ip, {
            "ip": ip, "os": "", "os_evidence": "", "role": set(),
            "sent": 0, "received": 0, "ja4": [], "ja4s": [],
            "snis": set(), "beacons": 0, "findings": 0,
        })

    for b in result.data_transfer.get("by_ip", []):
        p = prof(b["ip"])
        p["sent"] = b.get("sent", 0)
        p["received"] = b.get("received", 0)
    for o in result.os_fingerprints:
        p = prof(o["ip"])
        p["os"] = o["os"]
        p["os_evidence"] = o["evidence"]
    for j in result.ja4_fingerprints:
        p = prof(j["src_ip"])
        p["role"].add("client")
        if j["ja4"] not in p["ja4"]:
            p["ja4"].append(j["ja4"])
        if j.get("sni"):
            p["snis"].add(j["sni"])
    for j in result.ja4s_fingerprints:
        p = prof(j["src_ip"])
        p["role"].add("server")
        if j["ja4s"] not in p["ja4s"]:
            p["ja4s"].append(j["ja4s"])
    for b in result.beacons:
        prof(b["src"])["beacons"] += 1

    # Count findings whose text mentions each host
    for f in result.findings:
        text = f.get("title", "") + " " + f.get("detail", "")
        for ip in profiles:
            if ip and ip in text:
                profiles[ip]["findings"] += 1

    out = []
    for p in profiles.values():
        p["role"] = sorted(p["role"]) or ["client"]
        p["snis"] = sorted(p["snis"])[:10]
        out.append(p)
    out.sort(key=lambda p: p["sent"] + p["received"], reverse=True)
    return out[:30]


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
        # Conversations are emitted as {"pair": "<ip_a> <-> <ip_b>", "bytes": n}
        # (see parse_pcap; the key is tuple(sorted([src_ip, dst_ip])) — bare
        # IPs, no ports). Parse the pair rather than reading non-existent
        # src/dst/proto/packets keys, which left the graph permanently empty.
        pair = conv.get("pair", "")
        if " <-> " not in pair:
            continue
        src_ip, dst_ip = (p.strip() for p in pair.split(" <-> ", 1))
        if not src_ip or not dst_ip:
            continue

        is_private_src = _is_private(src_ip)
        is_private_dst = _is_private(dst_ip)

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
            # Only byte volume is tracked per conversation (no proto/packet
            # counts), so derive the label and edge width from bytes.
            byte_count = conv.get("bytes", 0)
            if byte_count > 1024 * 1024:
                label = f"{byte_count // (1024*1024)}MB"
            elif byte_count > 1024:
                label = f"{byte_count // 1024}KB"
            else:
                label = f"{byte_count}B"
            edges.append({
                "from": src_ip,
                "to": dst_ip,
                "label": label,
                "title": f"{src_ip} <-> {dst_ip}: {byte_count} bytes",
                "width": min(max(1, byte_count // (64 * 1024)), 6),
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
                detail="High proportion of IKE sessions explicitly deleted. May indicate "
                       "unstable VPN tunnels or DPD failures.",
            ))

    # Summary: all internal and healthy
    int_established = total - len(ext_established) - len(ext_failed) - len(ext_probing) \
        - len(int_no_response) - len(int_failed) - len(int_incomplete)
    if total > 0 and not findings:
        findings.append(Finding(
            category="ISAKMP/IKE",
            severity="low",
            title=f"IKE: {int_established}/{total} internal session(s) established normally",
            detail="All IKE/IPsec negotiations are between internal IPs and completed successfully. "
                   "No unauthorized external tunnels detected.",
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
                detail="Excessive unique subdomains under a single domain is a strong DNS tunneling indicator.",
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
                detail="High query volume to a single domain with multiple subdomains may indicate C2 beaconing over DNS.",
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

    # Web/DNS ports: visiting many web hosts is normal browsing — but a real
    # scanner sweeping for vulnerable web servers will hit hundreds of hosts.
    # Use a higher threshold for these ports rather than skipping entirely.
    WEB_FANOUT_PORTS = {53, 80, 123, 443, 8080, 8443}
    for (src, port), dsts in src_port_dsts.items():
        threshold = 50 if port in WEB_FANOUT_PORTS else 10
        if len(dsts) > threshold:
            findings.append(Finding(
                category="Reconnaissance",
                severity="medium",
                title=f"Horizontal scan: {src} port {port} -> {len(dsts)} hosts",
                detail=f"Source {src} connected to {len(dsts)} unique hosts on port {port}.",
            ))

    return findings


def _dga_score(sld: str) -> float:
    """Combined DGA likelihood in [0, 1] from entropy, digit ratio, vowel ratio, consonant runs.

    Entropy alone over-flags long-but-pronounceable CDN/ad-tech subdomains; folding in
    digit density, vowel scarcity, and consonant-run length sharpens DGA recall while
    keeping benign high-entropy names below threshold.
    """
    if not sld:
        return 0.0
    s = sld.lower()
    length = len(s)
    entropy = _shannon_entropy(s)
    digits = sum(c.isdigit() for c in s)
    vowels = sum(c in "aeiou" for c in s)
    digit_ratio = digits / length
    vowel_ratio = vowels / length if length else 0.0
    run = best = 0
    for c in s:
        if c.isalpha() and c not in "aeiou":
            run += 1
            best = max(best, run)
        else:
            run = 0
    score = 0.0
    if entropy > 3.5:
        score += 0.4
    elif entropy > 3.0:
        score += 0.2
    if digit_ratio > 0.3:
        score += 0.2
    if vowel_ratio < 0.25 and length >= 7:
        score += 0.2
    if best >= 5:
        score += 0.2
    return min(score, 1.0)


def _detect_dga(dns_counter: collections.Counter) -> list[Finding]:
    findings = []
    high_entropy_domains = []
    dga_hits = []  # (query, entropy, score) for combined-score-qualified domains
    for query in dns_counter:
        parts = query.split(".")
        if len(parts) >= 2:
            sld = parts[-2]  # second-level domain
            if len(sld) >= 6:
                entropy = _shannon_entropy(sld)
                if entropy > 3.5:
                    high_entropy_domains.append((query, round(entropy, 2)))
                if _dga_score(sld) >= 0.7:
                    dga_hits.append((query, round(entropy, 2)))

    # A cluster of multi-signal DGA hits is high-confidence — prefer it over the
    # entropy-only aggregate so digit-heavy / vowel-poor DGA (low raw entropy) is caught.
    if len(dga_hits) > 3:
        examples = dga_hits[:5]
        findings.append(Finding(
            category="DGA Detection",
            severity="high",
            title=f"Possible DGA: {len(dga_hits)} algorithmically-generated domains",
            detail=f"Multiple DNS queries score high on combined randomness signals (entropy, digit ratio, "
                   f"vowel scarcity, consonant runs), suggesting Domain Generation Algorithm activity. "
                   f"Examples: {', '.join(f'{d} (H={e})' for d, e in examples)}",
        ))
    elif len(high_entropy_domains) > 3:
        examples = high_entropy_domains[:5]
        findings.append(Finding(
            category="DGA Detection",
            severity="high",
            title=f"Possible DGA: {len(high_entropy_domains)} high-entropy domains",
            detail=f"Multiple DNS queries with high randomness in the domain name suggest Domain Generation "
                   f"Algorithm activity. Examples: {', '.join(f'{d} (H={e})' for d, e in examples)}",
        ))
    elif high_entropy_domains:
        # Drop per-domain severity from medium (10) → low (3): a single CDN/ad-tech
        # subdomain (e.g. `amch.questionmarket.com` H=3.52) shouldn't push a benign
        # PCAP over the 50-point threshold, but we still flag for visibility.
        for domain, entropy in high_entropy_domains:
            findings.append(Finding(
                category="DGA Detection",
                severity="low",
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
    n_crit = sum(1 for f in findings if f.severity == "critical")
    n_high = sum(1 for f in findings if f.severity == "high")

    # Deduplicate reasons by category
    reasons = []
    seen_cats = set()
    for f in sorted(findings, key=lambda x: SEVERITY_WEIGHTS.get(x.severity, 0), reverse=True):
        if f.category not in seen_cats and len(reasons) < 5:
            reasons.append(f.title)
            seen_cats.add(f.category)

    # Severity-aware three-band verdict. A single high-severity finding (port
    # scan, DNS tunnel, executable staged over SMB) must escalate out of
    # "benign" even though its raw score (25) sits below the 50-pt investigation
    # cliff — otherwise a genuine lateral-movement signal reads as clean. The
    # cliff still governs medium/low accumulation, and any critical or a
    # cumulative score ≥ 50 goes straight to full investigation.
    if n_crit >= 1 or score >= 50:
        return {
            "label": "Needs Investigation",
            "confidence": min(95, 50 + score),
            "reasons": reasons,
            "score": score,
            "finding_count": len(findings),
        }
    if n_high >= 1:
        return {
            "label": "Elevated",
            "confidence": min(90, 60 + score),
            "reasons": reasons,
            "score": score,
            "finding_count": len(findings),
        }
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
    # JA3S fingerprint MD5 is interoperability-defined (same as JA3 above).
    ja3s_hash = hashlib.md5(ja3s_str.encode(), usedforsecurity=False).hexdigest()
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
    # HASSH fingerprint MD5 is interoperability-defined like JA3/JA3S.
    hassh_hash = hashlib.md5(hassh_str.encode(), usedforsecurity=False).hexdigest()
    return hassh_str, hassh_hash


# ---------------------------------------------------------------------------
# SMB file transfer detection
# ---------------------------------------------------------------------------

def _smb2_create_name(data: bytes, pos: int) -> str:
    """Extract the target path from an SMB2 CREATE *request* at header offset ``pos``.

    Layout (offsets from the SMB2 header start): Flags at +16 (bit 0 set = a
    response, which carries a FileId not a name); the CREATE request body begins
    at +64 with StructureSize 57, and NameOffset/NameLength live at +108/+110.
    The name itself is UTF-16LE at header-relative NameOffset. Returns "" on any
    malformed/short/response PDU rather than raising."""
    try:
        flags = struct.unpack("<I", data[pos + 16:pos + 20])[0]
        if flags & 0x00000001:  # SMB2_FLAGS_SERVER_TO_REDIR → response
            return ""
        if struct.unpack("<H", data[pos + 64:pos + 66])[0] != 57:  # CREATE req StructureSize
            return ""
        name_off = struct.unpack("<H", data[pos + 108:pos + 110])[0]
        name_len = struct.unpack("<H", data[pos + 110:pos + 112])[0]
        if not (0 < name_len <= 1024) or pos + name_off + name_len > len(data):
            return ""
        name = data[pos + name_off:pos + name_off + name_len].decode("utf-16-le", "replace")
        return name.replace("\x00", "").strip()
    except (struct.error, IndexError):
        return ""


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
                    fname = _smb2_create_name(data, pos) if cmd == 0x0005 else ""
                    detail = f"SMB2 {cmd_name} detected on port {dport}"
                    if fname:
                        detail += f" — target: {fname}"
                    results.append(SMBTransfer(
                        src_ip=src_ip, dst_ip=dst_ip,
                        command=cmd_name,
                        filename=fname,
                        detail=detail,
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


def _arp_findings(arp_anomalies: list[dict]) -> list[Finding]:
    """Turn detected ARP anomalies (a MAC claiming multiple IPs) into findings.

    The anomaly is detected during parsing and stashed on ``arp_anomalies`` but,
    like SMB transfers, was never surfaced in the verdict. One MAC answering for
    many IPs is the ARP-spoofing / MITM signature (T1557.002)."""
    findings: list[Finding] = []
    for a in arp_anomalies:
        ips = a.get("ips", [])
        findings.append(Finding(
            category="ARP Spoofing",
            severity=a.get("severity", "medium"),
            title=f"ARP spoofing: MAC {a.get('mac')} claims {len(ips)} IPs",
            detail=a.get("detail", "") + (f" ({', '.join(ips[:6])}{'...' if len(ips) > 6 else ''})" if ips else ""),
        ))
    return findings


# Extensions representing directly executable / script payloads. A file of one
# of these types moving over an SMB file-share port is the classic lateral tool
# transfer pattern (staging a payload on a remote host before executing it), so
# it warrants a finding well above a generic file carve.
_SMB_EXEC_EXTS = {"exe", "elf", "dll", "class", "script"}
_SMB_PORTS = (445, 139)


def _smb_findings(smb_transfers: list[dict], extracted_files: list[dict]) -> list[Finding]:
    """Turn SMB evidence into findings (SMB1 hygiene + executable-over-SMB lateral transfer)."""
    findings: list[Finding] = []

    # Legacy SMB1 — deprecated, weak auth, EternalBlue/MS17-010 vector.
    smb1 = [t for t in smb_transfers if t.get("command") == "SMB1"]
    if smb1:
        pairs = sorted({f'{t.get("src_ip")} -> {t.get("dst_ip")}' for t in smb1})
        findings.append(Finding(
            category="Legacy SMB Protocol",
            severity="medium",
            title=f"Legacy SMB1 traffic detected ({len(pairs)} host pair(s))",
            detail="SMB1/CIFS is deprecated and vulnerable (e.g. EternalBlue/MS17-010). "
                   f"Observed between: {', '.join(pairs[:5])}"
                   + (f" ... and {len(pairs) - 5} more" if len(pairs) > 5 else ""),
        ))

    # Executable / script carved from an SMB file-share stream = lateral tool transfer.
    exe_over_smb = []
    for f in extracted_files:
        if f.get("dport") in _SMB_PORTS or f.get("sport") in _SMB_PORTS:
            fname = f.get("filename", "")
            ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
            if ext in _SMB_EXEC_EXTS:
                exe_over_smb.append(f)
    if exe_over_smb:
        names = ", ".join(f.get("filename", "?") for f in exe_over_smb[:5])
        findings.append(Finding(
            category="Lateral Tool Transfer",
            severity="high",
            title=f"Executable transferred over SMB: {len(exe_over_smb)} file(s)",
            detail=f"Executable/script payload(s) staged over SMB (port 445/139): {names}. "
                   "Common lateral-movement pattern (e.g. PsExec-style tool staging).",
        ))

    return findings


# ---------------------------------------------------------------------------
# DCE/RPC (MSRPC) interface detection — lateral movement / remote execution
# ---------------------------------------------------------------------------
#
# A bind to certain management interfaces over MSRPC (port 135 endpoint mapper,
# or 445/139 named pipes) is the on-the-wire signature of the tools SOC teams
# care about: PsExec (svcctl), wmiexec (IWbemServices), schtasks/at (task
# scheduler), and DCSync (drsuapi). The endpoint mapper itself is routine, so
# it is surfaced only as low-severity context. Detection keys off the 16-byte
# interface UUID — a full-UUID match alongside a DCE/RPC bind marker makes false
# positives on random binary data effectively impossible.

_DCERPC_INTERFACES: dict[str, tuple] = {
    # uuid                                   (name, severity, [mitre techniques])
    "367abb81-9844-35f1-ad32-98f038001003": ("svcctl (Service Control Manager)", "high", ["T1569.002"]),
    "86d35949-83c9-4044-b424-db363231fd0c": ("ITaskSchedulerService", "high", ["T1053.005"]),
    "1ff70682-0a51-30e8-076d-740be8cee98b": ("atsvc (Task Scheduler)", "high", ["T1053.005"]),
    "9556dc99-828c-11cf-a37e-00aa003240c7": ("IWbemServices (WMI)", "high", ["T1047"]),
    "e3514235-4b06-11d1-ab04-00c04fc2dcd2": ("drsuapi (Directory Replication / DCSync)", "critical", ["T1003.006"]),
    # Recon/enumeration interfaces below are used constantly by benign Windows file
    # sharing (net view, share access, LSA lookups), so they are surfaced only as
    # low-severity context — real breadth/volume analysis would be needed to escalate.
    "12345778-1234-abcd-ef00-0123456789ac": ("samr (SAM account enumeration)", "low", ["T1087.002"]),
    "12345778-1234-abcd-ef00-0123456789ab": ("lsarpc (LSA policy)", "low", ["T1482"]),
    "4b324fc8-1670-01d3-1278-5a47bf6ee188": ("srvsvc (share enumeration)", "low", ["T1135"]),
    "e1af8308-5d1f-11c9-91a4-08002b14a0fa": ("epmapper (endpoint mapper)", "low", ["T1046"]),
}

# Precompute little-endian UUID bytes (DCE/RPC wire format) → (uuid, name, sev, mitre).
_DCERPC_IFACE_BYTES: dict[bytes, tuple] = {
    uuid.UUID(u).bytes_le: (u, name, sev, mitre)
    for u, (name, sev, mitre) in _DCERPC_INTERFACES.items()
}

_DCERPC_PORTS = (135, 139, 445)


def _detect_dcerpc(streams: dict) -> list[Finding]:
    """Flag DCE/RPC binds to management interfaces used for lateral movement / RCE."""
    # uuid_str -> [name, severity, mitre, {(src, dst)}]
    hits: dict[str, list] = {}
    for (src_ip, sport, dst_ip, dport), payload in streams.items():
        # No port filter: WMI (IWbemServices) and DCSync (drsuapi) negotiate a
        # DYNAMIC high port via the endpoint mapper, so the interface bind is not
        # on 135/445. The bind marker + a full 16-byte known-interface UUID make
        # false positives on non-RPC streams effectively impossible regardless of port.
        data = bytes(payload)
        # Require a DCE/RPC bind / alter-context marker before trusting a UUID hit.
        if b"\x05\x00\x0b" not in data and b"\x05\x00\x0e" not in data:
            continue
        for ub, (uuid_str, name, sev, mitre) in _DCERPC_IFACE_BYTES.items():
            if ub in data:
                rec = hits.setdefault(uuid_str, [name, sev, mitre, set()])
                rec[3].add((src_ip, dst_ip))

    findings: list[Finding] = []
    for uuid_str, (name, sev, mitre, pairs) in hits.items():
        pair_list = sorted(f"{s} -> {d}" for s, d in pairs)
        category = "DCE/RPC Lateral Movement" if sev in ("high", "critical") else "DCE/RPC Activity"
        f = Finding(
            category=category,
            severity=sev,
            title=f"DCE/RPC bind to {name}",
            detail=f"Remote {name} interface accessed over MSRPC (port 135/445) between "
                   f"{', '.join(pair_list[:5])}. Remote use of this interface is associated "
                   "with lateral movement / remote execution.",
        )
        f.mitre = list(mitre)  # interface-specific technique; merged in _attach_mitre
        findings.append(f)
    return findings


# ---------------------------------------------------------------------------
# Kerberos ticket detection
# ---------------------------------------------------------------------------

# Kerberos ASN.1 DER application tags: AS-REQ [APPLICATION 10]=0x6a,
# AS-REP=0x6b, TGS-REQ [12]=0x6c, TGS-REP=0x6d.
_KERBEROS_MSG_TYPES = {0x6a: "AS-REQ", 0x6b: "AS-REP", 0x6c: "TGS-REQ", 0x6d: "TGS-REP"}


def _kerberos_msg_type(data: bytes, window: int) -> Optional[str]:
    """Return the Kerberos message type if an app tag appears in the first ``window`` bytes.

    UDP carries the message from offset 0; TCP prefixes a 4-byte record length,
    so the caller widens the window for stream data."""
    for tag_byte, msg_type in _KERBEROS_MSG_TYPES.items():
        if tag_byte in data[:window]:
            return msg_type
    return None


def _detect_kerberos(streams: dict) -> list[dict]:
    """Detect Kerberos AS-REQ/AS-REP/TGS-REQ/TGS-REP in TCP streams on port 88."""
    results: list[dict] = []
    for (src_ip, sport, dst_ip, dport), payload in streams.items():
        if dport != 88 and sport != 88:
            continue
        data = bytes(payload)
        if len(data) < 10:
            continue
        msg_type = _kerberos_msg_type(data, 4)
        if msg_type:
            results.append({
                "msg_type": msg_type,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "detail": f"{msg_type} detected ({src_ip} → {dst_ip})",
            })
        if len(results) >= 100:
            break
    return results


def _detect_kerberos_udp(packets: list[tuple]) -> list[dict]:
    """Detect Kerberos messages in UDP/88 datagrams (the classic transport).

    Each datagram is a bare KRB message, so the application tag is at offset 0.
    Deduplicated per (src, dst, msg_type) to keep a busy logon from flooding."""
    results: list[dict] = []
    seen: set[tuple] = set()
    for src_ip, dst_ip, data in packets:
        if len(data) < 10:
            continue
        msg_type = _kerberos_msg_type(data, 2)
        if not msg_type:
            continue
        key = (src_ip, dst_ip, msg_type)
        if key in seen:
            continue
        seen.add(key)
        results.append({
            "msg_type": msg_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "detail": f"{msg_type} detected over UDP ({src_ip} → {dst_ip})",
        })
        if len(results) >= 100:
            break
    return results


def _is_dns_over_tcp(data: bytes) -> bool:
    """True if the stream looks like legitimate DNS-over-TCP (2-byte length + DNS msg)."""
    try:
        if len(data) < 4:
            return False
        n = struct.unpack("!H", data[:2])[0]
        msg = data[2:2 + n] if 2 + n <= len(data) else data[2:]
        if len(msg) < 12:
            return False
        dns = dpkt.dns.DNS(msg)
        # Sanity: a real DNS message carries at least one record of some kind.
        return (len(dns.qd) + len(dns.an) + len(dns.ns) + len(dns.ar)) > 0
    except Exception:
        return False


def _detect_dns_port_abuse(streams: dict) -> list[Finding]:
    """Flag non-DNS traffic riding TCP/53 (interactive shell / tunnel to evade egress).

    DNS-over-TCP is legitimate (zone transfers, large responses), so parse first
    and skip anything that is valid DNS. What remains — high-printable-ASCII
    content on the DNS port — is a shell or covert channel (T1572 / T1071.004).
    The printable-ratio gate keeps binary/unknown DNS-adjacent traffic from
    tripping the rule; only clear text-protocol abuse is flagged."""
    findings: list[Finding] = []
    seen: set[tuple] = set()
    for (src_ip, sport, dst_ip, dport), payload in streams.items():
        if 53 not in (sport, dport):
            continue
        data = bytes(payload)
        if len(data) < 24:
            continue
        if _is_dns_over_tcp(data):
            continue
        sample = data[:512]
        printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b <= 126)
        if printable / len(sample) < 0.85:
            continue  # binary non-DNS — not the ASCII-shell pattern we're confident about
        key = tuple(sorted((src_ip, dst_ip)))
        if key in seen:
            continue
        seen.add(key)
        snippet = data[:60].decode("ascii", "replace").replace("\r", " ").replace("\n", " ")
        findings.append(Finding(
            category="Protocol Tunneling",
            severity="high",
            title=f"Non-DNS traffic on port 53: {src_ip} <-> {dst_ip}",
            detail="TCP port 53 is carrying non-DNS content — an interactive shell or "
                   f"covert channel riding the DNS port to evade egress filtering. Sample: {snippet!r}",
        ))
    return findings


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
                # MD5 is used as a content fingerprint for body dedup, not for security.
                md5 = hashlib.md5(body, usedforsecurity=False).hexdigest() if body else ""
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
            # MD5 used as a fingerprint to dedup base64 candidates, not for security.
            key = hashlib.md5(candidate[:100], usedforsecurity=False).hexdigest()
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
