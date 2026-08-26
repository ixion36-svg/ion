"""
Mock Arkime viewer — emulates the subset of the Arkime 5.x API that ION's
arkime_service calls:

- GET  /api/user                              — liveness probe
- GET  /api/sessions?expression=...           — Community ID → session id lookup
- GET  /api/sessions (no expression)          — synthetic flow sample (topology)
- GET  /api/connections                       — src↔dst conversation graph
- GET  /api/session/{node}/{id}/pcap          — PCAP download

Everything else returns 404.

It fakes a tiny deterministic database where a single Community ID maps to a
single session, and the session's PCAP is a small capture built at startup
with scapy (TCP three-way handshake + a handful of fake HTTP/DNS packets so
ION's pcap_service detectors have something to chew on).

Auth: supports HTTP basic (`arkime`/`arkime`) and plain open-access when
`MOCK_ARKIME_REQUIRE_AUTH=0`. Keycloak Bearer is NOT validated — if ION is
configured for Keycloak the service just accepts any `Bearer <token>` so we
can still exercise that code path. Not production-safe, obviously.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request, Response

# ── Configuration ───────────────────────────────────────────────────────────
MOCK_NODE = os.environ.get("MOCK_ARKIME_NODE", "capture01")
MOCK_COMMUNITY_ID = os.environ.get(
    "MOCK_ARKIME_COMMUNITY_ID",
    "1:0ECALHJBcs13AkbmCmvNd9CVOkA=",
)
MOCK_BASIC_USER = os.environ.get("MOCK_ARKIME_USER", "arkime")
MOCK_BASIC_PASS = os.environ.get("MOCK_ARKIME_PASS", "arkime")
REQUIRE_AUTH = os.environ.get("MOCK_ARKIME_REQUIRE_AUTH", "1") == "1"

# A deterministic fake Arkime session id derived from the Community ID so
# the resolve step is reproducible across restarts.
MOCK_SESSION_ID = hashlib.sha1(MOCK_COMMUNITY_ID.encode()).hexdigest()[:16] + "-1"


# ── Sample PCAP generation (with scapy) ─────────────────────────────────────

def build_sample_pcap() -> bytes:
    """Construct a small PCAP with enough structure to produce findings.

    Includes:
    - TCP three-way handshake (SYN → SYN/ACK → ACK)
    - DNS query for a suspicious-looking domain
    - HTTP GET with a suspicious user-agent that pcap_service's scanner hits
    - A few beacon-like repeated connections to trip the beaconing detector
    """
    from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap

    src = "10.50.12.17"
    dst = "185.220.101.78"  # intentionally in Tor exit node range-ish
    attacker_domain = "malware-c2.badsite.io"
    ua = "Mozilla/5.0 (Windows NT 10.0; rv:1.0) Gecko/20100101 Firefox/89.0"  # generic
    mal_ua = "python-requests/2.28.0"  # flagged as suspicious by pcap_service

    packets = []

    # TCP three-way handshake x 2 (two separate short-lived connections)
    for i in range(2):
        sport = 45000 + i
        eth = Ether()
        packets.append(eth / IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="S", seq=100 + i))
        packets.append(eth / IP(src=dst, dst=src) / TCP(sport=80, dport=sport, flags="SA", seq=200 + i, ack=101 + i))
        packets.append(eth / IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="A", seq=101 + i, ack=201 + i))
        # GET request with suspicious UA
        req = (
            f"GET /beacon?id=42 HTTP/1.1\r\n"
            f"Host: {attacker_domain}\r\n"
            f"User-Agent: {mal_ua}\r\n"
            "Accept: */*\r\n\r\n"
        ).encode()
        packets.append(
            eth / IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="PA", seq=101 + i, ack=201 + i) / Raw(load=req)
        )

    # DNS query
    packets.append(
        Ether() / IP(src=src, dst="8.8.8.8") / UDP(sport=53000, dport=53) /
        DNS(rd=1, qd=DNSQR(qname=attacker_domain))
    )

    # Beaconing — several identical short outbound connections spaced regularly
    for i in range(8):
        packets.append(
            Ether() / IP(src=src, dst=dst) /
            TCP(sport=50000 + i, dport=4444, flags="S", seq=500 + i)
        )

    # Write to in-memory PCAP
    buf = io.BytesIO()
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        wrpcap(tmp.name, packets)
        tmp.flush()
        with open(tmp.name, "rb") as f:
            data = f.read()
    return data


try:
    SAMPLE_PCAP = build_sample_pcap()
    print(f"[mock-arkime] sample PCAP built: {len(SAMPLE_PCAP)} bytes")
except Exception as e:
    # scapy may be absent on a bare-host run (flow/topology testing doesn't
    # need the PCAP half) — serve an empty capture rather than refusing to start.
    print(f"[mock-arkime] WARNING: no sample PCAP ({e}) — /pcap serves empty bytes")
    SAMPLE_PCAP = b""


# ── In-memory "database" ─────────────────────────────────────────────────────

SESSIONS = [
    {
        "id": MOCK_SESSION_ID,
        "node": MOCK_NODE,
        "communityId": MOCK_COMMUNITY_ID,
        "firstPacket": 1_744_689_000_000,  # Apr 15 2026 ~00:00 UTC
        "lastPacket":  1_744_689_035_000,
        "srcIp": "10.50.12.17",
        "srcPort": 45000,
        "dstIp": "185.220.101.78",
        "dstPort": 80,
        "ipProtocol": 6,
        "protocol": ["tcp", "http"],
        "packets": 28,
        "bytes": 2340,
    }
]


# ── Synthetic flow network (Flow Topology / conversations endpoints) ────────
# A small deterministic enterprise: two internal /24s, a DB host on a third,
# one threat-flavoured external peer, a CDN, and public DNS. Timestamps are
# anchored to process start so every ION range window (24h/7d/30d) sees them.

import time as _time

_FLOW_BASE_MS = int(_time.time() * 1000) - 3_600_000

# (src, dst, dstPort, ipProtocol, total_bytes, total_packets, duration_s, sessions)
FLOW_PAIRS = [
    ("10.50.12.17", "185.220.101.78", 443, 6, 48_200_000, 52_000, 900, 6),
    ("10.50.12.17", "10.50.20.5", 445, 6, 9_800_000, 11_000, 300, 4),
    ("10.50.12.23", "10.50.20.5", 445, 6, 6_100_000, 7_400, 250, 3),
    ("10.50.12.23", "10.50.20.9", 3389, 6, 2_500_000, 3_100, 600, 2),
    ("10.50.12.31", "8.8.8.8", 53, 17, 240_000, 2_900, 30, 10),
    ("10.50.20.5", "151.101.1.69", 443, 6, 122_000_000, 96_000, 1200, 5),
    ("10.50.20.9", "151.101.1.69", 80, 6, 18_000_000, 21_000, 700, 3),
    ("172.16.4.10", "10.50.20.5", 5432, 6, 30_500_000, 40_000, 1500, 8),
    ("10.50.12.44", "203.0.113.99", 8443, 6, 1_200_000, 1_500, 120, 2),
]

FLOW_SESSIONS: List[Dict[str, Any]] = []
_fn = 0
for _src, _dst, _port, _proto, _bytes, _pkts, _dur, _cnt in FLOW_PAIRS:
    for _i in range(_cnt):
        _fn += 1
        FLOW_SESSIONS.append({
            "id": f"flow-{_fn}",
            "node": MOCK_NODE,
            "srcIp": _src,
            "dstIp": _dst,
            "dstPort": _port,
            "ipProtocol": _proto,
            "totBytes": _bytes // _cnt,
            "packets": _pkts // _cnt,
            "firstPacket": _FLOW_BASE_MS + _fn * 1000,
            "lastPacket": _FLOW_BASE_MS + _fn * 1000 + (_dur * 1000) // _cnt,
        })
FLOW_SESSIONS.sort(key=lambda s: s["totBytes"], reverse=True)


def _flow_pairs_for(expression: Optional[str]):
    """Crude expression support: ION's east-west exclusion
    (``!(ip.src == [rfc1918] && ip.dst == [rfc1918])``) drops
    private↔private pairs; anything else passes everything through."""
    if expression and "!(ip.src ==" in expression:
        import ipaddress as _ipa

        def _priv(ip: str) -> bool:
            return _ipa.ip_address(ip).is_private

        return [p for p in FLOW_PAIRS if not (_priv(p[0]) and _priv(p[1]))]
    return FLOW_PAIRS


def _flow_sessions_for(expression: Optional[str]):
    allowed = {(p[0], p[1]) for p in _flow_pairs_for(expression)}
    return [s for s in FLOW_SESSIONS if (s["srcIp"], s["dstIp"]) in allowed]


# ── FastAPI app ─────────────────────────────────────────────────────────────

app = FastAPI(title="Mock Arkime viewer", version="0.1.0")


def _check_auth(authorization: Optional[str], request: Request) -> None:
    if not REQUIRE_AUTH:
        return
    # Accept any Bearer token (Keycloak path) without validation
    if authorization and authorization.lower().startswith("bearer "):
        return
    # Accept "Digest <key>" without validation
    if authorization and authorization.lower().startswith("digest "):
        return
    # Basic auth via httpx.BasicAuth
    import base64
    if authorization and authorization.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(authorization.split(None, 1)[1]).decode()
            user, _, password = decoded.partition(":")
            if user == MOCK_BASIC_USER and password == MOCK_BASIC_PASS:
                return
        except Exception:
            pass
    raise HTTPException(
        status_code=401,
        detail="auth required",
        headers={"WWW-Authenticate": 'Basic realm="arkime"'},
    )


@app.get("/api/user")
async def api_user(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    _check_auth(authorization, request)
    return {
        "userId": "mock-arkime",
        "userName": "Mock Arkime User",
        "enabled": True,
        "roles": ["arkimeUser"],
    }


_EXPRESSION_RX = re.compile(
    r'communityId\s*==\s*"([^"]+)"\s*&&\s*node\s*==\s*"([^"]+)"'
)


@app.get("/api/sessions")
async def api_sessions(
    request: Request,
    authorization: Optional[str] = Header(None),
    expression: Optional[str] = None,
    length: Optional[int] = 10,
    fields: Optional[str] = None,
):
    _check_auth(authorization, request)

    if expression:
        m = _EXPRESSION_RX.search(expression)
        if m:
            cid, node = m.group(1), m.group(2)
            matched: List[Dict[str, Any]] = [
                s for s in SESSIONS
                if s["communityId"] == cid and s["node"] == node
            ]
            return {"data": matched, "recordsTotal": len(matched), "recordsFiltered": len(matched)}

    # Everything else is an ION analytics query (talkers, geo, conversations) —
    # serve the synthetic flow network, honouring the east-west exclusion.
    flows = _flow_sessions_for(expression)
    return {"data": flows[: length or 10], "recordsTotal": len(flows)}


@app.get("/api/connections")
async def api_connections(
    request: Request,
    authorization: Optional[str] = Header(None),
    srcField: str = "ip.src",  # noqa: N803 — Arkime's own query param names
    dstField: str = "ip.dst",  # noqa: N803
    expression: Optional[str] = None,
):
    """Arkime 5.x connections graph: nodes + links with integer node indexes,
    `value` = session count, `by` = byte volume — the shape ION parses."""
    _check_auth(authorization, request)
    ids: List[str] = []
    index: Dict[str, int] = {}

    def _node(ip: str) -> int:
        if ip not in index:
            index[ip] = len(ids)
            ids.append(ip)
        return index[ip]

    links = []
    node_stats: Dict[str, Dict[str, int]] = {}
    for src, dst, _port, _proto, b, _pkts, _dur, cnt in _flow_pairs_for(expression):
        links.append({"source": _node(src), "target": _node(dst), "value": cnt, "by": b})
        for ip in (src, dst):
            st = node_stats.setdefault(ip, {"sessions": 0, "by": 0})
            st["sessions"] += cnt
            st["by"] += b
    nodes = [
        {"id": ip, "cnt": node_stats[ip]["sessions"], "sessions": node_stats[ip]["sessions"], "by": node_stats[ip]["by"]}
        for ip in ids
    ]
    return {"nodes": nodes, "links": links, "recordsFiltered": len(FLOW_SESSIONS)}


@app.get("/api/session/{node}/{session_id}/pcap")
async def api_pcap(
    node: str,
    session_id: str,
    request: Request,
    authorization: Optional[str] = Header(None),
):
    _check_auth(authorization, request)
    for s in SESSIONS:
        if s["id"] == session_id and s["node"] == node:
            return Response(
                content=SAMPLE_PCAP,
                media_type="application/vnd.tcpdump.pcap",
                headers={
                    "Content-Disposition": (
                        f'attachment; filename="{node}-{session_id}.pcap"'
                    )
                },
            )
    raise HTTPException(status_code=404, detail="session not found")


@app.get("/")
async def root():
    return {
        "service": "mock-arkime",
        "sessions": len(SESSIONS),
        "sample_pcap_bytes": len(SAMPLE_PCAP),
        "community_id": MOCK_COMMUNITY_ID,
        "node": MOCK_NODE,
        "session_id": MOCK_SESSION_ID,
        "require_auth": REQUIRE_AUTH,
    }


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8005"))
    print(f"[mock-arkime] listening on 0.0.0.0:{port}")
    print(f"[mock-arkime]   node={MOCK_NODE}")
    print(f"[mock-arkime]   community_id={MOCK_COMMUNITY_ID}")
    print(f"[mock-arkime]   session_id={MOCK_SESSION_ID}")
    print(f"[mock-arkime]   basic auth: {MOCK_BASIC_USER}:{MOCK_BASIC_PASS}")
    uvicorn.run(app, host="0.0.0.0", port=port)
