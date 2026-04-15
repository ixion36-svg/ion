"""
Mock Arkime viewer — emulates the subset of the Arkime 5.x API that ION's
arkime_service calls:

- GET  /api/user                              — liveness probe
- GET  /api/sessions?expression=...           — Community ID → session id lookup
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
import secrets
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response
import uvicorn

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
    print(f"[mock-arkime] FATAL: could not build sample PCAP: {e}")
    raise


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

    if not expression:
        return {"data": SESSIONS[:length or 10], "recordsTotal": len(SESSIONS)}

    matched: List[Dict[str, Any]] = []
    m = _EXPRESSION_RX.search(expression)
    if m:
        cid, node = m.group(1), m.group(2)
        for s in SESSIONS:
            if s["communityId"] == cid and s["node"] == node:
                matched.append(s)
    return {"data": matched, "recordsTotal": len(matched), "recordsFiltered": len(matched)}


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
