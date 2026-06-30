"""Mock Arkime viewer for the reworked realtime monitor (RTMON).

Unlike ``mock_arkime.py`` (community_id lookup only), this harness understands
the RTMON detector sweep expressions and returns crafted SPI sessions that trip
each detector — cleartext credentials, command/C2 channel, beacon cadence, DNS
tunneling — plus serves a real (dpkt-built) PCAP for the confirm-first DNS path
and the post-case PCAP enqueue.

No scapy dependency (not installed here); PCAPs are built with dpkt, which ION
already depends on. Auth: HTTP Basic arkime/arkime (set MOCK_REQUIRE_AUTH=0 to
disable).

    python test-arkime/mock_arkime_rtmon.py        # listens on :8005
"""

from __future__ import annotations

import base64
import io
import os
import re
import socket
from typing import Any, Dict, List, Optional

import dpkt
import uvicorn
from fastapi import FastAPI, Header, HTTPException

NODE = os.environ.get("MOCK_ARKIME_NODE", "capture01")
REQUIRE_AUTH = os.environ.get("MOCK_REQUIRE_AUTH", "1") == "1"
USER, PASS = "arkime", "arkime"

# A long, high-entropy DNS label (>50 chars) so the PCAP pipeline's DNS-tunnel
# detector (len(q) > 50) fires during confirm-first verification.
TUNNEL_QUERY = "k7f3p9q2w8e1r5t6y0u4i8o2a6s9d3f7g1h5j9k2l4z8x6c0v9b3.exfil.evil.example"


# ── dpkt PCAP builders ──────────────────────────────────────────────────────
def _eth(ip_pkt: bytes) -> bytes:
    return bytes(dpkt.ethernet.Ethernet(
        src=b"\x02\x00\x00\x00\x00\x01", dst=b"\x02\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip_pkt))


def _dns_packet(src: str, dst: str, qname: str) -> bytes:
    dns = dpkt.dns.DNS()
    dns.qd = [dpkt.dns.DNS.Q(name=qname, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN)]
    udp = dpkt.udp.UDP(sport=53000, dport=53)
    udp.data = bytes(dns)
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=dpkt.ip.IP_PROTO_UDP)
    ip.data = udp
    ip.len = len(ip)
    return _eth(bytes(ip))


def _tcp_syn(src: str, dst: str, sport: int, dport: int) -> bytes:
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=dpkt.tcp.TH_SYN, seq=1000)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=dpkt.ip.IP_PROTO_TCP)
    ip.data = tcp
    ip.len = len(ip)
    return _eth(bytes(ip))


def _build_pcap(packets: List[bytes]) -> bytes:
    buf = io.BytesIO()
    w = dpkt.pcap.Writer(buf)
    for i, p in enumerate(packets):
        w.writepkt(p, ts=1_744_689_000 + i)
    return buf.getvalue()


DNS_TUNNEL_PCAP = _build_pcap(
    [_dns_packet("10.50.12.20", "8.8.8.8", f"{i:02d}{TUNNEL_QUERY}") for i in range(6)]
)
GENERIC_PCAP = _build_pcap(
    [_tcp_syn("10.50.12.20", "45.77.198.7", 50000 + i, 4444) for i in range(4)]
)
print(f"[mock-rtmon] DNS-tunnel PCAP {len(DNS_TUNNEL_PCAP)}B · generic PCAP {len(GENERIC_PCAP)}B")


# ── fixture sessions (Arkime SPI shape) ─────────────────────────────────────
def _s(cid: str, **kw) -> Dict[str, Any]:
    base = {
        "id": cid.strip(":=") + "-id", "node": NODE, "communityId": cid,
        "srcIp": "10.50.12.20", "srcPort": 51000, "ipProtocol": 6,
        "firstPacket": 1_744_689_000_000, "lastPacket": 1_744_689_030_000,
        "totBytes": 800, "packets": 12,
    }
    base.update(kw)
    return base


CLEARTEXT = [_s("1:CLEAR=", dstIp="10.50.12.9", dstPort=21, protocol=["ftp"], user="svc_backup")]
COMMAND = [
    _s("1:TELNET=", dstIp="10.50.12.9", dstPort=23, protocol=["telnet"]),
    _s("1:SHELL=", dstIp="45.77.198.7", dstPort=4444, protocol=["tcp"]),  # external reverse shell
]
# Regular cadence to one external dst:443 → high RITA beacon score.
BEACON = [
    _s(f"1:BEACON{i}=", dstIp="45.77.198.50", dstPort=443, protocol=["tcp", "tls"],
       firstPacket=1_744_689_000_000 + i * 60_000, totBytes=512)
    for i in range(10)
]
DNS = [_s("1:DNS=", dstIp="8.8.8.8", dstPort=53, protocol=["dns"],
          **{"dns.host": [TUNNEL_QUERY]})]

ALL = CLEARTEXT + COMMAND + BEACON + DNS
BY_CID = {s["communityId"]: s for s in ALL}
PCAP_FOR = {s["id"]: (DNS_TUNNEL_PCAP if s["communityId"] == "1:DNS=" else GENERIC_PCAP) for s in ALL}

app = FastAPI(title="Mock Arkime (RTMON)")


def _auth(authorization: Optional[str]) -> None:
    if not REQUIRE_AUTH:
        return
    if authorization and authorization.lower().startswith("basic "):
        try:
            u, _, p = base64.b64decode(authorization.split(None, 1)[1]).decode().partition(":")
            if u == USER and p == PASS:
                return
        except Exception:
            pass
    raise HTTPException(401, "auth required", headers={"WWW-Authenticate": 'Basic realm="arkime"'})


@app.get("/api/user")
async def api_user(authorization: Optional[str] = Header(None)):
    _auth(authorization)
    return {"userId": "mock-arkime", "enabled": True, "roles": ["arkimeUser"]}


_CID_RX = re.compile(r'communityId\s*==\s*"([^"]+)"')


@app.get("/api/sessions")
async def api_sessions(authorization: Optional[str] = Header(None),
                       expression: Optional[str] = None, length: Optional[int] = 100):
    _auth(authorization)
    expr = expression or ""
    # 1) community_id lookups (confirm-first + post-case PCAP enqueue paths)
    m = _CID_RX.search(expr)
    if m:
        s = BY_CID.get(m.group(1))
        data = [s] if s else []
    # 2) detector sweeps
    elif "user == EXISTS!" in expr:
        data = CLEARTEXT
    elif "protocols == telnet" in expr:
        data = COMMAND
    elif "ip.dst != 10.0.0.0/8" in expr:
        data = BEACON
    elif "protocols == dns" in expr:
        data = DNS
    else:
        data = []
    data = data[: (length or 100)]
    return {"data": data, "recordsTotal": len(data), "recordsFiltered": len(data)}


@app.get("/api/session/{node}/{session_id}/pcap")
async def api_pcap(node: str, session_id: str, authorization: Optional[str] = Header(None)):
    _auth(authorization)
    sid = session_id[2:] if session_id.startswith("3@") else session_id
    pcap = PCAP_FOR.get(sid)
    if pcap is None:
        raise HTTPException(404, "session not found")
    from fastapi import Response
    return Response(content=pcap, media_type="application/vnd.tcpdump.pcap")


@app.get("/")
async def root():
    return {"service": "mock-arkime-rtmon", "fixtures": len(ALL),
            "detectors": ["cleartext", "command", "beacon", "dns"]}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8005"))
    print(f"[mock-rtmon] listening on :{port}  (auth={'on' if REQUIRE_AUTH else 'off'}, node={NODE})")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
