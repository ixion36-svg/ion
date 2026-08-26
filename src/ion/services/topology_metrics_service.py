"""Network Topology (NSE view) — compute-on-read metrics join.

Joins Arkime conversation volumetrics with what ION already knows about the
endpoints: CMDB asset identity (``NetworkAsset`` via exact IP match) and
threat context (``Observable`` threat level + case linkage). No new
ingestion — every figure is computed from data already in Arkime/Postgres at
request time, so the view stays air-gap-safe.

Metrics ION cannot source (RTT, retransmit rate, packet loss, interface
health) are declared in ``UNAVAILABLE_METRICS`` and shown as unavailable in
the UI rather than approximated — an NSE audience notices faked numbers.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from ion.models.network_asset import NetworkAsset, NetworkAssetIP
from ion.models.observable import (
    Observable,
    ObservableLink,
    ObservableLinkType,
    ObservableType,
)
from ion.services.arkime_service import (
    ArkimeService,
    arkime_sessions_link,
    get_arkime_service,
)

UNAVAILABLE_METRICS = [
    {"metric": "RTT / latency", "requires": "Packetbeat"},
    {"metric": "Retransmit / TCP-error rate", "requires": "Packetbeat or tcp-flag SPI fields"},
    {"metric": "Packet loss", "requires": "Packetbeat"},
    {"metric": "Per-interface utilization + health", "requires": "SNMP IF-MIB collection"},
]

# Threat levels that mark a node as malicious in the graph. LOW/MEDIUM still
# surface as context in the detail panel without turning the node red.
_MALICIOUS_LEVELS = {"high", "critical"}


def _subnet_of(ip: str) -> str:
    """Grouping subnet for a host: /24 for IPv4, /64 for IPv6, '' on garbage."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def _assets_by_ip(session: Session, ips: List[str]) -> Dict[str, Dict[str, Any]]:
    """Exact-IP CMDB lookup: ip → asset identity summary (unarchived only)."""
    if not ips:
        return {}
    rows = (
        session.query(NetworkAssetIP.ip, NetworkAsset)
        .join(NetworkAsset, NetworkAsset.id == NetworkAssetIP.asset_id)
        .filter(NetworkAssetIP.ip.in_(ips))
        .all()
    )
    out: Dict[str, Dict[str, Any]] = {}
    for ip, asset in rows:
        if asset.archived_at is not None:
            continue
        out[str(ip)] = {
            "asset_id": asset.id,
            "hostname": asset.display_hostname or asset.hostname,
            "criticality": asset.criticality,
            "environment": asset.environment,
        }
    return out


def _threat_by_ip(session: Session, ips: List[str]) -> Dict[str, Dict[str, Any]]:
    """Observable-ledger threat context: ip → level / IOC flag / case count."""
    if not ips:
        return {}
    obs_rows = (
        session.query(Observable)
        .filter(
            Observable.type.in_([ObservableType.IPV4, ObservableType.IPV6]),
            Observable.normalized_value.in_(ips),
            Observable.is_whitelisted.is_(False),
            Observable.is_ignored.is_(False),
        )
        .all()
    )
    if not obs_rows:
        return {}
    case_counts = dict(
        session.query(
            ObservableLink.observable_id,
            func.count(func.distinct(ObservableLink.entity_id)),
        )
        .filter(
            ObservableLink.observable_id.in_([o.id for o in obs_rows]),
            ObservableLink.link_type == ObservableLinkType.CASE,
        )
        .group_by(ObservableLink.observable_id)
        .all()
    )
    out: Dict[str, Dict[str, Any]] = {}
    for o in obs_rows:
        level = o.threat_level.value if hasattr(o.threat_level, "value") else str(o.threat_level)
        out[o.normalized_value] = {
            "level": level,
            "malicious": level in _MALICIOUS_LEVELS,
            "is_ioc": bool(o.is_ioc),
            "case_count": int(case_counts.get(o.id, 0)),
        }
    return out


async def build_topology(
    session: Session,
    start_ts: int,
    stop_ts: int,
    expression: Optional[str] = None,
    limit: int = 200,
) -> Dict[str, Any]:
    """The `/api/arkime/traffic/topology` payload.

    Raises ``ArkimeError`` (propagated from the service) when Arkime is
    unconfigured/unreachable — the API layer maps that to 503/502 like its
    sibling endpoints.
    """
    svc = get_arkime_service()
    convo = await svc.get_conversations(
        start_ts, stop_ts, expression=expression, limit=limit
    )
    ips = [n["ip"] for n in convo["nodes"]]
    assets = _assets_by_ip(session, ips)
    threats = _threat_by_ip(session, ips)

    nodes = [
        {
            **n,
            "subnet": _subnet_of(n["ip"]),
            "private": ArkimeService._is_private_ip(n["ip"]),
            "asset": assets.get(n["ip"]),
            "threat": threats.get(n["ip"]),
        }
        for n in convo["nodes"]
    ]
    # Endpoint IPs are ipaddress-validated upstream (_clean_endpoint_ip), so
    # bare interpolation into the expression is safe — IP terms are unquoted.
    edges = [
        {
            **e,
            "arkime_url": arkime_sessions_link(
                f"ip.src == {e['src']} && ip.dst == {e['dst']}"
            ),
        }
        for e in convo["edges"]
    ]

    port_bytes: Dict[int, int] = {}
    for e in convo["edges"]:
        if e.get("port") is not None:
            port_bytes[e["port"]] = port_bytes.get(e["port"], 0) + int(e.get("bytes") or 0)
    port_distribution = sorted(
        [{"port": p, "bytes": b} for p, b in port_bytes.items()],
        key=lambda x: x["bytes"],
        reverse=True,
    )[:10]

    return {
        "nodes": nodes,
        "edges": edges,
        "metrics": {
            "active_conversations": len(convo["edges"]),
            "hosts": len(nodes),
            "port_distribution": port_distribution,
            "method": convo["method"],
        },
        "unavailable": UNAVAILABLE_METRICS,
    }
