"""Flow topology panels for the Arkime conversation graph.

The page used to paint an unreachable Arkime the same way it painted an
empty window. A 503 returned before the metrics render, so the cards stayed
on a dash, and a missing host count was coerced with `|| 0`. An empty node
list is a window that was read and had no sessions. A 503 was never read.
A payload that is not a graph is neither of those.

Node positions stay in the page: they depend on the measured canvas. The
detail for a clicked node is looked up by the same key the layout drew.
Host details are the host itself. Edge details use the aggregated key, so a
grouped subnet does not answer a host-to-host question it did not draw.

Calls into the JSON handler are keyword-only, under the names the tests
replace.
"""
from __future__ import annotations

import logging
import math
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.arkime_traffic_analytics_api import traffic_topology
from ion.web.ui._shared import render_view

logger = logging.getLogger(__name__)

router = APIRouter()

BOARD = "_fragments/network_topology_board.html"
NODE = "_fragments/network_topology_node.html"
EDGE = "_fragments/network_topology_edge.html"

READ = "alert:read"

_UNCONFIGURED = "Arkime is not configured, so this graph was not read."
_FAILED = "The topology could not be read."


def _is_num(value: object) -> bool:
    """A real number. True is an int, and it is not a byte count."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _js_round(value: float) -> int:
    """Math.round for a non-negative number. Python round is bankers."""
    return int(math.floor(value + 0.5))


def fmt_bytes(value: object) -> Optional[str]:
    """B/KB/MB/GB/TB, matching the page formatter. None stays unknown."""
    if not _is_num(value):
        return None
    amount = float(value)
    units = ("B", "KB", "MB", "GB", "TB")
    index = 0
    while amount >= 1024 and index < len(units) - 1:
        amount /= 1024.0
        index += 1
    if index == 0:
        shown = str(int(amount)) if amount.is_integer() else format(amount, "g")
    else:
        shown = f"{amount:.1f}"
    return shown + " " + units[index]


def _fmt_rate(value: object) -> Optional[str]:
    text = fmt_bytes(value)
    if text is None:
        return None
    return text + "/s"


def _count(metrics: dict, key: str) -> Optional[int]:
    """Missing key is unknown, not zero. A present non-int is unknown too."""
    if key not in metrics:
        return None
    value = metrics[key]
    if not _is_int(value):
        return None
    return value


def _method(metrics: dict) -> Optional[str]:
    if "method" not in metrics:
        return None
    value = metrics["method"]
    if isinstance(value, str) and value:
        return value
    return None


def _http_url(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    lowered = value.lower()
    if lowered.startswith("https://") or lowered.startswith("http://"):
        return value
    return None


def _expanded(raw: Optional[str]) -> set[str]:
    if not raw:
        return set()
    return {part.strip() for part in raw.split(",") if part.strip()}


def _key_for(ip: str, subnet_of: dict, grouped: bool, expanded: set[str]) -> str:
    subnet = subnet_of.get(ip) or ""
    if (not grouped) or (not subnet) or (subnet in expanded):
        return "h:" + ip
    return "s:" + subnet


def _rank(threat: object) -> Optional[float]:
    if not isinstance(threat, dict):
        return None
    rank = threat.get("rank")
    if not _is_num(rank):
        return None
    return float(rank)


def _sum(values: list) -> Optional[float]:
    total = 0
    for value in values:
        if not _is_num(value):
            return None
        total += value
    return total


def _port_rows(metrics: dict) -> tuple[str, list]:
    if "port_distribution" not in metrics or not isinstance(metrics.get("port_distribution"), list):
        return "unreadable", []
    items = metrics["port_distribution"]
    if not items:
        return "empty", []
    parsed = []
    numbers = []
    for item in items:
        if not isinstance(item, dict):
            return "unreadable", []
        amount = item.get("bytes")
        if _is_num(amount):
            numbers.append(amount)
        parsed.append(item)
    peak = max(numbers) if numbers else None
    rows = []
    for item in parsed:
        amount = item.get("bytes")
        number = item.get("port")
        if isinstance(number, bool) or not isinstance(number, (int, str)):
            number = None
        width = None
        label = fmt_bytes(amount)
        if label is not None:
            if peak is not None and peak > 0:
                width = max(2, _js_round(float(amount) / float(peak) * 140))
            else:
                width = 2
        rows.append({"number": number, "width": width, "label": label})
    return "data", rows


def _unavailable_rows(payload: dict) -> tuple[str, list]:
    if "unavailable" not in payload or not isinstance(payload.get("unavailable"), list):
        return "unreadable", []
    items = payload["unavailable"]
    if not items:
        return "empty", []
    rows = []
    for item in items:
        if not isinstance(item, dict):
            return "unreadable", []
        metric = item.get("metric")
        requires = item.get("requires")
        rows.append({
            "metric": metric if isinstance(metric, str) else None,
            "requires": requires if isinstance(requires, str) else None,
        })
    return "data", rows


def _blank() -> dict:
    return {
        "hosts": None,
        "conversations": None,
        "method": None,
        "ports_state": "hidden",
        "ports": [],
        "unavailable_state": "hidden",
        "unavailable": [],
    }


def _figures(payload: dict) -> dict:
    metrics = payload.get("metrics")
    if not isinstance(metrics, dict):
        ports_state, ports = "unreadable", []
        unavailable_state, unavailable = _unavailable_rows(payload)
        return {
            "hosts": None,
            "conversations": None,
            "method": None,
            "ports_state": ports_state,
            "ports": ports,
            "unavailable_state": unavailable_state,
            "unavailable": unavailable,
        }
    ports_state, ports = _port_rows(metrics)
    unavailable_state, unavailable = _unavailable_rows(payload)
    return {
        "hosts": _count(metrics, "hosts"),
        "conversations": _count(metrics, "active_conversations"),
        "method": _method(metrics),
        "ports_state": ports_state,
        "ports": ports,
        "unavailable_state": unavailable_state,
        "unavailable": unavailable,
    }


async def _load(range_name: str, exclude_private: bool, user: User, session: Session) -> dict:
    try:
        payload = await traffic_topology(
            range=range_name,
            exclude_private=exclude_private,
            user=user,
            session=session,
        )
    except HTTPException as exc:
        if exc.status_code == 503:
            return {"outcome": "unconfigured", "payload": None}
        logger.exception("topology read failed")
        return {"outcome": "failed", "payload": None}
    except Exception:
        logger.exception("topology read failed")
        return {"outcome": "failed", "payload": None}
    if not isinstance(payload, dict):
        return {"outcome": "unreadable", "payload": None}
    nodes = payload.get("nodes")
    if not isinstance(nodes, list) or any(not isinstance(node, dict) for node in nodes):
        return {"outcome": "unreadable", "payload": None}
    if not nodes:
        return {"outcome": "empty", "payload": payload}
    return {"outcome": "data", "payload": payload}


def _board_view(loaded: dict) -> dict:
    outcome = loaded["outcome"]
    view = {"state": outcome, "title": _FAILED}
    if outcome == "unconfigured":
        view["title"] = _UNCONFIGURED
        view.update(_blank())
        return view
    if outcome in ("failed", "unreadable"):
        view["state"] = "failed" if outcome == "failed" else "unreadable"
        view.update(_blank())
        return view
    view.update(_figures(loaded["payload"]))
    return view


def _subnet_of(nodes: list) -> dict:
    found = {}
    for node in nodes:
        ip = node.get("ip")
        if not isinstance(ip, str):
            continue
        subnet = node.get("subnet")
        found[ip] = subnet if isinstance(subnet, str) else ""
    return found


def _aggregate_edges(nodes: list, edges: list, grouped: bool, expanded: set[str]) -> dict:
    subnet_of = _subnet_of(nodes)
    grouped_edges: dict = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        src = edge.get("src")
        dst = edge.get("dst")
        if not isinstance(src, str) or not isinstance(dst, str):
            continue
        left = _key_for(src, subnet_of, grouped, expanded)
        right = _key_for(dst, subnet_of, grouped, expanded)
        if left == right:
            continue
        key = left + "|" + right
        current = grouped_edges.get(key)
        if current is None:
            threat = edge.get("threat")
            grouped_edges[key] = {
                "from": left,
                "to": right,
                "byte_values": [edge.get("bytes")],
                "session_values": [edge.get("sessions")],
                "sample": edge,
                "threat": threat if isinstance(threat, dict) else None,
            }
            continue
        current["byte_values"].append(edge.get("bytes"))
        current["session_values"].append(edge.get("sessions"))
        new_bytes = edge.get("bytes")
        old_bytes = current["sample"].get("bytes")
        if _is_num(new_bytes) and _is_num(old_bytes) and new_bytes > old_bytes:
            current["sample"] = edge
        new_threat = edge.get("threat")
        if isinstance(new_threat, dict):
            old_threat = current["threat"]
            new_rank = _rank(new_threat)
            old_rank = _rank(old_threat)
            if not isinstance(old_threat, dict) or (
                new_rank is not None and (old_rank is None or new_rank > old_rank)
            ):
                current["threat"] = new_threat
    return grouped_edges


def _edge_ready(loaded: dict) -> tuple[str, list, list]:
    outcome = loaded["outcome"]
    if outcome != "data" and outcome != "empty":
        return outcome, [], []
    payload = loaded["payload"]
    edges = payload.get("edges", [])
    if not isinstance(edges, list):
        return "unreadable", [], []
    nodes = payload.get("nodes")
    if not isinstance(nodes, list):
        return "unreadable", [], []
    return outcome, nodes, edges


def _host_view(node: dict) -> dict:
    ip = node.get("ip") if isinstance(node.get("ip"), str) else ""
    asset = node.get("asset") if isinstance(node.get("asset"), dict) else None
    threat = node.get("threat") if isinstance(node.get("threat"), dict) else None
    private = node.get("private")
    if private is True:
        scope = "internal"
    elif private is False:
        scope = "external"
    else:
        scope = None
    subnet = node.get("subnet") if isinstance(node.get("subnet"), str) and node.get("subnet") else None
    sessions = node.get("sessions")
    case_count = threat.get("case_count") if threat else None
    search = quote(ip, safe="")
    return {
        "state": "data",
        "kind": "host",
        "title": ip,
        "bytes_label": fmt_bytes(node.get("bytes")),
        "sessions": sessions if _is_int(sessions) else None,
        "subnet": subnet,
        "scope": scope,
        "asset": asset,
        "threat": threat,
        "case_count": case_count if _is_int(case_count) else None,
        "observables_href": "/observables?search=" + search,
        "network_map_href": ("/network-map?search=" + search) if asset else None,
    }


def _node_view(loaded: dict, node: Optional[str], grouped: bool, expanded: set[str]) -> dict:
    outcome = loaded["outcome"]
    if outcome == "unconfigured":
        return {"state": "unconfigured", "title": _UNCONFIGURED}
    if outcome in ("failed", "unreadable"):
        return {"state": "failed", "title": _FAILED}
    payload = loaded["payload"] or {}
    nodes = payload.get("nodes") if isinstance(payload.get("nodes"), list) else []
    kind = ""
    ident = ""
    if isinstance(node, str) and ":" in node:
        kind, ident = node.split(":", 1)
    if kind == "h":
        for item in nodes:
            if isinstance(item, dict) and item.get("ip") == ident:
                return _host_view(item)
        return {"state": "missing", "title": "This node is not in this graph."}
    if kind == "s":
        members = [item for item in nodes if isinstance(item, dict) and item.get("subnet") == ident]
        if not members:
            return {"state": "missing", "title": "This node is not in this graph."}
        total = _sum([item.get("bytes") for item in members])
        return {
            "state": "data",
            "kind": "subnet",
            "title": ident,
            "host_count": len(members),
            "bytes_label": fmt_bytes(total) if total is not None else None,
            "subnet": ident,
        }
    return {"state": "missing", "title": "This node is not in this graph."}


def _edge_view(loaded: dict, src: Optional[str], dst: Optional[str], grouped: bool, expanded: set[str]) -> dict:
    outcome, nodes, edges = _edge_ready(loaded)
    if outcome == "unconfigured":
        return {"state": "unconfigured", "title": _UNCONFIGURED}
    if outcome in ("failed", "unreadable"):
        return {"state": "failed", "title": _FAILED}
    if not isinstance(src, str) or not isinstance(dst, str):
        return {"state": "missing", "title": "This conversation is not in this graph."}
    found = _aggregate_edges(nodes, edges, grouped, expanded)
    agg = found.get(src + "|" + dst)
    if agg is None:
        return {"state": "missing", "title": "This conversation is not in this graph."}
    sample = agg["sample"] if isinstance(agg["sample"], dict) else {}
    protocol = sample.get("protocol")
    if not isinstance(protocol, str) or not protocol:
        protocol = None
    port = sample.get("port")
    if not _is_int(port):
        port = None
    threat = agg["threat"] if isinstance(agg["threat"], dict) else None
    total_bytes = _sum(agg["byte_values"])
    total_sessions = _sum(agg["session_values"])
    packets = sample.get("packets")
    left = agg["from"][2:] if isinstance(agg["from"], str) and len(agg["from"]) > 2 else ""
    right = agg["to"][2:] if isinstance(agg["to"], str) and len(agg["to"]) > 2 else ""
    return {
        "state": "data",
        "title_from": left,
        "title_to": right,
        "bytes_label": fmt_bytes(total_bytes) if total_bytes is not None else None,
        "sessions": int(total_sessions) if total_sessions is not None and float(total_sessions).is_integer() else None,
        "protocol": protocol,
        "port": port,
        "rate_label": _fmt_rate(sample.get("throughput_bps")),
        "packets": packets if _is_int(packets) else None,
        "threat": threat,
        "arkime_url": _http_url(sample.get("arkime_url")),
        "arkime_pcap_url": _http_url(sample.get("arkime_pcap_url")),
    }


@router.get("/network-topology/board", response_class=HTMLResponse)
async def network_topology_board(
    request: Request,
    range: str = "24h",
    exclude_private: bool = False,
    user: User = Depends(require_permission(READ)),
    session: Session = Depends(get_db_session),
):
    loaded = await _load(range, exclude_private, user, session)
    return render_view(request, BOARD, _board_view(loaded))


@router.get("/network-topology/node", response_class=HTMLResponse)
async def network_topology_node(
    request: Request,
    node: Optional[str] = None,
    range: str = "24h",
    exclude_private: bool = False,
    grouped: bool = True,
    expanded: Optional[str] = None,
    user: User = Depends(require_permission(READ)),
    session: Session = Depends(get_db_session),
):
    loaded = await _load(range, exclude_private, user, session)
    return render_view(request, NODE, _node_view(loaded, node, grouped, _expanded(expanded)))


@router.get("/network-topology/edge", response_class=HTMLResponse)
async def network_topology_edge(
    request: Request,
    src: Optional[str] = None,
    dst: Optional[str] = None,
    range: str = "24h",
    exclude_private: bool = False,
    grouped: bool = True,
    expanded: Optional[str] = None,
    user: User = Depends(require_permission(READ)),
    session: Session = Depends(get_db_session),
):
    loaded = await _load(range, exclude_private, user, session)
    return render_view(
        request, EDGE, _edge_view(loaded, src, dst, grouped, _expanded(expanded)),
    )
