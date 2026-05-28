"""Arkime Traffic Analytics API — volume histograms + protocol mix + top talkers + geo.

Five endpoints under /api/arkime/traffic:
  GET /status          — is Arkime configured?
  GET /overview        — time-bucketed ingress/egress bytes + protocol mix
  GET /top-talkers     — top source/dest IPs by total bytes
  GET /top-countries   — top source/dest countries by total bytes (GeoIP)
  GET /per-node        — traffic volume broken down per Arkime capture node

All are read-only and require alert:read permission (same level as
the existing Arkime PCAP workflow).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from ion.auth.dependencies import require_permission
from ion.core.safe_errors import safe_error
from ion.models.user import User
from ion.services.arkime_service import ArkimeError, get_arkime_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/arkime/traffic", tags=["arkime-traffic"])

_RANGES: Dict[str, int] = {
    "24h": 24 * 3600,
    "7d": 7 * 24 * 3600,
    "30d": 30 * 24 * 3600,
}


def _range_to_epoch(range_str: str) -> tuple[int, int]:
    seconds = _RANGES.get(range_str, _RANGES["24h"])
    now = int(time.time())
    return now - seconds, now


@router.get("/status")
async def traffic_status(user: User = Depends(require_permission("alert:read"))):
    """Check whether Arkime is configured for traffic analytics."""
    svc = get_arkime_service()
    return {"configured": svc.is_configured}


@router.get("/overview")
async def traffic_overview(
    range: str = "24h",
    user: User = Depends(require_permission("alert:read")),
) -> Dict[str, Any]:
    """Return time-bucketed traffic histogram + protocol distribution.

    Query params:
        range: 24h | 7d | 30d  (default 24h)

    Response shape:
        {
            "src_histo":  [[epoch_ms, bytes], ...],
            "dst_histo":  [[epoch_ms, bytes], ...],
            "protocols":  {"tcp": N, ...},
            "total_sessions": N,
            "total_bytes": N,
            "range": "24h",
        }
    """
    if range not in _RANGES:
        raise HTTPException(status_code=400, detail=f"Invalid range '{range}'. Use: 24h, 7d, 30d")
    svc = get_arkime_service()
    if not svc.is_configured:
        raise HTTPException(status_code=503, detail="Arkime is not configured")
    start_ts, stop_ts = _range_to_epoch(range)
    try:
        data = await svc.get_traffic_overview(start_ts, stop_ts)
        data["range"] = range
        return data
    except ArkimeError as exc:
        logger.warning("Arkime traffic overview error: %s", exc)
        raise HTTPException(status_code=502, detail=safe_error(exc))


@router.get("/top-talkers")
async def traffic_top_talkers(
    range: str = "24h",
    limit: int = 10,
    exclude_private: bool = True,
    user: User = Depends(require_permission("alert:read")),
) -> Dict[str, Any]:
    """Return top source and destination IPs by total bytes.

    Query params:
        range:           24h | 7d | 30d  (default 24h)
        limit:           IPs per direction (default 10, max 25)
        exclude_private: drop sessions where both endpoints are RFC-1918
                         addresses (default true)

    Response shape:
        {
            "by_src": [{"ip": "1.2.3.4", "bytes": N, "sessions": N}, ...],
            "by_dst": [{"ip": "1.2.3.4", "bytes": N, "sessions": N}, ...],
            "range": "24h",
        }
    """
    if range not in _RANGES:
        raise HTTPException(status_code=400, detail=f"Invalid range '{range}'. Use: 24h, 7d, 30d")
    limit = min(max(limit, 1), 25)
    svc = get_arkime_service()
    if not svc.is_configured:
        raise HTTPException(status_code=503, detail="Arkime is not configured")
    start_ts, stop_ts = _range_to_epoch(range)
    try:
        data = await svc.get_top_talkers(
            start_ts, stop_ts, limit=limit,
            exclude_private_to_private=exclude_private,
        )
        data["range"] = range
        return data
    except ArkimeError as exc:
        logger.warning("Arkime top-talkers error: %s", exc)
        raise HTTPException(status_code=502, detail=safe_error(exc))


@router.get("/top-countries")
async def traffic_top_countries(
    range: str = "24h",
    user: User = Depends(require_permission("alert:read")),
) -> Dict[str, Any]:
    """Return top source and destination countries by total bytes.

    Query params:
        range: 24h | 7d | 30d  (default 24h)

    Response shape:
        {
            "by_src": [{"country": "US", "bytes": N, "sessions": N}, ...],
            "by_dst": [{"country": "US", "bytes": N, "sessions": N}, ...],
            "range": "24h",
        }
    """
    if range not in _RANGES:
        raise HTTPException(status_code=400, detail=f"Invalid range '{range}'. Use: 24h, 7d, 30d")
    svc = get_arkime_service()
    if not svc.is_configured:
        raise HTTPException(status_code=503, detail="Arkime is not configured")
    start_ts, stop_ts = _range_to_epoch(range)
    try:
        data = await svc.get_top_countries(start_ts, stop_ts)
        data["range"] = range
        return data
    except ArkimeError as exc:
        logger.warning("Arkime top-countries error: %s", exc)
        raise HTTPException(status_code=502, detail=safe_error(exc))


@router.get("/per-node")
async def traffic_per_node(
    range: str = "24h",
    user: User = Depends(require_permission("alert:read")),
) -> Dict[str, Any]:
    """Return traffic volume broken down per Arkime capture node/sensor.

    Query params:
        range: 24h | 7d | 30d  (default 24h)

    Response shape:
        {
            "nodes": [{"node": "dc-core-01", "bytes": N, "sessions": N}, ...],
            "range": "24h",
        }
    """
    if range not in _RANGES:
        raise HTTPException(status_code=400, detail=f"Invalid range '{range}'. Use: 24h, 7d, 30d")
    svc = get_arkime_service()
    if not svc.is_configured:
        raise HTTPException(status_code=503, detail="Arkime is not configured")
    start_ts, stop_ts = _range_to_epoch(range)
    try:
        data = await svc.get_per_node_traffic(start_ts, stop_ts)
        data["range"] = range
        return data
    except ArkimeError as exc:
        logger.warning("Arkime per-node error: %s", exc)
        raise HTTPException(status_code=502, detail=safe_error(exc))
