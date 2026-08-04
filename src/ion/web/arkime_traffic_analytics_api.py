"""Arkime Traffic Analytics API — volume histograms + protocol mix + top talkers + geo.

Five endpoints under /api/arkime/traffic:
  GET /status          — is Arkime configured?
  GET /overview        — time-bucketed ingress/egress bytes + protocol mix
  GET /top-talkers     — top source/dest IPs by total bytes
  GET /top-countries   — top source/dest countries by total bytes (GeoIP)
  GET /per-node        — traffic volume broken down per Arkime capture node
  GET /rtmon-summary   — Real-Time Monitor detections (per-detector/severity/day)

All are read-only and require alert:read permission (same level as
the existing Arkime PCAP workflow).
"""

from __future__ import annotations

import ipaddress
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_db_session, require_permission
from ion.core.safe_errors import safe_error
from ion.models.alert_triage import AlertCase, AlertTriage
from ion.models.traffic_exclusion import TrafficExclusion
from ion.models.user import AuditLog, User
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


def _active_exclusion_cidrs(session: Session) -> List[str]:
    """Current exclusion CIDRs. Best-effort — a query failure must not break
    the analytics views, so it degrades to no exclusions."""
    try:
        rows = session.query(TrafficExclusion).order_by(TrafficExclusion.id).all()
        return [r.cidr for r in rows]
    except Exception as exc:  # noqa: BLE001
        logger.debug("Traffic exclusion load failed: %s", exc)
        return []


def _exclusion_expression(session: Session) -> Optional[str]:
    """Arkime ``ip != cidr`` expression for the active exclusion list (or None)."""
    expr = get_arkime_service().build_exclusion_expression(_active_exclusion_cidrs(session))
    return expr or None


def _pct(cur: float, prev: float) -> Optional[float]:
    if not prev:
        return None
    return round((cur - prev) / prev * 100.0, 1)


def _trend(cur_sessions: int, cur_bytes: int, prev: Dict[str, int]) -> Dict[str, Any]:
    """Period-over-period deltas vs the immediately-preceding equal window."""
    return {
        "prev_sessions": prev.get("total_sessions", 0),
        "prev_bytes": prev.get("total_bytes", 0),
        "sessions_pct": _pct(cur_sessions, prev.get("total_sessions", 0)),
        "bytes_pct": _pct(cur_bytes, prev.get("total_bytes", 0)),
    }


@router.get("/overview")
async def traffic_overview(
    range: str = "24h",
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
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
        expr = _exclusion_expression(session)
        data = await svc.get_traffic_overview(start_ts, stop_ts, expression=expr)
        # Period-over-period trend vs the immediately-preceding equal window.
        span = stop_ts - start_ts
        try:
            prev = await svc.get_traffic_totals(start_ts - span, start_ts, expression=expr)
            data["trend"] = _trend(
                data.get("total_sessions", 0), data.get("total_bytes", 0), prev
            )
        except ArkimeError:
            data["trend"] = None
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
    session: Session = Depends(get_db_session),
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
            expression=_exclusion_expression(session),
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
    session: Session = Depends(get_db_session),
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
        data = await svc.get_top_countries(
            start_ts, stop_ts, expression=_exclusion_expression(session)
        )
        data["range"] = range
        return data
    except ArkimeError as exc:
        logger.warning("Arkime top-countries error: %s", exc)
        raise HTTPException(status_code=502, detail=safe_error(exc))


@router.get("/per-node")
async def traffic_per_node(
    range: str = "24h",
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
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
        data = await svc.get_per_node_traffic(
            start_ts, stop_ts, expression=_exclusion_expression(session)
        )
        data["range"] = range
        return data
    except ArkimeError as exc:
        logger.warning("Arkime per-node error: %s", exc)
        raise HTTPException(status_code=502, detail=safe_error(exc))


# ── Real-Time Monitor (RTMON) detection summary ──────────────────────────
# RTMON has no API of its own — its hits are stored as cases: AlertCase +
# AlertTriage where source_system == "arkime-rtmon", with the detector encoded
# in the AlertTriage.es_alert_id marker as `rtmon:<detector>:...`. This endpoint
# aggregates those cases on-read (no new table). RTMON is opt-in
# (ION_ARKIME_RTMON_ENABLED, default off), so it degrades to an empty-but-valid
# shape when it has never run.

_RTMON_SOURCE = "arkime-rtmon"


def _rtmon_detector(marker: Optional[str]) -> str:
    """Parse the detector name from an RTMON marker (`rtmon:<detector>:...`).

    Unknown / malformed markers collapse to "other" so the breakdown never
    drops a case."""
    parts = (marker or "").split(":")
    if len(parts) >= 2 and parts[0] == "rtmon" and parts[1]:
        return parts[1]
    return "other"


@router.get("/rtmon-summary")
def rtmon_summary(
    days: int = 7,
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
) -> Dict[str, Any]:
    """Real-Time Monitor detection summary over the last ``days``.

    Query params:
        days: lookback window, 1–90 (default 7)

    Response shape:
        {
            "days": 7,
            "total": N,
            "by_detector": [{"detector": "c2_beacon_shape", "count": N}, ...],
            "by_severity": [{"severity": "high", "count": N}, ...],
            "daily":       [{"date": "2026-08-01", "count": N}, ...],
            "enabled": true,     # false when RTMON has produced no cases at all
        }

    Always returns a valid shape — empty series when RTMON has never run.
    """
    days = min(max(days, 1), 90)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(days=days)

    # Pre-seed the daily buckets so the timeline is continuous (zero-filled),
    # not just the days that happened to have a detection.
    daily_counts: Dict[str, int] = {}
    for i in range(days):
        d = (cutoff + timedelta(days=i + 1)).date().isoformat()
        daily_counts[d] = 0

    empty = {
        "days": days,
        "total": 0,
        "by_detector": [],
        "by_severity": [],
        "daily": [{"date": d, "count": c} for d, c in sorted(daily_counts.items())],
        "enabled": False,
    }

    try:
        rows = (
            session.query(
                AlertTriage.es_alert_id,
                AlertCase.severity,
                AlertCase.created_at,
            )
            .join(AlertCase, AlertTriage.case_id == AlertCase.id)
            .filter(AlertTriage.source_system == _RTMON_SOURCE)
            .filter(AlertCase.created_at >= cutoff)
            .all()
        )
    except Exception as exc:  # noqa: BLE001 — analytics view must never 500
        logger.debug("RTMON summary query failed: %s", exc)
        return empty

    if not rows:
        return empty

    detector_counts: Dict[str, int] = {}
    severity_counts: Dict[str, int] = {}
    total = 0
    for marker, severity, created_at in rows:
        total += 1
        det = _rtmon_detector(marker)
        detector_counts[det] = detector_counts.get(det, 0) + 1
        sev = (severity or "unknown").strip().lower() or "unknown"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if created_at is not None:
            key = created_at.date().isoformat()
            if key in daily_counts:
                daily_counts[key] += 1

    return {
        "days": days,
        "total": total,
        "by_detector": sorted(
            [{"detector": k, "count": v} for k, v in detector_counts.items()],
            key=lambda r: r["count"], reverse=True,
        ),
        "by_severity": sorted(
            [{"severity": k, "count": v} for k, v in severity_counts.items()],
            key=lambda r: r["count"], reverse=True,
        ),
        "daily": [{"date": d, "count": c} for d, c in sorted(daily_counts.items())],
        "enabled": True,
    }


# ── Exclusion-list management ────────────────────────────────────────────
# Shared, server-side filter applied to every analytics view above. Reads are
# alert:read (same as the page); writes are security:read (lead) since one
# analyst's exclusion shapes everyone's view, and are audit-logged.


class ExclusionCreate(BaseModel):
    cidr: str = Field(..., min_length=1, max_length=64)
    note: Optional[str] = Field(default=None, max_length=255)


@router.get("/exclusions")
def list_exclusions(
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
) -> Dict[str, Any]:
    """List the active traffic-analytics IP/CIDR exclusions."""
    rows = session.query(TrafficExclusion).order_by(TrafficExclusion.id).all()
    return {"exclusions": [r.to_dict() for r in rows]}


@router.post("/exclusions")
def add_exclusion(
    payload: ExclusionCreate,
    user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
) -> Dict[str, Any]:
    """Add an IP or CIDR to the exclusion list (lead-gated, audit-logged)."""
    cidr = payload.cidr.strip()
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP/CIDR: {cidr!r}")
    existing = session.query(TrafficExclusion).filter(TrafficExclusion.cidr == cidr).first()
    if existing:
        return {"exclusion": existing.to_dict(), "created": False}
    row = TrafficExclusion(
        cidr=cidr, note=(payload.note or "").strip() or None, created_by_id=user.id
    )
    session.add(row)
    session.add(AuditLog(
        user_id=user.id, action="traffic_exclusion_added",
        resource_type="traffic_exclusion", resource_id=None,
        details=f"{cidr}" + (f" — {payload.note}" if payload.note else ""),
    ))
    session.commit()
    session.refresh(row)
    return {"exclusion": row.to_dict(), "created": True}


@router.delete("/exclusions/{exclusion_id}")
def delete_exclusion(
    exclusion_id: int,
    user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
) -> Dict[str, Any]:
    """Remove an exclusion (lead-gated, audit-logged)."""
    row = session.get(TrafficExclusion, exclusion_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Exclusion not found")
    cidr = row.cidr
    session.delete(row)
    session.add(AuditLog(
        user_id=user.id, action="traffic_exclusion_removed",
        resource_type="traffic_exclusion", resource_id=exclusion_id,
        details=cidr,
    ))
    session.commit()
    return {"deleted": exclusion_id, "cidr": cidr}


# ── AI traffic-pattern review ────────────────────────────────────────────


class AIReviewRequest(BaseModel):
    node: str = Field(..., min_length=1, max_length=128)
    range: str = Field(default="24h")


_AI_REVIEW_SYSTEM = (
    "You are Bob, ION's autonomous SOC analyst, reviewing NETWORK TRAFFIC for a "
    "single Arkime capture node over a time window. You are given an aggregated "
    "traffic profile (volume, protocol mix, top source/destination IPs, top "
    "countries). Identify what is NOTABLE or ANOMALOUS from a threat-hunting "
    "perspective — unusual destinations, suspicious protocols/ports, likely "
    "beaconing or exfiltration patterns, traffic to high-risk geographies, and "
    "anything worth pulling the full PCAP for before it ages out of retention. "
    "Ground every observation in the SPECIFIC IPs / countries / protocols / byte "
    "counts provided — never invent values. Output markdown with: "
    "1) **Summary** (2-3 sentences). 2) **Notable patterns** (bullets, each "
    "citing the concrete figure). 3) **Recommended hunts / PCAP pulls** (3-5 "
    "bullets). Be concise — under 350 words."
)


def _fmt_bytes(n: int) -> str:
    f = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or unit == "TB":
            return f"{f:.1f}{unit}"
        f /= 1024
    return f"{f:.1f}TB"


def _build_ai_review_prompt(profile: Dict[str, Any], range_str: str) -> str:
    p = profile
    lines = [
        f"## Traffic profile — node `{p.get('node')}` over {range_str}",
        f"- Total sessions: {p.get('total_sessions', 0)}",
        f"- Total volume: {_fmt_bytes(p.get('total_bytes', 0))}",
        "",
        "### Protocol mix",
    ]
    protos = p.get("protocols") or {}
    if protos:
        for name, cnt in sorted(protos.items(), key=lambda kv: kv[1], reverse=True)[:12]:
            lines.append(f"- {name}: {cnt}")
    else:
        lines.append("- (none reported)")

    def _ip_block(title: str, rows: List[dict]) -> None:
        lines.append("")
        lines.append(f"### {title}")
        if not rows:
            lines.append("- (none)")
            return
        for r in rows:
            lines.append(f"- {r.get('ip')}: {_fmt_bytes(r.get('bytes', 0))} over {r.get('sessions', 0)} sessions")

    _ip_block("Top source IPs", p.get("top_src", []))
    _ip_block("Top destination IPs", p.get("top_dst", []))

    def _geo_block(title: str, rows: List[dict]) -> None:
        lines.append("")
        lines.append(f"### {title}")
        if not rows:
            lines.append("- (none)")
            return
        for r in rows:
            lines.append(f"- {r.get('country')}: {_fmt_bytes(r.get('bytes', 0))} over {r.get('sessions', 0)} sessions")

    _geo_block("Top source countries", p.get("src_countries", []))
    _geo_block("Top destination countries", p.get("dst_countries", []))
    lines.append("")
    lines.append("Produce the Summary + Notable patterns + Recommended hunts sections.")
    return "\n".join(lines)


@router.post("/ai-review")
async def traffic_ai_review(
    payload: AIReviewRequest,
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
) -> Dict[str, Any]:
    """Bob (Foundation-Sec) reviews the traffic profile for a node + window and
    flags notable/anomalous patterns + PCAP-pull recommendations. 503 when
    Arkime or Ollama is unavailable."""
    if payload.range not in _RANGES:
        raise HTTPException(status_code=400, detail=f"Invalid range '{payload.range}'")
    svc = get_arkime_service()
    if not svc.is_configured:
        raise HTTPException(status_code=503, detail="Arkime is not configured")
    start_ts, stop_ts = _range_to_epoch(payload.range)
    try:
        profile = await svc.get_node_traffic_profile(
            payload.node.strip(), start_ts, stop_ts,
            expression=_exclusion_expression(session),
        )
    except ArkimeError as exc:
        logger.warning("Arkime node profile error: %s", exc)
        raise HTTPException(status_code=502, detail=safe_error(exc))

    from ion.services.ollama_service import get_ollama_service
    ollama = get_ollama_service()
    if not getattr(ollama, "enabled", True):
        raise HTTPException(status_code=503, detail="Ollama is disabled — AI review unavailable")
    try:
        result = await ollama.chat(
            messages=[{"role": "user", "content": _build_ai_review_prompt(profile, payload.range)}],
            system_prompt=_AI_REVIEW_SYSTEM,
            context_type="security",
            user_id=user.id,
            temperature=0.3,
            max_tokens=700,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Traffic AI review LLM call failed: %s", exc)
        raise HTTPException(status_code=503, detail=f"LLM call failed: {safe_error(exc)}")
    analysis = (result or {}).get("content") or ""
    if not analysis.strip():
        raise HTTPException(status_code=503, detail="Bob returned an empty response — please retry.")
    return {
        "analysis": analysis.strip(),
        "model": (result or {}).get("model"),
        "node": payload.node,
        "range": payload.range,
        "profile": profile,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
