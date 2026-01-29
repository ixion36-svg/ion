"""Security dashboard API endpoints."""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ixion.auth.dependencies import get_current_user, require_permission
from ixion.models.user import User
from ixion.models.security import (
    SecurityEventSeverity,
    SecurityEventStatus,
    SecurityEventType,
)
from ixion.services.security_service import (
    SecurityDetectionService,
    SIEMExportService,
)
from ixion.auth.dependencies import get_db_session
from ixion.core.logging import get_structured_logger


router = APIRouter(tags=["security"])
logger = get_structured_logger(__name__)


# =============================================================================
# Pydantic Models
# =============================================================================


class SecurityEventResponse(BaseModel):
    """Security event response model."""

    id: int
    event_type: str
    severity: str
    status: str
    title: str
    description: str
    source_ip: str
    user_agent: Optional[str] = None
    request_path: Optional[str] = None
    request_method: Optional[str] = None
    user_id: Optional[int] = None
    username: Optional[str] = None
    detection_rule: str
    confidence_score: int
    event_count: int
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    blocked: bool
    exported_to_siem: bool
    matched_patterns: Optional[List[str]] = None
    raw_data: Optional[dict] = None
    created_at: Optional[str] = None


class SecurityStatisticsResponse(BaseModel):
    """Security statistics response."""

    total_events: int
    by_severity: dict
    by_type: dict
    top_source_ips: List[dict]
    blocked_count: int
    time_period_hours: int


class TimelineDataPoint(BaseModel):
    """Timeline data point."""

    timestamp: str
    total: int
    critical: int
    high: int


class BlockedIPResponse(BaseModel):
    """Blocked IP response."""

    id: int
    ip_address: str
    reason: str
    blocked_until: Optional[str] = None
    permanent: bool
    created_at: Optional[str] = None


class BlockIPRequest(BaseModel):
    """Request to block an IP."""

    ip_address: str = Field(..., description="IP address to block")
    reason: str = Field(..., description="Reason for blocking")
    duration_minutes: Optional[int] = Field(60, description="Block duration in minutes")
    permanent: bool = Field(False, description="Permanent block")


class UnblockIPRequest(BaseModel):
    """Request to unblock an IP."""

    ip_address: str = Field(..., description="IP address to unblock")


class UpdateEventStatusRequest(BaseModel):
    """Request to update event status."""

    status: str = Field(..., description="New status")


class SIEMExportResponse(BaseModel):
    """SIEM export response."""

    exported_count: int
    events: List[dict]
    format: str


class AlertRuleResponse(BaseModel):
    """Alert rule response."""

    id: int
    name: str
    description: Optional[str] = None
    enabled: bool
    event_type: str
    threshold: int
    time_window_minutes: int
    severity: str
    block_source: bool
    send_to_siem: bool


class AlertRuleCreate(BaseModel):
    """Create alert rule request."""

    name: str
    description: Optional[str] = None
    enabled: bool = True
    event_type: str
    threshold: int = 5
    time_window_minutes: int = 5
    severity: str = "medium"
    patterns: Optional[List[str]] = None
    ip_whitelist: Optional[List[str]] = None
    ip_blacklist: Optional[List[str]] = None
    block_source: bool = False
    send_to_siem: bool = True


# =============================================================================
# API Endpoints
# =============================================================================


@router.get("/events", response_model=List[SecurityEventResponse])
async def get_security_events(
    hours: int = Query(24, ge=1, le=168, description="Time period in hours"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum events to return"),
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_permission("audit:read")),
):
    """Get recent security events."""
    security_service = SecurityDetectionService(session)

    # Parse severity
    severity_enum = None
    if severity:
        try:
            severity_enum = SecurityEventSeverity(severity.lower())
        except ValueError:
            pass

    events = security_service.get_recent_events(
        hours=hours,
        severity=severity_enum,
        limit=limit,
    )

    return [
        SecurityEventResponse(**event.to_dict())
        for event in events
    ]


@router.get("/events/{event_id}", response_model=SecurityEventResponse)
async def get_security_event(
    event_id: int,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_permission("audit:read")),
):
    """Get a specific security event."""
    from ixion.storage.security_repository import SecurityEventRepository

    repo = SecurityEventRepository(session)
    event = repo.get_by_id(event_id)

    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    return SecurityEventResponse(**event.to_dict())


@router.patch("/events/{event_id}/status")
async def update_event_status(
    event_id: int,
    request: UpdateEventStatusRequest,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_permission("audit:write")),
):
    """Update security event status."""
    security_service = SecurityDetectionService(session)

    try:
        status = SecurityEventStatus(request.status.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Valid values: {[s.value for s in SecurityEventStatus]}",
        )

    event = security_service.update_event_status(event_id, status)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    session.commit()

    logger.access_event(
        resource_type="security_event",
        resource_id=event_id,
        action="update_status",
        outcome="success",
    )

    return {"message": "Status updated", "event_id": event_id, "status": status.value}


@router.get("/statistics", response_model=SecurityStatisticsResponse)
async def get_security_statistics(
    hours: int = Query(24, ge=1, le=168, description="Time period in hours"),
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_permission("audit:read")),
):
    """Get security event statistics."""
    security_service = SecurityDetectionService(session)
    stats = security_service.get_statistics(hours)
    return SecurityStatisticsResponse(**stats)


@router.get("/timeline", response_model=List[TimelineDataPoint])
async def get_security_timeline(
    hours: int = Query(24, ge=1, le=168, description="Time period in hours"),
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_permission("audit:read")),
):
    """Get security event timeline for charts."""
    security_service = SecurityDetectionService(session)
    timeline = security_service.get_timeline(hours)
    return [TimelineDataPoint(**point) for point in timeline]


@router.get("/blocked-ips", response_model=List[BlockedIPResponse])
async def get_blocked_ips(
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_permission("audit:read")),
):
    """Get list of blocked IP addresses."""
    security_service = SecurityDetectionService(session)
    blocked = security_service.get_blocked_ips()

    return [
        BlockedIPResponse(
            id=b.id,
            ip_address=b.ip_address,
            reason=b.reason,
            blocked_until=b.blocked_until.isoformat() if b.blocked_until else None,
            permanent=b.permanent,
            created_at=b.created_at.isoformat() if b.created_at else None,
        )
        for b in blocked
    ]


@router.post("/blocked-ips")
async def block_ip(
    request: BlockIPRequest,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_permission("audit:write")),
):
    """Block an IP address."""
    security_service = SecurityDetectionService(session)

    blocked = security_service.block_ip(
        ip_address=request.ip_address,
        reason=request.reason,
        duration_minutes=request.duration_minutes,
        permanent=request.permanent,
    )
    session.commit()

    logger.security_event(
        action="manual_ip_block",
        outcome="success",
        details={
            "ip": request.ip_address,
            "reason": request.reason,
            "blocked_by": current_user.username,
        },
    )

    return {
        "message": "IP blocked",
        "ip_address": request.ip_address,
        "blocked_until": blocked.blocked_until.isoformat() if blocked.blocked_until else None,
        "permanent": blocked.permanent,
    }


@router.delete("/blocked-ips/{ip_address}")
async def unblock_ip(
    ip_address: str,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_permission("audit:write")),
):
    """Unblock an IP address."""
    security_service = SecurityDetectionService(session)

    if security_service.unblock_ip(ip_address):
        session.commit()

        logger.security_event(
            action="manual_ip_unblock",
            outcome="success",
            details={
                "ip": ip_address,
                "unblocked_by": current_user.username,
            },
        )

        return {"message": "IP unblocked", "ip_address": ip_address}

    raise HTTPException(status_code=404, detail="IP not found in block list")


@router.get("/export/siem", response_model=SIEMExportResponse)
async def export_to_siem(
    format: str = Query("json", description="Export format: json or syslog"),
    limit: int = Query(1000, ge=1, le=10000, description="Maximum events to export"),
    mark_exported: bool = Query(True, description="Mark events as exported"),
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_permission("audit:read")),
):
    """Export security events for SIEM ingestion."""
    siem_service = SIEMExportService(session)
    events = siem_service.get_unexported_events(limit)

    if format == "syslog":
        exported = siem_service.export_to_syslog_format(events)
        export_data = [{"message": msg} for msg in exported]
    else:
        export_data = siem_service.export_to_json(events)

    if mark_exported and events:
        event_ids = [e.id for e in events]
        siem_service.mark_exported(event_ids)
        session.commit()

    logger.access_event(
        resource_type="security_events",
        resource_id="export",
        action="siem_export",
        outcome="success",
    )

    return SIEMExportResponse(
        exported_count=len(events),
        events=export_data,
        format=format,
    )


@router.get("/export/download")
async def download_events(
    hours: int = Query(24, ge=1, le=720, description="Time period in hours"),
    format: str = Query("json", description="Export format: json or csv"),
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_permission("audit:read")),
):
    """Download security events as a file."""
    from fastapi.responses import Response
    import json
    import csv
    import io

    security_service = SecurityDetectionService(session)
    events = security_service.get_recent_events(hours=hours, limit=10000)

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "ID", "Timestamp", "Event Type", "Severity", "Status",
            "Title", "Source IP", "Username", "Request Path",
            "Detection Rule", "Confidence", "Event Count", "Blocked"
        ])

        # Data
        for event in events:
            writer.writerow([
                event.id,
                event.created_at.isoformat() if event.created_at else "",
                event.event_type.value,
                event.severity.value,
                event.status.value,
                event.title,
                event.source_ip,
                event.username or "",
                event.request_path or "",
                event.detection_rule,
                event.confidence_score,
                event.event_count,
                "Yes" if event.blocked else "No",
            ])

        content = output.getvalue()
        media_type = "text/csv"
        filename = f"security_events_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"

    else:
        content = json.dumps(
            [event.to_siem_format() for event in events],
            indent=2,
            default=str,
        )
        media_type = "application/json"
        filename = f"security_events_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/threat-summary")
async def get_threat_summary(
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_permission("audit:read")),
):
    """Get a summary of current threats and security posture."""
    security_service = SecurityDetectionService(session)

    # Get stats for different time periods
    stats_1h = security_service.get_statistics(hours=1)
    stats_24h = security_service.get_statistics(hours=24)
    stats_7d = security_service.get_statistics(hours=168)

    # Get active blocks
    blocked_ips = security_service.get_blocked_ips()

    # Calculate threat level
    critical_count = stats_24h["by_severity"].get("critical", 0)
    high_count = stats_24h["by_severity"].get("high", 0)

    if critical_count > 0:
        threat_level = "critical"
    elif high_count > 5:
        threat_level = "high"
    elif stats_24h["total_events"] > 50:
        threat_level = "medium"
    elif stats_24h["total_events"] > 10:
        threat_level = "low"
    else:
        threat_level = "normal"

    return {
        "threat_level": threat_level,
        "active_blocks": len(blocked_ips),
        "last_hour": {
            "total": stats_1h["total_events"],
            "blocked": stats_1h["blocked_count"],
        },
        "last_24_hours": {
            "total": stats_24h["total_events"],
            "blocked": stats_24h["blocked_count"],
            "by_severity": stats_24h["by_severity"],
        },
        "last_7_days": {
            "total": stats_7d["total_events"],
            "blocked": stats_7d["blocked_count"],
        },
        "top_threats": [
            {"type": t, "count": c}
            for t, c in sorted(
                stats_24h["by_type"].items(),
                key=lambda x: x[1],
                reverse=True,
            )[:5]
        ],
        "top_attackers": stats_24h["top_source_ips"][:5],
    }


@router.get("/event-types")
async def get_event_types(
    current_user: User = Depends(require_permission("audit:read")),
):
    """Get available security event types."""
    return {
        "event_types": [
            {"value": t.value, "label": t.value.replace("_", " ").title()}
            for t in SecurityEventType
        ],
        "severities": [
            {"value": s.value, "label": s.value.title()}
            for s in SecurityEventSeverity
        ],
        "statuses": [
            {"value": s.value, "label": s.value.replace("_", " ").title()}
            for s in SecurityEventStatus
        ],
    }
