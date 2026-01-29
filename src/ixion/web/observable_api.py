"""Observable API endpoints for IOC tracking and enrichment.

Provides endpoints for searching, viewing, correlating, and enriching observables.
"""

from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ixion.auth.dependencies import get_db_session, get_current_user
from ixion.models.user import User
from ixion.models.observable import Observable, ObservableType, ThreatLevel
from ixion.services.observable_service import ObservableService

router = APIRouter(tags=["observables"])


# =============================================================================
# Request/Response Models
# =============================================================================

class ObservableResponse(BaseModel):
    """Response model for an observable."""
    id: int
    type: str
    value: str
    normalized_value: str
    first_seen: str
    last_seen: str
    sighting_count: int
    threat_level: str
    is_whitelisted: bool
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    has_enrichment: bool = False
    latest_enrichment_at: Optional[str] = None
    # Watchlist fields
    is_watched: bool = False
    watch_reason: Optional[str] = None
    watched_by: Optional[str] = None
    watched_at: Optional[str] = None
    # Auto-enrich
    auto_enrich: bool = True

    class Config:
        from_attributes = True


class ObservableDetailResponse(ObservableResponse):
    """Detailed response including enrichment data."""
    enrichment: Optional[dict] = None
    alert_count: int = 0
    case_count: int = 0


class ObservableUpdate(BaseModel):
    """Request model for updating an observable."""
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    is_whitelisted: Optional[bool] = None
    threat_level: Optional[str] = None


class ObservableSearchRequest(BaseModel):
    """Request model for bulk search."""
    values: List[str] = Field(..., max_length=100)
    type: Optional[str] = None


class EnrichBatchRequest(BaseModel):
    """Request model for batch enrichment."""
    observable_ids: List[int] = Field(..., max_length=50)
    source: str = "opencti"


class AlertSummary(BaseModel):
    """Summary of an alert for correlation."""
    id: int
    es_alert_id: str
    status: str
    priority: Optional[str] = None
    created_at: str


class CaseSummary(BaseModel):
    """Summary of a case for correlation."""
    id: int
    case_number: str
    title: str
    status: str
    severity: Optional[str] = None
    created_at: str


class CoOccurringObservable(BaseModel):
    """Observable that co-occurs with another."""
    id: int
    type: str
    value: str
    threat_level: str
    co_occurrence_count: int


class StatsResponse(BaseModel):
    """Observable statistics."""
    total: int
    by_type: dict
    by_threat_level: dict
    enriched: int
    whitelisted: int


class MigrationResponse(BaseModel):
    """Migration result."""
    alerts_processed: int
    observables_created: int
    observables_existing: int
    links_created: int
    errors: int


# =============================================================================
# Helper Functions
# =============================================================================

def _observable_to_response(obs: Observable) -> ObservableResponse:
    """Convert Observable model to response."""
    latest = obs.latest_enrichment
    return ObservableResponse(
        id=obs.id,
        type=obs.type.value if hasattr(obs.type, 'value') else obs.type,
        value=obs.value,
        normalized_value=obs.normalized_value,
        first_seen=obs.first_seen.isoformat(),
        last_seen=obs.last_seen.isoformat(),
        sighting_count=obs.sighting_count,
        threat_level=obs.threat_level.value if hasattr(obs.threat_level, 'value') else obs.threat_level,
        is_whitelisted=obs.is_whitelisted,
        tags=obs.tags,
        notes=obs.notes,
        has_enrichment=latest is not None,
        latest_enrichment_at=latest.enriched_at.isoformat() if latest else None,
        is_watched=obs.is_watched,
        watch_reason=obs.watch_reason,
        watched_by=obs.watched_by,
        watched_at=obs.watched_at.isoformat() if obs.watched_at else None,
        auto_enrich=obs.auto_enrich,
    )


def _observable_to_detail(obs: Observable, session: Session) -> ObservableDetailResponse:
    """Convert Observable model to detailed response."""
    latest = obs.latest_enrichment
    enrichment_data = None
    if latest:
        enrichment_data = {
            "source": latest.source,
            "enriched_at": latest.enriched_at.isoformat(),
            "is_malicious": latest.is_malicious,
            "score": latest.score,
            "labels": latest.labels,
            "threat_actors": latest.threat_actors,
            "indicators": latest.indicators,
            "reports": latest.reports,
        }

    return ObservableDetailResponse(
        id=obs.id,
        type=obs.type.value if hasattr(obs.type, 'value') else obs.type,
        value=obs.value,
        normalized_value=obs.normalized_value,
        first_seen=obs.first_seen.isoformat(),
        last_seen=obs.last_seen.isoformat(),
        sighting_count=obs.sighting_count,
        threat_level=obs.threat_level.value if hasattr(obs.threat_level, 'value') else obs.threat_level,
        is_whitelisted=obs.is_whitelisted,
        tags=obs.tags,
        notes=obs.notes,
        has_enrichment=latest is not None,
        latest_enrichment_at=latest.enriched_at.isoformat() if latest else None,
        enrichment=enrichment_data,
        alert_count=len(obs.alert_links),
        case_count=len(obs.case_links),
    )


# =============================================================================
# Search & List Endpoints
# =============================================================================

@router.get("/observables")
async def search_observables(
    query: Optional[str] = Query(None, description="Search term"),
    type: Optional[str] = Query(None, description="Filter by type"),
    threat_level: Optional[str] = Query(None, description="Filter by threat level"),
    is_whitelisted: Optional[bool] = Query(None, description="Filter by whitelist status"),
    is_enriched: Optional[bool] = Query(None, description="Filter by enrichment status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Search observables with filters."""
    service = ObservableService(session)

    types = [type] if type else None
    results, total = service.search(
        query=query,
        types=types,
        threat_level=threat_level,
        is_whitelisted=is_whitelisted,
        is_enriched=is_enriched,
        limit=limit,
        offset=offset,
    )

    return {
        "observables": [_observable_to_response(obs) for obs in results],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/observables/stats")
async def get_observable_stats(
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> StatsResponse:
    """Get observable statistics for dashboard."""
    service = ObservableService(session)
    stats = service.get_stats()
    return StatsResponse(**stats)


@router.get("/observables/top")
async def get_top_observables(
    type: Optional[str] = Query(None, description="Filter by type"),
    limit: int = Query(10, ge=1, le=50),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Get most frequently seen observables."""
    service = ObservableService(session)
    results = service.get_top_observables(obs_type=type, limit=limit)
    return {
        "observables": [_observable_to_response(obs) for obs in results],
    }


@router.get("/observables/graph")
async def get_relationship_graph(
    observable_id: Optional[int] = Query(None, description="Center node ID"),
    limit: int = Query(100, ge=10, le=500),
    min_co_occurrence: int = Query(2, ge=1, le=100),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Get relationship graph data for visualization."""
    service = ObservableService(session)
    graph = service.get_relationship_graph(
        observable_id=observable_id,
        limit=limit,
        min_co_occurrence=min_co_occurrence,
    )
    return graph


@router.get("/observables/patterns")
async def detect_patterns(
    time_window_minutes: int = Query(60, ge=5, le=1440),
    min_occurrences: int = Query(3, ge=2, le=100),
    limit: int = Query(20, ge=1, le=100),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Detect patterns of observables that appear together."""
    service = ObservableService(session)
    patterns = service.detect_patterns(
        time_window_minutes=time_window_minutes,
        min_occurrences=min_occurrences,
        limit=limit,
    )
    return {"patterns": patterns, "total": len(patterns)}


@router.get("/observables/clusters")
async def get_time_clusters(
    hours: int = Query(24, ge=1, le=168),
    interval_minutes: int = Query(30, ge=5, le=360),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Get time-based activity clusters."""
    service = ObservableService(session)
    clusters = service.get_time_clusters(hours=hours, interval_minutes=interval_minutes)
    return {"clusters": clusters}


# =============================================================================
# Watchlist Endpoints (MUST come before {observable_id} routes)
# =============================================================================

class WatchlistAddRequest(BaseModel):
    """Request to add observable to watchlist."""
    reason: Optional[str] = None


class WatchlistAlertResponse(BaseModel):
    """Response model for a watchlist alert."""
    id: int
    observable_id: int
    alert_type: str
    message: str
    details: Optional[dict] = None
    created_at: str
    is_read: bool
    read_by: Optional[str] = None
    read_at: Optional[str] = None
    observable_value: Optional[str] = None
    observable_type: Optional[str] = None


@router.get("/observables/watchlist")
async def get_watchlist(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Get all watched observables."""
    service = ObservableService(session)
    observables, total = service.get_watched_observables(limit=limit, offset=offset)
    return {
        "items": [_observable_to_response(obs) for obs in observables],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/observables/watchlist/alerts")
async def get_watchlist_alerts(
    is_read: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Get watchlist alerts."""
    service = ObservableService(session)
    alerts, total = service.get_watchlist_alerts(
        is_read=is_read,
        limit=limit,
        offset=offset,
    )

    items = []
    for alert in alerts:
        obs = alert.observable
        items.append(WatchlistAlertResponse(
            id=alert.id,
            observable_id=alert.observable_id,
            alert_type=alert.alert_type.value if hasattr(alert.alert_type, 'value') else str(alert.alert_type),
            message=alert.message,
            details=alert.details,
            created_at=alert.created_at.isoformat() if alert.created_at else "",
            is_read=alert.is_read,
            read_by=alert.read_by,
            read_at=alert.read_at.isoformat() if alert.read_at else None,
            observable_value=obs.value if obs else None,
            observable_type=obs.type.value if obs else None,
        ))

    return {
        "items": [item.model_dump() for item in items],
        "total": total,
        "unread_count": total if is_read is False else None,
    }


# =============================================================================
# Import/Export Endpoints (MUST come before {observable_id} routes)
# =============================================================================

class CSVImportRequest(BaseModel):
    """Request for CSV import."""
    csv_data: str
    default_type: Optional[str] = None
    auto_enrich: bool = False
    tags: Optional[List[str]] = None


class STIXImportRequest(BaseModel):
    """Request for STIX import."""
    stix_bundle: dict
    tags: Optional[List[str]] = None


@router.post("/observables/import/csv")
async def import_from_csv(
    data: CSVImportRequest,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Import observables from CSV data."""
    service = ObservableService(session)
    result = service.import_from_csv(
        csv_data=data.csv_data,
        default_type=data.default_type,
        auto_enrich=data.auto_enrich,
        tags=data.tags,
    )
    session.commit()
    return result


@router.post("/observables/import/stix")
async def import_from_stix(
    data: STIXImportRequest,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Import observables from STIX 2.1 bundle."""
    service = ObservableService(session)
    result = service.import_from_stix(
        stix_bundle=data.stix_bundle,
        tags=data.tags,
    )
    session.commit()
    return result


@router.get("/observables/export/csv")
async def export_to_csv(
    types: Optional[str] = Query(None, description="Comma-separated types to export"),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    """Export observables to CSV format."""
    from fastapi.responses import Response

    service = ObservableService(session)

    type_list = None
    if types:
        type_list = [ObservableType(t.strip()) for t in types.split(",")]

    csv_data = service.export_to_csv(types=type_list)

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=observables.csv"},
    )


# =============================================================================
# Retention Policy Endpoints (MUST come before {observable_id} routes)
# =============================================================================

class RetentionPolicyRequest(BaseModel):
    """Request for applying retention policy."""
    max_age_days: int = 365
    min_sighting_count: int = 1
    preserve_watched: bool = True
    preserve_enriched: bool = True
    dry_run: bool = True


@router.post("/observables/retention/preview")
async def preview_retention_policy(
    data: RetentionPolicyRequest,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Preview what would be deleted by retention policy."""
    service = ObservableService(session)
    return service.apply_retention_policy(
        max_age_days=data.max_age_days,
        min_sighting_count=data.min_sighting_count,
        preserve_watched=data.preserve_watched,
        preserve_enriched=data.preserve_enriched,
        dry_run=True,
    )


@router.post("/observables/retention/apply")
async def apply_retention_policy(
    data: RetentionPolicyRequest,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Apply retention policy to delete old observables."""
    # Only admins can actually delete
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    service = ObservableService(session)
    result = service.apply_retention_policy(
        max_age_days=data.max_age_days,
        min_sighting_count=data.min_sighting_count,
        preserve_watched=data.preserve_watched,
        preserve_enriched=data.preserve_enriched,
        dry_run=data.dry_run,
    )
    session.commit()
    return result


@router.post("/observables/enrich/scheduled")
async def run_scheduled_enrichment(
    max_age_hours: int = Query(168, ge=1, le=720),
    limit: int = Query(100, ge=1, le=500),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Run scheduled enrichment for stale observables."""
    service = ObservableService(session)
    result = service.run_scheduled_enrichment(
        max_age_hours=max_age_hours,
        limit=limit,
    )
    session.commit()
    return result


# =============================================================================
# CRUD Endpoints (parameterized routes MUST come after static routes)
# =============================================================================

@router.get("/observables/{observable_id}")
async def get_observable(
    observable_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> ObservableDetailResponse:
    """Get observable detail including enrichment data."""
    service = ObservableService(session)
    observable = service.get_by_id(observable_id)
    if not observable:
        raise HTTPException(status_code=404, detail="Observable not found")
    return _observable_to_detail(observable, session)


@router.put("/observables/{observable_id}")
async def update_observable(
    observable_id: int,
    data: ObservableUpdate,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> ObservableDetailResponse:
    """Update observable tags, notes, or whitelist status."""
    service = ObservableService(session)
    observable = service.update(
        observable_id,
        tags=data.tags,
        notes=data.notes,
        is_whitelisted=data.is_whitelisted,
        threat_level=data.threat_level,
    )
    if not observable:
        raise HTTPException(status_code=404, detail="Observable not found")
    session.commit()
    return _observable_to_detail(observable, session)


@router.delete("/observables/{observable_id}")
async def delete_observable(
    observable_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Delete an observable."""
    service = ObservableService(session)
    if not service.delete(observable_id):
        raise HTTPException(status_code=404, detail="Observable not found")
    session.commit()
    return {"deleted": True, "id": observable_id}


# =============================================================================
# Correlation Endpoints
# =============================================================================

@router.get("/observables/{observable_id}/alerts")
async def get_observable_alerts(
    observable_id: int,
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Get all alerts containing this observable."""
    service = ObservableService(session)
    observable = service.get_by_id(observable_id)
    if not observable:
        raise HTTPException(status_code=404, detail="Observable not found")

    alerts = service.get_related_alerts(observable_id, limit=limit)
    return {
        "alerts": [
            AlertSummary(
                id=a.id,
                es_alert_id=a.es_alert_id,
                status=a.status.value if hasattr(a.status, 'value') else a.status,
                priority=a.priority,
                created_at=a.created_at.isoformat(),
            )
            for a in alerts
        ],
        "total": len(alerts),
    }


@router.get("/observables/{observable_id}/cases")
async def get_observable_cases(
    observable_id: int,
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Get all cases containing this observable."""
    service = ObservableService(session)
    observable = service.get_by_id(observable_id)
    if not observable:
        raise HTTPException(status_code=404, detail="Observable not found")

    cases = service.get_related_cases(observable_id, limit=limit)
    return {
        "cases": [
            CaseSummary(
                id=c.id,
                case_number=c.case_number,
                title=c.title,
                status=c.status.value if hasattr(c.status, 'value') else c.status,
                severity=c.severity,
                created_at=c.created_at.isoformat(),
            )
            for c in cases
        ],
        "total": len(cases),
    }


@router.get("/observables/{observable_id}/co-occurring")
async def get_co_occurring_observables(
    observable_id: int,
    limit: int = Query(20, ge=1, le=100),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Get observables that appear alongside this one."""
    service = ObservableService(session)
    observable = service.get_by_id(observable_id)
    if not observable:
        raise HTTPException(status_code=404, detail="Observable not found")

    results = service.get_co_occurring_observables(observable_id, limit=limit)
    return {
        "co_occurring": [
            CoOccurringObservable(
                id=r["observable"].id,
                type=r["observable"].type.value if hasattr(r["observable"].type, 'value') else r["observable"].type,
                value=r["observable"].value,
                threat_level=r["observable"].threat_level.value if hasattr(r["observable"].threat_level, 'value') else r["observable"].threat_level,
                co_occurrence_count=r["co_occurrence_count"],
            )
            for r in results
        ],
    }


# =============================================================================
# Enrichment Endpoints
# =============================================================================

@router.post("/observables/{observable_id}/enrich")
async def enrich_observable(
    observable_id: int,
    source: str = Query("opencti", description="Enrichment source"),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Trigger enrichment for an observable."""
    service = ObservableService(session)
    observable = service.get_by_id(observable_id)
    if not observable:
        raise HTTPException(status_code=404, detail="Observable not found")

    enrichment = await service.enrich(observable_id, source=source)
    if not enrichment:
        raise HTTPException(
            status_code=503,
            detail=f"Enrichment failed or {source} not configured",
        )

    session.commit()
    return {
        "enrichment": {
            "id": enrichment.id,
            "source": enrichment.source,
            "enriched_at": enrichment.enriched_at.isoformat(),
            "is_malicious": enrichment.is_malicious,
            "score": enrichment.score,
            "labels": enrichment.labels,
            "threat_actors": enrichment.threat_actors,
            "indicators": enrichment.indicators,
            "reports": enrichment.reports,
        },
        "observable": _observable_to_response(observable),
    }


@router.get("/observables/{observable_id}/enrichment")
async def get_observable_enrichment(
    observable_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Get latest enrichment data for an observable."""
    service = ObservableService(session)
    observable = service.get_by_id(observable_id)
    if not observable:
        raise HTTPException(status_code=404, detail="Observable not found")

    enrichment = observable.latest_enrichment
    if not enrichment:
        return {"enrichment": None}

    return {
        "enrichment": {
            "id": enrichment.id,
            "source": enrichment.source,
            "enriched_at": enrichment.enriched_at.isoformat(),
            "is_malicious": enrichment.is_malicious,
            "score": enrichment.score,
            "labels": enrichment.labels,
            "threat_actors": enrichment.threat_actors,
            "indicators": enrichment.indicators,
            "reports": enrichment.reports,
            "raw_response": enrichment.raw_response,
        },
    }


@router.get("/observables/{observable_id}/enrichment/history")
async def get_enrichment_history(
    observable_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Get all enrichment attempts for an observable."""
    service = ObservableService(session)
    observable = service.get_by_id(observable_id)
    if not observable:
        raise HTTPException(status_code=404, detail="Observable not found")

    history = service.get_enrichment_history(observable_id)
    return {
        "history": [
            {
                "id": e.id,
                "source": e.source,
                "enriched_at": e.enriched_at.isoformat(),
                "is_malicious": e.is_malicious,
                "score": e.score,
            }
            for e in history
        ],
    }


# =============================================================================
# Bulk Endpoints
# =============================================================================

@router.post("/observables/enrich/batch")
async def enrich_batch(
    data: EnrichBatchRequest,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Enrich multiple observables."""
    service = ObservableService(session)
    results = await service.enrich_batch(data.observable_ids, source=data.source)
    session.commit()
    return {
        "enriched": len(results),
        "results": [
            {
                "observable_id": e.observable_id,
                "is_malicious": e.is_malicious,
                "score": e.score,
            }
            for e in results
        ],
    }


@router.post("/observables/search/bulk")
async def bulk_search(
    data: ObservableSearchRequest,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Search for multiple values at once."""
    service = ObservableService(session)
    results = {}
    for value in data.values:
        matches = service.get_by_value(value, obs_type=data.type)
        results[value] = [_observable_to_response(obs) for obs in matches]
    return {"results": results}


@router.post("/observables/migrate")
async def migrate_observables(
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> MigrationResponse:
    """Migrate legacy JSON observables to normalized table."""
    service = ObservableService(session)
    stats = service.migrate_json_observables()
    session.commit()
    return MigrationResponse(**stats)


@router.post("/observables/extract-from-alert/{alert_triage_id}")
async def extract_from_alert(
    alert_triage_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Extract and link observables from an alert."""
    service = ObservableService(session)
    observables = service.extract_and_link_from_alert(alert_triage_id)
    session.commit()
    return {
        "extracted": len(observables),
        "observables": [_observable_to_response(obs) for obs in observables],
    }


@router.post("/observables/extract-from-case/{case_id}")
async def extract_from_case(
    case_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Extract and link observables from all alerts in a case."""
    service = ObservableService(session)
    observables = service.extract_and_link_from_case(case_id)
    session.commit()
    return {
        "extracted": len(observables),
        "observables": [_observable_to_response(obs) for obs in observables],
    }


# =============================================================================
# Watchlist Parameterized Endpoints
# =============================================================================

@router.post("/observables/watchlist/{observable_id}")
async def add_to_watchlist(
    observable_id: int,
    data: WatchlistAddRequest,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Add an observable to the watchlist."""
    service = ObservableService(session)
    try:
        obs = service.add_to_watchlist(
            observable_id=observable_id,
            reason=data.reason,
            watched_by=user.username,
        )
        session.commit()
        return {
            "success": True,
            "observable": _observable_to_response(obs),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/observables/watchlist/{observable_id}")
async def remove_from_watchlist(
    observable_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Remove an observable from the watchlist."""
    service = ObservableService(session)
    try:
        obs = service.remove_from_watchlist(observable_id)
        session.commit()
        return {
            "success": True,
            "observable": _observable_to_response(obs),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/observables/watchlist/alerts/{alert_id}/read")
async def mark_watchlist_alert_read(
    alert_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Mark a watchlist alert as read."""
    service = ObservableService(session)
    try:
        alert = service.mark_watchlist_alert_read(alert_id, read_by=user.username)
        session.commit()
        return {"success": True, "alert_id": alert.id}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# =============================================================================
# Timeline Endpoints
# =============================================================================

@router.get("/observables/{observable_id}/timeline")
async def get_observable_timeline(
    observable_id: int,
    limit: int = Query(100, ge=1, le=500),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Get timeline of events for an observable."""
    service = ObservableService(session)

    obs = service.get_by_id(observable_id)
    if not obs:
        raise HTTPException(status_code=404, detail="Observable not found")

    timeline = service.get_timeline(observable_id, limit=limit)

    return {
        "observable_id": observable_id,
        "observable_value": obs.value,
        "events": timeline,
    }


@router.get("/observables/{observable_id}/heatmap")
async def get_observable_heatmap(
    observable_id: int,
    days: int = Query(30, ge=1, le=365),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Get activity heatmap for an observable."""
    service = ObservableService(session)

    obs = service.get_by_id(observable_id)
    if not obs:
        raise HTTPException(status_code=404, detail="Observable not found")

    heatmap = service.get_activity_heatmap(observable_id, days=days)

    return {
        "observable_id": observable_id,
        "days": days,
        "heatmap": heatmap,
    }


# =============================================================================
# Auto-Enrichment Settings (parameterized routes)
# =============================================================================

@router.post("/observables/{observable_id}/auto-enrich/enable")
async def enable_auto_enrich(
    observable_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Enable auto-enrichment for an observable."""
    service = ObservableService(session)
    try:
        obs = service.enable_auto_enrich(observable_id)
        session.commit()
        return {"success": True, "auto_enrich": obs.auto_enrich}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/observables/{observable_id}/auto-enrich/disable")
async def disable_auto_enrich(
    observable_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> dict:
    """Disable auto-enrichment for an observable."""
    service = ObservableService(session)
    try:
        obs = service.disable_auto_enrich(observable_id)
        session.commit()
        return {"success": True, "auto_enrich": obs.auto_enrich}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
