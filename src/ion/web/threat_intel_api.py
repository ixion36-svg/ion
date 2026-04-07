"""Threat Intel API — search OpenCTI actors/campaigns, manage watches, view matches."""

import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_db_session, require_permission
from ion.models.user import User
from ion.services.opencti_service import get_opencti_service, OpenCTIError
from ion.services.threat_intel_service import ThreatIntelService
from ion.services.country_mapper import get_country_code, get_country_name, country_code_to_flag

logger = logging.getLogger(__name__)

router = APIRouter(tags=["threat-intel"])


# ---- Request/Response Models ----

class AddWatchRequest(BaseModel):
    entity_type: str  # "threat_actor" or "campaign"
    opencti_id: str
    name: str
    description: Optional[str] = None
    aliases: Optional[list] = None
    labels: Optional[list] = None
    reason: Optional[str] = None


# ---- Helper ----

def _watch_to_dict(w) -> dict:
    aliases = None
    if w.aliases:
        try:
            aliases = json.loads(w.aliases)
        except (json.JSONDecodeError, TypeError):
            aliases = []
    labels = None
    if w.labels:
        try:
            labels = json.loads(w.labels)
        except (json.JSONDecodeError, TypeError):
            labels = []
    code = get_country_code(w.name, aliases)
    return {
        "id": w.id,
        "entity_type": w.entity_type,
        "opencti_id": w.opencti_id,
        "name": w.name,
        "description": w.description,
        "aliases": aliases,
        "labels": labels,
        "country_code": code,
        "country_name": get_country_name(code),
        "country_flag": country_code_to_flag(code),
        "last_seen_at": w.last_seen_at.isoformat() if w.last_seen_at else None,
        "match_count": w.match_count,
        "watched_by": w.watched_by,
        "watch_reason": w.watch_reason,
        "is_active": w.is_active,
        "created_at": w.created_at.isoformat() if w.created_at else None,
    }


def _match_to_dict(m) -> dict:
    return {
        "id": m.id,
        "observable_id": m.observable_id,
        "observable_value": m.observable.value if m.observable else None,
        "observable_type": m.observable.type.value if m.observable else None,
        "alert_type": m.alert_type.value if hasattr(m.alert_type, "value") else m.alert_type,
        "message": m.message,
        "details": m.details,
        "is_read": m.is_read,
        "created_at": m.created_at.isoformat() if m.created_at else None,
    }


# ---- OpenCTI Search Endpoints ----

@router.get("/actors")
async def search_actors(
    search: str = Query("", description="Search term"),
    first: int = Query(20, ge=1, le=100),
    after: Optional[str] = Query(None),
    user: User = Depends(require_permission("observable:read")),
):
    """Search OpenCTI for threat actors."""
    service = get_opencti_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="OpenCTI integration is not configured")
    try:
        result = await service.search_threat_actors(search=search, first=first, after=after)
        return result
    except OpenCTIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/actors/{entity_id}")
async def get_actor_detail(
    entity_id: str,
    entity_class: str = Query("threat_actor", description="threat_actor or intrusion_set"),
    user: User = Depends(require_permission("observable:read")),
):
    """Get detailed info for a threat actor or intrusion set from OpenCTI."""
    service = get_opencti_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="OpenCTI integration is not configured")
    try:
        result = await service.get_entity_detail(entity_id, entity_class)
        if result.get("error"):
            raise HTTPException(status_code=404, detail=result["error"])
        return result
    except OpenCTIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/campaigns")
async def search_campaigns(
    search: str = Query("", description="Search term"),
    first: int = Query(20, ge=1, le=100),
    after: Optional[str] = Query(None),
    user: User = Depends(require_permission("observable:read")),
):
    """Search OpenCTI for campaigns."""
    service = get_opencti_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="OpenCTI integration is not configured")
    try:
        result = await service.search_campaigns(search=search, first=first, after=after)
        return result
    except OpenCTIError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/campaigns/{entity_id}")
async def get_campaign_detail(
    entity_id: str,
    user: User = Depends(require_permission("observable:read")),
):
    """Get detailed info for a campaign from OpenCTI."""
    service = get_opencti_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="OpenCTI integration is not configured")
    try:
        result = await service.get_entity_detail(entity_id, "campaign")
        if result.get("error"):
            raise HTTPException(status_code=404, detail=result["error"])
        return result
    except OpenCTIError as e:
        raise HTTPException(status_code=502, detail=str(e))


# ---- Watch Management ----

@router.get("/watches")
async def list_watches(
    entity_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:read")),
):
    """List watched threat actors and campaigns."""
    service = ThreatIntelService(session)
    items, total = service.get_watches(entity_type=entity_type, limit=limit, offset=offset)
    return {
        "watches": [_watch_to_dict(w) for w in items],
        "total": total,
    }


@router.post("/watches")
async def add_watch(
    data: AddWatchRequest,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:enrich")),
):
    """Add an entity to the threat intel watchlist."""
    if data.entity_type not in ("threat_actor", "campaign"):
        raise HTTPException(status_code=400, detail="entity_type must be 'threat_actor' or 'campaign'")

    service = ThreatIntelService(session)
    watch = service.add_watch(
        entity_type=data.entity_type,
        opencti_id=data.opencti_id,
        name=data.name,
        description=data.description,
        aliases=data.aliases,
        labels=data.labels,
        watched_by=user.username,
        reason=data.reason,
    )
    session.commit()
    return _watch_to_dict(watch)


@router.delete("/watches/{watch_id}")
async def remove_watch(
    watch_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:enrich")),
):
    """Remove (deactivate) a watch."""
    service = ThreatIntelService(session)
    if not service.remove_watch(watch_id):
        raise HTTPException(status_code=404, detail="Watch not found")
    session.commit()
    return {"ok": True}


# ---- Match Alerts ----

@router.get("/matches")
async def list_matches(
    unread_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:read")),
):
    """List threat actor match alerts."""
    service = ThreatIntelService(session)
    items, total = service.get_matches(unread_only=unread_only, limit=limit, offset=offset)
    return {
        "matches": [_match_to_dict(m) for m in items],
        "total": total,
    }


@router.post("/matches/{match_id}/read")
async def mark_match_read(
    match_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:read")),
):
    """Mark a match alert as read."""
    service = ThreatIntelService(session)
    if not service.mark_match_read(match_id, user.username):
        raise HTTPException(status_code=404, detail="Match not found")
    session.commit()
    return {"ok": True}


# ---- Overview ----

@router.get("/overview")
async def get_overview(
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:read")),
):
    """Get threat intel overview stats."""
    service = ThreatIntelService(session)
    return service.get_overview_stats()
