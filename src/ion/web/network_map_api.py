"""Network Mapper API — live CMDB from Elasticsearch host data."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Generator, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, or_, String
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.core.config import get_config
from ion.core.safe_errors import safe_error
from ion.models.network_asset import NetworkAsset, NetworkAssetIP, NetworkAssetMAC
from ion.models.user import User
from ion.storage.database import get_engine, get_session_factory

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/network-map", tags=["network-map"])


def get_db_session() -> Generator[Session, None, None]:
    engine = get_engine(get_config().db_path)
    factory = get_session_factory(engine)
    session = factory()
    try:
        yield session
    finally:
        session.close()


# ── Schemas ───────────────────────────────────────────────────────────────

class AssetUpdate(BaseModel):
    criticality: Optional[str] = None
    environment: Optional[str] = None
    owner: Optional[str] = None
    notes: Optional[str] = None


# ── Endpoints ─────────────────────────────────────────────────────────────

@router.get("/assets")
def list_assets(
    search: str = Query("", description="Filter by hostname or IP"),
    os_filter: str = Query("", description="Filter by OS name"),
    environment: str = Query("", description="Filter by environment"),
    criticality: str = Query("", description="Filter by criticality"),
    source_system: str = Query("", description="Filter by source system name"),
    last_seen_within: str = Query("", description="24h, 7d, 30d, or empty for all"),
    archived: bool = Query(False, description="Include archived assets"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Paginated asset list with filters."""
    q = session.query(NetworkAsset)

    if not archived:
        q = q.filter(NetworkAsset.archived_at.is_(None))

    if search:
        pattern = f"%{search}%"
        # Search hostname or any known IP
        ip_asset_ids = (
            session.query(NetworkAssetIP.asset_id)
            .filter(NetworkAssetIP.ip.ilike(pattern))
            .subquery()
        )
        q = q.filter(
            or_(
                NetworkAsset.hostname.ilike(pattern),
                NetworkAsset.display_hostname.ilike(pattern),
                NetworkAsset.id.in_(ip_asset_ids),
            )
        )

    if os_filter:
        q = q.filter(NetworkAsset.os_name.ilike(f"%{os_filter}%"))
    if environment:
        q = q.filter(NetworkAsset.environment == environment)
    if criticality:
        q = q.filter(NetworkAsset.criticality == criticality)
    if source_system:
        # JSON array contains — works on both Postgres (cast) and SQLite
        q = q.filter(NetworkAsset.source_systems.cast(String).ilike(f"%{source_system}%"))

    if last_seen_within:
        now = datetime.now(timezone.utc)
        if last_seen_within == "24h":
            cutoff = now - timedelta(hours=24)
        elif last_seen_within == "7d":
            cutoff = now - timedelta(days=7)
        elif last_seen_within == "30d":
            cutoff = now - timedelta(days=30)
        else:
            cutoff = None
        if cutoff:
            q = q.filter(NetworkAsset.last_seen >= cutoff)

    total = q.count()
    assets = q.order_by(NetworkAsset.last_seen.desc()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "assets": [_asset_to_dict(a) for a in assets],
    }


@router.get("/assets/{asset_id}")
def get_asset(
    asset_id: int,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Get full asset detail including IP history and MACs."""
    asset = session.query(NetworkAsset).filter_by(id=asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    return _asset_to_dict(asset, full=True)


@router.patch("/assets/{asset_id}")
def update_asset(
    asset_id: int,
    data: AssetUpdate,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Edit user-managed fields: criticality, environment, owner, notes."""
    asset = session.query(NetworkAsset).filter_by(id=asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    if data.criticality is not None:
        asset.criticality = data.criticality
    if data.environment is not None:
        asset.environment = data.environment
    if data.owner is not None:
        asset.owner = data.owner
    if data.notes is not None:
        asset.notes = data.notes
    session.commit()
    return {"status": "updated", "id": asset.id}


@router.post("/assets/{asset_id}/archive")
def archive_asset(
    asset_id: int,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    asset = session.query(NetworkAsset).filter_by(id=asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    asset.archived_at = datetime.now(timezone.utc)
    session.commit()
    return {"status": "archived"}


@router.post("/assets/{asset_id}/unarchive")
def unarchive_asset(
    asset_id: int,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    asset = session.query(NetworkAsset).filter_by(id=asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    asset.archived_at = None
    session.commit()
    return {"status": "unarchived"}


@router.post("/sync")
async def manual_sync(
    current_user: User = Depends(require_permission("integration:manage")),
):
    """Trigger an immediate network mapper sync (admin only)."""
    from ion.services.network_mapper_service import sync_once
    try:
        result = await sync_once()
        return {"status": "completed", **result}
    except Exception as e:
        raise HTTPException(500, safe_error(e))


@router.get("/stats")
def get_stats(
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Summary statistics for the network mapper dashboard."""
    now = datetime.now(timezone.utc)
    total = session.query(func.count(NetworkAsset.id)).filter(
        NetworkAsset.archived_at.is_(None)
    ).scalar() or 0
    seen_24h = session.query(func.count(NetworkAsset.id)).filter(
        NetworkAsset.archived_at.is_(None),
        NetworkAsset.last_seen >= now - timedelta(hours=24),
    ).scalar() or 0

    # OS breakdown
    os_rows = (
        session.query(NetworkAsset.os_family, func.count(NetworkAsset.id))
        .filter(NetworkAsset.archived_at.is_(None), NetworkAsset.os_family.isnot(None))
        .group_by(NetworkAsset.os_family)
        .all()
    )
    os_breakdown = {row[0]: row[1] for row in os_rows}

    # Environment breakdown
    env_rows = (
        session.query(NetworkAsset.environment, func.count(NetworkAsset.id))
        .filter(NetworkAsset.archived_at.is_(None))
        .group_by(NetworkAsset.environment)
        .all()
    )
    env_breakdown = {row[0]: row[1] for row in env_rows}

    # Criticality breakdown
    crit_rows = (
        session.query(NetworkAsset.criticality, func.count(NetworkAsset.id))
        .filter(NetworkAsset.archived_at.is_(None))
        .group_by(NetworkAsset.criticality)
        .all()
    )
    crit_breakdown = {row[0]: row[1] for row in crit_rows}

    # Total unique IPs
    total_ips = session.query(func.count(func.distinct(NetworkAssetIP.ip))).scalar() or 0

    # Distinct source systems across all assets
    all_assets = session.query(NetworkAsset.source_systems).filter(
        NetworkAsset.archived_at.is_(None),
        NetworkAsset.source_systems.isnot(None),
    ).all()
    source_sys_set = set()
    for (systems,) in all_assets:
        if isinstance(systems, list):
            source_sys_set.update(systems)
    source_systems = sorted(source_sys_set)

    return {
        "total_assets": total,
        "seen_24h": seen_24h,
        "total_ips": total_ips,
        "os_breakdown": os_breakdown,
        "environment_breakdown": env_breakdown,
        "criticality_breakdown": crit_breakdown,
        "source_systems": source_systems,
    }


# ── Helpers ───────────────────────────────────────────────────────────────

def _asset_to_dict(asset: NetworkAsset, full: bool = False) -> dict:
    """Serialize an asset for the API response."""
    # Primary IP = most recently seen
    primary_ip = None
    if asset.ips:
        sorted_ips = sorted(asset.ips, key=lambda x: x.last_seen, reverse=True)
        primary_ip = sorted_ips[0].ip

    d = {
        "id": asset.id,
        "hostname": asset.hostname,
        "display_hostname": asset.display_hostname,
        "primary_ip": primary_ip,
        "os_name": asset.os_name,
        "os_version": asset.os_version,
        "os_family": asset.os_family,
        "os_platform": asset.os_platform,
        "architecture": asset.architecture,
        "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
        "event_count": asset.event_count,
        "last_index": asset.last_index,
        "criticality": asset.criticality,
        "environment": asset.environment,
        "owner": asset.owner,
        "notes": asset.notes,
        "source_systems": asset.source_systems or [],
        "archived_at": asset.archived_at.isoformat() if asset.archived_at else None,
        "ip_count": len(asset.ips) if asset.ips else 0,
        "mac_count": len(asset.macs) if asset.macs else 0,
    }

    if full:
        d["ips"] = [
            {
                "ip": ip.ip,
                "first_seen": ip.first_seen.isoformat() if ip.first_seen else None,
                "last_seen": ip.last_seen.isoformat() if ip.last_seen else None,
                "event_count": ip.event_count,
            }
            for ip in sorted(asset.ips, key=lambda x: x.last_seen, reverse=True)
        ]
        d["macs"] = [
            {
                "mac": m.mac,
                "first_seen": m.first_seen.isoformat() if m.first_seen else None,
                "last_seen": m.last_seen.isoformat() if m.last_seen else None,
            }
            for m in (asset.macs or [])
        ]

    return d
