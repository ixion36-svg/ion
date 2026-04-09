"""Kibana Cases integration API router for ION.

All /api/kibana/* endpoints live here, extracted from api.py.
"""

from typing import Optional, List

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ion.core.config import get_kibana_config
from ion.services.kibana_cases_service import get_kibana_cases_service
from ion.services.kibana_sync_service import get_kibana_sync_service
from ion.models.user import User
from ion.models.alert_triage import AlertCase
from ion.auth.dependencies import get_current_user

# Import get_db_session from api to reuse the same dependency
from ion.web.api import get_db_session

router = APIRouter(tags=["kibana"])


# ============================================================================
# Pydantic Models
# ============================================================================


class KibanaCaseCreate(BaseModel):
    title: str
    description: Optional[str] = ""
    severity: Optional[str] = "low"
    tags: Optional[List[str]] = None
    alert_ids: Optional[List[str]] = None
    alert_index: Optional[str] = "alerts-ion"


class KibanaCaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    tags: Optional[List[str]] = None


class KibanaCaseComment(BaseModel):
    comment: str


# ============================================================================
# Kibana Cases Integration Endpoints
# ============================================================================


@router.get("/config")
async def get_kibana_config_endpoint(
    current_user: User = Depends(get_current_user),
):
    """Get Kibana Cases configuration status."""
    config = get_kibana_config()
    return {
        "enabled": config.get("enabled", False),
        "url": config.get("url", ""),
        "has_credentials": bool(config.get("username") and config.get("password")),
        "space_id": config.get("space_id", "default"),
        "case_owner": config.get("case_owner", "securitySolution"),
    }


@router.get("/status")
async def get_kibana_status(
    current_user: User = Depends(get_current_user),
):
    """Test Kibana connectivity and return status."""
    service = get_kibana_cases_service()
    if not service.enabled:
        return {
            "connected": False,
            "error": "Kibana Cases integration not enabled",
        }

    result = service.test_connection()
    connected = result.get("success", False)
    return {
        "connected": connected,
        "version": result.get("version"),
        "status": result.get("status"),
        # Don't echo the raw service-side error message — return a generic flag.
        "error": None if connected else "Connection test failed",
    }


@router.get("/cases")
async def list_kibana_cases(
    status: Optional[str] = None,
    include_closed: bool = False,
    page: int = 1,
    per_page: int = 20,
    current_user: User = Depends(get_current_user),
):
    """List cases from Kibana.

    By default excludes closed cases to avoid exposing completed investigation data.
    Pass include_closed=true to see all cases including closed ones.
    """
    service = get_kibana_cases_service()
    if not service.enabled:
        raise HTTPException(status_code=503, detail="Kibana Cases integration not enabled")

    if status:
        # Explicit status filter overrides include_closed
        result = service.list_cases(status=status, page=page, per_page=per_page)
    elif include_closed:
        # All statuses
        result = service.list_cases(page=page, per_page=per_page)
    else:
        # Default: only open + in-progress (fetch both and merge)
        result_open = service.list_cases(status="open", page=page, per_page=per_page)
        result_inprog = service.list_cases(status="in-progress", page=page, per_page=per_page)
        combined = result_open.get("cases", []) + result_inprog.get("cases", [])
        # Sort by updated_at desc
        combined.sort(key=lambda c: c.get("updated_at", ""), reverse=True)
        result = {
            "cases": combined[:per_page],
            "total": result_open.get("total", 0) + result_inprog.get("total", 0),
            "page": page,
            "per_page": per_page,
        }
    if "error" in result and result.get("error"):
        # Don't echo the raw service error message (may contain stack frames).
        raise HTTPException(status_code=502, detail="Failed to fetch cases from Kibana")

    # Transform to consistent format
    cases = []
    for c in result.get("cases", []):
        cases.append({
            "id": c.get("id"),
            "title": c.get("title"),
            "description": c.get("description"),
            "status": c.get("status"),
            "severity": c.get("severity"),
            "tags": c.get("tags", []),
            "created_by": c.get("created_by", {}).get("username"),
            "created_at": c.get("created_at"),
            "updated_at": c.get("updated_at"),
            "kibana_url": service.get_case_url(c.get("id")),
            "comments_count": c.get("totalComment", 0),
            "alerts_count": c.get("totalAlerts", 0),
        })

    return {
        "cases": cases,
        "total": result.get("total", 0),
        "page": result.get("page", page),
        "per_page": result.get("per_page", per_page),
    }


@router.post("/cases")
async def create_kibana_case(
    data: KibanaCaseCreate,
    current_user: User = Depends(get_current_user),
):
    """Create a new case in Kibana."""
    service = get_kibana_cases_service()
    if not service.enabled:
        raise HTTPException(status_code=503, detail="Kibana Cases integration not enabled")

    # Map severity
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }
    severity = severity_map.get(data.severity, "low")

    # Attribute case to the ION user
    display = current_user.display_name or current_user.username
    description = data.description or ""
    description += f"\n\n---\n*Created by {display} via ION*"

    result = service.create_case(
        title=data.title,
        description=description,
        severity=severity,
        tags=data.tags,
    )

    if not result:
        raise HTTPException(status_code=502, detail="Failed to create case in Kibana")

    case_id = result.get("id")

    # Attach alerts if provided
    if data.alert_ids and case_id:
        service.attach_alerts_to_case(
            case_id=case_id,
            alert_ids=data.alert_ids,
            alert_index=data.alert_index or "alerts-ion",
        )

    return {
        "id": case_id,
        "title": result.get("title"),
        "status": result.get("status"),
        "severity": result.get("severity"),
        "kibana_url": service.get_case_url(case_id),
        "message": "Case created in Kibana",
    }


@router.get("/cases/unimported")
async def get_unimported_kibana_cases(
    current_user: User = Depends(get_current_user),
):
    """Get list of cases created in Kibana that haven't been imported to ION."""
    sync_service = get_kibana_sync_service()

    unimported = await sync_service.get_unimported_kibana_cases()

    return {
        "cases": unimported,
        "count": len(unimported),
    }


@router.post("/cases/import")
async def import_kibana_cases(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Import all cases created in Kibana that don't exist in ION."""
    sync_service = get_kibana_sync_service()

    result = await sync_service.import_cases_from_kibana(session)

    # Don't echo raw service error strings (which may contain stack frames /
    # paths) back to the API client. Convert to a sanitized count + flag.
    raw_errors = result.get("errors") or []
    error_count = len(raw_errors) if isinstance(raw_errors, list) else 0
    has_top_level_error = bool(result.get("error"))
    return {
        "message": "Import completed",
        "imported": result.get("imported", 0),
        "skipped": result.get("skipped", 0),
        "error_count": error_count,
        "has_error": has_top_level_error,
    }


@router.get("/cases/{case_id}")
async def get_kibana_case(
    case_id: str,
    current_user: User = Depends(get_current_user),
):
    """Get a case from Kibana by ID."""
    service = get_kibana_cases_service()
    if not service.enabled:
        raise HTTPException(status_code=503, detail="Kibana Cases integration not enabled")

    result = service.get_case(case_id)
    if not result:
        raise HTTPException(status_code=404, detail="Case not found in Kibana")

    comments = service.get_case_comments(case_id)

    return {
        "id": result.get("id"),
        "title": result.get("title"),
        "description": result.get("description"),
        "status": result.get("status"),
        "severity": result.get("severity"),
        "tags": result.get("tags", []),
        "created_by": result.get("created_by", {}).get("username"),
        "created_at": result.get("created_at"),
        "updated_at": result.get("updated_at"),
        "version": result.get("version"),
        "kibana_url": service.get_case_url(case_id),
        "comments": [
            {
                "id": c.get("id"),
                "comment": c.get("comment"),
                "created_by": c.get("created_by", {}).get("username"),
                "created_at": c.get("created_at"),
            }
            for c in comments
            if c.get("type") == "user"
        ],
    }


@router.patch("/cases/{case_id}")
async def update_kibana_case(
    case_id: str,
    data: KibanaCaseUpdate,
    current_user: User = Depends(get_current_user),
):
    """Update a case in Kibana."""
    service = get_kibana_cases_service()
    if not service.enabled:
        raise HTTPException(status_code=503, detail="Kibana Cases integration not enabled")

    # Get current case to get version
    current = service.get_case(case_id)
    if not current:
        raise HTTPException(status_code=404, detail="Case not found in Kibana")

    version = current.get("version")

    # Map status
    status_map = {
        "open": "open",
        "acknowledged": "in-progress",
        "in-progress": "in-progress",
        "closed": "closed",
    }

    result = service.update_case(
        case_id=case_id,
        version=version,
        title=data.title,
        description=data.description,
        status=status_map.get(data.status) if data.status else None,
        severity=data.severity,
        tags=data.tags,
    )

    if not result:
        raise HTTPException(status_code=502, detail="Failed to update case in Kibana")

    return {
        "id": result.get("id"),
        "title": result.get("title"),
        "status": result.get("status"),
        "kibana_url": service.get_case_url(case_id),
        "message": "Case updated in Kibana",
    }


@router.post("/cases/{case_id}/comments")
async def add_kibana_case_comment(
    case_id: str,
    data: KibanaCaseComment,
    current_user: User = Depends(get_current_user),
):
    """Add a comment to a Kibana case."""
    service = get_kibana_cases_service()
    if not service.enabled:
        raise HTTPException(status_code=503, detail="Kibana Cases integration not enabled")

    # Attribute comment to the ION user (Kibana API posts as the service account)
    display = current_user.display_name or current_user.username
    attributed_comment = f"**{display}:** {data.comment}"

    result = service.add_comment(
        case_id=case_id,
        comment=attributed_comment,
    )

    if not result:
        raise HTTPException(status_code=502, detail="Failed to add comment to Kibana case")

    return {
        "case_id": case_id,
        "comment": data.comment,
        "message": "Comment added to Kibana case",
    }


@router.delete("/cases/{case_id}")
async def delete_kibana_case(
    case_id: str,
    current_user: User = Depends(get_current_user),
):
    """Delete a case from Kibana."""
    service = get_kibana_cases_service()
    if not service.enabled:
        raise HTTPException(status_code=503, detail="Kibana Cases integration not enabled")

    success = service.delete_case(case_id)
    if not success:
        raise HTTPException(status_code=502, detail="Failed to delete case from Kibana")

    return {
        "message": "Case deleted from Kibana",
    }


# ============================================================================
# Kibana Bidirectional Sync Endpoints
# ============================================================================


@router.post("/sync")
async def sync_from_kibana(
    current_user: User = Depends(get_current_user),
):
    """Manually trigger sync of comments from Kibana to ION."""
    sync_service = get_kibana_sync_service()

    result = await sync_service.sync_all_cases()

    return {
        "message": "Sync completed",
        "comments_synced": result.get("synced", 0),
        "cases_processed": result.get("cases", 0),
        "error": result.get("error"),
    }


@router.post("/sync/case/{case_id}")
async def sync_case_from_kibana(
    case_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Sync comments from Kibana for a specific case."""
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    if not case.kibana_case_id:
        raise HTTPException(status_code=400, detail="Case not linked to Kibana")

    sync_service = get_kibana_sync_service()
    synced = await sync_service.sync_case_comments(session, case)

    # Also sync status
    status_updated = await sync_service.sync_case_status_from_kibana(session, case)

    return {
        "message": "Case sync completed",
        "comments_synced": synced,
        "status_updated": status_updated,
        "case_number": case.case_number,
    }
