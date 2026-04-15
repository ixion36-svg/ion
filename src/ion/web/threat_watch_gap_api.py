"""Threat Watch Gap Analysis API — checks watched actors for detection gaps against TIDE coverage."""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.models.threat_intel import ThreatIntelWatch
from ion.services.tide_service import get_tide_service
from ion.services.opencti_service import get_opencti_service
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-watch-gaps", tags=["threat-watch-gaps"])


class CheckAndNotifyRequest(BaseModel):
    min_gap_count: int = 1


async def _check_watch_gaps(session: Session) -> dict:
    """Core logic: check all active watches for TIDE detection gaps."""
    tide = get_tide_service()
    if not tide or not tide.enabled:
        return {"enabled": False, "error": "TIDE integration is not configured or disabled"}

    opencti = get_opencti_service()
    if not opencti or not opencti.is_configured:
        return {"enabled": False, "error": "OpenCTI integration is not configured"}

    coverage_data = tide.get_global_mitre_coverage()
    if not coverage_data:
        return {"enabled": False, "error": "Unable to retrieve TIDE coverage data"}

    tide_techniques = coverage_data.get("techniques", {})

    watches = session.execute(
        select(ThreatIntelWatch).where(ThreatIntelWatch.is_active == True)
    ).scalars().all()

    results = []
    for watch in watches:
        try:
            detail = await opencti.get_entity_detail(watch.opencti_id, watch.entity_type)
        except Exception:
            logger.warning("Failed to get OpenCTI detail for watch %s (%s)", watch.id, watch.name)
            continue

        ttps = detail.get("ttps", []) if detail else []
        if not ttps:
            continue

        gap_techniques = []
        covered_count = 0

        for ttp in ttps:
            mitre_id = ttp.get("mitre_id", "")
            parent_id = mitre_id.split(".")[0] if mitre_id else ""

            if parent_id and parent_id in tide_techniques:
                tech = tide_techniques[parent_id]
                if tech.get("rule_count", 0) > 0:
                    covered_count += 1
                    continue

            gap_techniques.append({"mitre_id": mitre_id, "name": ttp.get("name", "")})

        total = len(ttps)
        coverage_pct = round((covered_count / total) * 100, 1) if total > 0 else 0.0

        results.append({
            "watch_id": watch.id,
            "actor_name": watch.name,
            "watched_by": watch.watched_by,
            "total_ttps": total,
            "covered": covered_count,
            "gaps": len(gap_techniques),
            "gap_techniques": gap_techniques,
            "coverage_pct": coverage_pct,
        })

    gaps_found = sum(1 for r in results if r["gaps"] > 0)

    return {
        "checked": len(results),
        "gaps_found": gaps_found,
        "results": results,
    }


@router.get("/check")
async def check_gaps(
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    result = await _check_watch_gaps(session)
    if "enabled" in result and not result["enabled"]:
        return result

    for r in result.get("results", []):
        r.pop("watched_by", None)

    return result


@router.post("/check-and-notify")
async def check_and_notify(
    body: Optional[CheckAndNotifyRequest] = None,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    min_gap_count = body.min_gap_count if body else 1

    result = await _check_watch_gaps(session)
    if "enabled" in result and not result["enabled"]:
        return result

    # Gap counting (notifications were removed in v0.9.76 — the caller can
    # still see which watches have gaps in the response body).
    gaps_detected = sum(
        1 for r in result.get("results", [])
        if r.get("gaps", 0) >= min_gap_count
    )

    for r in result.get("results", []):
        r.pop("watched_by", None)

    result["gaps_detected"] = gaps_detected
    return result
