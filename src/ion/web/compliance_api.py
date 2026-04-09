"""Compliance API — multi-framework posture from TIDE rules."""

import logging

from fastapi import APIRouter, Depends, HTTPException

from ion.auth.dependencies import require_permission
from ion.core.safe_errors import safe_error
from ion.services.tide_service import get_tide_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/frameworks", dependencies=[Depends(require_permission("alert:read"))])
def list_frameworks_endpoint():
    """Return metadata for all supported frameworks (no controls — small payload)."""
    from ion.services.compliance_mapping_service import list_frameworks
    return {"frameworks": list_frameworks()}


@router.get("/posture", dependencies=[Depends(require_permission("alert:read"))])
def all_postures_endpoint():
    """Compute the per-control scorecard for every framework in one TIDE call."""
    from ion.services.compliance_mapping_service import get_all_postures
    try:
        return get_all_postures(get_tide_service())
    except Exception as e:
        raise HTTPException(status_code=500, detail=safe_error(e, "compliance_all"))


@router.get("/{framework_id}/posture", dependencies=[Depends(require_permission("alert:read"))])
def framework_posture_endpoint(framework_id: str):
    """Compute the per-control scorecard for a single framework."""
    from ion.services.compliance_mapping_service import get_compliance_posture
    try:
        result = get_compliance_posture(get_tide_service(), framework_id)
        if "error" in result and result.get("error", "").startswith("Unknown framework"):
            raise HTTPException(status_code=404, detail=result["error"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=safe_error(e, "compliance_framework"))


@router.get("/{framework_id}", dependencies=[Depends(require_permission("alert:read"))])
def get_framework_endpoint(framework_id: str):
    """Return the full framework definition (controls, mappings, metadata)."""
    from ion.services.compliance_mapping_service import get_framework
    fw = get_framework(framework_id)
    if not fw:
        raise HTTPException(status_code=404, detail=f"Unknown framework: {framework_id}")
    return fw


# ---------------------------------------------------------------------------
# Legacy endpoint kept for backwards compatibility with the original code
# (was the only compliance endpoint, returning NIST CSF only).
# ---------------------------------------------------------------------------

@router.get("/nist", dependencies=[Depends(require_permission("alert:read"))])
def legacy_nist_endpoint():
    """Deprecated: use /compliance/nist_csf/posture."""
    from ion.services.compliance_mapping_service import get_compliance_posture_legacy
    return get_compliance_posture_legacy(get_tide_service())
