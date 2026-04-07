"""MITRE ATT&CK Navigator Export API."""

import logging
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from ion.auth.dependencies import require_permission
from ion.services.tide_service import get_tide_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/mitre-navigator", tags=["mitre-navigator"])


@router.get("/layer", dependencies=[Depends(require_permission("alert:read"))])
def get_navigator_layer(
    name: str = Query("ION Detection Coverage", max_length=200),
):
    """Generate MITRE ATT&CK Navigator layer JSON for download."""
    from ion.services.mitre_navigator_service import generate_navigator_layer
    tide = get_tide_service()
    layer = generate_navigator_layer(tide, layer_name=name)
    if not layer:
        return {"error": "Failed to generate layer — TIDE not configured or no data"}
    return JSONResponse(
        content=layer,
        headers={
            "Content-Disposition": f'attachment; filename="ion_mitre_coverage.json"',
            "Content-Type": "application/json",
        },
    )
