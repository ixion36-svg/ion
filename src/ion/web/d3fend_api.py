"""MITRE D3FEND defensive coverage API."""

import logging
from fastapi import APIRouter, Depends

from ion.auth.dependencies import require_permission
from ion.core.safe_errors import safe_error
from ion.services.d3fend_service import get_d3fend_coverage

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/d3fend", tags=["d3fend"])


@router.get("/coverage", dependencies=[Depends(require_permission("alert:read"))])
def coverage():
    """Compute D3FEND defensive coverage based on TIDE rule mappings."""
    try:
        return get_d3fend_coverage()
    except Exception as e:
        return {"error": safe_error(e, "d3fend_coverage"), "tactics": [], "techniques": [], "summary": {}}
