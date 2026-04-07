"""Compliance Mapping API — NIST CSF coverage from TIDE rules."""

import logging
from fastapi import APIRouter, Depends
from ion.auth.dependencies import require_permission
from ion.services.tide_service import get_tide_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/nist", dependencies=[Depends(require_permission("alert:read"))])
def get_nist_posture():
    from ion.services.compliance_mapping_service import get_compliance_posture
    tide = get_tide_service()
    return get_compliance_posture(tide)
