"""Cyber Range API — red team vs blue team training scenarios."""

import logging
from fastapi import APIRouter, Depends
from ion.auth.dependencies import require_page_auth

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/cyber-range", tags=["cyber-range"])


@router.get("/scenarios", dependencies=[Depends(require_page_auth)])
def list_scenarios():
    from ion.services.cyber_range_service import get_range_scenarios
    return {"scenarios": get_range_scenarios()}


@router.get("/scenarios/{scenario_id}", dependencies=[Depends(require_page_auth)])
def get_scenario(scenario_id: str):
    from ion.services.cyber_range_service import get_range_scenario
    s = get_range_scenario(scenario_id)
    if not s:
        return {"error": "Scenario not found"}
    return s
