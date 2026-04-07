"""Training Simulation API — interactive scenario-based training."""

import logging
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from ion.auth.dependencies import require_page_auth
from ion.services.training_sim_service import get_scenario_list, get_scenario, score_answers

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/training-sim", tags=["training-sim"])


class ScoreRequest(BaseModel):
    scenario_id: str
    answers: dict


@router.get("/scenarios", dependencies=[Depends(require_page_auth)])
def list_scenarios():
    return {"scenarios": get_scenario_list()}


@router.get("/scenarios/{scenario_id}", dependencies=[Depends(require_page_auth)])
def get_scenario_detail(scenario_id: str):
    s = get_scenario(scenario_id)
    if not s:
        return {"error": "Scenario not found"}
    return s


@router.post("/score", dependencies=[Depends(require_page_auth)])
def score_scenario(data: ScoreRequest):
    return score_answers(data.scenario_id, data.answers)
