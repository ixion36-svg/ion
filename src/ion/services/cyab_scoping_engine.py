"""CyAB scoping engine — shared question set + scoring across consumers.

Three planned callers (per spec):
  1. /cyab/scoping       (anonymous stakeholder questionnaire)
  2. /cyab/onboard Step 2 (live counter as user answers wizard intake)
  3. /cyab/systems/{id} 'Recommendations' tab (Phase 2)

This module *extends* cyab_assessment_service — `score_answers()` calls
into `compute_profile`, `score_use_cases`, and `rank_actors` rather than
duplicating their logic. Adds:
  - load_questions()       — JSON catalogue loader (file-cached)
  - score_answers(answers) — high-level dict for UI consumption
  - summary_text(scores)   — single-line presentable summary
  - mitre_coverage_pct()   — MITRE Initial Access % from ranked use cases
"""
from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_QUESTIONS_PATH = Path(__file__).parent.parent / "data" / "cyab_scoping_questions.json"


@lru_cache(maxsize=1)
def load_questions() -> List[Dict[str, Any]]:
    """Read the question catalogue from disk. Cached for the process lifetime.

    To force a reload during development, call `load_questions.cache_clear()`.
    """
    with open(_QUESTIONS_PATH, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data["questions"]


def score_answers(answers: Dict[str, Any]) -> Dict[str, Any]:
    """Stub — full implementation in Task 2."""
    return {
        "use_case_count": 0,
        "threat_actor_matches": 0,
        "mitre_coverage_pct": 0,
        "recommended_use_cases": [],
        "recommended_threat_actors": [],
    }


def summary_text(scores: Dict[str, Any]) -> str:
    """Stub — full implementation in Task 2."""
    return ""
