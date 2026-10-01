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


# ── MITRE Initial Access technique keywords ───────────────────────────────
# Used to compute mitre_coverage_pct from ranked playbook text. A playbook's
# name+description is searched for each technique keyword; the % is
# (techniques_hit / total_techniques * 100).
_MITRE_INITIAL_ACCESS = {
    "T1566": ["phishing", "spearphish", "phish"],
    "T1190": ["exploit public", "public-facing", "vulnerable web"],
    "T1133": ["external remote", "vpn", "rdp exposed"],
    "T1078": ["valid account", "credential", "stolen credential"],
    "T1199": ["trusted relationship", "third party"],
    "T1195": ["supply chain", "software update"],
    "T1091": ["replication", "removable media"],
    "T1200": ["hardware addition"],
    "T1189": ["drive-by", "drive by compromise", "watering hole"],
}


def mitre_coverage_pct(ranked_use_cases: List[Dict[str, Any]]) -> int:
    """Percentage of MITRE Initial Access techniques covered by the ranked
    playbooks. Pure: 0..100 integer.
    """
    if not ranked_use_cases:
        return 0
    text = " ".join(
        f"{uc.get('name', '')} {uc.get('description', '')}".lower()
        for uc in ranked_use_cases
    )
    hit = 0
    for technique_id, kws in _MITRE_INITIAL_ACCESS.items():
        if any(k in text for k in kws):
            hit += 1
    return int(round(100 * hit / len(_MITRE_INITIAL_ACCESS)))


def score_answers(answers: Dict[str, Any]) -> Dict[str, Any]:
    """High-level scoring for UI consumers.

    Wraps cyab_assessment_service.score_use_cases + rank_actors. Returns a
    dict shaped for the live counter widget and the summary view:

        {
          "use_case_count":           int,
          "threat_actor_matches":     int,
          "mitre_coverage_pct":       int (0..100),
          "recommended_use_cases":    [ {id, name, score, reasons}, ... top 25 ],
          "recommended_threat_actors":[ {name, why}, ... top 10 ],
          "computed_profile":         {sector, weak_controls, ...},
        }
    """
    if not answers:
        return {
            "use_case_count": 0,
            "threat_actor_matches": 0,
            "mitre_coverage_pct": 0,
            "recommended_use_cases": [],
            "recommended_threat_actors": [],
            "computed_profile": {},
        }

    # Lazy import to avoid pulling tide_service at module load (it touches ES).
    from ion.services import cyab_assessment_service as asmt
    from ion.services import tide_service

    try:
        playbooks = tide_service.get_playbooks_with_kill_chains() or []
    except Exception as exc:
        logger.warning("Failed to fetch TIDE playbooks for scoping: %s", exc)
        playbooks = []

    ranked, profile = asmt.score_use_cases(answers, playbooks, top_n=25)
    actors = asmt.rank_actors(profile, top_n=10)

    return {
        "use_case_count":            len(ranked),
        "threat_actor_matches":      len(actors),
        "mitre_coverage_pct":        mitre_coverage_pct(ranked),
        "recommended_use_cases":     ranked,
        "recommended_threat_actors": actors,
        "computed_profile":          profile,
    }


def summary_text(scores: Dict[str, Any]) -> str:
    """One-liner for the live counter widget on the side of the questionnaire.

    Format matches the spec literally: "47 use cases · 12 threat-actor
    matches · 64% MITRE Initial Access coverage".
    """
    uc = scores.get("use_case_count", 0)
    ta = scores.get("threat_actor_matches", 0)
    mt = scores.get("mitre_coverage_pct", 0)
    return f"{uc} use cases · {ta} threat-actor matches · {mt}% MITRE Initial Access coverage"
