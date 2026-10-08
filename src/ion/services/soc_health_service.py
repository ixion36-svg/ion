"""SOC Health Scorecard service.

Computes a living SOC health/maturity scorecard across five dimensions:
detection coverage, operational efficiency, team readiness, knowledge
completeness, and integration health. Each dimension is scored 0-100
and combined into an overall weighted grade.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.models.user import User
from ion.services.case_metrics import case_metrics

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dimension weights (must sum to 1.0)
# ---------------------------------------------------------------------------
WEIGHTS = {
    "detection_coverage": 0.30,
    "operational_efficiency": 0.30,
    "team_readiness": 0.15,
    "knowledge_completeness": 0.10,
    "integration_health": 0.15,
}

# Grade thresholds
GRADE_THRESHOLDS = [
    (80, "A"),
    (65, "B"),
    (50, "C"),
    (35, "D"),
    (0, "F"),
]


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> int:
    """Clamp a float to [lo, hi] and return as int."""
    return int(max(lo, min(hi, value)))


def _grade(score: int) -> str:
    for threshold, letter in GRADE_THRESHOLDS:
        if score >= threshold:
            return letter
    return "F"


def _label(score: int) -> str:
    if score >= 80:
        return "Excellent"
    if score >= 65:
        return "Good"
    if score >= 50:
        return "Fair"
    if score >= 35:
        return "Needs Improvement"
    return "Critical"


# ---------------------------------------------------------------------------
# Individual dimension calculators
# ---------------------------------------------------------------------------

def _detection_coverage() -> dict[str, Any]:
    """Score detection coverage using TIDE posture stats."""
    details: dict[str, Any] = {
        "tide_available": False,
        "technique_coverage_pct": 0,
        "rule_quality_pct": 0,
        "covered_techniques": 0,
        "total_techniques": 0,
        "avg_quality": 0,
    }

    try:
        from ion.services.tide_service import get_tide_service
        tide = get_tide_service()
        stats = tide.get_posture_stats()
        if stats is None:
            return {"score": 0, "label": _label(0), "details": details}

        details["tide_available"] = True
        total_tech = stats.get("total_techniques", 0)
        covered_tech = stats.get("covered_techniques", 0)
        quality = stats.get("quality", {})
        avg_quality = quality.get("avg_quality", 0) or 0

        details["covered_techniques"] = covered_tech
        details["total_techniques"] = total_tech
        details["avg_quality"] = avg_quality

        # Technique coverage: covered / total * 100
        tech_pct = (covered_tech / total_tech * 100) if total_tech > 0 else 0
        details["technique_coverage_pct"] = round(tech_pct, 1)

        # Rule quality: avg_quality / 40 * 100 (TIDE scores range 0-40)
        quality_pct = (avg_quality / 40 * 100) if avg_quality > 0 else 0
        details["rule_quality_pct"] = round(quality_pct, 1)

        # Combined: 60% technique coverage + 40% quality
        score = _clamp(tech_pct * 0.6 + quality_pct * 0.4)

    except Exception:
        logger.exception("Failed to compute detection coverage from TIDE")
        score = 0

    return {"score": score, "label": _label(score), "details": details}


def _operational_efficiency(session: Session) -> dict[str, Any]:
    """Score operational efficiency from case data over the last 30 days."""
    now = datetime.now(timezone.utc)
    thirty_days_ago = now - timedelta(days=30)

    details: dict[str, Any] = {
        "cases_opened_30d": 0,
        "cases_closed_30d": 0,
        "closure_rate_pct": 0,
        "fp_rate_pct": 0,
        "avg_mttr_hours": None,
    }

    try:
        # Opened / closed / FP / MTTR all come from the shared case_metrics
        # helper so this scorecard cannot disagree with /executive-report or
        # /analyst-efficiency for the same window. `fp_rate_of_closed` preserves
        # this dimension's historical denominator (all closures) — see
        # services/case_metrics for why the dispositions-based rate differs.
        core = case_metrics(session, thirty_days_ago)
        opened = core["opened"]
        closed = core["closed"]
        avg_mttr = core["avg_mttr_hours"]

        details["cases_opened_30d"] = opened
        details["cases_closed_30d"] = closed

        # Closure rate score (target >= 90%)
        closure_rate = core["closure_rate_pct"] if opened > 0 else 100
        details["closure_rate_pct"] = round(closure_rate, 1)
        closure_score = _clamp(closure_rate / 0.9)  # 90% -> 100 score

        # FP rate score (target < 30%)
        fp_rate = core["fp_rate_of_closed"] or 0
        details["fp_rate_pct"] = round(fp_rate, 1)
        # 0% FP = 100 score, 30% FP = 50 score, 60%+ FP = 0 score
        fp_score = _clamp(100 - (fp_rate / 0.6))

        # MTTR score (< 4h = 100, > 24h = 0, linear between)
        if core["mttr_sample_size"]:
            details["avg_mttr_hours"] = avg_mttr

            if avg_mttr is not None:
                if avg_mttr <= 4:
                    mttr_score = 100
                elif avg_mttr >= 24:
                    mttr_score = 0
                else:
                    # Linear: 4h->100, 24h->0
                    mttr_score = _clamp((24 - avg_mttr) / (24 - 4) * 100)
            else:
                mttr_score = 50  # No data, neutral
        else:
            mttr_score = 50  # No data, neutral

        # No cases at all means we can't assess — neutral score
        if opened == 0 and closed == 0:
            score = 50
        else:
            # Weighted: 40% closure rate, 30% FP rate, 30% MTTR
            score = _clamp(closure_score * 0.4 + fp_score * 0.3 + mttr_score * 0.3)

    except Exception:
        logger.exception("Failed to compute operational efficiency")
        score = 50

    return {"score": score, "label": _label(score), "details": details}


def _verified_operational_headcount(session: Session) -> int:
    """How many people have actually reached the operational stage of a role.

    The workforce module already tracks verified readiness through role
    journeys, so capacity does not have to be inferred from account rows.
    Returns 0 when no journeys exist, which the caller reads as "fall back
    to accounts, and say so".
    """
    try:
        from ion.models.workforce import UserJourney
        from ion.services.workforce_service import STAGE_OPERATIONAL

        return int(
            session.execute(
                select(func.count(func.distinct(UserJourney.user_id)))
                .where(UserJourney.stage == STAGE_OPERATIONAL)
            ).scalar() or 0
        )
    except Exception:
        logger.debug("Role journeys unavailable; readiness falls back to accounts")
        return 0


def _team_readiness(session: Session) -> dict[str, Any]:
    """Score analyst capacity against open case load.

    Review 2026-10-08 §18: this counted rows in ``users`` where
    ``is_active``, and called the result team readiness. An active account
    is not a verified, on-duty analyst — a service account, a departed
    joiner not yet offboarded and a trainee all counted as capacity.

    Verified operational role journeys are now preferred, and when none
    exist the account count is still used but labelled an estimate, so a
    reader can tell which number they are looking at.
    """
    details: dict[str, Any] = {
        "available": False,
        "active_analysts": 0,
        "analyst_capacity": 0,
        "capacity_source": "active_accounts",
        "estimated": True,
        "open_cases": 0,
        "cases_per_analyst": None,
        "definition": (
            "Open cases per analyst, against verified operational role "
            "journeys where they exist. With no journeys recorded this "
            "falls back to counting active user accounts, which overstates "
            "capacity: an account is not a verified, on-duty analyst."
        ),
    }

    try:
        active_analysts = session.execute(
            select(func.count(User.id)).where(User.is_active.is_(True))
        ).scalar() or 0

        open_cases = session.execute(
            select(func.count(AlertCase.id)).where(
                AlertCase.status == AlertCaseStatus.OPEN
            )
        ).scalar() or 0

        details["active_analysts"] = active_analysts
        details["open_cases"] = open_cases

        verified = _verified_operational_headcount(session)
        if verified > 0:
            details["analyst_capacity"] = verified
            details["capacity_source"] = "verified_journeys"
            details["estimated"] = False
        else:
            details["analyst_capacity"] = active_analysts
            details["capacity_source"] = "active_accounts"
            details["estimated"] = True
            if active_analysts:
                details["reason"] = (
                    "No verified operational role journeys recorded, so "
                    "capacity is estimated from active accounts."
                )

        active_analysts = details["analyst_capacity"]

        if active_analysts > 0:
            details["available"] = True
            cases_per = open_cases / active_analysts
            details["cases_per_analyst"] = round(cases_per, 1)

            # Target: < 10 open cases per analyst
            if cases_per <= 10:
                load_score = 100
            elif cases_per >= 30:
                load_score = 0
            else:
                load_score = _clamp((30 - cases_per) / (30 - 10) * 100)

            # Team size factor: at least 3 analysts = 100%, 1 = 40%
            if active_analysts >= 3:
                size_score = 100
            elif active_analysts == 2:
                size_score = 70
            else:
                size_score = 40

            score = _clamp(load_score * 0.6 + size_score * 0.4)
        else:
            # Nobody to score. That is missing input, not zero readiness.
            details["reason"] = "No analyst capacity recorded."
            return {"score": None, "label": "Unavailable", "details": details}

    except Exception:
        logger.exception("Failed to compute team readiness")
        details["reason"] = "Capacity inputs could not be read."
        return {"score": None, "label": "Unavailable", "details": details}

    return {"score": score, "label": _label(score), "details": details}


#: Weights for one capability's documentation score. doc_status is the
#: substance; runbooks and procedures are what make it usable on shift.
_DOC_STATUS_WEIGHT = 0.7
_RUNBOOK_WEIGHT = 0.15
_PROCEDURE_WEIGHT = 0.15

#: doc_status is a three-step scale, not a boolean.
_DOC_STATUS_SCORE = {
    "undocumented": 0.0,
    "basic": 0.5,
    "comprehensive": 1.0,
}


def _knowledge_completeness(session: Session) -> dict[str, Any]:
    """Score documentation coverage across the tracked SOC capabilities.

    Review 2026-10-08 §18: this used to divide a count of
    ``KnowledgeArticle`` rows by a target of 200 "articles". But
    ``KnowledgeArticle`` is one row per capability area carrying a
    ``doc_status``, unique on ``capability_key``, and the server seeds
    every capability in the catalogue as ``undocumented`` at startup. A
    fresh install with no documentation therefore scored about 45/100,
    and the dimension could never exceed 46 however well documented the
    SOC actually was. It counted placeholders, not written knowledge.

    The score is now the mean documentation completeness of the tracked
    capabilities, and the details carry the definition, the denominator
    and a status breakdown, so a manager can explain the number from
    records rather than trusting it.
    """
    details: dict[str, Any] = {
        "available": False,
        "capabilities_tracked": 0,
        "definition": (
            "Mean documentation completeness across tracked SOC capability "
            "areas. Each capability scores on its doc_status "
            "(undocumented/basic/comprehensive, 70%) plus whether it has "
            "runbooks (15%) and procedures (15%). A seeded but undocumented "
            "capability scores zero."
        ),
        "by_doc_status": {"undocumented": 0, "basic": 0, "comprehensive": 0},
        "with_runbooks": 0,
        "with_procedures": 0,
    }

    try:
        from ion.models.skills import KnowledgeArticle
        rows = session.execute(select(KnowledgeArticle)).scalars().all()
    except Exception:
        logger.exception("KnowledgeArticle not queryable; knowledge score unavailable")
        details["reason"] = "Capability documentation registry could not be read."
        return {"score": None, "label": "Unavailable", "details": details}

    if not rows:
        # An unseeded registry is unknown, not zero documentation.
        details["reason"] = "No capability documentation rows exist yet."
        return {"score": None, "label": "Unavailable", "details": details}

    total = 0.0
    for row in rows:
        status = (row.doc_status or "undocumented").lower()
        details["by_doc_status"][status] = details["by_doc_status"].get(status, 0) + 1
        if row.has_runbooks:
            details["with_runbooks"] += 1
        if row.has_procedures:
            details["with_procedures"] += 1

        total += _DOC_STATUS_SCORE.get(status, 0.0) * _DOC_STATUS_WEIGHT
        total += (_RUNBOOK_WEIGHT if row.has_runbooks else 0.0)
        total += (_PROCEDURE_WEIGHT if row.has_procedures else 0.0)

    details["available"] = True
    details["capabilities_tracked"] = len(rows)
    details["fully_documented"] = details["by_doc_status"].get("comprehensive", 0)

    # Round before clamping: _clamp truncates, and the weights sum to
    # 0.9999999999999999 in binary float, so a fully documented SOC would
    # otherwise score 99.
    score = _clamp(round(total / len(rows) * 100))
    return {"score": score, "label": _label(score), "details": details}


def _integration_health() -> dict[str, Any]:
    """Score integration health: TIDE, Elasticsearch, and OpenCTI."""
    details: dict[str, Any] = {
        "tide": {"configured": False, "healthy": False},
        "elasticsearch": {"configured": False, "healthy": False},
        "opencti": {"configured": False, "healthy": False},
    }
    points = 0

    # TIDE
    try:
        from ion.services.tide_service import get_tide_service
        tide = get_tide_service()
        details["tide"]["configured"] = tide.enabled
        if tide.enabled:
            result = tide.test_connection()
            details["tide"]["healthy"] = result.get("ok", False)
            if result.get("ok"):
                points += 33
    except Exception:
        logger.debug("TIDE health check failed")

    # Elasticsearch
    try:
        from ion.core.config import get_config
        config = get_config()
        es_configured = config.elasticsearch_enabled and bool(config.elasticsearch_url)
        details["elasticsearch"]["configured"] = es_configured
        if es_configured:
            # Lightweight check: try HEAD request to ES
            import httpx

            from ion.core.config import get_ssl_verify
            verify = get_ssl_verify()
            resp = httpx.get(
                config.elasticsearch_url,
                headers=(
                    {"Authorization": f"ApiKey {config.elasticsearch_api_key}"}
                    if config.elasticsearch_api_key else {}
                ),
                verify=verify,
                timeout=5.0,
            )
            details["elasticsearch"]["healthy"] = resp.status_code == 200
            if resp.status_code == 200:
                points += 33
    except Exception:
        logger.debug("Elasticsearch health check failed")

    # OpenCTI
    try:
        from ion.core.config import get_opencti_config
        octi = get_opencti_config()
        octi_configured = octi.get("enabled", False) and bool(octi.get("url"))
        details["opencti"]["configured"] = octi_configured
        if octi_configured:
            import httpx

            from ion.core.config import get_ssl_verify
            verify = get_ssl_verify() if octi.get("verify_ssl", True) else False
            resp = httpx.post(
                f"{octi['url']}/graphql",
                json={"query": "{ about { version } }"},
                headers={"Authorization": f"Bearer {octi.get('token', '')}"},
                verify=verify,
                timeout=5.0,
            )
            details["opencti"]["healthy"] = resp.status_code == 200
            if resp.status_code == 200:
                points += 34  # 33+33+34 = 100
    except Exception:
        logger.debug("OpenCTI health check failed")

    score = _clamp(points)
    return {"score": score, "label": _label(score), "details": details}


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------

def _build_recommendations(dimensions: dict[str, dict]) -> list[dict[str, str]]:
    """Generate actionable recommendations for dimensions scoring below 60."""
    recs: list[dict[str, str]] = []
    threshold = 60

    # An unavailable dimension has score None. Treat it as "nothing to
    # recommend from" rather than a failing score: its own details already
    # say why it could not be measured, and None < 60 is a TypeError.
    score_map = {
        k: (v["score"] if v.get("score") is not None else threshold)
        for k, v in dimensions.items()
    }

    if score_map["detection_coverage"] < threshold:
        details = dimensions["detection_coverage"]["details"]
        if not details.get("tide_available"):
            recs.append({
                "area": "Detection Coverage",
                "message": "TIDE integration is not configured. Connect TIDE to enable detection coverage tracking.",
                "priority": "high",
            })
        else:
            if details.get("technique_coverage_pct", 0) < 50:
                recs.append({
                    "area": "Detection Coverage",
                    "message": (
                        f"Only {details.get('covered_techniques', 0)} of "
                        f"{details.get('total_techniques', 0)} MITRE techniques are covered. "
                        "Review blind spots and deploy additional detection rules."
                    ),
                    "priority": "high",
                })
            if details.get("rule_quality_pct", 0) < 50:
                recs.append({
                    "area": "Detection Coverage",
                    "message": (
                        f"Average rule quality score is {details.get('avg_quality', 0)}/40. "
                        "Tune low-quality rules to reduce false positives and improve fidelity."
                    ),
                    "priority": "medium",
                })

    if score_map["operational_efficiency"] < threshold:
        details = dimensions["operational_efficiency"]["details"]
        if details.get("closure_rate_pct", 0) < 70:
            recs.append({
                "area": "Operational Efficiency",
                "message": (
                    f"Case closure rate is {details.get('closure_rate_pct', 0)}% (target: 90%). "
                    "Investigate bottlenecks in the triage pipeline."
                ),
                "priority": "high",
            })
        if details.get("fp_rate_pct", 0) > 30:
            recs.append({
                "area": "Operational Efficiency",
                "message": (
                    f"False positive rate is {details.get('fp_rate_pct', 0)}%. "
                    "Tune noisy detection rules and update exclusion lists."
                ),
                "priority": "high",
            })
        mttr = details.get("avg_mttr_hours")
        if mttr is not None and mttr > 8:
            recs.append({
                "area": "Operational Efficiency",
                "message": (
                    f"Mean time to resolve is {mttr}h (target: < 4h). "
                    "Consider automating initial triage steps or adding playbook guidance."
                ),
                "priority": "medium",
            })

    if score_map["team_readiness"] < threshold:
        details = dimensions["team_readiness"]["details"]
        if details.get("active_analysts", 0) < 3:
            recs.append({
                "area": "Team Readiness",
                "message": (
                    f"Only {details.get('active_analysts', 0)} active analyst(s). "
                    "Consider onboarding additional team members to reduce single-point-of-failure risk."
                ),
                "priority": "high",
            })
        cpa = details.get("cases_per_analyst")
        if cpa is not None and cpa > 10:
            recs.append({
                "area": "Team Readiness",
                "message": (
                    f"Analysts are handling {cpa} open cases each (target: < 10). "
                    "Re-balance workload or close stale cases."
                ),
                "priority": "medium",
            })

    if score_map["knowledge_completeness"] < threshold:
        details = dimensions["knowledge_completeness"]["details"]
        recs.append({
            "area": "Knowledge Completeness",
            "message": (
                f"Knowledge base has {details.get('article_count', 0)} articles "
                f"(target: {details.get('target', 200)}). "
                "Document runbooks, procedures, and tribal knowledge to improve resilience."
            ),
            "priority": "medium",
        })

    if score_map["integration_health"] < threshold:
        details = dimensions["integration_health"]["details"]
        for name, info in details.items():
            if not info.get("healthy"):
                label = name.upper() if name == "tide" else name.replace("_", " ").title()
                if not info.get("configured"):
                    recs.append({
                        "area": "Integration Health",
                        "message": f"{label} is not configured. Enable it to improve visibility and automation.",
                        "priority": "medium",
                    })
                else:
                    recs.append({
                        "area": "Integration Health",
                        "message": f"{label} is configured but not responding. Check connectivity and credentials.",
                        "priority": "high",
                    })

    return recs


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def get_soc_health_scorecard(session: Session) -> dict:
    """Compute the SOC health scorecard across all dimensions.

    Args:
        session: SQLAlchemy database session.

    Returns:
        Dictionary with overall_score, grade, dimensions, and recommendations.
    """
    dimensions = {
        "detection_coverage": _detection_coverage(),
        "operational_efficiency": _operational_efficiency(session),
        "team_readiness": _team_readiness(session),
        "knowledge_completeness": _knowledge_completeness(session),
        "integration_health": _integration_health(),
    }

    # Weighted average over the dimensions that could actually be
    # measured. A dimension with no inputs now reports score None rather
    # than a neutral or zero number, so including it would either invent
    # data or punish the SOC for an unconfigured source. The weights are
    # renormalised across what remains, and the result says which
    # dimensions were left out and what denominator was used.
    measured = {
        dim: d["score"] for dim, d in dimensions.items()
        if d.get("score") is not None
    }
    unavailable = sorted(set(dimensions) - set(measured))
    weight_total = sum(WEIGHTS[dim] for dim in measured)

    if weight_total > 0:
        overall = sum(
            measured[dim] * WEIGHTS[dim] for dim in measured
        ) / weight_total
        overall_score = _clamp(round(overall))
        grade = _grade(overall_score)
    else:
        overall_score = None
        grade = None

    return {
        "overall_score": overall_score,
        "grade": grade,
        "dimensions": dimensions,
        "scored_dimensions": sorted(measured),
        "unavailable_dimensions": unavailable,
        "weight_basis": round(weight_total, 4),
        "recommendations": _build_recommendations(dimensions),
    }
