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

from ion.models.alert_triage import AlertCase, AlertCaseStatus, CaseClosureReason
from ion.models.user import User

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
        # Cases opened in last 30 days
        opened = session.execute(
            select(func.count(AlertCase.id)).where(
                AlertCase.created_at >= thirty_days_ago
            )
        ).scalar() or 0

        # Cases closed in last 30 days
        closed = session.execute(
            select(func.count(AlertCase.id)).where(
                AlertCase.status == AlertCaseStatus.CLOSED,
                AlertCase.closed_at >= thirty_days_ago,
            )
        ).scalar() or 0

        # False-positive count among closed cases
        fp_count = session.execute(
            select(func.count(AlertCase.id)).where(
                AlertCase.status == AlertCaseStatus.CLOSED,
                AlertCase.closed_at >= thirty_days_ago,
                AlertCase.closure_reason == CaseClosureReason.FALSE_POSITIVE.value,
            )
        ).scalar() or 0

        # MTTR: average time from created_at to closed_at for closed cases
        mttr_rows = session.execute(
            select(AlertCase.created_at, AlertCase.closed_at).where(
                AlertCase.status == AlertCaseStatus.CLOSED,
                AlertCase.closed_at >= thirty_days_ago,
                AlertCase.closed_at.isnot(None),
            )
        ).all()

        details["cases_opened_30d"] = opened
        details["cases_closed_30d"] = closed

        # Closure rate score (target >= 90%)
        closure_rate = (closed / opened * 100) if opened > 0 else 100
        details["closure_rate_pct"] = round(closure_rate, 1)
        closure_score = _clamp(closure_rate / 0.9)  # 90% -> 100 score

        # FP rate score (target < 30%)
        fp_rate = (fp_count / closed * 100) if closed > 0 else 0
        details["fp_rate_pct"] = round(fp_rate, 1)
        # 0% FP = 100 score, 30% FP = 50 score, 60%+ FP = 0 score
        fp_score = _clamp(100 - (fp_rate / 0.6))

        # MTTR score (< 4h = 100, > 24h = 0, linear between)
        if mttr_rows:
            total_hours = 0.0
            count = 0
            for row in mttr_rows:
                created = row[0]
                closed_at = row[1]
                if created and closed_at:
                    delta = (closed_at - created).total_seconds() / 3600.0
                    total_hours += delta
                    count += 1
            avg_mttr = total_hours / count if count > 0 else None
            details["avg_mttr_hours"] = round(avg_mttr, 1) if avg_mttr is not None else None

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


def _team_readiness(session: Session) -> dict[str, Any]:
    """Score team readiness based on active analysts and case load."""
    details: dict[str, Any] = {
        "active_analysts": 0,
        "open_cases": 0,
        "cases_per_analyst": None,
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

        if active_analysts > 0:
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
            score = 0

    except Exception:
        logger.exception("Failed to compute team readiness")
        score = 0

    return {"score": score, "label": _label(score), "details": details}


def _knowledge_completeness(session: Session) -> dict[str, Any]:
    """Score knowledge base completeness by article count."""
    details: dict[str, Any] = {
        "article_count": 0,
        "target": 200,
    }

    try:
        from ion.models.skills import KnowledgeArticle
        count = session.execute(
            select(func.count(KnowledgeArticle.id))
        ).scalar() or 0
        details["article_count"] = count
    except (ImportError, Exception):
        logger.debug("KnowledgeArticle model not available, falling back to 0")
        count = 0

    # Target: >= 200 articles = 100 score
    score = _clamp(count / 200 * 100)
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

    score_map = {k: v["score"] for k, v in dimensions.items()}

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

    # Weighted average
    overall = sum(
        dimensions[dim]["score"] * weight
        for dim, weight in WEIGHTS.items()
    )
    overall_score = _clamp(overall)

    return {
        "overall_score": overall_score,
        "grade": _grade(overall_score),
        "dimensions": dimensions,
        "recommendations": _build_recommendations(dimensions),
    }
