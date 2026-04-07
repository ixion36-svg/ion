"""Rule Tuning Feedback Loop — cross-references TIDE rules with ES alert closure outcomes.

Identifies:
- FP-heavy rules (fire frequently, get closed as false_positive)
- High-value rules (fire and produce true_positive closures)
- Silent rules (exist in TIDE but never fire in ES)
- Noisy rules (high volume, low close rate)
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertTriage, AlertCase

logger = logging.getLogger(__name__)


def get_rule_tuning_analysis(
    session: Session,
    tide_service,
    es_service,
    hours: int = 168,
) -> dict[str, Any]:
    """Generate rule tuning recommendations.

    Cross-references:
    1. TIDE rules (quality scores, enabled status)
    2. ES alerts (which rules actually fire)
    3. ION case closures (FP/TP outcomes per rule)

    Args:
        session: DB session for case closure data
        tide_service: TideService instance
        es_service: ElasticsearchService instance
        hours: Lookback window for ES alerts
    """
    if not tide_service.enabled:
        return {"enabled": False, "error": "TIDE not configured"}

    # 1. Get all TIDE rules
    tide_rules = _get_tide_rules(tide_service)

    # 2. Get case closure outcomes grouped by rule name
    closure_data = _get_closure_by_rule(session)

    # 3. Build per-rule analysis
    fp_heavy = []
    high_value = []
    noisy = []
    silent = []
    tuning_recs = []

    tide_rule_names = {r["name"]: r for r in tide_rules}

    # Analyze rules with closure data
    for rule_name, stats in closure_data.items():
        tide_info = tide_rule_names.pop(rule_name, None)
        total = stats["total"]
        fp = stats.get("false_positive", 0)
        tp = stats.get("true_positive", 0)
        btp = stats.get("benign_true_positive", 0)

        entry = {
            "rule_name": rule_name,
            "total_closures": total,
            "true_positive": tp,
            "false_positive": fp,
            "benign_true_positive": btp,
            "other": total - tp - fp - btp,
            "fp_rate": round(fp / total * 100, 1) if total > 0 else 0,
            "tp_rate": round(tp / total * 100, 1) if total > 0 else 0,
        }

        if tide_info:
            entry["tide_quality"] = tide_info.get("quality_score")
            entry["tide_severity"] = tide_info.get("severity")
            entry["tide_enabled"] = tide_info.get("enabled")
            entry["mitre_ids"] = tide_info.get("mitre_ids") or []

        # Classify
        if total >= 3 and fp / total >= 0.6:
            fp_heavy.append(entry)
            tuning_recs.append({
                "rule_name": rule_name,
                "type": "reduce_fp",
                "severity": "high" if fp / total >= 0.8 else "medium",
                "message": f"{fp}/{total} closures are FP ({entry['fp_rate']}%). Consider tuning thresholds or adding exclusions.",
            })
        elif tp >= 2:
            high_value.append(entry)
        if total >= 10 and (tp + btp) / total < 0.3:
            noisy.append(entry)
            if rule_name not in [r["rule_name"] for r in tuning_recs]:
                tuning_recs.append({
                    "rule_name": rule_name,
                    "type": "noisy",
                    "severity": "medium",
                    "message": f"High volume ({total} closures) but only {tp} true positives. Generating analyst fatigue.",
                })

    # Silent rules (in TIDE, no closures)
    for rule_name, tide_info in tide_rule_names.items():
        if tide_info.get("enabled"):
            silent.append({
                "rule_name": rule_name,
                "tide_quality": tide_info.get("quality_score"),
                "tide_severity": tide_info.get("severity"),
                "mitre_ids": tide_info.get("mitre_ids") or [],
            })

    # Sort
    fp_heavy.sort(key=lambda r: r["fp_rate"], reverse=True)
    high_value.sort(key=lambda r: r["true_positive"], reverse=True)
    noisy.sort(key=lambda r: r["total_closures"], reverse=True)
    tuning_recs.sort(key=lambda r: 0 if r["severity"] == "high" else 1)

    # Summary stats
    total_rules_with_data = len(closure_data)
    total_fp = sum(s.get("false_positive", 0) for s in closure_data.values())
    total_tp = sum(s.get("true_positive", 0) for s in closure_data.values())
    total_closures = sum(s["total"] for s in closure_data.values())

    return {
        "enabled": True,
        "summary": {
            "total_tide_rules": len(tide_rules),
            "rules_with_closures": total_rules_with_data,
            "silent_rules": len(silent),
            "total_closures": total_closures,
            "total_true_positive": total_tp,
            "total_false_positive": total_fp,
            "overall_fp_rate": round(total_fp / total_closures * 100, 1) if total_closures > 0 else 0,
            "overall_tp_rate": round(total_tp / total_closures * 100, 1) if total_closures > 0 else 0,
        },
        "fp_heavy": fp_heavy[:20],
        "high_value": high_value[:20],
        "noisy": noisy[:20],
        "silent": silent[:50],
        "recommendations": tuning_recs[:30],
    }


def _get_tide_rules(tide_service) -> list[dict]:
    """Fetch all rules from TIDE."""
    result = tide_service.get_rules_paginated(limit=2000)
    return result.get("rows", [])


def _get_closure_by_rule(session: Session) -> dict[str, dict]:
    """Get case closure reason counts grouped by triggered_rules."""
    # Get all closed cases that have triggered_rules
    cases = session.execute(
        select(AlertCase).where(
            and_(
                AlertCase.status == "closed",
                AlertCase.triggered_rules.isnot(None),
            )
        )
    ).scalars().all()

    by_rule: dict[str, dict] = {}
    for case in cases:
        rules = case.triggered_rules or []
        if isinstance(rules, str):
            try:
                import json
                rules = json.loads(rules)
            except (ValueError, TypeError):
                rules = [rules]

        reason = case.closure_reason or "unspecified"
        for rule_name in rules:
            if rule_name not in by_rule:
                by_rule[rule_name] = {"total": 0}
            by_rule[rule_name]["total"] += 1
            by_rule[rule_name][reason] = by_rule[rule_name].get(reason, 0) + 1

    return by_rule
