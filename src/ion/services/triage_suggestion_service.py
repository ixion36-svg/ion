"""Triage suggestion service for ION.

Suggests triage actions based on historical case closure data. Analyses
closed cases matching a given rule name (and optionally host) to produce
a recommendation with confidence scoring.
"""

import json
import logging
from collections import Counter
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertCase, AlertCaseStatus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Closure-reason-to-action mapping
# ---------------------------------------------------------------------------

_REASON_ACTION_MAP = {
    "false_positive": "likely_false_positive",
    "true_positive": "likely_true_positive",
    "benign_true_positive": "likely_benign",
}

_MIN_CASES_FOR_SUGGESTION = 3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_json_list(value) -> list:
    """Safely parse a JSON list field that may be a string, list, or None."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []
    return []


def _compute_confidence(top_count: int, total: int) -> str:
    """Return confidence level based on how dominant the top reason is."""
    if total == 0:
        return "low"
    ratio = top_count / total
    if ratio >= 0.80:
        return "high"
    if ratio >= 0.60:
        return "medium"
    return "low"


def _avg_resolution_hours(cases: list[AlertCase]) -> Optional[float]:
    """Compute average resolution time in hours for cases with closure data."""
    durations = []
    for case in cases:
        if case.closed_at and case.created_at:
            closed = case.closed_at if isinstance(case.closed_at, datetime) else case.closed_at
            created = case.created_at if isinstance(case.created_at, datetime) else case.created_at
            delta = (closed - created).total_seconds()
            if delta >= 0:
                durations.append(delta / 3600.0)
    if not durations:
        return None
    return round(sum(durations) / len(durations), 2)


def _determine_action(distribution: Counter, total: int) -> tuple[str, str, str]:
    """Determine suggested action, confidence, and the top closure reason.

    Returns (action, confidence, top_reason).
    """
    if total < _MIN_CASES_FOR_SUGGESTION:
        return "insufficient_data", "low", ""

    top_reason, top_count = distribution.most_common(1)[0]
    confidence = _compute_confidence(top_count, total)
    action = _REASON_ACTION_MAP.get(top_reason, "needs_investigation")
    return action, confidence, top_reason


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_triage_suggestion(
    session: Session,
    rule_name: str,
    host: Optional[str] = None,
    severity: Optional[str] = None,
) -> dict:
    """Suggest a triage action based on historical closure data.

    Parameters
    ----------
    session : Session
        Active SQLAlchemy session.
    rule_name : str
        Detection rule name to look up in closed cases.
    host : str, optional
        Affected host to narrow the search.
    severity : str, optional
        Alert severity (currently used for context, not filtering).

    Returns
    -------
    dict
        Suggestion payload with action, confidence, distribution, and reasoning.
    """
    # Fetch all closed cases
    stmt = select(AlertCase).where(AlertCase.status == AlertCaseStatus.CLOSED)
    closed_cases: list[AlertCase] = list(session.scalars(stmt).all())

    # ---- Filter: cases whose triggered_rules contain rule_name ----
    rule_matches: list[AlertCase] = []
    for case in closed_cases:
        rules = _parse_json_list(case.triggered_rules)
        if rule_name in rules:
            rule_matches.append(case)

    # ---- Closure-reason distribution for rule matches ----
    rule_distribution: Counter = Counter()
    for case in rule_matches:
        reason = case.closure_reason or "unknown"
        rule_distribution[reason] += 1

    total = len(rule_matches)
    action, confidence, top_reason = _determine_action(rule_distribution, total)
    avg_hours = _avg_resolution_hours(rule_matches)

    # Build human-readable reasoning
    if total < _MIN_CASES_FOR_SUGGESTION:
        reasoning = (
            f"Only {total} closed case(s) found for rule '{rule_name}'. "
            "Not enough data to make a confident suggestion."
        )
    else:
        top_count = rule_distribution.get(top_reason, 0)
        pct = round(top_count / total * 100)
        reasoning = (
            f"This rule was closed as {top_reason} in {top_count}/{total} "
            f"cases ({pct}%)."
        )

    # ---- Host-specific stats (only when host is provided) ----
    host_specific = None
    if host:
        host_matches: list[AlertCase] = []
        for case in rule_matches:
            hosts = _parse_json_list(case.affected_hosts)
            if host in hosts:
                host_matches.append(case)

        if host_matches:
            host_distribution: Counter = Counter()
            for case in host_matches:
                reason = case.closure_reason or "unknown"
                host_distribution[reason] += 1

            host_total = len(host_matches)
            host_top_reason, host_top_count = host_distribution.most_common(1)[0]
            host_confidence = _compute_confidence(host_top_count, host_total)

            host_specific = {
                "total": host_total,
                "top_closure": host_top_reason,
                "confidence": host_confidence,
            }

    return {
        "rule_name": rule_name,
        "host": host,
        "total_matching_cases": total,
        "suggested_action": action,
        "confidence": confidence,
        "closure_distribution": dict(rule_distribution),
        "avg_resolution_hours": avg_hours,
        "reasoning": reasoning,
        "host_specific": host_specific,
    }
