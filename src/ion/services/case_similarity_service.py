"""Case similarity service — finds resolved cases similar to a given case."""

import json
import logging
from collections import Counter
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertCase

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

STOP_WORDS = frozenset({
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "was", "are", "were", "be", "been",
    "being", "have", "has", "had", "do", "does", "did", "will", "would",
    "could", "should", "may", "might", "shall", "can", "not", "no", "nor",
    "so", "if", "then", "than", "that", "this", "these", "those", "it",
    "its", "as", "into", "about", "up", "out", "over", "after", "before",
    "between", "under", "during", "through", "above", "below", "all", "each",
    "any", "both", "few", "more", "most", "other", "some", "such", "only",
    "very", "just", "also", "alert", "case", "detected", "detection",
})


def _safe_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []
    if isinstance(value, list):
        return value
    return []


def _jaccard(set_a: set, set_b: set) -> float:
    if not set_a and not set_b:
        return 0.0
    intersection = set_a & set_b
    union = set_a | set_b
    return len(intersection) / len(union)


def _severity_score(sev_a: Optional[str], sev_b: Optional[str]) -> float:
    if not sev_a or not sev_b:
        return 0.0
    a = sev_a.lower().strip()
    b = sev_b.lower().strip()
    if a == b:
        return 1.0
    if a in SEVERITY_ORDER and b in SEVERITY_ORDER:
        distance = abs(SEVERITY_ORDER.index(a) - SEVERITY_ORDER.index(b))
        if distance == 1:
            return 0.5
    return 0.0


def _title_words(title: Optional[str]) -> set[str]:
    if not title:
        return set()
    return {w for w in title.lower().split() if w not in STOP_WORDS and len(w) > 1}


def _build_match_reasons(
    target_rules: set,
    target_hosts: set,
    target_observables: set,
    candidate_rules: set,
    candidate_hosts: set,
    candidate_observables: set,
    target_severity: Optional[str],
    candidate_severity: Optional[str],
) -> list[str]:
    reasons = []
    shared_rules = target_rules & candidate_rules
    if shared_rules:
        reasons.append(f"{len(shared_rules)} shared rule{'s' if len(shared_rules) != 1 else ''}")
    shared_hosts = target_hosts & candidate_hosts
    for host in sorted(shared_hosts)[:3]:
        reasons.append(f"same host: {host}")
    if shared_hosts and len(shared_hosts) > 3:
        reasons.append(f"+{len(shared_hosts) - 3} more shared hosts")
    shared_obs = target_observables & candidate_observables
    if shared_obs:
        reasons.append(f"{len(shared_obs)} shared observable{'s' if len(shared_obs) != 1 else ''}")
    if target_severity and candidate_severity and target_severity.lower() == candidate_severity.lower():
        reasons.append(f"same severity: {target_severity.lower()}")
    return reasons


def find_similar_cases(session: Session, case_id: int, limit: int = 10) -> dict:
    target = session.execute(
        select(AlertCase).where(AlertCase.id == case_id)
    ).scalar_one_or_none()
    if not target:
        return {"case_id": case_id, "case_number": "", "similar_cases": [], "resolution_stats": {}}

    closed_cases = session.execute(
        select(AlertCase).where(
            AlertCase.status == "closed",
            AlertCase.id != case_id,
        )
    ).scalars().all()

    target_rules = set(str(r) for r in _safe_list(target.triggered_rules))
    target_hosts = set(str(h) for h in _safe_list(target.affected_hosts))
    target_observables = set(str(o) for o in _safe_list(target.observables))
    target_title_words = _title_words(target.title)

    scored = []
    for case in closed_cases:
        c_rules = set(str(r) for r in _safe_list(case.triggered_rules))
        c_hosts = set(str(h) for h in _safe_list(case.affected_hosts))
        c_observables = set(str(o) for o in _safe_list(case.observables))
        c_title_words = _title_words(case.title)

        rules_sim = _jaccard(target_rules, c_rules)
        hosts_sim = _jaccard(target_hosts, c_hosts)
        sev_sim = _severity_score(target.severity, case.severity)
        obs_sim = _jaccard(target_observables, c_observables)
        title_sim = _jaccard(target_title_words, c_title_words)

        score = (
            rules_sim * 30
            + hosts_sim * 25
            + sev_sim * 15
            + obs_sim * 20
            + title_sim * 10
        )
        score = int(round(score))

        if score == 0:
            continue

        resolution_hours = None
        if case.closed_at and case.created_at:
            delta = case.closed_at - case.created_at
            resolution_hours = round(delta.total_seconds() / 3600, 1)

        match_reasons = _build_match_reasons(
            target_rules, target_hosts, target_observables,
            c_rules, c_hosts, c_observables,
            target.severity, case.severity,
        )

        scored.append({
            "case_id": case.id,
            "case_number": case.case_number,
            "title": case.title,
            "severity": case.severity,
            "closure_reason": case.closure_reason,
            "closed_at": case.closed_at.isoformat() if case.closed_at else None,
            "similarity_score": score,
            "match_reasons": match_reasons,
            "resolution_time_hours": resolution_hours,
        })

    scored.sort(key=lambda x: x["similarity_score"], reverse=True)
    top = scored[:limit]

    resolution_stats: dict = {}
    if top:
        closure_reasons = [c["closure_reason"] for c in top if c["closure_reason"]]
        if closure_reasons:
            resolution_stats["most_common_closure"] = Counter(closure_reasons).most_common(1)[0][0]
        else:
            resolution_stats["most_common_closure"] = None

        hours = [c["resolution_time_hours"] for c in top if c["resolution_time_hours"] is not None]
        resolution_stats["avg_resolution_hours"] = round(sum(hours) / len(hours), 1) if hours else None
    else:
        resolution_stats["most_common_closure"] = None
        resolution_stats["avg_resolution_hours"] = None

    return {
        "case_id": target.id,
        "case_number": target.case_number,
        "similar_cases": top,
        "resolution_stats": resolution_stats,
    }
