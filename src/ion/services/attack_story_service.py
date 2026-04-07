"""Attack Story correlation service for ION.

Groups related alerts into narrative "attack stories" that show multi-step
attack progressions against a single entity (host or user).  Stories are
scored by kill-chain breadth and alert severity so analysts can prioritise
the most advanced intrusions first.
"""

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Canonical MITRE ATT&CK kill chain order.  Tactic names are lower-cased and
# hyphenated to match the ATT&CK framework identifiers used in detection rules.
KILL_CHAIN_ORDER: list[str] = [
    "reconnaissance",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

_TACTIC_INDEX: dict[str, int] = {t: i for i, t in enumerate(KILL_CHAIN_ORDER)}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_tactic(name: str | None) -> str | None:
    """Normalise a tactic name to the canonical hyphenated lower-case form."""
    if not name:
        return None
    return name.strip().lower().replace("_", "-").replace(" ", "-")


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse a timestamp from an alert dict value (str or datetime)."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        # Accept ISO-8601 with or without trailing Z / timezone
        cleaned = value.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(cleaned)
        except (ValueError, TypeError):
            pass
    return None


def _severity_label(score: int) -> str:
    """Map a numeric score (0-100) to a severity label."""
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _score_story(
    tactics: list[str],
    severity_breakdown: dict[str, int],
) -> int:
    """Compute a 0-100 severity score for an attack story.

    Scoring rules:
    - Each unique kill-chain tactic contributes +8 points (max 13 * 8 = 104,
      capped at 100).
    - Each critical-severity alert adds +15.
    - Each high-severity alert adds +8.
    - Each medium-severity alert adds +3.
    - Final score is capped at 100.
    """
    score = len(tactics) * 8
    score += severity_breakdown.get("critical", 0) * 15
    score += severity_breakdown.get("high", 0) * 8
    score += severity_breakdown.get("medium", 0) * 3
    return min(score, 100)


def _build_narrative(
    entity: str,
    tactics: list[str],
    first_ts: datetime,
    last_ts: datetime,
    span_hours: float,
    unique_rule_count: int,
) -> str:
    """Generate a template-based narrative summary for an attack story."""
    stage_count = len(tactics)
    first_tactic = tactics[0] if tactics else "unknown"
    last_tactic = tactics[-1] if tactics else "unknown"
    first_time = first_ts.strftime("%Y-%m-%d %H:%M UTC")
    last_time = last_ts.strftime("%Y-%m-%d %H:%M UTC")

    if stage_count <= 1:
        return (
            f"Entity {entity} triggered alerts in the {first_tactic} phase "
            f"at {first_time}. {unique_rule_count} unique detection "
            f"rule{'s' if unique_rule_count != 1 else ''} fired."
        )

    middle = ", ".join(tactics[1:-1]) if stage_count > 2 else None
    progression = (
        f"progressing through {middle}, reaching"
        if middle
        else "reaching"
    )

    return (
        f"Entity {entity} was targeted across {stage_count} stages of the "
        f"kill chain over {span_hours:.1f} hours. Starting with "
        f"{first_tactic} at {first_time}, {progression} {last_tactic} at "
        f"{last_time}. {unique_rule_count} unique detection "
        f"rule{'s' if unique_rule_count != 1 else ''} fired."
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_attack_stories(
    alerts: list[dict],
    min_alerts: int = 2,
    time_window_hours: int = 24,
) -> dict[str, Any]:
    """Correlate a flat list of alerts into attack stories per entity.

    Args:
        alerts: Alert dicts (from ``ElasticsearchAlert.to_dict()``).
        min_alerts: Minimum number of alerts for an entity to form a story.
        time_window_hours: Maximum span between first and last alert in a
            story.  Stories wider than this are still reported but the window
            is used only for documentation — no alerts are dropped.

    Returns:
        A dict containing ``total_alerts``, ``total_stories``, a list of
        ``stories`` sorted by score descending, and the canonical
        ``kill_chain_order``.
    """

    # 1. Group alerts by entity (host and/or user).
    entity_buckets: dict[tuple[str, str], list[dict]] = defaultdict(list)

    for alert in alerts:
        host = alert.get("host")
        user = alert.get("user")
        if host:
            entity_buckets[("host", host)].append(alert)
        if user:
            entity_buckets[("user", user)].append(alert)
        # Alerts with neither host nor user are silently skipped.

    # 2. Build stories for qualifying entities.
    stories: list[dict[str, Any]] = []

    for (entity_type, entity_value), bucket in entity_buckets.items():
        if len(bucket) < min_alerts:
            continue

        # Sort by timestamp.
        parsed: list[tuple[datetime, dict]] = []
        for a in bucket:
            ts = _parse_timestamp(a.get("timestamp"))
            if ts is None:
                continue
            parsed.append((ts, a))

        if len(parsed) < min_alerts:
            continue

        parsed.sort(key=lambda x: x[0])
        sorted_alerts = [a for _, a in parsed]
        timestamps = [ts for ts, _ in parsed]

        first_ts = timestamps[0]
        last_ts = timestamps[-1]
        span_seconds = (last_ts - first_ts).total_seconds()
        span_hours = span_seconds / 3600.0

        # Collect unique rules, techniques, tactics.
        unique_rules: list[str] = []
        unique_techniques: list[str] = []
        seen_rules: set[str] = set()
        seen_techniques: set[str] = set()
        tactic_set: set[str] = set()
        severity_breakdown: dict[str, int] = defaultdict(int)

        for a in sorted_alerts:
            rule = a.get("rule_name")
            if rule and rule not in seen_rules:
                seen_rules.add(rule)
                unique_rules.append(rule)

            technique = a.get("mitre_technique_name") or a.get("mitre_technique_id")
            if technique and technique not in seen_techniques:
                seen_techniques.add(technique)
                unique_techniques.append(technique)

            tactic = _normalise_tactic(a.get("mitre_tactic_name"))
            if tactic and tactic in _TACTIC_INDEX:
                tactic_set.add(tactic)

            sev = (a.get("severity") or "").lower()
            if sev:
                severity_breakdown[sev] += 1

        # Order tactics by kill-chain phase.
        tactics_progression = sorted(tactic_set, key=lambda t: _TACTIC_INDEX[t])

        # Score.
        score = _score_story(tactics_progression, dict(severity_breakdown))
        severity_label = _severity_label(score)

        # Narrative.
        narrative = _build_narrative(
            entity=entity_value,
            tactics=tactics_progression,
            first_ts=first_ts,
            last_ts=last_ts,
            span_hours=span_hours,
            unique_rule_count=len(unique_rules),
        )

        stories.append({
            "entity": entity_value,
            "entity_type": entity_type,
            "score": score,
            "severity": severity_label,
            "alert_count": len(sorted_alerts),
            "unique_rules": unique_rules,
            "unique_techniques": unique_techniques,
            "tactics_progression": tactics_progression,
            "time_span_hours": round(span_hours, 2),
            "first_seen": first_ts.isoformat(),
            "last_seen": last_ts.isoformat(),
            "severity_breakdown": dict(severity_breakdown),
            "narrative": narrative,
            "alerts": sorted_alerts,
        })

    # 3. Sort stories by score descending.
    stories.sort(key=lambda s: s["score"], reverse=True)

    return {
        "total_alerts": len(alerts),
        "total_stories": len(stories),
        "stories": stories,
        "kill_chain_order": list(KILL_CHAIN_ORDER),
    }
