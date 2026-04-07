"""Detect recurring alert patterns from historical alert data."""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    """Best-effort ISO timestamp parse."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        # Handle both 'Z' suffix and '+00:00' offset
        cleaned = value.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except (ValueError, TypeError):
        return None


def _classify_pattern(
    timestamps: list[datetime],
    avg_interval_hours: float,
) -> str:
    """Classify a group of alerts into a pattern type.

    - persistent: regular intervals < 4 h
    - periodic:   regular intervals 4-48 h
    - burst:      >5 alerts within any 1-hour window
    - sporadic:   everything else
    """

    # Check for burst: any 1-hour window with >5 alerts
    sorted_ts = sorted(timestamps)
    for i, t in enumerate(sorted_ts):
        count_in_window = 0
        for j in range(i, len(sorted_ts)):
            if (sorted_ts[j] - t).total_seconds() <= 3600:
                count_in_window += 1
            else:
                break
        if count_in_window > 5:
            return "burst"

    if avg_interval_hours < 4:
        return "persistent"
    if avg_interval_hours <= 48:
        return "periodic"
    return "sporadic"


def detect_alert_patterns(
    alerts: list[dict],
    min_occurrences: int = 3,
) -> dict:
    """Group alerts by (rule_name, host) and identify recurring patterns.

    Args:
        alerts: List of alert dicts with at least ``rule_name``,
            ``host``, ``severity``, and ``timestamp`` keys.
        min_occurrences: Minimum alerts in a group to qualify as a
            pattern.

    Returns:
        A dict with detected patterns, sorted by count descending.
    """

    # -- Group alerts by (rule_name, host) -------------------------------------
    groups: dict[tuple[str, Optional[str]], list[dict]] = {}
    for a in alerts:
        rule_name = a.get("rule_name")
        if not rule_name:
            continue
        key = (rule_name, a.get("host"))
        groups.setdefault(key, []).append(a)

    patterns: list[dict] = []
    persistent_count = 0
    burst_count = 0

    for (rule_name, host), group in groups.items():
        if len(group) < min_occurrences:
            continue

        # Parse timestamps
        timestamps = [
            ts
            for a in group
            if (ts := _parse_ts(a.get("timestamp"))) is not None
        ]
        timestamps.sort()

        # Average interval
        intervals: list[float] = []
        for i in range(1, len(timestamps)):
            delta_h = (timestamps[i] - timestamps[i - 1]).total_seconds() / 3600.0
            intervals.append(delta_h)
        avg_interval = round(sum(intervals) / len(intervals), 2) if intervals else 0.0

        # Time-of-day clustering (dominant hour)
        hour_counter: Counter[int] = Counter()
        for ts in timestamps:
            hour_counter[ts.hour] += 1
        peak_hour: Optional[int] = (
            hour_counter.most_common(1)[0][0] if hour_counter else None
        )

        # Classify
        pattern_type = _classify_pattern(timestamps, avg_interval) if timestamps else "sporadic"

        # Most common severity
        sev_counter: Counter[str] = Counter()
        for a in group:
            sev = a.get("severity")
            if sev:
                sev_counter[sev] += 1
        most_common_sev = sev_counter.most_common(1)[0][0] if sev_counter else "unknown"

        patterns.append({
            "rule_name": rule_name,
            "host": host,
            "count": len(group),
            "avg_interval_hours": avg_interval,
            "pattern_type": pattern_type,
            "peak_hour": peak_hour,
            "first_seen": timestamps[0].isoformat() if timestamps else "",
            "last_seen": timestamps[-1].isoformat() if timestamps else "",
            "severity": most_common_sev,
        })

        if pattern_type == "persistent":
            persistent_count += 1
        elif pattern_type == "burst":
            burst_count += 1

    # Sort by count descending
    patterns.sort(key=lambda p: p["count"], reverse=True)

    return {
        "total_patterns": len(patterns),
        "patterns": patterns,
        "persistent_count": persistent_count,
        "burst_count": burst_count,
    }
