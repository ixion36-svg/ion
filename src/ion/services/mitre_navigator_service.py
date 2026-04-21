"""Generate MITRE ATT&CK Navigator layer JSON from TIDE coverage data."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Iterable, List, Optional

logger = logging.getLogger(__name__)


_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

_SCAN_FIELDS = (
    "rule.id",
    "rule.name",
    "rule.description",
    "rule.groups",
    "rule.tags",
    "tags",
    "kibana.alert.rule.rule_id",
    "kibana.alert.rule.name",
    "kibana.alert.rule.description",
    "kibana.alert.rule.tags",
    "signal.rule.threat",
    "threat.technique.id",
    "threat.technique.name",
    "threat.tactic.id",
    "threat.tactic.name",
    "event.category",
    "message",
)


def _walk(obj: Any) -> Iterable[str]:
    """Yield every string value contained in a nested dict/list structure."""
    if obj is None:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)


def _lookup_dotted(obj: Any, path: str) -> Any:
    """Return the value at dotted path, or None. Handles flattened keys too
    (e.g. if the event has `kibana.alert.rule.name` as a literal string key)."""
    if not isinstance(obj, dict):
        return None
    if path in obj:
        return obj[path]
    current: Any = obj
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def tag_alert(alert: dict) -> List[str]:
    """Extract MITRE ATT&CK technique IDs referenced by an alert.

    Scans a curated set of rule/threat/category fields for strings matching
    the `T\\d{4}(\\.\\d{3})?` pattern. Deduped and sorted. Returns `[]` for
    alerts with no recognisable technique references.

    This is the canonical entry point used by the autonomous investigation
    loop to tag alerts without requiring the Detection Engine to have done
    the mapping upstream.
    """
    if not alert or not isinstance(alert, dict):
        return []
    collected: set[str] = set()
    for path in _SCAN_FIELDS:
        val = _lookup_dotted(alert, path)
        if val is None:
            continue
        for s in _walk(val):
            for match in _TECHNIQUE_ID_RE.findall(s):
                collected.add(match.upper())
    return sorted(collected)


def _coverage_color(rule_count: int) -> str:
    """Return Navigator hex color based on rule count."""
    if rule_count == 0:
        return "#f85149"   # red – no coverage
    if rule_count <= 3:
        return "#d29922"   # amber – partial
    return "#3fb950"       # green – good coverage


def generate_navigator_layer(
    tide_service: Any,
    layer_name: str = "ION Detection Coverage",
) -> dict:
    """Build an ATT&CK Navigator v4.x layer from TIDE global MITRE coverage.

    Args:
        tide_service: An initialised ``TideService`` instance whose
            ``get_global_mitre_coverage()`` method returns per-technique
            rule statistics.
        layer_name: Human-readable name for the generated layer.

    Returns:
        A dict conforming to the ATT&CK Navigator layer schema (v4.5).
        On failure an empty layer with zero techniques is returned.
    """

    # -- Fetch coverage data from TIDE -----------------------------------------
    try:
        coverage: Optional[dict] = tide_service.get_global_mitre_coverage()
    except Exception:
        logger.exception("Failed to retrieve MITRE coverage from TIDE")
        coverage = None

    techniques_map: dict = coverage.get("techniques", {}) if coverage else {}
    total_techniques: int = coverage.get("total_techniques", 0) if coverage else 0
    covered_techniques: int = coverage.get("covered_techniques", 0) if coverage else 0

    # -- Build per-technique entries -------------------------------------------
    nav_techniques: list[dict] = []

    for tid, info in techniques_map.items():
        rule_count: int = info.get("rule_count", 0)
        avg_quality: float = info.get("avg_quality", 0)
        enabled_rules: int = info.get("enabled_rules", 0)

        nav_techniques.append({
            "techniqueID": tid,
            "tactic": "",
            "color": _coverage_color(rule_count),
            "comment": f"{rule_count} rules, avg quality: {avg_quality}",
            "enabled": True,
            "score": rule_count,
            "metadata": [
                {"name": "Rules", "value": str(rule_count)},
                {"name": "Enabled", "value": str(enabled_rules)},
                {"name": "Quality", "value": str(avg_quality)},
            ],
        })

    # -- Assemble full layer ---------------------------------------------------
    layer: dict = {
        "name": layer_name,
        "versions": {
            "attack": "14",
            "navigator": "4.9.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            f"Auto-generated from ION/TIDE. "
            f"{covered_techniques}/{total_techniques} techniques covered."
        ),
        "filters": {
            "platforms": ["Windows", "Linux", "macOS"],
        },
        "sorting": 3,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
        },
        "hideDisabled": False,
        "techniques": nav_techniques,
        "gradient": {
            "colors": ["#f85149", "#d29922", "#3fb950"],
            "minValue": 0,
            "maxValue": 10,
        },
        "legendItems": [
            {"label": "No Coverage", "color": "#f85149"},
            {"label": "Partial (1-3 rules)", "color": "#d29922"},
            {"label": "Good Coverage (4+)", "color": "#3fb950"},
        ],
    }

    return layer
