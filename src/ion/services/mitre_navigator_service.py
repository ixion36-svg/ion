"""Generate MITRE ATT&CK Navigator layer JSON from TIDE coverage data."""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


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
