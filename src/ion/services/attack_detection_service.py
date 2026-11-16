"""ATT&CK Detection Strategies and Analytics, from the bundled snapshot.

ATT&CK v18 replaced the free-text `x_mitre_detection` field on each technique
with Detection Strategies (DET####), each holding one or more Analytics
(AN####). An analytic carries the platforms it applies to, the log sources it
reads, and the fields MITRE expects an engineer to tune per environment.

Read-only over `data/attack_detections.json`, which
`scripts/generate_attack_detections_json.py` writes. Nothing here fetches STIX:
ION is air-gapped and the snapshot ships in the image.

A missing or unreadable snapshot reports `loaded=False` rather than an empty
catalogue. "ION has no detection guidance for this technique" and "the file
never loaded" lead somewhere completely different, and a caller that cannot
tell them apart will render the second as the first.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SNAPSHOT_PATH = Path(__file__).resolve().parents[1] / "data" / "attack_detections.json"

_SNAPSHOT: Optional[Dict[str, Any]] = None
_LOAD_ERROR: Optional[str] = None


def _load() -> Dict[str, Any]:
    """Lazily load the snapshot. Returns {} when it could not be read."""
    global _SNAPSHOT, _LOAD_ERROR
    if _SNAPSHOT is None:
        try:
            with open(_SNAPSHOT_PATH, encoding="utf-8") as fh:
                _SNAPSHOT = json.load(fh)
            _LOAD_ERROR = None
        except Exception as exc:
            logger.warning("ATT&CK detection snapshot unreadable at %s: %s",
                           _SNAPSHOT_PATH, exc)
            _SNAPSHOT = {}
            _LOAD_ERROR = str(exc)
    return _SNAPSHOT


def reset_cache() -> None:
    """Drop the cached snapshot. For tests that point at a different file."""
    global _SNAPSHOT, _LOAD_ERROR
    _SNAPSHOT = None
    _LOAD_ERROR = None


def snapshot_status() -> Dict[str, Any]:
    """Whether the snapshot loaded, which ATT&CK version, and its counts."""
    snap = _load()
    return {
        "loaded": bool(snap),
        "attack_version": snap.get("attack_version"),
        "generated_utc": snap.get("generated_utc"),
        "counts": snap.get("counts", {}),
        "error": _LOAD_ERROR,
        "path": str(_SNAPSHOT_PATH),
    }


def attack_version() -> Optional[str]:
    """The ATT&CK version the snapshot was built from, or None if unloaded."""
    return _load().get("attack_version")


def _strategies_by_id() -> Dict[str, Dict[str, Any]]:
    return {s["id"]: s for s in _load().get("strategies", [])}


def strategies_for_technique(technique_id: str) -> List[Dict[str, Any]]:
    """Detection strategies for a technique id (e.g. ``T1070.005``).

    No parent fallback: a sub-technique carries its own strategy, and showing
    the parent's analytics against a sub-technique would claim detection
    coverage MITRE did not write for it.
    """
    if not technique_id:
        return []
    snap = _load()
    tid = technique_id.strip().upper()
    ids = snap.get("by_technique", {}).get(tid, [])
    by_id = _strategies_by_id()
    return [by_id[sid] for sid in ids if sid in by_id]


def analytics_for_technique(technique_id: str) -> List[Dict[str, Any]]:
    """Every analytic across the technique's strategies, strategy id attached."""
    out: List[Dict[str, Any]] = []
    for strategy in strategies_for_technique(technique_id):
        for analytic in strategy.get("analytics", []):
            out.append({**analytic,
                        "strategy_id": strategy["id"],
                        "strategy_name": strategy.get("name", "")})
    return out


def log_sources_for_technique(technique_id: str) -> List[Dict[str, Any]]:
    """Distinct log sources the technique's analytics read, with the analytics
    that need each one.

    This is the detection-engineering question the old free-text field could
    not answer: what must be collected before any of this is runnable.
    """
    seen: Dict[tuple, Dict[str, Any]] = {}
    for analytic in analytics_for_technique(technique_id):
        for ls in analytic.get("log_sources", []):
            key = (ls.get("name"), ls.get("channel"))
            entry = seen.setdefault(key, {
                "name": ls.get("name"),
                "channel": ls.get("channel"),
                "data_component": ls.get("data_component"),
                "data_component_name": data_component_name(ls.get("data_component")),
                "analytic_ids": [],
            })
            if analytic["id"] not in entry["analytic_ids"]:
                entry["analytic_ids"].append(analytic["id"])
    return sorted(seen.values(), key=lambda e: (e["name"] or "", e["channel"] or ""))


def data_component_name(data_component_id: Optional[str]) -> Optional[str]:
    """DC#### -> its ATT&CK name, or None when absent from the snapshot."""
    if not data_component_id:
        return None
    return _load().get("data_components", {}).get(data_component_id)


def covered_technique_ids() -> List[str]:
    """Technique ids the snapshot carries at least one strategy for."""
    return sorted(_load().get("by_technique", {}).keys())


def platform_breakdown() -> Dict[str, int]:
    """Analytic count per platform, most-covered first."""
    counts: Dict[str, int] = {}
    for strategy in _load().get("strategies", []):
        for analytic in strategy.get("analytics", []):
            for platform in analytic.get("platforms", []):
                counts[platform] = counts.get(platform, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def summary() -> Dict[str, Any]:
    """Headline numbers for a dashboard panel."""
    status = snapshot_status()
    if not status["loaded"]:
        return {**status, "platforms": {}, "analytics_per_strategy": None}
    strategies = _load().get("strategies", [])
    analytic_count = sum(len(s.get("analytics", [])) for s in strategies)
    return {
        **status,
        "platforms": platform_breakdown(),
        "analytics_per_strategy": (
            round(analytic_count / len(strategies), 1) if strategies else None
        ),
    }
