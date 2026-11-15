"""Generate src/ion/data/attack_detections.json from the ATT&CK STIX bundle.

Usage (from repo root):
    python scripts/generate_attack_detections_json.py
    python scripts/generate_attack_detections_json.py --bundle path/to/enterprise-attack-20.1.json

ATT&CK v18 replaced the free-text `x_mitre_detection` field on techniques with
two STIX objects: `x-mitre-detection-strategy` (DET####) and `x-mitre-analytic`
(AN####). No live technique carries `x_mitre_detection` any more, so a snapshot
built from techniques alone has no detection guidance in it at all.

Strategies attach to techniques through `detects` relationships; analytics
attach to strategies through the embedded `x_mitre_analytic_refs`, not through
relationship objects.

Fetches from MITRE's GitHub, same as the technique snapshot. ION is air-gapped
so runtime code never fetches STIX -- only this dev-time script does. Commit
the output. Re-run at every ION minor-version bump, alongside the technique and
KEV snapshots. `--bundle` reads a previously downloaded file instead, which is
how you refresh on a host with no route to GitHub.
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

#: Pinned, not `master`: a snapshot that silently changes shape under a rebuild
#: is worse than one that is a known version behind.
ATTACK_VERSION = "20.1"

_STIX_URL = (
    "https://github.com/mitre-attack/attack-stix-data/raw/master/"
    f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)
_OUT_PATH = (
    Path(__file__).parent.parent / "src" / "ion" / "data" / "attack_detections.json"
)


def _load_bundle(url: str) -> Dict[str, Any]:
    print(f"Fetching {url} ...", flush=True)
    with urllib.request.urlopen(url, timeout=300) as resp:  # nosec B310
        return json.loads(resp.read())


def _external_id(obj: Dict[str, Any]) -> Optional[str]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _is_live(obj: Dict[str, Any]) -> bool:
    return not (obj.get("revoked") or obj.get("x_mitre_deprecated"))


def extract(bundle: Dict[str, Any]) -> Dict[str, Any]:
    objects: List[Dict[str, Any]] = bundle.get("objects", [])
    by_stix_id = {o.get("id"): o for o in objects}

    # DC#### -> name, so an analytic's log sources can be reported without
    # carrying the data component's own multi-KB description into the snapshot.
    data_components: Dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-data-component" and _is_live(obj):
            dc_id = _external_id(obj)
            if dc_id:
                data_components[dc_id] = obj.get("name", dc_id)

    # A strategy names the technique it detects only through a `detects`
    # relationship, so the edges have to be walked before the strategies.
    strategy_to_techniques: Dict[str, List[str]] = {}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "detects":
            continue
        if not _is_live(obj):
            continue
        target = by_stix_id.get(obj.get("target_ref"))
        if not target or target.get("type") != "attack-pattern":
            continue
        tid = _external_id(target)
        if tid:
            strategy_to_techniques.setdefault(obj.get("source_ref"), []).append(tid)

    strategies: List[Dict[str, Any]] = []
    analytic_total = 0

    for obj in objects:
        if obj.get("type") != "x-mitre-detection-strategy" or not _is_live(obj):
            continue
        det_id = _external_id(obj)
        if not det_id:
            continue

        analytics: List[Dict[str, Any]] = []
        for ref in obj.get("x_mitre_analytic_refs", []):
            analytic = by_stix_id.get(ref)
            if not analytic or not _is_live(analytic):
                continue
            an_id = _external_id(analytic)
            if not an_id:
                continue

            log_sources = []
            for ls in analytic.get("x_mitre_log_source_references") or []:
                dc_obj = by_stix_id.get(ls.get("x_mitre_data_component_ref"))
                log_sources.append(
                    {
                        "data_component": _external_id(dc_obj) if dc_obj else None,
                        "name": ls.get("name"),
                        "channel": ls.get("channel"),
                    }
                )

            analytics.append(
                {
                    "id": an_id,
                    "name": analytic.get("name", an_id),
                    "platforms": sorted(analytic.get("x_mitre_platforms") or []),
                    "description": analytic.get("description", ""),
                    "log_sources": log_sources,
                    # MITRE's own name for the knobs an engineer is expected to
                    # tune per environment. Carries the tuning conversation that
                    # the old free-text detection field never had.
                    "tunables": [
                        {
                            "field": el.get("field"),
                            "description": el.get("description", ""),
                        }
                        for el in analytic.get("x_mitre_mutable_elements") or []
                    ],
                }
            )
            analytic_total += 1

        strategies.append(
            {
                "id": det_id,
                "name": obj.get("name", det_id),
                "technique_ids": sorted(set(strategy_to_techniques.get(obj["id"], []))),
                "analytics": sorted(analytics, key=lambda a: a["id"]),
            }
        )

    strategies.sort(key=lambda s: s["id"])

    by_technique: Dict[str, List[str]] = {}
    for strategy in strategies:
        for tid in strategy["technique_ids"]:
            by_technique.setdefault(tid, []).append(strategy["id"])
    for tid in by_technique:
        by_technique[tid].sort()

    return {
        "attack_version": ATTACK_VERSION,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": {
            "strategies": len(strategies),
            "analytics": analytic_total,
            "techniques_with_detection": len(by_technique),
            "data_components": len(data_components),
        },
        "data_components": dict(sorted(data_components.items())),
        "by_technique": dict(sorted(by_technique.items())),
        "strategies": strategies,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bundle",
        type=Path,
        default=None,
        help="Read a local STIX bundle instead of fetching from GitHub.",
    )
    args = parser.parse_args()

    if args.bundle:
        print(f"Reading {args.bundle} ...", flush=True)
        bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
    else:
        bundle = _load_bundle(_STIX_URL)

    snapshot = extract(bundle)
    if not snapshot["strategies"]:
        raise SystemExit(
            "Refusing to write an empty snapshot: the bundle produced no "
            "detection strategies. Check the bundle is v18 or later."
        )

    _OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _OUT_PATH.write_text(json.dumps(snapshot, indent=1) + "\n", encoding="utf-8")
    counts = snapshot["counts"]
    size_mb = _OUT_PATH.stat().st_size / 1024 / 1024
    print(
        f"Wrote ATT&CK v{ATTACK_VERSION}: {counts['strategies']} strategies, "
        f"{counts['analytics']} analytics, covering "
        f"{counts['techniques_with_detection']} techniques "
        f"({size_mb:.1f} MB) to {_OUT_PATH}"
    )


if __name__ == "__main__":
    main()
