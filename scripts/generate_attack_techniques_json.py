"""Generate src/ion/data/attack_techniques.json from ATT&CK Enterprise.

Usage (run once from repo root):
    python scripts/generate_attack_techniques_json.py
    python scripts/generate_attack_techniques_json.py --bundle path/to/bundle.json

Fetches the STIX bundle from MITRE's GitHub, extracts technique metadata,
and writes the bundled snapshot. Commit the output; ION is air-gapped so
runtime code never fetches STIX — only this dev-time script does.

Refresh cadence: re-run at every ION minor-version bump (same ritual as
the KEV snapshot refresh).
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

#: Keep in step with ATTACK_VERSION in generate_attack_detections_json.py --
#: the two snapshots are read side by side, and a technique with no entry in
#: the detections snapshot is indistinguishable from one MITRE wrote no
#: detection for.
ATTACK_VERSION = "20.1"

_STIX_URL = (
    "https://github.com/mitre-attack/attack-stix-data/raw/master/"
    f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)
_OUT_PATH = Path(__file__).parent.parent / "src" / "ion" / "data" / "attack_techniques.json"
_REVOCATIONS_PATH = (
    Path(__file__).parent.parent / "src" / "ion" / "data" / "attack_revocations.json"
)


def _tactic_short_id(phase_name: str) -> str:
    """Convert kill-chain phase name to TA00XX id.

    ATT&CK STIX uses kill_chain_phases[].phase_name (kebab-case) rather than
    the TA-number IDs in the external_references. We derive the TA number from
    the external_references where source_name == 'mitre-attack' on the tactic
    object. For technique objects we only have phase_name; we resolve at
    post-processing time using the tactic name-to-id map.
    """
    return phase_name  # placeholder; replaced during resolution


def _load_bundle(url: str) -> Dict[str, Any]:
    print(f"Fetching {url} …", flush=True)
    with urllib.request.urlopen(url, timeout=120) as resp:  # nosec B310
        return json.loads(resp.read())


def _build_phase_to_tactic_id(objects: List[Dict[str, Any]]) -> Dict[str, str]:
    """Build {phase_name: tactic_id} from x-mitre-tactic objects."""
    mapping: Dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        phase = obj.get("x_mitre_shortname", "")
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tactic_id = ref.get("external_id", "")
                if phase and tactic_id:
                    mapping[phase] = tactic_id
    return mapping


def _extract_technique_id(obj: Dict[str, Any]) -> Optional[str]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _is_revoked_or_deprecated(obj: Dict[str, Any]) -> bool:
    return bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))


def extract(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    objects = bundle.get("objects", [])
    phase_to_tactic = _build_phase_to_tactic_id(objects)

    results: List[Dict[str, Any]] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if _is_revoked_or_deprecated(obj):
            continue

        tid = _extract_technique_id(obj)
        if not tid:
            continue

        name: str = obj.get("name", tid)
        phases = obj.get("kill_chain_phases") or []
        tactic_ids = [
            phase_to_tactic[p["phase_name"]]
            for p in phases
            if p.get("kill_chain_name") == "mitre-attack"
            and p.get("phase_name") in phase_to_tactic
        ]

        is_sub = "." in tid
        parent_id: Optional[str] = tid.rsplit(".", 1)[0] if is_sub else None

        results.append(
            {
                "id": tid,
                "name": name,
                "tactic_ids": sorted(set(tactic_ids)),
                "is_subtechnique": is_sub,
                "parent_id": parent_id,
            }
        )

    results.sort(key=lambda r: r["id"])
    return results


def extract_revocations(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Map every revoked technique id to the id that replaced it.

    A catalogue bump drops revoked ids, and ION keeps only catalogue-valid
    technique ids in several places. Without this map a rule, template or PCAP
    finding carrying a pre-bump id stops matching and nothing says so -- the
    mapping just disappears. T1562 and its whole sub-tree moved this way at
    v18/v19.
    """
    objects = bundle.get("objects", [])
    by_stix_id = {o.get("id"): o for o in objects}

    revocations: Dict[str, Dict[str, str]] = {}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "revoked-by":
            continue
        source = by_stix_id.get(obj.get("source_ref"))
        target = by_stix_id.get(obj.get("target_ref"))
        if not source or not target:
            continue
        if source.get("type") != "attack-pattern":
            continue
        old_id = _extract_technique_id(source)
        new_id = _extract_technique_id(target)
        if old_id and new_id and old_id != new_id:
            revocations[old_id] = {
                "replacement": new_id,
                "name": target.get("name", ""),
            }

    return {
        "attack_version": ATTACK_VERSION,
        "count": len(revocations),
        "revocations": dict(sorted(revocations.items())),
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
    techniques = extract(bundle)
    if not techniques:
        raise SystemExit("Refusing to write an empty technique snapshot.")
    _OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _OUT_PATH.write_text(json.dumps(techniques, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(techniques)} techniques to {_OUT_PATH}")

    revocations = extract_revocations(bundle)
    _REVOCATIONS_PATH.write_text(
        json.dumps(revocations, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote {revocations['count']} revocations to {_REVOCATIONS_PATH}")


if __name__ == "__main__":
    main()
