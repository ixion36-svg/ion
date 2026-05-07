"""Generate src/ion/data/attack_techniques.json from ATT&CK Enterprise v15.1.

Usage (run once from repo root):
    python scripts/generate_attack_techniques_json.py

Fetches the STIX bundle from MITRE's GitHub, extracts technique metadata,
and writes the bundled snapshot. Commit the output; ION is air-gapped so
runtime code never fetches STIX — only this dev-time script does.

Refresh cadence: re-run at every ION minor-version bump (same ritual as
the KEV snapshot refresh).
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

_STIX_URL = (
    "https://github.com/mitre-attack/attack-stix-data/raw/master/"
    "enterprise-attack/enterprise-attack-15.1.json"
)
_OUT_PATH = Path(__file__).parent.parent / "src" / "ion" / "data" / "attack_techniques.json"


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


def main() -> None:
    bundle = _load_bundle(_STIX_URL)
    techniques = extract(bundle)
    _OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _OUT_PATH.write_text(json.dumps(techniques, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(techniques)} techniques to {_OUT_PATH}")


if __name__ == "__main__":
    main()
