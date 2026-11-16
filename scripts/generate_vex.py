"""Generate ION's VEX documents from security/vex_statements.yaml.

Usage (from repo root):
    python scripts/generate_vex.py
    python scripts/generate_vex.py --check    # fail if the outputs are stale

Writes two documents, both shipped in the image beside sbom.spdx.json:

    security/ion.openvex.json   OpenVEX 0.2.0
    security/ion.csaf.json      CSAF 2.0, csaf_vex profile

syft already lists every package ION installs. A scanner reading that SBOM
flags advisories against those packages and cannot tell a reachable one from a
pinned-and-patched one. These documents say which is which, in the two formats
that get asked for.

The generator validates before it writes, because a VEX document is an
assertion about a product's security: a malformed or unjustified statement is
worse than no statement, and an advisory nobody has ruled on should be absent
rather than defaulted to anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import yaml

_ROOT = Path(__file__).parent.parent
_SOURCE = _ROOT / "security" / "vex_statements.yaml"
_OPENVEX_OUT = _ROOT / "security" / "ion.openvex.json"
_CSAF_OUT = _ROOT / "security" / "ion.csaf.json"
_PYPROJECT = _ROOT / "pyproject.toml"

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

#: The four statuses OpenVEX allows. CSAF names the same four differently,
#: which _CSAF_STATUS maps.
STATUSES = ("not_affected", "affected", "fixed", "under_investigation")

#: The five justifications OpenVEX allows for not_affected. A sixth value
#: invented locally would be dropped by any conforming consumer, leaving a
#: not_affected claim with no stated reason.
JUSTIFICATIONS = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)

_CSAF_STATUS = {
    "not_affected": "known_not_affected",
    "affected": "known_affected",
    "fixed": "fixed",
    "under_investigation": "under_investigation",
}

#: CSAF spells the justifications in prose. Mapping is explicit rather than
#: derived from the key, so a new OpenVEX justification fails loudly here
#: instead of emitting a CSAF flag label that is not in the vocabulary.
_CSAF_FLAG_LABEL = {
    "component_not_present": "component_not_present",
    "vulnerable_code_not_present": "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path": "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary":
        "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist": "inline_mitigations_already_exist",
}

_PRODUCT_ID = "ION"


def _ion_version() -> str:
    text = _PYPROJECT.read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        raise SystemExit("Could not read version from pyproject.toml")
    return m.group(1)


def _load_source() -> Dict[str, Any]:
    return yaml.safe_load(_SOURCE.read_text(encoding="utf-8"))


def validate(source: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check every statement against the OpenVEX rules. Raises on the first
    problem, naming the vulnerability, because a half-written document is not
    something to ship a warning about."""
    statements = source.get("statements") or []
    if not statements:
        raise SystemExit("No statements in the source file.")

    seen = set()
    for s in statements:
        vuln = s.get("vulnerability")
        if not vuln:
            raise SystemExit(f"A statement has no vulnerability id: {s!r}")
        if vuln in seen:
            raise SystemExit(
                f"{vuln} appears twice. Two statuses for one advisory is a "
                f"contradiction, not an update."
            )
        seen.add(vuln)

        status = s.get("status")
        if status not in STATUSES:
            raise SystemExit(f"{vuln}: status {status!r} is not one of {STATUSES}")

        if status == "not_affected":
            just = s.get("justification")
            if just not in JUSTIFICATIONS:
                raise SystemExit(
                    f"{vuln}: not_affected needs a justification from "
                    f"{JUSTIFICATIONS}, got {just!r}. An unjustified "
                    f"not_affected is an unsupported security claim."
                )
        elif s.get("justification"):
            raise SystemExit(
                f"{vuln}: justification is only meaningful for not_affected, "
                f"but status is {status!r}."
            )

        if status == "affected" and not s.get("action_statement"):
            raise SystemExit(
                f"{vuln}: affected needs an action_statement saying what a "
                f"deployer should do."
            )

    return statements


def build_openvex(source: Dict[str, Any], version: str,
                  timestamp: str) -> Dict[str, Any]:
    product = source["product"]
    purl = product["purl_template"].format(version=version)

    statements = []
    for s in validate(source):
        out: Dict[str, Any] = {
            "vulnerability": {"name": s["vulnerability"]},
            "products": [{"@id": purl}],
            "status": s["status"],
        }
        if s.get("justification"):
            out["justification"] = s["justification"]
        if s.get("impact_statement"):
            out["impact_statement"] = " ".join(s["impact_statement"].split())
        if s.get("action_statement"):
            out["action_statement"] = " ".join(s["action_statement"].split())
        statements.append(out)

    # Deterministic @id: the document identifies its own content, so
    # regenerating without a change produces a byte-identical file and --check
    # means something.
    digest = hashlib.sha256(
        json.dumps(statements, sort_keys=True).encode()
    ).hexdigest()[:16]

    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"https://ixion36.dev/vex/ion/{version}/{digest}",
        "author": source["author"],
        "role": source.get("author_role", "vendor"),
        "timestamp": timestamp,
        "version": 1,
        "statements": statements,
    }


def build_csaf(source: Dict[str, Any], version: str,
               timestamp: str) -> Dict[str, Any]:
    product = source["product"]
    purl = product["purl_template"].format(version=version)
    cpe = product["cpe_template"].format(version=version)
    full_name = f"{product['name']} {version}"

    vulnerabilities = []
    for s in validate(source):
        csaf_status = _CSAF_STATUS[s["status"]]
        entry: Dict[str, Any] = {
            "cve" if s["vulnerability"].startswith("CVE-") else "title":
                s["vulnerability"],
            "product_status": {csaf_status: [_PRODUCT_ID]},
        }
        # A non-CVE id (PYSEC-, MAL-) cannot go in /cve, which the schema
        # constrains to the CVE pattern. It becomes an id entry instead.
        if not s["vulnerability"].startswith("CVE-"):
            entry["ids"] = [{
                "system_name": "OSV", "text": s["vulnerability"],
            }]
        if s.get("impact_statement"):
            entry["notes"] = [{
                "category": "other",
                "title": "Impact statement",
                "text": " ".join(s["impact_statement"].split()),
            }]
        if s.get("justification"):
            entry["flags"] = [{
                "label": _CSAF_FLAG_LABEL[s["justification"]],
                "product_ids": [_PRODUCT_ID],
            }]
        if s.get("action_statement"):
            entry["remediations"] = [{
                "category": "mitigation",
                "details": " ".join(s["action_statement"].split()),
                "product_ids": [_PRODUCT_ID],
            }]
        vulnerabilities.append(entry)

    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": f"ION {version} — VEX",
            "publisher": {
                "category": "vendor",
                "name": source["author"],
                "namespace": "https://ixion36.dev",
            },
            "tracking": {
                "id": f"ION-VEX-{version}",
                "initial_release_date": timestamp,
                "current_release_date": timestamp,
                "status": "final",
                "version": "1",
                "revision_history": [{
                    "date": timestamp,
                    "number": "1",
                    "summary": "Generated from security/vex_statements.yaml",
                }],
            },
        },
        "product_tree": {
            "full_product_names": [{
                "product_id": _PRODUCT_ID,
                "name": full_name,
                "product_identification_helper": {"cpe": cpe, "purls": [purl]},
            }],
        },
        "vulnerabilities": vulnerabilities,
    }


def _write(path: Path, doc: Dict[str, Any], check: bool) -> bool:
    text = json.dumps(doc, indent=2) + "\n"
    if check:
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        if current != text:
            print(f"STALE: {path.relative_to(_ROOT)}", file=sys.stderr)
            return False
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    print(f"Wrote {path.relative_to(_ROOT)}")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="Exit non-zero if the committed documents are stale.")
    args = parser.parse_args()

    source = _load_source()
    version = _ion_version()
    # --check regenerates with the committed timestamp so a rerun on a later
    # day does not report a stale document when nothing was edited.
    if args.check and _OPENVEX_OUT.exists():
        timestamp = json.loads(
            _OPENVEX_OUT.read_text(encoding="utf-8")
        ).get("timestamp")
    else:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    ok = _write(_OPENVEX_OUT, build_openvex(source, version, timestamp), args.check)
    ok = _write(_CSAF_OUT, build_csaf(source, version, timestamp), args.check) and ok

    if args.check and not ok:
        raise SystemExit(
            "VEX documents are out of date — run scripts/generate_vex.py"
        )
    if not args.check:
        n = len(source["statements"])
        print(f"{n} statements for ION {version}")


if __name__ == "__main__":
    main()
