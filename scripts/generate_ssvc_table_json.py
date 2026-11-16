"""Generate src/ion/data/ssvc_deployer_table.json from CERT/CC's published table.

Usage (from repo root):
    python scripts/generate_ssvc_table_json.py
    python scripts/generate_ssvc_table_json.py --csv path/to/table.csv

SSVC answers "when do we have to patch this", which CVSS does not: CVSS scores
severity, EPSS estimates exploitation likelihood, KEV confirms exploitation,
and none of the three produces a decision. The deployer tree takes four inputs
and yields one of defer / scheduled / out-of-cycle / immediate.

The table is transcribed, never computed. 72 rows of somebody else's published
decision are the kind of thing that looks easy to reproduce from memory and is
wrong in a way nobody notices, so it is generated from CERT/CC's own CSV and
the source and version are recorded in the output.

Fetched at dev time only. ION is air-gapped and runtime code never fetches.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

#: Pinned. A table that changes shape under a rebuild is worse than one a
#: version behind, and the decision it encodes is auditable only if it names
#: the revision it came from.
TABLE_VERSION = "1.0.0"
_SOURCE_URL = (
    "https://raw.githubusercontent.com/CERTCC/SSVC/main/data/csv/ssvc/"
    f"deployer_patch_application_priority_{TABLE_VERSION.replace('.', '_')}.csv"
)
_OUT_PATH = (
    Path(__file__).parent.parent / "src" / "ion" / "data" / "ssvc_deployer_table.json"
)

#: The CSV's column headings carry their own decision-point versions, which
#: change independently of the table's. Matched by prefix so a point-version
#: bump does not silently drop a column and leave a table of 72 empty keys.
_COLUMNS = {
    "exploitation": "Exploitation",
    "exposure": "System Exposure",
    "automatable": "Automatable",
    "human_impact": "Human Impact",
}
_OUTCOME_PREFIX = "Defer, Scheduled, Out-of-Cycle, Immediate"

_EXPECTED_ROWS = 72


def _resolve(headings: List[str], prefix: str) -> str:
    for h in headings:
        if h.startswith(prefix):
            return h
    raise SystemExit(f"No column starting {prefix!r} in {headings}")


def extract(text: str) -> Dict[str, Any]:
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows:
        raise SystemExit("Refusing to write an empty SSVC table.")

    headings = [h for h in rows[0] if h and h != "row"]
    cols = {k: _resolve(headings, p) for k, p in _COLUMNS.items()}
    outcome_col = _resolve(headings, _OUTCOME_PREFIX)

    table: Dict[str, str] = {}
    values: Dict[str, set] = {k: set() for k in cols}
    for row in rows:
        key = "|".join(row[cols[k]].strip().lower() for k in
                       ("exploitation", "exposure", "automatable", "human_impact"))
        outcome = row[outcome_col].strip().lower()
        if key in table and table[key] != outcome:
            raise SystemExit(f"Contradictory rows for {key!r}")
        table[key] = outcome
        for k, col in cols.items():
            values[k].add(row[col].strip().lower())

    # A tree with a hole in it decides nothing for the combination that falls
    # in the hole, and the caller cannot tell that from a decision.
    expected = 1
    for k in ("exploitation", "exposure", "automatable", "human_impact"):
        expected *= len(values[k])
    if len(table) != expected:
        raise SystemExit(
            f"Table is not complete: {len(table)} rows for {expected} "
            f"combinations of {[sorted(values[k]) for k in values]}"
        )
    if len(table) != _EXPECTED_ROWS:
        raise SystemExit(
            f"Expected {_EXPECTED_ROWS} rows, got {len(table)}. The published "
            f"tree changed shape; check the source before bumping."
        )

    return {
        "table_version": TABLE_VERSION,
        "source": _SOURCE_URL,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "decision_points": {k: sorted(v) for k, v in values.items()},
        "outcomes": sorted(set(table.values())),
        "rows": len(table),
        "table": dict(sorted(table.items())),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=None,
                        help="Read a local CSV instead of fetching.")
    args = parser.parse_args()

    if args.csv:
        print(f"Reading {args.csv} ...", flush=True)
        text = args.csv.read_text(encoding="utf-8")
    else:
        print(f"Fetching {_SOURCE_URL} ...", flush=True)
        with urllib.request.urlopen(_SOURCE_URL, timeout=120) as resp:  # nosec B310
            text = resp.read().decode("utf-8")

    snapshot = extract(text)
    _OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _OUT_PATH.write_text(json.dumps(snapshot, indent=1) + "\n", encoding="utf-8")
    print(
        f"Wrote SSVC deployer table v{TABLE_VERSION}: {snapshot['rows']} rows, "
        f"outcomes {snapshot['outcomes']} to {_OUT_PATH}"
    )


if __name__ == "__main__":
    main()
