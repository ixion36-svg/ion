"""Write the navigation baseline that tests/test_nav_parity.py compares against.

A CLI over `tests.nav_render.snapshot()`. The logic lives there because the
test is what depends on it; this script only regenerates the fixture, and
only when a nav change is deliberate.

    python tools/nav_snapshot.py --write tests/fixtures/nav_baseline.json

Run with no arguments to print the snapshot without touching the fixture.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.nav_render import snapshot  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", type=Path, help="write the baseline to this path")
    args = ap.parse_args()

    snap = snapshot()
    text = json.dumps(snap, indent=2, sort_keys=True) + "\n"

    if not args.write:
        sys.stdout.write(text)
        return 0

    args.write.parent.mkdir(parents=True, exist_ok=True)
    args.write.write_text(text, encoding="utf-8")

    tl = snap["structure"]["top_level"]
    groups = [i for i in tl if i["kind"] == "group"]
    print(f"wrote {args.write}")
    print(f"  top-level items : {len(tl)} ({len(groups)} groups)")
    print(f"  group items     : {sum(len(g['items']) for g in groups)}")
    print(f"  mobile entries  : {len(snap['structure']['mobile'])}")
    print(f"  g-key routes    : {len(snap['structure']['gkeys'])}")
    print(f"  paths pinned    : {len(snap['active_by_path'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
