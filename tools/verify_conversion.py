"""Verify a hashed-class conversion against the lookup table, class by class.

The tranche verifier only asks coarse questions: are the mappable classes gone,
are the unmappable ones still here, did raw inline styles appear. It never
checks that what REPLACED a class is what the table said it should be. A pass
that deleted every hashed class and substituted nothing would sail through it.

This compares the committed version against the working tree and, for each
hashed class that disappeared, asserts the mapped utilities landed on the same
line. Pass 2 is specified to change nothing but class attributes, so line
alignment is a fair test; a page that restructured markup will report
misalignment rather than silently pass.

Usage:
    python tools/verify_conversion.py --pages a.html b.html
    python tools/verify_conversion.py --changed
    python tools/verify_conversion.py --changed --verbose
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TEMPLATES = REPO / "src/ion/web/templates"
MAP = REPO / "tools/hashed_class_map.json"

HASHED = re.compile(r"_ion-s-[a-z0-9]+")


def git_show(rel: str) -> str | None:
    r = subprocess.run(["git", "show", f"HEAD:{rel}"], capture_output=True,
                       text=True, cwd=REPO)
    return r.stdout if r.returncode == 0 else None


def changed_templates() -> list[str]:
    out = subprocess.run(["git", "status", "--porcelain", "src/ion/web/templates/"],
                         capture_output=True, text=True, cwd=REPO).stdout
    return [Path(l[3:].strip()).name for l in out.splitlines() if l.strip().endswith(".html")]


def verify(page: str, cmap: dict, verbose: bool) -> tuple[list[str], dict]:
    rel = f"src/ion/web/templates/{page}"
    before = git_show(rel)
    after_path = TEMPLATES / page
    if before is None or not after_path.is_file():
        return [f"{page}: cannot read before/after"], {}
    after = after_path.read_text(encoding="utf-8", errors="replace")

    b_lines, a_lines = before.splitlines(), after.splitlines()
    problems, stats = [], {"converted": 0, "kept": 0, "wrong": 0, "unchecked": 0}

    sm = difflib.SequenceMatcher(None, b_lines, a_lines, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        old_block = b_lines[i1:i2]
        new_block = a_lines[j1:j2]
        old_classes = [c for line in old_block for c in HASHED.findall(line)]
        if not old_classes:
            continue
        new_text = "\n".join(new_block)

        for cls in old_classes:
            entry = cmap.get(cls)
            if entry is None:
                # Unmapped/dead: must survive untouched.
                if cls in new_text:
                    stats["kept"] += 1
                else:
                    stats["wrong"] += 1
                    problems.append(f"{cls}: unmapped class removed with no replacement")
                continue

            if entry["kind"] == "manual":
                if cls in new_text:
                    stats["kept"] += 1
                else:
                    stats["wrong"] += 1
                    problems.append(
                        f"{cls}: MANUAL rule removed — its CSS has no full utility "
                        f"equivalent ({entry['css'][:50]})")
                continue

            # Mappable: the class must be gone AND its utilities present here.
            if cls in new_text:
                stats["unchecked"] += 1
                problems.append(f"{cls}: still present, expected -> {entry['tailwind']}")
                continue

            expected = entry["tailwind"].split()
            missing = [u for u in expected if u not in new_text]
            if missing:
                stats["wrong"] += 1
                problems.append(
                    f"{cls}: converted but missing {missing} "
                    f"(css: {entry['css'][:44]})")
            else:
                stats["converted"] += 1
                if verbose:
                    print(f"        ok  {cls} -> {entry['tailwind']}")
    return problems, stats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", nargs="*")
    ap.add_argument("--changed", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    pages = changed_templates() if args.changed else (args.pages or [])
    if not pages:
        print("use --pages or --changed", file=sys.stderr)
        return 2

    cmap = json.loads(MAP.read_text(encoding="utf-8"))
    total_problems = 0
    for page in pages:
        problems, stats = verify(page, cmap, args.verbose)
        total_problems += len(problems)
        mark = "OK  " if not problems else "FAIL"
        print(f"[{mark}] {page}  converted={stats.get('converted',0)} "
              f"kept={stats.get('kept',0)} wrong={stats.get('wrong',0)} "
              f"still-present={stats.get('unchecked',0)}")
        for p in problems:
            print(f"        {p}")

    print(f"\n{len(pages)} page(s), {total_problems} problem(s)")
    print("Line-aligned: a page that restructured markup reports misalignment,")
    print("which for a conversion-only pass is itself a finding.")
    return 0 if total_problems == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
