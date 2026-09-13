"""Apply the hashed-class lookup table to a template's markup.

Pass 2 replaces each `_ion-s-*` class with its Tailwind equivalent. That is a
token substitution against a table that has already been reviewed, so there is
nothing for judgement to add — and quite a lot for it to get wrong. An agent
doing this by hand across 166 occurrences will transpose a class, reflow a line,
or quietly improvise a utility for a rule the table marked manual.

So this does the substitution and `verify_conversion.py` checks it afterwards,
class by class, against the same table.

WHAT IT WILL NOT TOUCH
----------------------
`<script>` and `<style>` blocks. Roughly 1,200 of the 1,370 hashed occurrences
live inside script template literals, building markup at runtime. Converting the
static copy of a class the script also emits would leave the two halves of the
same component looking different, so a class that appears in a script block is
skipped in the markup too, and reported.

`kind: "manual"` rules. Those have declarations with no clean utility; the table
deliberately publishes no `tailwind` string for them, and the only correct move
is to leave the class alone.

Usage:
    python tools/apply_conversion.py --pages forensics.html          # dry run
    python tools/apply_conversion.py --pages forensics.html --apply
    python tools/apply_conversion.py --all --apply
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TEMPLATES = REPO / "src/ion/web/templates"
MAP = REPO / "tools/hashed_class_map.json"

BLOCK = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.S | re.I)
HASHED = re.compile(r"_ion-s-[a-z0-9]+")
CLASS_ATTR = re.compile(r'class="([^"]*)"')


def load_map() -> dict:
    d = json.loads(MAP.read_text(encoding="utf-8"))
    return d.get("rules", d)


def script_classes(text: str) -> set[str]:
    """Hashed classes that appear inside <script> — off limits in markup too."""
    out: set[str] = set()
    for m in re.finditer(r"<script\b[^>]*>(.*?)</script>", text, re.S | re.I):
        out.update(HASHED.findall(m.group(1)))
    return out


def convert_text(text: str, rules: dict) -> tuple[str, dict]:
    """Return the converted text and a report of what happened."""
    protected = script_classes(text)
    spans = [(m.start(), m.end()) for m in BLOCK.finditer(text)]

    def in_block(pos: int) -> bool:
        return any(a <= pos < b for a, b in spans)

    stats = {"converted": [], "manual": [], "in_script": [], "unknown": []}

    def fix(m: re.Match) -> str:
        if in_block(m.start()):
            return m.group(0)
        tokens = m.group(1).split()
        out = []
        for tok in tokens:
            if not HASHED.fullmatch(tok):
                out.append(tok)
                continue
            rule = rules.get(tok)
            if rule is None:
                stats["unknown"].append(tok)
                out.append(tok)
            elif tok in protected:
                stats["in_script"].append(tok)
                out.append(tok)
            elif rule.get("kind") == "manual" or not rule.get("tailwind"):
                stats["manual"].append(tok)
                out.append(tok)
            else:
                stats["converted"].append(tok)
                out.extend(rule["tailwind"].split())
        # Rebuild preserving the original leading/trailing shape as far as the
        # token list allows; class attributes are whitespace-separated so this
        # is lossless for anything the browser cares about.
        return 'class="' + " ".join(out) + '"'

    return CLASS_ATTR.sub(fix, text), stats


def run(name: str, rules: dict, apply: bool) -> int:
    path = TEMPLATES / name
    if not path.is_file():
        print(f"[MISS] {name}: no such template")
        return 0
    before = path.read_text(encoding="utf-8")
    after, stats = convert_text(before, rules)
    n = len(stats["converted"])
    lines_before, lines_after = before.count("\n"), after.count("\n")
    if lines_before != lines_after:
        print(f"[FAIL] {name}: line count changed {lines_before} -> {lines_after}")
        return 0
    tag = "OK  " if n else "--  "
    print(f"[{tag}] {name}: {n} converted, {len(set(stats['manual']))} manual, "
          f"{len(set(stats['in_script']))} shared with script, "
          f"{len(set(stats['unknown']))} unknown")
    for label in ("manual", "in_script", "unknown"):
        for cls in sorted(set(stats[label])):
            print(f"          left {cls}  ({label})")
    if apply and n:
        path.write_text(after, encoding="utf-8", newline="")
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", nargs="*")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    rules = load_map()
    if args.all:
        pages = sorted(p.relative_to(TEMPLATES).as_posix()
                       for p in TEMPLATES.rglob("*.html"))
    elif args.pages:
        pages = args.pages
    else:
        print("use --pages or --all", file=sys.stderr)
        return 2

    total = sum(run(name, rules, args.apply) for name in pages)
    print(f"\n{total} hashed class(es) {'converted' if args.apply else 'convertible'}")
    if not args.apply:
        print("DRY RUN - pass --apply to write")
    else:
        print("Now run tools/verify_conversion.py --changed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
