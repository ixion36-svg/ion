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


OTHER_CLASS_WRITE = re.compile(
    r"(?:className\s*=|classList\.\w+\(|setAttribute\(\s*['\"]class['\"])"
    r"[^;\n]{0,120}?(_ion-s-[a-z0-9]+)")


def convert_text(text: str, rules: dict, include_scripts: bool = False) -> tuple[str, dict]:
    """Return the converted text and a report of what happened.

    With include_scripts, class attributes inside <script> template literals are
    converted too. That is the only way the hashed classes finally go away --
    989 of the 1,370 occurrences are markup the script builds at runtime. It is
    still a pure string edit: only the contents of a class="..." are touched,
    never a statement, an identifier or any logic.

    <style> blocks are never touched either way.
    """
    protected = set() if include_scripts else script_classes(text)
    if include_scripts:
        spans = [(m.start(), m.end()) for m in
                 re.finditer(r"<style\b[^>]*>.*?</style>", text, re.S | re.I)]
    else:
        spans = [(m.start(), m.end()) for m in BLOCK.finditer(text)]

    def in_block(pos: int) -> bool:
        return any(a <= pos < b for a, b in spans)

    stats = {"converted": [], "manual": [], "in_script": [], "unknown": [],
             "other_write": []}

    # A class name reached through className=/classList.add/setAttribute is not
    # inside a class="..." and will not be rewritten here. Converting one would
    # mean replacing a single token with several, which those APIs handle
    # differently (className takes a string, classList.add refuses spaces).
    # Reported so the operator can see what was skipped and why.
    for m in OTHER_CLASS_WRITE.finditer(text):
        stats["other_write"].append(m.group(1))

    def fix(m: re.Match) -> str:
        if in_block(m.start()):
            return m.group(0)
        # Substitute each hashed token IN PLACE rather than rebuilding the
        # attribute. Rebuilding joins on single spaces, which silently collapses
        # a class attribute written across several lines -- verdict_review.html
        # has one, and the line-count guard caught it. In-place substitution
        # leaves every other character, including newlines and indentation,
        # exactly as it was.
        def one(tm: re.Match) -> str:
            tok = tm.group(0)
            rule = rules.get(tok)
            if rule is None:
                stats["unknown"].append(tok)
                return tok
            if tok in protected:
                stats["in_script"].append(tok)
                return tok
            if rule.get("kind") == "manual" or not rule.get("tailwind"):
                stats["manual"].append(tok)
                return tok
            stats["converted"].append(tok)
            return rule["tailwind"]

        return 'class="' + HASHED.sub(one, m.group(1)) + '"'

    return CLASS_ATTR.sub(fix, text), stats


def run(name: str, rules: dict, apply: bool, include_scripts: bool = False) -> int:
    # A .js file under static/js is all script and has no <style> block, so the
    # same class-attribute substitution applies to the whole file.
    # alert-detail.js builds the shared alert-detail component's markup and
    # carries 52 hashed classes that no template can reach.
    path = (REPO / "src/ion/web/static/js" / name) if name.endswith(".js") \
        else (TEMPLATES / name)
    if not path.is_file():
        print(f"[MISS] {name}: no such file")
        return 0
    before = path.read_text(encoding="utf-8")
    after, stats = convert_text(before, rules, include_scripts)
    n = len(stats["converted"])
    lines_before, lines_after = before.count("\n"), after.count("\n")
    if lines_before != lines_after:
        print(f"[FAIL] {name}: line count changed {lines_before} -> {lines_after}")
        return 0
    tag = "OK  " if n else "--  "
    print(f"[{tag}] {name}: {n} converted, {len(set(stats['manual']))} manual, "
          f"{len(set(stats['in_script']))} shared with script, "
          f"{len(set(stats['unknown']))} unknown")
    for cls in sorted(set(stats.get("other_write", []))):
        print(f"          skipped {cls}  (className/classList write)")
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
    ap.add_argument("--include-scripts", action="store_true",
                    help="also convert class attributes inside <script> "
                         "template literals")
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

    total = sum(run(name, rules, args.apply, args.include_scripts)
                for name in pages)
    print(f"\n{total} hashed class(es) {'converted' if args.apply else 'convertible'}")
    if not args.apply:
        print("DRY RUN - pass --apply to write")
    else:
        print("Now run tools/verify_conversion.py --changed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
