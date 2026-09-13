"""Per-template baseline for the UI rewrite.

Emits a JSON snapshot of what each template contains that the rewrite must not
silently lose: CSP hashed classes, sanctioned data-ion-style hooks, and raw
inline style attributes.

Why this exists: the two most likely failures when rewriting 81,191 lines of
templates are both INVISIBLE. A dropped `_ion-s-*` class renders an unstyled
element, and a raw `style="..."` is refused by `style-src-attr 'none'` with no
error, no log line and no failed request. Neither shows up in a diff review at
this volume, and neither fails an existing test. See
tests/test_v080_csp_inline_styles.py, where 22 such violations sat unnoticed and
a severity stripe rendered colourless for three releases.

The inline-style regex carries a (?<![-\\w]) guard so `data-ion-style="..."`
cannot match as an inline style. Without it, already-migrated sites are counted
as violations -- the same trap that once produced a six-phase plan for work that
was already done.

Usage:
    python tools/ui_rewrite_audit.py            # write baseline
    python tools/ui_rewrite_audit.py --check    # diff against baseline, exit 1 on loss
"""

import argparse
import json
import re
import sys
from pathlib import Path

TEMPLATES = Path("src/ion/web/templates")
BASELINE = Path("tools/ui_rewrite_baseline.json")

# The guard is load-bearing. See module docstring.
INLINE_STYLE = re.compile(r'(?<![-\w])style\s*=\s*["\']')
HASHED_CLASS = re.compile(r'_ion-s-[a-z0-9]+')
ION_STYLE_HOOK = re.compile(r'data-ion-style\s*=')


def scan_one(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    hashed = HASHED_CLASS.findall(text)
    return {
        "lines": text.count("\n") + 1,
        "hashed_classes": sorted(set(hashed)),
        "hashed_count": len(hashed),
        "ion_style_hooks": len(ION_STYLE_HOOK.findall(text)),
        "raw_inline_styles": len(INLINE_STYLE.findall(text)),
    }


def scan_all() -> dict:
    return {
        str(p.relative_to(TEMPLATES)).replace("\\", "/"): scan_one(p)
        for p in sorted(TEMPLATES.rglob("*.html"))
    }


def load_map() -> dict:
    p = Path("tools/hashed_class_map.json")
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}


def check(baseline: dict, current: dict) -> list[str]:
    """Report only LOSSES and REGRESSIONS, never mere change.

    A rewrite is expected to change markup wholesale. What it must not do is
    drop a style with no replacement, or introduce a raw inline style (silently
    refused under style-src-attr 'none').

    MAP-AWARE, and it has to be. This originally failed on ANY lost hashed
    class, which was right while the plan was to preserve them. It is wrong now
    that pass 2 deliberately converts them: measured, 894 of 905 rules are
    plain static styling, not the JS-computed values the older docs claim, so
    the mappable ones SHOULD disappear. Losing one that the table could not map
    is still a real defect — that is a style deleted with no replacement.

    Whether the replacement utilities are correct is a different question, and
    a stronger one; tools/verify_conversion.py answers it line by line.
    """
    cmap = load_map()
    problems = []
    for name, base in baseline.items():
        cur = current.get(name)
        if cur is None:
            problems.append(f"{name}: template disappeared")
            continue

        lost = set(base["hashed_classes"]) - set(cur["hashed_classes"])
        unreplaceable = sorted(
            c for c in lost
            if c not in cmap or cmap[c].get("kind") == "manual"
        )
        # A utility is not the only legitimate replacement. Where the original
        # style was computed at runtime -- `flex:' + slaCounts.green + '` -- no
        # static class can express it, and the correct destination is a
        # data-ion-style hook applied through el.style.setProperty. Those
        # classes SHOULD disappear, and counting them as losses reports the
        # repair as the damage.
        #
        # Matched on the count of hooks the template gained rather than per
        # class, because by the time the class is gone there is nothing left to
        # tie it to the element that replaced it.
        gained_hooks = cur["ion_style_hooks"] - base["ion_style_hooks"]
        if gained_hooks > 0:
            unreplaceable = unreplaceable[max(0, gained_hooks):]
        if unreplaceable:
            problems.append(
                f"{name}: lost {len(unreplaceable)} class(es) with NO utility "
                f"equivalent: {unreplaceable[:5]}"
            )

        if cur["raw_inline_styles"] > base["raw_inline_styles"]:
            problems.append(
                f"{name}: raw inline styles {base['raw_inline_styles']} -> "
                f"{cur['raw_inline_styles']} (silently refused under CSP)"
            )
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    current = scan_all()

    if not args.check:
        BASELINE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        total = sum(v["hashed_count"] for v in current.values())
        print(f"baseline written: {len(current)} templates, {total} hashed classes")
        return 0

    if not BASELINE.is_file():
        print("no baseline; run without --check first", file=sys.stderr)
        return 2
    problems = check(json.loads(BASELINE.read_text(encoding="utf-8")), current)
    for p in problems:
        print(p, file=sys.stderr)
    print(f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
