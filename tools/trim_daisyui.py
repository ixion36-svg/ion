"""Drop daisyUI's unused responsive component variants from the vendored dist.

WHY THIS EXISTS
---------------
ION has no Node toolchain, so daisyUI is pulled in as a plain `@import` of its
prebuilt dist rather than through the npm plugin. A plain @import gets no
tree-shaking: everything daisyUI ships is served, on every page.

Most of what it ships is not components but BREAKPOINTS. Of the 1.12MB dist,
about 790KB is five `@media (width>=Npx)` blocks -- one per Tailwind
breakpoint -- each containing every component again under an `sm:` / `md:` /
`lg:` / `xl:` / `2xl:` prefix. daisyUI generates 2,725 such variants.

ION uses four of them:

    lg:border-base-300      gitlab.html
    lg:stats-horizontal     alert_arkime.html, canaries.html, ...
    md:stats-horizontal     analyst.html, coverage.html, overview.html
    sm:stats-horizontal     _scoping_summary.html, _signoff.html, ...

So this rewrites the five media blocks to hold only the rules ION needs, and
writes the result to daisyui.trimmed.css, which is what the build imports.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It does not touch the unprefixed components, the themes, the base layer or any
custom property -- only the responsive duplicates. Component-level
tree-shaking is a much riskier proposition: a component can be applied by a
script the scanner cannot follow, and getting it wrong removes styling with no
error anywhere. A breakpoint prefix, by contrast, is a static layout decision
written into the markup; nothing assembles one at runtime.

The vendored daisyui.css is left pristine so upgrades stay a straight file
swap, and so the trim is always reproducible from it.

Usage:
    python tools/trim_daisyui.py            # report
    python tools/trim_daisyui.py --write    # write daisyui.trimmed.css
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "frontend/daisyui.css"
OUT = REPO / "frontend/daisyui.trimmed.css"
SEARCH = [REPO / "src/ion/web/templates", REPO / "src/ion/web/static/js"]

BREAKPOINTS = ("sm", "md", "lg", "xl", "2xl")
PREFIXED = re.compile(r"(?<![A-Za-z0-9_-])(sm|md|lg|xl|2xl):([a-z][a-z0-9-]*)")
# PX only, and that is the whole trick. daisyUI writes its responsive COMPONENT
# variants under `@media (width>=640px)` and its responsive colour UTILITIES
# (sm:bg-base-100, lg:border-base-300, and so on for every base/primary shade)
# under `@media (width>=40rem)`. Matching px alone therefore separates the two
# without having to classify a single selector: the component blocks are
# filtered, the utility blocks pass through untouched.
RESPONSIVE_MEDIA = re.compile(r"@media\s*\(\s*width\s*>=\s*\d+px\s*\)\s*$")


def blocks(s: str):
    """Split a string into top-level `head{body}` blocks and the text between.

    Yields ("block", head, body) and ("text", raw, None). Brace-matching rather
    than regex, because the dist is minified, deeply nested, and uses CSS
    nesting (`&:hover`) inside almost every component.
    """
    depth = start = 0
    head_start = 0
    for i, ch in enumerate(s):
        if ch == "{":
            if depth == 0:
                head = s[head_start:i]
                body_start = i + 1
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                if head_start > start:
                    pass
                yield ("block", head, s[body_start:i])
                head_start = i + 1
    tail = s[head_start:]
    if tail:
        yield ("text", tail, None)


def unescape(sel: str) -> str:
    """`.\\32 xl\\:stats-horizontal` -> `.2xl:stats-horizontal`.

    A CSS identifier cannot start with a digit, so minifiers write `2xl` as the
    hex escape `\\32 ` followed by `xl` -- the trailing space is part of the
    escape, not a descendant combinator. Getting that wrong reads `2xl:tabs` as
    two selectors and keeps nothing.
    """
    return sel.replace("\\32 ", "2").replace("\\", "")


def wanted() -> set[str]:
    """Responsive variants that appear anywhere in the source.

    Deliberately a raw scan of the whole file rather than a class-attribute
    parser: a breakpoint prefix is cheap to over-collect and expensive to miss.
    """
    out: set[str] = set()
    for d in SEARCH:
        for p in list(d.rglob("*.html")) + list(d.rglob("*.js")):
            out.update(m.group(0) for m in
                       PREFIXED.finditer(p.read_text(encoding="utf-8",
                                                     errors="replace")))
    for p in (REPO / "src/ion/web").glob("*.py"):
        out.update(m.group(0) for m in
                   PREFIXED.finditer(p.read_text(encoding="utf-8",
                                                 errors="replace")))
    return out


def filter_media(body: str, keep: set[str]) -> str:
    """Keep only the rules in a media block that ION uses.

    Has to recurse. The rules are not direct children of the media block --
    each one sits inside a nested `@layer daisyui.l1.l2` or
    `@layer daisyui.l1.l2.l3`, so a version that inspected only the top level
    found no selectors at all, matched nothing, and dropped all five
    breakpoints including the four variants that had to survive. The check at
    the end of main() is what caught that.

    Below a real rule the recursion stops: a component's `&:hover` and its
    nested `.tab-content` are part of that rule, not separate ones, so the
    decision is made once per selector.
    """
    out = []
    for kind, head, inner in blocks(body):
        if kind == "text":
            continue
        if head.strip().startswith("@"):
            nested = filter_media(inner, keep)
            if nested:
                out.append(f"{head}{{{nested}}}")
            continue
        names = set(re.findall(r"\.([A-Za-z0-9_-]+:[A-Za-z0-9_-]+)",
                               unescape(head)))
        if names & keep:
            out.append(f"{head}{{{inner}}}")
    return "".join(out)


def transform(css: str, keep: set[str]) -> tuple[str, int, int]:
    kept_rules = dropped = 0

    def walk(s: str) -> str:
        nonlocal kept_rules, dropped
        parts = []
        for kind, head, inner in blocks(s):
            if kind == "text":
                parts.append(head)
                continue
            if RESPONSIVE_MEDIA.match(head.strip()):
                filtered = filter_media(inner, keep)
                if filtered:
                    kept_rules += 1
                    parts.append(f"{head}{{{filtered}}}")
                else:
                    dropped += 1
                continue
            if head.strip().startswith("@"):
                parts.append(f"{head}{{{walk(inner)}}}")
            else:
                parts.append(f"{head}{{{inner}}}")
        return "".join(parts)

    return walk(css), kept_rules, dropped


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    css = SRC.read_text(encoding="utf-8")
    used = wanted()
    generated = set()
    for m in re.finditer(r"\.((?:\\32 )?[a-z0-9]{1,3})\\:([a-z0-9-]+)", css):
        generated.add(m.group(1).replace("\\32 ", "2") + ":" + m.group(2))
    generated = {g for g in generated if g.split(":")[0] in BREAKPOINTS}
    keep = used & generated

    print(f"daisyUI generates {len(generated)} responsive component variant(s)")
    print(f"ION uses {len(keep)}:")
    for k in sorted(keep):
        print(f"    {k}")

    out, kept, dropped = transform(css, keep)
    print(f"\nmedia blocks: {kept} kept (filtered), {dropped} dropped entirely")
    print(f"{len(css):,} -> {len(out):,} bytes "
          f"({100 * (1 - len(out) / len(css)):.0f}% smaller)")

    if out.count("{") != out.count("}"):
        print("REFUSED: braces unbalanced")
        return 1
    # Every kept variant must still be present, or the escape handling is wrong.
    for k in sorted(keep):
        pre, name = k.split(":", 1)
        esc = ("\\32 xl" if pre == "2xl" else pre) + "\\:" + name
        if esc not in out:
            print(f"REFUSED: {k} was supposed to survive and did not")
            return 1

    if args.write:
        OUT.write_text(out, encoding="utf-8", newline="")
        print(f"written: {OUT.relative_to(REPO).as_posix()}")
    else:
        print("DRY RUN - pass --write")
    return 0


if __name__ == "__main__":
    sys.exit(main())
