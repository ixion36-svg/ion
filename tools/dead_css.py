"""Find CSS classes that nothing references, so the legacy sheets can shrink.

Deleting CSS is the most dangerous operation in this rewrite: a wrong call
removes styling from a page nobody opens until a customer does, and there is no
error, no log line and no failing test. So this errs heavily towards calling a
class LIVE.

WHAT COUNTS AS A REFERENCE
--------------------------
Templates and static/js are both searched, and four kinds of reference count:

  1. A literal token in a class attribute.            class="foo bar"
  2. A literal token in any quoted string.            querySelector('.foo')
  3. A CONSTRUCTED name.                              'sev-' + level
                                                      `sc-cov-${n}`
                                                      className = 'tab-' + id
  4. A name another CSS rule depends on, as an ancestor or in a compound
     selector.  Deleting `.panel` while `.panel .row` survives leaves the row
     unstyled -- the same orphaning the restyle kept hitting.

(3) is the one that catches people out. `health-green` never appears literally
anywhere; it is built as `health-${idx.health}`. A literal-only search calls it
dead and deleting it silently breaks the index browser. Every `prefix-` that
appears immediately before a concatenation or interpolation is collected, and
any class starting with one is treated as live.

Usage:
    python tools/dead_css.py                      # report, all sheets
    python tools/dead_css.py --sheet style.css    # one sheet
    python tools/dead_css.py --sheet ai-chat.css --write   # delete the rules
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CSS_DIR = REPO / "src/ion/web/static/css"
SEARCH_DIRS = [REPO / "src/ion/web/templates", REPO / "src/ion/web/static/js"]
# lucide.css is an icon font, not legacy styling.
SHEETS = ["style.css", "ion-migrated-styles.css", "alert-detail.css",
          "ai-chat.css", "design-system.css", "ion-workspace.css"]

CLASS_IN_SELECTOR = re.compile(r"\.(_?[A-Za-z][A-Za-z0-9_-]*)")
RULE = re.compile(r"(?P<sel>[^{}]+)\{(?P<body>[^{}]*)\}", re.S)
COMMENT = re.compile(r"/\*.*?\*/", re.S)


def mask_comments(css: str) -> str:
    """Blank comment bodies, preserving every offset.

    CSS comments routinely contain braces and selector-like text -- this repo
    has `/* ... style-src-attr 'none' ... */` sitting directly above a rule, and
    one comment documents a `.ion-ws-*` naming convention. Parsing the raw text
    treats those as rules: the first version of this tool spliced a comment into
    a declaration body and invented a class called `ion-ws-`. Masking first, and
    slicing output from the ORIGINAL string, keeps comments intact and offsets
    aligned.
    """
    out = list(css)
    for m in COMMENT.finditer(css):
        for i in range(m.start(), m.end()):
            if out[i] != "\n":
                out[i] = " "
    return "".join(out)


def corpus() -> str:
    parts = []
    for d in SEARCH_DIRS:
        if not d.is_dir():
            continue
        for p in list(d.rglob("*.html")) + list(d.rglob("*.js")):
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def literal_tokens(text: str) -> set[str]:
    out: set[str] = set()
    for m in re.finditer(r'class="([^"{}]*)"', text):
        out.update(m.group(1).split())
    for m in re.finditer(r"class='([^'{}]*)'", text):
        out.update(m.group(1).split())
    # Any quoted string can carry a class name: querySelector('.x'),
    # classList.add('x'), className = 'a b c', a template literal chunk.
    for m in re.finditer(r"""['"`]([^'"`\n]{1,200})['"`]""", text):
        for tok in re.split(r"[\s.,#>()\[\]{}:;+~*=]+", m.group(1)):
            if tok:
                out.add(tok)
    return out


def constructed_prefixes(text: str) -> set[str]:
    """`'sev-' + x` and `` `sc-cov-${n}` `` mean every sev-*/sc-cov-* is live."""
    out: set[str] = set()
    # The prefix is the TRAILING identifier of the string being concatenated,
    # not the whole string. cases.html builds severity rails as
    #     '<span class="rail-sev rail-sev-' + esc(sev) + '"></span>'
    # An earlier version anchored on the opening quote, so it only matched when
    # the entire string was the prefix. It missed this, called every
    # .rail-sev-critical/high/medium/low/info dead, and would have deleted five
    # live rules -- with no error, and the rails silently losing their colour.
    for m in re.finditer(r"([A-Za-z][A-Za-z0-9_-]*[-_])['\"]\s*\+", text):
        out.add(m.group(1))
    # `...prefix-${expr}`
    for m in re.finditer(r"([A-Za-z][A-Za-z0-9_-]*[-_])\$\{", text):
        out.add(m.group(1))
    # Also `className = base + '-' + x` style: a lone '-' joiner means we cannot
    # know the prefix, so treat every class in that file as live is too blunt --
    # instead flag it for the operator.
    return out


def lone_joiner_sites(text: str) -> list[str]:
    """Concatenations whose prefix cannot be recovered, e.g. `x + '-' + y`.

    These defeat prefix detection entirely, so any class they build looks dead.
    Reported rather than guessed at.
    """
    return [m.group(0).strip() for m in
            re.finditer(r".{0,40}\+\s*['\"]-['\"]\s*\+.{0,20}", text)]


def page_style_blocks() -> str:
    """Every template's own <style> block, concatenated.

    These are a reference source the first version ignored. alerts.html scopes
    `.side-panel .list-group` and executive_report.html hides `.navbar` in a
    print rule -- both name classes defined in style.css, from a file that is
    not style.css. Deleting the definition out from under a page rule leaves
    that rule matching nothing.
    """
    parts = []
    for p in (REPO / "src/ion/web/templates").rglob("*.html"):
        t = p.read_text(encoding="utf-8", errors="replace")
        parts.extend(re.findall(r"<style\b[^>]*>(.*?)</style>", t, re.S | re.I))
    return "\n".join(parts)


def css_internal_refs(css: str) -> set[str]:
    """Classes another surviving rule leans on: `.panel .row`, `.a.b`, `.x:hover`.

    A class used only as an ancestor is still load-bearing even if no markup
    names it directly -- deleting it orphans whatever it scopes.
    """
    out: set[str] = set()
    for m in RULE.finditer(mask_comments(css)):
        sel = m.group("sel")
        if "@" in sel:
            continue
        for part in sel.split(","):
            names = CLASS_IN_SELECTOR.findall(part)
            if len(names) > 1:
                out.update(names)          # compound or descendant: all needed
    return out


def analyse(sheet: str, live_tokens: set[str], prefixes: set[str],
            page_css: str = ""):
    path = CSS_DIR / sheet
    css = path.read_text(encoding="utf-8", errors="replace")
    # A class is live if this sheet leans on it, OR any page's own <style>
    # block does, OR any OTHER shared sheet does.
    internal = css_internal_refs(css) | css_internal_refs(page_css)
    for other in SHEETS:
        if other != sheet and (CSS_DIR / other).is_file():
            internal |= css_internal_refs(
                (CSS_DIR / other).read_text(encoding="utf-8", errors="replace"))
    masked = mask_comments(css)
    # Only names appearing in an actual SELECTOR count as defined. Scanning the
    # whole file swept up `.ion-ws-*` from a comment documenting the naming
    # convention and reported it as a dead class.
    defined: dict[str, int] = {}
    for m in RULE.finditer(masked):
        if "@" in m.group("sel"):
            continue
        for name in CLASS_IN_SELECTOR.findall(m.group("sel")):
            defined[name] = defined.get(name, 0) + 1

    dead = []
    for name in sorted(defined):
        if name in live_tokens or name in internal:
            continue
        if any(name.startswith(p) for p in prefixes):
            continue
        dead.append(name)
    return css, defined, dead


def strip_rules(css: str, dead: set[str]) -> tuple[str, int]:
    """Remove rules whose every selector targets only dead classes."""
    masked = mask_comments(css)
    out, last, removed = [], 0, 0
    for m in RULE.finditer(masked):
        sel_masked = m.group("sel")
        if "@" in sel_masked:
            continue
        # The captured "selector" span starts after the previous rule's `}`, so
        # it carries leading whitespace and any comment. Those are not part of
        # the selector and must survive verbatim: slice them from the ORIGINAL.
        sel_start = m.start("sel") + (len(sel_masked) - len(sel_masked.lstrip()))
        lead_end = m.start("sel")
        # Everything before the real selector text (comments, blank lines).
        real_sel_offset = len(sel_masked.rstrip()) and sel_masked.rfind("\n") + 1
        parts = [p.strip() for p in sel_masked.split(",") if p.strip()]
        if not parts:
            continue
        keep = []
        for part in parts:
            names = CLASS_IN_SELECTOR.findall(part)
            # Only drop a selector that is entirely about dead classes. One
            # mixing a dead class with a live element or another class stays.
            if names and all(n in dead for n in names):
                continue
            keep.append(part)
        if len(keep) == len(parts):
            continue
        out.append(css[last:lead_end])
        # Re-emit the prefix (comments/whitespace) exactly as it was written.
        prefix_len = len(sel_masked) - len(sel_masked.lstrip())
        out.append(css[lead_end:lead_end + prefix_len])
        if keep:
            out.append(f"{', '.join(keep)} {{{m.group('body')}}}")
        else:
            removed += 1
        last = m.end()
    out.append(css[last:])
    return "".join(out), removed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sheet", help="one sheet; default is all")
    ap.add_argument("--write", action="store_true", help="delete the dead rules")
    ap.add_argument("--list", action="store_true", help="print every dead class")
    args = ap.parse_args()

    text = corpus()
    live = literal_tokens(text)
    prefixes = constructed_prefixes(text)
    print(f"corpus: {len(live)} literal token(s), "
          f"{len(prefixes)} constructed prefix(es) treated as live")
    joiners = lone_joiner_sites(text)
    if joiners:
        print(f"  WARNING: {len(joiners)} concatenation(s) with an unrecoverable "
              f"prefix (x + '-' + y). Classes they build cannot be detected:")
        for j in joiners[:5]:
            print(f"    {j[:90]}")

    page_css = page_style_blocks()
    sheets = [args.sheet] if args.sheet else SHEETS
    grand = 0
    for sheet in sheets:
        css, defined, dead = analyse(sheet, live, prefixes, page_css)
        new_css, removed = strip_rules(css, set(dead))
        before = len(css.splitlines())
        after = len(new_css.splitlines())
        print(f"\n{sheet}: {len(defined)} classes, {len(dead)} dead, "
              f"{removed} rule(s) removable, {before} -> {after} lines")
        if args.list:
            for n in dead:
                print(f"    {n}")
        if args.write:
            if new_css.count("{") != new_css.count("}"):
                print("    REFUSED: braces unbalanced after strip")
                continue
            (CSS_DIR / sheet).write_text(new_css, encoding="utf-8", newline="")
            print("    written")
        grand += removed
    print(f"\n{grand} rule(s) {'removed' if args.write else 'removable'}")
    if not args.write:
        print("DRY RUN - pass --write")
    return 0


if __name__ == "__main__":
    sys.exit(main())
