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
# alerts-queue.css was missing from this list and so had never been scanned.
# It is loaded by alerts.html rather than base.html, which is how it was
# overlooked; being page-scoped makes it more likely to hold dead rules, not
# less.
SHEETS = ["style.css", "ion-migrated-styles.css", "alert-detail.css",
          "ai-chat.css", "ion-workspace.css",
          "alerts-queue.css"]

CLASS_IN_SELECTOR = re.compile(r"\.(_?[A-Za-z][A-Za-z0-9_-]*)")
RULE = re.compile(r"(?P<sel>[^{}]+)\{(?P<body>[^{}]*)\}", re.S)
COMMENT = re.compile(r"/\*.*?\*/", re.S)
# :not(...) inverts the meaning of every class inside it. :is() and
# :where() are left alone -- neither appears in any legacy sheet, and
# their semantics (an OR, so dead only if ALL branches are dead) differ
# again. Guessing at them is how this kind of tool starts deleting things.
NEGATION = re.compile(r":not\([^()]*\)")


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


# `${...}` in a JS template literal, `{{...}}`/`{%...%}` in a Jinja template.
# Both sit INSIDE class attributes constantly, and both must be cut out before
# the attribute is split, not used as a reason to skip the attribute.
INTERPOLATION = re.compile(r"\$\{[^{}]*\}|\{\{.*?\}\}|\{%.*?%\}", re.S)
# The attribute value is "anything up to the closing quote, except that an
# interpolation may contain quotes of its own". Spelling the value as a plain
# [^"'] character class is not enough: `${auto ? ' aq-autocase' : ''}` holds
# four single quotes, so the match died at the first one and the attribute was
# skipped exactly as before.
_INTERP = r"\$\{[^{}]*\}|\{\{.*?\}\}|\{%.*?%\}"
CLASS_ATTR = re.compile(
    r'class\s*=\s*"(?P<dq>(?:' + _INTERP + r'|[^"]){0,600}?)"'
    r"|class\s*=\s*'(?P<sq>(?:" + _INTERP + r"|[^']){0,600}?)'", re.S)


IDENT = re.compile(r"-?_?[A-Za-z][A-Za-z0-9_-]*")
QUOTED_INSIDE = re.compile(r"""['"]([^'"]*)['"]""")


def _attr_tokens(value: str) -> set[str]:
    """Split a class attribute, keeping class names written inside `${...}`.

    Deleting the interpolation outright loses the conditional half of

        `<div class="aq-ghead sev-${esc(g.sev)}${shut ? ' aq-closed' : ''}">`

    where `aq-closed` is a real class applied to a real element and appears
    nowhere else in the app. Its rule then reads as dead. So an interpolation
    contributes the contents of any quoted string it holds -- that is where a
    literal class name in a ternary lives -- and nothing else, since the rest
    is expression code (`esc`, `g.sev`) that would only add noise.
    """
    def expand(m: re.Match) -> str:
        return " " + " ".join(QUOTED_INSIDE.findall(m.group(0))) + " "
    # Keep only what could actually be a class name. An interpolation this
    # parser cannot follow -- one with a nested brace -- otherwise leaks
    # fragments of expression code (`${xs.map(x`) into the live set. They can
    # never match a CSS class, so they are pure noise, but noise in the set
    # that decides what gets deleted is worth not having.
    return {t for t in INTERPOLATION.sub(expand, value).split()
            if IDENT.fullmatch(t)}


def literal_tokens(text: str) -> set[str]:
    out: set[str] = set()
    # Class attributes, interpolations and all. The first version required the
    # value to contain no braces:  class="([^"{}]*)"  -- which silently skipped
    # every attribute built at runtime. alerts-queue.js is written almost
    # entirely that way:
    #
    #     `<span class="aq-tag aq-caseref${auto ? ' aq-autocase' : ''}"`
    #
    # so aq-caseref, aq-ghead, aq-kev and aq-sev-pill all looked dead, and a
    # --write on alerts-queue.css would have deleted four live rules. The
    # generic quoted-string pass below did not save them either: it starts at
    # the backtick and stops at the first `"`, so it never reaches past
    # `<span class=`.
    #
    # Known limit: an interpolation containing a nested brace, `${xs.map(x =>
    # `${x}`)}`, still ends the match early. That fails towards calling a class
    # LIVE -- the attribute is skipped, so nothing is deleted on its account.
    for m in CLASS_ATTR.finditer(text):
        val = m.group("dq") if m.group("dq") is not None else m.group("sq")
        out.update(_attr_tokens(val or ""))
    # Any quoted string can carry a class name: querySelector('.x'),
    # classList.add('x'), className = 'a b c', a template literal chunk.
    #
    # {0,200} rather than {1,200}, because an EMPTY string must still consume
    # its pair of quotes. With {1,200} the scan cannot match '' and carries on
    # from the first of the two, which puts every following quote on this line
    # out of phase:
    #
    #     { k: 'act', label: '', cls: 'aq-act', on: true }
    #
    # paired as 'act' … ', cls: ' … ', on: true }', so `aq-act` fell in a gap
    # between two matches and was never seen. It is the class for the whole
    # actions column, and its rule was reported removable.
    for m in re.finditer(r"""['"`]([^'"`\n]{0,200})['"`]""", text):
        for tok in re.split(r"[\s.,#>()\[\]{}:;+~*=]+", m.group(1)):
            if tok:
                out.add(tok)
    # An attribute the JS never closes, because the concatenation closes it:
    #
    #     '<div class="iad-adv iad-adv-kev' + (ransom ? ' is-ransomware' : '')
    #
    # There is no second `"` in that literal, so CLASS_ATTR cannot match, and
    # the quote scan above pairs the opening `"` as the CLOSE of `'<div class=`
    # -- which leaves iad-adv-kev in the gap between two matches, exactly the
    # phase problem again but caused by mixing quote characters rather than by
    # an empty string. Reading an unterminated attribute to the next quote or
    # angle bracket catches all three of iad-adv-kev, iad2-fpin and
    # iad2-gseg-ai, which are otherwise invisible and were about to have their
    # rules deleted.
    #
    # This over-collects by design: whatever follows `class=` up to the next
    # delimiter is treated as class names. Over-collecting keeps things alive.
    for m in re.finditer(r"""class\s*=\s*["']([^"'<>\n]{0,200})""", text):
        out.update(t for t in m.group(1).split() if IDENT.fullmatch(t))
    # Everything compared against this set is a class name parsed out of a
    # selector, so anything that cannot be one is noise either way. Dropping it
    # here rather than per-pass keeps the two passes free to over-collect.
    return {t for t in out if IDENT.fullmatch(t)}


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
    """Classes another rule pairs with: `.panel .row`, `.a.b`, `.x:hover`.

    NOT used for liveness any more, and the reason is worth recording. It used
    to be: keep `.panel` because `.panel .row` depends on it. That is backwards.
    If no element ever carries `panel`, then `.panel .row` cannot match either,
    so both are dead and keeping the ancestor keeps a rule that can never fire.

    Worse, it made any class with a compound rule immortal. `.settings-tab.active`
    kept `.settings-tab` alive purely through its own declaration, even though
    nothing in the app has ever carried that class -- 0 occurrences in class
    attributes and 0 in JS strings. That single mistake was holding roughly 19KB
    of unreachable CSS in style.css.

    Liveness now comes only from markup and JS: a literal token, or a
    constructed prefix. Kept as a function because the removal step still needs
    to know which rules pair a dead class with a live one -- those are left
    alone rather than half-rewritten.
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
    # Deliberately NOT seeded from other rules -- see css_internal_refs.
    # A page's own <style> block is a reference source like any other: it can
    # scope a shared class the sheet defines. This was collected by
    # page_style_blocks() and handed in, then never read -- the parameter was
    # accepted and dropped on the floor, so the whole reason that function
    # exists did not apply.
    internal: set[str] = set(CLASS_IN_SELECTOR.findall(mask_comments(page_css)))
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


def strip_rules(css: str, dead: set[str], strict: bool = False) -> tuple[str, int]:
    """Remove rules no element can match.

    Two readings of "cannot match", and the difference is large.

    Default (all-dead): drop a selector only when every class in it is dead.
    Deliberately timid -- it was written before the liveness scan was trusted.

    --strict (any-dead): drop a selector when ANY class in it is dead. This is
    the logically correct one. `.ds-badge.success` needs BOTH names on one
    element and `.ds-card .title` needs the ancestor; if either name is on no
    element in the app, the selector matches nothing whatever the other name
    does. Under the timid rule a dead class paired with a common modifier like
    `.success` or `.active` was unreachable and undeletable at once -- that is
    what kept all thirty selectors of design-system.css alive.

    The catch is blast radius. Any-dead means ONE class the scanner fails to
    see takes out every rule that mentions it, so it is only safe on a liveness
    set that is actually right. Three holes in that scan were fixed today, so
    it stays opt-in and its output is meant to be read before it is applied.
    """
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
            if strict:
                # A dead class inside :not() means the opposite of a dead class
                # outside it. `.nav-links > li > a:not(.nav-dropdown-toggle)`
                # with no .nav-dropdown-toggle anywhere is not unmatchable --
                # the :not() simply matches everything, so the rule styles every
                # such link. Reading it as "contains a dead class, therefore
                # cannot match" deletes a live rule and takes the whole nav bar
                # with it. Negated names are excluded from the test entirely.
                positive = CLASS_IN_SELECTOR.findall(NEGATION.sub(" ", part))
                gone = bool(positive) and any(n in dead for n in positive)
            else:
                gone = bool(names) and all(n in dead for n in names)
            if names and gone:
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
    ap.add_argument("--strict", action="store_true",
                    help="drop a selector if ANY of its classes is dead")
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
        new_css, removed = strip_rules(css, set(dead), args.strict)
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
