"""Repair CSS rules that contain JavaScript source instead of a value.

THE BUG
-------
The v0.31.21 migration hashed inline styles into static CSS classes. Where the
style was built at runtime it emitted the BUILDER as CSS:

    ._ion-s-09b0c9a2e1 { flex:' + slaCounts.green + ';background:var(--success);
                         border-radius:3px;height:6px }

A browser parses that rule, drops `flex` as invalid, and keeps the rest. So the
element gets its static styling and silently loses the dynamic part -- no
error, no console warning, nothing to see unless you know what it should have
looked like. The four SLA bar segments on the cases board have no flex, so the
bar never proportions; progress bars have no width; severity, TLP and closure
badges have no colour.

ion-dynamic-styles.js already fixes this class of bug for the `${...}`
template-literal form, by moving the dynamic declarations to a
`data-ion-style` attribute and applying them with el.style.setProperty (a DOM
write, so CSP's style-src-attr 'none' does not block it). It never covered the
`' + x + '` string-concatenation form, which is what these 23 are.

THE REPAIR
----------
The CSS body IS the original inline-style expression, extracted verbatim, so it
splices straight back into the JS string it came from:

    '<div class="_ion-s-09b0c9a2e1" title="...">'
 -> '<div class="_ion-s-09b0c9a2e1" data-ion-style="flex:' + slaCounts.green + '" title="...">'

and the CSS rule keeps only its static declarations. A rule left with nothing
is dropped.

Usage:
    python tools/fix_dynamic_style_rules.py           # diff, changes nothing
    python tools/fix_dynamic_style_rules.py --write
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CSS = REPO / "src/ion/web/static/css/ion-migrated-styles.css"
SEARCH = [REPO / "src/ion/web/templates", REPO / "src/ion/web/static/js"]

# A declaration is dynamic if it carries JS. `${...}` is here for completeness;
# ion-dynamic-styles.js already handles the sites that use it.
# A CONCATENATION, not just a quote beside a plus: daisyUI's
# `--tw-content:"+"` is a literal plus sign, not JavaScript.
JS_IN_VALUE = re.compile(r"['\"]\s*\+\s*[A-Za-z_$(]|[A-Za-z0-9_)\]]\s*\+\s*['\"]|\$\{")
HASHED = re.compile(r"_ion-s-[0-9a-f]+")


def split_decls(body: str) -> list[str]:
    """Split on ';' outside quotes and parentheses.

    A value can contain both: `background:conic-gradient(' + color + ' ' + pct
    + '%, rgba(99,110,123,.2) ' + pct + '%)` has commas, parens and quotes, and
    a naive split on ';' would cut a ternary like
    `(x > 7 ? 'a' : 'b')` in the wrong place.
    """
    out, buf, quote, depth = [], "", None, 0
    for i, c in enumerate(body):
        if quote:
            buf += c
            if c == quote and body[i - 1:i] != "\\":
                quote = None
        elif c in "\"'":
            quote = c
            buf += c
        elif c == "(":
            depth += 1
            buf += c
        elif c == ")":
            depth -= 1
            buf += c
        elif c == ";" and depth == 0:
            if buf.strip():
                out.append(buf.strip())
            buf = ""
        else:
            buf += c
    if buf.strip():
        out.append(buf.strip())
    return out


def drop_class(text: str, cls: str) -> str:
    """Remove one class name from every class attribute that carries it.

    An attribute left holding nothing is removed along with the space in front
    of it, rather than left as `class=""`, which reads to the next person like
    a mistake someone forgot to finish. Line count is unaffected either way,
    and the caller checks that.
    """
    def fix(m: re.Match) -> str:
        names = [n for n in m.group(1).split() if n != cls]
        return ' class="' + " ".join(names) + '"' if names else ""
    return re.sub(r'\s*class="([^"]*)"',
                  lambda m: fix(m) if cls in m.group(1).split() else m.group(0),
                  text)


def broken_rules(css: str):
    """(class, selector, whole match, static decls, dynamic decls)."""
    for m in re.finditer(r"(?P<sel>[^{}]+)\{(?P<body>[^{}]*)\}", css, re.S):
        body = m.group("body")
        if not JS_IN_VALUE.search(body):
            continue
        name = HASHED.search(m.group("sel"))
        if not name:
            continue
        decls = split_decls(body)
        dyn = [d for d in decls if JS_IN_VALUE.search(d)]
        static = [d for d in decls if not JS_IN_VALUE.search(d)]
        yield name.group(0), m, static, dyn


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    css = CSS.read_text(encoding="utf-8")
    files = {p: p.read_text(encoding="utf-8", errors="replace")
             for d in SEARCH for p in list(d.rglob("*.html")) + list(d.rglob("*.js"))}

    edits: dict[Path, str] = {}
    css_out, last = [], 0
    fixed = skipped = emptied = 0

    for cls, m, static, dyn in broken_rules(css):
        payload = ";".join(dyn)
        # The call site must carry the class in a quoted attribute we can extend.
        targets = [(p, t) for p, t in files.items() if cls in t]
        if not targets:
            print(f"  SKIP {cls}: no call site")
            skipped += 1
            continue

        ok = True
        for p, _ in targets:
            text = edits.get(p, files[p])
            # `class="... _ion-s-xxx"` -- extend the tag, not the class list.
            pat = re.compile(r'(class="[^"]*' + re.escape(cls) + r'[^"]*")')
            hit = pat.search(text)
            if not hit:
                print(f"  SKIP {cls}: class attribute not in the expected shape "
                      f"in {p.name}")
                ok = False
                break
            # Does THIS element already carry the attribute? Scoped to the
            # enclosing tag, not a character window: a window wide enough to
            # cover a long tag also reaches the next element, and the four SLA
            # segments are emitted on consecutive lines -- so each repair made
            # the following one look already-done and it was skipped.
            tag_open = text.rfind("<", 0, hit.start())
            tag_close = text.find(">", hit.end())
            tag = text[tag_open:tag_close if tag_close != -1 else hit.end()]
            if "data-ion-style" in tag:
                print(f"  SKIP {cls}: {p.name} already carries data-ion-style")
                ok = False
                break
            edits[p] = pat.sub(lambda mm: mm.group(1) + ' data-ion-style="'
                               + payload + '"', text)
        if not ok:
            skipped += 1
            continue

        css_out.append(css[last:m.start()])
        if static:
            sel = m.group("sel")
            css_out.append(f"{sel}{{ {'; '.join(static)}; }}")
        else:
            # Nothing static was left, so the rule goes -- and with it the
            # reason the class exists. Leaving the name on the element is not
            # harmless bookkeeping: tests/test_migrated_css_sweep.py asserts
            # every _ion-s-* class at a call site still resolves, precisely so
            # that a half-finished migration cannot hide behind a class that
            # looks meaningful and does nothing. Verified first that no
            # querySelector, classList or closest() call reads any of them.
            for p in list(edits):
                edits[p] = drop_class(edits[p], cls)
            emptied += 1
        last = m.end()
        fixed += 1
        print(f"  {cls}")
        print(f"      moved : {payload[:110]}")
        print(f"      kept  : {'; '.join(static)[:110] or '(rule deleted)'}")

    css_out.append(css[last:])
    new_css = "".join(css_out)

    print(f"\n{fixed} rule(s) repaired, {emptied} left empty and deleted, "
          f"{skipped} skipped")
    print(f"{len(edits)} template/JS file(s) touched")

    if new_css.count("{") != new_css.count("}"):
        print("REFUSED: braces unbalanced")
        return 1
    for p, t in edits.items():
        if t.count("\n") != files[p].count("\n"):
            print(f"REFUSED: {p.name} changed line count")
            return 1
    if JS_IN_VALUE.search(re.sub(r"/\*.*?\*/", "", new_css, flags=re.S)):
        left = [m.group(0)[:60] for m in
                re.finditer(r"\{[^{}]*'\s*\+[^{}]*\}", new_css)]
        print(f"WARNING: {len(left)} rule(s) still carry JS: {left[:3]}")

    if not args.write:
        print("\nDRY RUN - pass --write")
        return 0

    CSS.write_text(new_css, encoding="utf-8", newline="")
    for p, t in edits.items():
        p.write_text(t, encoding="utf-8", newline="")
    print("written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
