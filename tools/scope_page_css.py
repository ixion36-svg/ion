"""Scope each page's rules in ion-pages.css so they cannot bleep onto other pages.

Why this exists. Passing the redesign's `styled` column means deleting a
template's inline `<style>` and putting those rules in the compiled sheet. An
inline block is implicitly scoped: only the page carrying it is affected.
Concatenating many pages' blocks into one sheet throws that away, and the last
definition of a shared selector wins everywhere.

Both failure modes were observed, not predicted:

  * Tier B's flat merge changed `.se-header` padding on /templates/new from
    0px to 9.6px/16px, because template_form.html and template_render.html
    both define `.se-*` rules and the merge let one win on both pages.
    tools/style_snapshot.py caught it.
  * Tier A's merge put guide.html's `@media print` block into the global
    sheet, so every page in ION printed with `body { background:#fff
    !important; color:#333 !important }`. A screen-media snapshot reported
    zero changes, correctly, and could not see it. 11 selectors collide
    across the 33 page chunks, `body`, `.navbar`, `.card` and `.stat`
    among them.

So every rule is prefixed with `body[data-page="<page>"]`, and base.html
carries that attribute from a `page_id` block each template fills.

    python tools/scope_page_css.py --check    # report what would change
    python tools/scope_page_css.py --apply

Rules that must NOT be rewritten:

  * `@keyframes` bodies. Their "selectors" are percentages and from/to
    keywords, and three pages define a `to` step, which a naive pass would
    have turned into `body[data-page=x] to { ... }`.
  * `@font-face`, `@import`, `@charset`, `@property`: no selector list.

`:root` becomes the scoped body selector, so page-local custom properties
land on an element the page's own content descends from and still inherit.
`body` itself becomes `body[data-page="x"]` rather than gaining a descendant
prefix, which would never match.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SHEET = ROOT / "frontend" / "ion-pages.css"
CHUNK = re.compile(r"/\* ── ([a-z_]+)\.html [─]+ \*/")

#: At-rules whose block holds declarations or steps, never selectors.
OPAQUE = re.compile(r"@(?:keyframes|font-face|property|charset|import|namespace)\b", re.I)
#: At-rules whose block holds ordinary rules that still need scoping.
NESTING = re.compile(r"@(?:media|supports|layer|container)\b", re.I)


def _scope_selector(sel: str, scope: str) -> str:
    sel = sel.strip()
    if not sel:
        return sel
    if sel.startswith(":root"):
        return scope + sel[len(":root"):]
    if sel == "body" or sel.startswith(("body.", "body:", "body[", "body ", "body>")):
        return scope + sel[len("body"):]
    if sel.startswith(("html", "*")):
        # Leave document-level selectors alone; a page sheet should not be
        # reaching them, and prefixing would silently stop them matching.
        return sel
    return f"{scope} {sel}"


def scope_block(css: str, scope: str) -> tuple[str, int]:
    """Prefix every selector in `css`, descending into @media and friends.

    Comments are emitted verbatim and skipped before the selector head is
    read. The first version did not, so a comment sitting above an at-rule
    was swallowed into the head: `/* Print: hide chrome. */\\n@media print {`
    did not start with `@`, took the ordinary-rule branch, and produced

        body[data-page="guide"] /* Print... */ @media print{ ... }

    which is invalid. Tailwind then dropped the whole block without a word,
    so guide.html lost the print styling it had carried for releases and
    `body[data-page="guide"]` appeared zero times in the build. Found by
    checking a page's own print rule still applied after scoping, not by
    reading the output.
    """
    out, i, n, changed = [], 0, len(css), 0
    while i < n:
        # Emit whitespace and comments, then look at what actually follows.
        j = i
        while j < n:
            if css[j].isspace():
                j += 1
                continue
            if css.startswith("/*", j):
                close = css.find("*/", j + 2)
                j = n if close == -1 else close + 2
                continue
            break
        if j > i:
            out.append(css[i:j])
            i = j
        if i >= n:
            break

        brace = css.find("{", i)
        if brace == -1:
            out.append(css[i:])
            break
        head = css[i:brace]
        stripped = head.strip()

        if stripped.startswith("@"):
            # find the matching close brace
            depth, j = 0, brace
            while j < n:
                if css[j] == "{":
                    depth += 1
                elif css[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            body = css[brace + 1:j]
            if OPAQUE.match(stripped):
                out.append(css[i:j + 1])
            elif NESTING.match(stripped):
                inner, k = scope_block(body, scope)
                changed += k
                out.append(head + "{" + inner + "}")
            else:
                out.append(css[i:j + 1])
            i = j + 1
            continue

        close = css.find("}", brace)
        if close == -1:
            out.append(css[i:])
            break
        sels = [_scope_selector(s, scope) for s in head.split(",")]
        if any(a.strip() != b.strip() for a, b in zip(sels, head.split(","))):
            changed += 1
        # Preserve the leading whitespace of the original head.
        lead = head[:len(head) - len(head.lstrip())]
        out.append(lead + ", ".join(s.strip() for s in sels) + css[brace:close + 1])
        i = close + 1
    return "".join(out), changed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    src = SHEET.read_text(encoding="utf-8")
    marks = list(CHUNK.finditer(src))
    if not marks:
        print("no page chunks found")
        return 1

    pieces, total = [src[: marks[0].start()]], 0
    for idx, m in enumerate(marks):
        page = m.group(1)
        end = marks[idx + 1].start() if idx + 1 < len(marks) else len(src)
        body = src[m.end():end]
        if f'body[data-page="{page}"]' in body:
            pieces.append(m.group(0) + body)
            print(f"  {page:26} already scoped, skipped")
            continue
        scoped, n = scope_block(body, f'body[data-page="{page}"]')
        total += n
        pieces.append(m.group(0) + scoped)
        print(f"  {page:26} {n} selector list(s) scoped")

    print(f"\n{total} selector list(s) across {len(marks)} page(s)")
    if args.apply:
        SHEET.write_text("".join(pieces), encoding="utf-8")
        print(f"wrote {SHEET}")
    else:
        print("dry run, pass --apply")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
