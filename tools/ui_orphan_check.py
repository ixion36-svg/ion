"""Find elements left unstyled when a restyle drops a CSS ancestor class.

THE FAILURE MODE
----------------
A page's `<style>` block says:

    .form-group       { margin-bottom: 1.25rem; }
    .form-group label { display: block; font-weight: 600; }

A restyle converts the wrapper to utilities and drops `form-group`. The first
rule becomes inert, which is fine and expected. The second rule stops matching
anything, and every label inside that wrapper now renders with no styling at
all.

Nothing else in this repo catches it. `ui_rewrite_audit.py` counts hashed
classes and inline styles, both unchanged. `ui_spot_check.py` reads JS<->CSS
contracts, and no JavaScript is involved. The class was removed deliberately,
the rule is still in the file, and the page still renders. It only shows up by
looking at it.

It was found on settings.html, where dropping `.form-group` would have left all
43 labels unstyled. A sweep of the nine pages restyled at that point turned up
69 orphaned rules; exactly one, a checkbox on alerts.html that lost its 16px
sizing, was a real regression. That ratio is the whole design problem here: a
naive check drowns you in false positives.

WHY IT WORKS THE WAY IT DOES
----------------------------
Two cheaper approaches were tried first and both were wrong.

Reporting the orphaned RULE over-reports badly: agents routinely re-home the
styling onto the descendants themselves (ion-select on the selects, utilities
on the labels), so the rule is dead but nothing is unstyled.

Asking "is there a bare <h3> anywhere on the page" over-reports differently: it
finds unrelated bare headings elsewhere in the file and says nothing about the
specific descendants the orphaned rule used to match. On cases.html it pointed
at an analytics heading that had never been inside the modal header at all.

So this walks the OLD markup with a real parser, keeping an ancestor stack, and
collects the elements that genuinely matched `.parent TAG`. Each is identified
by id where it has one and by its text otherwise, then located in the NEW markup
and checked for a class attribute. An element that matched an orphaned rule and
is still classless is a real, visible regression.

Margin-only rules on headings are skipped: the reset already zeroes heading
margins, browser-verified, so those rules were inert before the restyle too.

USAGE
-----
    python tools/ui_orphan_check.py --changed
    python tools/ui_orphan_check.py --pages settings.html alerts.html
    python tools/ui_orphan_check.py --pages foo.html --against HEAD~3

Exit status is 1 if any element is left unstyled, so it can gate a commit.

LIMITS
------
A heuristic, like the rest of the UI tooling. It reads the template's own
`<style>` block, not the shared stylesheets, so an ancestor rule that lives in
style.css is invisible to it. It matches text-identified elements by prefix,
so two sibling elements with the same opening text can be conflated. Treat a
finding as "go and look at this", not as proof.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TEMPLATES = REPO / "src/ion/web/templates"

BLOCK = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.S | re.I)
STYLE = re.compile(r"<style\b[^>]*>(.*?)</style>", re.S | re.I)
HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
# Elements with no closing tag, so they must not be pushed on the ancestor stack.
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr"}


def blank_blocks(text: str) -> str:
    """Blank out <script>/<style> content, preserving offsets and line numbers."""
    for m in reversed(list(BLOCK.finditer(text))):
        text = text[:m.start()] + " " * (m.end() - m.start()) + text[m.end():]
    return text


def classes_used(markup: str) -> set[str]:
    out: set[str] = set()
    for m in re.finditer(r'class="([^"{}]+)"', markup):
        out.update(m.group(1).split())
    return out


class Descendants(HTMLParser):
    """Every `tag` element sitting under an ancestor carrying `parent`."""

    def __init__(self, parent: str, tag: str) -> None:
        super().__init__(convert_charrefs=True)
        self.parent = parent
        self.tag = tag
        self.stack: list[tuple[str, set[str]]] = []
        self.hits: list[dict] = []
        self._open: dict | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        d = dict(attrs)
        if tag == self.tag and any(self.parent in cs for _, cs in self.stack):
            self._open = {"id": d.get("id"), "text": ""}
            self.hits.append(self._open)
        if tag not in VOID:
            self.stack.append((tag, set((d.get("class") or "").split())))

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == self.tag:
            self._open = None
        while self.stack:
            if self.stack.pop()[0] == tag:
                break

    def handle_data(self, data: str) -> None:
        if self._open is not None:
            self._open["text"] += data


def orphaned_rules(old_markup: str, new_markup: str, styles: str):
    """(ancestor, descendant tag, selector, declarations) for each broken rule."""
    lost = classes_used(old_markup) - classes_used(new_markup)
    found = set()
    for cls in sorted(lost):
        pattern = re.compile(r"[^{}\n]*\." + re.escape(cls) + r"(?![-\w])[^{}]*\{")
        for m in pattern.finditer(styles):
            body = styles[m.end():styles.find("}", m.end())]
            decls = " ".join(body.split())
            for part in (p.strip() for p in m.group(0).rstrip("{").split(",")):
                if "." + cls not in part:
                    continue
                tail = part.split("." + cls, 1)[1]
                if not tail or not (tail[0].isspace() or tail[0] in ">+~"):
                    continue          # .cls:hover / .cls.other -- same element
                dm = re.match(r"^\s*[>+~]?\s*([a-zA-Z][a-zA-Z0-9]*)", tail)
                if not dm:
                    continue
                tag = dm.group(1).lower()
                # Heading margins are already zeroed by the reset.
                if tag in HEADINGS and re.fullmatch(r"(margin[^:]*:[^;]*;?\s*)+",
                                                    decls or "x"):
                    continue
                found.add((cls, tag, part.strip(), decls))
    return sorted(found)


def still_unstyled(new_raw: str, tag: str, hit: dict) -> tuple[bool, str]:
    """Is the element that matched the orphaned rule still without a class?"""
    if hit["id"]:
        m = re.search(rf'<{tag}\b[^>]*\bid="{re.escape(hit["id"])}"[^>]*>', new_raw)
        if not m:
            return False, f'id={hit["id"]} (element gone)'
        return 'class="' not in m.group(0), f'id={hit["id"]}'
    text = " ".join(hit["text"].split())[:40]
    if not text:
        return False, "(no text, cannot locate)"
    for m in re.finditer(rf"<{tag}\b[^>]*>", new_raw):
        following = " ".join(new_raw[m.end():m.end() + 200].split())
        if following.startswith(text[:25]):
            return 'class="' not in m.group(0), f'"{text[:30]}"'
    return False, f'"{text[:30]}" (not found)'


def previous_revision(rel: str, against: str | None) -> str:
    """The version to compare against: an explicit ref, else the commit before
    the one that last touched this file (so it works after committing)."""
    if against:
        ref = against
    else:
        revs = subprocess.run(["git", "log", "--format=%H", "-n", "2", "--", rel],
                              capture_output=True, text=True, encoding="utf-8",
                              cwd=REPO).stdout.split()
        if not revs:
            return ""
        # Uncommitted work: compare against HEAD. Otherwise the parent commit.
        dirty = subprocess.run(["git", "status", "--porcelain", "--", rel],
                               capture_output=True, text=True, encoding="utf-8",
                               cwd=REPO).stdout.strip()
        ref = revs[0] if dirty else (revs[1] if len(revs) > 1 else "")
        if not ref:
            return ""
    return subprocess.run(["git", "show", f"{ref}:{rel}"], capture_output=True,
                          text=True, encoding="utf-8", errors="replace",
                          cwd=REPO).stdout


def changed_templates() -> list[str]:
    out = subprocess.run(["git", "status", "--porcelain", "src/ion/web/templates/"],
                         capture_output=True, text=True, encoding="utf-8",
                         cwd=REPO).stdout
    names = []
    for line in out.splitlines():
        p = line[3:].strip()
        if p.endswith(".html"):
            names.append(str(Path(p).relative_to("src/ion/web/templates")).replace("\\", "/"))
    return names


def check(name: str, against: str | None) -> list[tuple[str, str, str]]:
    rel = f"src/ion/web/templates/{name}"
    path = REPO / rel
    if not path.is_file():
        return []
    new_raw = path.read_text(encoding="utf-8", errors="replace")
    old_raw = previous_revision(rel, against)
    if not old_raw:
        return []
    old, new = blank_blocks(old_raw), blank_blocks(new_raw)
    styles = "".join(STYLE.findall(new_raw))
    findings = []
    for parent, tag, selector, decls in orphaned_rules(old, new, styles):
        parser = Descendants(parent, tag)
        parser.feed(old)
        for hit in parser.hits:
            bad, ident = still_unstyled(new_raw, tag, hit)
            if bad:
                findings.append((selector, ident, decls))
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pages", nargs="*", help="template names, e.g. settings.html")
    ap.add_argument("--changed", action="store_true",
                    help="every modified template in the working tree")
    ap.add_argument("--against", help="git ref to compare against (default: the "
                                      "commit before this file last changed)")
    args = ap.parse_args()

    pages = changed_templates() if args.changed else (args.pages or [])
    if not pages:
        print("use --pages or --changed", file=sys.stderr)
        return 2

    total = 0
    for name in pages:
        findings = check(name, args.against)
        total += len(findings)
        print(f"[{'LOOK' if findings else 'OK  '}] {name}")
        # One line per rule, not per element. A table header rule fires on all
        # 13 <th> and printing each is noise, not information.
        grouped: dict[tuple[str, str], list[str]] = {}
        for selector, ident, decls in findings:
            grouped.setdefault((selector, decls), []).append(ident)
        for (selector, decls), idents in grouped.items():
            n = len(idents)
            where = idents[0] if n == 1 else f"{n} elements, e.g. {idents[0]}"
            print(f"        {selector}  ->  {where}")
            print(f"            lost: {decls[:100]}")
    print(f"\n{len(pages)} page(s) checked, {total} element(s) left unstyled")
    print("Reads the template's own <style> block only, not the shared sheets:")
    print("a descendant now covered by daisyUI (a <th> under .table, say) still")
    print("reports here. Confirm against the built ion.css before acting.")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
