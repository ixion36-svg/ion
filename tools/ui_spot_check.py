"""Spot-check rewritten templates for the failures no regex-on-markup catches.

The tranche verifier checks CSP bookkeeping: hashed classes present or absent,
raw inline styles at zero. It cannot see a broken JS<->CSS contract, which is
the failure mode that actually bit the pilot page — its JavaScript toggles
`.active` while daisyUI 5 opens modals via `modal-open`, so swapping in daisyUI
markup naively would have stopped the dialog opening with no error anywhere.

This checks three contracts:

  ADDED    a class JavaScript adds/toggles must be matched by some CSS rule,
           or adding it does nothing
  QUERIED  a selector JavaScript looks up must exist in the markup, or the
           lookup returns null
  IDS      an id JavaScript getElementById's must exist in the markup

All three fail silently in a browser: no error, no console warning, no failed
request. That is the whole reason this exists.

It is a heuristic, not a proof. It reads only the template's own <script>
blocks and cannot follow into static/js/. Treat findings as "look at this",
not "this is broken".

Usage:
    python tools/ui_spot_check.py --pages a.html b.html
    python tools/ui_spot_check.py --sample 3 --band M
    python tools/ui_spot_check.py --changed          # every modified template
"""

from __future__ import annotations

import argparse
import json
import random
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TEMPLATES = REPO / "src/ion/web/templates"
BASELINE = REPO / "tools/ui_rewrite_baseline.json"
# What a class can currently be satisfied by.
CSS_CURRENT = [
    REPO / "src/ion/web/static/css/ion.css",
    REPO / "src/ion/web/static/css/ion-migrated-styles.css",
    REPO / "src/ion/web/static/css/style.css",
    REPO / "src/ion/web/static/css/ion-ui.css",
]
# What will remain once the legacy sheets are retired. --strict checks against
# this, so it reports what BREAKS when style.css and friends are deleted.
#
# This distinction matters: style.css alone carries 25 `.active` rules, so a
# lenient check finds the class "defined somewhere" in 400KB of CSS and passes
# even when the specific contract is broken. That produced a false negative on
# the pilot page during development of this tool.
CSS_POST_LEGACY = [
    REPO / "src/ion/web/static/css/ion.css",
]
BANDS = {"XL": (2500, 10**9), "L": (1000, 2500), "M": (300, 1000), "S": (0, 300)}

SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)
STYLE = re.compile(r"<style\b[^>]*>(.*?)</style>", re.DOTALL | re.IGNORECASE)
CLASS_ADD = re.compile(r"classList\.(?:add|toggle|replace)\(\s*['\"]([A-Za-z0-9_-]+)['\"]")
QUERY_CLASS = re.compile(r"querySelector(?:All)?\(\s*['\"]\.([A-Za-z0-9_-]+)")
GET_BY_ID = re.compile(r"getElementById\(\s*['\"]([A-Za-z0-9_:-]+)['\"]")
QUERY_ID = re.compile(r"querySelector(?:All)?\(\s*['\"]#([A-Za-z0-9_:-]+)")

# Only classes owned by a library that injects its own CSS at runtime.
#
# Deliberately NOT ignoring "active", "show", "open", "selected", "collapsed":
# those look like inert behavioural markers but they are precisely the ones a
# daisyUI migration breaks. The pilot page toggles `.active` to open its modal
# while daisyUI uses `modal-open`. Ignoring them would blind this tool to the
# one failure it was written to catch.
IGNORE = {
    "htmx-request", "htmx-settling", "htmx-swapping", "htmx-added",
}


def css_corpus(strict: bool) -> str:
    files = CSS_POST_LEGACY if strict else CSS_CURRENT
    return "\n".join(p.read_text(encoding="utf-8", errors="replace")
                     for p in files if p.is_file())


def check(page: str, css: str) -> list[str]:
    path = TEMPLATES / page
    if not path.is_file():
        return [f"missing file: {page}"]
    text = path.read_text(encoding="utf-8", errors="replace")
    scripts = "\n".join(SCRIPT.findall(text))
    own_style = "\n".join(STYLE.findall(text))
    markup = SCRIPT.sub("", text)          # markup minus inline JS
    all_css = css + "\n" + own_style
    findings = []

    for cls in sorted(set(CLASS_ADD.findall(scripts))):
        if cls in IGNORE:
            continue
        if not re.search(r"\." + re.escape(cls) + r"[\s,:.\[{)>~+]", all_css):
            findings.append(
                f"ADDED   .{cls} — JS adds it, no CSS rule matches (adding it does nothing)")

    for cls in sorted(set(QUERY_CLASS.findall(scripts))):
        if cls in IGNORE:
            continue
        # Whole file, same reason as the id check below: classes are routinely
        # emitted from JS template literals, and those are real markup at
        # runtime even though they sit inside a <script> block.
        if not re.search(r'class="[^"]*\b' + re.escape(cls) + r'\b', text) \
           and not re.search(r"\." + re.escape(cls) + r"[\s,:.\[{)>~+]", all_css):
            findings.append(
                f"QUERIED .{cls} — JS queries it, absent from the template (lookup returns null)")

    for el_id in sorted(set(GET_BY_ID.findall(scripts)) | set(QUERY_ID.findall(scripts))):
        # Search the WHOLE file, not just markup: plenty of ids live inside JS
        # template literals that generate HTML at runtime. Stripping <script>
        # first produced six false positives on stories.html, where every id was
        # present and unchanged but emitted from a template literal.
        #
        # An id ending in a separator is a CONCATENATION PREFIX, not a whole id:
        #   getElementById('mat-domain-score-' + domainId)
        #   id="mat-domain-score-${domain.id}"
        # Demanding an exact match on the prefix produced 16 false positives
        # across 8 pages, so match it as a prefix instead.
        if el_id.endswith(("-", "_")):
            found = re.search(r'id=["\']' + re.escape(el_id), text)
        else:
            found = re.search(r'id="' + re.escape(el_id) + r'"', text) \
                 or re.search(r"id='" + re.escape(el_id) + r"'", text)
        if not found:
            findings.append(
                f"ID      #{el_id} — JS looks it up, no such id anywhere in the template")

    return findings


def changed_templates() -> list[str]:
    out = subprocess.run(["git", "status", "--porcelain", "src/ion/web/templates/"],
                         capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=REPO).stdout
    names = []
    for line in out.splitlines():
        p = line[3:].strip()
        if p.endswith(".html"):
            names.append(str(Path(p).relative_to("src/ion/web/templates")).replace("\\", "/"))
    return names


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", nargs="*")
    ap.add_argument("--band", choices=list(BANDS))
    ap.add_argument("--sample", type=int, default=3)
    ap.add_argument("--changed", action="store_true")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--strict", action="store_true",
                    help="check only against ion.css — what breaks when the "
                         "legacy sheets are deleted")
    args = ap.parse_args()

    if args.changed:
        pages = changed_templates()
    elif args.pages:
        pages = args.pages
    elif args.band:
        base = json.loads(BASELINE.read_text(encoding="utf-8"))
        lo, hi = BANDS[args.band]
        pool = [n for n, v in base.items() if lo <= v["lines"] < hi]
        random.seed(args.seed)
        pages = random.sample(pool, min(args.sample, len(pool)))
    else:
        print("use --pages, --band or --changed", file=sys.stderr)
        return 2

    css = css_corpus(args.strict)
    total = 0
    for page in pages:
        findings = check(page, css)
        total += len(findings)
        mark = "OK  " if not findings else "LOOK"
        print(f"[{mark}] {page}")
        for f in findings:
            print(f"        {f}")
    print(f"\n{len(pages)} page(s) checked, {total} thing(s) to look at")
    scope = "ion.css only (post-legacy)" if args.strict else "all current stylesheets"
    print(f"Checked against: {scope}")
    print("Heuristic only — reads the template's own <script> blocks, not static/js/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
