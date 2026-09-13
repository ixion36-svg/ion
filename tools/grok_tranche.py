"""Run the proven Grok rewrite prompt across a tranche of templates.

Each page is handled independently: back up, delegate, verify, keep or roll
back. A page that fails verification is RESTORED, never left half-rewritten, so
a bad run costs time rather than correctness.

Verification is per-page rather than the global `ui_rewrite_audit.py --check`,
because pages are processed in parallel and a global check cannot attribute a
loss to the page that caused it.

Two failure modes are checked, both invisible in a browser:
  - a lost `_ion-s-*` hashed class  -> silently unstyled element
  - a new raw `style="..."`         -> silently refused by style-src-attr 'none'

Not checked here, and the reason a human still reviews: a broken JS<->CSS
contract. The pilot page's JS toggles `.active` while daisyUI opens modals via
`modal-open`; nothing in this script would have caught that.

Usage:
    python tools/grok_tranche.py --list M              # show a band, run nothing
    python tools/grok_tranche.py --pages a.html b.html
    python tools/grok_tranche.py --band M --limit 5 --workers 3
    python tools/grok_tranche.py --band M --dry-run
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

GROK = Path("C:/Users/lyndo/.grok/bin/grok")
REPO = Path(__file__).resolve().parent.parent
TEMPLATES = REPO / "src/ion/web/templates"
BASELINE = REPO / "tools/ui_rewrite_baseline.json"
RESULTS = REPO / "tools/grok_tranche_results.json"

HASHED = re.compile(r"_ion-s-[a-z0-9]+")
INLINE_STYLE = re.compile(r'(?<![-\w])style\s*=\s*["\']')

# base.html is the shared layout for all 114 pages. Rewriting it in a batch
# would change every page at once with no way to attribute a regression.
# It gets its own dedicated pass, deliberately.
NEVER_BATCH = {"base.html", "_components.html", "_icons.html", "_nav_tabs.html"}

# Directory prefixes that must never be restyled onto daisyUI.
#
# emails/ are standalone documents delivered to mail clients. They do NOT
# extend base.html and CANNOT load /static/css/ion.css, so their styling has to
# be inline `style="..."` on table-based markup — exactly what the rewrite
# prompt forbids everywhere else. A restyle pass stripped all 81 inline styles
# across the three of them and replaced them with daisyUI classes, which would
# have rendered every ION notification email completely unstyled. The verifier
# missed it because inline styles went DOWN and it only flagged increases.
NEVER_BATCH_PREFIXES = ("emails/",)

# Templates that are SELF-CONTAINED: no `{% extends %}`, no <link rel=stylesheet>.
# Whatever styling they carry must be inline, because nothing else will ever
# reach them. Two kinds exist in ION:
#   emails/*            delivered to mail clients, which load no stylesheet
#   *_pdf.html          rendered by WeasyPrint through a bare Jinja Environment
#                       (see _render_scoping_pack_pdf_html) that injects no CSS
#
# The restyle prompt forbids inline styles, which is right for every page that
# loads ion.css and exactly wrong for these. A pass stripped all 84 inline
# styles across the four of them.
SELF_CONTAINED = {
    "emails/alert_digest.html",
    "emails/case_update.html",
    "emails/sla_breach.html",
    "cyab/_scoping_pack_pdf.html",
}


def is_self_contained(text: str) -> bool:
    """Detect the shape rather than trusting the list above to stay current."""
    return "{% extends" not in text and "stylesheet" not in text

BANDS = {"XL": (2500, 10**9), "L": (1000, 2500), "M": (300, 1000), "S": (0, 300)}


def load_baseline() -> dict:
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def pick_band(baseline: dict, band: str) -> list[str]:
    lo, hi = BANDS[band]
    names = [n for n, v in baseline.items()
             if lo <= v["lines"] < hi and n not in NEVER_BATCH
             and not n.startswith(NEVER_BATCH_PREFIXES)
             and n not in SELF_CONTAINED]
    # Lowest hashed-class count first: least CSP risk earliest, so an early
    # failure is cheap and tells us the prompt is wrong before the risky pages.
    return sorted(names, key=lambda n: (baseline[n]["hashed_count"], baseline[n]["lines"]))


def load_map() -> dict:
    p = REPO / "tools/hashed_class_map.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}


def build_prompt(page: str, mode: str) -> str:
    if mode == "convert":
        base = (REPO / "tools/grok_convert_prompt.md").read_text(encoding="utf-8")
        return base.replace("<PAGE>.html", page)
    base = (REPO / "tools/grok_rewrite_prompt.md").read_text(encoding="utf-8")
    # Strip the reviewer's retrospective; Grok only needs the instructions.
    base = base.split("## Observed behaviour", 1)[0].rstrip()
    return base.replace("security_dashboard.html", page)


def verify(page: str, before_text: str, mode: str) -> list[str]:
    """Return problems for this page only. Empty list means clean.

    The two passes have OPPOSITE expectations about hashed classes:
      restyle - they must all survive; the pass only changes surrounding markup
      convert - they must shrink to the subset with no clean utility equivalent
    Raw inline styles must not increase in either, ever.

    Judged against the file as it was immediately BEFORE this run, not against
    tools/ui_rewrite_baseline.json. The baseline records the original repo state
    and goes stale the moment a page is converted: shift_handover dropped from
    15 hashed classes to 3 in pass 2, so a later restyle checked against the
    baseline would report 12 phantom losses and roll back a perfectly good page.
    """
    path = TEMPLATES / page
    if not path.is_file():
        return [f"{page}: file missing after run"]
    text = path.read_text(encoding="utf-8", errors="replace")
    problems = []
    present = set(HASHED.findall(text))
    before_set = set(HASHED.findall(before_text))

    if mode == "restyle":
        lost = before_set - present
        if lost:
            problems.append(f"lost {len(lost)} hashed class(es): {sorted(lost)[:4]}")
    else:
        cmap = load_map()
        before = before_set

        # Mappable classes MUST be gone -- EXCEPT ones referenced from inside a
        # <script> block. The convert prompt's rule 4 explicitly tells Grok to
        # leave those alone, because converting the markup while JS still looks
        # for the old class name breaks the lookup silently. Failing the page
        # for obeying that instruction is the tooling contradicting itself: it
        # rolled back 5 of 26 M-band pages, and every one of the 9 "missed"
        # classes was inside a script block.
        in_script = set()
        for block in re.findall(r"<script\b[^>]*>(.*?)</script>", text, re.DOTALL | re.I):
            in_script.update(HASHED.findall(block))

        skipped = [c for c in present
                   if cmap.get(c, {}).get("kind") in ("exact", "arbitrary")
                   and c not in in_script]
        if skipped:
            problems.append(
                f"{len(skipped)} mappable class(es) left unconverted: {sorted(skipped)[:4]}"
            )

        # Classes the table could NOT map must remain. Removing one deletes a
        # style with no replacement and renders a silently unstyled element.
        # Not-in-the-map counts here too — four such classes exist and are dead
        # (no CSS rule anywhere), but this pass is not where that is decided.
        must_keep = {c for c in before
                     if c not in cmap or cmap[c].get("kind") == "manual"}
        dropped = sorted(must_keep - present)
        if dropped:
            problems.append(
                f"{len(dropped)} unmappable class(es) removed with no replacement: {dropped[:4]}"
            )

    inline_before = len(INLINE_STYLE.findall(before_text))
    inline_now = len(INLINE_STYLE.findall(text))
    if inline_now > inline_before:
        problems.append(f"raw inline styles {inline_before} -> {inline_now}")
    # A wholesale REMOVAL is equally suspicious. Checking only for increases let
    # the email templates through: 25 inline styles became 0, which is correct
    # for an app page and catastrophic for a document a mail client renders
    # without any stylesheet.
    elif inline_before >= 5 and inline_now == 0:
        problems.append(
            f"all {inline_before} inline styles removed — intended for an app page, "
            f"but fatal if this document is rendered without a stylesheet")
    return problems


def run_one(page: str, baseline: dict, timeout: int, mode: str) -> dict:
    path = TEMPLATES / page
    started = time.time()
    backup = Path(tempfile.gettempdir()) / f"grok-tranche-{page.replace('/', '_')}.bak"
    shutil.copy(path, backup)

    prompt_file = Path(tempfile.gettempdir()) / f"grok-prompt-{page.replace('/', '_')}.md"
    prompt_file.write_text(build_prompt(page, mode), encoding="utf-8")

    result = {"page": page, "mode": mode, "lines_before": baseline[page]["lines"]}

    if mode == "restyle" and is_self_contained(path.read_text(encoding="utf-8", errors="replace")):
        # Caught by shape, not by name: nothing will ever deliver a stylesheet
        # to this document, so its inline styles are the only styling it has.
        result.update(status="SKIPPED", problems=["self-contained (no extends, no stylesheet)"],
                      elapsed=0)
        return result
    try:
        proc = subprocess.run(
            [str(GROK), "--cwd", str(REPO), "--permission-mode", "bypassPermissions",
             "--max-turns", "60", "--prompt-file", str(prompt_file)],
            capture_output=True, text=True, timeout=timeout,
            # Grok emits UTF-8; without this Windows decodes as cp1252 and the
            # reader thread dies on the first non-ASCII byte, losing the output
            # tail used for diagnostics. Seen on the 27-page M-band run.
            encoding="utf-8", errors="replace",
        )
        result["exit"] = proc.returncode
        result["tail"] = (proc.stdout or "")[-400:]
    except subprocess.TimeoutExpired:
        shutil.copy(backup, path)
        result.update(status="TIMEOUT", problems=[f"exceeded {timeout}s"],
                      elapsed=round(time.time() - started))
        return result

    after = path.read_text(encoding="utf-8", errors="replace")
    before_text = backup.read_text(encoding="utf-8", errors="replace")
    result["lines_after"] = after.count("\n") + 1
    result["lines_before_actual"] = before_text.count("\n") + 1

    # Content comparison only. This previously also required the line count to
    # match `baseline[page]["lines"]`, which is the ORIGINAL repo state — for a
    # page already touched by an earlier pass that never matches, so a genuine
    # no-op would slip through as success.
    if after == before_text:
        # Grok explored and wrote nothing. Indistinguishable from success
        # unless checked -- this is exactly what --permission-mode acceptEdits
        # produced on the first pilot run.
        result.update(status="NO_CHANGE", problems=["template unchanged"],
                      elapsed=round(time.time() - started))
        return result

    problems = verify(page, backup.read_text(encoding="utf-8", errors="replace"), mode)
    if problems:
        shutil.copy(backup, path)   # never leave a page half-rewritten
        result.update(status="FAILED", problems=problems, rolled_back=True)
    else:
        result.update(status="OK", problems=[])
    result["elapsed"] = round(time.time() - started)
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--band", choices=list(BANDS))
    ap.add_argument("--pages", nargs="*")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=1200)
    ap.add_argument("--list", dest="list_band", choices=list(BANDS))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--mode", choices=["restyle", "convert"], default="restyle",
                    help="restyle = daisyUI pass 1; convert = hashed-class pass 2")
    args = ap.parse_args()

    baseline = load_baseline()

    if args.list_band:
        for n in pick_band(baseline, args.list_band):
            print(f"{baseline[n]['lines']:5d} lines  {baseline[n]['hashed_count']:4d} hashed  {n}")
        return 0

    pages = args.pages or (pick_band(baseline, args.band) if args.band else [])
    if not pages:
        print("nothing selected; use --band or --pages", file=sys.stderr)
        return 2
    if args.mode == "convert":
        # A page with no hashed classes has nothing to convert. Running Grok on
        # it burns ~8 minutes to produce a guaranteed no-op.
        skipped = [p for p in pages if baseline[p]["hashed_count"] == 0]
        pages = [p for p in pages if baseline[p]["hashed_count"] > 0]
        if skipped:
            print(f"skipping {len(skipped)} page(s) with 0 hashed classes")

    if args.limit:
        pages = pages[: args.limit]

    blocked = [p for p in pages
               if p in NEVER_BATCH or p.startswith(NEVER_BATCH_PREFIXES)
               or p in SELF_CONTAINED]
    if blocked:
        # --pages bypasses pick_band, so the exclusion has to be enforced here
        # too. This is how the email templates got through.
        print(f"refusing {len(blocked)} excluded page(s): {blocked}", file=sys.stderr)
        pages = [p for p in pages if p not in blocked]
        if not pages:
            return 2

    print(f"tranche[{args.mode}]: {len(pages)} page(s), {args.workers} worker(s)")
    for p in pages:
        print(f"  {baseline[p]['lines']:5d} lines  {baseline[p]['hashed_count']:4d} hashed  {p}")
    if args.dry_run:
        return 0

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(run_one, p, baseline, args.timeout, args.mode): p for p in pages}
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            flag = {"OK": "ok  ", "FAILED": "FAIL", "NO_CHANGE": "noop",
                    "TIMEOUT": "TIME", "SKIPPED": "skip"}.get(r["status"], "????")
            extra = f" {r['problems']}" if r["problems"] else ""
            # lines_before_actual is the file as it was before THIS run;
            # lines_before comes from the baseline and is the original repo
            # state, which for an already-touched page is misleading. Reporting
            # the baseline made a 2-line conversion look like +152 lines.
            lb = r.get("lines_before_actual", r["lines_before"])
            print(f"[{flag}] {r['page']} ({r.get('elapsed','?')}s)"
                  f" {lb}->{r.get('lines_after','?')}{extra}", flush=True)

    RESULTS.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    ok = sum(1 for r in results if r["status"] == "OK")
    print(f"\n{ok}/{len(results)} OK -> {RESULTS}")
    print("Failed and no-change pages were left at their original content.")
    print("Still required: human review of each OK page for JS<->CSS contracts.")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
