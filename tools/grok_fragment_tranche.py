"""Run the fragment conversion across a tranche of pages with Grok.

Companion to grok_tranche.py, which does the restyle pass. This one does the
`server` column: moving a page's JavaScript-built markup into a Jinja
fragment served over htmx.

Same contract as its sibling, for the same reason. Each page is handled
independently: snapshot, delegate, verify, keep or roll back. A page that
fails verification is RESTORED and any file Grok created for it is removed,
so a bad run costs time rather than correctness.

It is harder to roll back than a restyle, because a conversion CREATES
files. Reverting the page alone would leave an orphan module behind, and
ion/web/ui discovers modules, so an orphan is mounted at startup and a
half-written one takes the app down. The snapshot therefore records which
of the page's owned paths existed beforehand, and anything else is deleted
on failure.

What is checked here, all of it local and offline:

  - the page's runtime write count reaches 0, using ui_redesign_status's
    own regex rather than a second copy of it
  - the module imports, exposes a router, and mounts under /ui
  - every template the module names exists on disk
  - the shared registry guards still pass, which covers authentication, the
    licence gate on a de_* page, the HTML response class and the
    page-redirect prohibition
  - the page's own test file passes
  - whatever JavaScript is left parses

What is NOT checked here, and why a human still reviews every page:

  - that the fragment is HONEST. Nothing offline can tell that an
    unmeasured figure renders as unknown rather than as zero, or that a
    failed read says so instead of showing an empty table. That is the
    whole point of the conversion and it is the reviewer's job.
  - that it works in a browser. htmx swaps, a CSP-blocked event filter and
    a control that vanishes with a failed render are invisible to every
    check above. One converted page shipped a dead Enter key that only a
    browser console revealed.

Usage:
    python tools/grok_fragment_tranche.py --list
    python tools/grok_fragment_tranche.py --pages de_proposals de_bob
    python tools/grok_fragment_tranche.py --pages de_bob --dry-run
    python tools/grok_fragment_tranche.py --pages a b c --workers 2
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
FRAGMENTS = TEMPLATES / "_fragments"
UI = REPO / "src/ion/web/ui"
TESTS = REPO / "tests/unit"
RESULTS = REPO / "tools/grok_fragment_results.json"
VENV_PY = Path("C:/Users/lyndo/projects/ION/.venv/Scripts/python.exe")

# The same expression tools/ui_redesign_status.py measures with. Imported
# rather than retyped would be better, but that module is a script with a
# side-effecting main; one regex copied with a comment saying where it came
# from is the smaller evil, and a test holds the two to each other.
WRITES = re.compile(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=")
SCRIPT = re.compile(r"<script[^>]*>(.*?)</script>", re.S)

# Never hand these to a batch. base.html is the shared layout for every
# page, and the _fragments helpers are imported by the fragments themselves.
NEVER_BATCH = {"base.html", "_components.html", "_icons.html", "_nav_tabs.html"}

BRIEF = REPO / "docs/UI_FRAGMENT_CONVERSION.md"


def owned_paths(page: str) -> list[Path]:
    """Every path a conversion of `page` is allowed to create or edit."""
    stem = page.removesuffix(".html")
    return [
        TEMPLATES / f"{stem}.html",
        UI / f"{stem}.py",
        TESTS / f"test_ui_fragment_{stem}.py",
        *sorted(FRAGMENTS.glob(f"{stem}*.html")),
    ]


def snapshot(page: str, tmp: Path) -> dict:
    """Copy what exists and record what does not, so both can be undone."""
    stem = page.removesuffix(".html")
    existed, backups = [], {}
    for path in owned_paths(page):
        if path.exists():
            existed.append(str(path))
            dest = tmp / path.name
            shutil.copy(path, dest)
            backups[str(path)] = str(dest)
    return {"stem": stem, "existed": existed, "backups": backups}


def roll_back(snap: dict) -> list[str]:
    """Restore every file that existed, delete every file that did not."""
    undone = []
    for original, backup in snap["backups"].items():
        shutil.copy(backup, original)
        undone.append(f"restored {Path(original).name}")
    existed = set(snap["existed"])
    stem = snap["stem"]
    candidates = [
        UI / f"{stem}.py",
        TESTS / f"test_ui_fragment_{stem}.py",
        *sorted(FRAGMENTS.glob(f"{stem}*.html")),
    ]
    for path in candidates:
        if path.exists() and str(path) not in existed:
            path.unlink()
            undone.append(f"deleted {path.name}")
    # A deleted module leaves bytecode that pkgutil still lists as a module,
    # so discovery would import a file that is no longer there.
    cache = UI / "__pycache__"
    if cache.exists():
        for stale in cache.glob(f"{stem}.*"):
            stale.unlink()
    return undone


def inline_js(html: str) -> str:
    return "\n".join(SCRIPT.findall(html))


def write_count(page: str) -> int:
    """Runtime writes, counted the way ui_redesign_status.py counts them.

    Over the inline <script> bodies only, not the whole file. Counting the
    whole file rolled back correct pages: a conversion's own comments quote
    the thing they removed, as in "it used to do container.innerHTML =",
    and several converted pages carry exactly that sentence. The status
    tool never saw them because it only ever looked inside <script>.

    JavaScript comments are stripped too, for the same reason one step in:
    a surviving comment explaining why a write is gone should not count as
    the write.
    """
    path = TEMPLATES / page
    if not path.exists():
        return -1
    js = inline_js(path.read_text(encoding="utf-8"))
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
    js = re.sub(r"(?m)^\s*//.*$", "", js)
    return len(WRITES.findall(js))


def _run(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=str(REPO), capture_output=True, text=True, timeout=timeout,
        # Grok emits UTF-8. Without this Windows decodes as cp1252 and the
        # reader dies on the first non-ASCII byte, losing the diagnostic
        # tail. Recorded in grok_tranche.py from the 27-page M-band run.
        encoding="utf-8", errors="replace",
    )


def verify(page: str) -> tuple[bool, list[str]]:
    """Every offline check. Returns (ok, notes), notes always populated."""
    stem = page.removesuffix(".html")
    notes: list[str] = []
    ok = True

    writes = write_count(page)
    notes.append(f"writes={writes}")
    if writes != 0:
        ok = False
        notes.append("FAIL the page still builds markup in JavaScript")

    module = UI / f"{stem}.py"
    if not module.exists():
        return False, notes + [f"FAIL no {module.name}, nothing was wired up"]

    # Import through the package, which is how the app loads it, so a module
    # that imports alone but breaks discovery still fails here.
    probe = _run([
        str(VENV_PY), "-c",
        "import sys; sys.path.insert(0, 'src');"
        "import ion.web.ui as ui;"
        f"m = __import__('ion.web.ui.{stem}', fromlist=['router']);"
        "assert getattr(m, 'router', None) is not None, 'no router';"
        "paths = [r.path for r in ui.router.routes];"
        f"mine = [r.path for r in m.router.routes];"
        "assert all('/ui'+p in paths for p in mine), 'declared but not mounted';"
        "print('mounted', mine)",
    ], timeout=180)
    notes.append((probe.stdout or probe.stderr or "").strip().splitlines()[-1][:160]
                 if (probe.stdout or probe.stderr) else "import produced no output")
    if probe.returncode != 0:
        return False, notes + ["FAIL the module does not import or does not mount"]

    js = inline_js((TEMPLATES / page).read_text(encoding="utf-8"))
    if js.strip():
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                         encoding="utf-8") as fh:
            fh.write(js)
            js_path = fh.name
        node = _run(["node", "--check", js_path], timeout=120)
        Path(js_path).unlink(missing_ok=True)
        notes.append(f"node --check exit={node.returncode}")
        if node.returncode != 0:
            ok = False
            notes.append(f"FAIL remaining JavaScript does not parse: "
                         f"{(node.stderr or '')[:160]}")
    else:
        notes.append("no inline JavaScript left")

    test_file = TESTS / f"test_ui_fragment_{stem}.py"
    targets = ["tests/unit/test_ui_fragment_registry.py"]
    if test_file.exists():
        targets.insert(0, f"tests/unit/test_ui_fragment_{stem}.py")
    else:
        ok = False
        notes.append("FAIL no test file was written")
    pytest = _run([str(VENV_PY), "-m", "pytest", *targets, "-q"], timeout=900)
    tail = (pytest.stdout or "").strip().splitlines()
    notes.append(tail[-1][:160] if tail else "pytest produced no output")
    if pytest.returncode != 0:
        ok = False
        notes.append("FAIL tests do not pass")

    return ok, notes


PROMPT = """Convert one ION page so the redesign's `server` column passes:
move its JavaScript-built markup into a server-rendered Jinja fragment
served over htmx.

Your page: src/ion/web/templates/{page}

Read these in full before touching anything:

1. docs/UI_FRAGMENT_CONVERSION.md. This is the contract. Every rule in it
   came from a real defect in an earlier conversion. Follow all of it.
2. src/ion/web/ui/de_quirks.py with
   src/ion/web/templates/_fragments/de_quirks.html,
   src/ion/web/templates/de_quirks.html and
   tests/unit/test_ui_fragment_de_quirks.py. This is your reference
   implementation. Your page is a sibling of it: same licence gate, same
   shape. Match it closely, because the point of doing these together is
   that they come out consistent.

Then run: python tools/fragment_plan.py {stem}
It prints the page's own permission, every URL its JavaScript fetches with
the gates each one actually carries, the innerHTML sites with line numbers,
and the traps it expects you to hit. Use it. Do not guess a permission.

You may create or edit ONLY these paths:

    src/ion/web/ui/{stem}.py
    src/ion/web/templates/_fragments/{stem}.html
    src/ion/web/templates/{page}
    tests/unit/test_ui_fragment_{stem}.py

Touch nothing else. In particular do not edit src/ion/web/ui/__init__.py
(modules are discovered, not listed), src/ion/web/ui/_shared.py,
tests/unit/test_ui_fragment_registry.py, any other page, or any CSS file.
Run no git command that writes. Do not commit.

This page is part of ION's detection-engineering module, which is licence
gated. Copy the gate pair from de_quirks verbatim and in this order:

    dependencies=[
        Depends(require_de_module),
        Depends(require_permission("<the JSON endpoint's permission>")),
    ]

require_de_module comes first because /api/de/* receives it from the router
mount in server.py and router dependencies resolve before route ones. The
order decides what an unauthenticated request to an unlicensed deployment
is told: 404, meaning this does not exist here, rather than 401, meaning
log in and try again. The second answer tells an unlicensed caller the
feature is there and they are merely not signed in.

The rules that matter most, all from the brief:

- Reuse the service function the JSON endpoint already calls. Do not
  reimplement its logic.
- `is not none` for every number. Zero is a measurement, not a blank. A
  rate measured at zero and a rate nobody computed lead to opposite
  decisions.
- A read that fails renders a fragment that SAYS the read failed. It never
  prints 0 for it, and an empty list is a different claim from an
  unreadable one.
- Use ui._shared.plain for any SQLEnum column, the `ts` macro from
  _fragments/_time.html for any timestamp, and the `safe_url` filter for
  any stored URL.
- Write no htmx error handler; static/js/htmx-errors.js owns that.
- Use no htmx feature that compiles a string: no hx-trigger event filter
  such as `[key=='Enter']`, no `js:` hx-vals, no hx-on. ION's CSP blocks
  them and the feature silently does nothing.
- Keep the page's controls OUTSIDE the swap target, so a failed render
  cannot remove the control that retries.

Write tests that would fail against the defective version. For each guard,
name the defect it catches and make sure your arrangement can actually
produce it. A test that passes the moment you write it has proved nothing.

Your work is verified offline after you finish: the page's write count must
reach 0, your module must import and mount, your tests and the shared
registry guards must pass, and any remaining JavaScript must parse. If any
of that fails the whole page is rolled back and your work is discarded, so
check it yourself before you stop.

Report at the end: what the JavaScript was building, what the fragment does
now, which gate and permission you applied and how you confirmed it, and
anything you could not do.
"""


def convert(page: str, timeout: int, dry_run: bool) -> dict:
    stem = page.removesuffix(".html")
    result = {"page": page, "writes_before": write_count(page), "exit": None,
              "kept": False, "notes": [], "tail": "", "stderr": ""}
    if dry_run:
        result["notes"] = ["dry run, nothing delegated"]
        return result

    started = time.time()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        snap = snapshot(page, tmp)
        prompt_file = tmp / "prompt.txt"
        prompt_file.write_text(PROMPT.format(page=page, stem=stem),
                               encoding="utf-8")
        try:
            proc = _run([
                str(GROK), "--cwd", str(REPO),
                "--permission-mode", "bypassPermissions",
                "--max-turns", "120",
                "--prompt-file", str(prompt_file),
            ], timeout=timeout)
            result["exit"] = proc.returncode
            # BOTH streams. Recording only stdout once turned a hard API
            # error into an empty tail reported as "nothing to do", and a
            # whole band died on a 402 with no hint of the cause.
            result["tail"] = (proc.stdout or "")[-500:]
            result["stderr"] = (proc.stderr or "")[-600:]
        except subprocess.TimeoutExpired:
            result["exit"] = "timeout"
            result["notes"] = ["timed out"] + roll_back(snap)
            result["seconds"] = round(time.time() - started)
            return result

        ok, notes = verify(page)
        result["notes"] = notes
        result["writes_after"] = write_count(page)
        if ok:
            result["kept"] = True
        else:
            result["notes"] += roll_back(snap)

    result["seconds"] = round(time.time() - started)
    return result


def candidates() -> list[str]:
    """Pages that still build markup in JavaScript, smallest first."""
    out = []
    for path in sorted(TEMPLATES.glob("*.html")):
        if path.name in NEVER_BATCH:
            continue
        text = path.read_text(encoding="utf-8")
        n = len(WRITES.findall(text))
        if n:
            out.append((n, len(text.splitlines()), path.name))
    out.sort()
    return [f"{name}  writes={n} lines={lines}" for n, lines, name in out]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", nargs="*", default=[],
                    help="template names, with or without .html")
    ap.add_argument("--list", action="store_true",
                    help="show what is left and run nothing")
    ap.add_argument("--workers", type=int, default=1,
                    help="pages in parallel. Each runs its own Grok process "
                         "and they share one work tree, so keep it low.")
    ap.add_argument("--timeout", type=int, default=2400,
                    help="seconds per page before rollback")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.list:
        for line in candidates():
            print("  " + line)
        return 0
    if not args.pages:
        ap.error("name pages with --pages, or pass --list")

    pages = [p if p.endswith(".html") else p + ".html" for p in args.pages]
    for page in pages:
        if page in NEVER_BATCH:
            print(f"refusing {page}: it is shared by every page")
            return 2
        if not (TEMPLATES / page).exists():
            print(f"no such template: {page}")
            return 2

    results = []
    if args.workers > 1:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(convert, p, args.timeout, args.dry_run): p
                       for p in pages}
            for fut in as_completed(futures):
                results.append(fut.result())
                print(f"  done {futures[fut]}")
    else:
        for page in pages:
            print(f"  starting {page}")
            results.append(convert(page, args.timeout, args.dry_run))
            print(f"  done {page}")

    RESULTS.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print()
    kept = [r for r in results if r["kept"]]
    for r in results:
        mark = "KEPT  " if r["kept"] else "ROLLED"
        print(f"{mark} {r['page']:30} exit={r['exit']} "
              f"{r.get('seconds', '?')}s")
        for note in r["notes"]:
            print(f"         {note}")
    print(f"\n{len(kept)} of {len(results)} kept. Results in {RESULTS.name}.")
    print("Offline checks only. Every kept page still needs a human review "
          "for honesty and a browser pass.")
    return 0 if kept else 1


if __name__ == "__main__":
    sys.exit(main())
