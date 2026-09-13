# UI Rewrite — Foundation, Harness and Pilot

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a full template rewrite onto daisyUI *safe to execute in bulk* — port the light-mode apparatus that a clean-slate input file silently loses, build a harness that catches silent CSP and render failures, and prove the whole loop on one real page.

**Architecture:** Three layers, in order. (1) The new `tailwind-daisy.input.css` reaches parity with the 13KB of accumulated fixes in `tailwind.input.css`, guarded by a test. (2) A render-smoke harness asserts every route still renders and no new CSP inline-style violations appear. (3) One representative page is rewritten end to end, producing the repeatable pattern and the Grok delegation prompt the bulk phase will use.

**Tech Stack:** Tailwind v4.3.3 standalone binary (no Node), daisyUI 5.7.37 via plain `@import`, Plotly 4.1.0, Cytoscape 3.34.2, Jinja2, FastAPI, pytest.

**Not in this plan.** Plotly and Cytoscape are vendored (`0e81f29`) but nothing wires them into a page here. Replacing the hand-rolled SVG kill-chain, the inline sparklines and the CSS progress bars is its own piece of work with its own verification problem — a chart that renders but plots the wrong series passes every check in this plan. It follows once the restyle loop is proven.

**Scope note.** This plan deliberately stops after the pilot. The 114-template bulk migration is follow-on work, one plan per tranche, because each tranche's plan should be written with what the previous tranche learned. A single plan enumerating 81,191 lines of template changes would be unreadable and stale by task three.

## Global Constraints

Measured 2026-09-13 against `main` at v0.92.0. These supersede the June figures in `concepts/reskin-scope.md`, which are stale.

- 114 templates, 81,191 total lines. Largest: `alerts.html` 10,482, `training.html` 9,509, `cases.html` 5,568.
- **1,695 `_ion-s-*` occurrences across 60 templates.** These are CSP-mandated hashed classes for JS-computed values under `style-src-attr 'none'` — they are the *sanctioned pattern*, not debt. The count nearly doubled since June (~935), so they are actively growing. Counted with `_ion-s-[a-z0-9]+`; a `*` quantifier returns 1,696 by also matching a bare `_ion-s-…` in a JS comment at network_map.html:191. **The rewrite must preserve them.** Stripping one produces an unstyled element, not an error.
- **CSP failures are silent.** Per `tests/test_v080_csp_inline_styles.py`: a refused inline style yields no error, no log line, no failed request. 22 sat unnoticed; a severity stripe rendered colourless for three releases. Any rewrite step that cannot be checked by the harness must be checked by eye.
- **The counting trap:** a naive `style\s*=` regex also matches the tail of `data-ion-style="..."`, which is the sanctioned replacement. Any tooling that counts inline styles must carry the `(?<![-\w])` guard, or it will report already-migrated sites as violations. This once produced a six-phase plan for work already done.
- No Node, no npm. Tailwind builds only via `./frontend/tailwindcss.exe` (v4.3.3, gitignored, must be present).
- Commit messages must NOT carry a `Co-Authored-By` trailer. Convention is `type(scope): subject`.
- Branch: `feat/ui-rewrite-foundation`, already created, foundation committed at `0e81f29`.
- Tests: `source .venv/Scripts/activate && python -m pytest`. **12 pre-existing failures** are unrelated to this work (test_metrics_endpoint ×3, test_route_audit_phase8_proposals, test_v026_lab_history, test_v049_3_es_log_sanitization, test_v077_shared_alert_detail, test_v078_metis_service_account, unit/test_bugfixes ×4). A 13th is ours.

## Division of labour with Grok

Grok CLI is authenticated and drives headlessly:

```
/c/Users/lyndo/.grok/bin/grok -p "<prompt>" --cwd /c/Users/lyndo/projects/ION \
  --permission-mode acceptEdits --max-turns N
```

- **Claude (this session):** Tasks 1–3. Foundation parity, the harness, and the pilot page. These are judgement work where a wrong call is expensive and silent.
- **Grok:** the bulk tranches, after Task 4 produces a prompt template proven on a real page. Mechanical, high-volume, verified by the harness rather than by reading.

Grok is not used in Tasks 1–3. Delegating foundation work before the harness exists means nothing can check it.

---

### Task 1: Light-mode parity in the new input file

**Files:**
- Modify: `frontend/tailwind-daisy.input.css`
- Test: `tests/test_ui_rewrite_theme_parity.py`

**Interfaces:**
- Consumes: `frontend/ion-daisy-theme.css`, `frontend/daisyui.css` (committed at `0e81f29`).
- Produces: a `tailwind-daisy.input.css` that can replace `tailwind.input.css` without regressing light mode.

**Why this task exists.** A proof build on 2026-09-13 rendered light mode with `247`, `4m 12s` and `88.4%` still in dark-mode accent colours on white — roughly 1.6:1 contrast. The cause is that `tailwind-daisy.input.css` carried only the 30-line `@theme` block from `tailwind.input.css` and dropped the remaining ~13KB, which is not styling but accumulated bug fixes:

1. A `[data-mode="light"]` block that reassigns `--color-ink-*` so every `bg-ink-*` / `text-ink-*` utility flips automatically.
2. Shell tokens (`--ion-bg`, `--ion-surface`, `--ion-text`, borders, scrollbars, selection, radial backgrounds).
3. **13 explicit patch selectors** for utilities Tailwind bakes literally — `text-white`, `bg-white/5`, `border-white/5`. There is no variable to override for these, so the var flip cannot reach them. The list was built from a grep across templates.
4. A `[data-mode="light"] body` override, because `style.css` hardcodes the body background to `#07080c`.

- [ ] **Step 1: Write the failing parity test**

Create `tests/test_ui_rewrite_theme_parity.py`:

```python
"""The rewrite's stylesheet input must not silently drop light-mode support.

tailwind.input.css is 13KB of which only the first ~30 lines are tokens. The
rest is accumulated light-mode machinery: the ink-ramp flip, shell tokens, and
13 explicit patch selectors for utilities Tailwind bakes literally
(text-white, bg-white/5, border-white/5) which no CSS-variable override can
reach.

A clean-slate rewrite input that carries only the tokens regresses light mode
across the entire app, and does so silently — the page still renders, it is
just unreadable. This test is the guard.
"""

import re
from pathlib import Path

CURRENT = Path("frontend/tailwind.input.css")
REWRITE = Path("frontend/tailwind-daisy.input.css")


def _strip_comments(css: str) -> str:
    """Remove /* ... */ blocks.

    Both files discuss [data-mode="light"] in prose. Without this, the selector
    regex below matches inside a comment and runs on to the next real `{`,
    inventing a selector that was never dropped. That produced a false failure
    on the first run of this test.
    """
    return re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)


def _light_selectors(css: str) -> set[str]:
    """Every selector carrying a [data-mode="light"] qualifier."""
    return {
        m.group(0).strip()
        for m in re.finditer(r'\[data-mode="light"\][^{;}]*(?={)', _strip_comments(css))
    }


def test_rewrite_input_exists():
    assert REWRITE.is_file()


def test_rewrite_carries_a_light_mode_block():
    assert '[data-mode="light"]' in REWRITE.read_text(encoding="utf-8")


def test_rewrite_flips_the_ink_ramp_for_light_mode():
    """bg-ink-* utilities cascade off --color-ink-*; if those do not flip,
    every dark surface stays dark on a white page."""
    css = REWRITE.read_text(encoding="utf-8")
    light = css.split('[data-mode="light"]', 1)[1]
    for token in ("--color-ink-950", "--color-ink-900", "--color-ink-800",
                  "--color-ink-700", "--color-ink-600"):
        assert token in light, f"{token} is not flipped for light mode"


def test_rewrite_patches_every_literally_baked_utility_the_current_build_does():
    """Tailwind compiles text-white / bg-white/5 to literal values, so the
    variable flip cannot reach them. Each one the current build patches must
    still be patched, or it renders white-on-white."""
    current = _light_selectors(CURRENT.read_text(encoding="utf-8"))
    rewrite = _light_selectors(REWRITE.read_text(encoding="utf-8"))
    missing = current - rewrite
    assert not missing, f"light-mode patches dropped by the rewrite: {sorted(missing)}"


def test_rewrite_overrides_the_hardcoded_body_background():
    """style.css hardcodes body to #07080c. Without this override everything
    outside .ion-tw-page reads as dark on a light page."""
    css = REWRITE.read_text(encoding="utf-8")
    assert re.search(r'\[data-mode="light"\]\s+body', css)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `source .venv/Scripts/activate && python -m pytest tests/test_ui_rewrite_theme_parity.py -q`

Expected: FAIL. `test_rewrite_carries_a_light_mode_block`, the ink-ramp test, the patch-parity test and the body test all fail, because `tailwind-daisy.input.css` currently has no `[data-mode="light"]` content at all. The patch-parity failure should list 13 dropped selectors.

- [ ] **Step 3: Port the light-mode apparatus**

Copy the light-mode machinery from `frontend/tailwind.input.css` into `frontend/tailwind-daisy.input.css`, placing it AFTER the `@theme` block and AFTER the `@import "./ion-daisy-theme.css"` line so it wins the cascade.

Port these regions verbatim, then adapt:

```bash
# Inspect the regions to port — do not guess at their content
sed -n '85,250p'  frontend/tailwind.input.css   # [data-mode="light"] block: shell tokens + ink flip
sed -n '250,$p'   frontend/tailwind.input.css   # the literally-baked utility patches (13 selectors)
```

Two adaptations are required, and only two:

1. The ported block must not fight `ion-daisy-theme.css`. That file already sets daisyUI's `--color-base-*` and `--color-primary` etc. for both modes. The ported block owns `--color-ink-*`, `--ion-*` shell tokens, and the literal-utility patches. Do not duplicate the daisyUI slots in both files — if a value appears in both, delete it from the ported block and leave `ion-daisy-theme.css` as the single owner.
2. `ion-daisy-theme.css` keys light mode on `:root[data-mode="light"]`; the ported block uses `[data-mode="light"]`. Both work. Leave each as written rather than normalising, so the ported block stays diffable against its source.

**Do not "clean up" the ported block.** Every rule in it is a fix for a specific observed breakage. Anything that looks redundant is the part that will regress.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `source .venv/Scripts/activate && python -m pytest tests/test_ui_rewrite_theme_parity.py -q`
Expected: PASS, 5 passed.

- [ ] **Step 5: Rebuild and eyeball both modes**

```bash
./frontend/tailwindcss.exe -i ./frontend/tailwind-daisy.input.css -o ./src/ion/web/static/css/ion.css --content "./src/ion/web/templates/**/*.html" --minify
```

Then open the proof page from the theme-proof server and toggle `data-mode`. The three stat values (`247`, `4m 12s`, `88.4%`) must be legible in BOTH modes. That is the specific regression this task exists to fix, so confirm it by eye — no test asserts contrast.

- [ ] **Step 6: Commit**

```bash
git add frontend/tailwind-daisy.input.css tests/test_ui_rewrite_theme_parity.py src/ion/web/static/css/ion.css
git commit -m "feat(ui): port light-mode apparatus into the rewrite stylesheet

tailwind.input.css is 13KB of which only ~30 lines are tokens; the rest is
accumulated light-mode fixes — the ink-ramp flip, shell tokens, and 13 explicit
patches for utilities Tailwind bakes literally (text-white, bg-white/5) that no
variable override can reach.

The rewrite input had carried only the tokens, which rendered light mode at
about 1.6:1 contrast on accent text. Ported, with a parity test that fails if a
future edit drops one of the patches."
```

---

### Task 2: Render-smoke and CSP harness

**Files:**
- Create: `tests/test_ui_rewrite_harness.py`
- Create: `tools/ui_rewrite_audit.py`

**Interfaces:**
- Consumes: the FastAPI `app` from `ion.web.server`.
- Produces: `python tools/ui_rewrite_audit.py` — a per-template baseline report the bulk phase diffs against; and a pytest guard that fails when a rewritten template loses `_ion-s-*` classes or gains a raw inline style.

**Why this task exists.** 81,191 lines are about to be rewritten, largely by a delegated agent. CSP violations are silent, and so is a dropped hashed class. Reading every diff does not scale. This is the net that makes bulk delegation defensible.

- [ ] **Step 1: Write the audit tool**

Create `tools/ui_rewrite_audit.py`:

```python
"""Per-template baseline for the UI rewrite.

Emits a JSON snapshot of what each template contains that the rewrite must not
silently lose: CSP hashed classes, sanctioned data-ion-style hooks, and raw
inline style attributes.

The regex carries the (?<![-\\w]) guard so `data-ion-style="..."` cannot match
as an inline style. Without it, already-migrated sites are counted as
violations — a trap that once produced a six-phase plan for finished work
(see tests/test_v080_csp_inline_styles.py).

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
    return {
        "lines": text.count("\n") + 1,
        "hashed_classes": sorted(set(HASHED_CLASS.findall(text))),
        "hashed_count": len(HASHED_CLASS.findall(text)),
        "ion_style_hooks": len(ION_STYLE_HOOK.findall(text)),
        "raw_inline_styles": len(INLINE_STYLE.findall(text)),
    }


def scan_all() -> dict:
    return {
        str(p.relative_to(TEMPLATES)).replace("\\", "/"): scan_one(p)
        for p in sorted(TEMPLATES.rglob("*.html"))
    }


def check(baseline: dict, current: dict) -> list[str]:
    """Report only LOSSES and REGRESSIONS, never mere change.

    A rewrite is expected to change markup wholesale. What it must not do is
    drop a CSP hashed class (silent unstyled element) or introduce a raw inline
    style (silently refused by style-src-attr 'none').
    """
    problems = []
    for name, base in baseline.items():
        cur = current.get(name)
        if cur is None:
            problems.append(f"{name}: template disappeared")
            continue
        lost = set(base["hashed_classes"]) - set(cur["hashed_classes"])
        if lost:
            problems.append(
                f"{name}: lost {len(lost)} CSP hashed class(es): {sorted(lost)[:5]}"
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
```

- [ ] **Step 2: Generate the baseline and sanity-check the numbers**

```bash
source .venv/Scripts/activate
python tools/ui_rewrite_audit.py
```

Expected: `baseline written: 114 templates, 1695 hashed classes`.

If the hashed-class total is not 1695, stop and reconcile before continuing — the measurement was taken on 2026-09-13 against v0.92.0. A different number means either the repo moved or the regex is wrong, and a wrong baseline makes the whole harness worthless.

- [ ] **Step 3: Write the harness test**

Create `tests/test_ui_rewrite_harness.py`:

```python
"""Guards for the UI rewrite: every route still renders, nothing silently lost.

Rewriting 81,191 lines of templates produces breakage that no existing test
catches, because the two most likely failures are both silent: a dropped
_ion-s-* hashed class renders an unstyled element, and a raw inline style is
refused by style-src-attr 'none' with no error and no log line.
"""

import subprocess
import sys

from fastapi.testclient import TestClient

from ion.web.server import app


def test_audit_reports_no_losses_against_baseline():
    """The rewrite may change markup freely; it may not drop a CSP hashed class
    or add a raw inline style."""
    result = subprocess.run(
        [sys.executable, "tools/ui_rewrite_audit.py", "--check"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_every_get_route_renders():
    """A rewritten template with a Jinja syntax error 500s. This catches that
    across every page in one run, which reading diffs does not."""
    client = TestClient(app, raise_server_exceptions=False)
    failures = []
    for route in app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", set()) or set()
        # Only parameterless GET pages — templated paths need fixtures this
        # harness deliberately does not build.
        if "GET" not in methods or "{" in path or path.startswith("/api"):
            continue
        response = client.get(path)
        if response.status_code >= 500:
            failures.append(f"{path} -> {response.status_code}")
    assert not failures, f"routes failing to render: {failures}"
```

- [ ] **Step 4: Run the harness**

Run: `source .venv/Scripts/activate && python -m pytest tests/test_ui_rewrite_harness.py -q`

Expected: PASS. `test_every_get_route_renders` may report auth redirects (3xx) — those are fine, only 5xx counts as failure. If a route 500s *before* any rewrite, that is a pre-existing bug: record it in the plan's notes and exclude it explicitly with a comment naming why, rather than loosening the assertion.

- [ ] **Step 5: Prove the harness actually catches a loss**

A guard nobody has seen fail is not a guard.

```bash
# Deliberately break one template, confirm the audit catches it, then restore
cp src/ion/web/templates/security_dashboard.html /tmp/sd.bak
python - <<'EOF'
import pathlib, re
p = pathlib.Path("src/ion/web/templates/security_dashboard.html")
t = p.read_text(encoding="utf-8")
p.write_text(re.sub(r'_ion-s-[a-z0-9]+', '', t, count=1), encoding="utf-8")
EOF
python tools/ui_rewrite_audit.py --check ; echo "expect exit 1, got $?"
cp /tmp/sd.bak src/ion/web/templates/security_dashboard.html
python tools/ui_rewrite_audit.py --check ; echo "expect exit 0, got $?"
```

Expected: exit 1 naming the lost class, then exit 0 after restore.

- [ ] **Step 6: Commit**

```bash
git add tools/ui_rewrite_audit.py tools/ui_rewrite_baseline.json tests/test_ui_rewrite_harness.py
git commit -m "feat(ui): rewrite harness — CSP-loss audit + render smoke

Rewriting 81k lines of templates has two silent failure modes: a dropped
_ion-s-* hashed class renders an unstyled element, and a raw inline style is
refused by style-src-attr 'none' with no error and no log line. Neither shows
up in a diff review at this volume.

The audit snapshots all 114 templates (1,695 hashed classes) and fails on loss
or on new raw inline styles. The render smoke asserts no page 500s. Verified by
deliberately breaking a template and confirming the audit catches it.

The inline-style regex carries the (?<![-w]) guard so data-ion-style cannot
match — the trap recorded in test_v080_csp_inline_styles.py."
```

---

### Task 3: Pilot rewrite — one page, end to end

**Files:**
- Modify: `src/ion/web/templates/security_dashboard.html`
- Modify: `src/ion/web/templates/base.html` (load `ion.css` alongside the current stylesheets)
- Test: covered by the Task 2 harness

**Interfaces:**
- Consumes: `ion.css` built in Task 1, the harness from Task 2.
- Produces: the rewritten-page pattern and the measured facts Task 4's Grok prompt is built from.

**Why this page.** `security_dashboard.html` is 1,053 lines with only 4 `_ion-s-*` classes — substantial enough to be representative, low enough in CSP risk that a mistake is recoverable. The review also named it as one of the weak pages worth migrating.

- [ ] **Step 1: Record the starting state**

```bash
source .venv/Scripts/activate
python -c "
import json
b=json.load(open('tools/ui_rewrite_baseline.json'))
print(json.dumps(b['security_dashboard.html'], indent=2))
"
```

Write the four hashed class names down. They must all still be present at the end.

- [ ] **Step 2: Load the new stylesheet additively**

In `src/ion/web/templates/base.html`, add `ion.css` immediately after the existing `tailwind.css` link:

```html
    <link rel="stylesheet" href="/static/css/ion.css?v={{ ion_version }}">
```

Additive on purpose: every existing page keeps its current stylesheets and is unaffected, exactly as Phase 0 did. The old sheets retire only when the last page has moved.

- [ ] **Step 3: Rewrite the page**

Rewrite `security_dashboard.html` using daisyUI components (`card`, `stat`, `table`, `badge`, `btn`, `alert`) with ION semantic colours, replacing its `<style>` block and bespoke markup.

Three hard rules:

1. **Keep every `_ion-s-*` class exactly as-is.** They carry JS-computed values under CSP. Do not convert them to inline styles, do not rename them, do not "tidy" them.
2. **Never introduce a raw `style="..."` attribute.** It is silently refused. Use an existing hashed class or `data-ion-style`.
3. Use daisyUI semantic classes (`badge-error`) over raw Tailwind colour utilities (`bg-red-500`) so the ION theme stays the single source of colour.

- [ ] **Step 4: Verify with the harness**

```bash
source .venv/Scripts/activate
python tools/ui_rewrite_audit.py --check
python -m pytest tests/test_ui_rewrite_harness.py tests/test_v080_csp_inline_styles.py -q
```

Expected: audit exit 0, tests PASS. If the audit reports a lost hashed class, restore it — do not update the baseline to match. The baseline is the contract.

- [ ] **Step 5: Verify by eye, in both modes**

Start the app (`preview_start` with the `ion` config), open `/security-dashboard`, screenshot it in dark mode, toggle `data-mode="light"`, screenshot again.

This step is not optional and cannot be replaced by a test. The harness proves nothing was lost structurally; only looking proves the page is right.

- [ ] **Step 6: Commit**

```bash
git add src/ion/web/templates/security_dashboard.html src/ion/web/templates/base.html
git commit -m "feat(ui): pilot — rewrite security_dashboard on daisyUI

First page on the new stylesheet. ion.css loads additively alongside the
existing sheets, so every other page is untouched.

All 4 _ion-s-* hashed classes preserved and verified by the audit; no raw
inline styles introduced. Checked by eye in both light and dark mode."
```

---

### Task 4: Grok delegation, proven on a second page

**Files:**
- Create: `tools/grok_rewrite_prompt.md`
- Modify: one further template, chosen in Step 1

**Interfaces:**
- Consumes: the pattern established in Task 3, the harness from Task 2.
- Produces: a delegation prompt that has demonstrably worked once, which the bulk tranches reuse.

**Why prove it before scaling.** Handing Grok 114 templates on an unproven prompt risks 114 wrong rewrites. One verified delegation costs one page and tells us whether the loop works.

- [ ] **Step 1: Pick the second page**

Choose a template between 300 and 800 lines with at least 5 `_ion-s-*` classes, so the delegation is tested against the CSP constraint rather than around it:

```bash
source .venv/Scripts/activate
python -c "
import json
b=json.load(open('tools/ui_rewrite_baseline.json'))
for n,v in sorted(b.items(), key=lambda kv: kv[1]['lines']):
    if 300 <= v['lines'] <= 800 and v['hashed_count'] >= 5:
        print(v['lines'], v['hashed_count'], n)
" | head -10
```

- [ ] **Step 2: Write the delegation prompt**

Create `tools/grok_rewrite_prompt.md` with this content, substituting the page chosen in Step 1. Grok gets no other context, so everything it needs is here:

```markdown
Rewrite exactly one Jinja2 template in this repository onto daisyUI 5:
`src/ion/web/templates/<PAGE>.html`

This is ION, an air-gapped SOC platform. The stylesheet `static/css/ion.css` is
already built and loaded, and provides Tailwind v4 utilities plus daisyUI
components themed with ION's own tokens (primary is ION cyan, error is ION
coral, and so on).

Follow the pattern already applied in
`src/ion/web/templates/security_dashboard.html` — read that file first.

## Three rules you must not break

1. PRESERVE EVERY `_ion-s-*` CLASS EXACTLY.
   These are CSP-mandated hashed classes carrying JS-computed values. The app
   sets `style-src-attr 'none'`, so these classes are the sanctioned way to
   apply a dynamic style. Do not rename, remove, merge, or "tidy" them. Copy
   each one through unchanged.

2. NEVER EMIT A RAW `style="..."` ATTRIBUTE.
   It will be silently refused by the browser — no error, no console warning,
   no failed request, just an unstyled element. If you need a dynamic style
   hook, use `data-ion-style`, which is the sanctioned replacement.

3. DO NOT EDIT `tools/ui_rewrite_baseline.json`, AND DO NOT TOUCH ANY FILE
   OTHER THAN THE ONE TEMPLATE NAMED ABOVE.
   The baseline is the contract that proves nothing was lost. Editing it to
   make a check pass defeats the entire safety net.

Both failure modes in rules 1 and 2 are INVISIBLE. The page still renders and
returns 200. This is why they are stated so bluntly.

## Style guidance

- Prefer daisyUI semantic classes (`badge-error`, `btn-primary`, `card`,
  `stat`, `table`, `alert`) over raw Tailwind colour utilities
  (`bg-red-500`). The ION theme owns colour; hardcoding it defeats the theme.
- Replace the page's `<style>` block with daisyUI components and utilities
  where you can. If a rule cannot be expressed that way, leave it in place
  rather than approximating it.
- Keep all Jinja logic, block structure, template inheritance, `hx-*`
  attributes and `data-*` hooks exactly as they are. This is a restyle, not a
  refactor of behaviour.

## Before you report back

Run this and confirm it exits 0:

    python tools/ui_rewrite_audit.py --check

If it reports a lost hashed class, restore that class in the template. Do not
regenerate or edit the baseline.

Then report: the file you changed, the audit's exit code, and anything you
could not express in daisyUI and left as-is.
```

- [ ] **Step 3: Run the delegation**

```bash
cd /c/Users/lyndo/projects/ION
/c/Users/lyndo/.grok/bin/grok \
  --cwd /c/Users/lyndo/projects/ION \
  --permission-mode acceptEdits \
  --max-turns 40 \
  --prompt-file tools/grok_rewrite_prompt.md 2>&1 | tail -40
```

- [ ] **Step 4: Verify Grok's work independently**

Do not trust the self-check it reports.

```bash
source .venv/Scripts/activate
git diff --stat                                    # only the one template changed?
git diff tools/ui_rewrite_baseline.json            # MUST be empty
python tools/ui_rewrite_audit.py --check
python -m pytest tests/test_ui_rewrite_harness.py tests/test_v080_csp_inline_styles.py -q
```

Then open the page and look at it in both modes.

- [ ] **Step 5: Record the verdict**

Append to `tools/grok_rewrite_prompt.md` a short "Observed behaviour" section: what Grok got right, what it got wrong, and any prompt change that was needed. If it dropped hashed classes or edited the baseline, the prompt is not ready and the bulk phase does not start.

- [ ] **Step 6: Commit**

```bash
git add tools/grok_rewrite_prompt.md src/ion/web/templates/<page>.html
git commit -m "feat(ui): proven Grok delegation prompt for template rewrites

One page rewritten by Grok headlessly and verified independently: only the
target template changed, the audit baseline untouched, no CSP hashed classes
lost, harness green, checked by eye in both modes.

Records what Grok actually did rather than what the prompt asked for, so the
bulk tranches start from observed behaviour."
```

---

## Verification before calling this plan done

- [ ] `python -m pytest tests/ -q` shows 12 failures, all pre-existing
- [ ] `python tools/ui_rewrite_audit.py --check` exits 0
- [ ] Light mode is legible on the proof page AND on both rewritten pages — checked by eye, not by test
- [ ] `git diff main --stat -- tools/ui_rewrite_baseline.json` is empty since it was generated
- [ ] The Grok prompt has an "Observed behaviour" section written from a real run

## What comes after

One plan per tranche, ordered by risk rather than size. Suggested first tranche: the mid-sized pages the review called weak (`analytics` 1,732 lines, `dashboard_v2`). Leave `alerts.html` (10,482 lines, 184 hashed classes) until the loop has proven itself repeatedly — it is 13% of the template codebase in one file and should be split into sub-tasks when its turn comes.
