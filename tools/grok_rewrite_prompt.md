Rewrite exactly one Jinja2 template in this repository onto daisyUI 5:

    src/ion/web/templates/security_dashboard.html

This is ION, an air-gapped SOC platform (FastAPI + Jinja2). The stylesheet
`src/ion/web/static/css/ion.css` is already built and already loaded by
`base.html`. It provides Tailwind v4 utilities plus daisyUI 5 components,
themed with ION's own tokens — `primary` is ION cyan, `error` is ION coral,
`warning` is amber, `success` is lime.

## Three rules you must not break

**1. PRESERVE EVERY `_ion-s-*` CLASS EXACTLY.**

These are CSP-mandated hashed classes carrying JS-computed values. The app sets
`style-src-attr 'none'`, so these classes are the sanctioned way to apply a
dynamic style. Do not rename them, remove them, merge them, or tidy them. Copy
each one through unchanged, on the same element.

**2. NEVER EMIT A RAW `style="..."` ATTRIBUTE.**

It will be silently refused by the browser — no error, no console warning, no
failed request, just an unstyled element. If an element needs a dynamic style
hook, use `data-ion-style`, which is the sanctioned replacement.

**3. DO NOT EDIT `tools/ui_rewrite_baseline.json`, AND DO NOT TOUCH ANY FILE
OTHER THAN THE ONE TEMPLATE NAMED ABOVE.**

That baseline is the contract proving nothing was lost. Editing it to make a
check pass defeats the entire safety net. Changing any other file is out of
scope for this task.

Both failure modes in rules 1 and 2 are INVISIBLE — the page still renders and
still returns HTTP 200. That is why they are stated so bluntly. In this
codebase 22 such violations once sat unnoticed, and a severity stripe rendered
colourless for three releases.

## What to actually do

Restyle the page using daisyUI components in place of its bespoke markup and
its `<style>` block:

- `card` / `card-body` for panels
- `stat` / `stat-title` / `stat-value` / `stat-desc` for metric tiles
- `table` / `table-sm` for tabular data
- `badge` with `badge-error` / `badge-warning` / `badge-info` / `badge-success`
  for severities and statuses
- `btn` with `btn-primary` / `btn-ghost` / `btn-sm` for actions
- `alert` with `alert-warning` / `alert-info` for notices

Prefer daisyUI semantic classes (`badge-error`) over raw Tailwind colour
utilities (`bg-red-500`). The ION theme owns colour; hardcoding a palette value
defeats the theme and will not flip correctly in light mode.

Replace the page's `<style>` block with daisyUI components and Tailwind
utilities where you can. If a specific rule cannot be expressed that way, leave
that rule in the `<style>` block rather than approximating it.

## Layout pitfall seen in practice

Do not put a text block in `flex-1 min-w-0` inside a `flex ... justify-between`
header. `min-w-0` lets the text column collapse instead of wrapping, and on
network_topology.html the page heading shrank to 74px — one word per line —
below about 700px viewport width. It renders correctly at desktop widths, so it
is easy to miss.

If a header needs a text block beside controls, let the row wrap
(`flex-wrap`) and give the text block a sensible floor such as
`basis-full md:basis-auto md:flex-1`, so it drops to its own line rather than
being squeezed to nothing.

## daisyUI class collisions — check before you use a component

daisyUI defines some class names ION already uses for something else. Assume a
collision and check, rather than assuming the component is free.

**`.loading` is the known one.** daisyUI's `.loading` is a masked spinner glyph
(width 1.5rem, aspect-ratio 1, background-color:currentColor, spinner
mask-image). ION uses `class="loading"` as PLAIN TEXT in 211 places across 54
templates: `<p class="loading">Loading...</p>`. A global reset in
ion-daisy-theme.css already neutralises this for elements without a
`loading-*` modifier, so do NOT add a per-page workaround, and do NOT "fix" an
ION loading element by giving it a daisyUI spinner class.

Before using any daisyUI component class on this page, grep the template for
that class name. If ION already uses it for something else, keep ION's markup
and pick a different daisyUI component.

## Modals: check how the page actually opens them

daisyUI's `.modal` hides via `visibility`, `opacity` and `pointer-events` — NOT
via `display`. Several ION pages open a dialog with `el.style.display='flex'`
or by toggling a class like `.active`. Converting the markup to `.modal` /
`.modal-box` without checking will stop the dialog opening, with no error
anywhere.

Read the page's JavaScript first and find how it shows and hides dialogs. If it
sets `display` or toggles a bespoke class, add a small CSS bridge so daisyUI
responds to what the JS already does. Do not rewrite the JavaScript.

## What NOT to change

Keep all of this exactly as it is — this is a restyle, not a refactor:

- Jinja logic, `{% block %}` structure, template inheritance, includes
- All `hx-*` HTMX attributes
- All `data-*` hooks, especially `data-click-action` and `data-keydown-action`
  (inline `onclick=` is blocked by CSP; the delegation helper depends on these)
- Element `id` attributes and any class a `<script>` or `querySelector`
  references
- All existing JavaScript

## Before you report back

Run this and confirm it exits 0:

    python tools/ui_rewrite_audit.py --check

If it reports a lost hashed class, restore that class to the template. Do not
regenerate the baseline and do not edit it.

Then report:
1. The file you changed
2. The audit's exit code
3. Anything you could not express in daisyUI and deliberately left as-is
4. The count of `_ion-s-*` classes before and after (must be identical)

---

## Observed behaviour (first real run, 2026-09-13, security_dashboard.html)

**Permission mode is load-bearing.** The first run used
`--permission-mode acceptEdits` and produced **zero edits** — Grok read the
template, reasoned correctly about it, and exited without writing. Re-running
with `--permission-mode bypassPermissions` produced the work. Any tranche run
with `acceptEdits` will silently no-op, which looks identical to "nothing
needed changing". Always diff after a run.

**What it got right, verified independently:**

- All 4 `_ion-s-*` classes preserved, same names on the same elements.
- Zero raw `style=` attributes introduced. Audit exit 0.
- Touched only the one template. Left `tools/ui_rewrite_baseline.json` alone.
- 1,053 -> 891 lines (15% smaller) with the `<style>` block largely retired.
- Worked out unprompted that some hashed classes are emitted by JavaScript at
  runtime rather than present in static markup, and kept the script intact.
- Spotted that the page's JS toggles `.active` while daisyUI 5 opens modals via
  `modal-open`, and wrote a CSS bridge. Verified: adding `.active` flips the
  modal from `display:none` to `display:grid` with `.modal-box` at opacity 1.
  Had it swapped in daisyUI's markup naively, the dialog would have stopped
  opening **and the audit would not have caught it** — that failure is neither
  a dropped hashed class nor an inline style.
- Kept all 26 element ids and every `data-*` hook.

**What it could not do:** it reported honestly that it had no browser and could
not visually verify. That half of the check is the reviewer's, every time.

**Layout differences from the original, judged acceptable:**

- Metric tiles moved from a static 2x2 grid to
  `stats stats-vertical lg:stats-horizontal` — stacked below 1024px, one row
  above. Measured at 1280px: 4 tiles sharing `top: 399`, no overflow.
- The two filter selects moved from inline-beside-the-heading to stacked at the
  right. Cosmetic, not broken.

**Reviewer's note on method.** Three suspected regressions were raised from
downscaled screenshots and all three were wrong — a misread `}` that was
actually "Loading...", a "broken" stat grid that was correct responsive
behaviour seen at 640px, and "overlapping" selects that were merely stacked.
Judge layout by measuring the DOM (`getBoundingClientRect`, computed styles) at
a realistic desktop width. The preview pane downscales too far for the eye to
be trusted.
