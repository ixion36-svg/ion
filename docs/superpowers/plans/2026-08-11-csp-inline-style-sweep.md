# v0.80.0 — finish the CSP inline-style migration

**Status:** scoped, not started
**Raised:** 2026-08-11, while fixing two inline-style violations for v0.79.5
**Owner:** ION maintainer

---

## 1. The claim that turned out to be false

`src/ion/web/server.py` sets `style-src-attr 'none'` and the comment above it says:

> v0.31.21: `style-src-attr 'none'` flipped on after `tools/migrate_inline_styles.py`
> retired every inline `style=""` attribute (1,820 instances → 993 unique hashed CSS
> classes). … **P11 is now fully closed.**

It is not closed. A repo-wide sweep on 2026-08-11 found **163 inline `style=`
attributes still live across 36 first-party templates and scripts**. Every one is
refused by the browser at render time.

Separately counted and *excluded* as correct: **84** in `templates/emails/*` and
`*_pdf.html`. Those are not served under ION's CSP, and HTML email requires inline
styles. They must stay, and the guard test must skip them.

## 2. Why it matters, and why nobody noticed

A refused inline style produces no error page, no log line, and no failed request —
just an unstyled element and one console warning per occurrence. So the estate has
been quietly rendering:

- progress bars at **zero width** (53 sites)
- severity badges, verdict pills and score text with **no colour** (77 sites)
- the conic-gradient gauges on `/soc-health`, `/maturity`, `/guide-sim` and
  `/detection-engineering` **not filling** (4 sites)
- panels that should be hidden **visible**, or vice versa (5 `display:` toggles)

This is the same defect class as the v0.79.5 case-rail severity stripe, which
rendered colourless for three releases before anyone opened a console.

It is also the same class as the v0.77.0 finding recorded in
`ion-dynamic-styles.js`: 125 hashed rules containing a literal `${pct}` — invalid
CSS, silently dropped, unnoticed for ~40 releases. **This is the third time this
one mechanism has produced invisible breakage.**

## 3. The mechanism already exists — this is a migration, not an invention

`static/js/ion-dynamic-styles.js` (v0.31.21, hardened v0.77.0) is the sanctioned
pattern and is already loaded by `base.html`:

- markup carries `data-ion-style="width:${pct}%"` instead of `style="…"`
- the script applies each declaration with `el.style.setProperty(prop, val)`
- `setProperty` is a **DOM property write, not an inline attribute**, so it is
  CSP-legal without `unsafe-inline`
- a `MutationObserver` on `document.documentElement` covers every render path,
  which matters because ION builds markup with `innerHTML` in dozens of places and
  a missed call site is invisible

**144 sites across 29 files already use it.** The 163 remaining are simply the ones
the v0.77.0 sweep did not reach. The work is to finish the job, on a proven path.

## 4. Scope by remedy

| Count | Shape | Remedy | Risk |
|---|---|---|---|
| 77 | `color:${c}` / `background:${c}` | `data-ion-style` | low |
| 53 | `width:${pct}%` / `height:${h}px` | `data-ion-style` | low |
| 15 | ternaries, mixed declarations | case by case | medium |
| 7 | static (`margin-top:3px`) | plain CSS class | trivial |
| 5 | `display:none/flex` toggles | CSS class + `classList` | trivial |
| 4 | `conic-gradient(...)` gauges | custom property + CSS `background` | **high** |
| 2 | already `--custom-prop:${v}` | rename attribute only | trivial |

**163 total across 36 files.** Heaviest: `detection_engineering.html` (23),
`training.html` (23), `pcap.html` (19), `integrations.html` (14), `alerts.html` (10),
`analytics.html` (8), `soc_health.html` (7).

The 4 gradients are the only genuinely hard ones: the whole gradient string is
computed in JS (`conic-gradient(${gradParts.join(',')})`). They need the stops
expressed as custom properties with the gradient declared in CSS, which changes how
the value is composed rather than just where it is applied.

## 5. Phases

Sequenced so the cheap, zero-risk wins land first and the guard test can be
tightened progressively — a test that only tightens at the end would leave the
whole migration unprotected while it is in flight.

- **P0 — guard first.** Extend the v0.79.5 inline-style test from two templates to
  the whole repo, as an **allowlist of known-remaining files** with the exact
  current count per file. New violations fail immediately; existing ones are
  recorded, not hidden. Each later phase deletes entries from the allowlist, so the
  count can only go down.
- **P1 — trivial (14 sites).** 7 static + 5 display toggles + 2 already-custom-property.
  Pure CSS classes. No behaviour change.
- **P2 — sizes (53 sites).** Progress bars and bar charts → `data-ion-style`.
  Mechanical and highly repetitive; the visual check is "bars have width again".
- **P3 — colours (77 sites).** Same treatment. Largest phase, lowest complexity.
- **P4 — the awkward 15.** Ternaries and multi-declaration strings, read individually.
- **P5 — the 4 gradients.** Recompose as CSS with custom-property stops. Do last:
  highest risk, and by then the pattern is well exercised.
- **P6 — close it out.** Allowlist emptied; the test becomes an absolute ban
  (excluding `emails/` and `*_pdf.html`). **Correct the false "P11 is now fully
  closed" comment in `server.py`** and the corresponding claim in
  `SECURITY_ASSESSMENT.md`.

## 6. Verification

Static tests cannot prove a style *applied* — that is exactly how this survived
three times. Each phase needs a live render:

- browser check per touched page with **zero CSP console warnings**, using the
  harness approach from v0.79.5 (real CSS + real JS + fixture data) where a page
  cannot be driven without Elasticsearch
- spot-check computed values, not markup: `getComputedStyle(bar).width !== '0px'`
- the `MutationObserver` path specifically, since most of these render via
  `innerHTML` after page load

## 7. Release shape

`0.80.0` — a minor bump: no API, schema or permission change, but broad enough
across the UI to warrant more than a patch. Test scope stays **affected-module
only** per the 0.x policy; `0.80.0` is not a true major.

**Not in scope:** the `style-src-attr` directive itself does not change. Nothing
here weakens the CSP — the policy has been correct throughout; the markup was not.
