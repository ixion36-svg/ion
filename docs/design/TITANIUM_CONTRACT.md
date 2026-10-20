<!-- ion-doc:type=DESIGN CONTRACT -->
<!-- ion-doc:title=Titanium structural contract -->
<!-- ion-doc:subtitle=The containment, elevation and type rules that make a box tight, and how they land in ION's stack -->
<!-- ion-doc:version=0.99.13 -->
<!-- ion-doc:classification=INTERNAL -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Whoever ports or extends ION's UI -->
<!-- ion-doc:date=2026-10-20 -->

# Titanium structural contract

Extracted from `ion-workbench` @ `codex/investigation-foundation`
(`rebuild/frontend/src/titanium.css`, `workspace.css`, `engineering-titanium.css`).

That UI reads as tight and defined. This records **why**, as rules that can be
checked, and what each rule becomes in ION's Jinja + Tailwind + daisyUI stack.
It is a contract, not a theme: ION keeps its own palette.

## The one idea worth copying

Titanium is **two layers that declare the same token names**:

| layer | file | owns |
|---|---|---|
| structure | `workspace.css` | the grid, containment, scroll ownership, resets. 13px/1.5, 5px radius, flat |
| skin | `titanium.css` | redefines the same tokens, adds material. 14px/1.6, 10px radius, bevel |

The skin loads second and wins. Nothing in the skin is load-bearing for
**layout** — delete it and the app still contains its text correctly, it just
looks plain. That separation is why a third skin (ION's palette) is a
re-tokenisation rather than a rewrite.

ION has no such split. `frontend/ion-daisy-theme.css` mixes token mapping with
ported components, and 14,507 lines of page-scoped CSS under
`static/css/*-page.css` carry per-page structure that no shared layer owns.

---

## C — Containment. Why text does not escape a box.

Four rules. These are the whole of "the boxes are tight and the text doesn't
overlap", and they are independent of colour.

### C1 — every layout child that can hold unbounded text declares `min-width: 0`

A grid or flex child defaults to `min-width: auto`, which **refuses to shrink
below its content's intrinsic minimum**. One unbroken string — a sha256, a UNC
path, a rule name, a base64 blob, an analyst's pasted line — widens the track
past the container.

In ION the symptom is not text sitting outside a border, because
`.ion-tw-page` carries `overflow-x: hidden`. It is **silently clipped
evidence**. Measured on a representative detail page before the layer landed:
the `<pre>` holding an encoded command was 1,207px wide over 2,323px of
content (**48% unreadable**), and the sha256 in a four-column fact grid was
290px over 461px (**37% unreadable**). Nothing indicates anything is missing.

Titanium disables it structurally, in three forms:

```css
.iw-queue, .iw-main, .iw-panel { min-height: 0; min-width: 0; }
.iw-datum { min-width: 0; }
.iw :is(.aw-card, .cw-detail, .rw-content, .sw-tasks, .hw-main, .kl-list /* +14 more */) { min-width: 0; }
```

and in every grid template, as `minmax(0, 1fr)` rather than `1fr`:

```css
.iw-body  { grid-template-columns: 300px minmax(260px, 1fr) var(--iw-panel-width); }
.iw-facts { grid-template-columns: repeat(2, minmax(0, 1fr)); }
```

**Measured in ION:** 1,287 grid/flex containers, 51 sites declaring
`min-width: 0` — **3%**. Read that as an upper bound on exposure, not a bug
count: most flex children hold a short label or an icon and never overflow. The
rule only bites where a cell can hold an attacker-supplied or analyst-supplied
string, which in a SOC portal is most evidence surfaces.

### C2 — unbounded text declares a wrap policy where it is emitted

```css
.iw dd           { overflow-wrap: anywhere; white-space: pre-wrap; }
.iw-id           { overflow-wrap: anywhere; }
.iw-row-title    { overflow-wrap: anywhere; }
.iw-source       { white-space: pre-wrap; overflow-wrap: anywhere; }
.iw [role=alert] { overflow-wrap: anywhere; }
```

`anywhere`, not `break-word`. `break-word` does not affect the **intrinsic
minimum width**, so it wraps the text while still letting the box grow; only
`anywhere` does both. This is the rule most often got wrong.

**Measured in ION:** 39 wrap/break policies app-wide.

### C3 — prose declares a measure

```css
.iw-prose     { max-width: 78ch; }                    /* structure layer */
.iw .iw-prose { max-width: 75ch; }                    /* skin tightens it */
.iw .kl-body  { max-width: 75ch; line-height: 1.9; }
```

**Measured in ION:** 1 measure cap in the entire app. A findings narrative or a
KB article therefore runs the full 1920px container — readable width is not
expressed anywhere.

### C4 — scroll is owned by named regions, never by the page

```css
.iw      { height: 100dvh; display: flex; flex-direction: column; }
.iw-body { display: grid; flex: 1; min-height: 0; }
.iw-queue-scroll, .iw-main-scroll, .iw-panel-scroll {
  overflow: auto; min-height: 0;
  overscroll-behavior: contain;   /* a pane's scroll does not bleed to the page */
  scrollbar-gutter: stable;       /* an appearing scrollbar does not reflow content */
}
```

`min-height: 0` on the flex and grid parents is what lets a child actually
scroll instead of growing the page. `scrollbar-gutter: stable` is why nothing
shifts when a list grows long enough to need a scrollbar.

**Measured in ION:** 76 named scroll regions, 78 fixed-height shells — the
pattern exists, but per page rather than by a shell contract.

---

## E — Elevation. Why it reads calm.

> *Reading surfaces are quiet; buttons and selection own the elevation.*
> — `titanium.css`, verbatim

One elevation owner per screen. Cards are explicitly flattened:

```css
.iw :is(.aw-card, .rw-card, .ea-card, .cf-finding /* +12 more */) {
  border: 1px solid var(--iw-line);
  border-radius: 12px;
  background: var(--iw-surface);
  box-shadow: none;          /* deliberate */
}
```

Elevation is spent only on the app chassis (`0 18px 40px #0003`), buttons
(`inset 0 1px 0 #ffffff21, 0 3px 1px #12191f, 0 6px 10px #0002`) and the
**selected** row or nav item (bevel plus the `--ti-steel` gradient). Selection
is signalled by *material*, not by a colour change, which is why a dense queue
with one active row stays legible.

A single hairline token does all the separating: `--iw-line: #ffffff17` (9%
white). ION already has the equivalent (`--ion-border: rgba(255,255,255,0.08)`),
but page CSS reaches for `border-base-300` (344 uses), `border-white/10` (41)
and `border-white/5` (17) interchangeably.

---

## T — Type. Why nothing crowds.

**Every text role declares both a size and a line-height.** No role inherits a
default. That is the whole trick.

| role | size | line-height | tracking |
|---|--:|--:|--:|
| body | 14px | 1.6 | — |
| h1 | 27px | 1.2 | -0.03em |
| h2 | 23px | 1.3 | -0.025em |
| h3 | 16px | 1.4 | — |
| h4 | 14px | 1.5 | — |
| p | — | 1.7 | — |
| label, dt | 13px | 1.5 | — |
| dd | 14px | 1.65 | — |
| meta, ids | 12px | 1.65 | — |
| code, pre | 12px | 1.8 | — |
| prose | 14px | 1.8 | — |
| badge | 11px | 1.5 | — |

Plus `text-wrap: balance` on all of `h1,h2,h3,h4`, and negative tracking
**graded by size**: -0.035em brand, -0.03em h1, -0.025em h2, -0.015em default.
Larger text gets tighter tracking; small text gets none.

ION instead writes per-page arbitrary values —
`text-[36px] md:text-[44px] xl:text-[52px] leading-[1.05]` for `h1` on 61
pages, 14 pages off that scale entirely, and no declared line-height for the
`dd`, `dt`, meta or code roles.

---

## R — Radius, keyed to element size

A ladder, not a free choice. Small controls get small radii.

| element | radius |
|---|--:|
| app shell, nav | 18px (14px at ≤1024, 13px at ≤780) |
| card | 12px (10px at ≤780) |
| wrap, table, row | 10px |
| control (button, input, select) | 9px |
| badge | 6px |

**Measured in ION:** 22 distinct radius tokens, including seven arbitrary pixel
values (`rounded-[3px]`, `[4px]`, `[5px]`, `[6px]`, `[10px]`, `[12px]`,
`[14px]`) alongside `rounded`, `-md`, `-lg`, `-xl`, `-box` and `-field`.

---

## S — Spacing and the breakpoint ladder

Padding is a function of **region kind**, and every value steps down together at
each breakpoint. Five breakpoints: `≥1600`, `≤1200`, `≤1024`, `≤780`, `≤420`.

| region | ≥1600 | base | ≤1200 | ≤780 | ≤420 |
|---|--:|--:|--:|--:|--:|
| main scroll | 34/40 | 28/30 | 24 | 24/20 | ·/16 |
| panel scroll | — | 22/20 | 18 | 22/20 | ·/16 |
| card | — | 22 | 19 | 19 | 16 |
| toolbar | ·/32 | 20/26 | 18/22 | 22/20 | ·/16 |
| context strip | ·/32 | 19/26 | 18/22 | 20 | ·/16 |
| region heading | — | 17/16 | — | 16 | — |
| queue row | — | 16 | — | 16 | — |

Grids collapse to `minmax(0, 1fr)` at `≤780`, never to `1fr` — C1 again.

---

## D — Density. The dimension Titanium does not have.

Titanium has **one** density, tuned for reading one record thoroughly. Every
value above — 22px cards, 15/16px cells, 16px queue rows — belongs to that
single tier, because the rebuild never had to show 400 of anything.

Measured on the live Titanium page at a 1600px viewport:

| | Titanium queue |
|---|--:|
| row height | 132px |
| queue column | 220px, single column |
| rows visible at 1000px | 6 |
| scroll for 400 alerts | 52,640px |

ION reads to a 500-row cap (`ui/alerts.py`) and 100–400 open alerts is
ordinary. At 132px a row that is **6 of 400 visible, 1.5% of the queue**,
with no columns to scan, no sort across fields and no bulk selection —
`PARITY.md` lists bulk alert decisions as outstanding. Titanium's queue
pattern is therefore **rejected for ION's volume surfaces**, not tuned.

The contract gains a second tier instead. `.ion-dense` keeps ION's row
rhythm and adds the containment rules, which matter more in a dense table,
not less: a cell holding a sha256 is exactly the C1/C2 case.

| | comfortable | compact (`.ion-dense`) |
|---|--:|--:|
| where | detail, forms, findings, reading | queues, audit logs, observables |
| row height | — | **33.8px** measured |
| cell padding | 15/16px | 6/10px |
| font / leading | 14px / 1.65 | 12.5px / 1.45 |
| scroll for 400 | — | **13,519px** |

Two rules make the compact tier survive narrow widths, both learned by
measuring rather than by reading Titanium:

- **`overflow-wrap: anywhere` needs a floor.** In a 12-column table squeezed
  below its natural width it breaks a rule name one character per line.
  `td.cell-wrap` carries `min-width: 220px`.
- **The table gets a `min-width` and scrolls.** Below 940px the columns
  compress under their content; scrolling the table is the lesser failure.
  Titanium does the same thing at `≤780` for `.aw-table-wrap`.

## A — Affordance floors

```css
.iw button                        { min-height: 38px; }   /* 44px at ≤780 */
.iw :is(input, select, textarea)  { min-height: 40px; }   /* 44px at ≤780 */
.iw textarea                      { min-height: 102px; }
.iw details > summary             { min-height: 36px; align-content: center; }
.iw .iw-region-heading button     { min-height: 34px; }
```

At `≤780` inputs also go to **`font-size: 16px`**. Below 16px, iOS Safari zooms
the viewport on focus — the most common mobile form bug there is.

The accessibility floors ION should match:

```css
#investigation-root :focus-visible { outline: 2px solid var(--iw-accent); outline-offset: 4px; }
@media (prefers-reduced-motion: reduce) { /* kills transition, animation, scroll-behavior */ }
@media (hover: hover) and (pointer: fine) { /* every hover state gated: no sticky hover on touch */ }
@media print { /* nav hidden, report surfaces forced to #111 on #fff */ }
```

ION has `:focus-visible` (a 3px cyan ring) and **no** `prefers-reduced-motion`
block, while shipping `.rise`, `.pulse-red` and `.pulse-cyan` animations.

---

## How each rule lands in ION's stack

ION cannot copy the CSS. Titanium styles a React tree by semantic element
(`dd`, `summary`, `.aw-card`); ION composes Tailwind utilities in Jinja.

All three files compile into `ion.css`; nothing adds a `<link>`.

| rule | where it lives | state |
|---|---|---|
| C1 `min-width: 0` | `ion-box.css` — targets daisyUI's own class names, so a page opts in by existing rather than by editing 1,287 sites | done |
| C2 wrap policy | `ion-box.css`, plus `white-space: pre-wrap` on `pre` — `pre` beats `overflow-wrap` outright and clipped until that was added | done |
| C3 measure | `ion-box.css`, 75ch on `.card-body > p` | done |
| C4 scroll regions | **not ported.** Fixed-height panes are a page-structure change, and ION's pages are ways of working | rejected |
| E elevation | `ion-box.css` — one `--ion-border` hairline, `box-shadow: none` on `.card`/`.stats` | done |
| T type | `ion-box.css` — leading for the small roles. ION's display sizes are its identity and are left alone | partial |
| R radius | `ion-box.css` — 12px card, 9px control, 6px badge. The 22 existing tokens are not yet retired | partial |
| S spacing | `ion-box.css` 22px card. The per-region ladder is not ported | partial |
| D density | `ion-density.css` — the compact tier, which Titanium has no equivalent of | done |
| value scales | `ion-value-scales.css` — six scales, 35 rows, replacing ~45 per-page tables | layer done, pages not migrated |
| A floors | `ion-box.css` — input floors, the mobile 16px rule, and the reduced-motion block ION lacked | done |

The missing piece is the one ION deleted: **a Jinja macro library**.
`_components.html` was removed during the rewrite (recorded in the cleanup table
of `docs/UI_REDESIGN.md`), so all 75 pages hand-write their box markup and
nothing can enforce C1–C4. Re-introducing it is the prerequisite for every wave.

## What this layer does and does not change

The three files are additive and compile into `ion.css`. No template was
edited, no class renamed, no page sheet retired. Measured on a detail page
built from ION's own markup patterns, baseline against the same markup with
the layer:

| | baseline | with the layer |
|---|--:|--:|
| clipped px at 1440 | 1,287 | **0** |
| clipped px at 375 | 9,741 | **142** |

The residual 142px is a page-header flex cluster that will not wrap, which is
a markup problem and identical on both; CSS should not paper over it. It is
the case a shared header macro fixes once.

Still open, in order: retire the ~45 per-page value tables onto
`ion-value-scales.css`; reintroduce the Jinja macro library (`_components.html`
was deleted during the rewrite, recorded in the cleanup table of
`docs/UI_REDESIGN.md`, which is why all 75 pages hand-write their box markup
and nothing can enforce C1–C4); then the per-region spacing ladder and the
radius-token retirement. The wave order for those is not yet written.
