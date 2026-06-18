# ION full re-skin — migration scope

Complete, template-by-template scope for re-skinning ION to the consolidated
visual language locked in [`ion-ui-kit.html`](ion-ui-kit.html) (the Phase 0
component foundation), derived from the [`daily-work.html`](daily-work.html)
prototype.

**Goal:** every page adopts the `ion-*` component layer; all bespoke per-page
`<style>` blocks and `_ion-s-*` migrated one-off styles are retired.

**Principle:** foundation first, then migrate in **verified waves** — never a
big-bang find-replace. Each template is screenshot-verified before it's marked
done. Each wave is its own release.

---

## Scale (measured 2026-06-18)

| Metric | Value |
|---|---|
| Total template files | 97 (78 root + 19 `cyab/`) |
| Full pages to migrate | ~70 |
| Shared partials / includes | ~15 (`base.html`, `_components`, `_icons`, `_nav_tabs`, `cyab/_*`) |
| Templates carrying `_ion-s-*` styles | ~36 |
| Total `_ion-s-*` occurrences | ~935 |
| Templates with a page `<style>` block | ~63 |
| Standalone (no `base.html`) | `login`, `wallboard` (+ slide decks) |

---

## Complexity rubric

| Tier | Criteria | Per-template effort* |
|---|---|---|
| **XL** | >1,500 lines OR >100 `_ion-s-` | 3–5 units |
| **L** | 800–1,500 lines OR 30–100 `_ion-s-` | 2 units |
| **M** | 300–800 lines | 1 unit |
| **S** | <300 lines, ≤10 `_ion-s-` | 0.5 unit |
| **P** | partial/include (no standalone render) | 0.25 unit |

\* "unit" ≈ a focused half-day incl. screenshot verification. Calendar time
depends on release cadence — don't read units as a fixed schedule.

---

## Phase 0 — Foundation (prerequisite for every wave)

| Task | Status |
|---|---|
| Lock component vocabulary in `ion-ui-kit.html` | ✅ |
| Port `ion-*` layer into `static/css/ion-ui.css` (on ION's real tokens) | ✅ |
| Wire stylesheet into `base.html` (additive; touches no page markup) | ✅ verified — Cases renders unchanged, 0 console errors |
| Optional: add an in-app `/styleguide` page (dev-only) as living reference | ☐ |

Foundation is **additive** — it changes no existing page until that page opts in.

---

## Wave plan

Ordered for value-then-risk: warm up on a couple of mid pages, take the
high-traffic core, then sweep by nav area. XL pages each get their own slot.

### Wave 1 — Core SOC + the new feature  *(highest traffic)*
| Template | Lines | `_ion-s` | Tier | Notes | Status |
|---|--:|--:|:--:|---|:--:|
| **daily-work** (new page) | — | — | M | First page born native in the kit; ships the feature | ☐ |
| dashboard_v2 | 707 | 4 | M | Warm-up; visible landing page | ☐ |
| observables | 2,580 | 36 | XL | Tables + detail panels | ☐ |
| cases | 4,590 | 115 | XL | Kanban + case panel + modals | ☐ |
| alerts | 10,647 | 222 | XL | Biggest file; split into sub-tasks (table / analytics / detail panel / dashboard tab) | ☐ |

### Wave 2 — Investigation & queue
| Template | Lines | `_ion-s` | Tier | Status |
|---|--:|--:|:--:|:--:|
| investigation_queue | 458 | 0 | M | ☐ |
| investigation_memory | 629 | 3 | M | ☐ |
| entity_timeline | 222 | 5 | S | ☐ |
| analyst | 437 | 0 | M | ☐ |
| analyst_efficiency | 150 | 7 | S | ☐ |
| case_grouper | 190 | 2 | S | ☐ |
| tuning_proposals | 144 | 3 | S | ☐ |
| shift_handover | 313 | 19 | M | consumer of daily-work handover | ☐ |

### Wave 3 — Response & forensics
| Template | Lines | `_ion-s` | Tier | Status |
|---|--:|--:|:--:|:--:|
| forensics | 1,752 | 130 | XL | ☐ |
| pcap | 1,062 | 147 | L | ☐ |
| playbooks | 1,721 | 29 | L | ☐ |
| topology | 1,595 | 19 | L | ☐ |
| network_map | 829 | 5 | L | canvas/graph — verify viz unaffected | ☐ |
| arkime_traffic | 852 | 0 | L | Chart.js — verify charts | ☐ |
| alert_arkime | 468 | 1 | M | ☐ |
| canaries | 353 | 2 | M | ☐ |

### Wave 4 — Threat intel & briefings
| Template | Lines | `_ion-s` | Tier | Status |
|---|--:|--:|:--:|:--:|
| threat_intel | 1,375 | 118 | XL | ☐ |
| daily_standup | 1,192 | 5 | L | ☐ |
| knowledge_graph | 196 | 2 | S | viz | ☐ |
| threat_intel_actor | 170 | 0 | S | ☐ |
| stories | 472 | 0 | M | ☐ |
| social | 472 | 1 | M | ☐ |
| executive_report | 168 | 9 | S | ☐ |
| briefing | 238 | 4 | S | ☐ |
| briefings | 144 | 0 | S | standalone presenter — careful | ☐ |
| daily_standup_slides | 773 | 17 | L | standalone slide deck — careful | ☐ |

### Wave 5 — Detection engineering
| Template | Lines | `_ion-s` | Tier | Status |
|---|--:|--:|:--:|:--:|
| detection_engineering | 1,658 | 109 | XL | ☐ |
| discover | 1,516 | 31 | XL | ☐ |
| engineering_analytics | 908 | 9 | L | ☐ |
| gitlab | 967 | 10 | L | ☐ |
| data_flow | 623 | 20 | M | ☐ |
| architecture | 634 | 4 | M | ☐ |
| log_sources | 353 | 4 | M | ☐ |
| scheduler | 356 | 4 | M | ☐ |
| alert_prompt_templates | 533 | 19 | M | ☐ |
| bob_eval | 245 | 0 | S | ☐ |

### Wave 6 — Knowledge & training
| Template | Lines | `_ion-s` | Tier | Status |
|---|--:|--:|:--:|:--:|
| training | 9,509 | 206 | XL | second monster; split into sub-tasks (matrix / schedule / coverage) | ☐ |
| documents | 1,554 | 13 | XL | ☐ |
| template_form | 1,089 | 7 | L | ☐ |
| tools | 1,063 | 10 | L | ☐ |
| guide | 697 | 66 | M | ☐ |
| guide_sim | 586 | 0 | M | ☐ |
| template_render | 698 | 10 | M | ☐ |
| template_view | 603 | 6 | M | ☐ |
| cyber_range | 360 | 14 | M | ☐ |
| templates | 683 | 2 | M | ☐ |
| lesson | 448 | 0 | M | ☐ |
| admin_course_edit | 401 | 17 | M | ☐ |
| profile | 396 | 13 | M | ☐ |
| notes | 270 | 1 | S | ☐ |
| courses | 125 | 0 | S | ☐ |
| my_courses | 153 | 0 | S | ☐ |
| course_detail | 148 | 2 | S | ☐ |
| admin_courses | 184 | 4 | S | ☐ |

### Wave 7 — CyAB (subsystem; mostly partials)
| Template | Lines | Tier | Status |
|---|--:|:--:|:--:|
| cyab/scoping | 104 | S | ☐ |
| cyab/overview | 86 | S | ☐ |
| cyab/systems_list | 63 | S | ☐ |
| cyab/audit | 62 | S | ☐ |
| cyab/coverage | 62 | S | ☐ |
| cyab/system_detail | 52 | S | ☐ |
| cyab/onboard | 31 | S | ☐ |
| cyab/_*.html (12 partials) | 19–145 | P | ☐ |

### Wave 8 — Admin, settings & misc
| Template | Lines | `_ion-s` | Tier | Status |
|---|--:|--:|:--:|:--:|
| settings | 2,704 | 15 | XL | ☐ |
| chat | 2,180 | 9 | XL | ☐ |
| analytics | 1,607 | 55 | XL | ☐ |
| integrations | 1,438 | 5 | XL | ☐ |
| security_dashboard | 1,052 | 4 | L | ☐ |
| users | 526 | 5 | M | ☐ |
| maturity | 572 | 14 | M | ☐ |
| compliance | 216 | 6 | S | ☐ |
| soc_health | 164 | 8 | S | ☐ |
| audit_logs | 178 | 0 | S | ☐ |
| versions | 183 | 2 | S | ☐ |
| service_accounts | 121 | 9 | S | ☐ |
| ai_scorecard | 197 | 0 | S | ☐ |
| translator | 268 | 0 | S | ☐ |

### Wave 9 — Standalone pages & shared chrome  *(do last; highest blast radius)*
| Template | Lines | Tier | Notes | Status |
|---|--:|:--:|---|:--:|
| base.html | 621 | L | shared chrome/nav — re-skinning here touches **every** page; do after pages already overridden locally | ☐ |
| _nav_tabs | 33 | P | nav | ☐ |
| _components | 260 | P | shared macros | ☐ |
| _icons | 69 | P | icon defs | ☐ |
| login | 348 | M | **standalone** — own `<style>`, no base.html | ☐ |
| wallboard | 689 | L | **standalone** display board — own CSS, full-screen | ☐ |

### Wave 10 — Cleanup
| Task | Status |
|---|:--:|
| Prune orphaned `_ion-s-*` rules from `ion-migrated-styles.css` once unreferenced | ☐ |
| Remove dead per-page `<style>` blocks fully replaced by `ion-*` | ☐ |
| Final full-app screenshot regression pass | ☐ |

---

## Per-template acceptance criteria (every migration)

1. Page uses `ion-*` components; bespoke `<style>` block reduced to only
   genuinely page-unique rules.
2. No new inline `style="…"` (CSP `style-src-attr 'none'` still holds).
3. All `data-click-action` / event-delegation behaviour preserved.
4. Screenshot diff reviewed against the pre-migration page — layout intact,
   no regressions in interactive widgets (charts, canvas viz, modals).
5. Affected-module tests + `ruff` + strict import green (per project policy).

---

## Effort & cadence (honest estimate)

| Tier | Count | Units each | Subtotal |
|---|--:|--:|--:|
| XL | ~12 | 4 | ~48 |
| L | ~13 | 2 | ~26 |
| M | ~22 | 1 | ~22 |
| S | ~20 | 0.5 | ~10 |
| P | ~15 | 0.25 | ~4 |
| **Total** | **~82 pages/partials** | | **~110 units** |

At ~1 wave per release (the project's normal `0.x` cadence), this is roughly
**8–10 feature releases** of background work running alongside other features —
a genuine multi-month program. Front-loaded value: Phase 0 + Wave 1 deliver the
new look on the busiest pages early; the long tail migrates steadily.

## Risks & special handling

- **alerts.html (10.6k lines) & training.html (9.5k)** — too big for one pass.
  Split each into sub-tasks by section and migrate/verify independently.
- **Standalone pages** (`login`, `wallboard`, slide decks) don't inherit
  `base.html`'s stylesheet links — they need the `ion-ui.css` link added
  directly, or the components inlined.
- **base.html last** — re-skinning shared chrome changes every page at once;
  defer until individual pages already control their own look, to keep blast
  radius contained.
- **Viz pages** (`network_map`, `topology`, `arkime_traffic`, `knowledge_graph`,
  charts) — verify the canvas/Chart.js rendering is untouched by CSS changes.
- **CSP** — all styling stays in stylesheets / nonced blocks; no inline
  `style=` or `onclick=`. Dynamic values go through `data-*` + JS (the existing
  ION pattern).
