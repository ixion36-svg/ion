# CyAB IA redesign — design spec

**Date:** 2026-05-04
**Status:** Approved (brainstorming session, terminal + visual companion)
**Target version:** v0.19.0 (proposed)

## Context

CyAB today is two oversized pages under one nav entry:

- `/cyab` — 3,543-line dashboard (systems table, KPIs, due reviews, data sources, snapshots, TIDE)
- `/cyab/studio` — 1,494-line per-system page (intake + detection + audit + checklist + onboarding pack)

Most of the moving parts the user wants — pillars, sub-profiles, doc checklist (20 default items + critical-items gate), coverage rollups, sign-off, assessment scoring — already exist as backend features. They're just buried.

The trigger: the user has hundreds of systems to onboard, and all four typical flows (new system / resume work / pivot edit / fleet query) happen heavily. The current two-page IA can't carry that load.

## Primary user

SOC engineer (day-to-day). Manager and compliance/audit are secondary.

## Goals

1. Make the onboarding-progress state visible at a glance, per-system and across the fleet.
2. Support the full lifecycle: pre-onboarding scoping → first-session wizard → ongoing per-system work → fleet review → sign-off → audit trail.
3. Reuse the substantial existing backend (sub-profile catalogue, doc checklist service, assessment scoring, sub-profile coverage rollup) without rewriting.
4. Keep the doc checklist (HLD, LLD, Network Topology, …) as a first-class progress signal — not buried in a tab.
5. Add a stakeholder-facing scoping tool that answers "given your tech stack, here's what coverage you'd get."

## Sitemap

Seven top-level pages under the existing `Engineering → CyAB` nav entry. Inside CyAB, a secondary tab strip exposes the section pages.

| URL | Purpose | Audience |
|---|---|---|
| `/cyab` | Overview · KPIs, "in progress" feed, "needs attention" feed | manager / audit (landing) |
| `/cyab/systems` | Portfolio list · table + filters + bulk ops | SOC engineer (primary) |
| `/cyab/scoping` | Stack-to-use-cases discovery · presentable output | non-tech stakeholder discussions |
| `/cyab/onboard` | First-session wizard (4 steps) | SOC engineer creating new system |
| `/cyab/coverage` | Fleet data-health matrix (systems × dimensions) | manager / audit |
| `/cyab/audit` | Compliance trail · sign-offs, changes, snapshots | audit (rename candidate: `/history`) |
| `/cyab/systems/{id}` | Per-system page · sticky progress + 7 tabs | SOC engineer (primary working surface) |

### Per-system tabs

Sticky header on every tab: progress bar (e.g. `12/20 done`), critical-missing pill, last-edited timestamp.

1. **Overview** — checklist grouped by category (Critical first, then Design / Operational / Security / Compliance). Each item links to where to fix it. "Add custom item" inline.
2. **Intake** — sub-profile-driven questions; auto-save; progress count.
3. **Sources** — data source rows (existing `CyabDataSource`); add/edit/delete; field mapping editor.
4. **Data Health** — 4 panels (3 in Phase 1, 1 deferred):
   - Ingestion freshness — last event seen, SLA pill
   - Field mapping completeness — % of expected fields present in samples
   - Coverage rollup — intake/detection/audit %
   - *Reconciliation drift (Phase 2; needs CMDB integration)*
5. **Detection Use Cases** — sub-profile catalogue; per-use-case status (shipped / partial / gap / n/a) + "generate TIDE rule" button (existing).
6. **Audit Use Cases** — same shape as Detection.
7. **Sign-off** — Onboarding Pack PDF preview · containment authority · sign button · prior sign-offs list.

Naming note: per-system "Audit Use Cases" (security audit content) is distinct from top-level "Audit Trail" (compliance log). Both kept; renaming the top-level page to `/cyab/history` is on the table if the overload bites in practice.

## Onboarding wizard (`/cyab/onboard`)

Four steps. Wizard never blocks — user can exit anywhere and resume on the per-system page.

1. **Identity** — name, hostname(s), pillar, sub-profile, owner, department, containment authority.
2. **Intake** — questions from sub-profile catalogue (autosave). Live recommendation counter on the side: "47 use cases · 12 threat-actor matches · 64% coverage" (powered by the shared scoring engine — see Scoping section).
3. **First data source** — type, ingestion endpoint, expected event types. Creates one source row; more added later.
4. **Doc placeholders** — pre-create the 20 checklist items. User can attach docs now or mark "I'll do this later" → leaves item as `missing` (visible in Overview).

Finish → drops into `/cyab/systems/{id}` with the Overview tab highlighting what's missing.

## Scoping tool (`/cyab/scoping`)

A standalone questionnaire surface for the "given your tech stack" conversation with non-technical stakeholders. No system is created.

- **Input** — progressive questionnaire (~12-20 questions): identity provider, endpoint platform, cloud, email/collab, network edge, compliance regime. Each answer narrows recommendations.
- **Live counter** as they answer: "47 use cases · 12 threat-actor matches · 64% MITRE Initial Access coverage."
- **Output page** — shareable summary: "Recommended for your stack: 247 detection rules, 89 audit checks, 23 threat-actor profiles, full MITRE coverage map." Downloadable PDF (reuse the existing onboarding-pack PDF generator).
- **"Convert to system"** CTA — spin up a real `/cyab/onboard` session pre-filled with these answers.

### Engine architecture (the "scope for all" part)

Single shared question set (data-driven, JSON or DB) and a single shared scoring engine that extends `cyab_assessment_service`. Three planned consumers:

| Consumer | Phase |
|---|---|
| `/cyab/scoping` (anonymous, presentable) | 1 |
| `/cyab/onboard` Step 2 (live counter as user answers) | 1 |
| Per-system page "Recommendations" tab (refreshes as intake changes) | 2 |

## Phase scoping

**Phase 1 (this spec):**

- 7 pages: `/cyab`, `/cyab/systems`, `/cyab/scoping`, `/cyab/onboard`, `/cyab/coverage`, `/cyab/audit`, `/cyab/systems/{id}`
- Sticky progress header on every per-system tab
- Per-system tabs: Overview · Intake · Sources · Data Health (3 panels) · Detection Use Cases · Audit Use Cases · Sign-off
- Scoping page with shared engine
- Wizard Step 2 wired to same engine
- Data Health panels 1-3 (ingestion freshness, field mapping completeness, coverage rollup)

**Phase 2:**

- Reconciliation drift (Data Health 4th panel) — needs CMDB integration
- Per-system Recommendations tab (live re-scoping)
- Bulk operations on `/cyab/coverage` (mark reviewed across many systems)

## Code reuse vs new build

### Reuse (already in code)

| Existing | Becomes |
|---|---|
| Studio's intake / detection / audit catalogue tabs (`cyab_studio_api.py`) | Per-system page tabs (Intake / Detection Use Cases / Audit Use Cases) |
| Dashboard's systems table + KPIs (`cyab_api.py`) | Splits into `/cyab` KPI strip + `/cyab/systems` portfolio table + `/cyab/coverage` matrix |
| `cyab_doc_checklist_service` | Drives Overview tab + sticky progress bar + `/cyab/coverage` matrix |
| `cyab_subprofile_service.system_coverage()` | Drives the rollup % everywhere |
| `cyab_assessment_service` | Extends into shared scoring engine |
| Sign-off + Onboarding Pack PDF (`cyab_studio_api.py`) | Moves into per-system Sign-off tab + reused for `/cyab/scoping` PDF export |
| `CyabSnapshot` model | Powers `/cyab/audit` snapshot index |

### New build

- `/cyab/onboard` wizard (4 steps, autosave, can exit anywhere)
- `/cyab/coverage` matrix page (systems × data-health dimensions)
- `/cyab/audit` chronological feed page
- `/cyab/scoping` page (questionnaire UI + summary + PDF export + "convert to system" CTA)
- Shared question set + scoring engine module (extends `cyab_assessment_service`)
- Data Health tab — backend: ingestion freshness query (ES last_seen per source), field-mapping completeness check (sample event vs expected fields per source type)
- Sticky progress header component (template partial reused on every per-system tab)
- "In progress" + "Needs attention" feeds for `/cyab` Overview

### URL deprecation

- `/cyab/studio` → 301 redirect to `/cyab/systems/{id}` if a system is selected, else `/cyab/systems`. Keep the redirect for one minor version, then drop.

## Navigation

- `Engineering` dropdown `CyAB` entry stays as the parent link to `/cyab`.
- Inside CyAB pages, a secondary tab strip: `Overview · Systems · Scoping · Onboard · Coverage · Audit`.
- Per-system pages add breadcrumb: `CyAB · Systems · prod-sso-keycloak`.

## Out of scope

- Topology / system-relationship widgets (most CyAB systems are independent; the few with `parent_system_id` can be handled later).
- Multi-tenant / org-level role split beyond the existing CyAB permissions.
- Mobile-first layouts (CyAB is a desk-tool — responsive is fine, mobile is not the design driver).

## Open questions for the implementer

1. Is "ingestion freshness" driven by querying ES per-system data source, or by a periodic background sync that caches last-seen per source? Background sync scales better at hundreds of systems.
2. Field-mapping completeness needs an "expected fields per source type" definition. Where does it live — alongside sub-profile catalogue, or its own data-source-type module?
3. Scoping questionnaire schema — JSON file in code (versioned with the app), or DB-stored (editable at runtime)? Code is simpler for v1; DB enables ops to tweak without a release.
4. PDF export for `/cyab/scoping` — reuse `_render_onboarding_pack_pdf` or build a separate "scoping pack" template? Probably the latter, since the audience is different.
