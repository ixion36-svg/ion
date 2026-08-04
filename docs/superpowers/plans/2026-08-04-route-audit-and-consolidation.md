<!-- ion-doc:type=ROADMAP -->
<!-- ion-doc:title=ION Route Audit & Consolidation -->
<!-- ion-doc:subtitle=Full inventory of the 912 HTTP routes; delete / condense / move plan -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:date=2026-08-04 -->

# ION Route Audit & Consolidation

Full audit of every HTTP route, 2026-08-04. Inventory built by parsing all
`@router`/`@app` decorators, resolving each router's mount prefix from
`server.py`, then cross-referencing every path against templates, static JS,
tests, Python, the CLI, the MCP server, and the public docs.

**Scale:** 912 routes · 94 modules under `src/ion/web/` · 88 mounted routers · 96 page routes.

## Headline

- **Zero exact `(method, path)` duplicates** and **zero unmounted routers** — there is no literal duplication. The debt is *semantic*: parallel systems, split families, and stale endpoints.
- **The page layer is healthy.** 96 pages, no broken nav links, only 2 genuine orphans.
- **The API layer is where the sprawl is:** 103 dead routes, 9 families split across multiple files, and 16 routes carrying a prefix that describes neither their storage nor their domain.

## Method note — why naive "unused" scans lie

A literal path scan flagged 228 routes as unreferenced. **94 of those (41%) were false
positives.** The frontend almost never writes a full path; it uses a per-page base
constant (`const API = '/api/threat-intel'`), a helper that prepends it
(`apiFetch('/tide/de/posture')`), or a variable segment
(`` fetch(`/api/admin/config/${section}`) `` covers 12 routes in one line). Any future
dead-code sweep MUST expand these before deleting. The 228 resolved to
**103 dead / 94 reachable / 31 keep-despite-no-UI-caller**.

---

## A. Correctness findings (fix regardless of any cleanup)

These surfaced during the audit and are not tidiness items.

1. **Chain-of-custody ledger gap — `forensics_api.py`.** `forensic_ledger_service`
   is called from exactly one place (`forensic_workbench_api.py:241`).
   `forensics_api.py` has **zero** ledger references and the repository layer
   writes none. Evidence added via `forensics_api.py:407` hits the same
   `repo.add_evidence()` as the workbench upload but leaves **no ledger entry** —
   while `/api/forensics/cases/{id}/ledger/verify` attests the chain as complete.
   Same for case close, lock/unlock, custody entries, timeline notes. This is a
   tamper-evidence hole in the feature whose purpose is tamper-evidence.

2. **Lab completion bypasses grading — `course_api.py:635`.** `mark_lesson_complete`
   guards `QUIZ` but not `LAB`, so a LAB lesson can be completed through the generic
   endpoint, skipping `LabGradingService` and skipping teardown of materialised mock
   data (leaking seeded rows). The error string says "this endpoint is for
   reading/lab", so it was deliberate — treat as a decision to revisit, not a slip.

3. **Legacy proposal pipeline is live but stranded.** Bob auto-creates
   `TuningProposal` rows (`investigation_service.py:641`) and Detection Health drafts
   more (`detection_health_api.py:84`), but the review UI `/tuning-proposals` has
   **no nav link anywhere** — reachable only by typing the URL. Proposals accumulate
   unreviewed.

---

## B. The three parallel proposal systems

| System | Model | Routes | Perm | Shipped | Governance |
|---|---|---|---|---|---|
| Legacy tuning | `TuningProposal` | `/api/tuning-proposals/*` (5) + `/api/detection-health/tuning-proposal` | `tuning:review` | pre-v0.47 | none |
| DE detection | `DetectionProposal` | `/api/de/proposals/*` (7) | `de:propose` | v0.56.0 | decision record, outcome measurement |
| DE Bob-tuning | `BobTuningProposal` | `/api/de/bob-proposals/*` (9) | `de:approve` | v0.58.0 | SoD, versioned, one-click revert |

Three ways to say "this rule is noisy". The DE ones are strictly better governed.
**Recommendation: migrate the legacy flow into the DE module and retire it** —
repoint `investigation_service.py:641` and `detection_health_api.py:84` at
`DetectionProposal`, then delete `tuning_proposal_api.py`, the `/tuning-proposals`
page, and the `tuning:read`/`tuning:review` perms. Alternative (cheaper, worse):
just add the missing nav link and keep three systems.

---

## C. Structural: 9 families split across files

| Family | Routes / files | Verdict |
|---|---|---|
| `/api/arkime/*` | 11 / 2 | **DELETE** `/api/arkime/traffic/status` — strict subset of `/api/arkime/status`, same service + permission. Repoint `arkime_traffic.html:1034`. Then **rename** `arkime_api.py` → `alert_arkime_api.py` (100% of its remaining routes are `/api/alerts/*`). |
| `/api/threat-intel/*` | 17 / 2 | **MERGE** `threat_watch_gap_api.py` (135 lines, 2 routes) into `threat_intel_api.py`. `/check-and-notify` has been notify-less since v0.9.76 per its own comment — collapse into `/check`. Align perm (`alert:read` → `observable:read`). |
| `/api/admin/*` | 37 / 3 | **MERGE** `skill_publisher_api.py` into `alert_prompt_api.py` + re-prefix to `/api/alert-prompts/*` — it exports `AlertPromptTemplate`, and `/api/admin/skills/*` collides semantically with `/api/skills/*` (agent skills vs analyst competencies). |
| `/api/elasticsearch/*` | 47 / 5 | **Mostly principled** — a documented, half-finished god-module split (increments 2 & 3 done; 4 blocked on KFP↔`close_alert` entanglement). Two wrong seams: move `api.py:5528` + `api.py:5585` (case sub-resources) → `case_lifecycle_api.py`; fix `assignment_users` → `assignment-users` (only snake_case path in the app). |
| `/api/forensics/*` | 40 / 2 | **RE-SPLIT by layer, not by release.** Move evidence+custody (`forensics_api.py:407-500`) next to the ledger append so all evidence mutation can write it; rename `forensic_workbench_api.py` → `forensic_evidence_api.py`. Closes finding A1. |
| `/api/courses/*` | 15 / 2 | **KEEP SPLIT** (labs is a real lifecycle subsystem) + add the LAB guard (finding A2). Give both routers a real prefix — both currently register absolute paths under `prefix=""`. |
| `/api/skills/*` | 34 / 2 | **KEEP SPLIT** (distinct model + service) but re-mount consistently — `role_skills` uses a different convention from `skills`. Route the `UserCareerGoal` write through skills_api's own service. |
| `/api/cyab/*` | 87 / 2 | **MOVE** the 5 API routes out of `server.py` (lines 1500, 1957, 2010, 2054, 2098) into `cyab_api.py`. ⚠ Doubled-prefix trap: rewrite to relative paths. The `_cyab_wizard_redirect` helper (`server.py:1865`) carries an open-redirect guard and must move with them. |
| `/api/alerts/*` | 3 / 2 | 3-route island. Resolve **together with** the elasticsearch re-prefix decision below, not separately. |

## D. The largest naming debt

`/api/elasticsearch/alerts/cases/*` — **16 routes** — are Postgres `AlertCase` rows and
Ollama calls, not Elasticsearch. `elasticsearch` here means "alerts that originally came
from Elastic": a lineage artifact from when `api.py` was one module. Same for
`/api/elasticsearch/alerts-triage/*` (Postgres `AlertTriage`).

**Proposed:** `/api/elasticsearch/alerts/cases/*` → `/api/cases/*`, and
`/api/elasticsearch/alerts-triage/*` → `/api/alerts/triage/*`, keeping the old paths as
redirects for one release. `elasticsearch_api.py`'s own 18 routes (config, indices,
discover, ioc-hunt, raw alert reads) genuinely are Elasticsearch and stay.

⚠ **This is a breaking change for external consumers.** `docs/API.md` is
`classification=PUBLIC`, aimed at "integration engineers, customer automation teams, n8n
authors", and advertises a live `/api/openapi.json`. Needs an explicit decision.

---

## E. Deletion list — 103 confirmed-dead routes

Verified against templates, static JS (with base-URL expansion), htmx attributes,
tests, all of `src/`, `scripts/`, seed scripts, `loadtest/`, docs, the CLI, and the MCP
server (whose 8 tools query the DB directly and make no HTTP self-calls).

**Whole modules with zero frontend callers (27 routes):** `change_log_api` (5),
`playbook_action_api` (6), `dashboard_layout_api` (4), `report_scheduler_api` (4 — the
service imports `executive_report_service` directly, never over HTTP), `sla_api` (3),
`smtp_api` (2), plus `security_api` (3 of 12).

**Feature blocks that were never wired to a UI:**
- `cyab_api` (27) — org-assessment block (5; no assessment template exists), sub-profile
  catalogue (6; the template refs are Jinja context vars, not fetches), TIDE-direct block
  (7; the DE page only uses `/tide/de/*`), plus `tide_de_kill_chains_alias` whose own
  docstring says *"Deprecated: use /tide/de/use-cases"*.
- `ai_api` (13) — the entire chat-history/session feature (`create_session`,
  `chat_with_history`, `get_history_stats`, …). `chat.html` + `ai-chat.js` never call it.
- `observable_api` (7), `skills_api` (5 — certifications/CMM), `kibana_api` (4 — manual
  import/sync; the background reconciliation loop doesn't use HTTP),
  `elasticsearch_api` (3), `forensics_api` (2), plus ~10 singles.

**In `api.py`:** `POST /api/samples/create` (inline demo-seed blob),
`GET /api/documents/search` (duplicate of `GET /api/documents?search=`),
`POST /api/documents/create` (near-duplicate of `/upload`),
`POST /api/admin/users/resolve-elastic`.

### Must NOT delete (31) — dead in the UI, load-bearing elsewhere
- `POST /api/auth/oidc/callback` — **the Keycloak `redirect_uri`**; deleting it breaks SSO.
- `/api/webhooks/alert`, `/api/webhooks/health` — inbound receivers (RUNBOOK).
- `/api/health/deep` — monitoring probe (DEPLOYMENT.md).
- `/api/arkime/status` — declared interface IF-ARK-06.
- `POST /api/admin/seed-maturity` — operator bootstrap.
- `/api/ai/history/sessions` (exercised by `loadtest/locustfile.py`),
  `/api/elasticsearch/alerts/stats` (exercised by `test_case_integration.py`).
- ~20 more listed in `docs/API.md`'s public router catalogue (`bulk_ops`, `enrichment`,
  `comm_template`, `threat_landscape`, `compliance`, …) — advertised integration
  contracts; removing them is a breaking change regardless of UI usage.

**One to re-verify by hand:** `GET /api/stats` (`api.py:2410`). It has no internal
caller — the two `f"{svc.url}/api/stats"` calls in `daily_standup_api.py` target
**Arkime's** stats API, not ION's — but the name is generic enough that an external
proxy or dashboard could hit it.

---

## F. Orphaned pages

Only 2 of 96 are genuine problems: `/tuning-proposals` (finding A3) and `/wallboard`
(zero references anywhere — intentional TV screen, but undiscoverable and undocumented).
The other 4 zero-link pages are correct by design: `/login` (redirect target),
`/cyab/scoping` (deliberately anonymous stakeholder questionnaire),
`/api/network-correlation-report/html` (linked from Traffic Analytics with a query
string), `/api/executive-report/html`.

**`/api/templates` + `/api/documents` (43 routes) are NOT legacy** despite the
"Documentation Template Management System" origin. They're live in the nav as
"Reference" (`base.html:233`), share a tab strip with the Notes page, and `Document`
rows are written by playbook execution reports, forensic case reports, KB embeddings,
and AI chat context — plus a full CLI surface. They have **zero test coverage**, which
is a coverage gap, not a deletion argument.

---

---

## G. Page-level (feature) duplication — full nav sweep

Route-signature analysis cannot see this class: two pages with different paths that
answer the same question. Swept all 83 static pages against the 8 nav groups / 54 items.

**Reachability correction:** almost nothing is truly orphaned. `_nav_tabs.html` is a
sibling tab strip that 20 pages declare locally; the nav dropdown links only to the
*first* tab, so siblings are invisible to a `base.html` grep but visible to the user.
Genuinely unreachable: **`/tuning-proposals` and `/wallboard` only**.

### The systemic finding — one question, many implementations

The app *feels* duplicated because the same measurement is computed independently in
many places behind identically-worded headings, so pages can disagree:

- **Four MTTR implementations + three different FP-rate formulas** —
  `soc_health_service.py:155-198`, `executive_report_service.py:180-187`,
  `analyst_efficiency_service.py:86-98,266`, `analytics_engine.py:456-477`.
  (Exec uses `fp/total_closed`; analyst-efficiency uses `fp/(TP+FP)`.)
- **Five surfaces, one Bob-agreement metric** — `/de-metrics` and `/de-bob` render the
  *same number* from the same ledger, same dedupe, same predicate, same 90d default,
  under two labels in two nav groups. `/detection-health` slices it by rule,
  `/ai-scorecard` by template, `/bob-eval` recomputes it live.
- **Four hand-maintained copies of the AIFeedback dedupe contract**
  (`detection_health_service.py:119`, `de_bob_service.py:48`, `alert_prompt_api.py:149`,
  `bob_eval_service.py:498`) whose own docstrings insist they must stay identical —
  **and one has already drifted**: `/ai-scorecard` does not exclude `auto_escalated`,
  so circuit-breaker abstentions land in its denominator.
- **Three independent alert/case count paths** feeding `/analyst`, `/briefing`,
  `/shift-handover`, plus a fourth in `/wallboard`.

**The durable fix is a shared metrics helper**, not just merging pages.

### Correctness bugs found during the sweep

- **`/bob-eval` P/R/F1 are the same number three times.** Every disagreement does
  `fp += 1; fn += 1` (`bob_eval_service.py:448-451`) → `fp == fn` → precision == recall
  == f1 == the agreement rate. Three statistical names, one value, on a measurement page.
- **`/ai-scorecard`'s headline KPI is a self-documented approximation** —
  `const evaluated = c.sample_size; // good enough for KPI` (`ai_scorecard.html:133`).
- **"Noisy/Silent Rules" mean different things on two pages.**
  `/detection-engineering` Execution tab: noisy = `alert_count>=10 and close_rate>=70`
  (closed *at all*, `cyab_api.py:2048`); `/detection-health`: noisy = `fp_rate>=70`
  (closed *as false positive*, `detection_health_service.py:200`). Silent likewise.
  Same labels, incompatible maths, no cross-reference.
- **`/analyst` "Shift Notes" is `localStorage`-only** (`analyst.html:388,395`) — it
  evaporates on cache clear while the two adjacent note boxes persist.
- **`/daily-standup/slides` reads AI summary + AOB from `localStorage`**, so the deck is
  blank on another machine even though `/save` already persists the standup.

### Actions

| Action | Pages | Evidence |
|---|---|---|
| **MERGE** `/analyst-efficiency` → `/executive-report` (Team tab) | 2→1 | 5 identically-labelled stat cards, both default 7d, conflicting FP formulas |
| **MERGE** `/detection-health` → `/de-metrics` (Rule health tab) | 2→1 | same rule-noise job; complementary columns; conflicting perms (`security:read` vs `de:read`) |
| **MERGE** `/my-courses` → `/courses` (All/Mine toggle) | 2→1 | `list_my_courses` is `list_courses` + enrolment filter + 4 progress fields |
| **MERGE** `/change-requests` + `/bug-reports` → `/service-desk` (tabs) | 2→1 | same model module, same service, same page skeleton |
| **MERGE** `/topology` health map → `/integrations` (view toggle) | 2→1 | same question; `/integrations` has richer data (latency, version compat), `/topology` the better visual |
| **MERGE** `/translator` → `/tools` (15th panel) | 2→1 | text-in/text-out utility like the other 14 |
| **MERGE** `/shift-handover` detail → `/briefing` (Handover tab) | 2→1 | cases opened/closed/backlog computed twice from separate `AlertCase` queries |
| **DELETE** `/engineering-analytics` → 302 `/analytics?tab=systems` | −1 | same `get_system_analytics()`, same headings; port "Index Breakdown" first |
| **DELETE** `/ai-scorecard`, fold KPI tiles into `/alert-prompts` | −1 | renders one existing column; links back for every action |
| **DELETE** `/tuning-proposals` after migrating to `DetectionProposal` | −1 | needs `alert_id`/`investigation_id` + `duplicate` status added first |
| **DELETE** the "Shift handover" card on `/daily-work` | — | client-side, single-user, no severity/MTTR/pending — worse than `/shift-handover` |
| **DELETE** the GitLab config modal (`gitlab.html:60-90`) | — | writes the same `.ion/config.json` as `/settings#gitlab` |
| **RENAME** `/briefings` → `/about` | — | singular/plural collision: live SOC data vs static marketing decks |
| **RENAME** `/investigate`→`/investigation-queue`, `/investigations`→`/investigation-memory` | — | URLs differ by one character; nav labels already read this way |
| **ADD TO NAV** `/wallboard` | — | distinct service + panels + tests, zero inbound links |
| **REPOINT NAV** "Tools" → `/tools` (not `/translator`) | — | 1076-line toolbox is a second-level tab; 277-line single tool is the landing page |
| **MOVE** `/security` → Administration; `/data-flow` → `/guide`; `/soc-roles`+`/admin/courses` → training strip | — | nav-group placement |
| **REFACTOR** `/notes` folders onto `/api/collections` | — | second, incompatible folder system in the same 3-tab strip |
| **KEEP SEPARATE** | `/settings` vs `/integrations` (write vs read) · `/audit-logs` vs `/security` (different tables/producers) · `/compliance` vs `/maturity` (derived vs questionnaire; compliance is *evidence for* a maturity answer) · `/network-map` · `/architecture` · `/de-bob` · `/bob-eval` (live re-run, not ledger read) · `/daily-standup` (platform-health ritual + sign-off) |

**Also worth a look outside this audit:** `/stories` vs `/playbooks` — two automation
executors, two step catalogues, two run-history UIs, one concept. `story_api.py:1` calls
itself *"JSON-DAG playbook automation"*.

Net: **83 pages → ~72**, with the duplicated *metrics* consolidated behind shared helpers.

## Phasing

### Progress

- **Phase 0 — DONE.** Ledger appends added to the three evidence-chain mutations in
  `forensics_api` (`evidence_add` / `evidence_update` / `custody_entry`, appended inside
  the transaction so a ledger failure rolls the mutation back); LAB guard added to
  `course_api.mark_lesson_complete` (UI already used the lab endpoint — this closes a
  direct-API bypass of grading + fixture teardown); `/tuning-proposals` linked from the
  Engineering nav as a stop-gap until phase 8. Tests: `tests/test_route_audit_phase0.py`.
- **Phase 1 — core done.** Removed 6 fully-dead routers (`change_log`,
  `dashboard_layout`, `playbook_action`, `report_scheduler`, `sla`, `smtp` — each
  verified 0 refs in templates/static/tests/docs and absent from the public API
  catalogue), the `/api/arkime/traffic/status` duplicate (frontend repointed to
  `/api/arkime/status`), and 4 dead `api.py` routes (`samples/create`,
  `documents/search`, `documents/create`, `admin/users/resolve-elastic`). App route
  count 912 → 743. *Services* for `playbook_action` / `report_scheduler` / `smtp` are
  live elsewhere and were kept — only their unused HTTP surface went. `change_log` /
  `dashboard_layout` / `sla` services are now unreferenced (follow-up sweep).
  **Remaining, not yet cut:** the per-route dead entries inside live modules
  (`cyab_api` 27, `ai_api` 13, `observable_api` 7, `skills_api` 5, `kibana_api` 4,
  `security_api` 3, `elasticsearch_api` 3, `forensics_api` 2 + singles) — each needs
  individual verification and was deliberately not batch-deleted.
- **Phase 2 — partial.** `threat_watch_gap_api` merged into `threat_intel_api`: the two
  routes collapse to a single `GET /api/threat-intel/watches/gaps` (the POST
  `check-and-notify` had not notified since v0.9.76 and differed only by a derived
  counter), permission aligned `alert:read` → `observable:read`, module deleted, stale
  guide.html text corrected. **Remaining:** 5 CyAB routes out of `server.py`,
  `skill_publisher` → `alert_prompt` re-prefix, 2 case routes → `case_lifecycle_api`.
- **Phase 3 — done (the load-bearing part).** Mounting conventions normalised:
  `role_skills` now mounts at `prefix="/api/skills"` with an in-router `/role-match`
  (matching `skills_router` instead of using a third convention), and `arkime_api` no
  longer self-prefixes — it mounts at `prefix="/api"` like every other router. Both
  changes proven **URL-neutral** by diffing the full 883-entry route/method set before
  and after: zero added, zero removed. *Deliberately skipped:* the forensics re-split.
  Its stated purpose was closing the ledger gap, which phase 0 fixed directly at the
  mutation sites — re-splitting now would be file reorganisation with regression risk
  and no functional gain. `course_api`/`labs_api`'s `prefix=""` is also left alone:
  their decorators carry absolute paths, so converting is churn without benefit.
- **Phase 4 — done, as ALIASES not a re-prefix.** `/api/cases/*` and
  `/api/alerts/triage/*` are now published as canonical paths. Implemented as a single
  central mechanism in `server.py` (`_install_path_aliases`) that, after mounting,
  registers a second `APIRoute` for each legacy route pointing at the **same endpoint
  object** with the same response model / status / dependencies — rather than editing
  18 decorators across 5 files (easy to miss one) or issuing 3xx redirects (fragile for
  POST/PATCH/DELETE method+body preservation, and `docs/API.md` is a PUBLIC integration
  contract). 18 aliases registered. All 52 in-repo frontend call sites migrated to the
  canonical paths across `alerts.html`, `cases.html`, `analyst.html`, `dashboard_v2.html`;
  legacy paths remain fully served so external integrators are unaffected.
  Tests: `tests/test_route_audit_phase4_aliases.py` pins that every legacy route has a
  twin **bound to the same endpoint**, so the two can never drift.
  *Remaining for a future release:* retire the legacy paths once integrators have
  migrated, and update `docs/API.md` to advertise the canonical ones.

| Phase | Content | Risk |
|---|---|---|
| **0** | Correctness: forensics ledger gap, LAB guard, `/tuning-proposals` nav (or DE migration) | Low, high value |
| **1** | Delete the 103 dead routes + `/api/arkime/traffic/status` duplicate | Low — nothing calls them |
| **2** | Merge `threat_watch_gap` → `threat_intel`; `skill_publisher` → `alert_prompt`; move 5 CyAB routes out of `server.py`; move 2 case routes to `case_lifecycle_api` | Medium — internal moves, watch the doubled-prefix trap |
| **3** | Forensics re-split by layer; mounting-convention normalisation; router prefixes for course/labs | Medium |
| **4** | Re-prefix `/api/elasticsearch/alerts/cases/*` → `/api/cases/*` with one-release redirects | **Breaking** — needs a decision on the public API contract |
| **5** | Metric consolidation: one shared case-metrics helper (kills 4 MTTR / 3 FP-rate impls) + one `deduped_feedback()` helper (kills 4 copies, 1 already drifted). Fix `/bob-eval` P/R/F1, `/ai-scorecard` KPI, noisy/silent label clash. | Medium — behaviour-visible numbers change (they become *correct*) |
| **6** | Cheap page wins: nav repoint ("Tools"), `/wallboard` to nav, rename `/briefings`→`/about` + investigate/investigations, delete `/daily-work` handover card + GitLab config modal | Low |
| **7** | Page merges: analyst-efficiency→executive-report, detection-health→de-metrics, my-courses→courses, change-requests+bug-reports→service-desk, topology→integrations, translator→tools, shift-handover→briefing; delete `/engineering-analytics` + `/ai-scorecard` | Medium — UI moves + redirects for old URLs |
| **8** | `TuningProposal` → `DetectionProposal` migration (add `alert_id`/`investigation_id`/`duplicate` status), then delete `/tuning-proposals` + `tuning:*` perms | Medium — schema + repoint 2 write paths |

One release per phase, affected-module tests, 8-file ritual.

**Sequencing note:** Phase 5 (shared metrics helpers) should land *before* Phase 7,
because several merges assume one canonical number per metric. Phase 0's
`/tuning-proposals` nav link is the stop-gap until Phase 8 lands.
