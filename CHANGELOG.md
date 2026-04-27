# Changelog

## v0.11.4 (2026-04-27)

### Course admin authoring UI

Curriculum work no longer requires running the seeder. Admins (anyone with the existing `playbook:create`/`update`/`delete` permissions) can author courses end-to-end through the UI.

#### CRUD endpoints (10 new)

| Method | Path | Action |
|---|---|---|
| `POST` | `/api/courses` | Create a course shell |
| `PUT` | `/api/courses/{id}` | Update course metadata |
| `DELETE` | `/api/courses/{id}` | Delete (cascades to modules → lessons → questions) |
| `POST` | `/api/courses/{id}/modules` | Add a module |
| `PUT` | `/api/modules/{id}` | Update module |
| `DELETE` | `/api/modules/{id}` | Delete module |
| `POST` | `/api/modules/{id}/lessons` | Add a lesson |
| `PUT` | `/api/lessons/{id}` | Update lesson metadata + content_md |
| `DELETE` | `/api/lessons/{id}` | Delete lesson |
| `POST` | `/api/lessons/{id}/questions` | Add a question |
| `PUT` | `/api/questions/{id}` | Update question (kind, stem, options, correct, explanation, points) |
| `DELETE` | `/api/questions/{id}` | Delete question |

All mutating endpoints validate kind/lesson_type enums + slug uniqueness.

#### JSON import/export

- `GET /api/courses/{slug}/export` — full course tree as JSON, including correct answers + explanations (admins only)
- `POST /api/courses/import` — accepts the same shape, validates, creates the whole tree atomically. 409 if slug collides

The export → import round-trip is byte-stable so courses can be moved between ION instances or version-controlled in git.

#### Admin pages

- **`/admin/courses`** — list of all courses (published + drafts). Each row shows level pill, status pill, hours, pass threshold, and quick actions for Edit / Export. Two dialogs:
  - **+ New course** — minimal form (title, level, slug-optional, hours, pass-threshold, publish-flag). On create, auto-redirects to the editor.
  - **Import JSON** — paste-and-validate. Accepts either `{"course": {...}}` or `{...}` shape; both work.
- **`/admin/courses/{id}/edit`** — full editor:
  - Course metadata card (title, slug, level, hours, pass-threshold, order, publish-flag, description markdown) with a single Save button
  - Modules section — each module is a card with inline title/duration/description editing, Save / + Lesson / Delete buttons
  - Lesson cards — collapsible by default. When expanded: metadata grid (title, type, duration, lab URL), content_md textarea with **live markdown preview pane** (Mermaid diagrams render as you type), then a question editor for each question
  - Question editor — kind dropdown, stem textarea, options as JSON array, correct_answer as JSON, explanation textarea, points input. Two save buttons per question. Validation surfaces inline if JSON is malformed.
  - Image upload card — pick a file → upload → returns the public URL + a markdown snippet ready to paste into any lesson body
  - Top-right action bar — "Preview as analyst →" button opens the published-side `/courses/{slug}` page in a new tab; "Delete course" with confirmation

The editor saves at module / lesson / question granularity (not all-at-once) so an author can save progress on one section without re-validating the rest. Every save shows a toast.

#### Nav

New "Course authoring" entry in the user dropdown's Admin section, alongside Stories / AI Scorecard.

#### Why no full canvas editor?

Markdown + live preview is the right power-curve for v0.11.4. A full WYSIWYG canvas (drag-drop modules, etc.) is plausible but adds 1500+ LOC of frontend work and locks authoring into ION's UX choices — markdown stays portable and git-diffable. v0.11.5+ can layer on richer affordances (drag-reorder, structured question builder for non-technical authors) once the bar of usage is established.

#### Upgrade

Drop in `ion:0.11.4`. No schema changes from v0.11.3. CRUD endpoints register automatically; admin pages live at `/admin/courses` and `/admin/courses/{id}/edit`.

## v0.11.3 (2026-04-27)

### Course depth bar set + image upload + Mermaid vendored

After v0.11.2 shipped the course framework with deliberately-light demo lessons (~800-1200 words each), feedback was unambiguous: **"more depth and visuals like a proper course in the future"**. This ship sets the BTL1 / SANS-style depth bar so the v0.11.4-6 curriculum ships hit it from day one.

#### Demo lesson rewrites (one per tier)

The first reading lesson of each tier rewritten to proper-course depth — these become the quality template for the full curriculum. ~7,800 words of new curriculum content total:

- **L1 — "What happens to an alert?"** — ~2,300 words. Adds explicit learning objectives, prerequisites, deeper explanation of each lifecycle state with ION's actual data-model fields, a Mermaid sequence diagram of a worked end-to-end alert walk (DEMO-0001 from `seed_test_data.py`), four common-mistake patterns each with a fix, and a glossary + further-reading section. **Two diagrams**: lifecycle flowchart + worked-example sequence.
- **L2 — "The hunt hypothesis (PEAK methodology)"** — ~2,600 words. Strong-vs-weak hypothesis rewriting with five real anti-pattern examples, the four-element hypothesis template visualised as a Mermaid graph, full PEAK loop diagram, KQL with line-by-line commentary, refinement table covering structural-vs-content exclusions, hunt-log YAML schema for null results. **Three diagrams**.
- **L3 — "Why purple teaming beats annual pentests"** — ~2,900 words. Full purple-team workflow Mermaid graph, four-tier fidelity decision tree (Alerted / Logged-not-alerted / Unparsed / Not-logged) showing which team owns which gap, scoping-rules section with an exercise-notice template, complete worked T1059.001 cycle from authorisation through scorecard YAML, eight-mistake anti-pattern list. **Two diagrams**.

Every rewritten lesson includes:
- Explicit *learning objectives* + *prerequisites* at top
- Multiple sub-sections with named headings
- Worked scenarios that walk an analyst's actual cognitive process
- Code blocks with inline line commentary
- Glossary of jargon introduced
- Further reading with concrete pointers (ATT&CK, LOLBAS, PEAK, MITRE Evals, etc.)

#### Image upload infrastructure

New endpoint: `POST /api/courses/{slug}/images` accepts multipart-form file uploads with `name_override`. Files land at:

```
src/ion/web/static/img/courses/<course-slug>/<safe-stem>-<random8>.<ext>
```

Served by the existing `/static` mount — air-gap safe, no third-party storage, no CDN. Constraints: PNG/JPG/SVG/WebP/GIF, 5 MB cap, requires `playbook:create` permission, streamed write with size enforcement so a malicious giant upload can't OOM the worker. Returns the public URL plus a markdown-ready snippet for paste into lesson content:

```json
{
  "url": "/static/img/courses/demo-l1.../lifecycle-x7k2m9q1.png",
  "markdown": "![lifecycle](/static/img/courses/demo-l1.../lifecycle-x7k2m9q1.png)"
}
```

#### Mermaid vendored

`static/js/mermaid.min.js` (Mermaid 10.9.1, ~3.3 MB) is now bundled in the image. Air-gap deployments get diagrams out of the box — no curl-from-CDN required. Marked.js configured with a custom code-block renderer in `base.html` that converts ` ```mermaid ` fenced blocks to `<div class="mermaid">` so `mermaid.run()` picks them up. Without this hook, mermaid blocks would render as plain `<pre><code class="language-mermaid">` and never become diagrams.

#### What's deferred (still v0.11.4)

- Admin authoring UI — pushed to v0.11.4. The image upload endpoint is wired, but admins still edit course content via the seeder until the authoring UI lands.
- Inline knowledge-check widgets — embedded mini-quizzes within reading lessons. Requires a custom marked.js extension or custom directive parser; deferred.
- Full L1 / L2 / L3 curriculum — v0.11.4 / .5 / .6 will author the rest of the modules at the bar this ship just set.

#### Upgrade

Drop in `ion:0.11.3`. No schema changes. Run the updated `seed_courses.py` to refresh the demo content (it cleans and re-seeds idempotently):

```
cat seed_courses.py | docker exec -i ion python -
```

## v0.11.2 (2026-04-27)

### Course framework — L1/L2/L3 SOC analyst training (foundation ship)

First of a six-ship sequence building a full BTL1-style training course system for L1/L2/L3 analysts. This ship is the **framework** that everything else hangs off — models, executor, UI, Mermaid support, and one substantial demo lesson per tier to set the quality bar.

#### Models (7 new tables, all auto-create on first boot)

- **`Course`** — id, title, slug (unique), level (`L1`/`L2`/`L3`/`L4`), description_md, estimated_hours, badge_image_path, prerequisite_course_id (self-FK), order_in_level, pass_threshold, published, skill_keys (JSON, links to existing `SkillAssessment`), author_id
- **`CourseModule`** — child of Course, ordered, with own description + estimated minutes
- **`Lesson`** — child of Module. `lesson_type` ∈ `{reading, quiz, lab}`. Markdown body. Lab variant carries an optional `lab_target_url` pointing into ION (e.g. `/cases/1`)
- **`Question`** — child of Lesson. `kind` ∈ `{single, multi, truefalse, shortanswer}`. JSON-backed options + correct-answer + explanation
- **`UserEnrolment`** — one per `(user_id, course_id)`, captures started/completed/badge/score_pct
- **`UserLessonProgress`** — one per `(user_id, lesson_id)`, status, score, attempts
- **`UserAnswer`** — one per quiz attempt, replays preserved (each submission stamps a fresh `attempt_id`)

Distinct from the existing `TrainingPlan` (which tracks external certs like CompTIA/SANS) — Courses are interactive, in-app curriculum.

#### Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/courses` | catalog (filterable by level, published-only by default) |
| GET | `/api/courses/{slug}` | course detail with modules + lessons + per-lesson user progress |
| POST | `/api/courses/{id}/enrol` | self-enrol (blocked if prerequisite course incomplete) |
| GET | `/api/my-courses` | current user's enrolments dashboard payload |
| GET | `/api/lessons/{id}` | lesson content + questions (correct answers stripped) |
| POST | `/api/lessons/{id}/complete` | mark a reading/lab lesson complete |
| POST | `/api/lessons/{id}/submit-quiz` | submit answers; server grades + records attempt + updates progress + recomputes course completion |

Quiz grading: single/truefalse exact match, multi with partial credit (intersection-over-union × max points), shortanswer case-insensitive against an accepted-answer set.

Course completion auto-detection: when *every* lesson is in `completed` status, the enrolment row's `completed_at` is set and `badge_earned` flips to true. If a quiz re-attempt regresses a lesson from `completed` to `failed`, the enrolment is reopened automatically.

#### UI

Three pages — all use the existing `marked.js` + `DOMPurify` markdown stack:

- **`/courses`** — catalog grid by level with a filter strip. Cards show title, description preview, estimated hours, and pass threshold.
- **`/courses/{slug}`** — course detail with a progress bar across all lessons, modules expanded with lesson list, status dots (not_started / in_progress / completed / failed), per-lesson type pill (reading / quiz / lab) and last score.
- **`/lessons/{id}`** — lesson view. Markdown body rendered with full prose styling, then quiz questions inline if applicable. Submit returns per-question feedback with the correct answer + explanation. Pass/fail banner with pass threshold visible.

Nav: new "Courses (L1/L2/L3)" link in the Knowledge dropdown alongside Skills & Training.

#### Mermaid diagrams

Added `<script src="/static/js/mermaid.min.js">` to `base.html` with a graceful-degradation guard. Lesson markdown can include ` ```mermaid ... ``` ` blocks for attack chains, kill chains, lifecycle diagrams. Air-gap deployments need to drop `mermaid.min.js` into `static/js` (not bundled by default — adds ~2 MB to the image).

#### Demo content (one lesson per level)

Substantial Markdown + quiz content seeded by `seed_courses.py`:

- **L1 — Alert Triage Fundamentals** · 1 module, 3 lessons (1 reading + 2 quizzes, ~12 questions): the alert lifecycle as a Mermaid flowchart, the four-tier severity rubric with worked examples, true_positive / false_positive / benign_true_positive distinctions tied to ION's `CaseClosureReason` enum.
- **L2 — Threat Hunting with KQL** · 1 module, 2 lessons (1 reading + 1 quiz, ~4 questions): the PEAK methodology, a worked LotL hypothesis (mshta/regsvr32 invoked from PowerShell), KQL refinement that reduces noise without hiding signal, converting hunts into TIDE rules.
- **L3 — Adversary Emulation Basics** · 1 module, 2 lessons (1 reading + 1 quiz, ~4 questions): purple-team flow as a Mermaid graph, the four detection-fidelity tiers (alerted / logged-not-alerted / unparsed / not-logged), MITRE ATT&CK T1059.001 worked Atomic test, what to record on the scorecard.

Prerequisite locks are wired: L2 requires L1, L3 requires L2.

Each demo lesson is **substantive** — 800-1200 words, real worked examples, citations to ION's own enums and tables. Sets the quality bar for the full curriculum coming in v0.11.4 / v0.11.5 / v0.11.6.

#### Upgrade

Drop in `ion:0.11.2`. New tables (`courses`, `course_modules`, `lessons`, `course_questions`, `course_enrolments`, `course_lesson_progress`, `course_user_answers`) auto-create. Run `seed_courses.py` to populate the demo curriculum:

```
cat seed_courses.py | docker exec -i ion python -
```

#### What's next

- **v0.11.3** — admin authoring UI (no more JSON seeders for course content)
- **v0.11.4 / .5 / .6** — full L1 / L2 / L3 curriculum (each ~8 modules covering BTL1-equivalent depth)
- **v0.11.7** — hands-on labs that link into real ION pages + PDF certificate generation on completion

## v0.11.1 (2026-04-27) — PATCH

### Network Mapper sync: TZ comparison crash

`network_mapper_service._upsert_one` raised `TypeError: can't compare offset-naive and offset-aware datetimes` when comparing the parsed ES `@timestamp` against `NetworkAsset.last_seen` (and the IP/MAC variants). ES timestamps came back TZ-aware via `datetime.fromisoformat("...Z".replace("Z","+00:00"))`, but the DB columns are plain `DateTime` (no `timezone=True`) so SQLAlchemy returned naive values — the `now > asset.last_seen` comparison on lines 234/265/284 then crashed and stopped the sync mid-batch.

Single-line fix in `_parse_host_buckets`: drop tzinfo on `ts` after parsing so it's a naive UTC datetime, matching the DB column shape. Comparisons downstream stay consistent and the sync runs to completion.

## v0.11.0 (2026-04-27)

### Stories — JSON-DAG automation playbooks (Tines-inspired)

Third of three ships borrowing patterns from market SOC tools. This one comes from **Tines's Story model** — JSON-DAG playbooks with a small, opinionated step library and explicit conditional edges instead of nested if/else blocks.

This is a **major-version bump** because it introduces a new automation primitive alongside the existing TIDE-driven `Playbook` catalogue. Stories don't replace playbooks — they're user-authored automation for runtime triage / response, where playbooks are detection-engineering artifacts.

#### What ships in v0.11.0 (linear slice)

- **`Story` + `StoryRun` models** — DAG persisted as JSON, every execution captured with per-step output, status, and duration
- **3 step types** in the executor:
  - `case_note` — append a templated note to a case
  - `bob_investigate_alert` — run Bob's autonomous investigation pipeline against an alert and capture verdict + summary
  - `http_request` — outbound HTTP call, response into context
- **Tiny templating** — `{{ trigger.alert_id }}` / `{{ nodes.<id>.<field>}}` substitution. Not full Jinja — kept narrow on purpose for security on freshly-imported stories
- **Linear executor** — walks `start` node forward via each node's `next` until None or error. Validates the DAG up-front (cycle check + unknown-node refs + unknown-step-types)
- **Admin page at `/stories`** — list rail + raw-JSON editor + run button + recent-runs panel with per-step output expand
- **Endpoints**:
  - `GET /api/stories` · `GET /api/stories/{id}` · `POST /api/stories` · `PUT /api/stories/{id}` · `DELETE /api/stories/{id}`
  - `POST /api/stories/{id}/run` (synchronous; returns the run record)
  - `GET /api/stories/{id}/runs` · `GET /api/story-runs/{run_id}`
  - `GET /api/stories/step-types` (public catalogue)
- **Permissions** — read uses `playbook:read`, create `playbook:create`, update `playbook:update`, delete `playbook:delete`, execute `playbook:execute`

#### What's deferred (to v0.11.1+)

- **Conditional edges** — every node currently has at most one `next`. Branching arrives next ship.
- **Visual canvas editor** — v0.11.0 ships a JSON textarea with validation. Drag-and-drop graph editor is the obvious follow-up.
- **More step types** — Page (human-in-the-loop form), Send-to-Story (subroutine), Email/Slack/Teams notifications, OpenCTI enrich, ES query, observable mutate. The step registry is a single dict in `story_executor.py:_STEP_REGISTRY` — adding a step is one function + one entry.
- **Background execution** — runs are synchronous in v0.11.0 (a `bob_investigate_alert` step blocks ~30 s). Async + WebSocket progress updates land later.

#### Why a new model rather than extending `Playbook`?

Existing playbooks are TIDE-driven detection-engineering artifacts. Stories are user-authored runtime automation — different lifecycle (versioned, importable, executable against arbitrary entities), different audit story, different permission model. Keeping them parallel avoids breaking v0.10.x playbook UI.

#### Upgrade
Drop in `ion:0.11.0`. New tables (`stories`, `story_runs`) created via `Base.metadata.create_all` on first boot. No `.env` changes required.

## v0.10.20 (2026-04-27)

### Attack Story timeline (Hunters-inspired)

Second of three ships borrowing UX patterns from market SOC tools. This one comes from **Hunters AI's "Attack Story"** — a chronological narrative on the case detail page that aggregates every event tied to the case into a single scannable feed, with Bob's latest verdict surfaced as a header narrative.

#### What's new

A **"Attack Story Timeline"** section on every case detail page (top of the right rail, above "Similar Closed Cases"). Two parts:

1. **Bob's take** header — the latest investigation summary with its verdict pill (true_positive / false_positive / etc.) and the key-observation citations rendered as quote-style indented bullets. No extra LLM call needed; reuses the v0.10.11 `key_observations_json` and `summary_text` already persisted on each Investigation row.

2. **Chronological event feed** — a vertical timeline with kind-coloured markers and per-event detail expansion. Three lanes:
   - **🟢 Bob** — autonomous investigations with verdict + key-observation citations
   - **🟡 Analyst** — investigation notes (case status changes, sign-offs, free-text)
   - **⚪ System** — case lifecycle, alert linkage, observable extraction, playbook starts/completions

A counts strip at the top (`N events · X Bob · Y analyst · Z system`) gives the case-load shape at a glance.

#### Backend

New endpoint `GET /api/elasticsearch/alerts/cases/{case_id}/timeline` aggregates from the existing data sources:
- `AlertCase.created_at` / `closed_at` — case lifecycle
- `Note` rows scoped to the case (Bob-authored notes detected via the `🤖 Bob` marker)
- `AlertTriage` entries for linked alerts
- `Investigation` rows linked via `alert_id_ref` (verdict + summary + key_observations cited)
- `ObservableLink` rows for the case (extraction events)
- `PlaybookExecution` rows for the case (start + complete events)

Returns `{events: [...], narrative: {...}, counts: {...}}`. Events are sorted ascending by timestamp; `narrative` carries the latest Bob investigation for the header.

#### No schema changes
Pure aggregation of existing data. Drop in `ion:0.10.20`.

## v0.10.19 (2026-04-27)

### Observable TLP/PAP/IOC + cross-case sightings panel (TheHive 5 inspired)

First of three ships borrowing patterns from market SOC tools — this one from **TheHive 5's observable model**. ION already had `sighting_count`, `first_seen`, `last_seen`, threat-level, watchlist, and enrichment history; this fills in the missing TheHive bits.

#### Schema additions on `observables` (4 new columns)

- `tlp` — Traffic Light Protocol (`red`, `amber`, `green`, `clear`/`white`). Default `amber`.
- `pap` — Permissible Actions Protocol (same scale). Default `amber`.
- `is_ioc` — explicitly distinguishes "tracked malicious indicator" from "value that showed up in an alert but might be benign". Default false.
- `ignore_similarity` — escape hatch to mute high-noise values (`8.8.8.8`, `1.1.1.1`, internal DNS resolvers) from the cross-case sightings panel. Default false.

Idempotent ALTER TABLE migration — pre-v0.10.19 rows take the defaults. `Base.metadata.create_all` handles fresh deployments.

#### Cross-case observable sightings panel

New section on the case detail right-rail: **"Cross-Case Observable Sightings"**, sibling to the existing pgvector-driven "Similar Closed Cases" section. Where the pgvector panel asks *"which other cases look semantically similar?"*, this one asks *"which other cases share the literal same indicator value?"*

For every observable attached to the case (skipping `is_whitelisted` + `ignore_similarity`), the panel lists other cases that share that same `(type, normalized_value)` via the existing `ObservableLink` table. Sorted by sighting count — most-shared indicators surface first. TLP and IOC badges render on each row.

Endpoint: `GET /api/elasticsearch/alerts/cases/{case_id}/similar-observables`. Returns `{shared: [{observable, sightings: [{case_id, case_number, title, severity, status, last_seen}]}]}`.

#### `PUT /api/observables/{id}` extended

The existing update endpoint accepts `tlp`, `pap`, `is_ioc`, `ignore_similarity` in addition to the prior tags/notes/whitelist/threat-level. Lightweight enum-string validation (lowercased, restricted to the four canonical values). Other fields unchanged.

#### Upgrade
Drop in `ion:0.10.19`. Migration runs automatically. No `.env` changes required.

## v0.10.18 (2026-04-27)

### Daily Standup DC/WEF checks — configurable + diagnostic

The Domain Controllers and Windows Event Forwarding widgets on `/standup` were silently rendering "No host data" in environments where:

1. The host-name patterns didn't match (`*DCS*` / `*WEF*` were hard-coded)
2. The ES field name was something other than `host.hostname.keyword` (e.g. `winlog.computer_name.keyword`, `agent.name.keyword`)
3. Events lived in a different index pattern than `winlogbeat-*` (e.g. `logs-windows.*`, `filebeat-*`, `.ds-logs-windows-*`)
4. ES was unreachable / auth was failing — the error response was masked as empty hosts

All four cases produced the same "No host data" UI, with no way to tell them apart.

#### Backend

`_check_log_source_health` is now driven by four env vars:
- `ION_STANDUP_LOG_INDEX` (default `winlogbeat-*`)
- `ION_STANDUP_HOST_FIELD` (default `host.hostname.keyword`)
- `ION_STANDUP_DCS_HOSTS` (default `*DCS*`) — comma-separated, OR'd together
- `ION_STANDUP_WEF_HOSTS` (default `*WEF*`) — same shape

Multiple patterns are allowed per check (e.g. `*DCS*,*DC*,*DOMAIN*`) — the query becomes a `bool > should` with `minimum_should_match: 1`.

Response now includes a `diag` block with the index, field, patterns, total hits, and host count actually used. Error responses include `type(e).__name__` so `ConnectError` / `TimeoutError` / `AuthenticationError` are distinguishable.

#### UI

`renderLogHealth` (in `daily_standup.html`) now distinguishes four states:
- **`status === 'error'`** → red banner with the actual error text
- **`status === 'not_configured'`** → amber banner with a hint to set env vars
- **Empty `hosts: []`** → existing "No host data" message **plus a diagnostic footer**: `Queried winlogbeat-* for host.hostname.keyword matching *DCS* · 0 hits / 0 hosts`
- **Hosts present** → existing widget grid, unchanged

The diagnostic footer is the load-bearing change — operators can see exactly what was queried and adjust env vars accordingly without redeploying.

#### Upgrade
Drop in `ion:0.10.18`. No schema changes. Defaults preserve v0.10.17 behaviour exactly. Set `ION_STANDUP_*` in `.env` if your hostnames or indices don't match the defaults.

## v0.10.17 (2026-04-27)

### CyAB onboarding wizard — full system creation in one transaction

The CyAB landing page now leads with **"Onboard a System"** (replaces v0.10.15's standalone "Assessment" button). It opens a six-step wizard that captures everything needed to bring a SOC system online — identity, contacts, system assessment, data sources, governance, and sign-off — and persists it all in a single transaction.

The original simple **"New System"** modal stays as a **"Quick stub"** button for the power-user "just create the row, fill it in later" path.

### Wizard steps

| # | Step | Captures |
|---|---|---|
| 1 | **System identity** | Name, department, business unit, reference (auto-generated if blank), version, status (Draft/Active/Decommissioned), data classification, tags |
| 2 | **Points of contact** | Department lead + email + phone, deputy + email, SOC team, SOC lead + email, SOC analyst owner, stakeholder distribution list, IR runbook URL |
| 3 | **System assessment** | The 8 per-system questions (criticality, data sensitivity, internet-facing, user access, BYOD, MFA, segmentation, monitoring) |
| 4 | **Data sources** | Multi-pick from the 13 pre-built templates (sysmon, Windows Security, firewall, EDR, etc.). Optional — submit zero is fine |
| 5 | **Governance & SLA** | SAL tier default, review cadence days, next review date |
| 6 | **Review & sign-off** | Summary preview + optional dept/SOC sign-off names + dates. Sign-off can be deferred — system created in DRAFT if blank |

### Backend

New endpoint `POST /api/cyab/onboarding` accepts a single JSON body and creates:
- One `CyabSystem` row with all identity + contact + governance fields
- N `CyabDataSource` rows from the chosen templates
- One `CyabSystemAssessment` row scored against the latest org-wide assessment + this system's overlay
- One initial `CyabSnapshot` so the trend chart has day-one data

All four writes happen in one DB transaction. Failure rolls everything back. Returns the new `system_id`, ranked top-10 use cases, and ranked threat actors so the UI can land directly on the system detail page with results visible.

### Schema additions to `CyabSystem` (10 nullable columns)

Adds `business_unit`, `data_classification`, `dept_lead_email`, `dept_lead_phone`, `dept_deputy_name`, `dept_deputy_email`, `soc_lead_email`, `soc_analyst_owner`, `stakeholder_distribution` (Text), `ir_runbook_url`.

Idempotent `ALTER TABLE ADD COLUMN` migration in `database.py` (matches existing pattern). All columns nullable so pre-v0.10.17 rows stay valid. `Base.metadata.create_all` handles fresh deployments.

### Verification done locally
Migration tested end-to-end on a populated database: dropped a column, restarted, confirmed the migration log fired (`Migrated: cyab_systems.business_unit`) and the column re-added without affecting existing rows.

### Upgrade
Drop in `ion:0.10.17`. No `.env` or compose changes required. New columns auto-add on first boot.

## v0.10.16 (2026-04-27) — HOTFIX

### Assessment endpoints 404'd in v0.10.15

The 8 new assessment routes added in v0.10.15 declared their paths as `/api/cyab/assessment/...` etc. inside `cyab_api.py`. But that router is included in `server.py` with `prefix="/api/cyab"`, so paths are relative — every existing route uses `@router.get("/systems")`, `@router.get("/dashboard")`, etc. The new routes ended up registered at `/api/cyab/api/cyab/assessment/...` (doubled prefix), so the wizard's `GET /api/cyab/assessment/questions` returned a 404 and the UI showed "failed to load questions".

Fixed by stripping `/api/cyab` from the eight new route decorators. No behavioural change otherwise — the wizard, scoring, persistence, and per-system endpoints all work as designed in v0.10.15.

Drop-in upgrade from v0.10.15. No schema or `.env` changes.

## v0.10.15 (2026-04-27)

### CyAB use-case discovery questionnaire — Stream B foundation

New "Assessment" entry-point on the CyAB landing page. A 4-step wizard captures the org's profile (sector, geo, regulated data, public exposure), tech stack (endpoint OS, cloud, identity, email, OT), existing controls (MFA, EDR, backup, awareness), and concerns (top 3 worries, prior incidents, internet exposure) — 17 questions total, mostly yes/no/dropdown so a non-technical respondent can answer in 5–10 minutes.

Submit → ranked top-10 SOC use cases pulled from TIDE's playbook catalogue, each with a score breakdown and human-readable "why this is here" reasons (`You marked 'ransomware' as a top concern`, `MFA control is weak — this playbook covers techniques that exploit that gap`). Plus top-5 threat actors curated by sector with rationale.

Scoring is four weighted sub-scores (out of 100):
- **TA** (threat-actor relevance, 0–40) — sector-implied concern keywords + prior-incident keywords + public-profile multiplier
- **ST** (stack applicability, 0–20) — playbook platform mentions vs answered stack
- **CG** (control-gap penalty, 0–20) — boost when weak controls overlap with playbook coverage
- **CB** (concern boost, 0–20) — direct keyword match of top-concern values against playbook name/description

### Models + persistence

Two new tables (created via `create_all` on first boot — no migration needed):
- `cyab_assessments` — org-wide submissions; **immutable**, one row per submit
- `cyab_system_assessments` — per-`CyabSystem` overlays; same immutability shape; nullable FK to the org-assessment that was current at submit

Every submission stores `responses_json`, `computed_profile_json`, `ranked_use_cases_json`, and `ranked_actors_json`. Older versions stay queryable for trending posture quarter-over-quarter.

`schema_version` column tracks which question set the responses were captured against, so future tweaks to the question list don't break replay of older submissions.

### Endpoints

- `GET /api/cyab/assessment/questions` — current question schema
- `POST /api/cyab/assessment` — submit + compute results
- `GET /api/cyab/assessment` — list past submissions (no result blob)
- `GET /api/cyab/assessment/latest` — most recent with results
- `GET /api/cyab/assessment/{id}` — full detail
- `POST /api/cyab/systems/{system_id}/assessment` — per-system submit (overlays latest org profile)
- `GET /api/cyab/systems/{system_id}/assessment` — per-system list
- `GET /api/cyab/systems/{system_id}/assessment/latest` — per-system latest

### Out of scope this ship — coming in v0.10.16
- **Per-system assessment UI** — model + endpoint + scoring work end-to-end via the API, but the per-system 8-question wizard isn't wired into the system detail page yet. Use the org-wide assessment now; per-system overlays land next ship.
- **Trending UI** — past submissions are persisted but no diff-vs-previous view yet.
- **OpenCTI cross-reference** — actor list is sector-curated for MVP; OpenCTI lookup is in the design but deferred (sector + concern-driven curation already works for typical SOCs).

### Upgrade
Drop in `ion:0.10.15` — no schema migration, no `.env` change. Both new tables auto-create on first boot.

## v0.10.14 (2026-04-27)

### CyAB system detail — baseline coverage view (replaces MITRE heatmap)

The system detail page's coverage panel previously rendered a MITRE ATT&CK tactic heat-grid (4-column tactic boxes with %). Useful for ATT&CK-aligned reporting but useless for the actual analyst question — *"why is this step covered, and which rule covered it?"*

Replaced with a **baseline coverage view** that surfaces TIDE's full assurance-baseline model: each TIDE playbook (use case) is a collapsible card; inside, each step shows its state (covered / partial / blind), its MITRE techniques (with covered vs gap colour-coding), and crucially the **TIDE-recommended detection rules per step + the analyst's "why covered" note** straight from the `step_detections.note` column.

Each detection rule under a step is tagged **APPLIED** or **NOT APPLIED** — so a "blind" step makes the gap actionable: "rule X is recommended here but not live on this system, apply it to close the gap."

Cards default to expanded for `partial`/`blind` use cases (the actionable ones) and collapsed for `covered` (read-only confirmation).

The MITRE heatmap is **kept** but demoted to a "Show MITRE ATT&CK heatmap" toggle below the baseline view — still there for ATT&CK-style reporting, just not the primary signal.

### Backend

`get_system_use_case_coverage` already pulled `step_detections.note` via `get_playbooks_with_kill_chains` but discarded it from the per-step output. Now:

- Pulls the system's literal applied `detection_id` set in addition to the technique set
- Returns `detections: [{rule_ref, note, source, applied}]` per step, with `applied` cross-referenced against the system's actual rule application
- No SQL added (data was already coming through `get_playbooks_with_kill_chains`); only the per-step output shape changed
- Payload size grows ~2-5× per call (option A from the design discussion); acceptable given the per-step rule list is what makes the view useful

### No schema or compose changes
Drop in `ion:0.10.14` alongside existing volumes — no migration, no `.env` updates required.

## v0.10.13 (2026-04-23)

### Arkime — PCAP timeout + alert-anchored IP search (hours-old alert fix)

Production logs from a real air-gapped deploy surfaced two related bugs after v0.10.10's fallback loosening started actually exercising the IP path.

#### 1. PCAP download was cut off at 60 s
`download_pcap` shared the 60 s session-search client. Arkime assembles PCAPs server-side by walking capture files, and a busy session easily needs 30-120 s to produce before transfer even starts. The short timeout fired mid-stream and surfaced `ArkimeError: Arkime PCAP download error:` — blank — to operators because `str(httpx.ReadTimeout())` is empty.

- New `_pcap_client()` with a dedicated longer timeout (default 300 s)
- Tunable via `ION_ARKIME_PCAP_TIMEOUT_S` in `.env`
- All three Arkime httpx error wrappers now include `type(e).__name__` so `ReadTimeout` / `ConnectTimeout` / `SSLError` / `ConnectError` are all distinguishable in logs

#### 2. IP search window was anchored to `now`, not the alert timestamp

`find_sessions_by_ip` used `startTime = now - 2h`, `stopTime = now`. For a 24/7 SOC this is fine; for non-24/7 ops (most SOCs) investigating an 8-hour-old alert, the window misses the traffic entirely. The search would succeed — return zero sessions — and the workflow would dead-end at "no sessions found".

Fixed by anchoring the window on the **alert timestamp** ± `window_minutes` (default 30 min):

```python
# Before (busted for late investigations):
startTime = now - 2h
stopTime = now

# After (v0.10.13):
alert_epoch = parse(alert["@timestamp"])
startTime = alert_epoch - 30min
stopTime = alert_epoch + 30min
```

- `find_sessions_by_ip` gains `alert_timestamp` + `window_minutes` kwargs
- Default window tunable via `ION_ARKIME_IP_SEARCH_WINDOW_MIN` (default 30)
- Legacy `hours` kwarg kept for back-compat (converted to `hours × 60` minutes)
- Falls back to a now-anchored window only when the alert has no parseable timestamp
- INFO log now shows the anchor: `Arkime IP search: expression=... window=±30min anchor=alert_ts=1745389524 limit=10`

As a side effect, the narrower window (60 min total vs 120 min) also reduces the PCAP size Arkime has to assemble — directly compounding with the timeout fix for the typical case.

### `.env.deploy`
Two new optional settings documented in the Arkime section:
- `ION_ARKIME_PCAP_TIMEOUT_S=300`
- `ION_ARKIME_IP_SEARCH_WINDOW_MIN=30`

### Upgrade notes
Drop-in for v0.10.12 — no schema, no compose changes required.

## v0.10.12 (2026-04-23)

### AI Scorecard — per-template accuracy dashboard

New admin page at `/ai-scorecard` (linked from the user dropdown → Admin → AI Scorecard). Pulls from the existing `/api/alert-prompts/scorecards` endpoint and joins template names client-side from `/api/alert-prompts`.

Rows sort tuning-needed templates first. Agreement % is colour-coded (green ≥ 80%, amber ≥ 60%, red below). A template with sample size ≥ 10 AND agreement < 60% is flagged `NEEDS TUNING`. Templates under 10 samples show `LOW SAMPLE` so analysts don't chase noise. KPI strip at top: template count, total feedback rows, weighted overall agreement, count flagged for tuning. Window is selectable (7 / 30 / 90 / 365 days).

"Edit" column links straight into the prompt editor anchored to that template.

### Grounded evidence display

`key_observations` (added to the output contract in v0.10.11) now renders in two places:

1. **Investigation memory modal** — new "Key observations (grounded evidence)" section between Summary and Recommended actions. Each entry shows the cited field in cyan monospace, the exact value, and Bob's stated significance.
2. **Bob's auto-posted case/alert note** — bulleted list below the summary, formatted as `` `process.command_line` = `powershell -enc ...` — obfuscated base64 payload``.

Both gracefully fall back when `key_observations` is null (investigations from before v0.10.11 still render fine, just without the evidence section).

`InvestigationDetail` API response gains three fields: `key_observations`, `prompt_snapshot`, `raw_response`. The last two are how the per-template training loop will eventually surface "show me the prompt+response behind this disagreement".

### Self-consistency sampling (opt-in via `ION_INVESTIGATION_SAMPLES`)

Default remains 1 (single-pass, cheapest — indistinguishable from v0.10.11). Set to 2 in `.env` to enable:

- Two LLM passes per investigation with different seeds (42, 1337).
- **Verdicts agree** → first result used, confidence bumped one level (low→medium, medium→high). The sampling metadata is recorded on the parsed payload.
- **Verdicts disagree** → verdict forced to `inconclusive`, `suggested_closure_reason=insufficient_data`, confidence=low. The summary is prefixed `[Self-consistency disagreement — samples: X, Y]`. Better to admit ambiguity than coin-flip a confident wrong answer.
- Max 3 samples. Decision is logged at INFO (`Self-consistency OK` / `FAILED`) with the verdict list.
- Cumulative `duration_ms` reflects total wall-clock across samples. `raw_response` concatenates every sample separated by `===SAMPLE-BOUNDARY===` so the training loop can inspect each.

Tradeoff: 2-3x investigation latency. Run this on templates that have already been through the accuracy dashboard and appear in the `NEEDS TUNING` cohort — for well-behaved prompts, single-seed is fine.

### Upgrade notes
- No schema changes on top of v0.10.11
- Pull `ion:0.10.12`; no `.env` edits required to adopt the scorecard or evidence display
- `ION_INVESTIGATION_SAMPLES` must be explicitly set to 2 or 3 to opt into self-consistency — absent/1 keeps today's behaviour

## v0.10.11 (2026-04-23)

### Bob investigation quality — the "wild verdicts" fix

Same alert from the same host was producing wildly different verdicts across investigations. Three compounding root causes fixed in this release.

#### 1. Prompt starvation — expanded alert summary
Bob was seeing only 7 fields: `rule_name, host, source_ip, user_name, timestamp, severity, alert_id`. That's not enough context to reach a grounded verdict — the model was confabulating to fill the gap, and small models (qwen2.5:3b default) hit different fabrications on each call.

Expanded to ~40 fields, emitted only when present (no null noise). Additions: `kibana.alert.reason` (the human-readable one-liner), `destination_ip` + `destination_port` + `network.*`, full `process.*` tree (name, command_line, executable, pid, sha256 + parent process), `file.*` (path, name, hashes), `url.*`, `dns.question.*`, `http.*`, `user_agent`, `event.action` + `event.category` + `event.code` + `event.outcome` + `event.module` + `event.dataset`, `user.domain` + `user.email` + target user, host OS info, and — load-bearing — the actual **rule query text** (`kibana.alert.rule.parameters.query`) so Bob knows *what the rule was looking for*, not just its name.

Trade-off: prompts are larger, so `num_predict` is bumped from the default to 2048. Investigation calls take longer — the user signed off on slower-but-right.

#### 2. LLM non-determinism
Investigation Ollama calls ran with `temperature=0.7` and no `seed` / `top_p` / `top_k` pins. Same prompt literally sampled different tokens on every call. Accuracy was unmeasurable under random verdict drift.

Pinned to `temperature=0.0, seed=42, top_p=0.1, top_k=1`. Same alert in = same verdict out. The sampler is fully deterministic when ION drives the call; interactive chat UX (different code path) keeps the old defaults so conversational Bob isn't robotic.

`OllamaService.chat()` gained `seed`, `top_p`, `top_k` keyword parameters — passed through to Ollama's `options` dict only when set, so no behaviour change for callers that don't pass them.

#### 3. Unauditable reasoning → grounded evidence bullets
The output contract had `analyst_explanation` and `technical_details` (prose), but nothing forced the model to tie its verdict to specific alert fields. New mandatory field:

```jsonc
"key_observations": [
  {"field": "process.command_line",
   "value": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
   "significance": "obfuscated base64 payload — common for
                    living-off-the-land execution"}
]
```

Rule 5 of the Output Contract now requires every `key_observations` entry to cite a field that literally appears in `alert_summary`. If there's no supporting evidence in the alert, verdict MUST be `inconclusive`. This kills the "confident nonsense" failure mode where Bob asserted a verdict the alert data didn't support.

#### 4. Training loop foundation — persist prompt + response

`Investigation` table gains three nullable TEXT columns (idempotent ALTER TABLE):
- `prompt_snapshot` — full rendered user prompt sent to Ollama
- `raw_response` — model's raw output before any parsing
- `key_observations_json` — parsed evidence bullets

AIFeedback rows already link to `investigation_id`, so per-template accuracy queries can now JOIN to the exact prompt and response that led to each disagreement. Without this, "Bob was wrong N% of the time" was countable but undebuggable — you couldn't see *what* he saw. This is the prerequisite for the Tier-1 automatic prompt-refinement work.

Pre-v0.10.11 investigations stay NULL in the new columns. Hard-capped at 100 KB per column to prevent runaway prompts from bloating the DB.

### Upgrade notes
- Idempotent migration — safe to pull `ion:0.10.11` alongside existing v0.10.10 Postgres + Ollama volumes
- Investigation latency will increase. Expected. Verdict quality was the asked-for trade
- If you want the old chatty sampler for investigations, there is no flag — revert the pinned values in `_call_llm` yourself

## v0.10.10 (2026-04-23)

### Arkime PCAP fallback — loosened gate + diagnostic logging
- Preview endpoint now falls back to IP search on **any** `ArkimeError` when the alert has `source_ip` or `destination_ip`, not just `status_code == 404`. Covers the empty-result case, viewer 5xx, and timeouts — previously these returned 404 to the user even when IP search could have resolved the PCAP.
- Every community_id→IP fallback decision is logged at INFO with alert id, error, and `has_ips` flag so `docker logs ion | grep -i arkime` makes the decision tree visible.
- `find_sessions_by_ip` now emits an INFO log on every call (mirrors the existing community_id search log). Without it, IP-path calls were silent.
- Error message for "Arkime not configured" no longer mentions Keycloak — now names the actual env vars (`ION_ARKIME_URL` + `ION_ARKIME_USERNAME` + `ION_ARKIME_PASSWORD`).

### Arkime service — obsolete code removal
- Dropped Keycloak/OAuth2 module docstring (never implemented — v0.10.4 locked auth to HTTP Basic only).
- Removed unused `_arkime_client` module-level `httpx.AsyncClient` (never assigned; shared clients were abandoned when digest was ripped out).
- Removed `_auth()` method (returned `None` always — vestigial from the `httpx.BasicAuth` / `httpx.DigestAuth` era). Auth is sent exclusively via the `Authorization: Basic <base64>` header in `_headers()`.
- Stripped all `auth=self._auth()` call sites.
- Simplified stale `_client()` docstring (no more digest challenge/response).
- Cleaned up stale `reset_arkime_service()` body — no more `_arkime_client.aclose()` dance.
- Trimmed `Arkime PCAP GET` log line — dropped the now-useless "auth scheme=…" suffix.

### Why this matters
v0.10.9 users reported "PCAP only works via community_id". The real cause wasn't the node filter (reported node names matched Arkime's stored node exactly in the reported environment) — it was the fallback gate checking only `status_code == 404`, which missed empty-result and non-404 error cases. Combined with the silent IP-search path, operators had no way to diagnose what decision the code was making. Both issues are fixed in this release.

### No schema / config / image-layout changes
Drop in `ion:0.10.10` alongside the existing v0.10.9 postgres and ollama volumes — no migration required.

## v0.10.9 (2026-04-22)

### Air-gapped deployment — full bundle rebuild
- `scripts/build-offline-package.sh` rewritten for v0.10.4+ stack:
  - Adds `pgvector/pgvector:<PG_VERSION>` image (was missing — plain postgres has no pgvector binaries)
  - Adds `nomic-embed-text` model alongside the chat model in the Ollama volume export (was missing — case-similarity + KB RAG silently no-op without it)
  - Emits `MANIFEST.sha256` so the air-gapped side can verify transit integrity
  - Stamps the bundled `.env` with the ION/PG/model versions that were built, so compose defaults can't drift
  - Removed stale SQLite init path from the deploy helper (ION has been Postgres-only since v0.9.43)
- **New** `scripts/load-offline-package.sh` — runs on the air-gapped side. Verifies manifest, loads all three images, restores the Ollama models volume with project-name auto-detection, prints next-step commands. Idempotent.
- Signatures:
  - `./scripts/build-offline-package.sh [ion_version] [chat_model] [pg_version]`
  - `./scripts/load-offline-package.sh` (run from bundle dir)

### PG_VERSION env var
- `docker-compose.yml` postgres line is now `image: pgvector/pgvector:${PG_VERSION:-pg16}` so deployments on pg15/pg17/pg18 can pin via `.env` without hand-editing compose every time they pull
- Default stays `pg16` for fresh deploys

### Docs
- `SETUP.md` "Air-Gapped / Siloed Deployment" section rewritten — covers the three-image/two-model reality, PG_VERSION, build + load scripts, the silent-failure mode when `nomic-embed-text` is missing, and why partial upgrades break
- Makes explicit: from v0.10.4+, you cannot upgrade an air-gapped deployment by shipping just the ION image — the bundle must be rebuilt

### No app code change
All v0.10.9 changes are in compose/scripts/docs. The ION application image is byte-equivalent to v0.10.8 for users who just want to pull `latest` and keep going.

## v0.10.8 (2026-04-22) — HOTFIX

### Fresh-deploy crash: `type "vector" does not exist`
- `init_db()` was running `Base.metadata.create_all(engine)` BEFORE `_run_migrations()`
- `create_all` tries to create the `case_embeddings` and `kb_document_embeddings` tables (which carry `VECTOR(768)` columns), but pgvector's `vector` type doesn't exist in a fresh Postgres until `CREATE EXTENSION vector` runs — which was happening inside `_run_migrations()`, too late
- **Only affects fresh deployments** of v0.10.4+ (where the volume is empty on first boot). Incremental upgrades that evolved through 0.10.3 → 0.10.4 worked because the extension was enabled at migration time and the tables were added after
- **Fix:** run `CREATE EXTENSION IF NOT EXISTS vector` in `init_db()` BEFORE `create_all`. The same statement still runs inside `_run_migrations()` too (idempotent, no harm)

### Who needs this
- Anyone deploying ION fresh (empty postgres volume) on v0.10.4, 0.10.5, 0.10.6, or 0.10.7 hit this crash
- Anyone already running a healthy 0.10.4+ stack is unaffected

## v0.10.7 (2026-04-22)

### Ollama model residency — avoid swap tax on investigations
- `docker-compose.yml`: `OLLAMA_MAX_LOADED_MODELS` default raised from 1 → 2 (now env-overridable via `${OLLAMA_MAX_LOADED_MODELS:-2}`)
- Rationale: every investigation calls `/api/embed` (nomic-embed-text) then `/api/chat` (chat model) back-to-back. With only 1 loaded model, Ollama was evicting and reloading on each call, adding ~5-15s per investigation depending on chat-model size
- At 2 the residency budget is ~2.3GB for the default pair (qwen2.5:3b ~2GB + nomic-embed-text ~274MB) — well under the 8GB Ollama container cap
- Bump higher via `.env` (`OLLAMA_MAX_LOADED_MODELS=3`) if you run a second chat model (e.g. a larger one for deep investigations) OR a reranker. Mind the container memory limit

### Env vars
- `OLLAMA_MAX_LOADED_MODELS` (default 2)

## v0.10.6 (2026-04-22)

### KB RAG grounding for Bob (Bet A of the air-gapped roadmap)
- New `kb_document_embeddings` table (document_id PK + VECTOR(768) + model_name + embedded_at + source_text_hash) with HNSW index on `vector_cosine_ops`
- New background loop on advisory lock `LOCK_KB_EMBEDDING_BG=1020` (default 5-min interval, batched 20/tick) — embeds Documents under the "Knowledge Base" collection tree (recursive CTE to find descendants)
- Embeds `name + first 8000 chars of rendered_content` via the same `EmbeddingService` / `nomic-embed-text` pipeline used for case embeddings
- Re-embeds when source text hash drifts (KB article edited)
- At investigation time, Bob's prompt gets up to 3 KB articles most similar to the alert (cosine similarity ≥ 0.65 — looser than gold exemplars since KB is topic-level doc)
- Rendered as "## Knowledge Base Context" section in `render_system_prompt()`, placed BEFORE "Prior Similar Cases" — priority order is: per-rule playbook → KB grounding → prior cases → output contract
- **100% air-gapped compatible** — same local Ollama model, no external dependencies
- Opt-in: `ION_KB_RAG_ENABLED=true` (default off, same rationale as case embedding)

### Env vars
- `ION_KB_RAG_ENABLED` (default false — opt-in)
- `ION_KB_EMBEDDING_INTERVAL_S` (default 300)
- `ION_KB_EMBEDDING_BATCH` (default 20)

### Depends on
- v0.10.4 pgvector infrastructure + `ION_EMBEDDING_ENABLED=true`
- `nomic-embed-text` pulled in Ollama
- KB seeded (the `seed_knowledge_base` hook runs on startup — ~392 articles under 28 child collections)

### Ops notes
- No existing-deployment migration needed beyond `create_all()` picking up the new table
- Embedding the full ~392 article KB takes roughly 2-3 background passes (20/tick) = ~15 minutes the first time ION boots with the flag on
- After first pass, only changed articles re-embed

## v0.10.5 (2026-04-22)

### Few-shot gold exemplars for Bob (Bet B of the roadmap)
- When an alert is investigated, pgvector-retrieve up to 3 past closed cases that:
  - have `closure_reason IS NOT NULL` (human-closed)
  - AND have at least one `AIFeedback` row with `agreement=true` (Bob and the human agreed on the verdict)
  - AND exceed cosine similarity 0.7 to the current alert
- Inject retrieved cases as a new "Prior Similar Cases (analyst-verified)" section in Bob's system prompt, placed immediately before the Output Contract
- Uses the existing `EmbeddingService` (nomic-embed-text) and `case_embeddings` table — no new infrastructure
- Alert text serialisation aligned with `case_embedding_service._case_source_text` so vectors are directly comparable
- **Opt-in: set `ION_FEW_SHOT_EXEMPLARS_ENABLED=true` in .env.** Default off because fresh installs have no `AIFeedback` rows — the retrieval returns nothing until the ledger populates from real case closures

### Bob closed-case guard
- `_write_bob_outputs()` now short-circuits when the alert's `AlertTriage` row is `CLOSED` **or** its parent `AlertCase` is `CLOSED` — prevents AI-authored Notes, suggested_verdict updates, observable writes, or tuning proposals from landing on closed case timelines when investigations are re-run (force=True, manual retrigger)
- INFO-level log line records which condition tripped, for audit

### Env vars
- `ION_FEW_SHOT_EXEMPLARS_ENABLED` (default false — opt-in)

### Depends on
- v0.10.4 pgvector infrastructure
- `ION_EMBEDDING_ENABLED=true` + `nomic-embed-text` pulled in Ollama

## v0.10.4 (2026-04-22)

### pgvector + case similarity (Bet 1 of the roadmap)
- Postgres image swapped `postgres:16-alpine` → `pgvector/pgvector:pg16` (data-compatible PG16, preinstalled extension)
- `CREATE EXTENSION IF NOT EXISTS vector` added to `_run_migrations()` — idempotent, runs before create_all
- `pgvector>=0.3.0` added to Python deps for SQLAlchemy types
- New `case_embeddings` table (case_id PK + embedding VECTOR(768) + model_name + embedded_at + source_text_hash) with HNSW index on `vector_cosine_ops`
- `EmbeddingService` wrapping Ollama's `/api/embed` endpoint (default `nomic-embed-text`, 768-dim). Graceful degradation — Ollama unreachable = no-op, silent retry next tick
- Background loop under advisory lock `LOCK_CASE_EMBEDDING_BG=1019`, embeds cases every 5 min (batched at 50). Source text = title + description + hosts + users + rules + evidence_summary + Bob's latest investigation summary. Re-embeds when source hash changes
- `GET /api/elasticsearch/alerts/cases/{id}/similar` — pgvector cosine distance via ORM `.cosine_distance()`, filters to `closure_reason IS NOT NULL` (real human-closed cases only)
- "Similar Closed Cases" sidebar on case detail panel — colour-coded closure_reason badges (TP red, FP green, BTP amber), similarity % shown. Clickable cards pivot to the similar case

### Fixes
- `Investigation.alert_id_ref` / `summary_text` (correct field names) — had used wrong `Investigation.alert_id` / `.summary` in `ai_feedback_service.py` and `case_embedding_service.py`. Both now reference the right columns
- Similarity SQL uses pgvector ORM (`Vector.cosine_distance(target)`) instead of raw SQL with `str(target.embedding)` — numpy's default string representation is unparseable by pgvector

### Env vars
- `ION_EMBEDDING_ENABLED` (**default false** — opt-in; set to `true` to enable)
- `ION_EMBEDDING_MODEL` (default `nomic-embed-text`)
- `ION_CASE_EMBEDDING_INTERVAL_S` (default 300)
- `ION_CASE_EMBEDDING_BATCH` (default 50)

### Arkime auth lockdown
- Reverted Arkime to **Basic-only**. Digest and API-key code paths removed. `ION_ARKIME_AUTH_MODE` + `ION_ARKIME_API_KEY` env vars are now ignored. If you need something else, front Arkime with nginx + Basic.
- Added INFO-level logs for `Arkime community_id search` expression and `Arkime PCAP GET` URL so failing requests can be traced via `docker compose logs ion | grep Arkime`.

### Ops note
- Existing deployments: volume is retained across the Postgres image swap (same PG16). First boot on 0.10.4 adds the pgvector extension + case_embeddings table idempotently.
- **Embedding is off by default.** To enable case similarity: (1) run `docker exec ion-ollama ollama pull nomic-embed-text` (~300 MB, one-time), (2) set `ION_EMBEDDING_ENABLED=true` in `.env`, (3) restart ION.

## v0.10.3 (2026-04-22)

### AI Analyst — "Bob"
- New service user `bob` + role `ai_analyst` — AI-authored artefacts (notes, observables, tickers, tuning proposals) attribute to a single identity
- `User.is_service_account` column — login flow rejects service accounts early
- New permissions: `alert:comment`, `case:comment`, `case:link`, `ticker:read/create/manage`, `tuning:read/review`, `investigation:run`
- Bob auto-posts a markdown investigation summary to the alert Notes timeline
- Bob writes `suggested_verdict` + `suggested_verdict_confidence` onto `AlertTriage` (matches `CaseClosureReason` for 1:1 comparison)
- Bob auto-extracts high-confidence IOCs from the JSON envelope as `Observable` rows tagged `source:bob`
- Bob auto-files a `TuningProposal` when verdict is `false_positive` with a concrete `suggested_change`

### MITRE-tiered alert-prompt matcher + canonical output contract
- `AlertPromptTemplate` gains `mitre_techniques_json` + `mitre_tactics_json`
- Matcher now 5-tier: exact rule_id → regex → MITRE technique (parent↔sub tolerant) → MITRE tactic → `rule.groups`
- Canonical JSON output envelope pinned to ION's `CaseClosureReason` — verdict, confidence, severity, analyst_explanation, technical_details, mitre, iocs, recommended_actions, `suggested_closure_reason`, `tuning_recommendation` (the detection-engineering feedback bridge)
- Ollama `format: "json"` wired through `OllamaService.chat(response_format=…)` so investigations emit strict JSON
- 50 seeded prompt templates (25 existing + 12 new Sysmon events from Talon + 3 Talon Windows categories + 10 new coverage categories: Entra ID, Okta, MFA fatigue, K8s runtime, CI/CD abuse, macOS persistence, Zeek, DB access anomaly, session hijack, supply-chain)
- Sysmon 1/3/11 upgraded with exact Wazuh field refs, VirusTotal URL pattern, and a P1/P2/P3 Velociraptor artefact table (Event 1)

### Ticker
- New `Ticker` + `TickerDismissal` models
- Background producer (advisory lock `LOCK_TICKER_BG=1018`): flags critical alerts not assigned to a case after `ION_TICKER_CRITICAL_NO_CASE_MIN` minutes (default 10); auto-resolves when the alert is cased
- REST API + `/tickers` manage page; sticky strip below nav on all pages; critical entries non-dismissable (auto-resolve only)
- Env: `ION_TICKER_ENABLED`, `ION_TICKER_INTERVAL_S`, `ION_TICKER_CRITICAL_NO_CASE_MIN`

### Tuning proposals
- `TuningProposal` model + API + `/tuning-proposals` page
- Accept/reject/duplicate workflow, auto-created from Bob's FP verdicts

### Training foundation (Tier 1)
- `AIFeedback` ledger — captures `bob_suggested_verdict` vs `human_verdict` on case close, with agreement flag and optional delta reason
- Per-template scorecard on `/alert-prompts`: 30-day agreement %, FP/BTP/TP rates, "tune" flag when agreement < 60 % on 10+ samples
- `GET /api/alert-prompts/scorecards` endpoint

### Docs & tests
- `docs/AI_OUTPUT_CONTRACT.md` — full output schema reference
- `tests/test_alert_prompt_matcher.py` — matcher unit tests (18 cases)

## v0.9.43 (2026-04-07)
### Security Hardening
- Circuit breakers on ES, OpenCTI, TIDE, Ollama, Kibana external calls
- Startup config validation — fail fast on missing/invalid settings
- Rate limiting on escalation (10/min), bulk ops (20/min), token regen (3/min)
- Fix: Docker networking (explicit bridge network for all services)
- Fix: Remove ION_DATABASE_URL from Dockerfile build ENV
- Fix: Don't force password change when custom admin password is set

### Deployment
- `.env.deploy` template for siloed/air-gapped environments
- `build: .` commented out in docker-compose (pull pre-built image)
- Better entrypoint error messages with DNS pre-check
- PostgreSQL-only Docker image (SQLite fallback removed from container)
- Updated README, SETUP, SECURITY_ASSESSMENT, DEPLOYMENT_GUIDE

## v0.9.42 (2026-04-07)
- SLA Management — severity-based response time targets, compliance tracking
- Bulk Operations — multi-select alert acknowledge/assign/close
- Threat Hunting Workbench — hypothesis-driven hunting with queries/findings/IOCs
- Dashboard Widget Customization — 12 widgets, role-filtered, per-user layout
- Reporting Scheduler — daily/weekly/monthly auto-generated reports
- Automated Playbook Actions — 6 response actions with approval workflow

## v0.9.41 (2026-04-07)
- On-Call / Duty IM Escalation Manager — roster, escalation, notification
- Service Account Tracker — password age, risk levels, stale detection
- Incident Cost Calculator — analyst hours, downtime cost, per-severity
- NIST CSF Compliance Mapping — 13 controls mapped to TIDE rules
- Communication Templates — 6 pre-seeded incident notification templates
- Change Log — config/rule change tracking with approval and rollback
- Saved Searches / Bookmarks — personal workspace customization
- Navigation reorganized from 5 dropdowns to 4 focused groups

## v0.9.40 (2026-04-07)
- Interactive Training Guide (`/guide`) with visual UI mockups
- Training Simulator (`/guide/sim`) with 8 scored scenarios
- Fix: PCAP threat intel enrichment crash on None score
- Fix: Social hub emoji reactions (in-place update)
- Fix: Self-assessment section collapse state preservation

## v0.9.39 (2026-04-07)
- Attack Stories — alert correlation into multi-step narratives
- Case Similarity — find similar past cases by matching patterns
- Automated Triage Suggestions — historical closure data recommendations
- MITRE ATT&CK Navigator Export — one-click layer JSON download
- Playbook Effectiveness Analytics
- Alert Pattern Detection — persistent, periodic, burst, sporadic
- Executive Weekly Report — PDF/HTML with trends and metrics
- IOC Staleness Tracker — flag observables needing re-enrichment

## v0.9.38 (2026-04-07)
- Unified CSS severity/MITRE/quality design system variables
- Country flag attribution for threat actors
- Shift Handover Report — auto-generated end-of-shift summary
- Rule Tuning Feedback Loop — FP-heavy, high-value, silent rules
- Entity Timeline — unified cross-source timeline
- Analyst Efficiency Dashboard — MTTR, FP rates, per-analyst
- SOC Health Scorecard — 5-dimension maturity assessment (A-F)
- Threat Watch Auto-Gap Alerting

## v0.9.37 (2026-04-06)
- Detection Engineering page — 7 tabs (TIDE + ES + OpenCTI)
- TIDE system selector, actor readiness, PDF reports
- Docker `get_config()` fix for fresh DB path resolution

## v0.9.34 (2026-04-06)
- Kibana multi-alert fix, AI document generator
- Security hardening (open redirect, ES system index blocking, 50MB upload)
- Chat redesign, PDF export, data flow visualization

## Earlier versions
See [progression.md](docs/progression.md) in the memory directory for full v0.9.0–v0.9.33 history.
