# Changelog

## v0.19.5 — 2026-05-06

### Daily SOC standup — alerts panel was dropping criticals + showed high

Two issues, one commit:

- **Severity filter was case-sensitive.** `ElasticsearchService.get_alerts(severity=...)`
  used Elasticsearch `term` queries against four severity fields
  (`event.severity`, `kibana.alert.severity`, `signal.rule.severity`,
  `severity`). Kibana stores those lowercase, but Wazuh and various
  custom rule producers ship them capitalised (`"Critical"`) or all-caps
  (`"HIGH"`). The single-casing match silently dropped non-Kibana
  criticals — the standup looked empty even on a busy day. Replaced
  the four `term` clauses with `terms` queries that fan out the
  caller's value into every common casing
  (`{lower, capitalize, upper, original}`). Same inverted-index lookup
  cost on the ES side; no schema change.
- **Standup now shows Critical only.** Was Critical + High. The High
  band was diluting the signal — daily standup is meant to surface
  "what should ops act on right now," and analysts can still see High
  via `/alerts`. Dropped the second `get_alerts` call, the
  `high_count` field, and the `kpi-high` pill in the template.

## v0.19.4 — 2026-05-06

### CyAB Overview checklist is now actually editable

The Overview tab was shipped (v0.19.0 commit `656ddad`) as a read-only
display: each item rendered as a static `<div>` with the status text
beside it but no control to change it. The user could see "missing"
or "unknown" but had no way to mark "yes we have it now" (`done`) or
"not needed" (`na`). The backend endpoint was already there
(`PUT /api/cyab/studio/checklist/{item_id}`) — only the UI was missing.

The "+ Add custom checklist item" form was technically broken too:
it used HTMX form-encoded POST against an endpoint declared with a
Pydantic `BaseModel` body, which FastAPI rejects with `422` unless
the content type is JSON.

Fix:
- Each row now has a status `<select>` (Unknown / Missing / In progress /
  Done / Not needed) wired via `change` event delegation to a `fetch`
  PUT with a JSON body. On success the row's icon and colour swap
  in-place — no full tab re-render. On failure the tab reloads so the
  select reverts to the server's truth.
- The add-item form was rewritten as a vanilla `fetch` POST with
  `Content-Type: application/json`, deriving `kind` as `custom_<slug>`
  from the label so callers don't have to invent one.
- Both calls send `credentials: 'same-origin'` so the session cookie
  carries the `case:update` permission check.

## v0.19.3 — 2026-05-05

### Bob investigation reliability — regression from v0.18.1

- **Memory context bound + kill switch.** v0.18.1's "sanity sweep"
  (`9a262d0`) added the late-import for `get_investigation_memory_service`
  that the v0.10.x prompt path had been calling without importing.
  Pre-v0.18.1, `memory_ctx_md` was always `""` because the missing
  import raised `NameError` and was silently caught by `except Exception`.
  Once the sweep landed, memory context populated correctly — and started
  growing every time a new investigation completed (FP signatures + up
  to 5 prior investigation snippets + IOC history + host sightings).
  Within a few weeks of running, that bloat tipped 7-8B-class models
  past their effective reasoning budget: `format: "json"` strict mode
  forced the cheapest valid output, which is `{}`.
  Two new env knobs:
  - `ION_INVESTIGATION_MEMORY_ENABLED` (default `true`) — kill switch
  - `ION_INVESTIGATION_MEMORY_MAX_CHARS` (default `1500`) — hard cap
  with a single helper `_build_memory_ctx()` covering both single-alert
  (`investigate_alert`) and cluster (`investigate_open_alerts_sweep`)
  paths.
- **`max_tokens` 2048 → 4096.** With the bigger prompt, 7-8B models
  were spending their generation budget on the analyst_explanation
  field and never reaching the closing brace, so the JSON parser fell
  back to extracting the first balanced `{}` block — often an empty
  inner object. 4096 gives the envelope room to close cleanly.

### Linked-alerts on case page now show rule names

- New denormalised `alert_triage.rule_name` column (idempotent
  `ALTER TABLE` migration, nullable). Populated at triage-create time
  in `create_case` from the supplied `alert_contexts[*].raw_data`
  (`rule.name` / `kibana.alert.rule.name` / `_source.rule.name`).
- `GET /elasticsearch/alerts/cases/{id}` now exposes `rule_name` on
  each linked alert; `cases.html` prefers it for the card header
  (`"Suspicious PowerShell Execution"` instead of a 24-char ES id
  prefix). Legacy rows fall through to the existing id-substring.

### Rare alert↔case-link inconsistency

- When an alert was reassigned to a new case, the previous case's
  `source_alert_ids` JSON list still referenced it, while the
  `AlertTriage.case_id` FK pointed to the new case. The "linked cases"
  panel and the case detail panel read different sources, so they
  could disagree silently. `create_case` now strips the alert from
  the old case's `source_alert_ids` and logs a `WARNING` so the
  reassignment is auditable.

### Ticker producer was filtering on a state nothing sets

- The producer queried `AlertTriage.status == OPEN`, but every
  triage-row creator (`kibana_sync_service`, `case_grouper_service`,
  `bulk_operations_service.bulk_acknowledge_alerts`, `api.create_case`)
  inserts rows as `ACKNOWLEDGED`. Only the SQLAlchemy column default
  ever produced `OPEN`, and almost no path relies on it. Net result:
  enabled or not, the producer found zero candidates and zero tickers
  fired.
  Filter changed to `status != CLOSED`. Resolver mirrored. Plus
  per-tick INFO logging (`Ticker tick: N uncased ... created=X
  resolved=Y`) and a `WARNING` if the ES service exposes neither
  `get_alert_by_id` nor `fetch_alert` (so a future rename doesn't
  silently kill the ticker again).

## v0.19.2 — 2026-05-05

### Fix-pack 2 for v0.19.0 CyAB rollout

- **Packaging gap — `cyab_scoping_questions.json` not shipped**: the
  setuptools `package-data` glob in `pyproject.toml` only included
  `data/**/*.md` and `data/**/*.yaml`. The new
  `src/ion/data/cyab_scoping_questions.json` (added in v0.19.0,
  commit a086a81) was silently dropped from every wheel — so the
  Docker image ran fine until you opened `/cyab/scoping`, which then
  500'd with `FileNotFoundError: ion/data/cyab_scoping_questions.json`.
  Added `data/**/*.json` to the glob so the scoping engine can read it.
- **Cache-bust on `tailwind.css`**: `base.html` was serving the stylesheet
  with `?v=0.9.80-lightmode`, so browsers that had cached the old file
  during the v0.19.0/v0.19.1 window kept serving the stale, unstyled
  CSS even after the v0.19.1 image rolled out. Bumped the query string
  to `?v=0.19.2` so every browser refetches.
- **Rebuilt `tailwind.css`** from `frontend/tailwind.input.css` against
  the current template tree (76,082 → 77,957 bytes) to guarantee the
  on-disk asset matches the post-fix templates, not whatever was
  bundled into a pre-existing image.

## v0.19.1 — 2026-05-04

### Fix-pack for v0.19.0 CyAB UI

- **Tailwind classes**: stripped non-existent `tw-` prefix from 516 classes
  across 23 new CyAB templates. Project doesn't configure a Tailwind
  prefix; `tw-bg-slate-900` etc. produced no styling. Now use plain
  `bg-slate-900`. Rebuilt `tailwind.css` (70K → 76K) so the `@source`
  scan picks up the corrected classes.
- **HTMX**: vendored `htmx.min.js` (1.9.10) and loaded it from `base.html`.
  Every `hx-*` attribute across the new CyAB UI was previously dead
  (tab swaps, wizard step transitions, scoping live counter, scoping
  summary swap, systems-list filters, bulk ops, audit/coverage filter
  forms). Now functional.

## v0.19.0 — 2026-05-04

### CyAB IA — Scoping + Coverage + Audit (Sub-plan C of 3) — completes the v0.19.0 series

- New `/cyab/scoping` page — anonymous stack-to-coverage questionnaire
  (~14 progressive questions) with live counter widget
  ("47 use cases · 12 threat-actor matches · 64% MITRE Initial Access
  coverage") and downloadable scoping-pack PDF.
- New shared scoring engine `cyab_scoping_engine.py` extends
  `cyab_assessment_service`. Single engine drives both `/cyab/scoping`
  and the wizard's Step 2 live counter — the spec's "scope for all"
  architecture.
- New `/cyab/coverage` matrix page — every system × seven data-health
  dimensions (ingestion, fields, intake, detections, audit, checklist,
  sign-off). Cells deep-link into the relevant per-system tab. Aggregates
  strip + filters by pillar / owner / "any red".
- New `/cyab/audit` page — chronological feed unioning sign-offs,
  checklist deltas, containment-authority changes, and system lifecycle
  events. Each sign-off row includes an "as-of-date" link to the
  onboarding pack PDF.
- "Convert to system" CTA on /cyab/scoping — stashes scoping answers in
  session and 303-redirects to the wizard with `?from_scoping=1`.

### v0.19.0 series — full picture (A + B + C)

- 7 top-level CyAB pages: `/cyab`, `/cyab/systems`, `/cyab/scoping`,
  `/cyab/onboard`, `/cyab/coverage`, `/cyab/audit`, `/cyab/systems/{id}`.
- 7-tab per-system page with sticky onboarding-progress header.
- 4-step onboarding wizard with autosave + scope-for-all live counter.
- New backend services: `cyab_data_health_service`, `cyab_scoping_engine`.
- `/cyab/studio` 301 redirected (drop in v0.20.0).

### Phase-2 deferrals (separate plans)

- Reconciliation drift Data Health panel (needs CMDB integration)
- Per-system Recommendations tab (live re-scoping as intake changes)
- Bulk operations on /cyab/coverage
- DB-backed scoping question editor (engine API is already swap-ready)

## v0.19.0-rc.2 — 2026-05-04

### CyAB IA — Onboarding wizard + landing pages (Sub-plan B of 3)

- **New `/cyab/onboard` 4-step wizard** — Identity, Intake, First data
  source, Doc placeholders. Wizard never blocks: every step accepts
  partial data and the user can exit and resume from the same wid URL.
  Finish drops the user into `/cyab/systems/{id}` with the doc checklist
  lazy-seeded (20 default items).
- **New `/cyab` Overview landing** — KPI strip (total systems, %
  onboarded, % critical-missing, sign-offs this week), "In progress"
  feed (5 most recent), "Needs attention" feed (critical-missing rows),
  CTAs to + Onboard / View systems / Run coverage rollup.
- **New `/cyab/systems` portfolio list** — table with name / pillar /
  sub-profile / owner / progress / critical-missing / last-edited /
  status; HTMX-filtered search by name/owner; filters for pillar /
  sub-profile / status / owner / "missing X" / stale data; bulk ops
  (mark reviewed, export CSV, re-run health checks).
- **Secondary tab strip** added to every CyAB page: Overview · Systems ·
  Scoping · Onboard · Coverage · Audit. Coverage and Audit are
  placeholder pages that ship the nav strip + "coming soon" card; both
  are filled in by Sub-plan C.
- **New `cyab_wizard_sessions` table + `cyab_wizard_service`** — manages
  in-progress wizard state server-side so users can resume across page
  reloads.
- `/api/cyab/dashboard` now returns `signoffs_this_week`.
- New `/api/cyab/systems/_table` HTMX partial endpoint.
- New `/api/cyab/systems/bulk` endpoint — `mark-reviewed`,
  `export-csv`, `rerun-health` (last is a stub pending Sub-plan C).

### Removed

- Legacy `src/ion/web/templates/cyab.html` template (3,543 lines) —
  replaced by the new Overview page. Per-system content already moved
  to `/cyab/systems/{id}` tabs in v0.19.0-rc.1.

### Coming in Sub-plan C (v0.19.0-rc.3)

Stack-to-use-cases scoping at `/cyab/scoping`; fleet `/cyab/coverage`
matrix; `/cyab/audit` trail. Live recommendation counter wired into
wizard Step 2.

## v0.19.0-rc.1 — 2026-05-04

### CyAB IA — Foundation + per-system page (Sub-plan A of 3)

- New per-system page at `/cyab/systems/{id}` with sticky onboarding-progress
  header and 7 tabs: Overview, Intake, Sources, Data Health, Detection Use
  Cases, Audit Use Cases, Sign-off.
- New `cyab_data_health_service` aggregates ingestion freshness, field
  mapping completeness, and coverage rollup. Reconciliation panel stubbed
  for Phase 2 (needs CMDB).
- `/cyab/studio` 301 redirects to `/cyab/systems/{id}` (deprecated; drop in
  v0.20.0).
- Section consolidation: `demarcation`, `field-mapping`, `sal-tiers` from
  the legacy `/cyab` page now live in the **Sources** tab. `governance`
  consolidated into the **Sign-off** tab (was previously duplicated).

### Coming in Sub-plan B (v0.19.0-rc.2)
Onboarding wizard at `/cyab/onboard`; portfolio list at `/cyab/systems`;
new `/cyab` Overview landing page.

### Coming in Sub-plan C (v0.19.0-rc.3)
Stack-to-use-cases scoping at `/cyab/scoping`; fleet `/cyab/coverage`
matrix; `/cyab/audit` trail.

## v0.18.0 (2026-04-30) — feature

### CyAB Onboarding — Documentation Checklist

A new "Documentation" tab in `/cyab/studio` tracks the documentation artifacts every onboarded system should have on record (HLD, LLD, network topology, runbook, threat model, …). Each item carries a status, an optional URL to wherever the doc lives (Confluence, SharePoint, git, etc.), free-text notes, and last-updated metadata.

#### Default catalogue (20 items)

| Architecture & Design | Operational | Security & Risk | Compliance |
|---|---|---|---|
| ★ HLD | Runbook / Operational SOP | Threat Model | Data Classification |
| LLD | Asset Inventory / CMDB Entry | Risk Assessment | Compliance / Controls Mapping |
| ★ Network Topology Diagram | ★ Owners & Escalation Matrix | Vulnerability / Pentest Report | Incident Response Plan |
| Data Flow Diagram | Backup & Recovery Plan | Authentication & RBAC | Change Management Process |
| Logging & Telemetry Architecture | Disaster Recovery / BCP | | Vendor / License Documentation |
| | Decommissioning Plan | | |

★ = critical. The three critical items drive a soft warning banner on the Pack export and the sign-off response — never blocks, but the analyst sees the gap.

#### Per-item fields

- **Status** — `Done`, `In progress`, `Missing`, `N/A`, `Unknown`
- **URL** — link to the live document
- **Notes** — free text
- **Updated by / at** — auto-tracked

#### Storage

New table `cyab_doc_checklist` keyed on `(system_id, kind)`. Default rows are **lazy-seeded** the first time a system's checklist is fetched, so existing systems get the catalogue without a backfill migration. Sites can add custom items per-system (`is_custom=True`) and delete those custom rows; default rows can have status / URL / notes edited but the row itself stays.

#### Where it surfaces

1. **Studio "Documentation" tab** — table per category, status dropdowns + URL + notes inline-editable, badge on the tab shows `done/total`
2. **Onboarding Pack PDF** — new "Documentation checklist" appendix (★ critical items marked, coverage summary at top, critical-missing warning banner)
3. **Sign-off response** — `POST /api/cyab/studio/systems/{id}/onboarding-pack/sign` now returns `doc_checklist_coverage` so the UI can show a warning banner if critical items are open

#### New routes (mounted under `/api/cyab/studio`)

- `GET    /systems/{sys_id}/checklist` — list + coverage
- `PUT    /checklist/{item_id}` — update status / URL / notes (custom items also: label, is_critical)
- `POST   /systems/{sys_id}/checklist` — add a custom item
- `DELETE /checklist/{item_id}` — remove a custom item (default rows return 400)

All write routes gated on `case:update` (matching the rest of the Studio per v0.17.2).

#### Verifying

```bash
docker compose pull ion
docker compose up -d --force-recreate ion
```

Open `/cyab/studio`, pick a system → "Documentation" tab → 20 default rows appear with status `Unknown`. Edit a row → save is auto-persisted, badge updates. Export the Onboarding Pack → new "Documentation checklist" section near the bottom. Add a custom item via the "+ Add custom item" button.

---

## v0.17.3 (2026-04-30) — fix

Two related Bob investigation bugs in one ship.

### A. Investigations timing out on every call (chat + summary unaffected)

Reported on the deployed v0.15.3 image and still present through v0.17.x. Every Bob investigation came back as "LLM call timed out after 120s", but Bob's chat and summary endpoints worked fine.

#### Root cause

Two stacked 120s timers in the investigation flow racing each other:

1. `investigation_service._call_llm` wraps the Ollama call in `asyncio.wait_for(..., timeout=120)` (`investigation_service.py:1412`).
2. `OllamaService` configures its httpx client with `httpx.Timeout(120s)` (`ollama_service.py:781`).

Investigation prompts are long — full alert context + history + observables + MITRE chain. On llama3.1:8b they routinely take 130-180s, so 120s reliably under-shot. Chat / summary prompts are short (~1-3k tokens) and finished well inside 120s, which is why those paths kept working.

#### Fix

- **`_DEFAULT_LLM_TIMEOUT_S` 120 → 300** in `investigation_service.py`. Resolution order is now: `ION_INVESTIGATION_LLM_TIMEOUT_S` env → config attr `investigation_llm_timeout_s` → module default — operators can tune without a rebuild.
- **OllamaService default `timeout` 120 → 300** so the inner httpx timer doesn't fire before the outer asyncio gate.
- Both timers now have headroom over real-world investigation latencies; chat / summary / embedding paths inherit the new default and become more tolerant of slow Ollama hosts as a side effect.

#### Verifying

```bash
docker compose pull ion
docker compose up -d --force-recreate ion
```

Trigger a Bob investigation on a real alert. Should return a verdict instead of "LLM call timed out". To confirm the new default is loaded:

```bash
docker exec ion python -c "from ion.services.investigation_service import _DEFAULT_LLM_TIMEOUT_S; print(_DEFAULT_LLM_TIMEOUT_S)"
# 300
```

If the work box's LLM is genuinely slower, set `ION_INVESTIGATION_LLM_TIMEOUT_S=600` in `.env` and recreate.

> **Existing deployments — important**: three places can pin the old 120s value, listed in resolution order (highest priority first):
> 1. **`ION_OLLAMA_TIMEOUT` env var in `.env`** — wins over everything. Remove the line OR set to `300` and `docker compose up -d --force-recreate ion`.
> 2. **`/data/.ion/config.json`** — auto-migrated to 300 on load if the file has 120 (we treat 120 as "user didn't customise, give them the new default"). Anyone who explicitly chose 120 would need to set the env var to lock it.
> 3. **Code default** — already 300 as of v0.17.3.

### B. Investigations succeeding but writing `{}` as the summary

When an investigation didn't time out, the summary field on the case / alert often came back as the literal string `{}` — an empty object. Same root cause across many shapes of alert.

#### Root cause

`investigation_service._call_llm_raw` was passing `temperature=0.0` + `top_p=0.1` + `top_k=1` + `response_format="json"` to Ollama. That combination is over-constrained: with greedy decoding (top_k=1) and JSON-mode forcing valid JSON syntax on the output, the model regularly emits **just `{}`** — the smallest valid JSON object — when the first few tokens of its response are uncertain. The downstream `_parse_llm_json` then sees a parsed dict with no `summary` key, falls back to its default of `(content or "").strip()` — which is `"{}"` — and that string ends up persisted on the alert / case.

#### Fix

Relaxed the sampling parameters in `investigation_service.py:1376-1404`:

| Param          | Was   | Now  |
|----------------|-------|------|
| `temperature`  | `0.0` | `0.2` |
| `top_p`        | `0.1` | `0.9` |
| `top_k`        | `1`   | `40` |
| `response_format` | `"json"` | `"json"` (unchanged — correct here) |
| `seed`         | per-call | per-call (unchanged) |

`seed` is still supplied per call so cross-run reproducibility is preserved when needed; the relaxed sampling just gives the decoder room to actually generate content instead of collapsing to `{}`. Determinism for accuracy-tracking purposes is preserved within ~5% verdict variance — well under the noise floor of LLM-judge eval anyway.

---

---

## v0.17.2 (2026-04-30) — fix

### CyAB Studio — permission gates referenced a non-existent permission

Six write-side routes in `cyab_studio_api.py` (sub-profile create / patch / use-case CRUD / intake answer save / onboarding-pack sign-off) were gated on `require_permission("case:write")` — but `case:write` isn't a real permission in ION's RBAC catalogue. The actual case permissions are `case:read`, `case:create`, `case:update`, `case:close`, `case:comment`, `case:link`. So `require_permission("case:write")` always rejected, regardless of role.

Symptom: trying to add a sub-profile, save intake answers, or sign off an Onboarding Pack returned a permission error.

Fix: all 6 routes flipped to `case:update` — a real, analyst-level permission, consistent with the existing pattern (e.g. `cyab_api.py:528` uses `case:close` for system delete).

#### Verifying

```bash
docker compose pull ion
docker compose up -d --force-recreate ion
```

Open `/cyab/studio`, pick a system, edit a sub-profile or save an intake answer — should land instead of erroring on permission.

---

## v0.17.1 (2026-04-30) — feature + fix

### Daily standup — three new KPI panels

A new "Section 2b · KPIs" row on the daily standup page surfaces three operational metrics that were previously buried or missing:

1. **Alert backlog · 30d** — total alerts ION has seen in the last 30 days, broken down by current status (open / acknowledged / closed) plus a "still open %" headline. Reads from the local `AlertTriage` table so it's honest about analyst workload even when ES rotates older alerts out of hot indices.
2. **Cases** — open / in-progress / closed counts (all-time) plus a "7d: N opened / M closed" flow line. Status mapping: `acknowledged` displays as "in progress" since that's how ION's case lifecycle uses it.
3. **Triage · 24h** — count of alerts triaged in the last 24h plus avg / p50 / p90 mean-time-to-acknowledge in minutes. Computed from `AlertTriage.updated_at − created_at` for rows that moved out of `OPEN` in the window.

Each panel is also rendered in the standup PDF / saved-document HTML so the report carries the same KPIs.

New backend collectors (in `daily_standup_api.py`): `_check_open_alerts_30d`, `_check_case_status_counts`, `_check_triage_throughput_24h`. Three new keys on `GET /api/daily-standup/checks`: `open_alerts_30d`, `case_status_counts`, `triage_throughput`.

### Arkime panels — `'ArkimeService' object has no attribute '_auth'`

The Arkime traffic + node-stats panels on the daily standup were calling `svc._auth()`, but `ArkimeService` carries auth in the `Authorization` header (built by `_headers()`), not via httpx's `auth=` kwarg — there is no `_auth` method to call. All four call sites cleaned (`/api/stats`, `/api/sessions`, `/api/eshealth`); auth still travels via the headers as before.

#### Verifying

```bash
docker compose pull ion
docker compose up -d --force-recreate ion
```

Open `/daily-standup`. The three new KPI cards should populate within a second of the page loading. Arkime panels (Section 5) should resolve to data instead of "AttributeError".

---

## v0.17.0 (2026-04-30) — feature

### Translator — standalone page + inline buttons + document upload

A new `/translator` page plus inline Translate buttons across the alerts and cases pages. Backed by your local Ollama model (`ION_TRANSLATOR_MODEL` → `ION_OLLAMA_MODEL` → `llama3.1:8b`), so it inherits whatever you've configured for Bob.

#### Standalone page (`/translator`)

- Dual-pane editor: paste text in the source pane, get translation in the target pane.
- Source language picker (Auto-detect + 14 explicit choices); target language picker. Defaults: Auto-detect → English.
- **Document upload** — `.txt .md .csv .log .json .html .htm .eml .msg .docx .pdf` (via existing `python-docx` / `BeautifulSoup` / `email` stdlib + new `pypdf>=4.0`). Cap: 10 MB per upload.
- Long inputs auto-chunk on paragraph/sentence boundaries (≤10k chars per LLM call) so multi-page reports translate in one click without context-window errors.
- Copy + download buttons on the target pane. Ctrl/Cmd+Enter triggers translate from the source pane.
- Routes:
  - `GET  /translator` — the page
  - `GET  /api/translator/languages` — supported language list
  - `POST /api/translator/translate` — JSON in/out
  - `POST /api/translator/translate-file` — multipart upload + translate
  - `POST /api/translator/extract` — extract source text without calling the LLM (preview)

#### Inline on alerts page

- Translate button + target-language picker rendered alongside the alert message body. Translates in place; "show original" reverts.
- Each comment in the Comments tab gains a Translate toggle (second click flips back to the original markdown).

#### Inline on cases page

- Each Investigation Note in the right-hand panel gains a Translate toggle. Same in-place toggle behaviour.

#### Languages

Auto-detect + en, ru, zh, ja, ko, ar, fa, es, fr, de, pt, it, tr, vi. Model selection: `ION_TRANSLATOR_MODEL` overrides `ION_OLLAMA_MODEL`; both default to `llama3.1:8b`. Llama 3.1 + qwen2.5 are both multilingual enough for the typical SOC inputs (decoded payloads, threat-actor messages, phishing content, intel reports).

#### New dependency

- `pypdf>=4.0` (~200 KB pure-Python) for PDF text extraction. Already present: `python-docx`, `beautifulsoup4`, stdlib `email`.

#### Verifying

```bash
docker compose pull ion
docker compose up -d --force-recreate ion
```

Open `/translator`, paste a foreign-language string, click Translate. Or upload a `.docx` / `.pdf` / `.eml` and watch the extracted text + translation populate. Open any alert with a non-English message → "Translate" button should appear under the message body.

---

## v0.16.2 (2026-04-30) — tooling

### `scripts/ollama_import_gguf.sh` — side-load a Hugging Face GGUF into the Ollama container

ION's embedding service already calls Ollama; sites that want to pin to a specific Hugging Face GGUF build (e.g. `nomic-embed-text-v1.5` with longer context + task-prefix support) rather than whatever Ollama's library ships now have a one-shot helper.

What the script does:

1. Downloads the GGUF from `huggingface.co/nomic-ai/nomic-embed-text-v1.5-GGUF` (default Q4_K_M, ~81 MiB; `--quant Q8_0` etc. for higher quality).
2. `docker cp`s it into the running Ollama container.
3. Writes a minimal `Modelfile` (just `FROM /tmp/import.gguf`).
4. Runs `ollama create <name> -f Modelfile` to register the model under a name you choose (default `nomic-embed-text-v1.5`).
5. Cleans up the temp files inside the container and prints the resulting `ollama list`.

Usage:

```bash
# Default — pull v1.5 Q4_K_M, register as "nomic-embed-text-v1.5":
./scripts/ollama_import_gguf.sh

# Higher quality:
./scripts/ollama_import_gguf.sh --quant Q8_0

# Air-gapped — fetch first on a connected box, then import on the target:
./scripts/ollama_import_gguf.sh --download-only --out /tmp/nomic.gguf
# (copy the GGUF across the gap, then on the air-gapped host:)
./scripts/ollama_import_gguf.sh --gguf /tmp/nomic.gguf

# Then in .env:
#   ION_EMBEDDING_ENABLED=true
#   ION_EMBEDDING_MODEL=nomic-embed-text-v1.5
# and:
docker compose up -d --force-recreate ion
```

No image change, no compose change, no new Python dependency — just a bash helper. The default Ollama container name is `ion-ollama`; override with `ION_OLLAMA_CONTAINER=<name>` if your deployment uses a different name.

---

---

## v0.16.1 (2026-04-30) — fix + polish

### Attack Origin Map — rotating globe + geo data fix

Two related changes on the alerts page's "Attack Origin Map" tab:

#### 1. Geo data now actually pulls from alerts

The map's `extractGeoPoints()` only walked `a.raw_data.{source,destination,…}.geo`, but the list endpoint sends `include_raw=False` to cut payload size — so `a.raw_data` is empty for every alert in the list view, and the map yielded zero points regardless of how much geo enrichment Elasticsearch had captured. (`a.geo_data` — the flattened `source_country` / `source_lat` / `source_lon` block — IS always sent and was being ignored.)

`extractGeoPoints` now reads from `a.geo_data` first, with the raw_data path retained as a fallback for single-alert detail views. `computeArcTarget()` got the same treatment.

#### 2. Flat equirectangular map → orthographic rotating globe

The previous map was a static `earth_night.jpg` background with a Canvas2D overlay. Replaced with a pure-canvas orthographic globe:

- Dark sphere with radial gradient + atmospheric rim
- **Country outlines** projected on the sphere (110m world-atlas topojson, ~107 KB; decoded with the 7 KB `topojson-client` lib at page load)
- 20° lat/lon graticule (equator + prime meridian highlighted)
- Auto-rotation: ~one full revolution per minute (`MAP_ROT_DEG_PER_SEC = 6`)
- Lat/lon → 3D unit-vector → orthographic 2D projection
- Backface culling: points, arc segments and country edges on the far hemisphere are not drawn
- Arcs follow great-circle geodesics rather than 2D quadratic Béziers

New static assets: `static/data/world-countries-110m.json` (Natural Earth public-domain) and `static/js/topojson-client.min.js`. The `earth_night.jpg` asset is no longer referenced.

Hover tooltips updated to the new projection (skips invisible points). Empty state now reads "No geo data on current alerts".

#### Verifying

```bash
docker compose pull ion
docker compose up -d --force-recreate ion
```

Open `/alerts`, switch to the **Threat Map** tab. The globe should rotate slowly. With geo-enriched alerts in scope, source dots appear and arc to the most-targeted destination (London by default). The legend shows `N sources · M countries`.

If your ES alerts don't have `source.geo` enrichment, the legend reads "No geo data on current alerts" — that's an ES pipeline matter, not an ION bug.

---

## v0.16.0 (2026-04-30) — feature

### PCAP auto-analysis on case creation + alert-page comment markdown

Two related shipments:

#### 1. PCAP auto-analysis triggered by `network.community_id`

When a case is linked to alerts that carry `network.community_id` (the Zeek/Arkime flow hash), ION now fires a fire-and-forget background task that:

1. Resolves each unique community_id to an Arkime session (`/api/sessions?expression=communityId == "..."`).
2. Downloads the matching PCAP via Arkime's session-download endpoint.
3. Parses it through the existing `pcap_service.parse_pcap()` (dpkt-based — protocols, top talkers, DNS queries, TLS SNI, HTTP hosts, findings, verdict).
4. Posts a markdown analysis as a case Note attributed to **Bob** (the AI service-user), with a deep link back to Arkime so analysts can pivot.

Best-effort throughout — if Arkime isn't configured, the session lookup fails, or the PCAP can't be parsed, the relevant fallback markdown still gets posted (metadata-only, with the failure reason attached) so the analyst can see the flow exists. Case creation never blocks waiting on Arkime.

New service: `src/ion/services/pcap_analysis_service.py` (~250 LOC). Exposes `enqueue_pcap_analysis_for_case(case_id, community_ids, alert_node_hint=None)`. Mirrors the fire-and-forget pattern used by `case_grouper_service.enqueue_investigation` (running event loop preferred; daemon thread fallback).

Hook point: `web/api.py` `create_case`, after observable enrichment. Scans the linked alerts' `raw_data` for `network.community_id` (and the legacy flat `community_id` key); pulls a node hint from `arkime_node` or `arkime.node` so Arkime can prefer the right capture node when a community_id matches multiple sessions.

#### 2. Alert-page comment renderer now renders markdown

The alert-detail Comments tab was rendering note content as plain escaped text while the Investigation Notes panel on the case page was rendering as markdown — same `Note` model, two different renderers. Now the alert-page renderer uses the same `marked.parse() + DOMPurify.sanitize()` path as `cases.html:2491`, so PCAP-analysis notes (and any other markdown-formatted comment) render identically across both pages.

The `.cpanel-note-markdown` CSS block was also lifted from `cases.html` into the shared `style.css` so future templates that need markdown notes get the same look without duplicating ~90 lines of CSS.

#### Verifying

```bash
docker compose pull ion
docker compose up -d --force-recreate ion
```

Create a case from one or more alerts that carry `network.community_id`. Within a few seconds (Arkime + dpkt round-trip), a new note appears on the case from "Bob" with the PCAP analysis. Reload the alert detail panel for any of the linked alerts and you'll see the same note rendered with full markdown styling (headings, tables, code blocks).

If Arkime isn't configured, the note still posts but contains only the metadata block + an "Arkime not configured" note — useful for noticing the integration is missing.

---

## v0.15.3 (2026-04-30) — fix

### Case creation — observables harvested from every linked alert, not just 2-3

When a case was created from multiple linked alerts, only 2-3 observables ended up on the case even when the linked alerts collectively had many more. The bug was in the case-creation flow's data source: it relied entirely on **client-supplied** `alert_contexts.raw_data`, then ran extraction from that. If the frontend linked five alerts but only included `raw_data` for two of them, the remaining three contributed zero observables — even though their `AlertTriage.observables` JSON column was already populated from the original triage.

#### Fix

- `create_case` now **harvests observables directly from `AlertTriage.observables`** for every alert in `alert_ids`. The triage rows are linked to the case anyway (line 4341 sets `triage.case_id`), and their observable lists were already extracted at triage time — no need to re-extract from raw ES docs.
- Falls back to re-extracting from `raw_data` only for alerts whose triage row is freshly created during the same call (those have `observables=None`).
- Results from both paths are merged and deduped by `(type, value)`.

New service method: `ObservableService.enrich_and_link_observables_for_case(case_id, observables)` — same enrich-and-link logic as `extract_enrich_for_case`, but takes a pre-extracted `[{type, value}, …]` list instead of raw alert documents.

#### Net effect

A case linking five alerts that each had ten observables at triage time now lands all 50 (deduped) on the case, with OpenCTI enrichment, instead of dropping 80%+ of them on the floor.

#### Verifying

```bash
docker compose pull ion
docker compose up -d --force-recreate ion
```

Pick five existing triaged alerts, link them into a single new case, then check `/cases/{id}` → "Observables" tab. The list should reflect all observables across every linked alert.

---

## v0.15.2 (2026-04-30) — fix

### Daily standup — PDF export missed the threat summary + reports; saved docs were JSON

Two related bugs on the daily standup page:

1. **The PDF export was missing the AI threat-landscape summary AND the reports-of-interest list.** Frontend `collectState()` was sending `threat_summary` / `servicenow_incidents` / `signoff_analyst` / `signoff_confirmed` while the backend `StandupSaveRequest` expected `ai_summary` / `servicenow_notes` / `analyst_name` / `signed_off`. Pydantic silently dropped the unmatched fields, so the AI summary, ServiceNow notes, sign-off block, and the meetings checklist never made it into the rendered PDF. The reports-of-interest list was never sent at all.

2. **Saving the standup as a document then exporting that document to PDF produced a PDF dump of raw JSON.** The save endpoint stored `rendered_content=json.dumps(...)` with `output_format="json"`, so the generic `/documents/{id}/pdf` flow rendered the JSON blob into a PDF instead of a styled report.

#### Fixes

- Extracted `_render_standup_html(data, current_user)` — single source of truth for the rendered standup HTML, used by both `/save` and `/pdf`.
- Added a **"Threat Reports of Interest"** section (rendered as a linked list with publication dates).
- Added a **"Daily Meetings"** checklist section (renders the checked / unchecked items by stable label, plus the custom meeting item if one was entered).
- `/save` now stores `rendered_content=<rendered HTML>` with `output_format="html"` — so the document-export-PDF flow produces the same styled PDF as the inline export, instead of a raw-JSON dump.
- Frontend `collectState()` field names aligned with the backend (`ai_summary`, `reports_of_interest`, `servicenow_notes`, `analyst_name`, `signed_off`). `loadReports()` now caches the report list on `DS.reports` so it ships with every save / export.
- Removed `meeting_notes` from the save model (it was unused — the meetings data lives in the `meetings` dict + `custom_meeting_item`).

#### Verifying

```bash
docker compose pull ion
docker compose up -d --force-recreate ion
```

Open the daily standup, run the checks, generate the threat summary, tick a couple of meetings, then export PDF → all sections present. Save the standup, open it from `/documents`, hit "Export PDF" on that document → same styled PDF (not raw JSON).

---

## v0.15.1 (2026-04-30) — fix

### Daily standup — WEF log-source-health timeouts on busy estates

The WEF check in the daily standup was timing out on busy estates because the global Elasticsearch request timeout was hardcoded to 10 s, while the WEF aggregation (terms over hosts × 24 hourly buckets + a 7-day rollup) routinely exceeded that on real data volumes.

#### Fixes

1. **Global ES timeout 10 s → 30 s**, configurable via `ION_ES_TIMEOUT` (seconds). Picks up automatically from `.env` on container recreate.
2. **Per-request timeout override** on `elasticsearch_service._request()`. Heavy aggregations can now pass `timeout=60.0` without affecting the global default for fast endpoints.
3. **Standup `terms.size` reduced 500 → 100**, configurable via `ION_STANDUP_TERMS_SIZE`. WEF estates rarely have >100 forwarders in scope; the 500-host fan-out was the dominant cost. Operators with more hosts override via env.
4. **Standup queries pass `timeout=60.0`** explicitly, isolating the slow path from any future global-timeout tightening.

Net effect on a typical busy estate: the WEF check that was timing out at 10 s now completes in 8-15 s with the lighter `terms.size` and has 60 s of headroom on the rare slow run.

#### Verifying

```bash
docker compose pull ion
docker compose up -d --force-recreate ion
```

If WEF still times out after the upgrade, raise `ION_ES_TIMEOUT=60` in `.env` (covers very large estates) and check `/api/daily-standup/full` — the response includes a `diag` block with the resolved index / host_field / patterns / hit count for fault-finding.

---

## v0.15.0 (2026-04-29) — feature

### Wallboard — operational panel swap (Rules + Topology + Threat Landscape)

The v0.14.x wallboard pulled three of its panels from areas that aren't useful on a SOC wall display (`detection` was just a template count, `cyab` was onboarding KPIs, `curriculum` was course enrolments). v0.15.0 swaps all three for content that earns its place on a wall:

| Panel | Was | Now |
|---|---|---|
| Detection | AlertPromptTemplate count + TIDE healthy/total | **Rules** — real rule posture from TIDE |
| CyAB | systems + readiness donut + sub-profile bar | **Platform Topology** — hub-and-spoke SVG of the estate |
| Curriculum | enrolments + completions + top-3 courses | **Threat Landscape** — Ollama-generated 24h summary |

#### Panel 4 — Rules (real posture)

Calls `tide_service.get_posture_stats()`. Big number is **enabled rules** (the count that actually matters for coverage); subtitle shows enabled / total. Body shows MITRE technique coverage as a fraction + percentage, plus the avg rule quality score. Severity rows (critical / high / medium / low) render as stacked bars where the brighter overlay shows the *enabled* fraction so disabled rules read as a darker stub. Falls back to a "TIDE not configured" tile when the integration is offline.

#### Panel 5 — Platform Topology

Replaces both the panel content and the header service-health dots — a single SVG hub-and-spoke graph with ION at the centre and seven integration spokes (Postgres, Elasticsearch, Kibana, TIDE, OpenCTI, Ollama, Bob). Edge colour matches status: ion-lime (up), ion-coral pulsing (down), grey-dashed (off / not configured). Node order is fixed so the only thing that moves between snapshots is the colour — the eye reads movement as instability on a wall display.

The header now shows a compact `up / down / off` count strip instead of the dot row, since the topology panel is the canonical place to read service status.

#### Panel 6 — Threat Landscape (AI summary)

Aggregates last-24h alert severity, last-7d verdict distribution, top closure reasons (7d), and the open-case backlog severity profile. Builds an analyst-grade prompt and POSTs to Ollama via the `/api/generate` endpoint with a 15s timeout. The wallboard's 5-min cache TTL means Ollama is hit at most once per 5 minutes regardless of how many wall displays are loaded.

If Ollama is unreachable or unconfigured, the panel falls back to a stats-only sentence so it never goes blank. Configure with `ION_OLLAMA_URL` (or `OLLAMA_HOST`) + optional `ION_WALLBOARD_OLLAMA_MODEL` (defaults to `llama3.1:8b`).

#### Backend changes

- `_collect_detection` → `_collect_rules` (sources from TIDE posture stats)
- `_collect_cyab` → `_collect_topology` (derives from existing service-health collection — no new data sources)
- `_collect_curriculum` → `_collect_threat_landscape` (calls Ollama via httpx sync client; falls back gracefully)
- `_gather` rewired; the snapshot keys are now `rules`, `topology`, `threat_landscape` (the previous `detection` / `cyab` / `curriculum` keys are removed — any external snapshot consumer will need to update)

#### Verifying

```bash
docker compose pull ion
docker compose up -d ion
```

Hit `/wallboard`. The Rules panel populates from TIDE on the first refresh; the topology renders immediately from service-health; the threat-landscape paragraph appears after the first Ollama round-trip (~10-15s on the first load after TTL expiry, cached afterwards).

---

## v0.14.1 (2026-04-29) — polish

### Wallboard restyle — ION design tokens, sparklines, donut

The v0.14.0 wallboard shipped functional but with a generic palette. This pass brings it in line with `dashboard_v2.html` / `analytics.html` so the wall display reads as part of the same product.

#### Visual changes

- **Tailwind-token panels** — each panel now uses `rounded-[16px] border border-white/5 bg-ink-900/50` to match the dashboard cards. Big numbers move to `font-sans font-semibold tabular-nums tracking-tight text-[44px] xl:text-[56px]` with ION accent colours (`text-ion-cyan` / `iris` / `lime` / `amber` / `coral`) per panel.
- **SVG sparklines** — Alerts panel gains a 24-hour hourly sparkline; Cases panel a 7-day closures sparkline; Bob panel a 7-day investigations sparkline. Hand-drawn SVG (no Chart.js dep), matching the pattern already used on `dashboard_v2`.
- **Donut for CyAB readiness** — replaces the plain percentage with a 60×60 stroke-dasharray donut + numeric centre, coloured by score band.
- **Distribution bars** with grid layout (`110px / 1fr / 44px`) and ION-coloured fills (`ion-coral` for critical/malicious, `ion-lime` for benign/healthy, `ion-amber` for warn/investigating, `ion-cyan` for closed).
- **Service-health dots** — `bg-ion-lime` (up), `bg-slate-600` (off / not configured), `bg-ion-coral` with `wb-pulse-down` animation (down).
- **Marquee ticker** — kept full-width, but now uses `wb-scroll 60s linear infinite` keyframes and ION accent colours per priority tier.
- **CSS bundle** — page now loads `lucide.css` + `style.css` + `design-system.css` + `tailwind.css`, identical to the rest of the app, so token changes flow through automatically.

#### Backend additions

- `_collect_alerts` now emits `histogram_24h` (24 hourly buckets, last-24h) for the sparkline.
- `_collect_cases` now emits `closures_history_7d` (7 daily buckets) for the sparkline.
- `_collect_bob` now emits `history_7d` (7 daily buckets of investigations) for the sparkline.

All three are derived from the same data already being aggregated; cost-neutral relative to v0.14.0.

#### Verifying

```bash
docker compose pull ion
docker compose up -d ion
```

Hit `/wallboard` and put it on a wall display. The histograms populate immediately on first refresh. `GET /api/wallboard/snapshot` now includes the three new arrays so external consumers (dashboards, Grafana plugins) can render their own charts.

---

## v0.14.0 (2026-04-29) — feature

### Wallboard dashboard — full-screen ION snapshot for wall display

A single page intended for full-screen wall monitoring of the SOC. Six metric panels (alerts, cases, Bob, detection, CYAB, curriculum), a service-health strip across the top, a marquee ticker across the bottom, and a clock. Auto-refreshes every 5 minutes client-side; the underlying snapshot is server-cached with a 5-min TTL so N concurrent wall displays cost the same as 1.

#### What's authored

- **`services/wallboard_service.py`** — single-snapshot service. `get_snapshot(session)` returns a fresh snapshot if the cached one is older than 5 min, otherwise serves cached. Each panel-collector is wrapped in a try/except so a broken integration (e.g. ES unreachable) emits a partial result with `error: <msg>` rather than blowing up the whole snapshot. ~340 LOC.
- **`web/wallboard_api.py`** — three routes: `GET /wallboard` (HTML page), `GET /api/wallboard/snapshot` (JSON; cached), `POST /api/wallboard/refresh` (force-recompute).
- **`web/templates/wallboard.html`** — standalone full-screen template (does not extend `base.html` to maximise screen real estate). 1920×1080-friendly grid: header + 3×2 panel grid + ticker. High-contrast colour palette; all numbers in tabular-nums for visual stability under live update; service-health dots with pulse animation on `down` state.

#### What each panel surfaces

| Panel | Big number | Supporting metrics |
|---|---|---|
| **Alerts** | `last 24h count` | open / acknowledged / closed; verdict distribution (last 7d) |
| **Cases** | `open right now` | closures last 24h; severity distribution of open cases |
| **Bob — AI Analyst** | `investigations 24h` | total investigations; feedback rows; analyst-Bob agreement % bar |
| **Detection** | `alert-prompt template count` | TIDE healthy / total; TIDE error count |
| **CyAB Onboarding** | `system count` | avg readiness score; sub-profile assignment progress bar |
| **Curriculum** | `completed courses` | total enrolments; certificates issued; top 3 enrolled courses |

#### Service health strip

Six dots across the header — Postgres / Elasticsearch / Kibana / TIDE / OpenCTI / Ollama / Bob. Green = up, grey = off (not configured), red-pulsing = down. Best-effort checks; never blocks the snapshot.

#### Caching strategy

The first wallboard load after a TTL-expiry recomputes the snapshot; subsequent loads within the next 5 minutes serve the cached version. `cache_age_seconds` is exposed on the response so the page can render *Snapshot refreshed Nm ago* in the header. Setting `force=true` (or hitting `POST /api/wallboard/refresh`) bypasses the cache for admin / cron use.

#### Verifying the feature

```bash
docker compose pull ion seeder
docker compose up -d
```

Then in a browser, navigate to `/wallboard` (auth-required) and put it on a wall display. The page auto-refreshes every 5 min. Direct API access at `/api/wallboard/snapshot` returns the same JSON with `cache_age_seconds` indicating when the snapshot was last computed.

For dedicated kiosk-mode deployment, point a Chromium kiosk session at the URL after a one-time login. The snapshot auto-refreshes; no further interaction needed.

#### Notes on extension

- New panel? Add a `_collect_<x>(session)` function to `wallboard_service.py`, hook into `_gather()`, add a `<section class="wb-panel">` in `wallboard.html`, write a `render<X>` JS function. ~30 LOC per panel.
- New service-health entry? Add to `_collect_service_health` in the service + add the name to the `SERVICES` JS array.
- Tighter refresh? Set `_CACHE_TTL_SECONDS` lower in `wallboard_service.py` and the matching `REFRESH_MS` in the template. Default is 300 / 5 minutes; tighter than that risks DB load on multi-display deployments.

---

## v0.13.2 (2026-04-29) — feature

### Labs (foundational) — 8 hands-on labs across L1 / L2 / L3 + the missing /my-courses page

The third post-curriculum backlog item lands. 8 LAB-type lessons added to the curriculum, each pointing at an ION URL with a written task description + 3-4 verification questions. Plus the missing `/my-courses` analyst dashboard that the nav has linked to since v0.11.x but that was never actually built.

#### What's authored

| # | Course | Module | Title | Target URL |
|---|---|---|---|---|
| 1 | L1 | M2 SIEM Fundamentals | Read your first alert | `/alerts` |
| 2 | L1 | M5 IOC Handling | Tag and triage an observable | `/observables` |
| 3 | L1 | M7 Escalation Workflow | Escalate via the runbook | `/cases?status=acknowledged` |
| 4 | L2 | M2 KQL/EQL/ES&#124;QL | Hunt with KQL on Discover | `/discover` |
| 5 | L2 | M5 Network telemetry | Hunt a beacon with ES&#124;QL CV | `/discover` |
| 6 | L2 | M8 Hunt-to-Detection | Convert a hunt finding to TIDE rule | `/cyab/studio` |
| 7 | L3 | M3 Caldera operations | Caldera operation end-to-end | `http://caldera.local:8888` |
| 8 | L3 | M6 Multi-host chain | 3-host FIN6 chain via Caldera | `http://caldera.local:8888` |

Each LAB lesson is a `Lesson` row with `lesson_type=LAB` + `lab_target_url`; verification questions attach via the existing `Question` model. Reuses the `LessonType.LAB` enum and `lab_target_url` column that have been on the model since v0.11.2 but went unused until now.

#### Lesson totals after this ship

| Course | Modules | Lessons (was → now) |
|---|---|---|
| L1 — Alert Triage Fundamentals | 8 | 59 → **62** (+3 labs) |
| L2 — Threat Hunting with KQL | 8 | 64 → **67** (+3 labs) |
| L3 — Adversary Emulation Basics | 8 | 64 → **66** (+2 labs) |
| **Total** | **24** | **187 → 195** |

#### `/my-courses` page — fixed

The `/my-courses` route was referenced in the top-nav across `base.html` and `courses.html` since v0.11.x, but neither the page route nor the template existed. v0.13.2 fixes the gap:

- New page route `GET /my-courses` in `course_api.py`.
- New template `my_courses.html` rendering the user's enrolments with: aggregate stats (enrolled / completed / in-progress / avg-score), per-course rows with status badges, and direct **Download Certificate** buttons (cross-link to v0.13.0) on completed courses.

#### LAB rendering already wired

The `course_detail.html` and `lesson.html` templates already had LAB-distinct rendering wired (lab pill colour, "Hands-on lab" banner with link to `lab_target_url`, verification-quiz form). v0.13.2 contributes content; the UI surface was already live.

#### Verifying the feature

```bash
docker compose pull ion seeder
docker compose up -d
docker exec ion python /app/seed_all.py --force
```

After re-seed:
1. `/courses` → any of L1 / L2 / L3 → the course-detail page now lists LAB lessons (orange pill) alongside reading + quiz lessons.
2. Open any LAB lesson — orange "🛠 Hands-on lab" banner with a link to the target URL; markdown task description; verification questions below.
3. `/my-courses` now works — shows enrolled courses with completion status + cert download buttons.
4. Complete a lab (mark its verification questions correct enough to pass `pass_threshold` on the lesson); the course's overall progress updates; if all lessons (including labs) are complete, completion fires + certificate becomes available.

#### Why the foundational scope

This is the "foundational" Labs scope per `_research_labs_design.md`. Subsequent ships:

- **v0.13.3** — Lab fixtures: a new `lab_fixtures` table holding seed-data fixtures (mock alerts / cases / observables) that get inserted on lab launch and torn down on completion. Makes labs replayable with predictable content.
- **v0.14.0** — Adaptive grading: an audit-log subscriber that watches the analyst's actions in ION (queries run, alerts triaged, cases closed) and grades against expected actions. Verification quizzes become reinforcement; primary score comes from the grading hooks.

---

## v0.13.1 (2026-04-29) — feature

### Elastic Agent Skills consumer — Bob's 6th matcher tier

ION now consumes the Anthropic-originated **Agent Skills** format (`SKILL.md` folders with YAML frontmatter + Markdown body). Loaded skills are matched against the current alert via the existing alert context — technique-id, rule-group, keyword overlap with `when_to_use` — and injected into the system prompt rendered by `render_system_prompt`. The matcher is **keyword / technique / tag-driven, not embedding-driven** — works on estates with `ION_EMBEDDING_ENABLED=false` and `ION_KB_RAG_ENABLED=false`.

#### What's authored

- **`services/skill_loader.py`** — parses bundled + runtime SKILL.md folders, matches against alert via `matches_techniques` (parent-sub tolerant), `matches_rule_groups`, and a keyword scan of `when_to_use`. ~250 LOC.
- **Two bundled skills** in `src/ion/data/skills/`:
  - `elasticsearch-esql/SKILL.md` — ES|QL idioms, ECS field discipline, aggregation patterns, time-windowing. Triggered when `rule.language: esql` or alert is from Elastic Security / Sigma / Elastic Agent rule groups.
  - `process-tree-investigation/SKILL.md` — process parent-child reasoning, integrity-level shifts, LOLBin patterns. Triggered on Sysmon / EDR / process techniques (T1059, T1003, T1055, T1218, T1547.001).
- **Runtime override** at `${ION_SKILLS_DIR}` or `${ION_DATA_DIR}/skills` — operator can drop skills there to override or supplement bundled ones (skills with the same `name` overwrite by source-precedence: runtime > bundled).
- **`alert_prompt_service.render_system_prompt`** — appends a "Loaded Skills (Tier-6 augmentation)" block to the system prompt after the per-rule template, KB context, and gold exemplars; before the canonical output contract.
- **`pyproject.toml package-data`** updated to include `data/**/*.md` so the bundled SKILL.md files install with `pip install .`.

#### Verifying the feature

```bash
docker compose pull ion seeder
docker compose up -d
```

After restart:
1. Alerts whose rule mentions ES|QL or matches Elastic Security rule groups gain a *Loaded Skills* block in the LLM system prompt with the `elasticsearch-esql` skill body inline.
2. Endpoint alerts on Sysmon / process techniques gain the `process-tree-investigation` skill.
3. Operator can drop new SKILL.md folders into `${ION_DATA_DIR}/skills/<name>/SKILL.md` and they're picked up on next investigation invocation (no restart needed).

#### Why it's keyword-driven, not embedding-driven

Skills are **prompt augmentations**, not retrieval results. The matching dimension (technique-id / rule-group / explicit tag) is well-defined enough to not need vector similarity. ION's existing 5-tier `AlertPromptTemplate` matcher is also keyword-driven, by the same reasoning. This means Skills work cleanly on estates with embeddings disabled — no `nomic-embed-text` dependency, no pgvector requirement.

The follow-on **publisher** angle (export ION's `AlertPromptTemplate` rows as `SKILL.md` folders for cross-SOC reuse) is deferred until the consumer path is in production for a quarter.

---

## v0.13.0 (2026-04-29) — feature

### PDF course-completion certificates

With the full curriculum (L1 + L2 + L3) shipped at v0.12.14, course completers can now download a PDF certificate. The cert is generated weasyprint-side at request time, A4-landscape, with ION branding, course / level / learner-name / completion-date / aggregate-score / module + lesson totals, and a verification id of the form `CERT-<slug>-<enr-id>-<YYYYMMDD>`.

#### What's authored

- New API route `GET /api/courses/{slug}/certificate.pdf` — generates the certificate PDF for the current user's enrolment. Returns 404 if the course doesn't exist, 403 if the user isn't enrolled or hasn't completed the course, 200 + `application/pdf` otherwise. Falls back to HTML render if weasyprint unavailable.
- `_render_certificate_html()` — internal renderer building the styled HTML body. Same weasyprint pattern as the v0.12.0 CyAB Onboarding Pack.
- `course_detail.html` — *Download certificate* button rendered on completed courses, alongside the existing "✓ Completed · NN%" pill. Links directly to the new endpoint.
- The pre-existing `course_enrolments.certificate_url` column (defined v0.11.7+) is now populated on first download — caches the URL so the catalog can show issued state without re-rendering.

#### Verifying the feature

```bash
docker compose pull ion seeder
docker compose up -d
```

After upgrade:
1. Open `/courses` and pick any course (e.g. *Adversary Emulation Basics*).
2. Enrol; complete every lesson (mark as done; submit quizzes with passing scores).
3. The course-detail header shows ✓ Completed + a *Download certificate* button.
4. Click — a PDF downloads named `ion_certificate_<slug>_enr<id>.pdf`. Open it; A4-landscape with the framed cert, learner name, completion date, score, verification id at the bottom.
5. Re-clicking issues the same PDF (idempotent rendering; `certificate_url` is cached after first download).

No DB migration — uses the existing `certificate_url` column that has been on `UserEnrolment` since v0.11.7.

---

## v0.12.14 (2026-04-29) — curriculum (L3 COMPLETE; FULL CURRICULUM SHIPPED)

### L3 Module 8 — Capstone — Full purple-team programme review

L3 closes 7/8 → **8/8 ✅**. The capstone integrates all seven prior modules into one quarterly programme cycle: planning + execution + scoring + retrospective. Mid-quarter pivot when CTI shifts; integration with the org's risk register; the quarterly board package the L3 prepares for the CISO; career-path post-L3 (IR / detection-eng / architect / CTI); the five L3 anti-patterns; programme handoff to a successor.

#### What's authored

8 lessons (7 reading + 1 quiz capstone), 9 questions, ~12k words at BTL1/SANS GCTH depth. (Capstone-style — heavier on integration, lighter on new material than M2-M7.)

| Lesson | Topic |
|---|---|
| 8.1 | Five-phase quarterly cycle — plan / execute / score / action / retrospective |
| 8.2 | Worked Q3 12-week programme plan with exercise mix |
| 8.3 | Mid-quarter pivot triggers + two-week pivot rule |
| 8.4 | 30-min retrospective format with systemic-vs-local pattern analysis |
| 8.5 | Risk register integration — control-effectiveness rating contributions |
| 8.6 | Quarterly board package — five one-page sections |
| 8.7 | Career paths + the five L3 anti-patterns + programme handoff |
| 8.8 | Capstone — trajectory framing + handoff package |

#### Curriculum status — **L1 + L2 + L3 ALL COMPLETE**

- **L1 — Alert Triage Fundamentals**: 8 modules / 59 lessons ✅
- **L2 — Threat Hunting with KQL**: 8 modules / 64 lessons ✅
- **L3 — Adversary Emulation Basics**: 8 modules / 64 lessons ✅
- **Total**: 24 modules / 187 lessons / hundreds of questions / ~360k words at BTL1/SANS GCTH depth

The full SOC analyst's curriculum from first-day triage (L1) through threat hunting with KQL (L2) through detection-engineering programme leadership (L3) is now shipped at proper depth.

#### Verifying the feature

```bash
docker compose pull ion seeder
docker compose up -d
docker exec ion python /app/seed_all.py --force
```

After re-seed, the *Adversary Emulation Basics* course should show **8 modules, 64 lessons** matching the L1 + L2 cadence. The full curriculum is now ready for analyst self-paced learning.

#### Post-curriculum backlog

Now that the curriculum is complete, the post-curriculum work resumes:

- **PDF certificate generation** on course completion.
- **Elastic Agent Skills consumer** (Bob's 6th matcher tier).
- **Labs** — interactive exercises that link into ION's investigation queue.

---

## v0.12.13 (2026-04-29) — curriculum

### L3 Module 7 — Out-of-hours / off-shift validation

L3 advances 6/8 → **7/8**. Why in-hours coverage doesn't imply OOH; the OOH response stack (SOAR + on-call as load-bearing front line); OOH exercise design + scoping (Tuesday 02:00 window, direct on-call pre-brief, < 1h time-box); the dual-window comparison (same chain in-hours and OOH; per-phase TTR delta); OOH-specific gap audit (dashboards no one watches, 9-5 automation, vendor-support hours, cross-team paths); OOH-coverage parity rule (80% threshold); leadership reporting that splits in-hours and OOH metrics with explicit trade-off framing.

#### What's authored

8 lessons (7 reading + 1 quiz capstone), 9 questions, ~14k words at BTL1/SANS GCTH depth.

| Lesson | Topic |
|---|---|
| 7.1 | In-hours ≠ OOH — ten things change at 03:14; MTTR splitting |
| 7.2 | OOH response stack — SOAR + on-call as front line |
| 7.3 | OOH exercise design — Tuesday 02:00, direct pre-brief, time-box |
| 7.4 | Dual-window comparison — per-phase TTR delta drives severity reclassification |
| 7.5 | OOH-specific gap audit — five gap classes with backlog routing |
| 7.6 | Coverage parity — 80% / 100% bands; per-technique parity |
| 7.7 | Leadership reporting — split scorecard; trade-off framing |
| 7.8 | Capstone — backlog routing for OOH gaps + investment-vs-accept framing |

#### Curriculum status

- **L1**: 8/8 ✅
- **L2**: 8/8 ✅
- **L3**: **7/8** authored at proper depth (M1-M7). M8 — Capstone — next, then L3 COMPLETE.

---

## v0.12.12 (2026-04-29) — curriculum

### L3 Module 6 — Multi-host chain emulation

L3 advances 5/8 → **6/8**. The applied module: takes M3 (Caldera) + M4 (telemetry) + M5 (DE loops) and runs an end-to-end multi-host chain. From single-TTP fidelity scoring to chain response-time measurement; per-host authorisation + pre-brief; Caldera's `look` planner with cross-agent fact propagation; per-phase TTR + end-to-end chain time; chain-vs-containment-gap arithmetic; chain-level scorecard with kill-chain step columns; mid-exercise mistaken-IR-engagement recovery procedure; cohesive TuningProposals with cross-references.

#### What's authored

8 lessons (7 reading + 1 quiz capstone), 9 questions, ~14k words at BTL1/SANS GCTH depth.

| Lesson | Topic |
|---|---|
| 6.1 | Single-TTP vs chain — what each measures; rule of N (≥ 4 hosts) |
| 6.2 | Chain design — pick adversary, map phases, host roles, chain plan document |
| 6.3 | Per-host authorisation + pre-brief — scaling M1.3 to multi-host; operational chats |
| 6.4 | Caldera execution — agent deploy + `look` planner + cross-agent fact verification |
| 6.5 | Per-phase TTR + end-to-end chain time + chain-vs-containment gap |
| 6.6 | Chain scorecard — kill-chain step columns + cohesive TuningProposals |
| 6.7 | Mistaken-IR-engagement — five-step recovery (pause/notify/confirm/decide/document) |
| 6.8 | Capstone — response-leverage math + leadership reporting |

#### Curriculum status

- **L1**: 8/8 ✅
- **L2**: 8/8 ✅
- **L3**: **6/8** authored at proper depth (M1-M6). M7 — Out-of-hours / off-shift validation — next.

---

## v0.12.11 (2026-04-29) — curriculum

### L3 Module 5 — Detection-engineering loops

L3 advances 4/8 → **5/8**. The post-exercise lifecycle: TuningProposal authoring with the eight required fields; the acceptance-criteria contract (specific test + outcome + evidence + time-boxed); gap-fix verification re-tests on the same atomic + scoping; regression tracking quarterly via prior-Tier-1 sampling; lifecycle KPIs (FP rate, TP rate, MTT, drift); TIDE submission and the handoff to detection-engineering (cross-link to L2 M8's five-gate framework). The discipline that turns audit findings into shipping rules and prevents the *paper-closed* failure mode.

#### What's authored

8 lessons (7 reading + 1 quiz capstone), 9 questions, ~14k words at BTL1/SANS GCTH depth.

| Lesson | Topic |
|---|---|
| 5.1 | Closed-loop overview — gap → ticket → fix → re-test → close; paper-closed vs verified-closed |
| 5.2 | TuningProposal authoring — eight required fields with worked example |
| 5.3 | Acceptance-criteria contract — testable / reproducible / time-boxed; anti-patterns |
| 5.4 | Re-test execution — same atomic + same scoping; four outcomes (closes / partial / no change / worse) |
| 5.5 | Regression tracking — quarterly sampling of prior-Tier-1 techniques; five regression triggers |
| 5.6 | Lifecycle KPIs — FP rate (50% drift threshold), TP rate (30% floor), MTT, deprecation triggers |
| 5.7 | TIDE submission — pre-submission five-gate check; CI validation; ownership handoff |
| 5.8 | Capstone — regression handling + paper-closed pushback |

#### Curriculum status

- **L1**: 8/8 ✅
- **L2**: 8/8 ✅
- **L3**: **5/8** authored at proper depth (M1-M5). M6 — Multi-host chain emulation — next.

---

## v0.12.10 (2026-04-29) — curriculum

### L3 Module 4 — Telemetry quality assessment

L3 advances 3/8 → **4/8**. The pivot module: M1-M3 covered *how to emulate*; M4 covers *whether the telemetry can see it*. The technique → telemetry contract; field-coverage audits with the three-band threshold; parser-health monitoring beyond pass/fail (drift, schema-version regressions); Florian Roth's Detection-Maturity Model (DML-0 to DML-9) for per-technique rating; the schema-debt backlog as a fourth queue (alongside detection-eng / SIEM-team / platform); Sysmon coverage audit against SwiftOnSecurity / Olaf Hartong baselines; quarterly fleet-wide gap audit + leadership summary.

#### What's authored

8 lessons (7 reading + 1 quiz capstone), 9 questions, ~16k words at BTL1/SANS GCTH depth.

| Lesson | Topic |
|---|---|
| 4.1 | Technique → telemetry contract — fingerprint fields per technique; uncatchable techniques |
| 4.2 | Field-coverage audit — three-band threshold (95% / 50-95% / <50%); ES&#124;QL skeleton |
| 4.3 | Parser health beyond pass/fail — `ingest.failed_documents` trends, drift signals, schema-version regressions |
| 4.4 | DML model — DML-0 (none) to DML-9 (predictive); per-technique rating; heatmap |
| 4.5 | Schema-debt backlog — fourth queue; upstream of detection-eng; leadership KPI |
| 4.6 | Sysmon coverage audit — SwiftOnSecurity vs Olaf Hartong; missing event class as schema-debt |
| 4.7 | Quarterly fleet-wide gap audit — five-stream audit; leadership summary; backlog routing |
| 4.8 | Capstone — order-of-operations question + DML rating |

#### Curriculum status

- **L1**: 8/8 ✅
- **L2**: 8/8 ✅
- **L3**: **4/8** authored at proper depth (M1-M4). M5 — Detection-engineering loops — next.

---

## v0.12.9 (2026-04-29) — curriculum

### L3 Module 3 — MITRE Caldera operations

L3 advances 2/8 → **3/8**. M3 covers the agent-based half of L3's toolkit: server stand-up, sandcat agents and the beacon mechanic, ability authoring, adversary profile chaining, the four planners (`batch` / `atomic` / `buckets` / `look`), multi-host operations with cross-agent fact propagation, and the agent-removal-after rule at scale.

#### What's authored

8 lessons (7 reading + 1 quiz capstone), 9 questions, ~16k words at BTL1/SANS GCTH depth.

| Lesson | Topic |
|---|---|
| 3.1 | Five core concepts — server / agent / ability / adversary / operation; ART vocabulary mapping |
| 3.2 | Server stand-up — canonical docker-compose, `--recursive` clone, plugin set, default-cred rotation, contact channels |
| 3.3 | Sandcat agent — Win/Lin/macOS deploy, beacon mechanic (paw / group / platform), jitter, agent-removal-after |
| 3.4 | Ability authoring — YAML format, `#{var}` fact substitution, requirements, plugin loading |
| 3.5 | Adversary profiles — `atomic_ordering`, fact dependencies, `atomic` plugin bridging ART → Caldera |
| 3.6 | Operations — four planners (`batch` / `atomic` / `buckets` / `look`), operation report, pause/resume |
| 3.7 | Multi-host operations — fact propagation across agents, `look` planner, agent-to-agent abilities |
| 3.8 | Capstone — submodule failure mode + multi-host planner pick |

#### Curriculum status

- **L1**: 8/8 ✅
- **L2**: 8/8 ✅
- **L3**: **3/8** authored at proper depth (M1 / M2 / M3). M4 — Telemetry quality assessment — is next.

---

## v0.12.8 (2026-04-29) — curriculum

### L3 Module 2 — Atomic Red Team library deep-dive

L3 advances 1/8 → **2/8**. Module 2 goes deep on the ART ecosystem M1 introduced lightly: repo structure, the YAML test schema, custom-atomic authoring for org-specific TTPs, dependency engineering, multi-platform tests, MITRE Engenuity CTID's Adversary Emulation Library, and the four-point safety harness.

#### What's authored

8 lessons (7 reading + 1 quiz capstone), 9 questions, ~17k words at BTL1/SANS GCTH depth.

| Lesson | Topic |
|---|---|
| 2.1 | Repo structure — `atomics/` / `Indexes/` / per-platform indexes / Navigator → ART path workflow |
| 2.2 | YAML schema — five required top-level fields, `#{var}` interpolation, executor types, multi-step executors |
| 2.3 | Authoring custom atomics — six-step workflow, public-PR vs org-internal decision tree, ART CI requirements |
| 2.4 | Dependency engineering — prereq blocks, CDN-cached download, runtime-fetch vs pre-staged trade-offs |
| 2.5 | Multi-platform atomics — `supported_platforms` gating, path-separator gotchas, IART host-platform detection |
| 2.6 | MITRE Adversary Emulation Library — full-actor plans, FIN6 worked walk, atomic-by-atomic vs Caldera-chained execution |
| 2.7 | Safety harness — dry-run, permission audit, four-point blast-radius check, snapshot-and-revert mitigation |
| 2.8 | Capstone quiz — `-PathToAtomicsFolder` + cleanup-failure prediction |

#### Curriculum status

- **L1**: 8/8 ✅
- **L2**: 8/8 ✅
- **L3**: **2/8** authored at proper depth (M1 Purple-team flow, M2 ART deep-dive). M3-M8 are next ships.

#### Verifying the feature

```bash
docker compose pull ion seeder
docker compose up -d
docker exec ion python /app/seed_all.py --force
```

After re-seed:
1. `/courses` → *Adversary Emulation Basics* → module count shows **2 modules, 16 lessons**.
2. Open Module 2 — *Atomic Red Team library deep-dive*. 8 lessons; the final is a 2-question capstone.
3. Lesson 2.6 (Adversary Emulation Library) — the FIN6 12-phase walkthrough should be present.

---

## v0.12.7 (2026-04-29) — curriculum

### L3 Module 1 — Purple-team flow expansion (2 lessons → 8 lessons, BTL1/SANS depth)

L3 was a v0.11.2 stub: 1 module / 2 lessons / 4 questions. v0.12.7 expands Module 1 to the L1/L2 module bar — 8 lessons, 9 questions, ~17k words. The existing Lesson 1 (Why purple teaming beats annual pentests) and the Lesson 2 quiz are preserved; six new reading lessons are inserted between them; the quiz becomes Lesson 8 with one additional question.

#### What's authored

| Lesson | Topic |
|---|---|
| 1.1 | **Why purple teaming beats annual pentests** (existing — preserved) |
| 1.2 | **Picking a TTP**: threat profiles, ATT&CK Navigator overlays, sector-specific TTPs, the priority decision rule |
| 1.3 | **Authorisation, scoping, and pre-briefing**: written-auth chain, four scoping constraints, exercise-notice format, legal exposure |
| 1.4 | **Atomic Red Team**: installation, prereq → test → cleanup phases, picking the right test number, Linux atomics, mandatory clean-up |
| 1.5 | **MITRE Caldera**: agent-based emulation, when chained / multi-host / long-running exercises need it, agent-removal-after rule |
| 1.6 | **Telemetry verification**: 30-minute wait, the four-tier pivot path in order, sub-channel gap classification, latency + fidelity scoring |
| 1.7 | **Scoring + scorecards**: 8-field scorecard row, empirical detection coverage, q-over-q trending, TuningProposal acceptance criteria |
| 1.8 | **Capstone quiz** (existing 4 questions + 1 new — TuningProposal field selection) |

#### Curriculum status

- **L1**: 8/8 ✅
- **L2**: 8/8 ✅
- **L3**: **1/8** authored at proper depth (Module 1 — Purple-team flow). M2-M8 begin in v0.12.8.

L3 module backlog (per the v0.11.2 placeholder):
- M2 — Atomic Red Team library deep-dive
- M3 — MITRE Caldera operations
- M4 — Telemetry quality assessment
- M5 — Detection-engineering loops (TuningProposal lifecycle)
- M6 — Multi-host chain emulation
- M7 — Out-of-hours / off-shift validation
- M8 — Capstone — full purple-team exercise across the kill chain

#### Verifying the feature

```bash
docker compose pull ion seeder
docker compose up -d
docker exec ion python /app/seed_all.py --force
```

After re-seed:
1. `/courses` → *Adversary Emulation Basics* → module count shows **1 module, 8 lessons**.
2. Open Module 1 — *Purple-team flow*. 8 lessons; the final is a 5-question capstone.
3. Lesson 1.2 (TTP-pick) — the worked decision-rule example with T1486 priority 5.0 should be present.
4. Lesson 1.7 (scoring) — the worked Q1 scorecard with 75% empirical coverage should be present.

#### Upgrade

```bash
docker compose pull ion seeder
docker compose up -d
```

---

## v0.12.6 (2026-04-29) — curriculum

### L2 Module 8 — Hunt-to-Detection Capstone (L2 COMPLETE)

L2 closes 7/8 → **8/8 ✅**. The capstone walks the *hunt finding → detection candidate → production rule* pipeline through five conversion gates, with a worked end-to-end example converting one of M7's six APT-chain candidates into a production Kibana Security ML rule.

#### What's authored

8 lessons (7 reading + 1 capstone-quiz), 8 questions, ~17k words at BTL1 / SANS GCTH depth.

| Lesson | Topic |
|---|---|
| 8.1 | Hunt finding → candidate → rule vocabulary; the five-gate pipeline |
| 8.2 | **G1 — Data quality**: ECS schema stability across 8.x, retention check, parser-health monitoring, schema-debt backlog |
| 8.3 | **G2 — FP rate**: 30d backtest, predicted weekly FP rate, sample classification (TP / FP / Indeterminate), the tuning-during-backtest anti-pattern |
| 8.4 | **G3 — ATT&CK mapping**: technique → sub-technique → tactic decision tree, common mis-mappings, version pinning |
| 8.5 | **G4 — Kill-chain step + routing**: 14-tactic frame, response-leverage rule, playbook id vs runbook URL |
| 8.6 | **G5 — Metadata**: severity matrix, threat block YAML, owner (team/role), lifecycle plan with KPIs and deprecation criteria |
| 8.7 | Worked end-to-end conversion of M7's ML-population candidate through all five gates |
| 8.8 | L2 capstone — four-question quiz |

ATT&CK mapping pinned at v15.0 throughout; rule-type variations (threshold / EQL / threat_match / machine_learning) covered in §8.7.

#### Curriculum status

- **L1**: 8/8 ✅ (since v0.11.11)
- **L2**: **8/8 ✅** (this ship)
- **L3**: 1/8 stub — replacement starts v0.12.7 (next ship)

#### Verifying the feature

```bash
docker compose pull ion seeder
docker compose up -d
docker exec ion python /app/seed_all.py --force
```

After re-seed:
1. `/courses` → *Threat Hunting with KQL* → module count shows **8 modules**.
2. Open Module 8 — *Hunt-to-Detection Capstone*. 8 lessons; the final is a 4-question capstone.
3. Lesson 8.3 (G2 FP rate) covers the canonical backtest math; the L8.8 capstone Q2 tests the same arithmetic.

#### Upgrade

```bash
docker compose pull ion seeder
docker compose up -d
```

---

## v0.12.5 (2026-04-29) — curriculum

### L2 Module 7 — Anomaly Hunts (statistical methods)

L2 advances 6/8 → 7/8. Module 7 covers the PEAK Model-Assisted arm: stack counting & rarity, beacon detection by interval coefficient of variation, time-series spikes against rolling baselines, Shannon entropy on DNS labels for DGA, per-entity z-score baselining (so noisy users don't drown quiet ones), and Elastic ML `anomaly_detector` jobs for problems that exceed a single query. Closes with a worked APT-campaign capstone where every chain step is invisible to behavioural rules but lights up across the M7 hunt suite.

#### What's authored

8 lessons (7 reading + 1 capstone-quiz), 8 questions, ~16k words at BTL1 / SANS GCTH depth.

| Lesson | Topic | Focus |
|---|---|---|
| 7.1 | Statistical-hunt frame | PEAK Model-Assisted, FP budgets, why fleet-wide thresholds fail |
| 7.2 | Stack counting & rarity | Cardinality-aware bottom-N, worked hunts on `process.command_line`, OAuth scopes, SP `appDisplayName` |
| 7.3 | Beacon detection by interval CV | CV thresholds (< 0.10 fixed, < 0.30 jittered), 50-sample floor, allowlist mandatories |
| 7.4 | Time-series spikes & rolling baselines | μ + 3σ formula, hour-of-day filters, distributional pitfalls (zero-inflated, non-Normal) |
| 7.5 | Shannon entropy & DGA | Four-signal combo: entropy + length + cheap-TLD + per-source uniqueness |
| 7.6 | Per-entity baselining (z-score) | The fleet-wide-threshold trap, z = (x − μ_e) / σ_e, absolute-count floor pairing |
| 7.7 | Elastic ML `anomaly_detector` jobs | Single-metric / multi-metric / population / rare templates, bucket-span tuning |
| 7.8 | Capstone | A chained APT campaign caught only across the M7 suite; hand-off to M8 detection-engineering |

ATT&CK mapped through the lessons: T1098.001 / .003 / .005, T1071.001 / .004, T1568.002, T1556.006, T1110.003, T1530, T1571, T1027.

Cross-links to prior modules: M3 (Windows event mapping), M4 (Kerberoasting baselined per service account), M5 (NXDOMAIN + DGA upstream + downstream), M6 (`MailItemsAccessed` + AiTM cluster), M1 (PEAK methodology — Model-Assisted arm).

#### Curriculum status

- **L1**: 8/8 ✅
- **L2**: 7/8 (M8 Hunt-to-Detection Capstone is next, v0.12.6)
- **L3**: 1/8 stub — replacement starts v0.12.7

#### Verifying the feature

```bash
docker compose pull ion seeder
docker compose up -d
# Force a re-seed of courses since the catalogue grew
docker compose exec ion python /app/seed_all.py --force
```

After the seeder runs:
1. Open `/courses` and find *Threat Hunting with KQL*. The module count should now show **7 modules**.
2. Open Module 7 — *Anomaly Hunts*. 8 lessons; the final lesson is a 4-question capstone quiz.
3. Read Lesson 7.3 (Beacon detection); the CV formula and 50-sample-floor concept should both appear.
4. The capstone quiz Q1 should test population-template ML jobs against per-entity z-score and time-series spikes.

#### Upgrade

```bash
docker compose pull ion seeder
docker compose up -d
```

The course seeder is idempotent and re-runs on every boot; existing user enrolments and progress are preserved.

---

## v0.12.4 (2026-04-29) — feature

### CyAB Onboarding Studio — operator authoring polish (in-page add forms + custom sub-profiles)

The Studio gains four authoring affordances that let operators extend the catalogue without touching code. Every save flips `is_custom=true` so the seeder leaves it alone on subsequent boots.

#### What's new

- **+ Add intake question** button on the Detailed Intake tab. Inline form: question text, answer type (yesno / single / multi), custom options (`value=Label` per line for single/multi). Saves via PATCH to the sub-profile catalogue.
- **+ Add detection use case** button on the Detection library tab. Inline form: title, summary, description, risk, MITRE IDs (CSV), logic language (ES|QL / KQL / EQL / SPL), logic snippet, optional SOAR playbook id. Appends to `detection_use_cases`.
- **+ Add audit use case** button on the Audit & compliance tab. Same as detection, with an extra "Compliance frames" CSV field.
- **+ New sub-profile** button at the bottom of the sub-profile rail. Inline form: id (a-z / 0-9 / underscore), label, pillar (dropdown of the 6), icon (Lucide name), description. POSTs `/api/cyab/studio/subprofiles`; on success the rail refreshes and the new sub-profile is auto-selected.

#### New API

- `POST /api/cyab/studio/subprofiles` — create an operator-authored sub-profile under a pillar. Validates `id` shape (`[a-z0-9_]{2,64}`), pillar existence, and id uniqueness. Catalogue starts with empty arrays; operators populate via the existing PATCH route.

#### Verifying the feature

1. `docker compose pull ion && docker compose up -d`
2. Open `/cyab/studio`. In the rail, click **+ New sub-profile**. Pick a pillar (Identity), give it an id (`my_test`), label, save. The new sub-profile appears in the rail with the `●` custom marker.
3. With the new sub-profile selected, switch to **Detection library**. Click **+ Add detection use case**. Fill the form. Save. The new use case appears in the grid.
4. Refresh the page; URL state restores; new content is still there.
5. Reboot the container with `docker compose up -d --force-recreate ion` — the seeder log line should report `subprofiles_skipped_custom: 1` (or higher) — your edits survived.

No DB migration. Pure UI + one new POST route.

---

## v0.12.3 (2026-04-29) — feature

### CyAB Onboarding Studio — wire-up: per-data-source use-case status + coverage rollup on system detail

v0.12.2 filled the catalogue. v0.12.3 wires it up: operators can now mark each detection / audit use case as `shipped` / `partial` / `gap` / `n/a` against the data source, and a coverage rollup appears on the `/cyab` system detail page summarising readiness per sub-profile.

#### What changed

- **`cyab_data_sources.use_case_status`** is reframed from free-text into a JSON map keyed by use-case id with the four allowed values. Pre-v0.12.3 free-text values are tolerated on read (returned as `legacy_text`) and discarded on first write — no migration needed.
- **3 new API routes** under `/api/cyab/studio/`:
  - `GET /systems/{sys_id}/data-sources?subprofile_id=…` — list data sources for a system, optionally filtered by sub-profile.
  - `GET /data-sources/{ds_id}/use-case-status` — parsed status map.
  - `POST /data-sources/{ds_id}/use-case-status` — merge status updates (send `null` to clear; unknown values rejected with 400).
- **Studio: status pill on every use-case card.** Click cycles `gap → partial → shipped → n/a → gap`. A coverage banner above the use-case grid shows shipped/partial/total + the resolved data source name. The Studio resolves which data source to write against by `(system_id, subprofile_id)`. If multiple data sources match, status writes to the first (alphabetical by name). If none match, the banner instructs the operator to assign a sub-profile in `/cyab` first.
- **`/cyab` system detail: new "Onboarding Studio coverage" card** rendered alongside the existing alert rollup. Shows per-sub-profile bars for Intake / Detection / Audit, with a deep link to the Studio (`/cyab/studio?system=<id>`).

#### Verifying the feature

1. `docker compose pull ion && docker compose up -d`
2. Open `/cyab` and pick the SmokeTest System (or any system with a data source whose `subprofile_id` is set). The detail panel should now show two rollups (alerts + coverage).
3. Open `/cyab/studio?system=<id>`, navigate to a sub-profile whose data source matches, switch to **Detection library**. The banner above the grid should report `Coverage: 0 shipped / 0 partial / N total · 0%`. Click any use-case status pill — it cycles colour and `status saved · HH:MM:SS` appears at the bottom of the intake area.
4. Refresh — status persists. Reopen `/cyab` → system detail; the coverage card reflects the new shipped count.

No data-model migration; no new tables. Pure column-semantic + UI wire-up.

---

## v0.12.2 (2026-04-29) — feature

### CyAB Onboarding Studio — catalogue fill (12 skeletons → full depth)

v0.12.0 shipped 3 sub-profiles (Active Directory, Windows endpoint, Next-Gen Firewall) at full depth and 12 as skeletons. v0.12.2 fills all 12 skeletons to the same bar — intake banks, detection use cases with ES|QL logic + MITRE IDs + SOAR ids, and audit use cases with NIST / CIS / IEC compliance frames.

#### Catalogue totals (15 sub-profiles)

| Pillar | Sub-profile | Intake | Detection | Audit |
|--------|-------------|:--:|:--:|:--:|
| Identity | Active Directory | 7 | 5 | 4 |
| Identity | Entra ID / Okta | 6 | 5 | 3 |
| Identity | VPN / Remote access | 4 | 4 | 2 |
| Endpoint | Windows endpoint | 5 | 6 | 4 |
| Endpoint | Linux / Unix | 5 | 5 | 3 |
| Endpoint | macOS endpoint | 4 | 4 | 2 |
| Network | Next-Gen Firewall | 3 | 4 | 2 |
| Network | DNS | 3 | 4 | 2 |
| Network | Web proxy | 4 | 3 | 2 |
| Cloud | Cloud audit (AWS/Azure/GCP) | 5 | 5 | 4 |
| Cloud | Email platform (M365/Workspace) | 5 | 4 | 3 |
| Cloud | SaaS app (generic) | 4 | 3 | 2 |
| Data | Database | 4 | 4 | 3 |
| Data | Web application | 5 | 4 | 2 |
| OT | ICS / SCADA | 4 | 3 | 2 |
| **Total** | **15** | **68** | **63** | **41** |

#### What changed

- `services/cyab_subprofile_catalogue.py` — the 12 stubs are replaced with fully-authored module-level dicts (ENTRA_OKTA, VPN_REMOTE, LINUX_ENDPOINT, MACOS_ENDPOINT, DNS_PROFILE, WEB_PROXY, CLOUD_AUDIT, EMAIL_PLATFORM, SAAS_GENERIC, DATABASE, WEB_APP, ICS_SCADA). The `_stub` helper and `SKELETONS` list are gone.
- `CATALOGUE_VERSION` 1 → 2.
- The seeder's existing idempotency contract is preserved: `is_custom=true` rows still skip the update, so any operator-edited sub-profile sticks.

#### Threat / audit lens

Each sub-profile maintains a similar shape: intake questions are technical-config-specific (e.g., "Is `auditd` configured for syscall tracking?"), detection use cases carry an ES|QL snippet keyed to the sub-profile's ECS anchor, and audit use cases carry compliance-frame mapping (NIST 800-53, CIS benchmarks, PCI DSS, OWASP ASVS, IEC 62443 for OT).

#### Verifying the feature

```bash
docker compose pull ion seeder
docker compose up -d
```

After boot:

1. Open `/cyab/studio` → pick **Cloud & SaaS** → **Email platform (M365 / Workspace)**. Intake should now show 5 questions; Detection library should show 4 use cases (mailbox forward rule, OAuth grant, BEC pattern, bulk OWA download); Audit tab should show 3 (external delegation, audit disabled, transport rule).
2. Sub-profile rail badges (`Nd · Ma`) should show non-zero counts for every entry.
3. `psql -c "SELECT id, label FROM cyab_subprofiles ORDER BY pillar_id, label"` — 15 rows.

No DB migration; no data-model change. Catalogue content only.

---

## v0.12.1 (2026-04-29) — feature

### CyAB Onboarding Studio — answer-and-proceed (intake form + system selector + auto-save)

v0.12.0 shipped the Studio chrome but the Detailed Intake tab was display-only — questions rendered as static cards with no way to actually answer them. v0.12.1 closes that gap.

#### What's new

- **System selector at the top of the page.** A dropdown grouped by department lists every CyAB system; picking one wires the entire page to that system. URL state gains `?system=<id>` so deep links carry the scope.
- **Interactive intake form.** Each question now renders as pill-style answer controls based on its `answer_type`:
  - `yesno` → 4 pills (Yes / Partial / No / Don't know)
  - `single` → one pill per option, single-select
  - `multi` → toggle pills, multi-select
- **Per-question status badge** (`● answered` vs `○ open`) and a **progress bar** (`X of Y answered`) at the top of the tab.
- **Debounced auto-save** (600 ms) on every click — answers persist into a marker-tagged `CyabSystemAssessment` row (`notes='STUDIO_AUTOSAVE'`). The legacy 6-step wizard's immutable history rows are untouched.
- **Save & continue → Detection library** button at the bottom of the intake tab — saves and switches to the Detection tab in one action.
- **Footer Onboarding Pack button** is now wired to the selected system; the manual ID input is gone. The button is disabled until a system is picked.

#### Persistence model

Answers go into one row per system, identified by `notes='STUDIO_AUTOSAVE'`. POSTs merge by key (sending `null` clears a key). The GET endpoint merges the autosave row over the most-recent legacy wizard row, so the operator sees a single coherent answer set even if a system was first onboarded via the wizard and is now being deepened in the Studio. Crucially the legacy row is **never mutated** — its immutability and version history are preserved.

#### New API

- `GET /api/cyab/studio/systems` — lightweight system list for the dropdown
- `GET /api/cyab/studio/systems/{sys_id}/answers` — merged answer blob (legacy ⊕ studio autosave)
- `POST /api/cyab/studio/systems/{sys_id}/answers` — patch answers (send `null` to clear)

#### Verifying the feature

1. `docker compose pull ion && docker compose up -d`
2. Open `/cyab/studio`. The system dropdown should populate with every CyAB system grouped by department.
3. Pick a system → pick **Identity & Access** → **Active Directory** → **Detailed intake**. Each of the 7 questions should show pill answer controls. Click answers — auto-save status should appear at the bottom (`saving…` → `saved · HH:MM:SS`).
4. Refresh the page; URL carries `?system=<id>&pillar=identity&sub=active_directory&tab=intake`. Answers should reload from the server.
5. Click **Save & continue → Detection library** — saves and switches tabs.
6. Click **Export Onboarding Pack** in the footer — should download a PDF that includes the answers under "Per-sub-profile readiness".

#### Upgrade

```bash
docker compose pull ion
docker compose up -d
```

No data-model migration in this ship — answers go into the existing `cyab_system_assessments.responses_json` column. v0.12.0's tables and columns are unchanged.

---

## v0.12.0 (2026-04-29) — feature

### CyAB Onboarding Studio — sub-profile-driven onboarding intake, detection library, audit catalogue

The CyAB feature gains a second-generation onboarding workflow that complements the existing strategic 6-step wizard with a **technical, sub-profile-driven layer**. Operators now pick a top-level **pillar** (Identity / Endpoint / Network / Cloud / Data / OT) → a **sub-profile** (Active Directory, Windows endpoint, Next-Gen Firewall, etc.) → and work three tabs of curated content: **Detailed intake** (sub-profile-specific config questions), **Detection library** (use cases with ECS|QL logic + MITRE mapping + SOAR + TIDE links), **Audit & compliance** (audit use cases keyed to NIST / CIS frames). A bottom drawer surfaces the full use-case anatomy. A footer action exports a bundled **Onboarding Pack** PDF for sign-off.

#### What's new

- **New page:** `/cyab/studio` — separate from the existing `/cyab` dashboard. The CyAB header now carries an "Onboarding Studio →" link.
- **New tables:** `cyab_pillars` (6 rows) + `cyab_subprofiles` (15 rows). Both are code-seeded from `services/cyab_subprofile_catalogue.py` on first boot and respect an `is_custom` flag on subsequent boots so operator edits survive seeder runs.
- **New columns:**
  - `cyab_data_sources.subprofile_id` — FK to `cyab_subprofiles.id`. Backfilled on first boot from the legacy `data_source_type` string via the catalogue's migration table. Three legacy types are ambiguous (`windows_security`, `edr`, unrecognised) and stay NULL until an operator confirms.
  - `cyab_systems.containment_authority` — TEXT, captured on the Onboarding Pack approval flow.
- **New router:** `/api/cyab/studio/*` — 9 routes (list pillars, list sub-profiles in a pillar, get full sub-profile catalogue, PATCH operator overlay, get one use case, generate TIDE rule stub, per-system coverage rollup, render Onboarding Pack PDF, sign Onboarding Pack).
- **Catalogue:** 3 sub-profiles authored to full depth (Active Directory, Windows endpoint, Next-Gen Firewall — full intake banks, 4–6 detection use cases each with ES|QL snippets + MITRE IDs, 2–4 audit use cases each with compliance frame mapping). 11 sub-profiles ship as skeletons (label + ECS anchors + expected feeds, empty content arrays) — v0.12.1 will fill them.
- **TIDE coupling — both modes:** the use-case drawer links to existing TIDE rules when `tide_rule_ids[]` is non-empty, AND offers a "Generate TIDE rule stub" action when it's empty. The stub-generate POST creates a TIDE rule from the catalogue's logic snippet + MITRE IDs + risk + tags, then writes the new rule id back into the use case (flips `is_custom=true`).
- **Onboarding Pack PDF:** weasyprint-rendered, modeled on the existing `/cyab/tide/de/readiness-pdf` route. Sections: cover (system + governance), strategic context (latest org assessment), system scope (data sources), per-sub-profile readiness (intake answers + detection coverage + audit coverage), containment authority, sign-off block. POST `/sign` persists `sign_dept_name`, `sign_soc_name`, and the new `containment_authority` column; if both signatures are present, the system status flips to `ACTIVE`.
- **Schema version bump:** `cyab_assessment_questions.SCHEMA_VERSION` 1 → 2 — sub-profile-namespaced keys (`sub_id_ad_*`, `sub_ep_win_*`, `sub_net_fw_*`) extend the existing question schema; old v1 submissions remain valid.

#### Design background

The redesign is documented in `_research_cyab_onboarding_studio.md` at the repo root — Gemini gold-standard frame (NIST SP 800-61, SANS PICERL, MITRE 11 Strategies), React mockup translation, ION's existing CYAB surface inventory (5 tables + 56 routes preserved), and the 4-ship phased delivery plan. v0.12.0 is **ship 1: plumbing**. Ship 2 is catalogue fill, ship 3 is per-data-source `use_case_status` JSON wire-up, ship 4 is operator authoring polish.

#### Verifying the feature

1. `docker compose pull ion seeder && docker compose up -d`
2. Open `/cyab/studio`. The pillar pills row should populate (Identity / Endpoints / Network / Cloud / Data / OT). Pick **Identity & Access** → **Active Directory** → **Detection library** tab. You should see 5 detection use cases. Click **Kerberoasting**; the bottom drawer should render the ES|QL snippet + MITRE T1558.003 chip.
3. From `/cyab` (the dashboard), the new **Onboarding Studio →** link should be visible in the header.
4. From `/cyab/studio`, type a system ID into the footer input + click **Export Onboarding Pack** — should download a PDF.
5. `psql -c "SELECT id, label, priority FROM cyab_pillars ORDER BY priority"` — six rows.
6. `psql -c "SELECT id, pillar_id, is_custom FROM cyab_subprofiles ORDER BY pillar_id, label"` — 15 rows, all `is_custom=false`.

#### Upgrade

```bash
docker compose pull ion seeder
docker compose up -d
```

The seeder runs idempotently and respects operator edits; safe to run on every boot. Existing CyAB systems and data sources are untouched apart from the `subprofile_id` backfill.

---

## v0.11.21 (2026-04-28) — feature

### System Analytics — logs ingested per system, alongside alerts and TIDE coverage

The System Analytics tab on `/analytics` now shows **logs ingested per system** in addition to the existing per-system alert volume and TIDE rule-coverage. Operators wanted visibility into the *raw log volume* feeding each system's data streams — previously the page only counted what fired into `.alerts-security.alerts-*`, missing entirely the upstream picture.

#### What changed

- **`elasticsearch_service.py`** — `get_system_analytics()` now *always* fetches per-namespace log volumes from the `logs-*` index pattern via the existing `_discover_systems_from_logs()` helper (previously this fired only as a one-namespace fallback). Each system entry is enriched with `logs_ingested`, `logs_timeline`, `logs_datasets`, `logs_categories`, `logs_unique_hosts`, `logs_unique_users`. Namespaces that exist in `logs-*` but produced no alerts in the window now also surface as zero-alert system entries.
- **`analytics_api.py`** — `/api/analytics/system-overview` exposes a top-level `total_logs_ingested` (sum across systems) so the UI can render a fleet-wide stat.
- **`analytics.html`** — the System Analytics top stats bar now has 6 cards (was 5): adds **Logs Ingested** between Total Alerts and Systems. Each per-system card surfaces a "📜 *N* logs" entry alongside hosts and users.

#### Data sources

The log query targets the Elastic Agent default index pattern `logs-*` and aggregates by `data_stream.namespace`. The same index pattern the existing one-namespace-fallback used since v0.11.x — no new env var required for typical Elastic Agent deployments. For non-default deployments (Beats / Logstash with custom index naming), the pattern lives in `_discover_systems_from_logs` and can be tuned in a follow-up if needed.

#### Verifying the feature

After upgrade, open `/analytics` → *System Analytics* tab. The top stats bar should show six cards including **Logs Ingested**; each per-system card should show the log-volume count alongside the existing alert count.

#### Upgrade

```bash
docker compose pull ion seeder
docker compose up -d
```

No data-model or course content changes in this ship.

---

## v0.11.20 (2026-04-28) — bug fix

### Daily Standup — duplicate `const overallLight` SyntaxError + downstream `runChecks` ReferenceError

**Bug.** Two console errors on the `/standup` page:

1. `Uncaught SyntaxError: Identifier 'overallLight' has already been declared` (rendered line 1076).
2. `Uncaught ReferenceError: runChecks is not defined` at `HTMLButtonElement.onclick` (rendered line 554).

**Root cause.** `src/ion/web/templates/daily_standup.html` declared `const overallLight = document.getElementById(prefix + '-overall-light')` *twice* inside `renderLogHealth(prefix, data)` — once at line 440 (covering the early error / not-configured / empty-hosts branches) and again at line 486 (the happy-path RAG-status branch). Re-declaring the same `const` in the same function-level scope is a SyntaxError in strict-mode ES6+, which aborts the script-block parse. Every function defined later in the same `<script>` — including `runChecks()` (defined at line 691) — is therefore never assigned to the global scope, so the *Run Checks* button's inline `onclick="runChecks()"` handler at the top of the page throws `ReferenceError`. Two errors, one root cause.

**Fix.** Drop the redundant `const` redeclaration at line 486; the earlier line-440 binding is already in scope across the whole function. The two later branches at lines 487–491 simply assign through the existing reference.

```diff
   // Determine overall RAG status for the section header light
   const hasCritical = hosts.some(h => h.status === 'critical');
   const hasWarning = hosts.some(h => h.status === 'warning');
-  const overallLight = document.getElementById(prefix + '-overall-light');
   if (overallLight) {
     overallLight.className = 'ds-rag-light ' + (hasCritical ? 'ds-rag-red' : hasWarning ? 'ds-rag-amber' : 'ds-rag-green');
   }
```

Once the SyntaxError clears, `runChecks()` becomes defined as the script parses to completion, and the button's `onclick` works.

#### Verifying the fix

After upgrade, open `/standup` in the browser. Console should be clean — no `overallLight` SyntaxError, no `runChecks` ReferenceError. Click *Run Checks* and the standup widgets should refresh.

#### Upgrade

```bash
docker compose pull ion seeder
docker compose up -d
```

No course content or data-model changes in this ship.

---

## v0.11.19 (2026-04-28) — bug fix

### Kibana case assignee now propagates from the auto-assigned creator

**Bug.** When a user created a case in ION without explicitly setting an assignee, the case was auto-assigned to the *creator* (`current_user.id`) on the ION side — but the corresponding Kibana case was created with **no assignee**. Subsequent assignee changes via the case-update endpoint synced correctly; only the *initial create* path missed the auto-assigned value.

**Root cause.** `src/ion/web/api.py` line 4319 sets `new_case.assigned_to_id = data.assigned_to_id if data.assigned_to_id else current_user.id` — so the persisted ION case carries an assignee even when the request body doesn't supply one. The downstream Kibana-sync block then resolved the assignee UID by reading **`data.assigned_to_id`** (the request body), not **`new_case.assigned_to_id`** (the persisted value). When the request body's `assigned_to_id` was empty, `create_assignee_uid` stayed `None` and the Kibana payload omitted the `assignees` array entirely.

**Fix.** Read the assignee from `new_case.assigned_to_id` (the persisted value) instead of `data.assigned_to_id`. The Kibana case is now created with the same assignee the ION case shows — including the auto-assigned creator on cases that didn't specify one.

```diff
-    if data.assigned_to_id:
-        assignee_user = session.query(User).filter_by(id=data.assigned_to_id).first()
+    if new_case.assigned_to_id:
+        assignee_user = session.query(User).filter_by(id=new_case.assigned_to_id).first()
```

The case-update path already reads from the request body correctly (line 5269) and passes the assignee through to `_background_kibana_case_sync` — that path was unaffected.

The auto-promote path (`case_grouper_service.py:441`) creates cases without an ION-side assignee, so its omission of `assignees=` from the Kibana create payload remains correct (no assignee to push) and was not part of this fix.

#### Verifying the fix

After upgrade, create a fresh case in the ION UI without specifying an assignee. The ION case should auto-assign to you (the creator), and the corresponding Kibana case should now show you as the assignee in Kibana's case UI. Assignee changes via the ION update path were already syncing correctly and continue to do so.

#### Upgrade

```bash
docker compose pull ion seeder
docker compose up -d
```

No course content changes in this ship.

---

## v0.11.18 (2026-04-28)

### L2 Module 6 — Email & collaboration: Initial Access

Sixth L2 ship. **L2 Module 6 — Email & collaboration — Initial Access** authored at BTL1+/SANS depth. ~9,000 words, 8 lessons (4 reading + 4 quiz), 16 quiz questions. Covers the Microsoft 365 Unified Audit Log surface end to end, with the AiTM-to-BEC-to-data-exfil four-step capstone.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 6.1 | Email + collaboration data plane + ECS email field reference | reading | — |
| 6.2 | Email data plane — quiz | quiz | 4 |
| 6.3 | T1566 Phishing — sub-techniques and email-side hunts | reading | — |
| 6.4 | T1566 phishing — quiz | quiz | 4 |
| 6.5 | Post-click and AiTM downstream + collaboration-platform hunts | reading | — |
| 6.6 | Post-click & collaboration — quiz | quiz | 4 |
| 6.7 | Statistical-anomaly hunts on email + collaboration and worked end-to-end capstone | reading | — |
| 6.8 | Email statistical hunts & capstone — quiz | quiz | 4 |

#### Topics covered

- **Email + collaboration data plane** — Microsoft 365 Unified Audit Log workloads (Exchange / SharePoint / OneDrive / Teams / Entra) via `o365.audit.Workload`; the operation-name reference (`Send`, `MailItemsAccessed`, `New-InboxRule` / `Set-InboxRule`, `Set-Mailbox`, `Add-MailboxPermission`, `FileDownloaded`, `SharingSet`, `MessageSent`, `SearchQueryPerformed`, `Set domain authentication`, `Add member to role`, `Add service principal credentials`); ECS `email.*` field reference (8.6+); third-party gateway integrations cite-only (Mimecast / Proofpoint TAP / IronPort / Barracuda / Abnormal); cross-source pivot `signinlogs ↔ auditlogs ↔ o365.audit` keyed on UPN
- **T1566 phishing** — sub-techniques .001 attachment / .002 link / .003 service / .004 voice; T1027.006 **HTML smuggling** email-side fingerprint with novel-hash + 100KB+ HTML body filter; **AiTM-kit per-recipient-token URLs** (`?id=USER-XXXX`, `?rid=*-*`) on cloud-fronted domains as the AiTM email-side fingerprint; **email authentication** (SPF / DKIM / DMARC / ARC / SRS / Microsoft compauth) — DMARC fail that landed-in-inbox detection, **Reply-To swap** as the BEC fingerprint that passes auth on `From`; **lookalike-domain detection** via brand-string-but-not-on-whitelist filter; **display-name vs domain mismatch**; **legacy-auth post-AiTM** detection
- **Post-click + AiTM downstream** — recap of M4 `session_id` reuse joined to O365 audit; **T1098 account manipulation** (.001 `Add service principal credentials` OAuth backdoor, .003 `Add member to role` for Global/Privileged/Application Administrator, .005 `Add device` compliant-CA bypass); **T1556.006 `Set federation settings on domain`** Golden-SAML preparation as page-IR signal; **T1114 email collection** — .003 inbox forwarding rules with finance keywords (`MoveToFolder` / `MarkAsRead` / `Forward` paired with `*invoice*` / `*wire*` / `*remit*`), **.002 `MailItemsAccessed` clusters** (E5/A5/G5-gated with explicit licensing call-out); **T1213 SharePoint / OneDrive** mass-pull via `FileDownloaded` aggregation, `SharingSet` external-share signal, Teams `MessageSent` external-chat exfil, `SearchQueryPerformed` recon; **T1534 Internal Spear Phishing** auth-passing post-compromise mass-send pattern (>50 sends with ≤3 distinct subjects per hour)
- **Statistical hunts + capstone** — five canonical email-plane patterns (rare-sender / attachment-hash novelty / subject-burst / DMARC fail-rate spike / mailbox-rule create-rate); MailItemsAccessed cluster paired with M4 sign-in-risk for high-confidence T1114.002; **the worked PEAK capstone** — full *AiTM-to-BEC-to-data-exfil* chain via EQL `sequence by user.target.name with maxspan=2h` covering risky sign-in → device add → inbox rule → SharePoint download. Output: a Kibana Security EQL detection-rule body with severity *critical* + threat-metadata for TA0001 / TA0006 / TA0009 / TA0010 + the relevant T-numbers + runbook ref + owner team

6 Mermaid diagrams: data-plane taxonomy, T1566 sub-technique tree, AiTM-to-BEC kill chain, T1114/T1213 collection-platform fan-out, statistical-hunt decision tree, capstone hunt-to-detection pipeline.

L2 course now sits at **6 modules / 48 lessons / 96 questions**.

#### Upgrade

```bash
docker compose pull ion seeder
docker compose up -d
```

The seeder picks up the new course content automatically (v0.11.16+ in-image seed pipeline).

---

## v0.11.17 (2026-04-28)

### L2 Module 5 — Network telemetry: Command and Control + Exfiltration

Fifth L2 ship. **L2 Module 5 — Network telemetry — Command and Control + Exfiltration** authored from a research-agent dossier at BTL1+/SANS GCIH+/SANS FOR572-equivalent depth. ~9,000 words, 8 lessons (4 reading + 4 quiz), 16 quiz questions. Covers the Elastic network-data plane (Elastic Agent endpoint network events / Packetbeat / Zeek / Suricata) end to end, with the cross-source `network.community_id` join and the process-attribution capstone.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 5.1 | The network-event data plane in Elastic and the ECS network/DNS/TLS field reference | reading | — |
| 5.2 | Network data plane — quiz | quiz | 4 |
| 5.3 | Command and Control (TA0011) — top techniques and EQL+ES&#x7C;QL fingerprints | reading | — |
| 5.4 | Command and Control — quiz | quiz | 4 |
| 5.5 | DNS hunts and TLS hunts | reading | — |
| 5.6 | DNS & TLS hunts — quiz | quiz | 4 |
| 5.7 | Exfiltration (TA0010), statistical-anomaly hunts, and a worked end-to-end capstone | reading | — |
| 5.8 | Exfil & capstone — quiz | quiz | 4 |

#### Topics covered

- **Network data plane** — the four sources (Elastic Agent endpoint `logs-endpoint.events.network-*` with `process.entity_id` for process-attribution; Packetbeat / `logs-network_traffic.*` for L7 protocol decoding; Zeek `logs-zeek.connection-*` / `dns-*` / `ssl-*` / `http-*` / `notice-*` for connection states + per-protocol indices; Suricata `logs-suricata.eve-*` for IDS rules + EVE protocol events) with strengths/weaknesses; ECS `network.*` / `source.*` / `destination.*` / `dns.*` / `tls.*` / `url.*` / `http.*` field reference; **`network.community_id` as the cross-source join key**; Zeek `conn_state` codes (S0 / S1 / SF / REJ / RSTO / RSTR / OTH from L1 M4) for established-vs-failed-vs-rejected discrimination; multi-index `FROM logs-zeek.connection-*, logs-suricata.eve-*, logs-endpoint.events.network-*` cross-source pivots; worked broad-to-narrow KQL → EQL → ES&#x7C;QL on a beacon hunt
- **C2 TA0011** — T1071 application-layer protocol with sub-techniques .001 web (the dominant envelope) / .002 file transfer / .003 mail / .004 DNS C2 (TXT-record carrier vs benign DNS); **T1573.002 Encrypted Channel — TLS** as the near-universal C2 envelope; T1090 proxy with .001 internal / .002 external / .003 multi-hop (Tor / I2P) / .004 domain fronting; **T1568.002 DGA** with consonant-ratio + length entropy proxy in ES&#x7C;QL; **T1102 Web Service** SaaS dead-drops (`*.workers.dev` / Discord webhook / GitHub raw / Telegram Bot API / Pastebin / Slack hooks / Notion); T1572 protocol tunneling (DNS / ICMP / SSH); **T1219 Remote Access Software** (AnyDesk / ScreenConnect / TeamViewer / Atera / Splashtop / NetSupport / Action1 / TacticalRMM) with process+network co-occurrence; **beacon shape along four axes** (periodicity ± jitter, size symmetry small-out + larger-in, working-hours-agnostic, sparse hostname diversity) with full ES&#x7C;QL multi-axis hunt; **C2 domain-class tells** (NRD / DGA / typosquat / SaaS dead-drop / bulletproof TLDs `.top` / `.xyz` / `.icu` / `.click` / `.cn` / `.ru`); **JA3 / JA3S TLS-fingerprinting** basics with rare-fingerprint fleet hunt
- **DNS + TLS hunts** — DNS tunneling fingerprints (long subdomains > 80 chars, TXT-record query-volume bursts > 20/5min, NXDOMAIN bursts followed by A-record success, **DoH detection** of outbound TCP/443 to known DoH endpoints `1.1.1.1` / `8.8.8.8` / `dns.google` / `cloudflare-dns.com` / `dns.quad9.net` from non-admin hosts, rare-TLD detection); DNS exfil shape (T1048.003 + T1572) with `LENGTH(dns.question.name)` cumulative-bytes hunt; TLS hunts — rare JA3 / JA3S (`COUNT_DISTINCT(host.name) ≤ 3 AND COUNT() ≥ 5`), **self-signed cert detection** via subject-equals-issuer comparison, untrusted-root issuers exclusion list (`Let's Encrypt` / `DigiCert` / `GlobalSign` / `Sectigo` / `Microsoft` / `Amazon` / `Google` / `Cloudflare`), short-validity certs (`DATE_DIFF` between `not_before` and `not_after` < 30 days), **CN-vs-SNI mismatch** detection, TLS 1.0/1.1 downgrade detection (legacy + likely malicious in 2026); HTTP hunts — UA anomalies (`python-requests/2.x` / `curl/7.81` / `Go-http-client` / missing UA), unusual methods (`PROPFIND` / `MKCOL` / `LOCK` / `COPY` / `MOVE` WebDAV verbs from outbound traffic), suspicious-path discovery (`/.git/config` / `/.env` / `/phpinfo.php` / `/wp-admin/` cluster from one source). JA4 successor to JA3 noted (extension-order robustness)
- **Exfiltration TA0010 + statistical hunts + capstone** — T1041 exfil over C2 channel via byte-volume asymmetry (`SUM(source.bytes) / SUM(destination.bytes) > 5.0` per host-IP-hour); T1567 web-service exfil with the canonical drop-off domain list (`*.mega.nz` / `*.dropbox.com` / `*.transfer.sh` / `*.anonfiles.com` / `*.file.io` / `*.gofile.io` / `*.bashupload.com` / `*.0x0.st` / `*.catbox.moe` / `*.pixeldrain.com` / Discord CDN / OneDrive / Google Drive); T1567.003 code-repo exfil (GitHub / GitLab over SSH); T1048 alternative-protocol exfil with DNS-bytes hunt; T1029 scheduled transfer with `DATE_EXTRACT(\"HOUR_OF_DAY\")` 02:00–05:00 off-hours filter; **the four canonical statistical-anomaly hunt patterns** (beacon-shape, rare-destination by host, byte-volume outlier, UA / JA3 rarity); **the worked PEAK capstone — beaconing-anomaly hunt** end to end: Q1 broad ES&#x7C;QL aggregation per (host × destination × hour), Q2 narrow with `conn_count > 100 AND unique_dest == 1 AND active_hours > 12`, Q3 enrichment via `logs-zeek.dns-*` + `logs-zeek.ssl-*` for DNS resolution and JA3S, **Q4 process attribution via EQL `sequence by host.name, process.entity_id with maxspan=5m`** joining the network-side beacon to the host-side spawning process. Two **Kibana Security detection-rule bodies** as the deliverable — an ES&#x7C;QL threshold rule and an EQL `sequence` rule — both ready for TIDE submission with severity / runbook / threat-metadata

7 Mermaid diagrams across the module: data-plane taxonomy, TA0011 family tree, beacon-shape four-axis scorecard, DNS-tunnel fingerprint flow, TLS-cert lifecycle, exfil-channel decision tree, capstone hunt-to-detection pipeline.

L2 course now sits at **5 modules / 40 lessons / 80 questions**.

#### Upgrade

```bash
docker compose pull ion seeder
docker compose up -d
```

The seeder container (baked-in from v0.11.16) now picks up `seed_courses.py` automatically — no manual `curl ... | docker exec -i` required. To force a re-seed: `docker exec ion python /app/seed_all.py --force`.

---

## v0.11.16 (2026-04-28) — `seed_courses.py` baked into the image

### Operator fix — courses now seed automatically on deploy

`seed_courses.py` is now baked into the ION image and registered in `seed_all.py`'s `SEEDS` list. Pre-v0.11.16, course content lived only in the local-dev `seed_courses.py` file at the repo root — it was never copied into the image and never invoked by `seed_all.py`. Operators who pulled a new image on a deployed environment got the application code update but no course refresh, and had to manually `curl` the seed script from GitHub raw and pipe it into `docker exec -i ion python -`.

#### What changed

- **`Dockerfile`** — `seed_courses.py` added to the `COPY` block alongside the other production seed scripts. The file lands at `/app/seed_courses.py` inside the image.
- **`seed_all.py`** — `("Courses (L1/L2/L3)", "seed_courses.py")` appended to the `SEEDS` list (last entry, after Core Templates / KB / Playbooks / SOC Templates). The subprocess runner invokes it the same way as every other seeder; `seed_courses.py` uses direct DB access via SQLAlchemy (`ion.storage.database`) rather than the HTTP API like the others, but the runner doesn't care which path the script takes.

#### Operator workflow on deployed environments

After this ship, the standard upgrade flow is:

```bash
# On the deployed host:
sed -i 's/^ION_VERSION=.*/ION_VERSION=0.11.16/' .env
docker compose pull ion seeder
docker compose up -d
```

The `seeder` service runs after `ion` becomes healthy, executes `seed_all.py` end to end (including courses), writes the `.seeded` marker, and exits. On subsequent restarts, the marker prevents redundant seeding; pass `--force` to `seed_all.py` to re-seed.

To force a re-seed of an already-seeded volume (for instance after a course-content update on a *new* image tag with the same data volume):

```bash
# Option A — via seed_all.py --force (recommended)
docker exec ion python /app/seed_all.py --force

# Option B — via seed_courses.py only (when only courses changed)
docker exec ion python /app/seed_courses.py
```

`seed_courses.py` is itself idempotent — it removes `demo-*` courses first and re-seeds — so calling it directly is also a safe operation.

#### Why this is a structural fix

Pre-v0.11.16, every minor release that ships course content (v0.11.5 through v0.11.15) required operators to remember to `curl ... | docker exec -i ion python -` after pulling. That instruction was in the upgrade section of every CHANGELOG entry but easy to miss, and produced exactly the failure mode reported during v0.11.15 testing — pulled the new image, the new courses didn't appear, no obvious error.

After v0.11.16, the seed pipeline is uniform: every release that touches `seed_courses.py` ships its updates the same way every release that touches KB articles or playbooks ships its updates — via the `seeder` container, gated by the `.seeded` marker, with a documented `--force` path for re-seeding.

#### Note for offline-bundle users

The offline build script (`scripts/build-offline-package.sh`) bundles `seed_courses.py` indirectly via the image — no changes needed there. Air-gapped operators get the same automatic behaviour after `load.sh` + `docker compose up -d`.

#### Upgrade

```bash
docker compose pull ion seeder
docker compose up -d seeder    # forces seeder to run on the new image
```

Or simply `docker compose up -d` to start every service (including `seeder`) on the new tag.

---

## v0.11.15 (2026-04-28)

### L2 Module 4 — Identity & sign-in: Credential Access + Lateral Movement

Fourth L2 ship. **L2 Module 4 — Identity & sign-in — Credential Access + Lateral Movement** authored from a research-agent dossier at BTL1+/SANS depth. ~9,200 words, 8 lessons (4 reading + 4 quiz), 16 quiz questions. Covers the on-prem Windows Security log + Entra ID / Azure AD sign-in plane, with the cross-pivot pattern.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 4.1 | The identity-event data plane in Elastic and the auth-event ECS reference | reading | — |
| 4.2 | Identity data plane — quiz | quiz | 4 |
| 4.3 | Credential Access (TA0006) — top techniques and EQL fingerprints | reading | — |
| 4.4 | Credential Access — quiz | quiz | 4 |
| 4.5 | Lateral Movement (TA0008) — top techniques and their fingerprints | reading | — |
| 4.6 | Lateral Movement — quiz | quiz | 4 |
| 4.7 | Cloud-identity hunts (Entra/Azure AD), AiTM signals, and a worked end-to-end capstone | reading | — |
| 4.8 | Cloud identity & capstone — quiz | quiz | 4 |

#### Topics covered

- **Identity data plane** — on-prem Windows Security log canonical events (4624 / 4625 / 4634 / 4647 / 4672 / 4720 / 4732 / 4738 / 4768 / 4769 / 4776 / 4662 / 4778 / 4779) and **Windows logon types** (2 Interactive / 3 Network / 4 Batch / 5 Service / 7 Unlock / 8 NetworkCleartext / 9 NewCredentials / 10 RemoteInteractive / 11 CachedInteractive); ECS field reference (`user.name`, `user.target.name`, `winlog.event_data.LogonType` / `TargetUserName` / `IpAddress` / `LogonProcessName` / `AuthenticationPackageName` / `TicketEncryptionType` / `Properties`); Entra ID sign-in log fields (`azure.signinlogs.properties.user_principal_name`, `app_display_name`, `client_app_used`, `authentication_requirement`, `risk_level_during_sign_in`, **`risk_event_types_v2`** with the 12 documented values, `session_id`, `correlation_id`, `device_detail.*`, `location.*`); cross-pivot multi-index `FROM winlogbeat-*, logs-azure.signinlogs-*` pattern keyed on `user.name`
- **Credential Access TA0006** — T1003 OS dumping (.001 LSASS via Sysmon EID 10 GrantedAccess masks `0x1010`/`0x1410`/`0x1438`/`0x143a`/`0x1F0FFF`/`0x1FFFFF`, .002 SAM via `reg save HKLM\\SAM`, .003 NTDS via `ntdsutil ifm` / `vssadmin create shadow` on DC, **.006 DCSync via EID 4662 with the replication GUID `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` from non-DC source — page-IR signal**); T1110 Brute Force (.001 password guessing — many failures one user, .003 password spraying — many distinct users low per-user count, .004 credential stuffing — failures-then-success cluster); T1539 Steal Web Session Cookie downstream from M6 phishing; T1187 Forced Authentication (outbound 445 to non-RFC1918); T1558 Kerberos (.003 Kerberoasting via 4769 `TicketEncryptionType: 0x17` RC4 downgrade + high TGS volume, .004 AS-REP Roasting via 4768 `PreAuthType: 0`, .001 Golden / .002 Silver Tickets); T1621 MFA Request Generation push-bombing detection in Entra logs
- **Lateral Movement TA0008** — T1021 Remote Services (.001 RDP via 4624 LT10 + 4778/4779, .002 SMB via 4624 LT3 to ADMIN$/C$/IPC$, .003 DCOM via `mmc.exe` parent of script-host, .004 SSH password-auth, .005 VNC, .006 WinRM via 4624 with `LogonProcessName: \"WinRM\"`); T1570 Lateral Tool Transfer (`bitsadmin /transfer`, `certutil -urlcache -split -f`, `Invoke-WebRequest`, SMB copy to admin share); T1550 Use Alternate Authentication Material (.002 Pass-the-Hash via 4624 NTLM LT9 from non-DC, .003 Pass-the-Ticket); T1210 Exploitation of Remote Services (EternalBlue / ProxyShell / ZeroLogon / PrintNightmare); **multi-key EQL `sequence by host.name, user.name with maxspan` for lateral chains** distinguishing per-user pivots from incidental noise
- **Cloud identity + AiTM + capstone** — high-risk Entra sign-in aggregations; **legacy authentication detection** (`client_app_used IN (IMAP4, POP3, Authenticated SMTP, Other clients)` — bypasses MFA at protocol level); **the AiTM session-cookie reuse pattern** as EQL `sequence by user_principal_name, session_id with maxspan=15m` matching MFA `satisfied` followed by `previouslySatisfied`; ES|QL aggregation flagging same `(user, session_id)` with multiple `device_detail.device_id` or `device_detail.browser` in 30-min window; Entra audit-log signals — `New-InboxRule` / `Set-InboxRule` with finance keywords, `Add-MailboxPermission`, `Set-Mailbox -ForwardingSmtpAddress`, `Update application` / `Add service principal credentials` (T1098.001 OAuth backdoor), `Add member to role`; **federation tampering T1556.006** via `Set federation settings on domain` — page-IR signal paving Golden SAML T1606.002; **the worked PEAK capstone — Kerberoasting → Lateral RDP → DCSync chain** as a single EQL `sequence by host.name with maxspan=30m` covering all three steps with the explicit Kibana Security rule body + threat metadata (TA0006 / TA0008 / T1558.003 / T1021.001 / T1003.006)

6 Mermaid diagrams across the module: auth-event taxonomy, Kerberos protocol with hunt anchors, AiTM session-cookie reuse, Pass-the-Hash chain, lateral-movement matrix, Entra `risk_event_types_v2` decision tree.

L2 course now sits at **4 modules / 32 lessons / 64 questions**.

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.14 (2026-04-28)

### L2 Module 3 — Process & file events: Execution + Defense Evasion

Third L2 ship. **L2 Module 3 — Process & file events — Execution + Defense Evasion** authored from a research-agent dossier at BTL1+/SANS depth. ~9,000 words, 8 lessons (4 reading + 4 quiz), 16 quiz questions. First *concrete-hunt* module in L2 — applies the PEAK methodology of Module 1 and the KQL/EQL/ES|QL fluency of Module 2 to the **Execution (TA0002)** and **Defense Evasion (TA0005)** ATT&CK tactic families against Elastic indices.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 3.1 | The process-event data plane in Elastic and the ECS field reference for hunters | reading | — |
| 3.2 | Data plane & ECS — quiz | quiz | 4 |
| 3.3 | Execution (TA0002) — top techniques and their EQL+ES&#x7C;QL fingerprints | reading | — |
| 3.4 | Execution — quiz | quiz | 4 |
| 3.5 | Defense Evasion (TA0005) — top techniques and their fingerprints | reading | — |
| 3.6 | Defense Evasion — quiz | quiz | 4 |
| 3.7 | Statistical hunts in ES&#x7C;QL, cross-source pivots, and a worked end-to-end capstone | reading | — |
| 3.8 | Statistical hunts & capstone — quiz | quiz | 4 |

#### Topics covered

- **Process-event data plane** — three sources: Elastic Agent endpoint integration (`logs-endpoint.events.process-*`, `.file-*`, `.library-*`, `.registry-*`); Winlogbeat + Sysmon (`winlogbeat-*` with EID 1/2/3/7/8/10/11/13/22/25 mapped via `event.code`); native Windows Security log (4624/4688/4698/4720/7045/1102/104). The **EID 4688 command-line gap** (requires *Audit Process Creation* GPO + *Include command line* sub-policy). ECS field reference table for process / file / library / registry hunts. **`process.entity_id` as the host-stable join key** for chain reconstruction. Cross-source schema differences in a comparison table. Multi-index `FROM logs-endpoint.events.process-*, winlogbeat-*` pattern in ES&#x7C;QL with the `event.action` / `event.code` disjunction. Worked broad-to-narrow KQL → EQL → ES&#x7C;QL on the encoded-PowerShell-from-Office-parent hunt
- **Execution TA0002** — T1059 Command and Scripting Interpreter (.001 PowerShell, .003 cmd, .005 VBS, .007 JS) with the **suspicious-PowerShell vocabulary memo** (`-EncodedCommand` / `-enc` / `-ep bypass` / `-w hidden` / `IEX` / `DownloadString` / `FromBase64String` / `Invoke-Mimikatz` / `[Reflection.Assembly]::Load` / `AmsiUtils` / `amsiInitFailed`); **PowerShell EID 4104** script-block logging; T1204 User Execution click-paths (Office → script-host, browser → script-host) as EQL `sequence` queries with `maxspan`; **T1218 LOLBAS** family with the catalogue overlay (`mshta.exe`, `regsvr32.exe`/Squiblydoo, `rundll32.exe javascript:`, `msiexec.exe`, `cmstp.exe`, `hh.exe`, `installutil.exe`, `regasm.exe`, `wmic.exe`) in a single covering EQL hunt; T1053.005 Scheduled Task with EID 4698/4702/4700 and `schtasks /create`; T1569.002 PsExec-class with EID 7045 service-install paired with SCM-spawned payload from user-writable path. **When to author EQL `sequence` rules vs ES&#x7C;QL aggregations** — chain vs threshold/pivot
- **Defense Evasion TA0005** — T1027.010 command obfuscation with special-character density proxy in ES&#x7C;QL `EVAL`; T1027.002 packing via `process.code_signature.status`; T1070 Indicator Removal — .001 EID 1102/104 + `wevtutil cl Security` (page-IR signal), .003 PSReadLine `ConsoleHost_history.txt` deletion, .004 file-deletion EQL chains, **.006 Timestomp via `file.mtime < file.created`**; T1562 Impair Defenses cluster — .001 (`sc stop Sense` / `Set-MpPreference -DisableRealtimeMonitoring` / `taskkill MsMpEng.exe`), .002 (`Auditpol disable` / `EventLog stop`), .004 (`netsh advfirewall set allprofiles state off`), .009 (`bcdedit safeboot`); the **ransomware pre-encryption `sample by host.name` cluster** (T1562.001 + T1490 `vssadmin delete shadows` + `bcdedit recoveryenabled No`); T1036 Masquerading — .005 `svchost`/`lsass` running outside `System32`/`SysWOW64`, .001 invalid signature with claimed-Microsoft subject_name; T1112 Modify Registry — LSA Protection / AMSI providers / WDigest UseLogonCredential / Defender policy; T1140 deobfuscate, T1497 sandbox evasion (recognise)
- **Statistical hunts + cross-source pivots + capstone** — five canonical statistical patterns: rare-process by SHA256 (`COUNT_DISTINCT(host.name)` ≤ N + unsigned), rare parent-child pair, command-line entropy proxy via `LENGTH` − `LENGTH(REPLACE(...))`, signed-vs-unsigned ratio per host with `BUCKET(@timestamp, 1d)`, time-of-day anomalies via `DATE_EXTRACT("HOUR_OF_DAY", @timestamp)`. Cross-source pivots Elastic Agent ↔ Sysmon with `event.action`/`event.code` disjunction. **Worked PEAK capstone** — full hunt for *encoded PowerShell from Office parent*: hypothesis (4-element + SMART), Q1 broad KQL, Q2 narrowed KQL with parent filter, Q3 EQL `sequence` for click-context, Q4 ES&#x7C;QL aggregation for triage with `STATS BY BUCKET(1h)`, then the **Kibana Security EQL detection-rule body** ready for TIDE submission with severity / runbook / whitelist metadata. Full hunt-cycle close from red → orange → yellow → green Navigator coverage

8 Mermaid diagrams across the module: data-plane taxonomy (3 sources), verb-field crosswalk, T1218 LOLBAS catalogue overlay, T1204 click-path sequence, Defense-Evasion family tree, TA0005 triage flowchart, statistical-hunt decision tree, cross-source pivot flow.

L2 course now sits at **3 modules / 24 lessons / 48 questions**.

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.13 (2026-04-28)

### L2 Module 2 — KQL, EQL, and ES|QL: the Elastic-stack query languages

Second L2 ship. **L2 Module 2 — KQL, EQL, and ES|QL** authored from a research-agent dossier at BTL1+/SANS depth. ~10,000 words, 8 lessons (4 reading + 4 quiz), 16 quiz questions. Aligned to ION's actual stack — Elastic + Kibana — with all worked queries against Beats / Elastic-Agent indices using ECS field paths.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 2.1 | The Elastic query-language landscape: Lucene, KQL, EQL, ES&#x7C;QL | reading | — |
| 2.2 | Language landscape — quiz | quiz | 4 |
| 2.3 | KQL fundamentals — and Lucene as the legacy fallback | reading | — |
| 2.4 | KQL & Lucene — quiz | quiz | 4 |
| 2.5 | EQL — sequence queries and behavioural chains | reading | — |
| 2.6 | EQL — quiz | quiz | 4 |
| 2.7 | ES&#x7C;QL — the piped DSL for stats, joins, and time-series | reading | — |
| 2.8 | ES&#x7C;QL — quiz | quiz | 4 |

#### Topics covered

- **The query-language landscape** — Lucene query syntax (the original; regex / fuzzy / proximity), **KQL** (Kibana 6.3+; search-bar; filter-only), **EQL** (7.9 GA mid-2020; `sequence by host with maxspan`; security event correlation), **ES|QL** (8.13 GA March 2024; piped DSL; `STATS BY BUCKET()`; cross-index; ENRICH / LOOKUP JOIN). Painless as the *non*-query language. Decision framework for which to reach for given the question shape; per-language Kibana surface (Discover bar, Lucene toggle, Timelines, ES|QL mode, detection-rule body); version timeline (Lucene since v0; KQL 6.3 / 2018; EQL 7.9 / 2020; ES|QL 8.13 / 2024; LOOKUP JOIN 8.16 / late-2024). Crucial disambiguation: *Microsoft KQL* (Kusto) vs *Elastic KQL* (Kibana) — same acronym, completely different languages
- **KQL + Lucene** — field equality, ranges (bracket and comparator), Boolean operators with grouping, wildcards (with the leading-wildcard performance trap), exists/missing via `field: *`, **the keyword vs text mapping case-sensitivity trap** (the same predicate behaves differently on `process.command_line` keyword vs `process.command_line.text` analyzer-tokenised), **the `nested:{...}` same-element trap** (multiple predicates on `nested`-mapped arrays without explicit scope produce silent over-counts), free-text fallback with caveats. KQL's filter-only nature with explicit *when to switch* — switch to ES|QL for stats/joins, EQL for chains, Lucene for regex/fuzzy/proximity. Lucene cheat sheet (anchored regex, fuzzy edit-distance, phrase proximity, term boost, legacy `_exists_` / `_missing_`). Worked three-iteration KQL hunt (PowerShell encoded command from Office parent, narrowed to known-good account exclusions)
- **EQL** — design centre is security event correlation; ECS `event.category` as the first-class predicate target (`process where ...`, `network where ...`, `file where ...`, `authentication where ...`, etc.); `==` keyword-exact case-sensitive vs `:` case-insensitive *like*-with-wildcards (the most common EQL fluency error); `sequence by host.name with maxspan=5m` as the behavioural-chain primitive with multi-key `by` and `until` for early termination; `sample` for unordered correlation (T1490 ransomware staging across `vssadmin` / `wbadmin` / `bcdedit` in any order); EQL's pipe operators (`head` / `tail` / `unique` / `sort` / `count by` / `filter`) for *post*-processing — and recognition that EQL pipes are limited compared to ES|QL. Functions reference (`endsWith`, `startsWith`, `wildcard`, `cidrMatch`, `between`, `length`, arithmetic). Worked phishing-click → script-host chain via `sequence by host.name with maxspan=10m`; worked CIDR-membership predicate via `cidrMatch`
- **ES|QL** — pipeline shape `FROM | WHERE | EVAL | STATS BY | SORT | LIMIT | KEEP | DROP` with each `|` passing a tabular result-set forward (Kusto-like / Splunk-like); `FROM` with multi-index (`logs-*, winlogbeat-*`) and cross-cluster (`cluster1:logs-*, cluster2:logs-*`); `WHERE` with `==`, `IN`, `IS NULL`, `LIKE` (SQL-style `%` / `_` — *not* `*` / `?` — the most common ES|QL fluency error), `RLIKE` for regex, embedded **`KQL("...")`** for "filter half in KQL, aggregation half in ES|QL"; `EVAL` for computed columns including `DATE_TRUNC` / `DATE_EXTRACT` / `CASE`; `STATS` aggregations (`COUNT` / `COUNT_DISTINCT` / `SUM` / `AVG` / `MEDIAN` / `PERCENTILE` / `VALUES` / `TOP`) with the **column-drop trap** (everything not in `BY` and not aggregated is dropped); **`BUCKET(@timestamp, 1h)`** as the workhorse time-series form; `DISSECT` and `GROK` for runtime parsing of unstructured strings (`message`, raw command lines); **`ENRICH`** for joins to a small reference index via an enrich policy; **`LOOKUP JOIN`** (8.16+) for explicit left-outer joins to a lookup index; default 10,000-row cap with explicit `LIMIT` for large `STATS` results. Worked beaconing-anomaly hunt with TCP / 443 + 80 outbound to non-RFC1918, COUNT/COUNT_DISTINCT/SUM per (host × IP × hour), filtered to single-destination-IP buckets with > 50 connections

8 Mermaid diagrams across the module: query-language decision tree, where-each-language-runs map, EQL-vs-ES|QL-vs-KQL-vs-Lucene capabilities matrix, EQL sequence visualisation, ES|QL pipeline horizontal flow, cross-language pivot pipeline, ES|QL detection-rule hand-off, the *KQL embedded in ES|QL* pattern.

L2 course now sits at **2 modules / 16 lessons / 32 questions**.

#### Note on prior modules

L1 Module 8 (Common ATT&CK Techniques) and L2 Module 1 (PEAK methodology) shipped with KQL examples that referenced *Microsoft Kusto* / Defender Advanced Hunting tables (`DeviceProcessEvents`, etc.) — pre-dating the explicit clarification that ION runs on Elastic + Kibana. From v0.11.13 onward, all L2 modules use Elastic query languages and ECS field paths consistently. The L1 examples remain as written (still pedagogically sound for technique recognition); future L2 modules (3–8) will be Elastic-native end to end.

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.12 (2026-04-28) — L2 begins

### L2 Module 1 — The Hunt Hypothesis (PEAK methodology) — first L2 ship at BTL1+/SANS depth

L2 *Threat Hunting with KQL* leaves the v0.11.2 stub state. **L2 Module 1 — The Hunt Hypothesis (PEAK methodology)** authored from a research-agent dossier at the BTL1+/SANS GCIH+/FOR578-equivalent depth bar. ~10,000 words, 8 lessons (4 reading + 4 quiz), 16 quiz questions. The previous v0.11.2 stub (1 module / 2 lessons covering PEAK at framework-demo depth) is *replaced* — same module slot, eight times the depth.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 1.1 | Why hunt? The strategic frame | reading | — |
| 1.2 | Why hunt? — quiz | quiz | 4 |
| 1.3 | The PEAK loop end-to-end (Prepare → Execute → Act → Know) | reading | — |
| 1.4 | PEAK loop — quiz | quiz | 4 |
| 1.5 | The hypothesis: four-element + SMART, hypothesis types, criticism | reading | — |
| 1.6 | The hypothesis — quiz | quiz | 4 |
| 1.7 | Documenting and learning: hunt reports, the negative-result discipline, ION surfaces, and a worked T1218.011 hunt | reading | — |
| 1.8 | Documenting & ION — quiz | quiz | 4 |

#### Topics covered

- **Why hunt? Strategic frame** — detection-only SOCs are structurally blind; *detection rule = hypothesis frozen in code*; hunt fills the gap. The dwell-time problem with current-year medians — 5–10 day medians for ransomware, sub-24h for fast-flux, much longer for quiet identity-tier intrusions; the long-tail matters more than the median; *hunting is asymmetrically valuable on cases the rules missed*. CTID **threat-informed defence** doctrine — Top Techniques calculator + Adversary Emulation Library. **Pyramid of Pain reframed for hunters** — for triage, hunt the bottom; for hunting, prioritise the top three layers (TTPs / tools / artefacts) because re-engineering tradecraft is the most expensive thing you can make an adversary do. Five-axis distinction between **hunt vs IR vs DE** (trigger / stance / disposition / timebox / output) — *the hunt produces the idea; detection engineering produces the rule*. Bianco's **Hunting Maturity Model HM0 → HM4** — most SOCs sit at HM1–HM2, L2 hunters individually unblock HM3. Why L2 hunting is the career-defining skill — builds the mental model for IR, DE, threat-intel, and red-team work; epistemic shift from response to interrogation
- **The PEAK loop** — Splunk SURGe (2023) successor to the Sqrrl Hunting Loop and TaHiTI; Prepare ~20–30% (topic pick / hypothesis / data-source confirmation / success criteria / window / intent) → Execute ~40–50% (broad-to-narrow KQL with audit trail) → Act ~15–20% (TP / BTP / FP / Inconclusive / no-findings disposition) → Know ~10–15% (retro / Navigator update / next-hunt seed). Iteration *within* phases is legitimate as long as time-budget drift is tracked. **Sprint hunts** as PEAK at 90-minute scale for fresh-CTI response. Predecessor lineage — HEAT → Sqrrl Hunting Loop → TaHiTI → Sqrrl Reference Model → PEAK; NIST SP 800-150 feeds Prepare. Where PEAK improves: cleaner phase split, hypothesis as first-class artefact, *Know* phase makes negatives valuable, TIDE/Sigma compatible
- **The hypothesis** — the **four-element template** (TTP + artefact + data source + window) and the **SMART criteria** (Specific, Measurable, Adversary-relevant, Realistic, Time-bounded). Worked good vs weak hypotheses with rewrite flow. Five **hypothesis types** — TTP-based / anomaly-based / situational-awareness / threat-actor-based / custom-detector-based — with worked seed examples. The four-question **criticism step** before Execute (data-source resolution / FP base-rate / variants that escape / null hypothesis). Three failure modes — *hypothesis-as-keyword*, *hypothesis-as-tool-list*, *hypothesis-as-fishing-trip*
- **Documenting and learning** — the **hunt-report template** (Hunt ID / Hypothesis verbatim / Type / ATT&CK mapping / Data sources / Window / Queries Q1–Qn / Findings TP/BTP/FP/Inconclusive / Verdict / Confidence-on-negative / Action items / Time by phase). The **negative-result discipline** with the three-component confidence-on-absence statement (quantify the negative + quantify data confidence + state residual uncertainty); the **false-confidence trap** with bounded-claim discipline. **Worked PEAK hunt for T1218.011 Rundll32 javascript** end-to-end — Prepare 1.5h, Execute 3.0h with the five-query progression (broad → parent filter → account filter → process-tree enrichment → network correlation), Act 1.0h with 0 TPs / 7 BTPs / 4 FPs / 1 Inconclusive, Know 0.8h with confidence-medium-high and a follow-up T1218.010 hunt seeded. The **five-gate detection-rule hand-off** (FP-rate measurement → whitelist → metadata → TIDE submission → lifecycle). **ATT&CK Navigator coverage states** (red → orange → yellow → green) and the rolling 90-day re-hunt cadence on orange cells. **ION-specific surfaces** — hunt-tagged cases routing to IR with the hunt report attached, AlertPromptTemplate matcher tier 2 (regex) and tier 3 (technique) authoring by L2 hunters, Bob's hunt-derived reasoning citing hunt-report IDs, the **hunt repository** indexed semantically by pgvector, and Bob's *triage-augmentation* role on Execute results. The **data-gap log** as the SOC's strongest argument for telemetry budget

7 Mermaid diagrams across the module: PEAK loop with time-budgets, predecessor-models lineage, HMM HM0–HM4 vertical pyramid, four-element hypothesis quadrant, weak-to-strong hypothesis rewrite flow, hunt-vs-IR-vs-DE comparison, T1218.011 PEAK timeline, hunt-to-detection five-gate pipeline.

L2 course now sits at **1 module / 8 lessons / 16 questions**.

#### L2 roadmap

The L2 *Threat Hunting with KQL* curriculum will be eight modules:

| M | Title | Status |
|---|---|---|
| 1 | The Hunt Hypothesis (PEAK methodology) | **v0.11.12** |
| 2 | KQL fundamentals — tabular operators | pending |
| 3 | Process & file events — execution & defense evasion | pending |
| 4 | Identity & sign-in — credential access & lateral | pending |
| 5 | Network telemetry — command & control, exfiltration | pending |
| 6 | Email & collaboration — initial access | pending |
| 7 | Anomaly hunts — statistical methods | pending |
| 8 | Hunt to detection capstone — TIDE / DE conversion | pending |

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.11 (2026-04-28) — L1 COMPLETE

### L1 Module 8 — Common ATT&CK Techniques (the L1 finale)

Seventh and final L1 curriculum ship at the v0.11.3 depth bar. **L1 Module 8 — Common ATT&CK Techniques** authored from a research-agent dossier. ~10,000 words, 8 lessons (4 reading + 4 quiz), 15 quiz questions. **L1 *Alert Triage Fundamentals* is now structurally complete.**

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 8.1 | The ATT&CK framework, reading a technique page, and mapping alerts on the fly | reading | — |
| 8.2 | Framework & technique pages — quiz | quiz | 3 |
| 8.3 | Top techniques: Initial Access, Execution, and Persistence | reading | — |
| 8.4 | IA + Execution + Persistence — quiz | quiz | 4 |
| 8.5 | Privilege Escalation, Defense Evasion, Credential Access, and Discovery | reading | — |
| 8.6 | PrivEsc, Evasion, Cred, Discovery — quiz | quiz | 4 |
| 8.7 | Lateral Movement, Collection / Exfil / Impact, C2, ransomware + cloud chains, worked scenarios, ION conventions | reading | — |
| 8.8 | Lateral, Impact, C2 & ION — quiz | quiz | 4 |

#### Topics covered

- **Framework & technique-page reading** — the four-tier hierarchy (Tactic / Technique / Sub-technique / Procedure), 14 enterprise tactics with TA-numbers, Enterprise / Windows / macOS / Linux / Cloud / Network / Containers / ESXi matrices, ATT&CK Navigator (coverage / threat-actor / detection-coverage layers), versioning inflection points (v6 → v7 sub-tech overhaul → v9-10 cloud reshuffle → v15 ESXi → v16 cloud cleanup), the **30-second / 3-minute / 30-minute** reading cadences, the *zero-second-read* anti-pattern, mapping ATT&CK Data Components to Sysmon / Windows Event Log / Defender Advanced Hunting / ECS, the alert-title → technique-ID mapping table (12 worked translations)
- **Initial Access + Execution + Persistence** — T1566 (Module 6 callback), **T1190** with KEV-cross-reference and Log4Shell / MOVEit / Citrix Bleed / Ivanti canonical examples, T1078 valid-account sub-techniques, T1133 external remote services, T1195 / T1199 / T1189 (recognise but rarely L1-triaged); **T1059** workhorse with the suspicious-PowerShell vocabulary memo (`-enc`, `-w hidden`, `IEX`, `DownloadString`, `FromBase64String`, AMSI bypass strings), T1204 user execution, **T1218** LOLBAS sub-techniques (Mshta, Regsvr32 Squiblydoo, Rundll32, CMSTP, Msiexec) plus the LOLBAS / GTFOBins references, T1053 scheduled tasks (EID 4698/4700/4702), T1569.002 PsExec (EID 7045), T1106 native-API, T1559 IPC; **T1547.001** registry Run keys (Sysmon EID 13), T1543.003 service persistence (EID 7045), T1136 account creation, T1098 account manipulation (`.005` device registration / `.003` cloud roles / `.001` cloud credentials), T1574 DLL hijack/sideload, T1505.003 web shell, T1546.003 WMI subscription
- **PrivEsc + Defense Evasion + Cred Access + Discovery** — T1068 BYOVD, T1134 token manipulation, T1055 process injection (EID 8 + EID 10), T1548.002 UAC bypass; T1027 obfuscation (`.002` packing / `.006` HTML smuggling / `.010` command obfuscation), T1070 indicator removal (EID 1102), T1562 impair defenses (Set-MpPreference, sc stop Sense, Auditpol disable), T1036 masquerading; **T1003 OS credential dumping** (`.001` LSASS with the `0x1010` / `0x1F0FFF` granted-access fingerprint, `.002` SAM, `.003` NTDS, **`.006` DCSync** with the EID 4662 + replication-GUID signal), T1110 brute force / spray / stuffing, T1555.003 browser passwords, T1539 cookie theft, T1187 forced authentication, **T1558 Kerberos** (`.003` Kerberoasting with EID 4769 RC4 downgrade, `.004` AS-REP Roasting with EID 4768 preauth-not-required, `.001` Golden Ticket, `.002` Silver Ticket), T1621 MFA fatigue; the **discovery cluster** — *the cluster is the signal* — full T1087 / T1018 / T1083 / T1057 / T1016 / T1033 / T1069 / T1482 / T1518 mapping
- **Lateral + Collection / Exfil / Impact + C2 + chains + scenarios** — T1021 remote services (`.001` RDP LT10, `.002` SMB LT3, `.006` WinRM with `WinRM` logon-process), T1570 lateral tool transfer (`bitsadmin`, `certutil -urlcache`), T1550 alternate-auth (PtH, PtT), T1210 EternalBlue / ProxyShell / ZeroLogon; T1005 / T1114 / T1213 / T1560.001; T1041 / T1567.002 cloud-storage exfil / T1048; **T1486 / T1490 / T1485 / T1489** ransomware Impact cluster — *T1490 is page-everyone*; T1071 / T1573.002 / T1090 / T1568.002 DGA / **T1102** SaaS dead-drops / T1572 tunnels / T1219 RMM abuse, plus the **beacon-shape** pattern from Module 4; the **modal ransomware-affiliate intrusion chain** in ATT&CK shorthand with **dwell-time compression to 5–10 day medians** (under 24h for fast-flux operators); the **modal cloud-takeover chain** (T1566.002 → T1539 → T1078.004 → T1098.005 → T1098.001/.003 → T1114.003 + T1213 → T1567.002); **ION-specific** — matcher tier 3 (technique) + tier 4 (tactic) drive Bob's prompt selection, case taxonomy carries technique IDs through escalation packets (Module 7), Bob's verdict cites technique IDs, pgvector case-similarity uses technique tags as a deterministic axis; **three end-to-end worked scenarios** — *(A) discovery-cluster fingerprint* on a workstation, *(B) LSASS read → DCSync chain* with isolation + IR page, *(C) ransomware staging* (T1490 → T1489 → T1486) with 2–10 minute time pressure; the **eight common L1 ATT&CK-mapping mistakes** to avoid (parent-instead-of-sub-tech, group-name-pinning from procedures, single-discovery-as-high, cluster-as-info, T1490 as monitor, T1055 as escalation, on-prem T1078 for cloud, Detection-section as must-match)

10+ Mermaid diagrams across the module: ATT&CK matrix-style horizontal flow with most-common L1 techniques, ransomware-affiliate chain, cloud-takeover chain, alert-title → technique decision tree, discovery-cluster Gantt timeline, LSASS → DCSync flow, ransomware staging timeline.

L1 course now sits at **8 modules / 59 lessons / 127 questions — STRUCTURALLY COMPLETE**.

#### L1 milestone

The full L1 *Alert Triage Fundamentals* curriculum (v0.11.3 onwards) covers the day-shift triage analyst from first principles to capstone:

| M | Title | Lessons | Questions | Shipped |
|---|---|---|---|---|
| 1 | The alert lifecycle | 3 | 8 | v0.11.3 |
| 2 | SIEM Fundamentals | 8 | 23 | v0.11.5 |
| 3 | Windows Event Logs | 8 | 23 | v0.11.6 |
| 4 | Network Telemetry | 8 | 14 | v0.11.7 |
| 5 | IOC Handling | 8 | 14 | v0.11.8 |
| 6 | Phishing Triage | 8 | 15 | v0.11.9 |
| 7 | Escalation Workflow | 8 | 15 | v0.11.10 |
| 8 | Common ATT&CK Techniques (finale) | 8 | 15 | **v0.11.11** |
| **L1 total** | | **59** | **127** | |

**Backlog from here:** L2 *Threat Hunting with KQL* full curriculum (8 modules, currently a 1-module / 2-lesson v0.11.2 stub) — kicks off in the next ship. After L2: L3 *Adversary Emulation Basics* (currently a stub). After all three: labs ship, PDF certificate generation, Elastic Agent Skills consumer integration as Bob's 6th matcher tier.

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.10 (2026-04-28)

### L1 Module 7 — Escalation Workflow

Sixth curriculum ship at the v0.11.3 depth bar. **L1 Module 7 — Escalation Workflow** authored from a research-agent dossier. ~10,000 words, 8 lessons (4 reading + 4 quiz), 15 quiz questions. Lives on the existing `demo-l1-alert-triage-fundamentals` course as Module 7.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 7.1 | The escalation decision: cost calculus, criteria, and timeboxing | reading | — |
| 7.2 | Decision & timeboxing — quiz | quiz | 3 |
| 7.3 | Severity, priority, blast radius, and the escalation paths | reading | — |
| 7.4 | Severity, priority, paths — quiz | quiz | 4 |
| 7.5 | The handover packet, chain of custody, and communication discipline | reading | — |
| 7.6 | Handover, custody, comms — quiz | quiz | 4 |
| 7.7 | External reporting, CERTs and ISACs, ION conventions, and worked scenarios | reading | — |
| 7.8 | Clocks, CERTs, ION & scenarios — quiz | quiz | 4 |

#### Topics covered

- **The escalation decision** — cost calculus of *false escalation* (L2 burnout, alert-fatigue erosion, KPI distortion) vs *missed escalation* (delayed containment, dwell-time growth, regulator-clock-started-late, board-level event); the chokepoint principle; default escalation criteria (credential exposure, EDR-high, lateral movement, multi-host/multi-user, VIP, privileged-account out-of-window, novel TTP, SLA risk, cross-team action, suspected data exposure); contain-and-close criteria; "when in doubt escalate — *but*" anti-pattern; SLA bands as escalation triggers; 80/20 of L1 disposition; *stuck-authority* vs *stuck-skill* vs *stuck-scale* vs *stuck-novelty*
- **Severity, priority, blast radius, paths** — five-tier severity scale; FIRST CSIRT services framework, CVSS adapted for incidents, ENISA Reference Incident Classification Taxonomy, NIST 800-61r2 categories, MITRE D3FEND / RE&CT vocabulary; severity × asset class priority matrix; blast-radius lens (hosts × users × data class × services × external entities); TLP / PAP marking on every handoff; the **15 escalation paths** — L2, IR / DFIR, Threat Intel, Detection Engineering / TIDE, IT / Ops, Identity / IAM, Legal / Compliance / Privacy, HR-Security liaison, Comms / PR, Management / CISO, MSSP / vendors, External CIRT / CERT, Sector ISACs, Regulators, Law enforcement — each with *who / when / how / what / why* and the L1-owns vs L1-triggers distinction
- **Handover packet, custody, comms** — the full handover-packet template (title, header, affected entities, monotonic UTC timeline, IOCs with TLP/PAP, containment actions, hypothesis, hashed artefacts, open questions, recommended next steps, stakeholder log) with worked good and bad examples; 5-line vs 5-page question; the **irreducible minimum** five fields; chain-of-custody discipline (legal admissibility, regulatory inquiry, criminal-referral, insurance); SHA-256 hashing at collection; source-of-truth principle; **RFC 3227** order of volatility; UTC time discipline + clock-skew documentation; live-forensics vs containment trade-off; six L1 chain-of-custody rules of thumb; channel hygiene by severity; the **3-line update** (what happened / impact / what's being done) for execs; status-update cadence; plain-language discipline; TLP information-sharing rules; the *no-surprises* rule
- **External clocks, CERTs, ION conventions, scenarios** — **GDPR Art.33** 72h clock from awareness; **NIS2** 24h / 72h / 30d cascade; **DORA** financial-sector regime; **SEC 8-K Item 1.05** 4-business-day disclosure from materiality determination; **HIPAA** 60-day breach notification; **CIRCIA** phased-in 72h / 24h ransom; sectoral (PCI-DSS, TSA, NERC CIP-008); national CERTs (NCSC UK, CISA US, BSI DE, ANSSI FR, JPCERT JP, AusCERT AU, CCCS CA, CERT-EU, ENISA); twelve sector ISACs (FS / MS / H / E / Auto / Aviation / Space / Water / ND / REN / Retail / MFG); reporting portals; ION-specific conventions (case state machine `open → investigating → escalated → closed`, Bob verdict + confidence as nudge-not-authority, ticker as escalation trigger, audit log as automatic in-platform chain of custody, `CaseClosureReason` taxonomy as Tier-1 training feedback, AlertPromptTemplate matcher tier as DE-feedback signal); three full worked scenarios — **AiTM token theft on HR-Director** (4-team handover), **suspected insider IP exfil** (preserve-not-tip-off discipline), **mass phishing with ≥50 confirmed clicks** (cascading into 9 escalation paths within the first hour, GDPR/NIS2/SEC clocks all engaged)

7 Mermaid diagrams across the module: escalation decision tree, multi-team escalation routing topology, handover-packet anatomy, chain-of-custody flow, external-reporting clock Gantt.

L1 course now sits at **7 modules / 51 lessons / 112 questions**.

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.9 (2026-04-28)

### L1 Module 6 — Phishing Triage

Fifth curriculum ship at the v0.11.3 depth bar. **L1 Module 6 — Phishing Triage** authored from a research-agent dossier. ~10,000 words, 8 lessons (4 reading + 4 quiz), 15 quiz questions. Lives on the existing `demo-l1-alert-triage-fundamentals` course as Module 6.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 6.1 | Phishing taxonomy and email authentication | reading | — |
| 6.2 | Taxonomy & email auth — quiz | quiz | 4 |
| 6.3 | Lure analysis, lookalike domains, and attachment + link triage | reading | — |
| 6.4 | Lure & link triage — quiz | quiz | 3 |
| 6.5 | Detection telemetry: email side, endpoint side, identity side | reading | — |
| 6.6 | Telemetry & AiTM — quiz | quiz | 4 |
| 6.7 | Reporting pipeline, decision framework, ATT&CK, and worked scenarios | reading | — |
| 6.8 | Decision framework, ATT&CK & scenarios — quiz | quiz | 4 |

#### Topics covered

- **Taxonomy & email auth** — credential phishing, malware delivery, BEC (CEO fraud / vendor invoice redirect / payroll diversion), spear/whaling, smishing/vishing, **quishing** (QR-phishing), **consent phishing** (OAuth abuse), browser-in-the-browser, **AiTM** kits (Evilginx, EvilProxy, Tycoon 2FA), MFA fatigue / push bombing; RFC 5321 envelope vs RFC 5322 header From; reading the Received chain bottom-up; Authentication-Results / `compauth` interpretation; SPF (RFC 7208), DKIM (RFC 6376) including DKIM replay, DMARC (RFC 7489) alignment + policy, ARC (RFC 8617) for forwarders; the four spoofs none of SPF/DKIM/DMARC stops alone (display-name, lookalike, compromised legitimate sender, Reply-To swap)
- **Lures & link triage** — pretext catalogue (HR / IT / voicemail / DocuSign / courier / invoice / Teams / calendar / captcha / QR), urgency–authority–scarcity psychology, brand-impersonation tells (display-name vs domain, hover-vs-display URL, favicon, footer), lookalike domain families (typosquat / combosquat / IDN homoglyph / TLD swap / sub-domain abuse) with worked Cyrillic-`о` example, risky file types (HTML smuggling, ISO/IMG/VHD MOTW bypass, .lnk, .one, weaponised PDF, .docm/.xlsm/.xll macros, .svg with script, password-protected zip, ClickOnce, .url SMB-cred-theft), URL reputation tooling (VT, urlscan.io, Hybrid Analysis, abuse.ch, OPSWAT), the **OPSEC submission rule** with per-victim-token handling, sandbox decision criteria
- **Email + endpoint + identity telemetry** — Microsoft 365 Defender for Office 365 (Threat Explorer, Email Entity Page, Quarantine, ZAP, Submissions API), Exchange Message Trace fields + `Get-MessageTrace` PowerShell, Google Workspace Investigation Tool, EDR process trees rooted at `outlook.exe` / `<browser>.exe` / Office, Sysmon event-ID fingerprints (1/3/7/11/15/22/25), full ECS field-path map for phishing follow-on (`process.parent.name`, `url.original`, `email.from.address`, `dns.question.name`, `file.hash.sha256`), worked KQL + Lucene queries, **AiTM signal in Entra ID sign-in logs** (riskEventTypes_v2, sessionId reuse, `previouslySatisfied` MFA), Unified Audit Log events (`New-InboxRule`, `Set-Mailbox -ForwardingSmtpAddress`, `Add-MailboxPermission`, `Consent to application`), illicit OAuth grants and the risky scopes that demand escalation, the textbook post-takeover BEC inbox-rule pivot
- **Pipeline, decisions, ATT&CK, scenarios** — user-reported phishing pipeline (PhishER, Cofense, Microsoft Report Message), confirmed-phish workflow (scope → pull → contain → IOC-pivot → 7-day hunt → submit), L1-vs-L2 authority boundaries, escalate/contain/close decision tree, ATT&CK mapping across **T1566.001/.002/.003/.004**, T1583.001 lookalike domains, **T1656** impersonation, T1027.006 HTML smuggling, **T1539** Steal Web Session Cookie, **T1098.005** Device Registration, T1556 Modify Authentication Process, **T1114.003** Email Forwarding Rule, T1621 MFA Request Generation, T1071.001/.004 C2; three full worked scenarios — **AiTM credential phish with token theft**, **HTML smuggling → ISO → LNK → loader**, **BEC vendor invoice redirect (no malware)**

10 Mermaid diagrams across the module: SPF/DKIM/DMARC validation flow, AiTM kit topology, click-path process tree, post-confirmation containment checklist, triage decision tree.

L1 course now sits at **6 modules / 43 lessons / 97 questions**.

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.8 (2026-04-27)

### L1 Module 5 — IOC Handling

Fourth curriculum ship at the v0.11.3 depth bar. **L1 Module 5 — IOC Handling** authored from a research-agent dossier. ~10,000 words, 8 lessons (4 reading + 4 quiz), 14 quiz questions. Connects Modules 3 (host telemetry) and 4 (network telemetry) to the threat-intel side.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 5.1 | IOC types and the Pyramid of Pain | reading | — |
| 5.2 | IOC types — quiz | quiz | 3 |
| 5.3 | IOC formats, sharing, and threat intel platforms | reading | — |
| 5.4 | STIX/MISP/TLP/PAP — quiz | quiz | 3 |
| 5.5 | Reputation services, enrichment, and OPSEC | reading | — |
| 5.6 | Reputation & OPSEC — quiz | quiz | 4 |
| 5.7 | IOC lifecycle, matching in ION, and decay | reading | — |
| 5.8 | Lifecycle & matching — quiz | quiz | 4 |

#### Topics covered

- **IOC types & Pyramid of Pain** — observable vs indicator vs IOC, Mandiant atomic/computed/behavioural taxonomy, full IOC catalogue (hashes, network atomics, host artefacts, TLS, pattern-based, adversary-level), Bianco's tier model with cost-to-adversary breakdown, precision-vs-durability-vs-FP-rate trade-offs
- **Formats, sharing, platforms** — STIX 2.1 SDO/SRO/SCO with worked indicator JSON, MISP events/attributes/objects/tags/galaxies with worked attribute JSON, OpenIOC legacy, CSV / Suricata / YARA / Sigma drops, **TLP 2.0** (CLEAR/GREEN/AMBER/AMBER+STRICT/RED) sharing rules, **PAP** (WHITE/GREEN/AMBER/RED) action rules — emphasising TLP and PAP are independent, OpenCTI as upstream truth source, defanging/refanging conventions
- **Reputation & OPSEC** — VirusTotal interpretation (the 0/72 trap, Behaviour tab, Relations graph), AbuseIPDB confidence semantics, abuse.ch (URLhaus, ThreatFox, MalwareBazaar), AlienVault OTX pulse caveats, Shodan/Censys passive scan databases, Passive DNS for resolution-at-alert-time reconstruction, **the OPSEC trap** of submitting fresh hashes/samples/URLs to public services against live adversaries, active-vs-passive enrichment decision tree, end-to-end fresh-C2-domain triage walkthrough
- **Lifecycle & matching in ION** — 8-stage lifecycle (production → ingestion → enrichment → distribution → matching → triage → feedback → decay), type-appropriate decay (hashes never auto-expire, IPs 30 d, domains 90 d, URLs 14 d), MISP decaying-indicators model + OpenCTI valid_until, Elastic Indicator Match rules with full ECS field-path table (`file.hash.sha256` ↔ `threat.indicator.file.hash.sha256`, `source.ip` ↔ `threat.indicator.ip`, etc.), KQL hunting examples for hash/IP/domain/URL, sightings semantics + feed efficacy measurement, FP-marking discipline, **end-to-end Emotet-dropper IOC-hit triage** (Module 3/4 callbacks, classification, sighting-write, escalation)

10 Mermaid diagrams across the module: Pyramid of Pain, observable taxonomy, STIX object relationships, intel ingestion flow, active-vs-passive sources, OPSEC enrichment decision tree, IOC lifecycle, IOC match-then-investigate workflow.

L1 course now sits at **5 modules / 35 lessons / 82 questions**.

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.7 (2026-04-27)

### L1 Module 4 — Network Telemetry

Third curriculum ship at the v0.11.3 depth bar. **L1 Module 4 — Network Telemetry** authored from a research-agent dossier. ~10,000 words, 8 lessons (4 reading + 4 quiz), 14 quiz questions. Lives on the existing `demo-l1-alert-triage-fundamentals` course as Module 4.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 4.1 | Network data sources — PCAP, flow, Zeek, IDS | reading | — |
| 4.2 | Data sources — quiz | quiz | 3 |
| 4.3 | Reading Zeek logs and the ECS mapping | reading | — |
| 4.4 | Zeek + ECS — quiz | quiz | 3 |
| 4.5 | Beaconing, DNS tunneling, and C2 detection | reading | — |
| 4.6 | Beaconing & C2 — quiz | quiz | 4 |
| 4.7 | Reconnaissance, exfiltration, and ATT&CK mapping | reading | — |
| 4.8 | Recon & exfil — quiz | quiz | 4 |

#### Topics covered

- **Data sources** — PCAP vs NetFlow/IPFIX/sFlow vs Zeek metadata vs Suricata/Snort IDS; sampling-rate context; proxy and NGFW logs
- **Zeek + ECS** — full conn.log field set, the seven `conn_state` codes that matter (S0/S1/SF/REJ/RSTO/RSTR/OTH), suspicious dns.log shapes (long subdomains, NXDOMAIN bursts, DGAs, TXT volume), ssl.log + SNI + JA3/JA3S, uid pivot, complete Zeek-to-ECS field mapping table
- **Beaconing & C2** — statistical signature, worked 144-conn / 600 s-jitter example with full conn.log shape and ES|QL aggregation, DNS tunneling shape with `dnscat2` / `iodine` worked example, HTTP/HTTPS C2 indicators, CDN-hidden C2 nuance, JA3 enrichment caveats, escalation criteria
- **Recon & exfil** — port scan vs sweep distinction with conn_state shapes, post-scan service enumeration (SMB/RDP/WinRM/SSH/WMI), exfil patterns to mega.nz / Discord CDN / transfer.sh with ES|QL outbound-bytes query, DNS exfil vs HTTPS exfil trade-off, lateral-movement port catalogue (445/5985/6/3389/RPC/LDAP/Kerberos), MITRE ATT&CK technique mapping (T1046, T1041, T1048, T1071, T1572)

10 Mermaid diagrams across the module: data-source taxonomy, detail-vs-volume pyramid, Zeek log family + uid pivot, Zeek-to-ECS mapping, beacon timeline, DNS-tunneling shape, scan vs sweep visualisation, DNS exfil workflow.

L1 course now sits at **4 modules / 27 lessons / 68 questions**.

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.6 (2026-04-27)

### L1 Module 3 — Windows Event Logs

Second curriculum ship at the v0.11.3 depth bar. **L1 Module 3 — Windows Event Logs** authored from a research-agent dossier covering channels, providers, the high-value Security event IDs, Sysmon, and canonical attacker patterns. ~10,000 words of curriculum content, 8 lessons (4 reading + 4 quiz), 23 quiz questions. Now lives on the existing `demo-l1-alert-triage-fundamentals` course as Module 3.

#### Lesson breakdown

| # | Title | Type | Words | Quiz qs |
|---|---|---|---|---|
| 3.1 | The Windows logging architecture and how it reaches ION | reading | ~2,200 | — |
| 3.2 | Architecture quiz | quiz | — | 5 |
| 3.3 | High-value Security channel event IDs | reading | ~2,800 | — |
| 3.4 | Security event IDs — quiz | quiz | — | 6 |
| 3.5 | Sysmon — the L1 superpower | reading | ~2,500 | — |
| 3.6 | Sysmon recognition — quiz | quiz | — | 6 |
| 3.7 | Triaging common attack patterns from raw events | reading | ~2,700 | — |
| 3.8 | Attack patterns — quiz | quiz | — | 6 |

Each reading lesson hits the v0.11.3 quality bar: explicit learning objectives + prerequisites, multiple Mermaid diagrams (10 across the module — flowcharts, sequence diagrams, decision trees), worked scenarios with full ECS field traces and ATT&CK technique mappings, KQL with line-by-line commentary, glossary, and references.

#### Topics covered

- **Architecture** — channels (Security, System, Application, Setup, Forwarded Events) vs providers, EVTX format, winlogbeat ECS normalisation, channel-to-index mapping, Windows Event Forwarding (WEF) source-initiated subscriptions
- **Security event IDs** — the 4624/4625/4634/4647/4648/4672 logon cluster with all 11 LogonTypes, 4625 SubStatus codes (`0xC000006A` bad password, etc.), the 4720/4722/4724/4732/4738/4756 account/group cluster, Kerberos 4768/4769 with `TicketEncryptionType` Kerberoasting tells, NTLM 4776, audit log clearing 1102, service install 7045, command-line process creation 4688
- **Sysmon** — provider/channel naming, SwiftOnSecurity vs Olaf Hartong baselines, the high-value event IDs (1, 3, 7, 8, 10, 11, 13, 22) with full ECS field mapping, `OriginalFileName` for renamed-binary detection, Mimikatz LSASS signature on Event 10
- **Attack patterns** — Pass-the-Hash signatures (`AuthenticationPackageName: NTLM` for admin accounts), golden/silver ticket conceptual signals (4624 without 4768/4769 on DC), service install persistence with `ImagePath` heuristics, account-creation-then-group-add cluster, parent-child anomaly table (Office spawning shells, IIS spawning shells = webshell, lsass.exe spawning anything), DNS exfiltration via Sysmon 22

22 ATT&CK technique mappings cited (T1078, T1110, T1021, T1550.002, T1558.001/002/003, T1003.001, T1059, T1218, T1036, T1071, T1041, T1574, T1055, T1486, T1547.001, T1543.003, T1505.003, T1070.001, T1566.001, T1059.005, T1110.003).

#### Upgrade

Drop in `ion:0.11.6`. Re-run the seeder to refresh course content (idempotent — wipes `demo-*` courses and re-seeds):

```
cat seed_courses.py | docker exec -i ion python -
```

After re-seed, browse `http://localhost:8000/courses/demo-l1-alert-triage-fundamentals` — Module 3 (Windows Event Logs) appears below Modules 1 and 2.

#### What's next

L1 Module 4 (Network Telemetry) → 5 (IOC Handling) → 6 (Phishing Triage) → 7 (Escalation Workflow) → 8 (Common ATT&CK), all using the same research-agent → dossier → curriculum pattern. Then L2 and L3 curricula. Then the Elastic Agent Skills integration we scoped earlier.

## v0.11.5 (2026-04-27)

### L1 Module 2 — SIEM Fundamentals (curriculum kick-off)

First curriculum ship at the v0.11.3 depth bar. **L1 Module 2 — SIEM Fundamentals** authored from a research-agent dossier covering the Elastic / Wazuh / ECS stack ION integrates with. ~10,500 words of curriculum content, 8 lessons (4 reading + 4 quiz), 22 quiz questions. Now lives on the existing `demo-l1-alert-triage-fundamentals` course as Module 2.

#### Lesson breakdown

| # | Title | Type | Words | Quiz qs |
|---|---|---|---|---|
| 2.1 | What a SIEM is and how data flows through it | reading | ~2,400 | — |
| 2.2 | Pipeline + architecture quiz | quiz | — | 5 |
| 2.3 | Speaking ECS — the data model L1 lives in | reading | ~2,500 | — |
| 2.4 | ECS field knowledge — quiz | quiz | — | 6 |
| 2.5 | Querying the SIEM with KQL | reading | ~2,800 | — |
| 2.6 | KQL fluency — quiz | quiz | — | 6 |
| 2.7 | Pivots, timelines, and the alert lifecycle | reading | ~2,800 | — |
| 2.8 | Pivots + lifecycle — quiz | quiz | — | 6 |

Each reading lesson hits the v0.11.3 quality bar:
- Explicit *learning objectives* + *prerequisites* at top
- Multiple Mermaid diagrams (sequence, flowchart, state machine, classDiagram) — 9 diagrams across the module
- Worked scenarios with concrete ECS field names + realistic hostnames + actual KQL queries with line-by-line commentary
- ION-specific callouts: how each topic ties back to `AlertTriage`, `Investigation`, `AIFeedback`, the `CaseClosureReason` enum, Bob's role
- Glossary of jargon (~10–12 terms per lesson)
- Further reading with concrete URLs (Elastic docs, Wazuh docs, MITRE ATT&CK, BTL1, SANS GCIH KSA references)

#### Topics covered

The four lessons collectively cover:

- **Pipeline anatomy** — the six stages (ingest → parse → normalise → store → query → alert), which Elastic Stack component owns each, where failures localise
- **SIEM vs aggregator** — five concrete capability differences (schema, detection engine, enrichment, workflow, retention tiers)
- **Architectures** — cloud-native vs on-prem vs hybrid, with practical implications for L1 self-service vs escalation
- **ECS data model** — the ten core fields used in 90% of L1 queries, source-to-ECS mapping for winlogbeat/sysmon/auditd/packetbeat/wazuh, common pitfalls (case sensitivity, multi-value fields, action vs code)
- **KQL fluency** — boolean operators, wildcards, ranges, existence checks, escaping, four canonical hunt patterns (failed-auth-by-user, suspicious-child-of-svchost, beaconing, DNS to newly-registered domains)
- **SPL contrast + translation** — KQL-to-CIM-to-SPL field mappings (`source.ip` ↔ `src_ip`, etc.) for analysts moving between employers
- **Cluster investigation pattern** — the 10-step pivot chain from anchor IOC through host → user → process → network → file → hash → DNS → lateral
- **Dashboard pitfalls** — when to trust them, when they hide answers (time-range mismatch, filter inheritance, index-pattern drift, ranking truncation)
- **Alert lifecycle in ION** — the state machine, ION as system of record vs Kibana as a connector view, why closure-comment quality matters for AIFeedback

#### Authoring approach

This module is the first to follow the **research-agent → dossier → curriculum** pattern. A research agent produced ~10,000 words of structured input (sections + worked examples + diagrams + question stems + glossary + references) which was then woven into final lesson copy. The pattern scales — subsequent L1 modules (3-8) and the L2/L3 ships will use the same flow.

#### Upgrade

Drop in `ion:0.11.5`. Re-run the seeder to refresh course content (idempotent — wipes `demo-*` courses and re-seeds):

```
cat seed_courses.py | docker exec -i ion python -
```

After re-seed, browse `http://localhost:8000/courses/demo-l1-alert-triage-fundamentals` — Module 2 with its 8 lessons appears below the existing Module 1.

#### What's next

- **v0.11.6+** — additional L1 modules using the same dossier pattern (Windows Event Logs, Network Telemetry, IOC Handling, Phishing Triage, Escalation Workflow, Common ATT&CK)
- **After L1 curriculum complete** — Elastic Agent Skills exploration (separate research conversation queued by user)

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
