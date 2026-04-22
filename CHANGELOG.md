# Changelog

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
