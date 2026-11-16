<!-- ion-doc:type=CODEBASE MAP -->
<!-- ion-doc:title=ION Codebase Map -->
<!-- ion-doc:subtitle=Dependency structure from the Graphify code graph: hubs, layers, blast radius -->
<!-- ion-doc:version=0.99.17 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Engineers -->
<!-- ion-doc:date=2026-11-16 -->

# ION Codebase Map

A dependency-level map of ION, built from the Graphify code graph of
`origin/main` at commit `02cc7ae`. It complements `ARCHITECTURE.md` (components
and data flow) with *what depends on what*, so a change can be sized before it is
made. Line numbers and counts drift — re-query the graph rather than trusting
them after a large change.

## Size

| | |
|---|---|
| Graph | 34,941 nodes, 82,118 edges, 1,420 code areas |
| `src/ion/data` | 16 files, ~127k lines — KB and ATT&CK seed data, not indexed |
| `src/ion/services` | 167 files, ~82k lines |
| `src/ion/web` | 180 files, ~81k lines — 83 `*_api.py` routers, 362 Jinja templates |
| `src/ion/models` | 62 files, ~10k lines |
| `src/ion/storage` | 16 files, ~7k lines |
| `src/ion/core` / `auth` / `cli` | ~3.8k / ~2.5k / ~2.2k lines |
| `tests/` | ~12,600 definitions — about two-thirds of all definitions in the graph |

`.graphifyignore` keeps the vendored `static/js/*.min.js` bundles and
`src/ion/data/` out of the graph. With the bundles in, their dense internal edges
collapsed the whole repo into one code area labelled `mermaid.min.js`; adding a
new vendored bundle without a matching ignore rule brings that back.

The hubs below
(`storage/database.py`, `core/config.py`, `models/user.py`) still connect nearly
everything, so reason about subsystems by directory first.

## Layers

```
Browser (Jinja pages + static/js)
   │
web/server.py ──── 132 symbols, 56 neighbour files
   ├─ middleware: SecurityHeaders, CSRF, RateLimitSecurity, SecurityMonitoring,
   │              RequestLogging, Prometheus
   ├─ _startup_event(): ~12 seeders + ~16 background loops
   ├─ _install_path_aliases(): legacy path aliases (runtime only — not in the graph)
   └─ page routes → auth/dependencies.require_page_permission
   │
web/*_api.py (83 routers) ── auth/dependencies.py
   │                           get_current_user → _authenticate
   │                           → apply_post_session_policy → _bind_tenant
services/ (167)
   ├─ connectors/registry.py ── ConnectorRegistry (singleton) over BaseConnector
   │     Elasticsearch · Kibana Cases · TIDE · OpenCTI · Arkime · GitLab
   ├─ alert_prompt_service.py ── AlertPromptService + RAG layers
   │     (KB / playbook / TI report / few-shot exemplars / skills)
   └─ case_ledger_service.py ── sha256 evidence chain
   │
storage/database.py ──── 234 dependent files
   get_engine · get_session(_factory) · advisory_lock · run_locked
   _run_migrations · init_db
```

## Hubs and blast radius

### `storage/database.py` — 234 dependent files

The widest blast radius in the codebase; `server.py` has 56. Heaviest users:
`web/ai_api.py`, `web/daily_standup_api.py`, `services/investigation_service.py`,
`cli/main.py`, `web/admin_api.py`, `web/mcp_api.py`, `services/webhook_service.py`.

`_run_migrations()` spans roughly L357–L1649 — most of the file. Changes here
need the widened affected-module test set (see CLAUDE.md, *Test scope by version*).

### `web/server.py` — 56 neighbour files

Mostly fan-out: `_startup_event()` imports a seeder or loop starter from ~30
service modules. Its inbound edges are tests and `loadtest/locustfile.py`.

Startup seeders: auth (admin, Bob, METIS users, roles, permissions), default
tenant, playbooks, SOC templates, KB, KEV, forensic playbooks, capability
articles, comm templates, CyAB sub-profiles, alert prompt templates, analytics jobs.

Background loops: Kibana sync, analytics, TIDE sync, network map, scheduler, case
grouper, session cleanup, data retention, Arkime auto-case / realtime monitor /
retention, case / KB / playbook embedding, TI reports.

### Background-loop pattern

Every `start_*_if_enabled()` loop starter — scheduler, case grouper, case / KB /
playbook embedding, TI report — calls `run_locked()` from `storage/database.py`.
That is the advisory-lock leader election; a new loop that skips it runs once per
worker.

## Subsystems

### Auth and session policy — `auth/dependencies.py`

`apply_post_session_policy` has exactly four callers, all authentication entry
points:

| Caller | File |
|---|---|
| `_authenticate()` | `auth/dependencies.py` |
| `_authenticate_page()` | `auth/dependencies.py` |
| `_authenticate()` | `web/events_api.py` |
| `_authenticate()` | `web/mcp_api.py` |

A new entry point that authenticates a user must become the fifth.
`tests/test_shared_auth_policy.py` asserts the policy is the only password gate.

Other files: `auth/service.py` (AuthService, seeding), `auth/oidc.py` +
`auth/oidc_config.py` (Keycloak RS256), `auth/password.py`.

### Connectors — `services/connectors/`

`ConnectorRegistry` is a singleton (`__new__`) populated by
`register_default_connectors()` in `connectors/__init__.py`. Consumers:
`web/integration_api.py` (status, config schema, health checks),
`web/admin_api.py` (architecture health), `services/wallboard_service.py`,
`web/server.py` (Kibana sync start). `version_compat.py` runs at startup.

Connector files: `elasticsearch_connector.py`, `kibana_cases_connector.py`,
`tide_connector.py`, `opencti_connector.py`, `arkime_connector.py`,
`gitlab_connector.py`, all over `base.py`.

### Bob prompt path — `services/alert_prompt_service.py`

`AlertPromptService` starts around L4072; the ~4,000 lines above it are inline
seed templates. Entry points into it:

- `web/bob_analysis_api.py` → `_augment_system_prompt()` →
  `resolve_template_for_alert()` + `build_rag_context_blocks()`
- `services/investigation_service.py` → `investigate_case()` →
  `resolve_template_for_alert()` + `render_system_prompt()`

Outbound: `storage/alert_prompt_repository.py`, `models/alert_prompt.py`,
`services/embedding_service.py`, `services/skill_loader.py`,
`models/ti_report.py`. Each RAG layer has its own `_*_enabled()` gate.

### Case evidence ledger — `services/case_ledger_service.py`

Small and isolated (7 neighbour files).

`canonical_payload()` → `compute_content_hash(prev_hash, action, payload)` →
`_per_case_lock()` → `append()`; `verify_chain()` and `list_entries()` read it
back. Model: `CaseEvidenceLedger` in `models/case_evidence.py`.

Writers: `services/case_pin_service.py` (`create_pin`, `update_pin`,
`dismiss_pin`) and `services/annotation_service.py` (`create`). Reader:
`web/workbench_api.py` (`list_ledger_endpoint`, `verify_ledger_endpoint`).
Ownership checks belong in the writers, before `append()`. Forensic cases use
the separate `services/forensic_ledger_service.py`.

## Querying the graph

Graphify answers best by exact symbol name. Free-text ranking
(`graphify_rank_files`) mis-routes vague questions — "Workbench ledger" returned
session-token hashing. Prefer:

| Question | Tool |
|---|---|
| What depends on this file? | `graphify_file_neighbors` |
| Who calls this function? | `graphify_callers` |
| What breaks if I change it? | `graphify_impact` |
| Which tests cover it? | `graphify_tests_for` |

Graph answers carry the commit they were built from. The index tracks `main`;
for files changed on a feature branch, read the file.
