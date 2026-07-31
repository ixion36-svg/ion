<!-- ion-doc:type=ARCHITECTURE REFERENCE -->
<!-- ion-doc:title=ION Architecture Reference -->
<!-- ion-doc:subtitle=Components, data flow, schema — the original architectural reference (peer to HLD/LLD) -->
<!-- ion-doc:version=0.62.0 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Architects, engineers, operators -->
<!-- ion-doc:date=2026-07-30 -->

# ION Architecture

Technical architecture overview for ION (Intelligent Operating Network).

---

## System Overview

```
                                    +------------------+
                                    |    Browser       |
                                    |  (Tailwind UI)   |
                                    +--------+---------+
                                             |
                                     HTTPS / port 443
                                             |
                                    +--------+---------+
                                    |  Nginx (optional)|
                                    |  TLS termination |
                                    +--------+---------+
                                             |
                                      HTTP / port 8000
                                             |
                          +------------------+-------------------+
                          |           ION Application            |
                          |   FastAPI + Jinja2 + SQLAlchemy      |
                          |   (4 uvicorn workers, 1 leader)      |
                          +--+---+---+---+---+---+---+---+---+--+
                             |   |   |   |   |   |   |   |   |
              +--------------+   |   |   |   |   |   |   |   +----------+
              |                  |   |   |   |   |   |   |               |
     +--------+-------+  +------+---+-+  |   |   |   |  ++--------+  +--+--------+
     |  PostgreSQL 16  |  | Elastic-   |  |   |   |   |  | OpenCTI |  |  GitLab   |
     |  (bundled)      |  | search 8.x |  |   |   |   |  | (GraphQL|  |           |
     |                 |  |            |  |   |   |   |  |  API)   |  |           |
     +-----------------+  +------+-----+  |   |   |   |  +---------+  +-----------+
                                 |        |   |   |   |
                          +------+-----+  |   |   |  ++----------+
                          | Kibana 8.x |  |   |   |  | Ollama    |
                          | (case sync)|  |   |   |  | (local LLM|
                          +------------+  |   |   |  |  air-gap)  |
                                          |   |   |  +-----------+
                                   +------+-+ | +-+-------+
                                   | TIDE    | | | Arkime  |
                                   | (DuckDB | | | (PCAP)  |
                                   |  + API) | | +---------+
                                   +---------+ |
                                          +----+------+
                                          | Keycloak  |
                                          | (OIDC SSO)|
                                          +-----------+
```

### Component Roles

| Component | Role | Protocol |
|-----------|------|----------|
| **ION** | Central platform -- UI, API, business logic, background tasks | HTTP/HTTPS |
| **PostgreSQL** | Primary data store -- users, cases, observables, config, audit logs | TCP 5432 |
| **Elasticsearch** | Alert ingestion, log search, discover queries, alert triage state | HTTP 9200 |
| **Kibana** | Bidirectional case sync, space-aware detection scoping | HTTP 5601 |
| **TIDE** | Detection rule analytics, MITRE coverage, gap analysis (DuckDB backend) | HTTPS + API key |
| **OpenCTI** | Threat intelligence -- actors, campaigns, IOCs, reports (GraphQL API) | HTTP 8080 |
| **Arkime** | Full packet capture retrieval by community ID | HTTPS + Keycloak |
| **Keycloak** | OIDC SSO, user federation, Arkime client_credentials auth | HTTPS |
| **Ollama** | Local LLM for AI chat, alert analysis, briefings (air-gap safe) | HTTP 11434 |
| **GitLab** | Change tracking integration | HTTPS |
| **Nginx** | Optional reverse proxy -- TLS termination, rate limiting, security headers | HTTPS 443 |

---

## Data Flow: Alert Lifecycle

```
  Elasticsearch               ION                          Kibana
  +-----------+         +-------------+              +-------------+
  |           |  poll   |             |    sync       |             |
  | Security  +-------->| Alert Queue +------------->| Kibana Case |
  | Alerts    |         |             |    (bi-dir)   |             |
  +-----------+         +------+------+              +-------------+
                               |
                    triage (ack/escalate/close)
                               |
                        +------+------+
                        |    Case     |
                        | Management  |
                        +------+------+
                               |
             +-----------------+-----------------+
             |                 |                 |
      +------+------+  +------+------+  +-------+-----+
      | Observables |  | Playbook    |  | Forensics   |
      | (IOC track) |  | Execution   |  | Pipeline    |
      +------+------+  +-------------+  +------+------+
             |                                  |
      +------+------+                   +-------+-----+
      |  Enrichment |                   |   Arkime    |
      | OpenCTI, VT |                   | PCAP fetch  |
      | Shodan, GN  |                   +-------------+
      +-------------+
```

### Flow Steps

1. **Ingestion** -- ION polls Elasticsearch for security alerts matching configured index patterns. Alerts are normalised to ECS format.
2. **Triage** -- Analysts review alerts in the queue. Triage suggestions recommend FP/TP based on historical closure patterns. The auto-investigation queue can process alerts automatically via LLM.
3. **Case Creation** -- Escalated alerts become cases. Cases sync bidirectionally with Kibana cases (status, assignee, comments).
4. **Investigation** -- Analysts attach observables (IPs, hashes, domains), enrich via OpenCTI/VirusTotal/Shodan/GreyNoise, build entity timelines, and correlate with attack stories.
5. **Response** -- Playbook execution guides step-by-step response. Automated actions (block IP, disable account, quarantine host) can fire with approval. Forensic pipeline handles evidence chain of custody.
6. **PCAP Retrieval** -- For network-based alerts, ION fetches full packet captures from Arkime by community ID, authenticating via Keycloak client_credentials.
7. **Closure** -- Cases are closed with a reason (true positive, false positive, etc.). Closure data feeds triage suggestions for future alerts.

---

## Service Layer

ION's business logic lives in `src/ion/services/` (80+ modules). Key services:

### Integration Services

| Service | File | Purpose |
|---------|------|---------|
| `ElasticsearchService` | `elasticsearch_service.py` | Alert polling, search, triage state, user profile resolution, alert rollups |
| `TideService` | `tide_service.py` | TIDE SQL query proxy, rule analytics, MITRE coverage |
| `TideSyncService` | `tide_sync_service.py` | Background sync of TIDE data snapshots into PostgreSQL |
| `OpenCTIService` | `opencti_service.py` | GraphQL client for threat actors, campaigns, IOCs, reports |
| `ArkimeService` | `arkime_service.py` | PCAP download by community ID, Keycloak client_credentials auth |
| `KibanaCasesService` | `kibana_cases_service.py` | Bidirectional case sync with Kibana |
| `KibanaSyncService` | `kibana_sync_service.py` | Background loop for continuous Kibana case sync |
| `OllamaService` | `ollama_service.py` | LLM chat, streaming, model management |
| `GitlabService` | `gitlab_service.py` | GitLab API client for change tracking |
| `VirusTotal/Shodan` | `virustotal_service.py`, `shodan_service.py` | Observable enrichment providers (AbuseIPDB enrichment via `web/enrichment_api.py`) |
| `DFIRIrisService` | `dfir_iris_service.py` | Case escalation to an external DFIR-IRIS platform |

### Investigation Services

| Service | File | Purpose |
|---------|------|---------|
| `InvestigationService` | `investigation_service.py` | Auto-investigation queue, LLM-driven alert analysis |
| `AttackStoryService` | `attack_story_service.py` | Multi-step attack narrative correlation |
| `AttackPathService` | `attack_path_service.py` | Bob Pathfinding — per-case directed kill-chain graph with MITRE reachability scoring (Case Detail attack-path tab) |
| `CaseSimilarityService` | `case_similarity_service.py` | Find similar past cases by rules, hosts, observables |
| `TriageSuggestionService` | `triage_suggestion_service.py` | Historical FP/TP suggestions |
| `EntityTimelineService` | `entity_timeline_service.py` | Unified cross-source timeline for hosts/IPs/users |
| `CaseGrouperService` | `case_grouper_service.py` | Automated alert clustering into case groups |
| `ObservableService` | `observable_service.py` | IOC lifecycle, enrichment orchestration |
| `InvestigationMemoryService` | `investigation_memory_service.py` | Persistent investigation context for AI |

### Operations Services

| Service | File | Purpose |
|---------|------|---------|
| `AnalyticsEngine` | `analytics_engine.py` | 6 automated jobs: risk scoring, repeat offenders, rule noise, case metrics |
| `BriefingService` | `briefing_service.py` | AI-generated daily threat and operations briefing |
| `ShiftHandoverService` | `shift_handover_service.py` | End-of-shift report generation |
| `SchedulerService` | `scheduler_service.py` | Cron-based background job scheduling |
| `NetworkMapperService` | `network_mapper_service.py` | Automated network asset discovery |
| `SLAService` | `sla_service.py` | Response time targets and compliance tracking |
| `PlaybookExecutorService` | `playbook_executor_service.py` | Step-by-step playbook execution engine |
| `PlaybookActionService` | `playbook_action_service.py` | Automated response actions (block, quarantine, etc.) |

### Reporting Services

| Service | File | Purpose |
|---------|------|---------|
| `SOCHealthService` | `soc_health_service.py` | 5-dimension maturity scorecard |
| `ExecutiveReportService` | `executive_report_service.py` | PDF/HTML executive report generation |
| `AnalystEfficiencyService` | `analyst_efficiency_service.py` | Per-analyst MTTR, FP rates |
| `ComplianceMappingService` | `compliance_mapping_service.py` | Multi-framework compliance mapping |
| `MaturityService` | `maturity_service.py` | SOC-CMM maturity assessment |
| `ReportSchedulerService` | `report_scheduler_service.py` | Scheduled report generation |

### AI Services

| Service | File | Purpose |
|---------|------|---------|
| `AIChatService` | `ai_chat_service.py` | Chat session management, context injection |
| `AIContextService` | `ai_context_service.py` | Contextual data gathering for AI prompts |
| `AIDocumentService` | `ai_document_service.py` | AI-assisted document generation |
| `AlertPromptService` | `alert_prompt_service.py` | Pre-built prompt templates for alert types |
| `PIIAnonService` | `pii_anon_service.py` | PII detection and anonymisation |

### Detection Engineering module & optional server modes

The optional **Detection Engineering (DE) module** adds read-and-review services (`de_service`, `de_proposal_service`, `de_quirk_service`, `de_bob_service` / `de_bob_proposal_service`) covering DE Metrics / Noise Campaigns, Detection Proposals, the System Quirks register, and a Bob improvement loop — gated by the `de:read` / `de:propose` / `de:verify` / `de:approve` permissions. Two optional server modes ship off by default: an **MCP server** (`mcp_api.py`, `POST /api/mcp`, `ION_MCP_ENABLED`) exposing core SOC data as MCP tools, and **observability** (`metrics_api.py` Prometheus `/metrics` + `core/apm.py` Elastic APM, `ION_METRICS_ENABLED` / `ION_APM_ENABLED`). See [`HLD.md`](HLD.md) / [`LLD.md`](LLD.md) for the full data model and sequence detail rather than duplicating it here.

---

## Database Schema

PostgreSQL is the primary data store. The schema is defined via SQLAlchemy models in `src/ion/models/` (35+ modules).

### Core Tables

```
users
  +-- id, username, email, password_hash, display_name, is_active
  +-- keycloak_sub, elastic_username, elastic_uid
  +-- employment_type, failed_login_attempts, locked_until

roles
  +-- id, name, description, is_system

permissions
  +-- id, name, resource, action, description

user_roles          (M:N join -- users <-> roles)
role_permissions    (M:N join -- roles <-> permissions)

user_sessions
  +-- id, user_id, token, active_role_id, expires_at

audit_logs
  +-- id, user_id, action, resource_type, resource_id, details, ip_address
```

### Investigation Tables

```
alert_triage
  +-- id, alert_id, status, severity, assigned_to, notes
  +-- source_system, mitre_technique_id
  +-- created_at, updated_at, closed_at, closure_reason

alert_cases (cases)
  +-- id, title, description, severity, status
  +-- assigned_to_id, kibana_case_id, kibana_case_version
  +-- created_at, updated_at, closed_at

observables
  +-- id, case_id, type, value, source, tlp, confidence
  +-- enrichments (JSON), tags, whitelisted

investigations
  +-- id, alert_id, case_id, status, llm_analysis
  +-- created_at, completed_at

forensic_investigations
  +-- id, title, case_id, status, classification
  +-- evidence_items, custody_log, timeline_events
```

### Detection Engineering Tables

```
tide_snapshots
  +-- id, snapshot_date, rules_count, techniques_covered
  +-- quality_scores (JSON)

cyab_systems
  +-- id, name, namespace, data_sources
  +-- use_case_coverage, alert_rollup_cache
```

### Knowledge & Training Tables

```
knowledge_articles
  +-- id, title, content, category, subcategory
  +-- capability_key, difficulty_level

playbooks
  +-- id, name, category, description, steps (JSON)
  +-- is_active, effectiveness_data

training_scenarios
  +-- id, name, difficulty, role_tier, steps (JSON)

role_assessments
  +-- id, user_id, responses (JSON), scores (JSON)
  +-- recommendations (JSON)
```

### Operations Tables

```
analytics_results
  +-- id, job_type, results (JSON), run_at

scheduled_jobs
  +-- id, name, cron_expression, job_type, config (JSON)
  +-- last_run, next_run, is_enabled

network_assets
  +-- id, hostname, ip_address, asset_type, os
  +-- discovered_at, last_seen

log_sources
  +-- id, name, source_type, status, last_event_at
  +-- expected_interval, volume_stats
```

### Migrations

ION uses an internal migration system in `storage/database.py:_run_migrations()`. Migrations run automatically on startup under a PostgreSQL advisory lock (`LOCK_RUN_MIGRATIONS = 1001`) to prevent races when multiple workers start simultaneously.

New columns are added via `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` statements. The `Base.metadata.create_all()` call handles new tables, but cannot add columns to existing tables -- hence the explicit migrations.

---

## Background Tasks

ION runs several background loops. In multi-worker deployments, exactly ONE worker runs each loop, enforced by PostgreSQL advisory locks with `hold_until_close=True`. The lock-holding connection is pinned for the worker's lifetime.

| Task | Lock ID | Interval | Purpose |
|------|---------|----------|---------|
| Kibana Case Sync | 1010 | 60s | Sync case status/assignee between ION and Kibana |
| TIDE Data Sync | 1011 | 5 min | Snapshot TIDE rule analytics into PostgreSQL |
| Analytics Engine | 1013 | 15 min | Run 6 automated analytics jobs (risk scoring, repeat offenders, etc.) |
| Network Mapper | 1014 | 30 min | Discover network assets via Elasticsearch data |
| Job Scheduler | 1015 | 60s | Execute cron-scheduled jobs (reports, etc.) |
| Investigation Loop | 1016 | 15 min | Process auto-investigation queue via LLM |
| Case Grouper | 1017 | 10 min | Cluster related alerts into case groups |

### Idempotent Seeds (run at startup, lock released after)

| Seed | Lock ID | Purpose |
|------|---------|---------|
| Migrations | 1001 | Schema migrations |
| Permissions | 1002 | RBAC roles and permissions |
| Playbooks | 1003 | Default SOC playbooks |
| SOC Templates | 1004 | Communication templates |
| Knowledge Base | 1005 | KB article seeding |
| Forensic Playbooks | 1006 | DFIR playbook seeding |
| Capability KB | 1007 | Role Match capability articles |
| Skills Snapshot | 1008 | Daily skills snapshot |
| Analytics Jobs | 1009 | Default analytics job config |

### Lock Resilience

- If a worker holding a `hold_until_close` lock crashes, the PostgreSQL connection drops and the lock auto-releases. Another worker can then acquire it on the next startup cycle.
- Same-worker re-acquisition short-circuits via a module-level dictionary (`_pinned_lock_conns`), avoiding redundant lock attempts.

---

## Security Model

### RBAC Architecture

```
User ──M:N──> Role ──M:N──> Permission
                               |
                       (resource:action)
                       e.g. "alert:triage"
                            "case:close"
                            "forensic:create"
```

ION uses a role-based access control system with 10 built-in roles. Each role is a collection of permissions, where each permission is a `resource:action` pair.

### Permission Categories

| Resource | Actions | Description |
|----------|---------|-------------|
| `alert` | `read`, `triage` | View and triage security alerts |
| `case` | `read`, `create`, `update`, `close` | Case management |
| `observable` | `read`, `create`, `update`, `delete`, `enrich` | IOC management |
| `playbook` | `read`, `execute`, `create`, `update`, `delete` | Playbook lifecycle |
| `forensic` | `read`, `create`, `update`, `close`, `manage_playbooks` | DFIR investigations |
| `template` | `read`, `create`, `update`, `delete` | Document templates |
| `document` | `read`, `create`, `update`, `delete` | Document management |
| `user` | `read`, `create`, `update`, `delete` | User administration |
| `system` | `audit_view`, `settings` | System administration |
| `integration` | `read`, `manage` | Integration management |
| `security` | `read`, `manage` | Security dashboard |
| `discover` | `read` | Elasticsearch discover/hunting |
| `ai` | `chat` | AI chat access |

### Role Hierarchy

| Role | Tier | Capabilities |
|------|------|-------------|
| `analyst` | L1 (Analyst) | Alert triage, basic cases, playbook execution, AI chat |
| `senior_analyst` | L2 (Analyst) | + case closure, observable enrichment, forensic viewer |
| `principal_analyst` | L3 (Analyst) | + playbook creation, forensic cases, security dashboard |
| `lead` | Management | All analyst perms + full forensic + team oversight |
| `forensic` | Specialist | Full DFIR access, limited case/alert view |
| `soc_engineer` | L1 (Engineering) | Alert triage, integration viewer, tooling support |
| `senior_engineer` | L2 (Engineering) | + detection engineering, integration management, system settings |
| `platform_engineer` | L3 (Engineering) | + full observable/playbook/template lifecycle, security management |
| `engineering` | Engineering | Full operational + system management (legacy catch-all) |
| `admin` | Admin | All permissions |

### Focus Mode

Users can hold multiple roles simultaneously. The **Focus Mode** feature allows a user to activate a single role at a time, restricting their permissions to that role's set. This is stored in `UserSession.active_role_id` and toggled via `POST /api/auth/focus-mode`.

The UI presents role pills on the dashboard and a dropdown in the user menu for quick switching.

### Authentication Flow

```
Browser                    ION                      Keycloak
  |                         |                          |
  |--- GET /login --------->|                          |
  |<-- login page ----------|                          |
  |                         |                          |
  |  (Session auth)         |                          |
  |--- POST /api/auth ----->|                          |
  |    username + password  |-- bcrypt verify -------->|
  |<-- Set-Cookie: session  |                          |
  |                         |                          |
  |  (OIDC auth)            |                          |
  |--- GET /auth/oidc ----->|--- redirect ------------>|
  |                         |                          |
  |<-- redirect to KC ------|                          |
  |--- authenticate ------->|                          |
  |<-- redirect + code -----|                          |
  |--- GET /auth/callback ->|--- exchange code ------->|
  |                         |<-- JWT (access token) ---|
  |                         |-- validate + map roles ->|
  |<-- Set-Cookie: session  |                          |
```

### Security Middleware

ION applies multiple security layers:

- **SecurityHeadersMiddleware** -- CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **RateLimitSecurityMiddleware** -- Per-endpoint rate limiting via slowapi
- **SecurityMonitoringMiddleware** -- Failed login detection, suspicious activity logging
- **RequestLoggingMiddleware** -- Structured access logging with timing

### API Documentation

API docs (`/docs`, `/redoc`, `/openapi.json`) are disabled by default in production. Enable with `ION_DEBUG_MODE=true` for development only.

---

## API Layer

ION's API is composed of 60+ FastAPI router modules mounted in `server.py`. All routes are prefixed with `/api/` except page routes which return HTML.

### Router Organisation

| Router | Prefix | Purpose |
|--------|--------|---------|
| `api.py` | `/api/` | Core: auth, alerts, cases, users, health |
| `observable_api.py` | `/api/` | Observables CRUD and enrichment |
| `ai_api.py` | `/api/ai/` | AI chat sessions and streaming |
| `forensics_api.py` | `/api/forensics/` | DFIR investigations |
| `threat_intel_api.py` | `/api/threat-intel/` | OpenCTI threat intelligence |
| `integration_api.py` | `/api/integrations/` | ES, Kibana, TIDE status and metrics |
| `cyab_api.py` | `/api/cyab/` | Cyber Assurance Board systems |
| `compliance_api.py` | `/api/compliance/` | Multi-framework compliance |
| `soc_health_api.py` | `/api/soc-health/` | SOC health scorecard |
| `network_map_api.py` | `/api/network-map/` | Network asset management |
| `arkime_api.py` | `/api/arkime/` | PCAP retrieval via Arkime |

### Performance

- **orjson** -- All JSON responses use orjson for 5-10x faster serialisation
- **selectinload** -- SQLAlchemy eager loading to eliminate N+1 queries
- **Advisory locks** -- Prevent duplicate background work across workers
- **Connection pooling** -- SQLAlchemy pool sized to PostgreSQL `max_connections` / worker count
- **Circuit breaker** -- External service calls wrapped in circuit breaker pattern (`core/circuit_breaker.py`)

---

## Frontend

ION uses server-rendered HTML via Jinja2 templates with Tailwind CSS for styling. There is no SPA framework -- pages are full HTML documents with vanilla JavaScript for interactivity.

### Template Structure

- `base.html` -- Base layout with navigation, Geist font, ion-* colour palette
- `_components.html` -- Reusable Tailwind component macros (buttons, cards, badges, modals)
- `_icons.html` -- SVG icon macros
- 66 page templates covering all features

### Design System

- **Font:** Geist (sans-serif)
- **Palette:** `ion-*` custom colours via Tailwind config
- **Components:** Macro-based (`_components.html`) for consistent styling
- **Legacy:** `style.css` is frozen -- all new UI uses Tailwind utilities only

---

## Deployment Topology

### Minimal (Development)

```
Host machine
  +-- ION (uvicorn, 1 worker, SQLite)
  +-- Elasticsearch (Docker or remote)
```

### Standard (Production)

```
Docker Compose
  +-- ion-postgres (PostgreSQL 16)
  +-- ion (4 workers)
  +-- ion-seeder (one-shot)

External
  +-- Elasticsearch cluster
  +-- Kibana
  +-- Keycloak (optional)
  +-- Ollama (optional, or use --profile ai)
```

### Full Stack

```
Docker Compose
  +-- ion-postgres
  +-- ion (4 workers)
  +-- ion-seeder
  +-- ion-ollama (--profile ai)
  +-- nginx (TLS termination)

External
  +-- Elasticsearch cluster (3+ nodes)
  +-- Kibana
  +-- TIDE (DuckDB + FastAPI)
  +-- OpenCTI
  +-- Arkime (full PCAP)
  +-- Keycloak
  +-- GitLab
```
