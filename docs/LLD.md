<!-- ion-doc:type=LOW-LEVEL DESIGN -->
<!-- ion-doc:title=ION Low-Level Design -->
<!-- ion-doc:subtitle=Modules, data model, API surface, services, sequences, and per-feature deep dives -->
<!-- ion-doc:version=0.29.1 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Engineers, integrators, security reviewers needing implementation depth -->
<!-- ion-doc:date=2026-05-12 -->

# 1. Introduction

## 1.1 Purpose

This Low-Level Design (LLD) gives the implementation-depth view of ION. It is the companion to `docs/HLD.md`; the HLD establishes the architectural envelope, the LLD shows how each layer is realised in code.

Use this document to:

- onboard a new contributor to a specific subsystem
- security-review a particular feature with implementation context
- diagnose where a behaviour comes from when triaging an issue
- plan a refactor or extension without re-reading the whole repo

## 1.2 Scope

In scope: code organisation, data model entity map, router catalogue, service catalogue, key sequence diagrams, per-feature deep dives, error handling, configuration.

Out of scope: every endpoint, every model field. Where a field-level detail matters, the LLD points to the source file rather than reproducing it.

## 1.3 Related documents

| Document | Purpose |
|---|---|
| `docs/HLD.md` | Architectural envelope |
| `docs/ARCHITECTURE.md` | Original technical reference |
| `docs/DEVELOPMENT_LIFECYCLE.md` | SDLC, secure-by-design process |
| `docs/DEPLOYMENT.md` | Operator deployment guide |
| `docs/RUNBOOK.md` | Operator runbook |
| `docs/AI_OUTPUT_CONTRACT.md` | Bob's structured output contract |
| `STACK.md` | Env-var catalogue |

# 2. Code organisation

## 2.1 Top-level layout

```
src/ion/
├── __init__.py          # __version__  (load-bearing for {{ ion_version }})
├── auth/                # auth context, OIDC, password, RBAC decorators
├── cli/                 # CLI entry points (seeders, admin)
├── core/                # config, db session, app factory, middleware
├── data/                # bundled snapshots (ATT&CK, KEV, seed data)
├── diff/                # diff helpers
├── engine/              # rule + correlation engine
├── models/              # SQLAlchemy ORM (48 modules)
├── plugins/             # opt-in feature plugins
├── services/            # business logic (122 modules)
├── storage/             # file storage abstraction
└── web/                 # FastAPI routers (73), templates (80), static
```

## 2.2 The 4 layers and where each lives

| Layer | Path | Count |
|---|---|---|
| Presentation | `src/ion/web/templates/`, `src/ion/web/static/` | 80 templates, single static tree |
| HTTP / routing | `src/ion/web/*.py` (one router per concern) | 73 routers |
| Service / domain | `src/ion/services/*.py` | 122 services |
| Data / ORM | `src/ion/models/*.py` | 48 model modules |

## 2.3 Naming convention

- Router files: `<concern>_api.py` (e.g. `case_grouper_api.py`).
- Service files: `<concern>_service.py` (e.g. `case_pin_service.py`).
- Model files: noun (`forensics.py`, `playbook.py`).
- Templates: `<surface>.html` plus partials `_<partial>.html`.
- Tests: `tests/test_<concern>.py`.

## 2.4 Router mount pattern

Every router is mounted in `src/ion/web/server.py` with a `prefix=...`:

```python
app.include_router(case_router, prefix="/api/cases")
```

Route decorators inside the router file MUST use relative paths (e.g. `@router.get("/{case_id}")`) or the prefix doubles up — see the `project_ion_router_prefixes.md` memory rule.

# 3. Data model

## 3.1 Entity catalogue (selected)

| Domain | Key entity | Source | Notes |
|---|---|---|---|
| Investigation | `Investigation` (AlertCase) | `models/investigation.py` | Top-level case container |
| Investigation | `IOCSighting` | `models/investigation.py` | IOC seen-in-case |
| Forensics | `ForensicCase` | `models/forensics.py` | Parallel deep-dive case |
| Forensics | `EvidenceItem` | `models/forensics.py` | Evidence under chain of custody |
| Forensics | `CustodyLogEntry` | `models/forensics.py` | Chain-of-custody audit row |
| Workbench (alert) | `CaseEvidencePin` | `models/case_evidence.py` | Pinned evidence on AlertCase |
| Workbench (alert) | `CaseEvidenceLedger` | `models/case_evidence.py` | sha256-chained ledger |
| Workbench (forensic) | `ForensicCasePin` | `models/forensic_workbench.py` | Pinned evidence on ForensicCase |
| Workbench (forensic) | `ForensicCaseLedger` | `models/forensic_workbench.py` | sha256-chained ledger |
| Observables | `Observable` | `models/observable.py` | IOCs |
| Alerts | `AlertTriage` | `models/alert_triage.py` | Triage state for an alert |
| AI / Bob | `AlertPromptTemplate` | `models/alert_prompt.py` | Per-rule / per-pattern prompt |
| AI / Bob | `AIFeedback` | `models/ai_feedback.py` | Bob verdict ledger |
| AI / Bob | `BobEval*` | `models/bob_eval.py` | Eval harness data |
| AI / Bob | `CaseEmbedding` | `models/case_embedding.py` | pgvector embedding |
| Playbooks | `PlaybookAction` | `models/sla.py` | Playbook step definition |
| Playbooks | `PlaybookActionLog` | `models/sla.py` | Execution record |
| Auth | `User`, `Role`, `Permission`, `RolePermission` | `models/security.py`, `models/user.py` | 7-tier RBAC |
| Audit | `AuditLog` | `models/security.py` | Per-request mutation row |
| Settings | `Settings` | `models/security.py` | Per-deployment configuration |
| Curriculum | `Course`, `Lesson`, `Quiz`, `Lab`, `Module` | `models/course.py` | L1/L2/L3 learning |
| CyAB | `CyABPillar`, `CyABSubprofile`, `CyABAssessment` | `models/cyab.py` | Maturity framework |

## 3.2 Investigation (AlertCase) — selected fields

| Field | Type | Notes |
|---|---|---|
| `id` | int | PK |
| `title` | str | Analyst-given |
| `status` | enum | open / investigating / closed |
| `priority` | enum | low / medium / high / critical |
| `closure_reason` | enum (`CaseClosureReason`) | Bound to AI output contract |
| `alerts` | JSONB | Alert IDs the case covers |
| `affected_hosts` | JSONB | Hostnames |
| `affected_users` | JSONB | Usernames |
| `mitre_techniques` | JSONB | Linked techniques |
| `created_at`, `updated_at` | timestamp | TimestampMixin |
| `assignee_id` | FK -> users | RBAC-driven assignment |
| `ledger_head_hash` | str | Workbench tamper-evident pointer |

## 3.3 CaseEvidencePin + CaseEvidenceLedger

The Workbench (v0.20.0) introduced the pinned-evidence + tamper-evident-ledger pattern. Every pin operation produces:

1. A `CaseEvidencePin` row (the pinned thing — alert, observable, query, note, file, …).
2. A `CaseEvidenceLedger` row whose `event_hash = sha256(prev_hash || event_payload)`.

Tamper detection is a single SQL pass: walk the ledger by insertion order, recompute each event_hash, fail if any doesn't match.

The advisory-lock namespace for the AlertCase workbench is `CEVL` (Case EVidence Ledger). ForensicCase uses `FCWL` (Forensic Case Workbench Ledger) to avoid cross-namespace collisions.

## 3.4 Pydantic schema layer

Each surface has its own request + response Pydantic models in the router file. The pattern is:

- `*Create` for POST bodies
- `*Update` for PUT/PATCH bodies (`model_config = ConfigDict(extra='forbid')`)
- `*Out` for response bodies
- `*Summary` for list-endpoint responses (smaller projection)

# 4. HTTP routing layer

## 4.1 Router catalogue (grouped)

| Group | Routers | Notes |
|---|---|---|
| Core API | `api.py` | Root catch-all + health |
| Auth + security | `security_api.py`, `admin_api.py` | Login, sessions, users, roles |
| Cases (AlertCase) | `investigation_api.py`, `case_grouper_api.py`, `case_similarity_api.py` | |
| Forensics | `forensics_api.py`, `forensic_workbench_api.py` | |
| Observables | `enrichment_api.py`, `ioc_staleness_api.py` | |
| AI / Bob | `ai_api.py`, `bob_analysis_api.py`, `bob_eval_api.py`, `alert_prompt_api.py` | |
| Threat intel | `threat_intel_api.py`, `threat_landscape_api.py`, `attack_story_api.py` | |
| Detection eng | `tide_api.py`, `engineering_analytics_api.py`, `compliance_api.py`, `d3fend_api.py` | |
| Operations | `analyst_efficiency_api.py`, `soc_health_api.py`, `daily_standup_api.py`, `shift_handover_api.py`, `briefing_api.py` | |
| Playbooks | `playbook_api.py`, `automation_api.py` | |
| PCAP / Arkime | `arkime_api.py`, `pcap_api.py` | |
| CyAB | `cyab_api.py` | |
| Curriculum | `course_api.py`, `cyber_range_api.py` | |
| Knowledge | `notes_api.py`, `comm_template_api.py`, `kb_api.py` | |
| Misc | `wallboard_api.py`, `translator_api.py`, `social_api.py` | |

## 4.2 Endpoint-level patterns

```python
# canonical endpoint signature
@router.post("/{case_id}/pins", response_model=PinOut)
@permission_required("case:pin")
def pin_create(
    case_id: int,
    body: PinCreate,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    return case_pin_service.create_pin(db, auth, case_id, body)
```

Three things are always true:

1. The endpoint is decorated with `@permission_required(...)`.
2. The service is called with the `auth` context, not just the user id.
3. The service re-checks auth internally before mutating (`feedback_service_check_before_commit.md`).

# 5. Service layer

## 5.1 Service catalogue (selected)

| Service | Responsibility |
|---|---|
| `case_pin_service` | Workbench pin lifecycle on AlertCase |
| `case_ledger_service` | sha256-chained ledger on AlertCase |
| `forensic_workbench_service` | Workbench pin lifecycle on ForensicCase |
| `forensic_annotation_service` | Forensic case annotations (v0.22.0 timeline) |
| `case_similarity_service` | pgvector-backed similar-case lookup |
| `case_embedding_service` | Background embedding generation (Ollama `nomic-embed-text`) |
| `case_grouper_service` | Automated alert correlation into cases |
| `bob_prompt_service` | 5-tier matcher (rule_id → regex → MITRE technique → tactic → groups) |
| `bob_eval_service` | Offline replay of Bob against historical alerts (v0.21.0) |
| `pcap_analysis_service` | Arkime PCAP retrieval + heuristic analysis |
| `arkime_service` | Arkime API adapter; community_id + IP fallback |
| `elasticsearch_service` | ES Security adapter; alert pull + workflow status sync |
| `tide_*_service` | TIDE adapter; rule sync; coverage analysis |
| `threat_intel_*_service` | OpenCTI adapter; threat landscape, actors, IOCs |
| `playbook_service` | Playbook lifecycle + action execution |
| `compliance_mapping_service` | TIDE rule → framework (NIST/ISO/Essential8) mapping |
| `cyab_*_service` | CyAB pillar, sub-profile, assessment lifecycle |
| `course_service` | Curriculum lifecycle (modules, lessons, labs, quizzes) |

## 5.2 Service-internal auth pattern

```python
def update_case(db: Session, auth: AuthContext, case_id: int, body: CaseUpdate):
    case = db.get(Investigation, case_id)
    if not case:
        raise NotFound("case")
    # Service-internal auth check (defence-in-depth):
    if not auth.can("case:update") or not _owns_or_lead(case, auth):
        raise Forbidden("case:update")
    # ...mutate...
```

The pattern was introduced after a v0.20.1 TOCTOU bug. See `feedback_service_check_before_commit.md` for the rationale.

# 6. Background tasks

## 6.1 Advisory-lock pattern

```python
# pseudocode
LOCK_NS = 0x434556  # "CEVL"
LOCK_KEY = case_id  # per-case lock

with db.begin():
    got = db.scalar(text("SELECT pg_try_advisory_xact_lock(:ns, :k)"),
                    {"ns": LOCK_NS, "k": LOCK_KEY})
    if not got:
        return  # someone else is processing this case
    # ...do work...
```

Lock namespaces:

| Namespace | Purpose | ASCII tag |
|---|---|---|
| 0x434556 | AlertCase workbench ledger | `CEV` |
| 0x4643574c | ForensicCase workbench ledger | `FCWL` |
| 0x434559 | Case embedding generation | `CEY` |
| 0x42434b | Bob (case-close) AI feedback | `BCK` |
| 0x504341 | PCAP auto-analysis runner | `PCA` |
| 0x434750 | Case grouper periodic | `CGP` |

Each background runner is invoked from FastAPI's `BackgroundTasks` or from a periodic kick-off in a worker module. Workers run in the same process as the web app (no separate Celery process).

## 6.2 Periodic runners

| Runner | Cadence | Lock | Service |
|---|---|---|---|
| Case embedding backfill | every 30s | `CEY` | `case_embedding_service` |
| Bob case-close AI feedback dedup | on case-close + every 60s | `BCK` | `ai_feedback_service` |
| PCAP auto-analysis | on case-create + retry | `PCA` | `pcap_analysis_service` |
| Case grouper | every 5 min | `CGP` | `case_grouper_service` |
| Alert workflow sync | every 30s | per-source | `elasticsearch_service` |
| Bob eval (admin-triggered) | on-demand | per template | `bob_eval_service` |

# 7. AI subsystem (Bob)

## 7.1 Surface map

```
Alert arrives ─┐
               │
               ▼
   ┌────────────────────────────────────────────────────┐
   │ bob_prompt_service.choose_template(alert)          │
   │  • 5-tier matcher:                                 │
   │    1) rule_id direct                               │
   │    2) regex over rule_name                         │
   │    3) MITRE technique                              │
   │    4) MITRE tactic                                 │
   │    5) "groups" fallback                            │
   └─────────────────────┬──────────────────────────────┘
                         │
                         ▼
   ┌────────────────────────────────────────────────────┐
   │ bob_analysis_service.run(alert, template)          │
   │  • renders prompt with alert context               │
   │  • calls Ollama with strict output schema          │
   │  • validates against AlertPromptOutput Pydantic    │
   │  • stores in AIFeedback (case-close-time dual-     │
   │    write; dedup via MAX(id) per (alert, template)) │
   │  • emits audit_log row                             │
   └────────────────────────────────────────────────────┘
```

## 7.2 Output contract

Bob's output schema is the **load-bearing** safety boundary. Defined in `docs/AI_OUTPUT_CONTRACT.md` and pinned to `CaseClosureReason`. Arbitrary free-form text is refused.

```python
class AlertPromptOutput(BaseModel):
    verdict: CaseClosureReason  # enum, not str
    confidence: int             # 0..100
    confidence_band: Literal["low", "medium", "high"]
    reasoning_text: str         # explanatory, advisory
    suggested_next_steps: list[str]
    iocs_extracted: list[ObservableSpec]
```

## 7.3 Eval harness

`services/bob_eval_service.py` replays a live prompt template against historical alerts:

1. Picks a sample of alerts that match the template (per the 5-tier matcher).
2. For each: re-runs Bob, compares verdict + confidence with the ground-truth `CaseClosureReason` from the closed case.
3. Computes precision / recall / F1 per template.
4. Hard-blocks if an investigation loop is active for the template (advisory lock + safety check).

# 8. Authentication + authorisation

## 8.1 Login flow (local password)

```
[Browser] --POST /api/security/login--> [security_api]
                                           │
                                           ▼
                                    [bcrypt verify]
                                           │
                                           ▼
                                    [slowapi rate-limit check]
                                           │
                                           ▼
                                    [session created]
                                           │
                                           ▼
[Browser] <--Set-Cookie: ion_session; Secure; HttpOnly; SameSite=Lax--
```

## 8.2 Login flow (OIDC)

```
[Browser] -- /api/security/oidc/start --> [security_api]
                                           │
                                           │   redirect to Keycloak
                                           ▼
[Browser] <--302--> [Keycloak] (user auths)
                                           │
                                           ▼
[Browser] -- /api/security/oidc/callback?code=... --> [security_api]
                                           │
                                           ▼
                                    [JWT verify with JWKS, RS256 only]
                                           │
                                           ▼
                                    [user upsert, session created]
```

RS256 only; HS256 is explicitly refused. JWKS is cached and auto-refreshed.

## 8.3 RBAC enforcement

Two places:

1. **Endpoint decorator** — `@permission_required("case:update")` reads from `Permission` + `RolePermission` tables.
2. **Service entry** — every state-mutating service call re-checks the auth context. This is the TOCTOU defence-in-depth.

# 9. Audit + ledger

## 9.1 Audit log middleware

Every request that mutates state passes through a middleware that:

1. Captures `user_id`, `ip`, `method`, `path`, `request_id`.
2. After the handler returns 2xx, writes an `AuditLog` row with `action` + `target` + `outcome`.
3. Emits the same structured row to stdout (ECS shape).

## 9.2 Workbench ledger

Two parallel ledger tables:

- `CaseEvidenceLedger` — for AlertCase Workbench
- `ForensicCaseLedger` — for ForensicCase Workbench

Each insertion computes:

```python
event_hash = sha256(
    (prev_hash or b"").encode()
    + json.dumps(event_payload, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
```

Tamper detection job (read-only): walk by insertion order, recompute, compare. A single mismatch flags the chain.

# 10. Per-feature deep dives

## 10.1 Alert ingestion → case open

```
[ES Security]
     │
     │ pulled by elasticsearch_service every 30s
     ▼
[ION alerts cache]
     │
     ▼
[case_grouper_service] (every 5 min, advisory lock CGP)
     │
     │ correlates alerts by host/user/technique/timewindow
     ▼
[Investigation.create()]
     │
     │ triggers chain:
     │  • case_embedding_service.queue_for_embedding(case)
     │  • pcap_analysis_service.queue_if_pcap_relevant(alerts)
     │  • bob_prompt_service.choose_template + run for each alert
     ▼
[Case landing page]
```

## 10.2 PCAP auto-analysis (v0.29.1 IP-fallback)

```
case_create event
     │
     ▼
pcap_analysis_service._build_pcap_flows(case)
     │
     │  for each alert:
     │   • extract community_id (preferred)
     │   • extract source.ip + destination.ip + @timestamp
     │   • build {community_id, src_ip, dst_ip, ts, alert_id, node_hint}
     ▼
pcap_analysis_service._runner(flows)  (advisory lock PCA)
     │
     ▼
pcap_analysis_service._analyze_one(flow)
     │
     │  1) try arkime_service.find_sessions_by_community_id
     │  2) if empty AND ip available:
     │       arkime_service.find_sessions_by_ip(ts=anchor)
     │       record search_mode="ip_time" + fallback_warning
     │  3) arkime_service.download_pcap(node, session_id)
     │  4) heuristic analysis (12 detectors)
     │
     ▼
[Case comment with PCAP findings + ⚠️ fallback warning if applicable]
```

## 10.3 Bob verdict at case-close

```
[Analyst clicks Close Case]
     │
     ▼
[investigation_api.close_case]
     │
     │  • dual-write AIFeedback row (fire-time + close-time)
     │  • dedup uses MAX(id) per (alert_id, template_id)
     │  • compute confidence band; if low, circuit-breaker badge
     │  • emit audit_log
     ▼
[CaseEvidenceLedger.append] (advisory lock CEV)
     │
     ▼
[case state: closed; closure_reason: <selected enum>]
```

## 10.4 Workbench pin lifecycle

```
[Analyst clicks Pin]
     │
     ▼
[forensic_workbench_api / case_pin_api]
     │
     │  • permission check (endpoint decorator)
     │  • service auth re-check
     │  • advisory lock acquire (CEVL or FCWL)
     │
     ▼
[CaseEvidencePin INSERT]
     │
     ▼
[CaseEvidenceLedger INSERT with sha256 chain]
     │
     ▼
[advisory lock release; commit]
     │
     ▼
[Workbench UI refresh; ledger badge ticks up]
```

## 10.5 Case similarity (pgvector)

```
[Case Detail page request]
     │
     ▼
[case_similarity_service.find_similar(case_id, k=5)]
     │
     │  • load this case's embedding from CaseEmbedding
     │  • HNSW <-> nearest-neighbours query
     │  • filter by RBAC (must can("case:read"))
     │
     ▼
[Sidebar: 5 similar past cases with similarity score]
```

## 10.6 Bob prompt 5-tier matcher

```python
def choose_template(alert) -> AlertPromptTemplate | None:
    # Tier 1: exact rule_id match
    if t := find_by_rule_id(alert.rule_id): return t
    # Tier 2: regex over rule_name
    if t := find_by_rule_name_regex(alert.rule_name): return t
    # Tier 3: MITRE technique
    if t := find_by_technique(alert.mitre_techniques): return t
    # Tier 4: MITRE tactic
    if t := find_by_tactic(alert.mitre_tactic): return t
    # Tier 5: groups fallback
    if t := find_by_groups(alert.rule_groups): return t
    return None  # Bob abstains
```

Templates are seeded from `data/alert_prompts/*.json` (54 seeded as of v0.17, including 4 ESXi v17 templates). An admin can override `confidence_threshold_override` per template via `/alert-prompts`.

## 10.7 Playbook approval gate

```
[Analyst clicks Run Playbook Action]
     │
     ▼
[playbook_api.execute_action]
     │
     │  • lookup PlaybookAction.requires_approval (default true)
     │  • if true: enqueue ApprovalRequest, return 202
     │  • approver reviews + approves
     │  • only then: integration adapter called
     │
     ▼
[integration adapter] (firewall / AD / EDR / email_gateway / DNS)
     │
     ▼
[PlaybookActionLog INSERT with executor + approver attribution]
```

# 11. Error handling

## 11.1 Exception hierarchy

| Exception | HTTP | When |
|---|---|---|
| `NotFound` | 404 | entity missing |
| `Forbidden` | 403 | RBAC denied |
| `Conflict` | 409 | state-machine violation; advisory lock held |
| `ValidationError` (Pydantic) | 422 | bad input |
| `IntegrationUnavailable` | 502 | external system down |
| `RateLimited` | 429 | slowapi throttle |
| `Unauthorized` | 401 | session missing / expired |

All unhandled exceptions go to a global handler that logs the full traceback to stdout (ECS shape) and returns 500 with a request_id the analyst can quote.

## 11.2 Integration failure behaviour

ION never blocks core analyst workflow on an integration outage. Each integration adapter follows the pattern:

1. Configurable timeout + retry (`ION_<INTEG>_TIMEOUT_S`, `ION_<INTEG>_RETRY`).
2. On exhaustion: raise `IntegrationUnavailable`.
3. Caller catches; surfaces "integration unavailable" UI banner.
4. Core surfaces (alerts, cases, workbench) continue to function.

# 12. Configuration

## 12.1 Configuration surface

Two layers:

1. **Environment variables** — image-bound (URLs, credentials, feature flags). Catalogued in `STACK.md`.
2. **`Settings` table** — runtime-mutable per-deployment (slow-query threshold, pool size, Bob confidence override, …). Edited via `/settings` admin UI.

## 12.2 Critical env vars

| Variable | Default | Purpose |
|---|---|---|
| `ION_VERSION` | (must match `__version__`) | UI display |
| `DATABASE_URL` | (required) | Postgres connection |
| `ION_SECRET_KEY` | (required, 32+ bytes) | Session signing |
| `ION_OIDC_*` | unset | OIDC config; falls back to local password |
| `ION_OLLAMA_URL` | unset | Bob enable; unset disables Bob |
| `ION_ES_URL` + `ION_ES_API_KEY` | unset | ES Security adapter |
| `ION_TIDE_URL` + `ION_TIDE_API_KEY` | unset | TIDE adapter |
| `ION_OPENCTI_URL` + `ION_OPENCTI_API_KEY` | unset | OpenCTI adapter |
| `ION_ARKIME_URL` + `ION_ARKIME_AUTH` | unset | Arkime adapter |
| `ION_PII_ANON_ENABLED` | `false` | Optional PII anonymisation |
| `ION_BOB_STORE_REASONING` | `true` | Persist Bob's reasoning_text |
| `ION_FRESH_DB` | (no-op since v0.13) | Historical |

## 12.3 Feature flags

Most features are unconditionally on. Integration enablement is implicit via env-var presence (no separate `*_ENABLED` flag — if the URL is set, the adapter is used).

# 13. Testing

## 13.1 Test layout

```
tests/
├── conftest.py
├── test_<concern>.py          # per-feature smoke
├── test_<concern>_integration.py
├── test_pii_anon_smoke.py
└── data/                      # fixtures
```

Current state: 380+ tests; 2 known failures (fixture leak in older PII anon tests; tracked in `_backlog_v0_27.md`).

## 13.2 What CI runs

`.github/workflows/test.yml`:

1. `ruff check` — lint
2. `pip-audit --ignore-vuln CVE-2024-23342` — OSV/Pypi advisory (python-jose deferred to PyJWT migration)
3. `bandit -r src/` — static security
4. `syft` SBOM produce
5. `pytest tests/`

# 14. Glossary

(Identical to HLD §12; reproduced once in HLD.)

# 15. Change history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-05-12 | ION maintainer | Initial LLD authored against v0.29.1 |
