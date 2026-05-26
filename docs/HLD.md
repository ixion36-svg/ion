<!-- ion-doc:type=HIGH-LEVEL DESIGN -->
<!-- ion-doc:title=ION High-Level Design -->
<!-- ion-doc:subtitle=Architecture overview, containers, components, and cross-cutting concerns -->
<!-- ion-doc:version=0.29.1 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Architects, security reviewers, integrators, customer due-diligence -->
<!-- ion-doc:date=2026-05-12 -->

# 1. Introduction

## 1.1 Purpose

This High-Level Design (HLD) describes ION at the architecture-overview level. It is the entry-point document for architects, security reviewers, and integrators evaluating ION for deployment. It is deliberately customer-agnostic; customer-specific compliance overlays (e.g. MOD `_mod_*.md`) sit alongside it without modifying its content.

Companion artefacts that deepen each area:

- **LLD** (`docs/LLD.md`) — per-module low-level design, data model, sequences.
- **URD** (`docs/USER_REQUIREMENTS.md`) — numbered user requirements catalogue.
- **RTM** (`docs/TRACEABILITY.md`) — full UR → SR → Design → UC → Gap → Test traceability.
- **Architecture in-tree** (`docs/ARCHITECTURE.md`) — original technical architecture reference.
- **SDLC** (`docs/DEVELOPMENT_LIFECYCLE.md`) — secure development lifecycle.
- **Deployment** (`docs/DEPLOYMENT.md`) — operator deployment instructions.
- **Runbook** (`docs/RUNBOOK.md`) — operator runbook.
- **Security Assessment** (`SECURITY_ASSESSMENT.md`) — per-release severity trend.

## 1.2 Scope

ION is a Security Operations Centre (SOC) analyst workbench. The HLD covers:

- the application boundary and surrounding system context
- the major containers and components
- the data model at the entity level
- the cross-cutting concerns (auth, audit, observability, AI safety, accessibility)
- the deployment envelope (single-instance, scaled, air-gap)
- the integration boundary with the customer's own SOC tooling

Out of scope here (covered in companion docs): code-level structure, sequence diagrams, exhaustive API surface, full data schema.

## 1.3 Stakeholders

| Stakeholder | Concern |
|---|---|
| SOC analyst (L1/L2/L3) | Daily workbench: alerts, cases, threat intel, forensics |
| SOC manager / lead | Posture overview, shift handover, analyst efficiency |
| Detection engineer | Rule lifecycle via TIDE, MITRE coverage, gap analysis |
| Architect / reviewer | Architectural fitness, security posture, integration model |
| Compliance / DPO | Audit trail, data-protection, accessibility |
| Operator / SRE | Deployment, scaling, backup, monitoring |
| Customer security team | Threat surface, dependency risk, SBOM |

# 2. System context

## 2.1 Context diagram (C4 Level 1)

```
                  ┌───────────────────────────────────────────┐
                  │             SOC Analyst                   │
                  │  (browser, HTTPS, RBAC-gated session)     │
                  └─────────────────────┬─────────────────────┘
                                        │
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │                                           │
                  │                  ION                      │
                  │       SOC Analyst Workbench               │
                  │                                           │
                  └───┬────┬────┬────┬────┬────┬────┬─────────┘
                      │    │    │    │    │    │    │
              ┌───────┘    │    │    │    │    │    └────────┐
              ▼            ▼    ▼    ▼    ▼    ▼             ▼
       ┌────────────┐  ┌──────┐ ┌─────┐ ┌────────┐ ┌────────┐ ┌────────┐
       │ Elastic-   │  │TIDE  │ │Kib- │ │OpenCTI │ │Arkime  │ │Ollama  │
       │ search     │  │ Det. │ │ana  │ │ Threat │ │ PCAP   │ │ Local  │
       │ Security   │  │ Eng  │ │Cases│ │  Intel │ │ Capture│ │  LLM   │
       └────────────┘  └──────┘ └─────┘ └────────┘ └────────┘ └────────┘
              ▲
              │
       ┌──────┴───────┐
       │  Customer    │
       │  Keycloak    │
       │  (optional)  │
       └──────────────┘
```

## 2.2 Actors

| Actor | Type | Interaction |
|---|---|---|
| SOC Analyst | Human | Primary user; browser; HTTPS |
| Detection Engineer | Human | Browser; TIDE integration surface |
| SOC Manager | Human | Browser; oversight surfaces |
| Trainer / Learner | Human | Browser; curriculum surface |
| Admin | Human | Browser; admin + settings surface |
| Elasticsearch Security | System | Alert source (read); ION-pulled |
| TIDE | System | Detection-rule lifecycle; bidirectional |
| Kibana | System | Case sync; bidirectional |
| OpenCTI | System | Threat intel; ION-pulled |
| Arkime | System | PCAP retrieval; ION-pulled |
| Ollama | System | LLM inference; ION-pushed |
| Keycloak | System | OIDC SSO (optional); bidirectional |
| Customer SIEM | System | Audit-log ingestion (ECS); ION-pushed via stdout |

## 2.3 Boundaries

ION's process boundary is the single FastAPI application. It owns its own database (Postgres + pgvector) and emits structured logs over stdout. Every other named system in the context diagram is **external** and customer-operated; ION integrates with them by configured URL + credentials, and degrades gracefully when any of them is unavailable.

# 3. Container view (C4 Level 2)

## 3.1 Containers

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Customer Environment                          │
│                                                                     │
│  ┌──────────────┐                                                   │
│  │   Browser    │                                                   │
│  │  (HTTPS)     │                                                   │
│  └──────┬───────┘                                                   │
│         │                                                           │
│         ▼                                                           │
│  ┌──────────────┐    ┌───────────────────────────────────────┐      │
│  │   Reverse    │    │              ION container             │      │
│  │   Proxy /    │───▶│  ┌─────────────────────────────────┐  │      │
│  │  TLS termin. │    │  │       FastAPI + Jinja2 +        │  │      │
│  └──────────────┘    │  │       SQLAlchemy + uvicorn      │  │      │
│                      │  │       (4 workers)               │  │      │
│                      │  │                                 │  │      │
│                      │  │   - 73 routers                  │  │      │
│                      │  │   - 122 services                │  │      │
│                      │  │   - 80 templates                │  │      │
│                      │  │   - background advisory locks   │  │      │
│                      │  └─────────────────────────────────┘  │      │
│                      │              │                        │      │
│                      └──────────────┼────────────────────────┘      │
│                                     │                               │
│                       SQL           │   stdout (ECS JSON)           │
│                                     │                               │
│           ┌─────────────────────────┼──────────────┐                │
│           ▼                                        ▼                │
│  ┌───────────────────┐                  ┌────────────────────┐     │
│  │  PostgreSQL 16    │                  │  Customer SIEM     │     │
│  │  + pgvector       │                  │  (Splunk/ELK/...)  │     │
│  │  - cases          │                  │  ingests via       │     │
│  │  - audit_logs     │                  │  Filebeat / HEC /  │     │
│  │  - case_ledger    │                  │  Fluentd / syslog  │     │
│  │  - case_embedding │                  └────────────────────┘     │
│  │  - HNSW indexes   │                                              │
│  └───────────────────┘                                              │
│                                                                     │
│  ┌──────────────────────────┐                                       │
│  │   Optional: Ollama       │   ← Bob LLM analyst (decision-support)│
│  │   Local LLM runtime      │                                       │
│  └──────────────────────────┘                                       │
└─────────────────────────────────────────────────────────────────────┘
              │
              │ outbound, optional, per integration
              ▼
   ┌──────────────────────────────────────────┐
   │ ES Security · Kibana · TIDE · OpenCTI ·  │
   │ Arkime · Keycloak                        │
   └──────────────────────────────────────────┘
```

## 3.2 Container responsibilities

| Container | Responsibility | Tech |
|---|---|---|
| ION app | Web application, business logic, integration glue | Python 3.14, FastAPI, Jinja2, SQLAlchemy |
| Postgres | Primary datastore + vector search | PostgreSQL 16 + pgvector |
| Ollama (optional) | Bob LLM inference | Ollama runtime + chosen model |
| Reverse proxy (customer) | TLS termination, HSTS, sticky sessions | nginx / Traefik / customer choice |
| Customer SIEM | Audit-log retention | per customer |

## 3.3 Container interaction

- Browser ↔ ION: HTTPS via reverse proxy; ION listens on `:8000` plain HTTP inside the customer environment.
- ION ↔ Postgres: TCP, parameterised SQL only (SQLAlchemy ORM + advisory locks); connection pool sized via `pool_size` / `pool_overflow` settings.
- ION ↔ Ollama: HTTP, configurable timeout + retry; Bob fails open (returns "no suggestion" rather than blocking the case workflow).
- ION → external integrations: outbound HTTP, per-integration auth (API key / OAuth client_credentials / OIDC); failures are surfaced as "integration unavailable" UI banners rather than 500s.
- ION → SIEM: stdout ECS JSON; the customer's log-shipper picks it up.

# 4. Component view (C4 Level 3, ION app interior)

## 4.1 Layered architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Presentation layer                                              │
│   - Jinja2 templates (80 templates)                             │
│   - Strict CSP, no inline scripts                               │
│   - Vanilla JS, no SPA, no bundler                              │
│   - Tailwind utility classes + ION design system (ds-*)         │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │
┌─────────────────────────────────────────────────────────────────┐
│ HTTP routing layer (Application)                                │
│   - 73 routers in src/ion/web/*.py                              │
│   - prefix-mounted via app.include_router(..., prefix=...)      │
│   - permission decorator on every router endpoint               │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │
┌─────────────────────────────────────────────────────────────────┐
│ Service layer (Domain)                                          │
│   - 122 services in src/ion/services/*.py                       │
│   - service-internal auth checks (TOCTOU defence)               │
│   - advisory-lock-protected background tasks                    │
│   - integration adapters (es/tide/kibana/opencti/arkime/...)    │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │
┌─────────────────────────────────────────────────────────────────┐
│ Data layer (Persistence)                                        │
│   - SQLAlchemy ORM, 48 model modules                            │
│   - alembic migrations                                          │
│   - JSONB for flexible-schema payloads                          │
│   - pgvector + HNSW indexes for similarity                      │
└─────────────────────────────────────────────────────────────────┘
```

## 4.2 Logical components inside the ION app

| Component | Purpose | Lives in |
|---|---|---|
| Auth + RBAC | Login, session, OIDC, permission decorator | `auth/`, `web/security_api.py` |
| Alert ingestion | Pull alerts from ES, normalise, store | `services/elasticsearch_service.py`, `services/alert_*.py` |
| Case management | AlertCase lifecycle, closure, kanban | `models/investigation.py`, `services/case_*.py` |
| Forensic case | ForensicCase lifecycle, evidence chain | `models/forensics.py`, `services/forensic_*.py` |
| Workbench | Pinned evidence + tamper-evident ledger | `services/case_pin_service.py`, `services/case_ledger_service.py` |
| Threat intel | OpenCTI integration, threat landscape, actors, IOCs | `services/threat_intel_*.py`, `web/threat_intel_api.py` |
| Detection eng | TIDE integration, MITRE/D3FEND coverage | `services/tide_*.py`, `web/tide_api.py` |
| Bob (AI analyst) | LLM-backed verdict + reasoning | `services/bob_*.py`, `models/alert_prompt.py` |
| Bob eval harness | Offline replay of Bob against historical alerts | `services/bob_eval_service.py` |
| Playbooks | SOC playbook lifecycle + action execution | `models/sla.py`, `services/playbook_service.py` |
| PCAP analysis | Arkime PCAP retrieval + heuristic analysis | `services/pcap_analysis_service.py`, `services/arkime_service.py` |
| CyAB Studio | Cyber Assurance + Best practice 6-pillar framework | `services/cyab_*.py`, `web/cyab_api.py` |
| Curriculum | L1/L2/L3 courses, labs, SKILL publisher | `models/course.py`, `services/course_service.py` |
| Background workers | Advisory-lock-protected periodic tasks | `services/*_runner.py` |
| Audit + ledger | Audit log + tamper-evident sha256 chain | `models/audit_log`, `case_ledger`, `forensic_case_ledger` |
| Settings | Per-deployment configuration | `models/security.py::Settings` |

## 4.3 Cross-component dependencies (high level)

- Auth + RBAC underpins every other component (defence-in-depth: endpoint AND service-internal).
- Bob depends on Alert ingestion (it needs the alert payload) and Case management (it writes verdicts onto cases).
- Workbench depends on Audit + ledger (pins produce ledger events; ledger produces audit_log rows).
- Playbooks depend on Auth + RBAC for the `requires_approval` gate.

# 5. Architectural decisions

The following load-bearing choices are not negotiable without re-thinking ION's identity. Each is captured here as a one-line decision plus rationale; they are reaffirmed in CHANGELOG history and the SDLC doc.

| # | Decision | Rationale |
|---|---|---|
| AD-01 | Server-rendered Jinja2 only — no SPA, no JS bundler | Reduced client-side attack surface; accessibility-friendly; simpler supply chain; air-gap-friendly |
| AD-02 | Single Postgres for everything (incl. vectors, advisory locks) | One backup story, one HA story, one auth story; pgvector is mature in pg16 |
| AD-03 | Advisory locks instead of Redis/Celery for background work | Removes Redis as a dependency; battle-tested in Postgres for 20+ years |
| AD-04 | Air-gap-first deployment | Defence + critical-infra customers require it; bundled-snapshot pattern for ATT&CK + KEV |
| AD-05 | Tamper-evident sha256 ledger alongside audit_log | Auditability requirement; protects evidence in regulated environments |
| AD-06 | Service-internal auth checks (TOCTOU defence) | Defence-in-depth; a real v0.20.1 bug informed this rule |
| AD-07 | Bob is decision-support, never decision-maker | AI safety; human-in-the-loop on every state mutation |
| AD-08 | RS256 only for OIDC (no HS256) | Asymmetric verification; refuses to accept Keycloak tokens signed with shared-secret |
| AD-09 | Strict CSP, no inline scripts | XSS hardening |
| AD-10 | Customer-agnostic public surface; per-customer overlay docs | ION supports multiple customer environments without polluting the core |
| AD-11 | Two-commit release pattern (feat + chore release) | Release ritual is auditable; CHANGELOG decoupled from feature work |
| AD-12 | 8-file release version bump | All version-bearing files updated atomically; reduces drift |
| AD-13 | §3.4.8 release-acceptance walk | Catches deployment-image bugs CI can't (e.g. file not in `COPY`) |

# 6. Non-functional requirements

## 6.1 Availability

| Target | Value |
|---|---|
| Service availability | 99% monthly, excluding planned maintenance |
| Planned maintenance | Customer change-window; typically <30 min per release |
| RTO (Recovery Time Objective) | ≤ 1 hour (restore from Postgres backup + redeploy image) |
| RPO (Recovery Point Objective) | ≤ 24 hours (customer-side backup cadence) |

## 6.2 Performance

| Surface | Target |
|---|---|
| Server response, list pages (p95) | < 700 ms |
| Server response, detail pages (p95) | < 1500 ms |
| Bob inference (Ollama) | < 6 s per alert at the chosen model size |
| Embedding generation (pgvector) | < 300 ms per case |
| Background task latency | < 30 s end-to-end for the typical alert→case path |

Targets are validated via runtime metrics; not yet formally load-tested (see §10 open questions).

## 6.3 Scalability

- Vertical: Postgres scales by CPU/RAM/IO; ION app scales by CPU/RAM.
- Horizontal: ION app scales out with sticky sessions; advisory locks ensure background work runs on one node only.

## 6.4 Security

- All inputs validated (Pydantic at the boundary, SQLAlchemy ORM at the data layer).
- Strict CSP, no inline JS, no `eval` in the bundle.
- RBAC enforced at endpoint + service layer.
- Audit log + tamper-evident ledger.
- SBOM (SPDX-JSON) ships inside the image.
- pip-audit / ruff / bandit run in CI on every commit.
- See `SECURITY_ASSESSMENT.md` for the per-release severity trend.

## 6.5 Auditability

- Every state mutation → audit_log row with attribution (user_id, ip, timestamp, action, target).
- Workbench events → sha256-chained ledger; tamper-detectable.
- Bob verdicts → joinable from audit_log to bob_verdict row.
- ECS-compliant stdout for SIEM ingestion.

## 6.6 Accessibility

- WCAG 2.2 Level AA target across all analyst-facing pages.
- Per-tier audit + remediation plan in the customer-agnostic public site; tier-3/4 surfaces tracked for future releases.
- Server-rendered HTML keeps the markup screen-reader friendly by default.

## 6.7 Privacy

- Data minimisation: ION stores SOC operational metadata, not PII payloads.
- Optional PII anonymisation toggle (`ION_PII_ANON_ENABLED`); default off (acceptable threat model — ION users already have ES/Kibana access).
- Subject Access Request + Erasure procedures documented (DPIA companion).

## 6.8 Air-gap

- All bundled reference data (MITRE ATT&CK v15.1, CISA KEV) ships inside the Docker image.
- Refresh of bundled data is part of the release ritual.
- No live external feed dependencies.

# 7. Cross-cutting concerns

## 7.1 Authentication

Two interchangeable schemes:

1. **Local password.** bcrypt-hashed in `users.password_hash`; rate-limited by slowapi; configurable failed-login lockout.
2. **OIDC.** Keycloak (default) or any OIDC provider; RS256 only; HS256 explicitly refused; JWKS auto-refresh; SSO logout path.

Sessions are server-side, cookie-bound (`Secure`, `HttpOnly`, `SameSite=Lax`).

## 7.2 Authorisation (RBAC)

Seven-tier hierarchy (highest → lowest privilege):

1. `admin` — full system access
2. `soc_manager` — oversight + tuning + bulk operations
3. `detection_engineer` — TIDE + rule management
4. `l3_analyst` — case management + threat hunt + forensics
5. `l2_analyst` — case management
6. `l1_analyst` — alert triage + case create
7. `viewer` — read-only

Permissions are bound to roles in `models/security.py::Permission` + `RolePermission`. The `@permission_required("...")` decorator enforces at the endpoint; services re-check before any state mutation.

## 7.3 Audit + tamper-evident ledger

Two-tier audit story:

- **Traditional audit_log.** One row per state-mutating request; captures who/what/when/where. Inserted in a request-scoped middleware.
- **Tamper-evident ledger.** Used on Workbench (AlertCase + ForensicCase pin events). Each event computes `sha256(prev_hash || event_payload)`. A break in the chain is detectable post-hoc.

## 7.4 Observability

- **Stdout logs.** ECS-formatted JSON lines; the customer's log-shipper picks them up. Suggested SIEM detection rules included as a companion artefact.
- **Health endpoint.** `GET /health` returns stable JSON; customer monitoring polls.
- **Internal metrics.** Slow-query threshold (`slow_query_threshold_ms`), pool exhaustion, Bob latency — all in audit-shape logs.

## 7.5 AI safety (Bob)

| Safeguard | Mechanism |
|---|---|
| Human-in-the-loop | Case-close requires analyst to pick `CaseClosureReason`; Bob's suggestion is advisory |
| Confidence rating | Every verdict carries 0–100 numeric + low/medium/high band |
| Circuit breaker | Low-confidence verdicts surface a UI badge; suggestion suppressed |
| Output schema | Strict Pydantic structured-output contract; arbitrary text refused |
| Audit join | Every Bob output joinable to audit_log via `bob_verdict_id` |
| Per-template tuning | `confidence_threshold_override` per alert-prompt template |
| Eval harness | Offline replay of live prompt against historical alerts for P/R/F1 scoring |

## 7.6 Accessibility

- Semantic HTML (server-rendered, no SPA = standard markup).
- ARIA landmarks on layout components.
- Keyboard navigation tested on tier-1/2 pages.
- Colour contrast audited; current findings + remediation plan tracked.

# 8. Deployment views

## 8.1 Single-instance (default)

```
[Browser] → [Reverse Proxy] → [ION container :8000] → [Postgres]
                                       │
                                       └→ [Ollama (optional)]
```

Sized for typical SOC team (<= 50 analysts; <= 200 cases/day). One ION container, one Postgres instance, optional Ollama. RTO ≤ 1 hour from cold via Postgres restore + image redeploy.

## 8.2 Scaled

```
[Browser] → [Load Balancer (sticky sessions)] → [ION × N]
                                                    │
                                                    ▼
                                             [Postgres primary]
                                                    │
                                                    ▼
                                          [Postgres read replica]
```

Horizontal scale: N ION containers behind sticky-session LB; advisory locks ensure background tasks run on one node only. Postgres scales vertically + read-replica for analytics queries.

## 8.3 Air-gapped

Same as single-instance, except:

- No outbound internet
- Ollama runs locally (no API-key-based remote LLMs)
- Reference data (ATT&CK + KEV) loaded from the image's bundled snapshots
- Updates delivered as new Docker image tarball; loaded with `docker load`
- Offline package script (`scripts/build-offline-package.sh`) bundles the full deliverable for transport

# 9. Integration architecture

| Integration | Direction | Auth | Failure mode |
|---|---|---|---|
| Elasticsearch Security | ION → ES | API key or basic | "Alerts unavailable" banner; everything else works |
| TIDE | ION → TIDE | API key | TIDE pages show "not configured"; everything else works |
| Kibana Cases | bidirectional | basic or API key | Case-sync widget shows disabled; ION cases unaffected |
| OpenCTI | ION → OpenCTI | API key | Threat-intel pages show "no source"; cases unaffected |
| Arkime | ION → Arkime | Keycloak `client_credentials` or basic | PCAP actions disabled; cases unaffected |
| Keycloak (OIDC) | bidirectional | OIDC RS256 | Falls back to local password |
| Ollama | ION → Ollama | none (local) or bearer | Bob fails open; analyst proceeds without AI suggestion |

Each integration is opt-in via env vars (`ION_*_URL`, `ION_*_KEY`, `ION_*_USERNAME`, …); see `STACK.md` for the full env-var catalogue.

# 10. Risks + open questions

| # | Risk / Question | Mitigation / Tracking |
|---|---|---|
| R-01 | Single-maintainer supply risk | MIT-licensed public source, comprehensive docs, SBOM in image |
| R-02 | LLM availability (Ollama down) | Bob fails open; no false suggestions |
| R-03 | Bundled ATT&CK / KEV staleness | Refresh ritualised every release |
| R-04 | Formal load-test not run | Tracked as anticipated v0.31.0+ work |
| R-05 | Container image not signed (cosign / Sigstore) | Not a must-have at current tier; flagged but no exception filed |
| R-06 | WCAG remediation on lower-frequency pages | Remediation plan with v0.30.0/v0.31.0 targets |
| R-07 | Bob prompt-injection resilience monitored not formally tested | Structured output schema + enum-constrained close reasons bound the worst case; AIDefence wiring planned |

# 11. Roadmap pointers

Upcoming work (each tracked in `_backlog_v0_27.md` or anticipated for future release):

- v0.30.0+: WCAG remediation tier 2 + tier 3 pages
- v0.30.0+: Lab fixture system rework (4 known bugs in queue)
- v0.31.0+: Container image signing
- v0.31.0+: Formal load-test profile
- v0.31.0+: AIDefence wiring for prompt-injection-aware Bob testing

# 12. Glossary

| Term | Meaning |
|---|---|
| ION | Intelligent Operating Network — this product |
| SOC | Security Operations Centre |
| Bob | ION's AI analyst assistant (LLM-backed, decision-support) |
| Workbench | Pinned-evidence + tamper-evident-ledger surface on cases |
| Case (AlertCase) | Investigation container created from one or more security alerts |
| ForensicCase | Deep-dive investigation container, parallel to AlertCase |
| TIDE | Threat-Informed Defence Engineering platform |
| ATT&CK | MITRE's adversary tactics/techniques framework |
| CyAB | ION's Cyber Assurance + Best-practice maturity framework |
| RBAC | Role-Based Access Control |
| TOCTOU | Time-Of-Check-Time-Of-Use; a race-condition vulnerability class |
| ECS | Elastic Common Schema (log format) |
| SBOM | Software Bill Of Materials |
| KEV | CISA's Known Exploited Vulnerabilities catalogue |

# 13. Change history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-05-12 | ION maintainer | Initial HLD authored against v0.29.1 |
