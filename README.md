<!-- ion-doc:type=PROJECT OVERVIEW -->
<!-- ion-doc:title=ION — Intelligent Operating Network -->
<!-- ion-doc:subtitle=SOC analyst workbench: features, integrations, deployment, documentation index -->
<!-- ion-doc:version=0.63.0 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Any reader; first-touch overview -->
<!-- ion-doc:date=2026-07-30 -->

# ION - Intelligent Operating Network

![Version](https://img.shields.io/badge/version-0.77.0-blue)
![Python](https://img.shields.io/badge/python-3.14-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Docker](https://img.shields.io/badge/docker-ixion36%2Fion-blue)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20docker-lightgrey)

ION is a server-rendered Security Operations Centre portal for threat detection, investigation, and response. It runs in **air-gapped / siloed** environments (no live external feeds), built on FastAPI + Jinja2 + PostgreSQL (+ pgvector) with a local Ollama LLM — **Bob**, the AI analyst who triages alerts and drafts case findings. It pulls alerts from Elasticsearch and integrates OpenCTI threat intel, TIDE detection engineering, and Arkime PCAP capture into one workspace.

---

## Key Features

- **Alerts & AI triage (Bob)** — Elasticsearch 8.x alert queue with severity/MITRE ATT&CK filtering and workflow sync; a background investigation loop where Bob auto-investigates, suggests TP/FP verdicts with confidence, and drafts evidence-grounded closures. RAG-grounded on past cases, KB articles, playbooks, and threat-intel reports.
- **Cases** — Cases-as-widgets board with a per-alert widget detail view, auto-extracted + enriched observables, and an **Attack Path** kill-chain graph tab (Bob Pathfinding — directed attack graph with MITRE reachability scoring). Kibana case sync, tamper-evident sha256 workbench ledger, pgvector similar-case lookup, unified entity timeline.
- **Detection Engineering** — TIDE analytics (posture, gap analysis, MITRE coverage, ATT&CK Navigator export) plus the optional **DE module**: DE Metrics / Noise Campaigns, Detection Proposals, System Quirks register, and a Bob improvement loop (perms `de:read` / `de:propose` / `de:verify` / `de:approve`).
- **Threat Intel & integrations** — Unified threat-intel page (actors, IOCs, reports, watchlist), knowledge graph, canaries, and observable enrichment across OpenCTI, VirusTotal, Shodan, AbuseIPDB, and DFIR-IRIS.
- **Playbooks & response** — 25+ SOC playbooks with execution tracking and analytics, full DFIR forensics pipeline (chain of custody, timeline, IOC extraction), PCAP analysis (protocol heuristics, JA3, file/credential extraction), and 6 approval-gated response actions (block IP, disable account, quarantine host, DNS sinkhole, email block, webhook).
- **Reporting & operations** — SOC health scorecard, executive/compliance report scheduler, analyst efficiency, SLA tracking, morning briefing, shift handover, on-call roster, and a configurable command-centre dashboard.
- **Labs & training** — Knowledge base (~392 articles across 28 collections), scored training scenarios, cyber range lab exercises, role-match self-assessment, and the interactive ION Guide.

Also included: an optional **MCP server mode** (`POST /api/mcp`, `ION_MCP_ENABLED`, default off) exposing core SOC data as MCP tools, and optional **observability** (Prometheus `/metrics` + Elastic APM, both default off).

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.14 / FastAPI / SQLAlchemy 2.0 |
| Frontend | Jinja2 server-rendered HTML + Vanilla JS + Tailwind CSS (no SPA) |
| Database | PostgreSQL 16 + pgvector (Docker) / SQLite (local dev) |
| Search & Alerts | Elasticsearch 8.x |
| Case Sync | Kibana 8.x |
| Threat Intel | OpenCTI (GraphQL) |
| Detection Engineering | TIDE (DuckDB + FastAPI) |
| PCAP | Arkime (full packet capture) |
| AI / LLM | Ollama (local, air-gap safe) — default model Foundation-Sec-8B |
| Auth | bcrypt, python-jose (JWT), OIDC/Keycloak |
| Container | Docker Compose |

---

## Integrations

| System | Purpose |
|--------|---------|
| **Elasticsearch** | Alert ingestion, log search, discover queries |
| **Kibana** | Case sync, space-aware detection scoping |
| **TIDE** | Detection rule analytics, MITRE coverage, gap analysis |
| **OpenCTI** | Threat intelligence: actors, campaigns, IOCs, reports |
| **Arkime** | Full packet capture retrieval by community ID |
| **Keycloak** | OIDC SSO, role mapping, Arkime auth |
| **Ollama** | Local LLM for Bob, AI chat, analysis, briefings |
| **GitLab** | Change tracking, bug reports, CAB change requests |
| **VirusTotal** | Observable enrichment (file hashes, URLs, IPs) |
| **Shodan** | Internet-facing asset intelligence |
| **AbuseIPDB** | IP reputation / abuse-confidence enrichment |
| **DFIR-IRIS** | Case escalation to an external DFIR platform |

---

## Quick Start

```bash
# Clone
git clone https://github.com/ixion36-svg/ion.git
cd ion

# Configure
cp .env.deploy .env
# Edit .env — set your Elasticsearch URL, passwords, and integration endpoints

# Deploy (pulls pre-built image + PostgreSQL)
docker compose up -d

# The seeder container automatically populates the knowledge base and playbooks on first run.

# Access ION
# http://localhost:8000
# Login: admin / admin2025 (or your ION_ADMIN_PASSWORD value)
```

To include the built-in Ollama LLM service:

```bash
docker compose --profile ai up -d
```

Full setup walkthrough: [`SETUP.md`](SETUP.md). Air-gapped bundle instructions are in the same guide.

---

## Configuration

Every integration follows the `ION_<NAME>_ENABLED` + `_URL` + auth env-var pattern. The complete environment-variable reference — server, database, and all integration families — lives in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md#environment-variable-reference). At minimum, set `ION_ADMIN_PASSWORD`, `ION_DB_PASSWORD`, and your Elasticsearch connection (`ION_ELASTICSEARCH_URL` / `ION_ELASTICSEARCH_USERNAME` / `ION_ELASTICSEARCH_PASSWORD`).

---

## Security & RBAC

- **RBAC** — 10 built-in roles across analyst and engineering tiers plus `lead`, `forensic`, and `admin`. The canonical role table is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#role-hierarchy).
- **Focus Mode** — users with multiple roles can switch active role context to restrict their permission set to one role at a time.
- **OIDC / Keycloak SSO** — full OpenID Connect with auto user provisioning and role mapping.
- **Hardening** — per-endpoint rate limiting (slowapi), comprehensive audit logs, security headers (CSP, HSTS, X-Frame-Options, Permissions-Policy), and configurable account lockout.

---

## Docker Hub

```bash
docker pull ixion36/ion:latest
# or a specific version
docker pull ixion36/ion:0.62.0
```

---

## Project Structure

```
ion/
  src/ion/
    auth/          # Authentication, OIDC, password hashing
    core/          # Config, logging, error handling, APM
    models/        # SQLAlchemy models
    services/      # Business logic
    storage/       # Database, repositories, advisory locks
    web/           # FastAPI routes, templates, static
  deploy/          # Nginx config, docker-compose variants, cert generation
  tests/           # Test suite
  docker-compose.yml
  Dockerfile
```

---

## Documentation

| Document | Purpose |
|----------|---------|
| [`docs/HLD.md`](docs/HLD.md) | High-Level Design — C4 L1-L3, architectural decisions, NFRs, deployment views |
| [`docs/LLD.md`](docs/LLD.md) | Low-Level Design — modules, data model, API surface, sequence diagrams |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Architecture reference (componentry, data flow, schema, canonical RBAC table) |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Deployment topology, container orchestration, full env-var reference |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Operational duties, integration config, troubleshooting, release ritual |
| [`docs/API.md`](docs/API.md) | API reference — auth, RBAC, router catalogue, webhook contract |
| [`docs/USER_REQUIREMENTS.md`](docs/USER_REQUIREMENTS.md) | User Requirements Document — numbered URs per persona |
| [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) | Requirements Traceability Matrix |
| [`docs/USE_CASES.md`](docs/USE_CASES.md) | Use cases by persona |
| [`docs/GAPS_FILLED.md`](docs/GAPS_FILLED.md) | SOC pain points ION addresses, with feature evidence |
| [`docs/CRYPTOGRAPHY.md`](docs/CRYPTOGRAPHY.md) | Cryptographic inventory |
| [`docs/BACKUP_RESTORE.md`](docs/BACKUP_RESTORE.md) | Backup + restore runbook with RTO/RPO targets |
| [`docs/VULN_MGMT.md`](docs/VULN_MGMT.md) | Vulnerability management process |
| [`docs/CONFIG_MGMT.md`](docs/CONFIG_MGMT.md) | Configuration management plan |
| [`docs/CAPACITY.md`](docs/CAPACITY.md) | Performance + capacity plan |
| [`docs/DEVELOPMENT_LIFECYCLE.md`](docs/DEVELOPMENT_LIFECYCLE.md) | Secure-by-Design SDLC (5 phases) |
| [`docs/SECURE_BY_DESIGN.md`](docs/SECURE_BY_DESIGN.md) | 20 Secure-by-Design principles + per-principle audit |
| [`CHANGELOG.md`](CHANGELOG.md) | Per-release change record |
| [`SECURITY_ASSESSMENT.md`](SECURITY_ASSESSMENT.md) | Per-release security audit |
| [`SECURITY.md`](SECURITY.md) | Vulnerability disclosure policy |
| [`SETUP.md`](SETUP.md) | Local dev + air-gapped setup |
| [`STACK.md`](STACK.md) | Tech-stack reference |

---

## License

MIT
