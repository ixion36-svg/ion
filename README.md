<!-- ion-doc:type=PROJECT OVERVIEW -->
<!-- ion-doc:title=ION — Intelligent Operating Network -->
<!-- ion-doc:subtitle=SOC analyst workbench: features, integrations, deployment, documentation index -->
<!-- ion-doc:version=0.34.2 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Any reader; first-touch overview -->
<!-- ion-doc:date=2026-05-28 -->

# ION - Intelligent Operating Network

![Version](https://img.shields.io/badge/version-0.57.0-blue)
![Python](https://img.shields.io/badge/python-3.14-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Docker](https://img.shields.io/badge/docker-ixion36%2Fion-blue)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20docker-lightgrey)

A full-stack Security Operations Centre platform for threat detection, investigation, and response. ION integrates Elasticsearch alerts, OpenCTI threat intelligence, TIDE detection engineering, Arkime PCAP analysis, and Ollama AI into a unified workspace for SOC teams.

---

## Key Features

### Investigation
- **Alert Triage** -- Elasticsearch 8.x alert queue with severity filtering, MITRE ATT&CK mappings, workflow status sync, and auto-investigation queue
- **Case Management** -- Create cases from alerts, kanban board, Kibana case sync, closure reasons, affected hosts/users tracking
- **Observables** -- IOC tracking with batch OpenCTI enrichment, staleness detection, whitelisting
- **Entity Timeline** -- Unified cross-source timeline for any host, IP, or user across all ION data
- **Attack Stories** -- Auto-correlate alerts into multi-step attack narratives with kill chain visualisation
- **AI Chat** -- Ollama-powered analysis, document generation, triage assistance, NL-to-Elasticsearch queries
- **Case Similarity & Triage Suggestions** -- Historical closure data suggests FP/TP; find similar past cases by rules, hosts, observables, and MITRE techniques
- **Discover** -- Raw Elasticsearch query builder and saved searches

### Response
- **Playbooks** -- 25+ SOC playbooks with step-by-step execution tracking and effectiveness analytics
- **Forensics Pipeline** -- Full DFIR workflow: evidence chain of custody, timeline, IOC extraction, forensic playbooks
- **PCAP Analysis** -- Upload packet captures for protocol analysis (12 heuristic detectors), file extraction, JA3 fingerprinting, credential detection, network graph
- **Arkime Integration** -- One-click alert-to-PCAP-to-case workflow with Keycloak client_credentials auth
- **Automated Actions** -- 6 response actions (block IP, disable account, quarantine host, DNS sinkhole, email block, webhook) with approval workflow
- **Case Grouper** -- Automated alert correlation into case clusters

### Threat Intelligence
- **Unified Threat Intel** -- Single consolidated page (v0.27.0): threat landscape, actor deep-dive with IOC sparkline + ATT&CK click-through, live IOC feed, reports, watchlist with country attribution
- **Attack Stories** -- Multi-step attack narrative reconstruction with kill chain visualisation
- **Knowledge Graph** -- Visual relationship mapping across threat data
- **Canaries** -- Honeypot token deployment and monitoring
- **Threat Watch Gap Alerts** -- Auto-alerting when watched actors gain new techniques you lack coverage for

### Detection Engineering
- **TIDE Integration** -- 7-tab analytics: posture, use cases, rules, execution reports, actor readiness, gap analysis, MITRE coverage
- **MITRE ATT&CK Navigator Export** -- One-click ATT&CK Navigator layer JSON from TIDE coverage
- **D3FEND Mapping** -- Defensive technique coverage analysis
- **Emulation** -- Adversary emulation plan management
- **Multi-Framework Compliance** -- Map TIDE rules to NIST CSF, ISO 27001, ACSC Essential Eight, and more
- **Space Selector** -- Kibana space-aware detection rule scoping

### Infrastructure
- **Network Map / CMDB** -- Automated network asset discovery and topology visualisation
- **Log Source Health** -- Monitor ingestion status, detect silent log sources, data volume tracking
- **Data Flow** -- Pipeline visualisation showing ArcSight+NiFi vs Elastic+NiFi data flows
- **CyAB (Cyber Assurance Board)** -- System registry with data source templates, per-system use case coverage, alert rollups
- **System Analytics** -- Per-system detection posture and TIDE integration metrics

### Reporting
- **SOC Health Scorecard** -- 5-dimension maturity assessment (A-F grade): detection, operations, team, knowledge, integrations
- **Executive Reports** -- Auto-generated weekly/monthly PDF/HTML reports with trends, metrics, and notable incidents
- **Analyst Efficiency** -- Per-analyst MTTR, false positive rates, hourly activity, team comparison
- **Compliance Hub** -- Multi-framework mapping with coverage scores and gap identification
- **SOC Maturity Assessment** -- SOC-CMM based maturity model evaluation
- **Incident Cost Calculator** -- Estimate incident cost from case data: analyst hours, downtime, severity weighting
- **Report Scheduler** -- Schedule executive, health, and compliance reports on daily/weekly/monthly cadence

### Operations
- **SOC Workspace** -- Command centre dashboard with 12 configurable widgets, role-filtered, per-user layout
- **Morning Briefing** -- AI-generated daily threat and operations briefing
- **Shift Handover** -- Auto-generated end-of-shift report: cases, alerts, highlights, pending items
- **On-Call / Duty IM** -- Roster management, one-click escalation, escalation log
- **Job Scheduler** -- Cron-based background job scheduling with execution history
- **Alert Prompt Templates** -- Pre-built AI prompt templates for common alert types
- **SLA Management** -- Response time targets per severity, compliance tracking, breach detection
- **Bulk Operations** -- Multi-select alerts for bulk acknowledge, assign, or close
- **Communication Templates** -- 6 pre-built incident notification templates with variable substitution

### Knowledge & Training
- **Knowledge Base** -- 590+ articles across SOC, blue team, forensics, and security fundamentals
- **Training Simulator** -- 8 scored scenarios: phishing, credential dumping, Kerberoasting, Golden Ticket, DCSync, GPO malware, ransomware, VPN false positive
- **Cyber Range** -- Hands-on technical lab exercises
- **Role Match** -- Career skills self-assessment across 5 SOC roles with personalised training recommendations
- **Skills & Training** -- Self-assessment, career pathways, certifications, team skill overview
- **ION Guide** -- Interactive reference with visual UI mockups, role-based filtering, workflow diagrams
- **Social Hub** -- Team announcements, recognition, emoji reactions
- **Notes** -- Personal analyst notepad with folders and auto-save
- **Documents** -- Document management and version tracking

### AI (Ollama)
- AI-powered chat with contextual awareness (alerts, cases, observables)
- Alert analysis and triage suggestions
- Natural language to Elasticsearch query translation
- Threat briefing generation
- PII anonymisation for safe data sharing
- Investigation memory and context persistence

### Security
- **RBAC** -- 10 built-in roles: admin, analyst (L1), senior_analyst (L2), principal_analyst (L3), lead, forensic, soc_engineer (L1), senior_engineer (L2), platform_engineer (L3), engineering
- **Focus Mode** -- Users with multiple roles can switch active role context via dashboard
- **OIDC / Keycloak SSO** -- Full OpenID Connect integration with auto user provisioning and role mapping
- **Rate Limiting** -- Per-endpoint rate limiting via slowapi
- **Audit Logs** -- Comprehensive audit trail of all user actions
- **Security Headers** -- CSP, HSTS, X-Frame-Options, Permissions-Policy
- **Account Lockout** -- Configurable failed login threshold with automatic lockout

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.14 / FastAPI / SQLAlchemy 2.0 |
| Frontend | Jinja2 server-rendered HTML + Vanilla JS + Tailwind CSS |
| Database | PostgreSQL 16 (Docker) / SQLite (local dev) |
| Search & Alerts | Elasticsearch 8.x |
| Case Sync | Kibana 8.x |
| Threat Intel | OpenCTI (GraphQL) |
| Detection Engineering | TIDE (DuckDB + FastAPI) |
| PCAP | Arkime (full packet capture) |
| AI / LLM | Ollama (local, air-gap safe) |
| PDF Generation | WeasyPrint |
| JSON Serialisation | orjson (5-10x faster than stdlib) |
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
| **Ollama** | Local LLM for AI chat, analysis, briefings |
| **GitLab** | Change tracking, CI/CD integration |
| **VirusTotal** | Observable enrichment (file hashes, URLs, IPs) |
| **Shodan** | Internet-facing asset intelligence |
| **GreyNoise** | IP noise/benign classification |

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

---

## Environment Variables

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_PORT` | `8000` | HTTP listen port |
| `ION_HOST` | `0.0.0.0` | Bind address |
| `ION_WORKERS` | `4` | Uvicorn worker count |
| `ION_BASE_URL` | -- | Public URL for OIDC redirect URIs |
| `ION_ADMIN_PASSWORD` | `admin2025` | Initial admin account password |
| `ION_DEBUG_MODE` | `false` | Enable /docs and /redoc endpoints |
| `ION_COOKIE_SECURE` | `false` | Force Secure flag on session cookies |
| `ION_SECRET_KEY` | auto | JWT signing key |

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_DATABASE_URL` | `postgresql://ion:ion2025@postgres:5432/ion` | PostgreSQL connection string |
| `ION_DB_PASSWORD` | `ion2025` | PostgreSQL password (used by compose) |
| `ION_DATA_DIR` | `/data` | Persistent data directory (Docker) |

### Elasticsearch

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_ELASTICSEARCH_URL` | -- | Elasticsearch URL (e.g. `https://es:9200`) |
| `ION_ELASTICSEARCH_USERNAME` | -- | ES username |
| `ION_ELASTICSEARCH_PASSWORD` | -- | ES password |
| `ION_ELASTICSEARCH_API_KEY` | -- | ES API key (alternative to user/pass) |
| `ION_ELASTICSEARCH_ALERT_INDEX` | -- | Alert index pattern |
| `ION_ELASTICSEARCH_VERIFY_SSL` | `false` | Verify ES TLS certificate |

### Kibana

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_KIBANA_URL` | -- | Kibana URL for case sync |
| `ION_KIBANA_USERNAME` | -- | Kibana username |
| `ION_KIBANA_PASSWORD` | -- | Kibana password |
| `ION_KIBANA_SPACE_ID` | `production` | Default Kibana space |
| `ION_KIBANA_VERIFY_SSL` | `false` | Verify Kibana TLS certificate |

### TIDE (Detection Engineering)

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_TIDE_ENABLED` | `false` | Enable TIDE integration |
| `ION_TIDE_URL` | -- | TIDE API base URL |
| `ION_TIDE_API_KEY` | -- | TIDE API key |
| `ION_TIDE_VERIFY_SSL` | `false` | Verify TIDE TLS certificate |

### OpenCTI (Threat Intelligence)

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_OPENCTI_ENABLED` | `false` | Enable OpenCTI integration |
| `ION_OPENCTI_URL` | -- | OpenCTI URL |
| `ION_OPENCTI_TOKEN` | -- | OpenCTI API token |
| `ION_OPENCTI_VERIFY_SSL` | `false` | Verify OpenCTI TLS certificate |

### Arkime (PCAP)

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_ARKIME_ENABLED` | `false` | Enable Arkime integration |
| `ION_ARKIME_URL` | -- | Arkime viewer URL |
| `ION_ARKIME_KEYCLOAK_ISSUER` | -- | Keycloak issuer URL for Arkime auth |
| `ION_ARKIME_KEYCLOAK_CLIENT_ID` | -- | Keycloak client ID |
| `ION_ARKIME_KEYCLOAK_CLIENT_SECRET` | -- | Keycloak client secret |
| `ION_ARKIME_VERIFY_SSL` | `false` | Verify Arkime TLS certificate |

### Ollama (AI / LLM)

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_OLLAMA_ENABLED` | `true` | Enable Ollama AI features |
| `ION_OLLAMA_URL` | `http://ollama:11434` | Ollama API URL |
| `ION_OLLAMA_MODEL` | `hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF` | Default Bob model (security-tuned, Llama-3.1-8B based) |
| `ION_OLLAMA_TIMEOUT` | `120` | Request timeout (seconds) |
| `ION_OLLAMA_VERIFY_SSL` | `false` | Verify Ollama TLS certificate |

### OIDC / Keycloak (SSO)

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_OIDC_ENABLED` | `false` | Enable Keycloak SSO |
| `ION_OIDC_KEYCLOAK_URL` | -- | Keycloak base URL |
| `ION_OIDC_REALM` | -- | Keycloak realm name |
| `ION_OIDC_CLIENT_ID` | -- | OIDC client ID |
| `ION_OIDC_CLIENT_SECRET` | -- | OIDC client secret |
| `ION_OIDC_VERIFY_SSL` | `false` | Verify Keycloak TLS certificate |

### TLS / SSL

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_SSL_CERT` | -- | Path to TLS certificate (serve ION over HTTPS) |
| `ION_SSL_KEY` | -- | Path to TLS private key |
| `ION_CA_BUNDLE` | -- | Path to custom CA bundle for outbound connections |

### GitLab

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_GITLAB_ENABLED` | `false` | Enable GitLab integration |
| `ION_GITLAB_URL` | -- | GitLab instance URL |
| `ION_GITLAB_TOKEN` | -- | GitLab personal access token |

### SMTP (Email Notifications)

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_SMTP_ENABLED` | `false` | Enable email notifications |
| `ION_SMTP_HOST` | -- | SMTP server hostname |
| `ION_SMTP_PORT` | `587` | SMTP port |
| `ION_SMTP_USERNAME` | -- | SMTP username |
| `ION_SMTP_PASSWORD` | -- | SMTP password |

---

## RBAC Roles

| Role | Level | Description |
|------|-------|-------------|
| `analyst` | L1 | Alert triage, basic case management, playbook execution |
| `senior_analyst` | L2 | + case closure, observable enrichment, forensic viewer |
| `principal_analyst` | L3 | + playbook creation, forensic cases, security dashboard |
| `lead` | -- | All analyst permissions + team management, full forensic access |
| `forensic` | -- | Forensic investigations, evidence, chain of custody |
| `soc_engineer` | L1 | Log onboarding, basic SIEM config, tooling support |
| `senior_engineer` | L2 | Detection engineering, pipeline management, Elastic admin |
| `platform_engineer` | L3 | Infrastructure, architecture, security tooling at scale |
| `engineering` | -- | Full operational + system management access |
| `admin` | -- | Full access including user management and system settings |

**Focus Mode:** Users assigned multiple roles can switch their active role context via the dashboard, restricting permissions to a single role at a time.

---

## Docker Hub

```bash
docker pull ixion36/ion:latest
# or a specific version
docker pull ixion36/ion:0.29.1
```

---

## Project Structure

```
ion/
  src/ion/
    auth/          # Authentication, OIDC, password hashing
    core/          # Config, logging, error handling, circuit breaker
    models/        # SQLAlchemy models (35+ modules)
    services/      # Business logic (80+ service modules)
    storage/       # Database, repositories, advisory locks
    web/           # FastAPI routes (60+ API modules), templates, static
  deploy/          # Nginx config, docker-compose variants, cert generation
  loadtest/        # Locust load testing framework
  tests/           # Test suite
  docker-compose.yml
  Dockerfile
```

---

## Documentation

| Document | Purpose |
|----------|---------|
| [`docs/HLD.md`](docs/HLD.md) | High-Level Design — C4 L1-L3, architectural decisions, NFRs, deployment views |
| [`docs/LLD.md`](docs/LLD.md) | Low-Level Design — modules, data model, API surface, sequence diagrams, per-feature deep dives |
| [`docs/USER_REQUIREMENTS.md`](docs/USER_REQUIREMENTS.md) | User Requirements Document — 51 numbered URs per persona with source, priority, acceptance criterion |
| [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) | Requirements Traceability Matrix — UR → SR → HLD/LLD → Use Case → Gap → Test → Status |
| [`docs/USE_CASES.md`](docs/USE_CASES.md) | Use cases by persona (L1/L2/L3 analyst, detection engineer, SOC manager, admin, learner, compliance) |
| [`docs/GAPS_FILLED.md`](docs/GAPS_FILLED.md) | The SOC pain points ION addresses, with concrete feature evidence per gap |
| [`docs/ION_STACK_BRIEF.md`](docs/ION_STACK_BRIEF.md) | GG stack adoption brief — pre-GG state (Elastic + YouTrack + unconfigured n8n) vs operational GG stack (ION + TIDE + Elastic + GitLab + DFIR-IRIS + Arkime + OpenCTI + Keycloak + n8n); ION's specific gap-fill + tool-by-tool integration map; "if we bought everything else but not ION" analysis; adoption history + remaining acceptance gates |
| [`docs/API.md`](docs/API.md) | API reference — auth, RBAC, 73-router catalogue, webhook contract, OpenAPI pointer |
| [`docs/CRYPTOGRAPHY.md`](docs/CRYPTOGRAPHY.md) | Cryptographic inventory — every algorithm + key size + library used + NCSC alignment |
| [`docs/BACKUP_RESTORE.md`](docs/BACKUP_RESTORE.md) | Standalone backup + restore runbook with RTO/RPO targets and drill cadence |
| [`docs/VULN_MGMT.md`](docs/VULN_MGMT.md) | Vulnerability management process — CVE intake, triage, fix-cadence SLAs, disclosure |
| [`docs/CONFIG_MGMT.md`](docs/CONFIG_MGMT.md) | Configuration management plan — source control, branching, release ritual, CI catalogue |
| [`docs/CAPACITY.md`](docs/CAPACITY.md) | Performance + capacity plan — targets, sizing envelope, scaling levers, monitoring thresholds, load-test plan |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Original technical architecture reference (componentry, data flow, schema) |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Deployment topology, container orchestration, `.env.deploy` reference |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Operational duties (SOC lead daily activities, integration config, troubleshooting, release ritual) |
| [`docs/DEVELOPMENT_LIFECYCLE.md`](docs/DEVELOPMENT_LIFECYCLE.md) | Development lifecycle aligned to Secure by Design (5 phases); cross-references NCSC Secure Development and Deployment |
| [`CHANGELOG.md`](CHANGELOG.md) | Per-release change record |
| [`SECURITY_ASSESSMENT.md`](SECURITY_ASSESSMENT.md) | Per-release security audit with severity-trend table |
| [`SECURITY.md`](SECURITY.md) | Vulnerability disclosure policy — how to report, supported versions, disclosure timeline |
| [`SETUP.md`](SETUP.md) | Local dev setup |
| [`STACK.md`](STACK.md) | Tech-stack reference |
| `tools/pdf_build/build_docs.py` | Builder script — produces ION-branded PDFs from any of the above markdown docs |
| `tools/pdf_build/build_csv.py` | Builder script — emits editable CSV companions for table-shaped docs (URD, RTM, SR catalogue, Use Cases, regulated-environment compliance pack) for reviewers to mark up in Excel |

---

## License

MIT
