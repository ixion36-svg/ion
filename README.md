# ION

**Intelligent Operating Network** — v0.9.43

A comprehensive Security Operations Center (SOC) platform for the **Guarded Glass** team. ION integrates Elasticsearch alerts, OpenCTI threat intelligence, TIDE detection engineering, and Ollama AI into a unified workspace for alert triage, case management, threat hunting, and SOC operations.

## Quick Start

```bash
# Clone
git clone https://github.com/ixion36-svg/ion.git
cd ion

# Configure
cp .env.deploy .env
# Edit .env — replace REPLACE_WITH_ placeholders with your actual IPs

# Deploy (pulls pre-built image + PostgreSQL)
docker compose up -d

# Access at http://localhost:8000
# Login: admin / admin2025 (or your ION_ADMIN_PASSWORD)
```

## Architecture

```
docker compose up -d
  │
  ├── ion-postgres    PostgreSQL 16 (database)
  ├── ion             ION application (FastAPI + Jinja2)
  └── ion-seeder      One-shot data seeder (KB articles, playbooks)

External integrations (your infrastructure):
  ├── Elasticsearch   Alert data + log storage
  ├── Kibana          Case sync
  ├── OpenCTI         Threat intelligence
  ├── TIDE            Detection engineering (DuckDB)
  └── Ollama          Local LLM (optional)
```

## Features

### Investigation
| Feature | Description |
|---------|-------------|
| **Alert Triage** | ES-integrated alert queue with severity filtering, MITRE mappings, and workflow status sync |
| **Case Management** | Create cases from alerts, track affected hosts/users, closure reasons, Kibana sync |
| **Observables** | IOC tracking with batch OpenCTI enrichment, staleness detection, whitelisting |
| **Threat Intel** | Search OpenCTI actors/campaigns, watchlist with country flag attribution, auto-gap alerting |
| **Entity Timeline** | Unified cross-source timeline for any host/IP/user across all ION data |
| **Attack Stories** | Auto-correlate alerts into multi-step attack narratives with kill chain visualization |
| **Triage Suggestions** | Historical closure data suggests FP/TP based on rule+host patterns |
| **Case Similarity** | Find similar past cases by matching rules, hosts, observables, MITRE techniques |
| **AI Chat** | Ollama-powered analysis, document generation, triage assistance |
| **Discover** | Raw Elasticsearch query builder |
| **Threat Hunting** | Hypothesis-driven hunting workbench: create hunts, attach queries, track IOCs found |

### Operations
| Feature | Description |
|---------|-------------|
| **On-Call / Duty IM** | Roster management, one-click escalation to Duty Incident Manager, escalation log |
| **Shift Handover** | Auto-generated end-of-shift report: cases, alerts, highlights, pending items |
| **SLA Management** | Response time targets per severity, compliance tracking, breach detection, at-risk alerts |
| **Bulk Operations** | Multi-select alerts for bulk acknowledge, assign, or close |
| **Playbooks** | 25+ SOC playbooks with step tracking and effectiveness analytics |
| **Forensics** | Full DFIR workflow: evidence chain of custody, timeline, IOC extraction |
| **PCAP Analyzer** | Upload packet captures for protocol analysis (12 heuristic detectors) |
| **Analyst Efficiency** | Per-analyst MTTR, FP rates, hourly activity, team comparison |
| **Analytics Engine** | 6 automated jobs: risk scoring, repeat offenders, rule noise, case metrics |

### Engineering
| Feature | Description |
|---------|-------------|
| **Detection Engineering** | 7-tab TIDE analytics: posture, kill chains, rules, execution, actor readiness, gaps |
| **Rule Tuning** | Cross-reference TIDE rules with closure outcomes: FP-heavy, high-value, silent rules |
| **SOC Health Scorecard** | 5-dimension maturity assessment (A-F grade): detection, operations, team, knowledge, integrations |
| **NIST Compliance** | Map TIDE rules to 13 NIST CSF controls with coverage scores |
| **MITRE Navigator Export** | One-click ATT&CK Navigator layer JSON from TIDE coverage |
| **Executive Report** | Auto-generated weekly/monthly PDF/HTML with trends, metrics, notable incidents |
| **Service Accounts** | Lifecycle tracker: password age, rotation targets, risk levels, stale detection |
| **Automated Actions** | 6 response actions (block IP, disable account, quarantine host) with approval workflow |
| **Report Scheduler** | Schedule executive/health/compliance reports on daily/weekly/monthly cadence |
| **Change Log** | Track config/rule changes with approval and rollback |
| **Alert Patterns** | Detect persistent, periodic, burst, and sporadic alert patterns |
| **Incident Cost Calculator** | Estimate incident cost from case data: analyst hours, downtime, by severity |

### Knowledge
| Feature | Description |
|---------|-------------|
| **ION Guide** | Interactive reference with visual UI mockups, role-based filtering, workflow diagrams |
| **Training Simulator** | 8 scored scenarios: phishing, credential dumping, Kerberoasting, Golden Ticket, DCSync, GPO malware, ransomware, VPN false positive |
| **Knowledge Base** | 590+ articles across SOC, blue team, forensics, security fundamentals |
| **Skills & Training** | Self-assessment, career pathways, certifications, team overview |
| **Social Hub** | Team announcements, recognition, emoji reactions |
| **Communication Templates** | 6 pre-built incident notification templates with variable substitution |
| **Notes** | Personal analyst notepad with folders and auto-save |
| **Dashboard Customization** | 12 configurable widgets, role-filtered, per-user layout |
| **Saved Searches** | Bookmark queries, pin favorites, usage tracking |

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.14 / FastAPI / SQLAlchemy |
| Frontend | Vanilla JS + Jinja2 server-rendered HTML |
| Database | PostgreSQL 16 (Docker) / SQLite (local dev) |
| Search | Elasticsearch 8.x |
| Threat Intel | OpenCTI (GraphQL) |
| Detection | TIDE (DuckDB + FastAPI) |
| AI | Ollama (local LLM) |
| PDF | WeasyPrint |
| Container | Docker Compose |

## Configuration

Copy `.env.deploy` to `.env` and configure:

```bash
# Database (auto-configured by docker-compose)
ION_DATABASE_URL=postgresql://ion:ion2025@postgres:5432/ion

# Admin
ION_ADMIN_PASSWORD=your-secure-password

# Elasticsearch
ION_ELASTICSEARCH_URL=http://your-es-ip:9200
ION_ELASTICSEARCH_USERNAME=elastic
ION_ELASTICSEARCH_PASSWORD=your-password

# TIDE Detection Engineering
ION_TIDE_URL=https://your-tide-ip
ION_TIDE_API_KEY=your-api-key
ION_TIDE_VERIFY_SSL=false

# OpenCTI Threat Intelligence
ION_OPENCTI_URL=http://your-opencti-ip:8080
ION_OPENCTI_TOKEN=your-token

# Ollama AI (optional)
ION_OLLAMA_ENABLED=true
ION_OLLAMA_URL=http://your-ollama-ip:11434
ION_OLLAMA_MODEL=llama3.2:latest
```

## RBAC Roles

| Role | Level | Key Permissions |
|------|-------|----------------|
| Analyst | L1 | Alert triage, cases, observables, playbook execution |
| Senior Analyst | L2 | L1 + escalated cases, observable trends |
| Principal Analyst | L3 | L2 + SLA compliance, mentoring |
| Forensic | — | Forensic investigations, evidence, chain of custody |
| Lead | — | All analyst + team management, playbook CRUD |
| Engineering | — | Integrations, system config, detection engineering |
| Admin | — | Full access + user management |

**Focus Mode:** Users with multiple roles can switch between them via the dashboard pill buttons.

## Default Login

- **Username:** `admin`
- **Password:** Value of `ION_ADMIN_PASSWORD` (default: `admin2025`)

## Docker Hub

```bash
docker pull ixion36/ion:0.9.43
# or
docker pull ixion36/ion:latest
```

## License

Proprietary — Guarded Glass Security Toolkit
