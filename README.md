# IXION

**Intelligence eXchange & Integration Operations Network**

A Security Operations Center (SOC) platform with AI-powered analysis, alert triage, observable tracking, and threat intelligence integration.

## Features

- **AI Assistant**: Local LLM integration via Ollama for security analysis, code generation, and threat investigation
- **AI-Assisted Triage**: One-click AI analysis, observable extraction, MITRE technique suggestion, and contextual chat from alert detail view
- **AI-Powered Document Analysis**: Entity extraction, spell checking, and rewrite suggestions powered by Ollama
- **Alert Investigation**: Elasticsearch-integrated SOC alert triage with case management and analytics
- **Investigation Playbooks**: Step-based investigation workflows with trigger conditions for alert triage
- **Multi-Alert Pattern Detection**: Automatic detection of attack patterns across multiple alerts on the same host/user, with auto-triggered investigation playbooks
- **Saved Searches**: Save, share, and re-run Elasticsearch queries from Discover page
- **Observable Tracking**: Centralized observable management with cross-case correlation and enrichment
- **OpenCTI Integration**: IOC enrichment against OpenCTI threat intelligence
- **Template Management**: Document templates with version control and Jinja2 rendering
- **SOC Tools**: Client-side document processing tools for security analysts
- **Real-time Chat**: Team collaboration with chat rooms and expandable AI chat panel
- **Role-based Access**: Web UI with authentication and RBAC
- **GitLab Integration**: Issue tracking directly from IXION

---

## Deployment

### Architecture

IXION is designed to integrate with existing infrastructure:

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Infrastructure                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │Elasticsearch│  │   Kibana    │  │  OpenCTI    │          │
│  │  (alerts)   │  │  (cases)    │  │  (threat    │          │
│  │             │  │             │  │   intel)    │          │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │
│         │                │                │                  │
│         └────────────────┼────────────────┘                  │
│                          │                                   │
│                    ┌─────▼─────┐                             │
│                    │   IXION   │◄──── Docker Image           │
│                    │  (+ Ollama)│     (ixion:latest)         │
│                    └───────────┘                             │
└─────────────────────────────────────────────────────────────┘
```

**The IXION Docker image only contains:**
- IXION web application
- Ollama (local AI/LLM service)

**External services (deployed separately):**
- Elasticsearch - for alert data and log storage
- Kibana - for case management sync
- OpenCTI - for threat intelligence enrichment
- GitLab - for issue tracking (optional)

### Option 1: Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/ixion36-svg/ixion.git
cd ixion

# Copy and configure environment
cp .env.example .env
# Edit .env with your integration settings (ES, OpenCTI, etc.)

# Build IXION image
docker build -t ixion:latest .

# Start IXION + Ollama
docker-compose up -d

# Pull an AI model (first time only)
docker exec -it ixion-ollama ollama pull qwen2.5:0.5b

# Access at http://localhost:8000
```

**Note:** The `docker-compose.yml` only starts IXION and Ollama. Connect to your existing Elasticsearch/OpenCTI via environment variables.

### Option 2: Local Development

```bash
# Clone the repository
git clone https://github.com/ixion36-svg/ixion.git
cd ixion

# Install Python dependencies
pip install -e .

# Install Ollama (for AI features)
# Windows: Download from https://ollama.ai
# Linux: curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull qwen2.5:0.5b

# Start Ollama service
ollama serve

# In another terminal, start IXION
python -m uvicorn src.ixion.web.server:app --host 0.0.0.0 --port 8000

# Access at http://localhost:8000
```

---

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
# Required
IXION_ADMIN_PASSWORD=your-secure-password

# Security (Production)
IXION_COOKIE_SECURE=true           # Enable for HTTPS deployments
IXION_DEBUG_MODE=false             # Disable API docs in production (default)

# AI Features (Ollama)
IXION_OLLAMA_ENABLED=true
IXION_OLLAMA_URL=http://ollama:11434    # Docker service name
IXION_OLLAMA_MODEL=qwen2.5:0.5b         # or qwen2.5-coder:7b for better results

# Elasticsearch (your existing cluster)
IXION_ELASTICSEARCH_ENABLED=true
IXION_ELASTICSEARCH_URL=https://your-es-cluster:9200
IXION_ELASTICSEARCH_API_KEY=your-api-key
# Or use username/password:
# IXION_ELASTICSEARCH_USERNAME=elastic
# IXION_ELASTICSEARCH_PASSWORD=your-password

# OpenCTI (your existing instance)
IXION_OPENCTI_ENABLED=true
IXION_OPENCTI_URL=https://your-opencti:8080
IXION_OPENCTI_TOKEN=your-api-token

# Kibana Cases Sync (optional)
IXION_KIBANA_CASES_ENABLED=true
IXION_KIBANA_URL=https://your-kibana:5601
```

---

## Default Login

- **Username:** `admin`
- **Password:** `changeme` (or value of `IXION_ADMIN_PASSWORD`)

**Important:** Change the admin password after first login!

---

## AI Models

Recommended models for Ollama:

| Model | Size | Use Case |
|-------|------|----------|
| `qwen2.5:0.5b` | ~400MB | Testing, low resources |
| `qwen2.5:3b` | ~2GB | Balanced performance |
| `qwen2.5-coder:7b` | ~4GB | Best for code/security analysis |
| `llama3.2:3b` | ~2GB | General purpose |

Pull models with:
```bash
ollama pull qwen2.5-coder:7b
```

---

## SOC Features

### Entity Detection

IXION automatically detects SOC-relevant entities in documents:

| Category | Entities Detected |
|----------|-------------------|
| **Network** | IPv4, IPv6, MAC addresses, domains, URLs, ports |
| **Security IDs** | CVE IDs (CVE-2024-1234), MITRE ATT&CK (T1059, S1234) |
| **Hashes** | MD5, SHA1, SHA256 |
| **Paths** | Windows paths, Unix paths, Registry keys |
| **Identifiers** | Email addresses, hostnames, process names (.exe, .dll) |
| **Metadata** | ISO timestamps, severity levels (CRITICAL, HIGH, etc.) |
| **Windows** | Event IDs, user accounts |

### AI-Powered Spell Check

- Intelligent spell checking powered by local AI (Ollama)
- Context-aware: ignores technical terms, IPs, CVEs, hashes, URLs, acronyms
- Multiple suggestions with one-click correction

### AI Rewrite Suggestions

Four style modes for document improvement (powered by Ollama):
- **Professional**: Removes filler words, stronger language
- **Concise**: Simplifies verbose phrases
- **Formal**: Expands contractions for formal documents
- **Technical**: Uses precise security terminology

### Table Detection

Automatically detects and parses tables in:
- Markdown format (`| col1 | col2 |`)
- CSV format (comma-separated)
- TSV format (tab-separated)

## Folder Organization

Templates and documents can be organized into hierarchical folders:

```
SOI/
├── Network/
├── Endpoint/
└── Cloud/
SOP/
├── Incident Response/
└── Threat Hunting/
KB/
WI/
```

**Auto-assignment**: When you tag a template with a folder name (e.g., "SOI"), it's automatically assigned to that folder.

## CLI Commands

### Template Commands
- `docforge template create` - Create a new template
- `docforge template list` - List all templates
- `docforge template show <id>` - Show template details
- `docforge template edit <id>` - Edit a template
- `docforge template delete <id>` - Delete a template
- `docforge template search <query>` - Search templates
- `docforge template import <file>` - Import from file
- `docforge template export <id>` - Export to file
- `docforge template tag <id>` - Manage tags

### Version Commands
- `docforge version list <id>` - List versions
- `docforge version show <id> <version>` - Show version details
- `docforge version checkpoint <id>` - Create checkpoint
- `docforge version diff <id> <from> <to>` - Show diff
- `docforge version rollback <id> <to>` - Rollback to version
- `docforge version prune <id>` - Delete old versions

### Render Commands
- `docforge render preview <id>` - Preview rendered template
- `docforge render run <id>` - Render and save
- `docforge render variables <id>` - Show template variables
- `docforge render validate <id>` - Validate template syntax

### Extract Commands
- `docforge extract analyze <file>` - Analyze document patterns
- `docforge extract generate <file>` - Generate template
- `docforge extract schema <file>` - Generate JSON schema

### Document Commands
- `docforge document list` - List rendered documents
- `docforge document show <id>` - Show document details
- `docforge document regenerate <id>` - Regenerate document
- `docforge document delete <id>` - Delete document
- `docforge document export <id>` - Export document

## Template Syntax

Templates use Jinja2 syntax:

```jinja2
# Welcome, {{ name }}!

Hello {{ name | title }},

{% if department %}
You work in the {{ department }} department.
{% endif %}

Your tasks:
{% for task in tasks %}
- {{ task }}
{% endfor %}
```

## Data Files

Provide data as JSON:
```json
{
  "name": "John Doe",
  "department": "Engineering",
  "tasks": ["Review code", "Write tests"]
}
```

Or CSV:
```csv
name,email,department
John,john@example.com,Engineering
Jane,jane@example.com,Marketing
```

## Docker Details

### What's Included

The `docker-compose.yml` deploys:
- **ixion** - IXION web application (port 8000)
- **ollama** - Local LLM service for AI features (internal only)

### Resource Requirements

| Service | CPU | Memory | Storage |
|---------|-----|--------|---------|
| IXION | 0.5-2 cores | 256MB-1GB | ~100MB |
| Ollama | 1-4 cores | 2-8GB | ~5GB (per model) |

### Air-Gapped Deployment

See [DEPLOYMENT_GUIDE.md](deploy/DEPLOYMENT_GUIDE.md) for detailed instructions on deploying to secure/air-gapped environments.

## API Endpoints

### AI & Extraction

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/extract/nlp-status` | GET | Check AI/SOC pattern availability |
| `/api/extract/analyze` | POST | Analyze document for patterns |
| `/api/extract/generate` | POST | Generate template from document |
| `/api/extract/spell-check` | POST | AI-powered spell check |
| `/api/extract/rewrite-suggestions` | POST | AI-powered writing improvement suggestions |
| `/api/extract/apply-rewrites` | POST | Apply AI rewrite to text |

### AI Assistant

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ai/status` | GET | Check AI availability, model info, and queue status |
| `/api/ai/chat` | POST | Send chat message (non-streaming) |
| `/api/ai/chat/stream` | POST | Send chat message with SSE streaming response |
| `/api/ai/analyze/alert` | POST | Analyze alert data and return AI assessment |
| `/api/ai/triage/suggest` | POST | Structured triage suggestions (observables, MITRE techniques, priority) |
| `/api/ai/case/generate` | POST | Generate case fields (title, description, evidence) from alert context |

### Saved Searches

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/saved-searches` | GET | List user's + shared searches |
| `/api/saved-searches` | POST | Create new saved search |
| `/api/saved-searches/{id}` | GET | Get search by ID |
| `/api/saved-searches/{id}` | PUT | Update saved search (owner only) |
| `/api/saved-searches/{id}` | DELETE | Delete saved search (owner only) |
| `/api/saved-searches/{id}/execute` | POST | Run search and return results |
| `/api/saved-searches/{id}/favorite` | POST | Toggle favorite status |

### Investigation Playbooks

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/playbooks` | GET | List all playbooks |
| `/api/playbooks` | POST | Create playbook with steps |
| `/api/playbooks/{id}` | GET | Get playbook with steps |
| `/api/playbooks/{id}` | PUT | Update playbook |
| `/api/playbooks/{id}` | DELETE | Delete playbook |
| `/api/elasticsearch/alerts/{id}/recommended-playbooks` | GET | Get matching playbooks for alert |
| `/api/elasticsearch/alerts/{id}/playbook/{pb_id}/start` | POST | Start playbook execution |
| `/api/playbook-executions/{id}` | GET | Get execution status |
| `/api/playbook-executions/{id}/steps/{step_id}` | PUT | Mark step complete/skipped |
| `/api/alerts/host-patterns` | GET | Detect multi-alert attack patterns across hosts/users |

### Collections (Folders)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/collections` | GET | List all folders |
| `/api/collections` | POST | Create folder |
| `/api/collections/{id}` | GET | Get folder details |
| `/api/collections/{id}` | PUT | Update folder |
| `/api/collections/{id}` | DELETE | Delete folder |

### OpenCTI Integration

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/opencti/config` | GET | Get OpenCTI configuration status |
| `/api/opencti/config` | POST | Configure OpenCTI integration (admin) |
| `/api/opencti/config` | DELETE | Disable OpenCTI integration (admin) |
| `/api/opencti/test` | GET | Test OpenCTI connection |
| `/api/opencti/enrich` | POST | Enrich a single observable (type + value) |
| `/api/opencti/enrich/batch` | POST | Enrich multiple observables |

### GitLab Integration

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/gitlab/config` | GET | Get GitLab configuration status |
| `/api/gitlab/config` | POST | Configure GitLab integration (admin) |
| `/api/gitlab/test` | GET | Test GitLab connection |
| `/api/gitlab/issues` | GET | List issues |
| `/api/gitlab/issues` | POST | Create new issue |
| `/api/gitlab/issues/{iid}` | GET | Get issue details |
| `/api/gitlab/issues/{iid}` | PUT | Update issue |
| `/api/gitlab/issues/{iid}/close` | POST | Close issue |
| `/api/gitlab/issues/{iid}/reopen` | POST | Reopen issue |
| `/api/gitlab/issues/{iid}/comments` | GET | List issue comments |
| `/api/gitlab/issues/{iid}/comments` | POST | Add comment to issue |
| `/api/gitlab/labels` | GET | List project labels |
| `/api/gitlab/milestones` | GET | List project milestones |
| `/api/gitlab/members` | GET | List project members |

## OpenCTI Integration

IXION integrates with [OpenCTI](https://www.opencti.io/) to enrich alert observables with threat intelligence. When investigating an alert, analysts can click "Enrich via OpenCTI" to look up IPs, domains, hashes, and URLs against the OpenCTI platform and see matching indicators, threat actors, and threat scores inline.

### Configuration

```bash
# Environment variables
IXION_OPENCTI_ENABLED=true
IXION_OPENCTI_URL=https://opencti.example.com
IXION_OPENCTI_TOKEN=your-api-token-uuid
IXION_OPENCTI_VERIFY_SSL=true
```

Or in `.ixion/config.json`:
```json
{
    "opencti_enabled": true,
    "opencti_url": "https://opencti.example.com",
    "opencti_token": "your-api-token-uuid",
    "opencti_verify_ssl": true
}
```

### Test Instance

A Docker Compose stack with seed data is provided for local testing:

```bash
cd test-opencti
docker compose up -d
python seed_opencti.py
```

See [OPENCTI_INTEGRATION.md](deploy/OPENCTI_INTEGRATION.md) for full setup details, API reference, and troubleshooting.

## GitLab Integration

IXION integrates with GitLab to manage issues directly from the UI.

### Configuration

Configure GitLab via the web UI (Settings → Integrations) or environment variables:

```bash
# Environment variables
IXION_GITLAB_ENABLED=true
IXION_GITLAB_URL=https://gitlab.example.com
IXION_GITLAB_TOKEN=glpat-xxxxxxxxxxxx
IXION_GITLAB_PROJECT_ID=group/project
```

Or in `.ixion/config.json`:
```json
{
    "gitlab_enabled": true,
    "gitlab_url": "https://gitlab.example.com",
    "gitlab_token": "glpat-xxxxxxxxxxxx",
    "gitlab_project_id": "group/project"
}
```

### Required GitLab Token Scopes

Create a Personal Access Token with the `api` scope:
1. Go to GitLab > User Settings > Access Tokens
2. Create a token with the `api` scope
3. Copy the token and configure in IXION

### Features

- **Create Issues**: Create GitLab issues with title, description, labels, assignees, and milestones
- **Manage Issues**: Close, reopen, and update issues
- **Comments**: Add comments to issues
- **Labels & Milestones**: View and assign project labels and milestones
- **Direct Links**: Quick links to view issues in GitLab

## Alert Investigation

IXION includes a built-in alert investigation page (`/alerts`) that connects to Elasticsearch to provide SOC analysts with triage, case management, and analytics capabilities.

### Triage & Observables

- **Alert Table**: Sortable, filterable table showing severity, title, host, user, rule, case, status, and time
- **Triage Workflow**: Per-alert status tracking (open, investigating, escalated, resolved, closed, false positive)
- **Observables**: Auto-extracted from alert data — hostnames, IPs, URLs, domains, user accounts via ECS field mapping
- **Auto-populate on Case Creation**: When a case is created from an alert, observables are populated server-side immediately (idempotent — won't overwrite existing observables)
- **Comments**: Per-alert discussion thread for analyst collaboration

### Case Management

- **Case Creation**: Create investigation cases from alerts with auto-populated title, description, severity, affected hosts/users, triggered rules, and evidence summary
- **Case Management Modal**: Full overlay modal accessible from the cases side panel or the alert detail Case tab, with:
  - Editable status (open, in_progress, closed) and severity dropdowns
  - Read-only metadata (created by, assigned to, dates)
  - Context tags (affected hosts, users, triggered rules)
  - Evidence summary and description
  - Linked alerts list with triage status indicators
  - Investigation notes journal with add-note capability
- **Manage Case Button**: Available in the alert detail Case tab for quick access

### AI-Assisted Triage

When Ollama is running, AI assist buttons appear throughout the alert investigation workflow:

| Feature | Location | Description |
|---------|----------|-------------|
| **AI Analyze** | Alert detail modal | One-click AI analysis of alert context, severity assessment, and recommendations |
| **AI Extract** | Triage bar (Observables) | AI extracts observables (IPs, domains, hostnames, URLs, user accounts) from alert data |
| **AI Suggest** | Triage bar (MITRE) | AI suggests MITRE ATT&CK technique mappings based on alert content |
| **Discuss with AI** | Alert detail + enrichment results | Opens AI chat panel pre-loaded with full alert context (metadata, observables, enrichment results) for conversational investigation |
| **AI Summary** | Case management | Generates AI summary of case details and linked alerts |

The chat panel is expandable (click the expand icon in the header) for a larger workspace when discussing complex investigations.

All AI features degrade gracefully - buttons are hidden when Ollama is unavailable.

### Analytics Dashboard

A collapsible analytics panel (no external dependencies — pure SVG/CSS) provides:

| Visualization | Description |
|---------------|-------------|
| **Alert Trend** | Stacked bar chart of alert volume over time (auto-sized buckets based on selected time range). Critical and high severity alerts shown in red/orange |
| **Severity Breakdown** | Donut chart with counts and percentages for critical, high, medium, low, and info |
| **Status Overview** | Donut chart showing open, acknowledged, and resolved alert distribution |
| **Geographic Origin** | Equirectangular world map plotting alert source locations from ECS geo fields (`source.geo`, `destination.geo`, `client.geo`, `server.geo`, `host.geo`). Dot size scales by count, color by severity |
| **Top Hosts** | Horizontal bar chart of the top 7 hosts by alert count |
| **Top Rules** | Horizontal bar chart of the top 7 detection rules by alert count |

Geo data is extracted from standard ECS fields populated by Elasticsearch's GeoIP ingest processor. No external mapping libraries are used.

### Alert Investigation API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/elasticsearch/alerts` | GET | List alerts (params: hours, severity, status, limit) |
| `/api/elasticsearch/alerts/stats` | GET | Alert statistics and aggregations |
| `/api/elasticsearch/alerts/{id}/triage` | GET | Get triage state and comments for an alert |
| `/api/elasticsearch/alerts/{id}/triage` | PUT | Update triage status, assignee, priority, observables |
| `/api/elasticsearch/alerts/{id}/triage/auto-populate-observables` | POST | Auto-populate observables from alert context |
| `/api/elasticsearch/alerts/triage/batch` | POST | Batch fetch triage data (including case info) for multiple alerts |
| `/api/elasticsearch/alerts/{id}/comments` | POST | Add comment to an alert |
| `/api/elasticsearch/alerts/{id}/related` | GET | Get related alerts by host, user, rule |
| `/api/elasticsearch/alerts/cases` | GET | List investigation cases |
| `/api/elasticsearch/alerts/cases` | POST | Create case (with optional alert_contexts for auto-populating observables) |
| `/api/elasticsearch/alerts/cases/{id}` | GET | Get case detail with linked alerts and notes |
| `/api/elasticsearch/alerts/cases/{id}` | PATCH | Update case (status, severity, title, description) |
| `/api/elasticsearch/alerts/cases/{id}/notes` | POST | Add investigation note to a case |

## Saved Searches

Save, share, and re-run Elasticsearch queries from the Discover page.

### Features

- **Save Current Search**: Save index pattern, query, time range, and sort settings
- **Share with Team**: Optionally share saved searches with other analysts
- **Favorites**: Mark frequently-used searches for quick access
- **Execution Tracking**: Track how often searches are run and when they were last used
- **One-Click Execute**: Run saved searches directly from the dropdown

### Usage

1. Navigate to the **Discover** page
2. Configure your search (index pattern, query, time range)
3. Click **Save Search** to save the current configuration
4. Access saved searches from the **Saved Searches** dropdown
5. Click a search to load its parameters, or click **Run** to execute immediately

## Investigation Playbooks

Step-based investigation workflows that guide analysts through alert triage.

### Features

- **Trigger Conditions**: Automatically recommend playbooks based on:
  - Rule name patterns (regex matching)
  - Alert severity levels
  - MITRE ATT&CK techniques and tactics
- **Step Types**:
  - `manual_checklist`: Checklist items for analyst verification
  - `auto_enrich_observables`: Automatic IOC enrichment via OpenCTI
  - `auto_update_status`: Automatic triage status updates
  - `auto_create_case`: Automatic case creation
- **Execution Tracking**: Track playbook progress per alert
- **Required Steps**: Mark critical steps that must be completed

### Usage

1. Navigate to **Playbooks** (Admin menu) to create playbooks
2. Define trigger conditions (which alerts should recommend this playbook)
3. Add steps with titles, descriptions, and types
4. When investigating an alert, recommended playbooks appear in the triage bar
5. Start a playbook and mark steps as complete during investigation

### Playbook Management

| Action | Description |
|--------|-------------|
| Create | Define name, description, trigger conditions, and steps |
| Edit | Modify playbook configuration and steps |
| Activate/Deactivate | Toggle whether playbook is recommended for alerts |
| Priority | Higher priority playbooks are checked first for matching |

## Multi-Alert Pattern Detection

IXION automatically detects attack patterns when multiple alerts accumulate on the same host or user, recommending (or auto-starting) the appropriate investigation playbook.

### How It Works

1. Alerts are grouped by host or user
2. Six built-in pattern evaluators analyze each group for known attack signatures
3. Detected patterns are matched to seeded playbooks via `trigger_conditions.pattern_id`
4. High-confidence patterns (active intrusion, lateral movement, data exfiltration, ransomware) auto-start their playbook execution

### Default Pattern Playbooks

Six investigation playbooks are automatically seeded on startup:

| Playbook | Priority | Auto-Execute | Pattern Detected |
|----------|----------|-------------|------------------|
| Ransomware Response | 99 | Yes | File encryption/rename + privilege escalation on same host |
| Active Intrusion Response | 95 | Yes | Alerts spanning 3+ MITRE tactics on same host |
| Data Exfiltration Response | 92 | Yes | C2/beacon + exfiltration alerts on same host |
| Forensics Investigation | 90 | No | 3+ distinct rules on same host, at least 1 critical/high |
| Lateral Movement Containment | 85 | Yes | Lateral movement technique + alerts on 2+ hosts from same source |
| Compromised Account Investigation | 80 | No | Multiple auth failures + suspicious activity for same user |

### Pattern Detections Panel

The alerts page includes a collapsible **Pattern Detections** panel that:
- Displays detected patterns with severity badges and affected host/user
- Shows alert count, distinct rule count, and MITRE tactic count per pattern
- Provides "Start Playbook" buttons (or "View Execution" for auto-started patterns)
- Allows filtering the alert table to show only alerts in a pattern group
- Dismissible per session via sessionStorage
- Auto-refreshes when alerts are reloaded

## SOC Tools

The Tools page (`/tools`) provides a suite of client-side document processing utilities for security analysts. All text processing happens in the browser—no sensitive data is sent to the server (except for IOC Lookup which queries OpenCTI).

### Available Tools

| Tool | Description |
|------|-------------|
| **IOC Processor** | Defang/refang URLs, IPs, and emails. Extract IOCs from text. Custom find/replace rules saved to localStorage. |
| **Timestamp Converter** | Convert between Unix (seconds/milliseconds), ISO 8601, RFC 2822, local time, and Windows FILETIME formats. |
| **Hash Identifier** | Identify hash types (MD5, SHA-1, SHA-256, SHA-512, NTLM, bcrypt, CRC32, etc.) by length and format. |
| **URL Parser** | Parse URLs into components (protocol, host, path, query parameters, fragment). Shows defanged version. |
| **Regex Tester** | Test regular expressions with highlighting, capture groups, and match statistics. |
| **Email Header Analyzer** | Parse email headers to extract key fields, authentication results, mail path (Received chain), and IOCs. |
| **Log Parser** | Auto-detect and parse JSON, CEF, Syslog (RFC 3164), Apache access logs, Windows Event XML, and Key=Value formats. |
| **Encoding/Decoding** | Convert between plain text, Base64, Hex, URL encoding, HTML entities, Binary, ROT13, and ASCII decimal. |
| **IOC Lookup** | Query OpenCTI for threat intelligence on IPs, domains, hashes, and URLs. Supports single and bulk lookups with CSV export. |

### IOC Processor Features

- **Auto-detect IOCs**: URLs, IPv4 addresses, email addresses, domains, MD5/SHA1/SHA256 hashes
- **Defang/Refang**: Convert `http://evil.com` → `hxxp://evil[.]com` and back
- **Extract IOCs**: Pull all detected IOCs into a clean list
- **Quick Actions**: Base64 encode/decode, URL encode/decode, uppercase/lowercase, sort/unique/reverse lines, remove empty lines, trim whitespace
- **Custom Rules**: Create find/replace rules that persist in localStorage

### Timestamp Formats Supported

| Format | Example |
|--------|---------|
| Unix (seconds) | `1706454000` |
| Unix (milliseconds) | `1706454000000` |
| ISO 8601 | `2024-01-28T15:00:00Z` |
| Local Time | `2024-01-28 15:00:00` |
| RFC 2822 | `Sun, 28 Jan 2024 15:00:00 +0000` |
| Windows FILETIME | `133508412000000000` |

### Log Formats Auto-Detected

- **JSON**: Standard JSON objects
- **CEF**: Common Event Format (`CEF:0|vendor|product|...`)
- **Syslog**: RFC 3164 format (`Jan 28 15:00:00 hostname process[pid]: message`)
- **Apache**: Combined/Common log format
- **Windows XML**: Windows Event Log XML format
- **Key=Value**: Generic key=value pair format

## Testing

```bash
pytest tests/ -v
pytest tests/ --cov=docforge --cov-report=term-missing
```

## Dependencies

Core:
- Python 3.11+
- FastAPI, SQLAlchemy, Jinja2
- Ollama (AI-powered analysis via local LLM)

See [pyproject.toml](pyproject.toml) for full dependency list.

## License

MIT
