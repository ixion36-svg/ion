# DocForge

Documentation Template Management System with version control, template rendering, intelligent extraction, and SOC-focused NLP analysis.

## Features

- **Template Management**: Create, edit, and organize document templates in folders
- **Version Control**: Auto-save with snapshots, named checkpoints, diff, and rollback
- **Template Rendering**: Jinja2-based rendering with JSON/CSV data support
- **Multi-format Support**: Markdown, HTML, Plain Text, DOCX
- **Template Extraction**: Pattern detection to generate templates from existing documents
- **Folder Organization**: Organize templates and documents into hierarchical folders (SOI, SOP, KB, WI, etc.)
- **Tagging System**: Auto-assign to folders when tag matches folder name
- **SOC Entity Detection**: Detects IPs, CVEs, hashes, domains, MITRE ATT&CK IDs, and more
- **Spell Check**: Built-in spell checking with SOC/technical term awareness
- **Rewrite Suggestions**: Professional, concise, formal, and technical style improvements
- **Table Detection**: Recognizes Markdown, CSV, and TSV tables
- **Alert Investigation**: Elasticsearch-integrated SOC alert triage with case management, observables, and analytics
- **Web UI**: Browser-based interface with role-based access control
- **Authentication**: Local auth + optional Keycloak/OIDC SSO support
- **GitLab Integration**: Create, manage, and track GitLab issues directly from DocForge

## Installation

```bash
cd C:\Projects\docforge
pip install -e .
```

For development:
```bash
pip install -e ".[dev]"
```

## Quick Start

### Initialize DocForge

```bash
docforge init
```

### Start Web UI (Recommended)

```bash
docforge web
```

Then open http://127.0.0.1:8000 in your browser.

Options:
- `--host` / `-h`: Host to bind to (default: 127.0.0.1)
- `--port` / `-p`: Port to bind to (default: 8000)
- `--reload`: Enable auto-reload for development

### Default Login

- Username: `admin`
- Password: `changeme`

**Important:** Change the admin password after first login!

## SOC Features

### Entity Detection

DocForge automatically detects SOC-relevant entities in documents:

| Category | Entities Detected |
|----------|-------------------|
| **Network** | IPv4, IPv6, MAC addresses, domains, URLs, ports |
| **Security IDs** | CVE IDs (CVE-2024-1234), MITRE ATT&CK (T1059, S1234) |
| **Hashes** | MD5, SHA1, SHA256 |
| **Paths** | Windows paths, Unix paths, Registry keys |
| **Identifiers** | Email addresses, hostnames, process names (.exe, .dll) |
| **Metadata** | ISO timestamps, severity levels (CRITICAL, HIGH, etc.) |
| **Windows** | Event IDs, user accounts |

### Spell Check

- Intelligent spell checking that ignores technical terms
- Automatically skips: IPs, CVEs, hashes, URLs, acronyms
- Multiple suggestions with one-click correction

### Rewrite Suggestions

Four style modes for document improvement:
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

## Docker Deployment

### Quick Start

```bash
# Build image
docker build -t docforge:latest .

# Run
docker-compose up -d

# Access at http://localhost:8000
```

### Air-Gapped Deployment

See [DEPLOYMENT_GUIDE.md](deploy/DEPLOYMENT_GUIDE.md) for detailed instructions on deploying to secure/air-gapped environments.

## API Endpoints

### NLP & Extraction

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/extract/nlp-status` | GET | Check NLP/SOC pattern availability |
| `/api/extract/analyze` | POST | Analyze document for patterns |
| `/api/extract/generate` | POST | Generate template from document |
| `/api/extract/spell-check` | POST | Run spell check on text |
| `/api/extract/rewrite-suggestions` | POST | Get writing improvement suggestions |

### Collections (Folders)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/collections` | GET | List all folders |
| `/api/collections` | POST | Create folder |
| `/api/collections/{id}` | GET | Get folder details |
| `/api/collections/{id}` | PUT | Update folder |
| `/api/collections/{id}` | DELETE | Delete folder |

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

## GitLab Integration

DocForge integrates with GitLab to manage issues directly from the UI.

### Configuration

Configure GitLab via the web UI (GitLab page) or environment variables:

```bash
# Environment variables
DOCFORGE_GITLAB_ENABLED=true
DOCFORGE_GITLAB_URL=https://gitlab.example.com
DOCFORGE_GITLAB_TOKEN=glpat-xxxxxxxxxxxx
DOCFORGE_GITLAB_PROJECT_ID=group/project
```

Or in `.docforge/config.json`:
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
3. Copy the token and configure in DocForge

### Features

- **Create Issues**: Create GitLab issues with title, description, labels, assignees, and milestones
- **Manage Issues**: Close, reopen, and update issues
- **Comments**: Add comments to issues
- **Labels & Milestones**: View and assign project labels and milestones
- **Direct Links**: Quick links to view issues in GitLab

## Alert Investigation

DocForge includes a built-in alert investigation page (`/alerts`) that connects to Elasticsearch to provide SOC analysts with triage, case management, and analytics capabilities.

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

## Testing

```bash
pytest tests/ -v
pytest tests/ --cov=docforge --cov-report=term-missing
```

## Dependencies

Core:
- Python 3.11+
- FastAPI, SQLAlchemy, Jinja2
- NLTK (NLP processing)
- pyspellchecker (spell checking)

See [pyproject.toml](pyproject.toml) for full dependency list.

## License

MIT
