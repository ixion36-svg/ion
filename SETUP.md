# ION Setup Instructions

## Quick Start

### Docker Deployment (Recommended)

```bash
# Clone repository
git clone https://github.com/ion36-svg/ion.git
cd ion

# Configure environment
cp .env.example .env
# Edit .env with your Elasticsearch/OpenCTI URLs

# Build and start
docker build -t ion:latest .
docker-compose up -d

# Pull the default AI model (first time)
docker exec -it ion-ollama ollama pull llama3.1:8b

# Access at http://localhost:8000
```

### Local Development

```bash
# Install dependencies
pip install -e ".[dev]"

# Initialize database
python -m ion.cli.main init

# Upgrade database schema
python -m ion.cli.main upgrade

# Seed default users
python -m ion.cli.main seed-users --admin-password YourPassword123

# Start web server
python -m ion.cli.main web
```

Access at: http://localhost:8000

---

## Architecture

ION integrates with your existing infrastructure:

| Component | Included in Docker Image | Notes |
|-----------|-------------------------|-------|
| ION Web App | Yes | Core application |
| Ollama | Yes | Local AI/LLM service |
| Elasticsearch | **No** | Connect to existing cluster |
| Kibana | **No** | Connect for case sync |
| OpenCTI | **No** | Connect for threat intel |
| GitLab | **No** | Connect for issue tracking |

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_COOKIE_SECURE` | `false` | Set `true` for HTTPS |
| `ION_DEBUG_MODE` | `false` | Enable API docs (disable in prod) |
| `ION_ADMIN_PASSWORD` | `changeme` | Initial admin password |
| `ION_ELASTICSEARCH_ENABLED` | `true` | Enable ES integration |
| `ION_ELASTICSEARCH_URL` | - | Elasticsearch URL |
| `ION_ELASTICSEARCH_API_KEY` | - | ES API key |
| `ION_OPENCTI_ENABLED` | `true` | Enable OpenCTI |
| `ION_OPENCTI_URL` | - | OpenCTI URL |
| `ION_OPENCTI_TOKEN` | - | OpenCTI API token |
| `ION_OLLAMA_ENABLED` | `true` | Enable AI features |
| `ION_OLLAMA_URL` | `http://ollama:11434` | Ollama service URL |
| `ION_OLLAMA_MODEL` | `llama3.1:8b` | Default AI model |
| `ION_KIBANA_CASES_ENABLED` | `true` | Enable Kibana sync |
| `ION_KIBANA_URL` | - | Kibana URL |
| `ION_OIDC_ENABLED` | `true` | Enable Keycloak SSO |
| `ION_ACCOUNT_LOCKOUT_ENABLED` | `false` | Lock accounts after failed logins |

### Config File

Located at `.ion/config.json` (or `/data/.ion/config.json` in Docker):

```json
{
  "db_path": ".ion/ion.db",
  "default_format": "markdown",
  "cookie_secure": true,
  "debug_mode": false,
  "elasticsearch_enabled": true,
  "elasticsearch_url": "https://your-es:9200",
  "opencti_enabled": true,
  "opencti_url": "https://your-opencti:8080"
}
```

---

## Integration Setup

### Elasticsearch

1. Enable in `.env`:
   ```bash
   ION_ELASTICSEARCH_ENABLED=true
   ION_ELASTICSEARCH_URL=https://your-es:9200
   ION_ELASTICSEARCH_API_KEY=your-api-key
   ```

2. Test connection in ION: Settings → Integrations → Test

3. Configure alert index pattern (default: `.alerts-*,.watcher-history-*,alerts-*`)

### OpenCTI

1. Get API token from OpenCTI: Settings → API Access

2. Enable in `.env`:
   ```bash
   ION_OPENCTI_ENABLED=true
   ION_OPENCTI_URL=https://your-opencti:8080
   ION_OPENCTI_TOKEN=your-uuid-token
   ```

3. Test connection in ION: Settings → Integrations → Test

### Kibana Cases

1. Enable in `.env`:
   ```bash
   ION_KIBANA_CASES_ENABLED=true
   ION_KIBANA_URL=https://your-kibana:5601
   ION_KIBANA_USERNAME=elastic
   ION_KIBANA_PASSWORD=your-password
   ```

2. Cases created in ION will sync bidirectionally with Kibana

---

## Auto-Seeded Playbooks

On first startup, ION automatically seeds **6 default pattern-based investigation playbooks** for multi-alert attack detection:

- Ransomware Response (priority 99, auto-execute)
- Active Intrusion Response (priority 95, auto-execute)
- Data Exfiltration Response (priority 92, auto-execute)
- Forensics Investigation (priority 90, recommend only)
- Lateral Movement Containment (priority 85, auto-execute)
- Compromised Account Investigation (priority 80, recommend only)

These playbooks are created idempotently (safe to restart). They contain realistic SOC investigation steps and are triggered automatically when multi-alert patterns are detected on the same host or user. See the [README](README.md#multi-alert-pattern-detection) for details.

---

## Default Login

- **Username:** `admin`
- **Password:** `changeme` (or value of `ION_ADMIN_PASSWORD`)

**Important:** Change the admin password after first login!

---

## Default Roles

ION uses a 4-tier role hierarchy. All page routes are enforced server-side (unauthenticated requests redirect to `/login`, insufficient permissions return 403).

| Role | Permissions |
|------|-------------|
| **Analyst** | Alerts, cases, observables, playbooks, training, templates, documents, AI chat, notes |
| **Lead** | Analyst + topology, security dashboards |
| **Engineering** | Lead + integrations, system settings |
| **Admin** | Full access — user management, audit logs, all resources |

---

## Security Features

- **Server-side route enforcement**: All page routes require authentication; permission checks enforced via FastAPI dependencies
- Session-based authentication with secure cookies
- Session rotation on login (invalidates previous sessions)
- OIDC/Keycloak SSO support
- Role-based access control (RBAC) with 4-tier hierarchy
- **Global rate limiting** (120 req/min default, stricter on admin DB ops and AI chat)
- **Account lockout** (opt-in, disabled by default — 5 failed attempts → 15-min lock)
- **XSS sanitization**: DOMPurify on all Markdown rendering
- **Hardened CSP**: object-src, base-uri, form-action directives
- Security headers (HSTS, X-Frame-Options, Permissions-Policy)
- Timing-attack resistant login
- Sandboxed Jinja2 template rendering (SSTI protection)
- SSRF protection on integration endpoints
- CSRF protection for OIDC flows
- Attack detection with automatic IP blocking
- Audit logging

---

## Backup & Restore

### Docker

**Backup:**
```bash
docker run --rm -v ion-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/ion-backup.tar.gz -C /data .
```

**Restore:**
```bash
docker-compose down
docker run --rm -v ion-data:/data -v $(pwd):/backup \
  alpine sh -c "rm -rf /data/* && tar xzf /backup/ion-backup.tar.gz -C /data"
docker-compose up -d
```

### Local

```bash
cp -r .ion .ion-backup-$(date +%Y%m%d)
```

---

## Troubleshooting

### Container won't start

```bash
docker-compose logs ion
```

### Can't connect to Elasticsearch

1. Check URL is accessible from ION container
2. Verify API key or credentials
3. Check SSL certificate (set `verify_ssl: false` for self-signed)

### AI features not working

1. Check Ollama is running: `docker-compose logs ollama`
2. Verify model is pulled: `docker exec ion-ollama ollama list`
3. Pull model: `docker exec ion-ollama ollama pull llama3.1:8b`

### API docs not accessible

API documentation is disabled by default in production. To enable:
```bash
ION_DEBUG_MODE=true
```
Then restart the container.

---

## CLI Commands

```bash
# Database
python -m ion.cli.main init              # Initialize database
python -m ion.cli.main upgrade           # Upgrade schema
python -m ion.cli.main seed-users        # Create default users

# Server
python -m ion.cli.main web               # Start web server
python -m ion.cli.main web --port 8080   # Custom port
```

For more details, see [README.md](README.md).
