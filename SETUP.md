# IXION Setup Instructions

## Quick Start

### Docker Deployment (Recommended)

```bash
# Clone repository
git clone https://github.com/ixion36-svg/ixion.git
cd ixion

# Configure environment
cp .env.example .env
# Edit .env with your Elasticsearch/OpenCTI URLs

# Build and start
docker build -t ixion:latest .
docker-compose up -d

# Pull AI model (first time)
docker exec -it ixion-ollama ollama pull qwen2.5:0.5b

# Access at http://localhost:8000
```

### Local Development

```bash
# Install dependencies
pip install -e ".[dev]"

# Initialize database
python -m ixion.cli.main init

# Upgrade database schema
python -m ixion.cli.main upgrade

# Seed default users
python -m ixion.cli.main seed-users --admin-password YourPassword123

# Start web server
python -m ixion.cli.main web
```

Access at: http://localhost:8000

---

## Architecture

IXION integrates with your existing infrastructure:

| Component | Included in Docker Image | Notes |
|-----------|-------------------------|-------|
| IXION Web App | Yes | Core application |
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
| `IXION_COOKIE_SECURE` | `false` | Set `true` for HTTPS |
| `IXION_DEBUG_MODE` | `false` | Enable API docs (disable in prod) |
| `IXION_ADMIN_PASSWORD` | `changeme` | Initial admin password |
| `IXION_ELASTICSEARCH_ENABLED` | `false` | Enable ES integration |
| `IXION_ELASTICSEARCH_URL` | - | Elasticsearch URL |
| `IXION_ELASTICSEARCH_API_KEY` | - | ES API key |
| `IXION_OPENCTI_ENABLED` | `false` | Enable OpenCTI |
| `IXION_OPENCTI_URL` | - | OpenCTI URL |
| `IXION_OPENCTI_TOKEN` | - | OpenCTI API token |
| `IXION_OLLAMA_ENABLED` | `false` | Enable AI features |
| `IXION_OLLAMA_URL` | `http://ollama:11434` | Ollama service URL |
| `IXION_OLLAMA_MODEL` | `qwen2.5:0.5b` | Default AI model |
| `IXION_KIBANA_CASES_ENABLED` | `false` | Enable Kibana sync |
| `IXION_KIBANA_URL` | - | Kibana URL |
| `IXION_OIDC_ENABLED` | `false` | Enable Keycloak SSO |

### Config File

Located at `.ixion/config.json` (or `/data/.ixion/config.json` in Docker):

```json
{
  "db_path": ".ixion/ixion.db",
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
   IXION_ELASTICSEARCH_ENABLED=true
   IXION_ELASTICSEARCH_URL=https://your-es:9200
   IXION_ELASTICSEARCH_API_KEY=your-api-key
   ```

2. Test connection in IXION: Settings → Integrations → Test

3. Configure alert index pattern (default: `.alerts-*,.watcher-history-*,alerts-*`)

### OpenCTI

1. Get API token from OpenCTI: Settings → API Access

2. Enable in `.env`:
   ```bash
   IXION_OPENCTI_ENABLED=true
   IXION_OPENCTI_URL=https://your-opencti:8080
   IXION_OPENCTI_TOKEN=your-uuid-token
   ```

3. Test connection in IXION: Settings → Integrations → Test

### Kibana Cases

1. Enable in `.env`:
   ```bash
   IXION_KIBANA_CASES_ENABLED=true
   IXION_KIBANA_URL=https://your-kibana:5601
   IXION_KIBANA_USERNAME=elastic
   IXION_KIBANA_PASSWORD=your-password
   ```

2. Cases created in IXION will sync bidirectionally with Kibana

---

## Default Login

- **Username:** `admin`
- **Password:** `changeme` (or value of `IXION_ADMIN_PASSWORD`)

**Important:** Change the admin password after first login!

---

## Default Roles

| Role | Permissions |
|------|-------------|
| **Admin** | Full access to all resources |
| **Editor** | Create/edit templates and documents |
| **Viewer** | Read-only access |
| **Engineering** | Editor + system settings + integrations |

---

## Security Features

- Session-based authentication with secure cookies
- Session rotation on login (invalidates previous sessions)
- OIDC/Keycloak SSO support
- Role-based access control (RBAC)
- Rate limiting on authentication endpoints
- Security headers (CSP, HSTS, X-Frame-Options, Permissions-Policy)
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
docker run --rm -v ixion-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/ixion-backup.tar.gz -C /data .
```

**Restore:**
```bash
docker-compose down
docker run --rm -v ixion-data:/data -v $(pwd):/backup \
  alpine sh -c "rm -rf /data/* && tar xzf /backup/ixion-backup.tar.gz -C /data"
docker-compose up -d
```

### Local

```bash
cp -r .ixion .ixion-backup-$(date +%Y%m%d)
```

---

## Troubleshooting

### Container won't start

```bash
docker-compose logs ixion
```

### Can't connect to Elasticsearch

1. Check URL is accessible from IXION container
2. Verify API key or credentials
3. Check SSL certificate (set `verify_ssl: false` for self-signed)

### AI features not working

1. Check Ollama is running: `docker-compose logs ollama`
2. Verify model is pulled: `docker exec ixion-ollama ollama list`
3. Pull model: `docker exec ixion-ollama ollama pull qwen2.5:0.5b`

### API docs not accessible

API documentation is disabled by default in production. To enable:
```bash
IXION_DEBUG_MODE=true
```
Then restart the container.

---

## CLI Commands

```bash
# Database
python -m ixion.cli.main init              # Initialize database
python -m ixion.cli.main upgrade           # Upgrade schema
python -m ixion.cli.main seed-users        # Create default users

# Server
python -m ixion.cli.main web               # Start web server
python -m ixion.cli.main web --port 8080   # Custom port
```

For more details, see [README.md](README.md).
