<!-- ion-doc:type=DEPLOYMENT GUIDE -->
<!-- ion-doc:title=ION Deployment Guide -->
<!-- ion-doc:subtitle=Production deployment topology, container orchestration, environment configuration -->
<!-- ion-doc:version=0.62.0 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Operators, SREs, deployment engineers -->
<!-- ion-doc:date=2026-07-30 -->

# ION Deployment Guide

Production deployment guide for ION (Intelligent Operating Network).

---

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Docker Engine | 24.0+ | 27.0+ |
| Docker Compose | v2.20+ | v2.30+ |
| Host RAM | 16 GB | 64 GB |
| Host CPU | 4 cores | 8+ cores |
| Elasticsearch | 8.11+ | 8.15+ |
| PostgreSQL | 16 (bundled) | 16 (bundled) |
| Disk | 50 GB | 200 GB+ (depends on log volume) |

ION ships as a Docker Compose stack with PostgreSQL bundled. Elasticsearch and Kibana are external -- you bring your own cluster.

---

## Step-by-Step Deployment

### 1. Clone the Repository

```bash
git clone https://github.com/ixion36-svg/ion.git
cd ion
```

### 2. Configure Environment

```bash
cp .env.deploy .env
```

Edit `.env` with your environment-specific values. At minimum, set:

```bash
# Security -- change these from defaults
ION_ADMIN_PASSWORD=<strong-password>
ION_DB_PASSWORD=<strong-password>

# Elasticsearch (required for alert functionality)
ION_ELASTICSEARCH_URL=https://your-es-host:9200
ION_ELASTICSEARCH_USERNAME=elastic
ION_ELASTICSEARCH_PASSWORD=<es-password>
# OR use an API key instead:
# ION_ELASTICSEARCH_API_KEY=<base64-encoded-api-key>

# Kibana (required for case sync)
ION_KIBANA_URL=https://your-kibana-host:5601
ION_KIBANA_USERNAME=elastic
ION_KIBANA_PASSWORD=<kibana-password>
```

### 3. Start the Stack

```bash
docker compose up -d
```

This starts three containers:

| Container | Purpose |
|-----------|---------|
| `ion-postgres` | PostgreSQL 16 database |
| `ion` | ION application (FastAPI + 4 uvicorn workers) |
| `ion-seeder` | One-shot data population (KB articles, playbooks), then exits |

To include the built-in Ollama LLM service:

```bash
docker compose --profile ai up -d
```

### 4. Verify Health

```bash
# Basic health check
curl http://localhost:8000/api/health

# Deep health check (checks DB, ES, integrations)
curl http://localhost:8000/api/health/deep
```

### 5. Log In

Open `http://localhost:8000` in a browser. Default credentials:

- **Username:** `admin`
- **Password:** Value of `ION_ADMIN_PASSWORD` (default: `admin2025`)

### 6. Seed Additional Data (Optional)

The seeder container automatically populates the knowledge base and playbooks on first start. For additional seed data (test alerts, SOC team users), run the seed scripts manually:

```bash
# Seed test alerts into Elasticsearch
docker exec ion python /app/seed_ion_data.py

# Seed from outside the container (requires Python + requests)
python seed_alerts.py
python seed_skills_team.py
```

---

## Environment Variable Reference

All configuration is via `ION_*` environment variables loaded from `.env`. Every integration follows the `ION_<NAME>_ENABLED` + `_URL` + auth pattern and is **off / unconfigured by default** unless noted.

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
| `ION_ELASTICSEARCH_ALERT_INDEX` | `.alerts-security.alerts-production` | Alert index pattern |
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
| `ION_ARKIME_USERNAME` | -- | HTTP Basic username (the only supported auth) |
| `ION_ARKIME_PASSWORD` | -- | HTTP Basic password |
| `ION_ARKIME_VERIFY_SSL` | `false` | Verify Arkime TLS certificate |
| `ION_ARKIME_PUBLIC_URL` | `ION_ARKIME_URL` | Viewer URL reachable from analyst browsers (deep links) |
| `ION_ARKIME_RETENTION_ENABLED` | `true` | PCAP-retention awareness loop (analysis rescue before capture expiry) |
| `ION_ARKIME_RETENTION_INTERVAL_MINUTES` | `60` | Retention loop interval |
| `ION_ARKIME_RETENTION_MARGIN_HOURS` | `12` | Rescue window before the retention horizon |
| `ION_ARKIME_RTMON_JA4_ENABLED` | `true` | RTMON known-bad JA4 detector (no-op while the blocklist is empty) |
| `ION_ARKIME_RTMON_JA4_BLOCKLIST` | -- | `ja4=label,ja4=label` known-bad TLS fingerprints |
| `ION_ARKIME_TAG_WRITEBACK` | `false` | Tag case sessions `ion-<case>` in Arkime (needs a write-enabled viewer user) |
| `ION_WISE_TOKEN` | -- | Enables `/api/wise/ion-iocs` (WISE intel feed); endpoint is 404 while unset |
| `ION_WISE_MAX_IOCS` | `10000` | Cap per WISE feed response |

### Ollama (AI / LLM — Bob)

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_OLLAMA_ENABLED` | `true` | Enable Ollama AI features |
| `ION_OLLAMA_URL` | `http://ollama:11434` | Ollama API URL |
| `ION_OLLAMA_MODEL` | `hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF` | Default Bob model (security-tuned, Llama-3.1-8B based) |
| `ION_OLLAMA_NUM_CTX` | `16384` | Context window; raise toward 65536 on RAM-rich hosts |
| `ION_OLLAMA_TIMEOUT` | `300` | Request timeout (seconds) |
| `ION_OLLAMA_VERIFY_SSL` | `false` | Verify Ollama TLS certificate |

### Additional enrichment integrations

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_VIRUSTOTAL_ENABLED` / `ION_VIRUSTOTAL_API_KEY` | `false` / -- | VirusTotal observable enrichment |
| `ION_SHODAN_ENABLED` / `ION_SHODAN_API_KEY` | `false` / -- | Shodan internet-facing asset intel |
| `ION_ABUSEIPDB_ENABLED` / `ION_ABUSEIPDB_API_KEY` | `false` / -- | AbuseIPDB IP reputation |
| `ION_DFIR_IRIS_ENABLED` / `ION_DFIR_IRIS_URL` / `ION_DFIR_IRIS_API_KEY` | `false` / -- / -- | DFIR-IRIS case escalation |

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

### Optional server modes (default off)

| Variable | Default | Description |
|----------|---------|-------------|
| `ION_MCP_ENABLED` | `false` | Expose core SOC data as MCP tools at `POST /api/mcp` |
| `ION_METRICS_ENABLED` | `false` | Serve Prometheus OpenMetrics at `GET /metrics` |
| `ION_METRICS_TOKEN` | -- | Optional bearer token required to scrape `/metrics` |
| `ION_APM_ENABLED` | `false` | Enable Elastic APM instrumentation |

---

## TLS / SSL Configuration

ION supports TLS at three levels:

### Option A: Reverse Proxy TLS Termination (Recommended)

Use nginx (see [Reverse Proxy](#reverse-proxy-nginx) below) to terminate TLS. ION runs HTTP internally.

### Option B: Direct HTTPS via Uvicorn

Set in `.env`:

```bash
ION_SSL_CERT=/etc/ssl/certs/ion.pem
ION_SSL_KEY=/etc/ssl/private/ion.key
```

Mount the certificate files into the container via `docker-compose.override.yml`:

```yaml
services:
  ion:
    volumes:
      - ./certs/ion.pem:/etc/ssl/certs/ion.pem:ro
      - ./certs/ion.key:/etc/ssl/private/ion.key:ro
```

### Option C: Custom CA Bundle for Outbound Connections

When your Elasticsearch, Kibana, Keycloak, or other services use certificates signed by an internal CA:

```bash
# In .env
ION_CA_BUNDLE=/etc/ssl/certs/custom-ca.pem

# In docker-compose.yml (already configured -- just set ION_CA_CERT in .env)
# The compose file mounts ${ION_CA_CERT:-/dev/null} to /etc/ssl/certs/custom-ca.pem
```

Set `ION_CA_CERT` in `.env` to the path of your CA certificate on the Docker host:

```bash
ION_CA_CERT=/path/to/your/internal-ca.pem
ION_CA_BUNDLE=/etc/ssl/certs/custom-ca.pem
```

Per-integration SSL verification can be controlled individually:

```bash
ION_ELASTICSEARCH_VERIFY_SSL=true
ION_KIBANA_VERIFY_SSL=true
ION_TIDE_VERIFY_SSL=true
ION_OPENCTI_VERIFY_SSL=true
ION_ARKIME_VERIFY_SSL=true
ION_OIDC_VERIFY_SSL=true
ION_OLLAMA_VERIFY_SSL=false
ION_GITLAB_VERIFY_SSL=true
```

---

## Keycloak SSO Setup

ION supports OpenID Connect (OIDC) authentication via Keycloak.

### 1. Create a Keycloak Realm

Create a new realm (e.g., `ion`) or use an existing one.

### 2. Create a Client

In the realm, create a new client:

| Setting | Value |
|---------|-------|
| Client ID | `ion` |
| Client Protocol | `openid-connect` |
| Access Type | `confidential` |
| Valid Redirect URIs | `https://ion.example.com/*` |
| Web Origins | `https://ion.example.com` |

After saving, note the **Client Secret** from the Credentials tab.

### 3. Configure Role Mapping

ION maps Keycloak realm roles to ION roles. Create realm roles in Keycloak matching ION role names:

- `analyst`, `senior_analyst`, `principal_analyst`, `lead`, `forensic`
- `soc_engineer`, `senior_engineer`, `platform_engineer`, `engineering`
- `admin`

Assign these roles to users in Keycloak. ION reads roles from the `realm_access.roles` JWT claim by default.

### 4. Configure ION

Set in `.env`:

```bash
ION_OIDC_ENABLED=true
ION_OIDC_KEYCLOAK_URL=https://keycloak.example.com
ION_OIDC_REALM=ion
ION_OIDC_CLIENT_ID=ion
ION_OIDC_CLIENT_SECRET=<client-secret-from-step-2>
ION_OIDC_VERIFY_SSL=true
ION_BASE_URL=https://ion.example.com
```

### 5. Auto User Provisioning

When a user authenticates via Keycloak for the first time, ION automatically creates a local user account with the roles mapped from the JWT token. This behaviour is controlled by the `auto_create_users` setting (enabled by default).

---

## Reverse Proxy (Nginx)

A production nginx configuration is provided at `deploy/nginx/nginx.conf`. It includes:

- TLS termination with modern cipher suite
- HTTP to HTTPS redirect
- Security headers (CSP, HSTS, X-Frame-Options, Permissions-Policy)
- Rate limiting on login endpoint
- 120 MB request body limit (sized for PCAP uploads)
- SSE / streaming passthrough for AI chat endpoints
- Static file caching on tmpfs
- Request timing in access logs

### Docker Compose with Nginx

Use the HTTPS compose overlay:

```bash
docker compose -f docker-compose.yml -f deploy/docker-compose.https.yml up -d
```

Or add nginx to your own compose file:

```yaml
services:
  nginx:
    image: nginx:1.29-alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./deploy/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/ssl:ro
    depends_on:
      - ion
    networks:
      - ion-net
```

### Key Nginx Settings

The bundled config is sized for ION's 50-user design ceiling:

- `worker_processes 2` -- one for steady load, one for TLS handshake bursts
- `worker_connections 1024` -- 2048 total, ~6x the realistic peak
- `worker_rlimit_nofile 4096` -- prevents silent FD exhaustion
- `client_max_body_size 120m` -- PCAP upload support

---

## Scaling

### Uvicorn Workers

ION defaults to 4 uvicorn workers, sized for ~50 concurrent users:

```bash
ION_WORKERS=4   # Default. Increase for higher user counts.
```

Background tasks (TIDE sync, Kibana sync, Analytics Engine, Network Mapper, Case Grouper, Job Scheduler, Investigation loop) run on exactly ONE worker via PostgreSQL advisory lock leader election. This prevents duplicate work regardless of worker count.

### Container Resources

Default resource limits in `docker-compose.yml`:

| Container | CPU | Memory |
|-----------|-----|--------|
| `ion` | 6 cores | 6 GB |
| `ion-postgres` | 4 cores | 4 GB |
| `ion-ollama` | 4 cores | 8 GB |

Override via `.env`:

```bash
ION_CPUS=8
ION_MEMORY=8G
ION_DB_CPUS=4
ION_DB_MEMORY=4G
OLLAMA_MEMORY=16G
```

For a 16 GB dev machine, reduce:

```bash
ION_WORKERS=2
ION_MEMORY=2G
ION_DB_MEMORY=1G
```

### PostgreSQL Tuning

The bundled PostgreSQL is tuned for a 4 GB container:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `shared_buffers` | 1 GB | 25% of container RAM |
| `effective_cache_size` | 3 GB | Encourages index scans |
| `work_mem` | 32 MB | Per-sort/hash memory |
| `max_connections` | 320 | 4 workers x 75 pool ceiling |
| `random_page_cost` | 1.1 | SSD assumption |
| `log_min_duration_statement` | 100 ms | Slow query logging |

### Connection Pools

Each uvicorn worker maintains its own SQLAlchemy connection pool. The default pool size is configured to stay within the PostgreSQL `max_connections` limit across all workers.

---

## Backup

### PostgreSQL

```bash
# Dump the database
docker exec ion-postgres pg_dump -U ion ion > ion_backup_$(date +%Y%m%d).sql

# Restore
cat ion_backup_20260416.sql | docker exec -i ion-postgres psql -U ion ion
```

### Configuration

The ION runtime configuration is stored at `/data/.ion/config.json` inside the `ion-data` Docker volume. Back up this volume or mount it to a host directory:

```bash
# Copy config from volume
docker cp ion:/data/.ion/config.json ./config_backup.json

# Or mount to host in docker-compose.override.yml
services:
  ion:
    volumes:
      - ./data:/data
```

### Uploaded Files

Uploaded files (PCAPs, evidence, documents) are stored in the `ion-data` volume at `/data`. Include this volume in your backup strategy.

---

## Monitoring

### Health Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Basic liveness check (returns `{"status": "ok"}`) |
| `GET /api/health/deep` | Deep check: database, Elasticsearch, Kibana, TIDE, OpenCTI connectivity |

### Logging

ION uses structured JSON logging. Logs are available via Docker:

```bash
docker logs ion
docker logs ion-postgres
```

The nginx access log includes request timing (`rt=` and `urt=` fields) for performance monitoring.

### Slow Query Logging

PostgreSQL logs all queries taking longer than 100 ms (configurable via the `log_min_duration_statement` parameter in `docker-compose.yml`). View with:

```bash
docker logs ion-postgres 2>&1 | grep "duration:"
```

---

## Troubleshooting

### ION container won't start

**Symptom:** `ion` container exits immediately or restarts in a loop.

**Check:** Ensure PostgreSQL is healthy before ION starts:

```bash
docker compose ps
docker logs ion
```

The `depends_on: condition: service_healthy` in `docker-compose.yml` should handle this, but if PostgreSQL takes longer than expected to initialise, ION may fail its health check.

### Cannot connect to Elasticsearch

**Symptom:** Alerts page is empty, health/deep shows ES as unhealthy.

**Check:**
1. Verify `ION_ELASTICSEARCH_URL` is reachable from inside the container:
   ```bash
   docker exec ion python -c "import httpx; print(httpx.get('$ION_ELASTICSEARCH_URL', verify=False).status_code)"
   ```
2. On Windows/Docker Desktop, use the host IP or `host.docker.internal` instead of `localhost`.
3. If using self-signed certs, set `ION_ELASTICSEARCH_VERIFY_SSL=false` or configure `ION_CA_BUNDLE`.

### localhost vs 127.0.0.1 on Windows

On Windows, `localhost` may resolve to `::1` (IPv6) which Docker-hosted services do not listen on. Always use `127.0.0.1` in connection strings when targeting Docker-exposed ports from the host.

### Database migration errors

ION runs automatic migrations on startup. If a migration fails:

```bash
docker logs ion 2>&1 | grep -i "migration\|alter\|error"
```

To start fresh (destroys all data):

```bash
ION_FRESH_DB=true docker compose up -d
```

This is a one-shot operation -- the flag is consumed and will not trigger again.

### Seeder container keeps restarting

The seeder is configured with `restart: "no"` and should exit after seeding. If it keeps appearing as "restarting," check that ION's health check is passing:

```bash
docker compose ps
curl http://localhost:8000/api/health
```

The seeder depends on `ion: condition: service_healthy` and will not run until ION is fully up.

### AI chat returns errors

If Ollama is not reachable:

1. Ensure the `ai` profile is active: `docker compose --profile ai up -d`
2. Or point `ION_OLLAMA_URL` to an external Ollama instance
3. Pull Bob's model: `docker exec ion-ollama ollama pull hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF`
4. For low-RAM environments (< 8 GB for Ollama), use a smaller model: `ION_OLLAMA_MODEL=qwen2.5:0.5b`

### High memory usage

Each uvicorn worker uses ~1 GB steady state. Reduce worker count on constrained systems:

```bash
ION_WORKERS=2
ION_MEMORY=3G
```

PCAP parsing can cause temporary memory spikes. The nginx body limit (120 MB) caps the maximum upload size.

### Advisory lock warnings in logs

Messages like `"advisory lock 1010 already held"` are informational, not errors. They indicate that a background task (e.g., Kibana sync) is already running on another worker and this worker correctly skipped starting a duplicate.
