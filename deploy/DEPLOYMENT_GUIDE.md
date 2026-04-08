# ION Deployment Guide

## Air-Gapped / Secure Environment Deployment

This guide covers deploying ION v0.9.43 in environments with restricted or no internet access.

---

## What's in the Docker Image

The `ixion36/ion` image contains:

- ION web application (FastAPI + Jinja2)
- PostgreSQL client libraries
- WeasyPrint PDF generation (Pango/Cairo/GDK-Pixbuf)
- Knowledge base (590+ articles, auto-seeded on first start)
- Forensic playbooks (8, auto-seeded)
- Training simulator (8 scored scenarios)
- NLP entity detection (IPs, CVEs, hashes, MITRE IDs)

The image does **NOT** contain:
- PostgreSQL server (separate container: `postgres:16-alpine`)
- Elasticsearch, Kibana, OpenCTI, TIDE, Ollama (your infrastructure)

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Docker Compose                       │
│  ┌──────────────┐     ┌──────────────┐               │
│  │ ion-postgres  │◄────│     ion      │               │
│  │ PostgreSQL 16 │     │  ION v0.9.43 │               │
│  │  (database)   │     │  port 8000   │               │
│  └──────────────┘     └──────┬───────┘               │
│         ion-net network       │                       │
└───────────────────────────────┼───────────────────────┘
                                │
        ┌───────────────────────┼────────────────────┐
        │         Your Infrastructure                 │
        │  ┌─────────┐ ┌──────┐ ┌───────┐ ┌──────┐  │
        │  │   ES    │ │Kibana│ │OpenCTI│ │ TIDE │  │
        │  │ 8.x    │ │ 8.x  │ │       │ │      │  │
        │  └─────────┘ └──────┘ └───────┘ └──────┘  │
        └────────────────────────────────────────────┘
```

---

## Step 1: Prepare Offline Package

On a machine with internet access:

```bash
# Pull images
docker pull ixion36/ion:0.9.43
docker pull postgres:16-alpine

# Save to a tar file
docker save ixion36/ion:0.9.43 postgres:16-alpine -o ion-0.9.43-bundle.tar

# Gather config files
# You need: docker-compose.yml, .env.deploy
```

Transfer to your secure environment:
- `ion-0.9.43-bundle.tar` (~400MB)
- `docker-compose.yml`
- `.env.deploy`

---

## Step 2: Deploy

On the secure/air-gapped machine:

```bash
# Load images
docker load -i ion-0.9.43-bundle.tar

# Configure
cp .env.deploy .env
# Edit .env:
#   - Set ION_ADMIN_PASSWORD
#   - Set Elasticsearch IP/credentials
#   - Set TIDE IP/API key (if available)
#   - Set OpenCTI IP/token (if available)

# Start
docker compose up -d

# Verify
docker compose ps
# Expected: ion-postgres (healthy), ion (healthy)

# Access at http://<server-ip>:8000
```

---

## Step 3: First Login

1. Navigate to `http://<server-ip>:8000`
2. Login with `admin` / your `ION_ADMIN_PASSWORD`
3. Go to Settings to verify integration connections
4. Navigate to the ION Guide (`/guide`) for feature overview

---

## TLS / HTTPS Deployment

### Option A: ION native TLS

```bash
# In .env:
ION_SSL_CERT=/path/to/cert.pem
ION_SSL_KEY=/path/to/key.pem
ION_COOKIE_SECURE=true
```

### Option B: Nginx reverse proxy (recommended)

Use the example nginx configs in `deploy/nginx/`. Nginx handles TLS termination, ION runs HTTP internally.

```bash
# In .env:
ION_COOKIE_SECURE=true
ION_BASE_URL=https://ion.yourdomain.com
```

---

## Updating

```bash
# On internet-connected machine:
docker pull ixion36/ion:latest
docker save ixion36/ion:latest -o ion-latest.tar

# Transfer and load on air-gapped machine:
docker load -i ion-latest.tar
docker compose down
docker compose up -d
```

Data persists in Docker volumes. No data loss on update.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Could not translate host postgres" | Containers not on same network. Run `docker compose down && docker compose up -d` |
| "Database not ready after 60s" | PostgreSQL not starting. Check `docker logs ion-postgres` |
| Login redirect loop | Stale `config.json` in volume. Run `docker compose down -v && docker compose up -d` |
| ES connection refused | Check `ION_ELASTICSEARCH_URL` in `.env` — use actual IP, not `localhost` |
| TIDE connection failed | Check `ION_TIDE_URL` and `ION_TIDE_API_KEY`. Set `ION_TIDE_VERIFY_SSL=false` for self-signed certs |

---

## Resource Requirements

| Component | CPU | Memory | Storage |
|-----------|-----|--------|---------|
| ION | 0.5-2 cores | 256MB-1GB | ~500MB (image) |
| PostgreSQL | 0.25-1 core | 128-512MB | ~100MB + data |
| Total minimum | 1 core | 512MB | 1GB |
| Recommended | 2+ cores | 2GB+ | 5GB+ |
