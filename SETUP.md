# ION Setup Guide

## Prerequisites

- Docker Engine 20.10+ and Docker Compose v2
- 4GB RAM minimum (8GB recommended)
- Ports: 8000 (ION), 5432 (PostgreSQL internal)

External services (deployed separately):
- Elasticsearch 8.x with alert data
- Kibana 8.x (optional, for case sync)
- OpenCTI (optional, for threat intelligence)
- TIDE (optional, for detection engineering)
- Ollama (optional, for AI features)

---

## Quick Start (Docker Compose)

```bash
# 1. Clone
git clone https://github.com/ixion36-svg/ion.git
cd ion

# 2. Configure environment
cp .env.deploy .env
# Edit .env — replace all REPLACE_WITH_ placeholders with your actual IPs/credentials

# 3. Start (pulls pre-built image + PostgreSQL)
docker compose up -d

# 4. Verify
docker compose ps
# Should show: ion (healthy), ion-postgres (healthy)

# 5. Access
# http://localhost:8000
# Login: admin / <your ION_ADMIN_PASSWORD>
```

---

## Environment Configuration

Copy `.env.deploy` to `.env` and configure these sections:

### Required

```bash
ION_ADMIN_PASSWORD=your-secure-password    # Admin login password
```

### Database (auto-configured)

```bash
# Default — uses the PostgreSQL container from docker-compose
# Only change if using an external PostgreSQL server
ION_DATABASE_URL=postgresql://ion:ion2025@postgres:5432/ion
```

### Elasticsearch

```bash
ION_ELASTICSEARCH_ENABLED=true
ION_ELASTICSEARCH_URL=http://YOUR_ES_IP:9200
ION_ELASTICSEARCH_USERNAME=elastic
ION_ELASTICSEARCH_PASSWORD=your-es-password
```

### TIDE Detection Engineering

```bash
ION_TIDE_ENABLED=true
ION_TIDE_URL=https://YOUR_TIDE_IP
ION_TIDE_API_KEY=your-tide-api-key
ION_TIDE_VERIFY_SSL=false              # Set true if TIDE has valid TLS cert
```

### OpenCTI Threat Intelligence

```bash
ION_OPENCTI_ENABLED=true
ION_OPENCTI_URL=http://YOUR_OPENCTI_IP:8080
ION_OPENCTI_TOKEN=your-opencti-token
```

### Ollama AI (Optional)

```bash
ION_OLLAMA_ENABLED=true
ION_OLLAMA_URL=http://YOUR_OLLAMA_IP:11434  # NOT 127.0.0.1 (that means the container itself)
ION_OLLAMA_MODEL=llama3.2:latest
```

### TLS / Internal Certificates

```bash
# Trust your internal CA for self-signed certs on ES, OpenCTI, etc.
ION_CA_BUNDLE=/etc/ipa/ca.crt

# Serve ION itself over HTTPS
ION_SSL_CERT=/path/to/cert.pem
ION_SSL_KEY=/path/to/key.pem
```

---

## Air-Gapped / Siloed Deployment

For environments without internet access:

```bash
# On a machine WITH internet:
docker pull ixion36/ion:latest
docker pull postgres:16-alpine
docker save ixion36/ion:latest postgres:16-alpine -o ion-bundle.tar

# Transfer ion-bundle.tar + docker-compose.yml + .env.deploy to the air-gapped machine

# On the air-gapped machine:
docker load -i ion-bundle.tar
cp .env.deploy .env
# Edit .env with your internal IPs
docker compose up -d
```

---

## Fresh Database / Reset

To wipe the database and start fresh:

```bash
# Option 1: One-shot via environment variable
# Add to .env:
ION_FRESH_DB=true
# Restart — wipes once, then skips on subsequent restarts
docker compose down && docker compose up -d

# Option 2: Full volume wipe
docker compose down -v    # Removes all data volumes
docker compose up -d      # Fresh PostgreSQL + ION
```

---

## Networking Notes

| Hostname | What it means | Where it works |
|----------|---------------|----------------|
| `postgres` | Docker Compose service name | Inside compose network only |
| `127.0.0.1` | The container itself | NOT your host machine |
| `host.docker.internal` | Your host machine | Docker Desktop only (Windows/Mac) |
| Actual IP (e.g. `10.0.1.50`) | The real server | Works everywhere |

**For siloed Linux servers**: Always use actual IPs, not `host.docker.internal` or `localhost`.

---

## Troubleshooting

### "Could not translate host postgres"
The ION container can't reach PostgreSQL. Check:
- `docker compose ps` — is `ion-postgres` running and healthy?
- Both containers must be on the same Docker network
- Run: `docker exec ion ping postgres` to test DNS resolution

### "Database not ready after 60s"
PostgreSQL hasn't started yet. Check:
- `docker logs ion-postgres` for errors
- Ensure the postgres volume isn't corrupted: `docker compose down -v && docker compose up -d`

### Login redirects to change-password
The admin password matches a weak default. Set `ION_ADMIN_PASSWORD` to a custom value in `.env` and restart.

---

## Local Development (Without Docker)

```bash
pip install -e .

# Set environment variables (or use start_ion.ps1 on Windows)
export ION_ADMIN_PASSWORD=admin2025
export ION_ELASTICSEARCH_URL=http://127.0.0.1:9200
export ION_ELASTICSEARCH_USERNAME=elastic
export ION_ELASTICSEARCH_PASSWORD=your-password

# Start (uses SQLite by default for local dev)
ion-web
# Access at http://localhost:8000
```
