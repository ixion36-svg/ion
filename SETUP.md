<!-- ion-doc:type=SETUP GUIDE -->
<!-- ion-doc:title=ION Setup Guide -->
<!-- ion-doc:subtitle=Local development setup — prerequisites, quick start, container topology -->
<!-- ion-doc:version=0.29.1 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Developers, contributors -->
<!-- ion-doc:date=2026-05-12 -->

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
# Default Bob model — pull first: ollama pull hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF
ION_OLLAMA_MODEL=hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF
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

For environments without internet access. Starting **v0.10.4**, ION's stack
has three images that must cross the gap (ION, pgvector, Ollama) **plus** two
Ollama models that have to live inside the Ollama volume (the chat model and
`nomic-embed-text` for embeddings). A bundle that only ships the ION image
is a silent partial upgrade — the app boots, but case similarity, KB RAG, and
the Similar-Cases sidebar all quietly return nothing.

### What crosses the gap

| Artefact | Why |
|---|---|
| `ixion36/ion:<VERSION>` | Application |
| `pgvector/pgvector:<PG_VERSION>` | Postgres **with pgvector** (not plain postgres) |
| `ollama/ollama:latest` | LLM host |
| Chat model (default `hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF`) | Bob's reasoning |
| `nomic-embed-text` model | Embeddings — **new in v0.10.4, silently required by case-similarity + KB RAG** |
| `docker-compose.yml` | Config (pinned to matching ION + PG versions) |
| `.env` | Credentials + feature flags |

### Build the bundle (on an internet-connected box)

```bash
# From the repo root
./scripts/build-offline-package.sh [ion_version] [chat_model] [pg_version]

# Examples
./scripts/build-offline-package.sh 0.10.9
./scripts/build-offline-package.sh 0.10.9 hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF pg17
./scripts/build-offline-package.sh 0.10.9 qwen2.5:3b pg16
```

Output lands in `./dist/ion-offline-<VERSION>/` and contains:

- `images/` — ION + pgvector + Ollama image tarballs
- `models/ollama-models.tar.gz` — chat model + `nomic-embed-text` pre-populated
- `deploy/` — nginx + HTTPS override configs
- `docker-compose.yml`, `.env` (stamped with `ION_VERSION`, `PG_VERSION`, model names), `load.sh`
- `MANIFEST.sha256` — integrity manifest

### Transport

Copy the entire `dist/ion-offline-<VERSION>/` directory across your diode / USB / WAN-of-choice.

### Load on the air-gapped side

```bash
cd ion-offline-<VERSION>/
chmod +x load.sh
./load.sh

# load.sh does:
#   1. sha256sum -c MANIFEST.sha256 (integrity)
#   2. docker load for each images/*.tar.gz
#   3. Restore the ollama-models volume (named <project>_ollama-models)
#   4. Idempotent — safe to re-run

# Then:
# Edit .env — change the admin password, set ION_BASE_URL, any integrations
docker compose --profile ai up -d
```

### Turn on case-similarity + KB RAG (opt-in)

These are **off by default** because they need Ollama reachable. In the
air-gapped bundle the models are pre-loaded, so all you do is flip the flags
in `.env`:

```bash
ION_EMBEDDING_ENABLED=true            # enables case-embedding loop
ION_FEW_SHOT_EXEMPLARS_ENABLED=true   # Bob's prompt gets similar past cases
ION_KB_RAG_ENABLED=true               # Bob's prompt gets KB article context
```

Restart ION (`docker compose restart ion`). Case embeddings catch up in ~15 min; the KB (~392 articles) finishes in ~15 min.

### Picking the right PG_VERSION

Set `PG_VERSION` in `.env` on both sides to match the major version of your existing postgres volume. If you're starting fresh it doesn't matter much — pick `pg16` or `pg17`. If you have existing data, **the pgvector image major must match** (pg15 binaries can't read pg16 data files):

```bash
# Check your existing postgres version before building the bundle:
docker exec ion-postgres psql -U ion -d ion -c "SELECT version();"
# Then use the matching pgvector tag (pg15, pg16, pg17) in the build command.
```

### Upgrading an air-gapped deployment

The old "just ship the new ION image" shortcut **breaks** from v0.10.4+ because it leaves the old plain-postgres image (no pgvector) and never updates the Ollama models. Always rebuild the full bundle with `build-offline-package.sh` and re-run `load.sh` on the air-gapped side. The loader is idempotent and won't clobber existing data volumes.

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
