<!-- ion-doc:type=STACK REFERENCE -->
<!-- ion-doc:title=ION Stack Reference -->
<!-- ion-doc:subtitle=Container topology, env-var catalogue, integration endpoints, companion services -->
<!-- ion-doc:version=0.29.1 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Operators, deployment engineers, integrators -->
<!-- ion-doc:date=2026-05-12 -->

# ION Stack Reference

Local dev reference for the ION SOC platform + companion services.
Credentials live in [secrets.txt](secrets.txt) (gitignored).

## Container topology

| Container | Host port | Purpose | Compose file |
|---|---|---|---|
| `ion` | 8000 | ION app (FastAPI + HTMX) | `docker-compose.yml` |
| `ion-postgres` | (internal 5432) | ION primary DB | `docker-compose.yml` |
| `ion-ollama` | (internal 11434) | Local LLM inference | `docker-compose.yml` (profile: `ai`) |
| `ion-seeder` | — | One-shot data seeder | `docker-compose.yml` |
| `elasticsearch-test` | 9200 | Alert source / Kibana backend | `test-elasticsearch/docker-compose.yml` |
| `kibana-test` | 5601 | Cases + alert UI | `test-elasticsearch/docker-compose.yml` |
| `gitlab-test` | 8929, 2224 | Issue tracking | `test-gitlab/docker-compose.yml` |
| `opencti-platform` | 8888 | Threat intel (GraphQL) | `test-opencti/docker-compose.yml` |
| `opencti-elasticsearch` | 9201 | OpenCTI-private ES 9.3 | `test-opencti/docker-compose.yml` |
| `opencti-redis` / `rabbit` / `minio` / `worker` | — | OpenCTI deps | `test-opencti/docker-compose.yml` |
| `mock-arkime` | 8005 | Mock Arkime viewer (not real Arkime) | `test-arkime/docker-compose.yml` |
| `tide-app` | (internal 8000) | TIDE detection-eng backend | `~/TIDE/docker-compose.yml` |
| `tide-nginx` | 443 | TIDE reverse proxy (TLS) | `~/TIDE/docker-compose.yml` |

Cross-compose networking: ION reaches external stacks via `host.docker.internal:<port>`. Only the main compose joins the `ion_ion-net` network; the range compose joins it externally.

## Compose files (in `~/ION`)

- **`docker-compose.yml`** — core: postgres + ion + seeder + optional ollama (profile `ai`)
- **`docker-compose.dev.yml`** — dev overrides
- **`docker-compose.test.yml`** — test harness
- **`docker-compose.range.yml`** — cyber range (kali, dvwa, juiceshop, webgoat, vuln-ssh/smb/ftp, filebeat); layers on top of core. Joins `ion_ion-net` externally.
- **`deploy/docker-compose.yml` / `.elk.yml` / `.https.yml`** — deployment variants (nginx, full ELK stack, HTTPS)

## ION integration env vars

Set in `~/ION/.env`. Every integration follows the pattern `ION_<NAME>_ENABLED=true` + `_URL` + auth.

| Integration | Enabled flag | Key vars |
|---|---|---|
| Elasticsearch | `ION_ELASTICSEARCH_ENABLED` | `_URL`, `_USERNAME`/`_PASSWORD` or `_API_KEY`, `_ALERT_INDEX`, `_CASE_INDEX`, `_VERIFY_SSL` |
| Kibana Cases | `ION_KIBANA_CASES_ENABLED` | `_URL`, `_USERNAME`, `_PASSWORD`, `_SPACE_ID`, `_CASE_OWNER`, `_VERIFY_SSL` |
| TIDE | `ION_TIDE_ENABLED` | `_URL`, `_API_KEY`, `_SPACE`, `_CLIENT_ID`, `_MAX_CONCURRENT`, `_TOTAL_BUDGET_S`, `_VERIFY_SSL` |
| OpenCTI | `ION_OPENCTI_ENABLED` | `_URL`, `_TOKEN`, `_VERIFY_SSL` |
| GitLab | `ION_GITLAB_ENABLED` | `_URL`, `_TOKEN`, `_PROJECT_ID`, `_SUDO`, `_VERIFY_SSL` |
| Ollama | `ION_OLLAMA_ENABLED` | `_URL`, `_MODEL` (default `hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF`), `_TIMEOUT`, `_NUM_CTX` (default 16384), `_VERIFY_SSL` |
| Arkime | `ION_ARKIME_ENABLED` | `_URL`, `_KEYCLOAK_*` (OAuth2 client_credentials), or `_USERNAME`/`_PASSWORD`, `_API_KEY`, `_VERIFY_SSL` |
| DFIR-IRIS | `ION_DFIR_IRIS_ENABLED` | `_URL`, `_API_KEY`, `_DEFAULT_CUSTOMER`, `_VERIFY_SSL` |
| AbuseIPDB | `ION_ABUSEIPDB_ENABLED` | `_API_KEY` |
| OIDC (Keycloak) | `ION_OIDC_ENABLED` | `_KEYCLOAK_URL`, `_REALM`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_VERIFY_SSL` |

Other notable vars: `ION_BASE_URL`, `ION_DEBUG_MODE`, `ION_WORKERS` (uvicorn), `ION_DATABASE_URL`, `ION_ADMIN_PASSWORD`, `ION_CA_BUNDLE`.

## ION service-layer map

All in `src/ion/services/`.

| Service | File | Background task | API routes |
|---|---|---|---|
| Kibana Cases | `kibana_cases_service.py` | **60s sync loop** (`LOCK_KIBANA_BG_SYNC`, single-worker via pg advisory lock) | `/api/kibana/*` |
| TIDE | `tide_service.py` + `tide_sync_service.py` | **300s sync loop** (`LOCK_TIDE_BG_SYNC`) | consumed by detection-eng page |
| OpenCTI | `opencti_service.py` | on-demand | `/api/threat-intel/*` |
| GitLab | `gitlab_service.py` + `connectors/gitlab_connector.py` | on-demand | `/api/gitlab/*`, `/api/integrations/*` |
| Ollama | `ollama_service.py` | on-demand (streaming) | `/ai/chat`, `/ai/analyze_alert`, `/ai/case_generate`, etc. |
| Arkime | `arkime_service.py` | on-demand PCAP fetch | `/api/alerts/{id}/arkime/*` |
| Elasticsearch | `elasticsearch_service.py` | on-demand alert pull | `/api/integrations/*` |

Uvicorn runs **N workers** (default 4). Each runs startup hooks independently. Cross-worker coordination via Postgres advisory locks:

- **Seed hooks** (permissions, playbooks, SOC templates, KB articles, forensic playbooks) — each runs once at startup, guarded by a lock per seeder.
- **Background sync loops** — leader election via `hold_until_close=True` lock; only one worker runs each loop at any time.

## Startup order

1. `postgres` comes healthy → `ion` starts
2. ION app: `_validate_startup_config()` → `init_db()` (idempotent `create_all`) → seed hooks (idempotent) → background loops spawn on the leader worker
3. `ion-seeder` runs after `ion` is healthy (currently just a trigger container)

External stacks (ES, Kibana, GitLab, OpenCTI, TIDE, Arkime) are independent compose projects — bring them up first, then `ion`, so the integrations connect cleanly.

## Gotchas (hit in practice)

- **TIDE certs must exist as files before `up -d`.** If `certs/server.crt`, `server.key`, `ca.crt` don't exist, Docker creates them as *directories* (bind-mount target), nginx crashes with "PEM_read_bio_X509_AUX()". Fix: generate real certs first. On Git-Bash, `openssl` mangles `-subj "/CN=..."` — prefix with `MSYS_NO_PATHCONV=1`.
- **Kibana's `kibana_system` password must be set in ES explicitly** after first boot. Compose only sets the bootstrap `elastic` password; Kibana auths as `kibana_system` and gets 401s until you run `POST /_security/user/kibana_system/_password` on ES.
- **OpenCTI healthcheck** in `test-opencti/docker-compose.yml` uses `curl`, but the `opencti/platform` image only has `wget`. The platform itself is fine — only the healthcheck is broken. Fixed to `wget -qO- http://localhost:8080/`.
- **GitLab first-root-password**: stored at `/etc/gitlab/initial_root_password` inside the container and deleted after 24h. Grab it early: `docker exec gitlab-test cat /etc/gitlab/initial_root_password`. PATs can be created non-interactively with `gitlab-rails runner`.
- **Cross-compose DNS**: ION in one compose can't resolve `elasticsearch` in another. Use `http://host.docker.internal:<port>` in ION's .env.
- **`ION_FRESH_DB=true`** in current .env is *not* wired to a wipe flag in code — table creation is idempotent. To actually reset: wipe the postgres volume (`docker compose down -v`) or truncate tables.

## Auth model (ION)

- `ion_session` cookie OR `Authorization: Bearer <token>` header
- Session table in ION DB; validated each request by `AuthService.validate_session()` ([src/ion/auth/dependencies.py](src/ion/auth/dependencies.py))
- OIDC (Keycloak) optional — auto-creates users if `ION_OIDC_AUTO_CREATE_USERS=true`
- All endpoints gated by `require_page_auth` or `require_permission("resource:action")`

## Common commands

```bash
# Bring up external services (in order)
cd ~/ION/test-elasticsearch && docker compose up -d
cd ~/ION/test-gitlab        && docker compose up -d
cd ~/ION/test-opencti       && docker compose up -d
cd ~/ION/test-arkime        && docker compose up -d
cd ~/TIDE                   && docker compose up -d
# Then ION core (optional: --profile ai for ollama)
cd ~/ION && docker compose --profile ai up -d

# Restart just ION after .env change
cd ~/ION && docker compose restart ion

# Pull an Ollama model
docker exec ion-ollama ollama pull llama3.2:1b
```
