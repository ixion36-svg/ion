# ION — Elastic APM & Metrics Integration

End-to-end setup for shipping ION's **traces (APM)** and **metrics (Prometheus)**
into your Elastic stack / SIEM. The ION side is opt-in and default-off (see the
`ION_APM_*` and `ION_METRICS_*` block in `.env.deploy`); this guide is the
**Elastic side**.

> Air-gap: everything here stays inside your estate — ION → APM Server → ES, and
> Elastic Agent → ION `/metrics`. No internet egress. Pull the `apm-server` /
> `elastic-agent` images into your offline registry first.

---

## Part 1 — APM (traces)

ION uses the in-process Elastic APM Python agent (Starlette/FastAPI integration).
Once it can reach an APM Server with a matching auth token, the service
**auto-registers** in Kibana → Observability → APM as `service.name = ion`
(schema-on-write — there is no "create the service" step). You get transaction
latency, error rates, and — for free — child spans for ION's SQLAlchemy (Postgres)
queries and outbound `httpx` calls (Elasticsearch, Kibana, Ollama, OpenCTI, Arkime).

### 1a. You already have an APM Server → just wire auth
1. On the APM Server, note its URL (e.g. `http://apm:8200`) and its **secret token**
   (or mint an **API key** — see below).
2. In ION's `.env.deploy`:
   ```
   ION_APM_ENABLED=true
   ION_APM_SERVER_URL=http://<apm-host>:8200
   ION_APM_SERVICE_NAME=ion
   ION_APM_ENVIRONMENT=production
   ION_APM_SECRET_TOKEN=<same-secret-token-as-the-apm-server>
   # ...or, instead of the secret token:
   # ION_APM_API_KEY=<base64 id:api_key>
   ```
3. Restart ION. Within ~30 s of the first request, `ion` appears in Kibana → APM.

**Minting an APM API key** (preferred over a shared secret token; scoped, revocable):
```bash
curl -sk -u elastic:$ES_PASS -XPOST "$ES_URL/_security/api_key" -H 'Content-Type: application/json' -d '{
  "name": "ion-apm",
  "role_descriptors": { "ion_apm": { "cluster": [], "index": [],
    "applications": [{ "application": "apm", "privileges": ["event:write","config_agent:read"], "resources": ["*"] }] } }
}'
# Use the returned `encoded` value as ION_APM_API_KEY.
```

### 1b. You run APM as a **Fleet integration** (Elastic Agent)
Kibana → Fleet → Agent policies → your policy → **Add integration → APM**:
- Host: `0.0.0.0:8200`
- **Secret token** (or enable API-key auth) → copy it into `ION_APM_SECRET_TOKEN`.
- **RUM: disabled** (ION is backend-only; no browser agent).
Save; the managed Elastic Agent starts the APM Server. Point ION at that agent's
host:8200.

### 1c. You run APM **standalone**
Use [`apm/apm-server.yml`](apm/apm-server.yml) as a template (ES output + secret
token + RUM off + data-stream/ILM). Run:
```bash
docker run -d --name ion-apm --network ion-net -p 8200:8200 \
  -v $PWD/deploy/apm/apm-server.yml:/usr/share/apm-server/apm-server.yml:ro \
  -e APM_SECRET_TOKEN=$APM_SECRET_TOKEN \
  -e ELASTICSEARCH_HOSTS=http://elasticsearch:9200 \
  -e ELASTICSEARCH_USERNAME=elastic -e ELASTICSEARCH_PASSWORD=$ES_PASS \
  docker.elastic.co/apm/apm-server:8.19.11
```

### Verify APM
- Kibana → Observability → APM → services → **ion** shows transactions.
- Or check data landed: `GET /traces-apm*/_search?q=service.name:ion&size=1`.

---

## Part 2 — Metrics (Prometheus `/metrics` → SIEM)

ION exposes an OpenMetrics endpoint at `GET /metrics` when `ION_METRICS_ENABLED=true`
(HTTP rate/latency, build info, integration circuit-breaker states, DB pool).
Collect it with the **Elastic Agent Prometheus integration**.

### 2a. Fleet integration (recommended)
Kibana → Fleet → your agent policy → **Add integration → Prometheus Metrics**:
- Collection mode: **Collect Prometheus metrics** (not Remote Write).
- Hosts: `http://<ion-host>:8099`  •  Metrics path: `/metrics`  •  Period: `30s`
- If you set `ION_METRICS_TOKEN`, add a header
  `Authorization: Bearer <token>` (Advanced → headers).
- Optional: add a processor `add_fields → target: service, fields.name: ion`
  so the metrics carry `service.name: ion` and correlate with the APM service.

### 2b. Standalone Elastic Agent
Use [`apm/elastic-agent-ion.yml`](apm/elastic-agent-ion.yml) as a template
(a `prometheus/metrics` input pointed at ION `/metrics`, with the bearer header).
Field names vary slightly by agent version — check against your version's
standalone config reference.

### Verify metrics
- `GET metrics-prometheus.collector-*/_search?q=service.name:ion&size=1`, or
- Kibana → Discover on the `metrics-*` data view, filter `service.name: ion`,
  look for `prometheus.metrics.ion_*` fields (build info, circuit-breaker state).

Build a SIEM alert/rule on, e.g., `ion_circuit_breaker_state >= 2` (an integration
circuit is open) or p95 of `ion_http_request_duration_seconds`.

---

## Multi-worker note (important)
ION runs several uvicorn workers (`ION_WORKERS`, default 4). For the Prometheus
counters/histograms to aggregate across workers, ION must run with
`PROMETHEUS_MULTIPROC_DIR` set to a shared writable dir (see `.env.deploy`).
Without it, each scrape hits one worker and sees only that worker's counters
(gauges like circuit-breaker state still surface via `max` aggregation). APM is
per-process and needs no such handling — each worker reports independently and
Kibana aggregates by `service.name`.

## Security
- Prefer an **API key** over a shared secret token for APM (scoped + revocable).
- Gate `/metrics` with `ION_METRICS_TOKEN` and restrict it at the network layer
  (only the Elastic Agent should reach ION:8099/metrics).
- ION's `/metrics` and APM are **backend-only**; neither touches ION's browser
  CSP. Do **not** enable RUM.
