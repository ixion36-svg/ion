# ION SOC Lead Runbook

Operational guide for SOC leads running ION (Intelligent Operating Network).

---

## 1. Onboarding a New Analyst

### Create the User Account

1. Log in as **admin** and navigate to **Settings > Users** (`/users`).
2. Click **Create User** and fill in username, display name, and email.
3. Set a temporary password (e.g. `user2025`) and tell the analyst to change it on first login.

### Assign Roles

ION ships with these RBAC roles (ascending privilege):

| Role | Tier | Typical Use |
|------|------|-------------|
| `analyst` | L1 | Alert triage, basic case work |
| `senior_analyst` | L2 | Case ownership, observable enrichment |
| `principal_analyst` | L3 | Threat hunting, forensics, playbook authoring |
| `lead` | L3+ | Shift handover, SOC health, executive reports |
| `forensic` | L3 | PCAP analysis, Arkime, forensic tooling |
| `engineering` | -- | Detection engineering, CyAB, log sources |
| `admin` | -- | Full platform administration |

Assign one or more roles on the user edit page. Users with multiple roles can use **Focus Mode** to restrict their session to a single role's permission set. Focus mode is toggled via `POST /api/auth/focus-mode` or the pill buttons on the dashboard / user dropdown.

### Orient the Analyst

- Show them the **ION Guide** (`/guide`) for platform walkthrough.
- Point them to **Skills & Training** (`/training`) for self-assessment and the **Role Match** questionnaire.
- Ensure they know the keyboard shortcuts (press `?` on any page).

---

## 2. Configuring Integrations

All integration settings live in **Settings > Integrations** (`/integrations`) or in environment variables loaded by `start_ion.ps1` / Docker `.env`.

### Elasticsearch / Kibana

| Variable | Purpose | Example |
|----------|---------|---------|
| `ION_ES_URL` | Elasticsearch endpoint | `https://127.0.0.1:9200` |
| `ION_ES_USERNAME` | ES username | `elastic` |
| `ION_ES_PASSWORD` | ES password | `DocforgeTest2025` |
| `ION_KIBANA_URL` | Kibana endpoint | `https://127.0.0.1:5601` |
| `ION_CA_BUNDLE` | Path to internal CA cert | `C:\certs\ca.pem` |

ION auto-syncs cases bidirectionally with Kibana Cases when `ION_KIBANA_URL` is set. Case assignees resolve through the ES `_security/profile/_suggest` API.

### TIDE (Threat Informed Detection Engineering)

| Variable | Purpose |
|----------|---------|
| `ION_TIDE_ENABLED` | `true` to enable |
| `ION_TIDE_URL` | TIDE API base URL |
| `ION_TIDE_API_KEY` | API key for `X-TIDE-API-KEY` header |
| `ION_TIDE_VERIFY_SSL` | `false` for self-signed certs |

TIDE data syncs in the background on startup and refreshes periodically. The Detection Engineering page (`/detection-engineering`) reads from the local cache -- zero TIDE queries on page load.

### OpenCTI

| Variable | Purpose |
|----------|---------|
| `ION_OPENCTI_URL` | OpenCTI GraphQL endpoint |
| `ION_OPENCTI_TOKEN` | API token |

Used for threat intel enrichment on observables and PCAP analysis.

### Arkime

| Variable | Purpose |
|----------|---------|
| `ION_ARKIME_URL` | Arkime viewer URL |
| `ION_ARKIME_AUTH_MODE` | `keycloak`, `basic`, or `apikey` |
| `ION_ARKIME_USERNAME` | Username (basic/apikey mode) |
| `ION_ARKIME_PASSWORD` | Password (basic mode) |

The alert-to-PCAP workflow uses `ArkimeService.download_pcap_by_community_id(node, cid)` to pull full packet captures by community ID.

### Ollama (AI)

| Variable | Purpose | Default |
|----------|---------|---------|
| `ION_OLLAMA_URL` | Ollama API endpoint | `http://localhost:11434` |
| `ION_OLLAMA_MODEL` | Model name | `qwen2.5:3b` |
| `ION_OLLAMA_TIMEOUT` | Request timeout (seconds) | `120` |

For dev environments with limited RAM, use `qwen2.5:0.5b`. The admin wizard at `/settings` also lets you change URL/model/timeout at runtime.

| Variable | Purpose | Default |
|----------|---------|---------|
| `ION_BOB_STORE_REASONING` | Store LLM reasoning text in Investigation.reasoning_text and BobEvalRunSample.reasoning_text | `false` |

### PII and Data Retention Advisory

`ION_BOB_STORE_REASONING=true` increases the PII footprint of ION. The LLM reasoning chain may include hostnames, usernames, IP addresses, and other alert-payload values extracted from the original security event. These values are stored verbatim in:

- `investigations.reasoning_text` — one row per investigation run
- `bob_eval_run_samples.reasoning_text` — one row per eval harness sample

Neither column has an automatic purge policy. Operators are responsible for defining and enforcing a retention policy that complies with their local privacy obligations (GDPR Art. 5(1)(e), HIPAA minimum necessary, etc.). Recommended approach:

1. Leave `ION_BOB_STORE_REASONING=false` (default) unless you need the reasoning chain for debugging or training data collection.
2. If enabled, add a scheduled job or a DB-level TTL policy to null-out or delete `reasoning_text` columns after your retention window (e.g. 90 days).
3. Ensure your Postgres backup and WAL configuration handles the column appropriately — reasoning text from investigations is not subject to alert-level access controls.

---

## 3. Daily SOC Lead Checklist

### Morning Briefing

1. Open **Morning Briefing** (`/briefing`) for an AI-generated summary of overnight activity.
2. Review the **Dashboard** (`/`) for open alert/case counts, severity distribution, and SLA status.
3. Check **SOC Health** (`/soc-health`) for analyst workload balance and MTTD/MTTR trends.

### Shift Handover

1. Navigate to **Shift Handover** (`/shift-handover`).
2. Review the outgoing shift's handover notes -- open cases, pending escalations, ongoing incidents.
3. Create a new handover entry for the incoming shift with context on priority items.
4. Verify all open cases have an assigned analyst (check the Cases list filtered by `status=open`).

### Case Review

1. Open **Cases** (`/cases`) and sort by severity descending.
2. For each critical/high case:
   - Verify investigation progress via the case timeline and notes.
   - Check if playbook steps are being followed.
   - Confirm affected hosts/users are documented.
3. Use **Case Grouper** (`/case-grouper`) to identify related cases that should be merged.
4. Review **Investigation Queue** (`/investigate`) for cases awaiting triage.

---

## 4. Creating and Managing Playbooks

### Create a Playbook

1. Go to **Playbooks** (`/playbooks`) and click **Create Playbook**.
2. Fill in: title, category (e.g. Malware, Phishing, Insider Threat), description, and severity threshold.
3. Add **steps** in order. Each step has:
   - **Title** and **instructions** for the analyst.
   - **Step type**: manual, automated, or decision.
   - **Expected outcome** guidance.
4. Save and set the playbook to **Active**.

### Attach Playbooks to Cases

- When creating or editing a case, select the relevant playbook.
- Analysts execute steps in order, marking each complete. The case timeline logs step completions.

### Playbook Analytics

- **Playbook Analytics** (`/playbook-analytics`) shows execution frequency, average completion time, and step failure rates.
- Use this data to refine playbook steps that analysts frequently skip or fail.

---

## 5. Alert Prompt Templates

Alert prompt templates control how ION presents alert context to the AI assistant for different rule types.

1. Go to **Alert Prompts** (`/alert-prompts`).
2. Create a template for each rule category (e.g. "Brute Force", "Lateral Movement", "Data Exfiltration").
3. Each template defines:
   - **Match pattern**: which alert rule names trigger this template.
   - **Prompt text**: the system prompt sent to Ollama when an analyst asks the AI about a matching alert.
   - **Context fields**: which alert fields to include (source IP, destination, user, process, etc.).
4. Templates ensure the AI gives domain-specific guidance rather than generic responses.

---

## 6. Case Grouper and Investigation Queue

### Case Grouper

The Case Grouper (`/case-grouper`) uses heuristics to identify clusters of related cases:

- Cases sharing the same affected hosts, users, or triggered rules.
- Cases within a configurable time window.
- Similarity scoring based on title and description.

Review suggested groups and merge where appropriate to avoid duplicate investigation effort.

### Investigation Queue

The Investigation Queue (`/investigate`) prioritizes cases for analyst attention:

- Cases are ranked by severity, age, and SLA proximity.
- Analysts pull the next case from the queue rather than cherry-picking.
- Leads can manually reorder or assign cases from the queue view.

---

## 7. Executive Reports

1. Navigate to **Executive Report** (`/executive-report`).
2. Select the reporting period (daily, weekly, monthly).
3. The report auto-generates sections for:
   - Alert volume and triage metrics.
   - Case outcomes (true positive rate, MTTD, MTTR).
   - Top triggered rules and affected systems.
   - SOC maturity indicators.
4. Export as PDF (requires WeasyPrint -- available in Docker, not on bare Windows).
5. Use **Report Scheduler** to auto-generate and email reports on a cron schedule.

---

## 8. Common Troubleshooting

### Elasticsearch Connection Failures

**Symptom**: Alerts page is empty, "ES not configured" warnings in logs.

- Verify `ION_ES_URL` points to `https://127.0.0.1:9200` (not `localhost` -- IPv6 resolution issue on Windows).
- Check ES is running: `curl -k -u elastic:PASSWORD https://127.0.0.1:9200/_cluster/health`.
- If using self-signed certs, set `ION_CA_BUNDLE` to the CA cert path.
- Check Docker container status: `docker ps | grep elasticsearch`.

### TIDE 400 / 500 Errors

**Symptom**: Detection Engineering page shows stale data or errors.

- TIDE uses DuckDB which doesn't handle concurrent queries well. The background sync retries automatically.
- Verify API key: `curl -H "X-TIDE-API-KEY: <key>" <TIDE_URL>/api/external/query -d '{"query":"SELECT 1"}'`.
- Check `ION_TIDE_VERIFY_SSL=false` if TIDE uses self-signed certs.
- 504 errors usually mean pool exhaustion -- fixed in v0.9.55 but can recur under heavy load.

### Ollama OOM (Out of Memory)

**Symptom**: AI chat returns errors, Docker Desktop memory warnings.

- Docker Desktop's default VM is ~4GB. `qwen2.5:3b` needs ~3GB of VRAM/RAM.
- **Fix for dev**: Set `ION_OLLAMA_MODEL=qwen2.5:0.5b` in `.env` (lower quality but fits in 4GB).
- **Fix for prod**: Increase Docker Desktop memory or point `ION_OLLAMA_URL` to a remote machine with more RAM.
- Check Ollama is running: `curl http://127.0.0.1:11434/api/tags`.

### Database Issues

- ION uses SQLite locally (`~/.ion/ion.db`) and Postgres in Docker.
- Always start the server from your home directory (not the project dir) so `ion.db` resolves to the right path.
- If columns are missing after a model change, check that a migration was added to `_run_migrations()` -- `create_all()` does not add columns to existing tables.

### Multi-Worker Startup Deadlocks (Postgres)

- Fixed in v0.9.71 via Postgres advisory locks.
- If you see `psycopg2.errors.DeadlockDetected` in startup logs, ensure you're on v0.9.71+.
- Background loops (TIDE sync, Kibana sync, Analytics Engine) should only fire from one worker PID. Check logs to confirm.

### Webhook Integration

- External tools can send alerts to `POST /api/webhooks/alert` with a JSON body.
- Set `ION_WEBHOOK_SECRET` env var and pass it as `X-Webhook-Secret` header for authentication.
- Health check: `GET /api/webhooks/health`.

---

## Release Ritual — Version Bump

Past releases rotted version strings in less-obvious files. v0.22.0 cleaned up 13-release rot in `src/ion/__init__.py` (was `0.19.19`), README badge (was `0.9.98`), Dockerfile OCI label (was `0.11.6`), and `.env.deploy` (was `0.11.21`). To prevent regression, every release must bump the **eight canonical files** below in a single `chore(release): vX.Y.Z` commit applied at the end of the release ritual.

### Eight files that must bump every release

| # | File | What to change |
|---|------|----------------|
| 1 | `src/ion/__init__.py` | `__version__ = "X.Y.Z"` — **load-bearing** for `{{ ion_version }}` in every Jinja template. **Verify before assuming any other file is authoritative.** |
| 2 | `pyproject.toml` | `version = "X.Y.Z"` |
| 3 | `docker-compose.yml` | TWO `${ION_VERSION:-X.Y.Z}` fallback defaults (currently lines 101, 260; verify before bump) |
| 4 | `Dockerfile` | `org.opencontainers.image.version="X.Y.Z"` OCI label |
| 5 | `README.md` | Version badge `version-X.Y.Z-blue` |
| 6 | `.env.deploy` | `ION_VERSION=X.Y.Z` AND the human-readable comment on the line above it |
| 7 | `CHANGELOG.md` | New top entry `## vX.Y.Z — YYYY-MM-DD` |
| 8 | `SECURITY_ASSESSMENT.md` | Bump "Application Version" header, add new column to severity-trend table, add "Net-New Surfaces in vX.Y.Z" section (and "Net-Removed Surface" if applicable) |

### Two sanity-check greps (must return empty before tagging)

Run both immediately after the bump commit. Both expected output: empty.

```bash
# A — historical-rot values must be gone:
grep -RnE "0\.19\.19|0\.11\.6|0\.9\.98|0\.11\.21" \
  ~/ixion/ \
  --exclude-dir=.git \
  --exclude-dir=__pycache__ \
  --exclude=CHANGELOG.md \
  --exclude=SECURITY_ASSESSMENT.md \
  --exclude=RUNBOOK.md \
  --exclude='_spec_v0_*.md' \
  --exclude='_research_*.md' \
  --exclude='seed_courses.py'

# B — previous-released version must NOT remain in canonical-version files:
# (substitute PREV_VERSION with the version you're shipping over)
grep -nE 'version *= *"PREV_VERSION"|ION_VERSION:-PREV_VERSION|__version__ *= *"PREV_VERSION"|version-PREV_VERSION|=PREV_VERSION\b' \
  ~/ixion/pyproject.toml \
  ~/ixion/docker-compose.yml \
  ~/ixion/src/ion/__init__.py \
  ~/ixion/Dockerfile \
  ~/ixion/README.md \
  ~/ixion/.env.deploy
```

If either grep returns hits, fix and re-run before tagging.

### Why this ritual matters

`src/ion/__init__.py:__version__` is exposed as `{{ ion_version }}` to every Jinja template in the app. From v0.19.19 through v0.21.0 — across thirteen releases — the UI footer displayed the wrong version because this file was never updated alongside `pyproject.toml`. README badge, Dockerfile OCI label, and `.env.deploy` rotted to similar degrees. v0.22.0 reset the baseline; this section keeps it from drifting again.
