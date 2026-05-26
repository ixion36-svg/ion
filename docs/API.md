<!-- ion-doc:type=API DOCUMENTATION -->
<!-- ion-doc:title=ION API Reference -->
<!-- ion-doc:subtitle=Router catalogue, auth model, common patterns, webhook contract — for integrators -->
<!-- ion-doc:version=0.29.1 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Integration engineers, customer automation teams, n8n authors -->
<!-- ion-doc:date=2026-05-12 -->

# 1. Purpose

This document is the high-level API reference for ION's HTTP surface. It is the entry point for integrators who need to:

- automate against ION (n8n, custom scripts, SOAR adapters)
- understand the auth + permission model
- discover the router catalogue
- consume ION's outbound webhooks

For the per-endpoint signature, parameter schemas, and response shapes, the canonical source-of-truth is the **OpenAPI specification** generated at runtime — see §9 below.

## 1.1 Companions

- `docs/HLD.md` — architectural envelope
- `docs/LLD.md` §4 — HTTP routing layer
- `docs/HLD.md` §7.1–§7.2 — auth + RBAC
- `_mod_log_shipping_spec.md` — outbound webhook + audit-log structure

# 2. Base URL + transport

| Property | Value |
|---|---|
| Base URL (in customer deployment) | `https://<customer-domain>/` (TLS terminated at customer reverse proxy) |
| Internal listen | `http://ion:8000` (plain HTTP inside the customer trust zone) |
| Content-Type | `application/json` for API; `text/html` for analyst surfaces |
| Encoding | UTF-8 |
| HTTP version | 1.1 |

# 3. Authentication

ION supports two equivalent authentication schemes, configured per deployment:

## 3.1 OIDC (Keycloak — preferred)

| Step | Endpoint | Notes |
|---|---|---|
| Start OIDC flow | `GET /api/security/oidc/start` | Returns 302 to Keycloak authorize endpoint |
| Callback | `GET /api/security/oidc/callback?code=...` | Validates JWT (RS256 only); upserts user; sets session cookie |
| Logout | `POST /api/security/logout` | Destroys session; optional Keycloak end-session redirect |

**JWT verification:** RS256 only — HS256 explicitly refused. JWKS auto-refreshes. Token kid + sig validated; aud + exp + iss enforced.

## 3.2 Local password (fallback)

| Step | Endpoint | Notes |
|---|---|---|
| Login | `POST /api/security/login` | Form: `username` + `password`; rate-limited via slowapi; bcrypt verify |
| Logout | `POST /api/security/logout` | Destroys session |

## 3.3 Session model

- **Cookie name:** `ion_session`
- **Attributes:** `Secure`, `HttpOnly`, `SameSite=Lax`
- **Storage:** server-side; cookie carries opaque session id only
- **Expiry:** configurable; default 8 hours sliding

## 3.4 API tokens (for n8n / automation)

For non-browser callers, ION supports API token authentication:

| Header | Example |
|---|---|
| `Authorization: Bearer <token>` | `Bearer ion_pat_a1b2c3...` |

Tokens are issued via `/admin/api-tokens` (admin-only); each carries an explicit permission scope (cannot exceed the issuing user's permissions). Tokens are revocable.

# 4. Authorisation (RBAC)

Permission is enforced at two layers:

1. **Endpoint decorator** — `@permission_required("case:update")` checks `Permission` × `RolePermission` × the caller's role(s)
2. **Service layer** — every mutation re-checks auth before commit (TOCTOU defence)

## 4.1 Role hierarchy (7 tiers)

| Tier | Role | Inherits from |
|---|---|---|
| 1 | `viewer` | (base) |
| 2 | `l1_analyst` | viewer |
| 3 | `l2_analyst` | l1_analyst |
| 4 | `l3_analyst` | l2_analyst |
| 5 | `detection_engineer` | l3_analyst (parallel branch) |
| 6 | `soc_manager` | l3_analyst + detection_engineer |
| 7 | `admin` | (full) |

## 4.2 Permission naming

Permissions use `<resource>:<action>` shape: `case:read`, `case:update`, `case:pin`, `forensic:write`, `prompt:write`, `audit:read`, `admin:*`.

Full list returnable via `GET /api/security/permissions` (requires `admin:read`).

# 5. Common patterns

## 5.1 Request shape

```http
POST /api/cases HTTP/1.1
Content-Type: application/json
Cookie: ion_session=...
X-Request-ID: 9c7c... (optional client-set request id)

{
  "title": "Suspicious lateral movement on host-42",
  "priority": "high",
  "alert_ids": [101, 102]
}
```

## 5.2 Success response shape

```http
HTTP/1.1 201 Created
Content-Type: application/json
X-Request-ID: 9c7c... (echoed)

{
  "id": 4711,
  "title": "Suspicious lateral movement on host-42",
  "status": "open",
  "priority": "high",
  "created_at": "2026-05-12T10:23:45Z",
  ...
}
```

All timestamps are UTC, ISO-8601.

## 5.3 Error response shape

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "Forbidden",
  "detail": "case:update permission required",
  "request_id": "9c7c..."
}
```

Every error response carries `request_id` analysts can quote when reporting issues.

## 5.4 Error catalogue

| HTTP | Error | When |
|---|---|---|
| 400 | Bad Request | Malformed JSON |
| 401 | Unauthorized | Session missing or expired |
| 403 | Forbidden | RBAC denied |
| 404 | Not Found | Resource absent (or absent to this user — does not leak existence) |
| 409 | Conflict | State-machine violation; advisory lock held; idempotency-key collision |
| 422 | Unprocessable Entity | Pydantic validation failure; field-level errors in body |
| 429 | Too Many Requests | slowapi rate limit |
| 502 | Bad Gateway | External integration unavailable |
| 500 | Internal Server Error | Unhandled exception; request_id quotable to maintainer |

## 5.5 Pagination

List endpoints use page+size pagination:

```
GET /api/cases?page=1&size=50&sort=-created_at HTTP/1.1
```

Response:

```json
{
  "data": [ ... ],
  "page": 1,
  "size": 50,
  "total": 2347,
  "has_more": true
}
```

## 5.6 Idempotency

Mutating endpoints accept an `Idempotency-Key` header. Submitting the same key returns the original response without re-execution.

## 5.7 Versioning

The API surface is versioned with ION's semver. Breaking changes are introduced at minor (`v0.X.0`) bumps with at least one minor's deprecation notice. Patches (`v0.X.Y`) never break the API.

# 6. Router catalogue

ION exposes 73 routers grouped by domain. Each router is mounted at a prefix; the routers below list the prefix and the routes' high-level scope.

## 6.1 Core

| Router | Prefix | Scope |
|---|---|---|
| `api_router` | `/api` | Root catch-all; `/health` |
| `security_api` | `/api/security` | Login, logout, OIDC flow, user info |
| `admin_api` | `/api/admin` | User / role / permission CRUD; API tokens; settings |

## 6.2 Cases

| Router | Prefix | Scope |
|---|---|---|
| `investigation_api` | `/api/cases` | AlertCase CRUD; close; pin |
| `case_grouper_api` | `/api/case-grouper` | Alert-to-case correlation tooling |
| `case_similarity_api` | `/api/cases` | Similar-case sidebar query |
| `forensics_api` | `/api/forensics` | ForensicCase CRUD |
| `forensic_workbench_api` | `/api/forensics` | ForensicCase Workbench (pin + ledger) |
| `attack_story_api` | `/api/attack-stories` | Kill-chain story compose |

## 6.3 Observables + Threat Intel

| Router | Prefix | Scope |
|---|---|---|
| `observable_api` | `/api/observables` | Observable CRUD; staleness |
| `enrichment_api` | `/api/enrichment` | Batch OpenCTI enrichment |
| `ioc_staleness_api` | `/api/ioc-staleness` | Staleness rules |
| `threat_intel_api` | `/api/threat-intel` | TI landscape + actor profile + sparkline |
| `threat_landscape_api` | `/api/threat-landscape` | Briefing generator |
| `threat_watch_gap_api` | `/api/threat-intel` | Threat Watch Gap alerts |

## 6.4 AI / Bob

| Router | Prefix | Scope |
|---|---|---|
| `ai_api` | `/api/ai` | AI chat; NL-to-ES; document gen |
| `bob_analysis_api` | `/api/bob` | Bob's verdict surface for an alert |
| `alert_prompt_api` | `/api/alert-prompts` | Bob template CRUD + threshold override |
| `bob_eval_api` | `/api/bob-eval` | Offline eval harness |
| `alert_pattern_api` | `/api/alert-patterns` | Pattern-based template matching |

## 6.5 Detection engineering

| Router | Prefix | Scope |
|---|---|---|
| `tide_api` | `/api/tide` | TIDE rules, posture, execution reports |
| `engineering_analytics_api` | `/api/engineering/analytics` | Per-rule FP rate × volume |
| `compliance_api` | `/api/compliance` | Multi-framework compliance mapping |
| `d3fend_api` | `/api/d3fend` | D3FEND defensive technique map |
| `emulation_api` | `/api/emulation` | Adversary emulation plans + execution |
| `tuning_proposal_api` | `/api/tuning-proposals` | Tuning proposal lifecycle |

## 6.6 Operations

| Router | Prefix | Scope |
|---|---|---|
| `briefing_api` | `/api/briefing` | Daily briefing aggregator |
| `daily_standup_api` | `/api/daily-standup` | Standup workflow |
| `shift_handover_api` | `/api/shift-handover` | Shift handover composition |
| `analyst_efficiency_api` | `/api/analyst-efficiency` | Per-analyst metrics |
| `soc_health_api` | `/api/soc-health` | 5-dimension scorecard |
| `executive_report_api` | `/api/executive-report` | Exec report compose + export |
| `entity_timeline_api` | `/api/entity-timeline` | Cross-source timeline for host/user/IP |

## 6.7 PCAP + Arkime

| Router | Prefix | Scope |
|---|---|---|
| `arkime_api` | `/api/arkime` | Arkime session search + preview |
| `pcap_api` | `/api/pcap` | PCAP analysis results; auto-analysis triggers |

## 6.8 Playbooks + Response

| Router | Prefix | Scope |
|---|---|---|
| `playbook_api` | `/api/playbooks` | Playbook CRUD; action execution; approval gate |
| `canary_api` | `/api/canaries` | Canary token deploy + trip handling |
| `bulk_ops_api` | `/api/bulk` | Bulk alert/case operations |

## 6.9 CyAB + Curriculum

| Router | Prefix | Scope |
|---|---|---|
| `cyab_api` | `/api/cyab` | CyAB pillars, sub-profiles, assessments, ATT&CK heatmap |
| `course_api` | `/api/courses` | Curriculum module/lesson/quiz CRUD |
| `cyber_range_api` | `/api/cyber-range` | Range exercise execution |

## 6.10 Knowledge

| Router | Prefix | Scope |
|---|---|---|
| `notes_api` | `/api/notes` | Notes + folders |
| `comm_template_api` | `/api/templates` | Comm templates CRUD |
| `kb_api` | `/api/kb` | Knowledge-base docs + embeddings |
| `social_api` | `/api/social` | Social hub for team |

## 6.11 Infra

| Router | Prefix | Scope |
|---|---|---|
| `network_asset_api` | `/api/network-assets` | CMDB |
| `log_source_health_api` | `/api/log-source-health` | Per-source ingest health |
| `integration_api` | `/api/integrations` | Integration config + webhook config |
| `wallboard_api` | `/` | Wallboard surface (root-mounted) |

# 7. Outbound webhooks

ION emits HMAC-signed outbound webhooks on configurable events. Consumers verify the signature before processing.

## 7.1 Supported events

| Event | Fired when |
|---|---|
| `case.created` | Any new AlertCase or ForensicCase |
| `case.updated` | Case state change |
| `case.closed` | Case closed by analyst |
| `alert.p1` | Severity-critical alert created |
| `sla.breach.imminent` | Per-case SLA approaching threshold |
| `sla.breach` | Per-case SLA breached |
| `playbook.approval_requested` | Playbook action requiring approval |
| `playbook.executed` | Playbook action executed |
| `canary.tripped` | Canary token tripped |
| `bob.low_confidence` | Bob verdict below threshold (for tuning review) |

Customer configures which events fire via `/api/admin/webhooks`.

## 7.2 Payload shape

```http
POST /customer-webhook-receiver HTTP/1.1
Content-Type: application/json
X-ION-Event: case.closed
X-ION-Event-Id: 7f3a8c12-...
X-ION-Timestamp: 2026-05-12T10:23:45Z
X-ION-Signature: sha256=a4f1...

{
  "event": "case.closed",
  "event_id": "7f3a8c12-...",
  "timestamp": "2026-05-12T10:23:45Z",
  "data": {
    "case_id": 4711,
    "closure_reason": "true_positive_contained",
    "closed_by": "alice@customer.example",
    "case_link": "https://ion.example/cases/4711"
  }
}
```

## 7.3 Signature verification

```python
import hmac, hashlib
mac = hmac.new(secret_bytes, payload_bytes, hashlib.sha256).hexdigest()
ok = hmac.compare_digest(mac, header_value.removeprefix("sha256="))
```

## 7.4 Retry policy

- 3 retries with exponential backoff (1s / 4s / 16s)
- After exhaustion: marked `failed` in delivery log; surfaces in `/admin/webhook-log`
- Idempotency: receivers MUST treat `event_id` as the idempotency key — replays will reuse the id

# 8. Rate limiting

| Surface | Default limit |
|---|---|
| `/api/security/login` (local password) | 5/min per IP |
| `/api/security/oidc/*` | 30/min per IP |
| Authenticated read APIs | 600/min per user |
| Authenticated mutating APIs | 200/min per user |
| Webhook outbound (per receiver) | 60/min |

Customer can override defaults via `/settings` (admin permission required).

# 9. OpenAPI specification

ION exposes its full OpenAPI 3.0 spec at runtime:

| Endpoint | Purpose |
|---|---|
| `GET /api/openapi.json` | Machine-readable OpenAPI 3.0 JSON |
| `GET /api/docs` | Swagger UI (interactive) |
| `GET /api/redoc` | ReDoc UI (read-only browse) |

Both `/api/docs` and `/api/redoc` are gated by the `admin:read` permission to prevent surface enumeration without authentication.

# 10. CORS

ION does not enable CORS by default. The customer's reverse proxy is expected to set CORS headers if cross-origin browser callers are required. The customer's `/api/admin/cors` setting can override.

# 11. Change history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-05-12 | ION maintainer | Initial API reference authored at v0.29.1 |
