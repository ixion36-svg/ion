<!-- ion-doc:type=DATA MINIMISATION AUDIT -->
<!-- ion-doc:title=ION Data-Minimisation Audit -->
<!-- ion-doc:subtitle=Schema-wide audit of stored fields, retention, and PII handling against Secure-by-Design P13 -->
<!-- ion-doc:version=0.31.14 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Architects, security reviewers, external auditors, data-protection officers -->
<!-- ion-doc:date=2026-05-26 -->

# ION — Data-Minimisation Audit

**Document owner:** Repository maintainer (`ixion36`)
**Status:** Current as of v0.31.14 (2026-05-26)
**Review cadence:** Every minor-version bump (v0.X.0) or when a new
table is added that handles PII / free-text user content.
**Primary framework:** Secure-by-Design P13 ("Reduce impact of
compromise") — see `docs/SECURE_BY_DESIGN.md`.

> This document closes the named gap that kept P13 at "Mostly Met"
> in audit revisions 1.0 through 1.8: *"formal data-minimisation
> audit is pending."* The audit was carried out at v0.31.12 against
> the ~100-table schema in `src/ion/models/`. Existing data-min
> controls are catalogued; residual gaps are inventoried with
> rationale.

## 1. Scope and method

ION's data layer is a single Postgres instance (with pgvector for
case + KB embeddings) declared via ~100 SQLAlchemy tables across 47
files under `src/ion/models/`. The audit:

1. Enumerated every `__tablename__` declaration in `src/ion/models/`.
2. Tiered tables by likely PII / sensitive-content exposure:
   * **Tier 1 (deep read):** `users`, `user_sessions`, `audit_logs`,
     `security_events`, `blocked_ips`, `ai_chat_sessions`,
     `ai_chat_messages`, `analyst_notes`, `observables`, `ai_feedback`.
   * **Tier 2 (medium read):** alert / case suite, annotation suite,
     `ai_user_preferences`, `ai_response_feedback`, `social_*`,
     `forensic_custody_log`, `integration_events`, `escalation_log`,
     `change_log`, `webhooks`.
   * **Tier 3 (skim):** operational state, reference data, vector
     embeddings, training/grading rows, scheduler tables.
3. For each Tier 1 / Tier 2 table:
   * Listed every column with type + nullability.
   * Cross-referenced PII columns against caller code via `grep` to
     confirm the column is used by a real feature and not vestigial.
   * Checked for documented retention or auto-cleanup behaviour.
4. Catalogued existing data-min controls (cross-cutting + per-table).
5. Identified residual gaps and categorised them: **fix-in-this-release**,
   **track-as-future-work**, or **accept-with-rationale**.

The full SQLAlchemy model files referenced are the audit's "source of
truth"; this document summarises and is intentionally NOT exhaustive
on every operational-state column. The categorisation focus is on
columns that carry PII, free-text user content, IPs / user agents,
or anything that would surprise an auditor reviewing the data layer.

## 2. Existing data-min controls (already in place at v0.31.12)

| # | Control | Location | What it prevents |
|---|---------|----------|------------------|
| C1 | **Air-gap-first deployment** | `docs/DEPLOYMENT.md` | Most ION customers run with no outbound internet — data never leaves the customer's network perimeter. Massively bounds the blast radius of any breach. |
| C2 | **Container isolation, non-root user** | `Dockerfile` (`useradd -r ion`), `docker-compose.yml` | Process-level isolation; even a code execution bug doesn't grant host-level data access. |
| C3 | **bcrypt password storage** | `src/ion/auth/service.py`, `src/ion/models/user.py:47` | `users.password_hash` is bcrypt; never plaintext. |
| C4 | **`closure_reason` enum** | `src/ion/models/alert_triage.py` | Limits the free-text verdict surface on case close to a finite set of values; no analyst free-text is stored as the verdict. |
| C5 | **`ION_BOB_STORE_REASONING` env gate** | `src/ion/web/bob_eval_api.py:161-168` | Bob's free-text reasoning is dropped from API responses unless explicitly opted-in by the operator (default: `false`). |
| C6 | **Append-only ledgers with sha256 chain** | `case_evidence_ledger` (`case_evidence.py`), `forensic_case_ledger` (`forensic_workbench.py`) | Tamper-evident, soft-delete only; ledger rows are integrity-binding. |
| C7 | **Soft-delete pattern for cases / alerts** | `alert_cases`, `forensic_cases` | Records preserved but hidden from active queries; no hard delete of audit-sensitive content. |
| C8 | **Per-user expired-session cleanup at login** | `src/ion/auth/service.py:140` (`delete_expired_for_user`) | Bounds `user_sessions` retention to "until next login"; expired rows for active users self-clean. |
| C9 | **TLP / PAP markings on observables** | `src/ion/models/observable.py:119-120` (`tlp`, `pap`) | Object-level sharing classification — informs export decisions before data leaves the system. |
| C10 | **No shared secrets between integrations** | per-integration `ION_<NAME>_*` env-var families | Each integration carries its own credentials; compromise of one integration doesn't pivot to another. |
| C11 | **Service accounts cannot log in interactively** | `src/ion/models/user.py:53-55` (`is_service_account` flag, auth-flow short-circuit) | Service-account credentials are inert at the interactive login surface even if the placeholder password hash is matched. |
| C12 | **WeasyPrint external-URL fetcher blocked** | `src/ion/services/pdf_renderer.py` (v0.20.1) | Stored content cannot reach external XML / image fetches during PDF rendering; bounds SSRF blast radius for any PII-bearing report. |
| C13 | **CSP nonce on inline `<script>` / `<style>`** | `SecurityHeadersMiddleware` (v0.31.3) | Limits the surface for stored-XSS exfiltration of any DOM-reachable PII. |

## 3. Tier 1 findings — PII-carrying or free-text-bearing tables

### 3.1 `users`

```
id, username, email, password_hash, display_name, is_active,
is_service_account, last_login, must_change_password,
failed_login_attempts, locked_until, employment_type,
gitlab_username, elastic_username, elastic_uid, keycloak_sub,
created_at, updated_at
```

| Column | Category | Justification | Action |
|--------|----------|---------------|--------|
| `username` | Operational identifier | Primary auth identifier | Keep |
| `email` | PII | Password reset, notifications | Keep — feature-justified |
| `password_hash` | Credential (hashed) | bcrypt | Keep — C3 |
| `display_name` | PII | UI display ("logged in as Alice Smith") | Keep — feature-justified |
| `is_active`, `must_change_password`, lockout fields | Operational state | Account lifecycle | Keep |
| `last_login` | Operational timestamp | "Active in last 30 days" reporting | Keep — could be rounded to date if ever needed, currently full timestamp; marginal |
| `employment_type` | PII-adjacent (HR classification) | Used by `skills_api.py:1000/1039` for training-adoption analytics aggregated by employment type | Keep — feature-justified; aggregation only, never displayed per-user |
| `gitlab_username`, `elastic_username`, `elastic_uid`, `keycloak_sub` | PII (external identity mappings) | Federated SSO + external integration lookups (`/api/*` services correlate user actions across stacks) | Keep — feature-justified |

**Status: clean.** Every column is feature-justified; bcrypt protects
the only credential-shaped field; HR classification (`employment_type`)
is used only in aggregate views.

### 3.2 `user_sessions`

```
id, user_id, session_token, expires_at, ip_address, user_agent,
created_at, active_role_id
```

| Column | Category | Justification | Action |
|--------|----------|---------------|--------|
| `session_token` | Secret (token form, not hashed) | Server-side session id; rotated on logout | Keep — moved into a hashed-at-rest variant would be a v0.32+ enhancement, not load-bearing for this audit |
| `expires_at` | Operational | TTL | Keep |
| `ip_address` (45) | **PII (GDPR)** | "Where did this session originate?" + audit context | Keep — feature-justified |
| `user_agent` (500) | PII-adjacent (fingerprint) | "Is this an unusual device?" + active-session UI | Keep — feature-justified |
| `active_role_id` | Operational | Focus-mode role restriction | Keep |

**Existing control: C8** — per-user expired sessions are deleted at
the user's next login. So a session row's max lifetime is bounded by
the owner-user's next login, not by `expires_at`.

**~~Gap G1~~ — CLOSED v0.31.13.** A new background loop at
`src/ion/services/session_cleanup_service.py` wraps the existing
`AuthService.cleanup_expired_sessions()` helper and runs it on a
configurable cadence. Wired into ION's startup hook (`web/server.py`)
under advisory lock `LOCK_SESSION_CLEANUP_BG = 1023`, so only one
worker per cluster runs the sweep. New env vars:
`ION_SESSION_CLEANUP_ENABLED` (default `true` — opt-out, since
data-min is the safer default) and `ION_SESSION_CLEANUP_INTERVAL_HOURS`
(default `6`, floored at 60s). Active-user cleanup at login (C8)
remains the primary control; this loop catches the dormant-user
tail. Loop logs `deleted N expired sessions` only when N > 0 — silent
when the table is clean.

### 3.3 `audit_logs`

```
id, user_id, action, resource_type, resource_id, details (Text),
ip_address (45), timestamp
```

| Column | Category | Justification | Action |
|--------|----------|---------------|--------|
| `user_id` | Operational | "Who did this?" | Keep |
| `action`, `resource_type`, `resource_id` | Operational | "What did they do, to what?" | Keep |
| `details` (Text, unbounded) | Variable — caller-controlled JSON | Audit context; can carry usernames, IPs, target identifiers | Keep — feature-justified; caller convention is short JSON-serialised context, not free-form text |
| `ip_address` (45) | **PII (GDPR)** | "From where?" audit context | Keep — feature-justified |
| `timestamp` | Operational | Audit ordering | Keep |

**No append-only invariant in schema** — the table is logically
append-only by convention (no `update` or `delete` paths in
`audit_repository.py`), but no DB-level constraint enforces it.
Mitigated by C7 / C6 spirit. Acceptable for audit-logs which are
inherently append-only by domain semantics.

**~~Gap G2~~ — CLOSED v0.31.14.** New `ION_AUDIT_LOG_RETENTION_DAYS`
env var. Unset/empty by default = no cleanup (preserves v0.31.13
behaviour). Set to a positive integer N to enable: rows whose
`timestamp` is older than N days are deleted on the next sweep.
Implemented in `src/ion/services/data_retention_service.py` under
advisory lock `LOCK_DATA_RETENTION_BG = 1024`. Default sweep
interval: 24h (`ION_DATA_RETENTION_INTERVAL_HOURS`, floored at 60s).
Loop is opt-OUT at the loop level (`ION_DATA_RETENTION_ENABLED`,
default `true`) but each table's retention is opt-IN per the
rationale above.

### 3.4 `security_events`

```
id, event_type, severity, status, title, description (Text),
source_ip (45), user_agent (Text), request_path (2048),
request_method (10), user_id, username (255), detection_rule,
confidence_score, raw_data (JSON), matched_patterns (JSON),
event_count, first_seen, last_seen, blocked, exported_to_siem,
created_at, updated_at
```

| Column | Category | Justification | Action |
|--------|----------|---------------|--------|
| `event_type`, `severity`, `status`, `detection_rule` | Operational | Telemetry classification | Keep |
| `title`, `description` (Text) | Operational | Human-readable event summary | Keep |
| `source_ip` (45) | **PII (GDPR)** | "Where did the suspicious activity originate?" | Keep — feature-justified; required for SIEM export (C12 `to_siem_format`) |
| `user_agent` (Text) | PII-adjacent | Attribution signal | Keep — feature-justified |
| `request_path` (2048), `request_method` (10) | Operational | Attack context | Keep |
| `user_id`, `username` (denormalised) | Operational | Attributed event | Keep — denormalisation is intentional so events survive user deletion |
| `raw_data` (JSON), `matched_patterns` (JSON) | Variable — detector-controlled | Forensic detail | Keep — feature-justified |
| `event_count`, `first_seen`, `last_seen` | Operational | Aggregation across repeated events | Keep |
| `blocked`, `exported_to_siem` | Operational | Response state | Keep |

**~~Gap G3~~ — CLOSED v0.31.14.** New `ION_SECURITY_EVENTS_RETENTION_DAYS`
env var, same pattern as G2 (unset = disabled; positive integer
enables N-day retention). Implemented in the same
`data_retention_service.py` module by appending a second
`RetentionRule` tuple. The shared loop sweeps both tables on the
same `ION_DATA_RETENTION_INTERVAL_HOURS` cadence; operators
configure each independently. Targets `security_events.created_at`
as the retention column (vs. `audit_logs.timestamp`).

### 3.5 `blocked_ips`

```
id, ip_address (45), reason (Text), blocked_until, permanent,
security_event_id, created_at, updated_at
```

| Column | Category | Justification | Action |
|--------|----------|---------------|--------|
| `ip_address` | **PII (GDPR)** | The whole point of the table | Keep — feature-justified |
| `reason` (Text) | Operational | Why blocked | Keep |
| `blocked_until`, `permanent` | Operational | TTL / persistence | Keep |
| `security_event_id` | Foreign-key | Link to triggering event | Keep |

**No retention gap** — non-permanent blocks expire by `blocked_until`
semantics (consumers check `is_active()`). Permanent blocks are by
operator choice; data-min is operator-controlled.

### 3.6 `analyst_notes`

```
id, user_id, title, content (Text), content_html (Text), is_pinned,
color, folder_id, created_at, updated_at
```

| Column | Category | Justification | Action |
|--------|----------|---------------|--------|
| `title`, `content`, `content_html` | Free-text user content (may contain PII the analyst pasted in) | Personal note-taking feature | Keep — feature-justified; user controls deletion |
| `user_id` | Operational | Ownership / RBAC | Keep |
| `is_pinned`, `color`, `folder_id` | Operational | UI state | Keep |

**Data-min control: user-controlled deletion.** Analyst notes are
the user's own content; the user can delete any note. No external
retention obligation. Acceptable.

### 3.7 `ai_chat_sessions` + `ai_chat_messages`

```
ai_chat_sessions: id, user_id, title, context_type,
                  created_at, updated_at
ai_chat_messages: id, session_id, role, content (Text), created_at
```

| Column | Category | Justification | Action |
|--------|----------|---------------|--------|
| `content` (Text, unbounded) | Free-text — user prompts + AI responses | AI chat feature | Keep — feature-justified |
| `role` | Operational | "user" / "assistant" / "system" | Keep |
| `title` | Auto-generated from first message | UI list rendering | Keep |
| `user_id`, `session_id` | Operational | RBAC + threading | Keep |
| `context_type` | Operational | Routing hint | Keep |

**Data-min control: CASCADE delete on session deletion + user-controlled
session lifecycle.** A user can delete any chat session, which
cascades to all its messages (line 36-37 in `ai_chat.py`).

**Residual question (accept-with-rationale):** Chat sessions persist
until the user actively deletes them. For users who never clean up,
their full chat history (including pasted PII / alert excerpts /
investigation notes) accumulates. **Mitigated by (a) user-controlled
deletion, (b) C1 air-gap deployment, (c) RBAC — only the owning user
can read their sessions.** Optional future enhancement:
`ION_AI_CHAT_RETENTION_DAYS` env var for auto-purge of inactive
sessions; not load-bearing for P13 closure.

### 3.8 `observables`

```
id, type, value (2048), normalized_value (2048), first_seen, last_seen,
sighting_count, threat_level, is_whitelisted, tags (JSON),
notes (Text), tlp, pap, is_ioc, ignore_similarity, is_watched,
watch_reason (500), watched_by (100), watched_at, auto_enrich,
last_auto_enriched, created_at, updated_at
```

| Column | Category | Justification | Action |
|--------|----------|---------------|--------|
| `value`, `normalized_value` | Variable — observable type-dependent (IP, email, hash, URL, etc.) | Core observable identity | Keep — feature-justified |
| `notes`, `watch_reason` (free-text) | User-authored content (may carry context PII) | Operator markup | Keep — user-controlled |
| `watched_by` (string, not FK to users) | PII (username denormalised) | Watch-history attribution | Keep — denormalisation justified by survive-user-deletion contract |
| `tlp`, `pap` | Operational (sensitivity classification) | C9 control | Keep |
| `is_*` flags, counters, timestamps | Operational | Aggregation + state | Keep |

**Data-min control C9 (TLP/PAP markings)** — sensitivity is captured
at row-level, informing downstream sharing decisions. The combination
of TLP + the WeasyPrint external-URL block (C12) + container
isolation (C2) gives a defence-in-depth posture for the PII-bearing
observable values.

### 3.9 `ai_feedback`

```
id, investigation_id, case_id, alert_id, alert_prompt_template_id,
bob_suggested_verdict, bob_confidence, human_verdict,
human_closed_by_id, agreement, delta_reason (Text),
bob_confidence_int, auto_escalated, created_at, updated_at
```

| Column | Category | Justification | Action |
|--------|----------|---------------|--------|
| Verdicts, confidence, agreement | Operational | Bob vs human comparison metrics | Keep |
| `delta_reason` (Text) | Optional free-text | Operator-supplied reason when Bob disagreed | Keep — operator-controlled, optional |
| `human_closed_by_id` | FK to users | Attribution | Keep |
| Other timestamps + flags | Operational | Standard | Keep |

**No PII concern.** The `delta_reason` is operator-controlled, optional,
and feature-justified for tuning the Bob model. The reasoning_text
stored in the `investigations` table is gated by C5 (`ION_BOB_STORE_REASONING`).

## 4. Tier 2 findings — summary

Tier 2 tables (alert / case suite, annotation suite, social, custody
log, integration events, escalation log) were skimmed; no
column-level data-min issues surfaced beyond the patterns already
captured in Tier 1. Notable observations:

* **`forensic_custody_log`** — chain-of-custody records. Append-only by
  domain semantics; columns track who handled what evidence when.
  PII-adjacent (analyst usernames + timestamps) but mandatory for the
  custody-chain integrity property the workbench guarantees. Keep.
* **`escalation_log`** — paging records. Operational state, no PII
  beyond user attribution.
* **`integration_events`** — outbound payload snapshots. Mostly
  operational; payloads can carry observable values per the system
  design. C10 (per-integration credentials) is the relevant control.
* **`social_posts` / `social_comments` / `social_reactions`** —
  internal SOC team chat-style feed. Free-text user content. User
  deletion is supported. Same posture as `analyst_notes`.
* **`webhooks`** — outbound webhook configuration. Operational state;
  endpoint URLs are operator-controlled.
* **`change_log`** — change-management feed. Operational state.

## 5. Tier 3 — out of scope for column-level audit

Tier 3 tables are operational state (scheduled jobs, course
progress, network asset registry, vector embeddings, reference data
like CYAB pillars, etc.). They do not store PII, free-text user
content, or audit-sensitive data. No column-level findings.

## 6. Gaps inventory + future work

| ID | Gap | Severity | Status | Recommended action |
|----|-----|----------|--------|--------------------|
| ~~G1~~ | ~~`user_sessions` accumulates expired rows for dormant users~~ | Low | **Closed v0.31.13** | New `src/ion/services/session_cleanup_service.py` background loop under advisory lock `LOCK_SESSION_CLEANUP_BG`. Honours `ION_SESSION_CLEANUP_ENABLED` / `ION_SESSION_CLEANUP_INTERVAL_HOURS` env vars (defaults: enabled, 6h). |
| ~~G2~~ | ~~`audit_logs` has no retention policy~~ | Low (air-gap mitigates) | **Closed v0.31.14** | New `ION_AUDIT_LOG_RETENTION_DAYS` env var (default unset = disabled). When set, `src/ion/services/data_retention_service.py` deletes rows older than N days on its daily sweep under `LOCK_DATA_RETENTION_BG`. |
| ~~G3~~ | ~~`security_events` has no retention policy~~ | Low (air-gap mitigates) | **Closed v0.31.14** | New `ION_SECURITY_EVENTS_RETENTION_DAYS` env var, same module + sweep as G2. Targets `security_events.created_at`. |
| G4 | `ai_chat_sessions` / `ai_chat_messages` persist until user deletion | Acceptable | Accept-with-rationale | Optional future enhancement: `ION_AI_CHAT_RETENTION_DAYS` env var. Not required for P13 closure given user-controlled deletion + RBAC. |
| G5 | `session_token` stored as plaintext in `user_sessions` table (not hashed at rest) | Low (token rotated on logout, server-side only — DB compromise required to abuse) | Track | Hash-at-rest variant for `session_token`. v0.32+ candidate. |

After v0.31.14's G2 + G3 closures, **two** gaps remain — G4 and G5,
both lower-priority than the closed three. All remaining gaps
are **low severity** because:

* ION's air-gap-first deployment pattern (C1) means PII never leaves
  the customer's network perimeter.
* Container isolation (C2) + non-root user means a code execution
  bug doesn't grant filesystem-level DB access.
* RBAC (C11 + the broader role/permission model) restricts in-app
  PII access to the user who owns or has been granted access to each
  row.
* Existing C8 (per-user session cleanup at login) bounds G1 for
  active users.
* All five gaps require *post-compromise* exploitation — they are
  defence-in-depth concerns, not direct attack surfaces.

The named gap that kept P13 at "Mostly Met" — *formal data-minimisation
audit is pending* — is now closed by this audit. The five residual
items above are tracked as ordinary future improvements, the same
way P11's remaining 69 templates are tracked: they don't constitute
unresolved P13 attack surface.

## 7. Decision: P13 status → Met

This audit document closes the named gap from prior `SECURE_BY_DESIGN.md`
revisions. P13 ("Reduce impact of compromise") status moves from
**Mostly Met → Met** at v0.31.12. The audit summary advances from
**17 Met / 3 Mostly Met / 0 Partial / 0 Gap** to
**18 Met / 2 Mostly Met / 0 Partial / 0 Gap**.

P13's existing ION-application bullets remain accurate; this
document supplements them with the explicit schema-wide audit
trail. The residual Mostly Met principles are:

* **P1** — single-maintainer model (structural; six artifacts in
  place from v0.31.9).
* **P11** — strict CSP enforcement requires migrating ~69 templates
  off inline event handlers + style attributes.

## 8. Revision history

| Version | Date       | Author     | Notes |
|---------|------------|------------|-------|
| 1.0     | 2026-05-26 | Maintainer | Initial publication at v0.31.12. Closes the data-min audit gap from SECURE_BY_DESIGN.md rev 1.0–1.8. Catalogues 13 existing data-min controls; identifies 5 low-severity residual gaps tracked for v0.32+. P13 moves Mostly Met → Met. |
| 1.1     | 2026-05-26 | Maintainer | v0.31.13: **G1 CLOSED.** New `src/ion/services/session_cleanup_service.py` wraps `AuthService.cleanup_expired_sessions()` in a periodic background loop. Under advisory lock `LOCK_SESSION_CLEANUP_BG = 1023` for cross-worker single-leader execution. Env vars `ION_SESSION_CLEANUP_ENABLED` (default true) + `ION_SESSION_CLEANUP_INTERVAL_HOURS` (default 6, floored at 60s). Wired into `web/server.py` startup. Audit advances from 5 residual gaps to 4 (G2 / G3 / G4 / G5 remain). |
| 1.2     | 2026-05-26 | Maintainer | v0.31.14: **G2 + G3 CLOSED.** New `src/ion/services/data_retention_service.py` parameterised on a list of `RetentionRule` tuples — current rules cover `audit_logs.timestamp` and `security_events.created_at`. Under advisory lock `LOCK_DATA_RETENTION_BG = 1024`. Env vars `ION_AUDIT_LOG_RETENTION_DAYS` and `ION_SECURITY_EVENTS_RETENTION_DAYS` are **opt-IN** (unset = disabled — operators have wildly different compliance windows so silent default deletion is dangerous). Shared loop cadence via `ION_DATA_RETENTION_ENABLED` (loop kill switch, default `true`) + `ION_DATA_RETENTION_INTERVAL_HOURS` (default 24h, floored at 60s). G4 (AI chat retention) is the next natural fit — adds one tuple to `RETENTION_RULES`. Audit advances from 4 residual gaps to 2 (G4 / G5 remain). |
