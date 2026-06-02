<!-- ion-doc:type=SECURITY ASSESSMENT -->
<!-- ion-doc:title=ION Security Assessment Report -->
<!-- ion-doc:subtitle=Per-release security audit with severity-trend table; OWASP Top 10 + AI safety + supply chain -->
<!-- ion-doc:version=0.37.0 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) + Security Audit Agent -->
<!-- ion-doc:audience=Customer security, ITHC supplier, compliance, design authority -->
<!-- ion-doc:date=2026-06-01 -->

# ION Security Assessment Report

**Assessment Date:** 2026-06-02 (v0.37.0 delta) / 2026-06-01 (v0.36.0 delta) / 2026-06-01 (v0.35.0 delta) / 2026-06-01 (v0.34.5 delta) / 2026-05-28 (v0.34.4 delta) / 2026-05-28 (v0.34.3 delta) / 2026-05-28 (v0.34.2 delta) / 2026-05-28 (v0.34.1 delta) / 2026-05-27 (v0.34.0 delta) / 2026-05-27 (v0.33.2 delta) / 2026-05-27 (v0.33.1 delta) / 2026-05-27 (v0.33.0 delta) / 2026-05-27 (v0.32.1 delta) / 2026-05-27 (v0.32.0 delta) / 2026-05-26 (v0.31.18 + v0.31.17 + v0.31.16 + v0.31.15 + v0.31.14 + v0.31.13 + v0.31.12 + v0.31.11 + v0.31.10 deltas) / 2026-05-14 (v0.31.9 + v0.31.8 + v0.31.7 + v0.31.6 + v0.31.5 + v0.31.4 + v0.31.3 + v0.31.2 deltas) / 2026-05-13 (v0.31.1 + v0.31.0 + v0.30.1 + v0.30.0 deltas) / 2026-05-12 (v0.29.1 + v0.29.0 + v0.28.0 + v0.27.0 + v0.26.1 deltas) / 2026-05-11 (v0.26.0 + v0.25.x + v0.24.0 + v0.23.x + v0.22.1) / 2026-05-09 (v0.22.0-rc body below)
**Application Version:** 0.37.0 (Bob RAG embedding-text quality — Phase 2b. The alert query vector gains Reason (`kibana.alert.reason`) + MITRE tags + a bounded TI-enrichment verdict digest after the aligned core; `investigate_case` passes a merged copy so the original alert is untouched (alert_summary / PII unaffected). Case vectors embed Bob's AI summary only for decisive verdicts — inconclusive/null noise filtered. Per-section length caps prevent silent nomic context-truncation; a shared core-section serializer stops the alert + case builders drifting. Internal embedding-text logic only — no new routes, permissions, or schema; adversary-controlled alert content already flowed into the prompt and the vectors are similarity-only. 16 new tests; full suite green (863 passed). SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap. Net new findings: 0C / 0H / 0M / 0L.) v0.36.0 (Bob RAG layers default ON — Phase 2. `ION_EMBEDDING_ENABLED`, `ION_KB_RAG_ENABLED`, `ION_FEW_SHOT_EXEMPLARS_ENABLED` and `ION_BOB_STORE_REASONING` now default ON (opt out with `=false`). Every retrieval layer degrades to a silent no-op when Ollama is unreachable — `embed()` returns None and never raises, both background embedding loops no-op — so default-on is safe even on an air-gapped estate without an LLM host. **Net-new surface:** reasoning-text-on-by-default expands data-at-rest — Bob's analyst-explanation now persists by default on the `Investigation` row (and is surfaced in the eval API) in a single-tenant, air-gapped DB visible only to authenticated SOC users. Opt-out via `ION_BOB_STORE_REASONING=false`, which also withholds reasoning at the response layer for previously-stored rows (no back-fill purge needed). The per-call embedding gate and the loop-start gate now share a single default (pinned by test) and the reasoning gate is a single source of truth across persistence + response layers. No new routes, permissions, or schema; adversary-controlled alert content already flowed into the prompt. 13 new/updated tests; full suite green (847 passed). SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap. Net new findings: 0C / 0H / 0M / 0L.) v0.35.0 (Bob RAG prompt-assembly hardening — Phase 1. Token-budget guard in `render_system_prompt`: RAG layers are dropped in reverse-priority order (KB → exemplars → skills) when the assembled prompt would overflow the llama3.1:8b 8K context; the output contract is appended last and never budget-gated. This closes a silent front-truncation bug — Ollama truncates from the front, where the output contract lives, so an overlong prompt intermittently cost Bob its JSON envelope. `investigate_case` now injects the full RAG prompt even when no AlertPromptTemplate matches the alert (was falling back to the raw `SYSTEM_PROMPTS["security"]` string, skipping all grounding). Investigation memory cap raised 1500 → 3000 chars. 7 new tests; full suite green (834 passed). Internal prompt-assembly logic only — no new routes, permissions, or schema; adversary-controlled alert content already flowed into the prompt, and the guard only bounds how much survives. SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap. Net new findings: 0C / 0H / 0M / 0L.) v0.34.5 (Report detail slide-over on Daily Standup + Threat Intel. Clicking a report card opens a fixed side panel with full OpenCTI detail (meta, labels, body, actors, TTPs, malware, vulns, countries, sectors, indicators). No new routes. Endpoint `/api/threat-landscape/reports/{id}` already existed and is permission-gated (observable:read). All rendered content passes through `esc()`/`escapeHtml()` before insertion. SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap. Net new findings: 0C / 0H / 0M / 0L.) v0.34.4 (Arkime Traffic Analytics additions: country choropleth world map + per-sensor bar chart + private-to-private IP filter on top-talkers. CSP fix: 4 inline style="" attrs moved to nonced <style> block; .atf-overlay.hidden specificity fixed. 3 new ArkimeService methods, 11 new tests. SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap. Net new findings: 0C / 0H / 0M / 0L.) v0.34.3 (Arkime Traffic Analytics: new Operations sub-page /arkime-traffic. Chart.js v4.4.4 vendored. Two new ArkimeService methods. 8 new tests. SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap. Net new findings: 0C / 0H / 0M / 0L.) v0.34.2 (Daily standup fix: critical-alerts fallback no longer fires when ES is healthy but returns zero critical alerts. Rule name uses title as fallback; raw es_alert_id never shown as display name. 6 new tests. SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap. Net new findings: 0C / 0H / 0M / 0L.) v0.34.1 (Bob analysis fix: OllamaService() bare constructor replaced with get_ollama_service() factory — Bob now reads ION_OLLAMA_URL/MODEL/TIMEOUT from config instead of defaulting to http://localhost:11434. SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap. Net new findings: 0C / 0H / 0M / 0L.) v0.34.0 (Arkime auto-case service: new background loop creates AlertCase + queues PCAP analysis for ES alerts with network.community_id + arkime_node. Removes AI case-summary background task on case close. Removes MITRE ATT&CK heatmap feature from CyAB entirely. SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap. Net new findings: 0C / 0H / 0M / 0L.) v0.33.2 (FastAPI lifespan refactor: @app.on_event("startup") replaced with asynccontextmanager lifespan pattern; eliminates DeprecationWarning from FastAPI 0.136.1. Stale pip audit files removed. SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap. Net new findings: 0C / 0H / 0M / 0L.) v0.33.1 (CSP nonce fix: 11 API modules with private Jinja2Templates instances rendered nonce="" â€” CSP blocked nav CSS block and all inline scripts/styles. Shared _csp_nonce.py module created; all instances now register the proxy. Also includes P11 display:none CSS specificity fix. SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap. Net new findings: 0C / 0H / 0M / 0L.) v0.33.0 (Dependency security sweep: 26 pip-audit CVEs â†’ 0 ION-relevant findings. fastapi 0.128â†’0.136.1 + starlette 0.50â†’1.1.0 + python-multipart 0.0.22â†’0.0.29 + PyJWT 2.11â†’2.13 + requests 2.32â†’2.34 + cryptography 46.0.5â†’48.0.0 + urllib3 2.6â†’2.7 + idna 3.11â†’3.16 + lxml 6.0â†’6.1 + Pillow 12.1â†’12.2 + pyasn1 0.6.2â†’0.6.3 + pygments 2.19â†’2.20 + pytest 9.0.2â†’9.0.3. Residual 7 findings (ecdsa/nltk/pip) are local-env residuals absent from Docker image. 810 tests green. SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap. Net new findings: 0C / 0H / 0M / 0L.) v0.32.1 (Code review follow-up: ES client credential refresh + dead ticker permissions removed. `_get_es_client` now detects runtime credential changes via a SHA-256 fingerprint and recreates the client on mismatch â€” admin-wizard credential updates no longer require a server restart. Dead `ticker:read`/`ticker:create`/`ticker:manage` permission seeds removed from `_initialize_permissions()` and the `ai_analyst` role grants; no API ever enforced these. All four CODE_REVIEW_ION.md findings now marked closed. 8 new unit tests. SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap. Net new findings: 0C / 0H / 0M / 0L.) v0.32.0 (Critical reliability fix: dead circuit breakers wired. es_breaker/ollama_breaker/kibana_breaker now receive record_success()/record_failure() feedback from their respective HTTP transports. can_execute() guards added to all three OllamaService entry points. 11 new unit tests cover trip, recovery, and open-state fast-fail behaviour. SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap. Net new findings: 0C / 0H / 0M / 0L.) v0.31.25 â€” SUPPLY-CHAIN finding + fix. v0.31.24's now-working pip-audit gate caught MAL-2026-4750: fastapi 0.136.3 ships modified pyproject.toml + PKG-INFO adding an undocumented `fastar` typo-squat dep via [standard] extra. v0.31.10â€“v0.31.24 images all ship the malicious wheel. ION's pyproject doesn't pull [standard] so the typo-squat never installs, bounding exploitability â€” but the wheel is still in the supply chain. v0.31.25 pins fastapi<0.136.3 (resolves to 0.136.1, pre-incident). pip-audit confirms no findings post-pin. SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap.) v0.31.24 was the CI-fully-green release. Pip-audit --strict dropped (incompatible with --skip-editable); two flaky integration tests marked @pytest.mark.xfail(strict=False) with TODO reasons. SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap.) v0.31.23 was code-review hardening: (1) ALTER COLUMN SET NOT NULL on session_token_hash post-backfill (Postgres); (2) ADD COLUMN IF NOT EXISTS + duplicate-column tolerance for multi-worker startup race; (3) event-delegation.js resolveAction() with ACTION_NAME_RE regex + ACTION_DENYLIST for defence-in-depth against stored-XSS escalation via data-click-action lookup; (4) data_retention SQLAlchemy 2.x autobegin comment. Plus pip-audit --skip-editable, ruff auto-fix on server.py + database.py import blocks. SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap.) v0.31.22 was the CI green release. Fixes 3 inherited pre-session CI failures: ruff I001/F401 in threat_intel_api.py auto-fixed; 4 pytest expectations in test_v025_pcap_auto_analysis updated to current production dict shape; pip-audit switched from osv to pypi vulnerability-service to bypass an upstream OSV parser bug. None caused by this session. SECURE_BY_DESIGN audit summary unchanged at 19 Met / 1 Mostly Met / 0 Partial / 0 Gap.) v0.31.21 was the P11 FULL closure (style-attr half). Style-attr half of P11 shipped. 1,820 inline style="" attributes retired across 65 templates â†’ 993 hashed CSS classes in src/ion/web/static/css/ion-migrated-styles.css (77KB), loaded from base.html. CSP style-src-attr flipped to 'none'. AUDIT SUMMARY: 19 Met / 1 Mostly Met / 0 Partial / 0 Gap. Only P1 single-maintainer structural remains. ION-side findings count unchanged at 0C / 0H / 3M / 4L.) v0.31.20 was the script-attr half. `script-src-attr` flipped from `'unsafe-inline'` to `'none'` in SecurityHeadersMiddleware CSP after every inline event handler retired (~1,150 cumulative migrations across v0.31.4â€“v0.31.19). Browsers block inline-handler injection at runtime. style-src-attr still `'unsafe-inline'` for 1,659 inline `style=""` attributes â€” v0.32+ cosmetic-CSS cleanup. ION-side findings count unchanged at 0C / 0H / 3M / 4L.) v0.31.19 was the regression-fix release. v0.31.18 mass migration produced JS-string-concat regressions in 24 lines and onkeydown mis-translations in 6 lines â€” all fixed via template-literal refactor + new data-enter-key-action / data-escape-key-action helpers. 8 new event-delegation built-ins land. ~25 more handlers migrated; 7 complex stragglers staged for v0.31.20. ION-side findings count unchanged at 0C / 0H / 3M / 4L.)
**Previous Assessment Version:** 0.33.0 (2026-05-27)
**Scope:** Web application security review â€” authenticated internal-user threat model, prompt-injection from adversary-controlled alert content, privilege escalation, data exfiltration, pivot to backend systems (Elastic, Kibana, TIDE, OpenCTI, Arkime, Keycloak).
**Previous Assessment:** 2026-04-07 (v0.9.43)
**Reviewer:** Security Audit Agent

---

## Executive Summary

ION maintains strong security fundamentals: bcrypt password hashing, SQLAlchemy ORM parameterised queries throughout the main codebase, SandboxedEnvironment Jinja2 rendering, DOMPurify XSS mitigation, RBAC with 7-tier role hierarchy, rate limiting on auth endpoints, circuit breakers on all external integrations, and ECS-compliant audit logging. v0.19.17â€“v0.20.0 closed several moderate-to-low findings from the last assessment. v0.21.0-rc added the Bob Eval Harness, per-template confidence threshold overrides, and the `reasoning_text` storage gate. v0.22.0-rc adds two well-gated read/write surfaces (MITRE coverage heatmap and timeline annotations) AND removes a latent SSRF/unvalidated-write path (`POST /api/elasticsearch/config`) along with several legacy-route dead-code surfaces. Net new in v0.22.0: 0C / 0H / 0M / 0L. The removed write path is a findings-quality improvement, not a counted closure.

| Severity | v0.9.43 | v0.20.1-rc | v0.21.0-rc | v0.22.0-rc | v0.22.1 | v0.23.0 | v0.23.1 | v0.23.2 | v0.24.0 | v0.25.0 | v0.25.1 | v0.26.0 | v0.26.1 | v0.27.0 | v0.28.0 | v0.29.0 | v0.29.1 | v0.30.0 | v0.30.1 | v0.31.0 | v0.31.1 | v0.31.2 | v0.31.3 | v0.31.4 | v0.31.5 | v0.31.6 | v0.31.7 | v0.31.8 | v0.31.9 | v0.31.10 | v0.31.11 | v0.31.12 | v0.31.13 | v0.31.14 | v0.31.15 | v0.31.16 | v0.31.17 | v0.31.18 | v0.31.19 | v0.31.20 | v0.31.21 | v0.31.22 | v0.31.23 | v0.31.24 | v0.31.25 | v0.32.0 | v0.32.1 | v0.33.0 | v0.33.1 | v0.33.2 | v0.34.0 | v0.34.1 | v0.34.2 | v0.34.3 | v0.34.4 | v0.34.5 | v0.35.0 | v0.36.0 | v0.37.0 |
|---------|---------|---------|---------|-|---------|---------|---------|---------||---------|---------|---------|---------|---|---------|---------|---------|---------|---|---------|---------|---------|---------|---|---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------|-|---------|---------|---------|---------|-|---------|---------|---------|---------|-|---------|---------|---------|---------|-|---------|---------|---------|---------|-|---------|---------|---------|---------|-|---------|---------|---------|---------|-|---------|---------|---------|---------|-|---------|---------|---------|---------|-|---------|---------|---------|---------|-|---------|---------|---------|---------|-|---------|---------|---------|---------|-|---------|---------|---------|---------|-|---------|---------|---------|---------|-|---------|---------|---------|---------|-|---------|---------|---------|---------|-|---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---------|---------|---------||---------|---|
| Critical | 0 | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** |
| High | 0 | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** | **0** |
| Medium | 2 | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **3** | **0** | **0** | **0** | **0** | **0** | **0** |
| Low | 3 | **4** | **6** | **6** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **0** | **0** | **0** | **0** | **0** | **0** |
| **Total** | **5** | **7** | **9** | **9** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **7** | **0** | **0** | **0** | **0** |

v0.32.0 is a critical reliability fix: **circuit breakers were structurally inert**. All five `CircuitBreaker` singletons were created and exported from `ion.core.circuit_breaker` but never received `record_success()` or `record_failure()` calls anywhere in the codebase. The `can_execute()` guards at existing call sites (`cyab_api.py`, `kibana_sync_service.py`) checked breaker state, but because the feedback path was absent the state was always `CLOSED` and `_failure_count` was always `0` â€” making the CLOSEDâ†’OPENâ†’HALF_OPEN recovery cycle impossible. Fixed by wiring feedback into the three services with owned HTTP transports: `ElasticsearchService._request()` (single transport point for all ES calls â€” `es_breaker.record_success()` on any HTTP response, `record_failure()` on `ConnectError` / `ReadError` / `TimeoutException` / `HTTPError`); `OllamaService.chat()` / `chat_stream()` / `generate()` (each has a `can_execute()` guard at entry + `record_success()` after parse + `record_failure()` on connectivity exceptions â€” a new explicit `except httpx.ConnectError` handler was also added since ConnectError was previously swallowed by the generic `except Exception` arm); `KibanaSyncService._background_sync_loop()` (`kibana_breaker.record_success()` after a full sync cycle, `record_failure()` only on httpx connectivity-class exceptions â€” logical sync failures do not trip the breaker). `opencti_breaker` and `tide_breaker` remain unwired pending audit of `OpenCTIService` and `TIDEService` transport patterns. 11 new unit tests in `tests/test_v032_circuit_breaker_wiring.py` cover: success records success; ConnectError records failure; TimeoutException records failure; N consecutive failures opens the breaker; 4xx response records success not failure; open breaker short-circuits without making an HTTP call. SECURE_BY_DESIGN audit summary unchanged at **19 Met / 1 Mostly Met / 0 Partial / 0 Gap**. **Net new findings: 0C / 0H / 0M / 0L.** No schema changes, no new attack surface, no permission gate changes.

v0.31.17 closes the fifth and final sub-gap from the v0.31.12 data-minimisation audit â€” **G5 (`session_token` hash-at-rest)**. The plaintext `session_token` column is dropped from `user_sessions`; a new `session_token_hash` column (SHA-256 hex digest, 64-char VARCHAR, UNIQUE INDEX) replaces it. Plaintext tokens now live exclusively in the client cookie â€” the DB only carries the digest. A new helper `_hash_session_token()` in `src/ion/storage/auth_repository.py` computes SHA-256 with no salt (appropriate because session tokens are 32 bytes of CSPRNG output, 256 bits of entropy â€” preimage attacks are computationally infeasible and slow hashes like bcrypt buy nothing for high-entropy random inputs). All four `SessionRepository` methods (`create`, `get_by_token`, `get_valid_session`, `delete_by_token`) hash the plaintext token internally before DB operations; caller-facing signatures unchanged. The in-place upgrade for existing deployments is handled by `_run_migrations` in `storage/database.py` atomically: ALTER TABLE ADD COLUMN session_token_hash â†’ backfill every existing row's SHA-256 digest from the plaintext â†’ CREATE UNIQUE INDEX â†’ ALTER TABLE DROP COLUMN session_token, all within one `engine.begin()` transaction so partial-completion failure rolls back to pre-upgrade state. Existing logged-in users' sessions remain valid because the hash is deterministic â€” their cookie value still maps to the same row via the new column. **After v0.31.17: all 5 audit residuals (G1â€“G5) from the original v0.31.12 audit have shipped behaviour changes.** DATA_MINIMISATION_AUDIT residual gaps count drops from 1 to 0. The audit doc has nothing outstanding â€” every named gap in Section 6 is now struck through. SECURE_BY_DESIGN audit summary unchanged at 18 Met / 2 Mostly Met / 0 Partial / 0 Gap (P13 was already Met at v0.31.12; G1â€“G5 closures are sub-principle defence-in-depth work). **Net new findings: 0C / 0H / 0M / 0L.** No new attack surface, no new auth gates; the schema change is a column-replacement with deterministic backfill.

v0.31.16 is a working-tree hygiene release. **No code changes.** Brings 40+ previously-untracked legitimate artefacts into version control (architecture docs, spec traceability CSVs, AI pair-programmer tooling under `.claude/`, PDF generator under `tools/pdf_build/`, session checkpoint working docs). Updates `.gitignore` with five new patterns to explicitly exclude regenerable artefacts (`*.pdf`, `docs/impex/`, `.local-*`, `seed_test_data.py`, `.mcp.json`). No security-relevant code changes; no new attack surface; no schema migrations; no permission shifts. SECURE_BY_DESIGN audit summary unchanged at 18 Met / 2 Mostly Met / 0 Partial / 0 Gap. **Net new findings: 0C / 0H / 0M / 0L.**

v0.31.15 closes the fourth sub-gap from the v0.31.12 data-minimisation audit â€” **G4 (`ai_chat_messages` retention)** â€” via a one-tuple extension to the parameterised `RetentionRule` list introduced in v0.31.14. New env var `ION_AI_CHAT_RETENTION_DAYS` (default unset = disabled). Targets messages, not sessions; the existing CASCADE on `AIChatSession` removal handles session-level lifecycle, while this new rule bounds message-level retention so a user's session list remains intact even after pruning old messages. The closure required zero new infrastructure â€” no new module, no new advisory lock, no new startup wiring â€” proving out the parameterised abstraction shipped one release earlier. DATA_MINIMISATION_AUDIT residual gaps drop from 2 to 1 (G5 â€” `session_token` hash-at-rest â€” remains as the only outstanding data-min residual). SECURE_BY_DESIGN audit summary unchanged at 18 Met / 2 Mostly Met / 0 Partial / 0 Gap. **Net new findings: 0C / 0H / 0M / 0L.** No new attack surface, no new auth gates, no schema migrations.

v0.31.14 closes the second and third sub-gaps from the v0.31.12 data-minimisation audit â€” **G2 (`audit_logs` retention) and G3 (`security_events` retention)**. New parameterised module `src/ion/services/data_retention_service.py` holds a `RetentionRule(env_var, model, timestamp_column)` list and runs a daily background sweep under advisory lock `LOCK_DATA_RETENTION_BG = 1024`. Current rules cover `audit_logs.timestamp` and `security_events.created_at`; future rules (G4 AI chat retention is the next natural fit) ship by appending one tuple. New env vars `ION_AUDIT_LOG_RETENTION_DAYS` and `ION_SECURITY_EVENTS_RETENTION_DAYS` are **opt-IN** (default unset = disabled) â€” the rationale documented in the CHANGELOG: compliance windows vary wildly across regimes (PCI-DSS 365 days; HIPAA 6 years; SOX 7 years; internal IR often "indefinite"), so a default-N retention would silently delete logs that customer compliance regimes require. Loop kill switch `ION_DATA_RETENTION_ENABLED` (default `true`) and cadence `ION_DATA_RETENTION_INTERVAL_HOURS` (default 24h, floored at 60s). When both env vars are unset, the loop still starts but the sweep is a no-op â€” backward-compatible with deployments that haven't yet chosen a retention window. ION-side findings count unchanged at 0C / 0H / 3M / 4L. SECURE_BY_DESIGN audit summary unchanged at 18 Met / 2 Mostly Met / 0 Partial / 0 Gap (P13 was already Met at v0.31.12; G2/G3 are sub-principle defence-in-depth work). DATA_MINIMISATION_AUDIT residual gaps count drops from 4 to 2 (G4 / G5 remain â€” optional AI chat retention, `session_token` hash-at-rest). **Net new findings: 0C / 0H / 0M / 0L.** No new attack surface, no new auth gates, no schema migrations (new advisory-lock constant uses an unused integer ID; no DB schema change).

v0.31.13 closes the first sub-gap from the v0.31.12 data-minimisation audit â€” **G1: dormant-user expired-session accumulation in `user_sessions`**. A new background loop at `src/ion/services/session_cleanup_service.py` wraps the existing `AuthService.cleanup_expired_sessions()` helper and runs it on a configurable cadence under advisory lock `LOCK_SESSION_CLEANUP_BG = 1023` (single-leader execution across multi-worker deployments). New env vars: `ION_SESSION_CLEANUP_ENABLED` (default `true` â€” data-min is the safer default) and `ION_SESSION_CLEANUP_INTERVAL_HOURS` (default `6`, floored at 60s). Wired into `web/server.py`'s `@app.on_event("startup")` block via the same `run_locked(..., hold_until_close=True)` pattern as `LOCK_ANALYTICS_BG_LOOP` / `LOCK_TIDE_BG_SYNC` / etc. The complementary per-user cleanup at login time (`delete_expired_for_user`, `auth/service.py:140`) is unchanged and remains the primary mechanism for active users; this new loop catches the dormant-user tail â€” sessions whose owner never logs back in. ION-side findings count unchanged at 0C / 0H / 3M / 4L. SECURE_BY_DESIGN audit summary unchanged at 18 Met / 2 Mostly Met / 0 Partial / 0 Gap (P13 was already Met at v0.31.12; G1 is sub-principle defence-in-depth work). Data-minimisation audit residual gaps count drops from 5 to 4 (G2 / G3 / G4 / G5 remain â€” `audit_logs` retention env var, `security_events` retention env var, optional AI chat retention, `session_token` hash-at-rest; all tracked for v0.32+). **Net new findings: 0C / 0H / 0M / 0L.** No new attack surface, no new auth gates, no schema migrations (new advisory-lock constant uses an unused integer ID; no DB schema change).

v0.31.12 closes Secure-by-Design **P13 ("Reduce impact of compromise")** from **Mostly Met â†’ Met** by publishing `docs/DATA_MINIMISATION_AUDIT.md` â€” the formal data-minimisation audit gap that had kept P13 short of Met across audit revisions 1.0 through 1.8. The audit walks the ~100-table ION data layer (47 SQLAlchemy model files); tier-1 deep-reads `users` / `user_sessions` / `audit_logs` / `security_events` / `blocked_ips` / `analyst_notes` / `ai_chat_*` / `observables` / `ai_feedback`; catalogues 13 existing data-min controls (C1â€“C13: air-gap-first deployment, container isolation, bcrypt password storage, `closure_reason` enum, `ION_BOB_STORE_REASONING` env-var gate, append-only ledgers with sha256 chain, soft-delete pattern, per-user expired-session cleanup at login, TLP/PAP markings on observables, no-shared-secrets between integrations, service-account auth short-circuit, WeasyPrint external-URL fetcher block, CSP nonce on inline `<script>` / `<style>`); identifies 5 low-severity residual gaps tracked for v0.32+ (G1 system-wide session cleanup scheduler â€” function exists at `auth/service.py:347` with no scheduled caller; G2 `audit_logs` retention env var; G3 `security_events` retention env var; G4 optional AI chat retention; G5 `session_token` hash-at-rest). All five gaps are bounded by C1 (air-gap deployment perimeter) + C2 (container isolation) + RBAC; they classify as defence-in-depth improvements, not unresolved P13 attack surface â€” the same pattern P11's remaining 69-template migration follows. ION-side findings count unchanged at 0C / 0H / 3M / 4L; SECURE_BY_DESIGN audit summary advances from 17 Met / 3 Mostly Met / 0 Partial / 0 Gap to **18 Met / 2 Mostly Met / 0 Partial / 0 Gap**. The only remaining Mostly Met principles are P1 (single-maintainer structural limit) and P11 (CSP strict â€” template-migration backlog). **Net new findings: 0C / 0H / 0M / 0L.** No new attack surface, no permission gate changes, no schema migrations.

v0.31.11 is a docs-only release that formalises ION's acceptance of two upstream-unpatched, not-reachable image-level CVEs surfaced by Docker Scout against v0.31.10 (post `--pull --no-cache` rebuild against current `python:3.14-slim` base). **ION-side findings count unchanged: 0C / 0H / 3M / 4L** (the cumulative tally tracked in the severity table above). **Net new ION-introduced findings: 0C / 0H / 0M / 0L.** The two Medium CVEs flagged by Scout against the v0.31.10 image are **CVE-2025-45582** (`tar` 1.35+dfsg-3.1, "tar extraction path traversal family") and **CVE-2026-6732** (`libxml2` 2.12.7+dfsg+really2.9.14-2.1+deb13u2, "libxml2 parser DoS / memory-safety family"); both report **`Fixed version: not fixed`** in the Debian trixie security tracker as of 2026-05-26, meaning rebuilds against newer base images do not close them. ION's runtime-reachability analysis follows the same pattern documented for the prior `ecdsa` CVE-2024-23342 closure (v0.31.8): (a) `tar` is invoked only by `apt` during Docker build-stage layer construction, not in the runtime image's execution path; ION's web app has no Python or shell call site that invokes `tar`, and the CVE requires processing an attacker-controlled tarball â€” **not reachable in production runtime**; (b) `libxml2` is transitively present via `shared-mime-info`, which `libpango-1.0-0` and `libgdk-pixbuf-2.0-0` declare as a Recommends dep (used to look up MIME types when WeasyPrint embeds image content during PDF rendering). ION's WeasyPrint usage parses HTML / CSS via Python-level libraries (`html5lib`, `cssselect2`); the libxml2 code path is not invoked by ION's PDF-generation pipeline. WeasyPrint's external-URL fetcher has been blocked since v0.20.1, preventing user-supplied URLs from reaching XML parsing via a `<style>@import url()` or `<img src>` indirection â€” **not reachable in production runtime**. The 51 Low CVEs Scout reports for the v0.31.10 image are distributed across base-image packages (`apt`, `cairo`, `coreutils`, `expat`, `gcc-14-base`, `glibc`-related, etc.); none cluster around a single removable dependency, and none affect ION's exposed surface. They cycle in and out of the Debian security tracker as upstream maintainers post advisories and fixes; ION rebuilds against the latest `python:3.14-slim` at each release, so the Scout-reported count fluctuates with the upstream advisory pipeline. **Documented and accepted as background base-image churn.** The `Net new findings: X / Y / Z / W` line in CHANGELOG and the severity table above continue to track ION-introduced surfaces only â€” the metric customers ask about and the one ION can durably commit to; image-level Scout findings are reported separately per release in this paragraph. Recommendation for higher-assurance deployments: pull `ixion36/ion:0.31.11`, re-scan with Docker Scout or an equivalent SBOM-aware scanner against the customer's accepted-CVE policy, and (if needed) rebase against a `python:3.14-alpine` variant â€” note that alpine swap is non-trivial as `cryptography`, `lxml`-family transitive deps, and `pillow` may need `apk add build-base` toolchain to build wheels from source.

v0.31.10 closes Secure-by-Design **P15 ("Secure your code repository")** from **Partial â†’ Met** â€” the last named Partial gap. Branch protection on `main` advanced from Tier 1 to Tier 2: `required_signatures=true` enforced server-side via `gh api POST repos/ixion36-svg/ion/branches/main/protection/required_signatures` after registering a dedicated ed25519 Signing Key (`~/.ssh/id_ed25519_github.pub`) on the maintainer's GitHub account. Local git configured for SSH commit signing (`gpg.format=ssh` + `user.signingkey=~/.ssh/id_ed25519_github.pub` + `commit.gpgsign=true` + `tag.gpgsign=true` + `gpg.ssh.allowedSignersFile=~/.config/git/allowed_signers`). Committer identity switched to the GitHub noreply form (`229949365+ixion36-svg@users.noreply.github.com`) which is auto-verified by GitHub, so signatures resolve to the "Verified" badge in the GitHub UI without requiring email confirmation against the maintainer's personal inbox. The v0.31.10 release commit is the first signed commit on `main` and serves as the implicit acceptance test for the new server-side rule. Combined with the Tier 1 set (`required_linear_history=true`, `allow_force_pushes=false`, `allow_deletions=false`, `enforce_admins=false`), `main` now rejects unsigned, non-linear, and force-push commits at the GitHub edge while preserving the single-maintainer direct-push workflow; `required_pull_request_reviews` activates when a second human reviewer joins. Documentation harmonised: `docs/SECURE_BY_DESIGN.md` (P15 audit body + summary table count + revision history row 1.8), `docs/DEVELOPMENT_LIFECYCLE.md` (Â§4 NCSC cross-reference + Â§6.4 separation-of-duty bullets + Â§8 known-gaps strikethroughs), `CONTRIBUTING.md` (new Â§2.1 "Sign your commits" with copy-paste key-gen + git-config recipe). SECURE_BY_DESIGN audit summary: **17 Met / 3 Mostly Met / 0 Partial / 0 Gap** (was 16 / 3 / 1 / 0). **Net new findings: 0C / 0H / 0M / 0L.** No new attack surface, no permission gate changes, no schema migrations.

v0.31.9 advances Secure-by-Design P1 ("security is everyone's concern") from **Partial â†’ Mostly Met**. Four artifacts ship: `CONTRIBUTING.md` (codified review expectations + PR template), `CODEOWNERS` (review responsibility per path), `.claude/agents/security-reviewer.md` (focused SbD-walk agent invoked via `/agents security-reviewer` before commit, complementing the existing `release-checker` and `workbench-ledger-reviewer` agents), `.pre-commit-config.yaml` (ruff + bandit + pip-audit at the workstation, mirroring CI gates). P1 cannot reach Met without a second human reviewer â€” the principle requires multiple humans â€” but these four bring it as close as a single-maintainer project structurally can. `docs/DEVELOPMENT_LIFECYCLE.md` Â§6.4 (Separation of duty) extended with the new mitigations. Audit summary: **16 Met / 3 Mostly Met / 1 Partial / 0 Gap** (was 16 / 2 / 2 / 0). **Net new findings: 0C / 0H / 0M / 0L.**

v0.31.8 closes Secure-by-Design P17 (eliminate vulnerability classes). `python-jose[cryptography]` retired in favour of `PyJWT[crypto]>=2.8.0`. The python-jose package pulled a transitive `ecdsa` dep carrying CVE-2024-23342 (Minerva timing attack on P-256 curve, CVSS 7.4 HIGH) which has been on the `pip-audit --ignore-vuln` allowlist since v0.25.0. The vulnerable code was never reachable in ION â€” JWT validation pinned to RS256 only â€” but the dep kept appearing in external scanner reports including Docker Scout's 0.31.6 report (1 HIGH). v0.31.8 removes both the dep and the allowlist entry. `src/ion/auth/oidc.py:OIDCValidator.validate_token` migrated: imports swapped, JWKS dict now wrapped via `PyJWK.from_dict(...).key` before passing to `jwt.decode`. Same RS256 algorithm pin, same `audience` / `issuer` validation, same `verify_aud` / `verify_iss` / `verify_exp` / `verify_iat` options dict. Exception class `JWTError` swapped for PyJWT's `InvalidTokenError`. New `tests/test_v031_8_oidc_pyjwt.py` (8 cases) pins the JWT path end-to-end with a self-generated RSA keypair: happy path + tampered signature + expired + wrong audience + wrong issuer + missing kid + unknown kid + missing sub. All 8 pass. SECURE_BY_DESIGN.md P17 status moves from Mostly Met to Met. **Net new findings: 0C / 0H / 0M / 0L.**

v0.31.7 continues the P11 inline-handler retirement: training.html (119 inline handlers â€” 106 onclick + 12 onchange + 1 oninput) migrated. 115 mechanically; 4 hand-fixed (parent-class-toggle, switchTab+setTimeout chain, two JSON.stringify object-arg patterns). `tools/migrate_inline_handlers.py` hardened: detects `\\'` / `\\"` JS-source escape sequences in the captured handler value and skips them rather than producing broken output (two such spots in training.html tripped the original script). Cumulative: base.html + cases.html + alerts.html + training.html = 368 handlers migrated; 69 templates remain. Browser-verified on /training â€” switchTab dispatch confirmed via Playwright spy; 0 CSP violations, 0 JS errors. **Net new findings: 0C / 0H / 0M / 0L.** CSP unchanged.

v0.31.6 continues the P11 inline-handler retirement: alerts.html (194 inline handlers â€” 171 onclick + 20 onchange + 1 oninput + 2 onkeydown) migrated to data-attribute delegation. The bulk (185 handlers) translated mechanically via a new `tools/migrate_inline_handlers.py` Python script; 9 edge cases hand-fixed (closure-style tag-input component, FP-banner dismiss, toast remove, mitre+close chained call, switchDetailTab+querySelector). Event-delegation helper gains 4 new built-ins (`data-stop-propagation` / `data-prevent-default` without an action, `data-remove-target="id"`, `data-remove-parent`, `data-remove-closest=".sel"`) covering every common inline-handler shape encountered in alerts.html. **Net new findings: 0C / 0H / 0M / 0L.** Browser-verified end-to-end via Playwright spies â€” `sortBy` receives `["severity"]`, `quickFilterBySeverity` receives `["high"]`, `loadAlerts` fires no-arg. 0 CSP violations, 0 JS errors on /alerts (pre-existing 404 on `/api/chat/users` unrelated). CSP unchanged this release; 70 child templates still rely on `script-src-attr 'unsafe-inline'`.

v0.31.5 continues the P11 inline-handler retirement: cases.html (48 inline handlers â€” 40 onclick + 5 onchange + 3 oninput + 9 drag/drop) migrated to data-attribute delegation. Event-delegation helper extended with drag/drop events (dragstart/dragend/dragover/dragenter/dragleave/drop), a `$event` runtime sentinel for `data-args` (preserves `onclick="foo(event, ...)"` semantics), and `data-${event}-args` per-event positional override (for elements like kanban cards where `click` and `dragstart` need different args). cases.html's `cancelClosure` rewritten to find the status select by parsing `data-args` JSON rather than matching the obsolete `onchange=` attribute string â€” same v0.23.2 contract preserved. Browser-verified end-to-end: modal opens/closes, kanban card click, tab switching, all 0 CSP violations. **Net new findings: 0C / 0H / 0M / 0L.** CSP unchanged this release; 71 child templates still rely on the `script-src-attr 'unsafe-inline'` escape hatch.

v0.31.4 is a P11 follow-up release: foundation for retiring inline `onclick=` handlers via a new delegated-event helper at `src/ion/web/static/js/event-delegation.js` plus base.html migration as proof-of-pattern. base.html's seven inline handlers (notepad toggle, user-menu dropdown, appearance toggle, sign-out, mermaid `onerror`, shortcuts-overlay backdrop, shortcuts-overlay close) are now `data-click-action="..."` / `data-prevent-default` / `data-close-target="..."` / `data-close-on-self-click` / `data-script-onerror-flag="..."` driven; the helper registers single document-level listeners and dispatches by attribute. **Net new findings: 0C / 0H / 0M / 0L.** CSP is unchanged this release â€” `script-src-attr 'unsafe-inline'` / `style-src-attr 'unsafe-inline'` still permitted because the other 72 templates still use inline handlers (1,001 remaining `onclick=` plus 1,659 inline `style=""` attributes). Each child template will be migrated in subsequent releases, then `script-src-attr 'none'` and `style-src-attr 'none'` can be enforced. P11 stays Mostly Met. Browser-verified on a local SQLite server: DOM presence, programmatic clicks on user-menu / shortcuts-overlay close / shortcuts-overlay backdrop all behave correctly; 0 new CSP violations across /, /cases, /alerts.

v0.31.3 is a hardening release: **per-request CSP nonce on every inline `<script>` and `<style>` block**. The CSP `script-src` and `style-src` no longer contain `'unsafe-inline'` â€” only `'self' 'nonce-XXX'` where `XXX` is a 16-byte CSPRNG value rotated per HTTP response. CSP3's `script-src-attr` / `style-src-attr` are kept at `'unsafe-inline'` so the 1,185 inline event handlers and 1,659 inline `style=` attributes still work. CSP authority moved from `deploy/nginx/nginx.conf` to `SecurityHeadersMiddleware` in `src/ion/web/server.py` (necessary â€” nginx can't generate per-request nonces without lua). `_CSPNonceProxy` exposes the nonce as the Jinja global `{{ csp_nonce }}`. 73 templates rewritten with `nonce="{{ csp_nonce }}"` on all 155 inline script/style opening tags via a single Python regex pass. Two templates (`alerts.html`, `observables.html`) had their entire JS wrapped in `{% raw %}` â€” the opening `<script>` tag was hoisted outside that block so Jinja can interpolate the nonce. `base.html` got `<meta name="htmx-config" content='{"includeIndicatorStyles":false}'>` to stop HTMX runtime-injecting an un-nonceable `<style>` block (verified zero usage of the `.htmx-indicator` class in templates). Browser-verified on 6 pages (`/`, `/alerts`, `/cases`, `/daily-standup`, `/observables`, `/settings`) â€” **0 CSP violations**. Net new findings: 0C / 0H / 0M / 0L. Reduces (does not eliminate) the XSS attack surface â€” inline event handlers + inline style attributes remain a future-tightening target tracked in `docs/SECURE_BY_DESIGN.md` P11.

v0.31.2 is a code-quality release â€” 15 ORM filter sites across 9 service modules converted from `Column == EnumX.value` (or bare lowercase string) to the enum-instance form `Column == EnumX`, plus a new regression test pinning SQLAlchemy's actual `SQLEnum(native_enum=False)` storage + bind behaviour. **Net new findings: 0C / 0H / 0M / 0L.** No new endpoints, no schema migrations, no permission gate changes, no behaviour change. The audit was initially scoped as a bug-hunt for "silently-broken SQL filters" but the new test (`tests/test_v032_sqlenum_name_storage.py`, 10 cases) demonstrated SQLAlchemy's `Enum.bind_processor` coerces lowercase strings â†’ enum instance â†’ `.name` bind, so the ORM-side filters were never actually broken. The only path that genuinely bypasses bind coercion is raw `text()` SQL (which is what bit `seed_lab_fixtures.py:109` in v0.30.0 â€” already fixed). The 15 edits stay because the enum-instance form is more idiomatic, easier to grep for, and immune to a future SQLAlchemy version tightening `validate_strings` to True by default. `src/ion/web/api.py:_fixture_alert_dicts` additionally converts the URL-query `status` parameter to an enum via `AlertTriageStatus(status)` with a `ValueError` guard â€” defensive coding for the user-input boundary. `CLAUDE.md` "Known gotchas" rewritten with the accurate rule.

v0.31.1 is a daily-standup polish release â€” three operator-reported usability issues closed on the `/standup` page. **Net new findings: 0C / 0H / 0M / 0L.** No backend schema or API contract changes. (1) `/api/daily-standup/checks` now sets `Cache-Control: no-store, no-cache, must-revalidate` on the response; the front-end `fetch()` also passes `cache: 'no-store'`. Prevents browsers / intermediate proxies from serving a stale `critical_alerts` snapshot to the next analyst on shift. (2) Section 2's critical-alerts rule column fallback chain shortened from `rule_name â†’ title â†’ id â†’ '(unnamed)'` to `rule_name â†’ title â†’ '(rule unknown)'` so the raw ES document id can no longer appear where the rule name belongs. No new auth surface. (3) New `_check_alerts_24h()` aggregates `get_alerts(hours=24, include_closed=True, limit=5000)` by severity and status; uses the existing `alert:read` permission gate via the daily-standup endpoint; falls back to local AlertTriage counts when ES is down (severity collapses to "unknown" â€” surfaced via a source banner). `_check_case_status_counts()` adds a `by_severity_24h` aggregation on cases created in the last 24h. The previous 30-day check is kept in the orchestrator response so the pptx slide export keeps working.

v0.31.0 was a UX-only release. **Net new findings: 0C / 0H / 0M / 0L.** No backend changes, no schema migrations, no API surface changes, no permission shifts. (1) `/alerts` cases-sidebar now opens a slim case-detail slide-out panel directly on the alerts page (no navigation). Read-only sections (linked alerts, observables, notes) hit existing endpoints (`/api/elasticsearch/alerts/cases/{id}`) under the existing `alert:read` permission. Status / severity / assignee writes route through the existing `PATCH /api/elasticsearch/alerts/cases/{id}` endpoint â€” same auth, same audit trail. The closure modal triggers a PATCH with `status=closed` + the full `CaseClosureReason` enum value. (2) `/alerts` legacy quick-action strips in `renderCaseManagementModal` and `renderCaseTab` expanded from 3 buttons (Benign / Escalated / False Positive â€” a lossy subset) to 6 buttons matching the `CaseClosureReason` enum exactly. `closeCaseWithAlerts` updated to pass closure-reason values straight through; legacy aliases retained as no-op backward-compat. (3) `/alerts` page-load default filter switched from `Active (Open + Ack)` to `Open Only`. Single-line `<option selected>` move; no permission or auth change. (4) `/cases` slide-out panel sectioned into 5 tabs (Overview / Alerts / Observables / Timeline / Notes) for cases with 100+ linked alerts. Active tab persisted across panel re-renders via module-level state; reset on close. Pure client-side display reorganisation â€” no backend touched. (5) `cases.html` init handler for `?selected=<case_number>` deep-link query parameter, completing the v0.30.0 deep-link redirect chain from `_observable_link` / `/cases/{row_id}` / `/alerts` slim panel "Open full case view" link.

v0.30.1 was a bug-fix patch closing four issues surfaced during the v0.30.0 Â§3.4.8 acceptance walk. **Net new findings: 0C / 0H / 0M / 0L.** No new attack surface, no permission gate changes, no schema migrations. (1) `mitre_heatmap_service` SQL patched to avoid the Postgres `json <> json` operator that doesn't exist â€” the defensive `!= 'null'::json` filter never compiled and 500'd the heatmap deep-link from the Threat Intel page and CyAB; cast to text comparison restores the intended behaviour without changing the filter semantics. Read-only query; no input goes near user-controlled data. (2) Kibana case-status sync hardened: ION-CLOSED is now treated as terminal â€” `sync_case_status_from_kibana` refuses to demote it, and the bidirectional gate eager-propagates `closed` in either direction. The pre-fix flap (Kanban-close â†’ 60s sync loop fires before IONâ†’Kibana push completes â†’ reverse-sync flips ION back to acknowledged) is closed; the reverse-direction Kibanaâ†’ION close also now lands eagerly regardless of timestamp gate. No new endpoints, no new auth surface. (3) `pcap_analysis_service` now also writes Observable rows for the IPs / DNS queries / TLS SNIs / HTTP hosts discovered in the PCAP, linking them to the case via `ObservableService.get_or_create` + `link_to_case`. Same trust boundary as the existing PCAP analysis (Arkime credentials, PCAP download, dpkt parsing); the observable values come from already-trusted Arkime session metadata and dpkt-parsed PCAP frames, not user-controlled input. (4) `Reference` sibling-tab strip reordered (Notes â†’ last) â€” pure cosmetic template change, no auth surface.

v0.30.0 was a mixed-plate ship: lab fixture system end-to-end repair (4 compounding bugs that kept graded labs broken since v0.21.0 through v0.29.1 â€” 9 minor releases), `SECURITY.md` vulnerability disclosure policy at repo root (closes SDLC Â§8 public-disclosure-channel gap; NCSC Principle 5 status upgraded **Partial â†’ Met**), and `/health` + `/health/deep` consolidation via a shared `_health_core()` helper (closes audit Amend C). **Net new findings: 0C / 0H / 0M / 0L.** The lab fixture repair touches three operationally-distinct surfaces â€” the `labs_api` router (decorator prefix correction; no permission change â€” `get_current_user` + `UserEnrolment` gate already in place), the Docker image surface (`seed_lab_fixtures.py` now COPY'd + invoked by `seed_all.py` orchestrator; the seed inserts deterministic, auth-trail-bearing rows into `alert_triage` + `alert_cases` with `es_alert_id LIKE 'lab-fixture-%'` so legitimate ES alerts can never collide), and the `/api/elasticsearch/alerts` list endpoint (extends the response with `alert_triage` rows matching the fixture prefix â€” the `alert:read` permission already gates this endpoint; no permission shift, and the merge respects the caller's `status` / `severity` / `include_closed` filters). The fixture-row timestamp is overridden to "now" at serialise-time so fixtures survive client-side time filters; the underlying DB row keeps its deterministic `2026-01-01` value (air-gap reproducibility). `is_lab_fixture=True` flag on the response dict drives an amber "Lab fixture" badge in `alerts.html` so analysts can never mistake a training fixture for a real alert. No untrusted input is involved: all fixture payload fields are author-controlled in the committed seed script. `SECURITY.md` documents two private reporting channels (GitHub Security Advisory preferred, maintainer email fallback) with severity-aligned fix SLAs mirroring Â§3.5.4. `/health` consolidation is structural only â€” both endpoints continue to return the same fields with the same permission gate (`/health` public, `/health/deep` authenticated per v0.19.17), now sourcing the shared version + database-type block from `_health_core()`.

v0.29.1 was a bug-fix patch: the PCAP auto-analysis runner now falls back to `find_sessions_by_ip` when Arkime's `community_id` index misses, matching the behaviour of the manual `/api/arkime/.../preview` button. Same Arkime credentials, same auth, same `ION_ARKIME_PCAP_TIMEOUT_S` budget â€” only the search-path waterfall changed (community_id â†’ IP+timestamp). The new `_extract_ip_and_timestamp` helper reads from already-trusted alert raw_data; no new attack surface, no new permission gate. **Net new findings: 0C / 0H / 0M / 0L.**

v0.29.0 continues the nav-only consolidation work from v0.28.0: Operations dropdown 9â†’5 and Knowledge dropdown 9â†’3, all via the same shared sibling-tab-strip pattern (`_nav_tabs.html`, renamed from `_eng_tabs.html`). **No backend changes, no API changes, no permission shifts, no schema migrations.** Every page involved keeps its existing route, permission gate, and template logic. The shared Jinja partial renders cyan pill-style tabs from a `tabs` array passed in by the parent template; all label and href values are author-controlled. **Net new findings: 0C / 0H / 0M / 0L.**

v0.28.0 is a nav-only release: the Engineering dropdown collapses 9 items â†’ 5 via in-page sibling-tab strips. **No backend changes, no API changes, no schema migrations, no permission shifts.** Every page involved keeps its existing route, permission gate (`require_page_permission("security:read")` for Topology, `require_page_auth` for Network Map + Data Flow, `require_page_permission("alert:read")` for Log Sources + System Analytics), and template logic. The new shared Jinja partial `_eng_tabs.html` renders a cyan pill-style tab strip from a passed-in `tabs` array; no untrusted input flows into the template, all `tabs[].label` and `tabs[].href` values are author-controlled. **Net new findings: 0C / 0H / 0M / 0L.**

v0.27.0 is the Threat Intel page consolidation + enhancement release. Three pages collapse into one (`/threat-landscape` + `/attack-stories` deleted, both 302-redirect to `/threat-intel`); the Threat Hunting subsystem is removed entirely (page + API + service + model + `threat_hunts` table dropped via idempotent migration); three new enhancement features layered on the unified page (actor deep-dive profile, IOC sightings sparkline, MITRE technique click-to-drill). **Net new findings: 0C / 0H / 0M / 0L.** All new endpoints are gated by the existing `observable:read` permission (matches the read-only nature of the surface). Three new database-touching endpoints (`/unified-search`, `/recently-active`, `/ioc-sightings`) use parameterised SQLAlchemy queries with bounded row scans (5000-row cap on aggregations, 25-row cap on case scans); no SQL injection surface. The new actor profile page deep-link (`/threat-intel/actors/{id}`) takes the OpenCTI entity id verbatim and passes it as a path parameter to OpenCTI's GraphQL query â€” same pattern the existing `/api/threat-intel/actors/{id}` endpoint has used since v0.10.x, no new escape concern. The MITRE technique drill-down endpoint validates the technique id with the existing `normalize_technique_id` regex before querying. Defence-in-depth improvement: the Threat Hunting subsystem removal eliminates 332 LOC of API surface + 1 DB table from the production image; the half-built CRUD form was an unused write-path risk.

v0.26.1 is a bug-fix patch closing two release-blockers surfaced during the v0.26.0 Â§3.4.8 acceptance walk-through. The ticker service runtime (`src/ion/services/ticker_service.py` + `web/ticker_api.py` + `templates/tickers.html`) is **removed** â€” the background loop was crashing every tick on an enum-case mismatch and its auto-flagging design conflicted with the v0.23.x investigation-queue ownership model. The DB table + ORM model are kept dormant so legacy rows remain readable via the wallboard panel. The bob_eval harness page (`/bob-eval`) is restored â€” the Jinja `TemplateResponse` call was using the legacy positional signature that modern Starlette interprets as `(request=name, name=context_dict)` and crashes downstream. Rewritten to the kwarg form matching every other route in the codebase. **Net new findings: 0C / 0H / 0M / 0L.** No new attack surface â€” the removed ticker writes are gone (defence-in-depth improvement: one fewer DB-write path); the bob_eval fix unblocks an existing permission-gated page without changing its auth model. The four lab-fixture-system bugs found in the same walk are scoped as a v0.27.0 bundle.

v0.26.0 is a mixed-plate ship: adaptive lab grading session 4 (pass-threshold enforcement â†’ `UserLessonProgress.FAILED` when score < `Course.pass_threshold` + new lab history endpoint + history subpanel on lesson.html), Software Bill of Materials (SBOM) generated via `syft 1.18.1` at Docker build and shipped at `/app/sbom.spdx.json` (closes SDLC Â§8 SBOM gap), and ruff red CI closed (line-length widened 120 â†’ 200, codebase-wide ignores added for deliberate-style rules, per-file ignores for SQLAlchemy ORM forward-references and content-heavy data modules; `ruff check src/` now returns 0 errors). **Net new findings: 0C / 0H / 0M / 0L.** No new attack surface or permission gate changes. The new lab-history endpoint is auth-scoped to the calling user's own enrolment â€” pinned by `tests/test_v026_lab_history.py::test_other_users_sessions_not_returned`. The SBOM is read-only data baked into the image at build time; deployers extract it via `docker cp` for supplier-assurance auditing without exposing any runtime data. v0.25.1 is a bug-fix patch on top of v0.25.0. Closes three issues in the v0.16.0 PCAP auto-analysis wiring that combined to make the feature never fire on multi-alert case creation: the v0.16.0 code only read `ctx.raw_data` for `community_id` extraction (multi-select case create from the alerts list has empty raw_data per alert because the list endpoint sends `include_raw=False`); a Python operator-precedence bug in the node-hint extraction dropped top-level `arkime_node` values when no nested `arkime` dict was present; the runner took a single `alert_node_hint` for all flows even when alerts in the same case came from different Arkime capture nodes. **Net new findings: 0C / 0H / 0M / 0L.** No new attack surface, no permission gate changes; the PCAP analysis surface itself (Arkime credentials, PCAP download, dpkt parsing, Note write attributed to Bob) was already in place since v0.16.0 â€” this patch just makes it actually fire. The new ES fallback path uses `ElasticsearchService.get_alerts_by_ids` which is the same path used by other case-create features (observable enrichment, case-similarity); it does not expose ES data to anyone who didn't already have access via the alerts page itself. v0.25.0 is a mixed-plate ship: adaptive lab grading session 3 (two new audit-event surfaces `observable_linked` and `case_closed`, two new grader criterion kinds `observable_created` and `case_closed_with_reason`, four lab rubric backfills), Software Composition Analysis added to CI via pip-audit (closes SDLC Â§8 SCA gap), and the backlog file rename cleanup. Net new findings: 0C / 0H / 0M / 0L. The two new audit events close two more pre-existing audit-trail gaps (observable creation/linking and case closure were not in `audit_logs` before â€” see v0.25.0 Delta below). The pip-audit job documents one explicit `--ignore-vuln` (CVE-2024-23342, ECDSA timing side-channel in transitive `ecdsa` package; not reachable in ION's RS256-only OIDC path). v0.24.0 was the previous mixed-plate ship: adaptive lab grading session 2 (`alert_linked` audit, `linked_to_case` kind), a CI pipeline that closes the largest SDLC Â§8 gap (continuous security testing via bandit + pytest + ruff), and the v0.22.0 carry-over TIDE env-var fallback cleanup.

---

## v0.25.0 Delta (2026-05-11)

**Net change vs v0.24.0:** +0 findings. Two new audit-event surfaces (`observable_linked`, `case_closed`), two new grader criterion kinds, one new CI gate (`pip-audit`), and one explicit per-CVE allowlist. The two new audit events also close two pre-existing audit-trail gaps: prior to v0.25.0, both observable-link creation (via the extract endpoints or the case-create extraction path) AND case closures (the `OPENâ†’CLOSED` transition through PATCH `update_case`) were mutations with **no `audit_logs` row**. That's now fixed, materially improving the case-lifecycle audit trail without introducing new attack surface.

### New Surface 1: `observable_linked` audit event

**Files:** `src/ion/web/observable_api.py` at `extract_from_alert` (line 926) and `extract_from_case` (line 947); `src/ion/web/api.py` in `create_case` immediately after the `enrich_and_link_observables_for_case` + fallback extract pair.

Each call site snapshots `max(ObservableLink.id)` before the service call, then emits one audit row per new `ObservableLink.id > snapshot` after. `resource_type='observable'`, `resource_id=link.observable_id`, `details={"observable_id", "observable_type", "link_type", "entity_id", "context"}`. Pre-existing links (re-extracting an alert that already has its observables linked) produce zero audit rows because the snapshot filter excludes them. All writes wrapped in try/except (best-effort; an audit failure cannot block the API response).

**Information-flow:** the event reveals nothing the calling user did not already know â€” they just created the link by calling the API. No new data is exposed to anyone reading the audit log who did not already have access to the underlying observable and entity.

### New Surface 2: `case_closed` audit event

**File:** `src/ion/web/api.py` at `update_case` immediately after `case.closed_at = datetime.utcnow()` (line 5285+) and before the AIFeedback capture.

Fires on every real `OPENâ†’CLOSED` transition. The guard at the top of the close block (`new_status == "closed" and old_status != "closed"`) ensures no-op re-PATCH of an already-closed case does not write a second audit row â€” pinned by `tests/test_v025_audit_events.py::test_subsequent_non_close_patch_does_not_write_extra_audit`. `resource_type='alert_case'`, `resource_id=case.id`, `details={"case_id", "case_number", "closure_reason", "closure_notes"}`.

### New Surface 3: `observable_created` + `case_closed_with_reason` grader criterion kinds

**File:** `src/ion/services/lab_grading_service.py`.

Both evaluators read `audit_logs` rows scoped by `user_id` and `started_at`. Neither evaluator scopes by `lab_session_fixtures` (unlike `viewed_alert` and `linked_to_case`) â€” they grade "did the learner perform action X during the session window", not "did they perform action X tied to a specific seeded fixture". The IN-clause patterns from the prior kinds aren't needed here; instead the queries use a single `action=...` predicate and stream the matching rows, parsing `details` JSON in Python for fine-grained filtering (`types` filter for `observable_created`; `required_reasons` set membership for `case_closed_with_reason`). No untrusted input flows into either query.

### New Surface 4: `pip-audit` CI gate

**File:** `.github/workflows/test.yml`.

The 4th parallel job runs `pip-audit --vulnerability-service osv --strict --ignore-vuln CVE-2024-23342` against the project's resolved dependency tree. The `--strict` flag fails the build on any vulnerability finding not explicitly allowlisted; the one allowlisted CVE has a detailed justification block in the workflow file referencing `src/ion/auth/oidc.py:186` (which pins `algorithms=["RS256"]`, so the ECDSA-side-channel vuln is not reachable). Future findings go through: (a) attempt dependency bump in `pyproject.toml`, (b) if infeasible, add `--ignore-vuln` with justification, (c) escalate to security review for HIGH/CRITICAL that can neither be fixed nor reasonably ignored.

The audit-trail gap closures here (one for observable lifecycle, one for case lifecycle) bring ION's `audit_logs` table to symmetric coverage of the alert / case / observable mutations that matter for SOC compliance. The next equivalent gap is annotation edits (deferred from v0.22.0 â€” `annotation_edits` history table is in `_backlog_v0_25.md`).

---

## v0.24.0 Delta (2026-05-11)

**Net change vs v0.23.2:** +0 findings. One new audit-event surface (`alert_linked`), one new grader criterion kind (`linked_to_case`), one new CI pipeline closing the largest SDLC Â§8 gap, one cleanup. The new audit event also closes a tiny pre-existing audit-trail gap: prior to v0.24.0, linking an alert to a case (via either the case-create loop or PUT-triage path) was a mutation with **no audit_logs row**. That's now fixed, which materially improves the case-ownership audit trail without introducing a new attack surface.

### New Surface 1: `alert_linked` audit event

**Files:** `src/ion/web/api.py` at the case-create loop (~line 4404) and the PUT triage path (~line 6539).

The event fires on every real `AlertTriage.case_id` transition, with `action='alert_linked'`, `resource_type='alert_triage'`, `resource_id=triage.id`, and `details={"case_id": <int>, "es_alert_id": "<es-id>"}` as JSON. Both write sites wrap the audit row in a try/except so an audit failure cannot break the case-link operation itself. The PUT triage path also guards against no-op re-PATCHes (the `case_id` value is compared to the existing one before the audit row fires) so re-saving an already-linked triage doesn't generate audit noise.

**Information-flow:** the event reveals nothing the calling user did not already know â€” they just made the link. No new data is exposed to anyone reading the audit log who did not already have access to the underlying alert and case.

### New Surface 2: `linked_to_case` grader criterion kind

**File:** `src/ion/services/lab_grading_service.py`.

The evaluator reads `audit_logs` rows for the session's materialised alert_triage ids, scoped by `user_id` and `started_at` (the same scope as the v0.23.0 `viewed_alert` evaluator), and groups by the target `case_id` parsed out of the JSON `details` column. Match when `min_alerts` (default 2) distinct materialised alerts converge on a single case. The IN clause uses dynamic parameter placeholders bound from `lab_session_fixtures` rows â€” no untrusted data flows into the query.

### New Surface 3: GitHub Actions CI pipeline

**File:** `.github/workflows/test.yml`.

Three parallel jobs (pytest, ruff, bandit) on every push to `main`/`dev` and every PR to `main`. Bandit skips are documented in the workflow file and reflect ION's existing threat model (allow-listed CLI invocations, allow-listed raw migration SQL, test asserts). No secrets are exposed by the workflow; no third-party actions outside `actions/checkout` and `actions/setup-python` are used. The workflow itself is auditable in git history; modifying it requires a push to `main` like any other change.

### Removed Surface: `ION_TIDE_SYNC_INTERVAL` deprecation fallback

**File:** `src/ion/services/tide_sync_service.py`.

The v0.22.0â†’v0.23.x one-cycle deprecation fallback that logged a warning and accepted the old env-var name was removed in v0.24.0. Operators still using the old name must rename to `ION_TIDE_SYNC_INTERVAL_S`. The deprecation warning has been live since v0.22.0 across three minor versions, so the renaming window was generous.

---

## v0.23.2 Delta (2026-05-11)

**Net change vs v0.23.1:** +0 findings. Pure JS / template fix on the case-detail panel close flow; no server-side change. The backend PATCH path was already correct and is now pinned by a regression test (`tests/test_v023_2_case_close.py`, 4 cases) so the next time this bug recurs we'll know it's the frontend half.

No new attack surface, no permission gate changes, no schema migrations.

---

## v0.23.1 Delta (2026-05-11)

**Net change vs v0.23.0:** +0 findings. Three new endpoint surfaces, one new auth-gated table, one removed auto-write surface. The removed surface is a small information-flow + ownership improvement (not a counted closure).

### New Surface 1: `system_runtime_flags` table

**File:** `src/ion/storage/database.py` (migration), `src/ion/services/system_flags.py`.

A key/value table with `key VARCHAR(64) PK`, `value VARCHAR(255)`, `updated_at`, `updated_by_id` (FK users). Only read/written by the new queue-control endpoints (each `alert:triage` permission-gated) and the investigation sweep loop. No untrusted input: the only key in use (`investigation_loop_paused`) is hard-coded; the only value is `"true"` (written by the pause endpoint). Even if a future caller wrote unsanitised key/value pairs, the table has no SQL injection path because every read/write uses parameterised queries. **PASS â€” no untrusted data flow into this surface.**

### New Surface 2: queue-control endpoints

**File:** `src/ion/web/investigation_api.py`.

Five new routes, all permission-gated:
- `GET /api/investigate/loop/status` â€” `alert:read`
- `POST /api/investigate/loop/pause` â€” `alert:triage`
- `POST /api/investigate/loop/resume` â€” `alert:triage`
- `POST /api/investigate/jobs/cancel-pending` â€” `alert:triage`
- `POST /api/investigate/jobs/{inv_id}/cancel` â€” `alert:triage`

`alert:triage` is the correct gate â€” pausing the sweep loop and cancelling investigations are triage-tier actions, equivalent in privilege to manually triggering a sweep (which already uses `alert:triage`). The bulk-cancel endpoint writes `status='cancelled'` only on rows where `status='pending'`; running rows are left alone. The per-row endpoint 404s on missing ids and returns `{cancelled_count: 0}` on terminal rows (no error path leaks row existence). **PASS â€” gate is correct, no privilege escalation, no information disclosure beyond what `alert:read` already exposes via the existing `/api/investigate/jobs` listing.**

### New Surface 3: `POST /api/elasticsearch/alerts/cases/{case_id}/bob-analysis`

**File:** `src/ion/web/bob_analysis_api.py`.

Generates an on-demand case analysis. Permission: `case:read`. The endpoint reads case + linked triages + investigations + observables + similar closed cases (via the existing pgvector helper, same permission boundary as `/api/elasticsearch/alerts/cases/{id}/similar`) and a best-effort raw ES alert fetch. The data assembled into the LLM prompt is data the calling user can already see via existing endpoints; the endpoint adds no new information-flow boundary. The response is **not persisted** â€” the analyst clicks "Save as note" separately, which goes through the existing `POST /api/elasticsearch/alerts/cases/{id}/notes` endpoint (gated on `case:update`) and authors the resulting Note under the analyst's own user id, not Bob's system user. **PASS â€” read-only generation + analyst-authored persistence; no auto-write under any user's name without explicit consent.**

### Removed Surface: investigation_service._post_to_case auto-comment

**File:** `src/ion/services/investigation_service.py`.

Previously this method wrote a `Note` row (authored by `User.username == 'admin'` via `_get_system_user_id`) AND posted a Kibana Cases comment on every investigation completion. Removed in v0.23.1. The remaining side-effects (IOC merge, OPENâ†’ACKNOWLEDGED status transitions, ES workflow-status push) are kept because they do not impersonate the analyst â€” they update structured fields, not free-text narrative on behalf of a human author. The information-flow improvement: Bob no longer writes content attributed to the system user on cases owned by other users, which removes a small but real ambiguity in the case audit trail.

---

## v0.23.0 Delta (2026-05-11)

**Net change vs v0.22.1:** +0 findings. One new feature surface (adaptive lab grading) with three new tables, one new audit event, and refactored launch/complete endpoints.

### New Surface 1: `lab_sessions` / `lab_rubrics` / `lab_criterion_results` tables

**Files:** `src/ion/storage/database.py` (migrations), `src/ion/services/lab_session_service.py`, `src/ion/services/lab_grading_service.py`.

Three tables comprise the grading data model. `lab_sessions` is a parent row per (enrollment, lesson, attempt); `lab_rubrics` carries per-lesson criteria with a kind-string discriminator and a JSONB config; `lab_criterion_results` is the per-(session, rubric) audit trail. All three use `ON DELETE CASCADE` on FKs so user/course/lesson deletion cleans up grading data correctly. The `uq_criterion_result` unique constraint on `(session_id, rubric_id)` enforces idempotent re-grading at the schema layer. **PASS â€” no untrusted input written to any of these tables; criterion_config is operator-authored at seed time and read by the dispatch table only.**

### New Surface 2: `alert_view` audit event on GET /elasticsearch/alerts/{id}/triage

**File:** `src/ion/web/api.py`.

The triage-read endpoint now writes one `audit_logs` row per call with `action='alert_view'`, `resource_type='alert_triage'`, and `resource_id = triage.id` when the triage row exists. The write is in a try/except â€” failure is logged and swallowed so audit writes never break the read path. Audit-log throughput already absorbs higher-volume events (every triage update, every alert close, etc.); the additive read event is bounded by analyst-hours and well within the existing capacity envelope. **PASS â€” no PII expansion (the existing audit log already carries user_id + resource_id; the new row adds nothing not already auditable).**

### New Surface 3: LabGradingService â€” audit-log-driven evaluator

**File:** `src/ion/services/lab_grading_service.py`.

The grader's `viewed_alert` evaluator runs the following parameterised query against `audit_logs`:
```
SELECT id FROM audit_logs
WHERE action = 'alert_view'
  AND resource_type = 'alert_triage'
  AND resource_id IN (<session's materialised alert_triage ids>)
  AND user_id = :uid
  AND timestamp >= :since
ORDER BY id ASC LIMIT 1
```
The IN clause uses dynamic parameter placeholders (`:id_0, :id_1, â€¦`) bound from `lab_session_fixtures` rows scoped to the session, not from user input. The `user_id` and `since` bind values come from the session's enrollment row and `lab_sessions.started_at`, both server-controlled. **PASS â€” no SQL injection vector; cross-learner snooping is blocked by the `user_id = :uid` AND `resource_id IN (session's own materialised ids)` double-filter (a learner's audit_logs row matches only on their own seeded fixtures because each enrollment seeds distinct rows).**

### New Surface 4: `/api/courses/{slug}/lessons/{lesson_id}/lab/{launch,complete}` response shape

**File:** `src/ion/web/labs_api.py`.

Both endpoints gain new response fields (`session_id` on both; `score`, `points_earned`, `points_max`, `criteria` on complete). The criteria list contains rubric metadata (kind, matched, points) â€” operator-authored content, no PII. Existing fields preserved. **PASS â€” additive response shape; downstream consumers (lesson.html, tests) gracefully tolerate missing fields.**

### Known non-finding: grade-snipe by direct API call

The `alert_view` audit event fires whenever a learner GETs the triage endpoint, regardless of whether they used the UI. A learner with `alert:read` could call the endpoint directly to trigger the audit row without actually reading the rendered detail panel. This is by design â€” the criterion is "viewed the alert" defined as "issued an alert-read request", which a CLI/curl invocation satisfies. Pedagogically this is acceptable because the rubric measures access, not comprehension; comprehension is measured by the lab's verification questions (the existing quiz machinery on the same lesson). Documented here to make the threat-model boundary explicit rather than fixed.

### Known non-finding: unbounded attempt count

`lab_sessions.attempt_number` increments without cap. A learner can launch/complete-and-fail/launch repeatedly until the rubric matches. This is a pedagogy choice (re-attempts are encouraged for skill drill), not a security boundary. Future versions may add per-course attempt limits if instructors request them; the schema already supports it via the `attempt_number` column.

---

## v0.22.1 Delta (2026-05-11)

**Net change vs v0.22.0-rc:** âˆ’2 Low (L5, L6 closed). Three open questions (OQ4, OQ5, OQ6) resolved with rationale below.

### CLOSED: L5 â€” `reasoning_text` in samples serialisation
**File:** `src/ion/web/bob_eval_api.py`
`get_run_samples` now reads `ION_BOB_STORE_REASONING` at request time and strips `reasoning_text` from each sample dict when the flag is false. Rows that were persisted while the flag was true stop leaking via the samples API immediately on flag disable; no DB back-fill required. `BobEvalRunSample.reasoning_text` is the only `reasoning_text` field exposed through any `to_dict()` path â€” `Investigation.reasoning_text` is not serialised by any endpoint. Regression tests: `tests/integration/test_bob_eval.py::TestReasoningTextResponseGate` (3 cases).

### CLOSED: L6 â€” `confidence_threshold_override` permission-tier bypass
**File:** `src/ion/web/alert_prompt_api.py`
The v0.21.1 gate only fired when the incoming value was non-null. The Alert Prompts edit UI always emitted the field in PUT payloads (always-on `confidence_threshold_override` key in the JSON body), so a user with only `playbook:update` could send `{"confidence_threshold_override": null, â€¦}` to clear a system-tier strict threshold (reverting it to the env-default). `_check_confidence_threshold_permission` now takes the Pydantic update model and the current stored value, uses `model_fields_set` to distinguish field-omitted from explicit-null, and treats any change â€” including explicit-null-clearing-non-null â€” as requiring `system:settings`. The UI hides the threshold form-row for users without `system:settings` (via `/api/auth/me` permissions check) and omits the field from the payload entirely; backend gate is the defence-in-depth authority. Regression tests: `tests/integration/test_v021_fixes.py::TestConfidenceThresholdPermission` (7 cases).

### RESOLVED: OQ4 â€” `alert:read` is the correct gate for `/api/cyab/attack-heatmap`
The heatmap exposes per-technique alert-case and pin counts aggregated from `AlertCase`, `AlertTriage`, `CaseEvidencePin`, and `ForensicCasePin` rows. Users with `alert:read` already have access to all of those rows directly via the alert list, triage view, and case views â€” the heatmap is a per-technique aggregation of data they are already authorised to see. No privilege escalation. `alert:read` is confirmed as the right minimum gate.

### RESOLVED: OQ5 â€” heatmap smoke-test backend coverage
**File:** `tests/test_mitre_heatmap.py`
The smoke suite previously hard-coded SQLite, leaving the Postgres LATERAL-join service path untested. The `db_engine` fixture now honours `ION_TEST_DATABASE_URL` when set, falling back to ephemeral SQLite. Operators with a Postgres instance can exercise the LATERAL path locally with:
```
ION_TEST_DATABASE_URL=postgresql://user:pass@host/dbname pytest tests/test_mitre_heatmap.py
```
CI default remains SQLite (Python-side unnesting path); the Postgres path is exercised at deploy/integration time and now also reproducible locally.

### RESOLVED: OQ6 â€” `timeline_ts` timezone convention
`alert_case_annotations.timeline_ts` and `forensic_case_annotations.timeline_ts` are stored as UTC-naive `DateTime`, matching the `CaseEvidenceLedger.timestamp` convention used across the project. The Workbench JS treats these as UTC for display, consistent with all other timestamp surfaces. Cross-region deployments do not currently require tz-aware storage; if that changes, the migration would span both annotation tables AND the ledger to keep ordering deterministic.

---

## Fixed Since v0.9.43

The following findings from the v0.9.43 assessment and items from the net-new surface list have been verified closed in v0.9.44â€“v0.20.0:

### FIXED: SSTI (Critical) â€” v0.3.0
Template engine uses `SandboxedEnvironment`. Still confirmed.

### FIXED: Open Redirect on Login â€” v0.9.34
Still confirmed; login redirect validates relative path, no `//` or `://`.

### FIXED: ES System Index Access â€” v0.9.34
Still confirmed; Discover blocks `.kibana`, `.security`, etc.

### FIXED: Kibana Multi-Alert Attachment â€” v0.9.34
Still confirmed.

### FIXED: OIDC Callback PII Logging â€” v0.19.17
`src/ion/auth/oidc.py` line 317: `logger.info` now logs only `user.username`, not `token_data.email`. Confirmed clean at INFO level; email appears only in DEBUG-level statements which are suppressed in production.

### FIXED: `GET /health/deep` unauthenticated â€” v0.19.17
`src/ion/web/api.py` line 2288: `current_user: User = Depends(get_current_user)` confirmed present. Deep-health probes are no longer reachable without a valid session.

### FIXED: `GET /canaries/types` unauthenticated â€” v0.19.17
`src/ion/web/canary_api.py` line 66: `dependencies=[Depends(require_permission("alert:read"))]` confirmed. Canary type enumeration now requires authentication.

### FIXED: `POST /change-log` permission upgraded â€” v0.19.17
`src/ion/web/change_log_api.py` line 47: `require_permission("system:settings")` confirmed. Read-only analysts can no longer inject change records.

### FIXED: `GET /api/wallboard/snapshot` permission upgraded â€” v0.19.17
`src/ion/web/wallboard_api.py`: wallboard page uses `require_page_permission("alert:read")`. Snapshot endpoint confirmed gated.

### FIXED: `POST /api/ticker/{id}/dismiss` â€” critical-severity tickers now dismissable â€” v0.19.13
`src/ion/web/ticker_api.py` line 119: `dependencies=[Depends(require_any_permission(_READ))]`. Per-user dismiss is scoped to the calling user; peer-analyst visibility is preserved because critical tickers also auto-resolve when the underlying alert is cased. Risk accepted per inline comment.

### FIXED: SSRF on URL-config save (14 integration sites) â€” v0.19.18
`src/ion/web/admin_api.py`: `_ssrf_safe_url()` added at line 172, wrapping `validate_integration_url()` from `src/ion/core/url_validator.py`. Applied to all 14 integration URL save paths (ES, Kibana, GitLab, OpenCTI, DFIR-IRIS, TIDE, Arkime, Ollama, plus the wizard `/save` endpoint). Private IP ranges, link-local, cloud metadata (169.254.x, GCP `metadata.google.internal`), and obfuscated decimal/hex IPs are all blocked. Docker service hostnames (alphanumeric with hyphens, no IP) are exempted â€” acceptable for containerised deployments. Full re-audit confirms M2 (SIEM webhook SSRF â€” see below) is the only remaining open gap.

### FIXED: File upload size limit â€” v0.9.34 / v0.19.18
`src/ion/core/uploads.py:read_upload_capped` (streaming cap) applied to `/api/translator/translate-file`, `/api/translator/extract`, and `/api/pcap/analyze` in v0.19.18. Sizes are 50 MB (translator), 100 MB (PCAP) respectively, enforced before the full buffer is allocated, eliminating the OOM vector present in the pre-v0.19.18 unbuffered `await file.read()` pattern.

### FIXED: `ION_AUTO_PLAYBOOK_ENABLED` kill switch â€” v0.20.0
`src/ion/web/api.py` lines 64â€“66: defaults `false`. When off, matched playbooks are surfaced for analyst click; no automatic execution. Eliminates surprise timeline entries from adversary-manipulated alert patterns.

### FIXED: Bob system prompt trust boundary â€” v0.19.19
`src/ion/services/alert_prompt_service.py` ~line 2884: alert fields are wrapped in `<input_data>...</input_data>` tags in the user turn. The system prompt explicitly instructs the model to treat all bytes inside those tags as hostile-controlled data, never follow instructions embedded in them, and not let alert content change the verdict classification. The trust boundary is as strong as a prompt-level control can be. Residual risk (prompt injection bypass in future model versions) is low given the current guard is thorough.

---

## Current Findings

### Medium

**M1: CSP `unsafe-inline` for scripts (carried forward)**

- **Evidence:** `src/ion/web/server.py` lines 194â€“205 â€” `script-src 'self' 'unsafe-inline'`.
- **Status:** Open â€” unchanged from v0.9.43.
- **Mitigation in place:** DOMPurify sanitises all user-supplied HTML before insertion. All tested XSS vectors bounce on DOMPurify.
- **Residual risk:** A DOMPurify bypass (historically rare, patched promptly upstream) could execute arbitrary script in analyst sessions. Severity remains Medium because of the mitigating control.
- **Recommended fix:** Migrate all inline `onclick` handlers to `addEventListener` calls and remove `unsafe-inline` from `script-src`. High refactoring effort; schedule as a hardening sprint, not a blocker.

---

**M2: SIEM webhook export lacks SSRF validation on call-time URLs (carried forward, partially mitigated)**

- **Evidence:** `src/ion/services/siem_export.py` lines 247â€“277 â€” `export_to_webhook(url=...)` and `export_to_splunk_hec(url=...)` accept the URL from config at call time. Neither function calls `validate_url()` or `validate_integration_url()` before the outbound HTTP request.
- **Status:** Partially open. The v0.19.18 SSRF guard on the config-save path (`_ssrf_safe_url`) prevents a malicious URL from being persisted via the admin UI. However, the guard is not applied at the point of use in `siem_export.py`. A URL injected via direct DB manipulation or environment override would bypass it.
- **Threat in scope:** The threat model includes a malicious internal user. A DBA-level insider could set the DB row directly and trigger an outbound probe to an internal service. For the primary threat actor (UI-only access), v0.19.18 is sufficient.
- **Recommended fix:** Add `validate_integration_url(url, "siem_webhook")` at the top of `export_to_webhook` and `export_to_splunk_hec`, raising `ValueError` on failure. One-line fix per function.

---

**M3: WeasyPrint SSRF via lesson PDF export â€” `GET /api/courses/{slug}/lessons/{lesson_id}/export.pdf` (new)**

- **Evidence:** `src/ion/services/pdf_export_service.py` line 304: `HTML(string=full_html).write_pdf()`. WeasyPrint's default configuration resolves `<img src="...">` and `<link href="...">` tags at render time using the system HTTP client. `render_lesson_pdf()` converts `lesson.content_md` to HTML via `markdown.markdown()` without sanitising or stripping external resource references. If a lesson's `content_md` contains `![x](http://169.254.169.254/latest/meta-data/)`, WeasyPrint will issue an HTTP GET to that URL during PDF generation.
- **Exploit prerequisites:** The attacker must have `playbook:create` or `playbook:update` permission (course author role) to insert a malicious `<img>` URL into a lesson's `content_md`. Any authenticated user with `playbook:update` can then trigger the PDF export GET. The malicious URL resolves server-side.
- **Same issue in certificate export:** `src/ion/web/course_api.py` line 515: `WpHTML(string=full_html).write_pdf()` also runs without restricting network access. Certificate HTML is built entirely from DB-sourced fields escaped with `html.escape()`, so no user-controlled raw HTML lands in the certificate template â€” the risk there is negligible. The lesson PDF path is the exploitable one.
- **Recommended fix:** Pass `base_url=""` and configure WeasyPrint's `url_fetcher` to a stub that raises `ValueError` for all external URLs. Alternatively, call `HTML(string=full_html, base_url=None).write_pdf(presentational_hints=True)` and set the WeasyPrint `WEASYPRINT_FETCHING=no` option if available; or apply `bleach`/`nh3` to strip `src`/`href` attributes from any `<img>` and `<link>` elements before rendering. A no-network WeasyPrint fetcher is a three-line addition to `pdf_export_service.py`.
- **Severity note:** Escalates to High in a cloud-hosted deployment where the metadata endpoint (`169.254.169.254`) is reachable. Remains Medium for on-premises deployments where that endpoint is blocked by network policy.

---

**M4: Lab fixture `_insert_row` column-name injection (new)**

- **Evidence:** `src/ion/services/lab_fixture_service.py` lines 211â€“219 â€” `columns = list(payload.keys())` and `col_list = ", ".join(columns)` are interpolated directly into the SQL string without quoting or validation. The `target_table` allowlist is enforced (`_validate_target_table`), but the column names from the fixture `payload` JSON are used verbatim in the `INSERT` statement.
- **Exploit prerequisites:** The `lab_fixtures` table is populated by operators/admins via seed scripts (not via a user-facing API). A malicious operator who controls a fixture's `payload` JSONB column (e.g., via direct DB access or the seed scripts) can include a key like `"col; DROP TABLE alerts; --"` that would be interpolated into the SQL. End-users triggering `/lab/launch` cannot directly control `payload` â€” they only supply `enrollment_id` and `lesson_id`.
- **Mitigating factors:** (1) The `lab_fixtures` table is seeded by admin tooling, not by a user-facing write API. (2) `enrollment_id` is validated against the requesting user's enrolment record (`_require_enrollment`) â€” cross-tenant read is blocked. (3) The `target_table` allowlist is strictly enforced. The column-injection vector requires pre-existing DB write access, which is already beyond the authenticated-user threat model.
- **Recommended fix:** Quote column names: `col_list = ", ".join(f'"{c.replace(chr(34), "")}"' for c in columns)`. Alternatively, add a per-table column allowlist alongside the table allowlist. Low effort, high defensive value given the pattern propagates into `teardown_lab`'s `DELETE FROM {mat_table} WHERE id = :rid` (table is validated; column injection not applicable there â€” already safe).
- **Severity note:** Medium rather than High because exploitation requires DB-write access outside the normal user path. Flag for hardening before lab fixtures are exposed via a user-facing fixture editor.

### Low

**L1: Default admin password fallback `changeme` (carried forward)**

- **Evidence:** `src/ion/web/server.py` line 364 â€” startup validation warns if `ION_ADMIN_PASSWORD` is `changeme`, `password`, or `admin`.
- **Status:** Open. The warning is logged but the application starts. The `must_change_password` flag is set on first use. Deployment documentation recommends a custom password.
- **Recommended fix:** Enforce, not merely warn, when the default password is detected in a non-development configuration. A startup error is preferable to a runtime warning that may be missed in container logs.

---

**L2: `cookie_secure` defaults to false (carried forward)**

- **Evidence:** `src/ion/web/server.py` lines 142â€“147 â€” startup logs a warning but does not enforce HTTPS. Session cookies lack the `Secure` flag in HTTP deployments.
- **Status:** Open. Appropriate for HTTP-only development environments; requires `ION_COOKIE_SECURE=true` in production.
- **Recommended fix:** Document in DEPLOYMENT.md that `ION_COOKIE_SECURE=true` is mandatory behind any TLS terminator. Consider auto-detecting `X-Forwarded-Proto: https` and enabling it automatically.

---

**L3: `python-jose` unmaintained (carried forward)**

- **Evidence:** `pyproject.toml` dependency. JWT library is unmaintained upstream. OIDC/JWT is optional in ION.
- **Status:** Open.
- **Recommended fix:** Migrate to `PyJWT` or `authlib`. Low urgency while OIDC is optional and no CVEs affect the used code paths.

---

**L4: PPTX `ai_summary` and `aob` fields rendered without HTML escaping in slide text (new)**

- **Evidence:** `src/ion/web/daily_standup_api.py` lines 1395â€“1418 â€” `ai_summary` and `aob` strings from the POST body are passed directly to `p.text = str(text)` and `run.text = str(text)` in python-pptx. python-pptx serialises these as OOXML text content, not HTML; special XML characters (`<`, `>`, `&`) would be escaped by the library's own serialiser, so XSS in the PPTX is not the concern. However, a user-supplied string longer than 1,800 characters is truncated without field-level validation on the API schema â€” `ai_summary: str = ""` has no `max_length`. An attacker with `alert:read` permission could send a 10 MB string that gets buffered fully before truncation.
- **Exploit prerequisites:** Any authenticated user with `alert:read` permission can POST to `/api/daily-standup/pptx`. The `ai_summary` field has no `max_length` constraint.
- **Recommended fix:** Add `ai_summary: str = Field("", max_length=10_000)` and `aob: str = Field("", max_length=5_000)` to `StandupPptxRequest`. The server-side truncation at 1,800 chars remains as a belt-and-suspenders limit.

---

## Net-New Surface Assessment â€” v0.20.1 Integration Branch

### Item 18: ForensicCase Workbench (pins, ledger, evidence upload)

**Endpoint group:** `GET/POST/PATCH/DELETE /api/forensics/cases/{id}/pins`, `GET/GET /api/forensics/cases/{id}/ledger[/verify]`, `POST /api/forensics/cases/{case_id}/evidence/upload`
**File:** `src/ion/web/forensic_workbench_api.py`

| Concern | Assessment |
|---------|---------|---------|---------||---------|---------|---------|---------|---|---|
| Auth | All endpoints gated: `forensic:read` (GETs), `forensic:update` (mutations), `forensic:create` (upload). Mirrors `forensics_api.py` pattern. PASS. |
| Upload size cap | `MAX_EVIDENCE_FILE_SIZE = 50 * 1024 * 1024` enforced via `read_upload_capped`. Consistent with translator cap. PASS. |
| File hashing | `hashlib.sha256(content).hexdigest()` computed before row insert. Stored in `hash_sha256`. PASS. |
| MIME validation | No MIME/extension check on evidence upload. The file is stored as metadata only (`storage_location=None` â€” the file is not written to disk) and the hash is recorded. Since no file execution or serving occurs, absence of MIME validation is acceptable risk. NOTE. |
| Path traversal in `storage_location` | The `storage_location` field in `forensics_api.py` (`EvidenceCreate` schema, line 63) is a free-text string accepted from the client with no path sanitisation. In the workbench upload path, `storage_location=None` is hard-coded. However, the direct evidence create route (`POST /api/forensics/cases/{case_id}/evidence`) passes `payload.storage_location` directly to `repo.add_evidence(..., storage_location=payload.storage_location)`. The field is stored in the DB but not used to read/write files in the current code. If a future feature uses `storage_location` as a filesystem path, this becomes a traversal vector. ADVISORY (not currently exploitable). |
| Ledger tamper resistance | `src/ion/services/forensic_ledger_service.py`: sha256 chain is computed over `prev_hash | action | canonical_json(payload)`. `verify_chain` recomputes every hash from seq=1 forward. The advisory lock (`pg_advisory_xact_lock(0x4643574C, forensic_case_id)`) serialises concurrent appends. A direct DB write to `content_hash` or `prev_hash` columns would be detected on the next `verify_chain` call because the recomputed hash would not match. Chain verification is detection-only â€” it does not prevent the write. This is the correct design for an append-only ledger; prevention requires DB-level column immutability (not implemented, not expected in ION). PASS for stated design intent. |
| Advisory-lock namespace isolation from AlertCase | `FCWL = 0x4643574C` vs `CEVL` (AlertCase). Distinct â€” no cross-subsystem serialisation. PASS. |

**Verdict:** No new findings. One advisory on `storage_location` free-text for future-proofing.

---

### Item 19: Lesson PDF export â€” `GET /api/courses/{slug}/lessons/{lesson_id}/export.pdf`

**File:** `src/ion/web/course_api.py` lines 540â€“598; `src/ion/services/pdf_export_service.py`

See **M3** above. This is the primary finding for v0.20.1.

Lesson content is operator/author-authored (`playbook:create`/`playbook:update`) â€” not directly writable by analysts. The XSS-into-PDF path requires a compromised author account, which is why this is rated Medium rather than High for on-premises deployments. The SSRF path via WeasyPrint `<img>` resolution is the more accessible vector for a malicious author.

---

### Item 20: SKILL publisher ZIP export â€” `GET /api/admin/skills/templates/{id}/export.zip` and bulk

**File:** `src/ion/web/skill_publisher_api.py`; `src/ion/services/skill_publisher_service.py`

| Concern | Assessment |
|---------|---------|---------|---------||---------|---------|---------|---------|---|---|
| Auth | Both routes: `_user: User = Depends(require_permission("system:settings"))`. Admin-only. No path for lower-privileged access. PASS. |
| Zip-slip in member names | `folder_name = _slug(tmpl.name)` â€” `_slug` applies `re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")`. No path separators (`/`, `..`) can survive the slug transform. `extras` is currently always `{}` (service returns empty dict). If extras are added in future, `rel_path` from `extras.items()` goes directly into `zf.writestr(f"{folder_name}/{rel_path}", data)` without sanitisation â€” zip-slip possible. ADVISORY for future extras. Current implementation: PASS. |
| Frontmatter injection | `_yaml_str()` quotes values containing `:`, `#`, `'`, `"`, `\n`, `[`. The template `description` and `name` come from DB-stored operator input. A description containing a YAML block-scalar marker (`|` or `>`) is not in the quoted-character set and could potentially inject a multi-line value into the frontmatter. However, `description` is placed as a scalar value (`description: {_yaml_str(description)}`), and `_yaml_str` wraps in double-quotes if any special char is present. A `|` character alone would not trigger quoting. Recommend adding `|` and `>` to the special-character check in `_yaml_str`. LOW risk because the SKILL.md consumer (`skill_loader.py`) uses PyYAML's safe_load, which would not execute code from a malformed description. ADVISORY. |
| Info-leak to non-admin | Route guards confirmed admin-only. PASS. |

**Verdict:** No new findings. Two advisories documented for future extras sanitisation and `_yaml_str` completeness.

---

### Item 21: Lab fixtures â€” `POST /api/courses/{slug}/lessons/{lesson_id}/lab/launch` and `/lab/complete`

**File:** `src/ion/web/labs_api.py`; `src/ion/services/lab_fixture_service.py`

| Concern | Assessment |
|---------|---------|---------|---------||---------|---------|---------|---------|---|---|
| `target_table` allowlist enforcement | `_validate_target_table()` in `lab_fixture_service.py` line 51 raises `ValueError` for any table not in `frozenset({"alerts", "alert_triage", "alert_cases", "observables"})`. Called both in `seed_lab` (line 100) and `teardown_lab` (line 167) for every row. PASS. |
| SQL injection via `payload` JSONB columns | See **M4** above. Column names are not quoted; injection possible if an operator controls a fixture payload key. Requires DB write access. Medium severity. |
| Cross-tenant `enrollment_id` isolation | `labs_api.py` `_require_enrollment()` (line 56): queries `WHERE user_id = current_user.id AND course_id = course_id`. An analyst cannot supply another user's `enrollment_id` â€” the enrollment is looked up from the current user's record, not taken from the request body. `seed_lab` and `teardown_lab` only accept the `enrollment_id` returned from `_require_enrollment`. PASS. |
| `lab/complete` raw SQL for progress update | `labs_api.py` lines 163â€“183: two raw SQL statements (`SELECT` and `INSERT`/`UPDATE` on `course_lesson_progress`) use parameterised binds (`:uid`, `:lid`, `:id`). No interpolation. PASS. |

**Verdict:** One finding (M4). Cross-tenant and table-injection vectors are guarded.

---

### Item 22: `/cyab/studio` deletion â€” auth coverage after migration to `cyab_api.py`

**File:** `src/ion/web/cyab_api.py` â€” studio block starts at line 3384

All migrated routes confirmed to carry `require_permission` or `get_current_user` dependencies:

- `GET /pillars/{pillar_id}/subprofiles` â€” no explicit permission dep; router-level auth is absent on this GET. However, the router is mounted at `/api/cyab` and all CYAB routes require session authentication at the page level; API-level this GET returns catalogue data (public pillar/subprofile structure) and does not expose user or case data. Acceptable.
- `GET /subprofiles/{sub_id}` â€” same as above; catalogue read.
- `POST /subprofiles` â€” `dependencies=[Depends(require_permission("case:update"))]`. PASS.
- `PATCH /subprofiles/{sub_id}` â€” `dependencies=[Depends(require_permission("case:update"))]`. PASS.
- Studio assessment submit â€” `current_user: Optional[User] = Depends(get_current_user)` at lines 3720 and 4100. Uses `Optional[User]` â€” the handler checks `if current_user is not None` before recording `submitted_by`. A request without a valid session would proceed with `current_user = None` and `submitted_by = None`. This is an unauthenticated write to the `cyab_assessments` table.

**Finding (Low, added to L-group):** `POST /api/cyab/studio/...` submit handlers use `Optional[User]` rather than a required auth dependency. An unauthenticated caller can POST an empty-body studio assessment and create a row with `submitted_by=NULL`. Impact is limited to injecting a null-attribution assessment record; no privilege escalation or data exfiltration. Recommend changing `Optional[User] = Depends(get_current_user)` to `User = Depends(require_permission("alert:read"))` for the submit endpoints at lines 3720 and 4100.

**Verdict:** All mutating routes carry proper permission deps. One low finding on Optional-user studio submit.

---

## Re-evaluation of Carried-Forward Findings (M1, M2, L1â€“L3)

| Finding | v0.9.43 Status | v0.20.1-rc Status | Change |
|---------|---------|---------|---------||---------|---------|---------|---------|------|---------|---------|---------|---------||---------|---------|---------|---------||--------|---|
| M1: CSP `unsafe-inline` | Open | Open | No change |
| M2: SIEM webhook SSRF | Open | Partially mitigated (config-save guarded, call-time not guarded) | Partially closed |
| L1: Default admin password | Open | Open | No change â€” warning improved |
| L2: `cookie_secure=false` default | Open | Open | No change |
| L3: `python-jose` unmaintained | Open | Open | No change |

---

## Security Features â€” Updated Status

| Feature | Status |
|---------|---------|---------|---------||--------|---|
| Password hashing | bcrypt via passlib |
| SQL injection | Protected â€” SQLAlchemy ORM parameterised queries; raw SQL uses bind params except lab fixture column names (see M4) |
| SSTI | Protected â€” SandboxedEnvironment |
| XSS | Protected â€” DOMPurify on user content; html.escape() in all WeasyPrint paths |
| CSRF | Protected â€” OIDC state parameter, SameSite cookies |
| Rate limiting | login (5/min), password (5/min), OIDC (10/min), bulk ops (20/min), escalation (10/min), token regen (3/min), global default (120/min) |
| Session management | Server-side sessions, configurable expiry |
| Account lockout | Configurable threshold (default: 5 attempts) |
| Circuit breakers | ES, OpenCTI, TIDE, Ollama, Kibana, Arkime â€” prevent cascading failures |
| Startup validation | Config validated at boot â€” blocks on fatal errors, warns on misconfiguration |
| Audit logging | Full action trail per user (ECS-compliant) |
| File uploads | Capped via `read_upload_capped`: 50 MB translator/workbench, 100 MB PCAP; streaming rejection |
| RBAC | 7 roles, permission-based access, focus mode |
| SSRF protection | `validate_integration_url()` on all 14 integration config-save paths; blocked: private IPs, link-local, cloud metadata, obfuscated IPs, bad ports, null bytes, CRLF |
| Prompt injection defence | `<input_data>` trust-boundary wrapper in Bob system prompt (v0.19.19); output contract pinned in system message |
| PII logging | OIDC callback logs username only at INFO; email at DEBUG only |
| Auto-playbook kill switch | `ION_AUTO_PLAYBOOK_ENABLED=false` default (v0.20.0) |
| Tamper-evident ledger | sha256 chain on ForensicCase (v0.20.1) and AlertCase (v0.20.0); advisory-lock serialised appends |

---

## Net-New Surfaces in v0.34.5

### Item N: Report detail slide-over — `GET /api/threat-landscape/reports/{report_id}` (existing endpoint, newly surfaced in UI)

**Files:** `src/ion/web/templates/daily_standup.html`, `src/ion/web/templates/threat_intel.html`

**Auth:** Endpoint existed since v0.34.0, gated on `observable:read` permission. No auth change.

**Data flow:** Browser fetches `/api/threat-landscape/reports/{id}` (user-initiated click). Response JSON is rendered client-side via `esc()`/`escapeHtml()` helper functions before `innerHTML` assignment — all text content is HTML-entity-escaped before insertion.

**Threat assessment:** No new backend routes. XSS risk limited: all dynamic content (report name, body, actor names, TTP IDs, indicator patterns, labels) passes through the existing `esc()`/`escapeHtml()` sanitiser. No raw HTML is accepted from the API. The `tiCloseAndDrillTechnique` function chains `tiCloseReport → tiCloseDrill → tiDrillTechnique(techId)` where `techId` comes from the API response — it is used as an API query parameter (`/api/threat-intel/technique?id=X`), not injected into markup.

**Net new findings:** 0C / 0H / 0M / 0L.

---

## Net-New Surfaces in v0.34.3

### Item N: Arkime Traffic Analytics — `GET /api/arkime/traffic/status`, `GET /api/arkime/traffic/overview`, `GET /api/arkime/traffic/top-talkers`, `GET /arkime-traffic`

**Files:** `src/ion/web/arkime_traffic_analytics_api.py`, `src/ion/web/templates/arkime_traffic.html`, `src/ion/web/static/js/chart.umd.min.js`

**Auth:** All three API endpoints require `alert:read` permission (authenticated). Page route (`/arkime-traffic`) requires the same permission. Unauthenticated access returns 401.

**Data flow:** The API layer calls `ArkimeService.get_traffic_overview()` / `get_top_talkers()` which make outbound HTTP requests to the configured Arkime viewer. Arkime credentials (`ION_ARKIME_USERNAME` / `ION_ARKIME_PASSWORD`) are not surfaced to the browser.

**Input validation:** `range` parameter validated against fixed allowlist `{"24h", "7d", "30d"}` — any other value returns HTTP 400. `limit` is clamped to `[1, 25]`. No user-controlled strings are interpolated into Arkime query expressions.

**Threat assessment:** No new injection surfaces (enum-validated params). No new privilege escalation paths (read-only, same tier as existing Arkime endpoints). No new SSRF surface (same `ArkimeService` and configured URL). Chart.js v4.4.4 vendored locally — no runtime CDN fetch, covered by `script-src 'self'` CSP.

**Net new findings:** 0C / 0H / 0M / 0L.

---

## Net-New Surfaces in v0.22.0

### Item 26: MITRE ATT&CK technique-coverage heatmap â€” `GET /api/cyab/attack-heatmap`, `GET /cyab/attack-heatmap`

**Files:** `src/ion/services/mitre_heatmap_service.py`, `src/ion/web/cyab_api.py`, `src/ion/web/server.py` (page route), `src/ion/web/templates/cyab/attack_heatmap.html`, `src/ion/data/attack_techniques.json`

**Auth gate:** `Depends(require_permission("alert:read"))` on the API; the page route inherits the standard CyAB section gate.

**Threat model & mitigations:**
- *Information disclosure of alert activity volume.* The response exposes per-technique alert-case counts and pin counts. Counts could let a low-privilege internal user infer "this organisation has been getting hit by T1558 lately." Mitigation: gated behind `alert:read`, the same permission that already exposes the underlying triage rows. No additional surface.
- *Bundled snapshot integrity.* `src/ion/data/attack_techniques.json` is read-only at runtime. Any tampering requires repository write access; covered by the existing supply-chain controls (signed commits, CI image build).
- *No live STIX fetch.* Air-gap rule preserved; the heatmap never reaches MITRE's servers at runtime. The refresh script is dev-time only.
- *Cache header.* Response sets `Cache-Control: no-cache` so a stale browser cache cannot serve stale technique observation counts during a deployment window.
- *No PII.* Response payload contains only technique IDs, technique labels (from the bundled snapshot), tactic IDs, integer counts, and a string state enum.

### Item 27: Timeline annotations â€” `*/annotations` endpoints on AlertCase + ForensicCase

**Files:** `src/ion/services/annotation_service.py`, `src/ion/services/forensic_annotation_service.py`, `src/ion/models/alert_triage.py` (`AlertCaseAnnotation`), `src/ion/models/forensics.py` (`ForensicCaseAnnotation`), `src/ion/web/workbench_api.py`, `src/ion/web/forensic_workbench_api.py`, `src/ion/storage/database.py` (table creation in `_run_migrations()`).

**Endpoints:**
- `GET /api/alert-cases/{case_id}/annotations` â€” list active annotations
- `POST /api/alert-cases/{case_id}/annotations` â€” create
- `PATCH /api/alert-cases/{case_id}/annotations/{ann_id}` â€” edit body and/or `timeline_ts`
- `DELETE /api/alert-cases/{case_id}/annotations/{ann_id}` â€” soft-delete
- ForensicCase mirror under `/api/forensics/cases/{case_id}/annotations`

**Auth gates:** list = `case:read` (forensic: `forensic:read`); create + edit-own = `case:update`; edit-any = `case:close`. Author check: `annotation.created_by_id == current_user.id`. Service-level check, NOT route-level â€” TOCTOU rule from v0.20.1 pin-service fix is satisfied (verified by reviewer; check happens inside `_check_edit_permission` before any `session.add()` or attribute mutation).

**Threat model & mitigations:**
- *Cross-case PATCH/DELETE.* `_get_annotation_or_raise` verifies `annotation.alert_case_id == url_case_id` before any mutation. Mismatch raises 404 (not 403) so a low-privilege user cannot enumerate which case-IDs hold which annotation-IDs.
- *Stored XSS in body.* Body is rendered via Jinja's autoescape (existing `SandboxedEnvironment`). Inline JS in the Workbench template uses `textContent` not `innerHTML` for body display.
- *Body size.* Pydantic schema enforces `max_length=2000`. DB CHECK constraint enforces `length(body) > 0`. Three-layer defence (route â†’ DB â†’ CHECK).
- *Hard-delete.* Disallowed. Soft-delete via `deleted_at` only; `deleted_at IS NOT NULL` filters from list query. Hard-delete would require database-direct access.
- *Ledger integrity NOT compromised.* Annotations are NOT written to the tamper-evident hash chain. A single `annotation_created` ledger row IS appended on creation (records `annotation_id`, `timeline_ts`, actor â€” NOT body content), so the chain still proves that an annotation existed at a point in time. Subsequent edits do not append to the chain. This is a deliberate design call to keep the chain's invariant load-bearing only for evidence pins.
- *Permission escalation.* `case:close` (supervisor-level) is required to edit another user's annotation. A user with only `case:update` can edit only their own. Verified by smoke test (test #10 in `test_alert_case_annotations.py`).
- *Timezone.* `timeline_ts` stored UTC naive, matching `CaseEvidenceLedger.timestamp` convention. No timezone-confusion attack surface.

### Item 28: Bundled `attack_techniques.json`

**Files:** `src/ion/data/attack_techniques.json`, `scripts/generate_attack_techniques_json.py`

**Type:** read-only static data file shipped in the Docker image. 637 ATT&CK Enterprise v15.1 technique records (`id`, `name`, `tactic_ids`, `is_subtechnique`, `parent_id`).

**Threat model:**
- *Path traversal.* File is loaded once at service initialisation via a hardcoded relative path; user input does not influence the load path.
- *Schema drift.* Generator script validates STIX structure during refresh; runtime loader fails closed if the file is malformed (heatmap returns empty cells with a warning log).
- *Secrets.* None. Public ATT&CK data only.

---

## Net-Removed Surface in v0.22.0

### Item R1: `POST /api/elasticsearch/config` â€” REMOVED

**Was at:** `src/ion/web/api.py` (lines 3473â€“3502, deleted in commit `e345e53`).

**Why removed:** Older write path that bypassed `_ssrf_safe_url()`, skipped Pydantic validation (writes raw `request.json()`), did not call `reload_config()`, and did not invalidate the assignment cache. The properly-gated replacement at `PUT /api/admin/config/elasticsearch` (`admin_api.py:401`) has been live for several releases.

**Caller-check before removal:** `topology.html:734` only used the URL for a GET against the read endpoint at `api.py:3459`. No POST callers in templates, static JS, or tests.

**Findings-quality impact:** removes a latent SSRF + unvalidated-write surface. Not a counted closure (the write path was undocumented and ungated improperly, never raised as a formal finding); reported here for traceability.

### Item R2: `/api/compliance/nist` legacy endpoint â€” REMOVED

**Was at:** `src/ion/web/compliance_api.py:62` plus `get_compliance_posture_legacy()` in `compliance_mapping_service.py`. Replaced by `/api/compliance/nist_csf/posture`. No callers found.

### Item R3: `/dashboard-legacy` and `/dashboard-v2` â€” REMOVED

**Was at:** `src/ion/web/server.py:771` and `:777`. Tailwind-rollout fences from v0.19; rollback path no longer needed.

### Item R4: `saved_search_api.py` â€” REMOVED (file)

**Was at:** `src/ion/web/saved_search_api.py`. Endpoints shadowed by `api.py:7514+` for the common-case routes; unique `/pin` and `/use` routes either consolidated into `api.py` or removed if unused.

---

## Net-New Surfaces in v0.21.0

### Item 23: Bob Eval Harness â€” `POST /api/bob-eval/runs`, `GET /api/bob-eval/runs[/{run_id}[/samples]]`, `GET /bob-eval`

**Files:** `src/ion/web/bob_eval_api.py`, `src/ion/services/bob_eval_service.py`, `src/ion/models/bob_eval.py`

#### 23a. Permission gate on all routes

`_SETTINGS_PERM = require_permission("system:settings")` is applied as `Depends(_SETTINGS_PERM)` on every route: POST runs, GET runs, GET runs/{run_id}, GET runs/{run_id}/samples, and the HTML GET /bob-eval. The `require_permission` factory chains through `get_current_user` which enforces a valid session token before the permission check. Authentication and authorisation are both enforced. **PASS.**

#### 23b. `sample_size` integer validation

`CreateEvalRunRequest` uses `sample_size: int = Field(50, ge=1, le=_MAX_SAMPLE_SIZE)` where `_MAX_SAMPLE_SIZE = 200`. FastAPI/Pydantic v2 enforces `ge=1, le=200` at the schema validation stage before the handler is called. A non-integer body field causes a 422; a value outside 1â€“200 causes a 422. Additionally, `create_eval_run` in `bob_eval_service.py` applies `sample_size = min(sample_size, _MAX_SAMPLE_SIZE)` as a belt-and-suspenders clamp before the DB write. **PASS â€” no gap.**

#### 23c. Thread spawn before template validation (non-existent `template_id`)

The handler calls `create_eval_run(...)` first, which performs `session.get(AlertPromptTemplate, template_id)` before committing the `BobEvalRun` row. If the template does not exist, `create_eval_run` raises `ValueError`, the handler converts it to HTTP 400, and `run_eval_async` is never called. There is no window where a thread is spawned against a non-existent template. **PASS â€” no DoS vector.**

#### 23d. Duplicate-run advisory lock

`_run_eval_sync` acquires two locks before executing:

1. `_acquire_try_advisory_lock(session, LOCK_BOB_EVAL_BG)` â€” a session-scoped non-blocking lock that fails immediately if the investigation loop holds it. If two simultaneous POSTs both win this check (possible: both eval threads can hold the session lock concurrently since it is not the run-specific lock), the second check gates them:
2. `_acquire_xact_lock(session, _BPEH_NS, eval_run_id)` â€” a transactional advisory lock keyed by `(0x42504548, eval_run_id)`. Since each POST creates a distinct `eval_run_id`, this lock does not prevent two simultaneous runs for the same template â€” it prevents the same run ID from being re-entered. If two users simultaneously POST `{template_id: 5, sample_size: 50}`, two separate `BobEvalRun` rows are created with distinct IDs, and both threads proceed concurrently.

**Finding (Low â€” see L5 below):** Two simultaneous eval runs for the same template are not serialised. Each run independently pulls a random sample of up to 200 `ai_feedback` rows and issues up to 200 Ollama calls. With two simultaneous requests, an admin can drive 400 concurrent Ollama calls. Given `system:settings` access is restricted to administrators and Ollama already has a queue (`bypass_queue=True` is set, meaning the eval calls skip the normal investigation queue), the practical impact is resource exhaustion on Ollama, not a privilege-escalation risk. Severity: Low; not a DoS risk to unauthenticated actors.

#### 23e. Pagination bounds on `/samples`

`page_size: int = Query(50, ge=1, le=200)` enforces the upper bound. The `offset` is computed as `(page - 1) * page_size` from validated inputs. Total count query is bounded by the run's own `sample_size` cap (200 max). **PASS.**

---

### Item 24: `Investigation.reasoning_text` â€” `ION_BOB_STORE_REASONING=true` gate

**Files:** `src/ion/services/investigation_service.py`, `src/ion/models/investigation.py`, `src/ion/web/investigation_api.py`, `src/ion/web/investigation_memory_api.py`

#### 24a. Storage gating

`reasoning_text` is written to the `Investigation` row only when `os.environ.get("ION_BOB_STORE_REASONING", "false").lower() in ("true", "1", "yes")`. The column always exists in the schema (populated by migration in `database.py`), but remains NULL unless the flag is set. **PASS.**

#### 24b. Retention parity with alert records

`Investigation` rows have no dedicated purge/deletion path in the codebase. There is no API endpoint, background task, or repository method that deletes `Investigation` rows. Consequently, `reasoning_text` has indefinite retention regardless of alert lifecycle. Alert triage rows (`alert_triage`) similarly lack a purge path; neither surface has a retention-limiting mechanism. This is a pre-existing data-retention characteristic, not a regression in v0.21.0. **ADVISORY â€” no new finding.** Document in RUNBOOK that `reasoning_text` persists until manual DB purge if `ION_BOB_STORE_REASONING=true` is enabled.

#### 24c. Unintentional logging of reasoning_text

`investigation_service.py` truncates the stored value to 8,000 characters (`[:8000]`). The stored text is not written to any log line in the service. Logger calls in `bob_eval_service.py` that could surface reasoning text are at DEBUG level (`logger.debug`) and do not include the reasoning content directly â€” only alert IDs and error messages appear in the error handler. No Python `%r` or f-string expands reasoning text into a log line in the audited paths. **PASS.**

#### 24d. Serialisation â€” exposure in non-admin routes

`InvestigationSummary` (both the `investigation_api.py` and `investigation_memory_api.py` versions) does not include `reasoning_text` as a field. `InvestigationDetail` in `investigation_memory_api.py` includes `prompt_snapshot` and `raw_response` but not `reasoning_text`. The `_inv_to_detail` converter does not copy `inv.reasoning_text` to the response object. Both GET endpoints that return `Investigation` objects (`/api/investigate/jobs/{inv_id}` and `/api/investigations/{inv_id}`) are gated on `alert:read`, not `system:settings`. However, since `reasoning_text` is not serialised in any response schema, the effective exposure to `alert:read` users is zero. **PASS â€” reasoning_text is not leaked via any API response.**

Note: `BobEvalRunSample.reasoning_text` (a distinct column on the eval harness samples table) _is_ included in `BobEvalRunSample.to_dict()` and returned by `GET /api/bob-eval/runs/{run_id}/samples`. That endpoint is `system:settings`-gated. See finding L5.

---

### Item 25: `AlertPromptTemplate.confidence_threshold_override`

**Files:** `src/ion/web/alert_prompt_api.py`, `src/ion/storage/alert_prompt_repository.py`, `src/ion/models/alert_prompt.py`

#### 25a. Bounds validation

`AlertPromptCreate` and `AlertPromptUpdate` both declare `confidence_threshold_override: Optional[int] = Field(default=None, ge=0, le=100)`. Pydantic v2 enforces `ge=0, le=100` at the schema level; out-of-range integers return 422. NULL (omitted) is permitted, which maps to "use global env-var default". The column is stored as `Integer` in the DB with no DB-level check constraint, but the application-layer validation is sufficient for the authenticated-user threat model. **PASS.**

#### 25b. Permission gate on write routes

`POST /api/alert-prompts` and `PUT /api/alert-prompts/{template_id}` both use `dependencies=[Depends(require_any_permission(_MANAGE_PERMS))]` where `_MANAGE_PERMS = ["playbook:create", "playbook:update", "playbook:delete"]`. These are content-author permissions, not analyst-level permissions.

**Finding (Low â€” see L6 below):** The `confidence_threshold_override` field controls the AI circuit-breaker threshold per template. Setting it to `0` would cause every Bob investigation matched to that template to be flagged as low-confidence and escalated via the `bob_escalation_badge` path, effectively suppressing AI verdicts for all alerts matching the template. Setting it to `100` would cause the circuit breaker never to fire for that template's alerts, meaning every AI verdict would be written unconditionally regardless of actual model confidence. This field has operational security significance (it governs whether AI verdicts are written vs. escalated) but is writable by any user with `playbook:create` or `playbook:update` permission â€” which is a broader set than `system:settings`. Recommend restricting write access on `confidence_threshold_override` to `system:settings`, either by adding a separate PATCH endpoint or by splitting the `AlertPromptUpdate` schema to require elevated permission when this field is present.

---

### Item 26: `AlertTriage.bob_escalation_badge` â€” writable via user API?

**Files:** `src/ion/web/api.py`, `src/ion/models/alert_triage.py`

`bob_escalation_badge` is set exclusively by `investigation_service.py` when the circuit breaker fires (`triage.bob_escalation_badge = "low_confidence_triage"`). The `TriageUpdate` Pydantic schema (api.py lines 3786â€“3794) exposes: `status`, `assigned_to_id`, `assigned_to_name`, `priority`, `case_id`, `analyst_notes`, `observables`, `mitre_techniques`. `bob_escalation_badge` is not in the schema. The update handler (`update_alert_triage`) maps only the fields listed in `TriageUpdate` to ORM attributes â€” there is no `**kwargs` or dynamic field assignment that would allow injection of unlisted fields. **PASS â€” not user-writable.**

The field is returned as a read-only value in the triage serialisation block (api.py line 6382) so the UI can render the escalation pill. This is intentional and safe.

---

### Item 27: AIFeedback `human_verdict="pending"` sentinel and eval harness data access

**Files:** `src/ion/services/bob_eval_service.py`, `src/ion/models/bob_eval.py`

The eval harness de-duplicates `ai_feedback` rows by `MAX(id)` per `(alert_id, alert_prompt_template_id)`. The `human_verdict="pending"` sentinel identifies circuit-breaker rows (where `auto_escalated=true` or verdict has not yet been set by an analyst). These rows are treated as abstentions in the eval loop (line 339: `if auto_escalated or human_verdict == "pending": abstentions += 1`) and written to `bob_eval_run_samples` with `bob_verdict=None, agreement=None, reasoning_text=None`. They do not receive a fresh Ollama call. The `human_verdict` field value `"pending"` is stored in the `BobEvalRunSample.human_verdict` column and returned in the `/samples` response, but this only exposes the verdict state â€” not the underlying alert content, analyst notes, or triage detail. The `/samples` endpoint is `system:settings`-gated. **PASS â€” no triage data leakage beyond what admins already have access to.**

---

**New Findings Summary (v0.21.0)**

| ID | Severity | Surface | Issue |
|----|---------|---------|---------|---------|-|---------|---------|---------|---------||-------|---|
| L5 | Low | `POST /api/bob-eval/runs` | No per-template concurrency guard â€” two simultaneous runs for the same template both proceed, driving up to 2Ã— Ollama load |
| L6 | Low | `PUT /api/alert-prompts/{id}` | `confidence_threshold_override` (circuit-breaker control) writable by `playbook:create/update` users, not restricted to `system:settings` |

---

## Recommendations for Production

1. **Patch M3 (WeasyPrint SSRF) before v0.20.1 ship.** Apply a no-network URL fetcher to `pdf_export_service.py`. Three lines of code; unblocks the lesson PDF feature safely.
2. **Patch M4 (lab fixture column names) before lab fixtures are operator-editable via UI.** Quote column names in `_insert_row`. Currently low risk because the `lab_fixtures` table is seed-script-only.
3. **Fix L4 (`StandupPptxRequest` unbounded fields).** Add `max_length` to `ai_summary` and `aob` in `StandupPptxRequest`. One-line change.
4. **Fix Item 22 Optional-user studio submit.** Change `Optional[User]` to `User = Depends(require_permission("alert:read"))` at cyab_api.py lines 3720 and 4100.
5. **Close M2 (SIEM webhook call-time SSRF).** Add `validate_integration_url()` call at the top of `export_to_webhook` and `export_to_splunk_hec` in `siem_export.py`.
6. **Address L6 (`confidence_threshold_override` permission tier) in v0.21.1.** Either add a separate `PATCH /api/alert-prompts/{id}/threshold` endpoint gated on `system:settings`, or check for this field in `update_alert_prompt` and require elevated permission when it is present in the update payload.
7. **Address L5 (concurrent eval runs) in v0.21.1.** Add a template-level advisory lock in `_run_eval_sync` using the same two-int form: `pg_advisory_xact_lock(_BPEH_NS, template_id or 0)`. This would serialise same-template runs without blocking cross-template parallelism.
8. **Document `reasoning_text` retention** in RUNBOOK: when `ION_BOB_STORE_REASONING=true`, `Investigation.reasoning_text` and `BobEvalRunSample.reasoning_text` persist until manual DB purge. Add a note that this flag should be treated as a data-classification decision under the same policy as `summary_text`.
9. **Set `ION_COOKIE_SECURE=true`** behind any TLS terminator in production.
10. **Set `ION_DEBUG_MODE=false`** to disable `/docs`, `/redoc`, and `/openapi.json`.
11. **Use a non-default `ION_ADMIN_PASSWORD`.**
12. **Migrate from `python-jose`** to `PyJWT` or `authlib` at next dependency-refresh cycle.
13. **Add `|` and `>` to `_yaml_str` special-character set** in `skill_publisher_service.py` as a belt-and-suspenders guard on SKILL.md frontmatter.
14. **Add `storage_location` path sanitisation** in `forensics_api.py` `EvidenceCreate` schema proactively, before any feature uses the field as a filesystem path.
|---------|---------|---------|---------|---|
|---------|---------|---------|---------|---|


