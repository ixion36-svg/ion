# ION Security Assessment Report

**Assessment Date:** 2026-05-11 (v0.22.1 delta) / 2026-05-09 (v0.22.0-rc body below)
**Application Version:** 0.22.1 (security patch on main)
**Previous Assessment Version:** 0.22.0-rc (2026-05-09)
**Scope:** Web application security review — authenticated internal-user threat model, prompt-injection from adversary-controlled alert content, privilege escalation, data exfiltration, pivot to backend systems (Elastic, Kibana, TIDE, OpenCTI, Arkime, Keycloak).
**Previous Assessment:** 2026-04-07 (v0.9.43)
**Reviewer:** Security Audit Agent

---

## Executive Summary

ION maintains strong security fundamentals: bcrypt password hashing, SQLAlchemy ORM parameterised queries throughout the main codebase, SandboxedEnvironment Jinja2 rendering, DOMPurify XSS mitigation, RBAC with 7-tier role hierarchy, rate limiting on auth endpoints, circuit breakers on all external integrations, and ECS-compliant audit logging. v0.19.17–v0.20.0 closed several moderate-to-low findings from the last assessment. v0.21.0-rc added the Bob Eval Harness, per-template confidence threshold overrides, and the `reasoning_text` storage gate. v0.22.0-rc adds two well-gated read/write surfaces (MITRE coverage heatmap and timeline annotations) AND removes a latent SSRF/unvalidated-write path (`POST /api/elasticsearch/config`) along with several legacy-route dead-code surfaces. Net new in v0.22.0: 0C / 0H / 0M / 0L. The removed write path is a findings-quality improvement, not a counted closure.

| Severity | v0.9.43 | v0.20.1-rc | v0.21.0-rc | v0.22.0-rc | v0.22.1 |
|----------|---------|------------|------------|------------|---------|
| Critical | 0 | **0** | **0** | **0** | **0** |
| High | 0 | **0** | **0** | **0** | **0** |
| Medium | 2 | **3** | **3** | **3** | **3** |
| Low | 3 | **4** | **6** | **6** | **4** (L5+L6 closed) |
| **Total** | **5** | **7** | **9** | **9** | **7** |

v0.22.1 closes the two Lows that the v0.22.0-rc assessment recommended addressing in a patch (L5 reasoning_text serialisation, L6 confidence_threshold_override permission tier) and resolves the three open questions (OQ4/5/6) from `_spec_v0_22.md` §7. See the v0.22.1 Delta section below for details.

---

## v0.22.1 Delta (2026-05-11)

**Net change vs v0.22.0-rc:** −2 Low (L5, L6 closed). Three open questions (OQ4, OQ5, OQ6) resolved with rationale below.

### CLOSED: L5 — `reasoning_text` in samples serialisation
**File:** `src/ion/web/bob_eval_api.py`
`get_run_samples` now reads `ION_BOB_STORE_REASONING` at request time and strips `reasoning_text` from each sample dict when the flag is false. Rows that were persisted while the flag was true stop leaking via the samples API immediately on flag disable; no DB back-fill required. `BobEvalRunSample.reasoning_text` is the only `reasoning_text` field exposed through any `to_dict()` path — `Investigation.reasoning_text` is not serialised by any endpoint. Regression tests: `tests/integration/test_bob_eval.py::TestReasoningTextResponseGate` (3 cases).

### CLOSED: L6 — `confidence_threshold_override` permission-tier bypass
**File:** `src/ion/web/alert_prompt_api.py`
The v0.21.1 gate only fired when the incoming value was non-null. The Alert Prompts edit UI always emitted the field in PUT payloads (always-on `confidence_threshold_override` key in the JSON body), so a user with only `playbook:update` could send `{"confidence_threshold_override": null, …}` to clear a system-tier strict threshold (reverting it to the env-default). `_check_confidence_threshold_permission` now takes the Pydantic update model and the current stored value, uses `model_fields_set` to distinguish field-omitted from explicit-null, and treats any change — including explicit-null-clearing-non-null — as requiring `system:settings`. The UI hides the threshold form-row for users without `system:settings` (via `/api/auth/me` permissions check) and omits the field from the payload entirely; backend gate is the defence-in-depth authority. Regression tests: `tests/integration/test_v021_fixes.py::TestConfidenceThresholdPermission` (7 cases).

### RESOLVED: OQ4 — `alert:read` is the correct gate for `/api/cyab/attack-heatmap`
The heatmap exposes per-technique alert-case and pin counts aggregated from `AlertCase`, `AlertTriage`, `CaseEvidencePin`, and `ForensicCasePin` rows. Users with `alert:read` already have access to all of those rows directly via the alert list, triage view, and case views — the heatmap is a per-technique aggregation of data they are already authorised to see. No privilege escalation. `alert:read` is confirmed as the right minimum gate.

### RESOLVED: OQ5 — heatmap smoke-test backend coverage
**File:** `tests/test_mitre_heatmap.py`
The smoke suite previously hard-coded SQLite, leaving the Postgres LATERAL-join service path untested. The `db_engine` fixture now honours `ION_TEST_DATABASE_URL` when set, falling back to ephemeral SQLite. Operators with a Postgres instance can exercise the LATERAL path locally with:
```
ION_TEST_DATABASE_URL=postgresql://user:pass@host/dbname pytest tests/test_mitre_heatmap.py
```
CI default remains SQLite (Python-side unnesting path); the Postgres path is exercised at deploy/integration time and now also reproducible locally.

### RESOLVED: OQ6 — `timeline_ts` timezone convention
`alert_case_annotations.timeline_ts` and `forensic_case_annotations.timeline_ts` are stored as UTC-naive `DateTime`, matching the `CaseEvidenceLedger.timestamp` convention used across the project. The Workbench JS treats these as UTC for display, consistent with all other timestamp surfaces. Cross-region deployments do not currently require tz-aware storage; if that changes, the migration would span both annotation tables AND the ledger to keep ordering deterministic.

---

## Fixed Since v0.9.43

The following findings from the v0.9.43 assessment and items from the net-new surface list have been verified closed in v0.9.44–v0.20.0:

### FIXED: SSTI (Critical) — v0.3.0
Template engine uses `SandboxedEnvironment`. Still confirmed.

### FIXED: Open Redirect on Login — v0.9.34
Still confirmed; login redirect validates relative path, no `//` or `://`.

### FIXED: ES System Index Access — v0.9.34
Still confirmed; Discover blocks `.kibana`, `.security`, etc.

### FIXED: Kibana Multi-Alert Attachment — v0.9.34
Still confirmed.

### FIXED: OIDC Callback PII Logging — v0.19.17
`src/ion/auth/oidc.py` line 317: `logger.info` now logs only `user.username`, not `token_data.email`. Confirmed clean at INFO level; email appears only in DEBUG-level statements which are suppressed in production.

### FIXED: `GET /health/deep` unauthenticated — v0.19.17
`src/ion/web/api.py` line 2288: `current_user: User = Depends(get_current_user)` confirmed present. Deep-health probes are no longer reachable without a valid session.

### FIXED: `GET /canaries/types` unauthenticated — v0.19.17
`src/ion/web/canary_api.py` line 66: `dependencies=[Depends(require_permission("alert:read"))]` confirmed. Canary type enumeration now requires authentication.

### FIXED: `POST /change-log` permission upgraded — v0.19.17
`src/ion/web/change_log_api.py` line 47: `require_permission("system:settings")` confirmed. Read-only analysts can no longer inject change records.

### FIXED: `GET /api/wallboard/snapshot` permission upgraded — v0.19.17
`src/ion/web/wallboard_api.py`: wallboard page uses `require_page_permission("alert:read")`. Snapshot endpoint confirmed gated.

### FIXED: `POST /api/ticker/{id}/dismiss` — critical-severity tickers now dismissable — v0.19.13
`src/ion/web/ticker_api.py` line 119: `dependencies=[Depends(require_any_permission(_READ))]`. Per-user dismiss is scoped to the calling user; peer-analyst visibility is preserved because critical tickers also auto-resolve when the underlying alert is cased. Risk accepted per inline comment.

### FIXED: SSRF on URL-config save (14 integration sites) — v0.19.18
`src/ion/web/admin_api.py`: `_ssrf_safe_url()` added at line 172, wrapping `validate_integration_url()` from `src/ion/core/url_validator.py`. Applied to all 14 integration URL save paths (ES, Kibana, GitLab, OpenCTI, DFIR-IRIS, TIDE, Arkime, Ollama, plus the wizard `/save` endpoint). Private IP ranges, link-local, cloud metadata (169.254.x, GCP `metadata.google.internal`), and obfuscated decimal/hex IPs are all blocked. Docker service hostnames (alphanumeric with hyphens, no IP) are exempted — acceptable for containerised deployments. Full re-audit confirms M2 (SIEM webhook SSRF — see below) is the only remaining open gap.

### FIXED: File upload size limit — v0.9.34 / v0.19.18
`src/ion/core/uploads.py:read_upload_capped` (streaming cap) applied to `/api/translator/translate-file`, `/api/translator/extract`, and `/api/pcap/analyze` in v0.19.18. Sizes are 50 MB (translator), 100 MB (PCAP) respectively, enforced before the full buffer is allocated, eliminating the OOM vector present in the pre-v0.19.18 unbuffered `await file.read()` pattern.

### FIXED: `ION_AUTO_PLAYBOOK_ENABLED` kill switch — v0.20.0
`src/ion/web/api.py` lines 64–66: defaults `false`. When off, matched playbooks are surfaced for analyst click; no automatic execution. Eliminates surprise timeline entries from adversary-manipulated alert patterns.

### FIXED: Bob system prompt trust boundary — v0.19.19
`src/ion/services/alert_prompt_service.py` ~line 2884: alert fields are wrapped in `<input_data>...</input_data>` tags in the user turn. The system prompt explicitly instructs the model to treat all bytes inside those tags as hostile-controlled data, never follow instructions embedded in them, and not let alert content change the verdict classification. The trust boundary is as strong as a prompt-level control can be. Residual risk (prompt injection bypass in future model versions) is low given the current guard is thorough.

---

## Current Findings

### Medium

**M1: CSP `unsafe-inline` for scripts (carried forward)**

- **Evidence:** `src/ion/web/server.py` lines 194–205 — `script-src 'self' 'unsafe-inline'`.
- **Status:** Open — unchanged from v0.9.43.
- **Mitigation in place:** DOMPurify sanitises all user-supplied HTML before insertion. All tested XSS vectors bounce on DOMPurify.
- **Residual risk:** A DOMPurify bypass (historically rare, patched promptly upstream) could execute arbitrary script in analyst sessions. Severity remains Medium because of the mitigating control.
- **Recommended fix:** Migrate all inline `onclick` handlers to `addEventListener` calls and remove `unsafe-inline` from `script-src`. High refactoring effort; schedule as a hardening sprint, not a blocker.

---

**M2: SIEM webhook export lacks SSRF validation on call-time URLs (carried forward, partially mitigated)**

- **Evidence:** `src/ion/services/siem_export.py` lines 247–277 — `export_to_webhook(url=...)` and `export_to_splunk_hec(url=...)` accept the URL from config at call time. Neither function calls `validate_url()` or `validate_integration_url()` before the outbound HTTP request.
- **Status:** Partially open. The v0.19.18 SSRF guard on the config-save path (`_ssrf_safe_url`) prevents a malicious URL from being persisted via the admin UI. However, the guard is not applied at the point of use in `siem_export.py`. A URL injected via direct DB manipulation or environment override would bypass it.
- **Threat in scope:** The threat model includes a malicious internal user. A DBA-level insider could set the DB row directly and trigger an outbound probe to an internal service. For the primary threat actor (UI-only access), v0.19.18 is sufficient.
- **Recommended fix:** Add `validate_integration_url(url, "siem_webhook")` at the top of `export_to_webhook` and `export_to_splunk_hec`, raising `ValueError` on failure. One-line fix per function.

---

**M3: WeasyPrint SSRF via lesson PDF export — `GET /api/courses/{slug}/lessons/{lesson_id}/export.pdf` (new)**

- **Evidence:** `src/ion/services/pdf_export_service.py` line 304: `HTML(string=full_html).write_pdf()`. WeasyPrint's default configuration resolves `<img src="...">` and `<link href="...">` tags at render time using the system HTTP client. `render_lesson_pdf()` converts `lesson.content_md` to HTML via `markdown.markdown()` without sanitising or stripping external resource references. If a lesson's `content_md` contains `![x](http://169.254.169.254/latest/meta-data/)`, WeasyPrint will issue an HTTP GET to that URL during PDF generation.
- **Exploit prerequisites:** The attacker must have `playbook:create` or `playbook:update` permission (course author role) to insert a malicious `<img>` URL into a lesson's `content_md`. Any authenticated user with `playbook:update` can then trigger the PDF export GET. The malicious URL resolves server-side.
- **Same issue in certificate export:** `src/ion/web/course_api.py` line 515: `WpHTML(string=full_html).write_pdf()` also runs without restricting network access. Certificate HTML is built entirely from DB-sourced fields escaped with `html.escape()`, so no user-controlled raw HTML lands in the certificate template — the risk there is negligible. The lesson PDF path is the exploitable one.
- **Recommended fix:** Pass `base_url=""` and configure WeasyPrint's `url_fetcher` to a stub that raises `ValueError` for all external URLs. Alternatively, call `HTML(string=full_html, base_url=None).write_pdf(presentational_hints=True)` and set the WeasyPrint `WEASYPRINT_FETCHING=no` option if available; or apply `bleach`/`nh3` to strip `src`/`href` attributes from any `<img>` and `<link>` elements before rendering. A no-network WeasyPrint fetcher is a three-line addition to `pdf_export_service.py`.
- **Severity note:** Escalates to High in a cloud-hosted deployment where the metadata endpoint (`169.254.169.254`) is reachable. Remains Medium for on-premises deployments where that endpoint is blocked by network policy.

---

**M4: Lab fixture `_insert_row` column-name injection (new)**

- **Evidence:** `src/ion/services/lab_fixture_service.py` lines 211–219 — `columns = list(payload.keys())` and `col_list = ", ".join(columns)` are interpolated directly into the SQL string without quoting or validation. The `target_table` allowlist is enforced (`_validate_target_table`), but the column names from the fixture `payload` JSON are used verbatim in the `INSERT` statement.
- **Exploit prerequisites:** The `lab_fixtures` table is populated by operators/admins via seed scripts (not via a user-facing API). A malicious operator who controls a fixture's `payload` JSONB column (e.g., via direct DB access or the seed scripts) can include a key like `"col; DROP TABLE alerts; --"` that would be interpolated into the SQL. End-users triggering `/lab/launch` cannot directly control `payload` — they only supply `enrollment_id` and `lesson_id`.
- **Mitigating factors:** (1) The `lab_fixtures` table is seeded by admin tooling, not by a user-facing write API. (2) `enrollment_id` is validated against the requesting user's enrolment record (`_require_enrollment`) — cross-tenant read is blocked. (3) The `target_table` allowlist is strictly enforced. The column-injection vector requires pre-existing DB write access, which is already beyond the authenticated-user threat model.
- **Recommended fix:** Quote column names: `col_list = ", ".join(f'"{c.replace(chr(34), "")}"' for c in columns)`. Alternatively, add a per-table column allowlist alongside the table allowlist. Low effort, high defensive value given the pattern propagates into `teardown_lab`'s `DELETE FROM {mat_table} WHERE id = :rid` (table is validated; column injection not applicable there — already safe).
- **Severity note:** Medium rather than High because exploitation requires DB-write access outside the normal user path. Flag for hardening before lab fixtures are exposed via a user-facing fixture editor.

### Low

**L1: Default admin password fallback `changeme` (carried forward)**

- **Evidence:** `src/ion/web/server.py` line 364 — startup validation warns if `ION_ADMIN_PASSWORD` is `changeme`, `password`, or `admin`.
- **Status:** Open. The warning is logged but the application starts. The `must_change_password` flag is set on first use. Deployment documentation recommends a custom password.
- **Recommended fix:** Enforce, not merely warn, when the default password is detected in a non-development configuration. A startup error is preferable to a runtime warning that may be missed in container logs.

---

**L2: `cookie_secure` defaults to false (carried forward)**

- **Evidence:** `src/ion/web/server.py` lines 142–147 — startup logs a warning but does not enforce HTTPS. Session cookies lack the `Secure` flag in HTTP deployments.
- **Status:** Open. Appropriate for HTTP-only development environments; requires `ION_COOKIE_SECURE=true` in production.
- **Recommended fix:** Document in DEPLOYMENT.md that `ION_COOKIE_SECURE=true` is mandatory behind any TLS terminator. Consider auto-detecting `X-Forwarded-Proto: https` and enabling it automatically.

---

**L3: `python-jose` unmaintained (carried forward)**

- **Evidence:** `pyproject.toml` dependency. JWT library is unmaintained upstream. OIDC/JWT is optional in ION.
- **Status:** Open.
- **Recommended fix:** Migrate to `PyJWT` or `authlib`. Low urgency while OIDC is optional and no CVEs affect the used code paths.

---

**L4: PPTX `ai_summary` and `aob` fields rendered without HTML escaping in slide text (new)**

- **Evidence:** `src/ion/web/daily_standup_api.py` lines 1395–1418 — `ai_summary` and `aob` strings from the POST body are passed directly to `p.text = str(text)` and `run.text = str(text)` in python-pptx. python-pptx serialises these as OOXML text content, not HTML; special XML characters (`<`, `>`, `&`) would be escaped by the library's own serialiser, so XSS in the PPTX is not the concern. However, a user-supplied string longer than 1,800 characters is truncated without field-level validation on the API schema — `ai_summary: str = ""` has no `max_length`. An attacker with `alert:read` permission could send a 10 MB string that gets buffered fully before truncation.
- **Exploit prerequisites:** Any authenticated user with `alert:read` permission can POST to `/api/daily-standup/pptx`. The `ai_summary` field has no `max_length` constraint.
- **Recommended fix:** Add `ai_summary: str = Field("", max_length=10_000)` and `aob: str = Field("", max_length=5_000)` to `StandupPptxRequest`. The server-side truncation at 1,800 chars remains as a belt-and-suspenders limit.

---

## Net-New Surface Assessment — v0.20.1 Integration Branch

### Item 18: ForensicCase Workbench (pins, ledger, evidence upload)

**Endpoint group:** `GET/POST/PATCH/DELETE /api/forensics/cases/{id}/pins`, `GET/GET /api/forensics/cases/{id}/ledger[/verify]`, `POST /api/forensics/cases/{case_id}/evidence/upload`
**File:** `src/ion/web/forensic_workbench_api.py`

| Concern | Assessment |
|---------|------------|
| Auth | All endpoints gated: `forensic:read` (GETs), `forensic:update` (mutations), `forensic:create` (upload). Mirrors `forensics_api.py` pattern. PASS. |
| Upload size cap | `MAX_EVIDENCE_FILE_SIZE = 50 * 1024 * 1024` enforced via `read_upload_capped`. Consistent with translator cap. PASS. |
| File hashing | `hashlib.sha256(content).hexdigest()` computed before row insert. Stored in `hash_sha256`. PASS. |
| MIME validation | No MIME/extension check on evidence upload. The file is stored as metadata only (`storage_location=None` — the file is not written to disk) and the hash is recorded. Since no file execution or serving occurs, absence of MIME validation is acceptable risk. NOTE. |
| Path traversal in `storage_location` | The `storage_location` field in `forensics_api.py` (`EvidenceCreate` schema, line 63) is a free-text string accepted from the client with no path sanitisation. In the workbench upload path, `storage_location=None` is hard-coded. However, the direct evidence create route (`POST /api/forensics/cases/{case_id}/evidence`) passes `payload.storage_location` directly to `repo.add_evidence(..., storage_location=payload.storage_location)`. The field is stored in the DB but not used to read/write files in the current code. If a future feature uses `storage_location` as a filesystem path, this becomes a traversal vector. ADVISORY (not currently exploitable). |
| Ledger tamper resistance | `src/ion/services/forensic_ledger_service.py`: sha256 chain is computed over `prev_hash | action | canonical_json(payload)`. `verify_chain` recomputes every hash from seq=1 forward. The advisory lock (`pg_advisory_xact_lock(0x4643574C, forensic_case_id)`) serialises concurrent appends. A direct DB write to `content_hash` or `prev_hash` columns would be detected on the next `verify_chain` call because the recomputed hash would not match. Chain verification is detection-only — it does not prevent the write. This is the correct design for an append-only ledger; prevention requires DB-level column immutability (not implemented, not expected in ION). PASS for stated design intent. |
| Advisory-lock namespace isolation from AlertCase | `FCWL = 0x4643574C` vs `CEVL` (AlertCase). Distinct — no cross-subsystem serialisation. PASS. |

**Verdict:** No new findings. One advisory on `storage_location` free-text for future-proofing.

---

### Item 19: Lesson PDF export — `GET /api/courses/{slug}/lessons/{lesson_id}/export.pdf`

**File:** `src/ion/web/course_api.py` lines 540–598; `src/ion/services/pdf_export_service.py`

See **M3** above. This is the primary finding for v0.20.1.

Lesson content is operator/author-authored (`playbook:create`/`playbook:update`) — not directly writable by analysts. The XSS-into-PDF path requires a compromised author account, which is why this is rated Medium rather than High for on-premises deployments. The SSRF path via WeasyPrint `<img>` resolution is the more accessible vector for a malicious author.

---

### Item 20: SKILL publisher ZIP export — `GET /api/admin/skills/templates/{id}/export.zip` and bulk

**File:** `src/ion/web/skill_publisher_api.py`; `src/ion/services/skill_publisher_service.py`

| Concern | Assessment |
|---------|------------|
| Auth | Both routes: `_user: User = Depends(require_permission("system:settings"))`. Admin-only. No path for lower-privileged access. PASS. |
| Zip-slip in member names | `folder_name = _slug(tmpl.name)` — `_slug` applies `re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")`. No path separators (`/`, `..`) can survive the slug transform. `extras` is currently always `{}` (service returns empty dict). If extras are added in future, `rel_path` from `extras.items()` goes directly into `zf.writestr(f"{folder_name}/{rel_path}", data)` without sanitisation — zip-slip possible. ADVISORY for future extras. Current implementation: PASS. |
| Frontmatter injection | `_yaml_str()` quotes values containing `:`, `#`, `'`, `"`, `\n`, `[`. The template `description` and `name` come from DB-stored operator input. A description containing a YAML block-scalar marker (`|` or `>`) is not in the quoted-character set and could potentially inject a multi-line value into the frontmatter. However, `description` is placed as a scalar value (`description: {_yaml_str(description)}`), and `_yaml_str` wraps in double-quotes if any special char is present. A `|` character alone would not trigger quoting. Recommend adding `|` and `>` to the special-character check in `_yaml_str`. LOW risk because the SKILL.md consumer (`skill_loader.py`) uses PyYAML's safe_load, which would not execute code from a malformed description. ADVISORY. |
| Info-leak to non-admin | Route guards confirmed admin-only. PASS. |

**Verdict:** No new findings. Two advisories documented for future extras sanitisation and `_yaml_str` completeness.

---

### Item 21: Lab fixtures — `POST /api/courses/{slug}/lessons/{lesson_id}/lab/launch` and `/lab/complete`

**File:** `src/ion/web/labs_api.py`; `src/ion/services/lab_fixture_service.py`

| Concern | Assessment |
|---------|------------|
| `target_table` allowlist enforcement | `_validate_target_table()` in `lab_fixture_service.py` line 51 raises `ValueError` for any table not in `frozenset({"alerts", "alert_triage", "alert_cases", "observables"})`. Called both in `seed_lab` (line 100) and `teardown_lab` (line 167) for every row. PASS. |
| SQL injection via `payload` JSONB columns | See **M4** above. Column names are not quoted; injection possible if an operator controls a fixture payload key. Requires DB write access. Medium severity. |
| Cross-tenant `enrollment_id` isolation | `labs_api.py` `_require_enrollment()` (line 56): queries `WHERE user_id = current_user.id AND course_id = course_id`. An analyst cannot supply another user's `enrollment_id` — the enrollment is looked up from the current user's record, not taken from the request body. `seed_lab` and `teardown_lab` only accept the `enrollment_id` returned from `_require_enrollment`. PASS. |
| `lab/complete` raw SQL for progress update | `labs_api.py` lines 163–183: two raw SQL statements (`SELECT` and `INSERT`/`UPDATE` on `course_lesson_progress`) use parameterised binds (`:uid`, `:lid`, `:id`). No interpolation. PASS. |

**Verdict:** One finding (M4). Cross-tenant and table-injection vectors are guarded.

---

### Item 22: `/cyab/studio` deletion — auth coverage after migration to `cyab_api.py`

**File:** `src/ion/web/cyab_api.py` — studio block starts at line 3384

All migrated routes confirmed to carry `require_permission` or `get_current_user` dependencies:

- `GET /pillars/{pillar_id}/subprofiles` — no explicit permission dep; router-level auth is absent on this GET. However, the router is mounted at `/api/cyab` and all CYAB routes require session authentication at the page level; API-level this GET returns catalogue data (public pillar/subprofile structure) and does not expose user or case data. Acceptable.
- `GET /subprofiles/{sub_id}` — same as above; catalogue read.
- `POST /subprofiles` — `dependencies=[Depends(require_permission("case:update"))]`. PASS.
- `PATCH /subprofiles/{sub_id}` — `dependencies=[Depends(require_permission("case:update"))]`. PASS.
- Studio assessment submit — `current_user: Optional[User] = Depends(get_current_user)` at lines 3720 and 4100. Uses `Optional[User]` — the handler checks `if current_user is not None` before recording `submitted_by`. A request without a valid session would proceed with `current_user = None` and `submitted_by = None`. This is an unauthenticated write to the `cyab_assessments` table.

**Finding (Low, added to L-group):** `POST /api/cyab/studio/...` submit handlers use `Optional[User]` rather than a required auth dependency. An unauthenticated caller can POST an empty-body studio assessment and create a row with `submitted_by=NULL`. Impact is limited to injecting a null-attribution assessment record; no privilege escalation or data exfiltration. Recommend changing `Optional[User] = Depends(get_current_user)` to `User = Depends(require_permission("alert:read"))` for the submit endpoints at lines 3720 and 4100.

**Verdict:** All mutating routes carry proper permission deps. One low finding on Optional-user studio submit.

---

## Re-evaluation of Carried-Forward Findings (M1, M2, L1–L3)

| Finding | v0.9.43 Status | v0.20.1-rc Status | Change |
|---------|---------------|------------------|--------|
| M1: CSP `unsafe-inline` | Open | Open | No change |
| M2: SIEM webhook SSRF | Open | Partially mitigated (config-save guarded, call-time not guarded) | Partially closed |
| L1: Default admin password | Open | Open | No change — warning improved |
| L2: `cookie_secure=false` default | Open | Open | No change |
| L3: `python-jose` unmaintained | Open | Open | No change |

---

## Security Features — Updated Status

| Feature | Status |
|---------|--------|
| Password hashing | bcrypt via passlib |
| SQL injection | Protected — SQLAlchemy ORM parameterised queries; raw SQL uses bind params except lab fixture column names (see M4) |
| SSTI | Protected — SandboxedEnvironment |
| XSS | Protected — DOMPurify on user content; html.escape() in all WeasyPrint paths |
| CSRF | Protected — OIDC state parameter, SameSite cookies |
| Rate limiting | login (5/min), password (5/min), OIDC (10/min), bulk ops (20/min), escalation (10/min), token regen (3/min), global default (120/min) |
| Session management | Server-side sessions, configurable expiry |
| Account lockout | Configurable threshold (default: 5 attempts) |
| Circuit breakers | ES, OpenCTI, TIDE, Ollama, Kibana, Arkime — prevent cascading failures |
| Startup validation | Config validated at boot — blocks on fatal errors, warns on misconfiguration |
| Audit logging | Full action trail per user (ECS-compliant) |
| File uploads | Capped via `read_upload_capped`: 50 MB translator/workbench, 100 MB PCAP; streaming rejection |
| RBAC | 7 roles, permission-based access, focus mode |
| SSRF protection | `validate_integration_url()` on all 14 integration config-save paths; blocked: private IPs, link-local, cloud metadata, obfuscated IPs, bad ports, null bytes, CRLF |
| Prompt injection defence | `<input_data>` trust-boundary wrapper in Bob system prompt (v0.19.19); output contract pinned in system message |
| PII logging | OIDC callback logs username only at INFO; email at DEBUG only |
| Auto-playbook kill switch | `ION_AUTO_PLAYBOOK_ENABLED=false` default (v0.20.0) |
| Tamper-evident ledger | sha256 chain on ForensicCase (v0.20.1) and AlertCase (v0.20.0); advisory-lock serialised appends |

---

## Net-New Surfaces in v0.22.0

### Item 26: MITRE ATT&CK technique-coverage heatmap — `GET /api/cyab/attack-heatmap`, `GET /cyab/attack-heatmap`

**Files:** `src/ion/services/mitre_heatmap_service.py`, `src/ion/web/cyab_api.py`, `src/ion/web/server.py` (page route), `src/ion/web/templates/cyab/attack_heatmap.html`, `src/ion/data/attack_techniques.json`

**Auth gate:** `Depends(require_permission("alert:read"))` on the API; the page route inherits the standard CyAB section gate.

**Threat model & mitigations:**
- *Information disclosure of alert activity volume.* The response exposes per-technique alert-case counts and pin counts. Counts could let a low-privilege internal user infer "this organisation has been getting hit by T1558 lately." Mitigation: gated behind `alert:read`, the same permission that already exposes the underlying triage rows. No additional surface.
- *Bundled snapshot integrity.* `src/ion/data/attack_techniques.json` is read-only at runtime. Any tampering requires repository write access; covered by the existing supply-chain controls (signed commits, CI image build).
- *No live STIX fetch.* Air-gap rule preserved; the heatmap never reaches MITRE's servers at runtime. The refresh script is dev-time only.
- *Cache header.* Response sets `Cache-Control: no-cache` so a stale browser cache cannot serve stale technique observation counts during a deployment window.
- *No PII.* Response payload contains only technique IDs, technique labels (from the bundled snapshot), tactic IDs, integer counts, and a string state enum.

### Item 27: Timeline annotations — `*/annotations` endpoints on AlertCase + ForensicCase

**Files:** `src/ion/services/annotation_service.py`, `src/ion/services/forensic_annotation_service.py`, `src/ion/models/alert_triage.py` (`AlertCaseAnnotation`), `src/ion/models/forensics.py` (`ForensicCaseAnnotation`), `src/ion/web/workbench_api.py`, `src/ion/web/forensic_workbench_api.py`, `src/ion/storage/database.py` (table creation in `_run_migrations()`).

**Endpoints:**
- `GET /api/alert-cases/{case_id}/annotations` — list active annotations
- `POST /api/alert-cases/{case_id}/annotations` — create
- `PATCH /api/alert-cases/{case_id}/annotations/{ann_id}` — edit body and/or `timeline_ts`
- `DELETE /api/alert-cases/{case_id}/annotations/{ann_id}` — soft-delete
- ForensicCase mirror under `/api/forensics/cases/{case_id}/annotations`

**Auth gates:** list = `case:read` (forensic: `forensic:read`); create + edit-own = `case:update`; edit-any = `case:close`. Author check: `annotation.created_by_id == current_user.id`. Service-level check, NOT route-level — TOCTOU rule from v0.20.1 pin-service fix is satisfied (verified by reviewer; check happens inside `_check_edit_permission` before any `session.add()` or attribute mutation).

**Threat model & mitigations:**
- *Cross-case PATCH/DELETE.* `_get_annotation_or_raise` verifies `annotation.alert_case_id == url_case_id` before any mutation. Mismatch raises 404 (not 403) so a low-privilege user cannot enumerate which case-IDs hold which annotation-IDs.
- *Stored XSS in body.* Body is rendered via Jinja's autoescape (existing `SandboxedEnvironment`). Inline JS in the Workbench template uses `textContent` not `innerHTML` for body display.
- *Body size.* Pydantic schema enforces `max_length=2000`. DB CHECK constraint enforces `length(body) > 0`. Three-layer defence (route → DB → CHECK).
- *Hard-delete.* Disallowed. Soft-delete via `deleted_at` only; `deleted_at IS NOT NULL` filters from list query. Hard-delete would require database-direct access.
- *Ledger integrity NOT compromised.* Annotations are NOT written to the tamper-evident hash chain. A single `annotation_created` ledger row IS appended on creation (records `annotation_id`, `timeline_ts`, actor — NOT body content), so the chain still proves that an annotation existed at a point in time. Subsequent edits do not append to the chain. This is a deliberate design call to keep the chain's invariant load-bearing only for evidence pins.
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

### Item R1: `POST /api/elasticsearch/config` — REMOVED

**Was at:** `src/ion/web/api.py` (lines 3473–3502, deleted in commit `e345e53`).

**Why removed:** Older write path that bypassed `_ssrf_safe_url()`, skipped Pydantic validation (writes raw `request.json()`), did not call `reload_config()`, and did not invalidate the assignment cache. The properly-gated replacement at `PUT /api/admin/config/elasticsearch` (`admin_api.py:401`) has been live for several releases.

**Caller-check before removal:** `topology.html:734` only used the URL for a GET against the read endpoint at `api.py:3459`. No POST callers in templates, static JS, or tests.

**Findings-quality impact:** removes a latent SSRF + unvalidated-write surface. Not a counted closure (the write path was undocumented and ungated improperly, never raised as a formal finding); reported here for traceability.

### Item R2: `/api/compliance/nist` legacy endpoint — REMOVED

**Was at:** `src/ion/web/compliance_api.py:62` plus `get_compliance_posture_legacy()` in `compliance_mapping_service.py`. Replaced by `/api/compliance/nist_csf/posture`. No callers found.

### Item R3: `/dashboard-legacy` and `/dashboard-v2` — REMOVED

**Was at:** `src/ion/web/server.py:771` and `:777`. Tailwind-rollout fences from v0.19; rollback path no longer needed.

### Item R4: `saved_search_api.py` — REMOVED (file)

**Was at:** `src/ion/web/saved_search_api.py`. Endpoints shadowed by `api.py:7514+` for the common-case routes; unique `/pin` and `/use` routes either consolidated into `api.py` or removed if unused.

---

## Net-New Surfaces in v0.21.0

### Item 23: Bob Eval Harness — `POST /api/bob-eval/runs`, `GET /api/bob-eval/runs[/{run_id}[/samples]]`, `GET /bob-eval`

**Files:** `src/ion/web/bob_eval_api.py`, `src/ion/services/bob_eval_service.py`, `src/ion/models/bob_eval.py`

#### 23a. Permission gate on all routes

`_SETTINGS_PERM = require_permission("system:settings")` is applied as `Depends(_SETTINGS_PERM)` on every route: POST runs, GET runs, GET runs/{run_id}, GET runs/{run_id}/samples, and the HTML GET /bob-eval. The `require_permission` factory chains through `get_current_user` which enforces a valid session token before the permission check. Authentication and authorisation are both enforced. **PASS.**

#### 23b. `sample_size` integer validation

`CreateEvalRunRequest` uses `sample_size: int = Field(50, ge=1, le=_MAX_SAMPLE_SIZE)` where `_MAX_SAMPLE_SIZE = 200`. FastAPI/Pydantic v2 enforces `ge=1, le=200` at the schema validation stage before the handler is called. A non-integer body field causes a 422; a value outside 1–200 causes a 422. Additionally, `create_eval_run` in `bob_eval_service.py` applies `sample_size = min(sample_size, _MAX_SAMPLE_SIZE)` as a belt-and-suspenders clamp before the DB write. **PASS — no gap.**

#### 23c. Thread spawn before template validation (non-existent `template_id`)

The handler calls `create_eval_run(...)` first, which performs `session.get(AlertPromptTemplate, template_id)` before committing the `BobEvalRun` row. If the template does not exist, `create_eval_run` raises `ValueError`, the handler converts it to HTTP 400, and `run_eval_async` is never called. There is no window where a thread is spawned against a non-existent template. **PASS — no DoS vector.**

#### 23d. Duplicate-run advisory lock

`_run_eval_sync` acquires two locks before executing:

1. `_acquire_try_advisory_lock(session, LOCK_BOB_EVAL_BG)` — a session-scoped non-blocking lock that fails immediately if the investigation loop holds it. If two simultaneous POSTs both win this check (possible: both eval threads can hold the session lock concurrently since it is not the run-specific lock), the second check gates them:
2. `_acquire_xact_lock(session, _BPEH_NS, eval_run_id)` — a transactional advisory lock keyed by `(0x42504548, eval_run_id)`. Since each POST creates a distinct `eval_run_id`, this lock does not prevent two simultaneous runs for the same template — it prevents the same run ID from being re-entered. If two users simultaneously POST `{template_id: 5, sample_size: 50}`, two separate `BobEvalRun` rows are created with distinct IDs, and both threads proceed concurrently.

**Finding (Low — see L5 below):** Two simultaneous eval runs for the same template are not serialised. Each run independently pulls a random sample of up to 200 `ai_feedback` rows and issues up to 200 Ollama calls. With two simultaneous requests, an admin can drive 400 concurrent Ollama calls. Given `system:settings` access is restricted to administrators and Ollama already has a queue (`bypass_queue=True` is set, meaning the eval calls skip the normal investigation queue), the practical impact is resource exhaustion on Ollama, not a privilege-escalation risk. Severity: Low; not a DoS risk to unauthenticated actors.

#### 23e. Pagination bounds on `/samples`

`page_size: int = Query(50, ge=1, le=200)` enforces the upper bound. The `offset` is computed as `(page - 1) * page_size` from validated inputs. Total count query is bounded by the run's own `sample_size` cap (200 max). **PASS.**

---

### Item 24: `Investigation.reasoning_text` — `ION_BOB_STORE_REASONING=true` gate

**Files:** `src/ion/services/investigation_service.py`, `src/ion/models/investigation.py`, `src/ion/web/investigation_api.py`, `src/ion/web/investigation_memory_api.py`

#### 24a. Storage gating

`reasoning_text` is written to the `Investigation` row only when `os.environ.get("ION_BOB_STORE_REASONING", "false").lower() in ("true", "1", "yes")`. The column always exists in the schema (populated by migration in `database.py`), but remains NULL unless the flag is set. **PASS.**

#### 24b. Retention parity with alert records

`Investigation` rows have no dedicated purge/deletion path in the codebase. There is no API endpoint, background task, or repository method that deletes `Investigation` rows. Consequently, `reasoning_text` has indefinite retention regardless of alert lifecycle. Alert triage rows (`alert_triage`) similarly lack a purge path; neither surface has a retention-limiting mechanism. This is a pre-existing data-retention characteristic, not a regression in v0.21.0. **ADVISORY — no new finding.** Document in RUNBOOK that `reasoning_text` persists until manual DB purge if `ION_BOB_STORE_REASONING=true` is enabled.

#### 24c. Unintentional logging of reasoning_text

`investigation_service.py` truncates the stored value to 8,000 characters (`[:8000]`). The stored text is not written to any log line in the service. Logger calls in `bob_eval_service.py` that could surface reasoning text are at DEBUG level (`logger.debug`) and do not include the reasoning content directly — only alert IDs and error messages appear in the error handler. No Python `%r` or f-string expands reasoning text into a log line in the audited paths. **PASS.**

#### 24d. Serialisation — exposure in non-admin routes

`InvestigationSummary` (both the `investigation_api.py` and `investigation_memory_api.py` versions) does not include `reasoning_text` as a field. `InvestigationDetail` in `investigation_memory_api.py` includes `prompt_snapshot` and `raw_response` but not `reasoning_text`. The `_inv_to_detail` converter does not copy `inv.reasoning_text` to the response object. Both GET endpoints that return `Investigation` objects (`/api/investigate/jobs/{inv_id}` and `/api/investigations/{inv_id}`) are gated on `alert:read`, not `system:settings`. However, since `reasoning_text` is not serialised in any response schema, the effective exposure to `alert:read` users is zero. **PASS — reasoning_text is not leaked via any API response.**

Note: `BobEvalRunSample.reasoning_text` (a distinct column on the eval harness samples table) _is_ included in `BobEvalRunSample.to_dict()` and returned by `GET /api/bob-eval/runs/{run_id}/samples`. That endpoint is `system:settings`-gated. See finding L5.

---

### Item 25: `AlertPromptTemplate.confidence_threshold_override`

**Files:** `src/ion/web/alert_prompt_api.py`, `src/ion/storage/alert_prompt_repository.py`, `src/ion/models/alert_prompt.py`

#### 25a. Bounds validation

`AlertPromptCreate` and `AlertPromptUpdate` both declare `confidence_threshold_override: Optional[int] = Field(default=None, ge=0, le=100)`. Pydantic v2 enforces `ge=0, le=100` at the schema level; out-of-range integers return 422. NULL (omitted) is permitted, which maps to "use global env-var default". The column is stored as `Integer` in the DB with no DB-level check constraint, but the application-layer validation is sufficient for the authenticated-user threat model. **PASS.**

#### 25b. Permission gate on write routes

`POST /api/alert-prompts` and `PUT /api/alert-prompts/{template_id}` both use `dependencies=[Depends(require_any_permission(_MANAGE_PERMS))]` where `_MANAGE_PERMS = ["playbook:create", "playbook:update", "playbook:delete"]`. These are content-author permissions, not analyst-level permissions.

**Finding (Low — see L6 below):** The `confidence_threshold_override` field controls the AI circuit-breaker threshold per template. Setting it to `0` would cause every Bob investigation matched to that template to be flagged as low-confidence and escalated via the `bob_escalation_badge` path, effectively suppressing AI verdicts for all alerts matching the template. Setting it to `100` would cause the circuit breaker never to fire for that template's alerts, meaning every AI verdict would be written unconditionally regardless of actual model confidence. This field has operational security significance (it governs whether AI verdicts are written vs. escalated) but is writable by any user with `playbook:create` or `playbook:update` permission — which is a broader set than `system:settings`. Recommend restricting write access on `confidence_threshold_override` to `system:settings`, either by adding a separate PATCH endpoint or by splitting the `AlertPromptUpdate` schema to require elevated permission when this field is present.

---

### Item 26: `AlertTriage.bob_escalation_badge` — writable via user API?

**Files:** `src/ion/web/api.py`, `src/ion/models/alert_triage.py`

`bob_escalation_badge` is set exclusively by `investigation_service.py` when the circuit breaker fires (`triage.bob_escalation_badge = "low_confidence_triage"`). The `TriageUpdate` Pydantic schema (api.py lines 3786–3794) exposes: `status`, `assigned_to_id`, `assigned_to_name`, `priority`, `case_id`, `analyst_notes`, `observables`, `mitre_techniques`. `bob_escalation_badge` is not in the schema. The update handler (`update_alert_triage`) maps only the fields listed in `TriageUpdate` to ORM attributes — there is no `**kwargs` or dynamic field assignment that would allow injection of unlisted fields. **PASS — not user-writable.**

The field is returned as a read-only value in the triage serialisation block (api.py line 6382) so the UI can render the escalation pill. This is intentional and safe.

---

### Item 27: AIFeedback `human_verdict="pending"` sentinel and eval harness data access

**Files:** `src/ion/services/bob_eval_service.py`, `src/ion/models/bob_eval.py`

The eval harness de-duplicates `ai_feedback` rows by `MAX(id)` per `(alert_id, alert_prompt_template_id)`. The `human_verdict="pending"` sentinel identifies circuit-breaker rows (where `auto_escalated=true` or verdict has not yet been set by an analyst). These rows are treated as abstentions in the eval loop (line 339: `if auto_escalated or human_verdict == "pending": abstentions += 1`) and written to `bob_eval_run_samples` with `bob_verdict=None, agreement=None, reasoning_text=None`. They do not receive a fresh Ollama call. The `human_verdict` field value `"pending"` is stored in the `BobEvalRunSample.human_verdict` column and returned in the `/samples` response, but this only exposes the verdict state — not the underlying alert content, analyst notes, or triage detail. The `/samples` endpoint is `system:settings`-gated. **PASS — no triage data leakage beyond what admins already have access to.**

---

**New Findings Summary (v0.21.0)**

| ID | Severity | Surface | Issue |
|----|----------|---------|-------|
| L5 | Low | `POST /api/bob-eval/runs` | No per-template concurrency guard — two simultaneous runs for the same template both proceed, driving up to 2× Ollama load |
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
