<!-- ion-doc:type=SECURE BY DESIGN -->
<!-- ion-doc:title=ION Secure by Design Principles + Audit -->
<!-- ion-doc:subtitle=20 numbered principles synthesized from NCSC, CISA, NIST SSDF, OWASP, and Saltzer & Schroeder; ION-specific application + audit status per principle -->
<!-- ion-doc:version=0.31.15 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Architects, security reviewers, integrators, external assessors -->
<!-- ion-doc:date=2026-05-26 -->

# ION — Secure by Design Principles

> A canonical, customer-agnostic principle list for ION. The principles
> below are synthesized from public industry and government frameworks;
> each one carries an ION-specific application guide and an audit
> status. This is the authoritative reference for "what does Secure by
> Design mean to ION?"; `docs/DEVELOPMENT_LIFECYCLE.md` is the
> phase-by-phase SDLC and is harmonised with the principles below.

## 1. Purpose and audience

This document exists to:

* state the secure-design properties ION targets in plain terms;
* give every contributor a checklist to apply during design and review;
* give an external assessor a single page to evaluate ION against.

It is **not** a tutorial. Read the source frameworks below if you need
background.

## 2. Sources

The principles below are synthesised from these public, freely-available
frameworks. None of the principles is attributed to a single source;
where a principle is paraphrased from a single source the reference is
in the principle body itself.

* **NCSC Secure Design Principles** (5 principles, attack-stage framing)
* **NCSC Secure Development and Deployment Principles** (8 principles,
  team and pipeline framing)
* **CISA Secure by Design** (three core principles plus tactical action
  list — published with international partners)
* **NIST SP 800-218 Secure Software Development Framework (SSDF)** —
  four practice groups: Prepare the Organization (PO), Protect the
  Software (PS), Produce Well-Secured Software (PW), Respond to
  Vulnerabilities (RV)
* **OWASP Secure Architecture** practice (SAMM) and **OWASP Top 10:2025**
* **Saltzer & Schroeder (1975)** — the classical eight: economy of
  mechanism, fail-safe defaults, complete mediation, open design,
  separation of privilege, least privilege, least common mechanism,
  psychological acceptability

ION targets the **intersection** of these frameworks — anything every
serious framework agrees on, we adopt. Where frameworks disagree we
favour the stricter rule.

## 3. The principles

Each principle below carries:

* **What it means** — the rule in plain terms.
* **Why** — what failure mode the rule prevents.
* **ION application** — how the rule is applied in this codebase, with
  file or feature references where load-bearing.
* **Status** — `Met` / `Mostly Met` / `Partial` / `Gap`. The §4 audit
  summary aggregates these.

### Govern (organisation-level)

#### P1. Security is everyone's concern

**What it means.** Security cannot be the responsibility of a single
team or person; it must be part of every design and code review.

**Why.** Centralising security creates a bottleneck *and* a single
point of failure. Bugs caught in design are 10–100× cheaper than bugs
caught in production.

**ION application.**
* `CONTRIBUTING.md` (v0.31.9) codifies the security-review
  expectations any future contributor follows: pre-commit hooks,
  Secure-by-Design walk per change, `SECURITY_ASSESSMENT.md` update
  gate for any new attack surface. Even with one maintainer today,
  the policy is explicit so an external auditor (or future
  contributor) sees a single consistent process.
* `CODEOWNERS` (v0.31.9) routes review responsibility per path. With
  one maintainer it's a no-op; once a second contributor joins, it
  unlocks branch-protection rules (P15 closure path).
* `.claude/agents/security-reviewer.md` (v0.31.9) — focused agent
  that walks the diff against the 20 principles before commit.
  Materialises "AI pair-programmer reviews every change" from
  implicit practice to a callable workflow step (invoke via
  `/agents security-reviewer`).
* `.pre-commit-config.yaml` (v0.31.9) — `ruff` + `bandit` +
  `pip-audit` run at the workstation BEFORE every commit, mirroring
  the CI gates so issues are caught at design time, not after push.
* Every commit message lists what the change is and why; release
  commits carry a `SECURITY_ASSESSMENT.md` delta documenting any new
  attack surface.
* The single-maintainer model (with AI as second-reviewer) is a
  known structural limit of this principle — the literal "everyone"
  in "everyone's concern" requires multiple humans. For
  higher-assurance deployments, the customer-side Designated
  Security Officer pattern in `docs/DEVELOPMENT_LIFECYCLE.md` §6.4
  is the recommended additional control.

**Status:** Mostly Met (v0.31.9). The single-maintainer model
prevents reaching Met without onboarding a second human reviewer;
the six artifacts above bring the pattern as close to "Met" as a
single-maintainer project structurally can.

#### P2. Senior accountability for product security

**What it means.** Someone with the authority to halt a release owns
the security posture and signs off every material change.

**Why.** Without named accountability, security decisions drift toward
"easy" rather than "correct" under release pressure.

**ION application.**
* The maintainer is the named accountable owner. The
  `SECURITY_ASSESSMENT.md` is signed by them per release.
* The `chore(release)` commit pattern (`docs/DEVELOPMENT_LIFECYCLE.md`
  §3.4.2) makes the release sign-off visible in `git log`.

**Status:** Met for the single-maintainer model.

#### P3. Radical transparency

**What it means.** Make the vulnerability policy, security posture,
SDLC, and change history public; do not rely on obscurity for trust.

**Why.** External assessors and downstream operators need evidence;
hidden process erodes trust.

**ION application.**
* `SECURITY.md` (added v0.30.0) — disclosure channels, supported
  versions, severity-tiered SLAs.
* `SECURITY_ASSESSMENT.md` — per-release security audit with severity
  trend table.
* `CHANGELOG.md` — full per-release record going back to v0.9.43.
* `docs/DEVELOPMENT_LIFECYCLE.md` — public SDLC; this doc is its
  principles companion.
* MIT licence on the source.

**Status:** Met.

### Design

#### P4. Establish context

**What it means.** Know what the system does, what data it processes,
who uses it, and where the trust boundaries are — before designing
controls.

**Why.** Controls without context default to either too tight (and get
disabled) or too loose (and miss the actual threat).

**ION application.**
* `docs/ARCHITECTURE.md` + `docs/HLD.md` document the data flows and
  integration boundaries.
* `docs/DEVELOPMENT_LIFECYCLE.md` §3.3.2 makes threat modelling a
  required step for every material change.
* Each integration (Elasticsearch, Kibana, TIDE, OpenCTI, Arkime,
  Keycloak, Ollama) has a documented threat model under
  `test-<integration>/` and an `ION_<NAME>_*` env-var family.

**Status:** Met.

#### P5. Defence in depth

**What it means.** Every authority decision is enforced at multiple
independent layers. If one layer fails, the system still resists.

**Why.** A single line of defence is one bug away from a full
compromise. The v0.20.1 pin-service TOCTOU bug is the canonical
ION example of why this matters.

**ION application.**
* Route layer: FastAPI `dependencies=[Depends(require_permission(...))]`
  on every protected endpoint.
* Service layer: every mutation re-checks authorisation **inside the
  service** before commit (v0.20.1 TOCTOU rule, applied to both pin
  services and both annotation services).
* UI layer: visibility hints only — never the authoritative gate.
* Database layer: per-row foreign-key integrity, soft-delete instead
  of hard-delete on tamper-evident structures (Workbench ledger).

**Status:** Met. The TOCTOU rule is encoded in `CLAUDE.md` and audited
by the `workbench-ledger-reviewer` agent on every Workbench change.

#### P6. Least privilege

**What it means.** Every actor (human, service, integration) holds the
minimum capability needed and no more. Deny by default.

**Why.** A compromised actor can only do what they were authorised to
do. Wide grants compound the blast radius.

**ION application.**
* Seven RBAC roles — `analyst`, `senior_analyst`, `principal_analyst`,
  `lead`, `forensic`, `engineering`, `admin` — each with a curated
  permission set. New permissions ship with their role assignment.
* **Focus mode** (`UserSession.active_role_id`) — even users with
  multiple roles are restricted to one *active* role per session.
  Switch costs are visible (audit row); silent escalation is not
  possible.
* Integrations use service-account credentials with the minimum index
  / scope grants needed (documented in `docs/DEPLOYMENT.md`).
* Database connection runs as the application user, not a superuser.

**Status:** Met.

#### P7. Secure defaults (fail-safe defaults)

**What it means.** Out-of-the-box configuration is the secure
configuration. Insecure modes require explicit opt-in with documented
risk.

**Why.** The 90% case is operators who do not customise; "secure if
configured" means "insecure in practice".

**ION application.**
* `.env.deploy` template ships a secure-default config.
* `ION_BOB_STORE_REASONING=false` by default (PII implication
  documented).
* Cookie `Secure` flag warned at startup when missing.
* Debug mode default-off.
* Admin password forced to be non-default in production.
* `ION_BOB_CONFIDENCE_THRESHOLD=60` default — strict-enough to
  auto-escalate genuinely-uncertain triages.

**Status:** Met.

#### P8. Complete mediation

**What it means.** Every access to every protected resource is checked
at the authoritative point, every time. No caching of authorisation
decisions across trust boundaries.

**Why.** Cached authorisation is a TOCTOU bug waiting to be found.

**ION application.**
* `require_permission(...)` runs on every request; no session-side
  cache of permissions older than the in-process LRU (3-5s, planned)
* Service mutations re-fetch the authoritative record and re-check
  ownership before mutating (v0.20.1 rule).
* Database constraints (FK, UNIQUE, CHECK) are the last line of
  defence — application-side validation is not assumed sufficient.

**Status:** Met.

#### P9. Economy of mechanism (simplicity)

**What it means.** Prefer simple, auditable code over clever code.
Complexity is where bugs hide.

**Why.** A reviewer can only catch bugs in code they can hold in
their head. Every dependency, every abstraction layer, every
generic-over-type fan-out is more surface for the reviewer to miss.

**ION application.**
* Server-rendered HTML, no SPA — one stack, one mental model.
* No JS framework. DOMPurify for HTML sanitisation, vanilla JS for
  the rest.
* SQLAlchemy ORM throughout — one query idiom across the codebase.
* Single Python package, single FastAPI app, single Dockerfile.
* Trade-off recorded: `src/ion/web/api.py` is large (~7000 lines)
  because we accept monolithic API code over premature splitting.

**Status:** Met (with documented trade-off).

#### P10. Open design

**What it means.** Security must not rely on the secrecy of mechanism.
The algorithm must survive publication; only the keys remain secret.

**Why.** Obscurity-only mechanisms fail catastrophically when leaked,
and they leak.

**ION application.**
* Source published on GitHub under MIT.
* Threat model and SDLC public.
* Bundled snapshots (ATT&CK, KEV) are public reference data; only
  customer-controlled `.env` values are secret.
* JWT signing uses RS256 (asymmetric); the public key can be
  published.

**Status:** Met.

#### P11. Don't trust input

**What it means.** Every input crossing a trust boundary is validated,
treated as adversarial, and never propagated raw into queries, paths,
HTML, shell, or downstream systems.

**Why.** Injection attacks (SQL, XSS, command, path, prompt) all
descend from this principle.

**ION application.**
* SQL: SQLAlchemy ORM with bound parameters throughout. Raw `text()`
  with bound parameters where ORM is impractical (see
  `tests/test_v032_sqlenum_name_storage.py` for the SQLEnum subtlety).
* HTML: Jinja2 `SandboxedEnvironment` + DOMPurify on dynamic
  client-side renders.
* Path: `target_table` allow-list + column-name regex validation in
  `lab_fixture_service` (v0.20.1).
* Shell: bandit `-r src/` runs in CI with `B602`/`B608` skips
  audited and documented.
* Prompt injection: AI prompts ship a fixed system prompt; user
  content is delimited and never executes; circuit breaker auto-
  escalates low-confidence LLM verdicts (v0.21.0).
* PDF: WeasyPrint's external-URL fetcher is blocked
  (`_block_external_url_fetcher`, v0.20.1).
* CSP `script-src` / `style-src` now use **per-request nonces** —
  every inline `<script>` and `<style>` block carries a 16-byte
  CSPRNG nonce minted at request time by `SecurityHeadersMiddleware`
  and exposed to Jinja as `{{ csp_nonce }}` (v0.31.3). Inline event
  handlers (`onclick=`) and inline `style=""` attributes are still
  permitted via `script-src-attr` / `style-src-attr` `'unsafe-inline'`
  — these remain a future-tightening target.
* **Delegated event listener** (v0.31.4+) — `static/js/event-delegation.js`
  registers a single document-level listener per event type and
  dispatches based on `data-*-action` attributes. Templates being
  migrated swap `onclick="foo()"` → `data-click-action="foo"`.
  Per-element `data-args='[…]'` JSON or per-event `data-${event}-args`
  carry positional arguments; sentinel tokens `$event` / `$value` /
  `$checked` / `$target` substitute at dispatch time. Built-in
  shortcuts cover modal-close (`data-close-target` / `data-remove-target`),
  modal-backdrop (`data-close-on-self-click` /
  `data-remove-self-on-self-click`), ancestor removal
  (`data-remove-parent` / `data-remove-closest`), and optional-script
  error flags (`data-script-onerror-flag`). As of v0.31.7,
  **base.html + cases.html + alerts.html + training.html** are fully
  migrated (7 + 48 + 194 + 119 = 368 handlers).
  `tools/migrate_inline_handlers.py` mechanically translates the
  common patterns; v0.31.7 added detection for the `\'` / `\"`
  JS-source-escape pattern (handler inside a JS string-concat) so the
  script reports those for hand-fixing instead of emitting broken
  output. The remaining 69 templates carry ~650 `onclick=` + ~1,650
  inline `style=""` and are queued for per-template migration. Once all are migrated, `script-src-attr 'none'`
  and `style-src-attr 'none'` can be enforced and P11 moves to Met.

**Status:** Mostly Met — inline event handlers + inline `style=""`
attributes still permitted; full strict-CSP requires refactoring those
to `addEventListener` + CSS classes.

#### P12. Make compromise detection easier

**What it means.** Design the system so that malicious behaviour leaves
visible traces in real time and after the fact.

**Why.** Compromise happens; detection time directly determines blast
radius.

**ION application.**
* ECS-compliant structured logging across every router and service.
* `audit_logs` table — every authority decision (login, role switch,
  case linkage, observable extraction, lab launch/complete, etc.)
  writes a row.
* **Workbench tamper-evident ledger** (`case_evidence_ledger`,
  `forensic_case_ledger`) — sha256 chain, verifiable from any seq.
  Tamper detection surfaces in the UI banner.
* Bob's verdict ledger (`AIFeedback`) is dual-write fire-time +
  case-close; dedup via `MAX(id)`.
* Daily standup `/daily-standup` aggregates real-time alert + case
  counters for shift-handover visibility.

**Status:** Met. Metrics endpoint + log-shipping spec are
`docs/DEVELOPMENT_LIFECYCLE.md` §8 gaps.

#### P13. Reduce impact of compromise

**What it means.** When (not if) something is compromised, the blast
radius is contained.

**Why.** All controls fail eventually. Containment limits the cost.

**ION application.**
* Air-gap-first deployment pattern — most ION customers run with no
  outbound internet; lateral movement to ION from the wider internet
  is not in the threat model.
* Container isolation — ION runs as non-root in Docker, with explicit
  capability drops (see `docker-compose.yml`).
* No shared secrets between integrations — each integration has its
  own credential set.
* `closure_reason` enum limits the verdict surface; free-text
  reasoning is gated by `ION_BOB_STORE_REASONING`.
* Database `closure_reason`, audit_log, and Workbench tables are
  append-only or soft-delete only; hard-delete is forbidden.
* **Formal data-minimisation audit (v0.31.12)** — `docs/DATA_MINIMISATION_AUDIT.md`
  walks every Tier 1 / Tier 2 PII-carrying or free-text-bearing
  table in the ~100-table schema. Catalogues 13 existing data-min
  controls (air-gap deployment, bcrypt password hash, closure_reason
  enum, ION_BOB_STORE_REASONING gate, append-only ledgers with
  sha256 chain, soft-delete, per-user session cleanup at login,
  TLP/PAP markings, etc.); identifies 5 low-severity residual gaps
  (system-wide session cleanup, audit_logs / security_events
  retention env vars, optional AI chat retention, session_token
  hash-at-rest) all tracked as v0.32+ work and all bounded by the
  air-gap deployment + RBAC + container isolation controls.
* **G1 closure (v0.31.13)** — first behaviour change against the
  audit. New `src/ion/services/session_cleanup_service.py`
  background loop wraps `AuthService.cleanup_expired_sessions()` and
  runs it on a configurable cadence (default 6h) under advisory
  lock `LOCK_SESSION_CLEANUP_BG`. Honours
  `ION_SESSION_CLEANUP_ENABLED` (opt-out) and
  `ION_SESSION_CLEANUP_INTERVAL_HOURS`. Reduces dormant-user PII
  retention (`user_sessions.ip_address` / `user_agent`) from
  "indefinite" to "≤ interval after expiry".
* **G4 closure (v0.31.15)** — one-line extension of the
  parameterised retention service. New `ION_AI_CHAT_RETENTION_DAYS`
  env var (default unset = disabled). When set, sweeps
  `ai_chat_messages.created_at` on the existing daily cadence.
  Sessions left untouched — user-controlled session deletion
  remains the mechanism for full conversation removal. One gap
  remains (G5 — `session_token` hash-at-rest).
* **G2 + G3 closure (v0.31.14)** — parameterised retention service.
  New `src/ion/services/data_retention_service.py` holds a list of
  `RetentionRule(env_var, model, timestamp_column)` tuples; current
  rules cover `audit_logs.timestamp` and `security_events.created_at`.
  Single background loop under advisory lock `LOCK_DATA_RETENTION_BG`
  sweeps every rule whose env var is set. New env vars:
  `ION_AUDIT_LOG_RETENTION_DAYS` and `ION_SECURITY_EVENTS_RETENTION_DAYS`
  (both unset by default — operators opt in per deployment because
  compliance windows vary wildly across jurisdictions). Loop
  cadence: `ION_DATA_RETENTION_INTERVAL_HOURS` (default 24h);
  whole-loop kill switch: `ION_DATA_RETENTION_ENABLED` (default true).
  Two gaps remain (G4 — AI chat retention is the next natural rule
  to append; G5 — `session_token` hash-at-rest).

**Status:** Met (v0.31.12). Audit produced; residual gaps documented
and tracked the same way P11's template-migration backlog is — they
are defence-in-depth improvements, not unresolved attack surface.
See `docs/DATA_MINIMISATION_AUDIT.md`.

### Build & Verify

#### P14. Clean, maintainable code

**What it means.** Code is consistent, scoped, documented where
non-obvious, and reviewed by tooling.

**Why.** Reviewers catch bugs proportional to how easily they can
read the code.

**ION application.**
* `ruff check src/` returns 0 errors as of v0.26.0; line-length 200;
  per-file ignores documented inline in `pyproject.toml`.
* `bandit -r src/ --skip B602,B608,B101 -lll` runs in CI; the three
  skips are documented per ION's threat model.
* `pytest` test suite with `tests/integration/` for HTTP-level
  contract tests; new-feature regression tests pinned per release.
* CLAUDE.md and the `release-bump` skill encode the 8-file release
  ritual so version drift is prevented mechanically.

**Status:** Met.

#### P15. Secure your code repository

**What it means.** The repository itself is a security control. Access,
history integrity, and review are part of the trust chain.

**Why.** A compromised repo is a compromised release.

**ION application.**
* GitHub private repository.
* SSH-keyed access; HTTPS push uses a Windows credential helper.
* `main` is the only release-eligible branch.
* No secrets in history — `.env` is gitignored; `.env.deploy` is a
  template only.
* **Branch protection on `main`** (v0.31.0 Tier 1; v0.31.10 Tier 2):
  `required_linear_history=true`, `allow_force_pushes=false`,
  `allow_deletions=false`, `required_signatures=true`. The single
  maintainer can still direct-push (`enforce_admins=false`); the
  `required_pull_request_reviews` rule activates when a second
  maintainer joins.
* **Signed commits** (v0.31.10) — all commits on `main` are
  SSH-signed against an ed25519 key dedicated to GitHub commit
  signing (`~/.ssh/id_ed25519_github`, registered as a Signing Key
  on the maintainer's GitHub account). Verification chain:
  `gpg.format=ssh` + `user.signingkey` + `gpg.ssh.allowedSignersFile`
  → `~/.config/git/allowed_signers`. Committer identity uses the
  GitHub noreply form so signatures resolve against an
  account-verified address; GitHub renders a "Verified" badge per
  commit and `git verify-commit` returns success locally.

**Status:** Met (v0.31.10). Branch protection enforced server-side
and signed commits required. The single-maintainer workflow is
preserved via `enforce_admins=false`; required PR reviews will be
re-enabled when a second human reviewer is onboarded.

#### P16. Secure the build and deployment pipeline

**What it means.** The build pipeline runs reproducible, audited steps
against known-good inputs.

**Why.** A pipeline compromise scales to every deployment.

**ION application.**
* `.github/workflows/test.yml` runs 4 parallel jobs on every push and
  PR to `main` / `dev`:
  * `pytest` — full suite, Python 3.11 / Ubuntu / SQLite.
  * `ruff check src/` — style and import safety.
  * `bandit -r src/` — high-severity SAST.
  * `pip-audit --vulnerability-service osv --strict` — SCA against
    the OSV database (v0.25.0).
* Docker build generates a SPDX-JSON SBOM via syft 1.18.1, shipped
  at `/app/sbom.spdx.json` (v0.26.0).
* Multi-stage Dockerfile — build tools are dropped before the
  runtime stage; the runtime image is Python 3.14-slim.

**Status:** Met.

#### P17. Eliminate vulnerability classes

**What it means.** Prefer language and library choices that make a
whole class of bugs unreachable, rather than patching individual
instances.

**Why.** A single class-eliminating decision retires hundreds of
potential bugs.

**ION application.**
* **Memory safety** — Python (the entire backend) is memory-safe.
  No C / C++ runtime in the call graph except via wheels we audit.
* **SQL injection** — SQLAlchemy ORM with bound parameters
  everywhere. Raw `text()` SQL exists only with bind parameters.
* **XSS** — Jinja2 SandboxedEnvironment auto-escapes; DOMPurify on
  the client.
* **Password storage** — bcrypt; cost factor configurable, sensible
  default.
* **JWT** — RS256 (asymmetric) via `PyJWT[crypto]` since v0.31.8.
  Previously used `python-jose[cryptography]`, which pulled a
  transitive `ecdsa` dep with CVE-2024-23342 (Minerva timing attack
  on P-256). The vulnerable code was never reachable (ION's only JWT
  path pins `algorithms=["RS256"]`), but the dep kept appearing in
  scanner output and required a `pip-audit --ignore-vuln` allowlist
  entry. v0.31.8 retired `python-jose` entirely — `ecdsa` is no
  longer in the resolved tree and the `--ignore-vuln` flag is gone.
* **PDF SSRF** — WeasyPrint external URL fetcher blocked
  (v0.20.1).

**Status:** Met (v0.31.8).

#### P18. Continually test security

**What it means.** Security testing runs automatically on every change,
not as a one-time gate.

**Why.** Late-stage security testing finds late-stage bugs; cheap
ones to fix in design become expensive ones in production.

**ION application.**
* See P16 (CI pipeline) — 4 parallel security jobs on every push.
* Per-fix regression test pinned: every closed finding ships a test
  named `tests/test_v<version>_<fix>.py` that would have caught the
  regression.
* Per-release `SECURITY_ASSESSMENT.md` is a manual hostile re-read of
  the diff by the maintainer.
* Higher-tier SAST (Semgrep / CodeQL) is an aspirational item in
  `docs/DEVELOPMENT_LIFECYCLE.md` §8.

**Status:** Met.

### Operate

#### P19. Plan for security flaws

**What it means.** Bugs will exist. Publish how to report them and how
they will be fixed.

**Why.** Without a published policy, vulnerabilities get reported via
back-channels or not at all.

**ION application.**
* `SECURITY.md` (v0.30.0) — GitHub Security Advisory (preferred,
  E2E-encrypted) and maintainer email fallback.
* Severity-aligned SLAs in `docs/DEVELOPMENT_LIFECYCLE.md` §3.5.4:
  * **Critical** — patched image within 72 hours.
  * **High** — patched within 14 days.
  * **Medium** — next MINOR release.
  * **Low** — opportunistic, within 6 months.
* `SECURITY_ASSESSMENT.md` is updated per release with a severity
  trend column.
* Disclosure timeline: 90-day responsible disclosure default;
  earlier publication mutually agreed.

**Status:** Met.

#### P20. Continuous risk management — through-life

**What it means.** Security is not a one-time gate; it is a property
that must be maintained through the lifetime of the product.

**Why.** New attacks, new dependencies, deprecated controls — the
environment moves; the product must move with it.

**ION application.**
* Per-release security review (P19) is the heartbeat.
* `pip-audit` in CI catches new CVEs in existing dependencies on the
  next push.
* Bundled ATT&CK + KEV snapshots are refreshed at every minor-version
  bump via `scripts/generate_attack_techniques_json.py` and equivalent.
* The `MAINTENANCE` policy lives in `docs/RUNBOOK.md` — release
  cadence, retirement plan, dependency lifecycle.

**Status:** Met.

## 4. Audit summary

Aggregating §3 across 20 principles:

| Status | Count | Principles |
|---|---|---|
| **Met** | 18 | P2, P3, P4, P5, P6, P7, P8, P9, P10, P12, P13, P14, P15, P16, P17, P18, P19, P20 |
| **Mostly Met** | 2 | P1 (single maintainer; six artifacts in place), P11 (CSP strict — inline handlers in 69 templates still pending) |
| **Partial** | 0 | — |
| **Gap** | 0 | — |

Open named gaps (also in `docs/DEVELOPMENT_LIFECYCLE.md` §8):

* **Strict CSP** — eliminate `'unsafe-inline'` from `script-src-attr` /
  `style-src-attr` by migrating 1,185 inline event handlers to
  `addEventListener` and 1,659 inline `style=""` attributes to CSS
  classes (P11). The `<script>`/`<style>` block nonce work itself is
  done as of v0.31.3.
* ~~**Data-minimisation audit**~~ — **CLOSED v0.31.12.** Full
  schema-wide audit produced at `docs/DATA_MINIMISATION_AUDIT.md`.
  13 existing controls catalogued; 5 low-severity residual gaps
  tracked for v0.32+; P13 moves Mostly Met → Met.
* ~~`python-jose → PyJWT`~~ — **CLOSED v0.31.8.** `python-jose`
  retired; PyJWT in its place; transitive `ecdsa` dep removed;
  CI `--ignore-vuln CVE-2024-23342` flag dropped.
* **Single-maintainer model** — fundamental structural limit on P1
  (the principle requires multiple humans). The v0.31.9 artifacts
  (CONTRIBUTING.md, CODEOWNERS, security-reviewer agent, pre-commit
  hooks) bring this as close to Met as a single-maintainer project
  can. For higher-assurance deployments, the customer-side
  Designated Security Officer pattern in `docs/DEVELOPMENT_LIFECYCLE.md`
  §6.4 closes the remaining gap.
* ~~**Branch protection rules** + **signed commits**~~ — **CLOSED v0.31.10.**
  Branch protection enforced on `main` via GitHub API
  (`required_linear_history`, `allow_force_pushes=false`,
  `allow_deletions=false`, `required_signatures=true`). All commits
  must be SSH-signed; the maintainer's signing key (ed25519,
  dedicated to GitHub) is registered as a Signing Key on the
  ixion36-svg account.

None of the gaps is load-bearing for a single deployment; each is a
defence-in-depth improvement.

## 5. How this doc relates to the SDLC document

`docs/DEVELOPMENT_LIFECYCLE.md` is the **phase-by-phase** SDLC — what
to do at Plan / Define / Design / Build & Test / Operate. This doc is
the **principle list** — the timeless rules every phase applies. The
two are harmonised:

* SDLC §3.3.1 "Architectural principles" lists the 6 design principles
  that are non-negotiable for new code; those map to P5, P6, P7, P8,
  P11, P12 here.
* SDLC §4 cross-references the 8 Secure Development and Deployment
  principles to ION practice; those map to P1, P14, P15, P16, P18,
  P19 here.
* SDLC §8 "Known Gaps" lists the same gaps as §4 above.

The principles in this doc are the canonical reference. The SDLC doc
is the phase guide. If the two ever disagree, this doc wins for
"what?" and the SDLC doc wins for "when?".

## 6. Revision history

| Version | Date       | Author     | Notes |
|---------|------------|------------|-------|
| 1.0     | 2026-05-14 | Maintainer | Initial publication. 20 principles synthesised from NCSC, CISA, NIST SSDF, OWASP, and Saltzer & Schroeder. Audit at v0.31.2: 15 Met / 3 Mostly Met / 2 Partial / 0 Gap. |
| 1.1     | 2026-05-14 | Maintainer | v0.31.3: P11 application — per-request CSP nonce on every inline `<script>` and `<style>` block via `SecurityHeadersMiddleware` + Jinja global. Inline event handlers + inline `style=""` attributes still permitted via CSP3 split-directive `script-src-attr` / `style-src-attr`. P11 audit body updated; gap narrowed from "CSP nonce" to "strict CSP (refactor inline handlers)". Audit summary unchanged: 15 Met / 3 Mostly Met / 2 Partial / 0 Gap. |
| 1.2     | 2026-05-14 | Maintainer | v0.31.4: P11 follow-up — event-delegation foundation. New `static/js/event-delegation.js` + base.html migrated as proof-of-pattern. CSP unchanged this release (72 child templates still carry inline handlers). P11 audit body updated with the migration mechanism + remaining work. Audit summary unchanged: 15 Met / 3 Mostly Met / 2 Partial / 0 Gap. |
| 1.3     | 2026-05-14 | Maintainer | v0.31.5: P11 follow-up #2 — cases.html migrated (48 handlers incl. kanban drag-and-drop). Helper extended with drag events, `$event` sentinel, per-event positional args. CSP unchanged. P11 audit body updated with current count (55 handlers migrated; 71 templates remaining). Audit summary unchanged: 15 Met / 3 Mostly Met / 2 Partial / 0 Gap. |
| 1.4     | 2026-05-14 | Maintainer | v0.31.6: P11 follow-up #3 — alerts.html migrated (194 handlers). New `tools/migrate_inline_handlers.py` mechanical migration script; 4 new helper built-ins (`data-stop-propagation` alone, `data-remove-target`, `data-remove-parent`, `data-remove-closest`). CSP unchanged. P11 audit body updated (249 handlers migrated; 70 templates remaining). Audit summary unchanged: 15 Met / 3 Mostly Met / 2 Partial / 0 Gap. |
| 1.5     | 2026-05-14 | Maintainer | v0.31.7: P11 follow-up #4 — training.html migrated (119 handlers). 2 hand-fixed JS-source-escape spots; migration script patched to detect `\\'` / `\\"` escape sequences and skip them. P11 audit body updated (368 handlers migrated; 69 templates remaining). Audit summary unchanged: 15 Met / 3 Mostly Met / 2 Partial / 0 Gap. |
| 1.6     | 2026-05-14 | Maintainer | v0.31.8: **P17 CLOSED.** `python-jose[cryptography]` retired in favour of `PyJWT[crypto]>=2.8.0`. Transitive `ecdsa` dep (CVE-2024-23342, Minerva timing attack on P-256) removed from the resolved tree. CI `--ignore-vuln CVE-2024-23342` flag dropped. `src/ion/auth/oidc.py` migrated: `PyJWK.from_dict(jwk).key` wraps the JWKS dict before `jwt.decode`; same RS256-only semantics. New `tests/test_v031_8_oidc_pyjwt.py` (8 cases) pins happy path + tampered signature + expired + wrong audience/issuer + missing/unknown kid + missing sub. P17 status: **Mostly Met → Met.** Audit summary: **16 Met / 2 Mostly Met / 2 Partial / 0 Gap** (was 15 / 3 / 2 / 0). |
| 1.7     | 2026-05-14 | Maintainer | v0.31.9: **P1 PARTIAL → MOSTLY MET.** Four artifacts ship to systematize the single-maintainer review pattern: `CONTRIBUTING.md` (codified expectations + PR template), `CODEOWNERS` (review responsibility per path), `.claude/agents/security-reviewer.md` (focused SbD-walk agent invoked before commit), `.pre-commit-config.yaml` (ruff + bandit + pip-audit at the workstation; mirrors CI). P1 cannot reach Met without onboarding a second human reviewer. Audit summary: **16 Met / 3 Mostly Met / 1 Partial / 0 Gap** (was 16 / 2 / 2 / 0). |
| 2.2     | 2026-05-26 | Maintainer | v0.31.15: **G4 sub-gap closed.** One-tuple append to `RETENTION_RULES` in `data_retention_service.py`: `RetentionRule("ION_AI_CHAT_RETENTION_DAYS", "ion.models.ai_chat:AIChatMessage", "created_at", "ai_chat_messages")`. Opt-IN default (unset = disabled). Targets messages, not sessions — preserves user-controlled session lifecycle while bounding message PII retention. The parameterised abstraction did its job: closure required zero new infrastructure. DATA_MINIMISATION_AUDIT residual gaps drop from 2 to 1 (G5 remains). Audit summary unchanged: **18 Met / 2 Mostly Met / 0 Partial / 0 Gap**. |
| 2.1     | 2026-05-26 | Maintainer | v0.31.14: **G2 + G3 sub-gaps closed.** New `src/ion/services/data_retention_service.py` is parameterised on a `RetentionRule` list — current rules: (`ION_AUDIT_LOG_RETENTION_DAYS`, `audit_logs.timestamp`) and (`ION_SECURITY_EVENTS_RETENTION_DAYS`, `security_events.created_at`). Single background loop under advisory lock `LOCK_DATA_RETENTION_BG = 1024`. Both retention env vars are opt-IN (default unset = disabled) because compliance windows vary by jurisdiction; loop has whole-loop kill switch `ION_DATA_RETENTION_ENABLED` (default `true`) + cadence `ION_DATA_RETENTION_INTERVAL_HOURS` (default 24h, floored at 60s). Future G4 (AI chat retention) will fit by appending one tuple to `RETENTION_RULES`. P13 already Met at v0.31.12 — this is sub-principle defence-in-depth work. DATA_MINIMISATION_AUDIT residual gaps drop from 4 to 2 (G4 / G5 remain). Audit summary unchanged: **18 Met / 2 Mostly Met / 0 Partial / 0 Gap**. |
| 2.0     | 2026-05-26 | Maintainer | v0.31.13: **G1 sub-gap closed.** `src/ion/services/session_cleanup_service.py` background loop wraps `AuthService.cleanup_expired_sessions()` and runs periodically under advisory lock `LOCK_SESSION_CLEANUP_BG = 1023`. Env vars `ION_SESSION_CLEANUP_ENABLED` (default `true`) and `ION_SESSION_CLEANUP_INTERVAL_HOURS` (default 6, floored at 60s). DATA_MINIMISATION_AUDIT.md updated to reflect the closure; audit residual gaps count drops from 5 to 4 (G2 / G3 / G4 / G5). P13 already Met at v0.31.12 — this is sub-principle defence-in-depth work. Audit summary unchanged: **18 Met / 2 Mostly Met / 0 Partial / 0 Gap**. |
| 1.9     | 2026-05-26 | Maintainer | v0.31.12: **P13 MOSTLY MET → MET.** `docs/DATA_MINIMISATION_AUDIT.md` published — schema-wide audit of the ~100-table ION data layer (47 SQLAlchemy model files). Tier 1 deep-read of `users` / `user_sessions` / `audit_logs` / `security_events` / `blocked_ips` / `analyst_notes` / `ai_chat_*` / `observables` / `ai_feedback`; Tier 2 skim of alert / case / annotation / social / custody / integration tables; Tier 3 noted as operational state out of column-level scope. 13 existing data-min controls catalogued (C1–C13: air-gap, bcrypt, closure_reason enum, ION_BOB_STORE_REASONING gate, append-only ledgers with sha256 chain, soft-delete, per-user session cleanup at login, TLP/PAP markings on observables, service-account auth short-circuit, WeasyPrint SSRF guard, CSP nonce, etc.). 5 low-severity residual gaps identified and tracked for v0.32+: G1 system-wide session cleanup scheduler (function exists at `auth/service.py:347`, no caller); G2 `audit_logs` retention env var; G3 `security_events` retention env var; G4 optional AI chat retention; G5 session_token hash-at-rest. All 5 gaps bounded by C1 (air-gap) + C2 (container isolation) + RBAC; classified as defence-in-depth improvements, not unresolved P13 attack surface. Audit summary: **18 Met / 2 Mostly Met / 0 Partial / 0 Gap** (was 17 / 3 / 0 / 0). |
| 1.8     | 2026-05-26 | Maintainer | v0.31.10: **P15 PARTIAL → MET.** Branch protection on `main` advanced from Tier 1 to Tier 2 — `required_signatures=true` added via `gh api POST .../protection/required_signatures` after registering a dedicated ed25519 Signing Key (`~/.ssh/id_ed25519_github.pub`) on the maintainer's GitHub account. Local git configured for SSH commit signing (`gpg.format=ssh` + `gpg.ssh.allowedSignersFile`); committer identity switched to the GitHub noreply form so signatures resolve to a verified-by-GitHub address. The release commit for v0.31.10 is the first signed commit on `main` and the implicit acceptance test for the new server-side rule. Audit summary: **17 Met / 3 Mostly Met / 0 Partial / 0 Gap** (was 16 / 3 / 1 / 0). |
