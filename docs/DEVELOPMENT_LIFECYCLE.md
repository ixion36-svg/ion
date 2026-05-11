# ION Development Lifecycle

**Document owner:** Repository maintainer (`ixion36`)
**Status:** Current as of v0.24.0 (2026-05-11)
**Review cadence:** Every minor-version bump (v0.X.0) or on material process change, whichever is sooner.
**Primary framework:** Secure by Design (SbD)
**Secondary references:** NCSC *Secure Development and Deployment Guidance* (8 principles); NIST SP 800-218 (SSDF) for international interoperability.

---

## 1. Purpose and Scope

ION (Intelligent Operating Network) is a Security Operations Centre platform that ships into **siloed and air-gapped environments**. This constraint (recorded in the project's design memory and reflected throughout the codebase) drives several non-obvious lifecycle decisions: no live external feeds at runtime, bundled-snapshot pattern for threat intel data, every external integration must be optional, and dependencies must be installable offline.

This document is the single authoritative reference for *how ION is built, released, operated, and retired*. It supersedes any informal description of the development process. It does **not** replace:

- `docs/RUNBOOK.md` — operational duties (SOC lead daily activities, integration configuration, troubleshooting).
- `docs/ARCHITECTURE.md` — system architecture (components, data flow, service layer, schema).
- `docs/DEPLOYMENT.md` — deployment topology.
- `SECURITY_ASSESSMENT.md` — point-in-time security audit (refreshed every release).
- `CHANGELOG.md` — per-release change record.

Those documents are inputs into this lifecycle; this one describes the process that produces them.

### 1.1 Audience

This document is intended for:

- ION's primary maintainer and any future contributors.
- Defence-tier and other regulated-environment customers performing supplier due diligence.
- Independent assessors auditing ION against the Secure by Design methodology.
- The ION SOC operator team operating a deployed instance, when they need to understand the line between "operational change" (their authority) and "code change" (must go through the development lifecycle).

### 1.2 Threat context

ION's intended threat model is:

1. **Authenticated internal users** with varying RBAC tiers (admin / engineering / soc-lead / l1-analyst / l2-analyst / l3-analyst / read-only).
2. **Adversary-controlled alert content** (rule names, hostnames, log payloads) reaching the LLM via investigation prompts.
3. **Compromised integration endpoints** (Elastic, Kibana, TIDE, OpenCTI, Arkime, Keycloak, Ollama) — every integration must fail closed without taking the platform down.
4. **Supply-chain risk** on Python and Docker base images.
5. **Insider threat** at any RBAC tier; audit trail must be tamper-evident and analyst-attributable.

Out of scope:

- DDoS / volumetric attacks (handled by the deployment-tier reverse proxy / WAF, not in scope for ION itself).
- Physical security of the host (operator responsibility).
- Cryptographic primitive evaluation (we rely on `cryptography` / `passlib` / standard TLS via the reverse proxy).

---

## 2. Roles and Responsibilities

ION is currently maintained by a small team. Roles below are functional, not titular — the same individual may wear multiple hats provided the **separation-of-duty** controls in §6.4 are honoured.

| Role | Responsibility | Currently held by |
|------|----------------|-------------------|
| **Maintainer** | Code authorship, code review, release authority, security-assessment author. Final approver for `main` merges. | `ixion36` |
| **Reviewer** | Independent review of every code change before it merges. May be a peer; may be an AI pair-programmer subject to §6.3. | `ixion36` (with AI pair, see §6.3) |
| **Release engineer** | Executes the release ritual (`docs/RUNBOOK.md` §11). Same individual as Maintainer in current org. | `ixion36` |
| **Security officer** | Owns `SECURITY_ASSESSMENT.md`. Authority to block a release for unaddressed High/Critical findings. | `ixion36` |
| **Customer / operator** | Operates a deployed instance. May submit operator-reported bugs (see §3.1 and v0.23.1/v0.23.2 history) but does **not** have authority to alter ION code. | Deployment-specific |

**Future state (gap, tracked in §8):** in customer environments where the maintainer is also the operator, a customer-side **Designated Security Officer** must be appointed to act as the independent reviewer for at least Medium-severity changes and above. The current single-maintainer pattern is a known control weakness for higher-assurance deployments.

---

## 3. Lifecycle Phases — Secure by Design

The Secure by Design approach defines five phases that apply to every material change (not only headline features). ION's existing practice is mapped to each phase below. Where a phase contains practice that is **not yet documented elsewhere**, this section is the canonical reference. Where practice is documented elsewhere, this section cites the file and section number.

### 3.1 Plan

**Goal:** decide what to do next, why, and at what risk.

#### 3.1.1 Source of change

Material changes enter the lifecycle from one of three channels:

- **Operator-reported bug** — surfaced by a deployed customer or internal SOC use. Example: v0.23.2 close-via-dropdown silent no-op. Captured as a free-text problem statement with reproduction steps where possible.
- **Carry-over from prior version** — items deferred from a previous version with a stated scope reason. Example: v0.22.0's open questions OQ4/5/6 carried to v0.22.1; lab grading session-2 deferred from v0.23.0 to v0.24.0. Tracked in `_backlog_v0_<next>.md`.
- **Security finding** — surfaced by the per-release `SECURITY_ASSESSMENT.md` review, third-party penetration test, or a CVE in a dependency. Findings are categorised C/H/M/L. High and Critical findings have a fix-by-version target stated in the assessment.

There is currently **no public vulnerability disclosure channel** for external researchers. See §8 (Gaps).

#### 3.1.2 Versioning and release cadence

ION uses **semantic versioning** (`MAJOR.MINOR.PATCH`):

- **MAJOR** — reserved for breaking changes to data model, public APIs, or deployment topology. No MAJOR bumps to date.
- **MINOR** (e.g. v0.22.0 → v0.23.0) — new features. Example: v0.22.0 added MITRE coverage heatmap + Workbench timeline annotations; v0.23.0 added adaptive lab grading.
- **PATCH** (e.g. v0.23.0 → v0.23.1 → v0.23.2) — bug fixes and security closures. Example: v0.22.1 closed L5/L6 security carry-overs; v0.23.1 fixed three operator-reported bugs; v0.23.2 fixed the case-close panel-dropdown issue.

There is **no fixed release calendar**. Releases ship when the scoped batch is ready and passes the release ritual. Typical cadence in 2026 has been multiple PATCHes per week with a MINOR every 1-2 weeks.

#### 3.1.3 Scope confirmation (operator + maintainer alignment)

Before any non-trivial change is implemented, scope is confirmed with the requester. For maintainer-driven changes, this is captured in `_spec_v<version>.md` (e.g. `_spec_v0_22.md`). For operator-reported bugs, the maintainer states the proposed fix in plain English and (for non-trivial fixes) asks the operator to confirm the approach before code is written. This is recorded in the eventual commit message body.

**Rationale:** ION's customers are sometimes air-gapped — the cost of shipping a wrong fix is high (no rollback over the wire). Front-loading scope confirmation reduces wasted releases.

#### 3.1.4 Risk assessment per change

A risk assessment is a paragraph in either:

- The `_spec_v<version>.md` file (for MINOR features).
- The commit message body (for PATCH fixes and small features).

It states: what could go wrong, what the blast radius is, what controls mitigate it, and what cannot be mitigated. Example from v0.22.1 L6 fix commit (paraphrased): "A user without `system:settings` could clear an existing override via explicit-null; fix compares incoming vs stored; UI hides the field; backend remains authoritative."

For **High/Critical security findings**, the risk assessment is mandatory and authored in `SECURITY_ASSESSMENT.md` against the assessment template's existing format.

---

### 3.2 Define

**Goal:** turn the planned change into a verifiable specification.

#### 3.2.1 Specification documents

For MINOR features, a spec file `_spec_v<version>.md` is authored before implementation. This file:

- States the user-visible behaviour change.
- Names the new tables, endpoints, services, UI surfaces, and ADR-style design decisions.
- Includes an **8-file release-ritual checklist** (canonicalised in `docs/RUNBOOK.md` "Release Ritual — Version Bump" section).
- Contains an **Open Questions** section listing decisions deferred for follow-up. These OQs are tracked across versions until resolved (e.g. `_spec_v0_22.md` §7 OQ4/5/6 resolved in v0.22.1).

For PATCH fixes, the spec is embedded in the commit message body. The commit message acts as the contract for what was changed and why.

#### 3.2.2 Acceptance criteria

Every change has explicit acceptance criteria expressed as **automated regression tests** in `tests/`. Where the change is purely UI-only and the JS test harness does not cover it, an explanatory comment is added inline (example: the v0.23.2 fix has both backend tests AND comment blocks in `cases.html` documenting the four JS fixes).

A change is **not acceptable** until:

- Its regression tests pass locally.
- The full touched-surface suite passes (typical command: `pytest tests/test_<feature>.py tests/test_<related>.py`).
- The release ritual's two sanity-check greps return empty for version-string rot.

#### 3.2.3 Dependency-impact statement

When a change adds, removes, or upgrades a third-party dependency, the spec or commit body must state:

- Why the dependency was added.
- The maintainer's licence-compatibility check (must be MIT/BSD/Apache/MPL — no GPL/AGPL in the runtime path).
- A note on offline-installability (must work in air-gapped environments via cached wheels).

Dependency upgrades for security reasons are tagged in the commit message (e.g. `chore(deps): bump cryptography 41 → 43 (CVE-2024-XXXX)`).

---

### 3.3 Design

**Goal:** produce a design that fits ION's architecture and threat model.

#### 3.3.1 Architectural principles

The following principles are non-negotiable for new code. They are repeated here for external-reviewer visibility; the running architecture document is `docs/ARCHITECTURE.md`.

1. **No-SPA constraint** — server-rendered Jinja templates with vanilla JS only. No React, Vue, Angular, or build-step frontend. Rationale: simpler attack surface; offline-installable; no opaque bundled blobs at deploy time. (Memory: `project_ion_architecture.md`.)
2. **Air-gap rule** — no live external feeds at runtime. Threat intel (CISA KEV, MITRE ATT&CK STIX, RSS) ships as bundled JSON inside the Docker image and is refreshed by a script run at every release. (Memory: `feedback_ion_airgap_deployment.md`, `project_ion_kev_design.md`.)
3. **Bundled-snapshot pattern** — every external dataset (KEV, ATT&CK techniques v15.1, etc.) lives under `src/ion/data/` and is regenerated by a script in `scripts/`. The script is part of the release ritual.
4. **Service-side ownership check before commit** — any mutation service that operates on user-owned resources (pins, annotations, notes) must verify ownership inside the service before the `session.commit()` that writes the mutation. (Memory: `feedback_service_check_before_commit.md`, learned from a v0.20.1 TOCTOU bug.)
5. **Advisory-lock background tasks** — long-running loops (investigation sweep, case embedding, KB embedding) are leader-elected via Postgres advisory locks with unique namespaces (`LOCK_INVESTIGATION_BG=1016`, `LABF=0x4C414246`, `LABS=0x4C414253`, etc.) so multi-worker uvicorn deployments do not run the same loop twice.
6. **Defence in depth** — every authority decision is enforced at the service/API layer, not relied on at the UI layer. UI gates exist as UX hints. Example: v0.22.1 L6 backend gate is the authority; the UI hide is convenience.
7. **Tamper-evident audit trail** — Workbench pins on AlertCase (v0.20.0) and ForensicCase (v0.20.1) use a sha256 hash chain. Audit log rows for mutations are written by the service before commit, in the same transaction.

#### 3.3.2 Threat modelling

For every MINOR feature that introduces a **new attack surface** (new table, new endpoint, new audit event, new external integration, new file-upload path), the spec must include a threat model paragraph. The v0.23.0 SECURITY_ASSESSMENT.md v0.23.0 Delta is the worked example: four new-surface items each analysed for input-flow, parameterised-query correctness, and information-flow boundary.

For PATCH fixes, threat modelling is implicit in the commit body when relevant (e.g. v0.22.1 L6 fix explicitly described the bypass and why the new check closes it).

**Gap (§8):** there is currently no standalone threat-model document (e.g. STRIDE or PASTA). Threat modelling is per-change and folded into the security assessment. For higher-assurance deployments this should be supplemented with a system-level threat model.

#### 3.3.3 Design review

Design review currently consists of:

- The maintainer drafting the design.
- The maintainer's AI pair-programmer (Claude Opus 4.x) reviewing the design before code is written, focused on architectural fit, security implications, and edge cases. The pair-programmer's review is captured in the conversation transcript and reflected in the resulting spec or commit body.

**Gap (§8):** independent human design review is not currently in place for solo-maintainer changes. For higher-assurance deployments where the customer requires "two pairs of human eyes" on every design, a Designated Security Officer (DSO) on the customer side must be inserted before merge.

---

### 3.4 Build & Test

**Goal:** implement the design, prove it works, prove the rest of the system still works.

#### 3.4.1 Source control

- **Repository:** `github.com/ixion36-svg/ion`
- **Branches:**
  - `main` — the only branch material work merges into. Every tagged release points at a commit on `main`.
  - `dev` — currently a long-lived integration branch; little active use, but reserved for situations where a MINOR feature needs to be staged across multiple commits before landing on main.
- **Branch protection:** `main` is not currently force-push protected at the GitHub level. **Gap (§8).**
- **Signed commits:** not currently enforced. **Gap (§8).** Commits are attributed to `ixion36` via the configured git identity.

#### 3.4.2 Commit pattern

Every release on `main` is **two commits**:

1. `feat:`, `fix:`, or `security:` commit containing the code + test changes only.
2. `chore(release): vX.Y.Z` commit containing only the 8-file release-ritual bumps + CHANGELOG entry + SECURITY_ASSESSMENT delta.

Rationale: the chore commit is mechanical and auditable. The feature commit is the actual work and is reviewable on its own. Bisecting back through the history stays clean. See `git log --oneline` for the running pattern.

Co-authorship of AI pair-programmer contributions is recorded via the `Co-Authored-By:` trailer on every commit. See §6.3.

#### 3.4.3 Coding standards

- **Python:** PEP 8 with project-specific deviations noted inline. Type hints required on new public functions. SQLAlchemy 2.x `Mapped[...]` typed columns.
- **Templates:** Jinja2 SandboxedEnvironment is mandatory for any user-influenced template (`docs/ARCHITECTURE.md` security model). No raw `eval` / `exec` / dynamic-import paths on user input.
- **SQL:** all queries are parameterised. Raw SQL with format-string interpolation is rejected at code review.
- **Logging:** ECS-compliant via `ecs-logging`. No PII at INFO level; PII may appear at DEBUG which is suppressed in production builds.
- **Comments:** WHY-only, not WHAT. Refer to a memory of `feedback_*` files for the documented exceptions where memory entries provide the rationale.

#### 3.4.4 Test strategy

ION uses **integration-style tests** in `tests/` with SQLite as the default backend (PostgreSQL via `ION_TEST_DATABASE_URL` for tests that exercise dialect-specific paths, e.g. the heatmap LATERAL join).

Test categories in use:

- **Unit-style tests** on helpers and pure logic — example: `tests/test_lab_grading.py::TestGradeSession`.
- **Integration tests** that boot a real FastAPI `TestClient`, write to a real SQLite engine, and assert through the HTTP surface — example: `tests/test_v023_1_queue_control.py`.
- **End-to-end-style cycles** that simulate a full lifecycle (launch → audit → complete) — example: `tests/test_lab_grading.py::TestEndToEnd`.

There is **no current quantitative coverage target**. Coverage is gated by reviewer judgement: every new endpoint requires at least one happy-path + one error-path test; every fix requires a regression test that fails on the pre-fix code and passes on the fix.

A **CI pipeline** runs on every push to `main` / `dev` and every pull request to `main` via GitHub Actions (`.github/workflows/test.yml`, landed in v0.24.0; SCA added v0.25.0). Four jobs run in parallel:

- **pytest** — full `tests/` suite on Python 3.11 / Ubuntu / SQLite in-process. Timeout 15 minutes. Must pass for the workflow to be green.
- **ruff** — lint via `ruff check src/` with configuration in `pyproject.toml [tool.ruff]` (target Python 3.11, line length 120, per-file ignores for `data/` modules).
- **bandit** — security lint via `bandit -r src/` with documented skip set `B602,B608,B101` (rationale in the workflow file). High-severity findings fail the job; medium and below are warnings.
- **pip-audit** — Software Composition Analysis (v0.25.0) via `pip-audit --vulnerability-service osv --strict`. Scans the project's resolved dependency tree against the OSV vulnerability database. Any finding fails the job; specific CVEs may be allowlisted via `--ignore-vuln <id>` with a justification block in the workflow file. The v0.25.0 baseline ignores CVE-2024-23342 (ecdsa Minerva timing side-channel; not reachable in ION's RS256-only OIDC path — see the workflow file for the full justification).

Each job is independent, so a single review surface shows every category of failure at once rather than serialising on the first failure. CI failures **block tag/release** — the release ritual now requires a green CI run on the commit being tagged.

#### 3.4.5 Build artefacts

The shipped artefact is a Docker image:

- **Repository:** `docker.io/ixion36/ion`
- **Tags:** `vX.Y.Z` (immutable) and `latest` (mutable, points at the most recent release).
- **Base:** `python:3.14-slim`
- **OCI labels:** `org.opencontainers.image.version` set per release; updated by the release ritual (file 4 of 8).
- **Image is multi-arch** (built via buildx) and reproducible-by-tag (each `vX.Y.Z` tag is content-addressed by Docker Hub digest).

There is currently **no signed image** (`cosign` / Sigstore) and **no Software Bill of Materials** (SBOM) generated at build time. **Gap (§8).**

#### 3.4.6 The release ritual

The release ritual is canonicalised in `docs/RUNBOOK.md` "Release Ritual — Version Bump" section. The 8 files that must bump every release:

| # | File | Change |
|---|------|--------|
| 1 | `src/ion/__init__.py` | `__version__ = "X.Y.Z"` (load-bearing for `{{ ion_version }}` in templates) |
| 2 | `pyproject.toml` | `version = "X.Y.Z"` |
| 3 | `docker-compose.yml` | two `${ION_VERSION:-X.Y.Z}` fallback defaults |
| 4 | `Dockerfile` | `org.opencontainers.image.version="X.Y.Z"` OCI label |
| 5 | `README.md` | Version badge |
| 6 | `.env.deploy` | `ION_VERSION=X.Y.Z` + the human-readable comment above it |
| 7 | `CHANGELOG.md` | New `## vX.Y.Z — YYYY-MM-DD` top entry |
| 8 | `SECURITY_ASSESSMENT.md` | Application Version header bump, severity-trend table extension, new "vX.Y.Z Delta" section |

Two sanity-check greps must return empty before tagging — see `docs/RUNBOOK.md` for the canonical greps. The greps catch:

- Historical version-string rot (legacy hardcoded values from prior releases — `0.9.98`, `0.11.6`, `0.11.21`, `0.19.19`).
- Residual previous-release version strings in any of the 6 canonical version-bearing files (catches a missed bump before the tag goes out).

Memory: `feedback_release_version_bump.md` — the eight-file checklist is load-bearing because `src/ion/__init__.py:__version__` rotted at `0.19.19` for 13 releases before v0.22.0 reset the baseline.

#### 3.4.7 Release-time issue handling

If a sanity-check grep fires during the release ritual, or a routine lint / encoding / type-check issue surfaces, it is **fixed silently and the release proceeds**. Only true feature regressions are surfaced. Memory: `feedback_fix_silently.md`. Rationale: closeout-pass issues are noise; surfacing them every release inflates the SECURITY_ASSESSMENT delta and dilutes attention from real findings.

---

### 3.5 Operate

**Goal:** ship the release, observe its behaviour, retire it cleanly when superseded.

#### 3.5.1 Deployment

Deployment is governed by `docs/DEPLOYMENT.md` and the per-environment `.env.deploy` template. Key constraints:

- **Air-gap by default.** The release is delivered as a Docker image saved to disk and loaded into a registry inside the customer perimeter. No live `docker pull` from `docker.io` is assumed.
- **Container topology** in `docker-compose.yml` references `pgvector/pgvector:pg16` for the Postgres database (pgvector required for case similarity since v0.10.4) and `ollama/ollama:<version>` for the LLM service.
- **Operator-controlled** environment variables in `.env.deploy` drive every integration. None of the integrations is required for ION to start; each fails closed and shows a status banner in the UI.

#### 3.5.2 Operator runbook

Day-to-day operational duties are in `docs/RUNBOOK.md`:

- Onboarding analysts (§1)
- Configuring integrations (§2)
- Daily SOC lead checklist (§3)
- Playbooks (§4)
- Alert prompt templates (§5)
- Case grouper and investigation queue (§6)
- Executive reports (§7)
- Common troubleshooting (§8)
- (And the release ritual at the end, which is the *maintainer's* duty, not the operator's.)

#### 3.5.3 Monitoring

ION emits ECS-compliant structured logs via `ecs-logging`. Key events:

- Every API request: method, path, user_id, response status, duration.
- Every mutation: audit_log row with action / resource_type / resource_id / details.
- Every external-integration failure: a single-line WARN with the integration name and the upstream error code.

The operator is expected to ship these logs to an external SIEM (Elastic, Splunk, etc.) for retention and alerting. ION does not currently emit Prometheus metrics or expose an `/internal/metrics` endpoint. **Gap (§8).**

#### 3.5.4 Vulnerability response

When a CVE is reported against an ION dependency, or a `SECURITY_ASSESSMENT.md` review surfaces a new finding:

- **Critical** — Patch within 72 hours of confirmation. Issue an out-of-band PATCH release. Notify operators via the customary channel (email / signed advisory).
- **High** — Patch within 14 days. Bundle with the next PATCH release.
- **Medium** — Address within the next MINOR release.
- **Low** — Address opportunistically; track in `_backlog_v<next>.md`.

There is currently **no public security advisory channel** (e.g. `SECURITY.md` with a GPG-keyed contact). **Gap (§8).**

#### 3.5.5 Retirement

A release tag is **never removed** from `main` or from the Docker Hub registry. Superseded releases stay queryable for forensic / compliance purposes.

When a release becomes operationally unsupported (e.g. relies on a base image with end-of-life Python), the operator is notified at the latest 60 days in advance. There is currently no formal end-of-life calendar; the latest supported release is always whichever tag is also `:latest`. **Gap (§8).**

---

## 4. Cross-Reference: NCSC Secure Development and Deployment

The NCSC's 8 principles map to ION's existing practice as follows. Where a principle is fully met, the mapping cites the section above. Where it is partially met, the gap is repeated in §8.

| NCSC Principle | ION Implementation | Status |
|----------------|-------------------|--------|
| **1. Secure development environment** | Maintainer's workstation uses Windows 11 with BitLocker; AI pair-programmer (Claude Opus 4.7) runs locally via Claude Code. No third-party access to the dev environment. | **Partial** — formal DSE hardening checklist not documented. |
| **2. Protect your code repository** | GitHub private repository, SSH-keyed access, branch `main` is the only release-eligible branch. | **Partial** — branch protection not enabled; signed commits not enforced (§3.4.1). |
| **3. Secure-by-default configuration** | `.env.deploy` template ships secure defaults. Cookie Secure flag warned at startup. Debug mode default-off. Admin password forced to be non-default in production. | **Met** — see `docs/DEPLOYMENT.md`. |
| **4. Manage third-party risk** | Dependencies declared in `pyproject.toml` with version-floor constraints. Licence policy stated (§3.2.3). `pip-audit` runs in CI against the OSV database on every push and PR (v0.25.0). | **Mostly Met** — SCA scanning landed v0.25.0; SBOM (`syft`) and exact-pinned versions remain §8 gaps. |
| **5. Plan for vulnerabilities** | `SECURITY_ASSESSMENT.md` reviewed every release. Per-finding fix-by-version target stated. SLA documented in §3.5.4. | **Met** for internal findings; gap for public disclosure channel (§8). |
| **6. Continuous security testing** | Per-release `SECURITY_ASSESSMENT.md` is a manual audit pass. Regression tests are pinned to every fix. CI runs `pytest` + `ruff` + `bandit -r src/` + `pip-audit` on every push and PR via GitHub Actions (`.github/workflows/test.yml`, v0.24.0 / SCA v0.25.0). | **Met** — automated CI security scanning incl. SCA. Higher-tier static analysis (Semgrep / CodeQL) remains an aspirational §8 candidate. |
| **7. Auditable build** | Two-commit release pattern; `chore(release)` commit is mechanical and auditable. Docker images content-addressed by digest. | **Partial** — no signed images; no SBOM; no reproducible-build guarantee at the Python wheel layer (§8). |
| **8. Operational telemetry** | ECS-compliant structured logs; audit_log table; status banners on degraded integrations. | **Partial** — no metrics endpoint; no formal log-shipping spec (§8). |

---

## 5. Defence-Tier Supplier Alignment

Defence-tier and other regulated-environment supplier assurance schemes commonly require the following controls. ION's current state against each:

- **Recognised baseline cyber hygiene** (Cyber Essentials Plus or equivalent) for the supplier's general estate — out of scope for this document; covered by the maintainer's own organisational controls.
- **Documented secure development lifecycle** — this document satisfies that requirement.
- **Vulnerability response process** with severity-tiered SLAs — §3.5.4.
- **Supply-chain risk management** — §3.2.3 plus gap items in §8.
- **Auditable change history** — §3.4.2 (two-commit pattern) plus `CHANGELOG.md` and `SECURITY_ASSESSMENT.md`.
- **Documented incident response** — currently embedded in §3.5.4 (vulnerability response); a standalone Incident Response Plan is a §8 gap.

For deployments handling content above the standard regulated-environment threshold, additional controls would be required and are out of scope for ION as currently architected — the air-gap deployment pattern shifts most of the runtime controls to the deploying authority.

---

## 6. Tooling and Artefacts

### 6.1 Repository structure (top-level)

```
ixion/
├── docs/
│   ├── ARCHITECTURE.md          # Technical reference
│   ├── DEPLOYMENT.md            # Topology + .env.deploy template
│   ├── DEVELOPMENT_LIFECYCLE.md # This document
│   ├── RUNBOOK.md               # Operational duties + release ritual
│   ├── AI_OUTPUT_CONTRACT.md    # Constraints on Bob's structured output
│   └── ...
├── src/ion/                     # Application code (FastAPI + Jinja)
│   ├── data/                    # Bundled snapshots (KEV, ATT&CK, etc.)
│   ├── models/                  # SQLAlchemy 2.x models
│   ├── services/                # Business logic
│   ├── storage/                 # Database + migrations
│   └── web/                     # FastAPI routers + Jinja templates
├── tests/                       # pytest test suite
├── scripts/                     # Snapshot refresh scripts
├── CHANGELOG.md                 # Per-release change record
├── SECURITY_ASSESSMENT.md       # Per-release security audit
├── README.md
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
└── .env.deploy                  # Deployment template
```

### 6.2 Required local tools

- Python 3.14
- Docker Desktop (for building + pushing images)
- Git
- pytest 7+
- Network access to Docker Hub (for `:latest` push; can be bypassed for air-gap delivery via `docker save` + `docker load`)

### 6.3 AI pair-programmer

ION's development uses an AI pair-programmer (Claude Opus 4.x via Claude Code) as both a design reviewer and a code-authoring assistant. The maintainer is the **accountable** author of every commit; the AI is a tool. Specific controls:

- Every commit that includes AI-assisted code carries a `Co-Authored-By:` trailer naming the AI model and version. See any v0.22.x / v0.23.x commit message for the format.
- The AI **does not have** standalone authority to push, tag, or release. All git pushes are initiated by the maintainer.
- The AI **does not have** standalone access to production credentials (Docker Hub, GitHub, etc.); credentials are presented to it on demand via the maintainer's terminal session.
- The AI's outputs are subject to the same review and test gate as any other code change.

This pattern is consistent with NCSC guidance on AI-assisted development tools and is documented here for external-reviewer transparency.

### 6.4 Separation of duty

The current single-maintainer model is a known control weakness. Mitigations in effect:

- Two-commit release pattern (§3.4.2) — the `chore(release)` commit is mechanical and any deviation between its delta and the actual feature commit would be obvious in review.
- The AI pair-programmer acts as a second reviewer on every change. While this does not satisfy strict "two human pairs of eyes" controls, it materially reduces the risk of a maintainer-only blind spot.
- Per-release SECURITY_ASSESSMENT.md is authored by the same maintainer, but is structured as a deliberate hostile re-read of the diff; new-surface items, removed-surface items, and known-non-findings are recorded explicitly so an external reviewer can challenge each.

**For higher-assurance deployments:** a customer-side Designated Security Officer reviewing the per-release `CHANGELOG.md` + `SECURITY_ASSESSMENT.md` delta before the operator deploys it is the recommended additional control.

### 6.5 Memory and project context

The maintainer's working context is preserved across sessions via a file-backed memory system (`~/.claude/projects/<workdir>/memory/`). Memory entries document:

- Operator preferences and feedback (e.g. `feedback_release_version_bump.md`, `feedback_service_check_before_commit.md`).
- Project-state snapshots (e.g. `project_ion_curriculum.md`, `project_ion_v0_22_features.md`).
- Reference pointers (e.g. `reference_ion_docs.md`).

Memory entries are **non-authoritative** by themselves — they are working notes. Every claim a memory entry makes is verified against the live code before it influences a change. This is recorded as a default behaviour in the AI pair-programmer's operating instructions and is not unique to ION.

---

## 7. Change Control Summary

For external-reviewer convenience, the full set of artefacts produced by every release:

| Artefact | Location | Authored by | Reviewed by | Retained |
|----------|----------|-------------|-------------|----------|
| Commit (feature) | `git log` on `main` | Maintainer + AI pair | Maintainer | Forever |
| Commit (chore release) | `git log` on `main` | Maintainer | Self-reviewing (mechanical) | Forever |
| Git tag `vX.Y.Z` | `git tag` on origin | Maintainer | n/a | Forever |
| Docker image `vX.Y.Z` + `latest` | `docker.io/ixion36/ion` | Maintainer (Docker build) | n/a | Until superseded by base-image EOL |
| CHANGELOG entry | `CHANGELOG.md` | Maintainer | Maintainer (read-back) | Forever |
| SECURITY_ASSESSMENT delta | `SECURITY_ASSESSMENT.md` | Maintainer (security officer hat) | Maintainer (read-back); optional customer DSO | Forever |
| Test suite delta | `tests/test_<feature>.py` | Maintainer + AI pair | Maintainer | Forever |
| Spec (MINOR only) | `_spec_v<version>.md` | Maintainer | Maintainer | Forever (untracked-in-repo by convention; surfaced in handoff doc) |
| Handoff (next-session) | `_handoff_v<next>.md` | Maintainer | n/a | Until next session opens |

Audit trail is **complete from `git log` alone** for the canonical artefacts. The untracked spec and handoff files are working aids and are not load-bearing for compliance evidence.

---

## 8. Known Gaps and Roadmap

The following items are **not currently in place** and represent the delta between ION's current practice and full Secure by Design alignment for defence-tier supplier requirements. Each is logged in `_backlog_v0_23.md` (or the equivalent next-version backlog) with an indicative effort.

### Process gaps

| Gap | Status | Indicative target |
|-----|--------|-------------------|
| Public vulnerability disclosure channel (`SECURITY.md` + GPG contact) | Not in place | v0.24.x |
| Branch protection on `main` (force-push, required reviews) | Not in place | Configurable at the GitHub level — administrative, not code |
| Signed commits enforced | Not in place | Configurable at the GitHub level |
| Independent design review for solo-maintainer changes | Partially mitigated by AI pair (§6.3) | Requires customer-side DSO — deployment-specific |
| Formal Incident Response Plan (separate doc) | Embedded in §3.5.4; not separate doc | v0.25.x or earlier on customer request |
| End-of-life calendar for shipped releases | Not in place | Process-only; can be authored without code change |

### Tooling gaps

| Gap | Status | Indicative target |
|-----|--------|-------------------|
| ~~CI/CD pipeline (`.github/workflows`)~~ | **Closed v0.24.0** — `test.yml` runs pytest + ruff + bandit on every push and PR. |
| ~~Software Composition Analysis (Snyk / pip-audit)~~ | **Closed v0.25.0** — `pip-audit` runs in CI on every push and PR against the OSV database. One CVE-2024-23342 ignore documented with justification (ecdsa Minerva timing side-channel; not reachable in ION's RS256-only OIDC path). |
| Software Bill of Materials (SBOM) generation at build | Not in place | v0.24.x — `syft` or equivalent on the Docker image |
| Container image signing (cosign / Sigstore) | Not in place | v0.25.x — depends on customer infrastructure |
| Pinned dependency versions (vs `>=` floor) | Not in place | v0.24.x — `pyproject.toml` constraint hardening |
| Prometheus metrics endpoint | Not in place | v0.26.x — speculative |
| Standalone system-level threat model document (STRIDE/PASTA) | Per-change threat modelling in spec/commit only | v0.24.x |
| Quantitative test coverage target + reporting | Reviewer judgement only | v0.24.x — `coverage` integration |

### Compliance-only gaps

| Gap | Status |
|-----|--------|
| ISO 27001 certification | Not pursued. Customer environment is responsible for hosting controls; supplier-side Cyber Essentials Plus is in scope for the maintainer's organisation outside this repository. |
| Penetration test by independent third party | Not in place. Per-release `SECURITY_ASSESSMENT.md` is the standing internal audit. For higher-assurance deployments, customer-funded annual third-party pen-test is the recommended additional control. |

---

## 9. Revision History

| Version | Date | Author | Change |
|---------|------|--------|--------|
| 1.0 | 2026-05-11 | Maintainer | Initial publication, aligned to Secure by Design 5 phases. Cross-referenced NCSC SD&D 8 principles. Gap analysis (§8) captures the delta to full defence-tier supplier alignment. |
| 1.1 | 2026-05-11 | Maintainer | v0.24.0: CI pipeline landed at `.github/workflows/test.yml` (pytest + ruff + bandit). §3.4.4 rewritten to describe the running CI. §4 NCSC Principle 6 status moved from **Partial** to **Met**. §8 CI gap struck through with closure note. |
| 1.2 | 2026-05-11 | Maintainer | v0.25.0: Software Composition Analysis (`pip-audit`) added as a 4th parallel CI job, scanning the resolved dep tree against OSV. §3.4.4 lists the new job and the documented `--ignore-vuln` baseline. §4 NCSC Principle 4 status moved from **Partial** to **Mostly Met**; Principle 6 prose updated to list pip-audit alongside bandit. §8 SCA gap struck through with closure note. |

---

**End of document.**
