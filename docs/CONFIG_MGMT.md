<!-- ion-doc:type=CONFIGURATION MANAGEMENT -->
<!-- ion-doc:title=ION Configuration Management Plan -->
<!-- ion-doc:subtitle=Source control, branching, release ritual, configuration items catalogue, change control -->
<!-- ion-doc:version=0.29.1 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Customer DA, audit, change-control board, integrators -->
<!-- ion-doc:date=2026-05-12 -->

# 1. Purpose

This Configuration Management Plan (CMP) describes **how ION's configuration items (CIs) are identified, versioned, controlled, audited, and released**. It is the single document customer change-control bodies and auditors ask for when they need to understand how ION's deployable state is managed.

## 1.1 Companions

- `docs/DEVELOPMENT_LIFECYCLE.md` — SDLC reference (process)
- `CHANGELOG.md` — per-release change record (audit)
- `SECURITY_ASSESSMENT.md` — per-release security impact
- `_mod_through_life_plan.md` — through-life support tied to versioning
- `docs/VULN_MGMT.md` — patch-cadence policy

# 2. Source control

| Property | Value |
|---|---|
| Source-control system | **Git** (DCVS) |
| Public repo | `github.com/ixion36-svg/ion` |
| Customer-side mirror | GitLab (per customer infrastructure) |
| Code review | Pull-Request / Merge-Request based |
| Default branch | `main` |
| Branch protection | Required: passing CI; required reviewer (maintainer for public repo); signed commits encouraged |

## 2.1 Branching model

ION uses **trunk-based development** with very-short-lived feature branches:

```
main (always green; deployable)
  ├── feat/<scope>     ─ feature work; merged via PR/MR within days
  ├── fix/<scope>      ─ bug fixes; same lifecycle
  ├── chore/release-X  ─ release ritual commits (lives ~minutes before merge)
  └── docs/<scope>     ─ doc-only changes
```

**No long-lived release branches.** ION ships from `main` at each tag.

# 3. Configuration items (CIs) catalogue

Every artefact that affects what ION runs is a CI under version control:

| CI ID | Artefact | Location | Versioned by |
|---|---|---|---|
| CI-CODE | Source code (Python, Jinja templates, CSS, JS) | `src/ion/` | Git |
| CI-DEPS | Python dependencies | `pyproject.toml` + `uv.lock` (or equivalent) | Git + dependency lock |
| CI-CI | CI workflows (ruff + bandit + pip-audit + pytest + syft) | `.github/workflows/` | Git |
| CI-DOCKER | Container image build | `Dockerfile` + Docker Hub tag | Git + Docker Hub digest |
| CI-COMPOSE | Compose orchestration | `docker-compose.yml`, `docker-compose.deploy.yml` | Git |
| CI-MIGRATIONS | Database schema migrations | `migrations/versions/` | Git + alembic |
| CI-DATA-BUNDLED | Bundled reference snapshots (ATT&CK, KEV) | `data/attack/`, `data/kev/` | Git + per-release refresh |
| CI-SEED | Seed data (alert prompt templates, courses, CyAB content) | `data/seed/`, `scripts/seed_*.py` | Git |
| CI-CONFIG | Per-deployment env-var template | `.env.deploy` | Git |
| CI-DOCS-PUBLIC | Public documentation | `docs/`, root-level `.md` | Git |
| CI-DOCS-COMPLIANCE | MOD-overlay compliance pack | `_mod_*.md` | Customer-side controlled; not in public repo |
| CI-SBOM | Software bill of materials | `/app/sbom.spdx.json` inside image | Built by `syft` at release; immutable per tag |
| CI-OPENAPI | OpenAPI specification | `/api/openapi.json` (runtime-generated from code) | Inherits CI-CODE |

# 4. Version identification

## 4.1 Semantic versioning

ION follows **semver**:

| Part | Meaning | Examples |
|---|---|---|
| **MAJOR** | Breaking change to API / data model | `v1.0.0` (future) |
| **MINOR** | New feature, backward-compatible | `v0.29.0` (operations + knowledge nav condensation) |
| **PATCH** | Bug fix, no API change | `v0.29.1` (PCAP IP-fallback) |

## 4.2 Where the version appears (the 8-file release ritual)

Every release bumps **exactly these files** atomically. This rule is load-bearing: skipping any file rots the version across the system. The list is the canonical source.

| File | Occurrences | Why it matters |
|---|---|---|
| `src/ion/__init__.py:__version__` | 1 | UI footer (`{{ ion_version }}`) — load-bearing for every Jinja template |
| `pyproject.toml:version` | 1 | Build metadata; PyPI / Docker label inputs |
| `docker-compose.yml` (`ION_VERSION` default) | **2** | Local dev compose — the string appears on two `image:` lines |
| `Dockerfile` (OCI label `org.opencontainers.image.version`) | 1 | Image metadata |
| `README.md` badge | 1 | Public-facing version statement |
| `.env.deploy` (`ION_VERSION`) | 1 | Deploy template |
| `CHANGELOG.md` | — | New top entry, plus the `ion-doc:version`, `ion-doc:subtitle` and `ion-doc:date` header comments |
| `SECURITY_ASSESSMENT.md` | — | Delta prepended to the **Application Version** chain, plus the same three header comments and the **Assessment Date** line |

**Eight files; six of them carry a version string, across seven occurrences.**
That is what the "8-file rule" counts, and it is correct.

**Corrected in v0.99.6.** This section previously listed a ninth file,
`docker-compose.deploy.yml` — *which does not exist in this repository* — and
then explained the discrepancy away as "9 items, but SECURITY_ASSESSMENT is
sometimes considered an output". Both halves were wrong. The deploy compose
files present are `docker-compose.dev.yml` and `docker-compose.test.yml`,
neither of which carries a version; the deploy version lives in `.env.deploy`,
already in the table. The phantom row is removed, and the `docker-compose.yml`
row now states its **two** occurrences, which a single-substitution edit would
otherwise leave half-bumped.

This table now agrees with the two canonical lists in
`docs/RUNBOOK.md` ("Release Ritual — Version Bump") and
`docs/DEVELOPMENT_LIFECYCLE.md` §3, **both of which were already right.** If the
three ever disagree again, RUNBOOK is canonical — `DEVELOPMENT_LIFECYCLE.md`
says so explicitly, and it carries the sanity-check greps.

### Rot check

After bumping, verify no stale version remains. Three classes of match are
expected and must NOT be changed:

* `CHANGELOG.md` — every prior entry names its own version. That is history.
* `SECURITY_ASSESSMENT.md` — the **Application Version** chain names prior
  versions deliberately.
* `archive/README.md` — provenance rows record *when* each subsystem was
  archived, not the current version.
* KB content and tooling fixtures contain IP addresses and sample data that
  look like versions (`10.0.99.50`, `10.0.99.5`, `10.20.99.5`). Match on a
  version *assignment*, not a bare substring.

## 4.3 Image digest immutability

| Property | Value |
|---|---|
| Image tag is immutable per version | YES — never re-pushed |
| Image digest captured per release | YES — recorded in `_mod_design_passport.md` §2 at gate sign-off |
| Customer verification | `docker inspect <image> --format '{{.RepoDigests}}'` |

# 5. Release ritual

The full release ritual is documented in `docs/DEVELOPMENT_LIFECYCLE.md` §3 + `docs/RUNBOOK.md`. Summary:

## 5.1 Two-commit pattern

Each release uses two commits:

1. **`feat: <change>`** — the actual code change (one or more commits leading up to this)
2. **`chore(release): vX.Y.Z`** — the 8-file version bump

This makes CHANGELOG decoupled from feature work; reviewers can read either commit standalone.

## 5.2 Release-acceptance walk (§3.4.8)

After tagging a release, the maintainer performs the §3.4.8 walk:

| Step | Check |
|---|---|
| 1 | Pull the released image into a clean environment |
| 2 | Deploy via the documented `docker-compose.deploy.yml` |
| 3 | Run smoke checks (per `_mod_iteap.md` §1) |
| 4 | Verify the UI footer shows the bumped version |
| 5 | Verify SBOM in the image (`/app/sbom.spdx.json`) is intact |
| 6 | Verify CHANGELOG entry exists at the top |
| 7 | Verify SECURITY_ASSESSMENT.md has the new delta row |
| 8 | Visually walk the changed surfaces from the changelog |

Issues found here are fixed silently per `feedback_fix_silently.md` (closeout-pass issues like encoding, lint, minor version-count miscounts are corrected and the release proceeds; only true feature regressions are surfaced).

## 5.3 What never skips

Per the same `feedback` memories:

- **Never skip hooks** (`--no-verify`) unless explicitly requested
- **Never bypass signing** (`--no-gpg-sign`) unless explicitly requested
- **Never amend a published commit** — always make a new commit (`feedback_release_version_bump.md`)

# 6. Change control board (CCB)

For customer-side change control, the customer's CCB processes ION upgrades per the customer's normal change-management process. The customer's CCB receives the following from the maintainer for each release:

| Artefact | Where it lives |
|---|---|
| Version number | CHANGELOG.md top |
| Change description | CHANGELOG.md entry |
| Security delta | SECURITY_ASSESSMENT.md delta row |
| Image digest | Docker Hub + release notes |
| SBOM | `/app/sbom.spdx.json` (extractable) |
| Migration impact (if any) | Migration files in repo + CHANGELOG annotation |
| Backwards compatibility | Implied from semver (Minor = backward-compatible; Patch = bug fix) |
| Rollback plan | "Re-deploy previous image tag" — image immutability makes this trivial |

# 7. Migrations

## 7.1 Schema migrations

Every schema change ships as an alembic migration in `migrations/versions/`. Migrations are:

- Forward-only (no auto-down) by default
- Tested against a copy of customer's data in non-prod first
- Idempotent where possible
- Reversible where the change has any data-destructive risk (explicit `down_revision` paths)

## 7.2 Data migrations

When a release requires data backfill (e.g. embedding generation for newly-added similarity feature), the backfill runs in a background advisory-lock-protected worker. No operator action needed.

## 7.3 Breaking migrations

Truly breaking migrations (e.g. column rename) are split:

1. Phase A: add new column; backfill from old
2. Phase B: deploy new code that reads new column
3. Phase C: deploy migration that drops old column

This phased approach keeps each individual release backward-compatible.

# 8. Configuration audit cadence

| Audit | Cadence | Owner |
|---|---|---|
| `__version__` matches across the 8 files | Per release (release-acceptance walk) | Maintainer |
| CHANGELOG entry exists for each released tag | Per release | Maintainer |
| `SECURITY_ASSESSMENT.md` has a delta row per release | Per release | Maintainer |
| Image digest recorded | Per release | Maintainer |
| SBOM regenerated from the build | Per release | CI |
| Customer's deployed version matches a released tag | At deploy + monthly check | Customer ops |
| Dependency drift (planned upgrade) | Weekly + dependabot / equivalent | Maintainer |

# 9. Configuration identification artefacts

For the customer's CCB / CMDB:

| Field | Source |
|---|---|
| Application name | `pyproject.toml` |
| Version | `__version__` |
| Image | Docker Hub digest |
| Vendor | `ixion36` / Guarded Glass |
| License | MIT (in `LICENSE` file) |
| Architecture statement | `docs/HLD.md` |
| Operational tier | `_mod_safety_questionnaire.md` Q12 (Operationally-Significant) |
| Safety classification | `_mod_safety_questionnaire.md` (Safety-Benign / SIL-0 / DAL-E) |
| Information classification | `_mod_iar.md` (OFFICIAL) |

# 10. Configuration drift detection

| Drift type | How detected |
|---|---|
| Customer's deployed image ≠ documented version | Customer's monitoring + `/health` endpoint reports version |
| Customer's `__version__` (in Jinja footer) ≠ released | Visual inspection on first login per release |
| Dependencies in deployed image ≠ released SBOM | Customer can extract SBOM and diff (very rare — would imply image tampering, IR-S-06) |
| Customer-side modifications | NOT supported; if customer needs a fork, file a change request with maintainer |

# 11. Sign-off

- ION maintainer (process owner)
- Customer change-control board (process acceptance per customer policy)
- Customer SRO (Acceptance gate)

# 11a. Runtime configuration boundary

As of 2026-10-04, `.env` holds **8 keys and nothing else**. Everything else is
managed in the settings UI and stored in `$ION_DATA_DIR/.ion/config.json`.

**Read before ION can consult its own config, so they cannot move (6):**
`ION_VERSION`, `ION_DATA_DIR`, `ION_HOST`, `ION_PORT`, `ION_WORKERS`,
`ION_LOG_LEVEL`. `ION_DATA_DIR` is the strongest case: it is how `config.json`
is located. `ION_LOG_LEVEL` has no `Config` field and is consumed when logging
is set up, before config loads.

**Secrets structurally pinned to the environment (2):**

- `ION_DB_PASSWORD` — Compose interpolates it into `POSTGRES_PASSWORD`
  (`docker-compose.yml:71`, with `:?` so Compose refuses to start without it)
  and into `ION_DATABASE_URL` (`:145`, `:309`), before any ION process exists.
- `ION_ADMIN_PASSWORD` — read from `os.environ` at `src/ion/web/server.py:583`
  and `:785`. There is no `admin_password` field on `Config`. Removing it makes
  the startup weak-password check abort the boot with `CONFIG FATAL`.

**Why the other integration secrets are NOT in `.env`.** `Config.to_file`
(`src/ion/core/config.py:499`) serialises the whole in-memory config, secrets
included, and every section `PUT` calls it. Secrets therefore reach
`config.json` whatever `.env` says, so keeping a second copy in `.env` bought
nothing and described a boundary the code does not honour.

**Consequence: back up the `ion-data` volume.** The Elasticsearch, Kibana,
Arkime, GitLab, OpenCTI and TIDE credentials now live only in `config.json`
inside that volume. Losing the volume loses them.

**Environment variables still win.** `get_config()` ranks env above
`config.json`, so re-adding a key to `.env` silently overrides the UI. The
settings page shows an environment-held field read-only with a "set by
environment" badge, and drops it from the save payload.

Be precise about what that drop buys, because it is narrower than it looks:
every section `PUT` ends in `config.to_file(get_config_path())` against the
env-merged config object, so a save to any section rewrites the whole file
including env-held values. Dropping the field client-side prevents a masked
secret being written back, an SSRF rejection on an env-held empty URL, and
needless reassignment. It does not stop env values reaching `config.json`.

**The badge is a partial guard, not a general one.** `ENV_FIELD_MAP`
(`src/ion/core/config.py`) covers 37 of the ~153 `ION_*` variables
`get_config()` honours. Fields outside it — most of OIDC, `dfir_iris_*`,
`abuseipdb_*`, `virustotal_*`, `tide_api_key`, `elasticsearch_api_key`,
`ollama_model`, `ollama_timeout`, `kibana_case_owner` — are editable in the UI
and can still be silently overridden by an environment variable with no badge.
Extending the map to every field `GET /config` returns is outstanding work.

**Two fields are injected by Compose and are always environment-held.**
`docker-compose.yml` sets `ION_BASE_URL` and `ION_OLLAMA_URL` with `:-`
defaults, so they are present in the container whether or not `.env` lists
them. Both therefore render read-only with the badge and are managed in
`docker-compose.yml`, not in the UI. `base_url` is the OIDC redirect URI, so
check it before enabling OIDC.

**A fresh install starts from defaults.** `docker-entrypoint.sh` seeds a new
volume's `config.json` from `ION_*` variables that are now absent, so a brand
new deployment comes up with built-in defaults and must be configured through
the settings UI.

`tests/test_env_boundary.py` keeps the shipped templates honest.

**Known stale guidance.** `.env.deploy`, `deploy/DEPLOYMENT_GUIDE.md`,
`deploy/OPENCTI_INTEGRATION.md`, `docs/DEPLOYMENT.md` and `docs/LLD.md` still
describe configuring integrations through `.env`. They predate this boundary
and have not been rewritten.

# 12. Change history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-05-12 | ION maintainer | Initial CMP authored at v0.29.1 |
