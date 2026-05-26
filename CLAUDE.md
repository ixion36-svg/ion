# ION — Claude Code project memory

ION (Intelligent Operating Network) is a Security Operations Portal. Stack: FastAPI + Jinja2 + Postgres (+ pgvector) + Ollama. **No SPA** — server-rendered HTML throughout. Ships to **air-gapped / siloed** environments; no live external feeds.

Current released version: **v0.31.9** (see `pyproject.toml`). Memory above (`~/.claude/projects/.../memory/`) holds the cross-session context; this file is the repo-scoped index. Latest end-of-session handoff: `_handoff_v0_32.md`.

## Where to look first

| Need | Read |
|---|---|
| Architecture overview | `docs/ARCHITECTURE.md` |
| Stack inventory | `STACK.md` |
| Setup / first run | `SETUP.md` |
| Operations | `docs/RUNBOOK.md` |
| SDLC / Secure-by-Design (phases) | `docs/DEVELOPMENT_LIFECYCLE.md` (customer-agnostic — keep that way) |
| Secure-by-Design (principles + audit) | `docs/SECURE_BY_DESIGN.md` — 20 numbered principles, ION audit per principle, gap list |
| Recent change history | `CHANGELOG.md` |
| Backlog / next release | latest `_handoff_v*.md` (v0.32 captures the post-v0.31.9 state including the P15 pause point) |
| Latest handoff snapshot | latest `_handoff_v*.md` (v0.26 present; refresh on next release) |

## Load-bearing design choices

- **Advisory locks** for background tasks (`pg_advisory_lock`) — distinct namespaces per service. Workbench uses `CEVL` (AlertCase) / `FCWL` (ForensicCase); Labs use `LABS` (sessions) / `LABF` (fixture seed); Bob-eval harness uses `BPEH_NS`. Background-loop leader-election uses `LOCK_*` constants in `storage/database.py`.
- **AlertPromptTemplate 5-tier matcher**: `rule_id → regex → MITRE technique → tactic → groups`. Output contract pinned to `CaseClosureReason`.
- **AIFeedback ledger**: dual-write on fire-time + case-close. Readers MUST dedup with `MAX(id) per (alert_id, template_id)`.
- **Workbench ledger**: sha256 chain, tamper-evident. Ownership checks run **inside the service before mutation** (TOCTOU bug present in both pin services pre-v0.20.1 — never regress).
- **pgvector + HNSW** for case similarity (`CaseEmbedding`, `/cases/{id}/similar`). Embedder is Ollama `nomic-embed-text`.
- **Router prefixes** are mounted in `server.py` — decorators inside the router file MUST use relative paths or you get a doubled-prefix 404.

## Release ritual — the 8 files that ALL must bump

Canonical list (per `_spec_v0_22.md §5.4`, re-confirmed at v0.29.1):

- `pyproject.toml` — `version = "X.Y.Z"` (source of truth)
- `src/ion/__init__.py` — `__version__ = "X.Y.Z"` (Jinja-template-load-bearing)
- `README.md` — shields.io badge `version-X.Y.Z-blue`
- `Dockerfile` — OCI label `org.opencontainers.image.version="X.Y.Z"`
- `docker-compose.yml` — `ixion36/ion:${ION_VERSION:-X.Y.Z}` (TWO services)
- `.env.deploy` — `ION_VERSION=X.Y.Z`
- `CHANGELOG.md` — new `## vX.Y.Z — YYYY-MM-DD` heading at top
- `SECURITY_ASSESSMENT.md` — severity table column + Net-New Surfaces section

Run `/release-bump` for the guided ritual (skill at `.claude/skills/release-bump/`).

Historical annotations in source comments (`# v0.29.1: added X`) are NOT in the bump set — they're permanent markers.

## Known gotchas (learn once)

- **`Pydantic exclude_unset` null-bypass** — perm gates of the form `if value is None: return` are bypassable on PUT when client always emits the field. Compare against stored using `model_fields_set`. (Caught v0.22.1.)
- **`a or b if isinstance(c) else None`** — parses as `(a or b) if isinstance(c) else None`, drops `a` on type-check failure. Always write nested-path fallbacks as explicit if/else. (Caught v0.25.1 after 9 versions in flight.)
- **Postgres `json` type has no comparison operators** — `!= 'null'::json` won't compile; cast `col::text` and compare against `'null'`, or migrate the column to `jsonb`. (Caught v0.30.1 in three `mitre_heatmap_service` queries.)
- **`SQLEnum(native_enum=False)` stores the enum NAME — but only raw `text()` SQL bypasses the bind processor.** ORM filters (`M.status == "open"` or `… == EnumX.OPEN.value`) DO coerce via SQLAlchemy's `_object_lookup` — they silently work today, but write `M.status == EnumX.OPEN` so a future SQLAlchemy tightening doesn't break them. Raw `text("WHERE status = 'open'")` does NOT coerce → use the uppercase NAME or `UPPER(col)`. v0.30.0 lab fixture seed silently inserted zero rows for 9 versions due to this. See `tests/test_v032_sqlenum_name_storage.py` for the canonical contract.
- **TIDE certs / Kibana password / Windows IPv6** — see memory `project_ion_gotchas.md`.
- **`ION_FRESH_DB`** is a no-op.

## Integrations (11+) — env-var pattern

Elasticsearch, Kibana, TIDE, OpenCTI, Arkime, Keycloak (OIDC RS256), Ollama, plus stub harnesses under `test-*/` directories. Each integration has an `ION_<NAME>_*` env-var family and a test harness.

## Workflow notes

- **Pacing**: for multi-task plans, batch spec/quality reviews per phase; smoke/E2E once at end — don't review every task individually.
- **Closeout fixes**: trivial release-time issues (encoding, lint, version miscount, sanity-check hits) get fixed silently — surface only true feature regressions.
- **Curriculum authoring**: keep the `research-dossier → seed_courses.py → docker rebuild` pattern; do NOT shortcut via JSON import.
- **Service auth checks**: when a service commits, ownership/auth checks MUST run inside the service before mutation (lesson from v0.20.1 TOCTOU bug).

## Tooling installed under `.claude/`

| Path | What |
|---|---|
| `skills/release-bump/` | guided release ritual + drift checker |
| `skills/alert-prompt-add/` | scaffold a new AlertPromptTemplate |
| `agents/release-checker.md` | parallel release-readiness review |
| `agents/workbench-ledger-reviewer.md` | TOCTOU + sha256-chain auditor for workbench/ledger edits |
| `hooks/ruff_check.py` | PostToolUse — runs `ruff check` on edited `src/` Python files |
| `hooks/sensitive_paths_guard.py` | PreToolUse — confirmation gate on auth/cert/entrypoint paths |
| `settings.json` | wires the above |
