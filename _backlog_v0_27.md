# v0.27.0 Candidate Backlog

Curated from v0.22.0 → v0.26.0 deferrals, audit findings, and prior security assessments. Each item lists rough size (S/M/L), source, and a one-line case for picking it up.

> **Update 2026-05-11:** v0.22.1 (security) → v0.23.0 (adaptive lab grading session 1) → v0.23.1 (3 operator bugs) → v0.23.2 (panel-dropdown close) → v0.24.0 (lab grading session 2 + CI pipeline + TIDE cleanup) → v0.25.0 (lab grading session 3 + pip-audit SCA + backlog rename) → v0.25.1 (PCAP auto-analysis multi-alert fix) → **v0.26.0 (lab grading session 4 pass-threshold + history + SBOM via syft + ruff red CI closed + SDLC §3.4.8 acceptance testing)** all shipped. This file is now the v0.27.0 candidate list. File rename to `_backlog_v0_27.md` recommended at v0.27.0 spec time.

---

## Carry-over from v0.22.0 (still open)

### [M] Per-system drilldown filter for the MITRE heatmap
Source: `_spec_v0_22.md` §3.6.
The heatmap service already accepts `?system_id=N` but the v0.22.0 template doesn't expose the filter form. Surface a system selector on the page so analysts can scope coverage to a single CyAB system's data sources.

### [M] Unified case-timeline view (pin + annotation + ledger interleaved)
Source: `_spec_v0_22.md` §4.7 (sealed as out-of-scope for v0.22.0).
Annotations currently render in the Workbench panel only. A chronological timeline view interleaving pins + annotations + ledger events by timestamp would improve case review UX. Operator originally chose to defer; revisit if analysts ask for it.

### [S] `annotation_edits` history table
Source: `_spec_v0_22.md` §7 Resolved 2 (deferred).
Currently no audit trail when an analyst edits their annotation. If a compliance ask arrives requiring full edit audit, add an `alert_case_annotation_edits` + `forensic_case_annotation_edits` history table and have the update service append to it.

### ~~[S] Drop `ION_TIDE_SYNC_INTERVAL` deprecation fallback~~
**Closed v0.24.0** — fallback block reduced to single env-var read.

---

## v0.22.0 audit deferrals (still parked)

### [S] Consolidate `/health` and `/health/deep`
Source: audit Amend C.
Both endpoints re-import `ion.__version__` and rebuild DB info. `/health/deep` should call shallow internally rather than duplicating the version/DB logic.

### [M] Collapse `recommended-playbooks` and `suggested-playbooks`
Source: audit High-confidence #5.
`/elasticsearch/alerts/{id}/recommended-playbooks` returns a strict subset of `/elasticsearch/alerts/{id}/suggested-playbooks`. Replace with a single endpoint accepting `?active_only=true|false`. Caller-check UI/templates before merging.

### [M] Per-system 8-question assessment wizard wiring
Source: CHANGELOG line 3733 ("per-system overlays land next ship").
Backend (model + endpoint + scoring) works end-to-end via the API; the system-detail page wizard isn't wired. Surface the wizard on the per-system page.

### [M] DAG executor conditional edges
Source: CHANGELOG line 3532 ("Branching arrives next ship").
Workflow executor walks `next` linearly. Add branching: per-node `next_on_success` / `next_on_failure` (or condition-based) edges so workflows can fork.

### [S] Standardise the kb_*.py registry format
Source: audit Amend D.
v0.22.0 dropped the `uses_functions` flag via `callable()` duck-type but the underlying format inconsistency across 13 `kb_*.py` modules remains. Choose one format and convert the minority three (Main KB, Blue Team, Foundations) so new contributors don't have to learn two patterns.

### [S] Share the embedding-service tick between case + KB loops
Source: audit Sprawl 3.
`case_embedding_service` and `kb_embedding_service` both poll at 300s default and both call `EmbeddingService.embed()`. Consolidate behind a single scheduler tick to halve wakeups.

---

## Ticker subsystem — design rethink (removed v0.26.1)

The original ticker service (v0.10.3+) flagged critical alerts open without a case for N minutes and supported manual admin announcements. It was removed in v0.26.1 after the §3.4.8 walk surfaced that the background loop crashed every tick on an enum-case bug (`AlertTriageStatus` stored as enum NAME `'OPEN'`, queried as `'open'`) AND the auto-flagging design conflicted with the v0.23.x investigation-queue ownership model (analysts were getting flagged for queues that other workers owned).

The DB table (`tickers`) and ORM model (`src/ion/models/ticker.py`) were kept so legacy rows aren't lost and `wallboard_service._collect_ticker` continues to work read-only against existing rows. New tickers no longer get created.

If a future analyst-attention-surface is needed:
- Use the existing v0.23.1 investigation queue UI as the primary attention surface (it already shows pending work and is ownership-aware).
- A redesigned ticker would be event-driven (subscribe to specific audit events) rather than polled — no background loop, no enum-case footguns.
- Manual admin announcements could move into a separate `system_announcements` table with a much smaller surface than the old `Ticker` model (no severity matrix, no auto-resolve logic, just a banner + dismissable flag).

Not in scope for v0.27.0 — flagged here so a future ticker discussion has the prior-art context.

---

## Lab fixture system repair — v0.27.0 PRIORITY (4 dormant bugs found via v0.26.0 §3.4.8 acceptance walk)

Discovered during the v0.26.0 release acceptance walk-through that the lab fixture system has been broken end-to-end since v0.21.0 — four compounding bugs. Unit tests pass (32 cases across v0.25/0.26 suites) because they bypass the FastAPI router and the seeding pipeline; nothing exercises the deployed-image path until §3.4.8 ran. The headline v0.23-0.26 lab grading features (criterion kinds, audit events, pass-threshold, history) all work in isolation, but the analyst has never been able to actually run a graded lab session via the deployed UI.

### [S] Bug 1 — `labs_api` router prefix missing `/api/`
`src/ion/web/labs_api.py` route decorators read `@router.post("/courses/{slug}/lessons/{lesson_id}/lab/{launch,complete}")` but the router is mounted with `prefix=""`. The frontend at `src/ion/web/templates/lesson.html` calls `/api/courses/.../lab/launch`. Endpoint has been returning 404 since v0.21.0. **Fix already staged locally during the walk-through** (decorators rewritten to include `/api/` prefix, matching `course_api.py`'s convention). Uncommitted as of 2026-05-12; decide whether to land it as a surgical v0.26.1 or bundle into v0.27.0.

### [S] Bug 2 — `seed_lab_fixtures.py` not shipped in Docker image
The Dockerfile Stage-2 COPY list omits `seed_lab_fixtures.py`. The script can't be run inside a deployed container, so the `lab_fixtures` table is never populated in production. Fix: add the file to the COPY block alongside the other seed scripts.

### [S] Bug 3 — `seed_lab_fixtures.py` enum case mismatch
`seed_lab_fixtures.py:109` filters by `l.lesson_type = 'lab'` (lowercase) but SQLAlchemy `SQLEnum(native_enum=False)` stores the enum NAME (`'LAB'`, uppercase) — same dialect pattern that bit v0.23.2's case-close test. Script silently inserted zero fixtures even when run manually. **Fix already staged locally** (rewrote as `UPPER(l.lesson_type) = 'LAB'`). Uncommitted as of 2026-05-12.

### [M] Bug 4 — Lab fixtures invisible in the `/alerts` UI
`GET /api/elasticsearch/alerts` reads ONLY from Elasticsearch; fixture rows in `alert_triage` have no matching ES document so they don't appear in the list view. The analyst can't open them, so the `alert_view` audit row never fires, so the `viewed_alert` grader never matches. The lab fixture system needs one of: (a) `seed_lab_fixtures.py` pushes a synthetic ES document too (breaks the air-gap if ES isn't reachable at seed time; may need a separate "lab mode" code path); (b) `/alerts` list endpoint falls back to `alert_triage` rows when no matching ES doc exists; (c) a parallel `/lab-alerts/{lesson_id}` page that renders from `alert_triage` directly. **(b) is probably the right call** — adds a UNION/LEFT JOIN to the list query, lets fixture alerts surface alongside real ES alerts under a "Lab fixture" badge. The fixture detail link `/alerts/<triage_id>` from `lab_fixture_service._observable_link` also needs a real page route OR the link format needs to change to `/alerts?selected=<triage_id>` matching whatever the list page uses to pre-open a detail panel.

### How to scope v0.27.0

The four bugs are tightly coupled — fixing any one in isolation doesn't unlock end-to-end lab grading. Ship them as one bundle:
- v0.27.0's **feature slot** = "lab fixture system repair" (bundle bugs 1+2+3+4).
- New tests required:
  - HTTP-level integration test for `POST /api/courses/{slug}/lessons/{id}/lab/launch` via FastAPI TestClient (would have caught bug 1 immediately on first push).
  - Post-seed smoke for `seed_lab_fixtures.py` — assert `lab_fixtures` table has ≥1 row after the script runs (would have caught bugs 2 + 3).
  - Smoke for the alerts-list fallback path (bug 4).
- v0.27.0's **§3.4.8 acceptance gate** = complete the L1 M2 lab end-to-end through the browser: Launch → open fixture alert from /alerts (fires `alert_view` audit) → link both alerts to LAB-CASE-0001 (fires `alert_linked` audits) → Complete lab → score 100, status COMPLETED, green toast, history card shows green Pass badge. If THAT walks cleanly, the system is genuinely working.

The walk-through itself validates the v0.26.0 features in passing — pass-threshold + history will render correctly the moment a real graded session can complete.

## Adaptive lab grading — v0.27.0 follow-ups (sessions 1/2/3/4 shipped)

### ~~[M] Multi-criterion rubrics for L1 M5, L1 M7, L2 M2, L2 M5~~
**Closed v0.25.0** — all four LAB lessons now have rubrics built on the `observable_created` and `case_closed_with_reason` criterion kinds.

### ~~[M] `observable_created` and `case_closed_with_reason` criterion kinds~~
**Closed v0.25.0** — both evaluators + their `observable_linked` / `case_closed` audit events.

### ~~[S] Pass-threshold enforcement~~
**Closed v0.26.0** — `UserLessonProgress.status` becomes `failed` when score < `Course.pass_threshold` (boundary inclusive). Lifted into `labs_api.pick_lab_lesson_status` helper for unit testability.

### ~~[M] Score history view~~
**Closed v0.26.0** — `GET /api/courses/{slug}/lessons/{id}/lab-sessions` returns past attempts newest-first with per-criterion breakdown baked in. `lesson.html` "Lab attempt history" subpanel with status badges + expandable per-attempt breakdown.

### [M] Lab fixtures for the four newly-graded labs (L1 M5, L1 M7, L2 M2, L2 M5)
v0.25.0 backfilled with fixture-independent kinds only. To grade with `viewed_alert` + `linked_to_case` on these labs, extend `seed_lab_fixtures.py` from a single-lesson file to a per-lesson registry, then layer those kinds onto the existing rubrics for higher fidelity grading.

### [M] Fixture/rubric support for L2 M8, L3 M3, L3 M6
The three remaining LAB lessons grade actions that require criterion kinds tied to TIDE rule creation (M8) and Caldera operation telemetry (M3/M6) — neither exists today. Scope: research what audit surfaces would feed each, define the criterion kinds, add evaluators.

### [M] Real-time grading ticker
Background worker that grades open lab sessions every N seconds so criteria fire and feedback renders without waiting for `/lab/complete`. Matches the `case_embedding_service` + `kb_embedding_service` pattern. **Natural v0.27.0 feature slot.**

### [S] Lab retry-from-failed affordance
When an attempt fails, surface a "Retry lab" button on the lesson page that bumps `attempt_number` and resets session state automatically. v0.26.0 history subpanel makes this discoverable.

### [S] Additional criterion kinds — `regex_in_analyst_notes`, `mitre_technique_tagged`
Two more kinds with concrete use cases: `regex_in_analyst_notes` would grade open-text analyst journaling on cases, and `mitre_technique_tagged` would grade whether the analyst correctly applied ATT&CK technique tags during triage.

### [S] Grade-snipe documentation in RUNBOOK
The v0.23.0 SECURITY_ASSESSMENT.md documents that a learner with `alert:read` can trigger `alert_view` audit rows by direct API call. Add a short RUNBOOK note for instructors who want to detect / discourage this. Same concern now applies to `observable_linked` and `case_closed` audit rows.

---

## SDLC §8 gap closures — v0.27.0+ candidates

CI pipeline (v0.24.0), SCA via pip-audit (v0.25.0), SBOM via syft (v0.26.0), and ruff red CI (v0.26.0) all closed. Remaining gaps from `docs/DEVELOPMENT_LIFECYCLE.md` §8:

### ~~[M] Software Bill of Materials (SBOM) at Docker build~~
**Closed v0.26.0** — syft 1.18.1 generates SPDX-JSON at Docker build, shipped at `/app/sbom.spdx.json` in the image.

### ~~Ruff red CI~~
**Closed v0.26.0** — codebase-wide ignores added for deliberate-style rules + per-file ignores for SQLAlchemy ORM forward-refs and content modules; `ruff check src/` returns 0 errors.

### [M] Close pytest red CI (sole remaining red job)
2 pre-existing fixture-leak failures: `test_get_nonexistent_run_404` (missing `bob_eval_runs` table — likely a missing `_run_migrations` call in the fixture setup) and `test_overview_kpi_strip_reflects_new_system_count` (FOREIGN KEY constraint on `cyab_wizard_sessions.user_id` — a parent row that should exist by ordering doesn't). Run each in isolation first to confirm root cause. Landing this makes v0.27.0 the first version with fully-green CI on the tag commit — SDLC §3.4.4 release gate finally fully satisfied.

### [S] Public vulnerability disclosure channel
Add `SECURITY.md` at repo root with a documented private contact (GPG-signed email or GitHub Security Advisory). Required for many supplier-assurance frameworks. **Smallest remaining SDLC §8 closure — natural cleanup slot for any v0.27.x release.**

### [M] Pinned dependency versions
Replace `>=` floors in `pyproject.toml` with exact-version pins (`==`) for the runtime deps. Reproducible builds across rebuild events. Trade-off: pin maintenance becomes a recurring task (Dependabot-style PRs).

### [S] Container image signing (cosign / Sigstore)
Sign the Docker image at release time so deployers can verify provenance. Requires customer-side cosign verification infrastructure to be useful.

### [M] Standalone system-level threat model document
STRIDE or PASTA model authored as a separate doc (per-change threat modelling currently lives in spec/commit bodies). External reviewers commonly ask for the standalone artefact.

### [S] Quantitative test coverage reporting
`pytest --cov=src/ion` + a coverage badge + a CI threshold. Doesn't move the security needle by itself, but is a common defence-tier ask.

### [L] python-jose → PyJWT migration
The v0.25.0 SCA workflow allowlists CVE-2024-23342 (ecdsa Minerva timing side-channel) because ION's RS256-only OIDC path doesn't reach the vulnerable signing code, AND the upstream `ecdsa` maintainer states the fix is "use a different library". Replacing `python-jose[cryptography]` with `PyJWT` removes the ignore entirely and is the cleaner long-term fix.

### Process gaps (administrative, not code)
- Branch protection on `main` (GitHub setting; force-push prevention + required reviews).
- Signed commits enforced (GitHub setting).
- End-of-life calendar for shipped releases (`docs/EOL.md` or equivalent).
- Formal Incident Response Plan as a standalone document (currently embedded in §3.5.4).

---

## Quality-of-life

### [S] Stale untracked files in repo root
There are ~13 `_research_*.md` files untracked, plus `.local-test-bob.py`, `seed_test_data.py`. Decide: keep as personal scratch (current pattern) or move to `~/ixion-notes/` outside the repo. If they're being kept indefinitely, add to `.gitignore` explicitly so `git status` is quieter.

### [S] Spec / handoff / backlog parking spot
v0.22.0's spec, the rolling backlog (this file), and each handoff doc all live untracked in repo root. Decide: commit to `docs/specs/vX.Y.md` for posterity, or keep the untracked-scratch pattern.

---

## How to pick for v0.27.0

If the user gives no signal, propose **1 feature + 1 SDLC closure + 1 cleanup** mixed plate (matches v0.22.0 → v0.26.0 shape).

Natural pairings (top picks):
- **Feature:** lab grading session 5 — real-time grading ticker (M; mirrors `case_embedding_service` + `kb_embedding_service` pattern). Lets the analyst see grading feedback without waiting for `/lab/complete`. The infra is already there (advisory lock pattern, scheduler), so this is mostly wiring a worker around `lab_grading_service.grade_session`.
- **SDLC closure:** `SECURITY.md` disclosure channel (S; ~30 min). Smallest remaining §8 item. Author the file at repo root with private contact + GPG fingerprint, add a Documentation table entry in `README.md`, bump §8 + §4 NCSC Principle 5 in the SDLC doc.
- **Cleanup:** close the pytest red CI (M; fixture-isolation investigation). Two failures need root-causing. Landing this is **load-bearing** — v0.27.0 becomes the first version with fully-green tag-commit CI, satisfying SDLC §3.4.4 in full.

Alternate cleanup if pytest is too investigation-heavy: consolidate `/health` and `/health/deep` (S) OR collapse `recommended-playbooks` + `suggested-playbooks` with `?active_only=` (M). Both are v0.22.0 audit deferrals.
