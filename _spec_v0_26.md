# ION v0.26.0 Architecture Spec

**Status:** Draft — ready for implementation.
**Date:** 2026-05-11
**Base version:** v0.25.1 (commit 8dfe997)
**Stack constraint:** FastAPI + Jinja2 server-rendered HTML + Tailwind CSS. No SPA.
**Shape:** mixed plate (1 feature + 1 SDLC-gap-closure + 1 cleanup), matching v0.22 / 0.23.0 / 0.24.0 / 0.25.0.

---

## 1. Goals and Non-Goals

### Goals

- **Feature — adaptive lab grading session 4:**
  - Pass-threshold enforcement. `UserLessonProgress.status` becomes `FAILED` instead of `COMPLETED` when the lab session's score is below the course's `pass_threshold`. The enum value already exists (used by quiz submission since v0.23.0); we just need to wire it on the lab path.
  - Lab history view. New endpoint `GET /api/courses/{slug}/lessons/{lesson_id}/lab-sessions` returns the analyst's past lab attempts with per-session per-criterion breakdown. New "Lab history" subpanel on `lesson.html` lists each attempt with status badge, score, completed timestamp, and an expandable per-criterion breakdown.
- **SDLC gap closure — Software Bill of Materials (SBOM) via syft:**
  - `Dockerfile` final stage runs `syft` to generate an SPDX-JSON SBOM at `/app/sbom.spdx.json` inside the image. Extractable via `docker cp`. Closes the §8 SBOM gap; updates SDLC doc §3.4.5, §4 P4 (Mostly Met → Met), §8, §9 v1.3.
- **Cleanup — close the ruff red CI job:**
  - Auto-fix the 74 fixable rule violations via `ruff check --fix` (I001 unsorted-imports, F541 f-string-missing-placeholders, safe-fix F401 unused-imports).
  - Fix the 13 F821 undefined-name findings — these are real bugs (referencing names that don't exist at the call site).
  - Add explicit ignores for the rule categories the codebase deliberately violates: E501 (line-too-long; existing per-file ignores extended OR line-length widened), E402 (module-level imports deferred for circular-dep reasons), N806 (non-lowercase variable in function — local SQL-aliased values), E741 (ambiguous variable name — short-loop vars), E712 (`x == True` — readability choice in some SQL filter callers).
  - Result: `ruff check src/` returns 0 errors. CI's `ruff` job moves Partial → Green.

### Non-Goals

- Real-time grading ticker. Background worker that grades open lab sessions every N seconds is deferred to v0.27.0+.
- Lab fixtures for L1 M5 / L1 M7 / L2 M2 / L2 M5 (extending `seed_lab_fixtures.py` to a per-lesson registry). Deferred — would let `viewed_alert` / `linked_to_case` grade on those labs too, but the v0.25.0 fixture-independent kinds already grade them; this is enhancement not gap.
- Fixtures + criterion kinds for L2 M8 / L3 M3 / L3 M6. Deferred — needs TIDE-rule and Caldera telemetry surfaces not exposed today.
- Image signing via cosign / Sigstore. Separate v0.27.0+ SDLC closure.
- python-jose → PyJWT migration. v0.25.0's pip-audit allowlist stays in place this release.
- pytest red CI job. Two fixture-leak failures are pre-existing v0.24.0-and-earlier issues. Deferred to v0.27.0 (or a fix-only patch release between v0.26.0 and v0.27.0).
- Closing the >300 E501 line-too-long warnings by manually re-flowing code. The 120-char limit was deliberately chosen at v0.22.0 (was 100, codebase exceeded). The non-data-module E501s are accepted as design noise; we keep them out of CI via per-file ignores where useful.

---

## 2. Real-Code Findings (surface map)

### 2.1 Lab grading wiring
- `src/ion/services/lab_session_service.py:125-152` — `complete(session, *, session_id, score, points_earned, points_max)` writes to `lab_sessions` only. Does NOT touch `UserLessonProgress`.
- `src/ion/web/labs_api.py:158-246` — `complete_lab()` endpoint calls `lab_session_service.complete()`, then (lines 216-223) hard-codes `UserLessonProgress.status = "completed"` regardless of score. **This is the surgery site.**
- `src/ion/models/course.py:71-75` — `LessonProgressStatus.FAILED = "failed"` already exists in the enum; used by quiz path since v0.23.0 (`src/ion/web/course_api.py:763`). No schema change.
- `src/ion/models/course.py:103-105` — `Course.pass_threshold: int` column, default 70.

### 2.2 Lab history surface
- No endpoint exists today that returns per-attempt history for a lesson. The `complete_lab` endpoint returns only the current attempt's result.
- `lab_sessions` table already records `attempt_number` per (enrollment, lesson) pair (via `lab_session_service.start_or_resume`). Natural sort: `completed_at DESC`.
- `lab_criterion_results` table stores per-(session, rubric) results from v0.23.0.

### 2.3 lesson.html template
- `src/ion/web/templates/lesson.html:111-127` — Lab environment panel with "Launch lab" / "Complete lab" buttons.
- `src/ion/web/templates/lesson.html:331-352` — Current "Lab grading breakdown" UI renders only the most recent grade via `_renderLabCriteria()`. Insertion point for the new history subpanel.

### 2.4 Dockerfile + CI
- `Dockerfile` — multi-stage. Stage 2 (runtime) is where syft slots in. Syft is available as a static binary from `anchore/syft` GitHub releases — install via curl-and-pin (air-gap-safe at build time; the maintainer's machine has internet).
- `.github/workflows/test.yml` — does NOT build the Docker image. Image build is manual via `docker build` from the maintainer's machine. SBOM gen lives in the Dockerfile, not CI.

### 2.5 Ruff breakdown
`ruff check src/ --statistics` summary:

| Rule | Count | Auto-fix? | Treatment for v0.26.0 |
|---|---|---|---|
| E501 (line-too-long) | 366 | no | Widen `line-length` from 120 to 140 OR extend per-file ignores; remaining flagged ones get re-flowed. |
| E402 (module-import-not-at-top) | 66 | no | Ignore globally (deferred imports for circular deps are a deliberate pattern). |
| N806 (non-lowercase variable in function) | 34 | no | Ignore globally (SQL-aliased values, etc). |
| E741 (ambiguous variable name) | 32 | no | Ignore globally (short loop vars like `l`, `i` in tight scopes). |
| F401 (unused-import) | 32 | yes | Auto-fix; review the diff. |
| F841 (unused-variable) | 31 | no | Fix the few real ones; ignore the intentional `_unused = ...` patterns. |
| I001 (unsorted-imports) | 31 | yes | Auto-fix. |
| F541 (f-string-missing-placeholders) | 28 | yes | Auto-fix. |
| E712 (`x == True`) | 27 | no | Ignore (SQLAlchemy filter callers can't use `is True`). |
| F821 (undefined-name) | **13** | no | **Fix manually — these are real bugs.** Could be runtime AttributeError / NameError. |
| Others (N811, E701, E711, E731) | ~15 | mostly no | Case-by-case. |

---

## 3. Design

### 3.1 Pass-threshold enforcement

Modify `src/ion/web/labs_api.py:complete_lab()` to read the course's `pass_threshold` and pick the status conditionally:

```python
# Existing:
prog.status = "completed"

# New:
threshold = int(getattr(course, "pass_threshold", 70) or 70)
if grade_summary.get("score") is None:
    # No rubric → no judgement. Keep current "completed" semantics so
    # learners who launch a lab with no scoreable criteria aren't
    # penalised.
    prog.status = "completed"
elif int(grade_summary["score"]) >= threshold:
    prog.status = "completed"
else:
    prog.status = "failed"
```

The returned JSON's `lesson_status` field reflects the new status so the frontend can render a "Failed — score X% below threshold Y%" badge.

### 3.2 Lab history endpoint

New route in `labs_api.py`:

```python
@router.get("/courses/{slug}/lessons/{lesson_id}/lab-sessions")
async def get_lab_sessions(...) -> dict:
    """Return the analyst's past lab attempts for this lesson, newest first.
    
    Returns:
        {
            "lesson_id": int,
            "pass_threshold": int,
            "sessions": [
                {
                    "session_id": int,
                    "attempt_number": int,
                    "score": Optional[int],
                    "points_earned": int,
                    "points_max": int,
                    "started_at": str,           # iso8601
                    "completed_at": Optional[str],
                    "status": str,               # "in_progress" | "completed" | "failed"
                    "criteria": [
                        {"rubric_id", "kind", "matched", "points_earned", "points_max", "description"}
                    ],
                },
                ...
            ],
        }
    """
```

Auth: same `require_permission` shape as `complete_lab`. Scope: only the calling user's sessions (no peeking at others').

Implementation: query `lab_sessions JOIN lab_criterion_results JOIN lab_rubrics` keyed by the user's enrolment + the lesson, ordered by `completed_at DESC NULLS LAST, started_at DESC`.

### 3.3 Lab history UI

Add a new section in `lesson.html` below the existing lab panel:

```html
<!-- Existing "Lab grading breakdown" stays unchanged. -->

<!-- v0.26.0: Lab history subpanel -->
<section id="lab-history" class="...">
  <h3>Lab attempt history</h3>
  <div id="lab-history-list">
    <!-- JS-populated -->
  </div>
</section>
```

JS calls the new endpoint on page load (when the lesson is type=LAB), renders one card per past attempt with:
- Attempt # + status badge (green/red/grey)
- Score (or "ungraded")
- Completed-at timestamp
- "Show breakdown" toggle → expands the per-criterion list (re-using the existing `_renderLabCriteria` helper)

No SPA router needed — pure DOM manipulation, matches the v0.23.0 pattern.

### 3.4 SBOM via syft

Add to `Dockerfile` Stage 2 (runtime), after the app is copied in:

```dockerfile
# v0.26.0: SBOM generation via syft
# Generates SPDX-JSON for both the venv (Python packages) and the
# image filesystem. Output lands at /app/sbom.spdx.json so deployers
# can extract it via `docker cp <container>:/app/sbom.spdx.json .`
# Syft is installed as a static binary (anchore release), pinned to a
# specific version so the artefact is reproducible at the SBOM-tool
# layer too.
ARG SYFT_VERSION=1.18.1
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin v${SYFT_VERSION} && \
    syft /app /opt/venv -o spdx-json=/app/sbom.spdx.json && \
    rm /usr/local/bin/syft
```

Trade-offs:
- We could ALSO ship CycloneDX-JSON alongside SPDX, but SPDX is the more universally accepted format for supplier assurance. CycloneDX can be added in a follow-up if customer needs it.
- Inside-image vs side-channel: shipping the SBOM inside the image means deployers can audit what they're running by `docker cp`. The alternative (separate `.sbom.json` file in the Docker Hub repo) requires Docker Hub feature support; not all registries have it.
- Adds ~20 MB to build time and ~200 KB to image size. Acceptable.

### 3.5 SDLC doc updates

- §3.4.5 — replace "no SBOM" gap note with the new syft-in-build language.
- §4 NCSC Principle 4 (Manage third-party risk) — moves from **Mostly Met** to **Met** (SCA from v0.25.0 + SBOM from v0.26.0; the only remaining gap is pinned-deps which is now isolated).
- §8 — strike SBOM gap with closure note.
- §9 — v1.3 row dated 2026-05-11.

### 3.6 Ruff cleanup

Three-step plan:

**Step A — auto-fix (74 violations):**
```bash
ruff check src/ --fix
```
Diff review: ensure no behaviour changed. Commit as one focused commit.

**Step B — fix F821 undefined-name (13 violations):**
Walk each finding. Two outcomes:
- Real bug → fix the reference (import correction, typo fix, etc).
- False positive (e.g. conditional import in a try/except) → add a targeted `# noqa: F821` with a one-line justification.

**Step C — update `pyproject.toml [tool.ruff.lint]`:**

```toml
[tool.ruff.lint]
select = ["E", "F", "I", "N", "W"]
# Codebase-wide ignores reflecting deliberate style choices:
ignore = [
    "E402",  # module-import-not-at-top: deferred imports for circular deps are intentional.
    "E712",  # `x == True`: SQLAlchemy filter callers can't use `is True` against ColumnElement.
    "E741",  # ambiguous-variable-name: short loop vars (`l`, `i`) are fine in tight scopes.
    "N806",  # non-lowercase-variable-in-function: SQL-aliased values look uppercase by convention.
]

# Per-file ignores (extended from v0.22.0):
[tool.ruff.lint.per-file-ignores]
"src/ion/data/kb_*.py" = ["E501"]
"src/ion/services/cyab_subprofile_catalogue.py" = ["E501"]
"src/ion/services/cyab_assessment_questions.py" = ["E501"]
"src/ion/services/soc_template_service.py" = ["E501"]
"src/ion/services/training_sim_service.py" = ["E501"]
"src/ion/services/forensic_seed_service.py" = ["E501"]
"src/ion/services/cyber_range_service.py" = ["E501"]
"src/ion/services/soc_maturity_seed.py" = ["E501"]
# v0.26.0: tests can have unused vars (parametrize fixtures) and longer lines (markdown blocks).
"tests/*" = ["E501", "F841"]
```

Then run `ruff check src/` and verify 0 errors. The line-length stays at 120 — the 366 E501 findings are split between (a) data modules already ignored, (b) tests (now ignored), (c) genuinely long lines in operational code that should be re-flowed in a follow-up cleanup.

**Goal:** `ruff check src/` returns 0 errors. CI ruff job → green.

---

## 4. Tests

### 4.1 Lab grading (extend `tests/test_lab_grading.py`)
- `test_status_completed_when_score_meets_threshold` — score=80, threshold=70 → status=COMPLETED.
- `test_status_failed_when_score_below_threshold` — score=50, threshold=70 → status=FAILED.
- `test_status_completed_when_no_rubric` — empty rubric, score=None → status=COMPLETED (no-rubric labs aren't penalised).
- `test_status_failed_at_zero_score` — score=0 → status=FAILED.
- `test_status_completed_at_threshold_boundary` — score==threshold → status=COMPLETED.

5 new tests on top of 29 existing in `test_lab_grading.py`. Target: 34/34.

### 4.2 Lab history endpoint (new file `tests/test_v026_lab_history.py`)
- `test_lab_history_returns_empty_for_lesson_with_no_sessions`
- `test_lab_history_returns_sessions_newest_first`
- `test_lab_history_includes_criteria_breakdown_per_session`
- `test_lab_history_scoped_to_calling_user` (no peeking)
- `test_lab_history_pass_threshold_is_in_payload`

5 new tests. Target: 5/5.

### 4.3 Ruff
No automated test — verified by running `ruff check src/` and observing 0-error CI output.

### 4.4 SBOM
No automated test — verified by:
1. `docker build` produces an image with `/app/sbom.spdx.json` present.
2. `docker run --rm ixion36/ion:0.26.0 cat /app/sbom.spdx.json | head -20` shows valid SPDX-JSON.
3. The SBOM lists at least the runtime Python packages (`fastapi`, `sqlalchemy`, etc).

---

## 5. Release checklist

The 8-file release ritual is canonical. For v0.26.0:

1. `src/ion/__init__.py` — `__version__ = "0.26.0"`
2. `pyproject.toml` — `version = "0.26.0"` (plus the new `[tool.ruff.lint]` ignore list — keep in scope of this same commit since it's release-time cleanup)
3. `docker-compose.yml` x2 fallbacks — `0.26.0`
4. `Dockerfile` — `org.opencontainers.image.version="0.26.0"` (plus the new syft step)
5. `README.md` — badge bump
6. `.env.deploy` — `ION_VERSION=0.26.0` + header comment refresh
7. `CHANGELOG.md` — v0.26.0 entry with feat + build + cleanup sections
8. `SECURITY_ASSESSMENT.md` — v0.26.0 Delta + severity-trend column

Plus:
- `docs/DEVELOPMENT_LIFECYCLE.md` §3.4.5 / §4 P4 / §8 / §9 v1.3
- Two-commit pattern: `feat:` first, `chore(release):` second
- Tag, push, build Docker image (now with SBOM), update handoff
- Confirm CI green on tag commit before pushing image (the ruff cleanup closes one of the two red jobs; pytest fixture-leaks still red)

---

## 6. Open questions

- **OQ1 — line-length:** keep at 120, widen to 140, or accept the 366 non-data-module E501 warnings as design noise via global ignore? **Decision: keep at 120, add `tests/*` to per-file E501 ignores, leave non-test E501s as warnings (don't ignore globally — they're a useful signal that an SQL string or comment is getting unwieldy).** Future cleanup release can re-flow specific call sites.
- **OQ2 — SBOM format:** SPDX-JSON only, or also CycloneDX? **Decision: SPDX-JSON only for v0.26.0.** Add CycloneDX in a v0.27.0+ patch if a customer asks. SPDX is the broader standard.
- **OQ3 — syft pin:** specific version or `latest`? **Decision: pin to `1.18.1` (current stable as of 2026-05-11)** so the SBOM-tool layer is reproducible. Future syft bumps go through the standard dependency-bump process.
- **OQ4 — F821 vs F401 priority:** which to fix first? **Decision: F821 first (13 real bugs).** F401 is auto-fixable and lower risk. Do F821 in step B of the ruff plan so any new bugs surfaced get their own commit attribution.
