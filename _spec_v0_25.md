# ION v0.25.0 Architecture Spec

**Status:** Draft — ready for implementation.
**Date:** 2026-05-11
**Base version:** v0.24.0 (commit 6f4ffc3)
**Stack constraint:** FastAPI + Jinja2 server-rendered HTML + Tailwind CSS. No SPA.
**Shape:** mixed plate (1 feature + 1 SDLC-gap-closure + 1 cleanup), matching v0.22/0.23.0/0.24.0.

---

## 1. Goals and Non-Goals

### Goals

- **Feature — adaptive lab grading session 3:**
  - Two new criterion kinds: `observable_created` and `case_closed_with_reason`.
  - Two new audit events at the api.py write sites that those kinds depend on (`observable_linked`, `case_closed`).
  - Backfill multi-criterion rubrics on the LAB lessons we can grade with the now-five criterion kinds. Surface-mapped LAB inventory has eight total; four are gradable now (L1 M5, L1 M7, L2 M2, L2 M5). The remaining three (L2 M8 TIDE-rule conversion, L3 M3 Caldera op, L3 M6 FIN6 chain) are explicitly deferred — they need criterion kinds tied to TIDE-rule creation and Caldera-operation telemetry that are out of scope for this release.
- **SDLC gap closure — Software Composition Analysis:** add `pip-audit` as a 4th parallel job in `.github/workflows/test.yml`, failing the build only on HIGH/CRITICAL findings. Update `docs/DEVELOPMENT_LIFECYCLE.md` §3.4.4, §4 (NCSC Principle 7 Partial → Met), §8 (strike SCA), §9 (v1.2 row).
- **Cleanup — backlog file rename:** `_backlog_v0_23.md` → `_backlog_v0_25.md`. Refresh its content to reflect what v0.24.0 closed and what remains as v0.26.0 candidates.

### Non-Goals

- Pass-threshold enforcement (FAILED status), score-history view, real-time grading ticker. All adaptive-lab-grading items the v0.24.0 handoff listed under "session 3" beyond the two new criterion kinds are deferred to v0.26.0.
- Backfill of L2 M8 / L3 M3 / L3 M6 rubrics. No measurable criterion kinds exist for "convert hunt finding to TIDE rule" or Caldera-operation telemetry; adding them is a separate research thread.
- SBOM (`syft`), SECURITY.md disclosure channel, pinned `pyproject.toml` deps, threat-model doc, coverage reporting, image signing. All v0.25.x – v0.26.x candidates in the SDLC §8 gap list.
- pip-audit auto-fix or PR automation. The CI job reports and fails; remediation is human-driven.

---

## 2. Real-Code Findings (surface map)

### 2.1 Evaluator dispatch
`src/ion/services/lab_grading_service.py:198-201` —
```python
_EVALUATORS = {
    "viewed_alert": _evaluate_viewed_alert,
    "linked_to_case": _evaluate_linked_to_case,
}
```
Each evaluator returns `(matched: bool, audit_log_id: Optional[int])`. Called from `grade_session` at line 275-281 with `session_id`, `user_id`, `started_at`, `config`. New evaluators slot into this dict.

### 2.2 Lab inventory (eight lessons)
Seeded in `seed_courses.py`:

| Lesson | Line | Title | Has rubric? |
|---|---|---|---|
| L1 M2 Lab | 1496 | Read your first alert in /alerts | **yes (v0.24.0)** — 40 viewed_alert + 60 linked_to_case |
| L1 M5 Lab | 4299 | Tag and triage an observable | no |
| L1 M7 Lab | 6569 | Escalate a case via the runbook | no |
| L2 M2 Lab | 9435 | Hunt with KQL / EQL / ES|QL on /discover | no |
| L2 M5 Lab | 12674 | Hunt a beacon with ES|QL coefficient-of-variation | no |
| L2 M8 Lab | 16005 | Convert a hunt finding to a TIDE rule | deferred (no criterion kind) |
| L3 M3 Lab | 19390 | Caldera operation end-to-end | deferred (no criterion kind) |
| L3 M6 Lab | 22065 | Run a 3-host FIN6 chain via Caldera + measure response time | deferred (no criterion kind) |

### 2.3 Audit events — current state
- `alert_view`, `alert_linked` exist (v0.23.0, v0.24.0).
- **No** `observable_created` or `observable_linked` audit row anywhere in the code today. Observable creation/linking happens in `src/ion/services/observable_service.py:enrich_and_link_observables_for_case` and via two POST endpoints in `src/ion/web/observable_api.py` (`/observables/extract-from-alert/{triage_id}`, `/observables/extract-from-case/{case_id}`); none of them write to `audit_logs`.
- **No** `case_closed` audit row. The case-close path is `src/ion/web/api.py:5269-5284` (PATCH `update_case` with status="closed") and does not write to `audit_logs`.

### 2.4 CaseClosureReason enum
`src/ion/models/alert_triage.py:42-50`:
- `TRUE_POSITIVE`, `FALSE_POSITIVE`, `BENIGN_TRUE_POSITIVE`, `DUPLICATE`, `INSUFFICIENT_DATA`, `NOT_APPLICABLE`.

### 2.5 CI workflow
`.github/workflows/test.yml` (v0.24.0) runs three parallel jobs: pytest, ruff, bandit. Adding a 4th `pip-audit` job is structurally identical to the bandit job — same `setup-python@v5` step, same `pip install -e .[dev]`, then a `pip-audit` invocation.

---

## 3. Design

### 3.1 Audit events to add (preconditions for the new evaluators)

**`observable_linked`** — fired when an ObservableLink row is created. Single write site is the simplest design: emit one audit row per **new** link created via the analyst-facing extraction endpoints. Existing-link no-ops do NOT fire (mirrors the `alert_linked` no-op guard from v0.24.0).

- Where: `observable_api.py:extract_from_alert` (line 868) and `:extract_from_case` (line 884) — both endpoints already commit; insert the audit write before commit, in a try/except (best-effort, never blocks).
- `details` JSON: `{"observable_id": int, "observable_type": str, "case_id": Optional[int], "alert_triage_id": Optional[int]}`.
- `resource_type`: `"observable"`, `resource_id`: the observable id.
- Loop emits one row per new ObservableLink — to know "new vs existing", compare existing links pre-call vs post-call by ObservableLink.id range (the service returns the observable list; we capture the link rows from session.new before commit or by checking ObservableLink.created_at >= a captured timestamp).

**`case_closed`** — fired when a case transitions to closed status with a closure_reason.

- Where: `api.py:update_case` immediately after line 5284 (`case.closed_at = datetime.utcnow()`) and before the AIFeedback capture block at line 5289 — same try/except wrap pattern as v0.24.0's `alert_linked`.
- `details` JSON: `{"case_id": int, "case_number": str, "closure_reason": str, "closure_notes": Optional[str]}`.
- `resource_type`: `"alert_case"`, `resource_id`: the case id.

### 3.2 Evaluator — `observable_created`

```python
# config: {"min_count": int = 1, "types": Optional[list[str]] = None}
# Matches when at least min_count audit rows with action='observable_linked' exist
# for this user in the session window. If types is set, the audit row's
# details["observable_type"] must be in the list. Does NOT require the
# observables to be linked to a session fixture (the L1 M5 lab needs the
# learner to create observables anywhere, not tied to a particular case).
```

Implementation:
- Query `audit_logs WHERE action='observable_linked' AND user_id=:uid AND timestamp >= :since`.
- If `types` is configured, filter on `details->>'observable_type' IN (...)` (Postgres) / parse JSON in Python (SQLite test path).
- Return `(True, earliest_audit_id)` once count ≥ `min_count`; otherwise `(False, None)`.

### 3.3 Evaluator — `case_closed_with_reason`

```python
# config: {"required_reasons": list[str], "min_count": int = 1}
# Matches when at least min_count audit rows with action='case_closed' exist
# for this user in the session window, where details["closure_reason"] is in
# required_reasons. Defaults: required_reasons must be specified; min_count=1.
```

Implementation:
- Query `audit_logs WHERE action='case_closed' AND user_id=:uid AND timestamp >= :since`.
- For each row, parse `details` JSON, check `closure_reason in required_reasons`.
- Return `(True, earliest_audit_id)` once count ≥ `min_count`; otherwise `(False, None)`.

Both evaluators register in `_EVALUATORS` and follow the same shape as `_evaluate_linked_to_case`.

### 3.4 Rubric backfill — four lessons

**Constraint discovered during impl:** `viewed_alert` and `linked_to_case` evaluators scope by `lab_session_fixtures` (the materialised alert_triage/alert_cases ids the session was seeded with). Only L1 M2 has fixtures today (LAB-CASE-0001 + two alerts in `seed_lab_fixtures.py`). Adding fixtures for the other four labs is a separate body of work (extending `seed_lab_fixtures.py` from a single-lesson file to a per-lesson registry) — out of scope for v0.25.0's mixed plate. So this version's backfill uses only the two new fixture-independent kinds (`observable_created` and `case_closed_with_reason`). Adding fixture-dependent grading on the remaining labs becomes a v0.26.0 candidate.

| Lesson | Rubric | Total |
|---|---|---|
| **L1 M5 Lab** — Tag and triage an observable | 100pt observable_created config={"min_count": 1} (sort=0) | 100 |
| **L1 M7 Lab** — Escalate a case via the runbook | 100pt case_closed_with_reason config={"required_reasons": ["true_positive"]} (sort=0) | 100 |
| **L2 M2 Lab** — Hunt with KQL/EQL/ES\|QL | 100pt observable_created config={"min_count": 1} (sort=0) | 100 |
| **L2 M5 Lab** — Hunt a beacon with ES\|QL CoV | 60pt observable_created config={"min_count": 2} (sort=0) + 40pt case_closed_with_reason config={"required_reasons": ["true_positive"]} (sort=1) | 100 |

L1 M7 chose `true_positive` as the required closure_reason: the lesson is "escalate via the runbook" — by definition the analyst escalates because they've confirmed a true incident. Other lessons (e.g. a FP-triage lab if added later) would use a different reason set. L2 M5 keeps the multi-criterion shape — combined with the existing L1 M2 (viewed_alert + linked_to_case) it gives the system two multi-criterion exemplars across two different kind combinations.

All rubrics use `_add_lab_rubric` (v0.24.0 upsert) so they are reseed-safe.

### 3.5 Lab content (LAB-CASE / LAB-ALERT fixtures)

Lab content for the four backfill lessons may already reference appropriate fixtures. We do **not** need new fixtures for v0.25.0 — the existing seed_lab_fixtures.py LAB-CASE/LAB-ALERT entries are sufficient. The new rubric criteria operate on whatever observable/closure events the learner generates during their session window; fixtures bound the alert/case rows, not the observable creation.

If L1 M5 lab text currently doesn't explicitly tell the analyst to extract observables, it may need a one-line update. Will be confirmed during impl by reading the lesson body.

### 3.6 SCA — pip-audit CI job

`.github/workflows/test.yml` gains:

```yaml
  pip-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install pip-audit
        run: python -m pip install pip-audit
      - name: Run pip-audit
        run: pip-audit --strict --vulnerability-service osv --severity-threshold HIGH
```

Notes:
- `--severity-threshold HIGH` fails on HIGH and CRITICAL only. MEDIUM/LOW report but don't fail (avoid noise from transitive deps that can't be patched without a major-version bump).
- Uses OSV as the vuln source (default; doesn't need a token). PyPI advisory DB is the alternative.
- Audits the project's `pyproject.toml` resolved deps — no separate requirements.txt needed.
- Runs in parallel with pytest/ruff/bandit; same triggers (push to main/dev, PR to main).

If the first CI run on origin surfaces a HIGH/CRITICAL we'd need to address in v0.25.0 itself, we either bump the offending dep in `pyproject.toml` or document a deliberate ignore via `--ignore-vuln <id>` with a justification comment in the workflow.

### 3.7 SDLC doc updates

- §3.4.4 — append pip-audit to the CI gate description (was just pytest + ruff + bandit).
- §4 — NCSC Principle 7 (Vulnerability management) moves Partial → Met (or Mostly Met — depending on current language; check existing prose).
- §8 — strike SCA from the gap list with a closure note ("closed v0.25.0").
- §9 — add v1.2 row dated 2026-05-11: "v0.25.0 — SCA via pip-audit added to CI gate; Principle 7 Met."

### 3.8 Cleanup — backlog file rename

- `git mv _backlog_v0_23.md _backlog_v0_25.md`.
- Edit the header to reflect v0.25.0 as the current cycle.
- Strip any v0.23.x / v0.24.x items already shipped.
- Add a v0.26.0 candidates section seeded from the v0.24.0 handoff's deferred list (lab grading session 3 remainder, SBOM, pinned deps, threat-model doc, coverage, image signing, SECURITY.md, the v0.22.0 audit deferrals).

---

## 4. Tests

### 4.1 Lab grading
Extend `tests/test_lab_grading.py` (currently 19 tests):

- `test_evaluate_observable_created_no_audit_rows` — empty audit_logs, matched=False.
- `test_evaluate_observable_created_single_count` — one observable_linked row, min_count=1, matched=True.
- `test_evaluate_observable_created_min_count_unmet` — one row, min_count=2, matched=False.
- `test_evaluate_observable_created_type_filter_match` — types=["ip"] config, audit row's details has type="ip", matched=True.
- `test_evaluate_observable_created_type_filter_miss` — types=["domain"] config, audit row has type="ip", matched=False.
- `test_evaluate_case_closed_with_reason_no_audit_rows` — empty, matched=False.
- `test_evaluate_case_closed_with_reason_correct_reason` — audit row with closure_reason="true_positive", required_reasons=["true_positive"], matched=True.
- `test_evaluate_case_closed_with_reason_wrong_reason` — audit row with closure_reason="false_positive", required_reasons=["true_positive"], matched=False.
- `test_evaluate_case_closed_with_reason_multi_reason_match` — required_reasons=["true_positive","duplicate"], audit row with "duplicate", matched=True.
- `test_grade_session_three_criterion_rubric_partial` — full grade_session with the L1 M7 shape (3 criteria), 2 of 3 match → 60/100.

Target: 10 new tests on top of the 19 existing. Total 29 in test_lab_grading.py.

### 4.2 Audit-event smoke
- `tests/test_v025_audit_events.py` — small file (3-4 cases): observable_linked audit row written on POST /observables/extract-from-alert; case_closed audit row written on PATCH /api/cases/{id} with status=closed; no audit row on no-op re-PATCH or re-extract.

### 4.3 CI workflow
No automated test — verified by running pip-audit locally + observing the green/red badge on the v0.25.0 commit at origin.

---

## 5. Release checklist

The 8-file release ritual is canonical (`docs/RUNBOOK.md`). For v0.25.0 specifically:

1. `src/ion/__init__.py` — `__version__ = "0.25.0"`
2. `pyproject.toml` — `version = "0.25.0"`
3. `docker-compose.yml` x2 (root + `deploy/docker-compose.yml` if present) — `ION_VERSION=0.25.0`
4. `Dockerfile` — `LABEL org.opencontainers.image.version="0.25.0"`
5. `README.md` — badge bump
6. `.env.deploy` x2 — `ION_VERSION=0.25.0` + comment header
7. `CHANGELOG.md` — v0.25.0 entry with feat + ci + cleanup sections
8. `SECURITY_ASSESSMENT.md` — v0.25.0 Delta section (0 new findings expected unless pip-audit surfaces one; otherwise document any patched vuln as a closed Low)

Plus:
- `docs/DEVELOPMENT_LIFECYCLE.md` §3.4.4 / §4 / §8 / §9 v1.2 row
- Two-commit pattern: `feat:` first, `chore(release):` second
- Tag, build, push Docker image, update handoff

---

## 6. Open questions

- **OQ1 — observable_linked emission granularity:** one row per new ObservableLink, or one row per extract-call (with details containing the list of new observable ids)? **Decision: one row per new ObservableLink** so the evaluator counts cleanly. The audit volume increase is bounded (typical extract produces 1-5 observables per alert).
- **OQ2 — type filter dialect:** Postgres JSON operator (`details->>'observable_type'`) vs Python-side parse. **Decision: Python-side parse** — matches `_evaluate_linked_to_case`'s case_id extraction, keeps SQLite test path working, evaluator runs in-process so the perf difference is negligible at any plausible scale.
- **OQ3 — closure_reason case sensitivity:** the enum stores lowercase string values (`"true_positive"`); audit row should store the raw value as-is. **Decision: lowercase throughout**; evaluator compares exact string match against `required_reasons` list which the rubric author must populate with lowercase values.
- **OQ4 — pip-audit threshold:** HIGH-only would let MEDIUM stack up. **Decision: HIGH for v0.25.0** with a note in the workflow comment that we may tighten to MEDIUM after a clean baseline. The doc-style note belongs in `docs/DEVELOPMENT_LIFECYCLE.md` §3.4.4.
