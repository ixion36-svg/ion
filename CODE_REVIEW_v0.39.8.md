# Code Review Baseline — ION v0.39.8

**Date:** 2026-06-14
**Reviewer:** Claude Code (`/code-review`, local max-effort: 9 finder angles → independent verification)
**Scope:** v0.39.8 code delta `6d08b33..beef8c9` (previous release → release commit). Excludes KB/seed data files.
**Method:** Each candidate independently verified against source; refuted candidates dropped.

> This is a **baseline / line-in-the-sand** snapshot. The repo's `SECURITY_ASSESSMENT.md`
> records v0.39.8 as `0C / 0H / 0M / 0L` for *security* severity — the findings below are
> **correctness / quality** defects in the v0.39.8 feature work, not security findings.
> For a full-codebase deep pass, run `claude ultrareview` from a terminal.

## Files in scope

- `src/ion/models/observable.py` (+8) — `is_ignored` column
- `src/ion/storage/database.py` (+3) — `is_ignored` migration
- `src/ion/services/observable_service.py` (+4) — search filter
- `src/ion/web/observable_api.py` (+23) — ignore endpoints/params
- `src/ion/services/investigation_service.py` (+40) — suppression + values-only blob
- `src/ion/services/ioc_text_extractor.py` (+32) — field-name guard
- `src/ion/services/arkime_auto_case_service.py` (+39) — Kibana auto-case attach
- `src/ion/web/templates/cases.html` (+172) — linked-alert field viewer
- `src/ion/web/templates/observables.html` (+38) — ignore UI
- `tests/test_v039_8_pcap_observable_fixes.py` (+176)

---

## Confirmed findings

### 1 — HIGH: `is_ignored` suppression is incomplete (feature largely non-functional)
The flag only skips **newly-merged** IOCs. Gaps:
- Observables already in `case.observables` before being ignored are **never pruned**
  (`investigation_service.py` builds `existing = list(case.observables or [])` and only
  guards the *append* loop).
- **Case-detail endpoint** returns `case.observables` raw — no filter (`api.py:5046`).
- **Kibana case-sync** description builder iterates `case.observables` unfiltered (`api.py:5534`).
- **Shared/linked-observables** correlation filters `is_whitelisted` + `ignore_similarity`
  but **not** `is_ignored` (`api.py:4850`).

**Effect:** an analyst who "ignores" an observable still sees it in the case detail, the AI
investigation guide (for pre-existing entries), the Kibana case, and cross-case correlation.

**Root cause (altitude):** suppression is applied at one call site instead of a shared
query/serialization layer. Fix at the layer that materializes `case.observables` for read.

### 2 — HIGH: ignore match compares raw `v.lower()` to `normalized_value`
`ignored_values` is built from `Observable.normalized_value` (lowercased), but the membership
test uses `v.lower()` on the raw extracted IOC. `normalize_value` does more than lowercase:
- **CVE** → uppercased ⇒ never matches (always re-surfaces).
- **MAC** → separators rewritten to `:` ⇒ `aa-bb-...` never matches.
- **Domain/hostname** → trailing `.` stripped ⇒ `evil.com.` misses.
- Set is **type-agnostic** ⇒ a value can cross-match an ignored value of a different type.

`investigation_service.py:1212-1235`, normalization in `models/observable.py:186`.

**Fix:** normalize the extracted value with the same function before the membership test, and
key the ignored set by `(type, normalized_value)`.

### 3 — HIGH: blocking synchronous HTTP on the async event loop
The auto-case loop (`async def _loop`/`_run_pass`) calls `_create_case_for_alert` per alert,
which calls `sync_new_case_to_kibana` → `create_case` + `attach_alerts_to_case` using a
**synchronous `httpx.Client.post` (5s read / 3s connect)** with no `asyncio.to_thread`.
N new alerts ⇒ up to 2N serial blocking round-trips stalling every coroutine; a slow/unreachable
Kibana freezes the loop for up to ~5s × 2N per pass.
`arkime_auto_case_service.py:204`, `kibana_cases_service.py:187`.
(The "runs in BackgroundTasks" comment applies only to the FastAPI request paths, not this loop.)

**Fix:** wrap the sync calls in `asyncio.to_thread`, or use the async Kibana client.

### 4 — MED: broad `except` silently disables all suppression
Loading `ignored_values` is wrapped in `except Exception: ignored_values = set()` with no log
or re-raise. Any transient DB error (or a missing column pre-migration) silently re-surfaces
**every** ignored observable. `investigation_service.py:1210`.
**Fix:** log at warning level; consider narrowing the except.

### 5 — MED: `case_number = max(AlertCase.id) + 1`
Decoupled from the actual auto-assigned id and not concurrency-safe — two concurrent passes (or
an interleaved manual case) compute the same number; on a unique constraint the create errors and
is swallowed by the caller's `except`. `arkime_auto_case_service.py:168`.
**Fix:** use a dedicated sequence / DB default, or derive from `max(case_number)` atomically.

### 6 — MED: `is_ignored` migration not multi-worker / cross-DB safe
Bare `ALTER TABLE observables ADD COLUMN is_ignored BOOLEAN NOT NULL DEFAULT FALSE` with no
`IF NOT EXISTS` / `try-except` — a concurrent worker boot races and crashes — **unlike** the
`session_token_hash` migration the repo explicitly hardened for exactly this race. Also hardcodes
`DEFAULT FALSE` with no Postgres/SQLite branch, unlike the sibling `is_service_account` migration.
`storage/database.py:913`.
**Fix:** follow the established hardened-migration pattern (existence check + swallow
duplicate-column errors + DB-specific default).

### 7 — MED-LOW: `_alert_to_text_blob` values-only walk drops dict keys + booleans
The new `_walk` recurses into dict **values only** and skips booleans, so an IOC present only as a
dict **key** (field-keyed aggregation/enrichment maps, e.g. `{"evil.com": {...}}`) is no longer
extracted — the old `json.dumps` path caught it. Low for canonical ECS alert docs, real for
reshaped aggregations. `investigation_service.py:679`.

---

## Lower-severity / cleanup

- **Perf:** `is_ignored` has no index but is filtered on the default observables-list page and the
  investigation merge. Low impact (low-cardinality bool), though `is_watched` on the same model is
  indexed for similar reasons. `models/observable.py:135`.
- **Cleanup:** `esc()` returns `''` for falsy input (`esc(0)` → blank). Mitigated here by `String()`
  at the call site, but the helper is a latent display-bug trap. `web/templates/cases.html:2109`.
- **Cleanup:** extra per-alert `session.commit()` in the auto-case loop (double commit per alert).

---

## Refuted (checked, not real)

- **DOM id collision** on `alert-fields-<idx>` — only one case panel renders at a time; ids are
  unique. Fragile if a future change renders two panels, but not a present bug.
- **`esc()` quote-breakage of the alert id** — ES `_id` is URL-safe base64; cannot contain quotes.
- **IOC field-name guard dropping `.dev`/`.app`/`.id` domains** — those TLDs aren't in
  `_ECS_FIELD_TOKENS`, so they pass through. Only real (narrow) false-negative: `.name`-TLD domains
  whose every label is a field token (e.g. `host.name`) — which collide with ECS paths by design.

---

## Priority

Fix **1, 2, 3** before considering v0.39.8 complete: the headline `is_ignored` feature is
effectively non-functional on the common read paths (1, 2), and the auto-case loop has a real
event-loop stall (3).
