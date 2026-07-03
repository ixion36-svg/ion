# Code Review — ION v0.39.8 → v0.49.2 delta

**Date:** 2026-07-03
**Reviewer:** Claude Code (`/code-review` high effort: 7 finder angles → per-candidate adversarial verification)
**Scope:** `beef8c9..f7f3d61` (64 commits, 140 files, +17,422 / −4,294). Baseline: [CODE_REVIEW_v0.39.8.md](CODE_REVIEW_v0.39.8.md).
**Verification:** 18 deduped correctness candidates verified against source → 15 CONFIRMED, 1 PLAUSIBLE, 2 REFUTED.

---

## Top findings (ranked)

### 1 — CRITICAL: every RTMON IOC hit is downgraded to `medium` severity
`arkime_realtime_monitor_service.py:452` stores `str(o.threat_level)` where `threat_level` is a
`(str, Enum)` member — `str()` yields `'ThreatLevel.HIGH'`, not `'high'`. `_severity_for()`
(lines 137–143) lowercases to `'threatlevel.high'`, matches neither `'critical'` nor `'high'`,
and falls through to `'medium'`. A known-**critical** IOC observed in live traffic files as a
**medium** case, and the case summary displays `threat=ThreatLevel.CRITICAL` verbatim.
**Fix:** use `.value` (`o.threat_level.value if o.threat_level else "unknown"`).

### 2 — HIGH: `_get_es_client` TOCTOU re-creates the "Event loop is closed" crash
`elasticsearch_service.py:76–85` assigns the new client to the **global** `_es_client` and then
`return _es_client` — no lock, no local variable. 10+ background services call ES via
`asyncio.run()` in threads (case_grouper 199/517/555, scheduler 337/369, network_mapper 312,
kibana_sync 591, pcap_analysis 768, playbook_action 291, investigation 2730, story_executor 155,
bob_eval 654, large_doc 327). A background thread can rebind the global between create and return,
handing a web request a client bound to a throwaway loop that closes mid-call — the exact crash
commit `f90879d` set out to fix. **Fix:** build into a local and return the local; ideally a
per-loop client map (`WeakKeyDictionary` keyed by loop) shared with `ollama_service`.

### 3 — HIGH: a restart mid-analysis permanently bricks document analysis (409 forever)
`large_doc_service.py:277/108` — the single-job guard queries for any `DocAnalysisJob` row with
`status='running'`; the job runs in a `daemon=True` thread whose only status transitions are its
own success/error writes. No startup reaper, no TTL, no lease. Kill/redeploy/reload mid-job →
the row stays `running` forever → every future analysis on **any** worker 409s until someone
hand-edits the table. **Fix:** stale-timeout on the guard (e.g. `started_at` older than N min →
mark error) or a boot-time reaper; longer-term, one shared job mechanism (this is the repo's
third bespoke job table).

### 4 — HIGH: hierarchical reduce can spin forever when Ollama fails
`large_doc_service.py:215` — `while True` exits only when `len(combined) <= reduce_chars or
len(level) == 1`. `_reduce_call`'s failure fallback (line 250) returns its input verbatim, and
`_batch_by_chars` always emits an oversized item as a singleton batch. LLM outage during reduce
with ≥2 surviving partials > 12,000 chars combined → each round reproduces the identical level →
infinite loop in the worker thread, hammering Ollama, holding the single-job slot (see #3).
**Fix:** detect no-progress (`next_level == level`) and abort the job as failed.

### 5 — HIGH: SSE stream can go silently dead — pages stop refreshing with no fallback
`event_stream.py:221–236` — a failing signature computation is swallowed (`sig = last_sig`,
debug-level log) while `: keepalive` frames keep flowing, so the connection looks healthy.
`live-updates.js` only starts polling at `readyState === CLOSED`, which an open heartbeat-fed
stream never reaches — there is **no polling safety net** for a connected-but-broken stream.
A SOC alert queue that silently stops updating is an operational hazard. **Fix:** send an
`error`-typed SSE event after N consecutive signature failures (client falls back), and log at
warning, not debug.

### 6 — MED-HIGH: RTMON discards detections due to divergent "private IP" semantics
`arkime_realtime_monitor_service.py:147–158` uses `ipaddress.is_private`, which counts the
documentation ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 as private. But
`ArkimeService._is_private_ip` is deliberately RFC-1918-only, with a docstring saying doc/test
ranges "show up in real pcap" (ION ships a cyber-range). The beacon ES query excludes only
RFC-1918, so flows to doc-range destinations are fetched and then silently dropped by
`_is_external` at lines 270/310 — beacon/C2 detections lost exactly on lab traffic. **Fix:**
reuse `ArkimeService._is_private_ip`.

### 7 — MED: MCP-added case notes never reach ES or Kibana
`mcp_api.py:590–621` re-implements the REST add-note route but omits its `_sync_case_to_es()`
and `sync_note_to_kibana()` side effects (`case_lifecycle_api.py:925–931`). Notes added by an AI
agent via MCP exist only in the ION DB — ES-driven case views and Kibana comments silently
diverge. Symptom of the deeper issue: MCP tools fork ORM logic instead of calling the service
layer, so the copies will keep drifting. **Fix:** route MCP tools through the same functions the
REST layer uses.

### 8 — MED: MCP `limit` accepts negatives → unbounded table dump
`mcp_api.py:329` (also :398, :493): `limit = min(int(args.get("limit", 50)), 200)` clamps only
the upper bound; the schema's `minimum: 1` is never enforced server-side. `limit=-1` reaches
`Query.limit(-1)`, which on SQLite returns the **entire table** (alerts/cases/observables),
bypassing the 200-row cap — memory/response blow-up for an authenticated client. **Fix:**
`max(1, min(..., 200))`.

### 9 — MED: multi-second event-loop stall on every large-document upload
`large_doc_api.py:51` — the async handler calls `lds.start_analysis()` synchronously, which runs
full pypdf extraction (`large_doc_service.py:280`) plus DB writes on the event loop; the 10 MB
size cap is checked only **after** `await file.read()` buffers the body. Every upload freezes all
requests/SSE on that worker for the extraction duration. **Fix:** `asyncio.to_thread` (or move
extraction into the worker thread that already exists).

### 10 — MED: RTMON runs sync DB work on the event loop every pass
`arkime_realtime_monitor_service.py:597–663` — `async def _run_pass` calls `_load_ioc_ips`
(full Observable scan + enrichment join), a per-candidate `AlertTriage` dedup SELECT (line 648,
one per candidate — batchable to one `IN` query), and `_open_case` flush/commit, all blocking.
Every pass stalls HTTP/SSE on that worker for the DB duration. Same class as #9 and as the
v0.39.8 baseline F3 (still open). **Fix:** `asyncio.to_thread` around the pass body; batch the
dedup query; cache the IOC set across passes.

---

## Also confirmed (below the cut)

- **ES client leak + pooling defeated:** on cross-loop rebind the old `AsyncClient` is dropped
  without `aclose()` (the "teardown reclaims connections" comment is wrong — `asyncio.run()`
  doesn't close httpx pools, and when a background loop evicts the web-loop client no teardown
  happens at all). Every web/background alternation leaks up to 10 keepalive sockets and forces
  a fresh TLS handshake. `elasticsearch_service.py:62–76`.
- **Doc-analysis dual-job race:** the 409 guard is check-then-insert across separate
  transactions with no unique constraint — two workers can both start GPU map-reduce jobs.
  `large_doc_service.py:277–290`.
- **MCP batch 500:** a JSON-RPC batch entry that isn't an object hits `msg.get()` →
  `AttributeError` → unhandled 500 instead of per-item `-32600`. `mcp_api.py:733–737`.
- **`ix_ai_feedback_alert_template` never created on upgrades:** declared on the model only;
  `database.py`'s own `_perf_indexes` comment explains `create_all` skips pre-existing tables,
  but the list wasn't extended. Upgraded SOCs full-scan the detection-health GROUP BY; fresh
  installs are fine, masking it in testing. `models/ai_feedback.py:33`.
- **KB duplicate-root cause unfixed:** the v0.49.2 fix makes one reader tolerate duplicate
  "Knowledge Base" roots, but both seeders can still create it (no unique constraint;
  `Collection.name` lacks `unique=True` unlike `Template.name`), and `get_by_name` returns an
  unordered `.first()` — consumers can resolve different roots (articles under one, embeddings
  indexing another). `kb_seed_service.py:47`, `soc_template_service.py:3580`,
  `collection_repository.py:49`.
- **PLAUSIBLE — log-sanitization whack-a-mole:** the CodeQL fix sanitized one site;
  ~14 sibling handlers in `elasticsearch_service.py` still log raw exception bodies (and ~10
  more return `str(e)` in API responses). Mitigation verified: URL userinfo is redacted at
  construction and auth goes via header, so **credentials** can't leak under current code —
  but internal URLs/index paths/error bodies can, and CodeQL will re-flag.

## Cleanup / efficiency themes (from the finder pass, not individually verified)

1. **Event-loop hygiene** is the systemic theme: three new subsystems (RTMON, large-doc,
   MCP tools) run sync DB/CPU work on the loop — worth one shared pattern (`to_thread` wrapper
   or a sync-service executor) rather than per-file fixes.
2. **Copy-paste infrastructure:** 4+ private env-parser sets with already-divergent semantics
   (0/negative handling differs per file); duplicated session-token auth (`events_api` vs
   `mcp_api`); three copies of the pgvector similar-cases query; `_SHELL_C2_PORTS` hand-mirror
   of `SUSPICIOUS_PORTS` already diverged (adds 1337, drops 3389/23/21); 20+ template-local
   HTML-escape helpers (the class of bug dacf0aa fixed keeps regenerating).
3. **SSE fan-out:** every client runs its own 3-query signature poll every 4s
   (`event_stream.py:222`) — one per-topic watcher broadcasting to subscribers scales to
   wallboard use. Team-day (`worklog_service.py:290`, ~6 queries × N users) and
   detection-health (full-row streaming aggregation) have the same shape.
4. **Dual-kit CSS:** legacy `.btn`/`.badge` blocks still live in `style.css` under the ion-*
   kit that shadows them by load order only.

## Refuted during verification

- "RTMON cases never reach Kibana" — the 60s `kibana_sync_service` sweep backfills
  `kibana_case_id IS NULL` cases; ≤60s delay, and there's no ES alert to attach for rtmon
  markers anyway.
- "SSE 503 never triggers the polling fallback" — per current WHATWG spec a non-200 fails the
  connection to `CLOSED`; the JS fallback condition fires as designed.

## Baseline carry-over — v0.39.8 findings ALL still open

None of the 7 findings in [CODE_REVIEW_v0.39.8.md](CODE_REVIEW_v0.39.8.md) were addressed in
these 64 commits (F1 `is_ignored` read-path gaps — now in `case_lifecycle_api.py`, still
unfiltered; F2 normalized-value mismatch at `investigation_service.py:1246`; F3 sync Kibana call
in the async auto-case loop; F4 silent suppression-disable except; F5 `id+1` case numbering —
now copied into a 7th place by RTMON; F6 migration race window). The review doc only ever
existed locally — feed these into the dev loop this time.
