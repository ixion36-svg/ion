# Attack Path (Bob Pathfinding) — Roadmap

**Status:** Forks decided (2026-07-30) — Phase 0 in build. A=compute-on-read · B=all four edges · C=tactic-laned DAG · D=MITRE-tactic heuristic (all recommended options taken).
**Date:** 2026-07-30
**Type:** Feature on shared rails (not a separate module) — lands in the Cases/Bob surface
**Owning principle:** *ION traces the path and shows the evidence; the analyst decides.*

Prompted by comparing Maze's vuln "pathfinding" (trace an exploit entry→impact with a
validated evidence chain) to Bob's alert triage. Today Bob is a RAG-grounded, single-model,
**per-alert / per-case narrative** analyst: cross-alert linkage is scalar clustering
(`case_grouper` `(rule,host,user)` + 15-min window), semantic case similarity (pgvector),
shared-IOC co-occurrence rollups, and a **chronological** Attack Story Timeline
(`case_lifecycle_api.py:1131`, rendered `cases.html:3436`). There is **no explicit
attack-path / entity graph** — the LLM is merely *asked* to narrate a kill-chain in free
text (`bob_analysis_api.py:257`). This roadmap closes that gap.

---

## 1. Framing

The wow of "pathfinding" is a **structured directed graph** — entry → … → impact, with typed
nodes and edges and an evidence chain — not another paragraph of prose. The key insight:
**v0.59.0 already extracts every node and edge we need.** Each alert now carries
`observables: [{type,value,threat_level,score,source}]` plus common fields
`source_ip`/`destination_ip`, `process_name`/`parent_process_name`/`command_line`,
`file_hash`, `host`, `user`, and `mitre_technique_id`/tactic
(`ElasticsearchAlert.to_dict`). Assembling those into a graph is mostly **wiring data we
already have**, which is why this is high-leverage.

### Hard constraint (JSP / air-gap governance) — mirror the DE module

Advisory only. The path graph and Bob's reasoning over it **surface and prioritise; they
never auto-close, auto-suppress, or auto-action**. Edge/impact scoring changes *ranking and
narrative*, never stored alert/case state without a human decision. Everything degrades
safely offline (deterministic derivation needs no network; TI enrichment is the existing
air-gap-safe OpenCTI no-op). Grain:

> **Extract → link (deterministic) → trace path → Bob reasons (cited) → *human decides*.**

### Two threads it must carry

1. **Structure before narrative** — the graph is built deterministically from alert data
   *first*; the LLM reasons *over* the structure and must cite its nodes/edges (extends the
   existing `auto_investigation_service.parse_and_validate` citation discipline). No
   hallucinated edges.
2. **Reachability, not just severity** — the path's value is whether it *reaches something
   that matters* (impact tactic / high-value asset), the SOC analogue of Maze's
   exploitability-in-context over raw CVSS.

---

## 2. Core objects (net-new, on shared rails)

| Object | Purpose | Reuses |
|---|---|---|
| **Path Node** | A deduped entity in a case: host, user, process, ip, domain, file, hash, observable. | v0.59.0 observables + common fields |
| **Path Edge** | A typed directed relation: process-lineage (parent→child), network-flow (src→dst ip), auth/presence (user→host), shared-observable (alert↔alert). | common fields, observables |
| **Attack Path** | The ordered graph for a case: nodes + edges arranged initial-access → impact by MITRE tactic + timestamp, with per-node threat_level. | case grouping, MITRE map, evidence ledger |
| **Reachability score** | Does the chain reach an impact tactic / high-value asset? Drives priority + Bob's verdict weighting. | MITRE tactics, (optional) asset registry |

Derived **compute-on-read** from the case's alerts (mirrors DE Phase 0 / the v0.59.0
observable pattern) — no new table in Phase 0; persist only if profiling demands it.

---

## 3. Phased roadmap (ordered by leverage-per-effort, lowest risk first)

### Phase 0 — Path model + deterministic edge derivation (no LLM, zero risk)
Build the graph **deterministically** from a case's alerts: dedupe nodes across alerts; derive
edges (process lineage, network flow, user→host, shared-observable); order nodes/alerts by
`@timestamp` + MITRE tactic into initial-access→impact "lanes". Emit graph JSON
(`nodes[]`, `edges[]`, `phases[]`). New read endpoint `GET /api/.../cases/{id}/attack-path`
gated `case:read`. **No LLM, no writes.** Ships value immediately (structured path even with
Bob off) and cannot break prod. *Effort: Low–Medium.*
**Decision → Fork A (persistence), Fork B (edge scope).**

### Phase 1 — Path visualization (the wow)
Upgrade the Attack Story Timeline into a **kill-chain graph**: nodes coloured by type +
threat_level (reuse the v0.59.0 observable threat badges), typed labelled edges, laid out as
a tactic-laned left→right DAG (initial-access → impact). Reuse `ion-*` tokens + `csp_nonce`;
keep the chronological timeline as an alternate view. Pure client render of Phase 0's JSON —
air-gap safe, no physics library. *Effort: Medium.*
**Decision → Fork C (layout).**

### Phase 2 — Bob reasons over the path + reachability
Feed the **structured** path into Bob's prompt (replace the free-text "look for a kill-chain"
ask) so Bob narrates over explicit nodes/edges and **must cite them** (extend
`evidence_refs` validation to path elements). Output a path narrative + a **reachability/
impact score**. Verdict/priority incorporate reachability. Advisory, cited, air-gap-safe.
*Effort: Medium.*
**Decision → Fork D (reachability basis).**

### Phase 3 — Verifier pass (validation layer) + path→root-cause link
(a) Add an adversarial **verifier pass** (same 8B, temp 0: "does the cited path support this
verdict? downgrade if not") — Maze's "validation layers", extended beyond the auto-investigate
path. (b) Link recurring path *patterns* to the DE module: "this path recurs across N cases →
root-cause detection/tuning here", cross-linking Bob Pathfinding to Noise Campaigns /
Detection Proposals. *Effort: Medium.*
**Decision → Fork E (verifier trigger).**

### Phase 4 — Confidence-gated escalation tier + package
The air-gap-friendly version of Maze's cost routing: low-confidence **+** high-severity →
a "try harder" tier (more context / more seeds / on PROD a larger background-queue model)
*before* escalating to a human (today low-confidence just abstains,
`investigation_service.py:446`). Plus feature-flag + docs. *Effort: Medium.*
**Decision → Fork F (escalation model).**

---

## 4. RBAC / release

- Reads reuse **`case:read`**; Bob reasoning reuses existing AI paths — **no new write perm**
  through Phase 2 (advisory, read-only). Phase 2's optional asset-criticality registry (if
  chosen) would need a small admin-gated config surface.
- Cadence per house style: one release per phase (feature `X.Y.0`), affected-module tests
  only, 8-file ritual + signed tag + Docker. No auto-action guarantees pinned by tests
  (mirror the DE "no-suppression" tests).

---

## 5. Open forks (decide before Phase 0)

- **A — Persistence:** compute-on-read (recommended, mirrors DE P0 / v0.59.0) vs a persisted `attack_path` cache.
- **B — Edge scope (P0):** ship all four edge types now vs start with process-lineage + network-flow only.
- **C — Layout (P1):** tactic-laned left→right DAG (recommended — reads as entry→impact, deterministic, CSP-safe) vs force-directed graph.
- **D — Reachability basis (P2):** MITRE-tactic-reached heuristic (recommended, no new config) vs an asset-criticality registry (richer, needs a tag store).
- **E — Verifier trigger (P3):** verify only medium-confidence decisive verdicts (recommended, cheap) vs verify all.
- **F — Escalation model (P4):** more-context/seeds of the same 8B (recommended, air-gap-safe) vs a second larger model on PROD's background queue.
