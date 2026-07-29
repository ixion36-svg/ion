# Detection Engineering (DE) Module — Roadmap

**Status:** Phase 0 (v0.55.0) + Phase 1 (v0.56.0) + Phase 2 (v0.57.0) + Phase 3 (v0.58.0) SHIPPED · Phase 4 planned
**Date:** 2026-07-26 (Phase 0 → 07-27; Phases 1 & 2 → 07-28; Phase 3 → 07-29)
**Type:** Optional product module (CyAB-style)
**Owning principle:** *ION drafts and measures; the analyst decides and acts.*

---

## 1. Framing

A full Detection Engineering function, shipped as an **optional, licensable module** — the
same shape as CyAB: its own nav section, its own models, its own feature flag, but built
entirely on rails ION already owns (alerts, closure reasons, tuning proposals, TIDE/MITRE,
Bob, Bob-eval, case similarity, playbook analytics, MCP). It is not a new product category
and does not need a second company to maintain.

### Hard constraint (JSP / air-gap governance)

No auto-close, no auto-suppress, no auto-deploy of detection changes. Every state change
that could hide a real threat **requires a human decision with an audit record**. This
matches ION's existing grain (`_auto_playbook_enabled` defaults OFF — no surprise
executions). The module is therefore strictly:

> **Surface → cluster → draft → *human decides* → measure.**

Dropping auto-action removes the riskiest, hardest quarter of the build while keeping ~100%
of the leverage. The value was always in the clustering, the draft, and the measurement.

### Two threads the module must carry

1. **Continuous improvement of Bob's analysis** — a structured feedback loop from real
   closures back into Bob's prompt-stack / context, human-approved, never silent drift.
2. **System-quirk register** — captured environmental knowledge ("this benign scanner trips
   rule X every Tuesday") that informs triage — *without becoming a suppression backdoor.*
   Anti-abuse is a first-class design requirement, see §4.

---

## 2. Core objects (net-new, on shared rails)

| Object | Purpose | Reuses |
|---|---|---|
| **Noise Campaign** | An FP cluster: N alerts over a window sharing rule + benign trigger, with a cost estimate (analyst-hours). The unit of DE work. | alerts, closure reasons, case similarity |
| **Detection Proposal** | A *reviewable draft* of a tuning change / exception / new rule. An artifact, never a deployed change. Carries rationale, expected noise-drop, MITRE delta. | tuning proposals, TIDE, MITRE map |
| **System Quirk** | A human-verified, scoped, expiring record of known-benign behaviour in *this* estate. Advisory only — annotates/deprioritises, never silences. | entities/observables, alert prompts |
| **Bob Feedback Item** | A structured correction from a real closure ("Bob called this malicious; analyst closed benign because…") feeding the improvement loop. | Bob, Bob-eval, closure reasons |
| **DE Metrics** | Read-only: noise-drop after a change lands, hours saved, FP-prevented, proposal cycle time, Bob agreement rate. | playbook analytics |

---

## 3. Phased roadmap (ordered by leverage-per-effort, lowest risk first)

### Phase 0 — Measurement & read-only (no write path, zero risk) — ✅ SHIPPED v0.55.0 (2026-07-27)
- **Noise Campaign** object: cluster FP closures by rule + trigger signature; cost estimate.
- **DE Metrics** dashboard: noise trend, hours saved, Bob-vs-human agreement rate.
- No proposals, no suppression — pure visibility. Ships value on day one, cannot break prod.
- *Effort: Low.* This is the "measurement half" already agreed as the right first slice.

**As built (v0.55.0):** `services/de_metrics_service.py` + `web/de_api.py` (`/api/de/metrics`, `/api/de/campaigns`) + page `/de-metrics`, gated on new perm **`de:read`**. Noise Campaigns are **computed on-read** (no table/migration) from the `AlertTriage → AlertCase` join — so every FP/benign closure counts, independent of whether Bob ran. Deviations from the sketch above, all deliberate:
- **Clustered by rule only** for now; trigger-signature *sub*-clustering is deferred to Phase 1 (gated on §5 Q2 "what's actually in ES?"). Signatures + hosts are surfaced *within* each campaign instead.
- **"Hours saved" → "addressable hours"** — with no write path nothing is saved yet, so the metric is the reclaimable cost (`fp_alerts × ION_DE_MINUTES_PER_ALERT`, default 10 min). Real "saved" arrives in Phase 1.
- **No feature flag** — mounted unconditionally, RBAC-gated only; the licence/flag gate stays deferred to Phase 4 (matches CyAB, which also has no `_enabled` flag).
- Mirrors the Detection Health (v0.47.0) dashboard pattern end-to-end. 10 tests in `tests/test_v055_de_metrics.py`.

### Phase 1 — Detection Proposals as reviewable artifacts
- From a Noise Campaign, draft a candidate exception / tuning change (text + structured diff).
- DE reviews, edits, and **applies it themselves** in the detection backend. ION records the
  decision and links the outcome back to the campaign; Phase-0 metrics then prove the drop.
- No write-back to detection backends by ION. Human is the deploy mechanism.
- *Effort: Medium.*

**As built (v0.56.0):** new `detection_proposals` table + `de_proposal_service` +
`/api/de/proposals*` + `/de-proposals` review page + "Draft proposal" button on DE Metrics.
The first DE write path, tightly bounded — ION persists only its own proposal artifact + the
human's one-shot decision; it **never** writes to a detection backend, calls out, or executes.
- Drafting is **deterministic** (no LLM): pre-filled from the campaign's top benign
  signature/host → a suggested exclusion + expected drop. Human edits every field.
- Lifecycle draft → applied | rejected (one-shot, cloned from the tuning-proposal `_review`
  pattern). Marking *applied* records `applied_at`; `measure_outcome` then re-runs the Phase-0
  FP metric before vs after that date to show the realized drop (live-verified: 80% on a
  seeded campaign).
- Write gated a new **`de:propose`** permission (5 DE roles). Separation of duties
  (`de:propose` ≠ `de:verify` ≠ `de:approve`) is introduced in **Phase 2** below.

### Phase 2 — System-Quirk register (advisory, hard anti-abuse — see §4)
- Analysts raise a quirk from an alert/case; it enters a **pending** state.
- A *different* role verifies it before it has any effect (separation of duties).
- Verified quirks **annotate and reorder** triage (badge, context note, priority nudge) —
  the alert is always still fully visible and actionable. No hidden suppression.
- Every quirk is scoped (specific entities/rules), owned, justified, audited, and **expires**
  on a review date.
- *Effort: Medium.* Anti-abuse controls are the bulk of the work, not the data model.

**As built (v0.57.0):** new `system_quirks` table + `de_quirk_service` + `/api/de/quirks*` +
`/de-quirks` registry page. The anti-abuse controls are enforced in code and pinned by tests,
not just intended:
- **No suppression, by construction.** `quirk_match` / `annotate_alerts` only *decorate* the
  alert response dict (badge/note/nudge); there is no code path from a quirk to closing,
  filtering, hiding, or mutating an alert's stored state. It stays clear of the separate
  `KnownFalsePositive` auto-close path, and the annotation injected into the alerts serializer
  is additive + exception-guarded (can't drop an alert or break the view).
- **Separation of duties** — ION's first maker/checker control: raised `pending` by one user,
  activatable only by a *different* user (`verified_by_id != raised_by_id`, enforced
  server-side irrespective of role), gated by a new **`de:verify`** permission on the
  lead/senior tier only (not `senior_engineer`, who can raise but not self-verify).
- **Bounded + expiring** — ≥1 concrete scope required, wildcards rejected (never global); a
  mandatory `review_date` with **on-read expiry** (a lapsed quirk is inert — no worker, so a
  lapse can never suppress). Full AuditLog trail (raise/verify/revert) + one-click revert.
- The "reorder triage" idea is realised as an advisory `priority_nudge` shown on the badge —
  it never rewrites the analyst-owned `AlertTriage.priority`.

### Phase 3 — Bob improvement loop (human-approved, reversible) — ✅ SHIPPED v0.58.0 (2026-07-29)
- **Bob Feedback Items** accumulate from closures where Bob disagreed with the analyst.
- Weekly **Bob scorecard** (productised Bob-eval): agreement rate, drift, top disagreement
  classes.
- Feedback is triaged into concrete, reviewable changes to Bob's prompt-stack / retrieval
  context — **applied only after human approval**, versioned, and reversible. No silent
  online learning, no per-alert model mutation.
- *Effort: Medium–High.* Highest-value differentiator vs the "agentic auto-remediation" crowd.

### Phase 4 — Package as an optional module
- Feature flag + licence gate (CyAB pattern). Own nav, RBAC permissions (`de:read`,
  `de:propose`, `de:verify`, `de:approve`).
- **Content-pack export/import** (signed): ship curated proposals, quirk templates, Bob
  tuning packs between air-gapped enclaves — reuses the air-gap content-pack rail.
- *Effort: Low–Medium once Phases 0–3 exist.*

---

## 4. Anti-abuse design (first-class requirement)

The quirk register and Bob-feedback loop are the two features that could be *weaponised* to
blind the SOC (insider marks their own C2 as a "known quirk"; poisons Bob to downgrade a real
TTP). Controls, baked in from Phase 2:

- **No silencing, ever.** Quirks deprioritise/annotate; the alert stays visible and closable.
  There is no path from "quirk" to "alert never shown."
- **Separation of duties.** The raiser cannot be the sole verifier/approver. `de:propose` ≠
  `de:verify` ≠ `de:approve` as distinct permissions.
- **Scoped blast radius.** A quirk binds to specific entities/rules — never global, never
  wildcard-by-default.
- **Mandatory expiry + review.** Quirks and Bob-tuning changes auto-lapse on a review date;
  stale environmental knowledge dies rather than accreting silently.
- **Full audit + reversibility.** Who raised, who verified, justification, when, effect, and a
  one-click revert. Every Bob prompt-stack change is versioned and diffable.
- **No silent model drift.** Bob never learns online from a single closure. All learning is
  batched into reviewable, approved, versioned changes.
- **Abuse monitoring.** Flag suspicious patterns: one user raising many quirks against
  high-severity rules, quirks that would blanket a MITRE technique, verify/approve collusion.

---

## 5. Open questions that gate scope

These decide whether adjacent asks (identity lane, UEBA) are view-layer builds or dead ends,
and how large Phase 2/3 get:

1. **What detection backends must proposals target?** (Elastic rules / TIDE / Sigma / KQL?)
   Determines the Proposal diff format and how "apply" is documented for the human.
2. **What's actually in ES?** Auth/logon/EDR telemetry availability sets the ceiling on
   clustering quality and on any future identity/UEBA adjacency.
3. **How many concurrent DE/analyst users?** Sets how heavy the separation-of-duties workflow
   should be (lightweight dual-control vs full maker/checker queues).
4. **Licence/packaging model** for the optional module — mirror CyAB, or a distinct SKU?

---

## 6. Recommended first slice

**Phase 0 only** — the Noise Campaign object + DE Metrics dashboard. It:
- ships measurable value immediately,
- has no write path so it cannot endanger detections or fall foul of the JSP,
- produces the FP-cluster data that every later phase depends on,
- lets us validate the clustering heuristic against real closures before investing in proposals.

Everything else is sequenced behind it. Nothing here starts without an explicit go.

---

## 7. Explicitly out of scope (traps for a small team)

Auto-close / auto-suppress / auto-deploy (JSP + design principle); UEBA statistical baselining
(FP factory / data-science project); real-time collaborative war room (paradigm shift, ROI
scales with analyst count); MSSP multi-tenant portal (a second product). These stay parked
unless a concrete deployment demands them.
