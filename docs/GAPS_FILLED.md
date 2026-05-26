<!-- ion-doc:type=GAPS FILLED -->
<!-- ion-doc:title=Gaps ION Fills -->
<!-- ion-doc:subtitle=The SOC pain points ION addresses, and the concrete features that close each gap -->
<!-- ion-doc:version=0.29.1 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Buyers, SOC leaders, procurement, customer evaluators -->
<!-- ion-doc:date=2026-05-12 -->

# 1. Introduction

## 1.1 What this document is

This document maps **real, named SOC pain points** to **the specific ION features that close them**. It's the "why ION exists, in plain terms" companion to the architectural docs.

Each gap entry follows the same structure:

- **Pain point** — what's broken in a typical SOC without ION
- **Status quo** — what teams do today to limp along
- **How ION fills it** — the concrete feature(s) involved
- **Evidence** — pointer to the surface or service in the product
- **Outcome claim** — the measurable improvement

The claims are framed against a SOC that is using best-of-breed point tools (ES, Kibana, OpenCTI, Arkime, an EDR) but no analyst workbench tying them together — which is the most common state we see.

## 1.2 Audience

SOC leaders evaluating ION, procurement, customer evaluators, anyone who needs to articulate the value proposition to a non-technical stakeholder.

# 2. Triage + alert management gaps

## GAP-01 — Alert fatigue and context-poor queues

**Pain point.** SIEM alert queues are flat lists. Every alert looks the same; severity is the only quick signal; analysts ration their attention by gut feel. False-positive rates of 70%+ are normal. New analysts burn out within 12–18 months.

**Status quo.** Teams build custom dashboards in Kibana / Splunk; bolt on tags and notes; periodically purge the queue when it overruns. There's no shared notion of "what is this alert actually likely to be."

**How ION fills it.** Every alert in `/alerts` shows:

- Severity + age + MITRE technique + grouping tag (case_grouper_service)
- **Bob's verdict** + confidence band (low / medium / high)
- **Similar past cases** (pgvector HNSW) — same rule, same host pattern, what closure reasons did they get?
- Bulk-ops for batch close on Bob-high-confidence false-positives

**Evidence.** `/alerts`, `bob_prompt_service`, `bob_analysis_service`, `case_similarity_service`.

**Outcome claim.** Analyst time-per-alert reduced; FP-close volume per shift goes up; cognitive load per decision goes down.

---

## GAP-02 — "What is this rule, really?" — no rule-context at triage time

**Pain point.** An alert fires citing a rule by name; the analyst has no quick way to know *why* this rule exists, what it's trying to catch, what the typical FP shape is.

**Status quo.** A Confluence page somewhere — if you can find it.

**How ION fills it.** Each alert is paired with its `AlertPromptTemplate`. The template encodes (per detection engineering review) the rule's intent, what evidence to look for, what closure reasons are likely. Bob's verdict is computed from this template; the analyst sees the verdict + the reasoning text.

**Evidence.** `models/alert_prompt.py`, `/alert-prompts`, `bob_analysis_service`.

**Outcome claim.** Tier-1 analysts don't need to ask Tier-2 "what's this rule again?" — the answer is in the alert.

---

## GAP-03 — Bob doesn't have a template — analyst flies blind

**Pain point.** Even with templated rules, the long tail of detections has no template. Analyst gets nothing from AI.

**Status quo.** Either over-build templates (high maintenance) or accept the unhelpful state.

**How ION fills it.** A **5-tier matcher** falls back from exact rule_id → regex over rule name → MITRE technique → MITRE tactic → rule groups. The template doesn't need to be hand-bound to every rule — broad templates cover the long tail.

**Evidence.** `bob_prompt_service.choose_template`, `data/alert_prompts/*.json` (54 seeded templates).

**Outcome claim.** Bob coverage approaches 100% with O(50) templates instead of O(1000+).

# 3. Case + investigation gaps

## GAP-04 — Cases are document-only; evidence is "I'll paste it in the description"

**Pain point.** Most case-management tools (Jira, Kibana Cases, OpenCTI cases) treat a case as a markdown blob. Evidence pasted into the description is mutable, untimestamped, unverifiable.

**Status quo.** Screenshots in OneDrive, raw queries copied into Slack, notes in Notion. Reconstructing what happened is hard, sometimes impossible. Tamper-evident is a fantasy.

**How ION fills it.** The **Workbench**:

- Every relevant artefact (alert, observable, query, note, file) is **pinned** explicitly.
- Each pin appends to a **sha256-chained tamper-evident ledger** (`CaseEvidenceLedger`).
- Tamper detection is a single SQL pass.

**Evidence.** `models/case_evidence.py`, `services/case_pin_service.py`, `services/case_ledger_service.py`.

**Outcome claim.** Cases produce evidence that holds up to internal audit or external review.

---

## GAP-05 — Forensic cases live in a separate tool with no shared chain

**Pain point.** When a case requires forensic deep-dive (memory analysis, host triage), it transitions to a separate workflow — often outside the analyst's daily toolset. Chain of custody is paper.

**Status quo.** A second case-management tool (DFIR IRIS, custom JIRA), a separate evidence locker, manual export-import between systems.

**How ION fills it.** `ForensicCase` is a first-class entity (v0.20.1 parity with AlertCase). Same Workbench pattern. Same tamper-evident ledger (with distinct advisory-lock namespace `FCWL`). `EvidenceItem` rows carry `CustodyLogEntry` rows; chain of custody is a single SQL query.

**Evidence.** `models/forensics.py`, `models/forensic_workbench.py`, `services/forensic_workbench_service.py`.

**Outcome claim.** A SOC can run alert-triage AND forensic deep-dive in one tool without losing chain of custody between hand-offs.

---

## GAP-06 — Similar past cases are tribal knowledge

**Pain point.** A new alert that matches a past case (same host pattern, same observables, same kill-chain) is treated as fresh. The team's accumulated knowledge sits in some Senior Analyst's head.

**Status quo.** "Have we seen this before?" → free-text search → maybe.

**How ION fills it.** **Case similarity** via pgvector + HNSW. Every closed case is embedded (`nomic-embed-text` via Ollama). On a new case detail page, the sidebar shows top-5 similar past cases with closure reasons.

**Evidence.** `models/case_embedding.py`, `services/case_similarity_service.py`, `services/case_embedding_service.py`.

**Outcome claim.** Institutional knowledge becomes queryable, not tribal.

# 4. Network forensics gap

## GAP-07 — PCAP review is a manual, separate workflow

**Pain point.** When an alert needs network corroboration, the analyst pivots out to Arkime, builds a query, finds the session, downloads the PCAP, opens it in Wireshark / NetworkMiner, eyeballs it. By the time it's done, 30 minutes have passed and three alerts have stacked.

**Status quo.** That.

**How ION fills it.** **PCAP auto-analysis** on case-create:

- Extracts `community_id` (and source/destination IP + timestamp) from every alert.
- Pulls the session via Arkime (community_id preferred, IP+time fallback added in v0.29.1).
- Runs 12 heuristic detectors over the PCAP (TLS abuse, JA3 fingerprints, credential exposure, beaconing, exfil patterns, …).
- Appends findings to the case Workbench as a pinned PCAP-analysis comment.

**Evidence.** `services/pcap_analysis_service.py`, `services/arkime_service.py`, `web/pcap_api.py`.

**Outcome claim.** PCAP-context is on the case in seconds, not 30 minutes. Analyst sees the network signal alongside the alert signal.

# 5. Threat intelligence gap

## GAP-08 — Threat intel is a separate page nobody opens

**Pain point.** OpenCTI or similar TI platforms are excellent at storing TI, terrible at putting it under the analyst's nose at decision time.

**Status quo.** Analyst closes an alert without checking TI. Three weeks later it turns out the IOC was on the watchlist.

**How ION fills it.**

- **Unified Threat Intel page** (v0.27.0 consolidation): actor profile + IOC sparkline + ATT&CK click-through, all on one screen.
- **IOC enrichment** is in-line on alerts (batch OpenCTI lookup on observables).
- **Threat Watch Gap Alerts**: auto-alerts when a watched actor gains a new technique you don't have coverage for.
- **Attack Stories** correlate multiple alerts into a kill-chain narrative.

**Evidence.** `/threat-intel`, `services/threat_intel_service.py`, `services/threat_watch_gap_service.py`, `services/attack_story_service.py`.

**Outcome claim.** TI is in the analyst's workflow at the decision moment, not a tab they remember to open.

# 6. Detection engineering gap

## GAP-09 — Detection performance is invisible to detection engineering

**Pain point.** Detection engineers tune rules based on the loudest analyst complaint. Real per-rule performance — FP rate, dwell time, closure-reason distribution — is locked inside the case-management tool.

**Status quo.** Quarterly review meeting where everyone argues about the same five noisy rules.

**How ION fills it.** **AIFeedback ledger** + `/engineering/analytics`:

- Every Bob verdict + every analyst closure are written to `AIFeedback` (dual-write at fire-time and case-close-time; dedup by MAX(id) per (alert, template)).
- The analytics page ranks rules by FP rate × volume.
- Drilling into a rule shows the exact alerts, the closures, and the divergences (Bob said X, analyst said Y).
- Tuning proposals can be filed in-product and synced to TIDE.

**Evidence.** `models/ai_feedback.py`, `services/ai_feedback_service.py`, `/engineering/analytics`, `/tuning-proposals`.

**Outcome claim.** Detection engineering tunes on data, not on the loudest complaint.

---

## GAP-10 — Coverage gaps vs MITRE ATT&CK are invisible

**Pain point.** "How are we doing against MITRE?" is a board-level question with no easy answer.

**Status quo.** Manually maintained Excel heatmap, updated quarterly, always out of date.

**How ION fills it.** **MITRE coverage heatmap** (v0.22.0): bundled ATT&CK v15.1, overlaid with the customer's TIDE rules, drillable by technique. **Threat Watch Gap Alerts** raise the alarm when a tracked actor gains coverage you don't have.

**Evidence.** `/cyab/attack-heatmap`, `services/d3fend_service.py`, `services/threat_watch_gap_service.py`, `data/attack/` (bundled).

**Outcome claim.** Coverage answer is live, not "let me get back to you".

---

## GAP-11 — Compliance frameworks → SIEM rules is a manual map

**Pain point.** "Show me which detection rules satisfy NIST CSF DE.AE-3 / ACSC E8 control 4 / DefStan X.Y." → blank stare.

**Status quo.** Spreadsheet maintained by a single person, brittle, never current.

**How ION fills it.** **Multi-Framework Compliance Mapping** (`compliance_mapping_service`): each TIDE rule is mapped to NIST CSF, ISO 27001, ACSC Essential Eight, and other frameworks. The page shows coverage per framework + drill-into-control.

**Evidence.** `services/compliance_mapping_service.py`, `/compliance`.

**Outcome claim.** Compliance evidence is a click, not a project.

# 7. SOC management gap

## GAP-12 — Shift handovers are tribal + ad-hoc

**Pain point.** Shift handover happens in Slack threads, voice handoff, or a "morning email" that says nothing useful. Critical context is lost between shifts.

**Status quo.** Best case: a wiki page. Worst case: nothing.

**How ION fills it.** **Shift Handover** (`/shift-handover`) auto-populates with: cases changed this shift, alert volume by severity, P1/P2 incidents, outstanding tunings, action items. Analyst edits / annotates. Visible in the next shift's `/briefing`.

**Evidence.** `models/oncall.py`, `services/briefing_service.py`, `/shift-handover`, `/briefing`.

**Outcome claim.** Shift-handover quality is consistent across shifts and analysts.

---

## GAP-13 — Analyst efficiency is hard to measure fairly

**Pain point.** Productivity metrics in SOCs are either too crude (cases closed) or too invasive (every click logged). Fairness is impossible.

**Status quo.** Cases-closed-per-day or vague "feels".

**How ION fills it.** **Analyst Efficiency** (`/analyst-efficiency`) shows per-analyst: cases closed, dwell time, closure-reason distribution, Bob-agreement rate. Bob-agreement isn't punitive (Bob is decision-support, not authority) — it's a diagnostic signal for coaching.

**Evidence.** `services/analyst_efficiency_service.py`, `/analyst-efficiency`.

**Outcome claim.** SOC manager has a fair, data-driven view of efficiency without surveillance.

---

## GAP-14 — No on-ramp for new analysts

**Pain point.** Tier-1 hires are expected to be productive in week 1. Training is on-the-job, ad-hoc, painful.

**Status quo.** Pair-with-a-senior, watch-the-team, sink-or-swim.

**How ION fills it.** **Curriculum** (v0.20.1 shipped — 24 modules / 187 lessons across L1/L2/L3): lessons (BTL1/SANS depth — ~2000-3000 words, visuals, worked scenarios, mixed quiz), labs, and the SKILL publisher for ongoing extension. (Note: lab fixture system has 4 known bugs queued for v0.30.0.)

**Evidence.** `/training`, `/courses`, `models/course.py`, `services/course_service.py`.

**Outcome claim.** A new hire can self-onboard the first two weeks; SOC manager sees progress in `/courses`.

# 8. Architecture, deployment + safety gaps

## GAP-15 — Air-gap deployment is everyone's afterthought

**Pain point.** Most modern SOC tools assume internet (live TI feeds, cloud LLMs, OTA updates). Defence + critical-infra environments don't have it.

**Status quo.** Either deploy nothing, or run a stale clone of the cloud version offline.

**How ION fills it.** **Air-gap-first**:

- MITRE ATT&CK + CISA KEV ship bundled in the image (`data/attack/`, `data/kev/`); refreshed every release.
- Bob runs against **local Ollama**, no SaaS LLM dependency.
- No live external feeds at runtime.
- Offline package script (`scripts/build-offline-package.sh`) bundles everything for transport.

**Evidence.** `feedback_ion_airgap_deployment.md`, `project_ion_kev_design.md`, bundled `data/`.

**Outcome claim.** ION runs offline, including AI, without functional regression.

---

## GAP-16 — AI in SOC is a black box; nobody knows when to trust it

**Pain point.** Most AI-in-SOC offerings are opaque. Either the analyst over-trusts and skips investigation, or under-trusts and ignores the AI entirely.

**Status quo.** Trust drifts; outcomes vary by analyst.

**How ION fills it.** **Calibrated AI** (Bob):

- Structured Pydantic output schema; arbitrary text refused.
- **Confidence rating** (0–100 + low/medium/high band) on every verdict.
- **Circuit breaker** badge on low-confidence verdicts (UI suppresses the suggestion).
- **Eval harness** scores each template (P/R/F1) on historical data; detection engineering tunes confidence thresholds per template.
- **Human-in-the-loop**: case-close requires the analyst to pick `CaseClosureReason`; Bob never closes a case.

**Evidence.** `docs/AI_OUTPUT_CONTRACT.md`, `services/bob_eval_service.py`, `/alert-prompts`, `/bob-eval`.

**Outcome claim.** Analyst trust in Bob is **calibrated** — high where the data says so, low where it doesn't.

---

## GAP-17 — Audit trail is best-effort

**Pain point.** Audit logs are flat append-only with no integrity guarantee. A motivated insider with DB write can rewrite history.

**Status quo.** Accept that, or ship to immutable storage with delay (which loses interactive auditability).

**How ION fills it.** Two-tier audit story:

- Traditional `audit_log` table for per-request mutation rows.
- **Tamper-evident ledger** (`CaseEvidenceLedger`, `ForensicCaseLedger`) with sha256 chaining for Workbench events. A single broken link is detectable post-hoc.

**Evidence.** `models/case_evidence.py`, `services/case_ledger_service.py`, `project_ion_workbench.md`.

**Outcome claim.** Workbench evidence chain is mathematically tamper-evident; the broader audit log is operationally complete.

---

## GAP-18 — Supplier lock-in to a customer's compliance regime

**Pain point.** A tool sold to MOD, NHS, NATO, and a private bank should not have different public artefacts for each.

**Status quo.** Buy the MOD-flavoured one; the private bank's reviewers can't read it.

**How ION fills it.** **Customer-agnostic core + per-customer overlays**:

- Public docs (`docs/`) stay neutral.
- Per-customer compliance artefacts live in named-overlay files (`_mod_*.md`, etc.); gitignored.
- One product asset, many customer-specific scopings.

**Evidence.** `reference_ion_sdlc.md` memory rule, this file family, `_mod_compliance_mapping.md`.

**Outcome claim.** ION ships to MOD, NHS, NATO, and private-sector customers without forking the public surface.

# 9. Workflow integration gap

## GAP-19 — Tools that don't talk to each other

**Pain point.** ES, Kibana, Arkime, OpenCTI, TIDE — each is excellent in isolation. None of them know the others exist.

**Status quo.** Manual pivot. Open six tabs. Lose context twice an hour.

**How ION fills it.** ION is the **glue layer**:

- Alerts arrive from ES; analyst stays in ION
- IOC enrichment hits OpenCTI; result inline
- Rule lifecycle hits TIDE; coverage map lives in ION
- PCAP needs Arkime; PCAP analysis lives in the case Workbench
- Case sync round-trips to Kibana Cases
- SSO routes through Keycloak

**Evidence.** Every `services/*_service.py` integration adapter.

**Outcome claim.** Analyst stays in ION for ~95% of work; pivots only when a tool's native surface is unambiguously better (rare).

# 10. The remaining honest gaps (ION's own)

ION isn't perfect. The following are gaps ION currently has, listed for honesty:

| Honest gap | ION's posture | When |
|---|---|---|
| Formal load-test profile not published | Empirical perf only; tracked | v0.31.0+ |
| Container image not signed (cosign / Sigstore) | Image-tag immutability only | v0.31.0+ |
| WCAG remediation on tier-3/4 surfaces | Audit done, remediation plan published | v0.30.0–v0.31.0 |
| Lab fixture system has 4 known bugs | Documented; queued | v0.30.0 |
| Prompt-injection-aware Bob eval | Structured output schema bounds the worst case; formal testing pending | v0.31.0+ |

These are tracked in `_backlog_v0_27.md` and the SDLC §8 gap analysis. Honesty about gaps is itself a feature; ION's compliance-mapping doc keeps a JSP 892 exception register even when there are zero open exceptions (template ready).

# 11. Change history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-05-12 | ION maintainer | Initial gaps document authored against v0.29.1 |
