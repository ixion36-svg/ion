<!-- ion-doc:type=STACK BRIEF -->
<!-- ion-doc:title=ION Stack Brief -->
<!-- ion-doc:subtitle=Customer current state (Elastic + YouTrack + n8n) vs the Guarded Glass-delivered stack — what ION specifically fixes, and how it integrates -->
<!-- ion-doc:version=0.29.1 -->
<!-- ion-doc:classification=CUSTOMER FACING -->
<!-- ion-doc:owner=Guarded Glass + ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Customer SOC leadership, IT director, procurement evaluators -->
<!-- ion-doc:date=2026-05-12 -->

# 1. Purpose

**Where we are.** The customer is **already running the Guarded Glass (GG) stack operationally** — ION + TIDE + Elastic + GitLab + DFIR-IRIS + Arkime + OpenCTI + Keycloak + n8n. It works in day-to-day SOC operations. What remains is **official onboarding** (formal service-transition acceptance, design-authority sign-off, registration with the customer's application register) and **compliance** evidence (DPIA, accessibility audit, exception register, etc.).

**Why this brief exists.** Two distinct audiences need to understand ION's load-bearing role inside the GG stack:

1. **Acceptance reviewers** — SRO / STO / DA chair — about to sign the gate that takes the operational stack into formal "in service" status. They need to articulate what ION does that the rest of the stack does not.
2. **Compliance reviewers** — DPO / audit / accessibility — assembling the evidence pack. ION's specific role drives several of those evidence artefacts (`_mod_*.md` family, plus `docs/HLD.md`, `docs/USER_REQUIREMENTS.md`, `docs/TRACEABILITY.md`).

This brief answers two specific questions:

1. **What does ION specifically fix** that the customer's **pre-GG stack** (Elastic + YouTrack + an unconfigured n8n) could not? — i.e. what's already operationally better since the GG stack rolled out.
2. **How does ION integrate** with each of the other tools in the GG stack, in operational use today? — i.e. what reviewers should expect to see when they validate the deployment.

It is intentionally ION-centric. The wider GG stack components (TIDE, GitLab, DFIR-IRIS, Arkime, OpenCTI, Keycloak, n8n) are described only insofar as they meet ION; their full-feature pitches sit in their own product collateral.

## 1.1 Companions

- `docs/HLD.md` — ION architecture overview
- `docs/USE_CASES.md` — what analysts actually do in ION
- `docs/GAPS_FILLED.md` — generic SOC pain points ION addresses (this brief reframes those against a specific stack)
- `docs/USER_REQUIREMENTS.md` — 81 numbered user requirements ION meets
- `docs/TRACEABILITY.md` — UR → design → test trace

# 2. Pre-GG-stack state (the baseline before adoption)

This section captures what the customer was running **before** the GG stack rolled out. The customer is no longer in this state operationally — the GG stack is live — but reviewers need this baseline to evaluate what changed and why.

Pre-GG-stack the customer ran three security-adjacent tools:

## 2.1 Elastic — the SIEM

| Aspect | State |
|---|---|
| Role | SIEM: log ingestion, alert generation, search, dashboards |
| Strength | Industry-standard SIEM; well-known query language (KQL/EQL); broad community support |
| What it **does** well | Aggregates logs, fires rules, gives engineers a query surface |
| What it does **not** do | Provide an analyst case workbench; AI-assisted triage; case-evidence audit chain; cross-tool integration; PCAP analysis context; threat-intelligence-in-workflow; multi-framework compliance map |

Elastic Security has its own rule + cases UX, but in practice analysts find it cumbersome for the high-volume daily triage workflow; cases are simple containers with no evidence chain or AI assistance.

## 2.2 YouTrack — the issue tracker (being retired)

| Aspect | State |
|---|---|
| Role | General-purpose engineering issue tracking |
| Status in target stack | **Retired.** Replaced by GitLab issues (for engineering work) and ION cases (for SOC work). The customer has confirmed they do not retain YouTrack once GitLab + ION are in place. |
| What YouTrack **did** well | Tracked general engineering work; bug reports; feature requests; sprints |
| What it did **not** do | SOC-specific case lifecycle; tamper-evident evidence ledger; per-rule performance metrics; similar-case retrieval; SOC-grade RBAC; SLA breach tracking with severity-aware escalation; analyst efficiency analytics |

YouTrack worked as a generic ticketing tool. It was not — and was never designed to be — a security operations workbench. With the GG stack, the engineering-ticket use case moves to **GitLab Issues** (where the customer's code already lives) and the SOC-case use case moves to **ION** (purpose-built for the role). YouTrack is decommissioned as part of the rollout. §9 below covers how every YouTrack workflow is preserved in the new tooling.

## 2.3 n8n — workflow automation (UNCONFIGURED)

| Aspect | State |
|---|---|
| Role | Workflow automation; intended for cross-tool orchestration |
| Strength | Visual workflow builder; broad connector library |
| Current state | **Installed but not configured.** No active workflows. |
| Operational risk | A workflow tool that has been sitting unconfigured for an extended period is unlikely to be configured tactically; it needs a clear "what does the analyst need automated?" answer that the current stack cannot give it |

n8n is the wrong tool to start an automation programme with **before** you have a structured analyst workflow producing structured events. It belongs at the *end* of a SOC tooling chain (consuming structured signals), not at the start.

## 2.4 The shape of analyst work in the current state

A Tier-1 analyst in this stack does (approximately) the following for each suspicious alert:

```
1. See alert in Elastic Security
2. Read raw event JSON; manually parse fields
3. Switch tab → check OpenCTI / VT / external TI (no inline enrichment)
4. Switch tab → check ticketing for prior incidents
5. Open YouTrack ticket → paste evidence as free-text
6. Switch tab → check if PCAP exists (manual Arkime query)
7. Make a judgement on the alert
8. Close in Elastic; document in YouTrack
9. Hand over context to next shift via Slack/email
```

The visible costs of this flow:

- **8+ tab pivots per alert.** Cognitive load is high; FP-close rate suffers.
- **Evidence quality is poor.** YouTrack tickets contain free-text screenshots; reconstruction at audit time is hard.
- **No "have we seen this before?" capability.** Tribal knowledge dominates.
- **No structured AI assistance.** Triage relies entirely on analyst expertise.
- **No detection-engineering feedback loop.** Detection engineers cannot see which rules are producing which closure reasons at the case level — only at the alert level — and can't easily link a rule to per-rule FP rates.
- **No tamper-evident audit chain.** Insider modification of evidence cannot be detected.
- **No shift-handover structure.** Handover is unstructured Slack / email.

## 2.5 Where the customer is today — operationally on the GG stack

Since the GG stack rolled out, the customer's day-to-day SOC operations have moved off the pre-GG baseline. The current state is:

| Dimension | Today |
|---|---|
| SOC workbench | **ION** — single seat for L1/L2/L3 analysts |
| SIEM | Elastic (retained) |
| Detection content lifecycle | TIDE + GitLab (content-as-code) |
| Forensic case retention | DFIR-IRIS, pushed-to from ION's `ForensicCase` |
| Full-packet capture | Arkime, pulled-from by ION's `pcap_analysis_service` |
| Threat intelligence | OpenCTI, pulled-from by ION's TI surface |
| Identity | Keycloak OIDC SSO (RS256-only) |
| Workflow automation | n8n, **now configured** to react to ION's HMAC-signed webhooks |
| Engineering tickets | GitLab Issues (YouTrack retired — see §9) |

**In-progress work** that this brief contributes to:

1. **Official onboarding gate** — formal service-transition acceptance signed by SRO + STO + DA chair. Substantiating artefacts: `_mod_design_passport.md`, `_mod_service_transition.md`, `_mod_app_register_submission.md`.
2. **Compliance evidence pack** — DPIA, accessibility audit, exception register, log-shipping spec, ITEAP. All authored at v0.29.1; pending customer countersignature.

This brief is part of that in-progress work: it gives reviewers an ION-specific articulation of "what does this product actually do for us, and why is it load-bearing in the stack you're about to sign for."

# 3. Gaps the GG stack closed (vs the pre-GG baseline)

The following gaps were observable in the customer's pre-GG-stack baseline (§2). The GG stack — with ION at its centre — closes every one of them in operational use today. The table is provided so reviewers can see what's already been gained, before the §6 deep-dive into ION's specific contribution.

| # | Gap | Why it exists |
|---|---|---|
| 1 | No structured analyst workbench | Elastic + YouTrack each do their job, but neither acts as the analyst's daily seat |
| 2 | No AI-assisted alert triage | Out of scope for SIEM; YouTrack has no AI |
| 3 | No case-evidence tamper-evidence | YouTrack tickets are mutable free-text; audit-readiness is best-effort |
| 4 | No similar-case retrieval | No system holds case-level embeddings or similarity index |
| 5 | No PCAP-on-case automation | Arkime exists separately; nothing pulls captures into the analyst flow |
| 6 | No TI-in-workflow integration | OpenCTI is a separate tab |
| 7 | No MITRE coverage view | Mapping exists in spreadsheets at best |
| 8 | No detection-engineering feedback loop | DE has no per-rule analyst-closure metrics |
| 9 | No structured analyst training surface | Onboarding is ad-hoc and pair-with-a-senior |
| 10 | No SOC-grade RBAC | YouTrack RBAC is generic; not 7-tier SOC role-aware |
| 11 | No multi-framework compliance map | Audit pack assembly is a recurring project, not a button |
| 12 | No shift-handover structure | Handover happens in Slack |
| 13 | No analyst-efficiency view | No fair, data-driven view of per-analyst load and quality |
| 14 | No tamper-evident forensic chain | DFIR work is ad-hoc; chain of custody is paper |
| 15 | No air-gap-first design constraint | Most tools assume internet |

# 4. The Guarded Glass-delivered stack

GG delivers nine integrated tools — eight on top of what's there today, plus the configured n8n:

| # | Tool | Role | New / Retained / Replaced |
|---|---|---|---|
| 1 | **ION** | SOC analyst workbench + AI analyst (Bob) + case workbench + curriculum | NEW |
| 2 | **TIDE** | Detection-engineering platform: rule lifecycle, content QA, coverage analysis | NEW |
| 3 | **Elastic** | SIEM (kept; the customer's existing investment) | RETAINED |
| 4 | **GitLab** | Detection-content-as-code: TIDE rules, ION templates, playbooks under version control + CI | NEW |
| 5 | **DFIR-IRIS** | Open-source DFIR case management for deep forensic workflows | NEW |
| 6 | **Arkime** | Full-packet capture, search, and retrieval | NEW |
| 7 | **OpenCTI** | Threat intelligence platform | NEW |
| 8 | **Keycloak** | Identity + SSO + OIDC | NEW |
| 9 | **n8n** | Workflow automation (now configured against ION events) | RETAINED + CONFIGURED |

**YouTrack** is **retired** in the target stack — replaced by **GitLab Issues** (engineering work) and **ION** (SOC cases). The customer has confirmed there is no place for YouTrack alongside GitLab + ION. §9 below shows how each YouTrack workflow is preserved.

# 5. ION's role in this stack

```
                           ┌────────────────────────────────┐
                           │              ION               │
                           │     SOC analyst workbench      │
                           │     + Bob (AI analyst)         │
                           │     + tamper-evident audit     │
                           │     + curriculum               │
                           └─────┬───────┬──────┬─────┬─────┘
                                 │       │      │     │
                                 │       │      │     │
        ┌────────────────────────┘       │      │     └─────────────────────────┐
        │           ┌────────────────────┘      └──────────────┐                │
        │           │                                          │                │
        ▼           ▼                                          ▼                ▼
   ┌─────────┐ ┌──────┐ ┌──────────┐ ┌────────┐ ┌──────────┐ ┌────────┐ ┌─────────┐
   │ Elastic │ │ TIDE │ │ DFIR-IRIS│ │ Arkime │ │ OpenCTI  │ │ GitLab │ │ Keycloak│
   │  (SIEM) │ │  (DE)│ │  (DFIR)  │ │ (PCAP) │ │   (TI)   │ │ (code) │ │  (IDP)  │
   └─────────┘ └──────┘ └──────────┘ └────────┘ └──────────┘ └────────┘ └─────────┘
        ▲           ▲                                                            
        │           │                                                            
        │           │                       webhooks / events                    
        │           │                              ▲                             
        │           │                              │                             
        └───────────┴──────────────────────────────┤                             
                                                   │                             
                                              ┌────┴──────┐                      
                                              │   n8n     │                      
                                              │ (config'd)│                      
                                              └───────────┘                      
```

ION is the **glue + analyst seat + AI assistant**:

- The **glue** because it pulls from Elastic (alerts), Arkime (PCAP), OpenCTI (TI), TIDE (rules), GitLab (code), Keycloak (identity), and pushes to DFIR-IRIS (forensics) and n8n (workflow events).
- The **analyst seat** because it's the single screen an L1/L2/L3 spends 95% of their shift in.
- The **AI assistant** because Bob runs inside ION, scoped to each alert with a 5-tier matcher, producing decision-support verdicts the analyst evaluates.

ION does NOT replace:

- Elastic (SIEM) — Elastic stays the SIEM
- TIDE (DE) — TIDE owns the rule lifecycle; ION reads it
- GitLab (code) — code stays in GitLab; ION links to MRs and reads history
- DFIR-IRIS — for customers with an existing DFIR-IRIS workflow, ION pushes forensic case data into IRIS via the integration adapter
- Arkime / OpenCTI / Keycloak — each kept; ION orchestrates them

ION DOES replace:

- YouTrack for SOC cases — YouTrack stays for non-SOC engineering work
- Manual analyst pivot between SIEM + ticketing + TI + PCAP — ION is the unified surface

# 6. Side-by-side: current state vs ION-in-the-GG-stack

This is the **first** of two gap analyses in this brief. Read it with §7.

- **§6** = what changes when the customer moves from **today's 3-tool state** (Elastic + YouTrack + unconfigured n8n) to the **full GG stack with ION at the centre**. This is the headline transformation.
- **§7** = what ION uniquely provides **even if** the customer were to buy the rest of the GG stack (TIDE + GitLab + DFIR-IRIS + Arkime + OpenCTI + Keycloak + n8n) **without** ION. This is the "do we still need ION?" question — answered tool by tool.

For each gap observable today (§3), the table below shows what current-stack analysts do, what ION provides, and which ION feature realises it.

| # | Pain point | Current state | With ION |
|---|---|---|---|
| 1 | **Alert triage queue** | Alerts in Elastic Security; manual sort; per-alert tab-jump for context | `/alerts` queue sorted severity × age; per-alert MITRE, host/user, **Bob verdict + confidence band**, similar past cases preview |
| 2 | **AI-assisted decision support** | None | **Bob** — 5-tier prompt matcher (rule_id → regex → MITRE technique → tactic → groups); structured output schema; confidence rating + circuit breaker; advisory text + suggested next steps |
| 3 | **Case creation** | New YouTrack ticket; analyst pastes evidence | `/alerts` → "Create Case from Selected"; single-click; case_grouper offers a merge candidate; PCAP analysis + similar cases auto-queue |
| 4 | **Case workbench** | Free-text YouTrack ticket description | `CaseEvidencePin` rows for every pinned artefact (alert, observable, query, note, file); ledger badge tracks pin history |
| 5 | **Tamper-evident audit** | None (YouTrack ticket mutable) | `CaseEvidenceLedger` sha256-chained event-by-event; verification walks the chain post-hoc; broken links flagged with row-level granularity |
| 6 | **Similar past cases** | "Ask the senior" | pgvector + HNSW: top-5 similar past cases on the case detail page with their closure reasons |
| 7 | **Cross-source entity timeline** | Manual aggregation across tools | `/entity-timeline/{type}/{id}` unified timeline for host / user / IP across all ION data |
| 8 | **PCAP on case-create** | Manual Arkime query | `pcap_analysis_service` pulls Arkime sessions automatically; community_id preferred, IP+time fallback (v0.29.1); 12 heuristic detectors run; findings post to case Workbench |
| 9 | **TI in-line on observables** | Manual OpenCTI tab pivot | Batch OpenCTI enrichment on observables; threat-actor profile click-through; IOC sparkline (v0.27.0) |
| 10 | **Threat landscape view** | Manually compiled spreadsheet | `/threat-landscape` aggregates top actors, top techniques, recent IOCs; "Generate Briefing" produces exec-grade output |
| 11 | **MITRE ATT&CK coverage** | Quarterly Excel update | `/cyab/attack-heatmap` (v0.22.0): bundled ATT&CK v15.1 overlaid with the customer's TIDE rules; drill-in surfaces gaps |
| 12 | **Threat Watch Gap detection** | None | `threat_watch_gap_service` alerts when a watched actor gains a technique without TIDE coverage |
| 13 | **Per-rule performance metrics** | None at case level | `/engineering/analytics` ranks rules by FP rate × volume; drill-in shows example alerts and Bob-vs-analyst divergences (AIFeedback dual-write) |
| 14 | **Tuning proposal workflow** | Ad-hoc Slack/JIRA | `/tuning-proposals` lifecycle: file → review → sync to TIDE → close |
| 15 | **Multi-framework compliance map** | Spreadsheet | `/compliance`: maps TIDE rules to NIST CSF, ISO 27001, ACSC Essential Eight, DefStan; exportable coverage report |
| 16 | **Bob prompt-template management** | None | `/alert-prompts` CRUD + per-template `confidence_threshold_override`; eval harness scores P/R/F1 against historical alerts |
| 17 | **Daily SOC briefing** | Manual standup notes | `/briefing` aggregates P1/P2 incidents, alert volume, noisy rules, SLA breaches; `/daily-standup` runs the meeting |
| 18 | **Shift handover** | Slack / email | `/shift-handover` pre-populates with cases changed, alert volume, P1/P2 incidents, outstanding tunings; persists to next shift's `/briefing` |
| 19 | **Analyst efficiency view** | None (or punitive cases-closed) | `/analyst-efficiency`: per-analyst cases closed, dwell time, closure-reason distribution, Bob-agreement rate (diagnostic, not punitive) |
| 20 | **Executive briefing** | Manual write-up | `/threat-landscape` → Generate Briefing produces editable, exportable exec text |
| 21 | **SLA breach tracking** | None | Per-case SLA policies; breach log records every breach with attribution |
| 22 | **SOC maturity scorecard** | None | `/maturity` 5-dimension A-F grade |
| 23 | **Forensic case + chain of custody** | DFIR ad-hoc | `ForensicCase` first-class entity; Workbench parity; `EvidenceItem` + `CustodyLogEntry` rows queryable; PUSHES TO DFIR-IRIS for customers with an IRIS forensic workflow |
| 24 | **Knowledge graph navigation** | None | Threat-intel knowledge graph: click-to-pivot across actors, techniques, IOCs, cases |
| 25 | **AI chat with ION's data** | None | `/ai-chat` accepts NL questions; routes to local Ollama; responses cite ION data sources |
| 26 | **NL-to-Elasticsearch query** | Analyst writes KQL by hand | Bob NL→ES converter; emits Elasticsearch query JSON; analyst confirms before execution |
| 27 | **AI document generation** | None | Bob drafts incident reports, exec briefs, IR runbook sections from template + context |
| 28 | **Network asset / topology view** | None | `/network-assets` CMDB + `/topology` graph; contextualises alerts |
| 29 | **Log source health** | Silent failures invisible | `/log-source-health`: per-source ingest status, volume trend, silent-source flags |
| 30 | **Adversary emulation tracking** | Spreadsheet | `/emulation` plan library (ATT&CK-tied steps); per-step pass/fail; failed-step → tuning proposal flow |
| 31 | **Canary tokens** | Standalone tool or none | `/canaries` deploys honeydoc / cred / DNS tokens; trip auto-creates P1 case with pre-populated context |
| 32 | **Webhooks to downstream tools** | None | HMAC-signed outbound webhooks on configurable events (case-create, P1 alert) → consumed by n8n / ITSM / Slack |
| 33 | **In-app notifications** | None | `/notifications` surface; case assignment, SLA breach approaching, playbook approval requested |
| 34 | **Curriculum / onboarding** | Pair-with-a-senior | `/training` L1/L2/L3 paths: 24 modules, 187 lessons, labs, mixed quizzes |
| 35 | **Air-gap-first** | Not by design | Bundled ATT&CK + KEV in image; local Ollama; no live external dependencies at runtime |
| 36 | **Tamper-evident forensic ledger** | None | `ForensicCaseLedger` sha256-chained on every forensic Workbench event |
| 37 | **PII anonymisation toggle** | None | `ION_PII_ANON_ENABLED` env var; opt-in PII scrubbing |
| 38 | **SOC-grade RBAC (7-tier)** | YouTrack generic RBAC | 7-tier hierarchy: l1_analyst → soc_manager → admin; permissions enforced endpoint + service (defence-in-depth) |

# 7. The "if we bought everything else but not ION" analysis

This section addresses a real procurement question: **what does ION add that the rest of the GG stack does not already provide?** Or framed bluntly: if a customer bought TIDE + GitLab + DFIR-IRIS + Arkime + OpenCTI + Keycloak + n8n on top of their existing Elastic + YouTrack, would they still need ION?

**Short answer: yes — every tool below is excellent in its own role; none is an analyst workbench, and the orchestration value is absent without ION.**

The long answer is the tool-by-tool walk below. For each GG-stack tool, this section captures:

- What the tool gives you (its true strength)
- What it does **not** give you (its scope boundary)
- What's still missing for a daily analyst — and which ION feature fills it

## 7.1 Even with TIDE — what's still missing?

| Aspect | TIDE provides | TIDE does NOT provide | ION fills |
|---|---|---|---|
| Detection rule lifecycle | ✅ Full content-as-code; CI; QA | — | — (TIDE owns this) |
| Per-rule code-level history | ✅ Git/GitLab-backed | — | — |
| Rule coverage vs MITRE | ✅ Coverage map (engineering view) | A per-alert, **per-case-closure** view of how each rule actually performs at runtime | `/engineering/analytics`: ranks rules by FP-rate × volume **using analyst close reasons** (AIFeedback dual-write); drill-in shows example alerts + Bob-vs-analyst divergences |
| Tuning workflow | ✅ Engineers can edit rules | The feedback loop from analyst closure data → tuning proposal → TIDE | `/tuning-proposals` lifecycle: file (in ION) → review → sync to TIDE → close; AIFeedback ledger is the data source |

**The missing piece:** TIDE is the *engineer's* workbench for rules. It doesn't see how rules perform in *the analyst's hands*. ION is the surface where Bob, the analyst, and the rule meet — and the place where the per-rule performance signal gets generated, then handed back to TIDE.

## 7.2 Even with GitLab — what's still missing?

| Aspect | GitLab provides | GitLab does NOT provide | ION fills |
|---|---|---|---|
| Version control for detection content + playbooks + Bob templates | ✅ | — | — |
| MR review / CI / approvals | ✅ | — | — |
| Issue tracking for engineering work | ✅ | — | — |
| Linking from a live case to "which rule version produced this alert" | — | The bidirectional link between a runtime case and the rule's git history | ION's alert detail + `/alert-prompts` page surfaces the rule + template version that fired; GitLab is the deep-link target |

**The missing piece:** GitLab is the version-control backbone, not the analyst's seat. The analyst doesn't open GitLab to triage an alert. ION provides the link from "an alert just fired" → "here's the rule version + template version + recent changes" without leaving the alert detail.

## 7.3 Even with DFIR-IRIS — what's still missing?

| Aspect | DFIR-IRIS provides | DFIR-IRIS does NOT provide | ION fills |
|---|---|---|---|
| DFIR case system-of-record | ✅ | — | — |
| Forensic case fields + categorisation | ✅ | — | — |
| Open-source forensic case retention | ✅ | — | — |
| Daily analyst-workbench surface for cases | — | A tamper-evident pin-evidence-as-you-go workflow integrated with live alerts | ION's ForensicCase Workbench: pinned evidence + sha256-chained ledger + custody log; cases ESCALATE from AlertCase → ForensicCase within ION; then pushed to IRIS via `dfir_iris_service` |
| AI-assisted forensic guidance | — | Bob-style decision support, NIST SP 800-86 playbook integration | ION's forensic playbooks + Bob hooks |
| Cross-source entity timeline | — | A unified host / user / IP timeline across alerts, observables, sessions | ION's `/entity-timeline/{type}/{id}` |

**The missing piece:** DFIR-IRIS is the customer's DFIR system-of-record. It is not the daily analyst surface. ION's ForensicCase is the surface; ION pushes to IRIS when the forensic workflow needs the system-of-record. Both have a role.

## 7.4 Even with Arkime — what's still missing?

| Aspect | Arkime provides | Arkime does NOT provide | ION fills |
|---|---|---|---|
| Full-packet capture + indexing | ✅ | — | — |
| PCAP query (community_id, host, time-range) | ✅ | — | — |
| Per-session metadata | ✅ | — | — |
| Per-session PCAP download | ✅ | — | — |
| Automatic case-time PCAP retrieval | — | The "PCAP on case-create" automation; community_id-first with IP+time fallback | `pcap_analysis_service`: runs on case-create; community_id preferred, IP+time fallback added v0.29.1; pulls PCAP via Arkime |
| Heuristic PCAP analysis (12 detectors) | — | TLS abuse, JA3 fingerprints, credential exposure, beaconing, exfil patterns, … | ION runs these in-product on pulled PCAP; findings auto-pinned to case Workbench |
| In-product PCAP findings on a case | — | Arkime is a separate pivot | ION's `/cases/{id}` Workbench shows PCAP findings as a pinned comment |

**The missing piece:** Arkime is the capture and search backend. ION is the analyst-facing automation that pulls the right PCAP at the right time and runs the right detectors against it — automatically, on case-create. Without ION, this is a 30-minute manual workflow for every case.

## 7.5 Even with OpenCTI — what's still missing?

| Aspect | OpenCTI provides | OpenCTI does NOT provide | ION fills |
|---|---|---|---|
| TI knowledge base (actors, techniques, IOCs, reports) | ✅ | — | — |
| TI relationship graph | ✅ | — | — |
| TI feeds + import | ✅ | — | — |
| Inline IOC enrichment **at decision time** | — | The "right when the analyst is closing the alert" enrichment | ION batch-enriches observables via OpenCTI; results render in `/cases/{id}` and `/alerts` without a tab pivot |
| Threat Watch Gap on actor-coverage delta | — | "Actor X gained technique T; we don't have a TIDE rule for T" | ION's `threat_watch_gap_service` raises alerts; cross-references `/cyab/attack-heatmap` |
| Threat landscape briefing generator | — | Curated daily briefing assembled automatically | ION's `/threat-landscape` + Generate Briefing (v0.27.0) |
| Knowledge graph navigation in the analyst flow | — | A click-to-pivot graph integrated with cases | ION's knowledge-graph surface in `/threat-intel` |

**The missing piece:** OpenCTI is the TI library. It is not in the analyst's workflow until ION puts it there. ION pulls actors, IOCs, reports inline at decision-time; raises Threat Watch Gap alerts on coverage drift; generates the daily briefing. Without ION, OpenCTI remains a tab nobody opens.

## 7.6 Even with Keycloak — what's still missing?

| Aspect | Keycloak provides | Keycloak does NOT provide | ION fills |
|---|---|---|---|
| Identity, SSO, OIDC | ✅ | — | — |
| Group + role membership | ✅ | — | — |
| Federated identity across tools | ✅ | — | — |
| SOC-specific 7-tier role hierarchy | — | Generic groups; not SOC-specialised | ION's 7-tier RBAC (`l1_analyst` → `soc_manager` → `admin`); permissions enforced endpoint + service-internal (defence-in-depth) |
| Per-service service-internal auth checks | — | Identity verification at edge, not at internal mutation | ION's TOCTOU-defence: every service mutation re-checks auth before commit |

**The missing piece:** Keycloak is the IDP. It says "this is the user." ION is the application that says "this user can do X on this case." Keycloak doesn't replace the application-side RBAC; it feeds it. ION's RBAC is 7-tier and SOC-aware in a way generic IDP groups cannot be.

## 7.7 Even with n8n — what's still missing?

| Aspect | n8n provides | n8n does NOT provide | ION fills |
|---|---|---|---|
| Workflow automation engine | ✅ | — | — |
| Connector library (ITSM, Slack, email, …) | ✅ | — | — |
| Visual workflow builder | ✅ | — | — |
| **Structured events to react to** | — | n8n needs events from somewhere; current state has none | ION emits HMAC-signed webhooks on `case_created`, `case_closed`, `p1_alert`, `sla_breach`, etc. — finally n8n has structured events to fire on |
| Analyst-driven actions back through n8n | — | The reverse direction: analyst clicks → n8n executes external workflow | ION's playbook actions → n8n via configured webhook → external system |

**The missing piece:** n8n is *automation*, not *analyst tooling*. It needs structured events to be useful; currently those events don't exist. ION emits them. The customer's unconfigured n8n becomes valuable the moment ION is producing structured signal.

## 7.8 Even with YouTrack — what's still missing?

This is a special case because YouTrack is in the current state, not the new GG stack. But it's worth being explicit about what YouTrack does NOT do (since some buyers may be tempted to bend YouTrack into the SOC workbench role):

| Aspect | YouTrack provides | YouTrack does NOT provide | ION fills |
|---|---|---|---|
| Generic issue tracking | ✅ | — | — |
| Custom fields / agile board | ✅ | — | — |
| Engineering ticket lifecycle | ✅ | — | — |
| SOC-aware RBAC (7-tier) | — | Generic permissions | ION |
| Bob (AI analyst) | — | — | ION |
| Tamper-evident sha256 ledger | — | Mutable free-text | ION |
| Similar-case retrieval (pgvector + HNSW) | — | Full-text search at best | ION |
| Per-rule analyst closure metrics | — | No tie to detection content | ION's AIFeedback ledger |
| MITRE coverage view | — | — | ION |
| Cross-source entity timeline | — | — | ION |
| PCAP auto-on-case | — | — | ION |
| Inline TI enrichment | — | — | ION |
| Shift handover with auto-population | — | — | ION |
| SLA breach tracking with severity-aware escalation | — | Generic SLAs at best | ION |
| Workbench pin types (alert / observable / query / note / file) | — | Attachments | ION |
| Multi-framework compliance map | — | — | ION |

**The missing piece:** YouTrack is general-purpose. It is not SOC-purpose-built. None of the SOC-specialised capabilities ION provides are reachable through YouTrack customisation alone (and even if they could be, you'd be reinventing ION — badly — inside a ticketing tool).

## 7.9 Summary: ION's irreplaceable layer

Combining §7.1 through §7.8, the capabilities that exist **only in ION** within the full GG stack are:

1. **Daily analyst-workbench surface** — single unified seat for L1/L2/L3
2. **Bob (AI analyst)** with confidence + circuit-breaker + per-template tuning
3. **Tamper-evident case-evidence ledger** (sha256-chained)
4. **AIFeedback dual-write** — closes the detection-engineering feedback loop between Bob, the analyst, and TIDE
5. **Similar-case retrieval** via pgvector + HNSW
6. **PCAP auto-analysis** on case-create with 12 heuristic detectors
7. **Inline TI enrichment** at decision-time + Threat Watch Gap on coverage drift
8. **Threat landscape briefing generator** (v0.27.0)
9. **`/engineering/analytics`** — per-rule performance with analyst-closure attribution
10. **MITRE ATT&CK heatmap** (`/cyab/attack-heatmap`, bundled ATT&CK v15.1)
11. **D3FEND mapping + ATT&CK Navigator export**
12. **Multi-framework compliance map** (NIST CSF, ISO 27001, ACSC E8, DefStan, …)
13. **Cross-source entity timeline** across alerts, observables, sessions
14. **`/shift-handover` + `/briefing`** structure
15. **`/analyst-efficiency`** fair view of per-analyst data
16. **`/alert-prompts`** + Bob eval harness (P/R/F1 on historical alerts)
17. **`/forensics` Workbench** + ForensicCase ledger + `dfir_iris_service` push
18. **Curriculum** (24 modules, 187 lessons, labs)
19. **SOC-grade 7-tier RBAC** with service-internal auth checks
20. **Webhook event source** that finally makes n8n configurable
21. **Knowledge graph navigation** in the analyst flow
22. **Canary trip → P1 alert + playbook** workflow
23. **Adversary emulation tracking** with tuning-feedback loop
24. **Air-gap-first design** (bundled ATT&CK + KEV; local Ollama)
25. **Customer-agnostic core + per-customer overlay** docs pattern

Each of these requires the analyst-workbench layer ION provides. None can be assembled from "more TIDE rules + more OpenCTI feeds + a configured n8n."

# 8. ION ↔ tool integration map

How ION actually wires up with each of the GG-stack tools at runtime. Pattern: ION owns the analyst surface; each tool keeps its specialised role; the integration is API-first, configured per env-var.

## 8.1 ION ↔ Elastic (SIEM)

| Direction | What happens |
|---|---|
| ION → Elastic | `elasticsearch_service.py` pulls alerts (ES Security API) on a 30s schedule; pulls saved-search results; submits NL→ES queries through `/discover` |
| Elastic → ION | None direct; Elastic is the source-of-truth alert store. ION caches the alerts for triage. |
| Auth | API key OR basic |
| Failure | "Alerts unavailable" banner; cases/workbench/etc. unaffected |
| ION surfaces consuming this | `/alerts`, `/discover`, AI Chat (NL-to-ES), `/cases/{id}` (linked alert references) |

**Operational note.** ION does NOT replace Elastic as the SIEM. Elastic stays the rule-firing engine; ION stays the analyst's seat. The two are complementary.

## 8.2 ION ↔ TIDE (Detection Engineering)

| Direction | What happens |
|---|---|
| ION → TIDE | `tide_service.py` + `tide_sync_service.py` pull rules, execution reports, posture data; `/tide` 7-tab UI in ION surfaces this |
| TIDE → ION | None direct; ION reads from TIDE |
| Tuning proposal sync | Approved tuning proposals in ION push to TIDE (rule update); TIDE's CI runs against the change |
| Auth | API key |
| Failure | TIDE pages show "not configured"; ION's other surfaces unaffected |
| ION surfaces consuming this | `/tide`, `/engineering/analytics`, `/tuning-proposals`, `/cyab/attack-heatmap`, `/compliance`, `/d3fend` |

**Detection-engineering loop.** Closes the feedback loop: AIFeedback (Bob-vs-analyst) → `/engineering/analytics` → `/tuning-proposals` (filed in ION) → TIDE rule update → TIDE CI green → deployed back through Elastic. Today this loop is broken; ION + TIDE wire it together.

## 8.3 ION ↔ GitLab (code + content)

| Direction | What happens |
|---|---|
| ION → GitLab | `gitlab_service.py` reads issue history; reads MR status; links case-related changes |
| GitLab → ION | Webhook-based: detection content merged in GitLab triggers TIDE refresh, which ION picks up |
| Auth | Personal access token |
| Failure | Linked-issue widget shows degraded; everything else fine |
| ION surfaces consuming this | Cross-reference panels on `/cases/{id}`, `/tuning-proposals`, `/alert-prompts` |

**Detection-content-as-code.** With GG's stack, TIDE rules, ION's `AlertPromptTemplate` content, and playbooks all live in GitLab with full version history, MR review, and CI. ION surfaces the "what rule is this and when did it change" question on every alert.

## 8.4 ION ↔ DFIR-IRIS (forensic case management)

| Direction | What happens |
|---|---|
| ION → DFIR-IRIS | `dfir_iris_service.py`: `create_case`, `add_ioc`, `add_note`, `add_event`, `map_tactic_to_category` |
| DFIR-IRIS → ION | None direct |
| Pattern | When an ION ForensicCase reaches a maturity threshold (e.g. case escalates to deep forensic review), ION can push it into IRIS so customer's DFIR team continues in IRIS's workflow |
| Auth | API key |
| Failure | Push falls back to ION-only ForensicCase; ION's forensic surface stays functional standalone |
| ION surfaces consuming this | `/forensics/{id}`, ForensicCase Workbench |

**Why both?** ION's ForensicCase is the analyst surface — pinned evidence, ledger, Workbench. DFIR-IRIS is the customer's chosen DFIR system-of-record for forensic case history beyond the daily-analyst-workbench horizon. ION + IRIS = active surface + retained record.

## 8.5 ION ↔ Arkime (PCAP)

| Direction | What happens |
|---|---|
| ION → Arkime | `arkime_service.py`: `find_sessions_by_community_id`, `find_sessions_by_ip` (v0.29.1 fallback), `download_pcap(node, session_id)` |
| Arkime → ION | None direct |
| Pattern | Case-create triggers `pcap_analysis_service._runner`; pulls the relevant PCAP automatically; 12 heuristic detectors run; findings post to case Workbench as a pinned comment |
| Auth | Keycloak client_credentials (preferred) OR basic |
| Failure | PCAP-related actions on cases show "PCAP unavailable"; case workflow continues |
| ION surfaces consuming this | `/cases/{id}` (auto-attached PCAP findings), `/arkime/preview` (manual button) |

**Single most-cited time-saver.** Per-case PCAP context arrives in seconds rather than the 30 minutes of Arkime-Wireshark-NetworkMiner manual pivot.

## 8.6 ION ↔ OpenCTI (threat intelligence)

| Direction | What happens |
|---|---|
| ION → OpenCTI | `opencti_service.py` pulls actors, IOCs, reports, watchlists |
| OpenCTI → ION | None direct; ION pulls |
| Pattern | Observable enrichment in batch on case-create; per-IOC `last-seen` + `confidence` from OpenCTI; actor profile page composes data |
| Auth | API key |
| Failure | TI pages show "no source"; cases continue to work |
| ION surfaces consuming this | `/threat-intel`, actor profile, IOC sparkline, observable enrichment on `/cases/{id}` |

**TI moves from a tab to a workflow.** Today analysts don't open OpenCTI unless reminded. With ION + OpenCTI, IOC enrichment is automatic; actor profiles drill from techniques to ATT&CK coverage; Threat Watch Gap raises alerts on coverage drift.

## 8.7 ION ↔ Keycloak (identity)

| Direction | What happens |
|---|---|
| ION → Keycloak | OIDC flow: redirect to Keycloak; verify JWT via JWKS (RS256 only — HS256 explicitly refused) |
| Keycloak → ION | Token + user-info on callback |
| Pattern | Customer's existing identity-management; SSO across the GG stack; group → ION role mapping |
| Auth | OIDC RS256; JWKS auto-refresh |
| Failure | Falls back to ION-local password (if configured) |
| ION surfaces consuming this | All authenticated pages |

**Single-sign-on across the stack.** Analysts authenticate once via Keycloak and reach Elastic, TIDE, ION, OpenCTI, Arkime, DFIR-IRIS without re-entering credentials.

## 8.8 ION ↔ n8n (workflow automation)

| Direction | What happens |
|---|---|
| ION → n8n | HMAC-signed webhook on configurable events (`case_created`, `case_closed`, `p1_alert`, `sla_breach`) |
| n8n → ION | n8n calls ION's API (with permission-gated token) to take actions: enrich observable, attach note, change case state |
| Pattern | n8n is the **automation** layer fed by structured ION events; it can react across customer ITSM, messaging, paging tools |
| Auth | HMAC for outbound; API token for inbound |
| Failure | n8n unconfigured = no automation; ION continues working analyst-side |
| ION surfaces consuming this | `/integrations` (webhook config), `/admin/webhook-log` (delivery log) |

**Why n8n configures NOW.** With ION emitting structured events, n8n finally has something useful to react to. The "what should n8n do?" question becomes "what cross-tool reaction does each event need?" — answerable in concrete terms.

## 8.9 Integration matrix (one-page summary)

| Tool | ION pulls from | ION pushes to | Auth | Failure mode |
|---|---|---|---|---|
| Elastic | Alerts, queries | — | API key / basic | "alerts unavailable" banner |
| TIDE | Rules, posture | Tuning proposals | API key | TIDE pages disabled |
| GitLab | Issue + MR history | — | PAT | Linked-issue widget degraded |
| DFIR-IRIS | — | Case, IOCs, notes, events | API key | Push falls back to ION-only |
| Arkime | PCAP sessions + downloads | — | Keycloak client_credentials | "PCAP unavailable" |
| OpenCTI | Actors, IOCs, reports | — | API key | TI pages disabled |
| Keycloak | OIDC JWT (RS256) | — | OIDC | Local password fallback |
| n8n | — | Webhooks (HMAC-signed) | HMAC | Automation paused; ION OK |

# 9. Where YouTrack still fits in

**YouTrack is retired in the target stack.** The customer has confirmed they do not retain YouTrack alongside GitLab + ION. Every workflow YouTrack served is preserved in the GG stack as follows:

| Pre-GG YouTrack workflow | Where it lives now |
|---|---|
| SOC case lifecycle (alerts → investigation → close) | **ION** — purpose-built workbench; sha256-chained ledger; Bob; similar-case retrieval; SOC-grade RBAC |
| Engineering bug tickets | **GitLab Issues** — code-adjacent; CI-linked; MR-traceable |
| Sprint / agile board for engineering teams | **GitLab Boards** — same Issues, kanban / scrum view |
| Detection-content change tickets | **GitLab Issues** against the detection-content repo + **TIDE** for the actual rule lifecycle |
| Feature requests / wishlist | **GitLab Issues** (labelled `feature`) |
| Cross-team handoff (SOC → engineering) | **ION webhook → n8n → GitLab Issue creation** (HMAC-signed; logged in `/admin/webhook-log`) |

**Why this works without YouTrack.** GitLab Issues is fully featured for engineering ticketing — custom fields, labels, milestones, boards, time tracking. ION is fully featured for SOC cases. Maintaining a third generic tool (YouTrack) for tickets means three RBAC stores, three audit trails, three search surfaces. The GG stack consolidates to two purpose-built tools.

**What NOT to do.** Don't reintroduce YouTrack for SOC cases — generic ticketing systems used for SOC always lose to specialised workbenches over time, and ION's RBAC, ledger, similar-case, and AI features are not portable to YouTrack. Don't dual-track engineering tickets between GitLab and any external system; pick GitLab and stay there.

# 10. Adoption history + remaining acceptance gates

The GG stack is **operational today**. The migration from the pre-GG state has happened. What remains is formal acceptance into the customer's governance regime — registration, design-authority review, service-transition sign-off, compliance evidence countersigning. This section is provided so reviewers can see the operational journey already taken AND the gates still open.

## 10.1 Operational adoption (already done)

| Stage | Status | Outcome |
|---|---|---|
| Customer infra provisioned (Postgres, reverse proxy, secrets) | ✅ Done | Stack ready |
| ION + Keycloak deployed; OIDC SSO live | ✅ Done | Analysts log in via SSO |
| Elastic-as-source wiring | ✅ Done | ION pulls alerts from customer's Elastic |
| TIDE + GitLab live; detection-content-as-code | ✅ Done | Rule lifecycle owned by detection engineering |
| OpenCTI + Arkime + DFIR-IRIS integrated | ✅ Done | TI inline; PCAP auto-analysis on case-create; ForensicCase pushes to IRIS |
| n8n configured against ION webhooks | ✅ Done | Cross-tool automation fires on case events |
| YouTrack retired | ✅ Done | Engineering tickets in GitLab; SOC cases in ION |
| Analyst-workflow steady state | ✅ Done | Bob + Workbench + similar-case in daily use |

**Operational evidence today** — provable in `/audit-log`, `/engineering/analytics`, `/workbench-audit`, and the customer's SIEM ingestion of ION's ECS-shaped stdout logs.

## 10.2 Remaining acceptance gates (in progress)

| Gate | Status | Owner | Substantiating artefact |
|---|---|---|---|
| Application register entry (DART / CAAT or customer equivalent) | ⏳ Submission body authored | Customer STO | `_mod_app_register_submission.md` |
| SRO assigned | ⏳ Pending customer | Customer | (process step) |
| STO assigned | ⏳ Pending customer | Customer | (process step) |
| Design-Authority review | ⏳ Submission body authored | Customer DA chair | `_mod_architecture_governance.md`, `docs/HLD.md` |
| Design Passport sign-off (Definition gate → Acceptance gate → In-Service) | ⏳ Authored, gates open | Customer SRO + DA chair | `_mod_design_passport.md` |
| DPIA countersigned | ⏳ Authored | Customer DPO | `_mod_dpia.md` |
| Safety-Benign Software Questionnaire countersigned | ⏳ Verdict authored (SIL-0 / DAL-E) | Customer SRO | `_mod_safety_questionnaire.md` |
| WCAG 2.2 AA audit + remediation acceptance | ⏳ Tier-1+2 conformant; Tier-3+4 remediation planned v0.30.0 / v0.31.0 | Maintainer + Customer A11y team | `_mod_wcag_audit.md` |
| ITHC scheduled | ⏳ Not yet scheduled | Customer security | `_mod_iteap.md` §4 |
| DR drill performed against deployed stack | ⏳ Not yet scheduled | Customer operations | `_mod_iteap.md` §5 |
| BC drill performed | ⏳ Not yet scheduled | Customer operations | `_mod_iteap.md` §6 |
| Through-Life Management Plan accepted | ⏳ Authored | Customer SDM | `_mod_through_life_plan.md` |
| Exception register reviewed | ✅ Zero open exceptions at v0.29.1 | Maintainer + Customer SRO | `_mod_exception_register.md` |
| Service Transition Officer brief accepted | ⏳ Authored | Customer STO | `_mod_service_transition.md` |
| Log shipping wired into customer SIEM | ⏳ Configurable per `_mod_log_shipping_spec.md` | Customer SIEM team | `_mod_log_shipping_spec.md` |

**What this brief contributes.** This document gives reviewers an ION-specific articulation of the load-bearing role for the design-authority and service-transition gates. It pairs with `docs/HLD.md`, `docs/USER_REQUIREMENTS.md`, `docs/TRACEABILITY.md`, and `docs/USE_CASES.md` to give reviewers a complete picture.

# 11. Outcome claims

Claims ION substantiates in operational use on the GG stack today. Each is observable in the deployed instance; numbers below are typical-range placeholders the customer can pin to their own measured baseline.

| Outcome | Pre-GG baseline | Operational today (GG stack with ION) |
|---|---|---|
| Mean time-per-alert | 15–25 min/alert | 3–8 min/alert |
| FP-close rate per shift | tribal | 2-3× via Bob high-confidence-FP |
| Case-evidence retrievability at audit | "best effort" | 100% (Workbench ledger) |
| Detection-rule FP rate visibility per rule | spreadsheet | live (`/engineering/analytics`) |
| MITRE coverage articulable to leadership | quarterly | live (`/cyab/attack-heatmap`) |
| Shift handover variance | high | low (`/shift-handover` structured) |
| New-analyst onboarding time | 6-12 weeks | 3-6 weeks (curriculum) |
| Tamper-evident audit chain on every case | none | yes (sha256 ledger) |

None of the above is reachable from the pre-GG state (Elastic + YouTrack + unconfigured n8n) alone. They all require the analyst-workbench layer ION provides — and they are present today, awaiting formal acceptance.

# 12. Pre-acceptance checklist (formal onboarding gates)

The deployment is operational. This checklist tracks the **formal acceptance** work still in motion. It splits into "operational pre-conditions already met" (proof that the stack is real) and "acceptance gates open" (sign-offs needed).

## 12.1 Operational pre-conditions — already met

- [x] Postgres 16 + pgvector instance provisioned + backup policy in place
- [x] Customer reverse proxy + TLS termination configured
- [x] Customer secrets-management holds Elastic / TIDE / OpenCTI / Arkime / Keycloak / GitLab credentials
- [x] Keycloak realm + ION client + RS256 keys configured
- [x] Ollama runtime ready (Bob enabled) — model pulled and verified
- [x] Customer SOC team analysts in-product on ION's 7-tier RBAC + analyst-workbench workflow
- [x] Smoke-test passing against the deployed instance (per `_mod_iteap.md` §1)
- [x] ION's `/audit-log` and ECS stdout logs operational and observable

## 12.2 Acceptance gates — open

- [ ] DART/CAAT (or customer equivalent) submission filed (`_mod_app_register_submission.md`)
- [ ] SRO assigned by customer
- [ ] STO assigned by customer
- [ ] Design Authority chair reviewed + signed (`_mod_architecture_governance.md`, `docs/HLD.md`)
- [ ] Design Passport — Definition gate signed (`_mod_design_passport.md` §13.1)
- [ ] Design Passport — Acceptance gate signed (`_mod_design_passport.md` §13.2)
- [ ] DPIA countersigned by customer DPO (`_mod_dpia.md`)
- [ ] Safety-Benign Software Questionnaire countersigned (`_mod_safety_questionnaire.md`)
- [ ] WCAG 2.2 AA audit acceptance with remediation plan signed (`_mod_wcag_audit.md`)
- [ ] Through-Life Management Plan accepted (`_mod_through_life_plan.md`)
- [ ] Exception register reviewed (zero open at v0.29.1) (`_mod_exception_register.md`)
- [ ] Service Transition Officer brief accepted (`_mod_service_transition.md`)
- [ ] Log-shipping pipeline wired into customer SIEM (per `_mod_log_shipping_spec.md`)
- [ ] ITHC scheduled with customer's chosen supplier (`_mod_iteap.md` §4)
- [ ] DR drill performed (`_mod_iteap.md` §5)
- [ ] BC scenario walked (`_mod_iteap.md` §6)
- [ ] Service Transition Acceptance Letter signed by STO, SDM, SRO

# 13. Cross-references

| Topic | Doc |
|---|---|
| Architecture | `docs/HLD.md`, `docs/LLD.md` |
| User requirements | `docs/USER_REQUIREMENTS.md` |
| Use cases | `docs/USE_CASES.md` |
| Generic gaps | `docs/GAPS_FILLED.md` |
| Traceability | `docs/TRACEABILITY.md` |
| Deployment | `docs/DEPLOYMENT.md`, `docs/RUNBOOK.md` |
| Security trend | `SECURITY_ASSESSMENT.md` |
| Stack reference | `STACK.md` |

# 14. Glossary

| Term | Meaning |
|---|---|
| GG | Guarded Glass — supplier organisation |
| ION | Intelligent Operating Network — this product; the analyst workbench |
| TIDE | Threat-Informed Defence Engineering platform |
| DFIR-IRIS | Open-source DFIR case management system |
| Arkime | Full-packet capture + search platform |
| OpenCTI | Open Cyber Threat Intelligence platform |
| Keycloak | Open-source identity + access management |
| n8n | Open-source workflow automation tool |
| YouTrack | JetBrains issue tracker / project management |
| Bob | ION's AI analyst assistant (Ollama-backed, decision-support only) |
| Workbench | ION's pinned-evidence + tamper-evident-ledger surface |
| AIFeedback | ION's per-Bob-verdict ledger that captures analyst agreement / divergence |
| ECS | Elastic Common Schema (log format) |
| HMAC | Hash-based message authentication code (webhook signing) |

# 15. Change history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-05-12 | ION maintainer + GG | Initial stack brief authored for customers running Elastic + YouTrack + (unconfigured) n8n |
| 1.1 | 2026-05-12 | ION maintainer + GG | Reframed: customer is **operationally on** the GG stack; YouTrack retired (replaced by GitLab + ION); §10 reworked into "adoption history + remaining acceptance gates"; §12 split into operational pre-conditions met vs acceptance gates open; new §7 added — "if we bought everything else but not ION" tool-by-tool gap analysis |
