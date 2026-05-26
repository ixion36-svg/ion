<!-- ion-doc:type=USE CASES -->
<!-- ion-doc:title=ION Use Cases -->
<!-- ion-doc:subtitle=End-to-end analyst, manager, engineer, admin, and learner workflows -->
<!-- ion-doc:version=0.29.1 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Buyers, end users, integrators, training teams -->
<!-- ion-doc:date=2026-05-12 -->

# 1. Introduction

## 1.1 Purpose

This document enumerates the **operational use cases** ION supports — what each persona does, end-to-end, using ION. It pairs with `docs/GAPS_FILLED.md` (which says *why* each use case matters in a SOC's day) and with `docs/HLD.md` (which says *how* ION supports it architecturally).

Each use case is structured as:

- **Actor** — the persona doing the work
- **Pre-conditions** — what must be true before the use case starts
- **Main flow** — the canonical happy path
- **Alternate flows** — common branches
- **Post-conditions** — what's true once the use case completes
- **ION pages / surfaces** — where in the product this happens

## 1.2 Personas

| Persona | Role | Permission band |
|---|---|---|
| L1 Analyst | Tier-1 triage; first-line responder | `l1_analyst` |
| L2 Analyst | Tier-2 investigation; case manager | `l2_analyst` |
| L3 Analyst | Tier-3 deep-dive; threat hunter; forensicator | `l3_analyst` |
| Detection Engineer | Owns the detection content lifecycle | `detection_engineer` |
| SOC Manager / Lead | Owns SOC posture, shifts, performance | `soc_manager` |
| Admin | Owns deployment configuration, RBAC, integrations | `admin` |
| Learner / Trainee | Inducted analyst, training in progress | `viewer` + curriculum access |
| Compliance / DPO | Owns audit, evidence, accessibility, privacy | `viewer` + `audit:read` |

# 2. L1 Analyst use cases

## UC-L1-01 — Triage an alert

**Actor:** L1 Analyst.
**Pre-conditions:** Alerts present in the Alert Queue (pulled from ES Security every ~30s).

**Main flow:**

1. L1 opens `/alerts` and sees the prioritised alert queue (severity × age).
2. L1 selects the highest-severity, oldest alert.
3. L1 reads the alert summary, MITRE technique annotation, and Bob's verdict suggestion (with confidence band).
4. If Bob's confidence is **high** and verdict is **false-positive**, L1 reviews the reasoning, confirms, and closes the alert with the matching `CaseClosureReason`.
5. If Bob's confidence is **medium**, L1 reads the linked evidence, asks for one more datapoint from Entity Timeline, then decides.
6. If the alert is **true-positive** or warrants further investigation, L1 escalates by creating a case (→ UC-L1-02).

**Alternate flows:**

- **Bob abstains.** No template matched (the 5-tier matcher returned None). L1 triages manually; their decision becomes future training data via AIFeedback dual-write.
- **Bob disagrees with L1.** L1 closes with a different `CaseClosureReason` than Bob suggested. The disagreement is captured for tuning by Detection Engineering.

**Post-conditions:** Alert is in `closed` or `escalated`. Audit log row created. AIFeedback row created (Bob's verdict vs analyst's actual closure).

**ION surfaces:** `/alerts`, alert detail modal, Bob verdict panel, Entity Timeline sidebar.

---

## UC-L1-02 — Create a case from one or more alerts

**Actor:** L1 Analyst.
**Pre-conditions:** One or more alerts open in the queue.

**Main flow:**

1. L1 selects alerts (single or multi-select via bulk-ops checkbox).
2. L1 clicks "Create Case from Selected".
3. ION offers two options:
   - New case with the selected alerts pre-linked, OR
   - Append to an existing case (suggested by case_grouper_service if a host/user/technique overlap matches).
4. L1 enters case title, priority, and assignee (defaults to themselves).
5. ION creates the case. In the background:
   - case_embedding_service queues the case for similarity embedding.
   - pcap_analysis_service queues PCAP retrieval for any alerts with `community_id` or source/destination IP.
   - Workbench is initialised with the alerts pinned and a `case_created` ledger row.

**Post-conditions:** Case is `open`. Alerts are bound. Workbench is seeded. Background tasks running.

**ION surfaces:** `/alerts` (bulk-ops bar), `/cases/{id}` (landing).

---

## UC-L1-03 — Hand over the shift

**Actor:** L1 Analyst (ending shift).
**Pre-conditions:** Open cases, recent alerts of note, ongoing tunings.

**Main flow:**

1. L1 opens `/shift-handover`.
2. ION pre-populates the handover form with: cases changed during the shift, alert volume by severity, open P1/P2 incidents, outstanding tunings.
3. L1 edits / annotates anything that needs context (e.g. "watch host XYZ — third alert today, may need to call EDR team").
4. L1 saves the handover.
5. The handover is visible at the start of the next shift in `/briefing`.

**Post-conditions:** Handover persisted; accessible to incoming shift.

**ION surfaces:** `/shift-handover`, `/briefing`.

# 3. L2 Analyst use cases

## UC-L2-01 — Investigate a case

**Actor:** L2 Analyst (escalated to by L1, or self-assigned).
**Pre-conditions:** Case `open` and assigned (or assignable).

**Main flow:**

1. L2 opens `/cases/{id}`.
2. L2 reviews:
   - Bob's per-alert verdict + reasoning.
   - The Workbench (pinned evidence, ledger).
   - Similar past cases (pgvector sidebar) — closure rate, common findings.
   - Entity timelines for affected hosts / users / IPs (cross-source).
   - Attack Stories if multiple alerts correlate into a kill-chain.
3. L2 pins relevant evidence: alerts, observables, queries, notes, files. Each pin appends to the tamper-evident ledger.
4. L2 enriches observables (batch OpenCTI lookup).
5. L2 makes a determination → either closes the case (with `CaseClosureReason`) or escalates to L3 (→ UC-L2-02).

**Alternate flows:**

- **PCAP needed.** L2 clicks "Preview PCAP" → Arkime preview → confirms → downloads + analyses (12 heuristic detectors). PCAP findings auto-pinned to Workbench with `pcap_attached` ledger row.
- **Playbook applicable.** L2 launches a playbook (with the analyst-approval gate for any external action).

**Post-conditions:** Case is `closed` or `escalated_to_l3`. Workbench ledger has the full pin history. Audit logs complete.

**ION surfaces:** `/cases/{id}` (full surface), Workbench tab, Similar Cases sidebar, Entity Timeline drawer.

---

## UC-L2-02 — Escalate to L3 (deep-dive / forensics)

**Actor:** L2 Analyst.
**Pre-conditions:** Case requires forensic depth (memory analysis, full timeline reconstruction, multi-host pivot).

**Main flow:**

1. L2 clicks "Escalate to Forensics" on the AlertCase.
2. ION creates a linked ForensicCase. All pinned evidence on the AlertCase is referenced (not copied) by the ForensicCase.
3. L3 is paged (in-app notification + assignment).

**Post-conditions:** ForensicCase created and linked. AlertCase remains active but is now `under_forensics_review`.

**ION surfaces:** `/cases/{id}`, `/forensics/{forensic_id}`.

# 4. L3 Analyst use cases

## UC-L3-01 — Run a forensic investigation

**Actor:** L3 Analyst / Forensicator.
**Pre-conditions:** ForensicCase open and assigned.

**Main flow:**

1. L3 opens `/forensics/{id}`.
2. L3 uploads evidence (memory images, file extracts, log dumps) — each upload generates a `CustodyLogEntry` (chain of custody).
3. L3 uses the Workbench on the ForensicCase (parallel to AlertCase): pin evidence, append timeline annotations (v0.22.0), run forensic playbooks (NIST SP 800-86 aligned).
4. L3 cross-references via Entity Timeline (host/user/IP rolling timeline across all ION data).
5. L3 produces a finding summary and case-closes with a `CaseClosureReason`.

**Post-conditions:** ForensicCase `closed`. Chain of custody intact and queryable. AlertCase notified of result.

**ION surfaces:** `/forensics/{id}`, Workbench tab, Custody Log tab, Timeline tab.

---

## UC-L3-02 — Hunt by hypothesis

**Actor:** L3 Analyst / Threat Hunter.
**Pre-conditions:** Threat Intelligence indicating a hypothesis worth testing (e.g. "actor X is using T1059 against our sector").

**Main flow:**

1. L3 opens `/threat-intel` and reviews the actor profile (v0.27.0 actor deep-dive).
2. L3 maps the actor's MITRE techniques onto the customer's `/cyab/attack-heatmap` (v0.22.0) to see coverage gaps.
3. For each gap, L3 builds a saved search (ES Discover) and runs it.
4. Any IOC sightings get logged; if anything turns up, an alert is raised manually or a case opened.

**Post-conditions:** Threat hypothesis tested; coverage gaps documented; cases opened where warranted.

**ION surfaces:** `/threat-intel`, `/cyab/attack-heatmap`, `/discover`, `/cases`.

---

## UC-L3-03 — Build an attack story

**Actor:** L3 Analyst.
**Pre-conditions:** Multiple correlated alerts (case_grouper_service has linked them or analyst-correlated).

**Main flow:**

1. L3 opens `/attack-stories` or the Attack Story panel inside a case.
2. ION auto-orders the alerts onto a kill-chain (Initial Access → Execution → Persistence → ...).
3. L3 annotates each step with their analysis.
4. The story attaches to the case as a pinned narrative; visible to leadership in reports.

**Post-conditions:** Attack story persisted; reportable.

**ION surfaces:** `/attack-stories`, case Workbench.

# 5. Detection Engineer use cases

## UC-DE-01 — Tune a noisy rule

**Actor:** Detection Engineer.
**Pre-conditions:** AIFeedback ledger shows a rule with high false-positive closure rate.

**Main flow:**

1. DE opens `/engineering/analytics` and sees rules ranked by FP rate × volume.
2. DE picks a target rule.
3. DE reviews the example alerts + closure reasons (linked from AIFeedback).
4. DE proposes a tuning (regex tightening, exception, time-window narrowing).
5. DE submits the tuning via `/tuning-proposals` for review.
6. After approval, DE syncs the rule change to TIDE.

**Post-conditions:** Rule updated in TIDE; tuning proposal closed; metrics auto-track post-tuning effect.

**ION surfaces:** `/engineering/analytics`, `/tuning-proposals`, `/tide`.

---

## UC-DE-02 — Map TIDE rules to a compliance framework

**Actor:** Detection Engineer.
**Pre-conditions:** TIDE rules synced; framework target (NIST CSF, ISO 27001, ACSC Essential Eight, or DefStan).

**Main flow:**

1. DE opens `/compliance`.
2. DE picks the framework.
3. ION shows the matrix of framework controls × TIDE rule coverage.
4. DE drills into uncovered controls; adds rules or annotates "covered elsewhere".
5. DE exports a coverage report for the audit team.

**Post-conditions:** Compliance posture report ready; gaps catalogued.

**ION surfaces:** `/compliance`, `/tide`.

---

## UC-DE-03 — Manage Bob's prompt templates

**Actor:** Detection Engineer with `security:settings` permission.
**Pre-conditions:** Bob is enabled; templates exist or need creation.

**Main flow:**

1. DE opens `/alert-prompts`.
2. DE inspects template performance metrics (P/R/F1 from the Bob Eval Harness).
3. DE edits a template's `rule_id` / regex / technique binding, or its `confidence_threshold_override`.
4. DE saves; next alert matching the template uses the new content.

**Post-conditions:** Bob behaviour updated; eval harness re-runs in the background to score the new template.

**ION surfaces:** `/alert-prompts`, `/bob-eval`.

# 6. SOC Manager use cases

## UC-SM-01 — Daily standup briefing

**Actor:** SOC Manager.
**Pre-conditions:** Shift has just ended.

**Main flow:**

1. SOC Manager opens `/briefing`.
2. ION shows: P1/P2 incidents last 24h, top noisy rules, analyst load distribution, SLA breaches, open tuning queue.
3. SOC Manager runs the standup with the team using `/daily-standup`.
4. Action items are captured and tracked.

**Post-conditions:** Daily action register updated; team aligned for the day.

**ION surfaces:** `/briefing`, `/daily-standup`.

---

## UC-SM-02 — Review analyst efficiency

**Actor:** SOC Manager.
**Pre-conditions:** ≥ 1 sprint of activity recorded.

**Main flow:**

1. SOC Manager opens `/analyst-efficiency`.
2. ION shows per-analyst: cases closed, dwell time, closure-reason distribution, Bob-agreement rate, hand-off frequency.
3. SOC Manager identifies coaching opportunities (e.g. "L1-Alice's closure dwell is 4× peer median on phishing cases — pair with L2-Bob").
4. SOC Manager assigns curriculum (→ UC-LR-02).

**Post-conditions:** Coaching plan recorded; learning paths assigned where needed.

**ION surfaces:** `/analyst-efficiency`, `/courses`.

---

## UC-SM-03 — Generate an executive briefing

**Actor:** SOC Manager.
**Pre-conditions:** Period (week/month/quarter) of activity to summarise.

**Main flow:**

1. SOC Manager opens `/threat-landscape` → Generate Briefing (v0.27.0 enhancement).
2. ION assembles an exec-grade briefing: top threats observed, rules tuned, incidents resolved, coverage delta, recommended actions.
3. SOC Manager edits and exports.

**Post-conditions:** Executive briefing ready for leadership read-out.

**ION surfaces:** `/threat-landscape`, `/executive-report`.

# 7. Admin use cases

## UC-AD-01 — Configure an integration

**Actor:** Admin.
**Pre-conditions:** Integration endpoint reachable; credentials available from customer secrets-management.

**Main flow:**

1. Admin opens `/integrations`.
2. Admin picks the integration (e.g. Arkime).
3. Admin enters URL + auth (basic / Keycloak client_credentials).
4. Admin clicks "Test" — ION fires a smoke call and reports OK/fail.
5. Admin saves.

**Post-conditions:** Integration live; surfaces that consume it become active.

**ION surfaces:** `/integrations`, `/settings`.

---

## UC-AD-02 — Manage users + roles

**Actor:** Admin.
**Pre-conditions:** RBAC schema seeded.

**Main flow:**

1. Admin opens `/users`.
2. Admin invites a new user (local password or via OIDC if SSO configured).
3. Admin assigns role (one of the 7 tiers).
4. ION generates an audit_log row for the assignment.

**Post-conditions:** User can log in with the assigned permissions.

**ION surfaces:** `/users`, `/roles`, `/permissions`.

---

## UC-AD-03 — Review audit log

**Actor:** Admin / Compliance.
**Pre-conditions:** `audit:read` permission.

**Main flow:**

1. User opens `/audit-log`.
2. User filters by user / action / target / date range.
3. User exports the slice as CSV for compliance evidence.

**Post-conditions:** Compliance has evidence; no data modified.

**ION surfaces:** `/audit-log`.

---

## UC-AD-04 — Tamper-evidence audit (Workbench)

**Actor:** Admin / Compliance.
**Pre-conditions:** Workbench used; ledger rows exist.

**Main flow:**

1. User opens `/workbench-audit` (or runs the verification CLI).
2. ION walks the ledger by insertion order, recomputes each `event_hash`, compares.
3. Result: all-OK or a specific row flagged as broken.

**Post-conditions:** Ledger integrity attested or a tamper alarm raised.

**ION surfaces:** `/workbench-audit`, CLI `ion verify-ledger`.

# 8. Learner / Trainer use cases

## UC-LR-01 — Complete a curriculum module

**Actor:** Learner (any role with curriculum access).
**Pre-conditions:** Course assigned (or self-enrolled).

**Main flow:**

1. Learner opens `/training` and picks the assigned module (L1, L2, or L3 path).
2. Learner reads the lesson, takes the quiz (mixed question types).
3. Learner runs the lab (v0.20.1 — note: 4 lab-fixture bugs queued for v0.30.0).
4. Quiz + lab outcome recorded; module marked complete.

**Post-conditions:** Curriculum progress tracked; certificate or badge if applicable.

**ION surfaces:** `/training`, `/courses`, `/guide`, `/guide/sim`, `/guide/range`.

---

## UC-LR-02 — Assign training to a team member

**Actor:** SOC Manager.
**Pre-conditions:** Learner identified.

**Main flow:**

1. SOC Manager opens `/courses`.
2. SOC Manager picks a learning path; assigns to the user.
3. Learner sees the assignment in their dashboard.

**Post-conditions:** Assignment persisted; deadline tracked.

**ION surfaces:** `/courses`, `/dashboard`.

# 9. Compliance / DPO use cases

## UC-CO-01 — Respond to a Subject Access Request

**Actor:** DPO / Admin.
**Pre-conditions:** SAR received from data subject (typically a SOC analyst).

**Main flow:**

1. DPO opens `/admin/sar` (or runs the SAR SQL from the DPIA appendix).
2. DPO enters the subject's identifier.
3. ION returns every row across all tables that references the subject (audit log, cases authored, comments, …).
4. DPO exports as CSV/JSON.

**Post-conditions:** SAR-ready data extracted; UK GDPR Article 15 obligation met.

**ION surfaces:** `/admin/sar`, DPIA Appendix A SQL.

---

## UC-CO-02 — Process an Erasure request

**Actor:** DPO / Admin.
**Pre-conditions:** Erasure request validated as legal under UK GDPR Article 17.

**Main flow:**

1. DPO opens `/admin/erasure`.
2. DPO enters the subject identifier; previews affected rows.
3. DPO confirms the erasure; ION nulls / anonymises per the DPIA's documented schema.
4. Audit log captures the erasure action.

**Post-conditions:** Personal identifiers removed; operational artefacts retained as anonymised.

**ION surfaces:** `/admin/erasure`, DPIA Appendix B SQL.

# 10. Threat Intelligence Analyst use cases

## UC-TI-01 — Generate the daily threat briefing

**Actor:** Threat Intel Analyst.
**Pre-conditions:** OpenCTI integration enabled; threat data current.

**Main flow:**

1. TI Analyst opens `/threat-landscape`.
2. Reviews top actors, top techniques, recent IOCs.
3. Clicks "Generate Briefing"; ION assembles an editable draft (v0.27.0).
4. Edits + saves; exports for leadership / SOC team.

**Post-conditions:** Daily briefing distributed; visible in `/briefing` next shift.

**ION surfaces:** `/threat-landscape`, `/executive-report`.

---

## UC-TI-02 — Actor deep-dive + coverage gap

**Actor:** Threat Intel Analyst.
**Pre-conditions:** Actor of interest identified.

**Main flow:**

1. TI Analyst opens the actor profile.
2. Reviews aliases, motivations, sector targets, technique map (with ATT&CK click-through), IOC sparkline.
3. Cross-references actor's techniques with `/cyab/attack-heatmap` to identify coverage gaps.
4. If a Threat Watch Gap fires for this actor, captures the gap as a tuning proposal (→ UC-DE-01).

**Post-conditions:** Coverage gap registered; tuning proposal filed if applicable.

**ION surfaces:** `/threat-intel`, actor profile page, `/cyab/attack-heatmap`, `/tuning-proposals`.

# 11. Operator / SRE use cases

## UC-OP-01 — Deploy a new ION instance

**Actor:** Operator / SRE.
**Pre-conditions:** Customer infrastructure (Postgres, container runtime, reverse proxy) provisioned; secrets in customer's secrets-management.

**Main flow:**

1. Operator follows `docs/DEPLOYMENT.md`: pull image, populate `.env.deploy`, run docker compose.
2. ION starts; runs migrations; emits health-OK to stdout.
3. Operator runs smoke test against `/health` (200 OK), `/login` (renders), one read API (200 OK).
4. Operator wires reverse-proxy + monitoring (per `_mod_service_transition.md`).

**Post-conditions:** ION operational; monitoring picks up health; first login works.

**ION surfaces:** `/health`, `/login`.

---

## UC-OP-02 — DR drill: restore from backup

**Actor:** Operator / SRE.
**Pre-conditions:** Postgres backup ≤ 24h old; image artefact accessible.

**Main flow:**

1. Operator simulates failure (drops the running instance).
2. Restores Postgres from backup using customer's standard procedure.
3. Redeploys ION image.
4. Runs smoke test; confirms data integrity (last case visible, ledger chain valid).
5. Captures wall-clock duration vs RTO target.

**Post-conditions:** Service restored; DR drill evidence captured for the `_mod_iteap.md` §5 record.

**ION surfaces:** `/health`, `/cases`, `/workbench-audit`.

---

## UC-OP-03 — Investigate a slow-query alarm

**Actor:** Operator / SRE.
**Pre-conditions:** Customer monitoring fired on a slow-query log row.

**Main flow:**

1. Operator opens the SIEM trace for the slow-query event.
2. Cross-references with `/admin/health-detail` (pool size, current-in-use, slow-query top-N).
3. Identifies root cause (missing index / scan-table query / pool-exhaustion adjacent).
4. Tunes settings (pool, threshold) via `/settings` OR escalates to maintainer if a code-level fix is needed.

**Post-conditions:** Root cause documented; tuning applied; alarm cleared.

**ION surfaces:** `/admin/health-detail`, `/settings`, SIEM trace.

# 12. AI Chat use cases

## UC-AI-01 — Ask Bob about ION's data

**Actor:** Any analyst.
**Pre-conditions:** Ollama enabled; AI chat surface accessible.

**Main flow:**

1. Analyst opens `/ai-chat` (or contextual chat panel inside a case).
2. Asks a question grounded in ION's data: "What's the trend in failed-logon alerts this week?"
3. Bob retrieves the relevant data, frames an answer with confidence statement.
4. Analyst optionally drills into the cited surfaces.

**Post-conditions:** Question answered with provenance; conversation persisted per user.

**ION surfaces:** `/ai-chat`, case detail (chat panel).

---

## UC-AI-02 — Natural-language to Elasticsearch query

**Actor:** Detection Engineer / L2/L3 Analyst.
**Pre-conditions:** ES Security adapter configured; Ollama enabled.

**Main flow:**

1. Analyst describes the query in plain English: "Show me Kerberos pre-auth failures from any host that's been flagged by an EDR alert in the last 7 days."
2. Bob returns a valid Elasticsearch query JSON preview.
3. Analyst reviews + executes; results appear in `/discover`.
4. If query is wrong, analyst refines the NL prompt.

**Post-conditions:** Query executed; saved-search optionally created.

**ION surfaces:** AI-chat surface, `/discover`.

# 13. Network / CMDB use cases

## UC-NET-01 — Review log source health before tuning a noisy rule

**Actor:** Detection Engineer.
**Pre-conditions:** Log Source Health page populated.

**Main flow:**

1. DE opens `/log-source-health`.
2. Reviews per-source ingest volume, latency, silent flags.
3. Notices a noisy rule's source is intermittent → rule may not be noisy, may be missing context.
4. Files a log-source-fix ticket with the operator (rather than a rule-tuning proposal).

**Post-conditions:** Root cause clarified; ticket filed against the source, not the rule.

**ION surfaces:** `/log-source-health`, `/tuning-proposals`.

# 14. Adversary emulation use case

## UC-EM-01 — Run an emulation plan

**Actor:** Detection Engineer.
**Pre-conditions:** Emulation plan selected; permission to run in customer environment.

**Main flow:**

1. DE opens `/emulation`.
2. Picks a plan (e.g. "APT29 Cozy Bear, T1059.001 PowerShell").
3. Runs each step; records observed detection per step (auto-correlated to alert if fired).
4. For un-detected steps, files a tuning proposal or new-rule proposal.

**Post-conditions:** Detection coverage measured; gaps tracked for closure.

**ION surfaces:** `/emulation`, `/tuning-proposals`.

# 15. Canary use case

## UC-CA-01 — Tripped canary token

**Actor:** L1/L2 Analyst (consumer); Detection Engineer (planner).
**Pre-conditions:** Canary tokens deployed; tripped event captured.

**Main flow:**

1. Tripped canary auto-creates a P1 case with pre-populated context (token type, source IP, time, deployment location).
2. L1 escalates immediately to L2; case priority is `critical`.
3. L2 runs the suggested SOC playbook (per `PlaybookAction` enumerated for canary-trip).
4. Case follows standard investigation flow (→ UC-L2-01) with elevated priority.

**Post-conditions:** Canary-trip handled with high-fidelity response.

**ION surfaces:** `/canaries`, `/cases/{id}`, suggested playbook.

# 16. API / Webhook use case

## UC-API-01 — Forward case-create to customer ITSM

**Actor:** Admin / Customer Integrations Team.
**Pre-conditions:** Webhook URL configured; HMAC secret set.

**Main flow:**

1. Admin configures the webhook in `/integrations` to fire on `case_created`.
2. A case is created; ION emits an HMAC-signed POST to the configured URL.
3. Customer's ITSM receives the payload; opens a ticket in the customer's standard workflow.
4. Delivery log records the call (success/failure/latency).

**Post-conditions:** Customer ITSM has the ticket; delivery is auditable.

**ION surfaces:** `/integrations`, `/admin/webhook-log`.

# 17. Use-case coverage matrix

| Persona | Use cases | Required permissions |
|---|---|---|
| L1 Analyst | UC-L1-01, 02, 03 | `alert:read`, `case:create`, `shift:write` |
| L2 Analyst | UC-L2-01, 02 | + `case:update`, `case:pin`, `playbook:execute` |
| L3 Analyst | UC-L3-01, 02, 03 | + `forensic:write`, `hunt:write`, `attack_story:write` |
| Detection Engineer | UC-DE-01, 02, 03 | + `rule:write`, `prompt:write`, `tuning:write` |
| SOC Manager | UC-SM-01, 02, 03 | + `analyst_efficiency:read`, `executive_report:write` |
| Admin | UC-AD-01, 02, 03, 04 | + `admin:*`, `audit:read` |
| Threat Intel Analyst | UC-TI-01, 02 | + `ti:read`, `briefing:write` |
| Operator / SRE | UC-OP-01, 02, 03 | + `admin:health`, `admin:backup` |
| Any analyst (AI) | UC-AI-01, 02 | + `ai_chat:use` |
| Detection Engineer (network) | UC-NET-01 | + `log_source:read` |
| Detection Engineer (emulation) | UC-EM-01 | + `emulation:execute` |
| Detection Engineer (canary) | UC-CA-01 (planner side) | + `canary:write` |
| L1/L2 Analyst (canary) | UC-CA-01 (consumer side) | + `alert:read`, `case:update` |
| Admin (webhook) | UC-API-01 | + `admin:integrations`, `webhook:write` |
| Learner | UC-LR-01 | `curriculum:read`, `curriculum:write` |
| SOC Manager (trainer) | UC-LR-02 | + `curriculum:assign` |
| Compliance / DPO | UC-CO-01, 02 | + `sar:read`, `erasure:write` |

# 18. Change history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-05-12 | ION maintainer | Initial use cases authored against v0.29.1; 22 UCs |
| 1.1 | 2026-05-12 | ION maintainer | +12 use cases covering Threat Intel Analyst, Operator/SRE, AI Chat, Network/CMDB, Emulation, Canaries, API/Webhooks. New total: 34 |
