<!-- ion-doc:type=USER REQUIREMENTS -->
<!-- ion-doc:title=ION User Requirements Document -->
<!-- ion-doc:subtitle=Numbered user requirements per persona, with source, priority, and acceptance criterion -->
<!-- ion-doc:version=0.29.1 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Buyers, integrators, architects, customer DA, test engineers -->
<!-- ion-doc:date=2026-05-12 -->

# 1. Introduction

## 1.1 Purpose

This User Requirements Document (URD) enumerates the **demands placed on ION by its users**. Each requirement is numbered and stable; downstream artefacts (the HLD, LLD, test plan, and Use Cases) trace back to these IDs via the Requirements Traceability Matrix in `docs/TRACEABILITY.md`.

## 1.2 Scope

The URD covers operational use of ION across all defined personas (`docs/USE_CASES.md` §1.2): L1/L2/L3 analyst, detection engineer, SOC manager, admin, learner, compliance/DPO. It also captures **non-functional user requirements** (performance perception, accessibility, audit, language).

It does not specify *how* ION meets each requirement — that's the design layer. It does not specify *test pass/fail criteria at the code level* — that's the verification layer.

## 1.3 Requirement notation

| Field | Meaning |
|---|---|
| **ID** | `UR-<persona>-<seq>` (e.g. `UR-L1-001`); persistent and stable |
| **Statement** | What the user needs, in plain English, in present-tense indicative |
| **Persona** | Primary persona (others may share) |
| **Source** | Where the requirement originated (analyst feedback, regulatory mandate, market parity, supplier-led) |
| **Priority** | M = Must / S = Should / C = Could (MoSCoW) |
| **Acceptance** | One sentence describing what makes the requirement satisfied |
| **Status** | ✅ Met / ◐ Partial / ⏳ Planned / ✗ Out-of-scope |

## 1.4 Relationship to other documents

| This URD provides | Consumed by |
|---|---|
| Numbered user requirements | `docs/TRACEABILITY.md` (RTM); links each UR to design + test |
| Persona scope | `docs/USE_CASES.md` (one or more UCs per UR) |
| Acceptance criteria | `_mod_iteap.md` (test cases verify these) |
| Priority + source | Customer + maintainer roadmap conversations |

# 2. Triage + alert management (UR-L1 series)

## UR-L1-001 — Prioritised alert queue
| | |
|---|---|
| **Statement** | The L1 analyst sees a single ordered queue of alerts pending triage, sorted by severity × age, so they can attack the queue in priority order. |
| **Persona** | L1 Analyst |
| **Source** | SOC operations parity; analyst feedback |
| **Priority** | M |
| **Acceptance** | The `/alerts` queue page displays alerts in `severity DESC, age ASC` order by default. |
| **Status** | ✅ Met |

## UR-L1-002 — Per-alert context
| | |
|---|---|
| **Statement** | For each alert, the L1 analyst sees enough context (rule name, MITRE technique, source, timestamp, affected entity) without opening a separate page. |
| **Persona** | L1 Analyst |
| **Source** | Reduce-tab-fatigue analyst feedback |
| **Priority** | M |
| **Acceptance** | The alert row in `/alerts` shows: severity, age, rule, technique, hostname/user, timestamp, status. |
| **Status** | ✅ Met |

## UR-L1-003 — AI investigation suggestion
| | |
|---|---|
| **Statement** | For each alert, the L1 analyst sees an AI-provided verdict suggestion with a confidence band, so they can triage common cases quickly. |
| **Persona** | L1 Analyst |
| **Source** | AI parity with leading SOC platforms |
| **Priority** | M |
| **Acceptance** | When Bob has a matching template, the alert row shows a verdict suggestion + confidence band (low/medium/high). When no template matches, the suggestion is suppressed (Bob abstains). |
| **Status** | ✅ Met |

## UR-L1-004 — Calibrated trust signal on AI
| | |
|---|---|
| **Statement** | The L1 analyst is shown a visible signal when the AI's confidence is low, so they know to investigate manually rather than rely on the suggestion. |
| **Persona** | L1 Analyst |
| **Source** | AI safety: avoid over-trust |
| **Priority** | M |
| **Acceptance** | Low-confidence verdicts display a "circuit-breaker" badge that suppresses the verdict text. |
| **Status** | ✅ Met |

## UR-L1-005 — Bulk close low-risk alerts
| | |
|---|---|
| **Statement** | The L1 analyst can select multiple alerts and close them as a batch when they share a closure reason. |
| **Persona** | L1 Analyst |
| **Source** | Throughput |
| **Priority** | S |
| **Acceptance** | The `/alerts` page has a bulk-ops toolbar; selecting ≥ 2 alerts and clicking "Close" applies the same `CaseClosureReason` to all. |
| **Status** | ✅ Met |

## UR-L1-006 — Create a case from one or more alerts
| | |
|---|---|
| **Statement** | The L1 analyst can promote one or more alerts to a case with a single action. |
| **Persona** | L1 Analyst |
| **Source** | Operations parity |
| **Priority** | M |
| **Acceptance** | A "Create Case" action exists on a single-selected alert and as a bulk-ops action on multi-selected alerts. |
| **Status** | ✅ Met |

## UR-L1-007 — Shift handover
| | |
|---|---|
| **Statement** | The L1 analyst hands over to the next shift with structured, pre-populated context. |
| **Persona** | L1 Analyst |
| **Source** | Reduce shift-handover variance |
| **Priority** | M |
| **Acceptance** | `/shift-handover` pre-populates with cases changed, alert volume, P1/P2 incidents, outstanding tunings, and persists for the next shift's `/briefing`. |
| **Status** | ✅ Met |

# 3. Investigation (UR-L2 series)

## UR-L2-001 — Case landing page with full context
| | |
|---|---|
| **Statement** | The L2 analyst opens a case and sees: linked alerts, observables, similar past cases, entity timelines, the Workbench, and an attack story if applicable, without further navigation. |
| **Persona** | L2 Analyst |
| **Source** | Reduce decision time per case |
| **Priority** | M |
| **Acceptance** | `/cases/{id}` renders all six surfaces above on initial load. |
| **Status** | ✅ Met |

## UR-L2-002 — Pinned evidence on a case
| | |
|---|---|
| **Statement** | The L2 analyst pins relevant artefacts (alerts, observables, queries, notes, files) to a case for clarity at hand-off and audit-time. |
| **Persona** | L2 Analyst |
| **Source** | Audit-readiness; analyst feedback |
| **Priority** | M |
| **Acceptance** | Workbench pin operation works for each pin type; every pin creates a `CaseEvidencePin` row + a `CaseEvidenceLedger` row. |
| **Status** | ✅ Met |

## UR-L2-003 — Tamper-evident evidence ledger
| | |
|---|---|
| **Statement** | The L2 analyst's pinned evidence forms a tamper-evident audit chain that can be verified by audit / compliance. |
| **Persona** | L2 Analyst (producer); Compliance (consumer) |
| **Source** | Regulatory / audit requirement |
| **Priority** | M |
| **Acceptance** | `CaseEvidenceLedger` rows form a sha256 chain; verification walks the chain and surfaces tampering with row-level granularity. |
| **Status** | ✅ Met |

## UR-L2-004 — Similar past cases
| | |
|---|---|
| **Statement** | The L2 analyst sees a list of similar past cases (top-5 by similarity), with their closure reasons, as context for the current decision. |
| **Persona** | L2 Analyst |
| **Source** | Institutional-knowledge capture |
| **Priority** | S |
| **Acceptance** | A sidebar on the case detail page shows top-5 similar cases (pgvector + HNSW + Ollama embedding). |
| **Status** | ✅ Met |

## UR-L2-005 — Cross-source entity timeline
| | |
|---|---|
| **Statement** | The L2 analyst views a unified timeline for a host / user / IP across all ION data sources to spot kill-chain progression. |
| **Persona** | L2 Analyst |
| **Source** | Hunt-and-pivot pattern |
| **Priority** | M |
| **Acceptance** | `/entity-timeline/{type}/{id}` returns a unified, sorted timeline; case-detail drawer surfaces it. |
| **Status** | ✅ Met |

## UR-L2-006 — PCAP context, automatically
| | |
|---|---|
| **Statement** | The L2 analyst sees PCAP-derived findings on a case automatically, without pivoting out to Arkime, when network capture exists. |
| **Persona** | L2 Analyst |
| **Source** | Reduce per-case decision time |
| **Priority** | M |
| **Acceptance** | Cases auto-trigger PCAP analysis on create; findings (12 heuristic detectors) post to the case Workbench as a pinned comment. |
| **Status** | ✅ Met (v0.29.1 IP-fallback closes the last gap) |

## UR-L2-007 — Case kanban
| | |
|---|---|
| **Statement** | The SOC team views cases on a kanban board to manage the team's queue. |
| **Persona** | L2 Analyst (consumer); SOC Manager (overview) |
| **Source** | Parity with ticketing tools |
| **Priority** | M |
| **Acceptance** | `/cases` offers a kanban view by status; columns reflect case statuses; drag-to-update works. |
| **Status** | ✅ Met |

## UR-L2-008 — Investigation memory
| | |
|---|---|
| **Statement** | The L2 analyst's in-progress working notes per case (queries tried, hypotheses, dead ends) are persisted alongside the case so a hand-off doesn't lose the investigation trail. |
| **Persona** | L2 Analyst (producer); next-shift L2/L3 (consumer) |
| **Source** | Reduce hand-off rework |
| **Priority** | S |
| **Acceptance** | Investigation memory persists per case; survives sessions; rendered on the case detail page; editable. |
| **Status** | ✅ Met |

## UR-L2-009 — AI chat scoped to a case
| | |
|---|---|
| **Statement** | The L2 analyst asks Bob ad-hoc questions in the context of the current case (e.g. "summarise what we know about host XYZ"), without leaving the case detail page. |
| **Persona** | L2 Analyst |
| **Source** | Cognitive ergonomics |
| **Priority** | S |
| **Acceptance** | The case detail page has an AI Chat panel scoped to the case; queries reach Ollama; responses are advisory and never close the case. |
| **Status** | ✅ Met |

# 4. Forensics (UR-L3 series)

## UR-L3-001 — Forensic case as a first-class entity
| | |
|---|---|
| **Statement** | The L3 analyst has a forensic-case workflow that is structurally parallel to AlertCase but specialised for evidence-heavy DFIR. |
| **Persona** | L3 Analyst / Forensicator |
| **Source** | DFIR maturity; chain-of-custody requirement |
| **Priority** | M |
| **Acceptance** | `ForensicCase` is a first-class entity; `/forensics/{id}` mirrors AlertCase capabilities; Workbench parity (v0.20.1). |
| **Status** | ✅ Met |

## UR-L3-002 — Chain of custody for every evidence item
| | |
|---|---|
| **Statement** | Each evidence item attached to a ForensicCase has a chain of custody: who uploaded it, when, what happened to it. |
| **Persona** | L3 Analyst (producer); Compliance / Legal (consumer) |
| **Source** | Forensic admissibility |
| **Priority** | M |
| **Acceptance** | `EvidenceItem` + `CustodyLogEntry` rows record every state change; queryable by evidence id. |
| **Status** | ✅ Met |

## UR-L3-003 — Threat-hypothesis hunt
| | |
|---|---|
| **Statement** | The L3 analyst tests a threat hypothesis (e.g. "actor X is using technique T against our sector") with ION's data without leaving the product. |
| **Persona** | L3 Analyst |
| **Source** | Threat-hunt parity |
| **Priority** | S |
| **Acceptance** | Threat intel pages link technique → coverage; analyst can build a saved search and run it from the hunt context. |
| **Status** | ✅ Met (post-v0.27.0 consolidation; Threat Hunting page removed in favour of unified threat-intel + saved searches) |

## UR-L3-004 — Attack story
| | |
|---|---|
| **Statement** | The L3 analyst correlates multiple alerts into a kill-chain narrative attached to a case. |
| **Persona** | L3 Analyst |
| **Source** | Communication with leadership; reporting |
| **Priority** | S |
| **Acceptance** | `case_grouper_service` auto-orders alerts onto a kill-chain; analyst annotates each step; narrative attaches to the case. |
| **Status** | ✅ Met |

## UR-L3-005 — Knowledge graph navigation
| | |
|---|---|
| **Statement** | The L3 analyst navigates a knowledge graph of relationships between actors, techniques, IOCs, and cases to pivot during a hunt. |
| **Persona** | L3 Analyst / Threat Hunter |
| **Source** | Hunt-pivot workflow |
| **Priority** | S |
| **Acceptance** | Knowledge graph surface in `/threat-intel` renders entities + relations and supports click-to-pivot. |
| **Status** | ✅ Met |

# 5. Detection engineering (UR-DE series)

## UR-DE-001 — Per-rule performance metrics
| | |
|---|---|
| **Statement** | The detection engineer sees per-rule false-positive rate, dwell time, and closure-reason distribution. |
| **Persona** | Detection Engineer |
| **Source** | Tuning by data |
| **Priority** | M |
| **Acceptance** | `/engineering/analytics` ranks rules by FP rate × volume; drill-in shows example alerts and Bob-vs-analyst divergences. |
| **Status** | ✅ Met |

## UR-DE-002 — Tuning proposal workflow
| | |
|---|---|
| **Statement** | The detection engineer files a tuning proposal, gets review, and pushes the change to TIDE. |
| **Persona** | Detection Engineer |
| **Source** | Auditable rule changes |
| **Priority** | M |
| **Acceptance** | `/tuning-proposals` supports the full lifecycle (file → review → sync to TIDE → mark closed). |
| **Status** | ✅ Met |

## UR-DE-003 — MITRE ATT&CK coverage view
| | |
|---|---|
| **Statement** | The detection engineer sees a live MITRE ATT&CK heatmap showing the customer's detection coverage. |
| **Persona** | Detection Engineer; Threat Hunter; SOC Manager |
| **Source** | Coverage-conversation parity |
| **Priority** | M |
| **Acceptance** | `/cyab/attack-heatmap` renders the bundled ATT&CK v15.1 with overlay of TIDE rules; drill-in surfaces gaps. |
| **Status** | ✅ Met |

## UR-DE-004 — Multi-framework compliance map
| | |
|---|---|
| **Statement** | The detection engineer maps detection rules to one or more compliance frameworks (NIST CSF, ISO 27001, ACSC E8, DefStan). |
| **Persona** | Detection Engineer; Compliance |
| **Source** | Audit-pack assembly |
| **Priority** | S |
| **Acceptance** | `/compliance` shows framework × rule matrix and exports a coverage report. |
| **Status** | ✅ Met |

## UR-DE-005 — Manage Bob's prompt templates
| | |
|---|---|
| **Statement** | The detection engineer creates, edits, and tunes Bob's prompt templates (matching, content, confidence threshold). |
| **Persona** | Detection Engineer with `security:settings` |
| **Source** | Bob calibration |
| **Priority** | M |
| **Acceptance** | `/alert-prompts` supports CRUD + matching-rule editing + `confidence_threshold_override` per template. |
| **Status** | ✅ Met |

## UR-DE-006 — Offline Bob eval against historical alerts
| | |
|---|---|
| **Statement** | The detection engineer scores a Bob template's precision / recall / F1 against historical alerts before deploying it live. |
| **Persona** | Detection Engineer |
| **Source** | AI safety, calibration |
| **Priority** | M |
| **Acceptance** | `/bob-eval` runs an offline replay against historical alerts; per-template P/R/F1 reported; hard-blocks if a live investigation loop is active. |
| **Status** | ✅ Met |

## UR-DE-007 — D3FEND defensive technique map
| | |
|---|---|
| **Statement** | The detection engineer maps detection rules to MITRE D3FEND defensive techniques to articulate defensive coverage in defender-language. |
| **Persona** | Detection Engineer |
| **Source** | Defender-language parity |
| **Priority** | S |
| **Acceptance** | `/d3fend` (or equivalent) shows D3FEND techniques mapped to TIDE rules; drill-in surfaces gaps. |
| **Status** | ✅ Met |

## UR-DE-008 — ATT&CK Navigator export
| | |
|---|---|
| **Statement** | The detection engineer exports the customer's current MITRE ATT&CK coverage as a Navigator layer JSON for sharing with external stakeholders. |
| **Persona** | Detection Engineer |
| **Source** | Cross-org standardised sharing |
| **Priority** | S |
| **Acceptance** | A single-click export from the ATT&CK heatmap produces a valid Navigator layer JSON. |
| **Status** | ✅ Met |

# 6. SOC management (UR-SM series)

## UR-SM-001 — Daily briefing
| | |
|---|---|
| **Statement** | The SOC manager runs a daily standup with pre-populated last-24h posture data. |
| **Persona** | SOC Manager |
| **Source** | Daily-cadence operations |
| **Priority** | M |
| **Acceptance** | `/briefing` aggregates P1/P2 incidents, alert volume, noisy rules, SLA breaches, tuning queue, action items. |
| **Status** | ✅ Met |

## UR-SM-002 — Analyst efficiency view
| | |
|---|---|
| **Statement** | The SOC manager sees fair, data-driven analyst efficiency without invasive surveillance. |
| **Persona** | SOC Manager |
| **Source** | Performance reviews |
| **Priority** | S |
| **Acceptance** | `/analyst-efficiency` shows per-analyst: cases closed, dwell time, closure-reason distribution, Bob-agreement rate. |
| **Status** | ✅ Met |

## UR-SM-003 — Executive briefing
| | |
|---|---|
| **Statement** | The SOC manager generates an executive briefing covering top threats, rules tuned, incidents resolved, coverage delta, recommended actions. |
| **Persona** | SOC Manager (producer); Leadership (consumer) |
| **Source** | Communication-with-leadership |
| **Priority** | S |
| **Acceptance** | `/threat-landscape` → Generate Briefing produces an editable, exportable exec brief (v0.27.0). |
| **Status** | ✅ Met |

## UR-SM-004 — SLA tracking
| | |
|---|---|
| **Statement** | The SOC manager sees per-case SLA status and is alerted on imminent breach. |
| **Persona** | SOC Manager |
| **Source** | Operations rigour |
| **Priority** | M |
| **Acceptance** | SLA policies are configurable; breach log records each breach with attribution. |
| **Status** | ✅ Met |

## UR-SM-005 — SOC maturity scorecard
| | |
|---|---|
| **Statement** | The SOC manager sees a 5-dimension SOC-CMM-style maturity scorecard. |
| **Persona** | SOC Manager |
| **Source** | Maturity-conversation parity |
| **Priority** | C |
| **Acceptance** | `/maturity` surfaces a A-F grade across detection / operations / team / knowledge / integrations. |
| **Status** | ✅ Met |

## UR-SM-006 — Per-user dashboard layout
| | |
|---|---|
| **Statement** | Each user can arrange their own dashboard surface (widget choice + order + size) to suit their role and shift cadence. |
| **Persona** | Any analyst; SOC Manager |
| **Source** | Productivity, role-fit |
| **Priority** | C |
| **Acceptance** | Dashboard layout is per-user; persists across sessions; drag-to-rearrange + add/remove widgets supported. |
| **Status** | ✅ Met |

# 7. Admin (UR-AD series)

## UR-AD-001 — Configure each integration
| | |
|---|---|
| **Statement** | The admin configures (URL, credentials) each enabled integration without restarting ION. |
| **Persona** | Admin |
| **Source** | Operations |
| **Priority** | M |
| **Acceptance** | `/integrations` supports CRUD per integration with a smoke "Test" action. |
| **Status** | ✅ Met |

## UR-AD-002 — Users + roles + permissions
| | |
|---|---|
| **Statement** | The admin manages users (invite, suspend), roles (assign), and permissions (grant/revoke). |
| **Persona** | Admin |
| **Source** | RBAC governance |
| **Priority** | M |
| **Acceptance** | `/users`, `/roles`, `/permissions` surfaces support the full lifecycle. |
| **Status** | ✅ Met |

## UR-AD-003 — OIDC SSO
| | |
|---|---|
| **Statement** | The admin enables OIDC SSO (Keycloak) for the analyst team. |
| **Persona** | Admin |
| **Source** | Customer identity-management policy |
| **Priority** | M |
| **Acceptance** | OIDC RS256 flow works end-to-end; HS256 explicitly refused; JWKS auto-refreshes. |
| **Status** | ✅ Met |

## UR-AD-004 — Settings tuning
| | |
|---|---|
| **Statement** | The admin tunes runtime settings (pool sizes, slow-query threshold, Bob confidence threshold) without redeploying. |
| **Persona** | Admin |
| **Source** | Operations |
| **Priority** | S |
| **Acceptance** | `/settings` (admin) edits the `Settings` table; changes take effect within the request handler. |
| **Status** | ✅ Met |

## UR-AD-005 — Audit log query + export
| | |
|---|---|
| **Statement** | The admin / compliance reviews and exports the audit log. |
| **Persona** | Admin; Compliance |
| **Source** | Compliance / audit |
| **Priority** | M |
| **Acceptance** | `/audit-log` supports filter by user / action / target / date and CSV export. |
| **Status** | ✅ Met |

## UR-AD-006 — Workbench tamper-evidence verification
| | |
|---|---|
| **Statement** | The admin / compliance verifies the integrity of the Workbench ledger. |
| **Persona** | Admin; Compliance |
| **Source** | Compliance / audit |
| **Priority** | M |
| **Acceptance** | `/workbench-audit` (or CLI) recomputes each sha256 hash and flags any broken link. |
| **Status** | ✅ Met |

## UR-AD-007 — Health endpoint
| | |
|---|---|
| **Statement** | The customer's monitoring system polls a stable health endpoint to alarm on ION outage. |
| **Persona** | Admin / Operator |
| **Source** | ITSM / monitoring integration |
| **Priority** | M |
| **Acceptance** | `GET /health` returns 200 with a stable JSON shape documented in `docs/RUNBOOK.md`; non-2xx on degraded states. |
| **Status** | ✅ Met |

# 8. Curriculum / training (UR-LR series)

## UR-LR-001 — Self-paced curriculum
| | |
|---|---|
| **Statement** | The learner self-paces through L1/L2/L3 curriculum (modules → lessons → quizzes → labs). |
| **Persona** | Learner |
| **Source** | New-analyst onboarding |
| **Priority** | M |
| **Acceptance** | `/training` shows the assigned learning path; lessons render; quizzes work; labs run (lab-fixture system has 4 known bugs queued for v0.30.0). |
| **Status** | ◐ Partial (labs known-issues queued) |

## UR-LR-002 — Trainer assignment
| | |
|---|---|
| **Statement** | The SOC manager assigns a learning path to a team member and tracks their progress. |
| **Persona** | SOC Manager (trainer) |
| **Source** | Coaching workflow |
| **Priority** | S |
| **Acceptance** | `/courses` supports assignment + progress dashboard. |
| **Status** | ✅ Met |

# 9. Compliance / DPO (UR-CO series)

## UR-CO-001 — Subject Access Request response
| | |
|---|---|
| **Statement** | The DPO retrieves all data referencing a named subject in response to a UK GDPR Article 15 request. |
| **Persona** | DPO; Admin |
| **Source** | UK GDPR / DPA 2018 |
| **Priority** | M |
| **Acceptance** | `/admin/sar` (or the DPIA Appendix A SQL) returns every row referencing the subject. |
| **Status** | ✅ Met |

## UR-CO-002 — Erasure
| | |
|---|---|
| **Statement** | The DPO processes a UK GDPR Article 17 erasure request: anonymises personal identifiers while retaining operational artefacts. |
| **Persona** | DPO; Admin |
| **Source** | UK GDPR / DPA 2018 |
| **Priority** | M |
| **Acceptance** | `/admin/erasure` (or the DPIA Appendix B SQL) anonymises affected rows; audit_log captures the action. |
| **Status** | ✅ Met |

## UR-CO-003 — Tamper-evident audit chain
| | |
|---|---|
| **Statement** | The compliance team verifies that the case-evidence audit trail has not been tampered with. |
| **Persona** | Compliance |
| **Source** | Audit / regulatory |
| **Priority** | M |
| **Acceptance** | Workbench ledger verification report runs read-only; identifies broken links to row granularity. |
| **Status** | ✅ Met |

## UR-CO-004 — Accessibility (WCAG 2.2 AA)
| | |
|---|---|
| **Statement** | Public-sector users have ION analyst surfaces conformant to WCAG 2.2 Level AA. |
| **Persona** | Any user; Compliance |
| **Source** | UK Public Sector Bodies (Websites and Mobile Applications) Accessibility Regulations 2018 |
| **Priority** | M |
| **Acceptance** | Tier-1 + Tier-2 analyst surfaces conformant; Tier-3 + Tier-4 remediation plans tracked for v0.30.0 / v0.31.0. |
| **Status** | ◐ Partial (per `_mod_wcag_audit.md`) |

# 10. Non-functional user requirements (UR-NFR series)

## UR-NFR-001 — Air-gap deployment
| | |
|---|---|
| **Statement** | The deployed instance operates with no live external internet connectivity. |
| **Persona** | Operator |
| **Source** | Defence + critical-infra customers |
| **Priority** | M |
| **Acceptance** | All bundled data (ATT&CK, KEV) ships in the Docker image; Bob runs against local Ollama; no runtime external calls. |
| **Status** | ✅ Met |

## UR-NFR-002 — Response time perception
| | |
|---|---|
| **Statement** | Analyst-facing pages render within 1.5 seconds at p95. |
| **Persona** | Any analyst |
| **Source** | Productivity |
| **Priority** | S |
| **Acceptance** | Empirical p95 < 1500ms on detail pages; < 700ms on list pages, at the target SOC load profile. |
| **Status** | ◐ Partial (empirical; formal load-test pending) |

## UR-NFR-003 — Continuous audit
| | |
|---|---|
| **Statement** | Every state-mutating request creates an audit_log row. |
| **Persona** | Compliance |
| **Source** | Audit / regulatory |
| **Priority** | M |
| **Acceptance** | Every 2xx mutating response has a corresponding audit_log row with user, ip, action, target, outcome. |
| **Status** | ✅ Met |

## UR-NFR-004 — Structured logs for SIEM ingestion
| | |
|---|---|
| **Statement** | Audit logs are emitted in a format the customer SIEM can ingest without parsing custom regex. |
| **Persona** | SIEM team |
| **Source** | Operations rigour |
| **Priority** | M |
| **Acceptance** | Logs are ECS-compliant JSON-lines on stdout. |
| **Status** | ✅ Met |

## UR-NFR-005 — Backup-restorable
| | |
|---|---|
| **Statement** | The deployed instance can be restored from a backup within the customer's RTO/RPO targets. |
| **Persona** | Operator |
| **Source** | Business continuity |
| **Priority** | M |
| **Acceptance** | RTO ≤ 1 hour; RPO ≤ 24 hours; backup script + restore procedure documented (`_mod_iteap.md` §5). |
| **Status** | ✅ Met |

## UR-NFR-006 — Graceful degradation on integration outage
| | |
|---|---|
| **Statement** | If an external integration (ES, Kibana, TIDE, OpenCTI, Arkime, Ollama, Keycloak) is unavailable, the analyst can still do core work. |
| **Persona** | Any analyst |
| **Source** | Operations rigour |
| **Priority** | M |
| **Acceptance** | Each adapter raises `IntegrationUnavailable` on exhaustion; surfaces display a banner; core pages remain functional. |
| **Status** | ✅ Met |

## UR-NFR-007 — Supply-chain transparency
| | |
|---|---|
| **Statement** | The customer sees the full dependency list (SBOM) for an ION release. |
| **Persona** | Customer security |
| **Source** | SBOM mandate |
| **Priority** | M |
| **Acceptance** | SPDX-JSON SBOM ships in the image at `/app/sbom.spdx.json`. |
| **Status** | ✅ Met |

## UR-NFR-008 — Per-release security trend
| | |
|---|---|
| **Statement** | The customer sees the severity trend across recent releases. |
| **Persona** | Customer security |
| **Source** | Maintainer-supplied evidence |
| **Priority** | S |
| **Acceptance** | `SECURITY_ASSESSMENT.md` carries the running severity-trend table for every release. |
| **Status** | ✅ Met |

## UR-NFR-009 — Localisation-ready
| | |
|---|---|
| **Statement** | All user-facing strings can be localised without code changes. |
| **Persona** | Any user |
| **Source** | International deployment readiness |
| **Priority** | C |
| **Acceptance** | Templates use a translation function or equivalent indirection. |
| **Status** | ⏳ Planned (not currently implemented; tracked future work) |

## UR-NFR-010 — Image immutability
| | |
|---|---|
| **Statement** | A tagged ION release image is immutable — re-pulling the same tag yields the same content. |
| **Persona** | Operator; Customer security |
| **Source** | Trust + reproducibility |
| **Priority** | M |
| **Acceptance** | Docker Hub tags are digest-pinned; image not republished under the same tag. |
| **Status** | ✅ Met |

## UR-NFR-011 — Strict CSP
| | |
|---|---|
| **Statement** | The application enforces a strict Content-Security-Policy to defang XSS attempts in the wild. |
| **Persona** | Customer security |
| **Source** | XSS hardening; OWASP A03 |
| **Priority** | M |
| **Acceptance** | CSP middleware emits a strict policy on every response; inline scripts are nonce-based; `unsafe-eval` not present. |
| **Status** | ✅ Met |

## UR-NFR-012 — Time-zone correctness
| | |
|---|---|
| **Statement** | Timestamps stored in UTC; analyst sees their preferred timezone in the UI. |
| **Persona** | Any analyst |
| **Source** | Multi-shift / multi-region SOC |
| **Priority** | S |
| **Acceptance** | All DB timestamps are UTC; per-user TZ preference renders display-side; logs always UTC. |
| **Status** | ✅ Met |

## UR-NFR-013 — In-app notifications
| | |
|---|---|
| **Statement** | The user sees in-app notifications (case assignment, SLA breach approaching, playbook approval requested). |
| **Persona** | Any analyst; SOC Manager |
| **Source** | Workflow attention-routing |
| **Priority** | S |
| **Acceptance** | A `/notifications` surface displays unread items; UI badge shows count; mark-read clears. |
| **Status** | ✅ Met |

# 11. Threat Intelligence Analyst (UR-TI series)

## UR-TI-001 — Threat landscape briefing
| | |
|---|---|
| **Statement** | The TI analyst views a curated threat landscape briefing for the current period (top actors, top techniques, recent IOCs) without manually assembling it. |
| **Persona** | Threat Intel Analyst |
| **Source** | Daily TI cadence |
| **Priority** | M |
| **Acceptance** | `/threat-landscape` renders the briefing; "Generate Briefing" produces editable exportable text (v0.27.0). |
| **Status** | ✅ Met |

## UR-TI-002 — Actor deep-dive
| | |
|---|---|
| **Statement** | The TI analyst opens an actor profile and sees: aliases, motivations, sector targets, techniques, IOC sparkline, recent reports. |
| **Persona** | Threat Intel Analyst |
| **Source** | Actor-driven workflow |
| **Priority** | M |
| **Acceptance** | Actor profile page includes aliases, motivations, sectors, techniques + ATT&CK click-through, IOC sparkline (v0.27.0). |
| **Status** | ✅ Met |

## UR-TI-003 — Live IOC feed
| | |
|---|---|
| **Statement** | The TI analyst sees the most recently observed IOCs across all watched feeds in a single live view. |
| **Persona** | Threat Intel Analyst |
| **Source** | Operational TI parity |
| **Priority** | S |
| **Acceptance** | Live IOC feed surface on `/threat-intel` shows latest IOCs with type, confidence, last-seen. |
| **Status** | ✅ Met |

## UR-TI-004 — Threat watch gap alerts
| | |
|---|---|
| **Statement** | The TI analyst is alerted when a watched actor gains a technique not covered by the customer's current TIDE rules. |
| **Persona** | Threat Intel Analyst; Detection Engineer |
| **Source** | Coverage drift detection |
| **Priority** | M |
| **Acceptance** | `threat_watch_gap_service` raises alerts; analyst sees them in `/threat-intel`; gaps cross-reference to `/cyab/attack-heatmap`. |
| **Status** | ✅ Met |

# 12. Operator / SRE (UR-OP series)

## UR-OP-001 — Repeatable deployment
| | |
|---|---|
| **Statement** | The operator deploys a new ION instance from documented Docker Compose / image artefacts, with no out-of-band steps. |
| **Persona** | Operator / SRE |
| **Source** | Operations rigour |
| **Priority** | M |
| **Acceptance** | `docs/DEPLOYMENT.md` end-to-end procedure works against a clean environment; smoke check passes. |
| **Status** | ✅ Met |

## UR-OP-002 — Backup + restore drill
| | |
|---|---|
| **Statement** | The operator backs up and restores ION's state per documented procedure within the agreed RTO. |
| **Persona** | Operator / SRE |
| **Source** | Business continuity |
| **Priority** | M |
| **Acceptance** | DR drill from `_mod_iteap.md` §5 passes: Postgres backup restored, image redeployed, smoke check green, ≤ 1 hour wall-clock. |
| **Status** | ✅ Met |

## UR-OP-003 — Slow-query observability
| | |
|---|---|
| **Statement** | The operator is alerted when Postgres queries cross a slow-query threshold so capacity issues are caught early. |
| **Persona** | Operator / SRE |
| **Source** | Operational early-warning |
| **Priority** | S |
| **Acceptance** | Settings has `slow_query_threshold_ms`; queries above it emit ECS-shaped log row; suggested SIEM detection in `_mod_log_shipping_spec.md`. |
| **Status** | ✅ Met |

## UR-OP-004 — Connection pool exhaustion alarm
| | |
|---|---|
| **Statement** | The operator is alerted before Postgres connection pool exhaustion, not at the moment of failure. |
| **Persona** | Operator / SRE |
| **Source** | Operational early-warning |
| **Priority** | S |
| **Acceptance** | Pool size, overflow, and current-in-use are exposed in `/health` or `/admin/health-detail`; suggested customer-side alarm at 80% utilisation. |
| **Status** | ✅ Met |

# 13. AI Chat & Natural-language Queries (UR-AI series)

## UR-AI-001 — Conversational AI chat with ION's data
| | |
|---|---|
| **Statement** | The analyst asks Bob open-ended analytical questions ("what's the trend in failed-logon alerts this week?") and receives an answer grounded in ION's data. |
| **Persona** | Any analyst |
| **Source** | Analyst ergonomics |
| **Priority** | S |
| **Acceptance** | `/ai-chat` (or contextual chat panel) accepts NL questions; routes to Ollama; responses cite ION data sources. |
| **Status** | ✅ Met |

## UR-AI-002 — Natural-language to Elasticsearch query
| | |
|---|---|
| **Statement** | The analyst describes a query in plain English and Bob produces a valid Elasticsearch query preview the analyst can review and execute. |
| **Persona** | Any analyst |
| **Source** | Reduce query-syntax friction |
| **Priority** | S |
| **Acceptance** | NL-to-ES surface accepts NL; emits Elasticsearch query JSON; analyst confirms before execution. |
| **Status** | ✅ Met |

## UR-AI-003 — AI-assisted document generation
| | |
|---|---|
| **Statement** | The analyst generates draft documents (incident report, exec brief, IR runbook section) by prompting Bob; the draft is editable before save. |
| **Persona** | L2/L3 Analyst; SOC Manager |
| **Source** | Reduce report-writing burden |
| **Priority** | C |
| **Acceptance** | AI document generation surface accepts a template + context prompt; produces a draft; analyst edits and saves. |
| **Status** | ✅ Met |

# 14. Network / CMDB (UR-NET series)

## UR-NET-001 — Asset CMDB + topology view
| | |
|---|---|
| **Statement** | The detection engineer / analyst sees the customer's network assets (hosts, services, segments) and their topology to contextualise alerts. |
| **Persona** | Detection Engineer; L2/L3 Analyst |
| **Source** | Investigation context |
| **Priority** | S |
| **Acceptance** | `/network-assets` lists assets; `/topology` (or equivalent) renders the graph. |
| **Status** | ✅ Met |

## UR-NET-002 — Log source health
| | |
|---|---|
| **Statement** | The detection engineer is alerted to silent log sources (ingest stalled / volume drop / missing fields). |
| **Persona** | Detection Engineer; Operator |
| **Source** | Avoid coverage holes from silent failures |
| **Priority** | M |
| **Acceptance** | `/log-source-health` surfaces per-source ingest status, volume trend, and silent-source flags. |
| **Status** | ✅ Met |

# 15. Knowledge management (UR-KM series)

## UR-KM-001 — Analyst notes
| | |
|---|---|
| **Statement** | Analysts capture and retrieve persistent notes (per case, per host, per playbook step) without leaving ION. |
| **Persona** | Any analyst |
| **Source** | Tribal-knowledge capture |
| **Priority** | S |
| **Acceptance** | `/notes` supports CRUD with folders + tags + search; notes attachable to cases / observables. |
| **Status** | ✅ Met |

## UR-KM-002 — Templates + reference docs
| | |
|---|---|
| **Statement** | The SOC team stores reusable templates (notification text, IR runbook, post-incident review) inside ION for consistency. |
| **Persona** | SOC Manager; Analyst |
| **Source** | Consistency in reporting |
| **Priority** | S |
| **Acceptance** | `/templates` + `/documents` support markdown editing, versioning, and template-fill at use-time. |
| **Status** | ✅ Met |

# 16. Adversary emulation (UR-EM series)

## UR-EM-001 — Emulation plan library
| | |
|---|---|
| **Statement** | The detection engineer browses an adversary-emulation plan library (CALDERA-style) to plan a purple-team exercise. |
| **Persona** | Detection Engineer; L3 Analyst |
| **Source** | Purple-team readiness |
| **Priority** | C |
| **Acceptance** | `/emulation` lists plans with steps tied to ATT&CK techniques. |
| **Status** | ✅ Met |

## UR-EM-002 — Emulation execution tracking
| | |
|---|---|
| **Statement** | The detection engineer runs an emulation plan and tracks per-step outcomes (was the technique detected? if not, why?). |
| **Persona** | Detection Engineer |
| **Source** | Purple-team-to-tuning feedback loop |
| **Priority** | C |
| **Acceptance** | Per-plan execution records the run; per-step pass/fail tracked; tuning proposals can be filed from a failed step. |
| **Status** | ✅ Met |

# 17. Canaries (UR-CA series)

## UR-CA-001 — Deploy canary tokens
| | |
|---|---|
| **Statement** | The detection engineer deploys canary tokens (honeydocs, credentials, DNS) to high-value assets for high-confidence breach detection. |
| **Persona** | Detection Engineer |
| **Source** | Early-warning detection |
| **Priority** | C |
| **Acceptance** | `/canaries` supports CRUD; deployment metadata captured; integration with email-token / DNS-token / cred-token types. |
| **Status** | ✅ Met |

## UR-CA-002 — Canary trip → high-priority alert
| | |
|---|---|
| **Statement** | A tripped canary token produces a high-priority alert + case with immediate-attention SLAs. |
| **Persona** | L1 Analyst (consumer); Detection Engineer (producer) |
| **Source** | High-fidelity-trigger workflow |
| **Priority** | C |
| **Acceptance** | Canary trip creates an alert with `severity: critical` and pre-populated case context; SOC playbook auto-suggested. |
| **Status** | ✅ Met |

# 18. API + Webhooks (UR-API series)

## UR-API-001 — Outbound webhook on key events
| | |
|---|---|
| **Statement** | ION emits outbound webhooks on configurable events (case-create, case-close, P1-alert) so the customer's wider ITSM / messaging stack can react. |
| **Persona** | Admin; Customer integrations team |
| **Source** | Cross-tool workflow |
| **Priority** | S |
| **Acceptance** | Webhook configuration in `/integrations`; HMAC-signed payload; retry on transient failure; delivery log. |
| **Status** | ✅ Met |

# 19. Requirement count + priority distribution

| Persona / NFR | Total | M | S | C | Met | Partial | Planned |
|---|---|---|---|---|---|---|---|
| L1 Analyst | 7 | 5 | 2 | 0 | 7 | 0 | 0 |
| L2 Analyst | 9 | 6 | 3 | 0 | 9 | 0 | 0 |
| L3 Analyst | 5 | 2 | 3 | 0 | 5 | 0 | 0 |
| Detection Engineer | 8 | 4 | 4 | 0 | 8 | 0 | 0 |
| SOC Manager | 6 | 2 | 2 | 2 | 6 | 0 | 0 |
| Admin | 7 | 6 | 1 | 0 | 7 | 0 | 0 |
| Threat Intel Analyst | 4 | 3 | 1 | 0 | 4 | 0 | 0 |
| Operator / SRE | 4 | 2 | 2 | 0 | 4 | 0 | 0 |
| Learner / Trainer | 2 | 1 | 1 | 0 | 1 | 1 | 0 |
| Compliance / DPO | 4 | 4 | 0 | 0 | 3 | 1 | 0 |
| AI Chat | 3 | 0 | 2 | 1 | 3 | 0 | 0 |
| Network / CMDB | 2 | 1 | 1 | 0 | 2 | 0 | 0 |
| Knowledge management | 2 | 0 | 2 | 0 | 2 | 0 | 0 |
| Adversary emulation | 2 | 0 | 0 | 2 | 2 | 0 | 0 |
| Canaries | 2 | 0 | 0 | 2 | 2 | 0 | 0 |
| API / Webhooks | 1 | 0 | 1 | 0 | 1 | 0 | 0 |
| NFR | 13 | 9 | 3 | 1 | 11 | 1 | 1 |
| **TOTAL** | **81** | **45** | **28** | **8** | **77** | **3** | **1** |

# 20. Change history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-05-12 | ION maintainer | Initial URD authored against v0.29.1; 51 requirements |
| 1.1 | 2026-05-12 | ION maintainer | Expanded URD: +30 requirements covering Threat Intel Analyst + Operator/SRE personas; AI Chat, Network/CMDB, Knowledge mgmt, Emulation, Canaries, API/Webhooks functional areas; extended L2/L3/DE/SM/AD and NFR series. New total: 81 |
