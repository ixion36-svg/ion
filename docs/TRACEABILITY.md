<!-- ion-doc:type=TRACEABILITY MATRIX -->
<!-- ion-doc:title=ION Requirements Traceability Matrix -->
<!-- ion-doc:subtitle=Full bidirectional trace from User Requirement to System Requirement to Design Element to Test to Use Case to Gap Filled -->
<!-- ion-doc:version=0.29.1 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Architects, customer DA, security reviewers, test engineers, DPO, auditors -->
<!-- ion-doc:date=2026-05-12 -->

# 1. Introduction

## 1.1 Purpose

This Requirements Traceability Matrix (RTM) provides **full bidirectional trace** between ION's user requirements and the design, implementation, verification, and use-case artefacts that realise them.

For every User Requirement (UR) in `docs/USER_REQUIREMENTS.md`, this RTM identifies:

- the **System Requirement(s)** (SR) the UR decomposes into
- the **HLD section** that names the architectural choice that realises the SR
- the **LLD section** that gives the implementation detail
- the **Use Case(s)** that exercise it (`docs/USE_CASES.md`)
- the **Gap Filled** narrative (`docs/GAPS_FILLED.md`) — why the requirement matters
- the **Test(s)** that verify it
- the **Status** at v0.29.1

The matrix also includes a **reverse trace** (§4) — from each design element back to the requirements it supports — used to spot any design element that exists without a requirement (a smell).

## 1.2 Scope

The RTM covers every UR in `docs/USER_REQUIREMENTS.md` (51 requirements at v0.29.1). System Requirements are listed inline; they're maintained here rather than in a separate SR document.

## 1.3 How to read a row

Each row in the matrix below corresponds to a **single UR**. Reading left-to-right:

```
UR-L2-002  →  SR-L2-002a, SR-L2-002b  →  HLD §7.3, §3.3  →  LLD §3.3, §9.2  →
            UC-L2-01  →  GAP-04  →  test_workbench_pins.py, test_ledger_chain.py  →  ✅
```

That row says: the L2 analyst's pin-evidence-to-case need is decomposed into two system requirements; realised by the Workbench + ledger architecture (HLD §7.3) and the per-feature deep dive (LLD §3.3 + §9.2); exercised by use case UC-L2-01; closes pain point GAP-04; verified by two named tests; status met.

## 1.4 Verification status legend

| Symbol | Meaning |
|---|---|
| ✅ | Implemented + verified (test passes) |
| ◐ | Implemented + partial verification (one or more dimensions empirical only) |
| ⏳ | Planned (work item known) |
| ✗ | Out of scope at this version |

# 2. System Requirements catalogue

Before the matrix proper, the System Requirements that URs decompose into are catalogued. Each SR is named once and reused across the matrix.

| SR ID | Statement |
|---|---|
| **SR-AUTH-001** | Local password auth uses bcrypt and is rate-limited via slowapi |
| **SR-AUTH-002** | OIDC auth supports RS256 only; HS256 rejected at verification time |
| **SR-AUTH-003** | Sessions are server-side, cookie-bound, with Secure/HttpOnly/SameSite=Lax flags |
| **SR-RBAC-001** | 7-tier role hierarchy with explicit `Permission` ↔ `RolePermission` binding |
| **SR-RBAC-002** | Every endpoint enforces a permission via `@permission_required(...)` |
| **SR-RBAC-003** | Every service-layer mutation re-checks auth before commit (TOCTOU defence) |
| **SR-ALERT-001** | ES Security adapter pulls alerts on a 30-second schedule into ION's cache |
| **SR-ALERT-002** | `/alerts` displays alerts sorted by severity DESC, age ASC |
| **SR-ALERT-003** | Each alert row exposes severity, age, rule, technique, host/user, timestamp, status |
| **SR-AI-001** | Bob template selection uses a 5-tier matcher: rule_id → regex → technique → tactic → groups |
| **SR-AI-002** | Bob output validates against a Pydantic-bound schema (`AlertPromptOutput`); arbitrary text refused |
| **SR-AI-003** | Bob confidence is reported as 0-100 + low/medium/high band; low-confidence triggers UI circuit breaker |
| **SR-AI-004** | Bob never closes a case; `CaseClosureReason` selection is analyst-only |
| **SR-AI-005** | Bob outputs are joinable to audit_log via `bob_verdict_id` |
| **SR-AI-006** | `confidence_threshold_override` per template; admin-editable via `/alert-prompts` |
| **SR-AI-007** | Eval harness replays templates against historical alerts; reports P/R/F1; advisory-lock-blocked when a live investigation loop is active |
| **SR-CASE-001** | Cases are first-class entities (`Investigation`) with status / priority / closure_reason / assignee |
| **SR-CASE-002** | `case_grouper_service` correlates alerts by host/user/technique/timewindow into cases (every 5 min, advisory lock CGP) |
| **SR-CASE-003** | `/cases/{id}` renders linked alerts + observables + similar cases + entity timelines + workbench + attack story on initial load |
| **SR-CASE-004** | Case kanban view supports drag-to-update status |
| **SR-PIN-001** | Workbench pin operation accepts alert / observable / query / note / file pin types |
| **SR-PIN-002** | Every pin produces a `CaseEvidencePin` row + a `CaseEvidenceLedger` row in the same transaction |
| **SR-LEDGER-001** | `CaseEvidenceLedger.event_hash = sha256(prev_hash + json(payload))` |
| **SR-LEDGER-002** | Tamper detection walks the chain by insertion order; flags row-level breaks |
| **SR-LEDGER-003** | ForensicCase ledger uses distinct advisory-lock namespace FCWL |
| **SR-SIM-001** | Closed cases are embedded with `nomic-embed-text` via Ollama; stored in `CaseEmbedding` |
| **SR-SIM-002** | Similarity lookup uses pgvector + HNSW indexes |
| **SR-SIM-003** | Top-5 similar-cases panel appears on case detail page |
| **SR-PCAP-001** | Case-create triggers PCAP analysis for alerts with `community_id` OR source/destination IP + timestamp |
| **SR-PCAP-002** | Arkime adapter uses community_id preferred; IP+time fallback when community_id misses |
| **SR-PCAP-003** | PCAP heuristic analysis runs 12 detectors; findings post to case Workbench as pinned comment |
| **SR-FOR-001** | `ForensicCase` is parallel to AlertCase with own Workbench (advisory lock FCWL) |
| **SR-FOR-002** | Every `EvidenceItem` has a `CustodyLogEntry` audit chain |
| **SR-FOR-003** | Forensic playbooks are NIST SP 800-86 aligned |
| **SR-TI-001** | OpenCTI adapter provides threat landscape, actors, IOCs, reports |
| **SR-TI-002** | Threat Watch Gap raises alert when a watched actor gains a technique not covered by TIDE rules |
| **SR-TI-003** | Unified `/threat-intel` page replaces 3 prior pages (v0.27.0 consolidation) |
| **SR-DE-001** | `/engineering/analytics` ranks rules by FP rate × volume |
| **SR-DE-002** | `/tuning-proposals` supports full lifecycle: file → review → sync to TIDE → close |
| **SR-DE-003** | `/cyab/attack-heatmap` renders bundled ATT&CK v15.1 (v0.22.0) with TIDE rule overlay |
| **SR-DE-004** | `/compliance` maps TIDE rules to NIST CSF, ISO 27001, ACSC E8, DefStan, and exports a coverage report |
| **SR-OPS-001** | `/briefing` aggregates: P1/P2 incidents, alert volume, noisy rules, SLA breaches, tuning queue |
| **SR-OPS-002** | `/shift-handover` pre-populates from shift state; persists for next shift's briefing |
| **SR-OPS-003** | `/analyst-efficiency` shows per-analyst metrics fairly (no surveillance signals) |
| **SR-OPS-004** | Executive briefing generator produces editable / exportable summary (v0.27.0) |
| **SR-ADMIN-001** | Each integration is configurable via `/integrations` + smoke "Test" action |
| **SR-ADMIN-002** | Users/roles/permissions managed via dedicated admin pages |
| **SR-ADMIN-003** | Settings table is runtime-mutable via `/settings` for non-secret operational parameters |
| **SR-ADMIN-004** | `/audit-log` supports filter + CSV export |
| **SR-ADMIN-005** | `/workbench-audit` recomputes sha256 chain and reports integrity |
| **SR-CURR-001** | `/training` exposes modules → lessons → quizzes; tracks per-user progress |
| **SR-CURR-002** | Lab system runs containerised exercises (v0.20.1; 4 known bugs queued for v0.30.0) |
| **SR-DPO-001** | SAR query returns every row referencing a named subject (SQL in DPIA Appendix A) |
| **SR-DPO-002** | Erasure query anonymises personal identifiers (SQL in DPIA Appendix B) |
| **SR-NFR-AIRGAP** | Image bundles ATT&CK + KEV snapshots; no live external feed dependency at runtime |
| **SR-NFR-LOG** | stdout JSON-lines ECS-compliant; one log entry per request and per state-mutating action |
| **SR-NFR-AUDIT** | Every 2xx state-mutating response generates an `AuditLog` row |
| **SR-NFR-RTO** | Postgres backup + image redeploy procedure documented; RTO ≤ 1h target |
| **SR-NFR-RPO** | Customer-side backup cadence ≤ 24h |
| **SR-NFR-INTEG** | Each adapter raises `IntegrationUnavailable` on exhaustion; surfaces show banner; core pages remain functional |
| **SR-NFR-SBOM** | SPDX-JSON SBOM bundled in image at `/app/sbom.spdx.json` |
| **SR-NFR-SCA** | pip-audit + bandit + ruff run in CI on every commit |
| **SR-NFR-IMG** | Docker Hub tags are digest-pinned; image not re-pushed under same tag |
| **SR-INV-MEM-001** | Investigation memory persists analyst working notes per case across sessions |
| **SR-AI-CHAT-001** | `/ai-chat` surface routes NL queries to Ollama; conversation persisted per user |
| **SR-AI-CHAT-002** | Case-scoped AI chat panel constrains chat context to the current case |
| **SR-AI-CHAT-003** | NL-to-Elasticsearch converter emits query JSON preview before execution |
| **SR-AI-DOC-001** | AI document generation produces editable drafts from template + context prompt |
| **SR-KG-001** | Knowledge graph surface renders entity-relation graph with click-to-pivot |
| **SR-D3FEND-001** | D3FEND defensive technique map; bidirectional cross-reference with ATT&CK |
| **SR-ATTACK-NAV-001** | ATT&CK Navigator layer JSON export from `/cyab/attack-heatmap` |
| **SR-DASH-001** | Per-user dashboard layout; persists across sessions; drag-to-rearrange |
| **SR-HEALTH-001** | `GET /health` returns stable JSON schema documented in `docs/RUNBOOK.md`; non-2xx on degraded state |
| **SR-CSP-001** | Strict CSP middleware on every response; inline scripts nonce-based; no `unsafe-eval` |
| **SR-TZ-001** | DB timestamps in UTC; per-user TZ preference renders display-side; logs always UTC |
| **SR-NOTIF-001** | `/notifications` surface; in-app unread count badge; mark-read clears |
| **SR-TI-LANDSCAPE-001** | Threat landscape briefing generator produces editable exportable text (v0.27.0) |
| **SR-TI-ACTOR-001** | Actor profile page includes aliases, motivations, sectors, techniques + ATT&CK click-through, IOC sparkline (v0.27.0) |
| **SR-TI-IOC-FEED-001** | Live IOC feed surface with type, confidence, last-seen |
| **SR-OP-DEPLOY-001** | `docs/DEPLOYMENT.md` end-to-end deployment procedure; smoke check at completion |
| **SR-OP-BACKUP-001** | Postgres backup + restore procedure documented; meets RTO ≤ 1h |
| **SR-OP-SLOWQ-001** | `slow_query_threshold_ms` configurable; threshold-exceeding queries emit ECS log row |
| **SR-OP-POOL-001** | Pool size, overflow, in-use exposed on `/health` or `/admin/health-detail` |
| **SR-NET-CMDB-001** | `/network-assets` CMDB + `/topology` graph render |
| **SR-NET-LOG-HEALTH-001** | `/log-source-health` shows per-source ingest status, volume trend, silent flags |
| **SR-KM-NOTES-001** | `/notes` with folders + tags + search; attachable to cases / observables |
| **SR-KM-DOCS-001** | `/templates` + `/documents` with markdown editing, versioning, template-fill |
| **SR-EM-PLAN-001** | `/emulation` plan library with steps tied to ATT&CK techniques |
| **SR-EM-EXEC-001** | Emulation execution tracked per step (pass/fail); failed-step → tuning proposal flow |
| **SR-CA-DEPLOY-001** | `/canaries` CRUD for honeydoc / credential / DNS tokens |
| **SR-CA-TRIP-001** | Canary trip auto-creates `severity: critical` alert with pre-populated context + playbook suggestion |
| **SR-API-WEBHOOK-001** | HMAC-signed outbound webhook on configurable events; retry on transient failure; delivery log |

# 3. Traceability matrix (UR → SR → Design → UC → Gap → Test → Status)

The full matrix below has one row per UR. Some URs span multiple SRs / design elements / use cases; those are itemised within the row.

| UR | SR(s) | HLD ref | LLD ref | UC | Gap | Test(s) | Status |
|---|---|---|---|---|---|---|---|
| UR-L1-001 | SR-ALERT-002 | §6.3 | §10.1 | UC-L1-01 | GAP-01 | `test_alert_queue_order.py` | ✅ |
| UR-L1-002 | SR-ALERT-003 | §6.3 | §10.1 | UC-L1-01 | GAP-01 | `test_alert_row_fields.py` | ✅ |
| UR-L1-003 | SR-AI-001, SR-AI-002 | §7.5 | §7.1, §7.2 | UC-L1-01 | GAP-02, GAP-03 | `test_bob_template_match.py`, `test_bob_output_contract.py` | ✅ |
| UR-L1-004 | SR-AI-003 | §7.5 | §7.1 | UC-L1-01 | GAP-16 | `test_bob_confidence_band.py` | ✅ |
| UR-L1-005 | SR-CASE-001 | §4 | §5 | UC-L1-01 | GAP-01 | `test_bulk_close.py` | ✅ |
| UR-L1-006 | SR-CASE-001, SR-CASE-002 | §4 | §5, §6.2 | UC-L1-02 | GAP-01 | `test_case_create_from_alerts.py`, `test_case_grouper.py` | ✅ |
| UR-L1-007 | SR-OPS-002 | §4.2 | §10.1 | UC-L1-03 | GAP-12 | `test_shift_handover.py` | ✅ |
| UR-L2-001 | SR-CASE-003 | §4 | §10.1 | UC-L2-01 | GAP-04, GAP-06 | `test_case_landing_page.py` | ✅ |
| UR-L2-002 | SR-PIN-001, SR-PIN-002 | §7.3 | §3.3, §10.4 | UC-L2-01 | GAP-04 | `test_workbench_pin_lifecycle.py` | ✅ |
| UR-L2-003 | SR-LEDGER-001, SR-LEDGER-002 | §7.3 | §9.2 | UC-AD-04 | GAP-04, GAP-17 | `test_ledger_chain.py`, `test_ledger_tamper_detection.py` | ✅ |
| UR-L2-004 | SR-SIM-001, SR-SIM-002, SR-SIM-003 | §4.2 | §10.5 | UC-L2-01 | GAP-06 | `test_case_similarity.py`, `test_case_embedding_backfill.py` | ✅ |
| UR-L2-005 | SR-CASE-003 | §4.2 | §10.1 | UC-L2-01 | GAP-19 | `test_entity_timeline.py` | ✅ |
| UR-L2-006 | SR-PCAP-001, SR-PCAP-002, SR-PCAP-003 | §4.2 | §10.2 | UC-L2-01 | GAP-07 | `test_pcap_auto_analysis.py`, `test_pcap_ip_fallback.py` | ✅ |
| UR-L2-007 | SR-CASE-004 | §4 | §10.1 | UC-L2-01 | GAP-04 | `test_case_kanban.py` | ✅ |
| UR-L3-001 | SR-FOR-001, SR-LEDGER-003 | §4.2 | §3.3, §10.4 | UC-L3-01 | GAP-05 | `test_forensic_case_lifecycle.py`, `test_forensic_workbench.py` | ✅ |
| UR-L3-002 | SR-FOR-002 | §4.2 | §3.1 | UC-L3-01 | GAP-05 | `test_custody_log.py` | ✅ |
| UR-L3-003 | SR-TI-001, SR-TI-002 | §4.2 | §10.1 | UC-L3-02 | GAP-08 | `test_threat_intel_landscape.py`, `test_threat_watch_gap.py` | ✅ |
| UR-L3-004 | SR-CASE-002 | §4.2 | §10.1 | UC-L3-03 | GAP-08 | `test_attack_story.py` | ✅ |
| UR-DE-001 | SR-DE-001 | §4.2 | §10.1 | UC-DE-01 | GAP-09 | `test_engineering_analytics.py`, `test_ai_feedback_dual_write.py` | ✅ |
| UR-DE-002 | SR-DE-002 | §4.2 | §10.1 | UC-DE-01 | GAP-09 | `test_tuning_proposal_lifecycle.py` | ✅ |
| UR-DE-003 | SR-DE-003 | §4.2 | §10.1 | UC-L3-02, UC-DE-02 | GAP-10 | `test_attack_heatmap.py` | ✅ |
| UR-DE-004 | SR-DE-004 | §4.2 | §10.1 | UC-DE-02 | GAP-11 | `test_compliance_mapping.py` | ✅ |
| UR-DE-005 | SR-AI-006 | §7.5 | §7.1 | UC-DE-03 | GAP-02, GAP-16 | `test_alert_prompt_crud.py`, `test_confidence_threshold_override.py` | ✅ |
| UR-DE-006 | SR-AI-007 | §7.5 | §7.3 | UC-DE-03 | GAP-16 | `test_bob_eval_harness.py` | ✅ |
| UR-SM-001 | SR-OPS-001 | §4.2 | §10.1 | UC-SM-01 | GAP-12 | `test_briefing_aggregation.py` | ✅ |
| UR-SM-002 | SR-OPS-003 | §4.2 | §10.1 | UC-SM-02 | GAP-13 | `test_analyst_efficiency.py` | ✅ |
| UR-SM-003 | SR-OPS-004, SR-TI-003 | §4.2 | §10.1 | UC-SM-03 | GAP-08 | `test_executive_report_generator.py`, `test_threat_landscape_brief.py` | ✅ |
| UR-SM-004 | SR-CASE-001 | §4 | §5 | UC-SM-01 | GAP-12 | `test_sla_breach_log.py` | ✅ |
| UR-SM-005 | SR-OPS-001 | §4.2 | §10.1 | UC-SM-01 | (general) | `test_maturity_scorecard.py` | ✅ |
| UR-AD-001 | SR-ADMIN-001 | §9 | §12 | UC-AD-01 | GAP-19 | `test_integration_config.py`, `test_integration_smoke_action.py` | ✅ |
| UR-AD-002 | SR-RBAC-001, SR-ADMIN-002 | §7.2 | §8.3 | UC-AD-02 | GAP-19 | `test_user_role_lifecycle.py`, `test_permission_grant.py` | ✅ |
| UR-AD-003 | SR-AUTH-002 | §7.1 | §8.2 | UC-AD-02 | GAP-19 | `test_oidc_rs256_only.py`, `test_oidc_hs256_refused.py` | ✅ |
| UR-AD-004 | SR-ADMIN-003 | §7.2 | §12.1 | UC-AD-01 | (general) | `test_settings_runtime_mutation.py` | ✅ |
| UR-AD-005 | SR-ADMIN-004, SR-NFR-AUDIT | §7.3 | §9.1 | UC-AD-03, UC-CO-01 | GAP-17 | `test_audit_log_filter.py`, `test_audit_log_export.py` | ✅ |
| UR-AD-006 | SR-ADMIN-005, SR-LEDGER-002 | §7.3 | §9.2 | UC-AD-04 | GAP-17 | `test_workbench_audit_verify.py` | ✅ |
| UR-LR-001 | SR-CURR-001, SR-CURR-002 | §4.2 | §3.1 | UC-LR-01 | GAP-14 | `test_curriculum_lifecycle.py`; lab tests partial (4 bugs queued) | ◐ |
| UR-LR-002 | SR-CURR-001 | §4.2 | §3.1 | UC-LR-02 | GAP-14 | `test_course_assignment.py` | ✅ |
| UR-CO-001 | SR-DPO-001 | §6.7 | §12 | UC-CO-01 | GAP-17 | `test_sar_query.py` (+ DPIA App. A SQL) | ✅ |
| UR-CO-002 | SR-DPO-002 | §6.7 | §12 | UC-CO-02 | GAP-17 | `test_erasure_anonymise.py` (+ DPIA App. B SQL) | ✅ |
| UR-CO-003 | SR-LEDGER-002 | §7.3 | §9.2 | UC-AD-04 | GAP-04, GAP-17 | `test_ledger_chain.py`, `test_ledger_tamper_detection.py` | ✅ |
| UR-CO-004 | (NFR; multiple SRs) | §6.6 | (cross-cutting) | (all UCs) | (general) | `_mod_wcag_audit.md` tier-1+2 audit | ◐ |
| UR-NFR-001 | SR-NFR-AIRGAP | §6.8, §8.3 | §12.2 | (operator) | GAP-15 | `test_airgap_no_network_calls.py`, image inspection | ✅ |
| UR-NFR-002 | (perf) | §6.2 | (cross-cutting) | (all UCs) | (general) | empirical; formal load-test planned v0.31.0+ | ◐ |
| UR-NFR-003 | SR-NFR-AUDIT | §6.5, §7.3 | §9.1 | UC-AD-03 | GAP-17 | `test_audit_log_every_mutation.py` | ✅ |
| UR-NFR-004 | SR-NFR-LOG | §7.4 | §11.2 | (SIEM team) | GAP-19 | `test_ecs_log_shape.py`, `_mod_log_shipping_spec.md` | ✅ |
| UR-NFR-005 | SR-NFR-RTO, SR-NFR-RPO | §6.1 | §12 | (operator) | (general) | `_mod_iteap.md` §5 DR drill | ✅ |
| UR-NFR-006 | SR-NFR-INTEG | §9 | §11.2 | (all UCs) | GAP-19 | `test_integration_failure_modes.py` (×7 per adapter) | ✅ |
| UR-NFR-007 | SR-NFR-SBOM | §6.4 | §13.2 | (customer security) | (general) | image-inspection step in `_mod_iteap.md` | ✅ |
| UR-NFR-008 | SR-NFR-SCA | §6.4 | §13.2 | (customer security) | (general) | CI workflow `.github/workflows/test.yml` | ✅ |
| UR-NFR-009 | (none yet) | §11 | (n/a) | (n/a) | (general) | not implemented | ⏳ |
| UR-NFR-010 | SR-NFR-IMG | §6.4 | §13 | (operator) | (general) | Docker Hub digest immutability | ✅ |
| UR-L2-008 | SR-INV-MEM-001 | §4.2 | §10.1 | UC-L2-01 | GAP-04 | `test_investigation_memory.py` | ✅ |
| UR-L2-009 | SR-AI-CHAT-002 | §7.5 | §7 | UC-L2-01, UC-AI-01 | GAP-16 | `test_ai_chat_case_scope.py` | ✅ |
| UR-L3-005 | SR-KG-001 | §4.2 | §10.1 | UC-L3-02 | GAP-08 | `test_knowledge_graph_nav.py` | ✅ |
| UR-DE-007 | SR-D3FEND-001 | §4.2 | §10.1 | UC-DE-02 | GAP-10, GAP-11 | `test_d3fend_mapping.py` | ✅ |
| UR-DE-008 | SR-ATTACK-NAV-001 | §4.2 | §10.1 | UC-DE-02 | GAP-10 | `test_attack_navigator_export.py` | ✅ |
| UR-SM-006 | SR-DASH-001 | §4.2 | §10.1 | (cross-cutting) | (general) | `test_dashboard_layout.py` | ✅ |
| UR-AD-007 | SR-HEALTH-001 | §6.1, §7.4 | §11 | UC-OP-01, UC-OP-03 | (general) | `test_health_endpoint.py` | ✅ |
| UR-NFR-011 | SR-CSP-001 | §6.4 | §11 | (cross-cutting) | (general) | `test_csp_header.py` | ✅ |
| UR-NFR-012 | SR-TZ-001 | §6.4 | §3 | (cross-cutting) | (general) | `test_timezone_handling.py` | ✅ |
| UR-NFR-013 | SR-NOTIF-001 | §4.2 | §10.1 | (cross-cutting) | (general) | `test_notifications.py` | ✅ |
| UR-TI-001 | SR-TI-LANDSCAPE-001 | §4.2 | §10.1 | UC-TI-01 | GAP-08 | `test_threat_landscape_brief.py` | ✅ |
| UR-TI-002 | SR-TI-ACTOR-001 | §4.2 | §10.1 | UC-TI-02 | GAP-08 | `test_actor_profile.py`, `test_actor_ioc_sparkline.py` | ✅ |
| UR-TI-003 | SR-TI-IOC-FEED-001 | §4.2 | §10.1 | UC-TI-02 | GAP-08 | `test_live_ioc_feed.py` | ✅ |
| UR-TI-004 | SR-TI-002 | §4.2 | §10.1 | UC-TI-02 | GAP-08, GAP-10 | `test_threat_watch_gap.py` | ✅ |
| UR-OP-001 | SR-OP-DEPLOY-001 | §8.1, §8.2, §8.3 | §12 | UC-OP-01 | (general) | `_mod_iteap.md` §1 functional + deployment smoke | ✅ |
| UR-OP-002 | SR-OP-BACKUP-001, SR-NFR-RTO, SR-NFR-RPO | §6.1 | §12 | UC-OP-02 | (general) | `_mod_iteap.md` §5 DR drill | ✅ |
| UR-OP-003 | SR-OP-SLOWQ-001, SR-NFR-LOG | §7.4 | §11.2 | UC-OP-03 | (general) | `test_slow_query_log_emit.py`, `_mod_log_shipping_spec.md` | ✅ |
| UR-OP-004 | SR-OP-POOL-001, SR-HEALTH-001 | §7.4 | §11 | UC-OP-03 | (general) | `test_pool_metrics_exposed.py` | ✅ |
| UR-AI-001 | SR-AI-CHAT-001 | §7.5 | §7 | UC-AI-01 | GAP-19 | `test_ai_chat_grounded.py` | ✅ |
| UR-AI-002 | SR-AI-CHAT-003 | §7.5 | §7 | UC-AI-02 | GAP-02 | `test_nl_to_es.py` | ✅ |
| UR-AI-003 | SR-AI-DOC-001 | §7.5 | §7 | UC-SM-03, UC-AI-01 | (general) | `test_ai_document_gen.py` | ✅ |
| UR-NET-001 | SR-NET-CMDB-001 | §4.2 | §10.1 | UC-NET-01 | (general) | `test_network_asset_cmdb.py`, `test_topology_render.py` | ✅ |
| UR-NET-002 | SR-NET-LOG-HEALTH-001 | §4.2 | §10.1 | UC-NET-01 | (general) | `test_log_source_health.py` | ✅ |
| UR-KM-001 | SR-KM-NOTES-001 | §4.2 | §10.1 | (cross-cutting) | (general) | `test_notes_crud.py` | ✅ |
| UR-KM-002 | SR-KM-DOCS-001 | §4.2 | §10.1 | (cross-cutting) | (general) | `test_templates_crud.py`, `test_documents_crud.py` | ✅ |
| UR-EM-001 | SR-EM-PLAN-001 | §4.2 | §10.1 | UC-EM-01 | (general) | `test_emulation_plan_library.py` | ✅ |
| UR-EM-002 | SR-EM-EXEC-001 | §4.2 | §10.1 | UC-EM-01 | GAP-10 | `test_emulation_execution.py` | ✅ |
| UR-CA-001 | SR-CA-DEPLOY-001 | §4.2 | §10.1 | UC-CA-01 | (general) | `test_canary_deploy.py` | ✅ |
| UR-CA-002 | SR-CA-TRIP-001 | §4.2 | §10.1 | UC-CA-01 | (general) | `test_canary_trip_alert.py` | ✅ |
| UR-API-001 | SR-API-WEBHOOK-001 | §9, §11.2 | §12 | UC-API-01 | GAP-19 | `test_webhook_signed.py`, `test_webhook_retry.py` | ✅ |

# 4. Reverse trace: design element → requirements

The reverse trace lets architecture reviewers spot design elements that exist without a requirement justification (potential dead code, scope creep). This section walks each design element from `docs/HLD.md` §4–§7 and `docs/LLD.md` §3–§10 and lists the URs each supports.

## 4.1 By major design element

| Design element | LLD ref | URs supported |
|---|---|---|
| Alert ingestion | LLD §10.1 | UR-L1-001, UR-L1-002 |
| Bob 5-tier matcher | LLD §7.1, §10.6 | UR-L1-003, UR-DE-005 |
| Bob output contract | LLD §7.2 | UR-L1-003, UR-L1-004 |
| Bob eval harness | LLD §7.3 | UR-DE-006 |
| Case management | LLD §5, §10.1 | UR-L1-006, UR-L2-001, UR-L2-007, UR-SM-004, UR-SM-005 |
| case_grouper | LLD §6.2, §10.1 | UR-L1-006, UR-L3-004 |
| Workbench pins (AlertCase) | LLD §3.3, §10.4 | UR-L2-002 |
| Workbench pins (ForensicCase) | LLD §3.3, §10.4 | UR-L3-001 |
| sha256 ledger | LLD §9.2 | UR-L2-003, UR-AD-006, UR-CO-003 |
| pgvector + HNSW similarity | LLD §10.5 | UR-L2-004 |
| Entity timeline | LLD §10.1 | UR-L2-005 |
| PCAP auto-analysis (incl. IP fallback) | LLD §10.2 | UR-L2-006 |
| Forensic case + custody | LLD §3.1 | UR-L3-001, UR-L3-002 |
| Threat intel surface | LLD §10.1 | UR-L3-003, UR-SM-003 |
| Engineering analytics | LLD §10.1 | UR-DE-001 |
| AIFeedback dual-write | LLD §10.3 | UR-DE-001 |
| Tuning proposals | LLD §10.1 | UR-DE-002 |
| MITRE ATT&CK heatmap | LLD §10.1 | UR-DE-003 |
| Compliance mapping | LLD §10.1 | UR-DE-004 |
| Briefing aggregator | LLD §10.1 | UR-SM-001 |
| Analyst efficiency | LLD §10.1 | UR-SM-002 |
| Executive briefing | LLD §10.1 | UR-SM-003 |
| Integration adapters | LLD §11.2, §12 | UR-AD-001, UR-NFR-006 |
| RBAC (endpoint + service) | LLD §5.2, §8.3 | UR-AD-002 |
| OIDC RS256 | LLD §8.2 | UR-AD-003 |
| Settings runtime mutation | LLD §12.1 | UR-AD-004 |
| Audit log middleware | LLD §9.1 | UR-AD-005, UR-NFR-003 |
| Workbench audit verify | LLD §9.2 | UR-AD-006, UR-CO-003 |
| Curriculum lifecycle | LLD §3.1 | UR-LR-001, UR-LR-002 |
| SAR endpoint | LLD §12 (admin section) | UR-CO-001 |
| Erasure endpoint | LLD §12 (admin section) | UR-CO-002 |
| Bundled ATT&CK + KEV | LLD §12.2 | UR-NFR-001 |
| ECS stdout logs | LLD §11.2 | UR-NFR-004 |
| Backup + restore procedure | LLD §12 | UR-NFR-005 |
| SBOM in image | LLD §13.2 | UR-NFR-007 |
| pip-audit + bandit + ruff CI | LLD §13.2 | UR-NFR-008 |
| Docker Hub digest pinning | LLD §13 | UR-NFR-010 |
| Investigation memory | LLD §10.1 | UR-L2-008 |
| Case-scoped AI chat panel | LLD §7 | UR-L2-009 |
| Knowledge graph navigation | LLD §10.1 | UR-L3-005 |
| D3FEND mapping | LLD §10.1 | UR-DE-007 |
| ATT&CK Navigator export | LLD §10.1 | UR-DE-008 |
| Dashboard layout (per-user) | LLD §10.1 | UR-SM-006 |
| `/health` endpoint | LLD §11 | UR-AD-007, UR-OP-001, UR-OP-003 |
| CSP middleware | LLD §11 | UR-NFR-011 |
| UTC + per-user TZ | LLD §3 | UR-NFR-012 |
| In-app notifications | LLD §10.1 | UR-NFR-013 |
| Threat landscape briefing | LLD §10.1 | UR-TI-001, UR-SM-003 |
| Actor profile + IOC sparkline | LLD §10.1 | UR-TI-002 |
| Live IOC feed | LLD §10.1 | UR-TI-003 |
| Threat Watch Gap service | LLD §10.1 | UR-TI-004 |
| Deployment procedure | LLD §12 | UR-OP-001 |
| Backup/restore procedure | LLD §12 | UR-OP-002, UR-NFR-005 |
| Slow-query observability | LLD §11.2 | UR-OP-003 |
| Pool metrics on /health | LLD §11 | UR-OP-004 |
| AI Chat (open / NL / docs) | LLD §7 | UR-AI-001, UR-AI-002, UR-AI-003 |
| Network asset CMDB + topology | LLD §10.1 | UR-NET-001 |
| Log source health | LLD §10.1 | UR-NET-002 |
| Notes + folders + tags | LLD §10.1 | UR-KM-001 |
| Templates + documents | LLD §10.1 | UR-KM-002 |
| Adversary emulation library + tracking | LLD §10.1 | UR-EM-001, UR-EM-002 |
| Canary tokens + trip workflow | LLD §10.1 | UR-CA-001, UR-CA-002 |
| Outbound webhooks (HMAC + retry) | LLD §12 | UR-API-001 |

## 4.2 Orphans

A design element without a UR is a candidate for justification or removal. After walking §4.1 against the codebase:

**Zero confirmed orphans at v0.29.1.** Every major design element traces to at least one UR.

Items deliberately not yet implemented (and therefore traced to "planned"):

- Localisation infrastructure (UR-NFR-009) — planned, not implemented.

# 5. Forward trace: requirements → SDLC + compliance artefacts

For audit and DPIA purposes, this section maps requirements to the wider artefact universe.

| Requirement domain | Public artefacts | MOD-overlay artefacts (local-only) |
|---|---|---|
| Functional / Use Cases | `docs/USE_CASES.md`, `docs/GAPS_FILLED.md` | `_mod_iteap.md` §1 |
| Architecture | `docs/HLD.md`, `docs/LLD.md`, `docs/ARCHITECTURE.md` | `_mod_architecture_governance.md`, `_mod_design_passport.md` §5 |
| Security | `SECURITY_ASSESSMENT.md`, `docs/DEVELOPMENT_LIFECYCLE.md` | `_mod_design_passport.md` §6, `_mod_exception_register.md` |
| Safety | (n/a — Safety-Benign) | `_mod_safety_questionnaire.md`, `_mod_design_passport.md` §7 |
| Privacy | (n/a — privacy via design) | `_mod_dpia.md`, `_mod_design_passport.md` §8 |
| Accessibility | (n/a — implicit baseline) | `_mod_wcag_audit.md`, `_mod_design_passport.md` §9 |
| Through-life / Support | `CHANGELOG.md`, `docs/RUNBOOK.md` | `_mod_through_life_plan.md`, `_mod_service_transition.md` |
| Logs / Audit | `docs/DEVELOPMENT_LIFECYCLE.md` | `_mod_log_shipping_spec.md` |
| Registration | (n/a) | `_mod_app_register_submission.md` |
| Compliance overall | `docs/TRACEABILITY.md` (this doc) | `_mod_compliance_mapping.md` |

# 6. Verification summary

## 6.1 Overall verification

At v0.29.1 (RTM v1.1):

- 81 user requirements catalogued (51 in v1.0 + 30 in v1.1)
- 77 fully met + verified (✅)
- 3 partial (◐): UR-LR-001 (lab-fixture bugs queued v0.30.0), UR-CO-004 (WCAG tier-3/4 remediation), UR-NFR-002 (formal load-test pending)
- 1 planned (⏳): UR-NFR-009 (localisation)
- 0 out-of-scope (✗)

## 6.2 Test ownership

| Test category | Owner | Source |
|---|---|---|
| Unit + functional tests | Maintainer | `tests/` |
| Integration tests | Maintainer + customer | `tests/`, `_mod_iteap.md` §2 |
| Accessibility tests | Maintainer (auto) + customer A11y team (manual) | `_mod_wcag_audit.md` |
| Security tests (ITHC) | Customer + chosen ITHC supplier | `_mod_iteap.md` §4 |
| DR drill | Customer ops | `_mod_iteap.md` §5 |
| BC scenario | Customer ops | `_mod_iteap.md` §6 |

## 6.3 Continuous trace

When a new UR is added (typically at the start of a release-spec):

1. Add the UR to `docs/USER_REQUIREMENTS.md` with a unique stable ID.
2. Add the row to `docs/TRACEABILITY.md` §3 (matrix).
3. Reference the matching SR(s) in §2; add new SRs if needed.
4. Identify which HLD / LLD / UC / Gap / Test rows the new UR touches.
5. At release-acceptance walk (§3.4.8), confirm the trace row's Status reflects reality.

# 7. Change history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-05-12 | ION maintainer | Initial RTM authored against v0.29.1; 51 URs × full trace |
| 1.1 | 2026-05-12 | ION maintainer | Expanded against URD v1.1: +30 RTM rows; +29 SRs in catalogue; reverse-trace and verification summary updated. New total: 81 URs |
