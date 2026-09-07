<!-- ion-doc:type=SPEC -->
<!-- ion-doc:title=Response Actions + Verdict Review -->
<!-- ion-doc:subtitle=Govern ION's advisory AI into approved, audited on-prem response -->
<!-- ion-doc:classification=INTERNAL -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:status=DRAFT — Phase 0 complete, Phases 1–3 pending -->

# Spec — Response Actions + Verdict Review

**Goal.** Turn ION's existing advisory AI (Bob) into a *governed-action* platform:
Bob proposes a verdict and a response action → a human reviews the verdict and
approves any irreversible action → the action executes on-prem, fully audited.
This is the 2026 "agentic SOC, human-in-the-loop" pattern, delivered air-gapped.

**Headline: ~70% is already built.** Both engines exist in the codebase; this
arc is *surface + wire + govern*, not greenfield.

---

## Phase 0 — verified findings (2026-09-07)

1. **Response-action engine is real and DORMANT.**
   `src/ion/services/playbook_action_service.py` holds the catalog
   (`DEFAULT_ACTIONS`: block_ip / block_domain / disable_account /
   quarantine_host / reset_password / block_sender, each with `requires_approval`
   + `risk_level`) and the `request_action → approve_action → execute_action`
   flow over `PlaybookAction` + `PlaybookActionLog` (`executed_by_id`,
   `approved_by_id`, `status`). Execution dispatches **for real** via
   `playbook_executor_service` → `playbook_executors/registry.py` (7 adapters:
   firewall_rest, dns_sinkhole, active_directory_ldap, edr_webhook,
   email_gateway, generic_webhook, audit). Results carry a **`dry_run`** flag;
   `is_configured` / `is_adapter_configured` fail closed when the integration is
   unconfigured. **Confirmed: zero web routes and zero templates reference the
   action engine — it has no callers outside its own module + the executor
   bridge.** Fully built, entirely unsurfaced.

2. **`execute_action` docstring is stale** — says "simulate", actually calls the
   real adapter. Fix the docstring (Phase 1 cleanup).

3. **`approve_action` has NO separation-of-duty check** — any user can approve,
   and the approver may equal the requester. Must gate for irreversible actions.

4. **Two distinct playbook subsystems — do not conflate:**
   - *Playbook **executions*** (runbooks/checklists with steps + report):
     surfaced, `playbook:execute`, `api.py` 4980–5252 + `case_lifecycle_api`.
     Out of scope here.
   - *Playbook **actions*** (atomic SOAR actions + approval + executors):
     dormant. **This spec.**

5. **Permissions:** existing set includes `playbook:read/create/update/delete/
   execute` and `de:propose/approve/verify/read`. No `response:*` / `verdict:*`.
   Plan: reuse `playbook:execute` for execution; add `response:approve` (the
   irreversible-action gate) and `verdict:review` (the queue), mirroring the
   `de:propose`/`de:approve` split already in the role model.

6. **Verdict side already models the data:** `AIFeedback`
   (`bob_suggested_verdict` vs `human_verdict`, `agreement`, `delta_reason`) —
   `ai_feedback_service.record_*` writes it **at case-close**, a `"pending"`
   verdict state already exists in the data, and `bob_eval_service` already
   computes precision/recall over it. `auto_investigation_service` emits a
   **validated** verdict + a recommended playbook id (citation-checked against
   the real catalog). **Missing: a review-queue surface; Bob's verdict is never
   persisted as `pending` at investigation time.**

7. **Master-switch convention:** ION uses `ION_*_ENABLED` opt-in flags. Add
   `ION_RESPONSE_ACTIONS_ENABLED` (default **off**); air-gapped installs light it
   only when executors are wired.

---

## The three gaps to close

1. **No operator surface** for the response-action engine (dormant).
2. **No verdict-review queue** (feedback is post-close only).
3. **Not connected** — Bob's recommended action never becomes a proposed action
   awaiting approval, and its verdict never enters a review queue.

---

## Phase 1 — make the response engine operable  *(biggest chunk, highest value)*

- **API** (new router, `ION_RESPONSE_ACTIONS_ENABLED`-gated, per-route perms):
  `POST /api/response/actions` (request; target pre-filled from a case
  observable), `POST …/{id}/approve` (`response:approve`), `POST …/{id}/reject`,
  `GET …/pending`, `GET …/log`. Audit-log every transition.
- **Separation of duty:** for `requires_approval` (high-risk) actions enforce
  `approved_by_id != executed_by_id` in `approve_action` (currently absent).
- **Case-detail "Actions" tab:** propose an action against the case's deduped
  observables (block *this* IP/domain, disable *this* user); show pending /
  approved / executed status.
- **On execution:** result onto `PlaybookActionLog` **and** a case Note — must
  call `sync_note_to_kibana` (recurring gotcha) — recording who did what.
- Fix the stale `execute_action` docstring.

## Phase 2 — Verdict Review queue  *(mostly UI over existing data)*

- Persist Bob's verdict as a **`pending` `AIFeedback` row at investigation
  time**, not only at close.
- New `/verdict-review` page: alerts/cases with a Bob-proposed verdict awaiting
  review — verdict + **evidence-ledger citations** + confidence. Human
  **accepts** (close with Bob's verdict), **overrides** (verdict + `delta_reason`),
  or **sends back**. Writes the ledger row (agreement auto-computed) — reuse
  `ai_feedback_service` unchanged.
- Surface agreement-rate / precision from `bob_eval_service`.

## Phase 3 — connect the arc  *(the differentiator)*

- When Bob recommends a playbook/action id, create a **proposed
  `PlaybookActionLog` in `pending_approval`** linked to the case, shown *inside*
  the verdict-review item.
- One governed decision: "accept verdict = malicious C2 → approve Block-IP."
  Approve → Phase 1 execution path. Every step audited; irreversible actions
  gated; nothing auto-executes.

---

## ION invariants (baked into every phase)

Master switch off by default · service-side auth/ownership checks **before**
mutation (TOCTOU) · every action + verdict → `audit_logs` + Kibana-synced Note ·
per-route permission gates, new perms seeded to admin · executors
integration-gated + dry-run · affected-module tests only + ruff/import (no full
suite for a 0.x).

---

## Open decisions (owner)

1. **Live execution vs dry-run-first?** Recommend: ship Phases 1–2 in
   dry-run/logged mode; enable live executor calls behind the master switch in a
   later release. *(defence/air-gapped — live containment is sensitive.)*
2. **Separation of duty** for high-risk actions (requester ≠ approver)?
   Recommend **yes**.
3. **Any auto-execution?** Landscape: only ~30% of teams auto-execute even
   low-risk. Recommend **human-in-loop for everything in v1** (no auto-execute).

## Suggested sequencing

Phase 1 → its own release (operators can act). Phase 2 → next (verdict queue).
Phase 3 → capstone (the connect). Each affected-module-scoped.
