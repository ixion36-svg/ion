---
name: alert-prompt-add
description: Scaffold a new AlertPromptTemplate row — fill the 5-tier matcher fields (rule_id → regex → MITRE technique → tactic → groups), pin output contract to CaseClosureReason, add seed entry and a smoke test. Use when extending Bob's prompt catalogue.
---

# /alert-prompt-add — Add an AlertPromptTemplate

ION ships 54 seeded AlertPromptTemplate rows (50 + 4 ESXi at v0.17). Bob, the SOC service user, fires the matching template against each new alert and writes the result into the AIFeedback ledger. Adding the 55th template means:

1. A model row with the right matcher fields populated.
2. A seed entry committed to the appropriate seed file.
3. A smoke test that exercises the 5-tier matcher in priority order.
4. (Optional) An entry in the per-template advisory-lock catalogue if the prompt is long-running.

## When to use

- A new detection-engineering rule lands and needs an LLM-assisted closure prompt.
- An existing rule's auto-closure quality is bad and you're adding a more specific matcher.

## Background — read these first

These files define the contract. Read before composing:

- `src/ion/models/alert_prompt.py` — the SQLAlchemy model + column types
- `src/ion/services/alert_prompt_service.py` — fire path, dedup logic, matcher precedence
- `src/ion/storage/alert_prompt_repository.py` — the 5-tier resolution query
- `src/ion/web/alert_prompt_api.py` — admin CRUD endpoints
- `seed_alerts.py` (and/or `scripts/seed_alerts.py`) — seed-row authoring style
- `docs/AI_OUTPUT_CONTRACT.md` — the `CaseClosureReason` output contract Bob's response is parsed against

## Steps

1. **Identify the matcher.** Which of the 5 tiers fires for the rule you're adding? In priority order:
   1. `rule_id` — exact match on the detection's stable ID
   2. `rule_id_regex` — pattern over rule_id (use sparingly; specificity wins)
   3. `mitre_technique` — e.g. `T1059.001`
   4. `mitre_tactic` — e.g. `TA0002`
   5. `rule_group` — broad fallback (e.g. `windows_lateral_movement`)

   More specific = higher priority. The matcher resolver returns the highest-tier hit; ties within a tier are configuration error.

2. **Compose the prompt body.** Constraints (see `docs/AI_OUTPUT_CONTRACT.md`):
   - Output MUST validate against `CaseClosureReason` (Pydantic schema).
   - Include the alert payload placeholders Bob substitutes (`{alert.rule_name}`, `{alert.raw}`, etc. — exact list per service module).
   - Reference only data Bob can guarantee at fire time. No live external lookups.

3. **Add the seed row.** Append to `seed_alerts.py` (or the seed file that owns this domain). Fields to populate:
   - `rule_id` / `rule_id_regex` / `mitre_technique` / `mitre_tactic` / `rule_group` — one populated, others NULL
   - `prompt_body` — the composed prompt
   - `output_schema` — pin to `CaseClosureReason`
   - `enabled`, `confidence_threshold`, `circuit_breaker_*` — defaults from v0.21.0
   - Any template-specific overrides for advisory-lock namespace

4. **Add a smoke test.** In `tests/`, write a test that:
   - Builds a fake alert matching ONLY the new template's matcher.
   - Calls the alert-prompt-service fire path.
   - Asserts the new template won the resolution.
   - Asserts the fire didn't double-fire (AIFeedback dedup invariant: MAX(id) per (alert_id, template_id)).

5. **Run locally.**
   ```
   pytest tests/ -k alert_prompt -q --tb=short
   ruff check src/ion/services/alert_prompt_service.py
   ```

6. **Don't forget**: if this is the first template for a new MITRE technique/tactic, also confirm the eval harness fixtures cover it. See `project_ion_bob_eval_harness.md` in memory and `tests/` for the eval harness entry-point.

## What to skip

- The Elastic Agent Skills path (6th matcher tier) — that's a future addition; don't pre-populate it.
- Live external feed references — ION ships air-gapped; the prompt body must rely only on the alert payload.

## Failure modes

- **Two templates tie at the same tier** for the same rule — refactor: make one more specific or merge them.
- **Output fails CaseClosureReason validation** — check the prompt is instructing the model to emit the exact schema; review `docs/AI_OUTPUT_CONTRACT.md` for the canonical example.
- **AIFeedback duplicate fire** — the dedup invariant lives in the reader (`MAX(id) per (alert_id, template_id)`), but if the seed introduces a new fire path bypassing dedup, both fire-time and case-close writes will pile up. Re-check `alert_prompt_service.py`.
