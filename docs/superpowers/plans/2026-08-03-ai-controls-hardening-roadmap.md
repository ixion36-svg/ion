<!-- ion-doc:type=ROADMAP -->
<!-- ion-doc:title=Bob AI-Controls Hardening — Roadmap -->
<!-- ion-doc:subtitle=Tighten prompt trust boundary + grounding across Bob's LLM surfaces while retaining expert output -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:date=2026-08-03 -->

# Bob AI-Controls Hardening — Roadmap

Motivated by a full audit of Bob's LLM stack (prompt construction, grounding,
determinism, guardrails, injection resistance) run 2026-08-03. **Owning
principle:** *tight controls without degrading expert output* — every change
must fail safe (toward abstention) and must not blunt the analyst-grade
analysis Bob produces.

The autonomous investigation path (`investigation_service`) was already strong:
`<input_data>` trust boundary + per-field sanitiser, enum-whitelist verdict
persistence, multi-seed self-consistency → inconclusive, confidence circuit
breaker, temp-0 verifier, fail-safe JSON parsing. The gaps were concentrated in
the **on-demand advisory surfaces** and in a few **asymmetries** where the
autonomous path's defenses were not mirrored elsewhere.

## Phase 1 — SHIPPED v0.65.0 (2026-08-03)

- Shared `services/prompt_safety.py` (`sanitize_untrusted` / `wrap_untrusted` /
  `UNTRUSTED_DIRECTIVE`) — the `<input_data>` trust boundary lifted out for reuse.
- On-demand surfaces fenced + injection-scrubbed: `ai_api` `/analyze/alert`,
  `/triage/suggest`, `/case/generate`; `bob_analysis_api` case-data block.
  (This also closed the old "no size cap on /analyze + /triage alert JSON" gap
  via `sanitize_untrusted(max_chars=6000)`.)
- AI **chat** hardening: drop client-supplied `system`-role messages (jailbreak
  vector); temperature ceiling clamped 2.0 → 1.0; RAG + uploaded-file context
  sanitised.
- **Encoded-input rule** in every chat persona — decode & interpret pasted
  hex/base64, always answer in English, never mirror the input encoding
  (fixed Bob replying in hex to a pasted hex blob).

## Phase 2 — SHIPPED v0.66.0 (this release)

- **P2a — sanitise RAG in the *investigation* system prompt.** `build_rag_context_blocks`
  (`alert_prompt_service`) now runs every KB / exemplar / playbook / TI-report /
  skills block through `sanitize_untrusted` before it enters the highest-trust
  system-prompt region. Benefits both the autonomous path and the on-demand
  case-analysis path (which reuses the same builder).
- **P2b — code-enforce field-presence grounding on the main path.** The
  autonomous `_compute_confidence` now applies a conservative, fail-soft penalty
  when a *majority* of Bob's `key_observations` cite values that appear nowhere
  in the alert the model saw (`prompt_alert`). Confidence-only nudge toward the
  circuit breaker — it never hard-drops observations or rewrites the verdict —
  mirroring the citation discipline the auto-investigate path already enforces
  via `parse_and_validate`.
- **P3b — harden the closure / executive-summary call.** `_background_ai_case_summary`
  (`case_lifecycle_api`) gains an analyst persona + explicit anti-fabrication
  grounding instruction, and fences the case/notes context in `<input_data>` +
  the untrusted directive (previously the weakest-framed analytic call).

## Deferred — decision / design needed (not yet scheduled)

- **P3a — data-governance default posture.** PII anonymisation defaults **off**
  (`pii_anon_service`), while the fully-assembled prompt + raw model response
  persist to `investigations.prompt_snapshot` / `raw_response`. So the default
  posture writes un-redacted (sanitised-but-real) untrusted content + PII at
  rest. Flipping the default is a **deployment/compliance decision**, not a
  silent code change — options: (a) default PII-anon on for the persisted
  snapshot only, (b) gate raw-prompt persistence behind an explicit flag,
  (c) leave as-is and document. **Needs an owner decision before implementation.**
- **Streaming-chat PII tokenisation parity.** `/chat` tokenises user messages
  when PII-anon is enabled; `/chat/stream` does not. Detokenising a streamed
  response per-chunk is unreliable (tokens span chunk boundaries), so this is a
  genuine design problem, not a quick fix. Options: buffer-then-detokenise (loses
  streaming UX), or a boundary-aware detokeniser. Low priority (PII-anon off by
  default; local Ollama).

## Cadence

One release per phase (`X.Y.0`), affected-module tests only, 8-file bump +
signed tag + Docker, no-auto-action preserved. All Phase-2 changes fail safe
and are advisory — no new permission or schema.
