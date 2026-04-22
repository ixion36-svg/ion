# AI Investigation Output Contract

Every LLM-driven investigation in ION returns a single JSON object conforming
to this contract. The contract is enforced in two places:

1. `AlertPromptService.render_system_prompt()` appends the schema and the
   rules to every system prompt (see `src/ion/services/alert_prompt_service.py`).
2. `InvestigationService._call_llm()` passes `response_format="json"` to
   `OllamaService.chat()`, which forwards it as `format: "json"` to Ollama's
   API so the model cannot emit anything but valid JSON.

The parser `_parse_llm_json()` in `investigation_service.py` is defensive — it
normalises synonyms, fills safe defaults, and keeps back-compat fields so
existing callers don't break.

## Required envelope

| Field | Type | Notes |
|---|---|---|
| `verdict` | enum | `true_positive` \| `false_positive` \| `benign_true_positive` \| `inconclusive` |
| `confidence` | enum | `low` \| `medium` \| `high` |
| `severity` | enum | `info` \| `low` \| `medium` \| `high` \| `critical` |
| `summary` | string | 1–2 sentences, executive audience |
| `analyst_explanation` | string | Plain-language for an L1 analyst |
| `technical_details` | string | Expert-level analysis, with exact field values |
| `mitre` | object | `{ tactics: ["TA0002"], techniques: ["T1059.001"] }` |
| `recommended_actions` | array of object | Each: `{ priority: p1\|p2\|p3, action, owner: soc\|ir\|it\|user\|auto }` |
| `suggested_closure_reason` | enum | Matches `CaseClosureReason` (see `models/alert_triage.py`): `true_positive` \| `false_positive` \| `benign_true_positive` \| `duplicate` \| `insufficient_data` \| `not_applicable` |
| `tuning_recommendation` | object | `{ rule_needs_tuning: bool, rationale: string\|null, suggested_change: string\|null }` |

## Optional envelope (populate only if relevant)

| Field | Type | Notes |
|---|---|---|
| `iocs` | array of object | Each: `{ type, value, confidence, note }`. Types: `sha256`, `md5`, `ipv4`, `domain`, `url`, `file_path`, `process_name`, `command_line`, `registry_key`, `email`, `user`, `host` |
| `affected_assets` | array of object | Each: `{ type, identifier, role }`. Types: `host`, `user`, `account`, `service`. Roles: `source`, `target`, `transit` |
| `timeline` | array of object | Each: `{ ts (ISO8601), event, source }` |
| `kill_chain_phase` | enum | `reconnaissance` \| `weaponization` \| `delivery` \| `exploitation` \| `installation` \| `c2` \| `actions` \| `unknown` |
| `containment_state` | enum | `none` \| `partial` \| `full` \| `not_applicable` |
| `blast_radius` | object | `{ hosts_affected: int, accounts_affected: int, data_impact: string\|null }` |
| `references` | array of string | URLs: threat-intel reports, vendor KB articles, MITRE pages |
| `template_specific` | object | Template-defined fields (see `expected_outputs` on each `AlertPromptTemplate`) |

## Verdict semantics — why they match `CaseClosureReason`

The verdict enum is intentionally pinned to ION's case-closure enum so that
the AI's output feeds **directly into detection-engineering tuning metrics**.
A `false_positive` AI verdict rolls straight into the FP rate per rule, and
`tuning_recommendation.suggested_change` becomes a tuning-backlog candidate.

- **`true_positive`** — the rule fired on genuinely malicious or unauthorised
  activity. Continue the incident-response workflow.
- **`false_positive`** — the rule fired but the activity is benign. **The
  rule needs tuning** — `tuning_recommendation.rule_needs_tuning` must be
  `true` and `suggested_change` must contain a concrete exclusion / refinement.
- **`benign_true_positive`** — the rule correctly identified the behaviour it
  was designed to catch, but that behaviour is authorised in this environment
  (vuln scanner, pentest window, approved admin tool). The rule is working as
  designed; `rule_needs_tuning` is usually `false` unless you want an
  environment-specific suppression.
- **`inconclusive`** — the model cannot decide. `technical_details` must
  explain what evidence is missing, and `suggested_closure_reason` defaults
  to `insufficient_data`.

## Ollama JSON mode

Ollama's `/api/chat` supports a `format` parameter. Passing `"format": "json"`
forces the model to emit valid JSON and is a hard guarantee from the server
side — the model cannot stream anything but a well-formed object.

`OllamaService.chat()` accepts a `response_format: Optional[str]` kwarg.
`InvestigationService._call_llm()` threads `response_format="json"` through
for every investigation. Non-investigation flows (the generic AI chat page,
streaming chat) do **not** set this flag.

## Adding fields to `template_specific`

Each `AlertPromptTemplate` can list `expected_outputs` — a list of field
names that the template wants the LLM to populate specifically for that
alert category. Those fields are nested under `template_specific` in the
response, keeping the envelope stable.

Example — the Ransomware template wants `ransomware_family`. When that
template fires, `template_specific.ransomware_family` should appear in the
output.

## Parser back-compat

Legacy callers that read `confidence` as an `int` 0–100 still work — the
parser also emits `confidence_level` as the new enum. Legacy callers that
read `recommended_actions` as `list[str]` still work — the parser flattens
the new structured list into strings while also exposing
`recommended_actions_structured`.

Legacy verdict `"benign"` is coerced to `"benign_true_positive"` so metrics
don't split across two values during the transition.
