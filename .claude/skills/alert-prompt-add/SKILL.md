---
name: alert-prompt-add
description: Scaffold a new AlertPromptTemplate row — pick a matcher tier (rule_ids → rule_id_pattern → techniques → tactics → rule_groups), compose prompt_text, add the _DEFAULT_TEMPLATES entry and a matcher test. Use when extending Bob's prompt catalogue.
disable-model-invocation: true
---

# /alert-prompt-add — Add an AlertPromptTemplate

Bob, the SOC service user, resolves one `AlertPromptTemplate` per incoming
alert and writes the result into the `AIFeedback` ledger. Adding a template
means four things:

1. A `_DEFAULT_TEMPLATES` entry with the right matcher field(s) populated.
2. MITRE technique/tactic entries in `_TEMPLATE_MITRE_MAP` (keyed by template name).
3. A matcher test proving the new row wins for its alert and loses where it should.
4. Optionally a `_TEMPLATE_THRESHOLD_MAP` entry if the global confidence
   threshold is wrong for this alert class.

The current catalogue size is whatever this reports — don't trust a count
written into a doc:

```bash
grep -c '^        "name":' src/ion/services/alert_prompt_service.py
```

## When to use

- A new detection-engineering rule lands and needs an LLM investigation prompt.
- An existing rule's auto-closure quality is bad and you want a more specific matcher.

## Step 0 — orientation (delegate this)

Everything in this step is read-only context-gathering, and it is the single
biggest context cost in the task: `alert_prompt_service.py` alone is ~4,700
lines. **Dispatch it to a subagent** (`Explore`, breadth "medium") and work
from its summary — do not read these files into the main context yourself:

> Read and summarise, with line numbers: (1) the column list of
> `AlertPromptTemplate` in `src/ion/models/alert_prompt.py`; (2) the tier
> buckets in `AlertPromptRepository.find_matching` in
> `src/ion/storage/alert_prompt_repository.py`; (3) the line ranges of
> `_DEFAULT_TEMPLATES`, `_TEMPLATE_MITRE_MAP` and `_TEMPLATE_THRESHOLD_MAP`
> in `src/ion/services/alert_prompt_service.py`, plus two adjacent template
> dicts near the insertion point; (4) the `_make` helper and `session`
> fixture in `tests/test_alert_prompt_matcher.py`. Do not quote whole prompt
> bodies — they are hundreds of lines each.

Read in the main context only the file you are about to edit, and
`docs/AI_OUTPUT_CONTRACT.md` when you reach step 2.

## Steps

1. **Choose the matcher tier.** `find_matching` buckets every enabled
   template into five tiers and returns the first non-empty bucket's head.
   Tier N always beats tier N+1 **regardless of `priority`**:

   | Tier | Column | Shape | Notes |
   |---|---|---|---|
   | 1 | `rule_ids_json` | JSON list | exact membership on the alert's rule id |
   | 2 | `rule_id_pattern` | regex string | `re.search`; invalid regex is logged and skipped, not raised |
   | 3 | `mitre_techniques_json` | JSON list | **parent↔sub tolerant both ways**: `T1059` matches `T1059.001` and vice versa |
   | 4 | `mitre_tactics_json` | JSON list | `TAxxxx` id OR lowercase tactic name |
   | 5 | `rule_groups_json` | JSON list | set intersection with the alert's `rule.groups` |

   Two things that table implies:

   - **Populating several matchers on one row is normal, not an error.** The
     shipped "Credential Access" row sets `rule_groups` *and*
     `rule_id_pattern` so it catches both well-named rules and group-tagged
     ones. For any single alert, the first tier that hits classifies it.
   - **Ties within a tier are resolved, not rejected.** Candidates arrive
     pre-sorted `priority ASC, updated_at DESC`, so the lowest `priority`
     number wins and a recent edit breaks a remaining tie. Lower `priority`
     = higher precedence (inverted vs. Playbook semantics). If you *intend*
     to outrank an existing row in the same tier you must give it a lower
     number — adding a row at the default `100` behind an existing `30`
     achieves nothing.

2. **Compose `prompt_text`.** There is **no `output_schema` column and
   nothing to pin** — `AlertPromptService.render_system_prompt()` appends the
   output contract to every system prompt, and `_call_llm()` passes
   `response_format="json"`, which Ollama honours as a server-side guarantee.
   Read `docs/AI_OUTPUT_CONTRACT.md` now for the envelope. Your prompt body
   only has to:

   - Instruct the verdict in contract terms (`true_positive` /
     `false_positive` / `benign_true_positive` / `inconclusive`).
   - Reference only fields present on the alert payload at fire time
     (`data.win.eventdata.*`, `rule.*`, `host.*` …). ION ships air-gapped: no
     live external lookups. A VirusTotal **URL for the analyst to open** is
     fine; an instruction for the model to fetch it is not.
   - List any extra fields in `expected_outputs` — they are nested under
     `template_specific` in the response, keeping the envelope stable.

   Set `severity_hint` and a `description`; both surface in the admin UI
   (`src/ion/web/alert_prompt_api.py` exposes the CRUD surface).

3. **Add the seed entry.** It goes in `_DEFAULT_TEMPLATES` in
   `src/ion/services/alert_prompt_service.py` — **not** in `seed_alerts.py`
   or `scripts/seed_alerts.py`, which seed Elasticsearch *alerts* for
   development and have nothing to do with templates.

   MITRE lives in `_TEMPLATE_MITRE_MAP`, keyed by template name, so the
   template dicts stay readable; the seeder merges the two at insert time.

   `seed_default_templates()` keys on `name`, not on "table is empty": a new
   entry **is inserted on the next boot of an existing deployment**, and the
   top-up path fills `mitre_*` / `confidence_threshold_override` on rows that
   pre-date those columns, writing only where currently unset so operator
   edits survive. Pick a `name` that is unique and stable — it is the join key
   for both maps, the top-up path, and the Tier-6 export slug.

4. **Add a matcher test.** `tests/test_alert_prompt_matcher.py` already has
   the fixture (`session`, a SQLite file under `tmp_path`) and a
   `_make(repo, **kwargs)` helper taking the *unsuffixed* kwargs
   (`rule_ids=`, `mitre_techniques=` …) — `AlertPromptRepository.create` does
   the JSON encoding. Assert both directions:

   - your row wins for an alert that matches its tier;
   - your row **loses** to an existing higher-tier row — otherwise a broad
     `rule_groups` addition can be silently shadowed and you'd never know.

5. **Run locally.**
   ```bash
   pytest tests/test_alert_prompt_matcher.py -q --tb=short
   ruff check src/ion/services/alert_prompt_service.py
   ```

6. **Check the Tier-6 export.** `skill_publisher_service.py` exports template
   rows as Elastic Agent Skills `SKILL.md` folders consumed by
   `skill_loader.py` (Bob's Tier-6 matcher). The column → frontmatter mapping
   is in that module's docstring; note `matches_techniques` falls back to
   `["any"]` when `mitre_techniques_json` is empty, which makes a
   technique-less template match everything on that path. Populating the
   MITRE map in step 3 is what prevents that.

## Worked example

A real shipped row, trimmed: "Credential Access" — tiers 2 and 5 both
populated, `priority` 30 to outrank the default-100 rows, and no threshold
override, so it inherits the global `ION_BOB_CONFIDENCE_THRESHOLD`.

**Input — the `_DEFAULT_TEMPLATES` entry** (`alert_prompt_service.py`):

```python
{
    "name": "Credential Access",
    "description": (
        "Investigation guide for credential-access alerts — credential "
        "dumping, LSASS access, Kerberoasting, and pass-the-hash activity."
    ),
    "rule_groups": [
        "credential_dumping", "lsass", "mimikatz",
        "kerberoasting", "pass-the-hash",
    ],
    "rule_id_pattern": r"(?i)(credential.?dump|lsass|mimikatz|kerberoast|pass.the.hash)",
    "priority": 30,
    "severity_hint": "high",
    "prompt_text": (
        "You are investigating a credential-access alert. Determine which "
        "credential store was targeted (LSASS, SAM, NTDS.dit, Kerberos "
        "tickets, cached credentials, browser vaults). Identify the tool "
        "or technique used — Mimikatz, ProcDump, comsvcs.dll MiniDump, "
        "Rubeus, Kerberoasting via SPN enumeration, or pass-the-hash ..."
        # full body continues; it ends by assigning the verdict per the contract
    ),
    "expected_outputs": [
        "verdict",
        "mitre_techniques",
        "compromised_accounts",
        "recommended_actions",
    ],
},
```

**Its `_TEMPLATE_MITRE_MAP` entry** (same file, keyed by the name above):

```python
"Credential Access": {
    "techniques": ["T1003", "T1558", "T1550.002"],
    "tactics": ["TA0006"],
},
```

**Its `_TEMPLATE_THRESHOLD_MAP` entry**: none. Add one only when the class
warrants it — the shipped map raises noisy telemetry
(`"Sysmon Event 22 — DNS Query": 75`) and lowers critical classes
(`"Ransomware Indicators": 45`) so Bob still surfaces a take at moderate
confidence.

**Input — the test** (`tests/test_alert_prompt_matcher.py` idiom):

```python
def test_credential_access_regex_beats_group(self, session):
    repo = AlertPromptRepository(session)
    t_regex = _make(
        repo,
        name="credential-access",
        rule_id_pattern=r"(?i)(credential.?dump|lsass|mimikatz)",
        rule_groups=["credential_dumping"],
        priority=30,
    )
    # Tier-5 group candidate with a better priority number must still lose.
    _make(repo, name="broad-group", rule_groups=["credential_dumping"], priority=1)
    session.flush()

    alert = {
        "rule_id": "lsass-memory-read",
        "rule": {"groups": ["credential_dumping"]},
    }
    match = repo.find_matching(alert)
    assert match is not None
    assert match.name == t_regex.name
```

**Output — what Bob returns.** The envelope is fixed by the contract; only
`template_specific` is template-shaped, carrying the `expected_outputs`
fields:

```json
{
  "verdict": "true_positive",
  "confidence": "high",
  "severity": "critical",
  "summary": "Mimikatz-style LSASS memory read on dc01.corp.local by svc_backup.",
  "analyst_explanation": "A process opened LSASS with debug rights and read its memory - the standard way credentials are dumped. The account used is a service account that should never do this.",
  "technical_details": "GrantedAccess 0x1410 on lsass.exe from C:\\Users\\svc_backup\\AppData\\Local\\Temp\\pd.exe ...",
  "mitre": { "tactics": ["TA0006"], "techniques": ["T1003.001"] },
  "recommended_actions": [
    { "priority": "p1", "action": "Isolate dc01.corp.local", "owner": "ir" },
    { "priority": "p1", "action": "Force-reset svc_backup and all domain admin credentials", "owner": "it" }
  ],
  "suggested_closure_reason": "true_positive",
  "tuning_recommendation": { "rule_needs_tuning": false, "rationale": null, "suggested_change": null },
  "template_specific": {
    "compromised_accounts": ["svc_backup", "CORP\\administrator"]
  }
}
```

## What NOT to do

- **Don't put the seed row in `seed_alerts.py`.** Wrong file — it seeds
  Elasticsearch alerts.
- **Don't look for an `output_schema` or `circuit_breaker_*` column.** Neither
  exists. The per-template knob is `confidence_threshold_override` (integer,
  NULL = use the global env default).
- **Don't reference live external feeds** in `prompt_text`. Air-gapped.
- **Don't add a broad `rule_groups` row at the default `priority`** expecting
  it to take over from a specific one. It won't — and if it shares a tier with
  an existing row at a lower number, it will never fire at all.

## Failure modes

- **New template never fires** — almost always tier shadowing: a tier-1/2 row
  already claims the alert, or a same-tier row has a lower `priority`. Prove
  it with `find_matching` in a test, not by reading the catalogue.
- **New template fires on everything** — an over-broad `rule_id_pattern`
  (an unescaped `.` where you wanted a literal dot), or an empty
  `mitre_techniques_json` hitting the Tier-6 export's `["any"]` fallback.
- **Row doesn't appear after deploy** — name collision with an existing row.
  The seeder skips by `name` and takes the top-up path instead of inserting.
- **`AIFeedback` duplicate fire** — the reader dedups by `MAX(id)` per
  (`alert_id`, `alert_prompt_template_id`) over the lookback window, indexed
  as `ix_ai_feedback_alert_template`. If a new fire path bypasses that read,
  fire-time and case-close writes both pile up.
