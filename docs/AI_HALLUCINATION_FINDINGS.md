# Why the triage model fabricates decoded payloads

2026-10-19. Found while comparing ION against Ollama and DAEDALUS on identical
`qwen2.5:3b-instruct` Q4_K_M weights. The control-plane differences turned out
to be configuration; this is the part that affects verdict quality.

## The symptom

Alert `win-ps-encoded-cmd`, whose decisive field is
`powershell.exe -EncodedCommand JABwAGEAdABoAA==`.

That base64 is UTF-16LE for **`$path`**. Neither backend got it, and both
asserted a decode with confidence:

| run | claimed decode | verdict |
|---|---|---|
| ION → Ollama | `powershell.exe -encodedcommand "cmd /c regsvr32 c:\windows\system32\notepad.exe"` | `true_positive` / high |
| ION → DAEDALUS | `whoami` | **`false_positive` / 0.95** |

The DAEDALUS run's fabrication was load-bearing: having decided the payload was
`whoami`, it dismissed a critical alert. A fabricated decode does not merely add
noise — it can invert the verdict.

## Root cause 1: the model has no base64 capability, and fails *stably*

Asked directly, five seeds, `temperature: 0`:

```
Decode this base64 string and reply with ONLY the decoded text: JABwAGEAdABoAA==
  seed 1..5  ->  "Bob"      (every time)
truth: $path
```

Identical and wrong at every seed. This is not a sampling problem, so neither
`temperature: 0` nor a fixed `seed` touches it, and self-consistency sampling
cannot detect it — five agreeing samples look like high confidence. Base64
tokenises into arbitrary fragments and the transform is byte-level; a 3B model
cannot do it, and nothing in the sampler makes it abstain.

## Root cause 2: the triage prompt asks the model to do it anyway

`alert_prompt_service.py:976` asks:

> "- Does the decoded/deobfuscated content reveal known malware or framework stager?"

The question presupposes a decode that never happened. Asked for decoded
content it does not have, the model supplies some.

## Root cause 3: the fix already exists and is not wired in

`src/ion/services/command_deobfuscate.py` is a correct, deterministic
UTF-16LE `-EncodedCommand` / `-enc` decoder. Its docstring states the intent
exactly:

> Returns `[{"field": …, "decoded": …}, …]` — the facts to inject into the LLM
> prompt so the model reasons over the *decoded* content.

It works:

```python
decode_powershell_encoded("powershell.exe -EncodedCommand JABwAGEAdABoAA==")
# -> ['$path']
```

It has **one caller**: `investigation_service.py:2195`. The triage prompt path
(`alert_prompt_service`, which renders the system prompt used by alert triage
and by `.local-test-bob.py`) never calls it. The deterministic answer is
computed in one code path and withheld from the one that needs it most.

## Root cause 4: the few-shot exemplar teaches the fabrication

`alert_prompt_service.py:3951-3965` uses this very alert as a worked example.
Its input shows only the blob; its gold output asserts a decode:

> `"summary":"Encoded PowerShell launched on WS-12, payload decoded to filesystem path manipulation."`
> `"analyst_explanation":"… The base64 string decoded indicates path-prep for a follow-on stager."`

Whoever wrote it decoded `$path` by hand — the conclusion is right. But the
exemplar demonstrates *asserting a decode conclusion from the blob alone*,
which is precisely the behaviour to avoid. The Ollama run echoed its wording
("a file path manipulation attempt") while inventing unrelated supporting
detail in `technical_details` — few-shot mimicry of the conclusion without the
reasoning.

## The fix, verified

Injecting ION's own decoder output into the user body and re-asking the same
3B model, same seed:

```
deobfuscated (decoded deterministically by ION, authoritative):
  process.command_line -> '$path'
  message -> '$path'
```

Result:

```
technical_details: "The encoded PowerShell command-line argument
  '-EncodedCommand JABwAGEAdABoAA==' was decoded to '$path'. …"
verdict: true_positive   confidence: high   severity: critical
contains "$path": yes     contains "whoami": no     contains "regsvr32": no
```

One deterministic fact removed the fabrication on the decisive field and left
the defensible verdict intact. It still reads `$path` as stager preparation,
which is over-reach from that evidence alone but is now *over-interpretation of
a real fact* rather than invented evidence — a normal analyst judgement, and
reviewable.

## Recommendations, in order

1. **Call `deobfuscate_alert()` in the triage prompt path** and render the
   results as an authoritative block, as its docstring already describes.
   Lowest effort, highest value, no new dependency, proven above.
2. **Fix the shape bug in `deobfuscate_alert`.** `_CMD_FIELDS` are flat dotted
   keys (`"process.command_line"`), so against a nested alert
   (`alert["process"]["command_line"]`) the preferred-field scan misses
   entirely:
   ```
   nested dict -> [{'field': 'message', 'decoded': '$path'}]      # caught only via message
   flat keys   -> [{'field': 'process.command_line', ...}, ...]   # as intended
   ```
   Here it was saved by the blob also appearing in `message`. An alert carrying
   it only in a nested `process.command_line` returns `[]`. Flatten or recurse
   before scanning.
3. **Stop asking the model to decode.** Either supply the decode (1) or drop
   the question at `alert_prompt_service.py:976`; leaving it while supplying
   nothing is what invites the invention.
4. **Repair the exemplar** at `alert_prompt_service.py:3951-3965`: put the
   decoded value in its *input*, so the gold output's decode claim is grounded.
5. **Add a cheap post-hoc guard.** If a reply asserts a decode
   (`/decod(?:ed|es) to/i`) and no decoded fact was injected for that alert,
   flag the verdict for review. Catches this whole class, including fields no
   deterministic enricher covers yet.
6. **Generalise the principle.** Anything the model cannot compute should be
   computed before it is asked: hex and URL encoding, timezone arithmetic, CIDR
   containment, hash reputation, string entropy, domain age. Each one asked
   rather than supplied is a hallucination surface.

## Not tested

- **Foundation-Sec-8B (the production model).** The run was in flight when the
  machine was stopped for a backup, so whether the fabrication persists at 8B
  is **unknown**. Worth repeating: all findings above are measured on 3B, and
  only root causes 2-4 are model-independent (they are prompt and pipeline
  facts). Root cause 1 must be re-measured on 8B.
- Whether the escalation tier (`bob_escalation_samples`, 1..5) would catch this.
  It samples the same model, and the base64 failure was identical across five
  seeds, so agreement there would be a false reassurance — but this was not
  measured end to end.

## Note on the two cradles

Neither Ollama nor DAEDALUS prevents this, and neither is meant to. DAEDALUS's
guardrails gate the *shape and route* of an answer — contract, seal, grants,
ledger — not its truth; its grammar happily certified `contract_ok: true` for
the reply that invented `whoami`. DAEDALUS's `evidence` channel is the right
*place* for decoded material ("material to examine rather than instructions to
follow"), but it performs no decoding either. This is an enrichment-layer
problem and ION already owns the solution.
