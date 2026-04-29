# L3 Module 6 — Multi-host chain emulation — Research Dossier

_Authoring source-of-truth for `seed_courses.py` ship of L3 M6 in v0.12.12._

Audience: L3 detection-engineer / purple-team analyst. Prereq: L3 M1-M5.

## Module shape

8 lessons (7 reading + 1 quiz), 9 questions, ~14k words.

## Learning objectives

1. Design a **multi-host chain exercise** scoped to a specific named adversary.
2. Apply **per-host authorisation + pre-brief** for each host in the chain.
3. Run the chain via **Caldera's `look` planner** with cross-agent fact propagation.
4. Measure **per-phase response time** + **end-to-end chain time**.
5. Build the **chain-level scorecard** with kill-chain step columns.
6. Handle the **mid-exercise mistaken-IR-engagement** scenario.
7. Recognise **response-leverage** at the chain level — which step's containment kills the most downstream.
8. Convert the chain's findings into **cohesive TuningProposals**.

## Lesson plan

### L6.1 — From single-TTP to multi-host chain — when chains earn their weight
~1900 words. Single-TTP exercises measure fidelity per technique (M2-M3). Chain exercises measure *response time and containment leverage* — fundamentally different metrics. The chain earns its weight when the SOC is debating *response speed* questions: *can we contain in time? at which step is containment most effective?*

Comparison:

| Question the SOC asks | Right exercise |
|---|---|
| Do we detect T1059.001? | Single-TTP atomic |
| Do we detect FIN6? | Chain — multiple TTPs in FIN6's order |
| How fast do we contain a real intrusion? | Chain with response-time measurement |
| Which step's containment is most leveraged? | Chain with containment-leverage scoring |

Knowledge check: 1 SINGLE — given a question, pick chain or single-TTP.

### L6.2 — Designing the chain: pick adversary, map phases, identify hosts
~1900 words. Three steps:

1. **Pick the adversary** — from the org's threat profile (M1.2). FIN6 / FIN7 / Conti / etc.
2. **Map the kill chain** — 13-tactic ATT&CK phases the adversary touches; pick 4-8 representative TTPs.
3. **Identify host roles** — initial-access target, lateral target, impact target. Scale to 3-5 hosts; more is over-engineering.

The output: a chain plan document. Adversary, phase-by-phase TTP list, per-phase host, expected detection / response per phase.

Worked: a 4-host FIN6 chain plan.

Knowledge check: 1 MULTI — pick valid host roles for a chain.

### L6.3 — Per-host authorisation and pre-brief
~1700 words. Multi-host = multi-authorisation. Each host needs:
- **Written authorisation** with the four scoping constraints (M1.3 cross-link).
- **Owner sign-off** if the host has a different team than the L3.
- **Pre-brief** to L1 / L2 / IR for *each host*.
- **Network path approval** if the chain crosses network zones.

The L3's pre-exercise checklist:
1. Authorisation per host (written, with all four constraints).
2. Pre-brief published 1-4h before exercise start.
3. Abort contacts named for each host.
4. Snapshot any host carrying high-blast-radius abilities.

Knowledge check: 1 MULTI — pick valid pre-brief items.

### L6.4 — Caldera execution: `look` planner + cross-agent facts
~1900 words. M3.7 introduced the multi-host operation. M6.4 walks the *complete* execution loop:

1. Deploy sandcat to all hosts in scope; verify each beacon arrives.
2. Stand up the operation — adversary + all groups + `look` planner + plain-text obfuscator (so the SIEM sees the raw command for first runs).
3. Run; observe progress in the UI's *Operations* tab — abilities transition created → running → success/failure.
4. Verify cross-agent fact propagation in the *Facts* section (e.g. `host.user.password` discovered on agent A appears in agent B's input).
5. Capture the operation report when complete — total wall time, per-ability outcomes, facts collected.

Knowledge check: 1 SINGLE — pick the right planner for fact-driven multi-host.

### L6.5 — Measuring per-phase response time + end-to-end chain time
~1900 words. Two timing measurements:

| Measurement | What it tells you |
|---|---|
| **Per-phase response time** | Time from each phase's first event to SIEM alert + L1 ack |
| **End-to-end chain time** | Wall time from initial-access ability to impact ability |

The L3's reflex: pull these from the operation report (chain time) and the SIEM (per-phase response time). Both feed the chain-level scorecard.

Worked numbers from a FIN6 chain:
- Initial-access phase fired at T=0.
- L1 ack on the alert at T=4 min (response time = 4 min).
- Lateral phase fired at T=12 min.
- L1 ack on lateral alert at T=18 min (lateral response time = 6 min).
- Impact phase fired at T=24 min (encryption sandboxed).
- Chain ended at T=25 min total wall time.

Reading: SOC's response was *faster than the chain*. If TTR + containment-action time stayed under 25 min, the actor would have been contained pre-impact.

Knowledge check: 1 SHORTANSWER — compute chain time vs containment-time gap.

### L6.6 — Chain-level scorecard + kill-chain step columns
~1700 words. The chain scorecard adds columns beyond the single-TTP scorecard:

```
Chain ID: CH-2026-04-001 (FIN6 Compressed)
Hosts: PT-LAB-04, PT-LAB-05, PT-LAB-06
Caldera operation: 5d3e170e-...
Total wall time: 25 min
Per-phase TTR:
  Initial access (T1078.004):  4 min  — Tier-1 with concerns (severity should be Critical)
  Execution (T1059.001):       6 min  — Tier-1
  Persistence (T1547.001):     7 min  — Tier-1
  Cred access (T1003.001):    12 min  — Tier-2 (no rule fired)
  Discovery (T1018):          13 min  — Tier-1
  Lateral movement (T1021.002): 6 min  — Tier-1
  Collection (T1005):         16 min  — Tier-3 (parser gap on file events)
  Impact (T1486 sandboxed):   25 min  — Tier-1
Containment:
  Highest-leverage step: T1078.004 (kill at initial access stops the rest)
  Actual containment time: 27 min (post-exercise; SOAR not configured for auto-isolate)
Response gap: 25-min chain vs 27-min containment → ATT chain completed pre-response
TuningProposals:
  TP-2026-04-201: SOAR auto-isolate on T1078.004 detection → reduce containment to <5 min
  TP-2026-04-202: Cred-access (T1003.001) Tier-2 → write detection rule
  TP-2026-04-203: Collection (T1005) Tier-3 → fix parser
```

Knowledge check: 1 SINGLE — given a chain scorecard, identify the response gap.

### L6.7 — Handling mid-exercise mistaken-IR-engagement
~1500 words. Despite pre-briefs, sometimes the IR team engages mid-exercise — they see telemetry, didn't see / forgot the pre-brief, open a real case. The L3's recovery:

1. **Pause the operation immediately** (Caldera UI: *Pause*).
2. **Notify IR** — chat: *"This is exercise EX-2026-XX-XXX. See pre-brief at <link>. All activity originating from sandcat agents on PT-LAB-{04,05,06} between 14:00-15:00."*
3. **Confirm IR has stood down** — they explicitly acknowledge.
4. **Resume the operation** OR abort if confidence is low.
5. **Document the mis-engagement** on the exercise log + the chain scorecard. Add to the *common-failures* learning log so the next exercise's pre-brief is improved.

Common cause of mis-engagement: pre-brief in a chat the IR shift-on doesn't read. Fix: pre-brief in the *operational* chat (where IR works), not the L3's preferred chat.

Knowledge check: 1 MULTI — pick valid recovery actions.

### L6.8 — Capstone quiz
2 questions covering containment leverage + response gap math.

## Quiz blueprint (9)

- L6.1 — 1 SINGLE (chain vs single-TTP)
- L6.2 — 1 MULTI (host roles)
- L6.3 — 1 MULTI (pre-brief items)
- L6.4 — 1 SINGLE (planner pick)
- L6.5 — 1 SHORTANSWER (chain-vs-containment math)
- L6.6 — 1 SINGLE (response gap from scorecard)
- L6.7 — 1 MULTI (mis-engagement recovery)
- L6.8 — 2 capstone

## References

- L3 M3 (Caldera), L3 M5 (DE loops), L1 M7 (Escalation Workflow).
- MITRE Adversary Emulation Library (M2.6).
- Florian Roth — *Detection vs Response Time*.

---

_Implementation: append `mod6 = _add_module(...)` after `mod5`'s quiz, before `return course`. Print → "6 modules, 48 lessons"._
