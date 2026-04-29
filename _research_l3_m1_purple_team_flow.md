# L3 Module 1 — Purple-team flow: ATT&CK → Atomic → Detection check

_Authoring source-of-truth for `seed_courses.py` ship of L3 M1 expansion in v0.12.7._

Audience: L3 detection-engineer / purple-team analyst. Prereq: L1 + L2 complete; comfort with PowerShell or Bash on a managed endpoint.

The existing v0.11.2-stub L3 M1 has 1 reading lesson + 1 quiz lesson. v0.12.7 expands it to 8 lessons (7 reading + 1 quiz) to match the L1/L2 depth bar.

---

## Module shape

8 lessons, ~14 questions. Existing Lesson 1 stays at position 1; existing quiz moves to position 8 and gains questions. Six new reading lessons fill positions 2–7.

## Learning objectives (module level)

1. Plan a single-TTP purple-team exercise from threat-profile selection through scorecard.
2. Pick an Atomic Red Team test that maps to the chosen ATT&CK technique.
3. Author the four-part **exercise notice** (date / window / host / TTP / blast radius / authoriser).
4. Run an Atomic test safely with proper clean-up.
5. Apply the **30-minute telemetry wait** before declaring a missed detection.
6. Classify the result into one of four fidelity tiers and route the gap to the right team.
7. Convert a missed detection into a `TuningProposal` and a scoreboard entry that trends quarter-over-quarter.
8. Avoid the eight common mistakes that wreck early purple-team programs.

## Lesson plan

### L1.1 — Why purple teaming beats annual pentests (existing — preserved)

Existing reading lesson. Covers pentest vs adversary emulation, purple-team flow diagram, four detection-fidelity tiers, scoping rules, worked T1059.001 cycle.

### L1.2 — Picking a TTP: threat profiles, ATT&CK Navigator overlays, sector-specific TTPs (NEW)

~2300 words. Covers:
- *What's a threat profile?* — your sector's adversaries (sourced from CTI: Mandiant M-Trends, CrowdStrike OverWatch, MITRE CTID Top Techniques, sector-ISAC reports) mapped to ATT&CK.
- *ATT&CK Navigator overlays* — using Navigator JSON to overlay multiple actors and find the high-frequency techniques.
- *MITRE CTID Top 20* — the empirically-most-used techniques across all incidents in CTID's corpus.
- *Decision rules* for picking which TTP to exercise next: highest-frequency in profile × lowest-coverage in current detections × highest-impact-if-undetected.
- *Worked* — pick T1059.001 (PowerShell) for a finance-sector org targeted by FIN7 / Conti / Rhysida. Justify with Navigator overlay.

Quiz: 1 SINGLE — given a sector + active CTI, pick the right next TTP.

### L1.3 — Authorisation, scoping, and pre-briefing (NEW)

~2200 words. Covers:
- *Authorisation chain*: CISO + IR lead in writing. The exact sentence: *"Authorised to execute T1059.001-3 (mshta encoded PowerShell) against host ABACWKS042 between 14:00 and 14:30 on 2026-04-27."*
- *Scoping constraints*: technique ID + host + time window + blast radius + authoriser.
- *Pre-brief format* — the EX-2026-04-001 exercise notice template (preserved from L1.1).
- *Pre-brief audience*: L1 shift on shift-change handoff, L2 in chat at exercise -1h, IR on standby at exercise +0.
- *Common mistake*: the verbal-only authorisation that doesn't survive a real-IR escalation. Always written, always referenceable.
- *Legal* — emulation is unauthorised access without the chain. Your own SIEM should catch it; legal will pick you up.

Quiz: 1 MULTI — pick valid components of an authorisation.

### L1.4 — Atomic Red Team: installation, invoking, and clean-up (NEW)

~2400 words. Covers:
- *What is Atomic Red Team*: open-source repo of small executable tests, one per ATT&CK technique, maintained by Red Canary.
- *Repo structure*: `atomic-red-team/atomics/T<ID>/T<ID>.yaml` + `atomic-red-team/atomics/T<ID>/<files>` for each technique.
- *Invoke-AtomicRedTeam* — the PowerShell module that loads + runs tests with prerequisite check, execution, and clean-up phases.
- *Linux-side*: shell-script atomics; `bash atomics/T<ID>/T<ID>-1.sh`.
- *Prereq vs Test vs Cleanup* — every atomic ships these; running cleanup is mandatory.
- *Selecting test number* — when an ATT&CK technique has multiple atomic tests (1, 2, 3...), pick by *fidelity to the actor* not by ease.
- *Worked* — install Invoke-AtomicRedTeam on a test workstation, run T1059.001-3, run cleanup, verify state matches pre-test.

Quiz: 1 SHORTANSWER — given a technique id, find the right atomic test path.

### L1.5 — MITRE Caldera as alternative; when agent-based emulation is right (NEW)

~2000 words. Covers:
- *Caldera*: MITRE-maintained agent-based adversary emulation framework (https://github.com/mitre/caldera).
- *Agent (`sandcat`)* runs on the target host and accepts orders from the Caldera server.
- *Adversary profiles* — chained TTPs that emulate a named actor (FIN6, APT3, etc.).
- *When Caldera over Atomics*: chained multi-step exercises (atomic-by-atomic doesn't capture chaining); long-running campaigns; multi-host lateral movement; testing C2 infrastructure detection.
- *When Atomics over Caldera*: single-TTP focus; the four-fidelity-tier scorecard wants atomic results; minimal blast-radius; air-gapped or sensitive estates where an agent is unwelcome.
- *Authorisation differences* — Caldera lands an agent; the agent IS the artefact; needs explicit removal-after.

Quiz: 1 SINGLE — pick when to use Caldera vs Atomics.

### L1.6 — Telemetry verification and the 30-minute wait; pivoting through the four tiers (NEW)

~2200 words. Covers:
- *The 30-minute wait* (preserved from L1.1, expanded). Half of perceived gaps disappear after coffee — EDR / SIEM ingestion lag is real.
- *Pivot path through the four tiers*:
  - *Tier-1 check*: did the alert fire? (Kibana Security alerts, Sentinel incidents, etc.)
  - *Tier-2 check*: search the SIEM for the expected event without the rule filter; is the event there?
  - *Tier-3 check*: is the field that should match the rule queryable? (parsing problem)
  - *Tier-4 check*: is the data source even ingested? (telemetry problem)
- *Worked* — T1059.001-3 fired without alert. The L3 walks through the four tiers in order, finds the event in `winlogbeat-*` (Tier-2), confirms the field exists (`process.command_line` populated), and concludes: detection-engineering gap. Tier-2 outcome.
- *Documenting the tier* — the exercise log must record which tier the result is, not just "pass/fail".

Quiz: 1 SINGLE — given a scenario, pick the correct tier.

### L1.7 — Scoring, scorecards, and quarter-over-quarter trending (NEW)

~2300 words. Covers:
- *The scorecard format* — one row per exercise with: date, exercise id, TTP, host, tier-result, latency, owner-of-fix, fix-status.
- *Aggregating to coverage* — what fraction of tested techniques in your threat profile fired Tier-1 last quarter? That's your *empirical detection coverage*.
- *Trending* — quarter-over-quarter coverage. The line goes up if your purple-team program is working.
- *Reporting up* — the CISO + board want the coverage number; they don't want the technique-by-technique gap list.
- *Reporting down* — detection-eng wants the gap list with priority order.
- *TuningProposal conversion* — every Tier-2 / Tier-3 / Tier-4 result generates a `TuningProposal` ticket. ION's automation models this exact flow (cross-link to ION's TuningProposal system; v0.10.3 onwards).
- *Worked scorecard* — sample 6-row scorecard from a fictional first-quarter program; identify the patterns.

Quiz: 1 SHORTANSWER — given the scorecard, compute the coverage percentage.

### L1.8 — Quiz capstone (existing — preserved + extended)

Existing 4-question quiz preserved. Extending with 1 additional question (so module total is 6 inline + 5 capstone = 11 questions module-wide).

## Quiz blueprint (10 questions total)

- L1.2 — 1 SINGLE (TTP-pick)
- L1.3 — 1 MULTI (authorisation components)
- L1.4 — 1 SHORTANSWER (atomic-test path)
- L1.5 — 1 SINGLE (Caldera vs Atomic)
- L1.6 — 1 SINGLE (tier classification)
- L1.7 — 1 SHORTANSWER (coverage math)
- L1.8 — 5 capstone (existing 4 + 1 new)

## Cross-references

- L1 modules: M5 IOC Handling (Tier-1 alert), M7 Escalation Workflow (TuningProposal routing).
- L2 modules: M8 Hunt-to-Detection (TuningProposal lifecycle).
- ION features: TuningProposal model (v0.10.3), AlertPromptTemplate scorecard.

## References

- Atomic Red Team — https://github.com/redcanaryco/atomic-red-team.
- Invoke-AtomicRedTeam — https://github.com/redcanaryco/invoke-atomicredteam.
- MITRE Caldera — https://github.com/mitre/caldera.
- MITRE CTID Top Techniques — https://top-attack-techniques.mitre-engenuity.org/.
- Red Canary 2026 Threat Detection Report — annual TTP frequency data.

---

_End of dossier. Implementation: insert 6 new reading lessons between existing l1 and l2 in `_seed_l3` mod1; renumber existing l2 quiz to position 8; extend quiz with 1 question; leave the L3 M1 finalisation print to a future M2-shipping commit._
