# L3 Module 5 — Detection-engineering loops — Research Dossier

_Authoring source-of-truth for `seed_courses.py` ship of L3 M5 in v0.12.11._

Audience: L3 detection-engineer / purple-team analyst. Prereq: L1 M7 (Escalation Workflow), L2 M8 (Hunt-to-Detection Capstone), L3 M1-M4.

## Module shape

8 lessons (7 reading + 1 quiz), 9 questions, ~14k words at BTL1/SANS depth.

## Learning objectives

1. Author a **TuningProposal** ticket after a gap finding with the eight required fields.
2. Apply the **acceptance-criteria contract** — what re-test validates the fix.
3. Run the **gap-fix verification re-test** with the same atomic + same scoping.
4. Detect **regression** — fix held vs fix slipped — across releases.
5. Operate the **lifecycle KPI dashboard** — FP rate, FN rate, drift, deprecation triggers.
6. Convert findings into **TIDE submissions** (the cross-link to L2 M8).
7. Recognise the **close-the-loop pattern**: gap → ticket → fix → re-test → close.
8. Report the loop's **headline metrics** to leadership.

## Lesson plan

### L5.1 — The detection-engineering loop in 30 seconds
~1800 words. The full loop, end-to-end:

```
purple-team exercise → gap finding (Tier 2/3/4) → TuningProposal ticket
        → engineering work (rule / parser / agent) → re-test
        → close (loop fired) OR re-open (loop didn't)
```

The pattern is the closed-loop control system. The L3's job is to ensure every gap goes through the full loop — not "we opened a ticket, must be fine." Without the re-test, fixes silently slip.

Knowledge check: 1 SINGLE — name the closure step that distinguishes a real fix from a paper one.

### L5.2 — TuningProposal authoring: the eight required fields
~2000 words. Building on M1.7 (which introduced TuningProposals briefly), M5.2 specifies the canonical eight:

| Field | Purpose |
|---|---|
| **Exercise id** | Traceback to the scorecard row |
| **Tier** | Routes to the correct backlog (M1.6 / M4.5 cross-link) |
| **Owner-of-fix** | Named team / role; not a person |
| **Technique** | ATT&CK technique + sub-technique for cross-rule rollups |
| **Reproducer** | Exact test command, host, timestamp, SIEM screenshot |
| **Proposed fix** | L3's first-pass suggestion |
| **Acceptance criteria** | What re-test validates the fix |
| **Re-test schedule** | When the close-the-loop will be measured |

The acceptance-criteria field is load-bearing. M1.7 made the point: *the L3's reflex is to write the acceptance criteria before the ticket reaches engineering*. Without it, fixes get marked done without re-testing and the loop silently breaks.

Worked: a TuningProposal for the M1.6 worked example (T1059.001-3 — Tier 2 detection gap).

Knowledge check: 1 MULTI — pick the eight required fields from a list.

### L5.3 — The acceptance-criteria contract
~1900 words. Acceptance criteria are testable and reproducible. Bad acceptance criteria:
- "The rule should fire."
- "Detection should improve."
- "Latency should be lower."

Good acceptance criteria:
- "Re-run T1059.001-3 on PT-LAB-04 between 14:00-14:30. Expected: rule 'Suspicious encoded PowerShell' fires within 5 minutes, severity high. SIEM screenshot attached at re-test."

The contract:
1. **Specific test** — atomic id, host, window.
2. **Specific outcome** — rule name, severity, latency.
3. **Specific evidence** — SIEM screenshot / Detection Engine alert id.
4. **Time-boxed** — the re-test happens within a window.

Anti-patterns:
- Acceptance criteria written by engineering after the fix ships ("the fix worked because we say it did").
- Acceptance criteria that change post-fix to match what the fix actually does.
- Acceptance criteria that the L3 can't verify independently.

Knowledge check: 1 SINGLE — pick the testable acceptance criterion.

### L5.4 — Gap-fix verification: running the close-the-loop re-test
~2000 words. The re-test is the *exact same atomic, exact same scoping* as the original. Re-running with different parameters is a *new* exercise, not a verification.

Pre-re-test checklist:
1. Confirm the engineering ticket is marked done.
2. Confirm any required deploys have rolled out (parser updates need a few hours; rule deploys are fast).
3. Set the same exercise window length as the original.
4. Pre-brief the L1 / L2 / IR shifts (M1.3 cross-link).

Re-test execution:
1. Run the exact same atomic test on the exact same host (or the snapshot equivalent).
2. Wait the same 30 minutes (M1.6 cross-link).
3. Pivot through the four tiers in order (M1.6 again).
4. Compare outcome to the acceptance criterion.
5. Close-or-re-open.

The four outcomes:
- **Closes**: outcome matches acceptance. Ticket closes; scorecard row updates from "open" to "resolved".
- **Partial**: outcome closer to acceptance but not exact. Ticket stays open, scorecard updates to "improved", more engineering work scheduled.
- **No change**: outcome unchanged. Ticket stays open, the engineering team reviews — was the fix wrong, or did the fix not deploy?
- **Worse**: outcome regressed. Engineering team reviews; rollback may be needed.

Knowledge check: 1 SINGLE — pick the right scope for a re-test.

### L5.5 — Regression tracking across releases
~1800 words. A fix that closed last quarter doesn't necessarily hold this quarter. Detection rules drift:
- ECS field renames (M2 L8 / M4 L3 cross-links).
- Parser updates that change field shape.
- Sysmon config drift on individual hosts.
- ATT&CK version bumps that change the technique mapping.
- Vendor TTP shifts (the actor swaps tooling).

Regression tracking: **re-test prior-quarter passing techniques quarterly**. If they still pass, the fix held. If they don't, raise as new gaps.

The quarterly process:
1. List all prior-quarter Tier-1 results.
2. Pick a sample (10% of the list, or all critical techniques, whichever is larger).
3. Re-run each atomic on the same host.
4. Compare to the prior result.
5. Drift findings get fresh TuningProposals.

Worked: Q3's regression sample of 8 prior-Tier-1 techniques. 7 still Tier-1, 1 dropped to Tier-2 (rule was deprecated by mistake during a parser refactor in Q3 W6). New ticket; fix-and-re-test-and-close.

Knowledge check: 1 MULTI — pick the regression triggers.

### L5.6 — Lifecycle KPIs and the FP/FN drift signal
~1900 words. M1.7 introduced scorecard KPIs (coverage, latency, time-to-fix, breadth). M5.6 adds the *rule-level* KPIs that feed the scorecard:

| KPI | Computed | Threshold |
|---|---|---|
| **FP rate (weekly)** | analyst-flagged FPs / total alerts | Drift > 50% from backtest prediction → re-tune |
| **TP rate (sample, quarterly)** | sample 10 alerts; TPs / 10 | < 30% → re-tune (per L2 M8 G2) |
| **Mean time to triage (hours)** | alert ack time minus alert fire time | > 4h on Critical → routing problem |
| **Drift signal** | FP rate quarter-over-quarter delta | > +30% qoq → investigate root cause |
| **Deprecation triggers** | TTP no longer in profile / vendor adds first-party / replacement covers superset | Any → schedule deprecation review |

These KPIs get tracked per-rule. The detection-engineering team's quarterly review picks the worst-performing rules and either tunes them, replaces them, or deprecates them.

Knowledge check: 1 SINGLE — pick the FP-rate threshold.

### L5.7 — TIDE submissions: from candidate to production
~1700 words. The bridge to L2 M8 (Hunt-to-Detection Capstone). Every passing rule eventually gets submitted to TIDE for production deployment.

The submission flow:
1. L3 completes the close-the-loop re-test (M5.4).
2. Rule body is locked (no further tuning).
3. Five-gate metadata is complete (G1-G5 from L2 M8).
4. PR to the TIDE rule repository.
5. CI runs (schema validation, ATT&CK cross-check, smoke-test against 7d preview).
6. Deploy to production via Detection Engine API.

The L3's role here: confirm the rule's metadata is correct before submitting. The detection-engineering team owns the rule body; the L3 owns the *post-rule lifecycle* (FP/FN tracking, drift, regression). The handoff is at TIDE submission.

Knowledge check: 1 SHORTANSWER — name the load-bearing pre-submission check.

### L5.8 — Capstone quiz
2 questions covering the loop's closure step + acceptance-criteria recognition.

## Quiz blueprint (9)

- L5.1 — 1 SINGLE (closure step)
- L5.2 — 1 MULTI (eight required fields)
- L5.3 — 1 SINGLE (testable acceptance)
- L5.4 — 1 SINGLE (re-test scope)
- L5.5 — 1 MULTI (regression triggers)
- L5.6 — 1 SINGLE (FP rate threshold)
- L5.7 — 1 SHORTANSWER (pre-submission check)
- L5.8 — 2 capstone

## References

- L1 M7 (Escalation Workflow), L2 M8 (Hunt-to-Detection Capstone), L3 M1-M4.
- ION's TuningProposal model (`services/tuning_proposal_service.py`).
- Florian Roth — Detection KPIs.

---

_Implementation: append `mod5 = _add_module(...)` after `mod4`'s quiz, before `return course`. Print → "5 modules, 40 lessons"._
