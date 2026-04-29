# L3 Module 7 — Out-of-hours / off-shift validation — Research Dossier

_Authoring source-of-twin for `seed_courses.py` ship of L3 M7 in v0.12.13._

Audience: L3 detection-engineer / purple-team analyst. Prereq: L3 M1-M6.

## Module shape

8 lessons (7 reading + 1 quiz), 9 questions, ~14k words.

## Learning objectives

1. Recognise why **in-hours coverage doesn't imply OOH coverage**.
2. Characterise the **OOH response stack** — on-call rota, SOAR auto-isolate, paged escalation.
3. Design an **OOH exercise** with appropriate scoping (no surprise pages on the wrong shift).
4. Run a **dual-window comparison**: same chain in-hours and OOH; compare TTR.
5. Audit **OOH-specific gaps** — automation that only works during business hours, dashboards no one watches at 03:14.
6. Apply the **OOH-coverage parity** rule — every Tier-1 in-hours rule should also be Tier-1 OOH.
7. Convert OOH gaps into **specific TuningProposals** — typically SOAR / on-call routing.
8. Report **OOH posture** to leadership distinctly from in-hours.

## Lesson plan

### L7.1 — Why in-hours coverage doesn't imply OOH coverage
~1900 words. Ten things that change at 03:14 on Sunday:

1. L1 shift may be remote / reduced.
2. L2 / L3 not on shift at all (on-call rota only).
3. SOAR is the front line for containment.
4. Auto-isolation is the only sub-30-min response.
5. Critical alerts page on-call; non-critical wait for morning.
6. Detection-engineering not available (no rule tuning mid-incident).
7. Vendor support reduced (escalation paths longer).
8. Network team typically not on shift.
9. The actor knows this.
10. The MTTR target you measured in-hours is not the OOH MTTR.

The L3's reflex: every chain exercise needs an in-hours run AND an OOH run. The deltas tell the story.

Knowledge check: 1 SINGLE — pick the OOH-specific risk.

### L7.2 — The OOH response stack
~1900 words. The OOH-mode response infrastructure:

| Layer | In-hours | OOH |
|---|---|---|
| L1 detection | Full shift, multiple analysts | Reduced shift / on-call |
| L1 response | < 30 min ack | < 30 min only on critical (paged) |
| L2 / L3 | Same-day | Next business day |
| SOAR auto-isolate | Backup | Front line |
| IR engagement | Same-day | < 30 min for page-class alerts |
| Detection-eng tuning | Mid-day | Next business day |

The shift in centre-of-gravity: SOAR + on-call rota become load-bearing. If they don't work, OOH coverage doesn't exist.

Knowledge check: 1 MULTI — pick OOH front-line components.

### L7.3 — OOH exercise design + scoping
~1800 words. Designing an exercise that runs OOH without surprising the wrong shift. Three principles:
1. **Pre-brief the on-call rota explicitly** — name them in the pre-brief.
2. **Time-box tightly** — OOH exercises run < 1 hour to limit on-call disruption.
3. **Test specific OOH-load-bearing components** — SOAR auto-isolate, paged escalation, on-call routing.

The scoping document includes:
- Day / time of OOH exercise (typically a Tuesday morning 02:00-03:00 — middle of the OOH window, not weekend).
- Specifically which on-call team is on shift.
- The pre-brief target: the on-call person, named, with their mobile.
- The one specific component being tested (e.g. *SOAR auto-isolate on T1078.004*).
- Abort path that doesn't require waking the CISO.

Knowledge check: 1 MULTI — pick valid OOH scoping items.

### L7.4 — Dual-window comparison
~1900 words. Run the same chain in-hours AND OOH; compare TTR per phase. Worked numbers:

| Phase | In-hours TTR | OOH TTR | Delta | Cause |
|---|---|---|---|---|
| Initial Access | 4 min | 8 min | +4 min | On-call ack slower than shift |
| Execution | 6 min | 12 min | +6 min | L1 shift smaller |
| Cred Access | (Tier-2) | (Tier-2) | (same gap) | — |
| Lateral | 6 min | 25 min | +19 min | On-call routed wrong; second escalation needed |
| Impact | 5 min | 8 min | +3 min | Critical-page worked |

Reading: per-phase delta is small for critical-class alerts (L1 ack works on-call) but large for medium-class (lateral movement). The org's detection severity classification needs review — *lateral movement should be Critical-class, not Medium*, given the OOH delta.

Knowledge check: 1 SINGLE — pick the right interpretation of a dual-window result.

### L7.5 — Auditing OOH-specific gaps
~1700 words. OOH-specific gaps the L3 audits:
- **Dashboards no one watches** — the L1 shift's monitoring view doesn't have an on-call equivalent.
- **Automation that only works in-hours** — a SOAR playbook that calls a service desk that's only staffed 9-5.
- **Paged escalation paths** — does the alert reach the on-call within 5 min of fire?
- **Vendor support hours** — EDR's cloud control plane has 99.9% SLA but vendor Tier-3 only covers business hours.
- **Network team availability** — quarantining a host requires network-team approval; OOH this needs an explicit override path.

Each gap routes to a specific backlog: SOAR / SOC-process / vendor / on-call-procedure.

Knowledge check: 1 MULTI — pick OOH-specific gap classes.

### L7.6 — OOH-coverage parity
~1700 words. The parity rule: every Tier-1 in-hours rule should fire Tier-1 OOH at acceptable TTR. The L3 measures parity quarterly:

```
parity = OOH_Tier-1_count / in-hours_Tier-1_count
```

| Parity | Meaning | Action |
|---|---|---|
| 100% | Full parity | Maintain |
| 80-99% | Concerning | Investigate; specific rules / paths fail OOH |
| < 80% | Posture problem | The org has different security posture in-hours vs OOH; needs leadership discussion |

The OOH posture isn't *less coverage* — it's *the same coverage with longer TTR* if the org accepts that. But the L3 should make the trade-off *explicit and chosen*, not implicit and accidental.

Knowledge check: 1 SHORTANSWER — compute parity from numbers.

### L7.7 — Reporting OOH posture distinctly
~1500 words. Leadership reporting splits in-hours and OOH:

```
Detection coverage:
  In-hours:  78% (Q3, +5pp qoq)
  OOH:       64% (Q3, +3pp qoq)
  Parity:    82% (concerning; investigate)

Response time (median):
  In-hours:  9 min
  OOH:       14 min

Critical-class TTR:
  In-hours:  4 min
  OOH:       8 min  (acceptable)

Open OOH-specific TPs: 4
  TP-301: SOAR auto-isolate on T1078.004 (M6 finding) — high
  TP-302: Lateral-movement severity from Medium → High (M7 dual-window finding) — medium
  TP-303: On-call routing for cloud-team alerts — low
  TP-304: Vendor-support hours expansion (Tier-3 OOH) — leadership decision
```

The CISO needs to see both numbers; the OOH/parity gap is a leadership question (more on-call rota? bigger budget for SOAR?), not a detection-engineering one.

Knowledge check: 1 SINGLE — pick the right leadership report style for OOH.

### L7.8 — Capstone
2 questions covering parity computation + OOH gap routing.

## Quiz blueprint (9)

- L7.1 — 1 SINGLE (OOH risk)
- L7.2 — 1 MULTI (OOH front-line)
- L7.3 — 1 MULTI (scoping items)
- L7.4 — 1 SINGLE (dual-window interpretation)
- L7.5 — 1 MULTI (gap classes)
- L7.6 — 1 SHORTANSWER (parity computation)
- L7.7 — 1 SINGLE (leadership report)
- L7.8 — 2 capstone

## References

- L3 M5 (DE loops), L3 M6 (chain emulation), L1 M7 (Escalation Workflow).

---

_Implementation: append `mod7 = _add_module(...)` after `mod6`'s quiz, before `return course`. Print → "7 modules, 56 lessons"._
