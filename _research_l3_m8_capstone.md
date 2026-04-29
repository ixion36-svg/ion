# L3 Module 8 — Capstone — Full purple-team programme review — Research Dossier

_Authoring source-of-truth for `seed_courses.py` ship of L3 M8 in v0.12.14 (L3 COMPLETE)._

Audience: L3 detection-engineer / purple-team analyst. Prereq: L3 M1-M7.

## Module shape

8 lessons (7 reading + 1 quiz), 9 questions, ~12k words. Capstone style — emphasis on integration, less new material than M2-M7.

## Learning objectives

1. Plan a **quarterly purple-team programme** integrating all 7 prior L3 modules.
2. Run a **mid-quarter pivot** when CTI changes the threat profile.
3. Conduct the **quarterly retrospective** — what worked, what to change.
4. Integrate with the org's **risk register** and **leadership reporting**.
5. Recognise the L3's **career path** post-mastery — into IR, into detection-engineering, into security architecture.
6. Apply the **L3 maturity check** — what shipping looks like at full programme depth.
7. Spot **the L3 anti-patterns** that derail programmes after early success.
8. Hand off the programme to a successor when transitioning roles.

## Lesson plan

### L8.1 — The full cycle: plan → exercise → score → action → close
~1700 words. The L3's quarter:

```
Week 1-2: Planning — calendar + threat profile + per-exercise authorisation
Week 3-10: Execution — 1 in-hours per week + 1 OOH per month + 1 chain mid-quarter
Week 11: Quarterly audit — telemetry quality + coverage + parity
Week 12: Retrospective + report-up + plan next quarter
```

13 weeks per quarter; the L3's calendar is built around this rhythm.

Knowledge check: 1 SHORTANSWER — name the cycle phases.

### L8.2 — A worked Q3 programme plan
~1700 words. Real-shape Q3 plan:

```
Q3 2026 — 12-week programme
Threat profile: FIN6, FIN7, Conti, Carbanak, BlackCat (finance sector)
Tools: ART (single-TTP), Caldera (chain)
Targets: 12 in-hours single-TTP exercises + 4 OOH exercises + 1 full FIN6 chain (mid-quarter)

Week-by-week:
  W1: Planning + exercise calendar
  W2: First in-hours single-TTP (T1059.001)
  W3: Second in-hours single-TTP (T1003.001)
  W4: First OOH exercise (T1078.004 + paging test)
  W5: In-hours single-TTP (T1110.003)
  W6: In-hours single-TTP (T1547.001) + chain plan ready
  W7: FIN6 chain exercise (mid-quarter chain)
  W8: In-hours single-TTP (T1018)
  W9: OOH exercise (dual-window with W7's chain phases)
  W10: In-hours single-TTP (T1486 sandboxed)
  W11: Quarterly audit (M4 telemetry + M7 OOH parity)
  W12: Retrospective + report + Q4 plan
```

Knowledge check: 1 SINGLE — pick the right cadence balance.

### L8.3 — Mid-quarter pivot: CTI changes the threat profile
~1500 words. Mid-quarter, the sector ISAC publishes: *"BlackByte campaign pivots to T1556.006 (Federation Tampering)."* The L3's response:
1. Add T1556.006 to the threat profile.
2. Run a focused single-TTP exercise on T1556.006 within 2 weeks.
3. Compute parity with prior coverage.
4. If gap, raise TPs.
5. Update the rest of the quarter's calendar.

The pivot is *expected* — quarterly plans aren't sacred; CTI evolves. The L3's reflex: re-plan, don't stick to the original calendar at the cost of relevance.

Knowledge check: 1 MULTI — pick valid pivot triggers.

### L8.4 — Quarterly retrospective
~1700 words. End-of-quarter review:
- What worked (specific exercises that produced clean scorecards).
- What didn't (mistaken-IR-engagements, deferred TPs, re-test fail rate).
- What's the next quarter's investment? (more on-call? new SOAR playbook? CTI subscription?)

Format: a 30-min meeting with detection-eng + IR + L1 lead + L3. Each contributes one win, one ask, one observation. Capture in the programme retrospective doc.

Knowledge check: 1 SINGLE — pick valid retrospective output.

### L8.5 — Integrating with the org risk register
~1500 words. The org's risk register lists *risks* (data breach, ransomware, BEC). The L3's coverage data feeds the risk register's *likelihood* + *control effectiveness* columns:

- **Likelihood**: based on threat profile + sector data.
- **Control effectiveness**: based on M4 DML rating + M7 OOH parity.

The L3's reflex: re-rate the relevant risks each quarter using the audit data. If T1486 OOH coverage is weak, the *ransomware* risk's control-effectiveness rating drops.

Knowledge check: 1 SINGLE — pick the right L3 input to the risk register.

### L8.6 — Engaging with leadership: the quarterly board update
~1300 words. The L3 doesn't report directly to the board, but the CISO does — and the CISO needs the L3's data. The quarterly board package:
- One-page detection-coverage summary (M4 DML heatmap + M7 OOH parity).
- One-page response-time summary (in-hours / OOH MTTR).
- One-page TP backlog summary (open / closed / trend).
- The deferred-TP discussion (which gaps are out >90 days?).
- The investment ask (if any — bigger on-call / new SOAR / vendor 24/7).

Format simple, framing is M7.7 (trade-off). The L3 prepares the package; the CISO presents.

Knowledge check: 1 MULTI — pick valid board-package contents.

### L8.7 — Career path post-L3 + the L3 anti-patterns
~1300 words. Career trajectories:
- **IR / DFIR specialist** — go deeper into incident response.
- **Detection-engineering specialist** — own the rule-authoring pipeline.
- **Security architect** — design control frameworks.
- **CTI analyst** — focus on threat-actor profiles + research.

L3 anti-patterns (avoid):
- **Coverage-fatigue** — running exercises mechanically without learning.
- **Tool-tunnel-vision** — over-investing in ART or Caldera, missing the broader programme.
- **Ego on detection** — measuring success by rule-count rather than outcome.
- **Skipping retrospectives** — exercises become noise without the close-the-loop reflection.

Knowledge check: 1 MULTI — pick valid anti-patterns.

### L8.8 — L3 Capstone quiz
2 questions on cycle integration + post-L3 transition.

## Quiz blueprint (9)

- L8.1 — 1 SHORTANSWER (cycle phases)
- L8.2 — 1 SINGLE (cadence balance)
- L8.3 — 1 MULTI (pivot triggers)
- L8.4 — 1 SINGLE (retrospective output)
- L8.5 — 1 SINGLE (risk-register input)
- L8.6 — 1 MULTI (board package)
- L8.7 — 1 MULTI (anti-patterns)
- L8.8 — 2 capstone

## References

- All L3 prior modules (M1-M7).
- L1 + L2 capstones.
- The org's risk register / governance docs.

---

_Implementation: append `mod8 = _add_module(...)` after `mod7`'s quiz, before `return course`. Print → "8 modules, 64 lessons (L3 COMPLETE)"._
