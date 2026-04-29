# Labs — Design Dossier

_Source-of-truth for the v0.13.2+ Labs ship sequence. Read fully before any code._

Authored 2026-04-29 after v0.13.1 (Skills consumer) ship. Inputs:
1. The post-curriculum backlog: Labs (interactive, link into ION investigation queue).
2. The existing `Lesson` model already supports `LessonType.LAB` + `lab_target_url` (defined v0.11.2).
3. The `Question` model attaches to any Lesson — including LAB lessons — for verification.

---

## 1. Executive summary

The Lab is the curriculum's **practice surface**: the gap between *reading about T1059.001* (which the L1/L2 modules cover well) and *triaging a real T1059.001 alert in ION's investigation queue* (which only an exercise can teach).

Three integration scopes are possible. The biggest design surprise from the v0.11.2 model is that **the foundational scope is much cheaper than I initially estimated** — `LessonType.LAB` already exists, `lab_target_url` already exists, the verification path via `Question` rows already exists. The first ship is content + a tiny UI tweak.

**Recommended sequence:**

| Ship | Scope | Effort | New surface area |
|---|---|---|---|
| **v0.13.2** | Foundational labs — 6 LAB-type lessons targeting ION URLs with verification quizzes | ~40k tokens | Content only; existing schema |
| **v0.13.3** | Lab fixtures — seed mock alerts/cases/observables on lab launch so the lab has predictable content to investigate | ~80k tokens | One new table + seed runner |
| **v0.14.0** | Adaptive labs — grading hooks watch the analyst's actions in ION and score against expected | ~200k tokens | New tables + service + UI |

Ship 1 unlocks "labs are real" for users; ships 2-3 deepen the experience.

---

## 2. The problem

After completing the L1 / L2 / L3 curriculum, an analyst has read about every TTP they need to triage. They've answered quizzes about the right action. **They've never actually triaged an alert in ION's UI.**

The gap is bigger than it looks:
- The reading lesson teaches *what to do*; the analyst doesn't have to do it.
- The quiz tests *recognition* of right answers; not generation.
- The actual triage involves clicking through five panels, building queries, pivoting between alerts/cases/observables, deciding which actions are next.

Labs close this gap. The analyst gets a target ("triage this alert"), works inside ION's actual UI, and answers verification questions the lab uses to score them.

---

## 3. What the existing schema already supports

The `course.py` model from v0.11.2 already carries:

```python
class LessonType(str, Enum):
    READING = "reading"
    QUIZ = "quiz"
    LAB = "lab"   # hands-on link into ION, with verification questions

class Lesson(Base):
    ...
    lesson_type: ... default=LessonType.READING
    content_md: Text   # for LAB: the task description + the link
    lab_target_url: Optional[String(500)]   # the URL into ION
    questions: List[Question]   # verification questions
```

A LAB lesson already:
- Has a *task description* in markdown (content_md).
- Has a *target URL* the analyst clicks through to inside ION.
- Has *verification questions* the analyst answers based on what they saw.
- Reuses the existing `UserLessonProgress` for completion tracking.
- Reuses the existing `UserAnswer` for question-by-question scoring.
- Counts toward `_recompute_enrolment_completion()` and the `score_pct` rollup.

So **a basic lab is one row in `lessons` with `lesson_type=LAB`, plus 4-6 rows in `course_questions`**. No schema changes needed for the foundational scope.

---

## 4. Three scopes

### Scope A — Foundational labs (v0.13.2)

**What ships:** 6 LAB-type lessons authored across L1 / L2 / L3, each targeting a specific ION URL with verification questions about what the analyst should have seen / done.

Examples:
- *L1 lab:* "Triage the open `Suspicious encoded PowerShell` alert in `/alerts`. Confirm or refute the verdict; pick the right closure reason." Links to a pre-existing alert in ION's queue. Verification: 4 questions about the alert's MITRE technique, the parent process chain, the right closure-reason value, and the next escalation step.
- *L2 lab:* "Hunt for AS-REP Roasting on the `winlogbeat-*` data view. Find any `event.code:4768 AND PreAuthType:0` events in the last 7 days." Links to `/discover?_a=...`. Verification: 3 questions about the count, the affected user, and the right ATT&CK technique.
- *L3 lab:* "Open Caldera at `caldera.local:8888`. Stand up a sandcat agent on `PT-LAB-04`. Confirm beacon arrival in the agent panel." Verification: 3 questions about the agent's `paw`, `group`, and beacon cadence.

**New code:** None. Content only — a few rows in `seed_courses.py` for these labs. Maybe a small UI tweak: lab pill colour distinct from quiz pill (current behaviour: LAB lessons render in the same style as READING).

**New schema:** None.

**Limitations:**
- The lab's "target URL" is fixed; if the alert at the URL is dismissed / resolved, the lab can't be re-attempted with the same content.
- No environmental setup; the lab assumes the operator's ION instance has the right alert / case data.
- No grading beyond verification quiz answers.

**Earned value:** Labs become a real curriculum primitive. Analysts get *something to do*. Most of the immediate user benefit comes from this scope alone.

### Scope B — Lab fixtures (v0.13.3)

**What it adds:** A new `LabFixture` table holding seed-data fixtures (mock alerts, fake cases, fake observables) that get inserted into the appropriate ION tables when the lab launches. Lab scenarios pre-create a controlled environment for the analyst to investigate.

**New schema:**

```sql
CREATE TABLE lab_fixtures (
    id SERIAL PRIMARY KEY,
    lesson_id INT REFERENCES lessons(id) ON DELETE CASCADE,
    name VARCHAR(255),
    -- Setup runs at lab-start; teardown at lab-complete
    setup_actions_json TEXT,    -- list of {action, target_table, payload} dicts
    teardown_actions_json TEXT,
    expected_state_json TEXT    -- for the optional Scope C grader
);

CREATE TABLE lab_attempts (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    lesson_id INT REFERENCES lessons(id) ON DELETE CASCADE,
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    fixture_state_json TEXT,    -- record of inserted-fixture ids for teardown
    UNIQUE (user_id, lesson_id, started_at)
);
```

**New code:**
- `services/lab_fixture_service.py` — apply / unapply setup / teardown.
- A `POST /api/lessons/{id}/lab-launch` route that creates a LabAttempt row, applies the fixture, returns the (possibly-modified) target URL.
- A `POST /api/lessons/{id}/lab-complete` route that runs teardown.
- UI: a "Launch Lab" button on LAB lessons that's distinct from "Start lesson"; counter of in-flight lab attempts.

**Earned value:** Labs become *replayable*. The fixture inserts a predictable alert into the queue; the analyst triages it; teardown removes it. The next analyst gets the same lab, fresh.

**Open questions:**
- How do fixtures coexist with real alerts? Tag with `is_lab_fixture=true` on the inserted rows; production rules ignore tagged data.
- What if a fixture is forgotten (analyst abandons the lab)? Daily cleanup job removes orphan fixtures > 24h old.
- Fixtures span multiple ION objects (alert + case + observables). The `setup_actions_json` is a list of inserts; each carries the table + payload.

### Scope C — Adaptive labs with grading (v0.14.0)

**What it adds:** The lab watches what the analyst did inside ION (queries run, alerts triaged, cases closed, KQL searches executed) and scores against the lab's expected actions. The verification quiz becomes optional reinforcement; the *primary* score comes from the lab's grading hooks.

**New schema:**

```sql
CREATE TABLE lab_grading_rules (
    id SERIAL PRIMARY KEY,
    lesson_id INT REFERENCES lessons(id) ON DELETE CASCADE,
    rule_type VARCHAR(64),      -- 'alert_closed_with_reason', 'kql_query_ran',
                                -- 'observable_added', 'case_created', etc
    expected_value_json TEXT,
    weight INT DEFAULT 1
);

ALTER TABLE lab_attempts ADD COLUMN
    grading_log_json TEXT,      -- captured analyst actions during the attempt
    grading_score INT;
```

**New code:**
- An *audit log subscriber* that records every relevant analyst action while a lab attempt is in-flight.
- A `lab_grading_service.py` that compares the captured log against the grading rules.
- UI: real-time progress bar on the lab page ("Step 2 of 4 detected: alert closed with reason `false_positive`").

**Earned value:** Labs become an *examination*. The lab can require the analyst to *actually do the right thing* (close the alert with the right reason, run the right KQL query, escalate to the right team) and reward only that — not just answer questions about what they should have done.

**Why deferred:** Big surface area. Audit-log subscribers integrate with the alert / case / observable services; the grading service has its own complexity. Worth it eventually but not the right first ship.

---

## 5. Foundational scope (v0.13.2) — full content sketch

Six labs, distributed across the three courses. Each is a single LAB-type Lesson row in `seed_courses.py`, with 3-5 verification questions.

### L1 labs (3)

**L1.M2.LAB1 — Read your first alert in `/alerts`**
- Module 2 (SIEM Fundamentals).
- Target URL: `/alerts` (any open alert that exists on the operator's instance, OR a fixture in Scope B).
- Task: pivot through alert detail; identify rule.name, rule.severity, host.name, user.name.
- Questions: which fields uniquely identify the alert? what's the closure-reason for a TP? what's the right escalation tier?

**L1.M5.LAB1 — Tag an observable**
- Module 5 (IOC Handling).
- Target URL: `/observables`.
- Task: add a new IOC observable; classify with TLP / PAP; check the watchlist hit log.
- Questions: which TLP value applies for an observable shared with the SOC team but not the public? what's the difference between `ignore_similarity` and a normal observable?

**L1.M7.LAB1 — Escalate via the runbook**
- Module 7 (Escalation Workflow).
- Target URL: `/cases?status=acknowledged`.
- Task: open an acknowledged case; follow the escalation runbook; close with the right reason.
- Questions: which closure reason fits "the actor's IP turned out to be a security scanner"? which fits "we missed the alert and it's now stale"?

### L2 labs (2)

**L2.M2.LAB1 — Hunt with KQL on `/discover`**
- Module 2 (KQL / EQL / ES|QL).
- Target URL: `/discover`.
- Task: build a KQL query that surfaces all `event.action: process-started` events on `host.name: <one specific host>` in the last 24 hours.
- Questions: which field carries the parent process? what's the ES|QL equivalent?

**L2.M8.LAB1 — Convert a hunt finding into a TIDE rule**
- Module 8 (Hunt-to-Detection Capstone).
- Target URL: `/cyab/tide` (or wherever ION's TIDE rule editor lives).
- Task: take a confirmed hunt finding from L2 M7; walk it through G1-G5; submit the rule.
- Questions: which gate's failure produced the most rejections in the team's recent history? what's a reasonable backtest sample size?

### L3 labs (1)

**L3.M3.LAB1 — Caldera operation end-to-end**
- Module 3 (Caldera operations).
- Target URL: `http://caldera.local:8888` (operator's local Caldera; lab assumes it's stood up).
- Task: deploy sandcat to PT-LAB-04; run a 3-ability adversary profile; capture the operation report.
- Questions: which planner did the operation use? what was the chain's total wall time? which abilities failed?

### What this looks like in `seed_courses.py`

For each lab — one `_add_lesson(...)` call with `lesson_type=LessonType.LAB`, `lab_target_url=...`, and content_md including the task description. Then 3-5 `_add_q(...)` calls for the verification questions. ~150 lines per lab × 6 = ~900 lines. Pure content authoring.

UI work: in `course_detail.html` and `lesson.html`, render LAB-type lessons with a distinct pill (cyan / "LAB"), a "Open in ION →" link to the `lab_target_url`, and the existing quiz UI for verification questions. ~30 lines of template diff.

---

## 6. Open questions for sign-off

Five things to confirm before I start coding:

1. **Scope sequence** — agree with `v0.13.2 = foundational, v0.13.3 = fixtures, v0.14.0 = grading`? Or different order?

2. **Lab count for v0.13.2** — 6 labs (3 L1 + 2 L2 + 1 L3) is the proposed cut. Could go to 8 (one per L1/L2/L3 module pair) or 4 (lighter ship). Which?

3. **Target-URL approach** — labs target *real* ION URLs the operator's instance must have data at (rather than fixtures). The first lab attempt may "fail" if the queue is empty. Acceptable for v0.13.2?

4. **Lab pass criteria** — by default, the verification quiz is what counts. Pass threshold matches the course's `pass_threshold` (typically 75%). Acceptable?

5. **`/my-courses` page** — currently the route exists in API + nav-link but no actual page route / template (noted while authoring v0.13.0 PDF certs). Do labs surface the lab-attempts list anywhere new, or do they just show up under the existing course-detail page?

---

## 7. Phased delivery

| Ship | What | When | Token estimate |
|---|---|---|---|
| **v0.13.2** | Foundational labs — 6 LAB lessons + UI tweak | Next | ~40k tokens |
| v0.13.3 | Lab fixtures — `lab_fixtures` + `lab_attempts` tables; setup/teardown | Following ship | ~80k |
| v0.14.0 | Adaptive grading — audit-log subscriber + grading rules + scoring | Future | ~200k |

If the user agrees to start with v0.13.2, the implementation plan is:
1. Author 6 LAB Lessons in `seed_courses.py` with verification questions.
2. Tweak `course_detail.html` + `lesson.html` to render LAB-type lessons with a distinct pill + "Open in ION →" link.
3. Confirm `_recompute_enrolment_completion()` already counts LAB-completed correctly (it should — labs use `UserLessonProgress` like any other lesson).
4. Bump version, build, smoke-test, commit, push.

---

_End of dossier. Ready for sign-off on scope + sequence._
