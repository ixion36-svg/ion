"""Seed L1/L2/L3 demo courses (v0.11.2).

One substantial course per tier, one module each, multiple lessons per
module to set the quality bar. Re-runnable: deletes all courses with
slugs starting `demo-` first.

Run inside the ION container::

    docker exec ion python /tmp/seed_courses.py

Or copy + run::

    cat seed_courses.py | docker exec -i ion python -
"""
from __future__ import annotations

import json
from datetime import datetime
from sqlalchemy.orm import Session

from ion.storage.database import get_engine, get_session_factory
from ion.models.course import (
    Course, CourseLevel, CourseModule, Lesson, LessonType, Question,
    QuestionKind,
)
from ion.models.user import User


# ── Helpers ──────────────────────────────────────────────────────────────


def _admin_user(session: Session) -> User:
    return session.query(User).order_by(User.id.asc()).first()


def _add_course(
    session: Session, *, slug: str, title: str, level: str,
    description_md: str, estimated_hours: int, order_in_level: int,
    pass_threshold: int = 70, skill_keys: list[str] | None = None,
    author_id: int | None = None,
) -> Course:
    c = Course(
        title=title, slug=slug, level=level, description_md=description_md,
        estimated_hours=estimated_hours, order_in_level=order_in_level,
        pass_threshold=pass_threshold, published=True,
        skill_keys=json.dumps(skill_keys) if skill_keys else None,
        author_id=author_id,
    )
    session.add(c)
    session.flush()
    return c


def _add_module(session: Session, course: Course, *, order: int, title: str,
                description_md: str = "", estimated_minutes: int = 30) -> CourseModule:
    m = CourseModule(
        course_id=course.id, order=order, title=title,
        description_md=description_md, estimated_minutes=estimated_minutes,
    )
    session.add(m)
    session.flush()
    return m


def _add_lesson(session: Session, module: CourseModule, *, order: int, title: str,
                lesson_type: str, content_md: str, duration_min: int = 10,
                lab_target_url: str | None = None) -> Lesson:
    l = Lesson(
        module_id=module.id, order=order, title=title, lesson_type=lesson_type,
        content_md=content_md.strip(), duration_min=duration_min,
        lab_target_url=lab_target_url,
    )
    session.add(l)
    session.flush()
    return l


def _add_q(session: Session, lesson: Lesson, *, order: int, kind: str,
           stem_md: str, options: list[dict] | None, correct,
           explanation_md: str = "", points: int = 1) -> Question:
    q = Question(
        lesson_id=lesson.id, order=order, kind=kind, stem_md=stem_md.strip(),
        options_json=json.dumps(options) if options else None,
        correct_answer_json=json.dumps(correct),
        explanation_md=explanation_md.strip() if explanation_md else None,
        points=points,
    )
    session.add(q)
    session.flush()
    return q


# ── Cleanup ──────────────────────────────────────────────────────────────


def _cleanup(session: Session) -> None:
    demo_courses = session.query(Course).filter(Course.slug.like("demo-%")).all()
    if not demo_courses:
        return
    print(f"[cleanup] removing {len(demo_courses)} demo course(s)")
    for c in demo_courses:
        session.delete(c)  # cascade drops modules/lessons/questions
    session.flush()


# ── L1 — Alert Triage Fundamentals ───────────────────────────────────────


def _seed_l1(session: Session, author_id: int) -> Course:
    course = _add_course(
        session,
        slug="demo-l1-alert-triage-fundamentals",
        title="Alert Triage Fundamentals",
        level=CourseLevel.L1,
        description_md=(
            "Foundational L1 course covering what a SOC analyst actually does on shift: "
            "the alert lifecycle, severity rating, the difference between true positive / "
            "false positive / benign true positive, and when to escalate to L2. Pairs with "
            "ION's investigation queue and Bob (the AI analyst) so you can see real verdicts "
            "as you go.\n\n"
            "**By the end you'll be able to:**\n\n"
            "- Describe the five states of an alert from ingestion to closure\n"
            "- Apply severity ratings consistently using a documented rubric\n"
            "- Distinguish true positive, false positive, and benign true positive\n"
            "- Decide when to escalate vs close vs request more enrichment\n"
        ),
        estimated_hours=2,
        order_in_level=1,
        skill_keys=["alert-triage", "siem-operations"],
        author_id=author_id,
    )
    mod = _add_module(
        session, course, order=1,
        title="The alert lifecycle",
        description_md="From ingestion to closure — what every analyst needs to track.",
        estimated_minutes=45,
    )

    # Lesson 1.1 — reading: the lifecycle (rewritten v0.11.3 to BTL1 depth)
    l1 = _add_lesson(
        session, mod, order=1, title="What happens to an alert?",
        lesson_type=LessonType.READING, duration_min=22,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Name the five states every alert moves through, and identify which one a given alert is currently in
> 2. Explain who owns each state (L1 / L2 / detection-engineering / IT)
> 3. Read an `AlertTriage` row in ION and tell from its fields exactly where the alert sits in the lifecycle
> 4. Recognise the most common L1 anti-pattern (skipping triage and investigating everything) and avoid it
>
> **Prerequisites.** None — this is the first lesson of L1. You need access to ION's `/alerts` page to follow the worked example, but you can read this end-to-end first.

## Why this is the most useful mental model you'll learn

Working a SOC shift without an alert-lifecycle model is like working a hospital triage desk without one. You'll handle every patient with the same urgency, exhaust yourself, and miss the genuinely sick. The five-state model gives you a consistent answer to two questions you'll be asked thousands of times:

1. *What's the next thing that has to happen for this alert?*
2. *Whose problem is that — mine, or someone else's?*

Once you can answer those two questions in under five seconds for any alert, you're an effective L1.

## The lifecycle

Every alert — whether it came from Microsoft Defender, Splunk, Elastic Security, CrowdStrike, or a custom regex on a syslog feed — moves through these five states in order:

```mermaid
flowchart LR
    A[1. Ingested<br/>queue] --> B[2. Triaged<br/>L1 decision]
    B -->|investigate| C[3. Investigated<br/>L1 or L2 active work]
    B -->|fast close| D[4. Resolved<br/>verdict assigned]
    C --> D
    D --> E[5. Closed + Tuned<br/>detection-eng / SOC lead]
    B -. dup / FP signature .-> D
    C -. need senior eyes .-> F[Escalate to L2/L3]
    F --> D
```

The two dotted edges are the ones new analysts forget. From **Triaged**, you can shortcut directly to **Resolved** if the alert is a known false-positive signature, a duplicate of an open case, or matches a documented benign pattern. From **Investigated**, you can hand off to L2/L3 if the work is genuinely beyond your tier — that's not failure, it's good queue management.

### 1. Ingested

The detection rule fired and the alert landed in the queue. Nobody has looked at it yet.

What's true here:

- A row exists somewhere — for ION, it's an `AlertTriage` row with `status = OPEN`, `case_id IS NULL`, and `suggested_verdict IS NULL`
- The alert carries everything the rule emitted: rule name, MITRE techniques, host, user, source/destination IPs, the raw `kibana.alert.reason` one-liner, and any extracted observables
- **No human has formed an opinion yet.** Bob (the AI analyst) may have written a `suggested_verdict` if he's enabled, but the human-loop is unstarted

A common mis-read at this stage is judging severity from the *rule name*. A rule called `Suspicious PowerShell Execution` sounds urgent, but the same rule fires a hundred times a day on a SCCM-managed estate with PowerShell-driven config drift. The rule name is a *category*; the severity is whatever the analyst assigns after triage.

If your queue at the start of shift has 800+ unprocessed items, **that is a tuning problem, not a productivity problem.** No analyst can triage 800 items in eight hours without short-cutting. Fixing the noise belongs to detection-engineering, not to working harder.

### 2. Triaged

An analyst has eyeballed it for 10–60 seconds and made an initial decision. Triage is *not* investigation — it's the prioritisation step. Three outcomes are possible:

| Triage outcome | What happens next |
|---|---|
| **Worth investigating** | Move to state 3, decide whether L1 takes it or escalate up |
| **Duplicate / known FP signature** | Skip straight to state 4 with verdict `duplicate` or `false_positive` — record which signature matched |
| **Insufficient information to decide** | Set `status = ACKNOWLEDGED`, leave `suggested_verdict IS NULL`, and request enrichment (IP rep, hash lookup, asset-criticality lookup); revisit when enrichment comes back |

In ION, triage decisions show up as:
- `AlertTriage.status` — flips from `OPEN` → `ACKNOWLEDGED` (or → `CLOSED` if fast-closed)
- `AlertTriage.suggested_verdict` — the analyst's intent, not the final verdict (the final lives on `AlertCase.closure_reason` in state 5)
- `AlertTriage.assigned_to_id` — picks up the analyst who claimed it
- `AlertTriage.first_seen_at` — when triage *started*, used for SLA reporting

The discipline at state 2: **triage the whole queue first, then pick what to investigate.** Working alerts in arrival order is the reliable way to spend four hours on a false positive while a critical sits ignored at the bottom of the list.

### 3. Investigated

Someone is *actively working* the alert. They're pulling logs, looking up indicators on VirusTotal / OpenCTI / AbuseIPDB, checking whether a service account fired the rule (often benign) or a real human did (more often investigatable), and walking the timeline of what happened around the event.

In ION, investigation work shows up as:

- An `Investigation` row keyed by `alert_id_ref` — Bob writes one of these every time the AI analyst runs on the alert; humans add notes via `Note` rows
- `AlertTriage.status = ACKNOWLEDGED` and `case_id` set if a case was opened to track the investigation properly
- One or more `ObservableLink` rows tying extracted IOCs (IPs, hashes, domains) to the case
- Possibly a `PlaybookExecution` row if a playbook ran during the investigation

This is the time-expensive part of the job. A typical L1 investigation is 5–20 minutes; an L2/L3 investigation can run hours or days. **The point of state 2 (triage) is to make sure that only alerts which deserve a 20-minute investigation actually receive one.**

### 4. Resolved

A verdict has been reached. ION's `CaseClosureReason` enum captures the six allowed values — these are the same ones every detection-engineering team measures their detection quality against:

| Value | Meaning | Tuning owed? |
|---|---|---|
| `true_positive` | Rule fired on real malicious / unauthorised activity | No |
| `false_positive` | Rule fired on benign activity — the rule shouldn't have fired | **Yes** — exclusion or refinement |
| `benign_true_positive` | Rule correctly identified the behaviour, but the activity is authorised in this environment (vuln scanner, sanctioned admin tool) | Scope refinement only |
| `duplicate` | Already covered by an open case | No |
| `insufficient_data` | Can't decide — escalating or parking | No (yet) |
| `not_applicable` | Out of scope for this SOC (different team owns the asset) | No |

The single most-confused L1 distinction is **false_positive vs benign_true_positive**. Get them right and the detection-engineering team writes good tuning; get them wrong and they either delete a useful rule or fail to fix a noisy one.

A vuln scanner triggering the `Port scan from internal asset` rule is `benign_true_positive` — the rule correctly identified port-scan behaviour, the scanner is authorised. A typo'd regex matching every Word document is `false_positive` — the rule shouldn't be firing on those at all.

### 5. Closed + Tuned

The case is shut and any tuning actions are recorded. For `false_positive` and `benign_true_positive` verdicts, **a tuning action is owed** — without it, the same alert reappears tomorrow and the queue grows.

In ION, tuning actions show up as:

- A `TuningProposal` row created from the case detail page — captures the proposed exclusion / refinement / rule deletion
- The case is `CLOSED` in `AlertCase.status`
- The verdict is recorded in `AlertCase.closure_reason`
- `AIFeedback` row written automatically — captures Bob's predicted verdict vs the human's actual verdict for the per-template scorecard

The tuning step is what separates a healthy SOC from a noisy one. A SOC that closes 500 false-positives a week without tuning is a SOC that will close 500 false-positives next week too.

## Worked example — walking a real alert through all five states

Let's trace `DEMO-0001` (the seeded test case from `seed_test_data.py`). This is exactly the path an L1 analyst walks for one alert during a shift:

```mermaid
sequenceDiagram
    participant ES as Elasticsearch
    participant ION as ION
    participant Bob
    participant L1 as L1 Analyst

    ES->>ION: alert-demo-001-a fires (Suspicious PowerShell, severity=high)
    Note over ION: State 1 — Ingested. AlertTriage row, status=OPEN.
    ION->>Bob: investigate_alert(alert_id)
    Bob->>Bob: parse cmd_line, extract IOCs, check OpenCTI
    Bob-->>ION: verdict=true_positive, confidence=high, key_observations cited
    Note over ION: AlertTriage.suggested_verdict = "true_positive"
    L1->>ION: claims the alert, reads Bob's narrative + key observations
    Note over ION: State 2 — Triaged. status=ACKNOWLEDGED, assigned_to=L1.
    L1->>ION: opens case DEMO-0001, links the alert
    L1->>ION: pivots to similar-observables panel, sees IP shared with DEMO-0002
    Note over ION: State 3 — Investigated. case_id linked, observables extracted.
    L1->>ION: confirms phishing chain, requests host isolation via IT
    L1->>ION: closes case with closure_reason=true_positive
    Note over ION: State 4 — Resolved. AlertCase.status=CLOSED.
    L1->>ION: no tuning needed (TP) — adds note, signs off
    Note over ION: State 5 — Closed + Tuned. AIFeedback row written automatically.
```

The whole walk took 8 minutes of L1 time. Bob's investigation took 30 seconds and gave the analyst a strong starting point: a verdict suggestion, three cited key observations (the obfuscated command line, the Outlook parent process, the malicious IP), and three recommended actions. The L1's job wasn't to *redo* Bob's work — it was to **confirm**, **gather the cross-case context Bob couldn't see**, and **decide on the closure verdict**.

That's what good L1 work looks like in 2026: a partnership with the AI analyst, not a competition with it.

## Common mistakes (and how to avoid them)

These are the four mistakes new L1s make most often. All four show up in pre-shift reviews of analyst queue performance.

1. **Skipping triage and investigating every alert.** Works for two days, then the queue overwhelms you. Fix: every shift, *triage the whole queue first* — even if it takes 45 minutes. Then pick the highest-severity unaddressed alerts to investigate.

2. **Closing without tuning on false positives.** The rule will fire again tomorrow. Fix: any `false_positive` or `benign_true_positive` verdict requires either an immediate rule edit or a `TuningProposal` ticket — no exceptions.

3. **Confusing false_positive with benign_true_positive.** Detection-engineering loses signal either way: too many false_positives and they delete useful rules; too many benign_true_positives miscategorised as false_positives and they over-tune. Fix: always ask "did the rule correctly identify the behaviour it looks for?" — if yes, it's benign_true_positive (or true_positive); if no, it's false_positive.

4. **Re-investigating duplicates.** A different rule triggers on the same underlying event — and you investigate it like it's new. Fix: always check ION's "Cross-Case Observable Sightings" panel on case detail before opening a new case. If the IPs / hashes match an open case, link the alert to that case as `duplicate` instead.

## How this maps to ION's data model

ION's tables are designed around the lifecycle. Here's the cheat-sheet:

| Lifecycle state | Primary ION row | Key fields |
|---|---|---|
| Ingested | `AlertTriage` | `status=OPEN`, `case_id IS NULL` |
| Triaged | `AlertTriage` | `status=ACKNOWLEDGED`, `suggested_verdict` set |
| Investigated | `AlertCase` + `Investigation` + `Note` + `ObservableLink` | `case_id` linked from triage |
| Resolved | `AlertCase.closure_reason` | the six-value enum |
| Closed + Tuned | `AlertCase.status=CLOSED`, `TuningProposal`, `AIFeedback` | tuning row exists if FP/BTP |

If you're reading code or writing a query and want to know *which alerts are stuck at which stage*, those columns are the ones to filter on.

## Glossary

- **AlertTriage** — ION's row representing an L1's view on an alert. One per ES alert id.
- **AlertCase** — ION's row for the formal case opened around one or more linked alerts.
- **CaseClosureReason** — the six-value enum L1s use to verdict cases (`true_positive` / `false_positive` / `benign_true_positive` / `duplicate` / `insufficient_data` / `not_applicable`).
- **Bob** — ION's AI analyst service user. Authors automated `Investigation` rows + Note commentary.
- **TuningProposal** — ticket-shaped row that captures a proposed detection-rule change. Owed for every `false_positive` close.
- **AIFeedback** — the per-case ledger row that records Bob's predicted verdict vs the human's actual verdict, for scoring per-template Bob accuracy.

## Further reading

- MITRE D3FEND model — the *defensive* counterpart to ATT&CK. Worth bookmarking for tier-2 work.
- *Crafting the InfoSec Playbook* (O'Reilly, Bollinger / Enright / Valites) — chapter 4 covers the alert lifecycle from a process angle.
- ION's own docs: `docs/RUNBOOK.md` covers the L1 escalation matrix; `docs/ARCHITECTURE.md` walks the AlertTriage / AlertCase / Investigation row relationships.

---

When you're ready, move on to the **severity rating quiz** to lock in the rubric you'll use thousands of times this year.
""",
    )
    # Reading lessons have no questions; learner clicks "mark complete".

    # Lesson 1.2 — quiz: severity rating rubric
    l2 = _add_lesson(
        session, mod, order=2, title="Severity rating rubric — quiz",
        lesson_type=LessonType.QUIZ, duration_min=12,
        content_md="""
## Apply the severity rubric

Severity drives queue ordering — high severity alerts get worked first.
Apply the rubric consistently or your shift partner will work the wrong
items. ION uses the standard four-tier scale:

| Severity | When to use |
|---|---|
| **Critical** | Active confirmed compromise — adversary is in, data is moving, or systems are unavailable. Page on-call. |
| **High** | Strong indicators of compromise but not yet confirmed in-progress (e.g. credential theft confirmed, exfiltration not yet detected) |
| **Medium** | Suspicious activity that needs investigation but isn't visibly active (e.g. one anomalous logon, one failed exploit attempt) |
| **Low** | Policy violation, minor misconfiguration, informational |

### Rules of thumb

- **If unsure, rate one tier higher.** Better to investigate something
  that turns out to be medium than miss a critical.
- **A confirmed false positive becomes Low** regardless of original rating.
- **Asset criticality is a multiplier.** A medium-severity finding on a
  domain controller usually rates High because the blast radius matters.

Take the quiz to lock in the rubric.
""",
    )
    _add_q(session, l2, order=1, kind=QuestionKind.SINGLE,
        stem_md="A new alert fires: a domain admin account logged in from a country your org has never had presence in, at 3 AM local time. The login succeeded but no follow-on activity has been seen yet. What's the most appropriate severity?",
        options=[
            {"value": "low", "label": "Low — login succeeded, no follow-on"},
            {"value": "medium", "label": "Medium — anomalous but no observable damage"},
            {"value": "high", "label": "High — domain admin from impossible-travel geo"},
            {"value": "critical", "label": "Critical — page on-call immediately"},
        ],
        correct="high",
        explanation_md="**High** is right. Domain admin + impossible-travel + off-hours is a strong indicator of credential compromise even before downstream activity. *Critical* would be appropriate only after seeing follow-on (privilege use, lateral movement). *Medium* underweights the privilege of the account — domain admin makes the asset-criticality multiplier kick in.",
        points=2,
    )
    _add_q(session, l2, order=2, kind=QuestionKind.SINGLE,
        stem_md="A user reports a phishing email. Email security gateway already blocked it. No clicks were registered, no credentials submitted. What's the rating?",
        options=[
            {"value": "low", "label": "Low — informational; control did its job"},
            {"value": "medium", "label": "Medium — phishing is always at least medium"},
            {"value": "high", "label": "High — credential-theft attempt"},
            {"value": "critical", "label": "Critical — escalate"},
        ],
        correct="low",
        explanation_md="**Low**. The control worked — no human interaction occurred and no credentials moved. This is informational and useful for trending (which campaigns are hitting your org), but it's not an active incident. Resist the urge to inflate severity because the *category* feels scary.",
        points=2,
    )
    _add_q(session, l2, order=3, kind=QuestionKind.MULTI,
        stem_md="Which of the following correctly bump an alert's severity *upward*? (Pick all that apply.)",
        options=[
            {"value": "asset", "label": "The affected asset is a domain controller / cert authority / customer-data DB"},
            {"value": "actor", "label": "The user account holds privileged role (DA, root, finance approver)"},
            {"value": "active", "label": "Follow-on activity is observable (process spawned, network egress to unfamiliar IP)"},
            {"value": "outside", "label": "Activity is from outside the org's normal hours and geos"},
            {"value": "rule_age", "label": "The detection rule was added recently"},
            {"value": "match_count", "label": "The same rule fired against many assets at once"},
        ],
        correct=["asset", "actor", "active", "outside", "match_count"],
        explanation_md="All correct except *rule age*. Recent rules might be more or less accurate than mature ones — newness alone doesn't change the threat. Everything else is a real severity multiplier; especially the *match_count* one — many simultaneous matches often means a campaign or worm.",
        points=3,
    )
    _add_q(session, l2, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="A confirmed false positive should be rated `low` regardless of the original detection severity.",
        options=[
            {"value": "true", "label": "True"},
            {"value": "false", "label": "False"},
        ],
        correct="true",
        explanation_md="**True.** Once you've confirmed it's a false positive, the operational severity *to the SOC* is low — you're closing it and tuning the rule. A high-severity false positive is still a false positive.",
        points=1,
    )
    _add_q(session, l2, order=5, kind=QuestionKind.SHORTANSWER,
        stem_md="Name the four severity tiers, in order from least to most urgent (separate with commas, e.g. `low, medium, high, critical`).",
        options=None,
        correct=["low, medium, high, critical", "low,medium,high,critical"],
        explanation_md="The four tiers are **low, medium, high, critical** — escalating in operational urgency. ION uses the same scale across alerts, cases, and CyAB.",
        points=1,
    )

    # Lesson 1.3 — quiz: verdict semantics
    l3 = _add_lesson(
        session, mod, order=3, title="True positive vs false positive vs benign — quiz",
        lesson_type=LessonType.QUIZ, duration_min=10,
        content_md="""
## The three verdicts you'll close 95% of cases as

This is the single most-confused part of L1 work, and it has direct
consequences for the detection-engineering team. Get it wrong and they
either tune away real detections or fail to tune away noise.

### True positive

The rule fired on **real malicious / unauthorised activity**. Whether
the SOC stopped it or not, the alert was correct. Tuning is **not** owed.

### False positive

The rule fired on **benign activity that the rule shouldn't have fired
on**. The detection is broken or too broad. **Tuning is owed** — either
an exclusion, a refinement to the query, or a deletion of the rule.

### Benign true positive

The rule fired correctly — the behaviour the rule looks for *was* present —
but in this environment that behaviour is **authorised**. Examples:

- A vuln scanner triggered the "port scan from internal asset" rule. The
  rule is correct; the scanner is authorised.
- A new admin tool triggered the "PowerShell from unusual parent" rule.
  Behaviour is real; tool is sanctioned.

The rule is *working as designed*. Tuning is owed only as a scope
refinement (exclude this asset / this admin tool from this rule), not as
a fundamental rule change.
""",
    )
    _add_q(session, l3, order=1, kind=QuestionKind.SINGLE,
        stem_md="Vulnerability scanner Tenable runs nightly and triggers your `Port scan from internal asset` rule every time. The behaviour is real, the asset (the scanner) is authorised. Closure verdict?",
        options=[
            {"value": "true_positive", "label": "true_positive"},
            {"value": "false_positive", "label": "false_positive"},
            {"value": "benign_true_positive", "label": "benign_true_positive"},
            {"value": "not_applicable", "label": "not_applicable"},
        ],
        correct="benign_true_positive",
        explanation_md="**benign_true_positive**. The rule correctly identified the behaviour it looks for (port scanning from internal). The behaviour is authorised in this environment because it's the sanctioned vuln scanner. Tuning action: add the scanner asset to the rule's exclusion list. Don't delete the rule — it's still valuable for *unauthorised* internal scanning.",
        points=2,
    )
    _add_q(session, l3, order=2, kind=QuestionKind.SINGLE,
        stem_md="A rule named `Suspicious cmd.exe spawned by Word` fires whenever any user opens a Word doc that triggers a macro. After 5 cases all closed as benign (everyone is using approved macros), what's the right verdict for the *current* case and the right tuning action?",
        options=[
            {"value": "tp_no_tune", "label": "true_positive — no tuning needed; macros are dangerous"},
            {"value": "fp_delete_rule", "label": "false_positive — delete the rule"},
            {"value": "fp_refine_rule", "label": "false_positive — tune the rule to exclude approved macros"},
            {"value": "btp_add_exclude", "label": "benign_true_positive — add an asset exclusion"},
        ],
        correct="fp_refine_rule",
        explanation_md="**false_positive — tune the rule.** The detection's *intent* is right (cmd.exe from Word IS suspicious in general), but the implementation is too broad — it doesn't distinguish approved macros from unknown ones. The right move is refining the query (exclude signed/whitelisted macros, hash-of-spawned-binary in known-good list, etc.), not deleting the rule. *benign_true_positive* would apply if it were one specific approved macro firing repeatedly — here the noise is systemic so the rule itself needs work.",
        points=2,
    )
    _add_q(session, l3, order=3, kind=QuestionKind.SINGLE,
        stem_md="Bob (the AI analyst) suggested `false_positive` with high confidence. You agree on quick review. After you close the case as false_positive, what *must* happen next?",
        options=[
            {"value": "nothing", "label": "Nothing — Bob's confidence is enough"},
            {"value": "kibana_sync", "label": "Sync the closure verdict back to Kibana so analysts there see it"},
            {"value": "tuning", "label": "A tuning action is owed — either an exclusion, refinement, or a tuning ticket"},
            {"value": "page_l2", "label": "Page L2 because false_positive needs senior review"},
        ],
        correct="tuning",
        explanation_md="**A tuning action is owed.** This is the one thing that distinguishes a healthy SOC from a noisy one. *Every* false_positive should generate either an immediate rule tweak or a `TuningProposal` ticket. The Kibana sync happens automatically; L2 review isn't required for FPs.",
        points=2,
    )

    print(f"  L1: {course.title} — 1 module, 3 lessons")
    return course


# ── L2 — Threat Hunting with KQL ─────────────────────────────────────────


def _seed_l2(session: Session, author_id: int) -> Course:
    course = _add_course(
        session,
        slug="demo-l2-threat-hunting-with-kql",
        title="Threat Hunting with KQL",
        level=CourseLevel.L2,
        description_md=(
            "Hypothesis-driven threat hunting with Kibana Query Language. Where L1 reacts "
            "to detections that fired, L2 *looks for the threats no rule has caught yet*. "
            "This course covers building a hunt hypothesis, expressing it as a KQL query, "
            "iterating on results, and converting a successful hunt into a permanent "
            "detection.\n\n"
            "**Prerequisites:** L1 Alert Triage Fundamentals.\n\n"
            "**By the end you'll be able to:**\n\n"
            "- Frame an actionable hunt hypothesis (PEAK / SURGe-style)\n"
            "- Translate the hypothesis to KQL across host, network, and identity data\n"
            "- Reduce noise without losing signal — pivot from broad to narrow\n"
            "- Convert a one-off hunt into a TIDE detection rule with a tuning recommendation\n"
        ),
        estimated_hours=3,
        order_in_level=1,
        skill_keys=["threat-hunting", "kql-spl", "detection-engineering"],
        author_id=author_id,
    )
    mod = _add_module(
        session, course, order=1, title="From hypothesis to KQL",
        description_md="The PEAK methodology applied to one realistic hunt.",
        estimated_minutes=60,
    )

    l1 = _add_lesson(
        session, mod, order=1, title="The hunt hypothesis (PEAK methodology)",
        lesson_type=LessonType.READING, duration_min=25,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Define adversary-driven hunting and explain how it differs from alert response and "exploratory searching"
> 2. Apply the **PEAK** loop (Prepare → Execute → Act → Know) to a hunt from start to finish
> 3. Write a *strong* hunt hypothesis using the four-element template (TTP + artefact + data source + window)
> 4. Recognise weak hypotheses and rewrite them
> 5. Document a hunt's negative results so the team learns from null findings
>
> **Prerequisites.** L1 *Alert Triage Fundamentals* completed. You should be comfortable reading KQL or SPL queries and know what a MITRE ATT&CK technique ID looks like.

## Why hunt? Detection alone isn't enough

The SOC's detection layer can only catch threats it has rules for. **Threat hunting fills the gap** — a hypothesis-driven search for adversary behaviour that *no rule has caught yet*. Run consistently, hunting:

- Surfaces gaps in detection coverage *before* a real adversary exploits them
- Converts those gaps into permanent new detection rules (closing the loop)
- Builds analyst muscle memory for adversary TTPs that don't fire frequently
- Provides the data points your CISO uses to defend the SOC's budget at year-end review

A hunt is **not** a one-off "let me poke around the SIEM and see what looks weird". That's exploratory searching, which has its place but isn't repeatable, isn't measurable, and doesn't compound. A real hunt has the same structure every time: a documented hypothesis, a query, a result set you actually walk through, and a recorded outcome — finding or no-finding, both are valuable.

## The PEAK loop

The PEAK methodology was published by SURGe (Splunk's research team) in 2023 and has become the de facto standard for repeatable hunting. It's four phases that loop:

```mermaid
flowchart LR
    P[<b>P · Prepare</b><br/>Frame hypothesis<br/>Pick TTP + artefact + data source]
    E[<b>E · Execute</b><br/>Build the query<br/>Iterate, reduce noise]
    A[<b>A · Act</b><br/>Open case if found<br/>Document negative result]
    K[<b>K · Know</b><br/>Convert to detection rule<br/>Update hunt log]
    P --> E --> A --> K --> P
    style P fill:#1e3a8a,color:#fff
    style E fill:#0e7490,color:#fff
    style A fill:#15803d,color:#fff
    style K fill:#9a3412,color:#fff
```

| Phase | Length | What you do | Output |
|---|---|---|---|
| **P · Prepare** | 30 min | Frame the hypothesis, pick the TTP, the artefact, the data source, the time window. Define what *success* and *null* both look like. | A 3–5 sentence hypothesis written down before you touch the SIEM |
| **E · Execute** | 1–4 hrs | Build the query. Iterate to reduce noise without losing signal. Stop when the result set is small enough to *eyeball every row*. | A working query + a short result-set walkthrough |
| **A · Act** | varies | If you found something — open a case, treat it like an investigation, escalate. If nothing — record the null result with as much detail as a positive finding. | A case OR a hunt-log entry, never silence |
| **K · Know** | 30–60 min | Convert the successful hunt logic into a permanent detection rule. Capture the negative results in the hunt log so the next hunter doesn't repeat them. | A new detection rule + a hunt-log row |

The loop closes — once you've **K**nown a hunt, the hypothesis you formed in **P** evolves. You learn what your environment actually looks like, what's normal, and what TTPs are worth hypothesising next.

## Anatomy of a strong hypothesis

A strong hypothesis has **four elements**. Skip any one and the hunt collapses into searching:

```mermaid
flowchart TD
    H[Strong<br/>hypothesis] --> T[1. TTP<br/>Specific MITRE technique]
    H --> A[2. Artefact<br/>Field or pattern in the data]
    H --> D[3. Data source<br/>Index, table, log type]
    H --> W[4. Window<br/>Time range to query]
    style H fill:#7c3aed,color:#fff
```

### Element 1 — the TTP

A specific MITRE ATT&CK technique (or sub-technique). Not a category, not a tactic, not a vague "lateral movement" — a specific technique ID. *T1218.005 — Mshta* is good. *Defense Evasion* alone is not.

Why specific? Because adversaries execute *specific* TTPs that produce *specific* artefacts. The more specific the TTP, the more specific the artefact you can hunt for, the smaller the result set, the more likely you find what you came for.

### Element 2 — the artefact

The exact field or pattern you'd expect to see if the TTP were happening here. For T1218.005 it might be `process.name = "mshta.exe"` AND `process.command_line` containing both a script-engine reference (`vbscript:`, `javascript:`) AND a URL pattern.

The artefact is the *bridge* between the abstract TTP and the concrete data. When you write the hypothesis, write the artefact in pseudo-query form so you don't lose it later:

> Artefact: `process.name == "mshta.exe" AND process.command_line MATCHES /(vbscript|javascript):.*https?:\\/\\//`

### Element 3 — the data source

Which index / table / log type. Be precise — `winlogbeat-*` is fine; `logs` is not. The data source determines:

- Whether the artefact field actually exists (does winlogbeat collect `process.command_line`? *Yes* on Sysmon-equipped hosts; *no* on bare event logs)
- The fidelity (Sysmon Event 1 captures full command line; native Security 4688 captures truncated unless you've enabled the policy)
- The retention (are you searching back farther than the index keeps?)

### Element 4 — the window

How far back to look. Standard hunting windows: 7d, 14d, 30d, 90d. Longer windows catch slow-burn campaigns; shorter windows reduce noise. **Start narrow, widen if null.**

A null result over 7 days doesn't mean *no compromise* — it means *not in the last 7 days from this data source*. Widening the window is part of the *Know* loop after a null.

## Worked example — framing a hunt from scratch

Let's frame a hunt for the LotL family of techniques. A real hunt analyst's whiteboard, in order:

```mermaid
sequenceDiagram
    participant Hunter
    participant ATT&CK as ATT&CK Navigator
    participant Inv as Hunt log
    participant SIEM

    Hunter->>ATT&CK: Which Defense Evasion sub-techniques fired in recent CTI?
    ATT&CK-->>Hunter: T1218.005 (Mshta), T1218.010 (Regsvr32) trending
    Hunter->>Hunter: Pick T1218.005 — concrete enough
    Hunter->>Hunter: Artefact: mshta.exe spawned via PowerShell/WMIC + URL arg
    Hunter->>Hunter: Data source: winlogbeat-*  (Sysmon Event 1)
    Hunter->>Hunter: Window: last 7 days
    Hunter->>Inv: Hypothesis written down
    Hunter->>SIEM: Build query, iterate
    SIEM-->>Hunter: 3 results
    Hunter->>Hunter: Walk all 3 — all benign sysadmin scripts
    Hunter->>Inv: A · Act = no compromise; K · Know = convert to rule with sysadmin exclusions
```

The hypothesis written on the whiteboard:

> *"If an adversary used Living-off-the-Land binaries (LoLBins) to bypass EDR, I would see `powershell.exe` or `wmic.exe` invoking `mshta.exe` or `regsvr32.exe` with a remote URL argument, on Windows endpoints, in `winlogbeat-*` over the last 7 days. Null result is documented; positive result triggers an immediate case + cross-host pivot."*

That sentence has all four elements. Tape it to the wall, then open the SIEM.

A first-pass KQL on `winlogbeat-*`:

```kql
// 1. Restrict to recent events on the right index pattern
@timestamp >= "now-7d" and
// 2. Parent process is one of the unusual launchers
process.parent.name : ("powershell.exe" or "wmic.exe") and
// 3. Child process is one of the LoLBins we picked
process.name : ("mshta.exe" or "regsvr32.exe") and
// 4. Command line carries a URL — distinguishes LotL download from local-only execution
process.command_line : (*http://* or *https://*)
```

Each commented clause maps to one of the four hypothesis elements. If you can't draw that mapping, your query has more (or fewer) clauses than your hypothesis warrants — adjust until they line up.

## Anti-patterns: weak vs strong hypotheses

Five real-world hypotheses I've seen written by junior hunters, with the rewrites:

| Weak | Why it's weak | Rewrite |
|---|---|---|
| "Look for suspicious PowerShell" | No artefact, no data source, no window | "T1059.001 — encoded PowerShell launched by Office processes, `process.command_line` matching `-enc` or base64 entropy > 4.5, on `winlogbeat-*` over 14d" |
| "Hunt for lateral movement" | TTP is a *tactic*, not a technique. No artefact. | "T1021.002 — SMB/Admin shares used by non-admin accounts, `event.code:5140 AND user.role != 'admin'`, on `winlogbeat-security-*` over 7d" |
| "Look for malicious IPs" | No data source. Hunt vs detection confusion (this is what threat-intel feeds do automatically). | "T1071.001 — outbound HTTPS to IPs newly registered in last 30 days, joined against `threatintel-newly-registered-domains`, on `firewall-*` over 24h" |
| "Hunt for ransomware" | Ransomware is a *category*, not a TTP. By the time you see ransomware artefacts, you're past prevention. | "T1486 precursors — high volume of `crypto-` or `vssadmin delete` commands per host, on `winlogbeat-sysmon-*` over 24h" |
| "Find data exfiltration" | Tactic, not technique. No artefact. | "T1567.002 — outbound to cloud-storage providers (Mega, Anonfiles, Dropbox public) > 100MB from non-IT hosts, on `firewall-*` over 7d" |

Notice the rewrites all have a **specific MITRE technique ID**, a **concrete artefact pattern**, a **named index**, and a **time window**. Without those four elements, you can still find things — but you can't repeat the hunt, you can't compare across periods, and you can't convert findings into permanent rules.

## When the result set is too big

Iteration in the **E** phase isn't optional. A first-pass query that returns 4,800 rows is a query that won't be hunted properly — you'll abandon it or skim it badly. Each iteration narrows by adding context, never by removing the artefact:

| Refinement type | Effect | Loses signal? |
|---|---|---|
| Exclude signed-binary paths (`process.executable: "C:\\Windows\\System32\\*"`) | Big noise drop on regsvr32-style hunts | No (signed paths are by definition not the LoLBin abuse pattern) |
| Restrict to non-RFC1918 destination IPs | Massive drop on URL-arg hunts | Sometimes — internal exfil sites get hidden |
| Exclude known service accounts (e.g. `user.name: not "svc_sccm"`) | Cuts SCCM-driven config-management noise | Only if SCCM is the abused account |
| Require command-line length > N | Cuts short legit lines | **Often loses signal** — adversaries can chain compact loaders |
| Exclude alerts already in `critical` state | Cuts working-now alerts | **Loses signal** — they may be unrelated detections this hunt would disambiguate |

General principle: **exclude on structural properties (signed paths, RFC1918, known accounts), not on content properties (length, char set)**. Structural exclusions are unlikely to hide adversary activity; content exclusions often do.

## What "documenting null results" looks like

A hunt that returned zero results is *still a finding*. It tells:

- The next hunter — *don't run this hunt for at least 30 days, the data point is fresh*
- Detection-engineering — *no signal here on this artefact in this window, move budget elsewhere*
- The CISO — *we hunted for this and didn't find it; here's the evidence*

A good hunt-log entry has:

```yaml
hunt_id: HUNT-2026-04-001
hypothesis: "T1218.005 LotL via mshta launched by PowerShell/WMIC..."
ttp: T1218.005
data_source: winlogbeat-*
window: 7d
query: |
  @timestamp >= "now-7d" and
  process.parent.name : ("powershell.exe" or "wmic.exe") and
  ...
result_count: 0
walk_through_minutes: 0
findings: null
known_after:
  - "Sysmon Event 1 collection is healthy across endpoints (the query
     hit no exceptions)"
  - "Confirmed mshta.exe is parsed correctly into process.name field"
follow_up:
  - "Re-run in 30 days to catch slow-burn"
  - "Consider extending to T1218.010 (regsvr32) — already adjacent"
```

That's a reusable artefact. Three months from now, when someone says *"have we hunted for LotL recently?"*, the answer is in the log.

## Glossary

- **TTP** — Tactic, Technique, Procedure. The MITRE ATT&CK lingo for *what an adversary does*. A hunt picks one, usually a sub-technique.
- **PEAK** — Prepare, Execute, Act, Know. SURGe's hunt methodology.
- **LotL** — Living-off-the-Land. Adversary use of legitimate system binaries (PowerShell, mshta, regsvr32, certutil, bitsadmin) to execute malicious activity without dropping new files.
- **LoLBin** — Living-off-the-Land Binary. The specific binary being abused (mshta.exe, regsvr32.exe, etc.). LOLBAS.io maintains the canonical catalogue.
- **Artefact** — The specific data point you'd expect to see if the TTP were happening. Bridges the abstract technique to the concrete query.
- **Hunt log** — Persistent record of every hunt run, finding or null. Often a wiki page, sometimes a structured table.
- **K · Know phase** — The PEAK phase where hunt logic becomes a permanent detection rule and findings get propagated.

## Further reading

- **PEAK Threat Hunting Framework** (SURGe, Splunk, 2023) — the canonical reference. Search for "PEAK SURGe whitepaper".
- **LOLBAS Project** — `lolbas-project.github.io` — catalogue of every Windows LoLBin with example commands and detection ideas.
- **MITRE ATT&CK Navigator** — for picking the next hunt TTP. Filter by sector, campaign, or recent CTI to match your environment's threat profile.
- **The ThreatHunting Project** — `threathunterz.com` — community library of hunt hypotheses, organised by ATT&CK technique.

---

When you're ready, take the **Building the KQL query** quiz to lock in how each clause of a hunt query maps back to its hypothesis element.
""",
    )

    l2 = _add_lesson(
        session, mod, order=2, title="Building the KQL query — quiz",
        lesson_type=LessonType.QUIZ, duration_min=15,
        content_md="""
## From hypothesis to query

Continuing the worked example from the previous lesson:

> *"PowerShell or wmic invoking mshta or regsvr32 with a remote URL
> argument, on Windows, in winlogbeat-* in the last 7 days."*

A first-pass KQL on the `winlogbeat-*` index pattern looks like:

```kql
process.parent.name : ("powershell.exe" or "wmic.exe") and
process.name : ("mshta.exe" or "regsvr32.exe") and
process.command_line : (*http* or *https*) and
@timestamp >= "now-7d"
```

Read it and answer the quiz. The questions test whether you understand
*why* each clause is there and what would happen if you omitted or
changed it.
""",
    )
    _add_q(session, l2, order=1, kind=QuestionKind.SINGLE,
        stem_md="If you removed the `process.parent.name` clause from the query, what would happen to the result set?",
        options=[
            {"value": "narrower", "label": "It would get narrower (fewer results)"},
            {"value": "wider_noisy", "label": "It would get much wider — most legitimate mshta/regsvr32 launches don't have powershell.exe / wmic.exe as parent"},
            {"value": "unchanged", "label": "Unchanged — parent name is irrelevant"},
            {"value": "errors", "label": "The query would error because mshta requires a parent"},
        ],
        correct="wider_noisy",
        explanation_md="**Wider — and noisy.** The parent-name clause is what gives the hunt specificity. Without it you'd hit every legitimate `regsvr32 mylib.dll` registration on every host. The hypothesis specifically targets *PowerShell or WMIC spawning these LoLBins*, which is the unusual combination.",
        points=2,
    )
    _add_q(session, l2, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of these refinements would reduce noise *without* hiding real findings? (Pick all that apply.)",
        options=[
            {"value": "exclude_signed_path", "label": "Exclude command lines containing the signed Microsoft regsvr32 install path"},
            {"value": "exclude_localhost", "label": "Require the URL to be non-RFC1918 (i.e. internet-facing) — hunting LotL is about external download"},
            {"value": "exclude_known_admins", "label": "Exclude commands run under known service accounts that legitimately use mshta (e.g. SCCM)"},
            {"value": "exclude_critical_severity", "label": "Exclude alerts already rated `critical` — those are being worked"},
            {"value": "exclude_long_command_line", "label": "Exclude command lines under 60 characters (LotL payloads tend to be long)"},
        ],
        correct=["exclude_signed_path", "exclude_localhost", "exclude_known_admins"],
        explanation_md="The first three reduce noise without hiding signal. *Excluding critical alerts* is wrong — they may be unrelated detections that this hunt could disambiguate. *Excluding short command lines* could miss legitimate compact payloads (e.g. base64 decoded into env-vars). General rule: exclude on **structural** properties (signed paths, known accounts, RFC1918) not on **content length**.",
        points=3,
    )
    _add_q(session, l2, order=3, kind=QuestionKind.SINGLE,
        stem_md="The hunt returns 0 results. What's the best next step under PEAK?",
        options=[
            {"value": "give_up", "label": "Conclude the org is safe from LotL and close the hunt"},
            {"value": "broaden", "label": "Drop a clause and re-run — maybe the hypothesis was too narrow"},
            {"value": "k_log", "label": "Document the negative result in the hunt log and move to the next hypothesis"},
            {"value": "raise_severity", "label": "Raise the time window to 90 days to catch any historic activity"},
        ],
        correct="k_log",
        explanation_md="**Document the negative result** (the K · Know phase). A null result *is* a finding — it tells the next hunter and the detection-engineering team that this specific TTP-artefact-source combination didn't fire in the last 7 days. Don't conclude *safety* (could just mean adversaries used a different LoLBin), but don't pretend the hunt found nothing — record it properly. Broadening to 90 days first is also reasonable, but the *Know* step happens regardless.",
        points=2,
    )
    _add_q(session, l2, order=4, kind=QuestionKind.SINGLE,
        stem_md="The hunt returns 3 results. All three are legitimate sysadmin scripts that do `regsvr32 http://...` to register internal DLLs. What's the right *Act* + *Know* step?",
        options=[
            {"value": "alert_each", "label": "Open a case for each result and let L1 close them as benign"},
            {"value": "convert_with_exclusion", "label": "Document the legitimate scripts as known-good, then convert the hunt query into a TIDE rule that excludes them"},
            {"value": "delete_hunt", "label": "Delete the hunt — it's clearly only producing noise"},
            {"value": "block_path", "label": "Block the URL pattern at the proxy"},
        ],
        correct="convert_with_exclusion",
        explanation_md="**Convert to a rule with the known-good exclusions baked in.** That's the *Know* step — the value of the hunt is the resulting *detection*. Opening cases for the three benign findings clogs L1's queue with what you already know is benign. Deleting the hunt loses the future-detection value. Blocking at the proxy is over-reaction without checking impact.",
        points=2,
    )

    print(f"  L2: {course.title} — 1 module, 2 lessons")
    return course


# ── L3 — Adversary Emulation Basics ──────────────────────────────────────


def _seed_l3(session: Session, author_id: int) -> Course:
    course = _add_course(
        session,
        slug="demo-l3-adversary-emulation-basics",
        title="Adversary Emulation Basics",
        level=CourseLevel.L3,
        description_md=(
            "Move from defending against threats to actively *exercising* your detections. "
            "L3 analysts run controlled adversary emulations — picking a TTP, executing it "
            "in a sanctioned way, and verifying that the SOC catches it. This course covers "
            "purple-teaming concepts, MITRE ATT&CK → Atomic Red Team mapping, and how to "
            "turn negative emulation results into detection-engineering work.\n\n"
            "**Prerequisites:** L2 Threat Hunting with KQL, comfort with PowerShell or "
            "Bash on Windows endpoints.\n\n"
            "**By the end you'll be able to:**\n\n"
            "- Plan a purple-team exercise scoped to one TTP\n"
            "- Use Atomic Red Team to execute the TTP safely\n"
            "- Verify whether your detections fired and at what fidelity\n"
            "- Convert a missed-detection result into a `TuningProposal` ticket\n"
        ),
        estimated_hours=4,
        order_in_level=1,
        skill_keys=["adversary-emulation", "purple-teaming", "detection-engineering"],
        author_id=author_id,
    )
    mod = _add_module(
        session, course, order=1, title="Purple-team flow: ATT&CK → Atomic → Detection check",
        description_md="One realistic emulation cycle, end to end.",
        estimated_minutes=90,
    )

    l1 = _add_lesson(
        session, mod, order=1, title="Why purple teaming beats annual pentests",
        lesson_type=LessonType.READING, duration_min=28,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Articulate the difference between **penetration testing** and **adversary emulation** to a non-technical executive
> 2. Map the four detection-fidelity tiers (Alerted / Logged-not-alerted / Unparsed / Not-logged) to the team that owns the gap
> 3. Plan a single-TTP purple-team exercise from authorisation through to scorecard
> 4. Convert a missed detection into a `TuningProposal` ticket with the right scope
> 5. Avoid the eight common mistakes that wreck early purple-team programs
>
> **Prerequisites.** L1 *Alert Triage Fundamentals* and L2 *Threat Hunting with KQL* completed. Familiarity with PowerShell or Bash on a managed endpoint is required for the worked example.

## Pentests answer the wrong question

Annual pentests ask: *"Can a skilled attacker get in?"* The answer is almost always *yes*. You spend six figures on the engagement, get a 60-page report listing the same OWASP-style findings as last year, and your SOC team — the people who'd actually have to defend against a real intrusion — get nothing actionable from it. The pentesters got in. The remediation list goes to IT. The SOC was a bystander.

Worse, the report tells you almost nothing about your real risk: **whether your SOC would have caught a real adversary if they'd actually been malicious instead of contractually constrained.** A pentester who stays out of EDR's view because they bought the same EDR you have and tuned their tooling against it has proven nothing about whether *Conti* or *FIN7* would also stay out of view.

Adversary emulation flips the question:

> *"For each of the TTPs we know real adversaries against our sector use, can we **detect** them, **respond** to them, and **respond fast enough**? Show me the evidence — for every TTP — that we caught it or didn't."*

This is a question with a *measurable* answer. You can put numbers on it. You can track it quarter over quarter. You can defend the SOC budget at year-end review with it. A pentest report cannot.

## The full purple-team flow

A single purple-team cycle is one TTP, one exercise, one scorecard. Run it once a week against a planned curriculum of the TTPs that matter most to your org, and within six months you have empirical detection coverage data for ~25 techniques. That's a defensible posture.

```mermaid
flowchart TD
    P[1. Pick TTP<br/>from threat profile] --> A[2. Authorise<br/>CISO + IR signoff]
    A --> B[3. Pre-brief L1<br/>so they don't open<br/>a real case]
    B --> X[4. Execute<br/>Atomic Red Team test]
    X --> C[5. Wait for telemetry<br/>5-30 min ingestion]
    C --> D{6. Did it fire?}
    D -->|Alerted at right severity| E[7a. Score: latency + fidelity<br/>Pass]
    D -->|Logged but no rule| F[7b. Open TuningProposal<br/>Detection gap]
    D -->|Not in SIEM| G[7c. Logging or telemetry gap<br/>Talk to platform team]
    E --> S[8. Update scorecard<br/>Pick next TTP]
    F --> S
    G --> S
    S --> P
    style D fill:#7c2d12,color:#fff
    style E fill:#15803d,color:#fff
    style F fill:#a16207,color:#fff
    style G fill:#991b1b,color:#fff
```

Notice step 5 — *wait for telemetry*. New purple-teamers run the test and refresh the SIEM immediately, see no alert, declare a gap, and miss the fact that their EDR has a 15-minute ingestion lag. **Always wait at least 30 minutes before declaring a missed detection.** Half of perceived gaps disappear after coffee.

## The four detection-fidelity tiers

When you check whether a TTP fired, the answer is **never just yes/no**. There are four tiers, and they tell different teams different things:

```mermaid
graph TD
    Q{Did the SIEM<br/>alert?} -->|Yes — right severity| T1[<b>Tier 1 · Alerted</b><br/>Detection works.<br/>Score: latency, fidelity, severity accuracy.]
    Q -->|Yes — but wrong<br/>severity / 4hr latency| T1B[<b>Tier 1 with concerns</b><br/>Quality issue.<br/>Detection-eng tunes severity / latency.]
    Q -->|No alert.<br/>Data IS in SIEM| T2{Field queryable?}
    T2 -->|Yes — field exists| T3[<b>Tier 2 · Logged not alerted</b><br/>Detection gap.<br/>Detection-eng owns fix.]
    T2 -->|No — field missing| T4[<b>Tier 3 · Logged not parsed</b><br/>Logging gap.<br/>SIEM team owns fix.]
    Q -->|No alert.<br/>Data NOT in SIEM| T5[<b>Tier 4 · Not logged</b><br/>Telemetry gap.<br/>Platform team owns fix.<br/>Often a budget conversation.]

    style T1 fill:#15803d,color:#fff
    style T1B fill:#a16207,color:#fff
    style T3 fill:#a16207,color:#fff
    style T4 fill:#9a3412,color:#fff
    style T5 fill:#991b1b,color:#fff
```

| Tier | What fired | Owner | Typical fix |
|---|---|---|---|
| **1 · Alerted** | High-fidelity rule, right severity | Nobody (it works) | Just record the latency |
| **1 with concerns** | Rule fired but wrong severity or 4hr latency | Detection-eng | Tune severity / aggregation window |
| **2 · Logged not alerted** | Activity is in `winlogbeat-*`, field is queryable, no rule matched | Detection-eng | Write or extend a detection rule |
| **3 · Logged not parsed** | Activity is in the index, but the relevant field doesn't exist as a queryable column | SIEM team | Fix the parser, ECS mapping, or pipeline transform |
| **4 · Not logged** | Data source isn't being collected at all | Platform / Architecture team | Roll out new data source — usually a budget + agent-deployment conversation |

Calling all four "we missed it" is the single most common mistake in purple-team reporting. The fix for each tier lives with a different team, and conflating them either:

- Blames detection-eng for a *telemetry* problem they can't fix
- Lets the platform team off the hook for missing data sources by claiming it's a "rule" issue
- Burns goodwill: detection-eng won't engage with your scorecard if half the "gaps" you flag are actually parsing or telemetry issues

## Scoping rules — what *not* to do is half the discipline

Before you run anything, agree these constraints in writing:

### One TTP per exercise

If you chain T1059.001 → T1547.001 → T1003.001 in one execution, and only one detection fires, you can't tell which step it caught. You think you found two gaps when you might have found one. Or vice versa. Always test atomically.

### Authorisation in writing

CISO + IR lead must sign off, scoped to:

- **The specific MITRE technique ID** (and sub-technique)
- **The host or hosts** the test will run on
- **The time window** the test is allowed
- **The expected blast radius** — what files / processes / network calls it will create

Without authorisation you're conducting unauthorised intrusion testing. *Your* SIEM should catch it. *Your* legal team will pick you up if it does.

### Pre-brief the L1 shift

Tell the L1 team that a sanctioned T1059.001 exercise is happening between 14:00–14:30 on host `ABACWKS042`, with reference number `EX-2026-04-001`. Otherwise they'll see Bob's investigation, open a real case, and waste 30 minutes confirming it's the test you're running. They'll also start to *expect* exercises (good) and stop confusing them with real threats (also good).

The pre-brief format I use:

```
EXERCISE NOTICE — EX-2026-04-001
Date: 2026-04-27
Window: 14:00–14:30
Host: ABACWKS042 (test workstation, IT Ops scope)
TTP: T1059.001 — Encoded PowerShell via mshta
Atomic test: T1059.001-3
Expected SIEM activity:
  - Process creation events on Sysmon Event 1
  - Possible network egress to test.example.com
Expected outcome:
  - Rule "Suspicious PowerShell -enc" should fire within 5 min
  - Severity should be 'high'
  - Cross-host pivot panel should NOT show this on other hosts
Run by: <your name>
Authorised by: <CISO> + <IR lead>
```

That sentence — exactly that — goes into the exercise log and the L1 chat ahead of execution. After the exercise, the same log gets the result attached.

### Run during business hours for first attempts

You *want* detection-engineering on hand if a gap surfaces. Out-of-hours testing is a *separate* exercise validating *after-hours coverage* — it's a real exercise but it shouldn't be your first run of a TTP. First run in-hours, find the gaps, fix them, then re-run out-of-hours to validate the fix held when the team isn't watching live.

### Use a representative host

A vanilla freshly-imaged VM tells you nothing about your real telemetry. Run on a representative production-mirror host with the same EDR agent, same Sysmon config, same network egress posture as a real workstation in scope. Some orgs maintain a dedicated "purple-team labs" subnet of mirror-config hosts; that's the right pattern.

## Worked example — T1059.001 full cycle

Here's a complete cycle for *Command and Scripting Interpreter: PowerShell* using Atomic Red Team test #3 (mshta executing PowerShell).

### Prepare

ATT&CK Navigator says T1059.001 is in our threat profile (multiple sector-relevant adversaries use it). LOLBAS catalogues mshta as a viable launcher. We pick Atomic test:

```
T1059.001-3 — Mshta executes PowerShell
mshta vbscript:CreateObject("Wscript.Shell").Run(
  "powershell.exe -nop -w hidden -enc <base64-encoded payload>")(window.close)
```

The base64 payload in the public Atomic test is benign — it just runs `Get-ChildItem` on `C:\` to confirm execution. We use that payload unchanged; modifying it is a separate authorisation conversation.

### Authorise + pre-brief

Exercise notice published to L1 chat at 09:00, scheduled for 14:00. CISO + IR lead initials on the authorisation doc.

### Execute

At 14:02 we run the Atomic test on `ABACWKS042`. The exercise log captures the timestamp.

### Check telemetry — wait 30 minutes

At 14:32 we query the SIEM:

```kql
@timestamp >= "now-1h" and
host.name : "ABACWKS042" and
process.parent.name : "mshta.exe" and
process.name : "powershell.exe"
```

We expect 1 result. We get 1 result. Good — the data made it.

### Did it fire?

- Was an alert generated? Check `signal-*` index for alerts on `ABACWKS042` between 14:00–14:35
- If yes, is it the right rule? `Suspicious PowerShell -enc` should fire — not just `PowerShell launched` (too broad) or `Process Creation` (too noisy)
- If yes and right rule, what severity? Should be `high` for active LotL
- What was the latency? Time from execution (14:02) to alert created

Three possible outcomes, three different scorecard entries:

| Result | Tier | Action |
|---|---|---|
| `Suspicious PowerShell -enc` fired at 14:04 with severity `high` | 1 · Alerted | Pass. Latency 2 min, severity correct. |
| Same rule fired at 14:04 but with severity `low` | 1 with concerns | Detection-eng tunes severity for `mshta` parent up |
| No alert. Field `process.command_line` exists in winlogbeat. | 2 · Logged not alerted | Open `TuningProposal`: rule should match `mshta.exe → powershell.exe` parent-child + base64 payload |
| No alert. `process.command_line` field missing on the index. | 3 · Logged not parsed | SIEM team: fix Sysmon Event 1 parsing for command-line capture |
| Nothing in winlogbeat at all from `ABACWKS042` for that period. | 4 · Not logged | Platform team: agent dead, GPO drift, or asset isn't onboarded |

### Score and update

Whichever tier we hit, the scorecard row is:

```yaml
exercise_id: EX-2026-04-001
ttp: T1059.001
atomic_test: T1059.001-3
host: ABACWKS042
executed_at: 2026-04-27T14:02:14Z
fired_at: 2026-04-27T14:04:31Z   # or null
detection_rule: "Suspicious PowerShell -enc"  # or null
severity_assigned: high
severity_correct: true
latency_seconds: 137
fidelity_tier: 1
notes: "Clean catch. Latency under 5 min target."
```

That row goes in the scorecard. Six months in, you have ~25 of these and can answer the CISO with: *"On 22 of 25 in-scope TTPs we have Tier 1 detection. The three Tier 2 gaps are all on cloud-identity TTPs and detection-eng has the rule work in flight."* That's a defensible posture statement. *"We did a pentest and got rooted in 4 hours"* is not.

## Eight common mistakes when starting purple-team programs

These are real failure modes from actual programs. Avoid them all.

1. **Chaining TTPs in one exercise.** As covered — can't attribute findings. Always atomic.
2. **No telemetry-ingestion wait.** Declares Tier 4 gaps that are actually 30-second pipeline lag.
3. **Running on freshly-imaged VMs.** Tells you nothing about your real production telemetry posture.
4. **Skipping the pre-brief.** Wastes L1 time confirming the test isn't a real attack.
5. **Conflating detection gaps with logging gaps.** Pisses off detection-eng (you blamed them for a parsing issue) and lets the SIEM team off the hook (they should have fixed the parser).
6. **Running unsanctioned tests "to prove a point".** Career-limiting move. Always have written authorisation.
7. **Reporting binary pass/fail.** Loses fidelity-tier nuance. The scorecard needs all four tiers visible.
8. **Not closing the loop.** A gap found in March that's still a gap in September means the program isn't producing detection improvements. Set a 30-day follow-up cadence on every gap.

## Glossary

- **Adversary emulation** — Controlled execution of adversary TTPs to validate the SOC's ability to detect them. *Detection-validation*, not pentesting.
- **Atomic Red Team** — Open-source library of single-TTP tests. ~600 tests across most ATT&CK sub-techniques. `atomicredteam.io`.
- **Caldera** — MITRE's adversary-emulation platform. Heavier than Atomic; chains TTPs into emulated campaigns. Useful for chained-attack exercises *after* atomic coverage is mature.
- **TTP** — Tactic, Technique, Procedure. Specific adversary behaviour, usually a MITRE ATT&CK sub-technique ID.
- **Fidelity tier** — Where the detection landed on the four-tier scale (Alerted / Logged-not-alerted / Unparsed / Not-logged). Determines which team owns the fix.
- **Latency** — Time from TTP execution to alert creation. Sub-5-minutes is the common target for live-triage TTPs; 30-minutes acceptable for slow-burn TTPs (data exfiltration etc.).
- **Scorecard** — Persistent record of every exercise's TTP, host, fidelity tier, latency, and remediation status. The artefact you defend the SOC budget with.

## Further reading

- **Atomic Red Team** — `atomicredteam.io`. Start with the test catalogue filtered by your sector's threat actors.
- **MITRE ATT&CK Evaluations** — `attackevals.mitre.org`. MITRE benchmarks vendor EDR products against real APT TTPs. Reading the eval reports for *your* EDR is humbling and useful.
- **Caldera** — `caldera.mitre.org`. Adversary-emulation platform. Pick this up *after* you've done six months of Atomic-driven exercises.
- **PEAK Threat Hunting Framework** — see L2 *Threat Hunting with KQL* further reading. Hunting and emulation are the two sides of detection-validation.
- **Red Canary's annual Threat Detection Report** — empirical data on which TTPs actually got used in real intrusions last year. Use it to prioritise your exercise curriculum.

---

When you're ready, take the **Running an Atomic test for T1059.001** quiz to lock in the analysis flow.
""",
    )

    l2 = _add_lesson(
        session, mod, order=2, title="Running an Atomic test for T1059.001 — quiz",
        lesson_type=LessonType.QUIZ, duration_min=15,
        content_md="""
## A worked Atomic Red Team exercise

You've been authorised to emulate **T1059.001 — Command and Scripting
Interpreter: PowerShell**. Atomic Red Team's catalogue gives you ~14
tests for this technique. You pick:

> **T1059.001-3 — Mshta executes PowerShell**
>
> ```cmd
> mshta vbscript:CreateObject("Wscript.Shell").Run("powershell.exe -nop -w hidden -enc <base64>")(window.close)
> ```

You execute it on `ABACWKS042`, log the timestamp, and now ask:

1. Did the SIEM fire on it?
2. If yes, with what fidelity?
3. If no, *what* should have fired?

Take the quiz to lock in the analysis flow.
""",
    )
    _add_q(session, l2, order=1, kind=QuestionKind.SINGLE,
        stem_md="No alert fires from the SIEM. You query winlogbeat and find that `process.command_line` *does* contain the payload, but no rule matched. What's the right ATT&CK fidelity tier and what's the next action?",
        options=[
            {"value": "alerted_no_action", "label": "Alerted — score latency, no action needed"},
            {"value": "logged_open_tuning", "label": "Logged but not alerted → open a TuningProposal for the detection gap"},
            {"value": "unparsed_fix_parser", "label": "Logged but unparsed → fix the parser to expose process.command_line"},
            {"value": "not_logged_telemetry", "label": "Not logged → escalate to the platform team"},
        ],
        correct="logged_open_tuning",
        explanation_md="**Logged but not alerted.** The data was there (you confirmed the field exists in winlogbeat) but no rule matched. That's a detection-engineering gap — the right action is opening a `TuningProposal` ticket so the detection-eng team writes a new rule (or extends an existing one). Don't conflate it with a *parsing* gap (where the field doesn't exist) or a *telemetry* gap (where the data source isn't collected at all).",
        points=2,
    )
    _add_q(session, l2, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are valid pre-execution sanity checks? (Pick all that apply.)",
        options=[
            {"value": "ciso_auth", "label": "CISO + IR have signed off on the technique + window"},
            {"value": "soc_pre_brief", "label": "L1 shift has been told the test is happening so they don't open an investigation"},
            {"value": "rollback", "label": "You have a documented rollback for any persistence the test creates"},
            {"value": "production_target", "label": "You're running on a representative production host (not a freshly-imaged VM)"},
            {"value": "shift_off_hours", "label": "You're running outside business hours so the SOC isn't busy"},
        ],
        correct=["ciso_auth", "soc_pre_brief", "rollback", "production_target"],
        explanation_md="The first four are mandatory. *Off-hours* is wrong for first-attempt purple teaming — you actively *want* detection-eng on hand if you find a gap. Out-of-hours testing is a separate exercise validating after-hours coverage and should follow a successful in-hours run. The *production-host* one is sometimes contentious; prefer a representative production-mirror host where possible, but a vanilla golden-image VM doesn't tell you anything about your real telemetry.",
        points=3,
    )
    _add_q(session, l2, order=3, kind=QuestionKind.SHORTANSWER,
        stem_md="What's the MITRE ATT&CK technique ID for the parent technique 'Command and Scripting Interpreter'? (Format: T followed by 4 digits.)",
        options=None,
        correct=["T1059", "t1059"],
        explanation_md="**T1059** is the parent technique. Sub-techniques are T1059.001 (PowerShell), T1059.003 (Windows Command Shell), T1059.005 (Visual Basic), etc. When recording emulation results, capture both the parent and the sub-technique — your coverage map needs both.",
        points=1,
    )
    _add_q(session, l2, order=4, kind=QuestionKind.SINGLE,
        stem_md="A detection rule fires, but with severity *informational* and 4 hours after the event. What do you record on the exercise scorecard?",
        options=[
            {"value": "pass", "label": "Pass — detection fired"},
            {"value": "fail_severity", "label": "Fail — wrong severity"},
            {"value": "pass_with_concerns", "label": "Pass with concerns — record latency (4h is too slow) and fidelity (informational underweights an active LotL)"},
            {"value": "fail_completely", "label": "Fail completely — late & wrong severity is no different from missing"},
        ],
        correct="pass_with_concerns",
        explanation_md="**Pass with concerns.** The detection *did* fire, which is meaningful — but a 4-hour latency and informational severity for an active LotL technique are both quality issues. Record both on the scorecard so detection-engineering knows what to fix: tune severity *up*, and investigate why the rule took 4 hours (data ingestion lag? aggregation window? SIEM throughput?). Calling it a complete fail loses the partial-credit signal that something is monitoring the right field.",
        points=2,
    )

    print(f"  L3: {course.title} — 1 module, 2 lessons")
    return course


# ── Main ─────────────────────────────────────────────────────────────────


def main() -> None:
    engine = get_engine()
    factory = get_session_factory(engine)
    session = factory()
    try:
        admin = _admin_user(session)
        if not admin:
            print("[error] no users in DB — create at least one before seeding courses")
            return
        _cleanup(session)
        print("[seed] courses…")
        c1 = _seed_l1(session, admin.id)
        c2 = _seed_l2(session, admin.id)
        c3 = _seed_l3(session, admin.id)
        # L2 prerequisite is L1; L3 prerequisite is L2
        c2.prerequisite_course_id = c1.id
        c3.prerequisite_course_id = c2.id
        session.commit()

        print()
        print("─" * 60)
        print("DEMO COURSES SEEDED")
        print("─" * 60)
        print(f"  L1: /courses/{c1.slug}")
        print(f"  L2: /courses/{c2.slug}  (requires L1)")
        print(f"  L3: /courses/{c3.slug}  (requires L2)")
        print()
        print("Try: http://localhost:8000/courses")
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()
