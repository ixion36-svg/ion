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

    # ── Module 2 — SIEM Fundamentals (v0.11.5) ───────────────────────────
    # Authored at BTL1/SANS-equivalent depth. ECS-first throughout — every
    # KQL snippet uses ECS field names since ION integrates with Elastic.
    mod2 = _add_module(
        session, course, order=2,
        title="SIEM Fundamentals",
        description_md=(
            "Pipeline anatomy, the ECS data model, KQL queries, and the "
            "cluster-investigation pattern. By the end of this module you "
            "can read a Wazuh-sourced alert document, pivot in Kibana, and "
            "hand a clean timeline to L2."
        ),
        estimated_minutes=180,
    )

    m2l1 = _add_lesson(
        session, mod2, order=1,
        title="What a SIEM is and how data flows through it",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Name the six stages of the SIEM pipeline (ingest → parse → normalise → store → query → alert) and identify which Elastic Stack component owns each
> 2. Distinguish a SIEM from a plain log aggregator using at least three concrete capability differences
> 3. Compare cloud-native, on-prem, and hybrid SIEM architectures in terms an L1 cares about (data residency, latency, what you can self-serve vs escalate)
> 4. Trace a single Windows Security event from generation on the endpoint to visibility in Kibana
> 5. Identify the failure modes at each pipeline stage that an L1 is likely to notice
>
> **Prerequisites.** Module 1 *Alert Triage Fundamentals* completed.

## The six-stage pipeline

A SIEM is not a single product — it's a pipeline that ingests events from heterogeneous sensors, normalises them into a shared schema, stores them in a queryable substrate, and runs detection logic on top. Memorise the six stages — every SIEM you encounter in your career maps onto them:

```mermaid
flowchart LR
    subgraph Endpoint
        A[Sysmon / Security<br/>Event Log] --> B[Winlogbeat]
        C[auditd / syslog] --> D[Filebeat /<br/>Auditbeat]
        E[NIC mirror] --> F[Packetbeat]
    end
    B --> G[Ingest pipeline<br/>ECS normaliser]
    D --> G
    F --> G
    G --> H[(Elasticsearch<br/>data streams)]
    H --> I[Kibana Discover]
    H --> J[Detection engine<br/>scheduled rules]
    J --> K[(.alerts-security.<br/>alerts-default)]
    K --> L[ION case ingest]
    L --> M[Tier-1 analyst]
```

1. **Ingest** — A sensor (Sysmon, auditd, a firewall, a cloud audit log) emits an event. A shipper picks it up and forwards it. In ION's deployment that's `winlogbeat`, `filebeat`, `packetbeat`, `auditbeat`, or the Wazuh agent.
2. **Parse** — The raw event (XML for Windows, syslog text for Linux, JSON for cloud) is broken into key/value pairs. In Elastic this happens via Beats processors, ingest pipelines, or Logstash filters. The output is structured but not yet schema-conformant.
3. **Normalise** — Fields are renamed and re-typed to the canonical schema. ECS is the canonical schema for the Elastic Stack; CIM is the equivalent for Splunk. After this stage, a Windows logon and a Linux SSH login both produce documents with `event.category: ["authentication"]` and `user.name`.
4. **Store** — Documents are written to a time-series index. Elasticsearch uses index lifecycle management (ILM) to roll indices over (e.g. `winlogbeat-*` becomes `.ds-winlogbeat-2026.04.23-000001`).
5. **Query** — Analysts and detection rules read the indices via Kibana Discover, Lens, or the search API.
6. **Alert** — Detection logic (Elastic detection rules, Wazuh rules, EQL queries) runs on a schedule, evaluates conditions, and emits alert documents into a separate index (`.alerts-security.alerts-default`) which ION ingests as cases.

When an alert *doesn't* fire, the failure is almost always at parse, normalise, or query stage. **An L1 who can localise the failure to a stage is already more useful than one who can't.**

## Worked example — tracing a 4625 from endpoint to Kibana

A Windows host `WS-FIN-014.corp.example.org` has a failed logon. Walk through the pipeline:

```mermaid
sequenceDiagram
    participant EP as Endpoint
    participant WB as Winlogbeat
    participant ES as Elasticsearch
    participant DR as Detection rule
    participant ION as ION
    participant L1 as L1 Analyst
    EP->>WB: EventID 4625
    WB->>WB: Parse XML, apply ECS module
    WB->>ES: POST winlogbeat-* doc
    Note right of ES: stage: store
    DR->>ES: every 5min: query last 15min<br/>event.code:"4625" group by source.ip
    ES-->>DR: 14 hits, src 10.42.7.91
    DR->>ES: write .alerts-security doc
    ES-->>ION: alert pulled into case
    ION->>L1: Case CRIT-2026-04123 opened
    L1->>ES: Discover pivot: source.ip:"10.42.7.91"
```

- **Ingest:** Windows writes EventID 4625 to the `Security` channel; `winlogbeat` reads it via `winlogbeat.event_logs` configuration and forwards it.
- **Parse:** The Beat's Windows module decodes the event XML and extracts `winlog.event_id: "4625"`, `winlog.event_data.TargetUserName: "j.smith"`, `winlog.event_data.IpAddress: "10.42.7.91"`.
- **Normalise:** The module's ECS processor sets `event.code: "4625"`, `event.action: "logon-failed"`, `event.category: ["authentication"]`, `event.outcome: "failure"`, `user.name: "j.smith"`, `source.ip: "10.42.7.91"`, `host.name: "WS-FIN-014"`.
- **Store:** The document lands in the data stream backing `winlogbeat-*`, with `@timestamp` set to the event's UTC timestamp.
- **Query:** Analyst opens Discover with index pattern `winlogbeat-*` and filters `event.code : "4625" and host.name : "WS-FIN-014"`.
- **Alert:** A detection rule "Multiple Logon Failures from Same Source" runs every 5 minutes, queries the last 15 minutes for `event.code : "4625"` grouped by `source.ip`, and fires when count > 10. The alert document appears in `.alerts-security.alerts-default` and ION pulls it into a case.

## SIEM versus log aggregator

Every shop has a graveyard of "we'll just grep the logs" projects. A SIEM differs from a flat log aggregator (rsyslog-on-a-box, Loki, plain S3) along five axes:

1. **Schema enforcement** — ECS or CIM means a query for `user.name : "alice"` returns Windows logons, SSH logins, and AWS API calls in one result set. Aggregators preserve raw text; you'd have to know each format.
2. **Detection engine** — A SIEM runs scheduled rules with state (deduplication, suppression, throttling). An aggregator can be hooked up to alerting, but the rule logic, exception handling, and alert document format are bolted on.
3. **Enrichment** — Threat-intel lookups, GeoIP, asset criticality, user identity attributes — applied at ingest or query time. ION's TIDE/OpenCTI integration enriches IOCs at query time.
4. **Workflow** — Alert states (acknowledged, in-progress, closed), assignments, comments, runbooks, case handoff. The alert is treated as a long-lived object, not a transient log line.
5. **Retention tiers** — Hot/warm/cold/frozen storage with ILM. Aggregators usually do not separate detection-relevant retention from compliance retention.

ION layers cases, AI summaries, and ticker workflow on top of an Elastic SIEM, so the SIEM-vs-aggregator distinction matters: when an analyst says *"the data isn't in the SIEM"*, they may mean it's in raw log storage but never normalised. That's a real and recoverable failure, but it requires a different fix than *"the alert didn't fire"*.

## Architectures: cloud, on-prem, hybrid

Three deployment patterns dominate. An L1 should know which one their employer runs because it changes day-to-day workflow:

- **Cloud-native SIEM** — Elastic Cloud, Microsoft Sentinel, Chronicle, Sumo Logic. Storage and compute are vendor-managed. Ingest happens via cloud-side endpoints; on-prem assets ship via agents over TLS. **Pros:** scales without ops effort, vendor handles ILM and shard math. **Cons:** egress costs, data-residency concerns, less visibility into the underlying cluster when something breaks.
- **On-prem SIEM** — Self-hosted Elasticsearch, Splunk Enterprise, Wazuh manager. Common in regulated industries (healthcare, defence, finance). ION's reference deployment is on-prem-style: a Docker-Compose Elastic + Wazuh stack inside the customer environment. **Pros:** full control over data, no egress, integration with on-prem identity (Keycloak, AD). **Cons:** ops burden — you're responsible for cluster health, backups, ILM tuning.
- **Hybrid** — A common real-world shape: Wazuh manager on-prem ingesting endpoint events, forwarding alerts to a cloud-hosted Elastic for long-term retention and cross-tenant search.

For an L1, the architecture decision affects: (1) where to look when ingest is delayed (which queue is backed up?), (2) which hostname to use when contacting an asset (the SIEM's view may lag DHCP), (3) what you can self-serve versus what requires the platform team. ION analysts working an on-prem deployment can typically check `docker compose ps` on the SIEM host themselves; analysts on a cloud deployment cannot and must escalate.

## Worked example — "the dashboard says zero events"

Analyst sees `WS-MKT-022` is missing from the asset-coverage dashboard. They check Discover with `host.name : "WS-MKT-022"` over the last 24 hours and see 12,000 events. The dashboard's saved search is filtered on a custom field `asset.criticality : "high"` which is populated by an enrichment pipeline. The host's enrichment record was deleted last week. The pipeline flaw is at the **enrichment** stage — events are flowing, the schema is intact, but the dashboard's filter condition is no longer satisfied. The correct action is to escalate to the detection-engineering team for enrichment repair, not to chase the host as "offline".

## Glossary

- **ECS (Elastic Common Schema)** — Open schema defining canonical field names for security and observability data
- **Beats** — Lightweight Elastic shippers (Winlogbeat, Filebeat, Packetbeat, Auditbeat)
- **Ingest pipeline** — Server-side document processor in Elasticsearch that runs before storage
- **ILM (Index Lifecycle Management)** — Elasticsearch policy mechanism for hot/warm/cold/frozen tier transitions
- **Data stream** — Append-only abstraction over rolling indices; `winlogbeat-*` is a data stream alias
- **CIM (Common Information Model)** — Splunk's equivalent of ECS
- **Detection rule** — Scheduled query that emits an alert document when its condition is satisfied
- **Sensor** — Source of telemetry (Sysmon, auditd, NetFlow exporter)
- **Shipper** — Agent forwarding events from sensor to SIEM
- **Wazuh manager** — Open-source HIDS that produces alert documents consumable by Elastic
- **Hybrid SIEM** — Architecture mixing on-prem ingest with cloud retention/search

## Further reading

- Elastic Common Schema reference: https://www.elastic.co/guide/en/ecs/current/index.html
- Elastic Beats overview: https://www.elastic.co/guide/en/beats/libbeat/current/beats-reference.html
- Wazuh integration with Elastic Stack: https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html
- BTL1 syllabus: SIEM Domain — Investigating with Splunk / ELK
- SANS GCIH KSA: Domain 1 — Log Analysis Fundamentals
""",
    )

    # Quiz on Lesson 1
    m2l1q = _add_lesson(
        session, mod2, order=2,
        title="Pipeline + architecture quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md=(
            "Five questions on the pipeline stages, SIEM-vs-aggregator differences, "
            "and ION's deployment architecture. Pass threshold matches the course "
            "default — re-read Lesson 1 if you fall short."
        ),
    )
    _add_q(session, m2l1q, order=1, kind=QuestionKind.SINGLE,
        stem_md="Which Elastic Stack component is responsible for the **normalise** stage of the SIEM pipeline?",
        options=[
            {"value": "kibana", "label": "Kibana"},
            {"value": "beats_modules", "label": "Beats modules / ingest pipelines"},
            {"value": "detection_engine", "label": "The detection engine"},
            {"value": "ilm", "label": "ILM (Index Lifecycle Management)"},
        ],
        correct="beats_modules",
        explanation_md="**Beats modules** (or Logstash filters / ingest pipelines) apply the ECS schema during ingest. Kibana queries the normalised data and ILM manages index rollover; neither performs normalisation itself.",
        points=2,
    )
    _add_q(session, m2l1q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which capabilities differentiate a SIEM from a plain log aggregator? Pick all that apply.",
        options=[
            {"value": "schema", "label": "Schema normalisation"},
            {"value": "rules", "label": "Scheduled detection rules with suppression"},
            {"value": "compression", "label": "Compression of stored data"},
            {"value": "workflow", "label": "Alert lifecycle workflow"},
            {"value": "tiers", "label": "Hot/warm/cold retention tiers"},
        ],
        correct=["schema", "rules", "workflow", "tiers"],
        explanation_md="Compression is a property of any storage system. The other four capture the value SIEMs add over flat aggregators — schema enforcement, stateful detection, workflow, and tiered retention.",
        points=3,
    )
    _add_q(session, m2l1q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="A failed alert can always be diagnosed by checking whether the underlying events arrived in the index.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** Events may be present but with the wrong schema (parse/normalise failure), or the rule's filter context may exclude them, or the rule may have run during a query-stage outage. Index presence is necessary but not sufficient.",
        points=1,
    )
    _add_q(session, m2l1q, order=4, kind=QuestionKind.SINGLE,
        stem_md="ION ingests its cases from which Elasticsearch index family by default?",
        options=[
            {"value": "winlogbeat", "label": "winlogbeat-*"},
            {"value": "filebeat", "label": "filebeat-*"},
            {"value": "alerts", "label": ".alerts-security.alerts-default"},
            {"value": "metrics", "label": "metrics-*"},
        ],
        correct="alerts",
        explanation_md="Detection rules write to the alerts data stream; ION pulls cases from there, not from the raw Beats indices.",
        points=2,
    )
    _add_q(session, m2l1q, order=5, kind=QuestionKind.SHORTANSWER,
        stem_md="Name two architectural advantages of an on-prem SIEM relative to a cloud-native one.",
        options=None,
        correct=["data residency, no egress costs", "no egress, on-prem identity", "data residency, identity integration", "control over retention, no egress"],
        explanation_md="Acceptable answers: data residency / no egress costs, tighter integration with on-prem identity providers (AD, Keycloak), full control over retention. Any two are correct.",
        points=2,
    )

    # Lesson 2 — ECS data model
    m2l2 = _add_lesson(
        session, mod2, order=3,
        title="Speaking ECS — the data model L1 lives in",
        lesson_type=LessonType.READING, duration_min=22,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Recall the ten core ECS fields used in 90% of L1 triage queries and identify their data type
> 2. Map a Windows Security event, a Linux auditd record, and a Sysmon process-creation event to their ECS representations
> 3. Recognise common ECS pitfalls (case sensitivity, multi-value fields, `event.action` vs `event.code`)
> 4. Translate between Wazuh `rule.*` fields and ECS `event.*` fields
> 5. Validate an unfamiliar field by checking the ECS reference rather than guessing

## The ten fields you'll type every shift

ECS defines hundreds of fields, but L1 triage hinges on a small set. Memorise these:

| Field | Type | Meaning | Example |
| --- | --- | --- | --- |
| `@timestamp` | date | UTC timestamp of the event itself, not of ingest | `2026-04-23T08:14:22.331Z` |
| `host.name` | keyword | Hostname per the host's own metadata | `WS-FIN-014` |
| `user.name` | keyword | Acting user (logged-on, executing, authenticating) | `j.smith` |
| `source.ip` | ip | Source IP of an event with directionality | `10.42.7.91` |
| `destination.ip` | ip | Destination IP | `185.220.101.7` |
| `process.name` | keyword | Executable name without path | `powershell.exe` |
| `process.command_line` | keyword | Full command line as launched | `powershell.exe -enc JABh...` |
| `process.parent.name` | keyword | Parent process name | `winword.exe` |
| `event.action` | keyword | Source-agnostic action verb | `logon-failed`, `process-started` |
| `event.code` | keyword | Source-specific code | `4625`, `1` (Sysmon) |
| `event.category` | keyword (array) | High-level category | `["authentication"]`, `["process"]` |
| `network.transport` | keyword | TCP / UDP / ICMP | `tcp` |
| `file.path` | keyword | Full path of touched file | `C:\\\\Users\\\\j.smith\\\\AppData\\\\Local\\\\Temp\\\\inv.docm` |
| `file.hash.sha256` | keyword | SHA-256 of file content | `9f86d081...` |

### Three rules that bite L1 analysts repeatedly

1. **Field names are case-sensitive in KQL.** `User.Name` will silently match nothing.
2. **`event.category` is an array.** Use `event.category : "process"` (KQL handles array-contains automatically) but be aware aggregations may double-count.
3. **`event.action` versus `event.code`.** `event.action` is normalised across sources (a Windows logon-failed and a Linux ssh-failed both use `logon-failed`). `event.code` is source-specific (Windows EventID, Sysmon EventID, Wazuh rule ID). Default to `event.action` for cross-source hunts, `event.code` when you specifically need the Windows event ID.

## Worked example — same event, three sources

A user `m.alvarez` authenticates. Three telemetry sources record it; ECS makes the triple queryable in one shot:

- **Windows EventID 4624 (winlogbeat):** `event.category: ["authentication"]`, `event.action: "logged-in"`, `event.outcome: "success"`, `event.code: "4624"`, `user.name: "m.alvarez"`, `host.name: "WS-FIN-021"`.
- **Linux SSH (filebeat system module):** `event.category: ["authentication"]`, `event.action: "ssh_login"`, `event.outcome: "success"`, `user.name: "m.alvarez"`, `host.name: "lnx-jump-02"`, `source.ip: "10.42.4.18"`.
- **AWS CloudTrail ConsoleLogin (filebeat aws module):** `event.category: ["authentication"]`, `event.action: "ConsoleLogin"`, `event.outcome: "success"`, `user.name: "m.alvarez"`, `cloud.provider: "aws"`, `aws.cloudtrail.event_name: "ConsoleLogin"`.

A single KQL query `user.name : "m.alvarez" and event.category : "authentication" and @timestamp >= "now-24h"` returns all three. **That's the payoff of ECS** — and the reason ION's alert prompts and pgvector embeddings can stay source-agnostic.

```mermaid
flowchart TB
    subgraph Sources
        W[Windows<br/>Security 4624/4625]
        S[Sysmon<br/>EID 1/3/11]
        A[auditd<br/>execve / open]
        P[Packetbeat<br/>DNS / HTTP]
        WZ[Wazuh<br/>rule.id]
    end
    subgraph ECS
        E1[event.action]
        E2[event.category]
        E3[user.name]
        E4[host.name]
        E5[source.ip /<br/>destination.ip]
        E6[process.*]
        E7[file.*]
    end
    W --> E1 & E2 & E3 & E4 & E5
    S --> E1 & E2 & E4 & E6
    A --> E1 & E2 & E3 & E4 & E6 & E7
    P --> E5 & E2
    WZ --> E1 & E2
```

## Worked example — a Sysmon EventID 1 to ECS to KQL

Sysmon raw fields (what the endpoint emits):

```
ProcessId=8312
Image=C:\\Windows\\System32\\cmd.exe
CommandLine="cmd.exe" /c whoami
ParentImage=C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE
ParentCommandLine="WINWORD.EXE" /n "C:\\Users\\j.smith\\Downloads\\invoice.docm"
User=CORP\\j.smith
```

After ECS normalisation by the winlogbeat sysmon module:

```
event.code: "1"
event.action: "process-started"
event.category: ["process"]
process.name: "cmd.exe"
process.executable: "C:\\Windows\\System32\\cmd.exe"
process.command_line: "\\"cmd.exe\\" /c whoami"
process.parent.name: "WINWORD.EXE"
process.parent.command_line: "\\"WINWORD.EXE\\" /n \\"C:\\Users\\j.smith\\Downloads\\invoice.docm\\""
user.name: "j.smith"
user.domain: "CORP"
```

The ECS form is queryable by:

```kql
process.parent.name : "WINWORD.EXE" and process.name : ("cmd.exe" or "powershell.exe")
```

A classic Office-spawning-shell hunt mapped to MITRE ATT&CK **T1566.001** (Spearphishing Attachment) followed by **T1059** (Command and Scripting Interpreter).

## How sensors map to ECS

The mapping between sensor and ECS is the responsibility of the Beat/Agent module or the ingest pipeline. Knowing roughly how each common L1 source maps will save you hours when a field "doesn't seem to be populated":

- **Winlogbeat (Security, System, Application channels)** — XML EventData fields end up under `winlog.event_data.*` raw, with the most useful ones promoted to ECS via the Windows module. EventID 4624's `TargetUserName` becomes `user.name`; `IpAddress` becomes `source.ip`; the channel becomes `winlog.channel`.
- **Sysmon via Winlogbeat-sysmon module** — Sysmon EventID 1 (process create) maps to `event.action: "process-started"`, `process.executable`, `process.command_line`, `process.parent.executable`, `process.hash.sha256`. EventID 3 (network connect) populates `source.ip`, `destination.ip`, `network.transport`.
- **Auditbeat (auditd module on Linux)** — `event.action: "executed"` for execve, with `process.executable`, `process.args`, `user.name`, `user.effective.name`. File integrity events use `event.action: "modified"` / `"created"` / `"deleted"` and populate `file.path`, `file.hash.sha256`.
- **Packetbeat** — Protocol-aware passive sniffing. DNS queries map to `dns.question.name`, `dns.resolved_ip`. HTTP requests map to `http.request.method`, `url.full`, `user_agent.original`.
- **Wazuh agent / Wazuh-Elastic integration** — Wazuh produces its own JSON with `rule.id`, `rule.description`, `rule.level`, `rule.mitre.id` (an array of ATT&CK technique IDs), and `decoder.name`. ION's alert-prompt matcher uses both `rule.id` (5-tier matcher tier 1) and `rule.mitre.technique` (tier 3).

## Common pitfalls and gotchas

- **Field-not-populated versus field-not-present.** `not user.name : *` matches docs where the field is absent. `user.name : ""` matches docs where it's the empty string. Distinct cases, distinct meanings.
- **Time skew.** `@timestamp` is event time; `event.ingested` is ingest time. If a host's clock drifts, queries on `@timestamp` will mis-align with reality. Spot this by comparing the two fields.
- **Multi-value categories.** A document may have `event.category: ["network", "session"]`. A query `event.category : "network"` matches; a visualisation grouping by category may double-count.
- **Truncation.** Long `process.command_line` values can exceed `keyword`'s default `ignore_above` (1024 chars). The `.text` subfield (analysed) is searchable but the `keyword` is not — leading to confusing *"the command line is there but my term query doesn't hit"* results.
- **ECS version drift.** ECS evolves. ION's stack pins a version; new fields in ECS 8.x may not be present in older indices. Check Discover's field list before assuming a field is absent from the data model.

## Glossary

- **ECS field** — A canonical key under a defined namespace (e.g. `process.command_line`)
- **Keyword field** — Exact-match string field in Elasticsearch (case-sensitive)
- **Text field** — Analysed (tokenised) string field; supports full-text search
- **`@timestamp`** — Event-time, UTC, the primary time axis
- **`event.ingested`** — Time the document landed in the SIEM (post-pipeline)
- **`event.action`** — Source-agnostic action verb
- **`event.code`** — Source-specific event identifier
- **Multi-value field** — ECS field that legitimately holds an array
- **Promotion** — Beats-pipeline step that copies a raw field into its ECS counterpart
- **`winlog.event_data.*`** — Raw Windows EventData container (pre-promotion)
- **CIM mapping** — Splunk's Common Information Model equivalent (e.g. `src_ip` for `source.ip`)

## Further reading

- ECS field reference: https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
- ECS event categorisation: https://www.elastic.co/guide/en/ecs/current/ecs-category-field-values-reference.html
- Winlogbeat Windows module: https://www.elastic.co/guide/en/beats/winlogbeat/current/winlogbeat-module-security.html
- Wazuh ruleset: https://documentation.wazuh.com/current/user-manual/ruleset/index.html
- MITRE ATT&CK technique references: T1059 (Command and Scripting Interpreter), T1566.001 (Spearphishing Attachment)
""",
    )

    # Quiz on Lesson 2
    m2l2q = _add_lesson(
        session, mod2, order=4,
        title="ECS field knowledge — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Six questions on the core ECS fields, source mappings, and pitfalls.",
    )
    _add_q(session, m2l2q, order=1, kind=QuestionKind.SINGLE,
        stem_md="Which ECS field stores the **full executed command line** of a process?",
        options=[
            {"value": "name", "label": "process.name"},
            {"value": "executable", "label": "process.executable"},
            {"value": "command_line", "label": "process.command_line"},
            {"value": "args", "label": "process.args"},
        ],
        correct="command_line",
        explanation_md="`process.name` is the bare executable name, `process.executable` is the full path, `process.args` is the parsed argument array. `process.command_line` is the unparsed full string.",
        points=2,
    )
    _add_q(session, m2l2q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which fields would you add to a hunt query for *Office spawning a shell*? Pick all that apply.",
        options=[
            {"value": "parent_name", "label": "process.parent.name"},
            {"value": "name", "label": "process.name"},
            {"value": "os_family", "label": "host.os.family"},
            {"value": "category", "label": "event.category : \"process\""},
            {"value": "outcome", "label": "event.outcome"},
        ],
        correct=["parent_name", "name", "category"],
        explanation_md="`host.os.family` is rarely needed because Office is Windows-bound and the parent name already signals that. `event.outcome` doesn't apply meaningfully to process-creation events.",
        points=3,
    )
    _add_q(session, m2l2q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="`event.action` and `event.code` always have the same value for a Windows logon event.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** `event.action` is normalised (`logged-in`, `logon-failed`); `event.code` is the Windows EventID (`4624`, `4625`). They're intentionally distinct.",
        points=1,
    )
    _add_q(session, m2l2q, order=4, kind=QuestionKind.SHORTANSWER,
        stem_md="Why might a query `user.name : \"alice\"` return zero hits even when Discover shows authentication events for Alice?",
        options=None,
        correct=["case sensitivity", "case", "domain prefix", "normalisation gap", "the value is uppercase Alice"],
        explanation_md="Acceptable: case sensitivity (`Alice` vs `alice`), domain prefix (`CORP\\Alice` stored verbatim), or normalisation gap where the source populates `winlog.event_data.TargetUserName` but the ingest pipeline didn't promote it to `user.name`. Any one is correct.",
        points=2,
    )
    _add_q(session, m2l2q, order=5, kind=QuestionKind.SINGLE,
        stem_md="A Wazuh alert document's `rule.mitre.technique` field contains `[\"T1059.001\", \"T1566.001\"]`. What does this tell an L1 analyst?",
        options=[
            {"value": "invalid", "label": "The alert is invalid because techniques are mutually exclusive"},
            {"value": "multi", "label": "The Wazuh rule is mapped to multiple ATT&CK techniques and either may apply"},
            {"value": "twice", "label": "The alert fired twice"},
            {"value": "first", "label": "Only the first technique is authoritative"},
        ],
        correct="multi",
        explanation_md="ATT&CK technique mappings can be plural — a single rule may legitimately cover multiple techniques (here, PowerShell + Spearphishing Attachment). Both are candidate context.",
        points=2,
    )
    _add_q(session, m2l2q, order=6, kind=QuestionKind.SHORTANSWER,
        stem_md="Name two ECS fields that always appear on a Sysmon EventID 3 (network connect) document.",
        options=None,
        correct=["source.ip, destination.ip", "destination.ip, network.transport", "source.ip, network.transport", "host.name, source.ip", "source.ip and destination.ip"],
        explanation_md="Acceptable: `source.ip` / `destination.ip` (and/or `source.port` / `destination.port`), `network.transport`, `process.name`, `host.name`. Any two of these.",
        points=2,
    )

    # Lesson 3 — KQL
    m2l3 = _add_lesson(
        session, mod2, order=5,
        title="Querying the SIEM with KQL",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Write KQL boolean expressions using `and`, `or`, `not`, parentheses, and field-existence checks
> 2. Use wildcards, ranges, and lists in KQL queries while avoiding common performance pitfalls
> 3. Compose triage queries against `winlogbeat-*`, `filebeat-*`, and `logs-*` index patterns
> 4. Read SPL well enough to translate a basic Splunk detection into KQL
> 5. Recognise four hunt patterns: failed-auth-by-user, suspicious-child-of-svchost, beaconing detection, newly-registered-domain DNS

## KQL syntax in the depth an L1 actually needs

KQL (Kibana Query Language) is the default in Discover and detection rules. Syntax in the order you'll use it:

- **Term match:** `field : "value"`. Quotes are required if the value contains spaces or special characters.
- **Boolean:** `and`, `or`, `not`, lowercase. Group with parentheses: `(a or b) and not c`.
- **Wildcards:** `*` matches zero or more characters in a `keyword` field. `process.name : "power*"` works; leading wildcards (`*shell.exe`) are valid but slow — avoid in scheduled rules.
- **Lists:** `field : (val1 or val2 or val3)`. Equivalent to multiple ORs but easier to read.
- **Ranges:** `field >= value`, `field <= value`. For dates use Kibana time tokens: `@timestamp >= "now-1h"`.
- **Existence:** `field : *` matches any document with the field populated. `not field : *` matches absence.
- **Nested fields:** ECS dot notation works directly: `process.parent.name : "winword.exe"`.
- **Escaping:** Backslashes need doubling: `process.executable : "C:\\\\Windows\\\\System32\\\\cmd.exe"`. Colons inside quoted values are fine.

What KQL **does not** give you: aggregation, joins, regex (in Discover proper — Lens has different syntax), temporal correlation. For aggregations you use Lens or the search API; for cross-event correlation in Elastic you use EQL or detection-rule logic. As an L1, you stay in the boolean-filter regime; aggregations come from Lens visualisations or saved searches built by detection engineers.

## Worked example — building a query iteratively

**Goal:** find PowerShell launches by `j.smith` on `WS-FIN-014` in the last 6 hours, where the command line shows base64-encoded payloads.

```mermaid
flowchart LR
    A[Goal stated<br/>in English] --> B{Identify<br/>core ECS fields}
    B --> C[Term filters<br/>field : value]
    C --> D{Too broad?}
    D -- yes --> E[Add user,<br/>host, time]
    E --> D
    D -- no --> F{Too narrow?}
    F -- yes --> G[Loosen one<br/>condition]
    G --> D
    F -- no --> H[Save / hand to<br/>detection engineer]
```

- **Start:** `process.name : "powershell.exe"` — too broad.
- **Add user:** `process.name : "powershell.exe" and user.name : "j.smith"` — still broad if Smith uses PS legitimately.
- **Add host:** `... and host.name : "WS-FIN-014"`.
- **Add command-line condition:** `... and process.command_line : *-enc*` — common encoded-command flag.
- **Add time:** `... and @timestamp >= "now-6h"`.
- **Final:** `process.name : "powershell.exe" and user.name : "j.smith" and host.name : "WS-FIN-014" and process.command_line : *-enc* and @timestamp >= "now-6h"`.

If this returns 200 hits, the leading wildcard combined with broad command-line text is the bottleneck — replace with `process.command_line : ("*-enc *" or "*-encodedcommand*" or "*-e *")` to anchor the flag.

## Four hunt patterns L1 must read fluently

These four patterns cover most L1 triage queries. **Memorise the shape, not the verbatim string.**

### Pattern A — Failed logons by user, with a threshold

```kql
event.category : "authentication"
  and event.outcome : "failure"
  and user.name : "j.smith"
  and @timestamp >= "now-24h"
```

**Triage:** count by `source.ip` in Lens. > 5 distinct sources is suspicious. Cross-reference with successful logon (`event.outcome : "success"`) immediately following.

### Pattern B — Suspicious child of `svchost.exe`

```kql
process.parent.name : "svchost.exe"
  and not process.name : (
    "wuauclt.exe" or "WmiPrvSE.exe" or "TiWorker.exe" or
    "TrustedInstaller.exe" or "MoUsoCoreWorker.exe" or "sihost.exe"
  )
  and host.os.family : "windows"
```

**Triage:** `svchost.exe` legitimately spawns a known set of children. Anything outside the allow-list (e.g. `cmd.exe`, `powershell.exe`, unknown EXEs) is suspicious. Maps to ATT&CK **T1055** (Process Injection) and **T1543.003** (Windows Service).

### Pattern C — Beaconing detection (read-only at L1; detection engineers tune)

```kql
event.category : "network"
  and source.ip : "10.42.7.91"
  and destination.ip : *
  and not destination.ip : (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)
  and @timestamp >= "now-6h"
```

L1 won't compute interval consistency in KQL — that needs Lens or a detection rule. **The L1's job is to read the resulting alert:** "host X made N outbound connections to destination Y at consistent ~60s intervals over 6h". Maps to ATT&CK **T1071** (Application Layer Protocol).

### Pattern D — DNS to newly-registered or low-reputation domains

```kql
event.category : "network"
  and event.dataset : "*dns*"
  and dns.question.name : *
  and source.ip : 10.42.0.0/16
  and @timestamp >= "now-1h"
```

Then enrich with TIDE / OpenCTI in ION. The L1 doesn't compute "newly registered" — TIDE provides the verdict. The query gets the candidate set; the enrichment provides the score. Maps to ATT&CK **T1071.004** (DNS).

## Worked example — reading a real triage query

A detection engineer hands the L1 the following saved search to use during triage:

```kql
(event.code : "4688" or event.code : "1")
  and process.parent.name : "WINWORD.EXE"
  and not process.name : ("WerFault.exe" or "splwow64.exe")
```

**Line-by-line:**

- `(event.code : "4688" or event.code : "1")` — Windows Process Creation (4688) or Sysmon Process Create (1). Some hosts have one, some both, some neither — this hedges.
- `process.parent.name : "WINWORD.EXE"` — Word is the parent. Note no path or domain — this matches both legitimate and renamed-Word cases (a renamed process keeping the same `process.name` is itself suspicious; `process.executable` would tell that story).
- `not process.name : ("WerFault.exe" or "splwow64.exe")` — Word legitimately spawns these (crash reporter, print spooler bridge); excluding them removes noise.

The L1 reads this and understands: *"show me everything Word starts, except the two known-benign helpers"*. They do **not** modify the query without escalating to detection engineering, because the exclusion list is curated.

## SPL contrast and translation

ION uses KQL, but L1 analysts move between employers and you'll encounter Splunk. The translation is mostly mechanical:

- KQL `field : "value"` → SPL `field="value"`
- KQL `and` / `or` / `not` → SPL `AND` / `OR` / `NOT` (case-sensitive in SPL)
- KQL `field : *` → SPL `field=*`
- KQL aggregation? Done in Lens. SPL does it inline: `| stats count by user, src_ip`
- KQL time range? Time picker. SPL: `earliest=-1h latest=now`

Direct translation example:

```kql
event.code : "4625" and source.ip : 10.42.0.0/16 and @timestamp >= "now-1h"
```

```spl
index=wineventlog EventCode=4625 src_ip=10.42.0.0/16 earliest=-1h
| stats count by src_ip, user
```

Note SPL uses CIM (`src_ip`, `user`), not ECS (`source.ip`, `user.name`). **Memorise the half-dozen common mappings:** `src_ip` ↔ `source.ip`, `dest_ip` ↔ `destination.ip`, `user` ↔ `user.name`, `host` ↔ `host.name`, `process` ↔ `process.name`, `command_line` ↔ `process.command_line`.

## High-signal queries to keep in your head

```kql
process.parent.name : "svchost.exe"
  and process.name : ("cmd.exe" or "powershell.exe" or "rundll32.exe" or "regsvr32.exe")
  and @timestamp >= "now-24h"
```

High-signal hunt for living-off-the-land binaries spawned by `svchost.exe`. Maps to **T1218** (System Binary Proxy Execution).

```kql
event.code : "1102"
```

Windows Security log cleared. Single-event hunt — rare and high-signal. Maps to **T1070.001** (Indicator Removal: Clear Windows Event Logs).

```kql
process.command_line : (*Invoke-Expression* or *IEX*(* or *DownloadString* or *FromBase64String*)
```

PowerShell encoded-execution patterns. Maps to **T1059.001**. Note: not for production detection (too noisy without further qualifiers); fine for hunt.

## Glossary

- **KQL** — Kibana Query Language; boolean filter language used in Discover and detection rules
- **EQL** — Event Query Language; Elastic's correlation language (sequence, with-windows, joins)
- **SPL** — Splunk's Search Processing Language; pipeline-based search and analytics
- **Wildcard** — `*` in a query value, matching zero or more characters
- **Leading wildcard** — Wildcard at the start of a value (`*ell.exe`); generally slow
- **CIDR notation** — `10.42.7.0/24` form for IP ranges; KQL accepts directly on `ip` fields
- **Existence check** — `field : *` (present) or `not field : *` (absent)
- **Lens** — Kibana's drag-and-drop aggregation/visualisation tool
- **Detection rule** — Scheduled query that emits an alert; authored in KQL, EQL, or threshold form
- **Time picker** — Kibana's time-range selector that sets the implicit `@timestamp` filter
- **LOLBin** — Living-Off-the-Land Binary; a signed system binary abused by attackers (e.g. `regsvr32.exe`, `rundll32.exe`)

## Further reading

- KQL syntax reference: https://www.elastic.co/guide/en/kibana/current/kuery-query.html
- Elastic detection rules: https://github.com/elastic/detection-rules
- EQL syntax: https://www.elastic.co/guide/en/elasticsearch/reference/current/eql-syntax.html
- LOLBAS project: https://lolbas-project.github.io/
- MITRE ATT&CK: T1059, T1071, T1218, T1055, T1543.003, T1070.001
""",
    )

    # Quiz on Lesson 3
    m2l3q = _add_lesson(
        session, mod2, order=6,
        title="KQL fluency — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Six questions on KQL syntax, performance, and SPL translation.",
    )
    _add_q(session, m2l3q, order=1, kind=QuestionKind.SINGLE,
        stem_md="Which KQL expression matches documents where `user.name` is populated **and** not equal to `SYSTEM`?",
        options=[
            {"value": "exists_and_not", "label": "user.name : * and not user.name : \"SYSTEM\""},
            {"value": "neq", "label": "user.name != \"SYSTEM\""},
            {"value": "not_only", "label": "not user.name : \"SYSTEM\""},
            {"value": "wild", "label": "user.name : *SYSTEM*"},
        ],
        correct="exists_and_not",
        explanation_md="`not user.name : \"SYSTEM\"` alone matches absence as well as non-SYSTEM. KQL has no `!=` operator. The combined existence + negation form is required.",
        points=2,
    )
    _add_q(session, m2l3q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which KQL queries are likely to perform poorly in scheduled detection rules? Pick all that apply.",
        options=[
            {"value": "leading_wild_cmd", "label": "process.command_line : *encoded*"},
            {"value": "exact_proc", "label": "process.name : \"powershell.exe\""},
            {"value": "exact_code", "label": "event.code : \"4625\""},
            {"value": "leading_wild_user", "label": "user.name : *admin*"},
        ],
        correct=["leading_wild_cmd", "leading_wild_user"],
        explanation_md="Leading wildcards on `keyword` fields are expensive. Exact-match term queries are fast.",
        points=2,
    )
    _add_q(session, m2l3q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="KQL supports temporal correlation — for example, *find a 4625 within 60 seconds of a 4624 from the same source.ip*.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** That's EQL territory. KQL is purely a boolean filter language.",
        points=1,
    )
    _add_q(session, m2l3q, order=4, kind=QuestionKind.SHORTANSWER,
        stem_md="A detection engineer hands you `process.parent.name : \"WINWORD.EXE\" and process.name : (\"cmd.exe\" or \"powershell.exe\")`. State two ATT&CK technique IDs this query is most likely related to.",
        options=None,
        correct=["T1566.001 and T1059", "T1566.001, T1059", "T1059 and T1566.001", "T1566 and T1059", "T1059.001 and T1566.001"],
        explanation_md="**T1566.001** (Spearphishing Attachment, the delivery vector for malicious Office docs) and **T1059** (Command and Scripting Interpreter, with sub-technique T1059.001 for PowerShell or T1059.003 for cmd.exe). Either pair is acceptable.",
        points=2,
    )
    _add_q(session, m2l3q, order=5, kind=QuestionKind.SINGLE,
        stem_md="Translate `event.code : \"4625\" and source.ip : 10.42.7.0/24` into Splunk SPL using CIM field names.",
        options=[
            {"value": "ecs_in_spl", "label": "EventCode=4625 source.ip=10.42.7.0/24"},
            {"value": "cim_correct", "label": "EventCode=4625 src_ip=10.42.7.0/24"},
            {"value": "kql_punctuation", "label": "event.code=\"4625\" src_ip=\"10.42.7.0/24\""},
            {"value": "wrong_index", "label": "index=4625 src=10.42.7.0/24"},
        ],
        correct="cim_correct",
        explanation_md="Splunk's CIM uses `src_ip`, and field names use `=` rather than `:`.",
        points=2,
    )
    _add_q(session, m2l3q, order=6, kind=QuestionKind.SHORTANSWER,
        stem_md="Why do L1 analysts not author beaconing-detection queries themselves?",
        options=None,
        correct=["temporal aggregation", "interval consistency", "outside KQL filter scope", "needs detection rule", "needs Lens", "kql can't aggregate"],
        explanation_md="Beaconing requires temporal aggregation (interval-consistency analysis), which is outside KQL's filter scope and lives in scheduled detection rules or Lens visualisations curated by detection engineering. L1 consumes the resulting alert, not the math.",
        points=2,
    )

    # Lesson 4 — Pivots, timelines, lifecycle
    m2l4 = _add_lesson(
        session, mod2, order=7,
        title="Pivots, timelines, and the alert lifecycle",
        lesson_type=LessonType.READING, duration_min=22,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Construct a 5-to-10-step pivot chain from a single alert into an incident timeline using the host → user → process → network cluster pattern
> 2. Decide when a saved search or dashboard answers the question and when it misleads
> 3. Manage the in-SIEM alert state machine and synchronise it with the ION case workflow
> 4. Hand off a triaged case to L2 with a coherent timeline, indicators, and the pivots already attempted
> 5. Recognise three common dashboard pitfalls (time-range mismatch, filter inheritance, index-pattern drift)

## The cluster investigation pattern

A single alert is rarely the full story. The cluster investigation pattern (popularised by Splunk's SURGe team and Hunters' "cluster" formalism, codified in MITRE's PRE-ATT&CK and operator runbooks) gives an L1 a repeatable expansion sequence.

```mermaid
flowchart TD
    A[Alert: anchor IOC] --> B[Host context]
    B --> C[User context]
    C --> D[Process context]
    D --> E[Process parent]
    D --> F[Process children]
    D --> G[Network destinations]
    D --> H[File writes]
    H --> I[File hash]
    I --> J[Hash across fleet]
    G --> K[DNS queries]
    C --> L[Auth on other hosts<br/>lateral movement]
    A --> M[Auth failures<br/>prior 24h]
```

Translated to ECS pivots, an L1's standard expansion from a single suspicious destination IP `185.220.101.7`:

1. **Anchor:** `destination.ip : "185.220.101.7"` over the last 7 days. Get all hosts that talked to it.
2. **Host expansion:** From the result, take `host.name` values. For each host, get all `user.name` values active during the contact window.
3. **User expansion:** For each user, get all `process.name` values around contact time on that host.
4. **Process expansion:** For each suspicious process, get its parent (`process.parent.name`) and children (query for `process.parent.name : "<that process>"` on the same host).
5. **Network expansion:** For each suspicious process, get all `destination.ip` from its network events.
6. **Lateral expansion:** Take the set of suspicious users and check authentication events on *other* hosts.
7. **File expansion:** For each suspicious process, query `event.category : "file" and host.name : "<host>"` around the time window — what files did it write or read?
8. **Hash expansion:** Pull `process.hash.sha256` (or `file.hash.sha256`) and check for the same hash on other hosts in the fleet.
9. **DNS expansion:** Check `dns.question.name` from the suspicious host around the contact window.
10. **Authentication failure expansion:** Check for failed logons involving the implicated users in the prior 24 hours — was credential brute-force the entry vector?

By step 10, an L1 has a coherent **five-axis story** (host, user, process, network, file) without leaving Discover. The expansion is mechanical; the analyst's job is to *narrate* the result.

## Worked example — full pivot from an outbound-IP alert

ION case `CRIT-2026-04-118`: *"Outbound connection to known-bad IP 185.220.101.7"*. Anchor: `destination.ip : "185.220.101.7"`.

```mermaid
sequenceDiagram
    participant L1 as L1 Analyst
    participant K as Kibana Discover
    participant ION as ION

    Note over L1,K: Step 1 — anchor query
    L1->>K: destination.ip : "185.220.101.7"
    K-->>L1: WS-MKT-009, 2 events, rundll32.exe, TCP/443 @ 11:47:14Z

    Note over L1,K: Step 2 — host context (auth)
    L1->>K: host.name:"WS-MKT-009" and event.category:"authentication"<br/>and event.outcome:"success" and time near 11:47
    K-->>L1: k.patel logged in at 11:32:08Z

    Note over L1,K: Step 3 — process context
    L1->>K: host:"WS-MKT-009" and user:"k.patel" and event.category:"process"<br/>and time >= 11:32
    K-->>L1: 11:46:53Z rundll32 spawned by OUTLOOK.EXE<br/>cmdline: rundll32 url.dll,OpenURL https://[redacted]/m.html

    Note over L1,K: Step 4-5 — file + hash spread
    L1->>K: event.category:"file" + temp dir writes
    K-->>L1: rad48F2A.tmp written, sha256 abc123...
    L1->>K: file.hash.sha256:"abc123..." and not host.name:"WS-MKT-009"
    K-->>L1: same hash on WS-MKT-014 22min later — second host involved

    L1->>ION: case timeline + IOCs + 6 pivot strings
    L1->>ION: closure_reason: escalated to L2 (phishing-team)
```

Six pivots in, the L1 has a story: *phishing email → Outlook spawned rundll32 to fetch a remote payload → payload dropped a file in Temp → the file (or its delivery mechanism) reached a second host*. The L1 escalates to L2 with all six query strings, the time window, and the implicated host/user/file IOCs in the case.

## Dashboards and saved searches: when to trust them

Dashboards are condensed views; saved searches are pre-baked queries. Both can mislead.

**Trustworthy when:**

- Owned by detection engineering, version-controlled, with a documented purpose
- The time range is **explicit** (the panel header shows "last 24h", not relying on the page-level picker silently)
- The index pattern matches the question (an alert dashboard pulling from `winlogbeat-*` won't show Linux events)
- Filters are visible and the analyst can read them

**Misleading when:**

- The dashboard inherits the page-level time picker but the question requires a different window
- The saved search has a hard-coded filter that excludes the case-relevant data (a detection-engineering saved search may exclude `host.name : "DC-01"` because of historical noise; the analyst doesn't see this and reasons "there is no DC activity")
- The index pattern drifted (a panel pointing at `winlogbeat-7.*` after the cluster upgraded to 8.x will silently return zero)
- The visualisation rounds (a "top 10 failed-logon source IPs" pie chart hides ranks 11+; a brute-force from rank 11 is invisible)

**Rule for L1:** dashboards are good for *spotting trends*, bad for *answering specific questions about a single alert*. When the case asks *"what happened on host X at time T"*, go to Discover. When the shift handoff asks *"is the failed-logon rate normal"*, look at the dashboard.

## Worked example — when a dashboard hides the answer

L1 sees ION case *"spike in failed logons"* and opens the failed-logon dashboard. The trend panel shows flat. They check Discover with the case's specific query and find a 30× spike concentrated on one host. **The dashboard's panel aggregates fleet-wide; the spike on one host is invisible against the fleet baseline.** The L1 documents this in the case (*"dashboard fleet-aggregate masks per-host spike"*) and uses the per-host Discover query as authoritative.

## Alert lifecycle in the SIEM and ION

An alert is a long-lived object. Its state machine in Elastic Security and ION:

```mermaid
stateDiagram-v2
    [*] --> Open
    Open --> Acknowledged: L1 picks up
    Acknowledged --> InProgress: triage starts
    InProgress --> Closed_Resolved: closure reason set
    InProgress --> Closed_Escalated: L2 handoff
    Closed_Resolved --> Reopened: new evidence
    Closed_Escalated --> InProgress: L2 returns
    Reopened --> InProgress
    Closed_Resolved --> [*]
    Closed_Escalated --> [*]
```

- **Open / new** — Just fired. ION has just created the case.
- **Acknowledged** — An L1 has picked it up. ION moves the case to "in-progress".
- **In-progress** — Active triage. Analyst comments accumulate; pivots are saved.
- **Closed (resolved)** — Triage complete. ION requires a `CaseClosureReason` (true_positive / benign_true_positive / false_positive / duplicate / insufficient_data — see Module 1).
- **Closed (escalated)** — L1 hands off to L2. The case persists; ION assigns it to the L2 queue.

Every transition is auditable. **Comments in ION are first-class** — they're the thread future-you and future-L2 will read.

A good comment includes: (1) the pivot you ran, verbatim, (2) what you found, (3) why you concluded what you did. A bad comment: *"looks fine, closing"*.

ION-specific: closing with a `CaseClosureReason` feeds the **AIFeedback ledger** and the per-template scorecard. Sloppy reasons skew the Tier-1 training data Bob (the AI analyst service user) consumes for tuning proposals. **L1's discipline on closure-reason matters beyond the immediate case.**

The dual-write problem: if an analyst closes an alert in Kibana Security but ION still shows the case open (or vice versa), the synchronisation is broken. **Standard L1 protocol is to drive state from ION** (the case-management system of record) and let ION's connector update Kibana. Manual closure in Kibana can desync — escalate if you have to do it.

## Worked example — a clean handoff comment

Case `CRIT-2026-04-118`. L1 closure-comment template:

```
Investigated 11:32-12:05 UTC.
Alert: outbound to 185.220.101.7 from WS-MKT-009.
Pivots run:
  1. destination.ip : "185.220.101.7"  -> 1 host, 2 events
  2. user @11:32 logon -> k.patel
  3. parent of rundll32 -> OUTLOOK.EXE (rundll32 url.dll,OpenURL ...)
  4. file write Temp\\rad48F2A.tmp, sha256 <hash>
  5. same hash on WS-MKT-014 @12:09
Conclusion: phishing -> Outlook -> rundll32 dropper, second host involved.
Escalating to L2 for containment + email-source investigation.
Closure reason: escalated (L2 assignment: phishing-team).
```

This comment carries forward the timeline, the verbatim pivots, the IOCs, and the escalation reason. **L2 starts from a hot trail, not cold.**

## Glossary

- **Anchor IOC** — The single indicator that opens the pivot chain (IP, hash, user, process, host)
- **Pivot** — Moving from one query result to a follow-up query that uses a value from the result
- **Cluster (investigation)** — A coherent expansion across host/user/process/network/file axes
- **Saved search** — A stored Discover query (index pattern, KQL, filters, columns)
- **Dashboard panel** — A visualisation backed by a saved search or Lens query
- **Time picker** — Kibana's range selector; controls the implicit `@timestamp` filter at page or panel level
- **Index pattern drift** — When a panel's index pattern stops matching the live indices
- **Alert state machine** — Open → Acknowledged → In-progress → Closed (resolved | escalated)
- **`CaseClosureReason`** — ION's pinned enum for reasons a case is closed; load-bearing for AIFeedback
- **AIFeedback ledger** — ION's per-template scorecard table tracking closure outcomes vs alert prompt
- **Bob** — ION's AI-analyst service user that consumes feedback for tuning proposals
- **Lateral movement** — Adversary moving from one host/user to another within the environment
- **Handoff comment** — Closure comment that carries the case timeline + IOCs forward to L2

## Further reading

- Elastic Security alerts and cases: https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html
- Elastic Security cases workflow: https://www.elastic.co/guide/en/security/current/cases-overview.html
- MITRE ATT&CK Lateral Movement tactic: https://attack.mitre.org/tactics/TA0008/
- BTL1 syllabus: SIEM Domain — Investigation Workflow and Pivoting
- SANS GCIH KSA: Domain 4 — Incident Handling Process
""",
    )

    # Quiz on Lesson 4
    m2l4q = _add_lesson(
        session, mod2, order=8,
        title="Pivots + lifecycle — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Six questions on the cluster pattern, dashboard pitfalls, and alert lifecycle in ION.",
    )
    _add_q(session, m2l4q, order=1, kind=QuestionKind.SINGLE,
        stem_md="What is the **first pivot** in the cluster pattern after the anchor IOC?",
        options=[
            {"value": "hash", "label": "File hashes"},
            {"value": "host", "label": "Host context"},
            {"value": "dns", "label": "DNS queries"},
            {"value": "auth_fail", "label": "Authentication failures"},
        ],
        correct="host",
        explanation_md="Host context anchors everything else (without a host you can't meaningfully pivot to user, process, or network for that host).",
        points=2,
    )
    _add_q(session, m2l4q, order=2, kind=QuestionKind.MULTI,
        stem_md="A dashboard panel shows 0 events. Which are plausible **non-attacker** explanations? Pick all that apply.",
        options=[
            {"value": "time", "label": "Time range mismatch with the page picker"},
            {"value": "filter", "label": "Filter inherited from the dashboard excludes the relevant index"},
            {"value": "drift", "label": "Index pattern drift after a stack upgrade"},
            {"value": "saved", "label": "Saved-search hard-coded to exclude a host"},
            {"value": "rule_off", "label": "Detection rule disabled"},
        ],
        correct=["time", "filter", "drift", "saved"],
        explanation_md="Detection-rule state doesn't directly affect a Discover-backed dashboard panel — it would affect alert dashboards specifically, and even there it would show *fewer* alerts but still a non-zero historical count.",
        points=3,
    )
    _add_q(session, m2l4q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="An L1 closing a Kibana alert manually is the canonical way to close an ION case.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** ION is the case-management system of record; closure is driven from ION and ION's connector updates Kibana. Manual Kibana closure risks desync.",
        points=1,
    )
    _add_q(session, m2l4q, order=4, kind=QuestionKind.SHORTANSWER,
        stem_md="Name three IOCs you would extract from a process-creation alert and carry into the case timeline.",
        options=None,
        correct=["host.name, user.name, process.name", "host, user, process, hash", "host.name, process.command_line, file.hash.sha256", "user, process, parent process"],
        explanation_md="Acceptable: `host.name`, `user.name`, `process.name` / `process.command_line`, `process.hash.sha256`, `process.parent.name`, source/destination IP if a network event was correlated. Any three.",
        points=2,
    )
    _add_q(session, m2l4q, order=5, kind=QuestionKind.SINGLE,
        stem_md="A `CaseClosureReason` of **false_positive** is appropriate when:",
        options=[
            {"value": "no_events", "label": "The alert fired but the analyst couldn't find the underlying events"},
            {"value": "btp", "label": "The alert reflects benign expected activity (e.g. authorised admin tool)"},
            {"value": "rule_wrong", "label": "The detection rule's logic does not actually identify malicious behaviour as designed"},
            {"value": "dup", "label": "A duplicate of an earlier case"},
        ],
        correct="rule_wrong",
        explanation_md="A *false positive* specifically means the rule's detection is wrong (the activity it flags isn't actually what the rule claims to detect). 'Benign expected activity' is a *benign true positive*. 'Duplicate' is its own closure reason. Distinguishing these is what the AIFeedback ledger relies on.",
        points=2,
    )
    _add_q(session, m2l4q, order=6, kind=QuestionKind.SHORTANSWER,
        stem_md="Why does the quality of L1 closure comments matter beyond the immediate case in ION?",
        options=None,
        correct=["AIFeedback ledger", "feeds AIFeedback", "scorecard", "bob tuning", "training data for bob", "feeds the per-template scorecard"],
        explanation_md="Closure comments and reasons feed the AIFeedback ledger and per-template scorecard, which in turn feed Tier-1 training data and Bob's tuning proposals. Sloppy or inconsistent closure reasons degrade the AI-analyst service's recommendations and the per-template prompt-quality metrics.",
        points=2,
    )

    # ── Module 3 — Windows Event Logs (v0.11.6) ──────────────────────────
    # Authored at BTL1/SANS depth from research-agent dossier. ECS-first
    # throughout; pairs every event ID discussion with the ATT&CK
    # technique(s) it maps to.
    mod3 = _add_module(
        session, course, order=3,
        title="Windows Event Logs",
        description_md=(
            "The single richest endpoint telemetry source on a tier-1 shift. "
            "Channels and providers, the high-value Security event IDs, "
            "Sysmon's enriched telemetry, and the canonical attacker patterns "
            "you triage daily — pass-the-hash, persistence, suspicious service "
            "installs, Office spawning shells, DNS exfiltration."
        ),
        estimated_minutes=200,
    )

    # Lesson 3.1 — architecture
    m3l1 = _add_lesson(
        session, mod3, order=1,
        title="The Windows logging architecture and how it reaches ION",
        lesson_type=LessonType.READING, duration_min=22,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Identify the standard Windows event channels (Security, System, Application, Setup, Forwarded Events) and the role each plays
> 2. Explain the provider/channel relationship and how the same event can be authored by different providers
> 3. Describe how `winlogbeat` reads EVTX channels and ships them to Elastic with ECS-compliant field names
> 4. Define Windows Event Forwarding (WEF), distinguish it from agent-based shipping, and recognise forwarded events in ION
> 5. Map a `winlog.channel` value to the ION/Elastic index pattern an analyst should query
>
> **Prerequisites.** Module 2 *SIEM Fundamentals* completed.

## Channels, providers, and the EVTX format

Modern Windows (Vista and later) uses the **Windows Event Log** service to host log data in **channels**. A channel is a named stream of events — `Security`, `System`, `Application`, `Setup`, and `Forwarded Events` are the five default *Windows Logs* channels every workstation and server has. Beyond those, hundreds of *Applications and Services Logs* channels exist under the `Microsoft-Windows-*` namespace: `Microsoft-Windows-Sysmon/Operational`, `Microsoft-Windows-PowerShell/Operational`, `Microsoft-Windows-TaskScheduler/Operational`, and so on. Each channel is backed by an EVTX file (`.evtx`) on disk under `%SystemRoot%\\System32\\Winevt\\Logs\\`.

Every event has a **provider** — the component that authored the event — and a **channel** — the stream the event was written to. The provider for a 4624 logon event is `Microsoft-Windows-Security-Auditing`; the channel is `Security`. The provider for a Sysmon process-create is `Microsoft-Windows-Sysmon`; the channel is `Microsoft-Windows-Sysmon/Operational`. The same provider can write to multiple channels (operational, analytic, debug); the same channel can host events from multiple providers. In ION you'll see both surfaced as `winlog.provider_name` and `winlog.channel` in ECS.

The EVTX format itself is binary, structured, and self-describing. Events have a fixed `System` block (TimeCreated, EventRecordID, EventID, Computer, SecurityID) and a variable `EventData` block whose schema depends on the EventID. This is why field names like `winlog.event_data.TargetUserName` and `winlog.event_data.LogonType` exist — the `event_data` map is the per-EventID payload, and the keys are the names defined in the provider's manifest.

```mermaid
flowchart LR
    subgraph Endpoint[Windows Endpoint]
        Provider1[Provider: Security-Auditing]
        Provider2[Provider: Sysmon]
        Provider3[Provider: PowerShell]
        Channel1[Channel: Security]
        Channel2[Channel: Sysmon/Operational]
        Channel3[Channel: PowerShell/Operational]
        EVTX[(EVTX files on disk)]
        Provider1 --> Channel1
        Provider2 --> Channel2
        Provider3 --> Channel3
        Channel1 --> EVTX
        Channel2 --> EVTX
        Channel3 --> EVTX
    end
    EVTX --> Winlogbeat
    Winlogbeat -->|ECS-normalised JSON| Elastic[(Elasticsearch winlogbeat-*)]
    Elastic --> ION[ION Triage UI]
```

**Worked example.** A successful interactive logon at the console of `WS-FINANCE-04` produces an event written by provider `Microsoft-Windows-Security-Auditing` to the `Security` channel with EventID `4624`. After winlogbeat ships it to Elastic, the document will have `winlog.provider_name: "Microsoft-Windows-Security-Auditing"`, `winlog.channel: "Security"`, `event.code: "4624"`, `winlog.event_data.LogonType: "2"`, `winlog.event_data.TargetUserName: "alice"`, and ECS-mirrored fields `user.name: "alice"` and `host.name: "ws-finance-04"`.

## Winlogbeat, ECS, and channel-to-index mapping

`winlogbeat` is the Elastic-published agent that subscribes to Windows event channels via the EvtSubscribe API and forwards records to Elasticsearch. In ION's deployment, the default `winlogbeat.yml` subscribes to at minimum: `Application`, `Security`, `System`, `Microsoft-Windows-Sysmon/Operational`, `Microsoft-Windows-PowerShell/Operational`, `Windows PowerShell`, `ForwardedEvents`. Each subscribed channel becomes a stream of documents indexed under the `winlogbeat-*` data view.

Winlogbeat ships a fixed module set that performs **ECS normalisation** — it remaps native Windows field names to the Elastic Common Schema. So `EventData.SubjectUserName` becomes both `winlog.event_data.SubjectUserName` (preserved raw) and `user.name` (ECS-mapped). `Computer` becomes `host.name`. The TimeCreated SystemTime becomes `@timestamp`. `IpAddress` from a 4624 becomes `source.ip` when the LogonType implies a network logon. **Always prefer ECS field names in queries** because they are stable across data sources, but fall back to `winlog.event_data.*` when an attribute hasn't been ECS-promoted.

In ION, channels do **not** get separate indices — every winlogbeat document lands in the same daily index (e.g. `winlogbeat-8.11.0-2026.04.23`) and is distinguished by `winlog.channel`. So a query for *"all Sysmon events on this host"* is `host.name : "ws-finance-04" and winlog.channel : "Microsoft-Windows-Sysmon/Operational"`, not a different index.

### ECS field translation table

| Native Windows field | winlogbeat raw field | ECS-mapped field |
| --- | --- | --- |
| `EventData.SubjectUserName` | `winlog.event_data.SubjectUserName` | `user.name` |
| `EventData.IpAddress` (on 4624) | `winlog.event_data.IpAddress` | `source.ip` |
| `EventData.TargetUserName` | `winlog.event_data.TargetUserName` | `user.target.name` |
| `EventData.NewProcessName` (4688) | `winlog.event_data.NewProcessName` | `process.executable` |
| `EventData.CommandLine` (4688/Sysmon 1) | `winlog.event_data.CommandLine` | `process.command_line` |
| `Computer` | `winlog.computer_name` | `host.name` |
| `EventID` | `winlog.event_id` | `event.code` |

## Windows Event Forwarding (WEF)

Native Windows event logs are local — they live on the host that generated them. Two strategies exist for centralising them:

1. **Agent-based shipping** (winlogbeat, Splunk UF, NXLog) — each endpoint runs a process that reads its own EVTX and pushes records out
2. **Windows Event Forwarding (WEF)** — a Microsoft-native mechanism where a *collector* server subscribes to events on remote *source* machines via WinRM, and the source pushes matching events to the collector's `ForwardedEvents` channel

WEF subscriptions are configured via Group Policy or `wecutil` and identified by **subscription names** (e.g. `Security_Logs_Subscription`). Source-initiated subscriptions are the common production pattern — endpoints push to the collector after picking up GPO config — and are ideal for high-security zones where you can't run a third-party agent on every workstation. The downside: you need WinRM/HTTPS plumbing, certificate trust, and tuning of the XPath subscription queries to avoid forwarding everything.

```mermaid
flowchart LR
    subgraph Sources[Source Endpoints]
        S1[WS-001]
        S2[WS-002]
        S3[WS-003]
    end
    subgraph Collector[WEF Collector]
        FwdChannel[Channel: ForwardedEvents]
        WLB[winlogbeat]
    end
    S1 -->|WinRM HTTPS push| FwdChannel
    S2 -->|WinRM HTTPS push| FwdChannel
    S3 -->|WinRM HTTPS push| FwdChannel
    FwdChannel --> WLB
    WLB -->|host.name preserved| Elastic[(winlogbeat-*)]
```

In ION, forwarded events arrive in the collector's `ForwardedEvents` channel. Winlogbeat then ships them, and the document has `winlog.channel: "ForwardedEvents"` plus a preserved `winlog.computer_name` pointing at the *original source host* (not the collector). When triaging, **an L1 must read `winlog.computer_name` or `host.name` carefully** — the host that *generated* the event is what matters for the investigation, not the collector that relayed it.

## KQL snippets

```kql
winlog.channel : "Security" and event.code : "4624"
```
- `winlog.channel` filters to the Security channel — discards Sysmon, PowerShell, System
- `event.code` is the ECS-mapped EventID; using `event.code` (string) is preferred over `winlog.event_id` (integer) for stable cross-version queries

```kql
winlog.channel : "ForwardedEvents" and host.name : "dc01.corp.local"
```
- Filters to events that came through WEF specifically
- `host.name` here is the *source* host (the endpoint that generated the event), preserved by winlogbeat — not the collector

```kql
event.code : "4624" and winlog.event_data.LogonType : "10" and not user.name : "alice"
```
- `LogonType 10` is RemoteInteractive (RDP)
- The exclusion of `alice` shows pivoting by removing a known-good user during triage

## Glossary

- **Channel** — a named log stream Windows uses to organise events (Security, System, Sysmon/Operational, etc.)
- **Provider** — the component that authors events (e.g. `Microsoft-Windows-Security-Auditing`)
- **EVTX** — the binary file format used by Windows to store event logs on disk under `%SystemRoot%\\System32\\Winevt\\Logs\\`
- **winlogbeat** — Elastic's official agent for shipping Windows event channels with ECS normalisation
- **WEF** — Windows Event Forwarding; native Microsoft mechanism to centralise events to a collector via WinRM
- **Collector** — the Windows server that receives forwarded events from sources and writes them to its `ForwardedEvents` channel
- **Subscription** — a WEF configuration object defining which events from which sources to collect, expressed as an XPath query
- **EventData** — the per-EventID payload block in an EVTX record, surfaced as `winlog.event_data.*`
- **System block** — the fixed-schema header on every EVTX record (TimeCreated, EventID, Computer, etc.)
- **WinRM** — Windows Remote Management; the WS-Management transport WEF uses
- **Source-initiated subscription** — WEF mode where endpoints push to the collector based on GPO; standard production pattern

## Further reading

- Microsoft Learn — Windows Event Log overview: https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log
- Microsoft Learn — Windows Event Forwarding for intrusion detection: https://learn.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection
- Elastic — Winlogbeat reference: https://www.elastic.co/guide/en/beats/winlogbeat/current/index.html
- Elastic Common Schema — Field reference: https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
- BTL1 — Windows Event Logs domain
""",
    )
    m3l1q = _add_lesson(
        session, mod3, order=2, title="Architecture quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Five questions on channels/providers, winlogbeat, ECS mapping, and WEF.",
    )
    _add_q(session, m3l1q, order=1, kind=QuestionKind.SINGLE,
        stem_md="Which Windows component is the **provider** for a Sysmon process-create event?",
        options=[
            {"value": "security_auditing", "label": "Microsoft-Windows-Security-Auditing"},
            {"value": "sysmon", "label": "Microsoft-Windows-Sysmon"},
            {"value": "eventlog", "label": "Microsoft-Windows-Eventlog"},
            {"value": "winlogbeat", "label": "winlogbeat"},
        ],
        correct="sysmon",
        explanation_md="The provider is the component that authored the event. Sysmon authors its own events under the `Microsoft-Windows-Sysmon` provider into the `Microsoft-Windows-Sysmon/Operational` channel.",
        points=2,
    )
    _add_q(session, m3l1q, order=2, kind=QuestionKind.SINGLE,
        stem_md="A document in ION has `winlog.channel: \"ForwardedEvents\"` and `host.name: \"ws-hr-12\"`. Which host generated the original event?",
        options=[
            {"value": "collector", "label": "The WEF collector"},
            {"value": "source", "label": "ws-hr-12"},
            {"value": "ingest", "label": "The Elasticsearch ingest node"},
            {"value": "winlogbeat_host", "label": "The winlogbeat host"},
        ],
        correct="source",
        explanation_md="Winlogbeat preserves the source host's name in `host.name` (and `winlog.computer_name`) when shipping forwarded events. The `ForwardedEvents` channel is just the collection point on the collector; the originating host is `ws-hr-12`.",
        points=2,
    )
    _add_q(session, m3l1q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="Each Windows event channel maps to a separate Elasticsearch index in a default ION winlogbeat deployment.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** All winlogbeat-shipped channels land in the same `winlogbeat-*` daily index. They are distinguished by the `winlog.channel` field, not by index name.",
        points=1,
    )
    _add_q(session, m3l1q, order=4, kind=QuestionKind.MULTI,
        stem_md="Which of the following are true about ECS field mapping in winlogbeat?",
        options=[
            {"value": "target_user", "label": "winlog.event_data.TargetUserName becomes user.target.name"},
            {"value": "ecs_stable", "label": "ECS field names are stable across data sources whereas winlog.event_data.* is per-EventID"},
            {"value": "computer_event", "label": "The native Computer field maps to event.host"},
            {"value": "ip_source", "label": "EventData.IpAddress on a 4624 maps to source.ip when the logon type implies a network source"},
        ],
        correct=["target_user", "ecs_stable", "ip_source"],
        explanation_md="The ECS host field is `host.name`, not `event.host` — so the Computer-to-event.host claim is wrong. The other three are correct.",
        points=3,
    )
    _add_q(session, m3l1q, order=5, kind=QuestionKind.SHORTANSWER,
        stem_md="An analyst writes the query `winlog.event_id : 4624`. Why might this fail to return results, and what's the safer field to use?",
        options=None,
        correct=["event.code", "use event.code", "event.code is keyword", "event.code instead", "switch to event.code"],
        explanation_md="`winlog.event_id` is sometimes indexed as keyword, sometimes as number, depending on winlogbeat version and pipeline; comparing a number to a keyword field can silently return zero hits. The ECS-mapped `event.code` is consistently a keyword string and should be the default.",
        points=2,
    )

    # Lesson 3.2 — Security event IDs
    m3l2 = _add_lesson(
        session, mod3, order=3,
        title="High-value Security channel event IDs",
        lesson_type=LessonType.READING, duration_min=26,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Identify the 15-20 Security channel event IDs L1 must recognise on sight, and recall what each means
> 2. Decode the LogonType field on 4624/4625 events and reason about logon context
> 3. Distinguish Kerberos events (4768/4769) from NTLM events (4776) and identify the failure-code fields
> 4. Recognise account- and group-management events (4720/4722/4724/4732/4738/4756) as a triage cluster
> 5. Map every event ID covered to one or more MITRE ATT&CK techniques

## Authentication events: the 4624 / 4625 / 4634 / 4647 / 4648 / 4672 cluster

These six events are the bread and butter of identity-driven triage.

A successful logon writes **4624 — An account was successfully logged on**. The most important field on a 4624 is `LogonType` (`winlog.event_data.LogonType`):

| LogonType | Name | Meaning |
| --- | --- | --- |
| 2 | Interactive | At-keyboard / console logon |
| 3 | Network | SMB, IPC$, network share — the **pass-the-hash favourite** |
| 4 | Batch | Scheduled task |
| 5 | Service | Service account starting a service |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Network logon with cleartext password (basic auth, IIS) |
| 9 | NewCredentials | runas /netonly |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Cached domain credentials (laptop offline) |

A failed logon writes **4625 — An account failed to log on** with the same `LogonType` field plus a `Status` and `SubStatus`:

- `0xC0000064` — user does not exist
- `0xC000006A` — bad password
- `0xC0000234` — account locked
- `0xC0000072` — account disabled
- `0xC0000193` — account expired

A burst of 4625s with `SubStatus 0xC000006A` from one source IP against many usernames is **password spraying**. A burst against one username from many IPs is targeted brute force.

**4634 — An account was logged off** and **4647 — User initiated logoff** complement 4624: 4647 is specifically a user clicking sign-out, while 4634 fires for service/network session teardowns. **4648 — A logon was attempted using explicit credentials** is the `runas` event — a process tried to authenticate as someone other than its current security context. 4648 with a high-privilege target user is a strong signal of credential-laundering or admin escalation.

**4672 — Special privileges assigned to new logon** fires whenever a logon receives sensitive privileges (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`, etc.). Practically, every administrator logon produces a 4672 immediately after the corresponding 4624. A 4672 for a user account that *should not* be admin is a fast-pivot signal.

**ATT&CK mapping.** 4624/4625 → **T1078** (Valid Accounts), **T1110** (Brute Force), **T1021** (Remote Services). 4648 → **T1078**, **T1550** (Use Alternate Authentication Material). 4672 → **T1078.003** (Local Accounts) when on a local privileged account.

```mermaid
flowchart TD
    Logon[User attempts logon] --> Success{Auth result}
    Success -->|Pass| E4624[4624 logged on]
    Success -->|Fail| E4625[4625 failed]
    E4624 --> Privs{Has admin privs?}
    Privs -->|Yes| E4672[4672 special privs assigned]
    Privs -->|No| Done[Standard session]
    E4624 --> ExplicitCreds{runas / explicit creds?}
    ExplicitCreds -->|Yes| E4648[4648 explicit cred logon]
    Done --> Logoff{Session ends}
    Logoff -->|User-initiated| E4647[4647 user logoff]
    Logoff -->|System teardown| E4634[4634 logoff]
```

## Account, group, and Kerberos/NTLM events

When an attacker establishes persistence, they often **create a user and add it to a privileged group**. The events to memorise as a cluster:

- **4720** — A user account was created
- **4722** — A user account was enabled
- **4724** — An attempt was made to reset an account's password (admin reset, not user-driven)
- **4738** — A user account was changed
- **4732** — A member was added to a security-enabled local group
- **4756** — A member was added to a security-enabled universal group (and **4728** for global groups)

A 4720 followed within minutes by a 4732 against the local Administrators group (`TargetSid` ending in `-544`) is the canonical local-admin-persistence signature. Look for the `SubjectUserName` (who did it) and `TargetUserName` (the account being acted on).

### Kerberos and NTLM authentication on the DC

Three domain-controller-only events:

- **4768 — A Kerberos authentication ticket (TGT) was requested** (the AS-REQ). Fields: `TargetUserName`, `IpAddress`, `TicketEncryptionType` (`0x12` = AES256, `0x17` = RC4 — RC4 is the **Kerberoasting tell**), `Status` (`0x6` = client unknown, `0x12` = client locked, `0x18` = bad password)
- **4769 — A Kerberos service ticket was requested** (the TGS-REQ). Fields: `TargetUserName` (the *service account* the ticket targets, e.g. `MSSQLSVC/sql01`), `ServiceName`, `TicketEncryptionType` (RC4 here is **Kerberoasting**; AES is normal), `Status`
- **4776 — The computer attempted to validate the credentials for an account** — NTLM authentication. Fields: `TargetUserName`, `Workstation` (source NetBIOS name), `Status` (same family as 4625)

**4769 with `TicketEncryptionType: "0x17"` (RC4) for a service account** is the textbook Kerberoasting indicator (**T1558.003**) — attackers force RC4 because it's offline-crackable.

```mermaid
sequenceDiagram
    participant Client
    participant DC as Domain Controller
    participant FileSrv as File Server
    Client->>DC: AS-REQ (request TGT)
    DC->>DC: Log 4768 (TGT requested)
    DC-->>Client: TGT
    Client->>DC: TGS-REQ for cifs/fileserver
    DC->>DC: Log 4769 (Service ticket requested)
    DC-->>Client: TGS
    Client->>FileSrv: SMB session with TGS
    FileSrv->>FileSrv: Log 4624 LogonType 3
    FileSrv->>FileSrv: Log 5140 share accessed
```

### Other high-value Security events

- **5140 — A network share object was accessed** — fires when a user accesses an SMB share. Fields: `ShareName`, `ShareLocalPath`, `IpAddress`
- **5145 — A network share object was checked** — much noisier, fires per-file. Filter aggressively
- **1102 — The audit log was cleared** — single highest-priority event in the entire Security channel. Fires when someone runs `wevtutil cl Security` or otherwise clears the log. **T1070.001**. *Always* escalate
- **7045 — A service was installed in the system** (System channel, technically). Fields: `ServiceName`, `ImagePath`, `ServiceType`, `StartType`. Suspicious `ImagePath` patterns: temp directories, double extensions, base64-laden powershell
- **4688 — A new process has been created** — the native equivalent of Sysmon Event 1, but only includes `CommandLine` if the *Include command line in process creation events* GPO is enabled. Without the GPO, 4688 is much less useful than Sysmon 1

## A worked triage walkthrough

**Scenario.** An ION alert fires: *"10+ failed logons from one source IP in 60 seconds."* The KQL backing it:

```kql
event.code : "4625" and source.ip : "10.42.18.91"
```

The 12 hits all show:

- `winlog.event_data.LogonType: "3"` — network logon
- `winlog.event_data.SubStatus: "0xC000006A"` — bad password
- `winlog.event_data.TargetUserName: "alice", "bob", "carol", ...` — twelve different usernames
- `source.ip: "10.42.18.91"` — all from the same host

**Interpretation.** One source IP, one bad-password substatus, twelve different usernames, all over network logon (SMB or similar). This is **password spraying** (T1110.003). The attacker is iterating usernames against (probably) one weak password.

**Pivot 1 — did any spray succeed?**

```kql
event.code : "4624" and source.ip : "10.42.18.91" and winlog.event_data.LogonType : "3"
```

If you see a 4624 from the same `source.ip` within the same window, that's the **compromised account**.

**Pivot 2 — what is `10.42.18.91`?** Cross-reference asset inventory and DHCP logs. If it's a domain-joined endpoint, the attacker has a foothold and is pivoting. If it's an unknown IP on the corporate VLAN, that's a rogue device.

**Pivot 3 — if a 4624 succeeded, follow up with:**

```kql
host.name : "ws-finance-04" and event.code : ("4624" or "4672" or "4688") and @timestamp >= "2026-04-23T14:00:00Z"
```

…to see what the attacker did after the successful logon.

**This pattern is the heart of L1.** Recognise the burst, classify the type (spray vs brute force), check for success, pivot to the source.

## KQL snippets with line-by-line commentary

```kql
event.code : "4625" and winlog.event_data.LogonType : "3" and winlog.event_data.SubStatus : "0xC000006A"
```
- Network logon (`LogonType 3`) failures specifically for bad password
- Excluding `0xC0000064` (user does not exist) reduces noise from username enumeration; this clause focuses on actual credential testing

```kql
event.code : "4769" and winlog.event_data.TicketEncryptionType : "0x17" and not winlog.event_data.TargetUserName : *$
```
- `0x17` is RC4-HMAC, which Kerberoasting tools force
- Excluding usernames ending in `$` filters out machine accounts (which legitimately use weaker encryption in some cases)

```kql
event.code : "1102"
```
- The simplest and most important query in this lesson. `1102` is *audit log cleared.* Anyone clearing the security audit log on a production system gets investigated — full stop

## Glossary

- **LogonType** — integer field on 4624/4625 indicating logon method (2=interactive, 3=network, 10=RDP, etc.)
- **SubStatus** — failure-detail code on 4625 (e.g. `0xC000006A` = bad password, `0xC0000064` = user not found)
- **TGT** — Kerberos Ticket-Granting Ticket; obtained via AS-REQ (logged 4768)
- **TGS** — Kerberos Ticket-Granting Service ticket; obtained via TGS-REQ (logged 4769)
- **Kerberoasting** — credential-access technique (T1558.003) requesting RC4 service tickets to crack offline
- **NTLM** — legacy challenge/response authentication; validation logged as 4776 on the validating DC
- **TicketEncryptionType** — Kerberos ticket cipher (`0x12`=AES256, `0x17`=RC4); RC4 on 4769 is the Kerberoasting tell
- **Special privileges** — sensitive Windows privileges (SeDebugPrivilege, SeBackupPrivilege, etc.) whose assignment fires 4672
- **Explicit credentials** — credentials supplied at runtime via runas or RunAs API; logged as 4648
- **Audit log clearing** — manual clearing of the Security log; produces 1102, near-universal red flag
- **Service install** — registration of a new Windows service, logged as 7045 on System channel
- **Network share access** — SMB share open, logged as 5140; per-object access is 5145 (noisy)

## Further reading

- Microsoft Learn — Audit Logon (4624/4625): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- Microsoft Learn — Audit Kerberos Authentication Service: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kerberos-authentication-service
- Microsoft Learn — Event 1102 audit log cleared: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102
- MITRE ATT&CK — T1110 Brute Force, T1558 Kerberos Tickets, T1070.001 Clear Windows Event Logs
- SANS — Windows Logging Cheat Sheet (Malware Archaeology)
""",
    )
    m3l2q = _add_lesson(
        session, mod3, order=4, title="Security event IDs — quiz",
        lesson_type=LessonType.QUIZ, duration_min=10,
        content_md="Six questions on LogonTypes, account/group cluster, Kerberos, and triage pivots.",
    )
    _add_q(session, m3l2q, order=1, kind=QuestionKind.SINGLE,
        stem_md="A 4624 event has `LogonType: \"3\"` and `source.ip: \"10.4.5.99\"`. The source IP is a workstation, not a server. What is the most likely activity?",
        options=[
            {"value": "console", "label": "A user logged in at the console"},
            {"value": "rdp", "label": "A user RDP'd in"},
            {"value": "network_smb", "label": "A network logon from the workstation, e.g. SMB share access or pass-the-hash"},
            {"value": "task", "label": "A scheduled task started"},
        ],
        correct="network_smb",
        explanation_md="LogonType 3 is network logon. SMB share access, IPC$ enumeration, and pass-the-hash all produce LogonType 3 events. Console = LogonType 2; RDP = LogonType 10; scheduled task = LogonType 4.",
        points=2,
    )
    _add_q(session, m3l2q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which events are typical signals of attacker persistence via account creation?",
        options=[
            {"value": "4720", "label": "4720 (account created)"},
            {"value": "4732", "label": "4732 (member added to local group)"},
            {"value": "4634", "label": "4634 (account logged off)"},
            {"value": "4756", "label": "4756 (member added to universal group)"},
            {"value": "4624", "label": "4624 (account logged on)"},
        ],
        correct=["4720", "4732", "4756"],
        explanation_md="4720 then 4732/4756 is the canonical create-and-elevate pattern. 4634 is just logoff; 4624 is a logon and not specifically persistence by itself.",
        points=3,
    )
    _add_q(session, m3l2q, order=3, kind=QuestionKind.SHORTANSWER,
        stem_md="You see a 4769 with `TicketEncryptionType: \"0x17\"` and `TargetUserName: \"MSSQLSVC\"`. What's likely happening, and which ATT&CK technique applies?",
        options=None,
        correct=["Kerberoasting T1558.003", "Kerberoasting", "T1558.003 Kerberoasting", "T1558.003"],
        explanation_md="RC4-HMAC service tickets for a service account is the textbook signature of Kerberoasting (**T1558.003**). The attacker has requested a service ticket they can crack offline because RC4 keys are derived directly from the service account's NT hash.",
        points=2,
    )
    _add_q(session, m3l2q, order=4, kind=QuestionKind.SINGLE,
        stem_md="Which event is the *highest-priority* by itself, with essentially no false-positive case?",
        options=[
            {"value": "4624", "label": "4624"},
            {"value": "4625", "label": "4625"},
            {"value": "1102", "label": "1102"},
            {"value": "7045", "label": "7045"},
        ],
        correct="1102",
        explanation_md="**1102** is *audit log cleared.* There is no legitimate operational reason for someone to manually clear a production Security log; it's almost always evidence-destruction (T1070.001). 7045 is high-value but has many legitimate cases (driver installs).",
        points=2,
    )
    _add_q(session, m3l2q, order=5, kind=QuestionKind.SHORTANSWER,
        stem_md="You're triaging a 4625 burst from `10.42.18.91` against 12 usernames with `SubStatus: \"0xC000006A\"`. State your next two pivots.",
        options=None,
        correct=["check 4624 from same source", "query 4624 same source.ip", "see if any logon succeeded, check asset inventory", "look for successful 4624, check who owns the IP"],
        explanation_md="(1) Query `event.code : \"4624\" and source.ip : \"10.42.18.91\"` over the same window to see if any logon *succeeded*. (2) Cross-reference `10.42.18.91` against asset inventory / DHCP to identify the source host.",
        points=2,
    )
    _add_q(session, m3l2q, order=6, kind=QuestionKind.TRUEFALSE,
        stem_md="Event 4688 always includes the full process command line.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** 4688 only includes the `CommandLine` field if the GPO setting *Include command line in process creation events* is enabled. Many enterprises don't enable it (risk of credentials in command lines being logged). This is exactly why **Sysmon Event 1** — which always includes CommandLine and adds parent process and hash — is the L1's preferred process-create source.",
        points=1,
    )

    # Lesson 3.3 — Sysmon
    m3l3 = _add_lesson(
        session, mod3, order=5,
        title="Sysmon — the L1 superpower",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Explain what Sysmon is, how it differs from native Windows auditing, and why it's effectively mandatory in mature SOCs
> 2. List the high-value Sysmon event IDs (1, 3, 7, 8, 10, 11, 13, 22) and describe what each captures
> 3. Map common Sysmon fields (`Image`, `ParentImage`, `CommandLine`, `Hashes`, `OriginalFileName`) to ECS
> 4. Recognise the SwiftOnSecurity and Olaf Hartong baseline configurations as the de-facto starting points
> 5. Identify a typical Sysmon-driven detection (Office spawns shell, suspicious DNS query, code injection) from raw events

## What Sysmon is and why it matters

**Sysmon** (System Monitor) is a free Microsoft Sysinternals driver-and-service that augments Windows native auditing with vastly richer endpoint telemetry. Where native Windows logs tell you *"process X started"*, Sysmon tells you:

> *"process X (hash `abc123`, parent `winword.exe`, original filename `powershell.exe`, signature `Microsoft Corporation`) started with command line `-enc JABjAD0AbgBlA…`, run by user `alice`, with an integrity level of `High`"*

The richness gap is enormous, and most production detection logic in modern SOCs assumes Sysmon is present.

Sysmon is configured by an XML configuration file. The two community-standard baselines are:

- **SwiftOnSecurity / sysmon-config** — the original community baseline. Conservative, well-documented, focuses on attacker-relevant noise reduction
- **Olaf Hartong / sysmon-modular** — modular baseline organised per ATT&CK technique. Richer, more granular, requires more tuning

As an L1 you don't author Sysmon config — but you must understand that **the Sysmon channel is `Microsoft-Windows-Sysmon/Operational`** and that every Sysmon event arrives in ION at `winlog.channel: "Microsoft-Windows-Sysmon/Operational"` with `event.provider: "Microsoft-Windows-Sysmon"`.

A Sysmon document also has its own internal event IDs, ranging from 1 to 28+. **The ones an L1 must memorise: 1, 3, 7, 8, 10, 11, 13, 22.**

```mermaid
flowchart TD
    SysmonDriver[Sysmon driver] --> Channel[Microsoft-Windows-Sysmon/Operational]
    Channel --> Winlogbeat
    Winlogbeat --> ECS[ECS-mapped winlogbeat-*]
    subgraph EventsCaptured[Events captured]
        E1[ID 1 ProcessCreate]
        E3[ID 3 NetworkConnect]
        E7[ID 7 ImageLoaded]
        E8[ID 8 CreateRemoteThread]
        E10[ID 10 ProcessAccess]
        E11[ID 11 FileCreate]
        E13[ID 13 RegistryEvent]
        E22[ID 22 DnsQuery]
    end
    SysmonDriver --> EventsCaptured
```

## The high-value Sysmon event IDs

### Event ID 1 — Process Create

The single most-queried event in any mature SOC. Fields:

- `winlog.event_data.Image` → ECS `process.executable` (the new process)
- `winlog.event_data.CommandLine` → ECS `process.command_line`
- `winlog.event_data.ParentImage` → ECS `process.parent.executable`
- `winlog.event_data.ParentCommandLine` → ECS `process.parent.command_line`
- `winlog.event_data.Hashes` → contains MD5/SHA256/IMPHASH; ECS `process.hash.sha256` etc.
- `winlog.event_data.OriginalFileName` → the PE's original filename from its version resource (catches **renamed binaries**)
- `winlog.event_data.User` → ECS `user.name`
- `winlog.event_data.IntegrityLevel` → process integrity (Low / Medium / High / System)

**ATT&CK:** T1059 Command and Scripting Interpreter, T1218 Signed Binary Proxy Execution, T1036 Masquerading.

### Event ID 3 — Network Connection

A process initiated a network connection. Fields: `Image`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort`, `DestinationHostname`, `Protocol`. **ATT&CK:** T1071, T1041.

### Event ID 7 — Image Loaded

A DLL was loaded by a process. Fields: `Image` (loader), `ImageLoaded` (the DLL), `Signed`, `Signature`, `SignatureStatus`. Heavily filtered by config because Windows loads thousands of DLLs constantly. **ATT&CK:** T1574, T1055.

### Event ID 8 — CreateRemoteThread

A process created a thread in another process — the textbook code-injection primitive. Fields: `SourceImage`, `TargetImage`, `StartAddress`. **ATT&CK:** T1055.003.

### Event ID 10 — ProcessAccess

A process opened a handle to another process. **The classic Mimikatz signature** is `SourceImage` of any process opening `lsass.exe` with `GrantedAccess` of `0x1410` or `0x1010` (PROCESS_VM_READ + PROCESS_QUERY_INFORMATION). **ATT&CK:** T1003.001 (LSASS Memory).

### Event ID 11 — FileCreate

A file was created or overwritten. Fields: `Image`, `TargetFilename`, `CreationUtcTime`. The classic ransomware tell is mass `TargetFilename` writes ending in unusual extensions. **ATT&CK:** T1486.

### Event ID 13 — RegistryEvent (Value Set)

A registry value was written. Fields: `EventType`, `TargetObject` (the registry path), `Details`. **Persistence-detection gold** — Run keys, Image File Execution Options, services, scheduled tasks. **ATT&CK:** T1547.001.

### Event ID 22 — DnsQuery

A process performed a DNS query. Fields: `Image`, `QueryName`, `QueryStatus`, `QueryResults`. The textbook DNS-exfiltration signature is long, high-entropy `QueryName` values at high frequency. **ATT&CK:** T1071.004, T1048.003.

## A worked Sysmon triage

**Scenario.** ION fires the alert *"Office product spawned a shell"* against `WS-FINANCE-04`:

```kql
winlog.channel : "Microsoft-Windows-Sysmon/Operational"
and event.code : "1"
and process.parent.executable : ("*\\\\winword.exe" or "*\\\\excel.exe" or "*\\\\outlook.exe")
and process.executable : ("*\\\\powershell.exe" or "*\\\\cmd.exe" or "*\\\\wscript.exe")
```

The hit shows:

- `process.parent.executable: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"`
- `process.executable: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"`
- `process.command_line: "powershell.exe -nop -w hidden -enc JABjAD0AbgBlAHcALQBvAGIAagBlAGMAdAA…"`
- `winlog.event_data.OriginalFileName: "PowerShell.EXE"`
- `user.name: "alice"`
- `winlog.event_data.IntegrityLevel: "Medium"`

**Interpretation.** Word is the parent. PowerShell is the child. `-nop -w hidden -enc` is the standard *"hide and run base64"* pattern attackers use. The base64 blob is the encoded command. This is almost certainly a malicious macro execution (T1059.001 + T1566.001).

```mermaid
flowchart LR
    Email[Phishing email] --> Word[winword.exe]
    Word -->|Macro fires| PS[powershell.exe -enc ...]
    PS -->|Sysmon 1| Detect1[Office spawns shell]
    PS -->|Sysmon 22| Detect2[DNS query to C2]
    PS -->|Sysmon 3| Detect3[Network connect to C2]
    PS -->|Sysmon 11| Detect4[Drops payload to disk]
    PS -->|Sysmon 13| Detect5[Persistence in Run key]
```

**Pivot 1 — what did PowerShell do?** Find subsequent Sysmon Events 3, 11, or 1 from PowerShell.

**Pivot 2 — DNS queries.** Look at Sysmon 22 from the PowerShell process.

**Pivot 3 — was the macro a delivered email?** Pivot to Outlook attachment write events and from there to email logs.

**Disposition.** Almost always escalate. Containment runbook: isolate host, kill PowerShell, capture memory if possible, hand to L2/IR.

## KQL snippets

```kql
event.code : "10"
and process.target.executable : "*\\\\lsass.exe"
and not process.executable : ("*\\\\MsMpEng.exe" or "*\\\\System32\\\\svchost.exe")
```
- Sysmon 10 (ProcessAccess) targeting LSASS — the credential-dumping signature
- Excludes Defender (`MsMpEng.exe`) and svchost which legitimately query LSASS

```kql
event.code : "13"
and winlog.event_data.TargetObject : ("*\\\\CurrentVersion\\\\Run\\\\*" or "*\\\\CurrentVersion\\\\RunOnce\\\\*")
```
- Sysmon 13 RegistryEvent on the classic Run keys — a primary persistence detection

## Glossary

- **Sysmon** — Sysinternals system-monitor driver/service emitting enriched endpoint telemetry beyond native Windows auditing
- **Sysmon channel** — `Microsoft-Windows-Sysmon/Operational`
- **Image** — Sysmon's term for the executable path of a process; ECS `process.executable`
- **OriginalFileName** — PE version-resource original filename, used to detect renamed binaries
- **Hashes** — Sysmon-computed MD5/SHA256/IMPHASH on process create and image load
- **IntegrityLevel** — Windows process integrity (Low / Medium / High / System)
- **CreateRemoteThread** — Sysmon Event 8; cross-process thread creation, code-injection primitive
- **ProcessAccess** — Sysmon Event 10; opening a handle to another process, used by credential dumpers
- **GrantedAccess** — bitmask on Sysmon 10 indicating what access rights were requested
- **SwiftOnSecurity baseline** — community-standard Sysmon config, the conservative starting point
- **sysmon-modular** — Olaf Hartong's modular Sysmon config set, organised by ATT&CK technique
- **DnsQuery** — Sysmon Event 22; per-process DNS resolution capture, key for DNS-exfil detection

## Further reading

- Microsoft Sysinternals — Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- SwiftOnSecurity / sysmon-config: https://github.com/SwiftOnSecurity/sysmon-config
- Olaf Hartong / sysmon-modular: https://github.com/olafhartong/sysmon-modular
- MITRE ATT&CK — T1003.001 OS Credential Dumping: LSASS Memory
- MITRE ATT&CK — T1071.004 Application Layer Protocol: DNS
""",
    )
    m3l3q = _add_lesson(
        session, mod3, order=6, title="Sysmon recognition — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Six questions on Sysmon event IDs, fields, channel, and triage interpretation.",
    )
    _add_q(session, m3l3q, order=1, kind=QuestionKind.SINGLE,
        stem_md="Which Sysmon event captures a process opening a handle to another process — the foundational Mimikatz-against-LSASS signature?",
        options=[
            {"value": "id1", "label": "Event ID 1"},
            {"value": "id7", "label": "Event ID 7"},
            {"value": "id10", "label": "Event ID 10"},
            {"value": "id13", "label": "Event ID 13"},
        ],
        correct="id10",
        explanation_md="**Event ID 10** is ProcessAccess, capturing handle-opens between processes. The Mimikatz signature is `SourceImage` opening `TargetImage: lsass.exe` with high `GrantedAccess` (often `0x1410` or `0x1010`).",
        points=2,
    )
    _add_q(session, m3l3q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which Sysmon fields would you use to detect a *renamed* `powershell.exe`?",
        options=[
            {"value": "orig", "label": "winlog.event_data.OriginalFileName"},
            {"value": "image", "label": "winlog.event_data.Image"},
            {"value": "hashes", "label": "winlog.event_data.Hashes"},
            {"value": "cmdline", "label": "winlog.event_data.CommandLine"},
        ],
        correct=["orig", "hashes"],
        explanation_md="`OriginalFileName` is the PE version-resource original filename — `powershell.exe` even if the file on disk is `update.exe`. `Hashes` lets you match against known PowerShell SHA256s. `Image` is just the path to the renamed file (useless on its own); `CommandLine` is contextual but not definitive.",
        points=3,
    )
    _add_q(session, m3l3q, order=3, kind=QuestionKind.SHORTANSWER,
        stem_md="A Sysmon Event 1 fires with `ParentImage` of `outlook.exe`, `Image` of `wscript.exe`, and `CommandLine` of `wscript.exe C:\\Users\\bob\\AppData\\Local\\Temp\\invoice.vbs`. What is the most likely scenario and which ATT&CK technique applies?",
        options=None,
        correct=["T1566.001 spearphishing T1059.005 visual basic", "spearphishing attachment + visual basic", "T1566.001 + T1059.005", "phishing attachment running vbs"],
        explanation_md="The user opened a `.vbs` attachment from Outlook. Outlook spawned wscript to execute the script. This is **T1566.001 Spearphishing Attachment + T1059.005 Visual Basic**.",
        points=2,
    )
    _add_q(session, m3l3q, order=4, kind=QuestionKind.SINGLE,
        stem_md="What is the `winlog.channel` value for Sysmon events?",
        options=[
            {"value": "sysmon_only", "label": "Sysmon"},
            {"value": "provider_only", "label": "Microsoft-Windows-Sysmon"},
            {"value": "channel_full", "label": "Microsoft-Windows-Sysmon/Operational"},
            {"value": "security", "label": "Security"},
        ],
        correct="channel_full",
        explanation_md="The full channel name is `Microsoft-Windows-Sysmon/Operational`. The provider is `Microsoft-Windows-Sysmon` but the channel includes the `/Operational` suffix.",
        points=2,
    )
    _add_q(session, m3l3q, order=5, kind=QuestionKind.TRUEFALSE,
        stem_md="Sysmon Event ID 1 always includes the parent process command line.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** Sysmon Event ID 1 includes both `CommandLine` and `ParentCommandLine`. This is one of the largest advantages over native 4688, which often lacks `CommandLine` entirely (and never has `ParentCommandLine`).",
        points=1,
    )
    _add_q(session, m3l3q, order=6, kind=QuestionKind.SHORTANSWER,
        stem_md="You see a Sysmon Event 22 with `QueryName: \"5a3b2c1d.exfil.attacker.com\"` from `powershell.exe` on a finance workstation. State your next two queries.",
        options=None,
        correct=["aggregate by query name and count, find parent of powershell", "stats count by dns name, sysmon 1 to find parent", "aggregate volume, then find parent process"],
        explanation_md="(1) Aggregate Sysmon 22 by `dns.question.name` for the same host and process to estimate the DNS-tunnel volume. (2) Pivot to Sysmon Event 1 for the same host to identify the parent of `powershell.exe` and reconstruct how PowerShell was launched.",
        points=2,
    )

    # Lesson 3.4 — Attack patterns
    m3l4 = _add_lesson(
        session, mod3, order=7,
        title="Triaging common attack patterns from raw events",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Distinguish interactive, network, and remote-interactive logons by LogonType and reason about expected vs anomalous patterns
> 2. Recognise pass-the-hash signatures from a 4624/4625 LogonType 3 + NTLM authentication package
> 3. Identify the rough indicators of golden ticket and silver ticket abuse in 4624 / 4769 events
> 4. Triage suspicious service installs (7045) using `ImagePath` heuristics
> 5. Spot account-creation-then-group-add patterns and Office-spawns-shell parent-child anomalies
> 6. Recognise DNS exfiltration via Sysmon Event 22

## Logon-context triage and pass-the-hash

The single most common L1 question is: *is this logon legitimate?* The answer almost always begins with the LogonType. A legitimate user at their workstation produces LogonType 2 (interactive) or 7 (unlock). A user RDP-ing in produces LogonType 10. A scheduled task produces 4. A service starting produces 5. **Anything else needs explanation.**

**LogonType 3 (network) is where attackers live.** SMB, file shares, IPC$, WMI, PsExec, WinRM — all produce 4624 with LogonType 3. Most LogonType 3 events are completely legitimate (Group Policy refresh, browse to a share). The triage signal is *which user, from where, to where*. A workstation-to-workstation LogonType 3 with admin credentials is suspicious — workstations don't usually authenticate to each other. A service-account LogonType 3 from a client subnet to a server is normal.

### Pass-the-Hash (T1550.002)

PtH is the attack where an attacker has captured an NTLM hash and uses it to authenticate without knowing the cleartext password. The signatures:

- 4624 with `LogonType: "3"` and `AuthenticationPackageName: "NTLM"` (rather than Kerberos)
- `LogonProcessName: "NtLmSsp"`
- Often paired with `KeyLength: "0"` (no Kerberos session key)
- `TargetUserName` is a privileged account; `IpAddress` is a workstation, not a server

In modern domains where Kerberos is the default, **NTLM logons to servers from workstation IPs are inherently suspicious** — especially for admin accounts.

```kql
event.code : "4624"
and winlog.event_data.LogonType : "3"
and winlog.event_data.AuthenticationPackageName : "NTLM"
and winlog.event_data.TargetUserName : ("Administrator" or "*-adm" or "svc-*")
```

A clean enterprise can drop NTLM almost entirely with Kerberos-only policies, which makes any remaining NTLM logon stand out.

```mermaid
flowchart TD
    Logon[4624 received] --> LType{LogonType}
    LType -->|2 Interactive| Console[Expected at console]
    LType -->|3 Network| Net{NTLM or Kerberos?}
    LType -->|10 RDP| RDP[Check source IP and user]
    Net -->|NTLM| NTLM{Privileged user?}
    Net -->|Kerberos| Krb[Normal SMB / share access]
    NTLM -->|Yes admin| PtH[Pass-the-Hash candidate]
    NTLM -->|No| Investigate[Investigate source]
    PtH --> Escalate[Escalate to L2]
```

**Worked example.** ION shows a 4624 on `FILESRV-01`. Fields: `LogonType: 3`, `AuthenticationPackageName: NTLM`, `TargetUserName: Administrator`, `IpAddress: 10.50.4.119`, `WorkstationName: ATTACKER-WIN`. The source IP belongs to a VLAN with helpdesk laptops; the `WorkstationName` is not a known asset name. **This is a textbook PtH attempt** — workstation-named source authenticating to a file server as Administrator over NTLM. Escalate, contain the file server, hunt the source workstation, and check 4768/4769 absence (PtH bypasses Kerberos by definition).

## Golden tickets, silver tickets, and service-install persistence

**Golden ticket (T1558.001)** is forging a TGT using the krbtgt account's hash. A real TGT comes from a 4768 on a DC. A golden ticket *did not* — it was forged offline. The signature: a 4624 on a member server using a Kerberos-signed token whose corresponding 4768 on the DC does not exist.

**Silver ticket (T1558.002)** is forging a service ticket (TGS) using a service account's hash. Even more subtle — a silver ticket means the *DC is never contacted at all*. The 4624 on the targeted service host appears, but no 4769 fires on the DC.

**L1 generally cannot conclusively detect golden or silver tickets** — these are L2 hunting territory. But L1 should **flag for escalation any high-privilege Kerberos logon that lacks corresponding 4768/4769 on the DC**, because that's the conceptual signal.

### Service install persistence (T1543.003)

When attackers establish persistence as SYSTEM, installing a service is one of the cleanest mechanisms. Event ID 7045 on the System channel fires. The triage heuristics on `ImagePath`:

- Path in `%TEMP%`, `%APPDATA%`, `\\Users\\Public\\` → **suspicious**
- Path that's a base64-encoded PowerShell command (`powershell -enc …`) → almost certainly malicious
- `ImagePath` pointing to `cmd.exe /c …` → masqueraded service
- Random-string service names (`Hyguafkj`, `WindowsHelper42`) → tooling tell (Cobalt Strike, Metasploit `psexec_psh`)

```kql
event.code : "7045"
and (winlog.event_data.ImagePath : ("*\\\\Temp\\\\*" or "*\\\\AppData\\\\*" or "*powershell*-enc*" or "*\\\\Users\\\\Public\\\\*"))
```

### Account creation followed by group add

The 4720 → 4732/4756 cluster discussed in Lesson 2 is the persistence pattern that L1 sees most often:

```mermaid
flowchart LR
    A[4720 account created] --> B{Group add within 10m?}
    B -->|4732 BUILTIN Admins| Persist1[Local admin persistence]
    B -->|4756 Universal group| Persist2[Domain group persistence]
    B -->|4728 Global group e.g. Domain Admins| Persist3[CRITICAL escalate now]
    B -->|None| Watch[Continue monitoring]
    Persist1 --> Esc[Escalate]
    Persist2 --> Esc
    Persist3 --> Esc
```

Any 4720 with the same `TargetUserName` followed within minutes by a 4732 against `BUILTIN\\Administrators` (SID `S-1-5-32-544`) or 4756/4728 against `Domain Admins` (`-512`) is an **immediate-escalate**.

## Parent-child anomalies and DNS exfil

**Parent-child anomalies** are the cleanest Sysmon-driven signal. A baseline of *what should never spawn what* gives high-fidelity detection:

| Parent | Suspicious child |
| --- | --- |
| `winword.exe`, `excel.exe`, `outlook.exe`, `powerpnt.exe` | `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`, `regsvr32.exe` |
| `mshta.exe`, `regsvr32.exe`, `wmic.exe` | `cmd.exe`, `powershell.exe` |
| `services.exe` | anything in user-writable paths |
| `svchost.exe` | `cmd.exe` or `powershell.exe` (rare; investigate) |
| `lsass.exe` | any child (lsass should never spawn anything) |
| `w3wp.exe` (IIS), `httpd.exe` | `cmd.exe`, `powershell.exe` (**webshell tell**) |

The Office-spawns-shell example covered in Lesson 3 is the canonical. The IIS-spawns-shell row is the canonical webshell signature (T1505.003).

### DNS exfiltration via Sysmon 22

When attackers can't C2 over HTTP/HTTPS (egress-filtered networks), DNS is the fallback because almost all networks resolve outbound DNS. Tools like `dnscat2` and `iodine` encode payloads as long subdomains under an attacker-controlled domain. Signatures:

- `dns.question.name` length consistently >50 chars
- Subdomains base64- or hex-shaped (high entropy, mixed case)
- Hundreds of queries per minute from a single process
- Always to the same parent domain, varying subdomain
- Process is unexpected for DNS (e.g. `powershell.exe` rather than `chrome.exe`)

A workstation generating 200+ unique DNS names in a short window with a high cardinality from a single process is the smoke. Confirm by inspecting query lengths and entropy.

## Glossary

- **Pass-the-Hash (PtH)** — T1550.002, authenticating with an NTLM hash without the cleartext password
- **Golden ticket** — T1558.001, forged TGT signed with the krbtgt hash
- **Silver ticket** — T1558.002, forged TGS signed with the service account hash
- **AuthenticationPackageName** — 4624 field indicating Kerberos / NTLM / Negotiate; NTLM for admin accounts is the PtH tell
- **WorkstationName** — 4624 field carrying the NetBIOS name claimed by the source; attacker-controlled and often anomalous
- **ImagePath** — 7045 field giving the binary path of an installed service; primary triage heuristic for malicious service installs
- **Webshell** — server-side script enabling remote command execution via web requests; surfaces as `w3wp.exe` spawning shells in Sysmon 1
- **DNS exfiltration** — encoding payload data in DNS queries; surfaces as long, high-entropy subdomains in Sysmon Event 22
- **Parent-child anomaly** — process lineage that violates expected baselines (e.g. winword spawning powershell)
- **LAPS** — Local Administrator Password Solution; rotates local admin passwords per host to break PtH lateral movement
- **krbtgt** — special domain account whose hash signs TGTs; whoever steals it can forge golden tickets indefinitely
- **Privileged group escalation** — adding an attacker-controlled account to BUILTIN\\Administrators (SID -544) or Domain Admins (-512); 4732/4756/4728

## Further reading

- MITRE ATT&CK — T1550.002 Pass the Hash: https://attack.mitre.org/techniques/T1550/002/
- MITRE ATT&CK — T1558.001 Golden Ticket: https://attack.mitre.org/techniques/T1558/001/
- MITRE ATT&CK — T1558.002 Silver Ticket: https://attack.mitre.org/techniques/T1558/002/
- MITRE ATT&CK — T1543.003 Windows Service: https://attack.mitre.org/techniques/T1543/003/
- MITRE ATT&CK — T1505.003 Web Shell: https://attack.mitre.org/techniques/T1505/003/
- Microsoft Learn — Audit Process Creation (4688)
""",
    )
    m3l4q = _add_lesson(
        session, mod3, order=8, title="Attack patterns — quiz",
        lesson_type=LessonType.QUIZ, duration_min=10,
        content_md="Six questions on PtH, persistence, parent-child anomalies, and DNS exfil.",
    )
    _add_q(session, m3l4q, order=1, kind=QuestionKind.SHORTANSWER,
        stem_md="A 4624 fires on `FILESRV-02` with `LogonType: \"3\"`, `AuthenticationPackageName: \"NTLM\"`, `TargetUserName: \"Administrator\"`, `IpAddress: \"10.50.4.119\"` (a workstation subnet), `WorkstationName: \"WS-CONTRACTOR-07\"`. What attack are you looking at?",
        options=None,
        correct=["pass-the-hash T1550.002", "pass the hash", "PtH T1550.002", "T1550.002", "Pass-the-Hash"],
        explanation_md="**Pass-the-Hash (T1550.002).** NTLM authentication for the local Administrator account from a workstation source to a file server, in a domain that should default to Kerberos, is the textbook signature. Containment: isolate `FILESRV-02` and `WS-CONTRACTOR-07`, escalate to L2/IR.",
        points=2,
    )
    _add_q(session, m3l4q, order=2, kind=QuestionKind.SINGLE,
        stem_md="Which event ID directly indicates audit log tampering and should always be escalated?",
        options=[
            {"value": "4624", "label": "4624"},
            {"value": "4688", "label": "4688"},
            {"value": "1102", "label": "1102"},
            {"value": "7045", "label": "7045"},
        ],
        correct="1102",
        explanation_md="**1102** fires when the Security audit log is cleared. There is no legitimate operational reason for this on a production system; it's near-universally evidence destruction (T1070.001).",
        points=2,
    )
    _add_q(session, m3l4q, order=3, kind=QuestionKind.MULTI,
        stem_md="Which heuristics on a 7045 ImagePath are suspicious?",
        options=[
            {"value": "temp", "label": "Path under %TEMP%"},
            {"value": "progfiles", "label": "Path under C:\\Program Files\\"},
            {"value": "ps_enc", "label": "ImagePath containing powershell -enc"},
            {"value": "cmd_c", "label": "ImagePath containing cmd.exe /c"},
            {"value": "drivers_sys", "label": "Path ending in .sys under C:\\Windows\\System32\\drivers\\"},
        ],
        correct=["temp", "ps_enc", "cmd_c"],
        explanation_md="Temp paths, encoded PowerShell, and cmd-as-service are all attacker-tooling tells. Program Files and System32 driver paths are normal install locations for legitimate vendor software.",
        points=3,
    )
    _add_q(session, m3l4q, order=4, kind=QuestionKind.SHORTANSWER,
        stem_md="You see a Sysmon Event 22 burst from `WS-FINANCE-04`: 480 DNS queries in 2 minutes from `powershell.exe`, all to `*.exfil.attacker.com`, with average subdomain length of 60 characters. What is happening?",
        options=None,
        correct=["DNS exfiltration T1071.004", "DNS C2 / exfil", "DNS tunnelling T1071.004", "DNS exfiltration"],
        explanation_md="**DNS exfiltration via PowerShell to a C2 domain (T1071.004 + T1048.003).** The long subdomains are encoded payload chunks; the constant parent domain is the C2; the high query rate is the data-transfer pattern. Isolate the host immediately.",
        points=2,
    )
    _add_q(session, m3l4q, order=5, kind=QuestionKind.TRUEFALSE,
        stem_md="A legitimate Kerberos logon to a member server should always have a corresponding 4768/4769 on a domain controller around the same time.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True (mostly).** A legitimate Kerberos AS-REQ produces 4768 on the DC; a TGS-REQ produces 4769. A 4624 with Kerberos auth whose ticket lacks corresponding DC-side events is the conceptual signal of golden/silver ticket forgery. Caveat: ticket caching can produce a 4624 without a fresh 4768/4769 within a tight window, so absence over a short window is suspicious-not-conclusive.",
        points=2,
    )
    _add_q(session, m3l4q, order=6, kind=QuestionKind.SHORTANSWER,
        stem_md="You see a 4720 on `DC01` for new user `mssql_helper`, followed 4 minutes later by a 4732 adding the same user to `BUILTIN\\Administrators`. State your next two actions.",
        options=None,
        correct=["identify subjectusername actor, disable account, scope actor logons", "identify the actor, disable mssql_helper, escalate", "find SubjectUserName, pull actor 4624 logons, disable new account"],
        explanation_md="(1) Identify the `SubjectUserName` (the account that performed the create+add) — that's the actor. (2) Disable the new `mssql_helper` account immediately, remove it from Administrators, and pull all 4624 logons by the actor account in the prior 24h to scope how the attacker got admin in the first place.",
        points=2,
    )

    # ── Module 4 — Network Telemetry (v0.11.7) ───────────────────────────
    # Authored at BTL1/SANS depth from research-agent dossier. Builds on
    # Module 3 (endpoint logs) by covering what happens *between* hosts:
    # PCAP/flow/Zeek/IDS, conn_state codes, ECS mapping, beaconing and DNS
    # tunneling, scans/sweeps, exfiltration patterns, ATT&CK mapping for
    # network-side observables.
    mod4 = _add_module(
        session, course, order=4,
        title="Network Telemetry",
        description_md=(
            "What endpoint logs cannot tell you: who talked to whom, when, "
            "how often, and how much. PCAP, flow records, Zeek metadata, "
            "and IDS alerts; conn_state triage; beaconing and DNS tunneling "
            "fingerprints; scans, sweeps, lateral movement, and bulk "
            "exfiltration to cloud-storage destinations; mapping all of "
            "the above to MITRE ATT&CK."
        ),
        estimated_minutes=200,
    )

    # Lesson 4.1 — data sources
    m4l1 = _add_lesson(
        session, mod4, order=1,
        title="Network data sources — PCAP, flow, Zeek, IDS",
        lesson_type=LessonType.READING, duration_min=22,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Compare PCAP, flow records (NetFlow/IPFIX/sFlow), protocol metadata (Zeek), and IDS alerts (Suricata/Snort) across cost, retention, fidelity, and privacy
> 2. Explain why sampling rate is essential context for any flow-based count
> 3. Identify the major Zeek log families and what each captures
> 4. Position proxy and next-generation firewall logs in the telemetry stack
> 5. Pick the right tier of telemetry for a given investigative question
>
> **Prerequisites.** Module 3 *Windows Event Logs* completed.

## Why this module exists

Module 3 covered endpoint logs — what happens *on* a host. This module covers what happens *between* hosts. Attackers don't always leave clean endpoint traces; a living-off-the-land tool can produce normal-looking process events while its *network* behaviour — a slow regular callback to an external IP every ten minutes — is the only place the compromise is visible.

Network telemetry also scopes incidents. When an alert fires on one host, network logs tell you whether other hosts also talked to the bad destination, whether data left the perimeter, and over what time window. Scoping is an L1 job and you cannot scope without flow and DNS history.

Finally, network logs are durable in a way endpoint logs are not. An attacker who clears Windows Security logs (4624 / 1102, covered in Module 3) cannot retroactively unsend the packets a network sensor captured.

## The three tiers of network telemetry

Network monitoring data trades fidelity for volume.

**Full packet capture (PCAP)** is the byte-for-byte recording of traffic. Highest fidelity; you can replay, extract files, decode protocols you didn't know about at capture time. Also enormous: a single saturated 1 Gb/s link produces around 450 GB per hour. Most organisations retain full PCAP only at chokepoints for hours to days.

**Flow records** are statistical summaries of conversations — typically a 5-tuple (source IP, source port, destination IP, destination port, protocol) plus byte and packet counts and timestamps. No payload. Tiny — ~50–100 bytes per record. Excellent for *"did host A ever talk to host B?"* over months. Poor for *"what did they say?"*.

**Protocol metadata logs** — the Zeek family — sit between PCAP and flow. The sensor parses the protocol on the wire (DNS, HTTP, TLS, SMB) and emits structured records of what was seen: the DNS query name, the HTTP host header, the TLS server name, file hashes for transferred files. Vastly smaller than PCAP, vastly richer than flow. **This tier is the L1 analyst's bread and butter.**

**IDS alerts** (Suricata, Snort) sit alongside Zeek, not in place of it. Zeek produces the fact-trail; the IDS produces a *"this fact-trail contains a known-bad pattern"* pointer.

| Property | PCAP | Flow (NetFlow/IPFIX) | Zeek metadata | IDS alerts |
| --- | --- | --- | --- | --- |
| Captures payload | Yes | No | Partial (extracted fields, hashes) | Only matching context |
| Storage cost | Very high | Very low | Low–moderate | Very low |
| Typical retention | Hours–days | Months–years | Weeks–months | Months |
| Good for retrospective hunt | If retained | Yes | Yes | Only if a rule fired |
| Good for *"did X ever talk to Y?"* | Slow | Excellent | Excellent | Only if rule fired |
| Privacy footprint | Highest | Lowest | Medium | Medium |

```mermaid
graph TD
    A[Network traffic] --> B[Full PCAP]
    A --> C[Flow records]
    A --> D[Protocol metadata]
    A --> E[IDS alerts]
    C --> C1[NetFlow v5]
    C --> C2[NetFlow v9 / IPFIX]
    C --> C3[sFlow]
    D --> D1[Zeek conn.log]
    D --> D2[Zeek dns.log]
    D --> D3[Zeek http.log]
    D --> D4[Zeek ssl.log]
    D --> D5[Zeek files.log]
    E --> E1[Suricata]
    E --> E2[Snort]
```

## NetFlow, IPFIX, and sFlow

**NetFlow** was developed by Cisco. v5 is the legacy workhorse — fixed fields, IPv4-only. v9 added templates for extensibility and IPv6. NetFlow is unidirectional by default; a TCP connection produces two records, one per direction, and most collectors stitch them.

**IPFIX (IP Flow Information Export)** is the IETF-standard successor to NetFlow v9, defined in RFC 7011. Template-based, vendor-neutral, supports application identification when the exporter inspects deep enough.

**sFlow (sampled flow)** is fundamentally different. NetFlow/IPFIX try to record every flow by default. sFlow is *always sampled* — the exporter looks at, say, 1 in every 1024 packets, and exports those samples plus periodic interface counters. Cheap on switch ASICs, which is why high-density switches favour it. **You must remember the sampling rate when reasoning about volumes** — a single observed flow at 1:1024 implies roughly a thousand unseen real flows.

Every flow architecture has the same three parts: an **exporter** (router, switch, firewall, dedicated probe), a **collector** (the central system that ingests and stores), and an **analyser** (the SIEM or hunt UI you actually query). Sampling can be enabled even on NetFlow exporters under load — *always know your sampling rate before you call something rare.*

What flows do **not** capture: no payload. No DNS query name. No HTTP URL. No TLS server name. No file transferred. They tell you *"192.0.2.45 sent 14 MB to 198.51.100.12 over TCP/443 between 02:14 and 02:18"* — they do not tell you whether that 443 connection was Gmail, Slack, or a Cobalt Strike beacon.

## Zeek (formerly Bro)

Zeek is a network security monitor that parses traffic in real time and emits structured logs by protocol. It is not a signature-matching IDS; it is a programmable protocol decoder that produces a fact-trail. The Zeek log family an L1 should recognise:

- **conn.log** — every connection attempt, successful or not. The backbone log.
- **dns.log** — every DNS query and response.
- **http.log** — every cleartext HTTP transaction (host, URI, method, status, user-agent, referrer).
- **ssl.log** — every TLS handshake (SNI, certificate chain ID, JA3 fingerprint).
- **files.log** — every file Zeek extracted from a protocol stream, with hash.
- **x509.log** — every certificate seen, with subject, issuer, validity dates.
- **smtp.log / ftp.log / ssh.log** — protocol-specific envelopes and version exchanges.
- **weird.log** — protocol-violation events (often noise, sometimes real).
- **notice.log** — Zeek's curated *"you should look at this"* output.

Zeek differs from raw PCAP in that the parsing is already done. *"Did anyone resolve `evil-c2.example`?"* against PCAP needs you to decode every DNS packet in the timeframe; against Zeek it's a single field match on `dns.log`. Against NetFlow it's not answerable at all — flow records don't carry DNS query names.

## Suricata and Snort

Signature-based IDS. They watch traffic against a ruleset (Emerging Threats, Talos, custom) and emit alerts on match. For L1 work, IDS alerts are usually the *trigger* for an investigation, and Zeek/flow data is what you use to scope and confirm. A Suricata `ET MALWARE Cobalt Strike Beacon Activity` on host A is the starting gun; the conn.log shows how long the pattern has been going on, the dns.log shows what name resolved to that destination, the ssl.log carries the JA3.

Treat IDS alerts with healthy scepticism — false-positive rates on community rules are non-trivial. The default L1 question is not *"is this real?"* but *"given this alert, what does Zeek/flow show, and does that corroborate?"*.

## Proxy and firewall logs

Most enterprise networks force outbound HTTP/HTTPS through a forward proxy or NGFW.

- **Web proxies (Zscaler, Bluecoat, Squid)** log per-URL: timestamp, user, source IP, destination URL, host, method, content-category, action (allow/block), bytes, user-agent. Best place to answer *"did this user visit this site?"* with HTTP/HTTPS, especially with SSL inspection enabled.
- **Next-generation firewalls (Palo Alto, Fortinet, Check Point)** produce traffic logs (5-tuple plus app-id and bytes), URL filtering logs, threat logs, decryption logs. Palo Alto's `App-ID` is *"regardless of port, this looks like SSH"* or *"this looks like Tor"*.
- **Perimeter firewalls without app-awareness** (older Cisco ASA, basic iptables) produce 5-tuple connection logs equivalent to NetFlow.

What an L1 sees: usually a SIEM-normalised view that flattens proxy and firewall logs into a common schema (often ECS — covered next lesson). The fields you care about are source identity, destination, action, category, bytes.

## Trade-offs

- **Cost vs fidelity.** PCAP is highest fidelity, highest cost. Flow is lowest cost, lowest fidelity. Zeek is the practical sweet spot.
- **Retention vs volume.** Six months of flow data costs less than two days of PCAP at a busy site.
- **Privacy.** PCAP captures everything including credentials and personal data inside cleartext protocols. Many organisations restrict PCAP queries. Zeek can be configured to drop sensitive fields. Flow has the smallest privacy footprint.
- **Encryption.** Modern TLS 1.3 with Encrypted Client Hello (ECH) limits what unencrypted-decoder Zeek can see — SNI may be hidden. JA3 still works on the handshake. PCAP without keys is opaque past the handshake.

```mermaid
graph TD
    P[PCAP - highest detail, highest volume]
    Z[Zeek metadata - mid detail, mid volume]
    F[Flow records - low detail, lowest volume]
    P --> Z
    Z --> F
```

## Glossary

- **PCAP** — Packet Capture; lossless byte-for-byte recording. Highest fidelity, highest cost.
- **NetFlow** — Cisco-originated flow-record protocol. v5 IPv4-only legacy; v9 templates + IPv6.
- **IPFIX** — IETF standard flow protocol (RFC 7011), successor to NetFlow v9.
- **sFlow** — Always-sampled flow protocol favoured by high-density switches.
- **Sampling rate** — Ratio of inspected to total packets/flows; required context for flow counts.
- **Exporter / collector / analyser** — Device emits records → central store → query tool.
- **Zeek** — Open-source network monitor (formerly Bro); programmable, not signature-based.
- **Suricata / Snort** — Signature-based IDS engines.
- **App-ID** — Palo Alto's enriched protocol identifier independent of port.

## Further reading

- Zeek log reference: https://docs.zeek.org/en/master/script-reference/log-files.html
- RFC 7011 — IPFIX Protocol Specification: https://www.rfc-editor.org/rfc/rfc7011
- RFC 3954 — NetFlow v9: https://www.rfc-editor.org/rfc/rfc3954
- RFC 3176 — sFlow: https://www.rfc-editor.org/rfc/rfc3176
""",
    )
    m4l1q = _add_lesson(
        session, mod4, order=2, title="Data sources — quiz",
        lesson_type=LessonType.QUIZ, duration_min=6,
        content_md="Three questions on telemetry tier selection, sFlow behaviour, and Zeek's role.",
    )
    _add_q(session, m4l1q, order=1, kind=QuestionKind.SINGLE,
        stem_md="Which network telemetry tier is best suited to answering *\"did any host in the estate ever connect to 198.51.100.42 in the last 90 days?\"*",
        options=[
            {"value": "pcap", "label": "Full PCAP"},
            {"value": "flow", "label": "NetFlow / IPFIX records"},
            {"value": "ids_only", "label": "Suricata alerts only"},
            {"value": "edr", "label": "Endpoint EDR logs"},
        ],
        correct="flow",
        explanation_md="Flow records are designed for long retention and per-conversation queries. PCAP is rarely retained 90 days; Suricata only fires on rule matches; EDR doesn't index full network history.",
        points=2,
    )
    _add_q(session, m4l1q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are true about sFlow?",
        options=[
            {"value": "sampled", "label": "It is always sampled"},
            {"value": "payload", "label": "It captures full packet payloads"},
            {"value": "asic", "label": "Used by high-density switches because it's cheap on the ASIC"},
            {"value": "rate_context", "label": "Sampling rate must be considered when reasoning about volume"},
        ],
        correct=["sampled", "asic", "rate_context"],
        explanation_md="sFlow is statistically sampled, doesn't capture payloads, is favoured on busy switching gear, and the sampling rate is essential context when interpreting counts.",
        points=2,
    )
    _add_q(session, m4l1q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="Zeek is fundamentally a signature-based IDS, like Snort.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** Zeek is a programmable network monitor that parses protocols and emits structured logs. Suricata and Snort are signature-based. Zeek scripts can produce notices but the core engine is a protocol decoder, not a rule matcher.",
        points=1,
    )

    # Lesson 4.2 — Zeek + ECS mapping
    m4l2 = _add_lesson(
        session, mod4, order=3,
        title="Reading Zeek logs and the ECS mapping",
        lesson_type=LessonType.READING, duration_min=22,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Read a `conn.log` row and explain every field
> 2. Interpret the seven `conn_state` codes that matter for triage
> 3. Identify suspicious patterns in `dns.log` and `ssl.log`
> 4. Pivot between Zeek logs using the shared `uid`
> 5. Map every Zeek field to its Elastic Common Schema (ECS) equivalent
> 6. Write a basic KQL query against Zeek-via-Filebeat data

## conn.log fields

A `conn.log` record represents one connection (or attempt). The fields you must know:

- **ts** — connection-start timestamp.
- **uid** — *connection unique ID*, e.g. `CzZRSm4VC4P0E5VqTk`. Every other Zeek log produced for this connection (dns, http, ssl, files) shares this uid. **It is the pivot key.**
- **id.orig_h / id.orig_p** — originator IP and port (the side that initiated).
- **id.resp_h / id.resp_p** — responder IP and port.
- **proto** — transport protocol (`tcp`, `udp`, `icmp`).
- **service** — application protocol Zeek identified (`dns`, `http`, `ssl`, `ssh`, `smb`). Empty if Zeek couldn't identify it.
- **duration** — connection duration in seconds.
- **orig_bytes / resp_bytes** — application-layer bytes sent by each side (excludes retransmissions/headers).
- **conn_state** — the connection state code (next section).
- **history** — compact packet-sequence string. Lowercase = originator, uppercase = responder. `S`=SYN, `H`=SYN+ACK, `A`=ACK, `D`=data, `F`=FIN, `R`=RST. A successful TLS connection looks like `ShADdaFf`.

Example row (TSV, abbreviated):

```
ts=1714060800.123 uid=CzZRSm4VC4P0E5VqTk id.orig_h=10.20.30.40 id.orig_p=51234
id.resp_h=192.0.2.55 id.resp_p=443 proto=tcp service=ssl duration=14.21
orig_bytes=4502 resp_bytes=88210 conn_state=SF history=ShADadFf
```

Read it as: client `10.20.30.40` made an outbound TLS connection to `192.0.2.55:443`, lasted 14.2s, client sent 4.5 KB, received 88 KB, terminated cleanly.

## conn_state codes that matter

| Code | Meaning | Triage signal |
| --- | --- | --- |
| **S0** | SYN sent, no reply | Port-scan or dead destination |
| **S1** | Established, not terminated at flush | In-progress; usually unremarkable |
| **SF** | Normal establishment + termination | Healthy traffic — also healthy beacons |
| **REJ** | Responder rejected with RST | Closed port, or filtered |
| **RSTO** | Originator aborted with RST | Application-layer abort |
| **RSTR** | Responder aborted with RST | Server actively cut client off — investigate |
| **OTH** | No SYN seen, mid-connection only | Long-lived connection present at sensor start |

**Triage shortcuts:** thousands of `S0` to many destinations in a short window = scanning. Many `REJ` to one destination = misconfigured client. `SF` outbound with 1 KB out + 50 KB in = normal HTTP. `SF` outbound with 50 MB out + 2 KB in = exfil candidate.

## dns.log — patterns to flag

Key fields: `uid`, `id.orig_h`, `id.resp_h`, `query`, `qtype_name` (A, AAAA, TXT, MX), `rcode_name` (NOERROR, NXDOMAIN, SERVFAIL, REFUSED), `answers`, `TTLs`.

- **Long subdomain labels.** A query for `aGVsbG8tdGhpcy1pcy1leGZpbA.evil.example` with 50+ chars before the parent is a classic DNS-tunneling shape. CDN domains can have long labels too — context and parent reputation matter.
- **NXDOMAIN bursts.** A host generating dozens of NXDOMAIN replies in a short window often means a Domain Generation Algorithm (DGA) is at work; the malware burns through algorithmic candidates until it finds the live controller.
- **DGA-shaped queries.** High-entropy strings like `xkqzplmnvwert.com`, `qjxzbvwert42.net`. The labels look statistically random rather than English words.
- **Rare TLDs.** Heavy traffic to `.tk`, `.top`, `.xyz`, `.cf`, `.gq` correlates with abuse — use as a weight, not a verdict.
- **TXT-record volume.** TXT is normal for SPF/DKIM/domain-validation. *Thousands of TXT queries from one host to one parent domain over hours* is the hallmark of `dnscat2` / `iodine`-style tunneling.

## http.log and ssl.log

`http.log` covers cleartext HTTP — fields you'll use: `host`, `uri`, `method`, `status_code`, `user_agent`, `referrer`, `request_body_len`, `response_body_len`. With most traffic now TLS-encrypted, http.log is mostly relevant where SSL inspection decrypts on the wire, or for legitimate cleartext (internal HTTP, captive portals).

`ssl.log` is far more useful in TLS-everywhere networks. Fields: `version`, `cipher`, `server_name` (the SNI), `subject`, `issuer`, `validation_status`, `ja3`, `ja3s`, `established`.

**SNI (Server Name Indication)** is the unencrypted hostname in the TLS ClientHello. Until Encrypted Client Hello (ECH) deploys broadly, SNI is the analyst's window into *what site did this client claim to be visiting?* Note **claim** — domain fronting can lie; ECH will eliminate SNI visibility entirely on networks that adopt it.

**JA3 / JA3S in non-jargon terms.** JA3 is a fingerprint of how a TLS client speaks during the handshake — its list of cipher suites, extensions, elliptic curves, and curve formats. Different software stacks (Chrome, Firefox, Python `requests`, Cobalt Strike, Sliver) produce subtly different lists. JA3 hashes the lists into a 32-character MD5. Two clients with identical JA3s are probably running the same TLS library version. JA3S is the same idea on the server side. Why this matters for L1: even though the rest of the connection is encrypted, **a host producing a JA3 that matches a known Cobalt Strike beacon's JA3 is strong evidence of what's running, without ever decrypting the payload.** JA3 collisions are real (legitimate Java clients overlap with malware that uses the same TLS library), so use it as a strong weight, not a verdict.

## Pivoting via uid

The most powerful pivot in the Zeek stack. Every connection produces one `conn.log` row and zero or more rows in protocol-specific logs, all sharing the same `uid`.

1. Find the `conn.log` row of interest.
2. Take the `uid`.
3. Query every other Zeek log for that uid. You instantly get DNS resolution, TLS SNI/JA3, and any files transferred.

If the original alert is a Suricata signature, Suricata in eve.json mode emits a `flow_id` that maps to Zeek's connection key in most properly-integrated stacks.

```mermaid
graph LR
    C[conn.log uid=ABC123]
    D[dns.log uid=XYZ789]
    H[http.log uid=ABC123]
    S[ssl.log uid=ABC123]
    F[files.log uid=ABC123]
    X[x509.log fingerprint=...]
    C --- H
    C --- S
    C --- F
    S --- X
    D -. resolves to .-> C
```

The dashed arrow is the conceptual link from a DNS resolution (its own uid) to the resulting connection (different uid but matching destination IP).

## ECS field mapping

Modern ELK stacks ingest Zeek via Filebeat's Zeek module, which renames fields into the Elastic Common Schema (ECS). You'll see both names in practice — Zeek-native in some panels, ECS in others. The mapping you must memorise:

| Zeek field | ECS field |
| --- | --- |
| `id.orig_h` | `source.ip` |
| `id.orig_p` | `source.port` |
| `id.resp_h` | `destination.ip` |
| `id.resp_p` | `destination.port` |
| `proto` | `network.transport` |
| `service` | `network.protocol` |
| `orig_bytes` | `source.bytes` |
| `resp_bytes` | `destination.bytes` |
| `orig_bytes + resp_bytes` | `network.bytes` |
| `query` (dns.log) | `dns.question.name` |
| `qtype_name` (dns.log) | `dns.question.type` |
| `rcode_name` (dns.log) | `dns.response_code` |
| `host` (http.log) | `url.domain` |
| `uri` (http.log) | `url.path` |
| `user_agent` (http.log) | `user_agent.original` |
| `server_name` (ssl.log) | `tls.client.server_name` |
| `ja3` (ssl.log) | `tls.client.ja3` |
| `ja3s` (ssl.log) | `tls.server.ja3s` |

ECS uses dotted lowercase paths and prefers `source` / `destination` over `client` / `server` for connection-level data.

## Worked KQL examples

**Example 1 — rare destination ports for one host.** A user's workstation feels sluggish; you want any unusual outbound TCP destinations in 24h.

```kql
event.dataset : "zeek.conn"
and source.ip : "10.20.30.40"
and not destination.port : (80 or 443 or 53 or 123)
and network.transport : "tcp"
```

In Discover sort by `@timestamp` descending; in Lens aggregate by `destination.port` to spot any port that's unexpectedly common.

**Example 2 — long-subdomain DNS candidates.** Surface DNS-tunneling candidates across the estate.

```kql
event.dataset : "zeek.dns"
and dns.question.name : *
and dns.question.type : ("TXT" or "A")
```

Then in Lens aggregate by `dns.question.name`, top values, and add a runtime field `dns_label_length` from the leftmost label's character count. Anything above 50 chars with significant query volume warrants a closer look.

## Glossary

- **conn.log / uid** — Zeek connection record + connection-unique pivot key.
- **conn_state** — Two/three-character state code: S0, S1, SF, REJ, RSTO, RSTR, OTH.
- **history** — Per-packet-direction shorthand string in conn.log.
- **SNI** — Server Name Indication; unencrypted TLS hostname extension.
- **JA3 / JA3S** — TLS handshake fingerprint hashes (client / server).
- **DGA / NXDOMAIN** — Algorithmic-domain malware behaviour signal.
- **ECS** — Elastic Common Schema; normalised field naming for the SIEM.

## Further reading

- ECS network fields: https://www.elastic.co/guide/en/ecs/current/ecs-network.html
- ECS DNS fields: https://www.elastic.co/guide/en/ecs/current/ecs-dns.html
- ECS TLS fields: https://www.elastic.co/guide/en/ecs/current/ecs-tls.html
- JA3 (Salesforce original): https://github.com/salesforce/ja3
""",
    )
    m4l2q = _add_lesson(
        session, mod4, order=4, title="Zeek + ECS — quiz",
        lesson_type=LessonType.QUIZ, duration_min=6,
        content_md="Three questions on conn_state interpretation, ECS mapping, and the uid pivot.",
    )
    _add_q(session, m4l2q, order=1, kind=QuestionKind.SINGLE,
        stem_md="A host produced 4,000 conn.log records in 60 seconds, all with `conn_state=S0`, to many different destinations. What's the most likely explanation?",
        options=[
            {"value": "browse", "label": "Heavy legitimate web browsing"},
            {"value": "syn_scan", "label": "A TCP SYN port scan from this host"},
            {"value": "ssh", "label": "A long-lived SSH session"},
            {"value": "inbound", "label": "The host received many inbound connections"},
        ],
        correct="syn_scan",
        explanation_md="`S0` means SYN sent with no reply, and 4,000 such attempts to varied destinations in a minute is a textbook SYN-scan fingerprint.",
        points=2,
    )
    _add_q(session, m4l2q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which Zeek-to-ECS field mappings are correct?",
        options=[
            {"value": "src_ip", "label": "id.orig_h → source.ip"},
            {"value": "query", "label": "query (dns.log) → dns.question.name"},
            {"value": "sni_url", "label": "server_name (ssl.log) → url.domain"},
            {"value": "ja3", "label": "ja3 (ssl.log) → tls.client.ja3"},
        ],
        correct=["src_ip", "query", "ja3"],
        explanation_md="The SNI maps to `tls.client.server_name`, not `url.domain` (which is the HTTP host). The other three are correct.",
        points=3,
    )
    _add_q(session, m4l2q, order=3, kind=QuestionKind.SINGLE,
        stem_md="You have a suspicious conn.log row with `uid=CzZRSm4VC4P0E5VqTk`. What's the fastest way to retrieve every related Zeek event for this connection?",
        options=[
            {"value": "ip_time", "label": "Search every Zeek log for the source IP and timestamp"},
            {"value": "uid", "label": "Query every Zeek log dataset filtering on that uid"},
            {"value": "pcap", "label": "Replay the PCAP for that timeframe"},
            {"value": "suricata", "label": "Open a Suricata rule against the destination"},
        ],
        correct="uid",
        explanation_md="`uid` is the connection-level pivot key shared across all Zeek logs for that connection. Filtering on uid is exact and instant.",
        points=2,
    )

    # Lesson 4.3 — beaconing & C2
    m4l3 = _add_lesson(
        session, mod4, order=5,
        title="Beaconing, DNS tunneling, and C2 detection",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Define beaconing and identify its statistical signature in Zeek conn.log
> 2. Walk a worked example end-to-end (144 connections, ~600 s jitter, low byte volume)
> 3. Recognise DNS-tunneling shape and write the KQL aggregation that surfaces it
> 4. Identify HTTP/HTTPS C2 indicators despite encryption
> 5. Reason about CDN-hidden C2 (Cloudfront, Discord CDN) without false-positiving on legitimate cloud traffic
> 6. State the L1 escalation criteria for a suspected C2

## What beaconing is

A beacon is a periodic check-in by an implanted agent to its command-and-control (C2) server. The agent says *"I'm alive — any orders?"*; the server says *"yes, run this"* or *"no, sleep"*. Cadence varies — 60 s, 5 min, 1 hour. Mature C2 frameworks (Cobalt Strike, Sliver, Mythic, Brute Ratel) randomise with **jitter** — a percentage variation around the base — so check-ins cluster around an average rather than landing on the second.

Beaconing is hard to spot manually because each individual connection is unremarkable: a small TCP/443 from a workstation to an external IP, tens of kilobytes, completes cleanly. **The signal lives in the aggregate** — hundreds of nearly-identical connections, regularly spaced, over hours.

## The statistical signature

The shape an L1 should learn to recognise:

- **High connection count** to a single destination over a long window. *"144 connections to 192.0.2.55 in the last 24 hours"* is suspicious if the destination isn't a known service.
- **Low total byte volume per connection.** A beacon's check-in is small — a few hundred bytes to a few KB. If the C2 has work, the answer can be larger; otherwise both directions are tiny.
- **Regular interval with jitter.** Plot timestamps; look for clustering around a base period. Common: 30 s, 60 s, 300 s, 600 s, 3600 s. Jitter typically 0–30 %.
- **Long-lived destination.** Same destination contacted across hours or days, not a one-off burst.
- **Single source-destination pair.** Beaconing is usually one infected host to one C2 IP, not many sources to one destination.

**Mental rule.** A host that talks to one external IP **at least once every ten minutes for six hours straight**, with each connection under 10 KB total, is beaconing until proven otherwise. The proof is usually *"that destination is a legitimate service"* (Microsoft update endpoints, telemetry, mail polling).

## Worked example — 144 connections in 24 hours

A daily summary shows workstation `10.20.30.40` had exactly 144 successful TCP/443 connections to `192.0.2.55` over the last 24 hours, average 3.2 KB out / 2.8 KB in. 144 / 24 h = **once every ten minutes**, with low volume both ways.

Sample conn.log shape (abbreviated):

```
ts=...T00:00:14Z src=10.20.30.40:55001 dst=192.0.2.55:443 proto=tcp service=ssl
  duration=4.1 orig_bytes=3211 resp_bytes=2855 conn_state=SF
ts=...T00:10:32Z src=10.20.30.40:55012 dst=192.0.2.55:443 proto=tcp service=ssl
  duration=4.0 orig_bytes=3198 resp_bytes=2844 conn_state=SF
ts=...T00:20:51Z src=10.20.30.40:55021 dst=192.0.2.55:443 proto=tcp service=ssl
  duration=4.2 orig_bytes=3205 resp_bytes=2861 conn_state=SF
ts=...T00:31:08Z src=10.20.30.40:55029 dst=192.0.2.55:443 proto=tcp service=ssl
  duration=3.9 orig_bytes=3220 resp_bytes=2849 conn_state=SF
[... 140 more ...]
```

Inter-arrival times: 618 s, 619 s, 617 s — base **600 s with ~3 % jitter**. Byte counts uniform. **All `conn_state=SF`** — clean handshake, clean close. Classic beacon.

The ES|QL aggregation that surfaces this estate-wide:

```esql
FROM zeek-conn-*
| WHERE event.dataset == "zeek.conn"
   AND network.transport == "tcp"
   AND destination.ip IS NOT NULL
   AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS conn_count = COUNT(*),
        avg_bytes = AVG(network.bytes),
        unique_src = COUNT_DISTINCT(source.ip)
   BY source.ip, destination.ip, destination.port
| WHERE conn_count >= 50 AND avg_bytes < 20000 AND unique_src == 1
| SORT conn_count DESC
```

Returns source-destination pairs with ≥50 connections, average size <20 KB, single source per destination — the candidate beacon list. Walk the list, check SNI and JA3 in `ssl.log` for those connections, and look up the destination IP against threat intel.

```mermaid
sequenceDiagram
    participant A as Implant 10.20.30.40
    participant C as C2 192.0.2.55
    A->>C: TLS connect, 3.2KB out, 2.8KB in (T+0)
    Note over A,C: ~600s sleep with jitter
    A->>C: TLS connect, 3.1KB out, 2.9KB in (T+618s)
    Note over A,C: ~600s sleep with jitter
    A->>C: TLS connect, 3.2KB out, 2.8KB in (T+1235s)
    Note over A,C: pattern continues 144x in 24h
```

## DNS tunneling

DNS tunneling encodes data in DNS queries and responses. DNS is rarely blocked — even on networks that aggressively filter web traffic — so malware uses it as a covert channel for both C2 and exfiltration. Tools: `dnscat2`, `iodine`, DNS modes in Cobalt Strike.

The shape:

- High query volume from one source to one parent domain.
- Long subdomain labels (often 50+ chars) carrying base32/base64-encoded payload chunks.
- Frequent use of TXT records (the spec allows ~255 bytes of arbitrary text in a TXT response — useful for the C2 to send commands back).
- Sometimes A or AAAA records for short payloads, with the answer IP encoding the response.

**Worked example.** Internal host `10.20.30.40` is making DNS queries to `c2.example.test` (`.test` is reserved by RFC 6761 for examples). dns.log shows:

```
ts=... query=aGVsbG8tdGhpcy1pcy1jaHVuay0xLW9mLWV4ZmlsLWRhdGE.c2.example.test
       qtype=TXT rcode=NOERROR
ts=... query=Y2h1bmstMi1tb3JlLWRhdGEtaGVyZS1jb250aW51aW5n.c2.example.test
       qtype=TXT rcode=NOERROR
ts=... query=Y2h1bmstMy1ldmVuLW1vcmUtZGF0YS1iZWluZy1zZW50.c2.example.test
       qtype=TXT rcode=NOERROR
[... 800 more in a 5-minute window ...]
```

Each leftmost label ~45–50 chars of base32-shaped content. All TXT type. All to the same parent. Query rate ~3/s — far above any user behaviour.

```kql
event.dataset : "zeek.dns"
and dns.question.type : "TXT"
and source.ip : *
```

Aggregate in Lens by `source.ip` and `dns.question.registered_domain` (when ECS module is configured). Sort by query count; compute mean leftmost-label length — anything over 30 chars is unusual.

```mermaid
graph LR
    H[Internal host 10.20.30.40]
    R[Internal resolver]
    A[Authoritative for c2.example.test]
    H -- "TXT q: aGVsbG8...c2.example.test" --> R
    R -- "recursive lookup" --> A
    A -- "TXT response with command bytes" --> R
    R -- "answer back" --> H
```

## HTTP/HTTPS C2

Before TLS dominated, HTTP-based C2 was the norm; it's still common in commodity malware. Shape:

- **Low-and-slow GET/POST.** Periodic requests to one URL, small bodies.
- **Suspicious user agents.** `Mozilla/4.0 (compatible; MSIE 6.0)` in 2026, `Python-urllib/3.9` from a workstation that shouldn't run scripts, or unique strings. Some C2 mimics realistic UAs perfectly — UA alone is a weak signal.
- **No Referer.** A browser navigation almost always carries a Referer; a script-driven beacon usually doesn't.
- **Odd content-types.** A POST body marked `application/octet-stream` from a workstation to an unfamiliar domain is more suspicious than `application/json`.
- **Repeating URI patterns.** Long random-looking paths, embedded base64, repeated requests to identical paths.

For HTTPS, the same principles apply but you only see the encrypted shell — connection counts, byte volumes, SNI (when present), JA3, server certificate.

## Domain fronting and CDN-hidden C2

**Domain fronting** put one (innocuous) hostname in the SNI and another (malicious) hostname in the encrypted Host header, exploiting CDNs that routed by Host. Major CDNs (Google, AWS CloudFront, Azure Front Door) have largely closed it, but the descendant pattern persists: malware hosting C2 endpoints on legitimate cloud or CDN infrastructure so the traffic looks like normal cloud traffic.

What you'll see at L1: SNIs of `cloudfront.net`, `azureedge.net`, `cloudflare.com`, `cdn.discordapp.com`, `s3.amazonaws.com`. None are *automatically* bad. But:

- A host beaconing to the same Cloudflare IP every ten minutes for six hours is suspicious **regardless** of the SNI.
- A workstation that has no business hitting Discord CDN suddenly making periodic requests there is suspicious.
- Destination IP + JA3 + interval matters more than SNI alone.

Don't dismiss a beacon pattern because the SNI looks legit. **The shape is the signal.**

## JA3 against known-bad lists

Public and commercial lists ship JA3 hashes associated with specific malware. Indexing them as a SIEM enrichment turns a haystack into a small candidate set. Caveat: **JA3 collisions are real** — older Cobalt Strike default JA3 overlapped with common Java client JA3s. Always corroborate JA3 hits with destination, interval, and conn count.

## Escalation criteria

Escalate to L2 when any of the following are met (**two or more** for a strong case):

- **Beacon pattern confirmed** — high-count, low-byte, regular-interval connections from one internal host to one external destination, conn_state SF, over multiple hours.
- **Bad JA3 match** with corroborating shape (same host, regular interval).
- **DNS tunneling** — high TXT query rate, long subdomains, single source.
- **Known-bad destination IP or domain** that the host actually connected to.
- **Cleartext HTTP C2 indicators** — repeating requests, hardcoded suspicious UA, no Referer.

Write up: source host, destination(s), time window, connection count, average bytes, JA3 (if SSL), supporting query.

## Glossary

- **Beacon / jitter** — Periodic C2 check-in with randomised interval offset.
- **DGA** — Domain Generation Algorithm; algorithmically generated rendezvous candidates.
- **DNS tunneling** — Covert channel encoding payload in DNS queries/responses.
- **Domain fronting** — Mismatched SNI vs encrypted Host abusing CDN routing.
- **JA3** — TLS client handshake fingerprint hash; identifies stack despite encryption.

## Further reading

- MITRE ATT&CK T1071 Application Layer Protocol: https://attack.mitre.org/techniques/T1071/
- MITRE ATT&CK T1071.004 DNS: https://attack.mitre.org/techniques/T1071/004/
- MITRE ATT&CK T1572 Protocol Tunneling: https://attack.mitre.org/techniques/T1572/
""",
    )
    m4l3q = _add_lesson(
        session, mod4, order=6, title="Beaconing & C2 — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on the beaconing signature, DNS tunneling, CDN-hidden C2, and conn_state for a successful beacon.",
    )
    _add_q(session, m4l3q, order=1, kind=QuestionKind.SINGLE,
        stem_md="Which of these is the strongest *individual* signal of beaconing?",
        options=[
            {"value": "single", "label": "A single TCP/443 connection to an unfamiliar IP"},
            {"value": "regular", "label": "Many TCP/443 connections, regularly spaced, low byte volume, from one source to one destination over hours"},
            {"value": "burst", "label": "A burst of a thousand connections to a thousand different destinations in 60 seconds"},
            {"value": "nxdomain", "label": "An NXDOMAIN reply for a long subdomain"},
        ],
        correct="regular",
        explanation_md="Beaconing's signal is the *aggregate* shape of regular, low-byte, single-target connections sustained over time. A single connection isn't a beacon; a burst across many destinations is a scan; a single NXDOMAIN is a possible DGA hit, not a beacon.",
        points=2,
    )
    _add_q(session, m4l3q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are reasonable patterns for DNS tunneling?",
        options=[
            {"value": "txt_volume", "label": "High volume of TXT queries from one source"},
            {"value": "long_labels", "label": "Long leftmost labels of base32/base64-looking content"},
            {"value": "one_parent", "label": "Many queries to one parent domain"},
            {"value": "ms_a", "label": "A single A-record query for microsoft.com"},
        ],
        correct=["txt_volume", "long_labels", "one_parent"],
        explanation_md="A single A-record for microsoft.com is normal DNS. The other three together describe a textbook DNS tunnel.",
        points=3,
    )
    _add_q(session, m4l3q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="If a connection's SNI is `cloudfront.net`, the connection cannot be malicious because Cloudfront is a legitimate CDN.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** Malware routinely hosts C2 on legitimate CDNs. SNI alone proves nothing — interval, count, byte volume, and JA3 are what you should weight.",
        points=1,
    )
    _add_q(session, m4l3q, order=4, kind=QuestionKind.SHORTANSWER,
        stem_md="An L1 analyst suspects beaconing. The connections in question are completing cleanly — handshake, data exchange, graceful close. What `conn_state` value should they expect to see in conn.log for these beacon connections?",
        options=None,
        correct=["SF", "sf"],
        explanation_md="**SF** — normal establishment and termination. A successful beacon's TLS connection completes the handshake, exchanges its check-in payload, and closes cleanly, which Zeek records as `SF`. (`S0` would imply the C2 never replied; `RSTO` / `RSTR` would imply an abort, which is not the typical beacon pattern.)",
        points=2,
    )

    # Lesson 4.4 — recon & exfil
    m4l4 = _add_lesson(
        session, mod4, order=7,
        title="Reconnaissance, exfiltration, and ATT&CK mapping",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Distinguish a port scan from a sweep and identify each in conn.log
> 2. Recognise post-scan service-enumeration patterns (SMB, RDP, WinRM, WMI, LDAP)
> 3. Identify bulk data exfiltration to common cloud-storage destinations using flow and proxy telemetry
> 4. Compare DNS exfil vs HTTP/HTTPS exfil and pick the right detection
> 5. Recognise lateral-movement protocols (445, 5985/6, 3389, RPC, LDAP, Kerberos) on the wire
> 6. Map every wire-side observation in this module to MITRE ATT&CK techniques

## Port scans

A scan is one host probing many ports on one (or a small set of) targets. The conn.log shape depends on style:

- **TCP SYN scan ("half-open").** SYN sent, waits for response, never completes the handshake. `conn_state` typically **S0** (no reply / filtered), **REJ** (RST reply / closed), or **OTH** for unusual cases. `history` shows `S` only or `Sh` followed by reset. Noisy on the wire but doesn't produce server-side application logs.
- **Full-connect scan.** Completes the three-way handshake, then closes. `conn_state=SF` with `history=ShAfF`-ish, very short duration, no payload bytes. Hits the target's application logs (a complete handshake then immediate close looks like a TCP probe), so it's cheaper to write but more visible.
- **UDP scan.** UDP has no handshake. The scanner sends a UDP packet to a target port; an open port may stay silent, a closed port elicits ICMP "port unreachable". Zeek emits a conn.log for UDP traffic too; `conn_state` is usually **S0** or **SHR** patterns.

**Triage shortcut.** Filter conn.log for one source, time window of minutes, group by destination port. Many destination ports against few destination IPs with mostly `S0`/`REJ` = scan. Many destination IPs on one or two ports = sweep.

## Sweep vs scan

The intent differs.

- **Scan**: one source probing **many ports on one target** — *enumerate what's running here.*
- **Sweep**: one source probing **one port across many targets** — *find every host running this service.*

Common sweep targets: TCP/445 (SMB), TCP/3389 (RDP), TCP/22 (SSH), TCP/3306 (MySQL), TCP/5985/5986 (WinRM). **A sudden internal sweep for 445 from a workstation is one of the strongest indicators of lateral-movement reconnaissance**, especially after a phishing-induced compromise.

```mermaid
graph LR
    subgraph Scan
      S1[Source 10.20.30.40] --> T1[Target 192.0.2.10:21]
      S1 --> T2[Target 192.0.2.10:22]
      S1 --> T3[Target 192.0.2.10:23]
      S1 --> T4[Target 192.0.2.10:80]
      S1 --> T5[Target 192.0.2.10:443]
      S1 --> T6[Target 192.0.2.10:3389]
    end
    subgraph Sweep
      S2[Source 10.20.30.40] --> U1[10.20.30.51:445]
      S2 --> U2[10.20.30.52:445]
      S2 --> U3[10.20.30.53:445]
      S2 --> U4[10.20.30.54:445]
      S2 --> U5[10.20.30.55:445]
    end
```

## Service enumeration after a successful scan

After an open port is found, the attacker probes the service:

- **SMB (TCP/445).** Negotiates dialect and lists shares. Zeek's `smb_files.log` and `smb_mapping.log` (when enabled) record share access. A workstation that suddenly enumerates shares on dozens of file servers is anomalous.
- **RDP (TCP/3389).** A burst of short RDP attempts across many hosts is brute-force or credential spray — the most common ransomware-precursor signal.
- **WinRM (TCP/5985 cleartext, TCP/5986 TLS).** Less commonly enabled internally but heavily abused by Evil-WinRM. WinRM-over-HTTP from one workstation to many servers is suspicious.
- **SSH (TCP/22).** Inside Linux estates, brute-force shows as many `S0` / `SF`-immediate-RSTO rows.
- **WMI (DCOM, TCP/135 + ephemeral RPC).** Legitimate but heavily abused. Hard part: WMI uses dynamically allocated ephemeral RPC ports; you'll see TCP/135 establish then a high-port follow within seconds.

## Data exfiltration

Bulk exfil shapes:

- **Large outbound transfers.** Single internal host pushing tens of MB to hundreds of GB outbound in one or a few sessions. **Asymmetry matters** — `orig_bytes` (out) substantially exceeds `resp_bytes` (in) on what was meant to be a request/response service.
- **Off-hours patterns.** Heavy outbound from a workstation at 03:14 local, when the user is asleep. Some attackers schedule exfil for low-activity windows to avoid bandwidth alerts.
- **Unusual destinations.** Outbound to destinations the host has never talked to before, or destinations not used by other peers. New cloud-storage destinations are particularly interesting.
- **Compressed-and-encrypted blobs.** You can't see this directly without decryption or PCAP, but you can infer from byte ratios — uniformly random-looking patterns over TCP/443 to a fresh destination are consistent with encrypted archive uploads.

### Cloud-storage exfil destinations — L1 watchlist

- **mega.nz** — popular for ransomware exfil; large encrypted uploads.
- **anonfiles** (and successors when one shuts down) — anonymous file hosts with permissive limits.
- **Discord CDN (cdn.discordapp.com)** — frequently abused as a payload-and-exfil host.
- **GitHub gists / raw.githubusercontent** — small-volume staging for second-stage payloads and small-blob exfil.
- **transfer.sh, file.io, wetransfer.com** — generic file-share services.
- **Pastebin and clones** — text-only, but useful for credential dumps.

**Worked KQL example — outbound bytes by destination.**

```esql
FROM zeek-conn-*
| WHERE event.dataset == "zeek.conn"
   AND CIDR_MATCH(source.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
   AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS total_out = SUM(source.bytes),
        total_in = SUM(destination.bytes),
        sessions = COUNT(*)
   BY source.ip, destination.ip, destination.port
| WHERE total_out > 50000000
| SORT total_out DESC
```

Finds internal-source / external-destination pairs where cumulative outbound is over 50 MB. Cross-reference destination IPs against reverse-DNS or `tls.client.server_name`. **A workstation pushing 4 GB out to a single Mega.nz IP overnight, when the user has no Mega usage in their history, is a confirmed exfil candidate.**

## DNS exfil vs HTTP/HTTPS exfil

Both move data out, but they differ in volume and visibility.

- **DNS exfil**: low bandwidth (queries are tiny), but DNS is rarely blocked. Suited to small sensitive payloads — credentials, keys, command output. Detection: long subdomain labels, high TXT query rate, single source-to-domain.
- **HTTP/HTTPS exfil**: high bandwidth, but more often subject to outbound filtering, decryption, and DLP. Suited to bulk archives, databases, design files. Detection: large outbound bytes on TCP/443 to unfamiliar or cloud-storage destinations.

**Heuristic: DNS for stealth, HTTPS for volume.** Some campaigns use both — DNS for the C2 channel, HTTPS for the bulk pull.

```mermaid
sequenceDiagram
    participant H as Compromised host
    participant L as Local DNS resolver
    participant A as Authoritative for evil.example
    participant C as Operator
    H->>H: Read sensitive file
    H->>H: Chunk and base32 encode
    loop for each chunk
        H->>L: TXT q: chunk1.evil.example
        L->>A: recursive TXT lookup
        A->>C: log query (decode chunk1)
        A->>L: TXT response with ack/command
        L->>H: TXT response
    end
    C->>C: Reassemble decoded chunks
```

## Lateral movement on the wire

Once inside, attackers move host-to-host using protocols already in the environment:

- **SMB / TCP 445** — file-share access, named pipes, remote service creation. **Single most-abused port for Windows lateral movement.** PsExec, Impacket's `psexec.py` / `wmiexec.py`, DCSync, most ransomware spread.
- **WinRM / TCP 5985 (HTTP) / 5986 (HTTPS)** — PowerShell remoting; modern preferred lateral channel because it integrates with Windows policy and is less noisy than SMB on EDR.
- **RDP / TCP 3389** — interactive remote desktop. Brute-force entry plus hands-on movement. **Workstation-to-workstation RDP is anomalous** in most environments.
- **RPC ephemeral / TCP 49152–65535** — DCE/RPC over dynamic ports allocated via the Endpoint Mapper (TCP/135). Hard to alert on by port; alert on the workflow (TCP/135 established then a high-port connection between the same pair within seconds).
- **LDAP / TCP 389, LDAPS / 636, Global Catalog 3268/3269** — directory enumeration. SharpHound / BloodHound talk LDAP heavily; a workstation issuing thousands of LDAP queries to a DC is anomalous.
- **Kerberos / TCP & UDP 88** — ticket-granting traffic. Kerberoasting requests many service tickets — surprisingly visible if you watch ticket request volume.

**For L1: a workstation that suddenly initiates SMB or WinRM connections to many *other workstations* (not servers) is one of the loudest lateral-movement signals.** Workstation-to-workstation administrative protocol traffic is rare in normal operations.

## Mapping wire observations to MITRE ATT&CK

Memorise these — leading an L2 escalation with the technique ID is more compact than prose:

- **T1046 — Network Service Discovery.** Port scans and sweeps. SMB / RDP / WinRM enumeration after initial access.
- **T1041 — Exfiltration Over C2 Channel.** Data exfil through the same channel as C2 (HTTPS beacon carrying outbound data, DNS tunnel doing both).
- **T1048 — Exfiltration Over Alternative Protocol.** Data exfil via a different protocol than C2 — typical with ransomware operators staging on a workstation then pushing to mega.nz.
- **T1071 — Application Layer Protocol.** C2 via standard application-layer protocols (HTTP/S, DNS, SMTP). Sub-techniques: `.001` Web Protocols, `.004` DNS, etc.
- **T1572 — Protocol Tunneling.** DNS tunneling, HTTP-tunneled SSH, SOCKS-over-HTTPS.

A network-side incident write-up *"T1046 (port sweep on 445) followed by T1071.001 (HTTPS beacon to fresh CDN destination)"* tells L2 more in two phrases than a paragraph of prose.

## Glossary

- **Port scan / sweep** — One-source-many-ports vs one-source-many-IPs-one-port.
- **Service enumeration** — Probing identified open services to characterise version and capabilities.
- **Lateral movement** — Post-compromise host-to-host traversal inside a network.
- **Exfiltration** — Unauthorised data transfer out of the target environment.
- **T1041 / T1048 / T1071 / T1572** — Network-side ATT&CK techniques L1 should know on sight.

## Further reading

- MITRE ATT&CK T1046: https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK T1041: https://attack.mitre.org/techniques/T1041/
- MITRE ATT&CK T1048: https://attack.mitre.org/techniques/T1048/
- BTL1 — Network Analysis chapter
- SANS SEC503 Network Monitoring and Threat Detection In-Depth
""",
    )
    m4l4q = _add_lesson(
        session, mod4, order=8, title="Recon & exfil — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on scan vs sweep, lateral-movement protocols, ATT&CK technique selection, and cloud exfil destinations.",
    )
    _add_q(session, m4l4q, order=1, kind=QuestionKind.SINGLE,
        stem_md="A single internal host produces 250 conn.log records to 250 different internal IPs, all on TCP/445, in 90 seconds, almost all `conn_state=S0` or `REJ`. What is this?",
        options=[
            {"value": "smb", "label": "A normal SMB file-share workload"},
            {"value": "scan", "label": "A port scan (one source, many ports, one target)"},
            {"value": "sweep", "label": "A network sweep for SMB"},
            {"value": "beacon", "label": "Beaconing"},
        ],
        correct="sweep",
        explanation_md="Many destination IPs on a single port from one source is a sweep, not a scan. The 445/SMB target and the absence of successful connections are consistent with reconnaissance ahead of lateral movement.",
        points=2,
    )
    _add_q(session, m4l4q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are commonly observed lateral-movement protocols?",
        options=[
            {"value": "smb", "label": "SMB (TCP/445)"},
            {"value": "winrm", "label": "WinRM (TCP/5985 or 5986)"},
            {"value": "rdp", "label": "RDP (TCP/3389)"},
            {"value": "ntp", "label": "NTP (UDP/123)"},
        ],
        correct=["smb", "winrm", "rdp"],
        explanation_md="NTP is time synchronisation and is not used for lateral movement.",
        points=3,
    )
    _add_q(session, m4l4q, order=3, kind=QuestionKind.SINGLE,
        stem_md="Which MITRE ATT&CK technique best describes data being exfiltrated via the same HTTPS C2 channel the implant uses for command-and-control?",
        options=[
            {"value": "t1046", "label": "T1046 Network Service Discovery"},
            {"value": "t1041", "label": "T1041 Exfiltration Over C2 Channel"},
            {"value": "t1048", "label": "T1048 Exfiltration Over Alternative Protocol"},
            {"value": "t1572", "label": "T1572 Protocol Tunneling"},
        ],
        correct="t1041",
        explanation_md="**T1041** is exactly *exfil over the C2 channel*. T1048 applies if the exfil uses a different channel than C2 (e.g. C2 over HTTPS, exfil to mega.nz over a separate session).",
        points=2,
    )
    _add_q(session, m4l4q, order=4, kind=QuestionKind.MULTI,
        stem_md="Which of the following destinations should an L1 weight as common cloud-exfiltration targets when reviewing high-outbound-byte sessions?",
        options=[
            {"value": "mega", "label": "mega.nz"},
            {"value": "discord", "label": "cdn.discordapp.com"},
            {"value": "fileserver", "label": "An internal file server"},
            {"value": "transfersh", "label": "transfer.sh"},
        ],
        correct=["mega", "discord", "transfersh"],
        explanation_md="Internal file servers are normal destinations for internal hosts. The other three are well-known cloud-storage abuse destinations.",
        points=3,
    )

    print(f"  L1: {course.title} — 4 modules, 27 lessons (Module 4 Network Telemetry @ proper depth)")
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
