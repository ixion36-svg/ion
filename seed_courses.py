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

    # Lesson 1.1 — reading: the lifecycle
    l1 = _add_lesson(
        session, mod, order=1, title="What happens to an alert?",
        lesson_type=LessonType.READING, duration_min=10,
        content_md="""
## The five states an alert moves through

Every alert that hits the SOC moves through the same five states, regardless
of which SIEM, EDR, or detection platform produced it. Knowing them is the
single most useful mental model for an L1 analyst because it tells you
**what your job is right now** and **what has to be true before the alert moves on**.

```mermaid
flowchart LR
    A[1. Ingested] --> B[2. Triaged]
    B --> C[3. Investigated]
    C --> D[4. Resolved]
    D --> E[5. Closed + Tuned]
    B -.escalate.-> C
    C -.escalate.-> F[L2/L3]
    F --> D
```

### 1. Ingested

The detection platform produced the alert and it landed in your queue.
Nobody has looked at it yet. Good detections produce *fewer* alerts than
weak ones — if your queue has 800 unprocessed items, that's a tuning
problem, not a productivity problem.

### 2. Triaged

An analyst has eyeballed it and made an initial decision: is this worth
investigating, is it duplicate noise, or is it a known-benign pattern?
Triage decisions in ION are captured on the `AlertTriage` row as
`status` (open / acknowledged / closed) and a `suggested_verdict` from
Bob if the AI analyst has run.

### 3. Investigated

Someone is *actively working* on the alert: pulling logs, looking up
indicators, checking if a real human host did the thing or if a service
account did. Investigations are the time-expensive part of the job —
the goal of triage is to make sure you only investigate alerts that
*deserve* investigation.

### 4. Resolved

A verdict has been reached. ION's `CaseClosureReason` enum captures the
six allowed values:

| Value | Meaning |
|---|---|
| `true_positive` | The rule fired on real malicious / unauthorised activity |
| `false_positive` | The rule fired on benign activity — **rule needs tuning** |
| `benign_true_positive` | Rule fired correctly but the activity is authorised here (vuln scan, admin tool) |
| `duplicate` | Already covered by another open case |
| `insufficient_data` | Can't decide — escalating or sleeping on it |
| `not_applicable` | Out of scope for this SOC (different team owns it) |

### 5. Closed + Tuned

The case is shut. If the verdict was `false_positive` or
`benign_true_positive`, **a tuning action is owed** — either an exclusion
on the rule, a whitelist on the asset, or a scope refinement. Without
the tuning step the same alert reappears tomorrow and your queue grows.

### What L1 owns

You are responsible for **states 1 → 2 → 3** — moving alerts from the
ingestion queue through triage, into either an investigation or a fast
close. Anything that turns out to be complex enough that you need
malware analysis or threat-hunting workflows gets escalated to L2.

### A common mistake

New analysts skip state 2 and try to investigate every alert. That works
for two days. Then the queue overwhelms them. The discipline is: triage
the whole queue first, *then* pick the highest-severity unaddressed
alerts to investigate. You can always come back to lower-severity items
later — but you can't come back to *anything* if you spent four hours
on a false positive.
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
        lesson_type=LessonType.READING, duration_min=12,
        content_md="""
## Hunting starts with a question, not a query

A weak hunt is *"let me search for stuff that looks bad"*. A strong hunt
is *"if **this specific TTP** were happening here, **this specific
artefact** would be in **this specific data source**"*. You write the
artefact + data source down before you open the SIEM.

The PEAK methodology (SURGe / Splunk) breaks a hunt into four parts:

```mermaid
flowchart TD
    P[P · Prepare] --> E[E · Execute]
    E --> A[A · Act]
    A --> K[K · Know]
    K --> P
```

| Phase | What you do |
|---|---|
| **P · Prepare** | Frame the hypothesis. Pick the TTP, the artefact, the data source. Define what success looks like. |
| **E · Execute** | Build the query. Iterate. *Reduce noise without losing the signal you came for.* |
| **A · Act** | If you found something, open a case. If nothing, document the negative result. |
| **K · Know** | Convert the successful hunt logic into a permanent detection rule. Capture the negative results in your hunt log so you don't repeat them. |

### A worked hypothesis

> *"If an adversary used Living-off-the-Land binaries (LoLBins) to bypass
> EDR, I would see PowerShell or wmic invoking* `mshta` *or* `regsvr32`
> *with a remote URL argument, on Windows endpoints, in winlogbeat-* in
> the last 7 days."*

Notice what's specific about that:

1. **TTP** — LotL via mshta/regsvr32 (T1218.005 + T1218.010)
2. **Artefact** — `process.command_line` containing both an LoLBin name
   AND a URL pattern
3. **Data source** — `winlogbeat-*` from EDR / Sysmon
4. **Time window** — last 7 days

Without all four, you're searching, not hunting. Searching is fine —
just don't claim it counts as a hunt.

### Why specificity matters

Generic hunts (*"any suspicious PowerShell"*) produce so much noise that
you abandon the hunt or, worse, miss the real finding because it was
buried at result #4,712. A specific hypothesis has small enough output
that you can *eyeball every row*. If it doesn't, your hypothesis isn't
specific enough yet — narrow it.
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
        lesson_type=LessonType.READING, duration_min=15,
        content_md="""
## Adversary emulation is detection-validation, not pentesting

A pentest asks *"can a skilled attacker get in?"* — answer almost always
*yes*. The result is a list of findings the IT team has to remediate, but
it tells you nothing about whether your **SOC** would have caught the
attacker if they'd actually been malicious.

Adversary emulation flips the question:

> *"For each of the 50 TTPs we know real adversaries against our sector
> use, can we **detect** them, **respond** to them, and **respond fast
> enough**?"*

```mermaid
flowchart LR
    A[Pick a TTP] --> B[Atomic Red Team test]
    B --> C[Execute in a sanctioned way]
    C --> D[Check SIEM/EDR fired]
    D -->|Fired| E[Score: detection latency + fidelity]
    D -->|Missed| F[Open TuningProposal]
    F --> G[Detection-engineering writes rule]
    G --> H[Re-run emulation]
    H --> D
```

### What "catch" means at each fidelity

| Tier | What fired | Action |
|---|---|---|
| **Alerted** | A high-fidelity rule fired with the right severity | Pass — record the latency |
| **Logged but not alerted** | The activity appears in winlogbeat / EDR but no rule matched it | Detection gap — open a `TuningProposal` |
| **Logged but unparsed** | The data is there but not in a queryable field | Logging gap — fix the parser / ECS field |
| **Not logged** | The data source isn't being collected at all | Telemetry gap — talk to the platform team |

The four tiers tell different parts of your org *what to do next*. A
detection gap is a detection-eng problem; a logging gap is a SIEM-team
problem; a telemetry gap is a budget/architecture problem. Calling them
all "we missed it" misses the point.

### Scoping rules

- **One TTP per exercise.** Don't chain attacks. If you chain, you can't
  tell which detection caught which step.
- **Pre-announce the exercise window** to the SOC's L1 shift so they
  don't waste time investigating a known sanctioned test.
- **Run during business hours** for the first attempt — you want
  detection-engineering on hand if you find a gap. Out-of-hours testing
  is a separate exercise validating after-hours response.
- **Document everything.** The MITRE ATT&CK technique ID, the Atomic
  test number used, the host you ran it on, the time, and what fired
  vs what didn't.

### Don't run unsanctioned tests

Even if you're trying to prove a point. Always have a written
authorisation from the CISO + IR team scoped to the specific TTP and
window. Without it, what you're doing is *intrusion testing without
authorisation* — which is the same thing real adversaries do, and your
SIEM should pick it up. (And your legal team will pick *you* up.)
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
