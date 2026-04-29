# L3 Module 4 — Telemetry quality assessment — Research Dossier

_Authoring source-of-truth for `seed_courses.py` ship of L3 M4 in v0.12.10._

Audience: L3 detection-engineer / purple-team analyst. Prereq: L3 M1-M3 (purple-team flow + ART + Caldera) + L2 M2 (KQL/EQL/ES|QL).

## Module shape

8 lessons (7 reading + 1 quiz), 9 questions, ~16k words at BTL1/SANS depth.

## Learning objectives

1. Map ATT&CK techniques to **expected ECS fields** — the technique → telemetry contract.
2. Run a **field-coverage audit** — which fields are populated for which percentage of relevant events.
3. Operationalise **parser-health monitoring** beyond M1.6's tier-3 / tier-4 split.
4. Build a **DML (Detection-Maturity Level)** rating per technique — DML-0 to DML-9.
5. Recognise the **schema-debt backlog** as a first-class queue (alongside detection-eng + platform).
6. Audit **Sysmon coverage** against a published baseline (SwiftOnSecurity / Olaf Hartong).
7. Run a **fleet-wide gap audit** quarterly to surface drift.
8. Convert audit findings into **TuningProposals routed to the right team** (parser / agent config / new data source).

## Lesson plan

### L4.1 — The technique → telemetry contract
~2200 words. The mental model: every ATT&CK technique has one or more *fingerprints* — specific ECS fields whose presence / value is what makes the technique detectable. The L3's reflex: before running an emulation, list the expected fingerprint fields; after running, verify they were populated.

Worked: T1059.001 (PowerShell). Expected fingerprints:
- `process.name == "powershell.exe"`
- `process.parent.name` (so we can spot mshta / explorer parents)
- `process.command_line` (the encoded payload)
- `process.executable` (full path; EDR baseline)
- `event.action == "process-started"` or `winlog.event_id == "4688"` / `winlog.event_id == "1"` (Sysmon)
- `host.name`, `user.name`

If `process.command_line` is null on this estate, T1059.001 is *uncatchable*. The atomic ran; the SIEM saw a process spawn but couldn't read the payload.

Knowledge check: 1 SHORTANSWER — given a technique, name a fingerprint field.

### L4.2 — Running a field-coverage audit
~2300 words. The audit:
1. Pick a population (e.g. all winlogbeat-* events from a specific host).
2. For each fingerprint field expected on that population, compute the percentage of events where the field is non-null.
3. Pin a threshold: ≥ 95% populated = pass; 50-95% = parser concern; < 50% = parser broken or wrong source.

ES|QL skeleton:

```esql
FROM winlogbeat-* | WHERE host.name == "PT-LAB-04" AND @timestamp > NOW() - 7d
| STATS total = COUNT(*),
        with_cmdline = COUNT(WHERE process.command_line IS NOT NULL),
        with_user = COUNT(WHERE user.name IS NOT NULL)
| EVAL cmdline_pct = with_cmdline * 100 / total,
       user_pct = with_user * 100 / total
```

Per-field pass/fail report → schema-debt backlog entries.

Knowledge check: 1 SINGLE — given a 70%-populated field, classify the gap.

### L4.3 — Parser health beyond pass/fail
~2200 words. M1.6's four-tier framework is per-event. M4 expands: parser-health is *fleet-wide* and *time-series*.

Metrics:
- **`ingest.failed_documents`** — % of documents per data stream that failed parsing in the last 30d.
- **Field-population trend** — for each fingerprint field, is the populated-percentage stable, dropping, or oscillating?
- **Schema-version drift** — a parser update bumps an ECS field name; downstream rules break. Detect via field-population zero-cliff after a known parser-version bump.

The L3 maintains a **parser-health dashboard** with per-data-stream rows and per-field columns. Drift signals are obvious in the dashboard; the L3 raises tickets on observed drift.

Knowledge check: 1 MULTI — pick valid parser-health drift signals.

### L4.4 — DML (Detection-Maturity Level) rating
~2200 words. Florian Roth's Detection-Maturity Model: DML-0 (none) → DML-9 (campaign-aware). Per-technique, the L3 rates the SOC's detection maturity:
- **DML-0** — No detection.
- **DML-1** — Atomic indicator (specific hash / IP / URL).
- **DML-2** — Tool-based (catches a specific tool, not technique).
- **DML-3** — Procedure (catches a specific actor's procedure).
- **DML-4** — TTP (catches the technique class).
- **DML-5** — Goals / strategy (catches campaigns).
- **DML-6** — Strategy / TTP fusion.
- **DML-7-9** — Campaign-aware, intent-aware, predictive.

The L3 maps current rules + emulation results to a per-technique DML score. Aggregating across the org's threat profile gives a heatmap: DML-4+ techniques are well-covered; DML-0-2 techniques are blind spots.

Knowledge check: 1 SINGLE — given a rule description, identify its DML.

### L4.5 — Schema-debt backlog as a first-class queue
~2000 words. The L3's three queues:
1. **Detection-eng backlog** — Tier-2 gaps (logged but no rule).
2. **SIEM-team backlog** — Tier-3 gaps (logged but unparsed).
3. **Platform / agent backlog** — Tier-4 gaps (not logged).

But there's a fourth: the **schema-debt backlog** — fields that should exist, would be useful for detection, but aren't yet provided by the parser / agent / data source. The L3's role: surface schema-debt findings explicitly, with priority.

Schema-debt backlog entries:
- "Need entropy on `dns.question.registered_domain` pre-computed at ingest" (M7 L7.5 cross-link).
- "Need `process.command_line` populated on Estate-B Windows hosts" (Sysmon config gap).
- "Need `email.attachments.file.hash.sha256` from email gateway integration" (vendor-specific gap).

Each entry is owned (typically by the platform / data-engineering team), has a priority (mapped to the dependent rules' criticality), and has a timeline.

Knowledge check: 1 MULTI — distinguish the four backlogs.

### L4.6 — Sysmon coverage audit against a published baseline
~2200 words. Sysmon is the load-bearing telemetry source on Windows. The L3 audits the estate's Sysmon config against a published baseline.

Two canonical baselines:
- **SwiftOnSecurity** — github.com/SwiftOnSecurity/sysmon-config — high-quality, opinionated, low-false-positive.
- **Olaf Hartong sysmon-modular** — github.com/olafhartong/sysmon-modular — modular, technique-mapped, more verbose.

The audit:
1. Pull the deployed Sysmon config from a representative host (`sysmon -c`).
2. Diff against the chosen baseline.
3. Categorise differences: *intentional org-specific tune*, *pre-baseline legacy*, *missing event class*.
4. Create schema-debt backlog entries for missing event classes.

Worked: a host's Sysmon config doesn't include EventID 8 (CreateRemoteThread); the SOC's process-injection detection rules are blind. Schema-debt entry: enable EventID 8 on the standard Sysmon config; coordinate with SCCM / Intune to roll out.

Knowledge check: 1 SHORTANSWER — name two canonical Sysmon baselines.

### L4.7 — Fleet-wide quarterly gap audit
~2200 words. The L3's quarterly process:
1. **Coverage matrix** — for each technique in the threat profile, compute DML rating (M4.4).
2. **Field population audit** — for each fingerprint field, percentage populated across the fleet.
3. **Parser health** — `ingest.failed_documents` per data stream over 90d.
4. **Sysmon config drift** — diff each host's config against the org standard.
5. **EDR coverage** — % of hosts in inventory with active EDR agent.

Each output feeds the appropriate backlog. The quarterly review presents to leadership: *"telemetry coverage rose from 73% to 81%; three new Sysmon-config gaps closed; one new schema-debt item raised."*

Knowledge check: 1 SINGLE — pick the right backlog for a finding.

### L4.8 — Capstone quiz
2 questions. Closes Module 4.

## Quiz blueprint (9)

- L4.1 — 1 SHORTANSWER (fingerprint field for a technique)
- L4.2 — 1 SINGLE (70%-populated classification)
- L4.3 — 1 MULTI (parser-health drift signals)
- L4.4 — 1 SINGLE (DML rating)
- L4.5 — 1 MULTI (four backlogs)
- L4.6 — 1 SHORTANSWER (Sysmon baselines)
- L4.7 — 1 SINGLE (backlog routing)
- L4.8 — 2 capstone

## References

- Florian Roth — Detection Maturity Model. https://detect.fyi/.
- SwiftOnSecurity sysmon-config — https://github.com/SwiftOnSecurity/sysmon-config.
- Olaf Hartong sysmon-modular — https://github.com/olafhartong/sysmon-modular.
- ECS reference — https://www.elastic.co/guide/en/ecs/current/.

---

_Implementation: append `mod4 = _add_module(...)` after `mod3`'s quiz lesson, before `return course`. Update print to "4 modules, 32 lessons"._
