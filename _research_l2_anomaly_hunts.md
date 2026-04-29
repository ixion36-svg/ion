# L2 Module 7 — Anomaly Hunts (statistical methods) — Research Dossier

_Authoring source-of-truth for `seed_courses.py` ship of L2 M7 in v0.12.5._

Audience: L2 threat-hunting analyst. Prereq: L2 M1–M6 (PEAK methodology + KQL/EQL/ES|QL + per-domain hunts). Depth bar: BTL1 / SANS GCTH equivalent — ~2000–3000 words/lesson, mixed quiz kinds, worked queries.

---

## Module shape

8 lessons (7 reading + 1 quiz capstone), ~14 questions total (4 inline + 4 in the quiz capstone + ~6 mixed across mid-module knowledge checks).

## Learning objectives (module level)

By the end of M7 the L2 can:
1. Choose between **behavioural** and **statistical** hunts and explain when each fits the PEAK frame.
2. Build a **stack-counting / rare-value** hunt over an arbitrary ECS field; pin the rarity threshold to the cardinality of the field.
3. Detect a **periodic beacon** by computing the coefficient of variation (CV) of inter-arrival intervals and recognise the tells of jittered C2.
4. Spot **time-series spikes** (NXDOMAIN burst, login-failure burst, Send burst) using **rolling baselines** and **z-score thresholds**.
5. Compute **Shannon entropy** on `dns.question.name` and use it to surface DGA / domain-front patterns.
6. Run **per-entity baselines** so noisy users / hosts don't dominate the FP budget.
7. Operate **Elastic ML anomaly_detector jobs** for problem classes that exceed a single-query hunt.
8. Convert a confirmed statistical finding into a **detection candidate** ready for the M8 capstone.

## When statistical vs. behavioural hunts

| Frame | Statistical | Behavioural |
|---|---|---|
| **Inputs** | Aggregate fields (counts, rates, intervals, distributions) | Discrete events arranged in a sequence / chain |
| **Tooling** | KQL aggs, ES\|QL `STATS`, Elastic ML jobs, Lens/Vega | EQL `sequence`, KQL with `event.action` clusters, ATT&CK heatmap |
| **Strengths** | Catches *novel* / *unknown-unknown* TTPs, baseline drift, beaconing | Catches known TTPs, kill-chains, rule-able patterns |
| **Failure mode** | False positives in noisy populations; needs per-entity baselining | Misses anything outside the encoded sequence |
| **PEAK fit** | **Hypothesis-driven** + **Baseline / Model-Assisted** | **Hypothesis-driven** + **Baseline** |
| **Examples covered in M7** | Rare-sender, beacon CV, NXDOMAIN burst, DGA entropy, mailbox-rule rate, OAuth scope rarity | M3 / M4 / M5 / M6 modules |

The PEAK *Model-Assisted* arm (covered briefly in M2) is where statistical hunts live.

## Lesson-by-lesson outline

### L7.1 — The statistical-hunt frame; PEAK Model-Assisted reflex
~2200 words. Covers: PEAK refresher, decision matrix above, the *aggregate-then-anomaly-detect* shape, the FP-budget concept, why per-entity baselines matter, the anti-pattern of fleet-wide thresholds.

Knowledge check: 1 SINGLE — when to pick a stat hunt over a behavioural one.

### L7.2 — Stack counting and rarity
~2400 words. Stack count = enumerate every distinct value of a field, sort by count, pick the bottom-N (rare). Worked example: `process.command_line` rare-tail hunt over a Windows estate. ES\|QL `STATS count = COUNT(*) BY process.command_line | SORT count ASC | LIMIT 100`. KQL equivalent via Lens. The cardinality-aware threshold: a 10k-cardinality field's "rare" tail is much wider than a 100-cardinality field's. Worked: rare DLLs loaded by `lsass.exe`, rare Entra `appDisplayName` consenting accounts, rare `o365.audit.UserId` running `Set-Mailbox`.

Anti-pattern: rare-value hunts on high-cardinality fields where every event is "rare" (e.g. `event.id`).

Knowledge check: 1 MULTI — pick valid stack-count hunt fields.

### L7.3 — Beacon detection via interval coefficient of variation
~2600 words. Beacons emit at near-constant intervals. Real users / apps emit bursty traffic. Hunt frame:
- For each `(source.ip, destination.ip, destination.port)` tuple over 24h, gather inter-arrival timestamps.
- Compute mean (μ) and std-dev (σ).
- CV = σ / μ. **Beacons have CV < 0.1**; jittered beacons CV < 0.3.
- Filter to tuples with ≥ 50 samples (statistical floor).

Sample ES\|QL skeleton:
```esql
FROM logs-network.firewall-* | WHERE event.outcome == "allowed"
| EVAL gap = TS_DIFF(@timestamp, PREV(@timestamp))
| STATS samples = COUNT(*), mean_gap = AVG(gap), stddev_gap = STDDEV(gap) BY source.ip, destination.ip, destination.port
| WHERE samples >= 50
| EVAL cv = stddev_gap / mean_gap
| WHERE cv < 0.30
| SORT cv ASC
```

(The native `STDDEV` and `TS_DIFF / PREV` shapes vary by Elastic version — text version-tolerant; the *concept* is what's tested.)

Tells of jittered C2: bimodal distribution, narrow CV, even-multiple jitter (e.g. exactly 30s + Gaussian noise).

Knowledge check: 1 TRUEFALSE — does CV < 0.10 always mean C2?

### L7.4 — Time-series spikes and rolling baselines
~2200 words. Pattern: a per-entity 24h or 7d rolling **baseline mean + std-dev**, alert when *now > baseline + 3σ*. Worked examples:
- **NXDOMAIN burst per source.ip** — DGA fingerprint (M5 introduced; here we baseline it).
- **Login-failure burst per user.name** — credential spray distinguished from forgotten password.
- **`o365.audit Send`-rate per UPN** — internal spear-phishing mass-send (M6 cross-link).
- **Hour-of-day filter** — most spikes happen during business hours; the OOH spike is the high-signal subset.

The implementation choices:
1. **Pre-aggregation** at index time via Elastic *transform* into a daily summary index.
2. **Roll-up index** — equivalent.
3. **Vega in Lens** — direct on raw, slow but flexible.
4. **Elastic ML anomaly_detector job** — covered in L7.7.

Tabletop: an L2 sees 20× normal `4625` Failed Logon for `svc_backup` between 02:00 and 02:15. Walk the analysis.

Knowledge check: 1 SHORTANSWER — what's the formula for a 3σ alert threshold given μ and σ?

### L7.5 — Entropy and DGA detection
~2100 words. Shannon entropy on the `dns.question.registered_domain` label. Higher entropy + longer label + uncommon TLD ≈ DGA.

Worked: ES\|QL `EVAL entropy = ENTROPY(...)` (or whichever string-entropy function the runtime exposes; if missing, fall back to a Painless / runtime-field implementation).

Combine with:
- **Length** — DGA labels usually 12–24 chars.
- **Lexical novelty** — n-gram models / dictionary intersection (CompromisedDomainCheck, EnglishDictMatch).
- **TLD novelty** — DGA campaigns often live in `.xyz`, `.top`, `.icu`.
- **Per-source uniqueness** — one host hitting *many* high-entropy names is the strongest signal.

Anti-patterns: CDN domains and AWS S3 bucket names also score high entropy; allowlist these.

Knowledge check: 1 MULTI — which fields combine to make a high-confidence DGA hunt.

### L7.6 — Per-entity baselining (rolling z-score)
~2100 words. The fleet-wide threshold trap: one noisy host emits 1000 events/h baseline, the 50-event/h target's spike is invisible. Solution: rolling z-score per entity.

For each `entity_id` (host / user / service principal):
- 7d rolling mean μ_e
- 7d rolling std-dev σ_e
- Current period count x
- z = (x − μ_e) / σ_e
- Alert when z > 3 (one-tailed)

Implementation: an Elastic *transform* keyed by `host.name` writing summary docs hourly, then a `terms` agg over the last 24h flagging high-z entities.

Worked: `4769` (Kerberos TGS request) per service account — Kerberoasting (M4 cross-link) but now baselined per service account so a noisy SQL-server account doesn't drown a quiet AD-admin account's anomaly.

Knowledge check: 1 SINGLE — given μ_e=10, σ_e=2, x=22, what's z and does it cross threshold?

### L7.7 — Elastic ML anomaly_detector jobs
~2400 words. When a query-driven hunt isn't enough: Elastic ML's job templates. Covered:
- **Single-metric** — `count by host.name` over 1h buckets.
- **Multi-metric** — multiple analyses on the same partition.
- **Population** — find the entity that's *unlike its peers* (the canonical insider-threat job).
- **Rare** — values that have not appeared recently in the partition.
- **Categorisation** — clusters log messages and finds new categories.

Each job has: bucket span, detector function (`count`, `mean`, `rare`, `freq_rare`, `info_content`), influencer fields.

Worked: a **population job** on `o365.audit.Operation == "Send"`, partitioned by `o365.audit.UserId`, surfacing the user who sends *unlike their peers* — high-volume mass-send post-AiTM (M6 cross-link).

Anti-pattern: leaving the bucket span at the default 15m for a 7-day-baseline problem; ML jobs are sensitive to bucket sizing.

Knowledge check: 1 SHORTANSWER — pick the right job template for a given problem.

### L7.8 — Capstone + quiz
~1800 words. Worked end-to-end: an APT campaign that's invisible to behavioural rules but lights up across statistical hunts. The chain:
- **Hour 0**: a single new SP gets `appDisplayName` "Marketing-AnalyticsBot" — *rare-value hunt* on `appDisplayName` (L7.2).
- **Hour 1**: that SP issues `MailItemsAccessed` against 30 mailboxes — *per-entity baseline* on Mail.Read access count (L7.6).
- **Hour 6**: outbound 443 from the orchestrator host to a new domain at exactly-30s intervals — *beacon CV* (L7.3).
- **Hour 6**: that domain's label scores Shannon entropy 4.8 over 18 chars — *DGA entropy* (L7.5).
- **Hour 12**: NXDOMAIN burst from the same host as the C2 fails over — *time-series spike* (L7.4).

Hand-off to M8: each of those statistical hunts becomes a candidate detection rule. M8 walks the conversion.

Quiz capstone (4 mixed) at the end.

## Quiz blueprint (14 questions total)

- **L7.1** SINGLE — when to choose statistical over behavioural.
- **L7.2** MULTI — valid stack-count hunt fields.
- **L7.3** TRUEFALSE — CV < 0.10 always means C2 (false; CDN, NTP, scheduled tasks).
- **L7.4** SHORTANSWER — formula for 3σ threshold (μ + 3σ).
- **L7.5** MULTI — DGA hunt field combination.
- **L7.6** SINGLE — z-score arithmetic.
- **L7.7** SHORTANSWER — pick the right ML job template.
- **L7.8 capstone (4)** — chain ordering + threshold pinning + per-entity vs fleet + ML job pick.

(That's 11; pad to 14 with a 2nd-knowledge-check on L7.2 and L7.4 and L7.5 if budget allows.)

## ATT&CK mappings touched

| Lesson | Technique | Source module cross-link |
|---|---|---|
| L7.2 | T1098.001 (rare SP secret), T1098.003 (rare role grant), T1027 | M6 |
| L7.3 | T1071.001 (C2 over web), T1071.004 (DNS), T1571 (non-standard port) | M5 |
| L7.4 | T1110.003 (spray), T1556.006 (federation tamper) | M3, M6 |
| L7.5 | T1568.002 (DGA), T1090.003 (anonymisers) | M5 |
| L7.6 | T1558.003 (Kerberoasting baselined) | M4 |
| L7.7 | T1530 (cloud population insider), T1078 | M6 |
| L7.8 | T1098.001 → T1114.002 → T1071.001 (chained) | M5+M6 |

## ECS field surface used

- `process.command_line`, `process.parent.executable` (L7.2)
- `source.ip`, `destination.ip`, `destination.port`, `@timestamp`, `network.bytes` (L7.3)
- `dns.question.name`, `dns.response_code`, `dns.question.registered_domain` (L7.4, L7.5)
- `event.code`, `winlog.event_id`, `user.name` (L7.4, L7.6)
- `o365.audit.UserId`, `o365.audit.Operation`, `o365.audit.Workload`, `azure.signinlogs.properties.app_display_name` (L7.2, L7.7)
- `host.name`, `agent.name` (L7.6)

## References

- SANS *Cyber Threat Hunting* (FOR578 / SEC555) — statistical hunting frame.
- Elastic ML docs — anomaly_detector job types and bucket-span guidance.
- Eric Conrad *FreqServer / DomainStats* — DGA entropy reference implementation.
- *Hunting C2 with statistics* — Active Countermeasures / RITA.
- ATT&CK technique pages for each cross-linked TTP.

---

_End of dossier. Next: implement in `seed_courses.py` as `mod7` after M6, ~13230._
