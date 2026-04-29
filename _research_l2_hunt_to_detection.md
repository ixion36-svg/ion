# L2 Module 8 — Hunt-to-Detection Capstone — Research Dossier

_Authoring source-of-truth for `seed_courses.py` ship of L2 M8 in v0.12.6._

Audience: L2 threat-hunting analyst. Prereq: L2 M1–M7 (PEAK + KQL/EQL/ES|QL + per-domain hunts + statistical hunts). Depth bar: BTL1 / SANS GCTH equivalent.

---

## Module shape

8 lessons (7 reading + 1 capstone-quiz), ~14 questions total. Closes Level 2.

## Learning objectives

By the end of M8 the L2 can:
1. Distinguish a **hunt finding** from a **detection candidate** and explain the five gates between them.
2. Run a **backtest** against 30 days of historical data and compute the candidate rule's predicted weekly FP rate.
3. Tag a candidate with **ATT&CK technique + sub-technique + tactic** and explain why the technique mapping is load-bearing for kill-chain rollups.
4. Pick the right **kill-chain step** (Recon / Initial Access / Execution / Persistence / Privilege Escalation / Defence Evasion / Credential Access / Discovery / Lateral Movement / Collection / C2 / Exfiltration / Impact) and the right **playbook routing**.
5. Author the production **rule body** in the right query language (KQL threshold rule, EQL sequence rule, threshold-on-aggregation rule, ML-job-attached rule).
6. Complete the **rule metadata**: severity, threat metadata, runbook, owner, lifecycle plan.
7. Submit the rule via **TIDE** and operate the post-ship tuning lifecycle (FP/FN tracking, drift detection, deprecation).

## The five conversion gates

| Gate | Question | Pass criterion |
|---|---|---|
| **G1 — Data quality** | Does the underlying telemetry support the rule reliably? | ECS schema stable, retention ≥ 90d, no broken parsers in 30d |
| **G2 — FP rate** | Will the rule fire at a sustainable rate? | ≤ 5 unique findings/week against historical 30d corpus, allowing 1–3 in steady state |
| **G3 — MITRE mapping** | Does the rule have a defensible technique tag? | Technique + sub-technique + tactic; mapped to live ATT&CK version |
| **G4 — Kill-chain step + routing** | Where does this fit in the response taxonomy? | One of 13 kill-chain phases; explicit playbook id / runbook reference |
| **G5 — Metadata completeness** | Is the rule production-ready? | Severity + threat metadata + runbook + owner + lifecycle review cadence |

A rule failing any gate cannot ship. Failure modes for each:

- **G1**: ECS field schema changed in 8.x → rule produces nothing. Retention < window → rule misses real positives. Parser broken → silent failure.
- **G2**: Predicted > 5 FP/week → analysts dismiss without reading; rule actively hurts.
- **G3**: No technique → can't roll up coverage; can't map to threat-actor profiles in TIDE.
- **G4**: No kill-chain step → no playbook routes to it; analyst sees alert with no SOP.
- **G5**: Unknown owner → rule rots; severity drift undetected; no FP feedback loop.

## Lesson-by-lesson outline

### L8.1 — From hunt finding to detection candidate; the pipeline overview
~2200 words. The conceptual frame. Vocabulary: *finding* (one-time investigation outcome), *candidate* (a reusable rule body proposed for production), *production rule* (post-gates, deployed in TIDE / Kibana Security). The five-gate diagram. The two-track conversion: behavioural-hunt → EQL/KQL rule, statistical-hunt → threshold/ML rule.

Knowledge check: 1 SINGLE — finding vs candidate vs rule vocabulary.

### L8.2 — Gate 1: Data quality and ECS schema stability
~2300 words. Covers:
- ECS field stability across 8.x; common breakages (`source.user.name` → `user.name`, `event.original` content changes per beat).
- The retention check: rule look-back must be ≤ retention window.
- Parser health monitoring: dashboard on `ingest.failed_documents` per data stream.
- Schema linting via `data_view` API + ECS reference.
- The "schema-debt" backlog: rules failing G1 land here, not in production.

Worked: an M7 candidate `dns.question.registered_domain.entropy > 3.7` fails G1 because the entropy field is a runtime field on one estate but missing on another. Decision: pre-compute at ingest or pin the rule to the estate that has it.

Knowledge check: 1 MULTI — pick valid G1 failure modes.

### L8.3 — Gate 2: FP rate measurement and backtest methodology
~2600 words. The methodology:
- Lock the candidate query body. No further tuning during backtest.
- Replay against the most recent 30-day historical corpus.
- Count unique findings (de-dup on the rule's natural key — usually `(host.name, source.ip)` or `(user.name)` per bucket).
- Estimate the **predicted weekly FP rate** = findings × (7/30).
- Sample 10 random findings; classify as TP / FP / Indeterminate.
- Project: TP rate × predicted weekly = predicted weekly true positives; same for FP.
- **Pass criterion**: ≤ 5 weekly findings AND TP rate > 30%.

Worked: M3 EQL `process.parent.name == "lsass.exe"` rare-cmdline candidate. 30d backtest → 8 findings. 7/30 = 1.87 findings/week. Sample → 6 TP, 2 FP. **Passes G2** (1.87 < 5, TP rate 75% > 30%).

Anti-pattern: tuning during backtest. Iterating threshold values until the FP count fits the target is overfitting; the rule's real-world FP rate will be higher than the backtest predicts. Lock the body; if it fails, redesign.

Knowledge check: 1 SHORTANSWER — backtest math for a candidate firing 21 times in 30d, sample 10 → 8 TP / 2 FP.

### L8.4 — Gate 3: ATT&CK mapping (technique + sub-technique + tactic)
~2200 words.
- Why mapping matters: kill-chain rollups in TIDE, threat-actor coverage matrices, MITRE Navigator export.
- Technique vs sub-technique vs tactic. The decision tree:
  1. Identify the attacker behaviour the rule fires on.
  2. Find the most-specific sub-technique that matches.
  3. If sub-technique exists, use it; else use the parent technique.
  4. Tactic is implied by the technique; reaffirm in the metadata.
- Common mis-mappings: tagging T1059 (Command and Scripting Interpreter) when the rule actually fires on T1059.001 (PowerShell). Tagging T1078 when the rule is T1078.004 (Cloud Accounts).
- The ATT&CK version pinning: tag the version in the rule metadata; bump the rule when ATT&CK releases a major.

Worked: tag the M7 capstone's six candidates. Each gets a primary technique + tactic; some get sub-techniques.

Knowledge check: 1 SINGLE — a rule that fires on 4769 with RC4-HMAC encrypted TGS for high-volume service-account requests. What's the technique?

### L8.5 — Gate 4: Kill-chain step and playbook routing
~2100 words.
- Lockheed Martin 7-step vs MITRE 13-tactic vs Unified Kill Chain. ION uses the 13-tactic frame.
- Each rule pins one **primary tactic** (the kill-chain step where the alert is most actionable).
- Each rule names a **playbook id / runbook reference** that the L1 / L2 follows when the alert fires.
- Cross-cutting case: a rule fires on Credential Access activity but the highest-leverage response is at Persistence (revoke the persistence). The L2's reflex: pick the tactic where the *response* is, not where the *activity* is.
- Worked: M6 capstone's AiTM-to-BEC-to-exfil chain — four-step EQL `sequence` rule. Primary tactic? Highest-leverage step? Pick *Initial Access* (T1078.004 cloud accounts) — that's where the response (revoke session, password reset) is most effective.

Knowledge check: 1 SINGLE — which tactic is the right primary tag for a multi-step EQL rule.

### L8.6 — Gate 5: Severity, threat metadata, runbook, owner, lifecycle
~2400 words.

The **severity matrix**:

| Severity | Criteria | Examples |
|---|---|---|
| Critical | Confirmed compromise / page IR / business impact in progress | DCSync from non-DC, ransomware-staging chain, exfil > GB |
| High | High-confidence, requires same-day response | Kerberoasting, AS-REP, OAuth illicit consent, MailItemsAccessed cluster |
| Medium | Suspicious, requires investigation | Failed-auth spike, rare command-line, single OAuth grant |
| Low | Anomalous, batch-review | Stack-count rare value alone, single beacon CV match |

The **threat metadata block** (Kibana Security `threat.framework / threat.tactic / threat.technique` array):

```yaml
threat:
  - framework: MITRE ATT&CK
    tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1558.003
    technique_name: Steal or Forge Kerberos Tickets — Kerberoasting
```

The **runbook reference** — every alert must have one. Either:
- A URL to the org's runbook for this alert class (e.g. `https://wiki/runbooks/kerberoasting`).
- A playbook id (`pb_kerberoasting_triage`) routed through the SOAR platform.
- A pointer to the L1 module covering the analyst's first-mile actions (e.g., M5 IOC handling).

The **owner** — a named team / role that owns the rule's lifecycle. When a rule produces FPs, who tunes it? When a TTP evolves, who updates it?

The **lifecycle plan** — explicit re-review cadence (typically 90d), KPIs (FP rate, FN rate, mean time to triage), deprecation criteria (TTP no longer in scope, replacement rule covers superset).

Knowledge check: 1 MULTI — pick all valid components of a complete G5 metadata block.

### L8.7 — End-to-end worked conversion: M7's capstone APT chain → 6 production rules
~2400 words. Take the M7 capstone's six candidate rules and walk one — the population-template ML job for `MailItemsAccessed` cluster — through all five gates.

- **G1** — `o365.audit.UserId`, `o365.audit.Operation` are stable since 8.0; retention is 90d in this estate; ML job's bucket span is 15m which fits inside retention. ✅
- **G2** — Backtest the ML job over 30d historical. Anomaly score > 75 produced 4 alerts. Sample → 1 TP (the M6-AiTM case from last week), 3 FP (legit DLP scan, legit eDiscovery search, vacation-handover). 1 alert/week predicted. **Passes** (< 5/week; TP rate 25% borderline — flag for tuning post-ship).
- **G3** — Technique `T1114.002 — Email Collection: Remote Email Collection`. Tactic `TA0009 — Collection`. ATT&CK version pinned at v15.0.
- **G4** — Primary kill-chain step: Collection. Playbook id: `pb_oauth_mailbox_recon`. Runbook: `https://wiki/runbooks/mailbox-recon`. Routing: L1 acks within 30 min, L2 takes within 2h.
- **G5** — Severity High. Owner `team-detection`. Lifecycle review every 90d; deprecation criteria: ML job model_memory_limit exceeded *and* no FP/TP signal change in 60d.

Final rule body (Kibana Security ML rule):

```yaml
type: machine_learning
machine_learning_job_id: o365-mailitemsaccessed-population
anomaly_threshold: 75
severity: high
risk_score: 73
threat:
  - framework: MITRE ATT&CK
    tactic:
      id: TA0009
      name: Collection
      reference: https://attack.mitre.org/tactics/TA0009/
    technique:
      - id: T1114
        name: Email Collection
        reference: https://attack.mitre.org/techniques/T1114/
        subtechnique:
          - id: T1114.002
            name: Remote Email Collection
            reference: https://attack.mitre.org/techniques/T1114/002/
runbook: https://wiki/runbooks/mailbox-recon
playbook_id: pb_oauth_mailbox_recon
owner: team-detection
lifecycle:
  review_cadence_days: 90
  deprecation_criteria: model_memory_limit_exceeded AND no_signal_change_60d
```

The same shape applies to the other five candidates; each gets its own rule type (threshold / EQL / KQL / ML-attached) but the metadata block is identical.

### L8.8 — Capstone quiz
~1400 words preamble + 4 questions covering G2 backtest math, G3 mapping, G4 tactic pick, G5 metadata.

## Quiz blueprint (8 questions total)

- L8.1 SINGLE — finding / candidate / rule vocabulary.
- L8.2 MULTI — G1 failure modes.
- L8.3 SHORTANSWER — backtest math.
- L8.4 SINGLE — Kerberoasting technique mapping.
- L8.5 SINGLE — primary tactic for a multi-step rule.
- L8.6 MULTI — components of a complete G5 metadata block.
- L8.7 (capstone, in L8.8) covered by the L8.8 questions.
- L8.8 — 4 capstone questions.

## ATT&CK pinning

Every authored example pins a specific ATT&CK version (v15.0 at time of authoring). Annotate in the rule metadata.

## Cross-references to prior modules

| Lesson | Cross-link |
|---|---|
| L8.1 | M1 (PEAK methodology) — hunt finding is PEAK output |
| L8.2 | M2 (KQL/EQL/ES|QL) — schema literacy |
| L8.3 | M7 (statistical hunts) — backtest applies to ML rules too |
| L8.4 | M3 / M4 / M5 / M6 — every domain has its technique fingerprints |
| L8.5 | M5 / M6 — kill-chain rollups across cloud + endpoint |
| L8.6 | L1 M7 (Escalation Workflow) — runbook routing |
| L8.7 | M7 capstone — six candidates from the APT campaign |

## References

- MITRE ATT&CK Enterprise — technique pages.
- Elastic Security rule reference — threshold / EQL / ML / threat-match rule types.
- SANS *FOR578 / SEC555* on detection-engineering lifecycle.
- Florian Roth — *The Detection-Maturity Model*.

---

_End of dossier. Implementation slot in `seed_courses.py`: append `mod8` after the `mod7` block, before the L2 print line. Bump print to "8 modules, 64 lessons"._
