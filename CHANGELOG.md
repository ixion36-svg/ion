# Changelog

## v0.11.14 (2026-04-28)

### L2 Module 3 — Process & file events: Execution + Defense Evasion

Third L2 ship. **L2 Module 3 — Process & file events — Execution + Defense Evasion** authored from a research-agent dossier at BTL1+/SANS depth. ~9,000 words, 8 lessons (4 reading + 4 quiz), 16 quiz questions. First *concrete-hunt* module in L2 — applies the PEAK methodology of Module 1 and the KQL/EQL/ES|QL fluency of Module 2 to the **Execution (TA0002)** and **Defense Evasion (TA0005)** ATT&CK tactic families against Elastic indices.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 3.1 | The process-event data plane in Elastic and the ECS field reference for hunters | reading | — |
| 3.2 | Data plane & ECS — quiz | quiz | 4 |
| 3.3 | Execution (TA0002) — top techniques and their EQL+ES&#x7C;QL fingerprints | reading | — |
| 3.4 | Execution — quiz | quiz | 4 |
| 3.5 | Defense Evasion (TA0005) — top techniques and their fingerprints | reading | — |
| 3.6 | Defense Evasion — quiz | quiz | 4 |
| 3.7 | Statistical hunts in ES&#x7C;QL, cross-source pivots, and a worked end-to-end capstone | reading | — |
| 3.8 | Statistical hunts & capstone — quiz | quiz | 4 |

#### Topics covered

- **Process-event data plane** — three sources: Elastic Agent endpoint integration (`logs-endpoint.events.process-*`, `.file-*`, `.library-*`, `.registry-*`); Winlogbeat + Sysmon (`winlogbeat-*` with EID 1/2/3/7/8/10/11/13/22/25 mapped via `event.code`); native Windows Security log (4624/4688/4698/4720/7045/1102/104). The **EID 4688 command-line gap** (requires *Audit Process Creation* GPO + *Include command line* sub-policy). ECS field reference table for process / file / library / registry hunts. **`process.entity_id` as the host-stable join key** for chain reconstruction. Cross-source schema differences in a comparison table. Multi-index `FROM logs-endpoint.events.process-*, winlogbeat-*` pattern in ES&#x7C;QL with the `event.action` / `event.code` disjunction. Worked broad-to-narrow KQL → EQL → ES&#x7C;QL on the encoded-PowerShell-from-Office-parent hunt
- **Execution TA0002** — T1059 Command and Scripting Interpreter (.001 PowerShell, .003 cmd, .005 VBS, .007 JS) with the **suspicious-PowerShell vocabulary memo** (`-EncodedCommand` / `-enc` / `-ep bypass` / `-w hidden` / `IEX` / `DownloadString` / `FromBase64String` / `Invoke-Mimikatz` / `[Reflection.Assembly]::Load` / `AmsiUtils` / `amsiInitFailed`); **PowerShell EID 4104** script-block logging; T1204 User Execution click-paths (Office → script-host, browser → script-host) as EQL `sequence` queries with `maxspan`; **T1218 LOLBAS** family with the catalogue overlay (`mshta.exe`, `regsvr32.exe`/Squiblydoo, `rundll32.exe javascript:`, `msiexec.exe`, `cmstp.exe`, `hh.exe`, `installutil.exe`, `regasm.exe`, `wmic.exe`) in a single covering EQL hunt; T1053.005 Scheduled Task with EID 4698/4702/4700 and `schtasks /create`; T1569.002 PsExec-class with EID 7045 service-install paired with SCM-spawned payload from user-writable path. **When to author EQL `sequence` rules vs ES&#x7C;QL aggregations** — chain vs threshold/pivot
- **Defense Evasion TA0005** — T1027.010 command obfuscation with special-character density proxy in ES&#x7C;QL `EVAL`; T1027.002 packing via `process.code_signature.status`; T1070 Indicator Removal — .001 EID 1102/104 + `wevtutil cl Security` (page-IR signal), .003 PSReadLine `ConsoleHost_history.txt` deletion, .004 file-deletion EQL chains, **.006 Timestomp via `file.mtime < file.created`**; T1562 Impair Defenses cluster — .001 (`sc stop Sense` / `Set-MpPreference -DisableRealtimeMonitoring` / `taskkill MsMpEng.exe`), .002 (`Auditpol disable` / `EventLog stop`), .004 (`netsh advfirewall set allprofiles state off`), .009 (`bcdedit safeboot`); the **ransomware pre-encryption `sample by host.name` cluster** (T1562.001 + T1490 `vssadmin delete shadows` + `bcdedit recoveryenabled No`); T1036 Masquerading — .005 `svchost`/`lsass` running outside `System32`/`SysWOW64`, .001 invalid signature with claimed-Microsoft subject_name; T1112 Modify Registry — LSA Protection / AMSI providers / WDigest UseLogonCredential / Defender policy; T1140 deobfuscate, T1497 sandbox evasion (recognise)
- **Statistical hunts + cross-source pivots + capstone** — five canonical statistical patterns: rare-process by SHA256 (`COUNT_DISTINCT(host.name)` ≤ N + unsigned), rare parent-child pair, command-line entropy proxy via `LENGTH` − `LENGTH(REPLACE(...))`, signed-vs-unsigned ratio per host with `BUCKET(@timestamp, 1d)`, time-of-day anomalies via `DATE_EXTRACT("HOUR_OF_DAY", @timestamp)`. Cross-source pivots Elastic Agent ↔ Sysmon with `event.action`/`event.code` disjunction. **Worked PEAK capstone** — full hunt for *encoded PowerShell from Office parent*: hypothesis (4-element + SMART), Q1 broad KQL, Q2 narrowed KQL with parent filter, Q3 EQL `sequence` for click-context, Q4 ES&#x7C;QL aggregation for triage with `STATS BY BUCKET(1h)`, then the **Kibana Security EQL detection-rule body** ready for TIDE submission with severity / runbook / whitelist metadata. Full hunt-cycle close from red → orange → yellow → green Navigator coverage

8 Mermaid diagrams across the module: data-plane taxonomy (3 sources), verb-field crosswalk, T1218 LOLBAS catalogue overlay, T1204 click-path sequence, Defense-Evasion family tree, TA0005 triage flowchart, statistical-hunt decision tree, cross-source pivot flow.

L2 course now sits at **3 modules / 24 lessons / 48 questions**.

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.13 (2026-04-28)

### L2 Module 2 — KQL, EQL, and ES|QL: the Elastic-stack query languages

Second L2 ship. **L2 Module 2 — KQL, EQL, and ES|QL** authored from a research-agent dossier at BTL1+/SANS depth. ~10,000 words, 8 lessons (4 reading + 4 quiz), 16 quiz questions. Aligned to ION's actual stack — Elastic + Kibana — with all worked queries against Beats / Elastic-Agent indices using ECS field paths.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 2.1 | The Elastic query-language landscape: Lucene, KQL, EQL, ES&#x7C;QL | reading | — |
| 2.2 | Language landscape — quiz | quiz | 4 |
| 2.3 | KQL fundamentals — and Lucene as the legacy fallback | reading | — |
| 2.4 | KQL & Lucene — quiz | quiz | 4 |
| 2.5 | EQL — sequence queries and behavioural chains | reading | — |
| 2.6 | EQL — quiz | quiz | 4 |
| 2.7 | ES&#x7C;QL — the piped DSL for stats, joins, and time-series | reading | — |
| 2.8 | ES&#x7C;QL — quiz | quiz | 4 |

#### Topics covered

- **The query-language landscape** — Lucene query syntax (the original; regex / fuzzy / proximity), **KQL** (Kibana 6.3+; search-bar; filter-only), **EQL** (7.9 GA mid-2020; `sequence by host with maxspan`; security event correlation), **ES|QL** (8.13 GA March 2024; piped DSL; `STATS BY BUCKET()`; cross-index; ENRICH / LOOKUP JOIN). Painless as the *non*-query language. Decision framework for which to reach for given the question shape; per-language Kibana surface (Discover bar, Lucene toggle, Timelines, ES|QL mode, detection-rule body); version timeline (Lucene since v0; KQL 6.3 / 2018; EQL 7.9 / 2020; ES|QL 8.13 / 2024; LOOKUP JOIN 8.16 / late-2024). Crucial disambiguation: *Microsoft KQL* (Kusto) vs *Elastic KQL* (Kibana) — same acronym, completely different languages
- **KQL + Lucene** — field equality, ranges (bracket and comparator), Boolean operators with grouping, wildcards (with the leading-wildcard performance trap), exists/missing via `field: *`, **the keyword vs text mapping case-sensitivity trap** (the same predicate behaves differently on `process.command_line` keyword vs `process.command_line.text` analyzer-tokenised), **the `nested:{...}` same-element trap** (multiple predicates on `nested`-mapped arrays without explicit scope produce silent over-counts), free-text fallback with caveats. KQL's filter-only nature with explicit *when to switch* — switch to ES|QL for stats/joins, EQL for chains, Lucene for regex/fuzzy/proximity. Lucene cheat sheet (anchored regex, fuzzy edit-distance, phrase proximity, term boost, legacy `_exists_` / `_missing_`). Worked three-iteration KQL hunt (PowerShell encoded command from Office parent, narrowed to known-good account exclusions)
- **EQL** — design centre is security event correlation; ECS `event.category` as the first-class predicate target (`process where ...`, `network where ...`, `file where ...`, `authentication where ...`, etc.); `==` keyword-exact case-sensitive vs `:` case-insensitive *like*-with-wildcards (the most common EQL fluency error); `sequence by host.name with maxspan=5m` as the behavioural-chain primitive with multi-key `by` and `until` for early termination; `sample` for unordered correlation (T1490 ransomware staging across `vssadmin` / `wbadmin` / `bcdedit` in any order); EQL's pipe operators (`head` / `tail` / `unique` / `sort` / `count by` / `filter`) for *post*-processing — and recognition that EQL pipes are limited compared to ES|QL. Functions reference (`endsWith`, `startsWith`, `wildcard`, `cidrMatch`, `between`, `length`, arithmetic). Worked phishing-click → script-host chain via `sequence by host.name with maxspan=10m`; worked CIDR-membership predicate via `cidrMatch`
- **ES|QL** — pipeline shape `FROM | WHERE | EVAL | STATS BY | SORT | LIMIT | KEEP | DROP` with each `|` passing a tabular result-set forward (Kusto-like / Splunk-like); `FROM` with multi-index (`logs-*, winlogbeat-*`) and cross-cluster (`cluster1:logs-*, cluster2:logs-*`); `WHERE` with `==`, `IN`, `IS NULL`, `LIKE` (SQL-style `%` / `_` — *not* `*` / `?` — the most common ES|QL fluency error), `RLIKE` for regex, embedded **`KQL("...")`** for "filter half in KQL, aggregation half in ES|QL"; `EVAL` for computed columns including `DATE_TRUNC` / `DATE_EXTRACT` / `CASE`; `STATS` aggregations (`COUNT` / `COUNT_DISTINCT` / `SUM` / `AVG` / `MEDIAN` / `PERCENTILE` / `VALUES` / `TOP`) with the **column-drop trap** (everything not in `BY` and not aggregated is dropped); **`BUCKET(@timestamp, 1h)`** as the workhorse time-series form; `DISSECT` and `GROK` for runtime parsing of unstructured strings (`message`, raw command lines); **`ENRICH`** for joins to a small reference index via an enrich policy; **`LOOKUP JOIN`** (8.16+) for explicit left-outer joins to a lookup index; default 10,000-row cap with explicit `LIMIT` for large `STATS` results. Worked beaconing-anomaly hunt with TCP / 443 + 80 outbound to non-RFC1918, COUNT/COUNT_DISTINCT/SUM per (host × IP × hour), filtered to single-destination-IP buckets with > 50 connections

8 Mermaid diagrams across the module: query-language decision tree, where-each-language-runs map, EQL-vs-ES|QL-vs-KQL-vs-Lucene capabilities matrix, EQL sequence visualisation, ES|QL pipeline horizontal flow, cross-language pivot pipeline, ES|QL detection-rule hand-off, the *KQL embedded in ES|QL* pattern.

L2 course now sits at **2 modules / 16 lessons / 32 questions**.

#### Note on prior modules

L1 Module 8 (Common ATT&CK Techniques) and L2 Module 1 (PEAK methodology) shipped with KQL examples that referenced *Microsoft Kusto* / Defender Advanced Hunting tables (`DeviceProcessEvents`, etc.) — pre-dating the explicit clarification that ION runs on Elastic + Kibana. From v0.11.13 onward, all L2 modules use Elastic query languages and ECS field paths consistently. The L1 examples remain as written (still pedagogically sound for technique recognition); future L2 modules (3–8) will be Elastic-native end to end.

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.12 (2026-04-28) — L2 begins

### L2 Module 1 — The Hunt Hypothesis (PEAK methodology) — first L2 ship at BTL1+/SANS depth

L2 *Threat Hunting with KQL* leaves the v0.11.2 stub state. **L2 Module 1 — The Hunt Hypothesis (PEAK methodology)** authored from a research-agent dossier at the BTL1+/SANS GCIH+/FOR578-equivalent depth bar. ~10,000 words, 8 lessons (4 reading + 4 quiz), 16 quiz questions. The previous v0.11.2 stub (1 module / 2 lessons covering PEAK at framework-demo depth) is *replaced* — same module slot, eight times the depth.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 1.1 | Why hunt? The strategic frame | reading | — |
| 1.2 | Why hunt? — quiz | quiz | 4 |
| 1.3 | The PEAK loop end-to-end (Prepare → Execute → Act → Know) | reading | — |
| 1.4 | PEAK loop — quiz | quiz | 4 |
| 1.5 | The hypothesis: four-element + SMART, hypothesis types, criticism | reading | — |
| 1.6 | The hypothesis — quiz | quiz | 4 |
| 1.7 | Documenting and learning: hunt reports, the negative-result discipline, ION surfaces, and a worked T1218.011 hunt | reading | — |
| 1.8 | Documenting & ION — quiz | quiz | 4 |

#### Topics covered

- **Why hunt? Strategic frame** — detection-only SOCs are structurally blind; *detection rule = hypothesis frozen in code*; hunt fills the gap. The dwell-time problem with current-year medians — 5–10 day medians for ransomware, sub-24h for fast-flux, much longer for quiet identity-tier intrusions; the long-tail matters more than the median; *hunting is asymmetrically valuable on cases the rules missed*. CTID **threat-informed defence** doctrine — Top Techniques calculator + Adversary Emulation Library. **Pyramid of Pain reframed for hunters** — for triage, hunt the bottom; for hunting, prioritise the top three layers (TTPs / tools / artefacts) because re-engineering tradecraft is the most expensive thing you can make an adversary do. Five-axis distinction between **hunt vs IR vs DE** (trigger / stance / disposition / timebox / output) — *the hunt produces the idea; detection engineering produces the rule*. Bianco's **Hunting Maturity Model HM0 → HM4** — most SOCs sit at HM1–HM2, L2 hunters individually unblock HM3. Why L2 hunting is the career-defining skill — builds the mental model for IR, DE, threat-intel, and red-team work; epistemic shift from response to interrogation
- **The PEAK loop** — Splunk SURGe (2023) successor to the Sqrrl Hunting Loop and TaHiTI; Prepare ~20–30% (topic pick / hypothesis / data-source confirmation / success criteria / window / intent) → Execute ~40–50% (broad-to-narrow KQL with audit trail) → Act ~15–20% (TP / BTP / FP / Inconclusive / no-findings disposition) → Know ~10–15% (retro / Navigator update / next-hunt seed). Iteration *within* phases is legitimate as long as time-budget drift is tracked. **Sprint hunts** as PEAK at 90-minute scale for fresh-CTI response. Predecessor lineage — HEAT → Sqrrl Hunting Loop → TaHiTI → Sqrrl Reference Model → PEAK; NIST SP 800-150 feeds Prepare. Where PEAK improves: cleaner phase split, hypothesis as first-class artefact, *Know* phase makes negatives valuable, TIDE/Sigma compatible
- **The hypothesis** — the **four-element template** (TTP + artefact + data source + window) and the **SMART criteria** (Specific, Measurable, Adversary-relevant, Realistic, Time-bounded). Worked good vs weak hypotheses with rewrite flow. Five **hypothesis types** — TTP-based / anomaly-based / situational-awareness / threat-actor-based / custom-detector-based — with worked seed examples. The four-question **criticism step** before Execute (data-source resolution / FP base-rate / variants that escape / null hypothesis). Three failure modes — *hypothesis-as-keyword*, *hypothesis-as-tool-list*, *hypothesis-as-fishing-trip*
- **Documenting and learning** — the **hunt-report template** (Hunt ID / Hypothesis verbatim / Type / ATT&CK mapping / Data sources / Window / Queries Q1–Qn / Findings TP/BTP/FP/Inconclusive / Verdict / Confidence-on-negative / Action items / Time by phase). The **negative-result discipline** with the three-component confidence-on-absence statement (quantify the negative + quantify data confidence + state residual uncertainty); the **false-confidence trap** with bounded-claim discipline. **Worked PEAK hunt for T1218.011 Rundll32 javascript** end-to-end — Prepare 1.5h, Execute 3.0h with the five-query progression (broad → parent filter → account filter → process-tree enrichment → network correlation), Act 1.0h with 0 TPs / 7 BTPs / 4 FPs / 1 Inconclusive, Know 0.8h with confidence-medium-high and a follow-up T1218.010 hunt seeded. The **five-gate detection-rule hand-off** (FP-rate measurement → whitelist → metadata → TIDE submission → lifecycle). **ATT&CK Navigator coverage states** (red → orange → yellow → green) and the rolling 90-day re-hunt cadence on orange cells. **ION-specific surfaces** — hunt-tagged cases routing to IR with the hunt report attached, AlertPromptTemplate matcher tier 2 (regex) and tier 3 (technique) authoring by L2 hunters, Bob's hunt-derived reasoning citing hunt-report IDs, the **hunt repository** indexed semantically by pgvector, and Bob's *triage-augmentation* role on Execute results. The **data-gap log** as the SOC's strongest argument for telemetry budget

7 Mermaid diagrams across the module: PEAK loop with time-budgets, predecessor-models lineage, HMM HM0–HM4 vertical pyramid, four-element hypothesis quadrant, weak-to-strong hypothesis rewrite flow, hunt-vs-IR-vs-DE comparison, T1218.011 PEAK timeline, hunt-to-detection five-gate pipeline.

L2 course now sits at **1 module / 8 lessons / 16 questions**.

#### L2 roadmap

The L2 *Threat Hunting with KQL* curriculum will be eight modules:

| M | Title | Status |
|---|---|---|
| 1 | The Hunt Hypothesis (PEAK methodology) | **v0.11.12** |
| 2 | KQL fundamentals — tabular operators | pending |
| 3 | Process & file events — execution & defense evasion | pending |
| 4 | Identity & sign-in — credential access & lateral | pending |
| 5 | Network telemetry — command & control, exfiltration | pending |
| 6 | Email & collaboration — initial access | pending |
| 7 | Anomaly hunts — statistical methods | pending |
| 8 | Hunt to detection capstone — TIDE / DE conversion | pending |

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.11 (2026-04-28) — L1 COMPLETE

### L1 Module 8 — Common ATT&CK Techniques (the L1 finale)

Seventh and final L1 curriculum ship at the v0.11.3 depth bar. **L1 Module 8 — Common ATT&CK Techniques** authored from a research-agent dossier. ~10,000 words, 8 lessons (4 reading + 4 quiz), 15 quiz questions. **L1 *Alert Triage Fundamentals* is now structurally complete.**

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 8.1 | The ATT&CK framework, reading a technique page, and mapping alerts on the fly | reading | — |
| 8.2 | Framework & technique pages — quiz | quiz | 3 |
| 8.3 | Top techniques: Initial Access, Execution, and Persistence | reading | — |
| 8.4 | IA + Execution + Persistence — quiz | quiz | 4 |
| 8.5 | Privilege Escalation, Defense Evasion, Credential Access, and Discovery | reading | — |
| 8.6 | PrivEsc, Evasion, Cred, Discovery — quiz | quiz | 4 |
| 8.7 | Lateral Movement, Collection / Exfil / Impact, C2, ransomware + cloud chains, worked scenarios, ION conventions | reading | — |
| 8.8 | Lateral, Impact, C2 & ION — quiz | quiz | 4 |

#### Topics covered

- **Framework & technique-page reading** — the four-tier hierarchy (Tactic / Technique / Sub-technique / Procedure), 14 enterprise tactics with TA-numbers, Enterprise / Windows / macOS / Linux / Cloud / Network / Containers / ESXi matrices, ATT&CK Navigator (coverage / threat-actor / detection-coverage layers), versioning inflection points (v6 → v7 sub-tech overhaul → v9-10 cloud reshuffle → v15 ESXi → v16 cloud cleanup), the **30-second / 3-minute / 30-minute** reading cadences, the *zero-second-read* anti-pattern, mapping ATT&CK Data Components to Sysmon / Windows Event Log / Defender Advanced Hunting / ECS, the alert-title → technique-ID mapping table (12 worked translations)
- **Initial Access + Execution + Persistence** — T1566 (Module 6 callback), **T1190** with KEV-cross-reference and Log4Shell / MOVEit / Citrix Bleed / Ivanti canonical examples, T1078 valid-account sub-techniques, T1133 external remote services, T1195 / T1199 / T1189 (recognise but rarely L1-triaged); **T1059** workhorse with the suspicious-PowerShell vocabulary memo (`-enc`, `-w hidden`, `IEX`, `DownloadString`, `FromBase64String`, AMSI bypass strings), T1204 user execution, **T1218** LOLBAS sub-techniques (Mshta, Regsvr32 Squiblydoo, Rundll32, CMSTP, Msiexec) plus the LOLBAS / GTFOBins references, T1053 scheduled tasks (EID 4698/4700/4702), T1569.002 PsExec (EID 7045), T1106 native-API, T1559 IPC; **T1547.001** registry Run keys (Sysmon EID 13), T1543.003 service persistence (EID 7045), T1136 account creation, T1098 account manipulation (`.005` device registration / `.003` cloud roles / `.001` cloud credentials), T1574 DLL hijack/sideload, T1505.003 web shell, T1546.003 WMI subscription
- **PrivEsc + Defense Evasion + Cred Access + Discovery** — T1068 BYOVD, T1134 token manipulation, T1055 process injection (EID 8 + EID 10), T1548.002 UAC bypass; T1027 obfuscation (`.002` packing / `.006` HTML smuggling / `.010` command obfuscation), T1070 indicator removal (EID 1102), T1562 impair defenses (Set-MpPreference, sc stop Sense, Auditpol disable), T1036 masquerading; **T1003 OS credential dumping** (`.001` LSASS with the `0x1010` / `0x1F0FFF` granted-access fingerprint, `.002` SAM, `.003` NTDS, **`.006` DCSync** with the EID 4662 + replication-GUID signal), T1110 brute force / spray / stuffing, T1555.003 browser passwords, T1539 cookie theft, T1187 forced authentication, **T1558 Kerberos** (`.003` Kerberoasting with EID 4769 RC4 downgrade, `.004` AS-REP Roasting with EID 4768 preauth-not-required, `.001` Golden Ticket, `.002` Silver Ticket), T1621 MFA fatigue; the **discovery cluster** — *the cluster is the signal* — full T1087 / T1018 / T1083 / T1057 / T1016 / T1033 / T1069 / T1482 / T1518 mapping
- **Lateral + Collection / Exfil / Impact + C2 + chains + scenarios** — T1021 remote services (`.001` RDP LT10, `.002` SMB LT3, `.006` WinRM with `WinRM` logon-process), T1570 lateral tool transfer (`bitsadmin`, `certutil -urlcache`), T1550 alternate-auth (PtH, PtT), T1210 EternalBlue / ProxyShell / ZeroLogon; T1005 / T1114 / T1213 / T1560.001; T1041 / T1567.002 cloud-storage exfil / T1048; **T1486 / T1490 / T1485 / T1489** ransomware Impact cluster — *T1490 is page-everyone*; T1071 / T1573.002 / T1090 / T1568.002 DGA / **T1102** SaaS dead-drops / T1572 tunnels / T1219 RMM abuse, plus the **beacon-shape** pattern from Module 4; the **modal ransomware-affiliate intrusion chain** in ATT&CK shorthand with **dwell-time compression to 5–10 day medians** (under 24h for fast-flux operators); the **modal cloud-takeover chain** (T1566.002 → T1539 → T1078.004 → T1098.005 → T1098.001/.003 → T1114.003 + T1213 → T1567.002); **ION-specific** — matcher tier 3 (technique) + tier 4 (tactic) drive Bob's prompt selection, case taxonomy carries technique IDs through escalation packets (Module 7), Bob's verdict cites technique IDs, pgvector case-similarity uses technique tags as a deterministic axis; **three end-to-end worked scenarios** — *(A) discovery-cluster fingerprint* on a workstation, *(B) LSASS read → DCSync chain* with isolation + IR page, *(C) ransomware staging* (T1490 → T1489 → T1486) with 2–10 minute time pressure; the **eight common L1 ATT&CK-mapping mistakes** to avoid (parent-instead-of-sub-tech, group-name-pinning from procedures, single-discovery-as-high, cluster-as-info, T1490 as monitor, T1055 as escalation, on-prem T1078 for cloud, Detection-section as must-match)

10+ Mermaid diagrams across the module: ATT&CK matrix-style horizontal flow with most-common L1 techniques, ransomware-affiliate chain, cloud-takeover chain, alert-title → technique decision tree, discovery-cluster Gantt timeline, LSASS → DCSync flow, ransomware staging timeline.

L1 course now sits at **8 modules / 59 lessons / 127 questions — STRUCTURALLY COMPLETE**.

#### L1 milestone

The full L1 *Alert Triage Fundamentals* curriculum (v0.11.3 onwards) covers the day-shift triage analyst from first principles to capstone:

| M | Title | Lessons | Questions | Shipped |
|---|---|---|---|---|
| 1 | The alert lifecycle | 3 | 8 | v0.11.3 |
| 2 | SIEM Fundamentals | 8 | 23 | v0.11.5 |
| 3 | Windows Event Logs | 8 | 23 | v0.11.6 |
| 4 | Network Telemetry | 8 | 14 | v0.11.7 |
| 5 | IOC Handling | 8 | 14 | v0.11.8 |
| 6 | Phishing Triage | 8 | 15 | v0.11.9 |
| 7 | Escalation Workflow | 8 | 15 | v0.11.10 |
| 8 | Common ATT&CK Techniques (finale) | 8 | 15 | **v0.11.11** |
| **L1 total** | | **59** | **127** | |

**Backlog from here:** L2 *Threat Hunting with KQL* full curriculum (8 modules, currently a 1-module / 2-lesson v0.11.2 stub) — kicks off in the next ship. After L2: L3 *Adversary Emulation Basics* (currently a stub). After all three: labs ship, PDF certificate generation, Elastic Agent Skills consumer integration as Bob's 6th matcher tier.

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.10 (2026-04-28)

### L1 Module 7 — Escalation Workflow

Sixth curriculum ship at the v0.11.3 depth bar. **L1 Module 7 — Escalation Workflow** authored from a research-agent dossier. ~10,000 words, 8 lessons (4 reading + 4 quiz), 15 quiz questions. Lives on the existing `demo-l1-alert-triage-fundamentals` course as Module 7.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 7.1 | The escalation decision: cost calculus, criteria, and timeboxing | reading | — |
| 7.2 | Decision & timeboxing — quiz | quiz | 3 |
| 7.3 | Severity, priority, blast radius, and the escalation paths | reading | — |
| 7.4 | Severity, priority, paths — quiz | quiz | 4 |
| 7.5 | The handover packet, chain of custody, and communication discipline | reading | — |
| 7.6 | Handover, custody, comms — quiz | quiz | 4 |
| 7.7 | External reporting, CERTs and ISACs, ION conventions, and worked scenarios | reading | — |
| 7.8 | Clocks, CERTs, ION & scenarios — quiz | quiz | 4 |

#### Topics covered

- **The escalation decision** — cost calculus of *false escalation* (L2 burnout, alert-fatigue erosion, KPI distortion) vs *missed escalation* (delayed containment, dwell-time growth, regulator-clock-started-late, board-level event); the chokepoint principle; default escalation criteria (credential exposure, EDR-high, lateral movement, multi-host/multi-user, VIP, privileged-account out-of-window, novel TTP, SLA risk, cross-team action, suspected data exposure); contain-and-close criteria; "when in doubt escalate — *but*" anti-pattern; SLA bands as escalation triggers; 80/20 of L1 disposition; *stuck-authority* vs *stuck-skill* vs *stuck-scale* vs *stuck-novelty*
- **Severity, priority, blast radius, paths** — five-tier severity scale; FIRST CSIRT services framework, CVSS adapted for incidents, ENISA Reference Incident Classification Taxonomy, NIST 800-61r2 categories, MITRE D3FEND / RE&CT vocabulary; severity × asset class priority matrix; blast-radius lens (hosts × users × data class × services × external entities); TLP / PAP marking on every handoff; the **15 escalation paths** — L2, IR / DFIR, Threat Intel, Detection Engineering / TIDE, IT / Ops, Identity / IAM, Legal / Compliance / Privacy, HR-Security liaison, Comms / PR, Management / CISO, MSSP / vendors, External CIRT / CERT, Sector ISACs, Regulators, Law enforcement — each with *who / when / how / what / why* and the L1-owns vs L1-triggers distinction
- **Handover packet, custody, comms** — the full handover-packet template (title, header, affected entities, monotonic UTC timeline, IOCs with TLP/PAP, containment actions, hypothesis, hashed artefacts, open questions, recommended next steps, stakeholder log) with worked good and bad examples; 5-line vs 5-page question; the **irreducible minimum** five fields; chain-of-custody discipline (legal admissibility, regulatory inquiry, criminal-referral, insurance); SHA-256 hashing at collection; source-of-truth principle; **RFC 3227** order of volatility; UTC time discipline + clock-skew documentation; live-forensics vs containment trade-off; six L1 chain-of-custody rules of thumb; channel hygiene by severity; the **3-line update** (what happened / impact / what's being done) for execs; status-update cadence; plain-language discipline; TLP information-sharing rules; the *no-surprises* rule
- **External clocks, CERTs, ION conventions, scenarios** — **GDPR Art.33** 72h clock from awareness; **NIS2** 24h / 72h / 30d cascade; **DORA** financial-sector regime; **SEC 8-K Item 1.05** 4-business-day disclosure from materiality determination; **HIPAA** 60-day breach notification; **CIRCIA** phased-in 72h / 24h ransom; sectoral (PCI-DSS, TSA, NERC CIP-008); national CERTs (NCSC UK, CISA US, BSI DE, ANSSI FR, JPCERT JP, AusCERT AU, CCCS CA, CERT-EU, ENISA); twelve sector ISACs (FS / MS / H / E / Auto / Aviation / Space / Water / ND / REN / Retail / MFG); reporting portals; ION-specific conventions (case state machine `open → investigating → escalated → closed`, Bob verdict + confidence as nudge-not-authority, ticker as escalation trigger, audit log as automatic in-platform chain of custody, `CaseClosureReason` taxonomy as Tier-1 training feedback, AlertPromptTemplate matcher tier as DE-feedback signal); three full worked scenarios — **AiTM token theft on HR-Director** (4-team handover), **suspected insider IP exfil** (preserve-not-tip-off discipline), **mass phishing with ≥50 confirmed clicks** (cascading into 9 escalation paths within the first hour, GDPR/NIS2/SEC clocks all engaged)

7 Mermaid diagrams across the module: escalation decision tree, multi-team escalation routing topology, handover-packet anatomy, chain-of-custody flow, external-reporting clock Gantt.

L1 course now sits at **7 modules / 51 lessons / 112 questions**.

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.9 (2026-04-28)

### L1 Module 6 — Phishing Triage

Fifth curriculum ship at the v0.11.3 depth bar. **L1 Module 6 — Phishing Triage** authored from a research-agent dossier. ~10,000 words, 8 lessons (4 reading + 4 quiz), 15 quiz questions. Lives on the existing `demo-l1-alert-triage-fundamentals` course as Module 6.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 6.1 | Phishing taxonomy and email authentication | reading | — |
| 6.2 | Taxonomy & email auth — quiz | quiz | 4 |
| 6.3 | Lure analysis, lookalike domains, and attachment + link triage | reading | — |
| 6.4 | Lure & link triage — quiz | quiz | 3 |
| 6.5 | Detection telemetry: email side, endpoint side, identity side | reading | — |
| 6.6 | Telemetry & AiTM — quiz | quiz | 4 |
| 6.7 | Reporting pipeline, decision framework, ATT&CK, and worked scenarios | reading | — |
| 6.8 | Decision framework, ATT&CK & scenarios — quiz | quiz | 4 |

#### Topics covered

- **Taxonomy & email auth** — credential phishing, malware delivery, BEC (CEO fraud / vendor invoice redirect / payroll diversion), spear/whaling, smishing/vishing, **quishing** (QR-phishing), **consent phishing** (OAuth abuse), browser-in-the-browser, **AiTM** kits (Evilginx, EvilProxy, Tycoon 2FA), MFA fatigue / push bombing; RFC 5321 envelope vs RFC 5322 header From; reading the Received chain bottom-up; Authentication-Results / `compauth` interpretation; SPF (RFC 7208), DKIM (RFC 6376) including DKIM replay, DMARC (RFC 7489) alignment + policy, ARC (RFC 8617) for forwarders; the four spoofs none of SPF/DKIM/DMARC stops alone (display-name, lookalike, compromised legitimate sender, Reply-To swap)
- **Lures & link triage** — pretext catalogue (HR / IT / voicemail / DocuSign / courier / invoice / Teams / calendar / captcha / QR), urgency–authority–scarcity psychology, brand-impersonation tells (display-name vs domain, hover-vs-display URL, favicon, footer), lookalike domain families (typosquat / combosquat / IDN homoglyph / TLD swap / sub-domain abuse) with worked Cyrillic-`о` example, risky file types (HTML smuggling, ISO/IMG/VHD MOTW bypass, .lnk, .one, weaponised PDF, .docm/.xlsm/.xll macros, .svg with script, password-protected zip, ClickOnce, .url SMB-cred-theft), URL reputation tooling (VT, urlscan.io, Hybrid Analysis, abuse.ch, OPSWAT), the **OPSEC submission rule** with per-victim-token handling, sandbox decision criteria
- **Email + endpoint + identity telemetry** — Microsoft 365 Defender for Office 365 (Threat Explorer, Email Entity Page, Quarantine, ZAP, Submissions API), Exchange Message Trace fields + `Get-MessageTrace` PowerShell, Google Workspace Investigation Tool, EDR process trees rooted at `outlook.exe` / `<browser>.exe` / Office, Sysmon event-ID fingerprints (1/3/7/11/15/22/25), full ECS field-path map for phishing follow-on (`process.parent.name`, `url.original`, `email.from.address`, `dns.question.name`, `file.hash.sha256`), worked KQL + Lucene queries, **AiTM signal in Entra ID sign-in logs** (riskEventTypes_v2, sessionId reuse, `previouslySatisfied` MFA), Unified Audit Log events (`New-InboxRule`, `Set-Mailbox -ForwardingSmtpAddress`, `Add-MailboxPermission`, `Consent to application`), illicit OAuth grants and the risky scopes that demand escalation, the textbook post-takeover BEC inbox-rule pivot
- **Pipeline, decisions, ATT&CK, scenarios** — user-reported phishing pipeline (PhishER, Cofense, Microsoft Report Message), confirmed-phish workflow (scope → pull → contain → IOC-pivot → 7-day hunt → submit), L1-vs-L2 authority boundaries, escalate/contain/close decision tree, ATT&CK mapping across **T1566.001/.002/.003/.004**, T1583.001 lookalike domains, **T1656** impersonation, T1027.006 HTML smuggling, **T1539** Steal Web Session Cookie, **T1098.005** Device Registration, T1556 Modify Authentication Process, **T1114.003** Email Forwarding Rule, T1621 MFA Request Generation, T1071.001/.004 C2; three full worked scenarios — **AiTM credential phish with token theft**, **HTML smuggling → ISO → LNK → loader**, **BEC vendor invoice redirect (no malware)**

10 Mermaid diagrams across the module: SPF/DKIM/DMARC validation flow, AiTM kit topology, click-path process tree, post-confirmation containment checklist, triage decision tree.

L1 course now sits at **6 modules / 43 lessons / 97 questions**.

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.8 (2026-04-27)

### L1 Module 5 — IOC Handling

Fourth curriculum ship at the v0.11.3 depth bar. **L1 Module 5 — IOC Handling** authored from a research-agent dossier. ~10,000 words, 8 lessons (4 reading + 4 quiz), 14 quiz questions. Connects Modules 3 (host telemetry) and 4 (network telemetry) to the threat-intel side.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 5.1 | IOC types and the Pyramid of Pain | reading | — |
| 5.2 | IOC types — quiz | quiz | 3 |
| 5.3 | IOC formats, sharing, and threat intel platforms | reading | — |
| 5.4 | STIX/MISP/TLP/PAP — quiz | quiz | 3 |
| 5.5 | Reputation services, enrichment, and OPSEC | reading | — |
| 5.6 | Reputation & OPSEC — quiz | quiz | 4 |
| 5.7 | IOC lifecycle, matching in ION, and decay | reading | — |
| 5.8 | Lifecycle & matching — quiz | quiz | 4 |

#### Topics covered

- **IOC types & Pyramid of Pain** — observable vs indicator vs IOC, Mandiant atomic/computed/behavioural taxonomy, full IOC catalogue (hashes, network atomics, host artefacts, TLS, pattern-based, adversary-level), Bianco's tier model with cost-to-adversary breakdown, precision-vs-durability-vs-FP-rate trade-offs
- **Formats, sharing, platforms** — STIX 2.1 SDO/SRO/SCO with worked indicator JSON, MISP events/attributes/objects/tags/galaxies with worked attribute JSON, OpenIOC legacy, CSV / Suricata / YARA / Sigma drops, **TLP 2.0** (CLEAR/GREEN/AMBER/AMBER+STRICT/RED) sharing rules, **PAP** (WHITE/GREEN/AMBER/RED) action rules — emphasising TLP and PAP are independent, OpenCTI as upstream truth source, defanging/refanging conventions
- **Reputation & OPSEC** — VirusTotal interpretation (the 0/72 trap, Behaviour tab, Relations graph), AbuseIPDB confidence semantics, abuse.ch (URLhaus, ThreatFox, MalwareBazaar), AlienVault OTX pulse caveats, Shodan/Censys passive scan databases, Passive DNS for resolution-at-alert-time reconstruction, **the OPSEC trap** of submitting fresh hashes/samples/URLs to public services against live adversaries, active-vs-passive enrichment decision tree, end-to-end fresh-C2-domain triage walkthrough
- **Lifecycle & matching in ION** — 8-stage lifecycle (production → ingestion → enrichment → distribution → matching → triage → feedback → decay), type-appropriate decay (hashes never auto-expire, IPs 30 d, domains 90 d, URLs 14 d), MISP decaying-indicators model + OpenCTI valid_until, Elastic Indicator Match rules with full ECS field-path table (`file.hash.sha256` ↔ `threat.indicator.file.hash.sha256`, `source.ip` ↔ `threat.indicator.ip`, etc.), KQL hunting examples for hash/IP/domain/URL, sightings semantics + feed efficacy measurement, FP-marking discipline, **end-to-end Emotet-dropper IOC-hit triage** (Module 3/4 callbacks, classification, sighting-write, escalation)

10 Mermaid diagrams across the module: Pyramid of Pain, observable taxonomy, STIX object relationships, intel ingestion flow, active-vs-passive sources, OPSEC enrichment decision tree, IOC lifecycle, IOC match-then-investigate workflow.

L1 course now sits at **5 modules / 35 lessons / 82 questions**.

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.7 (2026-04-27)

### L1 Module 4 — Network Telemetry

Third curriculum ship at the v0.11.3 depth bar. **L1 Module 4 — Network Telemetry** authored from a research-agent dossier. ~10,000 words, 8 lessons (4 reading + 4 quiz), 14 quiz questions. Lives on the existing `demo-l1-alert-triage-fundamentals` course as Module 4.

#### Lesson breakdown

| # | Title | Type | Quiz qs |
|---|---|---|---|
| 4.1 | Network data sources — PCAP, flow, Zeek, IDS | reading | — |
| 4.2 | Data sources — quiz | quiz | 3 |
| 4.3 | Reading Zeek logs and the ECS mapping | reading | — |
| 4.4 | Zeek + ECS — quiz | quiz | 3 |
| 4.5 | Beaconing, DNS tunneling, and C2 detection | reading | — |
| 4.6 | Beaconing & C2 — quiz | quiz | 4 |
| 4.7 | Reconnaissance, exfiltration, and ATT&CK mapping | reading | — |
| 4.8 | Recon & exfil — quiz | quiz | 4 |

#### Topics covered

- **Data sources** — PCAP vs NetFlow/IPFIX/sFlow vs Zeek metadata vs Suricata/Snort IDS; sampling-rate context; proxy and NGFW logs
- **Zeek + ECS** — full conn.log field set, the seven `conn_state` codes that matter (S0/S1/SF/REJ/RSTO/RSTR/OTH), suspicious dns.log shapes (long subdomains, NXDOMAIN bursts, DGAs, TXT volume), ssl.log + SNI + JA3/JA3S, uid pivot, complete Zeek-to-ECS field mapping table
- **Beaconing & C2** — statistical signature, worked 144-conn / 600 s-jitter example with full conn.log shape and ES|QL aggregation, DNS tunneling shape with `dnscat2` / `iodine` worked example, HTTP/HTTPS C2 indicators, CDN-hidden C2 nuance, JA3 enrichment caveats, escalation criteria
- **Recon & exfil** — port scan vs sweep distinction with conn_state shapes, post-scan service enumeration (SMB/RDP/WinRM/SSH/WMI), exfil patterns to mega.nz / Discord CDN / transfer.sh with ES|QL outbound-bytes query, DNS exfil vs HTTPS exfil trade-off, lateral-movement port catalogue (445/5985/6/3389/RPC/LDAP/Kerberos), MITRE ATT&CK technique mapping (T1046, T1041, T1048, T1071, T1572)

10 Mermaid diagrams across the module: data-source taxonomy, detail-vs-volume pyramid, Zeek log family + uid pivot, Zeek-to-ECS mapping, beacon timeline, DNS-tunneling shape, scan vs sweep visualisation, DNS exfil workflow.

L1 course now sits at **4 modules / 27 lessons / 68 questions**.

#### Upgrade

```
cat seed_courses.py | docker exec -i ion python -
```

Idempotent — wipes `demo-*` courses and re-seeds.

---

## v0.11.6 (2026-04-27)

### L1 Module 3 — Windows Event Logs

Second curriculum ship at the v0.11.3 depth bar. **L1 Module 3 — Windows Event Logs** authored from a research-agent dossier covering channels, providers, the high-value Security event IDs, Sysmon, and canonical attacker patterns. ~10,000 words of curriculum content, 8 lessons (4 reading + 4 quiz), 23 quiz questions. Now lives on the existing `demo-l1-alert-triage-fundamentals` course as Module 3.

#### Lesson breakdown

| # | Title | Type | Words | Quiz qs |
|---|---|---|---|---|
| 3.1 | The Windows logging architecture and how it reaches ION | reading | ~2,200 | — |
| 3.2 | Architecture quiz | quiz | — | 5 |
| 3.3 | High-value Security channel event IDs | reading | ~2,800 | — |
| 3.4 | Security event IDs — quiz | quiz | — | 6 |
| 3.5 | Sysmon — the L1 superpower | reading | ~2,500 | — |
| 3.6 | Sysmon recognition — quiz | quiz | — | 6 |
| 3.7 | Triaging common attack patterns from raw events | reading | ~2,700 | — |
| 3.8 | Attack patterns — quiz | quiz | — | 6 |

Each reading lesson hits the v0.11.3 quality bar: explicit learning objectives + prerequisites, multiple Mermaid diagrams (10 across the module — flowcharts, sequence diagrams, decision trees), worked scenarios with full ECS field traces and ATT&CK technique mappings, KQL with line-by-line commentary, glossary, and references.

#### Topics covered

- **Architecture** — channels (Security, System, Application, Setup, Forwarded Events) vs providers, EVTX format, winlogbeat ECS normalisation, channel-to-index mapping, Windows Event Forwarding (WEF) source-initiated subscriptions
- **Security event IDs** — the 4624/4625/4634/4647/4648/4672 logon cluster with all 11 LogonTypes, 4625 SubStatus codes (`0xC000006A` bad password, etc.), the 4720/4722/4724/4732/4738/4756 account/group cluster, Kerberos 4768/4769 with `TicketEncryptionType` Kerberoasting tells, NTLM 4776, audit log clearing 1102, service install 7045, command-line process creation 4688
- **Sysmon** — provider/channel naming, SwiftOnSecurity vs Olaf Hartong baselines, the high-value event IDs (1, 3, 7, 8, 10, 11, 13, 22) with full ECS field mapping, `OriginalFileName` for renamed-binary detection, Mimikatz LSASS signature on Event 10
- **Attack patterns** — Pass-the-Hash signatures (`AuthenticationPackageName: NTLM` for admin accounts), golden/silver ticket conceptual signals (4624 without 4768/4769 on DC), service install persistence with `ImagePath` heuristics, account-creation-then-group-add cluster, parent-child anomaly table (Office spawning shells, IIS spawning shells = webshell, lsass.exe spawning anything), DNS exfiltration via Sysmon 22

22 ATT&CK technique mappings cited (T1078, T1110, T1021, T1550.002, T1558.001/002/003, T1003.001, T1059, T1218, T1036, T1071, T1041, T1574, T1055, T1486, T1547.001, T1543.003, T1505.003, T1070.001, T1566.001, T1059.005, T1110.003).

#### Upgrade

Drop in `ion:0.11.6`. Re-run the seeder to refresh course content (idempotent — wipes `demo-*` courses and re-seeds):

```
cat seed_courses.py | docker exec -i ion python -
```

After re-seed, browse `http://localhost:8000/courses/demo-l1-alert-triage-fundamentals` — Module 3 (Windows Event Logs) appears below Modules 1 and 2.

#### What's next

L1 Module 4 (Network Telemetry) → 5 (IOC Handling) → 6 (Phishing Triage) → 7 (Escalation Workflow) → 8 (Common ATT&CK), all using the same research-agent → dossier → curriculum pattern. Then L2 and L3 curricula. Then the Elastic Agent Skills integration we scoped earlier.

## v0.11.5 (2026-04-27)

### L1 Module 2 — SIEM Fundamentals (curriculum kick-off)

First curriculum ship at the v0.11.3 depth bar. **L1 Module 2 — SIEM Fundamentals** authored from a research-agent dossier covering the Elastic / Wazuh / ECS stack ION integrates with. ~10,500 words of curriculum content, 8 lessons (4 reading + 4 quiz), 22 quiz questions. Now lives on the existing `demo-l1-alert-triage-fundamentals` course as Module 2.

#### Lesson breakdown

| # | Title | Type | Words | Quiz qs |
|---|---|---|---|---|
| 2.1 | What a SIEM is and how data flows through it | reading | ~2,400 | — |
| 2.2 | Pipeline + architecture quiz | quiz | — | 5 |
| 2.3 | Speaking ECS — the data model L1 lives in | reading | ~2,500 | — |
| 2.4 | ECS field knowledge — quiz | quiz | — | 6 |
| 2.5 | Querying the SIEM with KQL | reading | ~2,800 | — |
| 2.6 | KQL fluency — quiz | quiz | — | 6 |
| 2.7 | Pivots, timelines, and the alert lifecycle | reading | ~2,800 | — |
| 2.8 | Pivots + lifecycle — quiz | quiz | — | 6 |

Each reading lesson hits the v0.11.3 quality bar:
- Explicit *learning objectives* + *prerequisites* at top
- Multiple Mermaid diagrams (sequence, flowchart, state machine, classDiagram) — 9 diagrams across the module
- Worked scenarios with concrete ECS field names + realistic hostnames + actual KQL queries with line-by-line commentary
- ION-specific callouts: how each topic ties back to `AlertTriage`, `Investigation`, `AIFeedback`, the `CaseClosureReason` enum, Bob's role
- Glossary of jargon (~10–12 terms per lesson)
- Further reading with concrete URLs (Elastic docs, Wazuh docs, MITRE ATT&CK, BTL1, SANS GCIH KSA references)

#### Topics covered

The four lessons collectively cover:

- **Pipeline anatomy** — the six stages (ingest → parse → normalise → store → query → alert), which Elastic Stack component owns each, where failures localise
- **SIEM vs aggregator** — five concrete capability differences (schema, detection engine, enrichment, workflow, retention tiers)
- **Architectures** — cloud-native vs on-prem vs hybrid, with practical implications for L1 self-service vs escalation
- **ECS data model** — the ten core fields used in 90% of L1 queries, source-to-ECS mapping for winlogbeat/sysmon/auditd/packetbeat/wazuh, common pitfalls (case sensitivity, multi-value fields, action vs code)
- **KQL fluency** — boolean operators, wildcards, ranges, existence checks, escaping, four canonical hunt patterns (failed-auth-by-user, suspicious-child-of-svchost, beaconing, DNS to newly-registered domains)
- **SPL contrast + translation** — KQL-to-CIM-to-SPL field mappings (`source.ip` ↔ `src_ip`, etc.) for analysts moving between employers
- **Cluster investigation pattern** — the 10-step pivot chain from anchor IOC through host → user → process → network → file → hash → DNS → lateral
- **Dashboard pitfalls** — when to trust them, when they hide answers (time-range mismatch, filter inheritance, index-pattern drift, ranking truncation)
- **Alert lifecycle in ION** — the state machine, ION as system of record vs Kibana as a connector view, why closure-comment quality matters for AIFeedback

#### Authoring approach

This module is the first to follow the **research-agent → dossier → curriculum** pattern. A research agent produced ~10,000 words of structured input (sections + worked examples + diagrams + question stems + glossary + references) which was then woven into final lesson copy. The pattern scales — subsequent L1 modules (3-8) and the L2/L3 ships will use the same flow.

#### Upgrade

Drop in `ion:0.11.5`. Re-run the seeder to refresh course content (idempotent — wipes `demo-*` courses and re-seeds):

```
cat seed_courses.py | docker exec -i ion python -
```

After re-seed, browse `http://localhost:8000/courses/demo-l1-alert-triage-fundamentals` — Module 2 with its 8 lessons appears below the existing Module 1.

#### What's next

- **v0.11.6+** — additional L1 modules using the same dossier pattern (Windows Event Logs, Network Telemetry, IOC Handling, Phishing Triage, Escalation Workflow, Common ATT&CK)
- **After L1 curriculum complete** — Elastic Agent Skills exploration (separate research conversation queued by user)

## v0.11.4 (2026-04-27)

### Course admin authoring UI

Curriculum work no longer requires running the seeder. Admins (anyone with the existing `playbook:create`/`update`/`delete` permissions) can author courses end-to-end through the UI.

#### CRUD endpoints (10 new)

| Method | Path | Action |
|---|---|---|
| `POST` | `/api/courses` | Create a course shell |
| `PUT` | `/api/courses/{id}` | Update course metadata |
| `DELETE` | `/api/courses/{id}` | Delete (cascades to modules → lessons → questions) |
| `POST` | `/api/courses/{id}/modules` | Add a module |
| `PUT` | `/api/modules/{id}` | Update module |
| `DELETE` | `/api/modules/{id}` | Delete module |
| `POST` | `/api/modules/{id}/lessons` | Add a lesson |
| `PUT` | `/api/lessons/{id}` | Update lesson metadata + content_md |
| `DELETE` | `/api/lessons/{id}` | Delete lesson |
| `POST` | `/api/lessons/{id}/questions` | Add a question |
| `PUT` | `/api/questions/{id}` | Update question (kind, stem, options, correct, explanation, points) |
| `DELETE` | `/api/questions/{id}` | Delete question |

All mutating endpoints validate kind/lesson_type enums + slug uniqueness.

#### JSON import/export

- `GET /api/courses/{slug}/export` — full course tree as JSON, including correct answers + explanations (admins only)
- `POST /api/courses/import` — accepts the same shape, validates, creates the whole tree atomically. 409 if slug collides

The export → import round-trip is byte-stable so courses can be moved between ION instances or version-controlled in git.

#### Admin pages

- **`/admin/courses`** — list of all courses (published + drafts). Each row shows level pill, status pill, hours, pass threshold, and quick actions for Edit / Export. Two dialogs:
  - **+ New course** — minimal form (title, level, slug-optional, hours, pass-threshold, publish-flag). On create, auto-redirects to the editor.
  - **Import JSON** — paste-and-validate. Accepts either `{"course": {...}}` or `{...}` shape; both work.
- **`/admin/courses/{id}/edit`** — full editor:
  - Course metadata card (title, slug, level, hours, pass-threshold, order, publish-flag, description markdown) with a single Save button
  - Modules section — each module is a card with inline title/duration/description editing, Save / + Lesson / Delete buttons
  - Lesson cards — collapsible by default. When expanded: metadata grid (title, type, duration, lab URL), content_md textarea with **live markdown preview pane** (Mermaid diagrams render as you type), then a question editor for each question
  - Question editor — kind dropdown, stem textarea, options as JSON array, correct_answer as JSON, explanation textarea, points input. Two save buttons per question. Validation surfaces inline if JSON is malformed.
  - Image upload card — pick a file → upload → returns the public URL + a markdown snippet ready to paste into any lesson body
  - Top-right action bar — "Preview as analyst →" button opens the published-side `/courses/{slug}` page in a new tab; "Delete course" with confirmation

The editor saves at module / lesson / question granularity (not all-at-once) so an author can save progress on one section without re-validating the rest. Every save shows a toast.

#### Nav

New "Course authoring" entry in the user dropdown's Admin section, alongside Stories / AI Scorecard.

#### Why no full canvas editor?

Markdown + live preview is the right power-curve for v0.11.4. A full WYSIWYG canvas (drag-drop modules, etc.) is plausible but adds 1500+ LOC of frontend work and locks authoring into ION's UX choices — markdown stays portable and git-diffable. v0.11.5+ can layer on richer affordances (drag-reorder, structured question builder for non-technical authors) once the bar of usage is established.

#### Upgrade

Drop in `ion:0.11.4`. No schema changes from v0.11.3. CRUD endpoints register automatically; admin pages live at `/admin/courses` and `/admin/courses/{id}/edit`.

## v0.11.3 (2026-04-27)

### Course depth bar set + image upload + Mermaid vendored

After v0.11.2 shipped the course framework with deliberately-light demo lessons (~800-1200 words each), feedback was unambiguous: **"more depth and visuals like a proper course in the future"**. This ship sets the BTL1 / SANS-style depth bar so the v0.11.4-6 curriculum ships hit it from day one.

#### Demo lesson rewrites (one per tier)

The first reading lesson of each tier rewritten to proper-course depth — these become the quality template for the full curriculum. ~7,800 words of new curriculum content total:

- **L1 — "What happens to an alert?"** — ~2,300 words. Adds explicit learning objectives, prerequisites, deeper explanation of each lifecycle state with ION's actual data-model fields, a Mermaid sequence diagram of a worked end-to-end alert walk (DEMO-0001 from `seed_test_data.py`), four common-mistake patterns each with a fix, and a glossary + further-reading section. **Two diagrams**: lifecycle flowchart + worked-example sequence.
- **L2 — "The hunt hypothesis (PEAK methodology)"** — ~2,600 words. Strong-vs-weak hypothesis rewriting with five real anti-pattern examples, the four-element hypothesis template visualised as a Mermaid graph, full PEAK loop diagram, KQL with line-by-line commentary, refinement table covering structural-vs-content exclusions, hunt-log YAML schema for null results. **Three diagrams**.
- **L3 — "Why purple teaming beats annual pentests"** — ~2,900 words. Full purple-team workflow Mermaid graph, four-tier fidelity decision tree (Alerted / Logged-not-alerted / Unparsed / Not-logged) showing which team owns which gap, scoping-rules section with an exercise-notice template, complete worked T1059.001 cycle from authorisation through scorecard YAML, eight-mistake anti-pattern list. **Two diagrams**.

Every rewritten lesson includes:
- Explicit *learning objectives* + *prerequisites* at top
- Multiple sub-sections with named headings
- Worked scenarios that walk an analyst's actual cognitive process
- Code blocks with inline line commentary
- Glossary of jargon introduced
- Further reading with concrete pointers (ATT&CK, LOLBAS, PEAK, MITRE Evals, etc.)

#### Image upload infrastructure

New endpoint: `POST /api/courses/{slug}/images` accepts multipart-form file uploads with `name_override`. Files land at:

```
src/ion/web/static/img/courses/<course-slug>/<safe-stem>-<random8>.<ext>
```

Served by the existing `/static` mount — air-gap safe, no third-party storage, no CDN. Constraints: PNG/JPG/SVG/WebP/GIF, 5 MB cap, requires `playbook:create` permission, streamed write with size enforcement so a malicious giant upload can't OOM the worker. Returns the public URL plus a markdown-ready snippet for paste into lesson content:

```json
{
  "url": "/static/img/courses/demo-l1.../lifecycle-x7k2m9q1.png",
  "markdown": "![lifecycle](/static/img/courses/demo-l1.../lifecycle-x7k2m9q1.png)"
}
```

#### Mermaid vendored

`static/js/mermaid.min.js` (Mermaid 10.9.1, ~3.3 MB) is now bundled in the image. Air-gap deployments get diagrams out of the box — no curl-from-CDN required. Marked.js configured with a custom code-block renderer in `base.html` that converts ` ```mermaid ` fenced blocks to `<div class="mermaid">` so `mermaid.run()` picks them up. Without this hook, mermaid blocks would render as plain `<pre><code class="language-mermaid">` and never become diagrams.

#### What's deferred (still v0.11.4)

- Admin authoring UI — pushed to v0.11.4. The image upload endpoint is wired, but admins still edit course content via the seeder until the authoring UI lands.
- Inline knowledge-check widgets — embedded mini-quizzes within reading lessons. Requires a custom marked.js extension or custom directive parser; deferred.
- Full L1 / L2 / L3 curriculum — v0.11.4 / .5 / .6 will author the rest of the modules at the bar this ship just set.

#### Upgrade

Drop in `ion:0.11.3`. No schema changes. Run the updated `seed_courses.py` to refresh the demo content (it cleans and re-seeds idempotently):

```
cat seed_courses.py | docker exec -i ion python -
```

## v0.11.2 (2026-04-27)

### Course framework — L1/L2/L3 SOC analyst training (foundation ship)

First of a six-ship sequence building a full BTL1-style training course system for L1/L2/L3 analysts. This ship is the **framework** that everything else hangs off — models, executor, UI, Mermaid support, and one substantial demo lesson per tier to set the quality bar.

#### Models (7 new tables, all auto-create on first boot)

- **`Course`** — id, title, slug (unique), level (`L1`/`L2`/`L3`/`L4`), description_md, estimated_hours, badge_image_path, prerequisite_course_id (self-FK), order_in_level, pass_threshold, published, skill_keys (JSON, links to existing `SkillAssessment`), author_id
- **`CourseModule`** — child of Course, ordered, with own description + estimated minutes
- **`Lesson`** — child of Module. `lesson_type` ∈ `{reading, quiz, lab}`. Markdown body. Lab variant carries an optional `lab_target_url` pointing into ION (e.g. `/cases/1`)
- **`Question`** — child of Lesson. `kind` ∈ `{single, multi, truefalse, shortanswer}`. JSON-backed options + correct-answer + explanation
- **`UserEnrolment`** — one per `(user_id, course_id)`, captures started/completed/badge/score_pct
- **`UserLessonProgress`** — one per `(user_id, lesson_id)`, status, score, attempts
- **`UserAnswer`** — one per quiz attempt, replays preserved (each submission stamps a fresh `attempt_id`)

Distinct from the existing `TrainingPlan` (which tracks external certs like CompTIA/SANS) — Courses are interactive, in-app curriculum.

#### Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/courses` | catalog (filterable by level, published-only by default) |
| GET | `/api/courses/{slug}` | course detail with modules + lessons + per-lesson user progress |
| POST | `/api/courses/{id}/enrol` | self-enrol (blocked if prerequisite course incomplete) |
| GET | `/api/my-courses` | current user's enrolments dashboard payload |
| GET | `/api/lessons/{id}` | lesson content + questions (correct answers stripped) |
| POST | `/api/lessons/{id}/complete` | mark a reading/lab lesson complete |
| POST | `/api/lessons/{id}/submit-quiz` | submit answers; server grades + records attempt + updates progress + recomputes course completion |

Quiz grading: single/truefalse exact match, multi with partial credit (intersection-over-union × max points), shortanswer case-insensitive against an accepted-answer set.

Course completion auto-detection: when *every* lesson is in `completed` status, the enrolment row's `completed_at` is set and `badge_earned` flips to true. If a quiz re-attempt regresses a lesson from `completed` to `failed`, the enrolment is reopened automatically.

#### UI

Three pages — all use the existing `marked.js` + `DOMPurify` markdown stack:

- **`/courses`** — catalog grid by level with a filter strip. Cards show title, description preview, estimated hours, and pass threshold.
- **`/courses/{slug}`** — course detail with a progress bar across all lessons, modules expanded with lesson list, status dots (not_started / in_progress / completed / failed), per-lesson type pill (reading / quiz / lab) and last score.
- **`/lessons/{id}`** — lesson view. Markdown body rendered with full prose styling, then quiz questions inline if applicable. Submit returns per-question feedback with the correct answer + explanation. Pass/fail banner with pass threshold visible.

Nav: new "Courses (L1/L2/L3)" link in the Knowledge dropdown alongside Skills & Training.

#### Mermaid diagrams

Added `<script src="/static/js/mermaid.min.js">` to `base.html` with a graceful-degradation guard. Lesson markdown can include ` ```mermaid ... ``` ` blocks for attack chains, kill chains, lifecycle diagrams. Air-gap deployments need to drop `mermaid.min.js` into `static/js` (not bundled by default — adds ~2 MB to the image).

#### Demo content (one lesson per level)

Substantial Markdown + quiz content seeded by `seed_courses.py`:

- **L1 — Alert Triage Fundamentals** · 1 module, 3 lessons (1 reading + 2 quizzes, ~12 questions): the alert lifecycle as a Mermaid flowchart, the four-tier severity rubric with worked examples, true_positive / false_positive / benign_true_positive distinctions tied to ION's `CaseClosureReason` enum.
- **L2 — Threat Hunting with KQL** · 1 module, 2 lessons (1 reading + 1 quiz, ~4 questions): the PEAK methodology, a worked LotL hypothesis (mshta/regsvr32 invoked from PowerShell), KQL refinement that reduces noise without hiding signal, converting hunts into TIDE rules.
- **L3 — Adversary Emulation Basics** · 1 module, 2 lessons (1 reading + 1 quiz, ~4 questions): purple-team flow as a Mermaid graph, the four detection-fidelity tiers (alerted / logged-not-alerted / unparsed / not-logged), MITRE ATT&CK T1059.001 worked Atomic test, what to record on the scorecard.

Prerequisite locks are wired: L2 requires L1, L3 requires L2.

Each demo lesson is **substantive** — 800-1200 words, real worked examples, citations to ION's own enums and tables. Sets the quality bar for the full curriculum coming in v0.11.4 / v0.11.5 / v0.11.6.

#### Upgrade

Drop in `ion:0.11.2`. New tables (`courses`, `course_modules`, `lessons`, `course_questions`, `course_enrolments`, `course_lesson_progress`, `course_user_answers`) auto-create. Run `seed_courses.py` to populate the demo curriculum:

```
cat seed_courses.py | docker exec -i ion python -
```

#### What's next

- **v0.11.3** — admin authoring UI (no more JSON seeders for course content)
- **v0.11.4 / .5 / .6** — full L1 / L2 / L3 curriculum (each ~8 modules covering BTL1-equivalent depth)
- **v0.11.7** — hands-on labs that link into real ION pages + PDF certificate generation on completion

## v0.11.1 (2026-04-27) — PATCH

### Network Mapper sync: TZ comparison crash

`network_mapper_service._upsert_one` raised `TypeError: can't compare offset-naive and offset-aware datetimes` when comparing the parsed ES `@timestamp` against `NetworkAsset.last_seen` (and the IP/MAC variants). ES timestamps came back TZ-aware via `datetime.fromisoformat("...Z".replace("Z","+00:00"))`, but the DB columns are plain `DateTime` (no `timezone=True`) so SQLAlchemy returned naive values — the `now > asset.last_seen` comparison on lines 234/265/284 then crashed and stopped the sync mid-batch.

Single-line fix in `_parse_host_buckets`: drop tzinfo on `ts` after parsing so it's a naive UTC datetime, matching the DB column shape. Comparisons downstream stay consistent and the sync runs to completion.

## v0.11.0 (2026-04-27)

### Stories — JSON-DAG automation playbooks (Tines-inspired)

Third of three ships borrowing patterns from market SOC tools. This one comes from **Tines's Story model** — JSON-DAG playbooks with a small, opinionated step library and explicit conditional edges instead of nested if/else blocks.

This is a **major-version bump** because it introduces a new automation primitive alongside the existing TIDE-driven `Playbook` catalogue. Stories don't replace playbooks — they're user-authored automation for runtime triage / response, where playbooks are detection-engineering artifacts.

#### What ships in v0.11.0 (linear slice)

- **`Story` + `StoryRun` models** — DAG persisted as JSON, every execution captured with per-step output, status, and duration
- **3 step types** in the executor:
  - `case_note` — append a templated note to a case
  - `bob_investigate_alert` — run Bob's autonomous investigation pipeline against an alert and capture verdict + summary
  - `http_request` — outbound HTTP call, response into context
- **Tiny templating** — `{{ trigger.alert_id }}` / `{{ nodes.<id>.<field>}}` substitution. Not full Jinja — kept narrow on purpose for security on freshly-imported stories
- **Linear executor** — walks `start` node forward via each node's `next` until None or error. Validates the DAG up-front (cycle check + unknown-node refs + unknown-step-types)
- **Admin page at `/stories`** — list rail + raw-JSON editor + run button + recent-runs panel with per-step output expand
- **Endpoints**:
  - `GET /api/stories` · `GET /api/stories/{id}` · `POST /api/stories` · `PUT /api/stories/{id}` · `DELETE /api/stories/{id}`
  - `POST /api/stories/{id}/run` (synchronous; returns the run record)
  - `GET /api/stories/{id}/runs` · `GET /api/story-runs/{run_id}`
  - `GET /api/stories/step-types` (public catalogue)
- **Permissions** — read uses `playbook:read`, create `playbook:create`, update `playbook:update`, delete `playbook:delete`, execute `playbook:execute`

#### What's deferred (to v0.11.1+)

- **Conditional edges** — every node currently has at most one `next`. Branching arrives next ship.
- **Visual canvas editor** — v0.11.0 ships a JSON textarea with validation. Drag-and-drop graph editor is the obvious follow-up.
- **More step types** — Page (human-in-the-loop form), Send-to-Story (subroutine), Email/Slack/Teams notifications, OpenCTI enrich, ES query, observable mutate. The step registry is a single dict in `story_executor.py:_STEP_REGISTRY` — adding a step is one function + one entry.
- **Background execution** — runs are synchronous in v0.11.0 (a `bob_investigate_alert` step blocks ~30 s). Async + WebSocket progress updates land later.

#### Why a new model rather than extending `Playbook`?

Existing playbooks are TIDE-driven detection-engineering artifacts. Stories are user-authored runtime automation — different lifecycle (versioned, importable, executable against arbitrary entities), different audit story, different permission model. Keeping them parallel avoids breaking v0.10.x playbook UI.

#### Upgrade
Drop in `ion:0.11.0`. New tables (`stories`, `story_runs`) created via `Base.metadata.create_all` on first boot. No `.env` changes required.

## v0.10.20 (2026-04-27)

### Attack Story timeline (Hunters-inspired)

Second of three ships borrowing UX patterns from market SOC tools. This one comes from **Hunters AI's "Attack Story"** — a chronological narrative on the case detail page that aggregates every event tied to the case into a single scannable feed, with Bob's latest verdict surfaced as a header narrative.

#### What's new

A **"Attack Story Timeline"** section on every case detail page (top of the right rail, above "Similar Closed Cases"). Two parts:

1. **Bob's take** header — the latest investigation summary with its verdict pill (true_positive / false_positive / etc.) and the key-observation citations rendered as quote-style indented bullets. No extra LLM call needed; reuses the v0.10.11 `key_observations_json` and `summary_text` already persisted on each Investigation row.

2. **Chronological event feed** — a vertical timeline with kind-coloured markers and per-event detail expansion. Three lanes:
   - **🟢 Bob** — autonomous investigations with verdict + key-observation citations
   - **🟡 Analyst** — investigation notes (case status changes, sign-offs, free-text)
   - **⚪ System** — case lifecycle, alert linkage, observable extraction, playbook starts/completions

A counts strip at the top (`N events · X Bob · Y analyst · Z system`) gives the case-load shape at a glance.

#### Backend

New endpoint `GET /api/elasticsearch/alerts/cases/{case_id}/timeline` aggregates from the existing data sources:
- `AlertCase.created_at` / `closed_at` — case lifecycle
- `Note` rows scoped to the case (Bob-authored notes detected via the `🤖 Bob` marker)
- `AlertTriage` entries for linked alerts
- `Investigation` rows linked via `alert_id_ref` (verdict + summary + key_observations cited)
- `ObservableLink` rows for the case (extraction events)
- `PlaybookExecution` rows for the case (start + complete events)

Returns `{events: [...], narrative: {...}, counts: {...}}`. Events are sorted ascending by timestamp; `narrative` carries the latest Bob investigation for the header.

#### No schema changes
Pure aggregation of existing data. Drop in `ion:0.10.20`.

## v0.10.19 (2026-04-27)

### Observable TLP/PAP/IOC + cross-case sightings panel (TheHive 5 inspired)

First of three ships borrowing patterns from market SOC tools — this one from **TheHive 5's observable model**. ION already had `sighting_count`, `first_seen`, `last_seen`, threat-level, watchlist, and enrichment history; this fills in the missing TheHive bits.

#### Schema additions on `observables` (4 new columns)

- `tlp` — Traffic Light Protocol (`red`, `amber`, `green`, `clear`/`white`). Default `amber`.
- `pap` — Permissible Actions Protocol (same scale). Default `amber`.
- `is_ioc` — explicitly distinguishes "tracked malicious indicator" from "value that showed up in an alert but might be benign". Default false.
- `ignore_similarity` — escape hatch to mute high-noise values (`8.8.8.8`, `1.1.1.1`, internal DNS resolvers) from the cross-case sightings panel. Default false.

Idempotent ALTER TABLE migration — pre-v0.10.19 rows take the defaults. `Base.metadata.create_all` handles fresh deployments.

#### Cross-case observable sightings panel

New section on the case detail right-rail: **"Cross-Case Observable Sightings"**, sibling to the existing pgvector-driven "Similar Closed Cases" section. Where the pgvector panel asks *"which other cases look semantically similar?"*, this one asks *"which other cases share the literal same indicator value?"*

For every observable attached to the case (skipping `is_whitelisted` + `ignore_similarity`), the panel lists other cases that share that same `(type, normalized_value)` via the existing `ObservableLink` table. Sorted by sighting count — most-shared indicators surface first. TLP and IOC badges render on each row.

Endpoint: `GET /api/elasticsearch/alerts/cases/{case_id}/similar-observables`. Returns `{shared: [{observable, sightings: [{case_id, case_number, title, severity, status, last_seen}]}]}`.

#### `PUT /api/observables/{id}` extended

The existing update endpoint accepts `tlp`, `pap`, `is_ioc`, `ignore_similarity` in addition to the prior tags/notes/whitelist/threat-level. Lightweight enum-string validation (lowercased, restricted to the four canonical values). Other fields unchanged.

#### Upgrade
Drop in `ion:0.10.19`. Migration runs automatically. No `.env` changes required.

## v0.10.18 (2026-04-27)

### Daily Standup DC/WEF checks — configurable + diagnostic

The Domain Controllers and Windows Event Forwarding widgets on `/standup` were silently rendering "No host data" in environments where:

1. The host-name patterns didn't match (`*DCS*` / `*WEF*` were hard-coded)
2. The ES field name was something other than `host.hostname.keyword` (e.g. `winlog.computer_name.keyword`, `agent.name.keyword`)
3. Events lived in a different index pattern than `winlogbeat-*` (e.g. `logs-windows.*`, `filebeat-*`, `.ds-logs-windows-*`)
4. ES was unreachable / auth was failing — the error response was masked as empty hosts

All four cases produced the same "No host data" UI, with no way to tell them apart.

#### Backend

`_check_log_source_health` is now driven by four env vars:
- `ION_STANDUP_LOG_INDEX` (default `winlogbeat-*`)
- `ION_STANDUP_HOST_FIELD` (default `host.hostname.keyword`)
- `ION_STANDUP_DCS_HOSTS` (default `*DCS*`) — comma-separated, OR'd together
- `ION_STANDUP_WEF_HOSTS` (default `*WEF*`) — same shape

Multiple patterns are allowed per check (e.g. `*DCS*,*DC*,*DOMAIN*`) — the query becomes a `bool > should` with `minimum_should_match: 1`.

Response now includes a `diag` block with the index, field, patterns, total hits, and host count actually used. Error responses include `type(e).__name__` so `ConnectError` / `TimeoutError` / `AuthenticationError` are distinguishable.

#### UI

`renderLogHealth` (in `daily_standup.html`) now distinguishes four states:
- **`status === 'error'`** → red banner with the actual error text
- **`status === 'not_configured'`** → amber banner with a hint to set env vars
- **Empty `hosts: []`** → existing "No host data" message **plus a diagnostic footer**: `Queried winlogbeat-* for host.hostname.keyword matching *DCS* · 0 hits / 0 hosts`
- **Hosts present** → existing widget grid, unchanged

The diagnostic footer is the load-bearing change — operators can see exactly what was queried and adjust env vars accordingly without redeploying.

#### Upgrade
Drop in `ion:0.10.18`. No schema changes. Defaults preserve v0.10.17 behaviour exactly. Set `ION_STANDUP_*` in `.env` if your hostnames or indices don't match the defaults.

## v0.10.17 (2026-04-27)

### CyAB onboarding wizard — full system creation in one transaction

The CyAB landing page now leads with **"Onboard a System"** (replaces v0.10.15's standalone "Assessment" button). It opens a six-step wizard that captures everything needed to bring a SOC system online — identity, contacts, system assessment, data sources, governance, and sign-off — and persists it all in a single transaction.

The original simple **"New System"** modal stays as a **"Quick stub"** button for the power-user "just create the row, fill it in later" path.

### Wizard steps

| # | Step | Captures |
|---|---|---|
| 1 | **System identity** | Name, department, business unit, reference (auto-generated if blank), version, status (Draft/Active/Decommissioned), data classification, tags |
| 2 | **Points of contact** | Department lead + email + phone, deputy + email, SOC team, SOC lead + email, SOC analyst owner, stakeholder distribution list, IR runbook URL |
| 3 | **System assessment** | The 8 per-system questions (criticality, data sensitivity, internet-facing, user access, BYOD, MFA, segmentation, monitoring) |
| 4 | **Data sources** | Multi-pick from the 13 pre-built templates (sysmon, Windows Security, firewall, EDR, etc.). Optional — submit zero is fine |
| 5 | **Governance & SLA** | SAL tier default, review cadence days, next review date |
| 6 | **Review & sign-off** | Summary preview + optional dept/SOC sign-off names + dates. Sign-off can be deferred — system created in DRAFT if blank |

### Backend

New endpoint `POST /api/cyab/onboarding` accepts a single JSON body and creates:
- One `CyabSystem` row with all identity + contact + governance fields
- N `CyabDataSource` rows from the chosen templates
- One `CyabSystemAssessment` row scored against the latest org-wide assessment + this system's overlay
- One initial `CyabSnapshot` so the trend chart has day-one data

All four writes happen in one DB transaction. Failure rolls everything back. Returns the new `system_id`, ranked top-10 use cases, and ranked threat actors so the UI can land directly on the system detail page with results visible.

### Schema additions to `CyabSystem` (10 nullable columns)

Adds `business_unit`, `data_classification`, `dept_lead_email`, `dept_lead_phone`, `dept_deputy_name`, `dept_deputy_email`, `soc_lead_email`, `soc_analyst_owner`, `stakeholder_distribution` (Text), `ir_runbook_url`.

Idempotent `ALTER TABLE ADD COLUMN` migration in `database.py` (matches existing pattern). All columns nullable so pre-v0.10.17 rows stay valid. `Base.metadata.create_all` handles fresh deployments.

### Verification done locally
Migration tested end-to-end on a populated database: dropped a column, restarted, confirmed the migration log fired (`Migrated: cyab_systems.business_unit`) and the column re-added without affecting existing rows.

### Upgrade
Drop in `ion:0.10.17`. No `.env` or compose changes required. New columns auto-add on first boot.

## v0.10.16 (2026-04-27) — HOTFIX

### Assessment endpoints 404'd in v0.10.15

The 8 new assessment routes added in v0.10.15 declared their paths as `/api/cyab/assessment/...` etc. inside `cyab_api.py`. But that router is included in `server.py` with `prefix="/api/cyab"`, so paths are relative — every existing route uses `@router.get("/systems")`, `@router.get("/dashboard")`, etc. The new routes ended up registered at `/api/cyab/api/cyab/assessment/...` (doubled prefix), so the wizard's `GET /api/cyab/assessment/questions` returned a 404 and the UI showed "failed to load questions".

Fixed by stripping `/api/cyab` from the eight new route decorators. No behavioural change otherwise — the wizard, scoring, persistence, and per-system endpoints all work as designed in v0.10.15.

Drop-in upgrade from v0.10.15. No schema or `.env` changes.

## v0.10.15 (2026-04-27)

### CyAB use-case discovery questionnaire — Stream B foundation

New "Assessment" entry-point on the CyAB landing page. A 4-step wizard captures the org's profile (sector, geo, regulated data, public exposure), tech stack (endpoint OS, cloud, identity, email, OT), existing controls (MFA, EDR, backup, awareness), and concerns (top 3 worries, prior incidents, internet exposure) — 17 questions total, mostly yes/no/dropdown so a non-technical respondent can answer in 5–10 minutes.

Submit → ranked top-10 SOC use cases pulled from TIDE's playbook catalogue, each with a score breakdown and human-readable "why this is here" reasons (`You marked 'ransomware' as a top concern`, `MFA control is weak — this playbook covers techniques that exploit that gap`). Plus top-5 threat actors curated by sector with rationale.

Scoring is four weighted sub-scores (out of 100):
- **TA** (threat-actor relevance, 0–40) — sector-implied concern keywords + prior-incident keywords + public-profile multiplier
- **ST** (stack applicability, 0–20) — playbook platform mentions vs answered stack
- **CG** (control-gap penalty, 0–20) — boost when weak controls overlap with playbook coverage
- **CB** (concern boost, 0–20) — direct keyword match of top-concern values against playbook name/description

### Models + persistence

Two new tables (created via `create_all` on first boot — no migration needed):
- `cyab_assessments` — org-wide submissions; **immutable**, one row per submit
- `cyab_system_assessments` — per-`CyabSystem` overlays; same immutability shape; nullable FK to the org-assessment that was current at submit

Every submission stores `responses_json`, `computed_profile_json`, `ranked_use_cases_json`, and `ranked_actors_json`. Older versions stay queryable for trending posture quarter-over-quarter.

`schema_version` column tracks which question set the responses were captured against, so future tweaks to the question list don't break replay of older submissions.

### Endpoints

- `GET /api/cyab/assessment/questions` — current question schema
- `POST /api/cyab/assessment` — submit + compute results
- `GET /api/cyab/assessment` — list past submissions (no result blob)
- `GET /api/cyab/assessment/latest` — most recent with results
- `GET /api/cyab/assessment/{id}` — full detail
- `POST /api/cyab/systems/{system_id}/assessment` — per-system submit (overlays latest org profile)
- `GET /api/cyab/systems/{system_id}/assessment` — per-system list
- `GET /api/cyab/systems/{system_id}/assessment/latest` — per-system latest

### Out of scope this ship — coming in v0.10.16
- **Per-system assessment UI** — model + endpoint + scoring work end-to-end via the API, but the per-system 8-question wizard isn't wired into the system detail page yet. Use the org-wide assessment now; per-system overlays land next ship.
- **Trending UI** — past submissions are persisted but no diff-vs-previous view yet.
- **OpenCTI cross-reference** — actor list is sector-curated for MVP; OpenCTI lookup is in the design but deferred (sector + concern-driven curation already works for typical SOCs).

### Upgrade
Drop in `ion:0.10.15` — no schema migration, no `.env` change. Both new tables auto-create on first boot.

## v0.10.14 (2026-04-27)

### CyAB system detail — baseline coverage view (replaces MITRE heatmap)

The system detail page's coverage panel previously rendered a MITRE ATT&CK tactic heat-grid (4-column tactic boxes with %). Useful for ATT&CK-aligned reporting but useless for the actual analyst question — *"why is this step covered, and which rule covered it?"*

Replaced with a **baseline coverage view** that surfaces TIDE's full assurance-baseline model: each TIDE playbook (use case) is a collapsible card; inside, each step shows its state (covered / partial / blind), its MITRE techniques (with covered vs gap colour-coding), and crucially the **TIDE-recommended detection rules per step + the analyst's "why covered" note** straight from the `step_detections.note` column.

Each detection rule under a step is tagged **APPLIED** or **NOT APPLIED** — so a "blind" step makes the gap actionable: "rule X is recommended here but not live on this system, apply it to close the gap."

Cards default to expanded for `partial`/`blind` use cases (the actionable ones) and collapsed for `covered` (read-only confirmation).

The MITRE heatmap is **kept** but demoted to a "Show MITRE ATT&CK heatmap" toggle below the baseline view — still there for ATT&CK-style reporting, just not the primary signal.

### Backend

`get_system_use_case_coverage` already pulled `step_detections.note` via `get_playbooks_with_kill_chains` but discarded it from the per-step output. Now:

- Pulls the system's literal applied `detection_id` set in addition to the technique set
- Returns `detections: [{rule_ref, note, source, applied}]` per step, with `applied` cross-referenced against the system's actual rule application
- No SQL added (data was already coming through `get_playbooks_with_kill_chains`); only the per-step output shape changed
- Payload size grows ~2-5× per call (option A from the design discussion); acceptable given the per-step rule list is what makes the view useful

### No schema or compose changes
Drop in `ion:0.10.14` alongside existing volumes — no migration, no `.env` updates required.

## v0.10.13 (2026-04-23)

### Arkime — PCAP timeout + alert-anchored IP search (hours-old alert fix)

Production logs from a real air-gapped deploy surfaced two related bugs after v0.10.10's fallback loosening started actually exercising the IP path.

#### 1. PCAP download was cut off at 60 s
`download_pcap` shared the 60 s session-search client. Arkime assembles PCAPs server-side by walking capture files, and a busy session easily needs 30-120 s to produce before transfer even starts. The short timeout fired mid-stream and surfaced `ArkimeError: Arkime PCAP download error:` — blank — to operators because `str(httpx.ReadTimeout())` is empty.

- New `_pcap_client()` with a dedicated longer timeout (default 300 s)
- Tunable via `ION_ARKIME_PCAP_TIMEOUT_S` in `.env`
- All three Arkime httpx error wrappers now include `type(e).__name__` so `ReadTimeout` / `ConnectTimeout` / `SSLError` / `ConnectError` are all distinguishable in logs

#### 2. IP search window was anchored to `now`, not the alert timestamp

`find_sessions_by_ip` used `startTime = now - 2h`, `stopTime = now`. For a 24/7 SOC this is fine; for non-24/7 ops (most SOCs) investigating an 8-hour-old alert, the window misses the traffic entirely. The search would succeed — return zero sessions — and the workflow would dead-end at "no sessions found".

Fixed by anchoring the window on the **alert timestamp** ± `window_minutes` (default 30 min):

```python
# Before (busted for late investigations):
startTime = now - 2h
stopTime = now

# After (v0.10.13):
alert_epoch = parse(alert["@timestamp"])
startTime = alert_epoch - 30min
stopTime = alert_epoch + 30min
```

- `find_sessions_by_ip` gains `alert_timestamp` + `window_minutes` kwargs
- Default window tunable via `ION_ARKIME_IP_SEARCH_WINDOW_MIN` (default 30)
- Legacy `hours` kwarg kept for back-compat (converted to `hours × 60` minutes)
- Falls back to a now-anchored window only when the alert has no parseable timestamp
- INFO log now shows the anchor: `Arkime IP search: expression=... window=±30min anchor=alert_ts=1745389524 limit=10`

As a side effect, the narrower window (60 min total vs 120 min) also reduces the PCAP size Arkime has to assemble — directly compounding with the timeout fix for the typical case.

### `.env.deploy`
Two new optional settings documented in the Arkime section:
- `ION_ARKIME_PCAP_TIMEOUT_S=300`
- `ION_ARKIME_IP_SEARCH_WINDOW_MIN=30`

### Upgrade notes
Drop-in for v0.10.12 — no schema, no compose changes required.

## v0.10.12 (2026-04-23)

### AI Scorecard — per-template accuracy dashboard

New admin page at `/ai-scorecard` (linked from the user dropdown → Admin → AI Scorecard). Pulls from the existing `/api/alert-prompts/scorecards` endpoint and joins template names client-side from `/api/alert-prompts`.

Rows sort tuning-needed templates first. Agreement % is colour-coded (green ≥ 80%, amber ≥ 60%, red below). A template with sample size ≥ 10 AND agreement < 60% is flagged `NEEDS TUNING`. Templates under 10 samples show `LOW SAMPLE` so analysts don't chase noise. KPI strip at top: template count, total feedback rows, weighted overall agreement, count flagged for tuning. Window is selectable (7 / 30 / 90 / 365 days).

"Edit" column links straight into the prompt editor anchored to that template.

### Grounded evidence display

`key_observations` (added to the output contract in v0.10.11) now renders in two places:

1. **Investigation memory modal** — new "Key observations (grounded evidence)" section between Summary and Recommended actions. Each entry shows the cited field in cyan monospace, the exact value, and Bob's stated significance.
2. **Bob's auto-posted case/alert note** — bulleted list below the summary, formatted as `` `process.command_line` = `powershell -enc ...` — obfuscated base64 payload``.

Both gracefully fall back when `key_observations` is null (investigations from before v0.10.11 still render fine, just without the evidence section).

`InvestigationDetail` API response gains three fields: `key_observations`, `prompt_snapshot`, `raw_response`. The last two are how the per-template training loop will eventually surface "show me the prompt+response behind this disagreement".

### Self-consistency sampling (opt-in via `ION_INVESTIGATION_SAMPLES`)

Default remains 1 (single-pass, cheapest — indistinguishable from v0.10.11). Set to 2 in `.env` to enable:

- Two LLM passes per investigation with different seeds (42, 1337).
- **Verdicts agree** → first result used, confidence bumped one level (low→medium, medium→high). The sampling metadata is recorded on the parsed payload.
- **Verdicts disagree** → verdict forced to `inconclusive`, `suggested_closure_reason=insufficient_data`, confidence=low. The summary is prefixed `[Self-consistency disagreement — samples: X, Y]`. Better to admit ambiguity than coin-flip a confident wrong answer.
- Max 3 samples. Decision is logged at INFO (`Self-consistency OK` / `FAILED`) with the verdict list.
- Cumulative `duration_ms` reflects total wall-clock across samples. `raw_response` concatenates every sample separated by `===SAMPLE-BOUNDARY===` so the training loop can inspect each.

Tradeoff: 2-3x investigation latency. Run this on templates that have already been through the accuracy dashboard and appear in the `NEEDS TUNING` cohort — for well-behaved prompts, single-seed is fine.

### Upgrade notes
- No schema changes on top of v0.10.11
- Pull `ion:0.10.12`; no `.env` edits required to adopt the scorecard or evidence display
- `ION_INVESTIGATION_SAMPLES` must be explicitly set to 2 or 3 to opt into self-consistency — absent/1 keeps today's behaviour

## v0.10.11 (2026-04-23)

### Bob investigation quality — the "wild verdicts" fix

Same alert from the same host was producing wildly different verdicts across investigations. Three compounding root causes fixed in this release.

#### 1. Prompt starvation — expanded alert summary
Bob was seeing only 7 fields: `rule_name, host, source_ip, user_name, timestamp, severity, alert_id`. That's not enough context to reach a grounded verdict — the model was confabulating to fill the gap, and small models (qwen2.5:3b default) hit different fabrications on each call.

Expanded to ~40 fields, emitted only when present (no null noise). Additions: `kibana.alert.reason` (the human-readable one-liner), `destination_ip` + `destination_port` + `network.*`, full `process.*` tree (name, command_line, executable, pid, sha256 + parent process), `file.*` (path, name, hashes), `url.*`, `dns.question.*`, `http.*`, `user_agent`, `event.action` + `event.category` + `event.code` + `event.outcome` + `event.module` + `event.dataset`, `user.domain` + `user.email` + target user, host OS info, and — load-bearing — the actual **rule query text** (`kibana.alert.rule.parameters.query`) so Bob knows *what the rule was looking for*, not just its name.

Trade-off: prompts are larger, so `num_predict` is bumped from the default to 2048. Investigation calls take longer — the user signed off on slower-but-right.

#### 2. LLM non-determinism
Investigation Ollama calls ran with `temperature=0.7` and no `seed` / `top_p` / `top_k` pins. Same prompt literally sampled different tokens on every call. Accuracy was unmeasurable under random verdict drift.

Pinned to `temperature=0.0, seed=42, top_p=0.1, top_k=1`. Same alert in = same verdict out. The sampler is fully deterministic when ION drives the call; interactive chat UX (different code path) keeps the old defaults so conversational Bob isn't robotic.

`OllamaService.chat()` gained `seed`, `top_p`, `top_k` keyword parameters — passed through to Ollama's `options` dict only when set, so no behaviour change for callers that don't pass them.

#### 3. Unauditable reasoning → grounded evidence bullets
The output contract had `analyst_explanation` and `technical_details` (prose), but nothing forced the model to tie its verdict to specific alert fields. New mandatory field:

```jsonc
"key_observations": [
  {"field": "process.command_line",
   "value": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
   "significance": "obfuscated base64 payload — common for
                    living-off-the-land execution"}
]
```

Rule 5 of the Output Contract now requires every `key_observations` entry to cite a field that literally appears in `alert_summary`. If there's no supporting evidence in the alert, verdict MUST be `inconclusive`. This kills the "confident nonsense" failure mode where Bob asserted a verdict the alert data didn't support.

#### 4. Training loop foundation — persist prompt + response

`Investigation` table gains three nullable TEXT columns (idempotent ALTER TABLE):
- `prompt_snapshot` — full rendered user prompt sent to Ollama
- `raw_response` — model's raw output before any parsing
- `key_observations_json` — parsed evidence bullets

AIFeedback rows already link to `investigation_id`, so per-template accuracy queries can now JOIN to the exact prompt and response that led to each disagreement. Without this, "Bob was wrong N% of the time" was countable but undebuggable — you couldn't see *what* he saw. This is the prerequisite for the Tier-1 automatic prompt-refinement work.

Pre-v0.10.11 investigations stay NULL in the new columns. Hard-capped at 100 KB per column to prevent runaway prompts from bloating the DB.

### Upgrade notes
- Idempotent migration — safe to pull `ion:0.10.11` alongside existing v0.10.10 Postgres + Ollama volumes
- Investigation latency will increase. Expected. Verdict quality was the asked-for trade
- If you want the old chatty sampler for investigations, there is no flag — revert the pinned values in `_call_llm` yourself

## v0.10.10 (2026-04-23)

### Arkime PCAP fallback — loosened gate + diagnostic logging
- Preview endpoint now falls back to IP search on **any** `ArkimeError` when the alert has `source_ip` or `destination_ip`, not just `status_code == 404`. Covers the empty-result case, viewer 5xx, and timeouts — previously these returned 404 to the user even when IP search could have resolved the PCAP.
- Every community_id→IP fallback decision is logged at INFO with alert id, error, and `has_ips` flag so `docker logs ion | grep -i arkime` makes the decision tree visible.
- `find_sessions_by_ip` now emits an INFO log on every call (mirrors the existing community_id search log). Without it, IP-path calls were silent.
- Error message for "Arkime not configured" no longer mentions Keycloak — now names the actual env vars (`ION_ARKIME_URL` + `ION_ARKIME_USERNAME` + `ION_ARKIME_PASSWORD`).

### Arkime service — obsolete code removal
- Dropped Keycloak/OAuth2 module docstring (never implemented — v0.10.4 locked auth to HTTP Basic only).
- Removed unused `_arkime_client` module-level `httpx.AsyncClient` (never assigned; shared clients were abandoned when digest was ripped out).
- Removed `_auth()` method (returned `None` always — vestigial from the `httpx.BasicAuth` / `httpx.DigestAuth` era). Auth is sent exclusively via the `Authorization: Basic <base64>` header in `_headers()`.
- Stripped all `auth=self._auth()` call sites.
- Simplified stale `_client()` docstring (no more digest challenge/response).
- Cleaned up stale `reset_arkime_service()` body — no more `_arkime_client.aclose()` dance.
- Trimmed `Arkime PCAP GET` log line — dropped the now-useless "auth scheme=…" suffix.

### Why this matters
v0.10.9 users reported "PCAP only works via community_id". The real cause wasn't the node filter (reported node names matched Arkime's stored node exactly in the reported environment) — it was the fallback gate checking only `status_code == 404`, which missed empty-result and non-404 error cases. Combined with the silent IP-search path, operators had no way to diagnose what decision the code was making. Both issues are fixed in this release.

### No schema / config / image-layout changes
Drop in `ion:0.10.10` alongside the existing v0.10.9 postgres and ollama volumes — no migration required.

## v0.10.9 (2026-04-22)

### Air-gapped deployment — full bundle rebuild
- `scripts/build-offline-package.sh` rewritten for v0.10.4+ stack:
  - Adds `pgvector/pgvector:<PG_VERSION>` image (was missing — plain postgres has no pgvector binaries)
  - Adds `nomic-embed-text` model alongside the chat model in the Ollama volume export (was missing — case-similarity + KB RAG silently no-op without it)
  - Emits `MANIFEST.sha256` so the air-gapped side can verify transit integrity
  - Stamps the bundled `.env` with the ION/PG/model versions that were built, so compose defaults can't drift
  - Removed stale SQLite init path from the deploy helper (ION has been Postgres-only since v0.9.43)
- **New** `scripts/load-offline-package.sh` — runs on the air-gapped side. Verifies manifest, loads all three images, restores the Ollama models volume with project-name auto-detection, prints next-step commands. Idempotent.
- Signatures:
  - `./scripts/build-offline-package.sh [ion_version] [chat_model] [pg_version]`
  - `./scripts/load-offline-package.sh` (run from bundle dir)

### PG_VERSION env var
- `docker-compose.yml` postgres line is now `image: pgvector/pgvector:${PG_VERSION:-pg16}` so deployments on pg15/pg17/pg18 can pin via `.env` without hand-editing compose every time they pull
- Default stays `pg16` for fresh deploys

### Docs
- `SETUP.md` "Air-Gapped / Siloed Deployment" section rewritten — covers the three-image/two-model reality, PG_VERSION, build + load scripts, the silent-failure mode when `nomic-embed-text` is missing, and why partial upgrades break
- Makes explicit: from v0.10.4+, you cannot upgrade an air-gapped deployment by shipping just the ION image — the bundle must be rebuilt

### No app code change
All v0.10.9 changes are in compose/scripts/docs. The ION application image is byte-equivalent to v0.10.8 for users who just want to pull `latest` and keep going.

## v0.10.8 (2026-04-22) — HOTFIX

### Fresh-deploy crash: `type "vector" does not exist`
- `init_db()` was running `Base.metadata.create_all(engine)` BEFORE `_run_migrations()`
- `create_all` tries to create the `case_embeddings` and `kb_document_embeddings` tables (which carry `VECTOR(768)` columns), but pgvector's `vector` type doesn't exist in a fresh Postgres until `CREATE EXTENSION vector` runs — which was happening inside `_run_migrations()`, too late
- **Only affects fresh deployments** of v0.10.4+ (where the volume is empty on first boot). Incremental upgrades that evolved through 0.10.3 → 0.10.4 worked because the extension was enabled at migration time and the tables were added after
- **Fix:** run `CREATE EXTENSION IF NOT EXISTS vector` in `init_db()` BEFORE `create_all`. The same statement still runs inside `_run_migrations()` too (idempotent, no harm)

### Who needs this
- Anyone deploying ION fresh (empty postgres volume) on v0.10.4, 0.10.5, 0.10.6, or 0.10.7 hit this crash
- Anyone already running a healthy 0.10.4+ stack is unaffected

## v0.10.7 (2026-04-22)

### Ollama model residency — avoid swap tax on investigations
- `docker-compose.yml`: `OLLAMA_MAX_LOADED_MODELS` default raised from 1 → 2 (now env-overridable via `${OLLAMA_MAX_LOADED_MODELS:-2}`)
- Rationale: every investigation calls `/api/embed` (nomic-embed-text) then `/api/chat` (chat model) back-to-back. With only 1 loaded model, Ollama was evicting and reloading on each call, adding ~5-15s per investigation depending on chat-model size
- At 2 the residency budget is ~2.3GB for the default pair (qwen2.5:3b ~2GB + nomic-embed-text ~274MB) — well under the 8GB Ollama container cap
- Bump higher via `.env` (`OLLAMA_MAX_LOADED_MODELS=3`) if you run a second chat model (e.g. a larger one for deep investigations) OR a reranker. Mind the container memory limit

### Env vars
- `OLLAMA_MAX_LOADED_MODELS` (default 2)

## v0.10.6 (2026-04-22)

### KB RAG grounding for Bob (Bet A of the air-gapped roadmap)
- New `kb_document_embeddings` table (document_id PK + VECTOR(768) + model_name + embedded_at + source_text_hash) with HNSW index on `vector_cosine_ops`
- New background loop on advisory lock `LOCK_KB_EMBEDDING_BG=1020` (default 5-min interval, batched 20/tick) — embeds Documents under the "Knowledge Base" collection tree (recursive CTE to find descendants)
- Embeds `name + first 8000 chars of rendered_content` via the same `EmbeddingService` / `nomic-embed-text` pipeline used for case embeddings
- Re-embeds when source text hash drifts (KB article edited)
- At investigation time, Bob's prompt gets up to 3 KB articles most similar to the alert (cosine similarity ≥ 0.65 — looser than gold exemplars since KB is topic-level doc)
- Rendered as "## Knowledge Base Context" section in `render_system_prompt()`, placed BEFORE "Prior Similar Cases" — priority order is: per-rule playbook → KB grounding → prior cases → output contract
- **100% air-gapped compatible** — same local Ollama model, no external dependencies
- Opt-in: `ION_KB_RAG_ENABLED=true` (default off, same rationale as case embedding)

### Env vars
- `ION_KB_RAG_ENABLED` (default false — opt-in)
- `ION_KB_EMBEDDING_INTERVAL_S` (default 300)
- `ION_KB_EMBEDDING_BATCH` (default 20)

### Depends on
- v0.10.4 pgvector infrastructure + `ION_EMBEDDING_ENABLED=true`
- `nomic-embed-text` pulled in Ollama
- KB seeded (the `seed_knowledge_base` hook runs on startup — ~392 articles under 28 child collections)

### Ops notes
- No existing-deployment migration needed beyond `create_all()` picking up the new table
- Embedding the full ~392 article KB takes roughly 2-3 background passes (20/tick) = ~15 minutes the first time ION boots with the flag on
- After first pass, only changed articles re-embed

## v0.10.5 (2026-04-22)

### Few-shot gold exemplars for Bob (Bet B of the roadmap)
- When an alert is investigated, pgvector-retrieve up to 3 past closed cases that:
  - have `closure_reason IS NOT NULL` (human-closed)
  - AND have at least one `AIFeedback` row with `agreement=true` (Bob and the human agreed on the verdict)
  - AND exceed cosine similarity 0.7 to the current alert
- Inject retrieved cases as a new "Prior Similar Cases (analyst-verified)" section in Bob's system prompt, placed immediately before the Output Contract
- Uses the existing `EmbeddingService` (nomic-embed-text) and `case_embeddings` table — no new infrastructure
- Alert text serialisation aligned with `case_embedding_service._case_source_text` so vectors are directly comparable
- **Opt-in: set `ION_FEW_SHOT_EXEMPLARS_ENABLED=true` in .env.** Default off because fresh installs have no `AIFeedback` rows — the retrieval returns nothing until the ledger populates from real case closures

### Bob closed-case guard
- `_write_bob_outputs()` now short-circuits when the alert's `AlertTriage` row is `CLOSED` **or** its parent `AlertCase` is `CLOSED` — prevents AI-authored Notes, suggested_verdict updates, observable writes, or tuning proposals from landing on closed case timelines when investigations are re-run (force=True, manual retrigger)
- INFO-level log line records which condition tripped, for audit

### Env vars
- `ION_FEW_SHOT_EXEMPLARS_ENABLED` (default false — opt-in)

### Depends on
- v0.10.4 pgvector infrastructure
- `ION_EMBEDDING_ENABLED=true` + `nomic-embed-text` pulled in Ollama

## v0.10.4 (2026-04-22)

### pgvector + case similarity (Bet 1 of the roadmap)
- Postgres image swapped `postgres:16-alpine` → `pgvector/pgvector:pg16` (data-compatible PG16, preinstalled extension)
- `CREATE EXTENSION IF NOT EXISTS vector` added to `_run_migrations()` — idempotent, runs before create_all
- `pgvector>=0.3.0` added to Python deps for SQLAlchemy types
- New `case_embeddings` table (case_id PK + embedding VECTOR(768) + model_name + embedded_at + source_text_hash) with HNSW index on `vector_cosine_ops`
- `EmbeddingService` wrapping Ollama's `/api/embed` endpoint (default `nomic-embed-text`, 768-dim). Graceful degradation — Ollama unreachable = no-op, silent retry next tick
- Background loop under advisory lock `LOCK_CASE_EMBEDDING_BG=1019`, embeds cases every 5 min (batched at 50). Source text = title + description + hosts + users + rules + evidence_summary + Bob's latest investigation summary. Re-embeds when source hash changes
- `GET /api/elasticsearch/alerts/cases/{id}/similar` — pgvector cosine distance via ORM `.cosine_distance()`, filters to `closure_reason IS NOT NULL` (real human-closed cases only)
- "Similar Closed Cases" sidebar on case detail panel — colour-coded closure_reason badges (TP red, FP green, BTP amber), similarity % shown. Clickable cards pivot to the similar case

### Fixes
- `Investigation.alert_id_ref` / `summary_text` (correct field names) — had used wrong `Investigation.alert_id` / `.summary` in `ai_feedback_service.py` and `case_embedding_service.py`. Both now reference the right columns
- Similarity SQL uses pgvector ORM (`Vector.cosine_distance(target)`) instead of raw SQL with `str(target.embedding)` — numpy's default string representation is unparseable by pgvector

### Env vars
- `ION_EMBEDDING_ENABLED` (**default false** — opt-in; set to `true` to enable)
- `ION_EMBEDDING_MODEL` (default `nomic-embed-text`)
- `ION_CASE_EMBEDDING_INTERVAL_S` (default 300)
- `ION_CASE_EMBEDDING_BATCH` (default 50)

### Arkime auth lockdown
- Reverted Arkime to **Basic-only**. Digest and API-key code paths removed. `ION_ARKIME_AUTH_MODE` + `ION_ARKIME_API_KEY` env vars are now ignored. If you need something else, front Arkime with nginx + Basic.
- Added INFO-level logs for `Arkime community_id search` expression and `Arkime PCAP GET` URL so failing requests can be traced via `docker compose logs ion | grep Arkime`.

### Ops note
- Existing deployments: volume is retained across the Postgres image swap (same PG16). First boot on 0.10.4 adds the pgvector extension + case_embeddings table idempotently.
- **Embedding is off by default.** To enable case similarity: (1) run `docker exec ion-ollama ollama pull nomic-embed-text` (~300 MB, one-time), (2) set `ION_EMBEDDING_ENABLED=true` in `.env`, (3) restart ION.

## v0.10.3 (2026-04-22)

### AI Analyst — "Bob"
- New service user `bob` + role `ai_analyst` — AI-authored artefacts (notes, observables, tickers, tuning proposals) attribute to a single identity
- `User.is_service_account` column — login flow rejects service accounts early
- New permissions: `alert:comment`, `case:comment`, `case:link`, `ticker:read/create/manage`, `tuning:read/review`, `investigation:run`
- Bob auto-posts a markdown investigation summary to the alert Notes timeline
- Bob writes `suggested_verdict` + `suggested_verdict_confidence` onto `AlertTriage` (matches `CaseClosureReason` for 1:1 comparison)
- Bob auto-extracts high-confidence IOCs from the JSON envelope as `Observable` rows tagged `source:bob`
- Bob auto-files a `TuningProposal` when verdict is `false_positive` with a concrete `suggested_change`

### MITRE-tiered alert-prompt matcher + canonical output contract
- `AlertPromptTemplate` gains `mitre_techniques_json` + `mitre_tactics_json`
- Matcher now 5-tier: exact rule_id → regex → MITRE technique (parent↔sub tolerant) → MITRE tactic → `rule.groups`
- Canonical JSON output envelope pinned to ION's `CaseClosureReason` — verdict, confidence, severity, analyst_explanation, technical_details, mitre, iocs, recommended_actions, `suggested_closure_reason`, `tuning_recommendation` (the detection-engineering feedback bridge)
- Ollama `format: "json"` wired through `OllamaService.chat(response_format=…)` so investigations emit strict JSON
- 50 seeded prompt templates (25 existing + 12 new Sysmon events from Talon + 3 Talon Windows categories + 10 new coverage categories: Entra ID, Okta, MFA fatigue, K8s runtime, CI/CD abuse, macOS persistence, Zeek, DB access anomaly, session hijack, supply-chain)
- Sysmon 1/3/11 upgraded with exact Wazuh field refs, VirusTotal URL pattern, and a P1/P2/P3 Velociraptor artefact table (Event 1)

### Ticker
- New `Ticker` + `TickerDismissal` models
- Background producer (advisory lock `LOCK_TICKER_BG=1018`): flags critical alerts not assigned to a case after `ION_TICKER_CRITICAL_NO_CASE_MIN` minutes (default 10); auto-resolves when the alert is cased
- REST API + `/tickers` manage page; sticky strip below nav on all pages; critical entries non-dismissable (auto-resolve only)
- Env: `ION_TICKER_ENABLED`, `ION_TICKER_INTERVAL_S`, `ION_TICKER_CRITICAL_NO_CASE_MIN`

### Tuning proposals
- `TuningProposal` model + API + `/tuning-proposals` page
- Accept/reject/duplicate workflow, auto-created from Bob's FP verdicts

### Training foundation (Tier 1)
- `AIFeedback` ledger — captures `bob_suggested_verdict` vs `human_verdict` on case close, with agreement flag and optional delta reason
- Per-template scorecard on `/alert-prompts`: 30-day agreement %, FP/BTP/TP rates, "tune" flag when agreement < 60 % on 10+ samples
- `GET /api/alert-prompts/scorecards` endpoint

### Docs & tests
- `docs/AI_OUTPUT_CONTRACT.md` — full output schema reference
- `tests/test_alert_prompt_matcher.py` — matcher unit tests (18 cases)

## v0.9.43 (2026-04-07)
### Security Hardening
- Circuit breakers on ES, OpenCTI, TIDE, Ollama, Kibana external calls
- Startup config validation — fail fast on missing/invalid settings
- Rate limiting on escalation (10/min), bulk ops (20/min), token regen (3/min)
- Fix: Docker networking (explicit bridge network for all services)
- Fix: Remove ION_DATABASE_URL from Dockerfile build ENV
- Fix: Don't force password change when custom admin password is set

### Deployment
- `.env.deploy` template for siloed/air-gapped environments
- `build: .` commented out in docker-compose (pull pre-built image)
- Better entrypoint error messages with DNS pre-check
- PostgreSQL-only Docker image (SQLite fallback removed from container)
- Updated README, SETUP, SECURITY_ASSESSMENT, DEPLOYMENT_GUIDE

## v0.9.42 (2026-04-07)
- SLA Management — severity-based response time targets, compliance tracking
- Bulk Operations — multi-select alert acknowledge/assign/close
- Threat Hunting Workbench — hypothesis-driven hunting with queries/findings/IOCs
- Dashboard Widget Customization — 12 widgets, role-filtered, per-user layout
- Reporting Scheduler — daily/weekly/monthly auto-generated reports
- Automated Playbook Actions — 6 response actions with approval workflow

## v0.9.41 (2026-04-07)
- On-Call / Duty IM Escalation Manager — roster, escalation, notification
- Service Account Tracker — password age, risk levels, stale detection
- Incident Cost Calculator — analyst hours, downtime cost, per-severity
- NIST CSF Compliance Mapping — 13 controls mapped to TIDE rules
- Communication Templates — 6 pre-seeded incident notification templates
- Change Log — config/rule change tracking with approval and rollback
- Saved Searches / Bookmarks — personal workspace customization
- Navigation reorganized from 5 dropdowns to 4 focused groups

## v0.9.40 (2026-04-07)
- Interactive Training Guide (`/guide`) with visual UI mockups
- Training Simulator (`/guide/sim`) with 8 scored scenarios
- Fix: PCAP threat intel enrichment crash on None score
- Fix: Social hub emoji reactions (in-place update)
- Fix: Self-assessment section collapse state preservation

## v0.9.39 (2026-04-07)
- Attack Stories — alert correlation into multi-step narratives
- Case Similarity — find similar past cases by matching patterns
- Automated Triage Suggestions — historical closure data recommendations
- MITRE ATT&CK Navigator Export — one-click layer JSON download
- Playbook Effectiveness Analytics
- Alert Pattern Detection — persistent, periodic, burst, sporadic
- Executive Weekly Report — PDF/HTML with trends and metrics
- IOC Staleness Tracker — flag observables needing re-enrichment

## v0.9.38 (2026-04-07)
- Unified CSS severity/MITRE/quality design system variables
- Country flag attribution for threat actors
- Shift Handover Report — auto-generated end-of-shift summary
- Rule Tuning Feedback Loop — FP-heavy, high-value, silent rules
- Entity Timeline — unified cross-source timeline
- Analyst Efficiency Dashboard — MTTR, FP rates, per-analyst
- SOC Health Scorecard — 5-dimension maturity assessment (A-F)
- Threat Watch Auto-Gap Alerting

## v0.9.37 (2026-04-06)
- Detection Engineering page — 7 tabs (TIDE + ES + OpenCTI)
- TIDE system selector, actor readiness, PDF reports
- Docker `get_config()` fix for fresh DB path resolution

## v0.9.34 (2026-04-06)
- Kibana multi-alert fix, AI document generator
- Security hardening (open redirect, ES system index blocking, 50MB upload)
- Chat redesign, PDF export, data flow visualization

## Earlier versions
See [progression.md](docs/progression.md) in the memory directory for full v0.9.0–v0.9.33 history.
