# CyAB Onboarding — Research Dossier

_Source-of-truth for the v0.12 CyAB redesign. Read fully before any code._

> **User-facing name:** **CyAB Onboarding** (the page tab, the
> Onboarding Pack PDF heading, etc.).
> **Internal code identifier:** `studio` (URLs, Jinja partials,
> service modules) — chosen to disambiguate from the pre-existing
> `POST /cyab/onboarding` legacy wizard route, which stays put.

Authored 2026-04-29, ION at v0.11.21.
Inputs: (a) Gemini "SOC System Onboarding Documentation Standards" PDF
(48 citations, NIST SP 800-61/800-92, SANS PICERL/Detection Engineering,
MITRE 11 Strategies, CREST, ISO 27035), (b) the React mockup
"SOC Onboarding Engine v4.0" supplied by the user, (c) the current ION
CYAB feature mapped at v0.11.21.

---

## 1. Executive summary

ION's existing **CYAB (Cyber Assurance Baseline)** is mature: a
6-step wizard, system + data-source CRUD, immutable assessments
(17 org + 8 per-system questions), TIDE-backed MITRE coverage and
threat-actor readiness PDFs, 12 data-source templates, and an
ES-alert namespace resolver. It already does the *strategic*
half of SOC system onboarding well.

What it does **not** yet do is the *technical, sub-profile-specific*
half that gold-standard onboarding requires:

1. A **pillar / sub-profile taxonomy** — Identity → AD vs. Entra,
   Endpoint → Windows vs. Linux, etc. ION today has only the flat
   `data_source_type` string and SYSTEM_ICONS dict.
2. **Sub-profile-specific technical intake questions**. Today's
   per-system questions (`sys_internet_facing`, `sys_mfa`,
   `sys_segmentation`, `sys_monitoring`) are platform-agnostic.
   Onboarding an AD domain controller and onboarding a Linux server
   ask the same eight questions. Operators need things like *"Is
   the AD Recycle Bin enabled?"* and *"Is auditd configured for
   syscall tracking?"*.
3. **Curated detection libraries per sub-profile**. ION's TIDE
   integration shows what playbooks/rules exist after onboarding;
   it does not present a pre-built, expectation-setting catalogue
   of *"here are the detections you should have for an Active
   Directory before this system is considered onboarded"*.
4. **Curated audit / compliance libraries per sub-profile**. Same
   gap, separated from threat detections (GPO tampering, sudoers
   edits, firewall any-any rules).
5. **A single Use Case detail anatomy** — logic, SOAR playbook,
   MITRE mapping — on one card.
6. **An "Onboarding Pack" export** that bundles intake answers,
   detection coverage, and audit coverage into a signed PDF for
   department sign-off — gold-standard charter / ISMS evidence.

The redesign — codenamed **CYAB Onboarding Studio** — adds these
six things on top of the existing CYAB without breaking the
CyabSystem, CyabDataSource, CyabAssessment, or CyabSnapshot tables.
Every existing route keeps working.

Ship target: **v0.12.0**, behind a feature-flag-free hard cutover
on the `/cyab` page. The existing 6-step wizard becomes the
governance/strategic intake; the new Onboarding Studio becomes the
technical intake. Both feed the same CyabSystem.

---

## 2. Why redesign now

Three concrete pulls:

**(a) Gemini gold-standard frame.** The PDF, citing MITRE 11
Strategies and NIST/SANS frameworks, is unambiguous on the
prioritisation hierarchy: *Identity (1) → Endpoint+Network (2) →
Cloud (3) → App (4)*. ION's wizard does not present onboarding
through that lens; an analyst onboarding a new system today picks
a flat `data_source_type` string from a dropdown.

**(b) React mockup direction.** The user's mockup is explicit
about the desired shape: a top header with **pillar pills**, a
left rail with **sub-profile cards**, a centre workspace with
**three tabs (Detailed Intake / Detection Library / Audit &
Compliance)**, and a bottom **Use Case detail panel**. This is a
solved interaction pattern — operators recognise it instantly
from Sentinel, Splunk Add-on Builder, and Elastic Integration
pages.

**(c) Course alignment.** L1 M2 (SIEM Fundamentals) and L2 M2
(KQL/EQL/ES|QL) already teach analysts to think in terms of
*"what telemetry from what sub-system"*. The CYAB UI today does
not reinforce that mental model. The redesign aligns the operator
UI with the curriculum vocabulary. (See
`project_ion_curriculum.md`.)

---

## 3. The Gemini gold-standard frame

The PDF distils the SOC onboarding standards into five layers
that the redesign must honour:

**3.1 Governance (charter / mandate / scope).** ION already
captures this via CyabSystem fields: `department`, `department_lead`,
`soc_lead`, `business_unit`, `data_classification`, sign-off dates.
The Onboarding Pack export must surface these as the *cover page*
of the bundled PDF.

**3.2 NIST + SANS PICERL lifecycle.** Onboarding is the
*Preparation* phase. The redesign must present *every* sub-profile
through the lens of the four PICERL phases that follow ingestion:
Detect (telemetry adequacy), Contain (asset isolation
authority), Eradicate/Recover (rebuild path), Lessons Learned
(post-incident loop back to the question set). Today CYAB is silent
on Contain/Eradicate/Recover authority per data-source.

**3.3 Log-source prioritisation.** The PDF's hierarchy:

| Tier | Category | ION current data_source_type | Pillar (proposed) |
|------|----------|------------------------------|-------------------|
| 1 | Identity (AD, SSO, VPN) | `identity_provider`, `windows_security` (DC) | Identity & Access |
| 2 | Endpoint (EDR, AV, Sysmon) | `sysmon`, `edr`, `windows_security`, `linux_auditd` | Endpoints & Servers |
| 2 | Network (FW, IPS, proxy) | `firewall`, `dns`, `web_proxy` | Network & Perimeter |
| 3 | Cloud audit | `cloud_audit` | Cloud & SaaS |
| 3 | Application | `database_audit` | Data & Apps |
| 4 | OT / ICS | `ot_scada` | OT / IoT |

The 6-pillar taxonomy lifts directly from this hierarchy. Each
pillar's *visual prominence* in the UI mirrors the priority tier.

**3.4 Operational readiness — playbooks, SLA, OLA.** The PDF
demands per-system playbooks, an SLA the SOC owes the business,
and an OLA the SOC negotiates with IT operations. ION captures
`p1_sla` and `uptime_target` on the data source, but no OLA. The
Onboarding Pack must capture and surface both.

**3.5 Continuous improvement — KPIs.** MTTD, MTTR, FPR, alert
throughput. ION exposes per-system MITRE coverage but not these
four. Out of scope for v0.12; tracked as a follow-on.

---

## 4. What the React mockup adds

The mockup is an interaction-design contribution, not a content
contribution. Translated to ION-native:

| Mockup element | ION-native rendering | Notes |
|----------------|----------------------|-------|
| Pillar pill row in header | Header tabs above the page card | Drives sub-profile rail. Uses ION's existing tab CSS pattern (see `alerts.html` toolbar). |
| Sub-profile rail (left, ~25%) | Vertical list of buttons in `lg:col-span-3` aside | Same component pattern as the Course module rail (`courses.html`). |
| Library Stats card | Mini-counter card | Two metrics: `len(detection_use_cases)` + `len(audit_use_cases)`. |
| Three workspace tabs | `<div class="ion-tabs">` with three `<button>` triggers | "Detailed Intake" / "Detection Library" / "Audit & Compliance". |
| Use case grid cards | 2-column responsive grid | Click-to-select; risk left-border colour stripe. |
| Bottom use-case detail panel | In-page collapsible drawer (NOT a modal) | Modals are reserved in ION for destructive actions and quick-creates. |
| Export Onboarding Pack button | Footer action bar — same affordance as the existing per-system PDF export | New endpoint, see §12. |

Critically — **the mockup is React/Tailwind/Lucide, but ION is
Jinja2 + design-system.css + Lucide via `<svg><use>` includes**.
There is no SPA conversion. The rail / tab / drawer state is held
in URL query params (`?pillar=identity&sub=active_directory&tab=detection`)
so the page is fully server-rendered and bookmarkable.

---

## 5. ION's existing CYAB surface (do-not-break inventory)

Mapped at v0.11.21 by direct read. Anything in this list is a
hard constraint — the redesign must keep all 56 routes working
and the 5 DB tables stable.

**5.1 DB tables (5):**
- `cyab_systems` — 35+ columns (governance, scores, sign-off)
- `cyab_data_sources` — per-source SAL/field-mapping/TIDE link
- `cyab_snapshots` — point-in-time health
- `cyab_assessments` — org-wide questionnaire (immutable, versioned)
- `cyab_system_assessments` — per-system questionnaire (immutable, versioned)

**5.2 Question schema:** 17 org + 8 per-system; SCHEMA_VERSION=1.
Feeds the scoring service (TA/ST/CG/CB lanes).

**5.3 Routes (56 — see exploration report).** Five clusters:
System CRUD, Data-Source CRUD, Assessment, Snapshot, TIDE detection
readiness (the largest cluster, 21 routes, owns MITRE Navigator
JSON, kill-chain alert correlation, weasyprint-rendered actor
readiness PDF).

**5.4 Templates (12):** sysmon, windows_security, firewall, dns,
edr, cloud_audit, email_gateway, web_proxy, identity_provider,
linux_auditd, database_audit, ot_scada — keyed by
`data_source_type` string. These migrate **as-is** into the new
sub-profile catalogue (see §15).

**5.5 UI:** `cyab.html` (3,485 lines). Three primary view states
(`#cyab-dashboard`, `#cyab-assessment` wizard, `#cyab-detail`).
The redesign adds a **fourth view state, `#cyab-studio`**,
without removing the others. Operators can deep-link to
`/cyab?view=studio&pillar=identity` from anywhere.

**5.6 Resolver:** `system_resolver_service.py` maps ES alert
`data_stream.namespace` → CyabDataSource → CyabSystem → TIDE
system. The new sub-profile concept must not break this — namespace
remains the enrichment key.

---

## 6. Gap analysis

Cross-walk of *what gold-standard onboarding requires* vs. *what
ION ships today*:

| Capability | Gold-standard requirement | ION today | Gap |
|------------|---------------------------|-----------|-----|
| Charter / mandate | SOC Charter signed by exec | CyabSystem.sign_dept_*, sign_soc_* | None — ION ships this. |
| Scope | Pillar-prioritised asset list | Flat `data_source_type` | **Pillar taxonomy missing.** |
| Telemetry adequacy | Per-source field-mapping vs. ECS | CyabDataSource.field_mapping_score | None — ION ships this. |
| Technical intake | Sub-profile-specific config questions | 8 generic per-system questions | **Sub-profile question banks missing.** |
| Detection coverage | Pre-built use-case catalogue per type | TIDE rule listing post-onboarding | **Curated catalogue missing.** |
| Audit coverage | Compliance use-case catalogue per type | None | **Audit catalogue missing.** |
| Use-case detail | Logic + SOAR + MITRE on one card | TIDE detail page (separate) | **Unified detail card missing.** |
| Containment authority | Per-source isolation playbook | None at data-source level | Out of scope v0.12. |
| MITRE coverage | Heatmap | `cyab/tide/de/navigator-layer` | None — ION ships this. |
| Threat-actor PDF | Readiness report | `cyab/tide/de/readiness-pdf` | None — ION ships this. |
| Onboarding Pack | Single bundled sign-off PDF | Per-system saveAsPdf via html2pdf | **Bundled pack with intake + detection + audit missing.** |
| KPIs (MTTD/MTTR/FPR) | Tracked & displayed | Not in CYAB | Out of scope v0.12. |

Six in-scope gaps. Five close in v0.12; the sixth (containment
authority capture) is deferred to v0.13.

---

## 7. Proposed taxonomy — 6 pillars × 14 sub-profiles

Each row is one sub-profile. The "ECS namespace anchor" column is
how the resolver knows which alerts belong to it; this is how the
catalogue connects to live alerts.

### Pillar 1 — Identity & Access (priority tier 1)

| Sub-profile | ECS anchor | Existing template | New |
|-------------|-----------|-------------------|-----|
| Active Directory | `winlog.channel:Security` (DC role) + `event.dataset:windows.security` from DCs | windows_security (split) | yes |
| Entra ID / Okta | `azure.signinlogs`, `okta.system` | identity_provider | rename + sharpen |
| VPN / Remote access | `cisco.asa`, `paloalto.panos` (vpn-tagged) | — | new |

### Pillar 2 — Endpoints & Servers (priority tier 2)

| Sub-profile | ECS anchor | Existing template | New |
|-------------|-----------|-------------------|-----|
| Windows endpoint | `winlog.event_id`, `winlog.channel:Microsoft-Windows-Sysmon/Operational` | sysmon, windows_security, edr | merge |
| Linux / Unix | `auditd.data.*`, `system.auth` | linux_auditd | yes |
| macOS endpoint | `endgame.events.*` | — | new |

### Pillar 3 — Network & Perimeter (priority tier 2)

| Sub-profile | ECS anchor | Existing template | New |
|-------------|-----------|-------------------|-----|
| Next-Gen Firewall | `panos.*`, `paloalto.panos`, `cisco.ftd` | firewall | yes |
| DNS | `dns.question.*`, `zeek.dns` | dns | yes |
| Web proxy | `zscaler.*`, `bluecoat.*` | web_proxy | yes |

### Pillar 4 — Cloud & SaaS (priority tier 3)

| Sub-profile | ECS anchor | Existing template | New |
|-------------|-----------|-------------------|-----|
| Cloud audit (AWS/Azure/GCP) | `aws.cloudtrail`, `azure.activitylogs`, `gcp.audit` | cloud_audit | yes |
| Email platform (M365/Workspace) | `o365.audit`, `gsuite.gmail` | email_gateway | rename |
| SaaS app generic | varies | — | new |

### Pillar 5 — Data & Apps (priority tier 3)

| Sub-profile | ECS anchor | Existing template | New |
|-------------|-----------|-------------------|-----|
| Database | `mysql.audit`, `mssql.*`, `postgres.*` | database_audit | yes |
| Web application | `nginx.access`, `apache.access` | — | new |

### Pillar 6 — OT / IoT (priority tier 4)

| Sub-profile | ECS anchor | Existing template | New |
|-------------|-----------|-------------------|-----|
| ICS / SCADA | varies (Modbus, BACnet, OPC) | ot_scada | yes |

**Migration arithmetic:** 12 existing templates → 14 sub-profiles
across 6 pillars. Of the 12, **9 carry over directly with a
pillar tag added**, **3 split or merge** (windows_security splits
across AD-DC and Windows-endpoint; sysmon + edr + windows_security
merge under Windows-endpoint as *expected feeds*), and **5 new
sub-profiles** are added (VPN, macOS, SaaS-generic, Web app, IoT).

---

## 8. Anatomy of a sub-profile

Every sub-profile is a row in a new `cyab_subprofiles` table (see
§11) with five chunks of content:

```
SubProfile {
  id                : "active_directory"
  pillar_id         : "identity"
  label             : "Active Directory"
  icon              : "users"            # Lucide name
  ecs_anchor        : ["winlog.channel:Security", ...]
  expected_feeds    : ["windows_security_dc", "sysmon_dc"]
  intake_questions  : [ ... 5–8 items ... ]
  recommended_tasks : [ ... 4–6 items ... ]
  detection_use_cases : [ ... 5–8 items ... ]
  audit_use_cases     : [ ... 4 items ... ]
  containment_notes : "Tier-0 — see §X"  # short string, deferred deeper in v0.13
  references        : [ {title, url}, ... ]
}
```

The five content chunks are **seeded from a Python module**
(`cyab_subprofile_catalogue.py`) by analogy to `cyab_templates.py`,
i.e. version-controlled in code, not in DB. The DB table holds
operator-edited overlays only.

---

## 9. Worked sub-profile content (3 exemplars)

These three are produced in full so the seed-file shape is locked.
The remaining 11 sub-profiles get the same skeleton but populated
during seed authoring — that is itself a ~1-week content task and
**should be tracked as its own ship**, not folded into the v0.12
plumbing ship.

### 9.1 Sub-profile: Active Directory (pillar `identity`)

**Intake questions (7).** Each is shape-compatible with the
existing CyAB question schema (`key`, `text`, `answer_type`,
`options`, `feeds`); they extend the schema not replace it. New
keys are namespaced `sub_<pillar>_<subprofile>_*`.

| Key | Question | Answer type | Feeds |
|-----|----------|-------------|-------|
| `sub_id_ad_recycle_bin` | Is the AD Recycle Bin enabled for forensics? | yesno | cg+5 |
| `sub_id_ad_advanced_audit` | Is Advanced Audit Policy pushed via GPO? | yesno | cg+8 |
| `sub_id_ad_priv_group_monitor` | Are Sensitive Groups (Domain Admins) monitored for additions? | yesno | cg+10 |
| `sub_id_ad_psh_logging` | Is PowerShell Script Block Logging enabled? | yesno | cg+6 |
| `sub_id_ad_msa_rotation` | How often are Managed Service Account passwords rotated? | single (≤30d / 30-90d / >90d / never / dont_know) | cg+4 |
| `sub_id_ad_ntlm_audit` | Is NTLM auditing enabled to identify legacy creds? | yesno | cg+5 |
| `sub_id_ad_dsa_audit` | Is Directory Service Access auditing enabled for OU changes? | yesno | cg+5 |

**Recommended tasks (4).** Free-text checklist; no scoring.

- Validate Event ID 4662 (Object Access) on GPO containers.
- Configure Sysmon for enhanced process tracking on every DC.
- Set up alerts for "Dormant Admin" activity (no logon >90d, then a logon).
- Map Tier-0 asset dependencies (KRBTGT, AdminSDHolder).

**Detection use cases (5).** Each carries `mitre_id`, `risk`,
`logic_snippet`, `soar_playbook_id`, and `references[]`.

| Title | MITRE | Risk | Logic snippet (Elastic ES\|QL) | SOAR |
|-------|-------|------|--------------------------------|------|
| Kerberoasting | T1558.003 | High | `event.code:4769 AND winlog.event_data.TicketEncryptionType:0x17 AND winlog.event_data.ServiceName:* AND NOT winlog.event_data.ServiceName:krbtgt` rolled up by `user.name` over 1h, threshold 50 | `pb_kerberoasting_triage` |
| DCShadow | T1207 | Critical | `event.code:4662 AND winlog.event_data.ObjectName:*Replicating Directory Changes*` from non-DC computer | `pb_replication_anomaly` |
| AS-REP Roasting | T1558.004 | High | `event.code:4768 AND winlog.event_data.PreAuthType:0` | `pb_asrep_triage` |
| DCSync | T1003.006 | Critical | `event.code:4662 AND winlog.event_data.Properties: ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" OR "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")` from non-DC | `pb_dcsync` |
| BloodHound enumeration | T1018 | Medium | `event.code:5145 AND winlog.event_data.ShareName:*\\IPC$* AND winlog.event_data.RelativeTargetName:samr` rolled up by `source.ip` over 5m, threshold 100 | `pb_recon_review` |

**Audit use cases (4).**

| Title | Risk | Logic | Compliance frame |
|-------|------|-------|------------------|
| Sensitive Group Drift | Medium | `event.code:4728 OR event.code:4732 OR event.code:4756 AND winlog.event_data.TargetUserName:("Domain Admins" OR "Enterprise Admins" OR "Schema Admins")` | NIST AC-6(7), CIS 5.4 |
| GPO Tampering | High | `event.code:5136 AND winlog.event_data.ObjectClass:groupPolicyContainer` | NIST CM-3, CIS 4.2 |
| Password Policy Weakening | Low | `event.code:4739` (domain policy changed) | NIST IA-5(1), CIS 5.2 |
| Trust Relationship Change | High | `event.code:4716 OR event.code:4865 OR event.code:4866` | NIST AC-3, CIS 4.5 |

**References.** MITRE ATT&CK Enterprise (T1558.003, T1207,
T1558.004, T1003.006, T1018), CIS Microsoft Active Directory
Benchmark v3, MS-ADTS [MS-DRSR] §4.1.10, SANS GCIH course
material on Kerberos attack chains.

### 9.2 Sub-profile: Windows endpoint (pillar `endpoint`)

**Intake (5):** Credential Guard enabled? Process creation +
command-line logging captured? PowerShell transcription? RDP logs
forwarded (4624 Type 10)? AppLocker / WDAC in enforcing mode?

**Detection use cases (6):**

| Title | MITRE | Risk |
|-------|-------|------|
| LSASS memory dump | T1003.001 | Critical |
| Scheduled Task persistence to Temp | T1053.005 | Medium |
| WMI Event Subscription | T1546.003 | High |
| Token impersonation | T1134 | High |
| BITS Job misuse | T1197 | Medium |
| Registry Run/RunOnce add | T1547.001 | Medium |

**Audit use cases (4):** Local admin addition, Defender disable,
Firewall profile change, Remote Registry service start.

### 9.3 Sub-profile: Next-Gen Firewall (pillar `network`)

**Intake (3):** Are denied + allowed both logged? SSL decryption
on for threat visibility? NetFlow on for east-west?

**Detection use cases (4):** DNS tunnelling, large HTTP POST
exfiltration, internal port scan, Tor exit-node connection.

**Audit use cases (2):** Any-Any rule creation, shadow rule
without change-ticket reference.

### 9.4 Remaining 11 sub-profiles

Skeletons in **Appendix A**. Full content authored in a follow-on
content-only ship after the plumbing lands — analogous to how
seed_courses.py was first stubbed, then filled in v0.11.12+.

---

## 10. Use case detail anatomy

Each detection / audit use case has a fixed schema. This is what
the bottom drawer renders.

```python
@dataclass
class UseCase:
    id: str                  # e.g. "ad_kerberoasting"
    title: str
    kind: Literal["detection", "audit"]
    risk: Literal["critical", "high", "medium", "low"]
    summary: str             # 1–2 sentences for the card
    description: str         # paragraph for the drawer
    mitre_ids: list[str]     # ["T1558.003", ...]
    logic_snippet: str       # ES|QL / KQL — display-only
    logic_lang: Literal["esql", "kql", "eql", "spl"]
    soar_playbook_id: str | None  # links to ION playbooks if present
    tide_rule_ids: list[str]      # links to TIDE if rule shipped
    compliance_frames: list[str]  # ["NIST AC-6(7)", "CIS 5.4"] (audit only)
    references: list[dict]   # [{title, url}]
```

In the drawer the layout is exactly the mockup:

- Left/main 2/3 column: `Logic & Thresholds` block — monospace
  pre-rendered Pygments-coloured ES|QL/KQL block.
- Right 1/3 column stack:
  - `SOAR Playbook` card — link to ION's playbook if the id
    resolves, otherwise a "Not yet built" pill with a
    "Generate playbook stub" action.
  - `MITRE Mapping` card — chips per id, each linking to ION's
    existing MITRE Navigator panel.
  - `TIDE Rule` card (if `tide_rule_ids` non-empty) — link to
    the TIDE rule detail page already shipped at
    `/cyab/tide/...`.

The drawer is collapsible, lives below the workspace card, and
the URL gets `&uc=ad_kerberoasting` appended so it's
deep-linkable.

---

## 11. Data model additions

Two new tables, one schema-version bump on the questions module,
no breaking changes to the five existing CYAB tables.

### 11.1 `cyab_pillars` (lookup, seeded by code)

```sql
CREATE TABLE cyab_pillars (
  id          VARCHAR(32) PRIMARY KEY,         -- 'identity' | 'endpoint' | ...
  label       VARCHAR(64) NOT NULL,
  icon        VARCHAR(32) NOT NULL,            -- Lucide name
  priority    INTEGER NOT NULL,                -- 1..6 (matches Gemini hierarchy)
  description TEXT
);
```

Six rows, populated from a Python constant at startup
(idempotent UPSERT).

### 11.2 `cyab_subprofiles` (lookup + operator overlay)

```sql
CREATE TABLE cyab_subprofiles (
  id              VARCHAR(64) PRIMARY KEY,       -- 'active_directory'
  pillar_id       VARCHAR(32) NOT NULL REFERENCES cyab_pillars(id),
  label           VARCHAR(128) NOT NULL,
  icon            VARCHAR(32) NOT NULL,
  ecs_anchors     TEXT,                          -- JSON list of strings
  expected_feeds  TEXT,                          -- JSON list of data_source_type strings
  catalogue_json  TEXT,                          -- intake + detection + audit content
  catalogue_version INTEGER NOT NULL DEFAULT 1,
  is_custom       BOOLEAN NOT NULL DEFAULT FALSE,
  created_at      TIMESTAMP NOT NULL DEFAULT now(),
  updated_at      TIMESTAMP NOT NULL DEFAULT now()
);
CREATE INDEX ix_cyab_subprofiles_pillar ON cyab_subprofiles(pillar_id);
```

`catalogue_json` mirrors §8 — intake questions, recommended tasks,
detection use cases, audit use cases, references. Stored as
JSON-as-text per ION's existing pattern (CyabAssessment uses the
same approach). Code-seeded sub-profiles set `is_custom=false`;
operator-created ones flip it `true` and the seed loader leaves
them alone.

### 11.3 `cyab_data_sources` — one new column

```sql
ALTER TABLE cyab_data_sources
  ADD COLUMN subprofile_id VARCHAR(64)
  REFERENCES cyab_subprofiles(id);
```

Backfill: for each existing row, look up `data_source_type`
against the migration table in §15 and set `subprofile_id`. If
ambiguous, leave NULL; the UI surfaces "needs sub-profile
assignment" pill.

### 11.4 `cyab_system_assessments` — schema bump

`SCHEMA_VERSION` from `1` → `2`. New keys (`sub_id_ad_*`,
`sub_ep_win_*`, etc.) are appended to the same `responses_json`
blob; the scoring service reads only what's present, so old v1
submissions remain valid. Per the existing pattern
(`cyab_assessment_questions.py` docstring): "bumping
SCHEMA_VERSION is mandatory when question keys / option values
change so old responses can be replayed correctly".

### 11.5 No new tables for use cases themselves

The detection/audit catalogue lives in `catalogue_json` on
`cyab_subprofiles`. *Use-case execution status* (which detections
this system has actually shipped, which gaps remain) lives on the
existing `CyabDataSource.use_case_status` /
`use_case_gaps` / `use_case_remediation` columns — they are
re-typed semantically: where today they're free-text, they
become a JSON object keyed by use_case_id with values
`{shipped|partial|gap|n/a}`. SCHEMA_VERSION bump covers this.

---

## 12. API surface — additions only

All new routes hang under `/cyab/studio/...`. Existing 56 routes
untouched.

| Route | Verb | Purpose |
|-------|------|---------|
| `/cyab/studio` | GET | Render the Studio view (HTML). Query params: `pillar`, `sub`, `tab`, `uc`. |
| `/cyab/studio/pillars` | GET | List 6 pillars. |
| `/cyab/studio/pillars/{id}/subprofiles` | GET | List sub-profiles in a pillar. |
| `/cyab/studio/subprofiles/{id}` | GET | Full catalogue for one sub-profile. |
| `/cyab/studio/subprofiles/{id}` | PATCH | Operator overlay: edit a question / add a use case. Sets `is_custom=true`. |
| `/cyab/studio/subprofiles/{id}/use-cases/{uc_id}` | GET | Single use case (drawer fetch). |
| `/cyab/systems/{id}/onboarding-pack` | GET | Render the Onboarding Pack PDF (weasyprint). See §13. |
| `/cyab/systems/{id}/onboarding-pack` | POST | Mark pack as approved + sign by current user. Persists into `cyab_systems.sign_*` columns. |
| `/cyab/systems/{id}/subprofile-coverage` | GET | Per-system rollup: for each attached data source's sub-profile, what % of intake answered, what % of detection use cases shipped, what % of audit use cases shipped. Powers a new card on the system detail page. |

Nine new endpoints. All sit under existing routers per the FastAPI
prefix convention (see `project_ion_router_prefixes.md` — routes
defined relative inside `cyab_api.py`, the router mounts the
`/cyab` prefix at server.py).

---

## 13. Onboarding Pack PDF

The signed bundle that closes the onboarding loop. Pattern lifts
from the existing `cyab/tide/de/readiness-pdf` weasyprint route.

**Cover page.** System name, department, business unit, data
classification, demarcation diagram (already exists on the system
detail page), sign-off lines for the Department Lead and the SOC
Lead, version, today's date.

**Section 1 — Strategic context.** Org-wide assessment summary
(sector, top concerns, prior incidents). Pulled from the most
recent `CyabAssessment.computed_profile_json`.

**Section 2 — System scope.** Per data source: name, type,
sub-profile, SAL tier, retention, P1 SLA, ECS namespace,
expected feeds checklist.

**Section 3 — Per-sub-profile readiness.** For each sub-profile
in scope (one or more per system, e.g. a "domain controllers"
system has both AD and Windows-endpoint sub-profiles):

- Intake answers table (question / answer / feeds).
- Detection coverage table (use case / risk / status / TIDE link).
- Audit coverage table (use case / status / compliance frame).

**Section 4 — Containment authority.** Operator-typed paragraph;
captured in `cyab_systems.ir_runbook_url` plus a new free-text
column or stored on the sign-off step. (TBD — see §17.)

**Section 5 — Sign-off.** Two-up signature block, captures
`sign_dept_name + date` and `sign_soc_name + date`, the existing
fields. POST persists.

**Cover sheet template.** A new `templates/cyab/onboarding_pack.html`,
weasyprint-rendered on POST. Reuses the same CSS primitives as the
existing readiness PDF.

---

## 14. UI structure (Jinja2)

No SPA. URL drives state. Three new partials:

```
templates/cyab/
  _studio_header.html        # pillar pills row
  _studio_subprofile_rail.html
  _studio_workspace.html     # contains _intake_tab.html, _detection_tab.html, _audit_tab.html
  _studio_drawer.html        # use-case detail
  onboarding_pack.html       # weasyprint output
```

`cyab.html` adds a fourth view-state block:

```jinja
{% if view == "studio" %}
  {% include "cyab/_studio_header.html" %}
  <div class="grid lg:grid-cols-12 gap-6 mt-6">
    <aside class="lg:col-span-3">
      {% include "cyab/_studio_subprofile_rail.html" %}
    </aside>
    <main class="lg:col-span-9">
      {% include "cyab/_studio_workspace.html" %}
      {% if active_use_case %}
        {% include "cyab/_studio_drawer.html" %}
      {% endif %}
    </main>
  </div>
{% endif %}
```

The existing dashboard / wizard / detail blocks stay where they
are. A new tab in the page header (`Studio`) toggles between
them via `?view=...`.

**Style fidelity to the mockup.** The mockup uses Tailwind-y
class names and a slate-900/blue-500 palette; ION's
`design-system.css` already exposes the equivalent CSS variables
(`--surface-0`, `--surface-1`, `--accent-500`). Translate
class-by-class — no new design tokens needed. Risk-stripe
colours: critical `--danger-500`, high `--warn-500`,
medium `--accent-500`, low `--muted-500`.

**Lucide icons.** All icons used in the mockup are already in
ION's icon sprite (Shield, Database, Activity, Settings, Search,
Zap, FileText, Eye, Bug, Code, HardDrive, Network, ShieldAlert,
Cpu, Fingerprint, Users, Globe). Cross-check before ship; add any
missing ones to `static/icons/sprite.svg`.

---

## 15. Migration / backfill

The 12 existing templates collapse into 14 sub-profiles.
Migration table (`cyab_data_source_type` → `subprofile_id`):

| Existing data_source_type | New subprofile_id | Notes |
|---------------------------|-------------------|-------|
| sysmon | `windows_endpoint` | Sysmon is a *feed* of Windows endpoint sub-profile |
| windows_security | (split — see below) | Domain Controllers → `active_directory`, member servers/workstations → `windows_endpoint`. UI prompts operator to pick which. |
| firewall | `next_gen_firewall` | |
| dns | `dns` | |
| edr | `windows_endpoint` *or* `linux_endpoint` *or* `macos_endpoint` | UI prompts. |
| cloud_audit | `cloud_audit` | |
| email_gateway | `email_platform` | |
| web_proxy | `web_proxy` | |
| identity_provider | `entra_okta` | |
| linux_auditd | `linux_endpoint` | |
| database_audit | `database` | |
| ot_scada | `ics_scada` | |

Three existing types need operator decision (the UI surfaces a
yellow banner "Confirm sub-profile" on first load). All others
migrate automatically.

**Migration script.** Idempotent UPSERT in
`scripts/migrate_cyab_subprofiles.py`. Runs in
`docker-entrypoint.sh` after the seeder, gated on
`SCHEMA_VERSION` of `cyab_subprofiles` row count.

---

## 16. Phased delivery (4 ships)

| Ship | Version | Scope | Token estimate |
|------|---------|-------|----------------|
| 1 | v0.12.0 | Plumbing: tables, migration, seed catalogue **scaffold** (3 worked sub-profiles per §9), Studio view (header + rail + 3 tabs + drawer), 9 new API routes, Onboarding Pack PDF generation. Ships behind a top-tab on `/cyab` so nothing else changes. | ~120k |
| 2 | v0.12.1 | Catalogue fill: remaining 11 sub-profiles authored to the same depth as §9.1 (full intake banks, detection use cases with ES\|QL, audit use cases with compliance frames). Pure content. | ~150k |
| 3 | v0.12.2 | Wire-up: per-data-source `use_case_status` JSON migration + UI ("which detections are shipped vs. gap"), `subprofile-coverage` rollup card on the system detail page. | ~70k |
| 4 | v0.12.3 | Operator authoring: PATCH route fully wired so operators can add a custom intake question / use case to a sub-profile (sets `is_custom=true`, no overwrite on next seed). | ~60k |

Total ~400k tokens for the full Studio. Ship 1 alone is the
useful MVP. Ships 2–4 can be paced.

---

## 17. Resolved decisions (2026-04-29)

User answers, locked in this dossier as the source-of-truth.

1. **Pillar count: six.** Identity & Access / Endpoints & Servers /
   Network & Perimeter / Cloud & SaaS / Data & Apps / OT & IoT.
   §7 stands as written.

2. **Custom sub-profiles: yes.** Operators can author a new
   sub-profile via the PATCH route. `is_custom=true` shields it
   from the seed loader's overwrite. §11.2 stands.

3. **Containment authority: new column.** Add
   `cyab_systems.containment_authority TEXT` (nullable). Captured
   on the Onboarding Pack approval flow (§13 §4). It carries the
   per-system isolation playbook reference (e.g., "Network
   isolate via NAC, contact NetOps on-call, max delay 30 min").
   Surfaced on the system detail page. §11.3 amended below.

4. **Catalogue source-of-truth: DB-overlay (current proposal).**
   Code (`cyab_subprofile_catalogue.py`) seeds rows on first boot;
   operator edits flip `is_custom=true` and the seeder skips them
   on subsequent boots. §11.2 stands.

5. **TIDE coupling: both.** The drawer *links* to existing TIDE
   rules when `tide_rule_ids[]` is non-empty, AND offers a
   *"Generate TIDE rule stub from this use case"* action when
   it's empty. The stub-generate route is added to the Ship-1
   scope (was originally deferred to v0.13). §10 + §12 amended
   below.

6. **Naming: "CyAB Onboarding"** (user-facing). Internal
   identifier `studio` retained for URL state and partial names
   to avoid collision with the legacy `POST /cyab/onboarding`
   route.

### 17.1 Amendments folded back into the spec

- **§11.3 supersession:** Two new columns on `cyab_data_sources`:
  ```sql
  ALTER TABLE cyab_data_sources
    ADD COLUMN subprofile_id VARCHAR(64)
    REFERENCES cyab_subprofiles(id);
  ```
  And one new column on `cyab_systems`:
  ```sql
  ALTER TABLE cyab_systems
    ADD COLUMN containment_authority TEXT;
  ```

- **§10 + §12 supersession (TIDE stub-generate):** Add one route
  to the table in §12:
  | Route | Verb | Purpose |
  |-------|------|---------|
  | `/cyab/studio/use-cases/{uc_id}/tide-stub` | POST | Generate a TIDE rule stub from a catalogue use case (logic_snippet → rule body, mitre_ids → tags, risk → severity). Returns the new TIDE rule id; UI inserts it into `tide_rule_ids[]` on the catalogue use case. |
  Drawer UI: when `tide_rule_ids[]` is empty, the "TIDE Rule"
  card shows a button "Generate TIDE rule stub" instead of a
  "Not yet built" pill. After generation, refresh sets
  `is_custom=true` on the sub-profile (the stub-link is an
  operator overlay).

- **§16 supersession (ship 1 scope):** Stub-generate route added
  to ship 1; v0.12.0 token estimate revised from ~120k to ~140k.

---

## Appendix A — Sub-profile content matrix (skeleton)

Eleven remaining sub-profiles. Each row will be authored to §9.1
depth in v0.12.1.

| Pillar | Sub-profile | Intake (target count) | Detection (target count) | Audit (target count) | Reference benchmarks |
|--------|-------------|-----------------------|--------------------------|----------------------|-----------------------|
| Identity | Entra ID / Okta | 6 | 5 | 3 | CIS Microsoft 365 Foundations, Okta CIS, NIST IA-5 |
| Identity | VPN / Remote access | 4 | 4 | 2 | NIST AC-17, CIS 12.7 |
| Endpoint | Linux / Unix | 5 | 5 | 3 | CIS Distribution-Independent Linux, NIST AC-3 |
| Endpoint | macOS | 4 | 4 | 2 | CIS Apple macOS Benchmark |
| Network | DNS | 3 | 4 | 2 | NIST SP 800-81 |
| Network | Web proxy | 4 | 3 | 2 | NIST SC-7, CIS 12 |
| Cloud | Cloud audit (AWS/Azure/GCP) | 6 | 5 | 4 | CIS AWS Foundations, Azure Foundations, GCP Foundations |
| Cloud | Email platform (M365/Workspace) | 5 | 5 | 3 | CIS Microsoft 365 Foundations, NIST SC-8 |
| Cloud | SaaS app generic | 4 | 3 | 2 | NIST SR-11 |
| Data | Database | 4 | 4 | 3 | CIS Database benchmarks, NIST AU-2 |
| Data | Web application | 5 | 4 | 2 | OWASP ASVS L2, NIST SI-10 |
| OT | ICS / SCADA | 4 | 3 | 2 | NIST SP 800-82 r3, IEC 62443 |

---

## Appendix B — Glossary diff vs. existing CYAB

| Term | Meaning in existing CYAB | Meaning in Studio |
|------|--------------------------|-------------------|
| System | A department/agreement-level grouping (CyabSystem row) | Unchanged. |
| Data source | Concrete log feed, e.g. "Domain Controller security log" | Unchanged. Now also tagged with `subprofile_id`. |
| Template | Pre-built data-source-type config (12 of them) | Unchanged but reframed in the UI as *"expected feed for Windows endpoint sub-profile"*. |
| Use case | Free-text status field on a data source | New: a row in a sub-profile catalogue with logic + MITRE + SOAR. The free-text status field becomes a per-data-source rollup of which catalogue use cases are shipped. |
| Pillar | (none) | New. Top-level taxonomy of 6. |
| Sub-profile | (none) | New. ~14 second-level taxonomy nodes under pillars. |
| Onboarding Pack | (none — just a per-page PDF export) | New. Bundled, sign-able multi-section PDF. |

---

_End of dossier. Approval gate before any plumbing code._
