"""Seed SOC-CMM document templates into the ION template library."""
import os
import requests

BASE = os.environ.get("ION_SEED_URL", "http://127.0.0.1:8000")
SESSION = requests.Session()

def login():
    r = SESSION.post(f"{BASE}/api/auth/login", json={"username": "admin", "password": os.environ.get("ION_ADMIN_PASSWORD", "admin2025")})
    r.raise_for_status()
    # Auth is cookie-based — session cookies are stored automatically
    print("Logged in as admin")

def get_or_create_collection(name, desc, parent_id=None):
    r = SESSION.get(f"{BASE}/api/collections")
    data = r.json()
    cols = data if isinstance(data, list) else data.get("collections", [])
    for c in cols:
        if c["name"] == name:
            return c["id"]
    body = {"name": name, "description": desc}
    if parent_id:
        body["parent_id"] = parent_id
    r = SESSION.post(f"{BASE}/api/collections", json=body)
    if r.status_code == 400:
        # Likely duplicate name — find it by name in existing list
        print(f"  Collection exists (skipped create): {name}")
        # Re-scan to find the id
        r2 = SESSION.get(f"{BASE}/api/collections")
        data2 = r2.json()
        cols2 = data2 if isinstance(data2, list) else data2.get("collections", [])
        for c2 in cols2:
            if c2["name"] == name:
                return c2["id"]
        return None
    r.raise_for_status()
    cid = r.json()["id"]
    print(f"  Created collection: {name} (id={cid})")
    return cid

def create_template(name, content, doc_type, collection_id, desc, tags=None):
    # Check if already exists
    r = SESSION.get(f"{BASE}/api/templates", params={"search": name})
    data = r.json()
    tpls = data if isinstance(data, list) else data.get("templates", [])
    for t in tpls:
        if t["name"] == name:
            print(f"  Skipped (exists): {name}")
            return t["id"]
    body = {
        "name": name,
        "content": content,
        "format": "markdown",
        "document_type": doc_type,
        "description": desc,
        "tags": tags or [],
    }
    r = SESSION.post(f"{BASE}/api/templates", json=body)
    r.raise_for_status()
    tid = r.json()["id"]
    # Move to collection
    SESSION.post(f"{BASE}/api/collections/{collection_id}/templates/{tid}")
    print(f"  Created: {name} (id={tid})")
    return tid

# --- Document header shared across all templates ---
DOC_HEADER = """| Field | Value |
|-------|-------|
| **Document Owner** | {{ author | default('[Assigned Owner]') }} |
| **Organisation** | {{ org_name | default('[Organisation Name]') }} |
| **Classification** | {{ classification | default('INTERNAL') }} |
| **Version** | {{ version | default('0.1') }} |
| **Last Review** | {{ review_date | default('[Date]') }} |
| **Next Review** | {{ next_review | default('[Date + 12 months]') }} |
| **Approved By** | {{ approver | default('[CISO / SOC Manager]') }} |

---
"""

REVIEW_TABLE = """
## Document Control

### Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | {{ date | default('[Date]') }} | {{ author | default('[Author]') }} | Initial draft |

### Review & Approval

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Author | | | |
| Reviewer | | | |
| Approver | | | |
"""

# =========================================================================
# Template content for each document
# =========================================================================

TEMPLATES = []

def T(key, name, doc_type, desc, tags, body):
    """Helper to register a template."""
    full = f"# {name}\n\n{DOC_HEADER}\n{body}\n\n---\n{REVIEW_TABLE}"
    TEMPLATES.append((key, name, doc_type, desc, tags, full))

# --- GOVERNANCE & CHARTER ---

T("doc:soc_charter", "SOC Charter", "SOP",
  "Defines the SOC mission, scope, authority, objectives and services",
  ["governance", "soc-cmm", "charter"],
  """## 1. Purpose

This document establishes the Security Operations Centre (SOC) and defines its mission, scope of authority, organisational alignment, and strategic objectives.

## 2. Mission Statement

The SOC provides continuous monitoring, detection, analysis, and response to cyber security threats targeting {{ org_name | default('[Organisation]') }} assets, data, and personnel.

## 3. Scope

### 3.1 In Scope
- All production IT infrastructure and cloud environments
- Corporate network and endpoints
- Third-party integrations with access to internal systems
- OT/ICS environments (if applicable)

### 3.2 Out of Scope
- Physical security (unless cyber-physical convergence applies)
- Business application support (L1 helpdesk)

## 4. Authority

The SOC is authorised to:
- Isolate or quarantine compromised systems without prior change approval during active incidents
- Collect and preserve forensic evidence
- Engage external incident response retainers
- Issue security advisories to all staff
- Request access to any system logs required for investigation

## 5. Strategic Objectives

| # | Objective | KPI | Target |
|---|-----------|-----|--------|
| 1 | Reduce Mean Time to Detect (MTTD) | MTTD hours | < 1 hour |
| 2 | Reduce Mean Time to Respond (MTTR) | MTTR hours | < 4 hours |
| 3 | Increase detection coverage | MITRE ATT&CK coverage % | > 80% |
| 4 | Reduce false positive rate | FP ratio | < 30% |
| 5 | Achieve SOC-CMM Level 3+ maturity | Maturity score | 3.0+ |

## 6. Services Provided

- 24/7 Security monitoring and alerting
- Incident triage, investigation, and response
- Threat intelligence collection and dissemination
- Vulnerability assessment coordination
- Detection engineering and rule development
- Forensic analysis and evidence handling
- Security awareness support
- Compliance monitoring and reporting

## 7. Organisational Structure

```
CISO
 └── SOC Manager
      ├── Shift Lead (x2)
      │    └── SOC Analysts (L1/L2)
      ├── Detection Engineer
      ├── Threat Intelligence Analyst
      └── Incident Response Lead
           └── DFIR Analysts
```

## 8. Operating Model

| Aspect | Detail |
|--------|--------|
| Operating hours | 24/7/365 |
| Shift pattern | {{ shift_pattern | default('[e.g., 4x4 12-hour shifts]') }} |
| Escalation model | Tiered (L1 → L2 → L3 → IR Lead → SOC Manager) |
| Reporting cadence | Weekly operational, monthly executive, quarterly board |

## 9. Dependencies & Interfaces

- **IT Operations** — system access, change management, asset data
- **Legal & Compliance** — breach notification, evidence handling
- **HR** — insider threat coordination, disciplinary actions
- **Executive Leadership** — strategic direction, budget approval
- **External** — CERT/CSIRT, law enforcement, IR retainer

## 10. Review Cycle

This charter shall be reviewed **annually** or upon significant organisational change, major incident, or regulatory update.""")

T("doc:org_chart", "SOC Organisational Chart", "KB",
  "SOC team structure, reporting lines, roles, and on-call rota",
  ["governance", "soc-cmm", "org-structure"],
  """## 1. Purpose

Define the SOC organisational structure, reporting lines, role responsibilities, and on-call arrangements.

## 2. Organisational Chart

```
{{ org_chart | default('CISO\\n └── SOC Manager\\n      ├── Shift Lead A / Shift Lead B\\n      │    ├── L2 Analyst x2\\n      │    └── L1 Analyst x3\\n      ├── Detection Engineer\\n      ├── Threat Intel Analyst\\n      └── IR Lead\\n           └── DFIR Analyst x2') }}
```

## 3. Role Definitions

| Role | Reports To | Key Responsibilities | FTE Count |
|------|-----------|---------------------|-----------|
| SOC Manager | CISO | Strategy, budget, hiring, reporting | 1 |
| Shift Lead | SOC Manager | Shift operations, escalation, mentoring | 2 |
| L2 Analyst | Shift Lead | Deep investigation, IR coordination | 4 |
| L1 Analyst | Shift Lead | Alert triage, initial classification | 6 |
| Detection Engineer | SOC Manager | Rule development, tuning, automation | 1 |
| Threat Intel Analyst | SOC Manager | TI collection, dissemination, profiling | 1 |
| IR Lead | SOC Manager | Major incident management, forensics | 1 |
| DFIR Analyst | IR Lead | Forensic analysis, evidence handling | 2 |

## 4. On-Call Rota

| Week | Primary On-Call | Secondary On-Call | IR Escalation |
|------|----------------|-------------------|---------------|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |

**On-call SLA:** Acknowledge within 15 minutes, begin investigation within 30 minutes.

## 5. Succession Planning

| Key Role | Primary Successor | Secondary Successor | Cross-training Status |
|----------|-------------------|---------------------|-----------------------|
| SOC Manager | | | |
| IR Lead | | | |
| Detection Engineer | | | |""")

T("doc:raci_matrix", "RACI Matrix", "KB",
  "Responsibility assignment matrix for all SOC functions",
  ["governance", "soc-cmm", "raci"],
  """## 1. Purpose

Define clear accountability for SOC processes using the RACI model (Responsible, Accountable, Consulted, Informed).

## 2. RACI Legend

- **R** — Responsible: performs the work
- **A** — Accountable: ultimately answerable (one per activity)
- **C** — Consulted: provides input before decision
- **I** — Informed: notified after decision

## 3. SOC RACI Matrix

| Activity | SOC Mgr | Shift Lead | L2 Analyst | L1 Analyst | Det. Eng. | TI Analyst | IR Lead | CISO |
|----------|---------|-----------|-----------|-----------|----------|-----------|---------|------|
| Alert triage | I | A | C | R | I | I | I | - |
| Incident investigation | I | A | R | C | C | C | C | I |
| Major incident management | A | C | R | I | C | C | R | I |
| Detection rule creation | A | C | I | I | R | C | I | I |
| Threat intel dissemination | I | I | I | I | C | R | C | I |
| Forensic analysis | I | I | C | I | I | I | A/R | I |
| Shift handover | I | A/R | R | R | I | I | I | - |
| Weekly reporting | A/R | C | C | I | C | C | C | I |
| Monthly exec report | R | C | I | I | I | I | I | A |
| Tool administration | A | I | I | I | R | I | I | I |
| Playbook development | A | C | C | I | R | C | R | I |
| Vulnerability coordination | A | I | C | I | I | I | R | I |
| Training & development | A/R | C | I | I | I | I | I | I |
| Budget & procurement | R | I | I | I | C | I | C | A |
| Hiring & onboarding | A/R | C | I | I | I | I | I | I |""")

T("doc:escalation_matrix", "Escalation Matrix", "SOP",
  "Escalation paths, contacts, thresholds, and response timelines",
  ["governance", "soc-cmm", "escalation"],
  """## 1. Purpose

Define clear escalation paths, thresholds, and timelines for security events and incidents.

## 2. Severity Levels

| Severity | Description | Examples | MTTR Target |
|----------|------------|---------|-------------|
| **P1 — Critical** | Active breach, data exfiltration, ransomware | Confirmed APT, active ransomware, PII breach | 1 hour |
| **P2 — High** | Confirmed compromise, contained | Compromised account, malware contained, C2 detected | 4 hours |
| **P3 — Medium** | Suspicious activity requiring investigation | Anomalous behaviour, policy violation, phishing success | 8 hours |
| **P4 — Low** | Minor event, informational | Failed login brute-force (blocked), policy alert | 24 hours |

## 3. Escalation Path

```
L1 Analyst → Shift Lead → L2 Analyst → IR Lead → SOC Manager → CISO → CEO
                                                         ↓
                                                  Legal Counsel
                                                  External IR Retainer
                                                  Law Enforcement
```

## 4. Escalation Triggers

| From → To | Trigger Condition | Timeframe |
|-----------|-------------------|-----------|
| L1 → Shift Lead | Cannot classify within 15 min; severity ≥ P3 | Immediate |
| Shift Lead → L2 | Requires deep investigation; potential compromise | Within 15 min |
| L2 → IR Lead | Confirmed incident; severity P1/P2 | Immediate |
| IR Lead → SOC Manager | P1 incident; requires business decisions | Within 30 min |
| SOC Manager → CISO | Data breach; regulatory impact; media risk | Within 1 hour |
| CISO → Legal | Personal data involved; breach notification required | Within 2 hours |
| CISO → CEO | Business-critical impact; public disclosure needed | Within 4 hours |

## 5. Contact Directory

| Role | Name | Phone | Email | Backup |
|------|------|-------|-------|--------|
| SOC Manager | | | | |
| IR Lead | | | | |
| CISO | | | | |
| Legal Counsel | | | | |
| External IR Retainer | | | | |
| Law Enforcement Contact | | | | |

## 6. Out-of-Hours Escalation

- **On-call SOC:** {{ oncall_phone | default('[On-call phone number]') }}
- **SOC Manager mobile:** {{ soc_mgr_mobile | default('[Mobile]') }}
- **IR Retainer hotline:** {{ ir_retainer | default('[Retainer hotline]') }}""")

T("doc:communication_plan", "Communication Plan", "SOP",
  "Internal and external communication procedures and templates during incidents",
  ["governance", "soc-cmm", "communications"],
  """## 1. Purpose

Define communication procedures, channels, templates, and responsibilities during security incidents and BAU operations.

## 2. Communication Channels

| Channel | Purpose | Audience | Classification |
|---------|---------|----------|---------------|
| SOC Slack/Teams channel | Real-time ops coordination | SOC team | INTERNAL |
| Incident bridge (conf call) | Active incident coordination | IR team + stakeholders | CONFIDENTIAL |
| Email — security-incidents@ | Incident notifications | Management + IT | CONFIDENTIAL |
| Email — all-staff | User awareness / phishing alerts | All employees | INTERNAL |
| Ticketing system | Incident tracking and audit trail | SOC + IT | INTERNAL |
| External portal | Customer/partner notifications | External stakeholders | Per classification |

## 3. Incident Communication Templates

### 3.1 Internal Stakeholder Notification
```
Subject: [SEVERITY] Security Incident — [Brief Description]
Priority: [P1/P2/P3/P4]
Status: [Investigating / Contained / Resolved]

Summary: [2-3 sentence description]
Impact: [Affected systems/users/data]
Current Actions: [What the SOC is doing]
Business Impact: [Operational / financial / regulatory]
Next Update: [Time of next scheduled update]

SOC Contact: [Name, phone, email]
```

### 3.2 Executive Briefing
```
Subject: Executive Briefing — Security Incident [ID]

Timeline: [When detected, key milestones]
Root Cause: [If known, or current hypothesis]
Business Impact: [Revenue, operations, data, reputation]
Regulatory: [Notification obligations, deadlines]
Containment Status: [Actions taken, effectiveness]
Recovery ETA: [Estimated time to full recovery]
Recommendations: [Immediate decisions needed]
```

### 3.3 Breach Notification (Regulatory)
```
Refer to legal counsel before sending.
[Follows GDPR Article 33/34 or applicable regulation template]
```

## 4. Communication Cadence During Incidents

| Severity | Internal Updates | Exec Updates | External |
|----------|-----------------|--------------|----------|
| P1 | Every 30 minutes | Every 1 hour | As required by legal |
| P2 | Every 2 hours | Every 4 hours | If customer impacted |
| P3 | Every 8 hours | Daily summary | N/A |
| P4 | Closure only | Weekly report | N/A |

## 5. Media & Public Communications

All external communications must be approved by:
1. Legal Counsel
2. CISO
3. Communications/PR team

**No SOC staff shall communicate with media directly.**""")

T("doc:service_catalogue", "SOC Service Catalogue", "KB",
  "SOC services offered with SLAs, KPIs, and service descriptions",
  ["governance", "soc-cmm", "services"],
  """## 1. Purpose

Define the services provided by the SOC, including service levels, KPIs, and delivery model.

## 2. Service Catalogue

### 2.1 Security Monitoring & Detection
| Attribute | Detail |
|-----------|--------|
| Description | Continuous monitoring of security events across all in-scope systems |
| Hours | 24/7/365 |
| SLA | Alert triage within 15 minutes of generation |
| KPI | MTTD < 1 hour; False positive rate < 30% |
| Tools | {{ siem_tool | default('SIEM, EDR, NDR, Cloud CSPM') }} |

### 2.2 Incident Response
| Attribute | Detail |
|-----------|--------|
| Description | Investigation, containment, eradication, and recovery for security incidents |
| Hours | 24/7/365 |
| SLA | P1: 1hr response; P2: 4hr; P3: 8hr; P4: 24hr |
| KPI | MTTR by severity; incidents resolved without re-occurrence |

### 2.3 Threat Intelligence
| Attribute | Detail |
|-----------|--------|
| Description | Collection, analysis, and dissemination of threat intelligence |
| Hours | Business hours + on-call |
| SLA | Critical IOC dissemination within 30 minutes |
| KPI | IOC integration rate; threat briefing frequency |

### 2.4 Detection Engineering
| Attribute | Detail |
|-----------|--------|
| Description | Development, testing, and tuning of detection rules and analytics |
| Hours | Business hours |
| SLA | New detection rule within 48 hours of identified gap |
| KPI | Detection coverage %; rules tuned per month |

### 2.5 Vulnerability Coordination
| Attribute | Detail |
|-----------|--------|
| Description | Vulnerability scanning coordination, risk assessment, remediation tracking |
| Hours | Business hours |
| SLA | Critical vulns reported within 4 hours; tracked to remediation |
| KPI | Mean time to remediate by severity |

### 2.6 Forensic Analysis
| Attribute | Detail |
|-----------|--------|
| Description | Digital forensic investigation and evidence handling |
| Hours | On-demand + on-call |
| SLA | Forensic acquisition within 4 hours of request |
| KPI | Evidence integrity rate; investigation closure time |

## 3. Service Request Process

All service requests via: {{ ticket_system | default('[Ticketing system / portal]') }}""")

# --- INCIDENT RESPONSE ---

T("doc:ir_plan", "Incident Response Plan", "IRP",
  "End-to-end IR lifecycle aligned to NIST SP 800-61",
  ["incident-response", "soc-cmm", "nist-800-61"],
  """## 1. Purpose

Establish a structured approach to managing security incidents, aligned with NIST SP 800-61 Rev. 2.

## 2. Scope

This plan covers all cyber security incidents affecting {{ org_name | default('[Organisation]') }} systems, networks, data, and personnel.

## 3. Incident Lifecycle (NIST SP 800-61)

```
1. Preparation → 2. Detection & Analysis → 3. Containment, Eradication & Recovery → 4. Post-Incident Activity
```

## 4. Phase 1 — Preparation

- [ ] IR team identified and trained
- [ ] Communication plan established
- [ ] Escalation matrix current
- [ ] IR tools and jump bag ready
- [ ] Forensic workstation configured
- [ ] External retainer contract active
- [ ] Tabletop exercises conducted (quarterly)

## 5. Phase 2 — Detection & Analysis

### 5.1 Detection Sources
- SIEM alerts and correlation rules
- EDR detections
- Network anomaly detection (NDR)
- User reports (phishing, suspicious activity)
- Threat intelligence feeds
- External notification (CERT, partners, law enforcement)

### 5.2 Analysis Process
1. Validate alert — confirm true positive
2. Classify severity (P1–P4) using severity matrix
3. Determine scope — affected systems, accounts, data
4. Identify attack vector and indicators of compromise
5. Document findings in incident ticket

## 6. Phase 3 — Containment, Eradication & Recovery

### 6.1 Containment Strategies

| Strategy | When to Use | Authority |
|----------|------------|-----------|
| Network isolation | Active C2, lateral movement | Shift Lead+ |
| Account disable | Compromised credentials | L2 Analyst+ |
| Endpoint quarantine | Malware, ransomware | L1 Analyst+ (via EDR) |
| DNS sinkhole | C2 domains identified | Detection Engineer |
| Firewall block | Malicious IPs confirmed | Shift Lead+ |

### 6.2 Eradication
- Remove malware and persistence mechanisms
- Patch exploited vulnerabilities
- Reset compromised credentials
- Verify removal across all affected systems

### 6.3 Recovery
- Restore from clean backups where necessary
- Verify system integrity before returning to production
- Enhanced monitoring for 30 days post-incident
- Confirm with system owners before service restoration

## 7. Phase 4 — Post-Incident Activity

- Lessons learned meeting within 5 business days
- Update detection rules based on findings
- Update playbooks if gaps identified
- Executive summary report within 10 business days
- Evidence retained per retention policy

## 8. Incident Classification

Refer to **Severity Classification Matrix** for detailed criteria.

## 9. Legal & Regulatory Considerations

- GDPR: 72-hour notification to supervisory authority
- Engage legal counsel for any incident involving personal data
- Preserve evidence for potential law enforcement referral""")

T("doc:ir_playbooks", "IR Playbooks / Runbooks", "RUNBOOK",
  "Step-by-step playbooks per incident type",
  ["incident-response", "soc-cmm", "runbook", "playbook"],
  """## 1. Purpose

Provide step-by-step response procedures for common incident types. Each playbook follows the detect → analyse → contain → eradicate → recover → lessons learned flow.

---

## Playbook 1: Phishing / Business Email Compromise

### Detection
- User report via phishing button or helpdesk
- Email gateway alert (malicious URL/attachment)
- EDR alert on payload execution

### Analysis
1. Extract email headers — identify sender, reply-to, return-path
2. Analyse URLs/attachments in sandbox
3. Search mailbox logs for other recipients
4. Check if any user clicked/opened

### Containment
1. Block sender domain/IP at email gateway
2. Purge email from all mailboxes (admin search & destroy)
3. Block malicious URLs at proxy/DNS
4. If credentials entered: force password reset, revoke sessions
5. If payload executed: isolate endpoint via EDR

### Eradication & Recovery
1. Remove any installed malware/persistence
2. Reset compromised credentials + enable MFA
3. Monitor for follow-up attacks (48 hours)

---

## Playbook 2: Malware / Ransomware

### Detection
- EDR detection / AV alert
- Anomalous file encryption activity
- Network beaconing (C2)

### Analysis
1. Identify malware family and capabilities
2. Determine infection vector (email, drive-by, lateral movement)
3. Scope: identify all affected hosts
4. Check for data exfiltration indicators

### Containment
1. Isolate affected hosts (network + EDR containment)
2. Block C2 domains/IPs at firewall and DNS
3. Disable compromised service accounts
4. Preserve forensic images before remediation

### Eradication & Recovery
1. Wipe and rebuild affected systems (do not trust cleanup alone for ransomware)
2. Restore data from clean backups (verify backup integrity)
3. Patch exploitation vector
4. Reset all credentials on affected systems
5. Enhanced monitoring for 30 days

---

## Playbook 3: Unauthorised Access / Compromised Account

### Detection
- Impossible travel alert
- Anomalous login (new device, location, time)
- Privilege escalation detection

### Analysis
1. Review authentication logs — timeline of access
2. Determine what was accessed/modified
3. Check for persistence (MFA changes, forwarding rules, OAuth apps)
4. Identify initial compromise vector

### Containment
1. Force sign-out all sessions
2. Reset password and MFA
3. Review and revoke suspicious OAuth/app consents
4. Remove email forwarding rules

### Eradication & Recovery
1. Review all changes made during compromise window
2. Restore any modified data
3. User awareness discussion
4. Monitor account for 30 days

---

## Playbook 4: Data Exfiltration / Data Loss

*[Expand with specific procedures for your environment]*

## Playbook 5: Insider Threat

*[Expand — coordinate with HR and Legal]*

## Playbook 6: DDoS Attack

*[Expand — coordinate with ISP and CDN provider]*

## Playbook 7: Supply Chain Compromise

*[Expand — third-party risk assessment and isolation]*""")

T("doc:severity_matrix", "Severity Classification Matrix", "SOP",
  "Incident severity levels, criteria, and response targets",
  ["incident-response", "soc-cmm", "classification"],
  """## 1. Purpose

Provide consistent criteria for classifying security incident severity to ensure appropriate response.

## 2. Severity Matrix

| Level | Name | Criteria | Response Time | Update Cadence | Exec Notify |
|-------|------|----------|---------------|----------------|-------------|
| **P1** | Critical | Active data breach; ransomware spreading; critical system down; APT confirmed | 15 min | 30 min | Immediately |
| **P2** | High | Confirmed compromise contained; malware on multiple hosts; privileged account compromised | 1 hour | 2 hours | Within 1 hour |
| **P3** | Medium | Suspicious activity under investigation; single host compromised; phishing with credential entry | 4 hours | 8 hours | Daily summary |
| **P4** | Low | Policy violation; blocked attack; reconnaissance; informational alert | 24 hours | Closure | Weekly report |

## 3. Classification Criteria Detail

### P1 — Critical
- Confirmed data exfiltration of sensitive/regulated data
- Ransomware actively encrypting systems
- Attacker has domain admin or equivalent access
- Critical business systems unavailable due to security incident
- Regulatory notification obligations triggered

### P2 — High
- Confirmed malware with C2 communication (contained)
- Compromised privileged account (admin, service account)
- Multiple hosts showing indicators of compromise
- Successful exploitation of critical vulnerability
- Insider threat with evidence of data access

### P3 — Medium
- Single compromised host (contained)
- Successful phishing with credential entry (no confirmed misuse)
- Anomalous behaviour requiring investigation
- Unauthorized software installation
- Policy violation with potential security impact

### P4 — Low
- Blocked brute-force attempts
- Phishing email received but no user interaction
- Vulnerability scan findings (no active exploitation)
- Minor policy deviations
- Security awareness gaps identified

## 4. Severity Adjustment Factors

Severity may be **escalated** if:
- Regulated data (PII, PHI, PCI) is involved
- Customer-facing systems are affected
- Media attention is likely
- Multiple business units impacted
- Attack is ongoing / spreading

Severity may be **de-escalated** if:
- Confirmed false positive after investigation
- Impact limited to non-production/test systems
- Attacker activity ceased and fully contained""")

T("doc:triage_guide", "Triage & Classification Guide", "RUNBOOK",
  "Alert triage decision trees, workflows, and classification criteria",
  ["incident-response", "soc-cmm", "triage"],
  """## 1. Purpose

Guide L1/L2 analysts through consistent alert triage and classification decisions.

## 2. Triage Workflow

```
Alert Received
  ├── Is this a known false positive? → YES → Close (FP), update tuning backlog
  └── NO
      ├── Enrich: user context, asset criticality, threat intel
      ├── Validate: can activity be confirmed from secondary source?
      │    ├── NO → Request additional logs, set 2hr follow-up
      │    └── YES
      │         ├── Is this malicious? → YES → Classify severity → Escalate per matrix
      │         └── Suspicious but unconfirmed → P3/P4, investigate
      └── Document decision in ticket
```

## 3. Enrichment Checklist

For every alert, gather:
- [ ] User identity — role, department, normal behaviour
- [ ] Source/destination — asset criticality, business function
- [ ] Threat intel — IOC match, known campaign
- [ ] Historical context — has this fired before? Previous outcome?
- [ ] Network context — internal ↔ external, lateral movement indicators

## 4. Common Alert Types — Triage Guide

### 4.1 EDR Alerts
| Alert Type | Likely FP? | Key Check | Escalate If |
|-----------|-----------|-----------|-------------|
| Suspicious PowerShell | Medium | Check if admin/IT user, script source | Encoded commands, download cradle |
| Malware detected | Low | Check EDR action (quarantined?) | Not quarantined, persistence indicators |
| Credential dump tool | Low | Check if pentest scheduled | Any unplanned use |
| Ransomware behaviour | Very Low | Verify file encryption activity | Always escalate P1 |

### 4.2 SIEM Correlation Rules
| Rule | Key Check | Escalate If |
|------|-----------|-------------|
| Impossible travel | Check VPN, mobile, shared accounts | Confirmed anomalous + sensitive access |
| Brute force success | Verify if final login succeeded | Successful auth after failures |
| Data exfil volume | Check if backup/sync job | Unusual destination or time |
| New admin account | Check change management | No corresponding change ticket |

### 4.3 Email Security
| Alert | Key Check | Escalate If |
|-------|-----------|-------------|
| Phishing reported | Sandbox URL/attachment | User clicked + entered creds |
| BEC detected | Verify sender authenticity | Wire transfer or data request |
| Malicious attachment | Check if executed | Payload executed on endpoint |

## 5. Disposition Codes

| Code | Meaning | Action |
|------|---------|--------|
| TP | True Positive | Create incident, follow playbook |
| FP | False Positive | Close, add to tuning backlog |
| BTP | Benign True Positive | Legitimate activity, close, document |
| INC | Inconclusive | Escalate to L2 with findings |""")

T("doc:lessons_learned", "Lessons Learned Repository", "AAR",
  "Post-incident review template and improvement tracking",
  ["incident-response", "soc-cmm", "lessons-learned", "after-action"],
  """## 1. Purpose

Capture findings from security incidents and near-misses to drive continuous improvement.

## 2. Incident Summary

| Field | Detail |
|-------|--------|
| Incident ID | {{ incident_id | default('[INC-XXXX]') }} |
| Date Detected | {{ detect_date | default('[Date]') }} |
| Date Resolved | {{ resolve_date | default('[Date]') }} |
| Severity | {{ severity | default('[P1/P2/P3/P4]') }} |
| Lead Investigator | {{ investigator | default('[Name]') }} |

## 3. What Happened?

*[Narrative description of the incident from detection through resolution]*

## 4. Timeline

| Time (UTC) | Event |
|-----------|-------|
| | Initial alert |
| | Triage begun |
| | Severity classified |
| | Containment action |
| | Eradication complete |
| | Recovery confirmed |
| | Incident closed |

## 5. What Went Well?

- *[What worked effectively during the response?]*

## 6. What Needs Improvement?

| # | Finding | Category | Priority | Owner | Due Date | Status |
|---|---------|----------|----------|-------|----------|--------|
| 1 | | Detection / Process / Tools / Training / Communication | | | | |
| 2 | | | | | | |
| 3 | | | | | | |

## 7. Root Cause Analysis

**Immediate cause:** *[What directly caused the incident]*

**Contributing factors:** *[What enabled or worsened the incident]*

**Root cause:** *[Underlying systemic issue]*

## 8. Action Items

| # | Action | Owner | Priority | Due Date | Status |
|---|--------|-------|----------|----------|--------|
| 1 | | | | | |
| 2 | | | | | |

## 9. Metrics

| Metric | Value |
|--------|-------|
| Time to Detect | |
| Time to Contain | |
| Time to Eradicate | |
| Time to Recover | |
| Total Duration | |""")

T("doc:evidence_handling", "Evidence Handling Procedures", "SOP",
  "Chain of custody, preservation, forensic acquisition, and legal hold",
  ["incident-response", "soc-cmm", "forensics", "evidence"],
  """## 1. Purpose

Define procedures for collecting, preserving, and handling digital evidence to maintain forensic integrity and legal admissibility.

## 2. Principles

- **Minimise handling** — work on forensic copies, never originals
- **Document everything** — every action, every access, every transfer
- **Maintain chain of custody** — unbroken record from collection to disposal
- **Use write-blockers** — prevent modification during acquisition
- **Hash everything** — SHA-256 before and after acquisition

## 3. Evidence Collection Procedure

### 3.1 Volatile Evidence (collect first — order of volatility)
1. Running processes and network connections
2. Memory (RAM) dump
3. Temporary files and swap
4. Network traffic capture
5. System logs

### 3.2 Non-Volatile Evidence
1. Disk forensic image (full bit-for-bit)
2. Log files (SIEM, firewall, proxy, DNS)
3. Email headers and content
4. Cloud service audit logs
5. Physical evidence (if applicable)

## 4. Chain of Custody Form

| Field | Value |
|-------|-------|
| Evidence ID | |
| Description | |
| Source system | |
| Collected by | |
| Collection date/time | |
| Collection method | |
| SHA-256 hash | |
| Storage location | |

### Transfer Log

| Date/Time | From | To | Purpose | Signature |
|-----------|------|----|---------|-----------|
| | | | | |

## 5. Evidence Storage

- Encrypted storage (AES-256) with access logging
- Physical: locked evidence room/safe with sign-in log
- Digital: dedicated forensic evidence server, restricted access
- Retention: per incident severity and legal requirements

## 6. Legal Hold

When instructed by Legal:
1. Preserve all evidence related to specified custodians/systems
2. Suspend normal data deletion/rotation for affected data
3. Document scope of hold
4. Notify relevant system administrators
5. Maintain hold until written release from Legal""")

# --- OPERATIONS & PROCESSES ---

T("doc:sops", "Standard Operating Procedures", "SOP",
  "Day-to-day SOC operational procedures",
  ["operations", "soc-cmm", "sop"],
  """## 1. Purpose

Define standard operating procedures for daily SOC operations.

## 2. Daily Operations Checklist

### Start of Shift
- [ ] Review shift handover notes
- [ ] Check SIEM dashboard for overnight alerts
- [ ] Review open incident queue
- [ ] Verify all monitoring tools are operational (health checks)
- [ ] Check threat intelligence feed for new IOCs
- [ ] Review scheduled maintenance/change windows

### During Shift
- [ ] Triage new alerts per triage guide
- [ ] Update open incident tickets (every 2 hours minimum)
- [ ] Escalate per escalation matrix
- [ ] Document all actions in ticketing system
- [ ] Monitor SOC communication channels

### End of Shift
- [ ] Complete shift handover document
- [ ] Brief incoming shift on active incidents
- [ ] Ensure no unacknowledged critical alerts
- [ ] Update shift log

## 3. Alert Handling SOP

1. New alert appears in SIEM queue
2. L1 analyst claims alert within 15 minutes
3. Perform initial triage (see Triage Guide)
4. Classify: TP / FP / BTP / Inconclusive
5. If TP: create incident ticket, classify severity, follow playbook
6. If FP: close with reason, add to tuning backlog
7. Document all findings and actions

## 4. Tool Health Monitoring

| Tool | Health Check | Frequency | Action if Down |
|------|-------------|-----------|----------------|
| SIEM | Dashboard + ingestion rate | Every 30 min | Page on-call engineer |
| EDR | Agent check-in rate | Hourly | Ticket to IT ops |
| Firewall | Log flow rate | Every 30 min | Escalate to network team |
| Email gateway | Queue depth + detection rate | Hourly | Escalate to email admin |
| Threat intel feeds | Last update timestamp | Daily | Check feed provider status |

## 5. Ticket Management

- All security events tracked in {{ ticket_system | default('[Ticketing System]') }}
- Minimum fields: severity, category, affected assets, status, owner, timeline
- Update frequency: P1 every 30min, P2 every 2hr, P3 every 8hr, P4 at closure
- Closure requires: root cause, actions taken, lessons learned (P1/P2)""")

T("doc:shift_handover", "Shift Handover Procedures", "SOP",
  "Shift transition checklists and protocols",
  ["operations", "soc-cmm", "shift-handover"],
  """## 1. Purpose

Ensure continuity of operations during shift transitions with structured information transfer.

## 2. Handover Template

### Shift Summary
| Field | Detail |
|-------|--------|
| Date | |
| Outgoing shift | |
| Incoming shift | |
| Handover time | |

### Active Incidents
| Ticket ID | Severity | Summary | Status | Next Action | Owner |
|-----------|----------|---------|--------|-------------|-------|
| | | | | | |

### Notable Events (not yet incidents)
| Time | Description | Action Taken | Follow-up Needed |
|------|-------------|-------------|-----------------|
| | | | |

### Tool Status
| Tool | Status | Notes |
|------|--------|-------|
| SIEM | OK / Degraded / Down | |
| EDR | OK / Degraded / Down | |
| Firewall | OK / Degraded / Down | |

### Pending Tasks
| Task | Priority | Due | Assigned To |
|------|----------|-----|-------------|
| | | | |

### Threat Intel Highlights
- *[Any new IOCs, campaigns, or advisories relevant to our environment]*

### Scheduled Changes
| Change ID | Description | Window | Impact |
|-----------|-------------|--------|--------|
| | | | |

## 3. Handover Process

1. Outgoing shift lead completes handover template (15 min before shift end)
2. Verbal briefing with incoming shift lead (face-to-face or video)
3. Walk through active incidents and pending tasks
4. Incoming shift lead acknowledges and signs off
5. Handover document posted to SOC channel""")

T("doc:onboarding", "On/Off-boarding Procedures", "SOP",
  "New analyst onboarding checklist and departure procedures",
  ["operations", "soc-cmm", "onboarding"],
  """## 1. Purpose

Standardise the onboarding of new SOC team members and secure off-boarding of departing staff.

## 2. Onboarding Checklist

### Week 1 — Access & Orientation
- [ ] IT accounts provisioned (AD, email, VPN)
- [ ] SOC tool access granted (SIEM, EDR, ticketing, wiki)
- [ ] Appropriate RBAC role assigned in ION
- [ ] Security clearance/background check confirmed
- [ ] NDA and acceptable use policy signed
- [ ] Introduction to team and key stakeholders
- [ ] SOC Charter reviewed and acknowledged
- [ ] Tour of SOC facilities / remote setup verified

### Week 2 — Training
- [ ] SIEM query training and saved searches
- [ ] EDR console navigation and response actions
- [ ] Ticketing system workflow
- [ ] Alert triage process walkthrough
- [ ] Escalation matrix reviewed
- [ ] Shadow experienced analyst (minimum 3 shifts)

### Week 3-4 — Supervised Operations
- [ ] Handle alerts with mentor oversight
- [ ] Complete at least 5 triage exercises
- [ ] Attend one tabletop exercise
- [ ] Review and acknowledge all SOPs and playbooks
- [ ] First solo shift (with senior backup available)

### Month 2+ — Development
- [ ] Assigned to skill development plan
- [ ] Certification roadmap discussed
- [ ] 30-day check-in with SOC Manager
- [ ] Full operational clearance granted

## 3. Off-boarding Checklist

- [ ] Access revoked: SIEM, EDR, ticketing, wiki, VPN, email
- [ ] RBAC role removed in ION
- [ ] Shared credentials rotated (if applicable)
- [ ] Knowledge transfer sessions completed
- [ ] Open tickets reassigned
- [ ] Equipment returned
- [ ] Exit interview conducted
- [ ] Access audit — confirm zero remaining access (48hr post-departure)""")

T("doc:change_mgmt", "Change Management Process", "SOP",
  "Process for SOC tooling and configuration changes",
  ["operations", "soc-cmm", "change-management"],
  """## 1. Purpose

Define the change management process for SOC tools, detection rules, and infrastructure.

## 2. Change Categories

| Category | Description | Approval | Examples |
|----------|------------|----------|---------|
| **Standard** | Pre-approved, low risk | Shift Lead | SIEM saved search, dashboard update |
| **Normal** | Planned, medium risk | SOC Manager | New detection rule, tool config change |
| **Emergency** | Urgent, during incident | Shift Lead + post-review | Firewall block, EDR policy change during IR |

## 3. Change Request Template

| Field | Value |
|-------|-------|
| Change ID | |
| Requester | |
| Category | Standard / Normal / Emergency |
| Description | |
| Justification | |
| Affected systems | |
| Risk assessment | |
| Rollback plan | |
| Testing performed | |
| Implementation date | |
| Approver | |

## 4. Change Process

### Normal Changes
1. Submit change request with justification
2. Peer review (detection rules require testing in staging)
3. SOC Manager approval
4. Schedule implementation window
5. Implement and verify
6. Document outcome and close

### Emergency Changes
1. Implement immediately (document intent)
2. Notify SOC Manager within 1 hour
3. Submit retrospective change request within 24 hours
4. Post-implementation review

## 5. Detection Rule Change Control

All detection rule changes must include:
- Rule logic and description
- Testing evidence (true positive validation)
- Expected alert volume estimate
- False positive assessment
- MITRE ATT&CK mapping
- Peer review sign-off""")

T("doc:monitoring_sops", "Monitoring & Alert SOPs", "SOP",
  "Per-tool monitoring procedures, thresholds, and response actions",
  ["operations", "soc-cmm", "monitoring"],
  """## 1. Purpose

Define monitoring procedures, alert thresholds, and expected response actions for each SOC tool.

## 2. SIEM Monitoring

### Key Dashboards
| Dashboard | Purpose | Review Frequency |
|-----------|---------|-----------------|
| Alert overview | Active alerts by severity | Continuous |
| Log ingestion health | Data source status | Every 30 min |
| Failed logins | Brute force detection | Continuous |
| Firewall denies | Network threats | Continuous |
| New user accounts | Privilege escalation | Hourly |

### Alert Thresholds
| Alert | Threshold | Window | Severity |
|-------|-----------|--------|----------|
| Failed login brute force | > 10 failures | 5 min | P4 (P3 if success follows) |
| Impossible travel | Login from 2+ countries | 1 hour | P3 |
| Large data transfer | > {{ data_threshold | default('500MB') }} outbound | 1 hour | P3 |
| New admin account | Any creation outside change window | Immediate | P3 |
| Malware detection | Any | Immediate | P2 |

## 3. EDR Monitoring

| Alert Category | Expected Action | Escalation Criteria |
|----------------|----------------|---------------------|
| Malware detected — quarantined | Verify quarantine, investigate source | If not quarantined, escalate P2 |
| Suspicious behaviour | Investigate process tree, network connections | Confirmed malicious → P2/P3 |
| Ransomware indicator | Immediately isolate host | Always P1 |
| Credential dumping | Isolate host, reset affected credentials | Always P2 |

## 4. Network Monitoring

| Source | What to Watch | Threshold |
|--------|--------------|-----------|
| Firewall | Denied traffic spikes, geo-anomalies | 5x baseline |
| DNS | Queries to known-bad domains, DGA patterns | Any IOC match |
| Proxy | Connections to uncategorised sites, tunnelling | Anomaly detection |
| NetFlow | Unusual internal lateral traffic | New host pairs |

## 5. Cloud Monitoring

| Cloud Service | Key Signals |
|--------------|-------------|
| Azure AD / Entra ID | Risky sign-ins, conditional access failures, MFA changes |
| AWS CloudTrail | Root login, IAM changes, S3 public access |
| M365 | Forwarding rules, OAuth app consents, DLP alerts |""")

# --- TECHNICAL DOCUMENTATION ---

T("doc:log_sources", "Log Source Inventory", "KB",
  "All ingested log sources, coverage gaps, and data owners",
  ["technical", "soc-cmm", "logging", "data-sources"],
  """## 1. Purpose

Maintain a comprehensive inventory of all log sources ingested by the SOC, including coverage gaps and data quality.

## 2. Log Source Registry

| # | Source | Type | Log Format | Ingestion Method | EPS (avg) | Retention | Owner | Status |
|---|--------|------|-----------|-----------------|-----------|-----------|-------|--------|
| 1 | Firewall — Primary | Network | Syslog/CEF | Syslog → SIEM | | 90 days | Network team | Active |
| 2 | Windows DCs | Endpoint | WinEventLog | Agent | | 90 days | IT Ops | Active |
| 3 | Linux servers | Endpoint | Syslog | Rsyslog → SIEM | | 90 days | IT Ops | Active |
| 4 | EDR | Endpoint | JSON/API | API pull | | 180 days | SOC | Active |
| 5 | Email gateway | Email | JSON | API/Syslog | | 90 days | Email admin | Active |
| 6 | Cloud (Azure/AWS) | Cloud | JSON | API connector | | 90 days | Cloud team | Active |
| 7 | DNS | Network | Syslog | Passive DNS | | 30 days | Network team | Active |
| 8 | Proxy / Web gateway | Network | CEF/Syslog | Syslog → SIEM | | 90 days | Network team | Active |
| 9 | VPN | Network | Syslog | Syslog → SIEM | | 90 days | Network team | Active |
| 10 | Database audit | Application | Varies | Agent/API | | 90 days | DBA team | Active |

## 3. Coverage Gap Analysis

| Gap Area | Missing Source | Risk | Priority | Remediation Plan |
|----------|--------------|------|----------|-----------------|
| | | High/Med/Low | | |

## 4. Data Quality Monitoring

| Metric | Target | Current | Alert Threshold |
|--------|--------|---------|----------------|
| Ingestion latency | < 5 min | | > 15 min |
| Missing sources | 0 | | Any source silent > 1hr |
| Parse failure rate | < 1% | | > 5% |
| Field extraction rate | > 95% | | < 90% |""")

T("doc:asset_inventory", "Asset Inventory", "KB",
  "Critical assets, owners, classification, and business impact",
  ["technical", "soc-cmm", "assets", "cmdb"],
  """## 1. Purpose

Maintain awareness of critical assets to enable risk-based alerting, triage, and incident response.

## 2. Asset Classification

| Tier | Classification | Description | Examples |
|------|---------------|-------------|---------|
| 1 | Crown Jewels | Business-critical, revenue-impacting | ERP, payment systems, customer DB |
| 2 | High Value | Important operational systems | Email, Active Directory, VPN |
| 3 | Standard | General business systems | File servers, printers, dev systems |
| 4 | Low | Non-critical, test/sandbox | Dev environments, labs |

## 3. Critical Asset Register

| Asset Name | IP/FQDN | Tier | Business Function | Owner | OS/Platform | Location | Monitoring Status |
|-----------|---------|------|-------------------|-------|-------------|----------|-------------------|
| | | | | | | | |

## 4. Asset-to-Detection Mapping

| Asset Tier | Required Detection Coverage |
|-----------|---------------------------|
| Tier 1 | EDR + SIEM + NDR + enhanced alerting rules + 24/7 monitoring |
| Tier 2 | EDR + SIEM + standard detection rules |
| Tier 3 | SIEM log collection + baseline detection rules |
| Tier 4 | Basic log collection |

## 5. Review Schedule

- Full inventory review: **Quarterly**
- Tier 1 assets: **Monthly** verification
- New asset onboarding: within **5 business days** of deployment""")

T("doc:network_diagrams", "Network Diagrams", "KB",
  "Network topology, segmentation, trust boundaries, and data flows",
  ["technical", "soc-cmm", "network", "architecture"],
  """## 1. Purpose

Maintain current network diagrams to support incident investigation, threat hunting, and architecture review.

## 2. Required Diagrams

### 2.1 High-Level Network Topology
*[Insert or link to diagram showing major network zones, interconnections, and internet egress points]*

### 2.2 Network Segmentation / Zone Map

| Zone | VLAN/Subnet | Purpose | Trust Level | Key Controls |
|------|------------|---------|-------------|-------------|
| DMZ | | Internet-facing services | Untrusted | WAF, IDS, strict ACLs |
| Corporate | | User workstations | Medium | NAC, EDR, proxy |
| Server | | Internal servers | High | Microsegmentation, PAM |
| Management | | Admin access | Critical | Jump server, MFA, logging |
| OT/ICS | | Operational technology | Isolated | Air-gap / data diode |
| Cloud | | AWS/Azure/GCP | Per workload | CSP controls + CSPM |

### 2.3 Data Flow Diagram
*[Insert or link to diagram showing how sensitive data flows between systems]*

### 2.4 Trust Boundary Map
*[Insert or link to diagram showing trust boundaries and control points]*

## 3. SOC-Relevant Network Details

| Item | Detail |
|------|--------|
| Internet egress points | |
| DNS resolvers | |
| SIEM collectors | |
| EDR management server | |
| Jump/bastion hosts | |
| VPN concentrators | |

## 4. Diagram Maintenance

- Diagrams updated within **5 business days** of any network change
- Stored in: {{ diagram_location | default('[SharePoint / Confluence / Git repo]') }}
- Format: {{ diagram_format | default('Visio / draw.io / Lucidchart') }}
- Reviewed: **Quarterly** by network + SOC teams""")

T("doc:detection_standards", "Detection Engineering Standards", "SOI",
  "Rule naming, testing, lifecycle, tuning, and MITRE ATT&CK mapping",
  ["technical", "soc-cmm", "detection-engineering", "mitre-attack"],
  """## 1. Purpose

Define standards for the development, testing, deployment, and lifecycle management of detection rules.

## 2. Rule Naming Convention

```
[SEVERITY]-[PLATFORM]-[TECHNIQUE]-[Description]
Example: HIGH-SIEM-T1059.001-PowerShell_Encoded_Command
```

## 3. Rule Development Lifecycle

```
Idea → Design → Develop → Test → Review → Deploy → Monitor → Tune → Retire
```

### 3.1 Design Phase
- Define detection hypothesis
- Map to MITRE ATT&CK technique(s)
- Identify required data sources
- Estimate expected alert volume

### 3.2 Testing Requirements
- [ ] Tested against known-true-positive data (red team / atomic tests)
- [ ] Tested against 30 days of production data for FP rate
- [ ] Expected EPS / alert volume documented
- [ ] Performance impact assessed

### 3.3 Peer Review Checklist
- [ ] Logic is correct and efficient
- [ ] MITRE ATT&CK mapping accurate
- [ ] Severity appropriate
- [ ] Response procedure documented or linked to playbook
- [ ] False positive handling documented

## 4. Rule Documentation Template

| Field | Value |
|-------|-------|
| Rule Name | |
| Rule ID | |
| Author | |
| Created | |
| MITRE ATT&CK | Tactic: / Technique: / Sub-technique: |
| Data Source | |
| Severity | Critical / High / Medium / Low / Informational |
| Description | |
| Detection Logic | |
| True Positive Indicators | |
| False Positive Scenarios | |
| Response Playbook | |
| Tuning Notes | |

## 5. Tuning Process

| Metric | Threshold | Action |
|--------|-----------|--------|
| FP rate > 50% for 7 days | Immediate | Tune or disable, investigate root cause |
| FP rate > 30% for 30 days | Normal | Schedule tuning |
| Zero alerts for 90 days | Review | Verify data source still active, consider retiring |
| TP confirmed | Validate | Ensure response playbook is adequate |

## 6. MITRE ATT&CK Coverage Tracking

Maintain a coverage map showing:
- Which techniques have at least one detection rule
- Which techniques are tested vs untested
- Coverage gaps prioritised by threat landscape relevance""")

T("doc:tool_admin", "Tool Administration Guides", "KB",
  "SIEM, EDR, SOAR administration, configuration, and maintenance",
  ["technical", "soc-cmm", "tool-admin"],
  """## 1. Purpose

Document administration procedures for SOC tools to ensure operational continuity and knowledge sharing.

## 2. Tool Inventory

| Tool | Purpose | Version | Admin Access | Vendor Support | License Expiry |
|------|---------|---------|-------------|---------------|----------------|
| {{ siem_name | default('SIEM') }} | Log collection & correlation | | | | |
| {{ edr_name | default('EDR') }} | Endpoint detection & response | | | | |
| {{ soar_name | default('SOAR') }} | Orchestration & automation | | | | |
| {{ ti_platform | default('TIP') }} | Threat intelligence | | | | |
| {{ ticketing | default('Ticketing') }} | Case management | | | | |

## 3. Per-Tool Admin Guide

### 3.1 SIEM Administration
- **Backup:** *[Schedule, location, restore procedure]*
- **User management:** *[Role-based access, provisioning]*
- **Index/data management:** *[Retention policies, index lifecycle]*
- **Connector management:** *[Adding/modifying data sources]*
- **Rule management:** *[Import, export, backup detection rules]*
- **Performance monitoring:** *[Key metrics, scaling thresholds]*
- **Upgrade procedure:** *[Tested upgrade path, rollback plan]*

### 3.2 EDR Administration
- **Agent deployment:** *[Deployment method, group policies]*
- **Policy management:** *[Prevention vs detection modes]*
- **Exclusions:** *[Approved exclusions and justification]*
- **Response actions:** *[Network isolation, process kill, remediation]*
- **Upgrade procedure:** *[Agent and console update process]*

### 3.3 Additional Tools
*[Repeat structure for each SOC tool]*

## 4. Break-Glass Procedures

| Scenario | Procedure | Contact |
|----------|-----------|---------|
| SIEM down | | |
| EDR console inaccessible | | |
| Admin account locked out | | |

## 5. Maintenance Schedule

| Task | Frequency | Owner | Last Completed |
|------|-----------|-------|----------------|
| SIEM health check | Weekly | | |
| EDR agent audit | Monthly | | |
| Certificate renewal | Before expiry | | |
| License audit | Quarterly | | |
| Backup test restore | Quarterly | | |""")

T("doc:use_case_catalogue", "Use Case Catalogue", "KB",
  "Detection use cases mapped to MITRE ATT&CK with coverage gaps",
  ["technical", "soc-cmm", "detection", "mitre-attack", "use-cases"],
  """## 1. Purpose

Catalogue all detection use cases with MITRE ATT&CK mapping to identify coverage and gaps.

## 2. Use Case Register

| ID | Use Case | MITRE Tactic | MITRE Technique | Data Source | Rule/Alert Name | Status | Priority |
|----|----------|-------------|----------------|-----------|----------------|--------|----------|
| UC-001 | Brute force login | Credential Access | T1110 | AD logs, VPN | | Active | |
| UC-002 | Encoded PowerShell | Execution | T1059.001 | EDR, Sysmon | | Active | |
| UC-003 | Lateral movement (PsExec) | Lateral Movement | T1021.002 | EDR, WinEventLog | | Active | |
| UC-004 | Data exfiltration (volume) | Exfiltration | T1048 | Proxy, NetFlow | | Active | |
| UC-005 | Ransomware behaviour | Impact | T1486 | EDR | | Active | |
| UC-006 | New admin account | Persistence | T1136 | AD logs | | Active | |
| UC-007 | Phishing link clicked | Initial Access | T1566.002 | Email GW, Proxy | | Active | |
| UC-008 | C2 beaconing | Command & Control | T1071 | NDR, DNS, Proxy | | Active | |
| *[Continue for all use cases]* | | | | | | | |

## 3. Coverage Summary by MITRE Tactic

| Tactic | Use Cases | Active Rules | Coverage % | Gap Priority |
|--------|-----------|-------------|-----------|--------------|
| Initial Access | | | | |
| Execution | | | | |
| Persistence | | | | |
| Privilege Escalation | | | | |
| Defense Evasion | | | | |
| Credential Access | | | | |
| Discovery | | | | |
| Lateral Movement | | | | |
| Collection | | | | |
| Command & Control | | | | |
| Exfiltration | | | | |
| Impact | | | | |

## 4. Gap Analysis & Roadmap

| Priority | Gap | MITRE Technique | Required Data Source | Target Date |
|----------|-----|----------------|--------------------|-----------
| High | | | | |
| Medium | | | | |
| Low | | | | |""")

# --- KNOWLEDGE & TRAINING ---

T("doc:knowledge_base", "Knowledge Base / Wiki", "KB",
  "Central knowledge repository structure and contribution guidelines",
  ["knowledge", "soc-cmm", "wiki"],
  """## 1. Purpose

Define the structure, standards, and contribution process for the SOC knowledge base.

## 2. Knowledge Base Structure

```
SOC Knowledge Base
├── Getting Started
│   ├── SOC Charter
│   ├── Tool Access Guide
│   └── Onboarding Checklist
├── Procedures
│   ├── Alert Triage
│   ├── Incident Response Playbooks
│   └── Standard Operating Procedures
├── Technical Reference
│   ├── SIEM Query Library
│   ├── EDR Response Actions
│   ├── Network Architecture
│   └── Log Source Reference
├── Threat Intelligence
│   ├── Threat Actor Profiles
│   ├── Campaign Tracking
│   └── IOC Repository
├── Training
│   ├── Skill Development Paths
│   ├── Exercise Library
│   └── Certification Guides
└── Lessons Learned
    └── Post-Incident Reviews
```

## 3. Contribution Guidelines

### Article Standards
- **Title:** Clear, descriptive, searchable
- **Structure:** Purpose → Content → References
- **Review:** Peer review before publish
- **Ownership:** Every article has an assigned owner
- **Review cycle:** Minimum annual, or after relevant changes

### Quality Checklist
- [ ] Technically accurate and current
- [ ] No sensitive data (credentials, IPs) in plain text
- [ ] Screenshots/diagrams where helpful
- [ ] Links to related articles
- [ ] Tagged with relevant categories

## 4. Maintenance

| Task | Frequency | Owner |
|------|-----------|-------|
| Stale content audit | Quarterly | SOC Manager |
| New article review | Within 5 days | Peer reviewer |
| Link validation | Monthly | Automated |""")

T("doc:ti_program", "Threat Intelligence Program", "SOI",
  "TI sources, collection processes, analysis framework, and dissemination",
  ["knowledge", "soc-cmm", "threat-intelligence"],
  """## 1. Purpose

Define the SOC threat intelligence program including sources, processes, and dissemination.

## 2. Intelligence Requirements

### Priority Intelligence Requirements (PIRs)
1. Which threat actors are targeting our industry/sector?
2. What TTPs are being used in current campaigns?
3. Are any of our assets or credentials exposed on dark web?
4. What vulnerabilities are being actively exploited in the wild?
5. What are the emerging threats to our technology stack?

## 3. Intelligence Sources

| Source | Type | Frequency | Cost | Owner |
|--------|------|-----------|------|-------|
| Commercial TI feed | Strategic + Tactical | Real-time | Licensed | TI Analyst |
| OSINT feeds (AlienVault, Abuse.ch) | Tactical IOCs | Real-time | Free | TI Analyst |
| ISAC/ISAO membership | Strategic + Operational | Daily | Membership | SOC Manager |
| Vendor advisories | Technical | As published | Included | Detection Eng |
| Dark web monitoring | Operational | Daily | Licensed | TI Analyst |
| Government (NCSC/CISA) | Strategic | As published | Free | TI Analyst |
| Internal telemetry | Tactical | Real-time | N/A | SOC team |

## 4. Intelligence Lifecycle

```
1. Direction (PIRs) → 2. Collection → 3. Processing → 4. Analysis → 5. Dissemination → 6. Feedback
```

## 5. Dissemination Products

| Product | Audience | Frequency | Format |
|---------|----------|-----------|--------|
| Daily TI brief | SOC team | Daily | Slack/Teams post |
| Weekly TI report | SOC + IT management | Weekly | PDF/Email |
| Flash alert | All IT + management | As needed | Email + Slack |
| Quarterly threat landscape | Executive | Quarterly | Presentation |
| IOC feed | SIEM / EDR / Firewall | Real-time | STIX/TAXII / API |

## 6. TI Platform Integration

- IOCs automatically ingested into SIEM for correlation
- Threat actor profiles maintained in {{ ti_platform | default('TIP / OpenCTI') }}
- Detection rules mapped to threat actor TTPs""")

T("doc:training_plan", "Training & Development Plan", "KB",
  "Skills development curriculum, schedule, and training resources",
  ["knowledge", "soc-cmm", "training"],
  """## 1. Purpose

Define the SOC training and skills development program aligned to SOC-CMM requirements.

## 2. Training Matrix by Role

| Topic | L1 Analyst | L2 Analyst | Shift Lead | Det. Engineer | TI Analyst | IR Lead |
|-------|-----------|-----------|-----------|--------------|-----------|---------|
| SIEM fundamentals | Required | Required | Required | Required | Awareness | Required |
| Advanced SIEM queries | Awareness | Required | Required | Expert | Optional | Required |
| EDR operation | Required | Required | Required | Required | Awareness | Required |
| Network analysis | Awareness | Required | Required | Optional | Optional | Required |
| Malware analysis | Optional | Awareness | Awareness | Optional | Awareness | Required |
| Incident management | Awareness | Required | Required | Awareness | Awareness | Expert |
| Threat intelligence | Awareness | Awareness | Awareness | Awareness | Expert | Required |
| Detection development | Awareness | Optional | Awareness | Expert | Optional | Awareness |
| Forensics | Optional | Awareness | Awareness | Optional | Optional | Required |
| Scripting/automation | Optional | Required | Awareness | Expert | Optional | Required |

## 3. Training Calendar

| Month | Training Activity | Target Audience | Delivery |
|-------|------------------|----------------|----------|
| Jan | Annual security refresher | All SOC | Online |
| Feb | Tabletop exercise — ransomware | All SOC | Workshop |
| Mar | Advanced SIEM lab | L2 + Shift Leads | Hands-on lab |
| Apr | Threat hunting workshop | L2 + TI | Workshop |
| May | Tabletop exercise — data breach | All SOC | Workshop |
| Jun | Forensics fundamentals | L2 + IR | Hands-on lab |
| Jul | Detection engineering | Det. Eng + L2 | Workshop |
| Aug | Tabletop exercise — insider threat | All SOC | Workshop |
| Sep | Cloud security monitoring | All SOC | Online |
| Oct | Purple team exercise | All SOC + Red Team | Exercise |
| Nov | Tabletop exercise — supply chain | All SOC | Workshop |
| Dec | Year-end review + planning | SOC Manager + Leads | Meeting |

## 4. External Training Budget

| Type | Annual Budget per Person | Approval |
|------|-------------------------|----------|
| Conference attendance | {{ conf_budget | default('[Amount]') }} | SOC Manager |
| Online courses (SANS, etc.) | {{ course_budget | default('[Amount]') }} | SOC Manager |
| Certification exam + prep | {{ cert_budget | default('[Amount]') }} | SOC Manager |

## 5. Skills Assessment

Skills tracked in ION Skills Matrix — self-assessment + lead validation quarterly.""")

T("doc:cert_roadmap", "Certification Roadmap", "KB",
  "Target certifications per role and recommended timeline",
  ["knowledge", "soc-cmm", "certifications"],
  """## 1. Purpose

Define recommended certifications for each SOC role and progression timeline.

## 2. Certification Matrix

| Certification | Issuer | L1 | L2 | Shift Lead | Det. Eng | TI | IR Lead |
|--------------|--------|----|----|-----------|---------|-------|---------|
| CompTIA Security+ | CompTIA | Year 1 | Prerequisite | Prerequisite | Prerequisite | Prerequisite | Prerequisite |
| CySA+ | CompTIA | Year 2 | Year 1 | Prerequisite | Optional | Optional | Optional |
| GCIA (SANS) | GIAC | Optional | Year 2 | Recommended | Optional | Optional | Recommended |
| GCIH (SANS) | GIAC | Optional | Year 2 | Year 2 | Optional | Optional | Year 1 |
| GCFE (SANS) | GIAC | Optional | Optional | Optional | Optional | Optional | Year 2 |
| GREM (SANS) | GIAC | — | Optional | Optional | Optional | Optional | Recommended |
| CISSP | ISC2 | — | Year 3+ | Year 2+ | Year 3+ | Year 3+ | Year 2+ |
| OSCP | OffSec | — | Optional | Optional | Recommended | Optional | Optional |
| CTIA | EC-Council | — | — | — | — | Year 1 | Optional |
| BTL1/BTL2 | Security Blue Team | Year 1 | Recommended | Optional | Optional | Optional | Optional |

## 3. Certification Support

| Support | Detail |
|---------|--------|
| Exam fees | Covered (first attempt + one retake) |
| Study materials | Budget allocated per person annually |
| Study time | {{ study_hours | default('4 hours per week during work hours') }} |
| Maintenance/CPE | Supported through conference and training attendance |

## 4. Progression Path

```
L1 Analyst: Security+ → CySA+ / BTL1 → choose specialisation
L2 Analyst: CySA+ → GCIH / GCIA → specialisation cert
Shift Lead: GCIH → CISSP → management track
Det. Engineer: CySA+ → OSCP → GREM
TI Analyst: CTIA → GCTI → strategic intelligence
IR Lead: GCIH → GCFE → CISSP
```""")

# --- CONTINUITY & RECOVERY ---

T("doc:bcp", "Business Continuity Plan", "SOP",
  "SOC operational continuity during disruptions and degraded operations",
  ["continuity", "soc-cmm", "bcp"],
  """## 1. Purpose

Ensure SOC operational continuity during disruptions including facility loss, tool failure, and personnel shortages.

## 2. SOC Critical Functions

| Function | Priority | RTO | RPO | Minimum Staff |
|----------|----------|-----|-----|---------------|
| Security monitoring | Critical | 1 hour | 0 | 2 analysts |
| Incident response | Critical | 1 hour | 0 | 1 IR analyst + 1 lead |
| Alert triage | Critical | 2 hours | 1 hour | 1 analyst |
| Threat intelligence | Important | 8 hours | 24 hours | 0 (deferred) |
| Detection engineering | Important | 24 hours | 24 hours | 0 (deferred) |
| Reporting | Normal | 48 hours | 24 hours | 0 (deferred) |

## 3. Disruption Scenarios

### 3.1 Primary SOC Facility Unavailable
- Activate remote operations (all staff work from home)
- VPN access to all SOC tools verified monthly
- Backup communication via {{ backup_comms | default('[Teams / Signal / satellite phone]') }}

### 3.2 SIEM Failure
- Activate direct log source monitoring (EDR console, firewall console)
- Manual log review for critical assets
- Escalate to SIEM vendor support
- **RTO:** 4 hours to vendor engagement, 24 hours to alternate monitoring

### 3.3 EDR Failure
- Increase SIEM alerting sensitivity
- Deploy host-based monitoring scripts to critical servers
- Escalate to EDR vendor support

### 3.4 Staffing Crisis (>50% team unavailable)
- Activate IR retainer for surge capacity
- SOC Manager + available leads cover shifts
- Reduce monitoring scope to Tier 1 assets only
- Defer non-critical activities

### 3.5 Internet/Network Outage
- On-site analysts use local tool consoles
- Out-of-band communication (mobile hotspots, phone bridge)
- Focus on local/internal threat monitoring

## 4. BCP Testing

| Test Type | Frequency | Last Test | Next Test |
|-----------|-----------|-----------|-----------|
| Tabletop — facility loss | Annual | | |
| Remote ops drill | Semi-annual | | |
| Tool failover test | Annual | | |
| Communication test | Quarterly | | |""")

T("doc:dr_plan", "Disaster Recovery Plan", "SOP",
  "Recovery procedures for SOC infrastructure and tooling",
  ["continuity", "soc-cmm", "disaster-recovery"],
  """## 1. Purpose

Define recovery procedures for SOC infrastructure, tools, and data following a disaster or major outage.

## 2. SOC Infrastructure Inventory

| System | Hosting | Backup Method | Backup Freq | RTO | RPO | Recovery Owner |
|--------|---------|-------------|-------------|-----|-----|----------------|
| SIEM | {{ siem_host | default('[On-prem / Cloud]') }} | | Daily | 4hr | 24hr | |
| EDR Console | {{ edr_host | default('[Cloud / On-prem]') }} | Vendor managed | N/A | 1hr | 0 | Vendor |
| Ticketing | | | Daily | 4hr | 24hr | |
| TI Platform | | | Daily | 8hr | 24hr | |
| SOC Wiki/KB | | | Daily | 24hr | 24hr | |
| Forensic workstation | On-prem | Image backup | Weekly | 8hr | 7 days | |

## 3. Recovery Procedures

### 3.1 SIEM Recovery
1. Assess failure scope (hardware, software, data)
2. If cloud: engage vendor support, verify SLA
3. If on-prem: deploy standby instance from latest backup
4. Reconfigure data source connections
5. Verify log ingestion from all sources
6. Validate detection rules are active
7. Confirm alert routing and notification

### 3.2 EDR Recovery
1. Verify cloud management console availability
2. If console down: engage vendor per SLA
3. Confirm agent connectivity (spot-check critical assets)
4. Verify policy enforcement
5. Test response action capability

### 3.3 Full SOC Rebuild (Worst Case)
1. Provision infrastructure (cloud or replacement hardware)
2. Restore SIEM from backup
3. Reconfigure all integrations
4. Restore detection rules and dashboards
5. Restore ticketing and case data
6. Restore knowledge base
7. Validate end-to-end: log → detection → alert → ticket
8. Resume operations

## 4. DR Testing Schedule

| Test | Frequency | Scope | Last Test | Result |
|------|-----------|-------|-----------|--------|
| SIEM backup restore | Semi-annual | Full restore to test instance | | |
| Tool failover | Annual | Primary → secondary | | |
| Full DR exercise | Annual | Simulated full SOC recovery | | |

## 5. Contact List — DR

| Role | Name | Phone | Email |
|------|------|-------|-------|
| SOC Manager | | | |
| IT Infrastructure Lead | | | |
| SIEM Vendor Support | | | |
| EDR Vendor Support | | | |
| Cloud Provider Support | | | |""")

# =========================================================================

def main():
    login()
    print()

    # Create parent collection
    parent = get_or_create_collection(
        "SOC-CMM Document Library",
        "Industry-standard SOC document templates aligned to SOC-CMM Knowledge Management"
    )

    # Create sub-collections
    categories = {
        "Governance & Charter": "SOC charter, organisational structure, RACI, escalation, and communication",
        "Incident Response": "IR plan, playbooks, severity matrix, triage, evidence handling",
        "Operations & Processes": "SOPs, shift handover, onboarding, change management, monitoring",
        "Technical Documentation": "Log sources, assets, network diagrams, detection standards, tool admin",
        "Knowledge & Training": "Knowledge base, threat intelligence program, training, certifications",
        "Continuity & Recovery": "Business continuity and disaster recovery plans",
    }

    cat_ids = {}
    for cat, desc in categories.items():
        cat_ids[cat] = get_or_create_collection(cat, desc, parent_id=parent)

    print()

    # Map doc keys to categories
    cat_map = {}
    for key, name, *_ in TEMPLATES:
        for cat, docs in {
            "Governance & Charter": ["doc:soc_charter", "doc:org_chart", "doc:raci_matrix", "doc:escalation_matrix", "doc:communication_plan", "doc:service_catalogue"],
            "Incident Response": ["doc:ir_plan", "doc:ir_playbooks", "doc:severity_matrix", "doc:triage_guide", "doc:lessons_learned", "doc:evidence_handling"],
            "Operations & Processes": ["doc:sops", "doc:shift_handover", "doc:onboarding", "doc:change_mgmt", "doc:monitoring_sops"],
            "Technical Documentation": ["doc:log_sources", "doc:asset_inventory", "doc:network_diagrams", "doc:detection_standards", "doc:tool_admin", "doc:use_case_catalogue"],
            "Knowledge & Training": ["doc:knowledge_base", "doc:ti_program", "doc:training_plan", "doc:cert_roadmap"],
            "Continuity & Recovery": ["doc:bcp", "doc:dr_plan"],
        }.items():
            if key in docs:
                cat_map[key] = cat
                break

    # Create templates
    for key, name, doc_type, desc, tags, content in TEMPLATES:
        cat = cat_map.get(key, "Governance & Charter")
        create_template(name, content, doc_type, cat_ids[cat], desc, tags)

    print(f"\nDone — {len(TEMPLATES)} SOC document templates seeded.")

if __name__ == "__main__":
    main()
