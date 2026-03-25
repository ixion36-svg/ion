"""SOC Documentation Templates & Framework Alignment.

Pre-built Jinja2 templates for common SOC operational documents,
aligned with NIST 800-61, NIST CSF 2.0, ISO 27035, SANS IR, SOC-CMM, MITRE ATT&CK.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

DOCUMENT_TYPES = {
    "SOP": "Standard Operating Procedure",
    "SOI": "Standard Operating Instruction",
    "WI": "Work Instruction",
    "KB": "Knowledge Base",
    "RUNBOOK": "Runbook",
    "IRP": "Incident Response Plan",
    "AAR": "After-Action Report",
    "THREAT_ADVISORY": "Threat Advisory",
    "DETECTION_RULE": "Detection Rule Documentation",
    "SAL": "Security Assurance Levels",
    "SLA": "Service Level Agreement",
}

# =============================================================================
# Collection definitions
# =============================================================================

COLLECTION_DEFS = [
    {"name": "Standard Operating Procedures", "description": "Formalized operational procedures for SOC activities", "icon": None},
    {"name": "Standard Operating Instructions", "description": "Tactical task-specific instructions", "icon": None},
    {"name": "Work Instructions", "description": "Granular step-by-step task guidance", "icon": None},
    {"name": "Knowledge Base", "description": "Self-service reference documentation", "icon": None},
    {"name": "Runbooks", "description": "Operational procedure guides for routine tasks", "icon": None},
    {"name": "Incident Response Plans", "description": "Strategic incident handling plans", "icon": None},
    {"name": "After-Action Reports", "description": "Post-incident retrospective analysis", "icon": None},
    {"name": "Threat Intelligence", "description": "Threat advisories and actor profiles", "icon": None},
    {"name": "Detection Engineering", "description": "Detection rule documentation", "icon": None},
    {"name": "Security Assurance", "description": "Security assurance frameworks, levels, and audit documentation", "icon": None},
    {"name": "Operational Agreements", "description": "Service level agreements, OLAs, and operational contracts", "icon": None},
]

# =============================================================================
# Template definitions — 22 templates
# =============================================================================

TEMPLATE_DEFS = [
    # =========================================================================
    # SOPs (4)
    # =========================================================================
    {
        "name": "SOC Monitoring & Triage SOP",
        "document_type": "SOP",
        "collection": "Standard Operating Procedures",
        "description": "Standard operating procedure for SOC monitoring, alert triage, and initial response activities.",
        "tags": ["NIST-CSF-2.0", "SOC-CMM"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "SOP-MON-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "classification", "var_type": "string", "required": False, "default_value": "INTERNAL", "description": "Document classification level"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "department", "var_type": "string", "required": False, "default_value": "Security Operations Center", "description": "Owning department"},
            {"name": "review_date", "var_type": "string", "required": False, "default_value": "", "description": "Next review date"},
            {"name": "approved_by", "var_type": "string", "required": False, "default_value": "", "description": "Approval authority"},
            {"name": "siem_tool", "var_type": "string", "required": False, "default_value": "Elastic SIEM", "description": "Primary SIEM platform"},
            {"name": "escalation_contacts", "var_type": "string", "required": False, "default_value": "", "description": "Escalation contact list"},
            {"name": "shift_schedule", "var_type": "string", "required": False, "default_value": "", "description": "Shift schedule description"},
        ],
        "content": """# {{ doc_id }} - SOC Monitoring & Triage SOP

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Classification** | {{ classification }} |
| **Author** | {{ author }} |
| **Department** | {{ department }} |
| **Review Date** | {{ review_date }} |
| **Approved By** | {{ approved_by }} |

---

## 1. Purpose

This Standard Operating Procedure defines the processes and responsibilities for continuous security monitoring, alert triage, and initial incident response within the {{ department }}.

## 2. Scope

This SOP applies to all SOC analysts responsible for monitoring security events and alerts generated by {{ siem_tool }} and associated security tools.

## 3. Roles & Responsibilities

| Role | Responsibility |
|------|---------------|
| **L1 Analyst** | Monitor dashboards, perform initial triage, classify alerts |
| **L2 Analyst** | Deep-dive investigation, correlation analysis, escalation decisions |
| **L3 Analyst / IR Lead** | Advanced threat hunting, incident response coordination |
| **SOC Manager** | Oversight, quality assurance, metrics review |

## 4. Monitoring Procedures

### 4.1 Dashboard Monitoring
- Review {{ siem_tool }} dashboards at the start of each shift
- Monitor real-time alert feed continuously
- Check health status of all log sources and data pipelines
- Review any overnight alerts flagged for follow-up

### 4.2 Alert Queue Management
- Process alerts in priority order (Critical > High > Medium > Low)
- Acknowledge alerts within SLA timeframes
- Document all triage decisions with rationale

## 5. Severity Classification

| Severity | Description | Response SLA | Examples |
|----------|-------------|-------------|----------|
| **Critical** | Active compromise, data exfiltration | 15 minutes | Ransomware execution, active C2 |
| **High** | Likely malicious, immediate risk | 30 minutes | Malware detection, brute force success |
| **Medium** | Potentially malicious, needs investigation | 2 hours | Suspicious process, policy violation |
| **Low** | Informational, low risk | 8 hours | Failed login attempts, scan activity |

## 6. Initial Triage Steps

1. **Verify Alert Legitimacy** - Confirm the alert is not a known false positive
2. **Gather Context** - Review source/destination, user, host, and process details
3. **Check Threat Intelligence** - Query IOCs against threat intelligence feeds
4. **Assess Impact** - Determine affected systems, users, and data
5. **Classify Severity** - Assign severity based on classification table above
6. **Document Findings** - Record all observations in the case management system
7. **Decide Action** - Close as false positive, escalate, or initiate response

## 7. Escalation Criteria

Escalate to the next tier when:
- Alert severity is Critical or High and confirmed malicious
- Multiple correlated alerts suggest an active campaign
- Analyst is unable to determine alert legitimacy within SLA
- Alert involves sensitive systems, executive accounts, or regulated data

**Escalation Contacts:**
{{ escalation_contacts }}

## 8. Metrics & KPIs

| Metric | Target | Measurement |
|--------|--------|-------------|
| Mean Time to Acknowledge (MTTA) | < 15 min (Critical) | Time from alert to first analyst action |
| Mean Time to Triage (MTTT) | < 30 min (Critical) | Time from alert to classification |
| False Positive Rate | < 30% | Alerts closed as FP / Total alerts |
| Escalation Rate | 10-20% | Escalated alerts / Total alerts |

## 9. Shift Schedule

{{ shift_schedule }}

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },
    {
        "name": "Incident Escalation SOP",
        "document_type": "SOP",
        "collection": "Standard Operating Procedures",
        "description": "Standard operating procedure for incident escalation, notification, and communication management.",
        "tags": ["NIST-800-61", "SANS-IR"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "SOP-ESC-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "classification", "var_type": "string", "required": False, "default_value": "INTERNAL", "description": "Document classification level"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "escalation_matrix", "var_type": "text", "required": False, "default_value": "", "description": "Escalation matrix details"},
            {"name": "notification_templates", "var_type": "text", "required": False, "default_value": "", "description": "Notification message templates"},
            {"name": "severity_definitions", "var_type": "text", "required": False, "default_value": "", "description": "Severity level definitions"},
        ],
        "content": """# {{ doc_id }} - Incident Escalation SOP

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Classification** | {{ classification }} |
| **Author** | {{ author }} |

---

## 1. Purpose

This SOP defines the escalation procedures for security incidents, including severity classification, escalation paths, notification requirements, and communication protocols aligned with NIST SP 800-61 and the SANS Incident Response framework.

## 2. Scope

Applies to all SOC personnel, incident responders, and management involved in security incident handling.

## 3. Severity Levels

| Level | Name | Description | Response Time | Escalation Path |
|-------|------|-------------|---------------|-----------------|
| **P1** | Critical | Active breach, data exfiltration, ransomware | Immediate | SOC Lead > CISO > Executive Team |
| **P2** | High | Confirmed malware, compromised account | 30 minutes | SOC Lead > IR Manager |
| **P3** | Medium | Suspicious activity, policy violation | 2 hours | L2 Analyst > SOC Lead |
| **P4** | Low | Informational, minor policy deviation | 8 hours | Documented, no escalation required |

{{ severity_definitions }}

## 4. Escalation Matrix

| Trigger | Escalate To | Method | Timeline |
|---------|------------|--------|----------|
| P1 confirmed | CISO + IR Team | Phone + Email | Immediate |
| P2 confirmed | IR Manager | Email + Chat | Within 30 min |
| P3 unresolved after 4h | SOC Lead | Chat | Within 4 hours |
| Multiple correlated P3+ | SOC Lead | Email | Within 1 hour |
| Regulatory data involved | Legal + DPO | Email | Within 1 hour |

{{ escalation_matrix }}

## 5. Notification Procedures

### 5.1 Internal Notifications
1. Create incident ticket in case management system
2. Notify on-call personnel via designated communication channel
3. Update incident status board / dashboard
4. Schedule bridge call for P1/P2 incidents

### 5.2 External Notifications
- **Law Enforcement**: Only with CISO/Legal approval
- **Regulators**: Per regulatory requirements (coordinate with Legal)
- **Customers**: Per contractual obligations (coordinate with Communications)
- **Third Parties**: Only if directly involved in incident

### 5.3 Communication Templates

{{ notification_templates }}

## 6. Timeline Requirements

| Action | P1 | P2 | P3 | P4 |
|--------|----|----|----|----|
| Initial notification | 15 min | 30 min | 2 hours | 8 hours |
| Status update | Every 30 min | Every 2 hours | Every 4 hours | Daily |
| Post-incident report | 24 hours | 72 hours | 1 week | N/A |

## 7. De-escalation Criteria

An incident may be de-escalated when:
- Threat has been contained and eradicated
- No further malicious activity detected for 24+ hours
- All affected systems restored to normal operation
- Stakeholders have been notified of resolution

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },
    {
        "name": "Evidence Handling & Chain of Custody SOP",
        "document_type": "SOP",
        "collection": "Standard Operating Procedures",
        "description": "Standard operating procedure for digital evidence collection, chain of custody, and forensic preservation.",
        "tags": ["ISO-27035", "NIST-800-61"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "SOP-EVD-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "classification", "var_type": "string", "required": False, "default_value": "CONFIDENTIAL", "description": "Document classification level"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "evidence_storage_location", "var_type": "string", "required": False, "default_value": "", "description": "Secure evidence storage location"},
            {"name": "forensic_tools", "var_type": "string", "required": False, "default_value": "", "description": "Approved forensic tools list"},
            {"name": "legal_contact", "var_type": "string", "required": False, "default_value": "", "description": "Legal department contact"},
        ],
        "content": """# {{ doc_id }} - Evidence Handling & Chain of Custody SOP

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Classification** | {{ classification }} |
| **Author** | {{ author }} |
| **Legal Contact** | {{ legal_contact }} |

---

## 1. Purpose

This SOP establishes procedures for the collection, handling, storage, and transfer of digital evidence during security investigations, ensuring chain of custody integrity for potential legal proceedings.

## 2. Scope

Applies to all personnel involved in evidence collection during incident response, forensic investigations, and internal investigations.

## 3. Evidence Types

| Type | Examples | Collection Method |
|------|----------|------------------|
| **Volatile** | Memory dumps, running processes, network connections | Live acquisition tools |
| **Non-volatile** | Disk images, log files, registry exports | Forensic imaging |
| **Network** | Packet captures, flow data, proxy logs | Network taps, PCAP |
| **Cloud** | API logs, storage snapshots, IAM audit trails | Provider console/API |

## 4. Collection Procedures

### 4.1 Pre-Collection
1. Obtain authorization from incident commander or management
2. Document the scene (screenshots, photographs if physical)
3. Note date, time, timezone, and personnel present
4. Prepare write-blocking hardware/software

### 4.2 Collection Order (Volatility)
1. CPU registers and cache
2. Memory (RAM) contents
3. Network connections and state
4. Running processes
5. Disk contents
6. Remote logging data
7. Physical configuration and network topology
8. Archival media and backups

### 4.3 Forensic Tools
{{ forensic_tools }}

## 5. Chain of Custody Form

For each evidence item, record:

| Field | Description |
|-------|-------------|
| Evidence ID | Unique identifier (e.g., EVD-YYYY-NNNN) |
| Description | Brief description of the evidence item |
| Source | System/device from which evidence was collected |
| Collected By | Name and title of collector |
| Collection Date/Time | Timestamp with timezone |
| Hash (SHA-256) | Cryptographic hash at time of collection |
| Storage Location | Where evidence is stored |

### Transfer Log

| Date/Time | Released By | Received By | Purpose | Signature |
|-----------|-------------|-------------|---------|-----------|
| | | | | |

## 6. Storage Requirements

- **Location**: {{ evidence_storage_location }}
- Evidence must be stored in a secure, access-controlled environment
- Digital evidence stored on encrypted, write-protected media
- Physical evidence in tamper-evident containers
- Access log maintained for all evidence storage areas
- Temperature and humidity controlled (for physical media)

## 7. Transfer Procedures

1. Complete transfer log entry before physical handoff
2. Both parties verify evidence integrity (hash verification)
3. Update chain of custody documentation
4. Notify case manager of transfer

## 8. Retention Policy

| Category | Retention Period | Disposition |
|----------|-----------------|-------------|
| Active investigation | Duration of case + 1 year | Review for archival |
| Legal hold | Until hold released by Legal | Secure destruction |
| Regulatory requirement | Per applicable regulation | Secure destruction |
| Standard | 3 years post-incident | Secure destruction |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },
    {
        "name": "Shift Handover SOP",
        "document_type": "SOP",
        "collection": "Standard Operating Procedures",
        "description": "Standard operating procedure for SOC shift handover including checklist and status reporting.",
        "tags": ["SOC-CMM"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "SOP-SHO-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "classification", "var_type": "string", "required": False, "default_value": "INTERNAL", "description": "Document classification level"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "shift_times", "var_type": "string", "required": False, "default_value": "Day: 07:00-15:00 | Swing: 15:00-23:00 | Night: 23:00-07:00", "description": "Shift schedule times"},
            {"name": "handover_checklist_items", "var_type": "text", "required": False, "default_value": "", "description": "Additional handover checklist items"},
        ],
        "content": """# {{ doc_id }} - Shift Handover SOP

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Classification** | {{ classification }} |
| **Author** | {{ author }} |

---

## 1. Purpose

This SOP ensures consistent and complete shift handovers between SOC analyst teams, minimizing information loss and ensuring continuity of security monitoring operations.

## 2. Scope

Applies to all SOC analysts performing shift rotations.

**Shift Schedule**: {{ shift_times }}

## 3. Handover Procedure

### 3.1 Outgoing Shift (15 min before shift end)
1. Complete all in-progress triage documentation
2. Update status of all open investigations
3. Prepare handover briefing document
4. Ensure all critical alerts are documented

### 3.2 Handover Meeting (At shift change)
1. Face-to-face or video briefing (10-15 minutes)
2. Walk through open incidents and investigations
3. Highlight any pending escalations or follow-ups
4. Transfer ownership of active tickets
5. Confirm incoming team has access to all necessary tools

### 3.3 Incoming Shift (First 15 min)
1. Review handover documentation
2. Verify dashboard and monitoring tool access
3. Check alert queue for any new items
4. Acknowledge receipt of handover

## 4. Handover Checklist

- [ ] All open incidents documented with current status
- [ ] Pending escalations identified and transferred
- [ ] Alert queue reviewed - no unacknowledged critical alerts
- [ ] SIEM and monitoring tools operational
- [ ] Log source health verified - no gaps in data collection
- [ ] Communication channels tested
- [ ] On-call contact information confirmed
- [ ] Any scheduled maintenance or changes noted
{{ handover_checklist_items }}

## 5. Open Investigations

| Ticket ID | Severity | Summary | Status | Next Action | Owner |
|-----------|----------|---------|--------|-------------|-------|
| | | | | | |

## 6. Pending Actions

| Action | Priority | Deadline | Assigned To | Notes |
|--------|----------|----------|-------------|-------|
| | | | | |

## 7. Environment Status

| System | Status | Notes |
|--------|--------|-------|
| SIEM Platform | | |
| EDR Console | | |
| Firewall Management | | |
| Email Gateway | | |
| Threat Intel Feeds | | |
| Case Management | | |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },

    # =========================================================================
    # SOIs (3)
    # =========================================================================
    {
        "name": "Alert Triage SOI",
        "document_type": "SOI",
        "collection": "Standard Operating Instructions",
        "description": "Standard operating instruction for triaging security alerts with decision tree and escalation paths.",
        "tags": ["NIST-CSF-2.0", "SOC-CMM"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "SOI-TRI-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "alert_source", "var_type": "string", "required": False, "default_value": "Elastic SIEM", "description": "Alert source system"},
            {"name": "triage_steps", "var_type": "text", "required": False, "default_value": "", "description": "Additional triage steps"},
            {"name": "classification_criteria", "var_type": "text", "required": False, "default_value": "", "description": "Alert classification criteria"},
        ],
        "content": """# {{ doc_id }} - Alert Triage SOI

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Author** | {{ author }} |
| **Alert Source** | {{ alert_source }} |

---

## Objective

Provide step-by-step instructions for triaging security alerts from {{ alert_source }}, enabling consistent classification and appropriate response.

## Prerequisites

- Access to {{ alert_source }} console
- Access to threat intelligence platform
- Access to case management system
- Understanding of network topology and asset inventory

## Triage Workflow

### Step 1: Alert Review
1. Open the alert in {{ alert_source }}
2. Note the alert rule name, severity, and timestamp
3. Identify source IP, destination IP, user, and host

### Step 2: Context Gathering
1. Check if source/destination are known internal assets
2. Review user account activity for anomalies
3. Check for related alerts within the last 24 hours
4. Query threat intelligence for any IOCs

### Step 3: Decision Tree

```
Alert Received
    |
    v
Known False Positive? --YES--> Document & Close
    |
    NO
    v
Matches Known IOC? --YES--> Escalate (P2+)
    |
    NO
    v
Suspicious Behavior? --YES--> Investigate Further
    |                              |
    NO                             v
    v                         Confirmed Malicious? --YES--> Escalate
    |                              |
Close as Benign                    NO
                                   v
                              Close with Notes
```

{{ classification_criteria }}

### Step 4: Classification

| Classification | Action | Documentation |
|---------------|--------|---------------|
| **True Positive** | Escalate per SOP | Full investigation notes |
| **Benign True Positive** | Close, document context | Brief note explaining legitimacy |
| **False Positive** | Close, request tuning | Tuning recommendation |
| **Inconclusive** | Escalate to L2 | All gathered evidence |

{{ triage_steps }}

## Escalation Path

1. **L1 > L2**: Alert requires deeper investigation or correlation
2. **L2 > L3/IR**: Confirmed incident requiring response actions
3. **Any > SOC Lead**: Multiple correlated alerts or uncertainty

## Expected Outputs

- Alert classified and documented in case management
- Escalation initiated if required
- False positive tuning request submitted if applicable
- Metrics updated (triage time, classification)

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },
    {
        "name": "Phishing Response SOI",
        "document_type": "SOI",
        "collection": "Standard Operating Instructions",
        "description": "Standard operating instruction for analyzing and responding to reported phishing emails.",
        "tags": ["SANS-IR", "NIST-800-61"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "SOI-PHI-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "email_gateway_tool", "var_type": "string", "required": False, "default_value": "", "description": "Email security gateway tool"},
            {"name": "sandbox_url", "var_type": "string", "required": False, "default_value": "", "description": "Malware sandbox URL"},
            {"name": "blocklist_tool", "var_type": "string", "required": False, "default_value": "", "description": "URL/domain blocklist tool"},
        ],
        "content": """# {{ doc_id }} - Phishing Response SOI

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Author** | {{ author }} |

---

## Objective

Provide step-by-step instructions for analyzing reported phishing emails, containing the threat, and extracting indicators of compromise.

## Prerequisites

- Access to email gateway: {{ email_gateway_tool }}
- Access to sandbox: {{ sandbox_url }}
- Access to blocklist tool: {{ blocklist_tool }}
- Email header analysis capability

## Analysis Steps

### Step 1: Email Header Analysis
1. Extract full email headers from the reported message
2. Verify sender address and SPF/DKIM/DMARC results
3. Identify the originating IP address and mail servers
4. Check for header anomalies (spoofed From, mismatched Reply-To)

### Step 2: Content Analysis
1. Review email body for social engineering indicators
2. Identify all URLs (hover, do not click)
3. Check for attachments - note file names, types, and sizes
4. Look for urgency language, impersonation, or brand spoofing

### Step 3: URL/Attachment Analysis
1. Submit URLs to sandbox for analysis: {{ sandbox_url }}
2. Submit attachments to sandbox for detonation
3. Check URLs against threat intelligence and reputation services
4. Verify if landing pages are credential harvesting forms

### Step 4: Scope Assessment
1. Search email gateway for similar messages to other recipients
2. Determine total number of recipients who received the email
3. Identify any users who clicked links or opened attachments
4. Check for any credential submissions on phishing pages

## Containment Actions

1. **Block sender** in email gateway: {{ email_gateway_tool }}
2. **Block URLs/domains** in web proxy: {{ blocklist_tool }}
3. **Quarantine** all copies of the phishing email
4. **Reset credentials** for any users who submitted credentials
5. **Block IOCs** (IPs, domains, hashes) at perimeter

## User Notification

- Notify affected users who received the email
- Provide guidance on what to do if they interacted with it
- Remind about phishing reporting procedures
- Send organization-wide advisory if campaign is widespread

## IOC Extraction

Document all indicators:
- Sender email address(es)
- Sender IP address(es)
- Malicious URLs
- Malicious domains
- Attachment hashes (MD5, SHA-256)
- Subject line patterns

## Reporting

1. Document all findings in case management system
2. Update IOC database with extracted indicators
3. Submit phishing kit/infrastructure to threat intel sharing platforms
4. Generate metrics (time to detect, scope, user interaction rate)

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },
    {
        "name": "Malware Analysis SOI",
        "document_type": "SOI",
        "collection": "Standard Operating Instructions",
        "description": "Standard operating instruction for static and dynamic malware analysis with MITRE ATT&CK mapping.",
        "tags": ["MITRE-ATT&CK", "NIST-800-61"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "SOI-MAL-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "sandbox_environment", "var_type": "string", "required": False, "default_value": "", "description": "Sandbox environment details"},
            {"name": "analysis_tools", "var_type": "string", "required": False, "default_value": "", "description": "Available analysis tools"},
            {"name": "submission_portal", "var_type": "string", "required": False, "default_value": "", "description": "Sample submission portal URL"},
        ],
        "content": """# {{ doc_id }} - Malware Analysis SOI

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Author** | {{ author }} |

---

## Objective

Provide instructions for performing static and dynamic analysis of suspected malware samples, extracting IOCs, and mapping behaviors to the MITRE ATT&CK framework.

## Prerequisites

- Isolated analysis environment: {{ sandbox_environment }}
- Analysis tools: {{ analysis_tools }}
- Sample submission portal: {{ submission_portal }}
- MITRE ATT&CK Navigator access

## Static Analysis

### Step 1: Initial Triage
1. Calculate file hashes (MD5, SHA-1, SHA-256)
2. Check hashes against VirusTotal and other reputation services
3. Identify file type using magic bytes (not extension)
4. Note file size, compilation timestamp, and packer detection

### Step 2: String Analysis
1. Extract ASCII and Unicode strings
2. Look for URLs, IP addresses, domains, email addresses
3. Identify API function names (especially suspicious ones)
4. Note registry keys, file paths, and mutex names

### Step 3: PE Analysis (if applicable)
1. Review import table for suspicious API calls
2. Check section names and entropy (packed sections > 7.0)
3. Review resources for embedded payloads
4. Verify digital signature validity

## Dynamic Analysis

### Step 4: Sandbox Execution
1. Configure sandbox environment: {{ sandbox_environment }}
2. Take pre-execution snapshot
3. Execute sample and monitor for 5-10 minutes minimum
4. Capture all network traffic during execution

### Step 5: Behavioral Analysis
1. Document process creation tree
2. Record file system modifications (created, modified, deleted)
3. Note registry modifications
4. Identify network connections (DNS queries, HTTP/HTTPS, C2)
5. Check for persistence mechanisms
6. Monitor for privilege escalation attempts

## IOC Extraction

| IOC Type | Value | Context |
|----------|-------|---------|
| File Hash (SHA-256) | | |
| Mutex | | |
| C2 Domain | | |
| C2 IP | | |
| Dropped File | | |
| Registry Key | | |

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Evidence |
|--------|-----------|-------------|----------|
| Initial Access | | | |
| Execution | | | |
| Persistence | | | |
| Defense Evasion | | | |
| Command & Control | | | |

## Report

Document findings including:
- Executive summary of malware capabilities
- Detailed technical analysis
- Complete IOC list
- MITRE ATT&CK mapping
- Recommended detection signatures
- Containment recommendations

## Containment Recommendations

1. Block all identified IOCs at perimeter
2. Deploy detection signatures to EDR/SIEM
3. Scan environment for indicators of compromise
4. Isolate any confirmed infected systems

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },

    # =========================================================================
    # WIs (3)
    # =========================================================================
    {
        "name": "IOC Blocking Work Instruction",
        "document_type": "WI",
        "collection": "Work Instructions",
        "description": "Work instruction for blocking indicators of compromise across security tools.",
        "tags": ["MITRE-ATT&CK"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "WI-IOC-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "firewall_tool", "var_type": "string", "required": False, "default_value": "", "description": "Firewall management tool"},
            {"name": "edr_tool", "var_type": "string", "required": False, "default_value": "", "description": "EDR platform"},
            {"name": "dns_filter_tool", "var_type": "string", "required": False, "default_value": "", "description": "DNS filtering tool"},
            {"name": "change_management_required", "var_type": "string", "required": False, "default_value": "Yes - for production firewall changes", "description": "Change management requirements"},
        ],
        "content": """# {{ doc_id }} - IOC Blocking Work Instruction

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Author** | {{ author }} |
| **Change Management** | {{ change_management_required }} |

---

## Objective

Step-by-step instructions for blocking malicious indicators of compromise (IOCs) across firewall, EDR, and DNS filtering tools.

## Scope

Covers blocking of IP addresses, domains, URLs, and file hashes across the security stack.

## Prerequisites

- Verified IOCs from investigation (confirmed malicious)
- Appropriate access to security tools
- Change management ticket (if required): {{ change_management_required }}

## IP Address Blocking

### Firewall: {{ firewall_tool }}
1. Log into {{ firewall_tool }} management console
2. Navigate to security policy / blocklist section
3. Add IP address(es) to the block list
4. Set rule action to "Block" with logging enabled
5. Apply changes and verify rule is active
6. Document: IP, ticket number, expiration date

### EDR: {{ edr_tool }}
1. Open {{ edr_tool }} console
2. Navigate to network isolation / IOC management
3. Add IP to blocklist with description and case reference
4. Verify block is deployed to all endpoints

## Domain/URL Blocking

### DNS Filter: {{ dns_filter_tool }}
1. Access {{ dns_filter_tool }} administration
2. Add domain(s) to blocklist category
3. Set action to block with custom block page
4. Verify resolution returns block page

### Web Proxy
1. Add URL/domain to proxy block category
2. Enable SSL inspection if HTTPS domain
3. Verify block is effective from test workstation

## File Hash Blocking

### EDR: {{ edr_tool }}
1. Navigate to hash blocklist / prevention policies
2. Add SHA-256 hash(es) with description
3. Set action to "Block and Quarantine"
4. Deploy policy update to all endpoint groups
5. Verify hash is blocked on test endpoint

## Verification

After implementing blocks, verify:
- [ ] Firewall rules active and logging
- [ ] DNS queries for blocked domains return expected response
- [ ] Web proxy blocks access to URLs
- [ ] EDR blocks execution of hashed files
- [ ] No business impact from blocks (check for false positives)

## Rollback

If a block causes business impact:
1. Immediately remove the block from the affected tool
2. Notify the investigation team
3. Document the false positive
4. Update IOC quality rating in threat intel platform

## Documentation

Record in case management:
- IOC value and type
- Where blocked (which tools)
- Date/time of block implementation
- Expiration/review date
- Associated case/ticket number

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },
    {
        "name": "Log Source Onboarding Work Instruction",
        "document_type": "WI",
        "collection": "Work Instructions",
        "description": "Work instruction for onboarding new log sources into the SIEM platform.",
        "tags": ["NIST-CSF-2.0", "SOC-CMM"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "WI-LOG-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "siem_platform", "var_type": "string", "required": False, "default_value": "Elastic SIEM", "description": "Target SIEM platform"},
            {"name": "log_formats", "var_type": "string", "required": False, "default_value": "Syslog, JSON, CEF, Windows Event Log", "description": "Supported log formats"},
            {"name": "retention_days", "var_type": "string", "required": False, "default_value": "90", "description": "Default log retention in days"},
        ],
        "content": """# {{ doc_id }} - Log Source Onboarding Work Instruction

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Author** | {{ author }} |
| **SIEM Platform** | {{ siem_platform }} |

---

## Objective

Step-by-step instructions for onboarding new log sources into {{ siem_platform }}, including collection, parsing, validation, and alert rule setup.

## Log Source Identification

Before onboarding, document:
- Log source name and type
- Log format: {{ log_formats }}
- Expected event volume (EPS)
- Data classification level
- Retention requirement: {{ retention_days }} days
- Business owner and technical contact

## Collection Method

| Method | Use Case | Configuration |
|--------|----------|---------------|
| Agent (Elastic Agent/Beats) | Endpoint logs, application logs | Deploy agent, configure integration |
| Syslog | Network devices, firewalls | Configure syslog forwarding to collector |
| API | Cloud services, SaaS applications | Configure API polling integration |
| File | Legacy systems, batch processing | Configure filebeat/logstash input |

## Parser Configuration

1. Identify log format and structure
2. Create or configure ingest pipeline / parser
3. Map fields to ECS (Elastic Common Schema) where applicable
4. Test parser with sample log events
5. Validate field extraction accuracy

## Validation

- [ ] Logs are arriving in {{ siem_platform }}
- [ ] Parsing is correct (fields extracted properly)
- [ ] Timestamp is accurate and in correct timezone
- [ ] No data loss or truncation
- [ ] Volume matches expected EPS
- [ ] Retention policy applied

## Alert Rules Setup

1. Review available detection rules for the log source type
2. Enable relevant pre-built rules
3. Tune thresholds based on baseline activity
4. Create custom rules for organization-specific use cases
5. Test alert generation with known-good triggers

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },
    {
        "name": "SIEM Query & Investigation Work Instruction",
        "document_type": "WI",
        "collection": "Work Instructions",
        "description": "Work instruction for SIEM query techniques and investigation workflows.",
        "tags": ["SOC-CMM"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "WI-QRY-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "siem_platform", "var_type": "string", "required": False, "default_value": "Elastic SIEM", "description": "SIEM platform"},
            {"name": "query_examples", "var_type": "text", "required": False, "default_value": "", "description": "Additional query examples"},
        ],
        "content": """# {{ doc_id }} - SIEM Query & Investigation Work Instruction

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Author** | {{ author }} |
| **SIEM Platform** | {{ siem_platform }} |

---

## Objective

Provide query syntax reference, common investigation queries, and correlation techniques for {{ siem_platform }}.

## Query Syntax Reference

### KQL (Kibana Query Language)
```
# Field matching
event.action: "login" AND event.outcome: "failure"

# Wildcard
source.ip: 192.168.1.*

# Range
@timestamp >= "2024-01-01" AND @timestamp < "2024-02-01"

# Boolean
(event.category: "authentication") AND NOT (source.ip: "10.0.0.0/8")
```

### Lucene
```
# Phrase search
message: "failed password"

# Proximity
message: "password reset"~5

# Fuzzy
user.name: admin~2
```

## Common Investigation Queries

### Authentication Anomalies
```
event.category: "authentication" AND event.outcome: "failure"
| stats count by source.ip, user.name
| where count > 10
```

### Suspicious Process Execution
```
event.category: "process" AND process.name: ("powershell.exe" OR "cmd.exe" OR "wscript.exe")
AND process.command_line: ("*-enc*" OR "*downloadstring*" OR "*invoke-expression*")
```

### Network Connections to Rare Destinations
```
event.category: "network" AND NOT destination.ip: ("10.0.0.0/8" OR "172.16.0.0/12" OR "192.168.0.0/16")
| stats count by destination.ip, destination.port
| where count < 5
```

### Lateral Movement Indicators
```
event.category: "authentication" AND event.type: "start"
AND source.ip: "10.0.0.0/8" AND destination.ip: "10.0.0.0/8"
AND NOT source.ip: destination.ip
```

{{ query_examples }}

## Correlation Techniques

1. **Time-based**: Group events within a time window from the same source
2. **Entity-based**: Correlate by user, host, or IP across event types
3. **Kill chain**: Map events to ATT&CK stages for attack reconstruction
4. **Statistical**: Identify outliers in normally distributed activity

## Performance Tips

- Always specify a time range to limit search scope
- Use specific field queries instead of full-text search
- Filter on indexed fields first, then apply text searches
- Use aggregations for summary views rather than raw events
- Save commonly used queries as saved searches

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },

    # =========================================================================
    # KB Articles (3)
    # =========================================================================
    {
        "name": "Common Alert Types KB",
        "document_type": "KB",
        "collection": "Knowledge Base",
        "description": "Knowledge base article documenting common security alert types, their meaning, and response guidance.",
        "tags": ["MITRE-ATT&CK"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "KB-ALT-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "alert_categories", "var_type": "text", "required": False, "default_value": "", "description": "Additional alert category details"},
        ],
        "content": """# {{ doc_id }} - Common Alert Types Knowledge Base

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Author** | {{ author }} |

---

## Overview

This knowledge base article provides reference information on common security alert types encountered in SOC operations, including descriptions, typical causes, and recommended response actions.

## Alert Categories

| Category | MITRE Tactic | Typical Severity | FP Rate |
|----------|-------------|-----------------|---------|
| Authentication Anomalies | Credential Access | Medium-High | Medium |
| Malware Detection | Execution | High-Critical | Low |
| Network Anomalies | Command & Control | Medium | High |
| Policy Violations | N/A | Low-Medium | Medium |
| Data Exfiltration | Exfiltration | High-Critical | Low |
| Privilege Escalation | Privilege Escalation | High | Low |
| Lateral Movement | Lateral Movement | High | Medium |

### Authentication Anomalies
- **Brute Force**: Multiple failed login attempts from a single source
- **Credential Stuffing**: Failed logins across multiple accounts from distributed sources
- **Impossible Travel**: Successful logins from geographically impossible locations
- **Off-hours Login**: Authentication outside normal business hours

### Malware Detection
- **Known Malware**: Signature-based detection of known malicious files
- **Behavioral Detection**: Suspicious process behavior matching malware patterns
- **Fileless Malware**: Script-based attacks using legitimate tools (LOLBins)
- **Ransomware**: File encryption behavior, ransom note creation

### Network Anomalies
- **Beaconing**: Regular periodic connections to external hosts
- **DNS Tunneling**: Unusually long or frequent DNS queries
- **Port Scanning**: Connection attempts to multiple ports on a target
- **C2 Communication**: Traffic matching known command-and-control patterns

{{ alert_categories }}

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },
    {
        "name": "Threat Actor Profile KB",
        "document_type": "KB",
        "collection": "Knowledge Base",
        "description": "Knowledge base template for documenting threat actor profiles including TTPs, campaigns, and IOCs.",
        "tags": ["MITRE-ATT&CK"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "KB-TA-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "actor_name", "var_type": "string", "required": True, "default_value": "", "description": "Threat actor name"},
            {"name": "aliases", "var_type": "string", "required": False, "default_value": "", "description": "Known aliases"},
            {"name": "motivation", "var_type": "string", "required": False, "default_value": "", "description": "Actor motivation (espionage, financial, etc.)"},
            {"name": "target_sectors", "var_type": "string", "required": False, "default_value": "", "description": "Target industry sectors"},
            {"name": "ttps", "var_type": "text", "required": False, "default_value": "", "description": "Tactics, techniques, and procedures"},
            {"name": "iocs", "var_type": "text", "required": False, "default_value": "", "description": "Known indicators of compromise"},
            {"name": "campaigns", "var_type": "text", "required": False, "default_value": "", "description": "Known campaigns"},
        ],
        "content": """# {{ doc_id }} - Threat Actor Profile: {{ actor_name }}

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Author** | {{ author }} |

---

## Actor Overview

| Attribute | Detail |
|-----------|--------|
| **Name** | {{ actor_name }} |
| **Aliases** | {{ aliases }} |
| **Motivation** | {{ motivation }} |
| **Target Sectors** | {{ target_sectors }} |
| **Confidence** | |
| **First Seen** | |
| **Last Active** | |

## TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Description |
|--------|-----------|-----|-------------|
| | | | |

{{ ttps }}

## Known Campaigns

{{ campaigns }}

## IOC Summary

| IOC Type | Value | First Seen | Last Seen | Confidence |
|----------|-------|------------|-----------|------------|
| | | | | |

{{ iocs }}

## Detection Recommendations

1. Deploy detection rules covering known TTPs
2. Monitor for IOCs listed above
3. Review alerts matching actor's target profile
4. Enable enhanced logging for targeted systems

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },
    {
        "name": "Tool Configuration Guide KB",
        "document_type": "KB",
        "collection": "Knowledge Base",
        "description": "Knowledge base template for documenting security tool configuration, integration, and troubleshooting.",
        "tags": ["SOC-CMM"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "KB-TOOL-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "tool_name", "var_type": "string", "required": True, "default_value": "", "description": "Tool name"},
            {"name": "tool_version", "var_type": "string", "required": False, "default_value": "", "description": "Tool version"},
            {"name": "purpose", "var_type": "string", "required": False, "default_value": "", "description": "Tool purpose"},
            {"name": "configuration_steps", "var_type": "text", "required": False, "default_value": "", "description": "Configuration steps"},
            {"name": "troubleshooting_items", "var_type": "text", "required": False, "default_value": "", "description": "Troubleshooting guide"},
        ],
        "content": """# {{ doc_id }} - Tool Configuration Guide: {{ tool_name }}

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Author** | {{ author }} |
| **Tool** | {{ tool_name }} |
| **Tool Version** | {{ tool_version }} |
| **Purpose** | {{ purpose }} |

---

## Overview

Configuration and administration guide for {{ tool_name }} ({{ tool_version }}).

**Purpose**: {{ purpose }}

## Prerequisites

- Administrative access to {{ tool_name }}
- Network connectivity to required services
- Valid license/subscription

## Configuration

{{ configuration_steps }}

## Integration

| Integration | Purpose | Protocol | Status |
|------------|---------|----------|--------|
| SIEM | Log forwarding | Syslog/API | |
| SOAR | Automated response | REST API | |
| Ticketing | Case creation | API | |

## Troubleshooting

{{ troubleshooting_items }}

| Issue | Possible Cause | Resolution |
|-------|---------------|------------|
| Service not starting | Configuration error | Check logs, validate config |
| No data received | Network connectivity | Verify firewall rules, test connectivity |
| High resource usage | Volume spike | Check EPS, tune retention |

## Maintenance

- **Backup**: Schedule regular configuration backups
- **Updates**: Follow vendor update schedule
- **Health Checks**: Monitor service health daily
- **License**: Track license expiration and usage

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },

    # =========================================================================
    # IRPs (2)
    # =========================================================================
    {
        "name": "Ransomware Incident Response Plan",
        "document_type": "IRP",
        "collection": "Incident Response Plans",
        "description": "Incident response plan for ransomware attacks following NIST 800-61 and SANS IR phases.",
        "tags": ["NIST-800-61", "SANS-IR"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "IRP-RAN-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "classification", "var_type": "string", "required": False, "default_value": "CONFIDENTIAL", "description": "Document classification level"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "approved_by", "var_type": "string", "required": False, "default_value": "", "description": "Approval authority"},
            {"name": "ir_team_contacts", "var_type": "text", "required": False, "default_value": "", "description": "IR team contact list"},
            {"name": "backup_contacts", "var_type": "text", "required": False, "default_value": "", "description": "Backup/recovery team contacts"},
            {"name": "legal_contacts", "var_type": "text", "required": False, "default_value": "", "description": "Legal team contacts"},
        ],
        "content": """# {{ doc_id }} - Ransomware Incident Response Plan

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Classification** | {{ classification }} |
| **Author** | {{ author }} |
| **Approved By** | {{ approved_by }} |

---

## 1. Purpose

This plan provides structured response procedures for ransomware incidents, following NIST SP 800-61 and SANS Incident Response methodology.

## 2. Roles & Responsibilities

| Role | Responsibility | Contact |
|------|---------------|---------|
| Incident Commander | Overall response coordination | |
| IR Lead | Technical investigation and containment | |
| SOC Analysts | Detection, monitoring, evidence collection | |
| IT Operations | System isolation, recovery | |
| Legal | Regulatory obligations, law enforcement | |
| Communications | Internal/external messaging | |

{{ ir_team_contacts }}

## 3. Detection Indicators

- File encryption activity across multiple files/directories
- Ransom notes appearing on systems
- Unusual file extension changes (.encrypted, .locked, etc.)
- Volume Shadow Copy deletion attempts
- Mass file modification events in short timeframes
- Known ransomware process names or hashes
- C2 beacon activity to known ransomware infrastructure

## 4. Response Phases (SANS)

### Phase 1: Identification
1. Confirm ransomware infection (verify it's not a false alarm)
2. Identify the ransomware variant (ransom note, file extensions, behavior)
3. Determine initial infection vector
4. Assess scope of encryption
5. Identify patient zero and timeline

### Phase 2: Containment
1. **Immediate**: Isolate affected systems from network
2. Disable shared drives and network shares
3. Block known C2 domains/IPs at perimeter
4. Disable compromised accounts
5. Preserve evidence before any recovery actions
6. **Do NOT** power off systems (preserves volatile evidence)
7. **Do NOT** pay ransom without executive and legal approval

### Phase 3: Eradication
1. Identify and remove ransomware from all affected systems
2. Remove persistence mechanisms
3. Patch vulnerability used for initial access
4. Reset all potentially compromised credentials
5. Scan environment for additional compromise indicators

### Phase 4: Recovery
1. Restore systems from clean backups (verify backup integrity first)
2. Rebuild systems that cannot be restored
3. Restore data in priority order (critical business functions first)
4. Monitor recovered systems for re-infection
5. Gradually restore network connectivity

**Backup Contacts**: {{ backup_contacts }}

## 5. Communication Plan

| Audience | When | Channel | Responsible |
|----------|------|---------|-------------|
| Executive leadership | Immediately on confirmation | Phone/meeting | Incident Commander |
| All employees | Within 4 hours | Email/intranet | Communications |
| Customers (if affected) | Per contractual/regulatory | Email/portal | Communications + Legal |
| Law enforcement | If warranted | In-person/phone | Legal |
| Regulators | Per requirements | Formal notification | Legal |

## 6. Evidence Preservation

- Memory dumps of affected systems
- Ransom notes (all variants found)
- Encrypted file samples
- Ransomware binary/payload
- Network traffic captures
- System and security logs
- Email/phishing artifacts (if applicable)

## 7. Post-Incident Review

Conduct within 1 week of incident closure:
- Timeline reconstruction
- Root cause analysis
- Lessons learned
- Action items with owners and deadlines
- Update this plan based on findings

**Legal Contacts**: {{ legal_contacts }}

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },
    {
        "name": "Data Breach Response Plan",
        "document_type": "IRP",
        "collection": "Incident Response Plans",
        "description": "Incident response plan for data breaches including regulatory notification requirements.",
        "tags": ["ISO-27035", "NIST-800-61"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "IRP-DBR-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "classification", "var_type": "string", "required": False, "default_value": "CONFIDENTIAL", "description": "Document classification level"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "approved_by", "var_type": "string", "required": False, "default_value": "", "description": "Approval authority"},
            {"name": "dpo_contact", "var_type": "string", "required": False, "default_value": "", "description": "Data Protection Officer contact"},
            {"name": "legal_contacts", "var_type": "text", "required": False, "default_value": "", "description": "Legal team contacts"},
            {"name": "notification_requirements", "var_type": "text", "required": False, "default_value": "", "description": "Regulatory notification requirements"},
        ],
        "content": """# {{ doc_id }} - Data Breach Response Plan

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Classification** | {{ classification }} |
| **Author** | {{ author }} |
| **Approved By** | {{ approved_by }} |
| **DPO Contact** | {{ dpo_contact }} |

---

## 1. Purpose

This plan provides structured response procedures for data breach incidents, including assessment, containment, notification requirements, and forensic investigation aligned with ISO 27035 and NIST SP 800-61.

## 2. Breach Classification

| Level | Description | Examples | Notification Required |
|-------|-------------|----------|----------------------|
| **Level 1** | Minor - limited data, low sensitivity | Employee contact info | Internal only |
| **Level 2** | Moderate - personal data affected | Customer PII, email addresses | DPO assessment required |
| **Level 3** | Severe - sensitive/regulated data | Financial data, health records | Regulatory notification likely |
| **Level 4** | Critical - mass breach, high sensitivity | Payment cards, SSN, credentials | Mandatory regulatory notification |

## 3. Roles & Responsibilities

| Role | Responsibility |
|------|---------------|
| Incident Commander | Overall coordination, executive briefing |
| DPO | Data impact assessment, regulatory guidance |
| Legal | Notification obligations, liability assessment |
| IR Team | Technical investigation and containment |
| Communications | Public statements, customer notifications |
| IT Operations | System remediation, access controls |

## 4. Detection & Assessment

1. Confirm data breach has occurred
2. Identify type and sensitivity of data exposed
3. Determine number of affected records/individuals
4. Identify breach vector and root cause
5. Assess ongoing risk (is breach still active?)
6. Document all findings for regulatory reporting

## 5. Containment

1. Stop the breach - close the vulnerability, revoke access
2. Preserve evidence before remediation
3. Reset compromised credentials
4. Isolate affected systems
5. Implement additional monitoring for further exposure

## 6. Notification Requirements

{{ notification_requirements }}

| Regulation | Timeline | Authority | Threshold |
|-----------|----------|-----------|-----------|
| GDPR | 72 hours | Supervisory Authority | Risk to individuals |
| CCPA | Without unreasonable delay | California AG | 500+ residents |
| HIPAA | 60 days | HHS OCR | Unsecured PHI |
| PCI DSS | Immediately | Card brands | Cardholder data |

## 7. Communication Templates

### Regulatory Notification
Include: nature of breach, categories of data, approximate number of individuals, likely consequences, measures taken/proposed, DPO contact information.

### Individual Notification
Include: plain language description, type of data involved, what we're doing about it, what they can do, contact for questions.

## 8. Forensic Investigation

1. Engage forensic team (internal or external)
2. Preserve all relevant logs and evidence
3. Determine full scope of data access
4. Identify all affected data records
5. Document chain of custody for all evidence
6. Prepare forensic report for legal and regulatory purposes

## 9. Regulatory Reporting

Coordinate with Legal and DPO:
{{ legal_contacts }}

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },

    # =========================================================================
    # AAR (1)
    # =========================================================================
    {
        "name": "Post-Incident After-Action Report",
        "document_type": "AAR",
        "collection": "After-Action Reports",
        "description": "After-action report template for post-incident review, lessons learned, and improvement recommendations.",
        "tags": ["NIST-800-61", "SANS-IR", "ISO-27035"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "AAR-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "classification", "var_type": "string", "required": False, "default_value": "CONFIDENTIAL", "description": "Document classification level"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "incident_id", "var_type": "string", "required": True, "default_value": "", "description": "Related incident ID"},
            {"name": "incident_title", "var_type": "string", "required": True, "default_value": "", "description": "Incident title"},
            {"name": "incident_date", "var_type": "string", "required": True, "default_value": "", "description": "Incident date"},
            {"name": "resolution_date", "var_type": "string", "required": False, "default_value": "", "description": "Resolution date"},
            {"name": "severity", "var_type": "string", "required": False, "default_value": "", "description": "Incident severity"},
            {"name": "lead_analyst", "var_type": "string", "required": False, "default_value": "", "description": "Lead analyst name"},
            {"name": "participants", "var_type": "text", "required": False, "default_value": "", "description": "AAR meeting participants"},
            {"name": "executive_summary", "var_type": "text", "required": False, "default_value": "", "description": "Executive summary"},
            {"name": "timeline_events", "var_type": "text", "required": False, "default_value": "", "description": "Timeline of events"},
            {"name": "findings", "var_type": "text", "required": False, "default_value": "", "description": "Key findings"},
            {"name": "recommendations", "var_type": "text", "required": False, "default_value": "", "description": "Improvement recommendations"},
        ],
        "content": """# {{ doc_id }} - After-Action Report: {{ incident_title }}

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Classification** | {{ classification }} |
| **Author** | {{ author }} |
| **Incident ID** | {{ incident_id }} |
| **Incident Date** | {{ incident_date }} |
| **Resolution Date** | {{ resolution_date }} |
| **Severity** | {{ severity }} |
| **Lead Analyst** | {{ lead_analyst }} |

**Participants**: {{ participants }}

---

## 1. Executive Summary

{{ executive_summary }}

## 2. Incident Overview

| Attribute | Detail |
|-----------|--------|
| Incident ID | {{ incident_id }} |
| Title | {{ incident_title }} |
| Date Detected | {{ incident_date }} |
| Date Resolved | {{ resolution_date }} |
| Severity | {{ severity }} |
| Category | |
| Attack Vector | |
| Systems Affected | |
| Data Impact | |

## 3. Timeline

| Date/Time | Event | Actor | Notes |
|-----------|-------|-------|-------|
| | | | |

{{ timeline_events }}

## 4. What Went Well

-
-
-

## 5. Areas for Improvement

-
-
-

## 6. Findings

{{ findings }}

## 7. Recommendations

| # | Recommendation | Priority | Owner | Deadline | Status |
|---|---------------|----------|-------|----------|--------|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |

{{ recommendations }}

## 8. Action Items

| # | Action | Owner | Due Date | Status |
|---|--------|-------|----------|--------|
| 1 | | | | Pending |
| 2 | | | | Pending |
| 3 | | | | Pending |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },

    # =========================================================================
    # Threat Advisory (1)
    # =========================================================================
    {
        "name": "Threat Advisory",
        "document_type": "THREAT_ADVISORY",
        "collection": "Threat Intelligence",
        "description": "Threat advisory template for communicating emerging threats, IOCs, and recommended mitigations.",
        "tags": ["MITRE-ATT&CK"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "TA-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "classification", "var_type": "string", "required": False, "default_value": "TLP:AMBER", "description": "Document classification / TLP level"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "advisory_title", "var_type": "string", "required": True, "default_value": "", "description": "Advisory title"},
            {"name": "severity", "var_type": "string", "required": False, "default_value": "HIGH", "description": "Advisory severity"},
            {"name": "date_issued", "var_type": "string", "required": False, "default_value": "", "description": "Date issued"},
            {"name": "tlp_level", "var_type": "string", "required": False, "default_value": "TLP:AMBER", "description": "Traffic Light Protocol level"},
            {"name": "affected_systems", "var_type": "text", "required": False, "default_value": "", "description": "Affected systems and versions"},
            {"name": "threat_description", "var_type": "text", "required": False, "default_value": "", "description": "Detailed threat description"},
            {"name": "iocs", "var_type": "text", "required": False, "default_value": "", "description": "Indicators of compromise"},
            {"name": "mitre_techniques", "var_type": "text", "required": False, "default_value": "", "description": "MITRE ATT&CK techniques"},
            {"name": "mitigations", "var_type": "text", "required": False, "default_value": "", "description": "Recommended mitigations"},
        ],
        "content": """# {{ doc_id }} - Threat Advisory: {{ advisory_title }}

| Field | Value |
|-------|-------|
| **Advisory ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Classification** | {{ classification }} |
| **TLP** | {{ tlp_level }} |
| **Severity** | {{ severity }} |
| **Date Issued** | {{ date_issued }} |
| **Author** | {{ author }} |

---

## Threat Overview

{{ threat_description }}

## Affected Systems

{{ affected_systems }}

## Technical Analysis

### Attack Flow

1. **Initial Access**:
2. **Execution**:
3. **Persistence**:
4. **Impact**:

## Indicators of Compromise

| IOC Type | Value | Context |
|----------|-------|---------|
| | | |

{{ iocs }}

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|--------|-----------|-----|-------------|
| | | | |

{{ mitre_techniques }}

## Mitigations

{{ mitigations }}

### Immediate Actions
1.
2.
3.

### Long-term Recommendations
1.
2.
3.

## Detection Signatures

```
# Add SIEM/IDS detection rules here
```

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },

    # =========================================================================
    # Detection Rule Documentation (1)
    # =========================================================================
    {
        "name": "Detection Rule Documentation",
        "document_type": "DETECTION_RULE",
        "collection": "Detection Engineering",
        "description": "Documentation template for detection rules including MITRE mapping, data requirements, and test cases.",
        "tags": ["MITRE-ATT&CK"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "DET-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "rule_name", "var_type": "string", "required": True, "default_value": "", "description": "Detection rule name"},
            {"name": "rule_id", "var_type": "string", "required": False, "default_value": "", "description": "Rule ID in SIEM"},
            {"name": "severity", "var_type": "string", "required": False, "default_value": "medium", "description": "Rule severity"},
            {"name": "mitre_technique", "var_type": "string", "required": False, "default_value": "", "description": "MITRE ATT&CK technique ID"},
            {"name": "mitre_tactic", "var_type": "string", "required": False, "default_value": "", "description": "MITRE ATT&CK tactic"},
            {"name": "data_sources", "var_type": "string", "required": False, "default_value": "", "description": "Required data sources"},
            {"name": "detection_logic", "var_type": "text", "required": False, "default_value": "", "description": "Detection logic description"},
            {"name": "query", "var_type": "text", "required": False, "default_value": "", "description": "Detection query/rule"},
            {"name": "false_positive_rate", "var_type": "string", "required": False, "default_value": "Medium", "description": "Expected false positive rate"},
            {"name": "test_cases", "var_type": "text", "required": False, "default_value": "", "description": "Test cases for validation"},
        ],
        "content": """# {{ doc_id }} - Detection Rule: {{ rule_name }}

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Author** | {{ author }} |
| **Rule ID** | {{ rule_id }} |
| **Severity** | {{ severity }} |
| **False Positive Rate** | {{ false_positive_rate }} |

---

## Rule Metadata

| Attribute | Value |
|-----------|-------|
| Name | {{ rule_name }} |
| Rule ID | {{ rule_id }} |
| Severity | {{ severity }} |
| Status | Active |
| Created | |
| Last Updated | |

## Description

{{ detection_logic }}

## MITRE ATT&CK Mapping

| Attribute | Value |
|-----------|-------|
| **Tactic** | {{ mitre_tactic }} |
| **Technique** | {{ mitre_technique }} |
| **Sub-technique** | |

## Data Requirements

**Required Data Sources**: {{ data_sources }}

| Data Source | Fields Required | Index Pattern |
|-------------|----------------|---------------|
| | | |

## Detection Logic

{{ detection_logic }}

## Query / Sigma Rule

```
{{ query }}
```

## Test Cases

{{ test_cases }}

| # | Test Description | Expected Result | Status |
|---|-----------------|-----------------|--------|
| 1 | True positive trigger | Alert generated | |
| 2 | Benign activity | No alert | |
| 3 | Edge case | | |

## False Positive Guidance

**Expected FP Rate**: {{ false_positive_rate }}

Common false positive scenarios:
-
-

Tuning recommendations:
-
-

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },

    # =========================================================================
    # Runbook (1)
    # =========================================================================
    {
        "name": "Operational Runbook",
        "document_type": "RUNBOOK",
        "collection": "Runbooks",
        "description": "Operational runbook template for routine SOC tasks with trigger conditions, procedures, and rollback steps.",
        "tags": ["SOC-CMM", "NIST-CSF-2.0"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "RB-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "runbook_title", "var_type": "string", "required": True, "default_value": "", "description": "Runbook title"},
            {"name": "trigger_conditions", "var_type": "text", "required": False, "default_value": "", "description": "Conditions that trigger this runbook"},
            {"name": "prerequisites", "var_type": "text", "required": False, "default_value": "", "description": "Prerequisites and requirements"},
            {"name": "procedure_steps", "var_type": "text", "required": False, "default_value": "", "description": "Detailed procedure steps"},
            {"name": "rollback_steps", "var_type": "text", "required": False, "default_value": "", "description": "Rollback procedure"},
            {"name": "escalation_contacts", "var_type": "text", "required": False, "default_value": "", "description": "Escalation contact list"},
            {"name": "success_criteria", "var_type": "text", "required": False, "default_value": "", "description": "Success/completion criteria"},
        ],
        "content": """# {{ doc_id }} - Runbook: {{ runbook_title }}

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Author** | {{ author }} |

---

## Overview

{{ runbook_title }}

## Trigger Conditions

This runbook should be executed when:

{{ trigger_conditions }}

## Prerequisites

{{ prerequisites }}

- [ ] Required access verified
- [ ] Required tools available
- [ ] Change management ticket created (if applicable)

## Procedure

{{ procedure_steps }}

| Step | Action | Expected Result | Verification |
|------|--------|----------------|--------------|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |

## Verification

### Success Criteria

{{ success_criteria }}

- [ ] Primary objective achieved
- [ ] No adverse impact on services
- [ ] Results documented

## Rollback

If the procedure fails or causes adverse impact:

{{ rollback_steps }}

1.
2.
3.

## Escalation Path

{{ escalation_contacts }}

| Condition | Escalate To | Method |
|-----------|------------|--------|
| Procedure fails | | |
| Unexpected results | | |
| Service impact | | |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },
    # =========================================================================
    # Security Assurance — CyAB SAL Framework + Log Quality Standards (2)
    # =========================================================================
    {
        "name": "CyAB Security Assurance Levels (SAL)",
        "document_type": "SAL",
        "collection": "Security Assurance",
        "description": "Complete Cyber Assurance Base (CyAB) Security Assurance Levels framework. Defines 5 risk-proportionate tiers (SAL 1-5) covering security controls, log quality and telemetry standards, assurance activities, evidence requirements, lifecycle gates, and compliance mapping.",
        "tags": ["NIST-CSF-2.0", "SOC-CMM", "NCSC-CAF", "ISO-27001", "NIS2", "PCI-DSS-4.0", "MITRE-ATT&CK"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "CyAB-SAL-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "classification", "var_type": "string", "required": False, "default_value": "OFFICIAL", "description": "Document classification level"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Document author"},
            {"name": "organisation", "var_type": "string", "required": False, "default_value": "", "description": "Organisation name"},
            {"name": "department", "var_type": "string", "required": False, "default_value": "Cyber Assurance Base", "description": "CyAB department name"},
            {"name": "review_date", "var_type": "string", "required": False, "default_value": "", "description": "Next review date"},
            {"name": "approved_by", "var_type": "string", "required": False, "default_value": "", "description": "Approval authority (CISO / Head of Cyber Security)"},
            {"name": "siem_tool", "var_type": "string", "required": False, "default_value": "Elastic SIEM", "description": "Primary SIEM platform"},
            {"name": "log_schema", "var_type": "string", "required": False, "default_value": "Elastic Common Schema (ECS)", "description": "Log normalisation schema standard"},
            {"name": "retention_policy_ref", "var_type": "string", "required": False, "default_value": "", "description": "Reference to data retention policy document"},
        ],
        "content": """# {{ doc_id }} — CyAB Security Assurance Levels (SAL)

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Classification** | {{ classification }} |
| **Organisation** | {{ organisation }} |
| **Author** | {{ author }} |
| **Department** | {{ department }} |
| **Review Date** | {{ review_date }} |
| **Approved By** | {{ approved_by }} |

---

## 1. Purpose

This document defines the **Security Assurance Levels (SAL)** framework for the {{ department }}. SALs provide a structured, risk-proportionate approach to determining the depth and rigour of security controls, verification activities, and evidence requirements applied to systems, services, and data assets.

Each assurance level prescribes a baseline of security controls, testing activities, documentation, and ongoing monitoring proportionate to the risk profile of the asset. This ensures that critical and high-risk systems receive greater scrutiny, while lower-risk assets are not burdened with disproportionate overhead.

---

## 2. Scope

This framework applies to:

- All information systems, applications, and services operated or managed under {{ department }} oversight
- Third-party and cloud-hosted services processing organisational data
- Operational technology (OT) and IoT devices within the security perimeter
- Development and staging environments where they process or replicate production data
- New systems during design, build, and pre-production assurance gates

---

## 3. Security Assurance Levels — Overview

| Level | Name | Risk Profile | Typical Assets |
|---|---|---|---|
| **SAL 1** | Foundation | Low risk, low business impact | Internal wikis, development sandboxes, non-sensitive file shares, printer infrastructure |
| **SAL 2** | Standard | Moderate risk, limited business impact | Corporate email, HR systems (non-payroll), project management tools, internal web apps |
| **SAL 3** | Enhanced | High risk, significant business impact | Customer-facing services, financial systems, authentication infrastructure, {{ siem_tool }}/SOC tooling |
| **SAL 4** | Critical | Very high risk, severe business/regulatory impact | Payment processing, PII/PHI data stores, domain controllers, PKI infrastructure, backup & recovery |
| **SAL 5** | Maximum | Existential risk, national security or safety-of-life | CNI control systems, classified networks, safety-critical OT, cryptographic key management |

---

## 4. SAL Classification Criteria

Systems are assigned an SAL based on the **highest applicable score** across the following dimensions:

### 4.1 Impact Assessment Matrix

| Dimension | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| **Confidentiality** | Public or internal-only data | Internal data, limited sensitivity | Confidential business data | PII, financial, legal privilege | Classified, TOP SECRET, safety-critical |
| **Integrity** | Corruption inconvenient | Corruption causes rework | Corruption causes financial loss or compliance breach | Corruption causes significant regulatory/legal action | Corruption causes safety failure or national security harm |
| **Availability** | Downtime tolerable (days) | Downtime tolerable (24h) | Downtime causes revenue loss (≤4h RTO) | Downtime causes major operational failure (≤1h RTO) | Zero-downtime required, life-safety dependency |
| **Regulatory** | No specific regulation | GDPR basics, internal policy | GDPR Art. 32, PCI DSS (low volume), Cyber Essentials Plus | PCI DSS (high volume), FCA, NIS2 essential | CNI (NIS Regulations), Official Secrets Act, DORA critical |
| **Data Subjects** | None / internal staff only | ≤ 1,000 individuals | 1,000–100,000 individuals | 100,000–1M individuals | > 1M individuals or vulnerable groups |
| **Supply Chain** | No external dependencies | Standard SaaS (low privilege) | SaaS with data processing, API integrations | Outsourced critical function, managed SOC | Sovereign infrastructure, cleared contractors |

### 4.2 Override Rules

- Any system processing **payment card data** → minimum SAL 4
- Any system processing **special category data** (Art. 9 GDPR) → minimum SAL 4
- Any system designated as **Critical National Infrastructure** → SAL 5
- Any system with **internet-facing authentication** → minimum SAL 3
- Any system acting as a **trust anchor** (CA, IdP, DNS root) → minimum SAL 4

---

## 5. Security Controls by SAL

### 5.1 Identity and Access Management

| Control | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| Unique user accounts | Required | Required | Required | Required | Required |
| Password policy (complexity + rotation) | Basic (12 char) | Standard (14 char, 365d) | Strong (16 char, 180d) | Strong (16 char, 90d) | Passphrase (20+ char, 90d) |
| Multi-factor authentication | Recommended | Required (SSO) | Required (hardware token accepted) | Required (hardware token / FIDO2) | Required (FIDO2 hardware only) |
| Privileged access management | Shared admin acceptable | Named admin accounts | PAM solution, session recording | PAM with JIT access, break-glass only | PAM with dual-auth, continuous recording, time-bound |
| Access review cycle | Annual | 6-monthly | Quarterly | Monthly | Continuous (automated) |
| Joiners/movers/leavers process | Manual | Semi-automated | Automated with approval workflow | Automated with manager + security approval | Automated with DV/SC clearance validation |
| Service account management | Documented | Documented + rotated annually | Managed secrets vault | Managed vault + auto-rotation | HSM-backed, short-lived certificates |

### 5.2 Network Security

| Control | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| Network segmentation | Flat network acceptable | VLAN separation | Micro-segmentation / zero-trust zones | Dedicated security zone, no lateral trust | Air-gapped or hardware-enforced boundary |
| Firewall rules | Default deny outbound recommended | Default deny outbound | Default deny both directions, reviewed quarterly | Allowlist-only, reviewed monthly | Allowlist-only, reviewed weekly, IDS/IPS inline |
| Encryption in transit | HTTPS for external | TLS 1.2+ for all external | TLS 1.2+ internal and external | TLS 1.3, mutual TLS for service-to-service | TLS 1.3, mTLS, CNSA-approved ciphers |
| DNS security | Standard DNS | Filtered DNS (malware/phishing) | DNSSEC validation, DNS logging | DNSSEC + DNS-over-HTTPS, full query logging | Dedicated resolvers, DNS sinkholing, anomaly detection |
| Remote access | VPN optional | VPN required | VPN + MFA, split-tunnel prohibited | Always-on VPN, device compliance check | Dedicated secure terminal, no BYOD |
| DDoS protection | None | Basic (ISP-level) | Cloud-based WAF/DDoS | Dedicated DDoS mitigation, auto-scaling | Multi-provider, sovereign DDoS mitigation |

### 5.3 Endpoint Security

| Control | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| Anti-malware | Signature-based AV | Next-gen AV | EDR with 24/7 monitoring | EDR + application allowlisting | EDR + allowlisting + host-based IDS |
| Patch management | Monthly | Fortnightly (14 day critical) | Weekly (72h critical, 14d high) | 48h critical, 7d high | 24h critical, 48h high, zero-day same-day |
| Device encryption | Recommended | Required (FDE) | Required (FDE + removable media) | Required (FDE + TPM-backed, USB disabled) | Required (FIPS 140-3 validated encryption) |
| Configuration hardening | Default install | CIS Level 1 | CIS Level 2 / DISA STIG | CIS Level 2 + custom hardening baseline | Bespoke hardened image, integrity monitoring |
| Logging | Local logs | Centralised (SIEM) | Centralised, tamper-evident | Centralised, tamper-evident, 12-month retention | Centralised, cryptographically signed, 7-year retention |

### 5.4 Application Security

| Control | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| Secure development lifecycle | Awareness training | OWASP Top 10 training + linting | SAST + DAST in CI/CD pipeline | SAST + DAST + SCA + manual code review | Formal methods, SAST/DAST/IAST, independent code audit |
| Dependency management | Manual updates | SCA scanning (quarterly) | SCA in CI/CD, auto-PR for critical | SCA + SBOM generation, licence compliance | SBOM + provenance attestation, signed dependencies |
| Input validation | Basic sanitisation | OWASP-compliant validation | WAF + server-side validation | WAF + CSP + server-side + parameterised queries | WAF + CSP + runtime application self-protection (RASP) |
| API security | API keys | API keys + rate limiting | OAuth 2.0 / OIDC + rate limiting | OAuth 2.0 + mTLS + request signing | mTLS + signed tokens + anomaly detection |
| Secrets management | Config files (gitignored) | Environment variables | Secrets vault (HashiCorp/AWS SM) | Secrets vault + auto-rotation + audit | HSM-backed vault, dual-control, break-glass |

### 5.5 Data Protection

| Control | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| Data classification | Not required | Labelled (internal/public) | Labelled (4-tier), handling rules enforced | Automated classification + DLP | Automated classification + DLP + egress monitoring |
| Encryption at rest | Recommended | Required (platform default) | Required (AES-256, managed keys) | Required (AES-256, customer-managed keys) | Required (FIPS 140-3, HSM-managed keys) |
| Backup & recovery | Ad-hoc | Scheduled (daily) | Scheduled (daily), tested quarterly | Scheduled (hourly), tested monthly, offsite | Real-time replication, tested weekly, immutable, geographically separated |
| Data retention | Undefined | Policy-defined | Policy-enforced, automated deletion | Policy-enforced, crypto-shredding capable | Policy-enforced, crypto-shredding, verified destruction |
| Data loss prevention | None | Email DLP (basic) | Endpoint + email DLP | Endpoint + email + cloud + USB DLP | Full-spectrum DLP + UEBA |

### 5.6 Monitoring and Detection

| Control | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| Log collection | Local only | Centralised SIEM (key sources) | Centralised SIEM (all sources), 90d retention | Full telemetry (SIEM + NDR + EDR), 12m retention | Full telemetry + UEBA + deception, 7yr retention |
| Alert monitoring | Business hours | Business hours, P1 on-call | 24/7 automated + analyst triage | 24/7 SOC with dedicated analyst coverage | 24/7 SOC + red team + continuous threat hunt |
| Detection rules | Vendor defaults | Vendor + basic custom rules | MITRE ATT&CK-mapped rules (≥40% coverage) | ATT&CK-mapped (≥60%), behavioural analytics | ATT&CK-mapped (≥80%), ML-based anomaly detection |
| Threat hunting | None | Reactive (post-incident) | Scheduled (monthly) | Scheduled (fortnightly) + ad-hoc | Continuous, dedicated hunt team |
| Incident response | Ad-hoc | Documented IRP | Documented IRP, tabletop annually | IRP + playbooks, tabletop quarterly, retainer | IRP + playbooks + automated SOAR, live exercise bi-annually |

---

## 6. Log Quality and Telemetry Standards

Log telemetry is a foundational security control. The depth, quality, and integrity of logging must be proportionate to the system's SAL.

### 6.1 Log Quality Dimensions

Every log source is assessed against six quality dimensions:

| Dimension | Definition | Why It Matters |
|-----------|-----------|----------------|
| **Completeness** | All required event types are generated and forwarded | Missing events create blind spots in detection coverage |
| **Timeliness** | Events arrive at the SIEM within acceptable latency | Stale logs delay detection and response |
| **Schema Conformance** | Events are normalised to {{ log_schema }} with all required fields populated | Inconsistent schemas break correlation rules, dashboards, and automated playbooks |
| **Integrity** | Events cannot be silently modified or deleted between source and SIEM | Tampered logs undermine forensic evidence and regulatory compliance |
| **Enrichment** | Events are augmented with contextual metadata (asset owner, geo, threat intel, business unit) | Raw logs lack the context analysts need to triage |
| **Retention** | Events are stored for the required duration per policy and regulation | Short retention prevents historical threat hunting and audit evidence |

### 6.2 Required Event Types by SAL

#### Authentication and Access Events

| Event Type | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|-----------|-------|-------|-------|-------|-------|
| Successful / failed login | — | Required | Required | Required | Required |
| Account lockout | — | Required | Required | Required | Required |
| MFA success/failure | — | — | Required | Required | Required |
| Privilege escalation (sudo, runas) | — | — | Required | Required | Required |
| Service account authentication | — | — | Required | Required | Required |
| Session creation / termination | — | — | — | Required | Required |
| Token issuance / refresh / revocation | — | — | — | Required | Required |
| PAM session recording metadata | — | — | — | Required | Required |
| Certificate-based auth events | — | — | — | — | Required |

#### System and Endpoint Events

| Event Type | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|-----------|-------|-------|-------|-------|-------|
| Process creation (with command line) | — | — | Required | Required | Required |
| Process termination | — | — | — | Required | Required |
| Service install / start / stop | — | Required | Required | Required | Required |
| Scheduled task creation / modification | — | — | Required | Required | Required |
| Driver / kernel module load | — | — | — | Required | Required |
| File creation in monitored paths | — | — | Required | Required | Required |
| File integrity monitoring (FIM) changes | — | — | — | Required | Required |
| Registry modification (Windows) | — | — | Required | Required | Required |
| USB device attach / detach | — | — | — | Required | Required |
| Boot / shutdown events | — | Required | Required | Required | Required |

#### Network Events

| Event Type | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|-----------|-------|-------|-------|-------|-------|
| Firewall allow/deny | — | Required | Required | Required | Required |
| DNS queries (with response) | — | — | Required | Required | Required |
| HTTP/HTTPS proxy logs | — | — | Required | Required | Required |
| NetFlow / IPFIX | — | — | — | Required | Required |
| Full packet capture (PCAP) | — | — | — | — | Required |
| VPN connect / disconnect | — | Required | Required | Required | Required |
| IDS/IPS alerts | — | — | Required | Required | Required |
| DHCP lease events | — | — | Required | Required | Required |
| TLS certificate metadata | — | — | — | Required | Required |
| Lateral movement indicators (SMB, RDP, WinRM, SSH) | — | — | Required | Required | Required |

#### Application and Cloud Events

| Event Type | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|-----------|-------|-------|-------|-------|-------|
| Application error / exception | Recommended | Required | Required | Required | Required |
| API access (request + response code) | — | — | Required | Required | Required |
| Data access (read/write to sensitive resources) | — | — | Required | Required | Required |
| Configuration change | — | Required | Required | Required | Required |
| Deployment / release events | — | — | Required | Required | Required |
| Cloud control plane (IAM, resource create/delete) | — | — | Required | Required | Required |
| Cloud data plane (object access, DB queries) | — | — | — | Required | Required |
| Container lifecycle (start, stop, exec) | — | — | Required | Required | Required |
| Secrets access (vault audit log) | — | — | — | Required | Required |
| Email gateway events | — | — | Required | Required | Required |

#### Security Tool Events

| Event Type | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|-----------|-------|-------|-------|-------|-------|
| AV / EDR detection alerts | Required | Required | Required | Required | Required |
| EDR telemetry (full) | — | — | Required | Required | Required |
| Vulnerability scan results | — | Required | Required | Required | Required |
| DLP alerts | — | — | — | Required | Required |
| WAF events | — | — | Required | Required | Required |
| SIEM health / ingestion metrics | — | Required | Required | Required | Required |
| Backup success / failure | — | Required | Required | Required | Required |
| Patch deployment status | — | — | Required | Required | Required |

### 6.3 Schema and Normalisation Standards

All log sources forwarding to {{ siem_tool }} must be normalised to **{{ log_schema }}** or an approved equivalent.

**Mandatory Fields (All SALs):**

| Field | ECS Field Name | Description |
|-------|---------------|-------------|
| Timestamp | `@timestamp` | Event time in UTC, ISO 8601, millisecond precision minimum |
| Event category | `event.category` | High-level classification (authentication, process, network, file) |
| Event action | `event.action` | Specific action (login, file-create, dns-query) |
| Event outcome | `event.outcome` | success, failure, or unknown |
| Source host | `host.name` | FQDN or hostname of the originating system |
| Source IP | `source.ip` | IP address of the event source |
| User identity | `user.name` | Username or service account |
| Data source | `event.dataset` | Log source identifier (e.g. windows.security, zeek.dns) |
| Observer | `observer.name` | Sensor/agent/forwarder that collected the event |

**Enhanced Fields (SAL 3+):**

| Field | ECS Field Name | Required From |
|-------|---------------|---------------|
| Process name + command line | `process.name`, `process.command_line` | SAL 3 |
| Process parent | `process.parent.name` | SAL 3 |
| File hash (SHA-256) | `file.hash.sha256` | SAL 3 |
| Destination IP + port | `destination.ip`, `destination.port` | SAL 3 |
| Geo enrichment | `source.geo.country_name`, `destination.geo.country_name` | SAL 3 |
| Threat indicator match | `threat.indicator.matched.*` | SAL 4 |
| User agent | `user_agent.original` | SAL 3 |
| TLS version and cipher | `tls.version`, `tls.cipher` | SAL 4 |
| Asset criticality tag | `labels.asset_criticality` | SAL 4 |
| Business unit tag | `labels.business_unit` | SAL 4 |
| Data classification | `labels.data_classification` | SAL 4 |

**Schema Compliance Targets:**

| SAL | Mandatory Fields Present | Enhanced Fields Present | Unparsed / Raw-Only Events |
|-----|-------------------------|------------------------|---------------------------|
| SAL 1 | 80%+ | N/A | Up to 50% acceptable |
| SAL 2 | 90%+ | N/A | Up to 20% acceptable |
| SAL 3 | 95%+ | 80%+ | Up to 5% acceptable |
| SAL 4 | 98%+ | 95%+ | 0% — all events must be parsed |
| SAL 5 | 100% | 100% | 0% — all events must be parsed and validated |

### 6.4 Timeliness Standards

| SAL | Max Ingestion Latency | Max Clock Skew | NTP Requirement |
|-----|----------------------|----------------|-----------------|
| SAL 1 | 60 minutes | 5 minutes | Recommended |
| SAL 2 | 15 minutes | 2 minutes | Required |
| SAL 3 | 5 minutes | 1 minute | Required (authenticated NTP) |
| SAL 4 | 2 minutes | 500ms | Required (authenticated NTP, redundant sources) |
| SAL 5 | 30 seconds | 100ms | Required (PTP or GPS-disciplined where available) |

- {{ siem_tool }} ingestion pipeline metrics must be monitored for each log source
- Alert if any source exceeds 2x its SAL latency target for more than 15 minutes
- Alert if any source goes silent for more than its expected heartbeat interval

### 6.5 Log Integrity Controls

| Control | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---------|-------|-------|-------|-------|-------|
| Separate log storage from source system | — | Required | Required | Required | Required |
| Forward-only (source cannot delete from SIEM) | — | Required | Required | Required | Required |
| Encrypted transport (TLS) | — | Required | Required | Required | Required |
| Log source authentication (mTLS / API key) | — | — | Required | Required | Required |
| Write-once / append-only storage | — | — | — | Required | Required |
| Cryptographic signing (per-event or per-batch) | — | — | — | — | Required |
| Independent integrity verification | — | — | — | — | Required |
| Tamper detection alerting | — | — | Required | Required | Required |
| Separation of duties (log admins vs system admins) | — | — | — | Required | Required |
| Chain of custody documentation for forensic use | — | — | — | Required | Required |

### 6.6 Telemetry Coverage and Health

| SAL | Systems Forwarding Logs | Event Types Collected (vs Required) | Log Source Health Monitored |
|-----|------------------------|-----------------------------------|-----------------------------|
| SAL 1 | 70%+ of in-scope assets | Best effort | — |
| SAL 2 | 85%+ of in-scope assets | 80%+ of required event types | Quarterly manual check |
| SAL 3 | 95%+ of in-scope assets | 90%+ of required event types | Automated heartbeat monitoring |
| SAL 4 | 99%+ of in-scope assets | 98%+ of required event types | Real-time health dashboard + alerts |
| SAL 5 | 100% of in-scope assets | 100% of required event types | Real-time + independent audit |

**Gap Detection:**

- Maintain a log source inventory mapping every in-scope asset to expected log types
- Run automated gap detection: compare asset register against SIEM source list
- For SAL 3+: automated detection of log sources that go silent (no events for over 2x normal interval)
- For SAL 4+: daily automated report of coverage percentage vs target
- For SAL 5: any coverage gap triggers an immediate security incident

**New Source Onboarding SLA:**

| SAL | Onboarding Target | Parser / Normalisation |
|-----|-------------------|-----------------------|
| SAL 1 | Best effort | Raw acceptable |
| SAL 2 | 10 business days or less | Basic parsing |
| SAL 3 | 5 business days or less | Full ECS normalisation |
| SAL 4 | 3 business days or less | Full ECS + enrichment + detection rules |
| SAL 5 | 1 business day or less | Full ECS + enrichment + detection rules + validation |

### 6.7 Enrichment Standards

| Enrichment Type | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|----------------|-------|-------|-------|-------|-------|
| Asset inventory lookup (hostname to owner, OS, criticality) | — | — | Required | Required | Required |
| GeoIP enrichment (source + destination) | — | — | Required | Required | Required |
| Threat intelligence IOC matching | — | — | Required | Required | Required |
| User identity resolution (username to employee, department) | — | — | — | Required | Required |
| Vulnerability context (host to open CVEs) | — | — | — | Required | Required |
| Business unit / data classification tagging | — | — | — | Required | Required |
| Historical baseline (is this normal for this host/user?) | — | — | — | — | Required |
| MITRE ATT&CK technique tagging on detection events | — | — | Required | Required | Required |

### 6.8 Retention Standards

| SAL | Hot Storage (searchable) | Warm Storage (queryable, slower) | Cold / Archive | Total Minimum |
|-----|------------------------|--------------------------------|----------------|---------------|
| SAL 1 | 7 days | 23 days | — | **30 days** |
| SAL 2 | 30 days | 60 days | — | **90 days** |
| SAL 3 | 30 days | 60 days | 275 days | **1 year** |
| SAL 4 | 90 days | 275 days | 2 years | **3 years** |
| SAL 5 | 90 days | 275 days | 6+ years | **7 years** |

Retention periods may be extended by regulatory requirements. Refer to: {{ retention_policy_ref }}

**Retention by Log Type (SAL 3+):**

| Log Type | Minimum Retention (SAL 3) | Minimum Retention (SAL 4/5) |
|----------|--------------------------|----------------------------|
| Authentication events | 1 year | 3 years / 7 years |
| Privilege escalation | 1 year | 3 years / 7 years |
| Firewall deny | 90 days | 1 year / 3 years |
| DNS queries | 90 days | 1 year / 3 years |
| NetFlow | 30 days | 90 days / 1 year |
| Full PCAP | N/A | 7 days / 30 days |
| Application access | 1 year | 3 years / 7 years |
| Configuration changes | 1 year | 3 years / 7 years |
| EDR telemetry | 90 days | 1 year / 3 years |
| SIEM alerts / detections | 1 year | 3 years / 7 years |
| Vulnerability scan results | 1 year | 3 years / 7 years |

### 6.9 Log Quality Assurance

**Review Cadence:**

| Activity | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|----------|-------|-------|-------|-------|-------|
| Log source inventory review | Annual | 6-monthly | Quarterly | Monthly | Continuous |
| Schema compliance audit | — | Annual | Quarterly | Monthly | Continuous |
| Coverage gap assessment | — | Annual | Quarterly | Monthly | Weekly |
| Ingestion latency review | — | — | Monthly | Weekly | Daily |
| Integrity controls audit | — | — | Annual | Quarterly | Monthly |
| Enrichment accuracy check | — | — | Quarterly | Monthly | Monthly |
| Retention compliance check | — | Annual | Quarterly | Quarterly | Monthly |

**Log Quality Scorecard (SAL 3+):**

Each log source receives a quarterly quality score:

| Metric | Weight | Measurement |
|--------|--------|-------------|
| Completeness (event types present vs required) | 25% | Automated inventory comparison |
| Timeliness (% events within latency target) | 20% | SIEM pipeline metrics |
| Schema conformance (% events with all required fields) | 25% | Automated field presence check |
| Availability (% uptime with no gaps over threshold) | 20% | Heartbeat monitoring |
| Enrichment (% events with expected enrichment) | 10% | Spot-check sample |

Score thresholds: **90%+** Compliant (green) — **75-89%** At risk (amber, remediation within 14 days) — **Below 75%** Non-compliant (red, escalate to system owner)


## 7. Assurance Activities by SAL

### 7.1 Verification and Testing

| Activity | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| **Vulnerability scanning** | Quarterly (external) | Monthly (external + internal) | Fortnightly (authenticated) | Weekly (authenticated + credentialed) | Continuous (agent-based) |
| **Penetration testing** | None | Annual (external) | Annual (external + internal) | Bi-annual (external + internal + social eng.) | Quarterly + continuous red team |
| **Configuration audit** | Annual self-assessment | Annual (automated CIS scan) | Quarterly (automated + spot check) | Monthly (automated + manual review) | Continuous compliance monitoring |
| **Code review** | Peer review (optional) | Peer review (required) | Peer review + SAST | Peer review + SAST + independent review | Formal security audit per release |
| **Architecture review** | None | At major change | At every significant change | Quarterly review + change-triggered | Continuous architecture oversight board |
| **Disaster recovery test** | None | Annual (documented) | Annual (live test) | Bi-annual (live test, failover validated) | Quarterly (live test, measured RTO/RPO) |
| **Business continuity test** | None | Annual (tabletop) | Annual (simulation) | Bi-annual (simulation + live) | Quarterly (live exercise, unannounced) |

### 7.2 Third-Party Assurance

| Activity | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| **Supplier risk assessment** | Self-certification | Security questionnaire | Questionnaire + evidence review | On-site audit or SOC 2 Type II | On-site audit + continuous monitoring + right-to-audit |
| **Contract security clauses** | Standard T&Cs | Data processing agreement | DPA + security schedule + breach notification | DPA + security schedule + pen test right + SLA | Bespoke security contract, sovereign hosting, escrow |
| **Ongoing monitoring** | None | Annual review | Annual review + incident notification | Quarterly review + automated risk scoring | Continuous monitoring + threat intel sharing |

---

## 8. Documentation and Evidence Requirements

### 8.1 Required Artefacts per SAL

| Artefact | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| System description / asset register entry | Required | Required | Required | Required | Required |
| Data flow diagram | — | Recommended | Required | Required (detailed) | Required (verified, classified) |
| Risk assessment | — | Lightweight | Full (ISO 27005 / NIST 800-30) | Full + threat modelling (STRIDE/PASTA) | Full + threat modelling + residual risk sign-off |
| Security architecture document | — | — | Required | Required (reviewed) | Required (independently assured) |
| Hardening guide / build standard | — | — | CIS benchmark reference | Custom hardening baseline | Formal hardening spec, deviation register |
| Incident response playbook | — | Generic IRP reference | System-specific playbook | System-specific + tested playbook | Tested + automated playbook |
| Pen test report | — | Annual summary | Full report + remediation tracker | Full report + retest evidence | Full report + retest + continuous findings |
| Compliance evidence pack | — | — | Annual evidence bundle | Quarterly evidence bundle | Continuous compliance dashboard |
| Business impact assessment | — | — | Required | Required (signed by business owner) | Required (signed by board-level sponsor) |
| Decommissioning plan | — | — | — | Required | Required (data destruction certified) |

### 8.2 Evidence Retention

| SAL | Minimum Retention | Storage |
|---|---|---|
| SAL 1 | 1 year | Standard file share |
| SAL 2 | 2 years | Standard file share (access-controlled) |
| SAL 3 | 3 years | Secured repository, tamper-evident |
| SAL 4 | 5 years | Secured repository, cryptographically signed |
| SAL 5 | 7 years (or regulatory minimum) | Immutable storage, dual-control access |

---

## 9. Assurance Lifecycle

### 9.1 Assurance Gates

All systems must pass through assurance gates at key lifecycle stages:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   DESIGN    │───▶│    BUILD    │───▶│   PRE-PROD  │───▶│  LIVE /     │───▶│  DECOMMIS-  │
│   GATE      │    │   GATE      │    │   GATE      │    │  OPERATE    │    │  SION GATE  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

| Gate | SAL 1 | SAL 2 | SAL 3 | SAL 4 | SAL 5 |
|---|---|---|---|---|---|
| **Design Gate** | Self-assessment | Peer review | Security architecture review | Security architecture review + threat model | Independent architecture assurance |
| **Build Gate** | N/A | SAST pass | SAST + DAST pass, dependency scan clean | SAST + DAST + code review + hardening verified | Independent code audit + hardening audit |
| **Pre-prod Gate** | Basic smoke test | Vuln scan (clean critical/high) | Vuln scan + pen test (clean critical) | Pen test + config audit + DR test | Full assurance pack review + sign-off board |
| **Operate** | Monitoring enabled | Monitoring + quarterly review | 24/7 monitoring + monthly review | 24/7 SOC + fortnightly review + threat hunt | 24/7 SOC + continuous hunt + red team |
| **Decommission Gate** | Asset register updated | Data migration verified | Data securely deleted, access revoked | Crypto-shredding + audit trail | Certified destruction + regulatory notification |

### 9.2 Review Cadence

| SAL | Full Assurance Review | Control Spot-check | SAL Re-classification |
|---|---|---|---|
| SAL 1 | Every 2 years | Annual | On significant change |
| SAL 2 | Annually | 6-monthly | On significant change |
| SAL 3 | Annually | Quarterly | Annually or on change |
| SAL 4 | Bi-annually | Monthly | Annually or on change |
| SAL 5 | Quarterly | Continuous | Quarterly |

---

## 10. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| **System Owner** | Ensures system meets its assigned SAL requirements. Provides resources for assurance activities. Accepts residual risk. |
| **Cyber Assurance Manager** | Maintains the SAL framework. Conducts or commissions assurance reviews. Escalates non-compliance. |
| **{{ department }} Analysts (L1–L3)** | Execute monitoring and detection at the depth prescribed by the system's SAL. Conduct threat hunts on SAL 3+ systems. |
| **SOC Lead** | Ensures operational coverage aligns with SAL requirements. Manages escalation and reporting cadence. |
| **Detection Engineer** | Builds and maintains detection rules at the coverage level required by each SAL tier. |
| **IT Operations / Platform Team** | Implements and maintains technical controls (patching, hardening, logging) to the standard required by the SAL. |
| **CISO / Head of Cyber Security** | Approves SAL 4/5 risk acceptances. Sponsors the framework. Reports assurance posture to board. |
| **Internal Audit** | Independently verifies SAL compliance for SAL 4/5 systems on an annual basis. |

---

## 11. SAL Assignment Process

### 11.1 Workflow

```
1. System Owner completes Impact Assessment (Section 4.1)
     │
     ▼
2. {{ department }} reviews assessment, applies override rules (Section 4.2)
     │
     ▼
3. Proposed SAL agreed between System Owner and Cyber Assurance Manager
     │
     ▼
4. SAL 4/5: Requires CISO sign-off
     │
     ▼
5. SAL recorded in asset register, controls baseline generated
     │
     ▼
6. Gap analysis: current controls vs. required SAL baseline
     │
     ▼
7. Remediation plan agreed (owner + timelines)
     │
     ▼
8. Assurance gate reviews commence per lifecycle stage
```

### 11.2 SAL Change Triggers

A system's SAL must be re-evaluated when:

- Significant change to data processed (volume, sensitivity, or classification)
- Change of hosting environment (on-prem ↔ cloud, change of provider)
- Regulatory change affecting the system or its data
- Merger, acquisition, or organisational restructure
- Security incident involving the system
- Major architectural change (new integrations, API exposure, public access)
- Scheduled re-classification review (per Section 9.2)

---

## 12. Non-Compliance and Risk Acceptance

### 12.1 Non-Compliance Handling

| Scenario | Action |
|---|---|
| **Control gap identified** (SAL 1–2) | Logged in risk register, remediation plan within 30 days |
| **Control gap identified** (SAL 3) | Escalated to Cyber Assurance Manager, remediation plan within 14 days |
| **Control gap identified** (SAL 4–5) | Escalated to CISO, remediation plan within 7 days, interim compensating controls required |
| **Systemic non-compliance** (multiple systems) | Triggered as a security incident, reported to senior leadership |

### 12.2 Risk Acceptance

Where a control cannot be implemented within the prescribed timeframe:

- **SAL 1–2:** System Owner may accept risk with documented justification (annual review)
- **SAL 3:** Cyber Assurance Manager must co-sign risk acceptance (6-month review)
- **SAL 4:** CISO must approve risk acceptance (quarterly review, compensating control required)
- **SAL 5:** Board-level sponsor must approve (monthly review, compensating control mandatory, time-limited ≤90 days)

---

## 13. Framework Alignment

| Framework | SAL Mapping |
|---|---|
| **NCSC CAF** | CAF Indicator A–D profiles map to SAL 2–5 |
| **ISO 27001:2022** | SAL 3+ aligns with Annex A control applicability |
| **Cyber Essentials / CE+** | SAL 2 baseline ≈ Cyber Essentials; SAL 3 baseline ≈ CE+ |
| **NIST CSF 2.0** | SAL tiers map to CSF implementation tiers (Partial → Adaptive) |
| **PCI DSS 4.0** | SAL 4 controls meet PCI DSS requirements for CDE systems |
| **NIS2 Directive** | Essential entities → SAL 4 minimum; Important entities → SAL 3 minimum |
| **DORA** | Critical ICT services → SAL 4/5 |
| **Common Criteria** | SAL 1≈EAL1, SAL 2≈EAL2, SAL 3≈EAL3, SAL 4≈EAL4, SAL 5≈EAL5+ |

---

## 14. Glossary

| Term | Definition |
|---|---|
| **SAL** | Security Assurance Level — a risk-proportionate tier of security controls and verification |
| **{{ department }}** | Cyber Assurance Base — the centralised cyber security assurance function |
| **CAF** | Cyber Assessment Framework (NCSC) |
| **CNI** | Critical National Infrastructure |
| **DLP** | Data Loss Prevention |
| **FDE** | Full Disk Encryption |
| **FIDO2** | Fast Identity Online 2 — hardware-based authentication standard |
| **HSM** | Hardware Security Module |
| **JIT** | Just-In-Time (access provisioning) |
| **mTLS** | Mutual Transport Layer Security |
| **PAM** | Privileged Access Management |
| **RASP** | Runtime Application Self-Protection |
| **SAST** | Static Application Security Testing |
| **DAST** | Dynamic Application Security Testing |
| **SCA** | Software Composition Analysis |
| **SBOM** | Software Bill of Materials |
| **SOAR** | Security Orchestration, Automation, and Response |
| **UEBA** | User and Entity Behaviour Analytics |
| **RTO** | Recovery Time Objective |
| **RPO** | Recovery Point Objective |

---

## 15. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-24 | {{ department }} | Initial release |

---

## 16. Signatories

| Role | Name | Signature | Date |
|---|---|---|---|
| **Cyber Assurance Manager** | | | |
| **Head of Cyber Security / CISO** | | | |
| **Head of IT Operations** | | | |
| **Internal Audit Representative** | | | |

---

*This document is subject to annual review. Next scheduled review: March 2027.*


---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | | {{ author }} | Initial version |
""",
    },
    # =========================================================================
    # SAL Assessment (form-driven with dropdowns)
    # =========================================================================
    {
        "name": "CyAB SAL Assessment",
        "document_type": "SAL",
        "collection": "Security Assurance",
        "description": "Structured SAL gap assessment with selectable compliance levels per control domain. Use the full SAL template as reference.",
        "tags": ["NIST-CSF-2.0", "SOC-CMM", "NCSC-CAF", "ISO-27001"],
        "variables": [
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "SAL-ASSESS-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "classification", "var_type": "string", "required": False, "default_value": "INTERNAL", "description": "Classification level"},
            {"name": "author", "var_type": "string", "required": True, "default_value": "", "description": "Assessor name"},
            {"name": "organisation", "var_type": "string", "required": True, "default_value": "", "description": "Organisation being assessed"},
            {"name": "department", "var_type": "string", "required": False, "default_value": "Security Operations Center", "description": "Department"},
            {"name": "assessment_date", "var_type": "string", "required": True, "default_value": "", "description": "Assessment date"},
            {"name": "approved_by", "var_type": "string", "required": False, "default_value": "", "description": "Approval authority"},
            {"name": "target_sal", "var_type": "string", "required": True, "default_value": "SAL 2 — Standard", "description": "Target SAL level",
             "options": ["SAL 1 — Foundation", "SAL 2 — Standard", "SAL 3 — Enhanced", "SAL 4 — High", "SAL 5 — Maximum"]},
            {"name": "current_sal", "var_type": "string", "required": True, "default_value": "SAL 1 — Foundation", "description": "Current assessed SAL level",
             "options": ["SAL 1 — Foundation", "SAL 2 — Standard", "SAL 3 — Enhanced", "SAL 4 — High", "SAL 5 — Maximum"]},
            # --- Control domain assessments ---
            {"name": "governance_status", "var_type": "string", "required": True, "default_value": "Partial", "description": "Governance & Policy",
             "options": ["Not Implemented", "Partial", "Largely Implemented", "Fully Implemented", "N/A"]},
            {"name": "asset_mgmt_status", "var_type": "string", "required": True, "default_value": "Partial", "description": "Asset Management",
             "options": ["Not Implemented", "Partial", "Largely Implemented", "Fully Implemented", "N/A"]},
            {"name": "access_control_status", "var_type": "string", "required": True, "default_value": "Partial", "description": "Access Control & Identity",
             "options": ["Not Implemented", "Partial", "Largely Implemented", "Fully Implemented", "N/A"]},
            {"name": "network_security_status", "var_type": "string", "required": True, "default_value": "Partial", "description": "Network Security",
             "options": ["Not Implemented", "Partial", "Largely Implemented", "Fully Implemented", "N/A"]},
            {"name": "endpoint_status", "var_type": "string", "required": True, "default_value": "Partial", "description": "Endpoint Protection",
             "options": ["Not Implemented", "Partial", "Largely Implemented", "Fully Implemented", "N/A"]},
            {"name": "logging_status", "var_type": "string", "required": True, "default_value": "Partial", "description": "Logging & Monitoring",
             "options": ["Not Implemented", "Partial", "Largely Implemented", "Fully Implemented", "N/A"]},
            {"name": "incident_response_status", "var_type": "string", "required": True, "default_value": "Partial", "description": "Incident Response",
             "options": ["Not Implemented", "Partial", "Largely Implemented", "Fully Implemented", "N/A"]},
            {"name": "vuln_mgmt_status", "var_type": "string", "required": True, "default_value": "Partial", "description": "Vulnerability Management",
             "options": ["Not Implemented", "Partial", "Largely Implemented", "Fully Implemented", "N/A"]},
            {"name": "data_protection_status", "var_type": "string", "required": True, "default_value": "Partial", "description": "Data Protection",
             "options": ["Not Implemented", "Partial", "Largely Implemented", "Fully Implemented", "N/A"]},
            {"name": "training_status", "var_type": "string", "required": True, "default_value": "Partial", "description": "Security Awareness & Training",
             "options": ["Not Implemented", "Partial", "Largely Implemented", "Fully Implemented", "N/A"]},
            {"name": "bcdr_status", "var_type": "string", "required": True, "default_value": "Partial", "description": "Business Continuity & DR",
             "options": ["Not Implemented", "Partial", "Largely Implemented", "Fully Implemented", "N/A"]},
            {"name": "third_party_status", "var_type": "string", "required": True, "default_value": "Partial", "description": "Third-Party & Supply Chain",
             "options": ["Not Implemented", "Partial", "Largely Implemented", "Fully Implemented", "N/A"]},
            {"name": "physical_status", "var_type": "string", "required": True, "default_value": "Partial", "description": "Physical Security",
             "options": ["Not Implemented", "Partial", "Largely Implemented", "Fully Implemented", "N/A"]},
            {"name": "compliance_status", "var_type": "string", "required": True, "default_value": "Partial", "description": "Compliance & Audit",
             "options": ["Not Implemented", "Partial", "Largely Implemented", "Fully Implemented", "N/A"]},
            # --- Notes fields ---
            {"name": "governance_notes", "var_type": "string", "required": False, "default_value": "", "description": "Governance notes/evidence"},
            {"name": "asset_mgmt_notes", "var_type": "string", "required": False, "default_value": "", "description": "Asset management notes"},
            {"name": "access_control_notes", "var_type": "string", "required": False, "default_value": "", "description": "Access control notes"},
            {"name": "network_security_notes", "var_type": "string", "required": False, "default_value": "", "description": "Network security notes"},
            {"name": "endpoint_notes", "var_type": "string", "required": False, "default_value": "", "description": "Endpoint protection notes"},
            {"name": "logging_notes", "var_type": "string", "required": False, "default_value": "", "description": "Logging & monitoring notes"},
            {"name": "incident_response_notes", "var_type": "string", "required": False, "default_value": "", "description": "Incident response notes"},
            {"name": "vuln_mgmt_notes", "var_type": "string", "required": False, "default_value": "", "description": "Vulnerability management notes"},
            {"name": "data_protection_notes", "var_type": "string", "required": False, "default_value": "", "description": "Data protection notes"},
            {"name": "training_notes", "var_type": "string", "required": False, "default_value": "", "description": "Training notes"},
            {"name": "bcdr_notes", "var_type": "string", "required": False, "default_value": "", "description": "BCDR notes"},
            {"name": "third_party_notes", "var_type": "string", "required": False, "default_value": "", "description": "Third-party risk notes"},
            {"name": "physical_notes", "var_type": "string", "required": False, "default_value": "", "description": "Physical security notes"},
            {"name": "compliance_notes", "var_type": "string", "required": False, "default_value": "", "description": "Compliance & audit notes"},
            # --- Summary ---
            {"name": "key_findings", "var_type": "string", "required": False, "default_value": "", "description": "Key findings summary"},
            {"name": "priority_recommendations", "var_type": "string", "required": False, "default_value": "", "description": "Priority recommendations"},
            {"name": "review_date", "var_type": "string", "required": False, "default_value": "", "description": "Next review date"},
        ],
        "content": """# {{ doc_id }} — CyAB SAL Assessment

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Classification** | {{ classification }} |
| **Assessor** | {{ author }} |
| **Organisation** | {{ organisation }} |
| **Department** | {{ department }} |
| **Assessment Date** | {{ assessment_date }} |
| **Approved By** | {{ approved_by }} |
| **Target SAL** | {{ target_sal }} |
| **Current SAL** | {{ current_sal }} |
| **Next Review** | {{ review_date }} |

---

## 1. Executive Summary

This assessment evaluates **{{ organisation }}** against the CyAB Security Assurance Levels (SAL) framework. The organisation is targeting **{{ target_sal }}** and is currently assessed at **{{ current_sal }}**.

> **Reference:** See the full *CyAB Security Assurance Levels (SAL)* document in the Security Assurance collection for detailed requirements at each tier.

### SAL Level Summary

| Level | Description | Typical Use Case |
|-------|-------------|-----------------|
| **SAL 1 — Foundation** | Baseline hygiene — antivirus, patching, password policies | Small orgs, low-risk environments |
| **SAL 2 — Standard** | Centralised logging, vulnerability scanning, IR plan | Mid-size orgs, standard compliance (CE+, ISO 27001 basic) |
| **SAL 3 — Enhanced** | SIEM with correlation, threat hunting, red team exercises | Regulated sectors, CNI operators, NIS2 scope |
| **SAL 4 — High** | 24/7 SOC, advanced EDR, deception tech, SOAR automation | Financial services, defence supply chain, PCI DSS |
| **SAL 5 — Maximum** | Zero-trust architecture, air-gapped enclaves, real-time CTI | National security, classified environments |

---

## 2. Control Domain Assessment

### Assessment Key

| Status | Meaning |
|--------|---------|
| **Fully Implemented** | Control fully operational, evidenced, and tested |
| **Largely Implemented** | Control in place with minor gaps or untested elements |
| **Partial** | Some elements implemented, significant gaps remain |
| **Not Implemented** | Control absent or non-functional |
| **N/A** | Not applicable to this organisation's scope |

### Assessment Matrix

| # | Control Domain | Status | Notes |
|---|---------------|--------|-------|
| 1 | Governance & Policy | **{{ governance_status }}** | {{ governance_notes }} |
| 2 | Asset Management | **{{ asset_mgmt_status }}** | {{ asset_mgmt_notes }} |
| 3 | Access Control & Identity | **{{ access_control_status }}** | {{ access_control_notes }} |
| 4 | Network Security | **{{ network_security_status }}** | {{ network_security_notes }} |
| 5 | Endpoint Protection | **{{ endpoint_status }}** | {{ endpoint_notes }} |
| 6 | Logging & Monitoring | **{{ logging_status }}** | {{ logging_notes }} |
| 7 | Incident Response | **{{ incident_response_status }}** | {{ incident_response_notes }} |
| 8 | Vulnerability Management | **{{ vuln_mgmt_status }}** | {{ vuln_mgmt_notes }} |
| 9 | Data Protection | **{{ data_protection_status }}** | {{ data_protection_notes }} |
| 10 | Security Awareness & Training | **{{ training_status }}** | {{ training_notes }} |
| 11 | Business Continuity & DR | **{{ bcdr_status }}** | {{ bcdr_notes }} |
| 12 | Third-Party & Supply Chain | **{{ third_party_status }}** | {{ third_party_notes }} |
| 13 | Physical Security | **{{ physical_status }}** | {{ physical_notes }} |
| 14 | Compliance & Audit | **{{ compliance_status }}** | {{ compliance_notes }} |

---

## 3. Domain Detail: Governance & Policy

**Status:** {{ governance_status }}

**What {{ target_sal }} requires:**
{% if 'SAL 1' in target_sal %}- Documented acceptable use policy
- Basic roles and responsibilities defined
- Annual policy review cycle{% elif 'SAL 2' in target_sal %}- Information security policy aligned to ISO 27001
- Risk register maintained and reviewed quarterly
- Security roles formally assigned (CISO or equivalent)
- Policy exception process documented{% elif 'SAL 3' in target_sal %}- Comprehensive ISMS with risk-based approach
- Board-level security reporting (quarterly minimum)
- Policy framework covering all NCSC CAF objectives
- Formal security committee with cross-functional membership{% elif 'SAL 4' in target_sal %}- Integrated GRC platform
- Real-time risk dashboard with automated control testing
- Third-party governance framework
- Regulatory change management process{% elif 'SAL 5' in target_sal %}- Continuous assurance model with automated evidence collection
- Zero-trust governance principles embedded
- Independent security oversight board
- Supply chain security governance{% endif %}

**Evidence / Notes:** {{ governance_notes }}

---

## 4. Domain Detail: Asset Management

**Status:** {{ asset_mgmt_status }}

**What {{ target_sal }} requires:**
{% if 'SAL 1' in target_sal %}- Hardware and software inventory maintained
- Asset ownership assigned
- End-of-life tracking{% elif 'SAL 2' in target_sal %}- Automated asset discovery (network scanning)
- CMDB or asset register with classification
- Software licence tracking
- Shadow IT detection{% elif 'SAL 3' in target_sal %}- Real-time asset visibility across all environments
- Data classification scheme enforced
- Cloud asset inventory (CSPM integration)
- Automated decommissioning workflows{% elif 'SAL 4' in target_sal %}- Full CMDB integration with SIEM and ticketing
- Asset risk scoring (criticality x exposure)
- IoT/OT asset discovery
- Automated compliance checking per asset class{% elif 'SAL 5' in target_sal %}- Cryptographic asset attestation
- Hardware root-of-trust verification
- Air-gapped asset management for classified systems
- Supply chain provenance tracking{% endif %}

**Evidence / Notes:** {{ asset_mgmt_notes }}

---

## 5. Domain Detail: Access Control & Identity

**Status:** {{ access_control_status }}

**What {{ target_sal }} requires:**
{% if 'SAL 1' in target_sal %}- Unique user accounts (no shared passwords)
- Password policy enforced (12+ characters)
- Leavers process documented{% elif 'SAL 2' in target_sal %}- MFA for all remote access and privileged accounts
- Role-based access control (RBAC)
- Quarterly access reviews
- Privileged Access Management (PAM) for admins{% elif 'SAL 3' in target_sal %}- MFA for all users (no exceptions)
- Just-in-time privileged access
- Automated joiner/mover/leaver workflows
- Conditional access policies (device, location, risk){% elif 'SAL 4' in target_sal %}- Passwordless authentication where feasible
- Continuous authentication / session risk scoring
- Privileged session recording and monitoring
- Cross-domain identity federation with governance{% elif 'SAL 5' in target_sal %}- Zero-trust identity verification (every request)
- Hardware token / smart card mandatory
- Biometric or multi-factor continuous auth
- Segregated identity planes for classified systems{% endif %}

**Evidence / Notes:** {{ access_control_notes }}

---

## 6. Domain Detail: Network Security

**Status:** {{ network_security_status }}

**What {{ target_sal }} requires:**
{% if 'SAL 1' in target_sal %}- Firewall at network perimeter
- Network segmentation (servers vs users)
- Wi-Fi secured with WPA3 or WPA2-Enterprise{% elif 'SAL 2' in target_sal %}- IDS/IPS deployed at key boundaries
- Network traffic logging (NetFlow/sFlow)
- DMZ for internet-facing services
- VPN for remote access{% elif 'SAL 3' in target_sal %}- Full packet capture at critical segments
- Micro-segmentation for sensitive workloads
- DNS filtering and monitoring
- Network access control (NAC / 802.1X){% elif 'SAL 4' in target_sal %}- Network detection and response (NDR)
- Encrypted traffic inspection (TLS interception at boundary)
- Software-defined perimeter / zero-trust networking
- Deception networks (honeypots, honeytokens){% elif 'SAL 5' in target_sal %}- Air-gapped network segments for classified data
- Cross-domain solutions for data transfer
- Quantum-resistant encryption planning
- Full traffic analysis with ML-based anomaly detection{% endif %}

**Evidence / Notes:** {{ network_security_notes }}

---

## 7. Domain Detail: Endpoint Protection

**Status:** {{ endpoint_status }}

**What {{ target_sal }} requires:**
{% if 'SAL 1' in target_sal %}- Anti-malware on all endpoints
- OS and application patching (monthly)
- Host-based firewall enabled{% elif 'SAL 2' in target_sal %}- EDR deployed on all endpoints
- Application whitelisting for servers
- USB/removable media controls
- Full disk encryption{% elif 'SAL 3' in target_sal %}- Advanced EDR with behavioural detection
- Automated threat containment (isolate endpoint)
- Mobile device management (MDM)
- Browser isolation for high-risk browsing{% elif 'SAL 4' in target_sal %}- XDR platform correlating endpoint, network, cloud
- Memory protection / exploit prevention
- Firmware integrity monitoring
- Automated forensic collection on detection{% elif 'SAL 5' in target_sal %}- Hardened operating systems (STIG/CIS Level 2)
- Application sandboxing for all untrusted code
- Hardware-backed attestation
- Air-gapped endpoint management{% endif %}

**Evidence / Notes:** {{ endpoint_notes }}

---

## 8. Domain Detail: Logging & Monitoring

**Status:** {{ logging_status }}

**What {{ target_sal }} requires:**
{% if 'SAL 1' in target_sal %}- Authentication logs retained 90 days
- Firewall logs collected centrally
- Failed login alerting{% elif 'SAL 2' in target_sal %}- Centralised SIEM with correlation rules
- Log sources: auth, endpoint, network, DNS, proxy
- 180-day hot retention, 1-year cold
- Alert triage within 4 hours (business hours){% elif 'SAL 3' in target_sal %}- 24/7 monitoring capability (SOC or MDR)
- Threat hunting programme (weekly cadence)
- UEBA for insider threat detection
- Log integrity controls (immutable storage, checksums)
- 1-year hot, 3-year cold retention{% elif 'SAL 4' in target_sal %}- Real-time correlation with sub-minute alert latency
- SOAR automation for Tier 1 triage
- Full ECS-compliant log schema
- Threat intelligence enrichment on ingest
- 2-year hot, 7-year cold retention{% elif 'SAL 5' in target_sal %}- Continuous monitoring with zero-gap coverage
- AI/ML-driven anomaly detection
- Cross-domain log correlation
- Cryptographic log integrity (tamper-evident)
- 7-year+ retention for all log classes{% endif %}

> **Detailed logging requirements:** See Section 6 of the full CyAB SAL document for event types, schema standards, timeliness, and quality scorecards.

**Evidence / Notes:** {{ logging_notes }}

---

## 9. Domain Detail: Incident Response

**Status:** {{ incident_response_status }}

**What {{ target_sal }} requires:**
{% if 'SAL 1' in target_sal %}- Documented IR plan with contact list
- Annual IR plan review
- Basic incident reporting process{% elif 'SAL 2' in target_sal %}- IR plan aligned to NIST 800-61
- Defined severity levels and escalation matrix
- Annual tabletop exercise
- Post-incident review process{% elif 'SAL 3' in target_sal %}- Dedicated IR team or retainer
- Quarterly exercises (tabletop + technical)
- Playbooks for top 10 incident types
- Digital forensics capability (in-house or retainer)
- Regulatory notification procedures{% elif 'SAL 4' in target_sal %}- 24/7 IR capability with 15-minute response SLA
- Automated containment playbooks (SOAR)
- Threat intelligence-driven IR
- Full forensic lab capability
- Cross-organisational IR coordination{% elif 'SAL 5' in target_sal %}- Military-grade IR with classified incident handling
- Red team / blue team continuous exercises
- Automated evidence preservation chain-of-custody
- International coordination capability
- Real-time regulatory reporting{% endif %}

**Evidence / Notes:** {{ incident_response_notes }}

---

## 10. Domain Detail: Vulnerability Management

**Status:** {{ vuln_mgmt_status }}

**What {{ target_sal }} requires:**
{% if 'SAL 1' in target_sal %}- Regular patching (monthly cycle)
- Annual vulnerability scan
- Critical patches within 14 days{% elif 'SAL 2' in target_sal %}- Monthly authenticated vulnerability scanning
- Risk-rated remediation SLAs (Critical: 7 days, High: 30 days)
- Patch management tooling
- Third-party software tracking{% elif 'SAL 3' in target_sal %}- Continuous vulnerability scanning
- Application security testing (SAST/DAST)
- Bug bounty or coordinated disclosure programme
- Configuration compliance scanning (CIS benchmarks){% elif 'SAL 4' in target_sal %}- Risk-based vulnerability prioritisation (EPSS, CISA KEV)
- Container and infrastructure-as-code scanning
- Red team engagements (annual minimum)
- Vulnerability correlation with threat intelligence{% elif 'SAL 5' in target_sal %}- Zero-day response capability
- Firmware and supply chain vulnerability scanning
- Continuous red/purple team operations
- Automated compensating controls for unpatched systems{% endif %}

**Evidence / Notes:** {{ vuln_mgmt_notes }}

---

## 11. Domain Detail: Data Protection

**Status:** {{ data_protection_status }}

**What {{ target_sal }} requires:**
{% if 'SAL 1' in target_sal %}- Data classification policy (Public, Internal, Confidential)
- Encryption for data in transit (TLS 1.2+)
- Backup and recovery procedures{% elif 'SAL 2' in target_sal %}- Encryption at rest for sensitive data
- DLP for email and web (basic rules)
- Data retention and disposal policy
- Backup testing (quarterly restore tests){% elif 'SAL 3' in target_sal %}- Enterprise DLP with content inspection
- Data discovery and classification tooling
- Rights management / information protection labels
- Cross-border data transfer controls{% elif 'SAL 4' in target_sal %}- Advanced DLP with ML-based detection
- Database activity monitoring
- Tokenisation for high-value data
- Automated data lifecycle management{% elif 'SAL 5' in target_sal %}- Cryptographic data compartmentalisation
- Hardware security modules (HSM) for key management
- Data sovereignty controls with geo-fencing
- Quantum-safe encryption roadmap{% endif %}

**Evidence / Notes:** {{ data_protection_notes }}

---

## 12. Domain Detail: Security Awareness & Training

**Status:** {{ training_status }}

**What {{ target_sal }} requires:**
{% if 'SAL 1' in target_sal %}- Annual security awareness training for all staff
- Acceptable use policy acknowledgement
- Basic phishing awareness{% elif 'SAL 2' in target_sal %}- Role-based training (developers, admins, executives)
- Quarterly phishing simulations
- New starter security induction
- Security champion programme{% elif 'SAL 3' in target_sal %}- Continuous learning platform with tracked completion
- Targeted training based on incident trends
- Social engineering assessments (phone, physical)
- Metrics-driven improvement programme{% elif 'SAL 4' in target_sal %}- Gamified security training with certifications
- Red team social engineering exercises
- Executive crisis simulation training
- Supply chain security training for procurement{% elif 'SAL 5' in target_sal %}- Insider threat awareness programme
- Counter-intelligence awareness for key personnel
- Continuous assessment with adaptive difficulty
- Annual security clearance refresher training{% endif %}

**Evidence / Notes:** {{ training_notes }}

---

## 13. Domain Detail: Business Continuity & DR

**Status:** {{ bcdr_status }}

**What {{ target_sal }} requires:**
{% if 'SAL 1' in target_sal %}- Documented backup procedures
- Offsite backup storage
- Key contact list for emergencies{% elif 'SAL 2' in target_sal %}- Business impact analysis (BIA) completed
- RTO/RPO defined for critical systems
- Annual DR test
- Cyber-specific BC plan{% elif 'SAL 3' in target_sal %}- Automated failover for critical systems
- Bi-annual DR testing (including cyber scenarios)
- Alternate operating site capability
- Communication plan for major incidents{% elif 'SAL 4' in target_sal %}- Real-time replication for tier-1 systems
- Multi-region / multi-site resilience
- Quarterly DR exercises with measured recovery times
- Ransomware-specific recovery playbook{% elif 'SAL 5' in target_sal %}- Zero-downtime architecture for classified systems
- Independent backup verification and integrity checking
- Cross-organisational resilience coordination
- Full supply chain continuity planning{% endif %}

**Evidence / Notes:** {{ bcdr_notes }}

---

## 14. Domain Detail: Third-Party & Supply Chain

**Status:** {{ third_party_status }}

**What {{ target_sal }} requires:**
{% if 'SAL 1' in target_sal %}- Vendor list maintained
- Standard contractual security clauses
- NDA for data-handling vendors{% elif 'SAL 2' in target_sal %}- Vendor risk assessment (annual questionnaire)
- Security requirements in procurement
- Right-to-audit clauses
- SLA monitoring for key suppliers{% elif 'SAL 3' in target_sal %}- Tiered vendor risk management programme
- Continuous monitoring of critical suppliers
- Supply chain incident notification requirements
- Fourth-party risk visibility{% elif 'SAL 4' in target_sal %}- Real-time supply chain risk scoring
- SBOM (Software Bill of Materials) requirements
- Vendor security certification requirements (SOC 2, ISO 27001)
- Automated vendor risk assessment platform{% elif 'SAL 5' in target_sal %}- Cryptographic supply chain verification
- Trusted supplier programme with enhanced vetting
- Hardware provenance and anti-tamper controls
- Sovereign supply chain requirements{% endif %}

**Evidence / Notes:** {{ third_party_notes }}

---

## 15. Domain Detail: Physical Security

**Status:** {{ physical_status }}

**What {{ target_sal }} requires:**
{% if 'SAL 1' in target_sal %}- Locked server rooms / network cabinets
- Visitor sign-in procedures
- Clean desk policy{% elif 'SAL 2' in target_sal %}- Access card / badge systems for sensitive areas
- CCTV at entry points and server rooms
- Environmental controls (fire, flood, UPS)
- Asset disposal procedures (WEEE compliant){% elif 'SAL 3' in target_sal %}- Zoned physical security with tiered access
- 24/7 security monitoring (manned or remote)
- Intrusion detection systems
- Secure media destruction (on-site shredding){% elif 'SAL 4' in target_sal %}- Biometric access for high-security zones
- Man-trap / airlock entry for data centres
- Environmental monitoring with automated alerts
- Anti-surveillance measures{% elif 'SAL 5' in target_sal %}- TEMPEST/EMSEC controls for classified areas
- Faraday-shielded rooms
- Armed security for highest-classification areas
- Full CCTV coverage with AI-assisted monitoring{% endif %}

**Evidence / Notes:** {{ physical_notes }}

---

## 16. Domain Detail: Compliance & Audit

**Status:** {{ compliance_status }}

**What {{ target_sal }} requires:**
{% if 'SAL 1' in target_sal %}- Awareness of applicable regulations
- Basic compliance checklist
- Annual self-assessment{% elif 'SAL 2' in target_sal %}- Compliance register mapped to controls
- External audit (annual)
- Remediation tracking for audit findings
- Regulatory reporting procedures{% elif 'SAL 3' in target_sal %}- Integrated compliance framework (multiple standards)
- Continuous control monitoring
- Internal audit programme
- Automated evidence collection{% elif 'SAL 4' in target_sal %}- GRC platform with real-time compliance dashboards
- Pre-audit readiness assessments
- Regulatory change management
- Cross-framework control mapping{% elif 'SAL 5' in target_sal %}- Continuous assurance with automated attestation
- Independent compliance verification
- International regulatory coordination
- Classified systems compliance (national frameworks){% endif %}

**Evidence / Notes:** {{ compliance_notes }}

---

## 17. Findings & Recommendations

### Key Findings

{{ key_findings }}

### Priority Recommendations

{{ priority_recommendations }}

---

## 18. Document Control

| Version | Date | Assessor | Changes |
|---------|------|----------|---------|
| {{ version }} | {{ assessment_date }} | {{ author }} | Initial assessment |
""",
    },
    # =========================================================================
    # SOC Data Service Level Agreement
    # =========================================================================
    {
        "name": "SOC Data Service Level Agreement",
        "document_type": "SLA",
        "collection": "Operational Agreements",
        "description": "Agreement between SOC and data-providing teams defining log source uptime, data quality standards, use case coverage, known gaps, and response commitments.",
        "tags": ["SOC-CMM", "NIST-CSF-2.0"],
        "variables": [
            # --- Agreement metadata ---
            {"name": "doc_id", "var_type": "string", "required": True, "default_value": "SLA-SOC-001", "description": "Document identifier"},
            {"name": "version", "var_type": "string", "required": True, "default_value": "1.0", "description": "Document version"},
            {"name": "classification", "var_type": "string", "required": False, "default_value": "INTERNAL", "description": "Classification level"},
            {"name": "effective_date", "var_type": "string", "required": True, "default_value": "", "description": "Agreement effective date"},
            {"name": "review_date", "var_type": "string", "required": True, "default_value": "", "description": "Next review date"},
            {"name": "review_cycle", "var_type": "string", "required": True, "default_value": "Quarterly", "description": "Review frequency"},
            # --- Parties ---
            {"name": "soc_team_name", "var_type": "string", "required": True, "default_value": "Security Operations Center", "description": "SOC team name"},
            {"name": "soc_lead", "var_type": "string", "required": True, "default_value": "", "description": "SOC lead / manager"},
            {"name": "data_provider_team", "var_type": "string", "required": True, "default_value": "", "description": "Data provider team (IT Ops, Infrastructure, etc.)"},
            {"name": "data_provider_lead", "var_type": "string", "required": True, "default_value": "", "description": "Data provider lead / manager"},
            {"name": "approved_by", "var_type": "string", "required": False, "default_value": "", "description": "Approved by (CISO / Head of Security)"},
            # --- SOC operating hours ---
            {"name": "soc_operating_hours", "var_type": "string", "required": True, "default_value": "Mon-Fri 08:00-18:00", "description": "SOC operating hours",
             "options": ["Mon-Fri 08:00-18:00", "Mon-Fri 07:00-19:00", "Mon-Sat 08:00-18:00", "24/5 (Mon-Fri)", "24/7", "24/7/365"]},
            {"name": "soc_tier", "var_type": "string", "required": True, "default_value": "Tier 1 + Tier 2 (business hours)", "description": "SOC capability tier",
             "options": ["Tier 1 only (business hours)", "Tier 1 + Tier 2 (business hours)", "Tier 1 + Tier 2 (extended hours)", "Tier 1 + Tier 2 + Tier 3 (24/7)", "Full SOC (24/7 with threat hunting)"]},
            # --- Data source 1 ---
            {"name": "ds1_name", "var_type": "string", "required": True, "default_value": "", "description": "Data source 1 name (e.g. Windows Event Logs)"},
            {"name": "ds1_type", "var_type": "string", "required": True, "default_value": "Endpoint", "description": "Data source 1 type",
             "options": ["Endpoint", "Network", "Identity / Auth", "Cloud", "Email / Web Proxy", "DNS", "Firewall / IDS", "Application", "Database", "Physical / IoT"]},
            {"name": "ds1_uptime", "var_type": "string", "required": True, "default_value": "99.5%", "description": "Data source 1 uptime target",
             "options": ["99.99% (< 53 min/year downtime)", "99.9% (< 8.7 hrs/year)", "99.5% (< 1.8 days/year)", "99% (< 3.65 days/year)", "95% (< 18.25 days/year)", "Best Effort"]},
            {"name": "ds1_latency", "var_type": "string", "required": True, "default_value": "< 5 minutes", "description": "Data source 1 max ingest latency",
             "options": ["< 1 minute (real-time)", "< 5 minutes", "< 15 minutes", "< 1 hour", "< 4 hours", "< 24 hours (batch)"]},
            {"name": "ds1_format", "var_type": "string", "required": True, "default_value": "ECS-compliant", "description": "Data source 1 schema standard",
             "options": ["ECS-compliant", "CEF", "LEEF", "Syslog (RFC 5424)", "JSON (custom)", "Raw / unstructured", "Windows Event XML", "CSV / delimited"]},
            {"name": "ds1_retention", "var_type": "string", "required": True, "default_value": "180 days hot / 1 year cold", "description": "Data source 1 retention",
             "options": ["30 days hot", "90 days hot / 1 year cold", "180 days hot / 1 year cold", "1 year hot / 3 years cold", "1 year hot / 7 years cold", "As per retention policy"]},
            # --- Data source 2 ---
            {"name": "ds2_name", "var_type": "string", "required": False, "default_value": "", "description": "Data source 2 name"},
            {"name": "ds2_type", "var_type": "string", "required": False, "default_value": "Network", "description": "Data source 2 type",
             "options": ["Endpoint", "Network", "Identity / Auth", "Cloud", "Email / Web Proxy", "DNS", "Firewall / IDS", "Application", "Database", "Physical / IoT"]},
            {"name": "ds2_uptime", "var_type": "string", "required": False, "default_value": "99.5%", "description": "Data source 2 uptime target",
             "options": ["99.99% (< 53 min/year downtime)", "99.9% (< 8.7 hrs/year)", "99.5% (< 1.8 days/year)", "99% (< 3.65 days/year)", "95% (< 18.25 days/year)", "Best Effort"]},
            {"name": "ds2_latency", "var_type": "string", "required": False, "default_value": "< 5 minutes", "description": "Data source 2 max ingest latency",
             "options": ["< 1 minute (real-time)", "< 5 minutes", "< 15 minutes", "< 1 hour", "< 4 hours", "< 24 hours (batch)"]},
            {"name": "ds2_format", "var_type": "string", "required": False, "default_value": "ECS-compliant", "description": "Data source 2 schema standard",
             "options": ["ECS-compliant", "CEF", "LEEF", "Syslog (RFC 5424)", "JSON (custom)", "Raw / unstructured", "Windows Event XML", "CSV / delimited"]},
            {"name": "ds2_retention", "var_type": "string", "required": False, "default_value": "180 days hot / 1 year cold", "description": "Data source 2 retention",
             "options": ["30 days hot", "90 days hot / 1 year cold", "180 days hot / 1 year cold", "1 year hot / 3 years cold", "1 year hot / 7 years cold", "As per retention policy"]},
            # --- Data source 3 ---
            {"name": "ds3_name", "var_type": "string", "required": False, "default_value": "", "description": "Data source 3 name"},
            {"name": "ds3_type", "var_type": "string", "required": False, "default_value": "Identity / Auth", "description": "Data source 3 type",
             "options": ["Endpoint", "Network", "Identity / Auth", "Cloud", "Email / Web Proxy", "DNS", "Firewall / IDS", "Application", "Database", "Physical / IoT"]},
            {"name": "ds3_uptime", "var_type": "string", "required": False, "default_value": "99.5%", "description": "Data source 3 uptime target",
             "options": ["99.99% (< 53 min/year downtime)", "99.9% (< 8.7 hrs/year)", "99.5% (< 1.8 days/year)", "99% (< 3.65 days/year)", "95% (< 18.25 days/year)", "Best Effort"]},
            {"name": "ds3_latency", "var_type": "string", "required": False, "default_value": "< 5 minutes", "description": "Data source 3 max ingest latency",
             "options": ["< 1 minute (real-time)", "< 5 minutes", "< 15 minutes", "< 1 hour", "< 4 hours", "< 24 hours (batch)"]},
            {"name": "ds3_format", "var_type": "string", "required": False, "default_value": "ECS-compliant", "description": "Data source 3 schema standard",
             "options": ["ECS-compliant", "CEF", "LEEF", "Syslog (RFC 5424)", "JSON (custom)", "Raw / unstructured", "Windows Event XML", "CSV / delimited"]},
            {"name": "ds3_retention", "var_type": "string", "required": False, "default_value": "180 days hot / 1 year cold", "description": "Data source 3 retention",
             "options": ["30 days hot", "90 days hot / 1 year cold", "180 days hot / 1 year cold", "1 year hot / 3 years cold", "1 year hot / 7 years cold", "As per retention policy"]},
            # --- Data source 4 ---
            {"name": "ds4_name", "var_type": "string", "required": False, "default_value": "", "description": "Data source 4 name"},
            {"name": "ds4_type", "var_type": "string", "required": False, "default_value": "Firewall / IDS", "description": "Data source 4 type",
             "options": ["Endpoint", "Network", "Identity / Auth", "Cloud", "Email / Web Proxy", "DNS", "Firewall / IDS", "Application", "Database", "Physical / IoT"]},
            {"name": "ds4_uptime", "var_type": "string", "required": False, "default_value": "99.5%", "description": "Data source 4 uptime target",
             "options": ["99.99% (< 53 min/year downtime)", "99.9% (< 8.7 hrs/year)", "99.5% (< 1.8 days/year)", "99% (< 3.65 days/year)", "95% (< 18.25 days/year)", "Best Effort"]},
            {"name": "ds4_latency", "var_type": "string", "required": False, "default_value": "< 5 minutes", "description": "Data source 4 max ingest latency",
             "options": ["< 1 minute (real-time)", "< 5 minutes", "< 15 minutes", "< 1 hour", "< 4 hours", "< 24 hours (batch)"]},
            {"name": "ds4_format", "var_type": "string", "required": False, "default_value": "ECS-compliant", "description": "Data source 4 schema standard",
             "options": ["ECS-compliant", "CEF", "LEEF", "Syslog (RFC 5424)", "JSON (custom)", "Raw / unstructured", "Windows Event XML", "CSV / delimited"]},
            {"name": "ds4_retention", "var_type": "string", "required": False, "default_value": "180 days hot / 1 year cold", "description": "Data source 4 retention",
             "options": ["30 days hot", "90 days hot / 1 year cold", "180 days hot / 1 year cold", "1 year hot / 3 years cold", "1 year hot / 7 years cold", "As per retention policy"]},
            # --- Data source 5 ---
            {"name": "ds5_name", "var_type": "string", "required": False, "default_value": "", "description": "Data source 5 name"},
            {"name": "ds5_type", "var_type": "string", "required": False, "default_value": "DNS", "description": "Data source 5 type",
             "options": ["Endpoint", "Network", "Identity / Auth", "Cloud", "Email / Web Proxy", "DNS", "Firewall / IDS", "Application", "Database", "Physical / IoT"]},
            {"name": "ds5_uptime", "var_type": "string", "required": False, "default_value": "99%", "description": "Data source 5 uptime target",
             "options": ["99.99% (< 53 min/year downtime)", "99.9% (< 8.7 hrs/year)", "99.5% (< 1.8 days/year)", "99% (< 3.65 days/year)", "95% (< 18.25 days/year)", "Best Effort"]},
            {"name": "ds5_latency", "var_type": "string", "required": False, "default_value": "< 15 minutes", "description": "Data source 5 max ingest latency",
             "options": ["< 1 minute (real-time)", "< 5 minutes", "< 15 minutes", "< 1 hour", "< 4 hours", "< 24 hours (batch)"]},
            {"name": "ds5_format", "var_type": "string", "required": False, "default_value": "ECS-compliant", "description": "Data source 5 schema standard",
             "options": ["ECS-compliant", "CEF", "LEEF", "Syslog (RFC 5424)", "JSON (custom)", "Raw / unstructured", "Windows Event XML", "CSV / delimited"]},
            {"name": "ds5_retention", "var_type": "string", "required": False, "default_value": "90 days hot / 1 year cold", "description": "Data source 5 retention",
             "options": ["30 days hot", "90 days hot / 1 year cold", "180 days hot / 1 year cold", "1 year hot / 3 years cold", "1 year hot / 7 years cold", "As per retention policy"]},
            # --- Use case coverage ---
            {"name": "uc1_name", "var_type": "string", "required": False, "default_value": "", "description": "Use case 1 (e.g. Brute force detection)"},
            {"name": "uc1_status", "var_type": "string", "required": False, "default_value": "Covered", "description": "Use case 1 coverage status",
             "options": ["Covered", "Partial — rule exists, data gaps", "Partial — data exists, rule needed", "Known Gap", "Planned", "Out of Scope"]},
            {"name": "uc1_data_sources", "var_type": "string", "required": False, "default_value": "", "description": "Use case 1 required data sources"},
            {"name": "uc2_name", "var_type": "string", "required": False, "default_value": "", "description": "Use case 2"},
            {"name": "uc2_status", "var_type": "string", "required": False, "default_value": "Covered", "description": "Use case 2 coverage status",
             "options": ["Covered", "Partial — rule exists, data gaps", "Partial — data exists, rule needed", "Known Gap", "Planned", "Out of Scope"]},
            {"name": "uc2_data_sources", "var_type": "string", "required": False, "default_value": "", "description": "Use case 2 required data sources"},
            {"name": "uc3_name", "var_type": "string", "required": False, "default_value": "", "description": "Use case 3"},
            {"name": "uc3_status", "var_type": "string", "required": False, "default_value": "Covered", "description": "Use case 3 coverage status",
             "options": ["Covered", "Partial — rule exists, data gaps", "Partial — data exists, rule needed", "Known Gap", "Planned", "Out of Scope"]},
            {"name": "uc3_data_sources", "var_type": "string", "required": False, "default_value": "", "description": "Use case 3 required data sources"},
            {"name": "uc4_name", "var_type": "string", "required": False, "default_value": "", "description": "Use case 4"},
            {"name": "uc4_status", "var_type": "string", "required": False, "default_value": "Covered", "description": "Use case 4 coverage status",
             "options": ["Covered", "Partial — rule exists, data gaps", "Partial — data exists, rule needed", "Known Gap", "Planned", "Out of Scope"]},
            {"name": "uc4_data_sources", "var_type": "string", "required": False, "default_value": "", "description": "Use case 4 required data sources"},
            {"name": "uc5_name", "var_type": "string", "required": False, "default_value": "", "description": "Use case 5"},
            {"name": "uc5_status", "var_type": "string", "required": False, "default_value": "Covered", "description": "Use case 5 coverage status",
             "options": ["Covered", "Partial — rule exists, data gaps", "Partial — data exists, rule needed", "Known Gap", "Planned", "Out of Scope"]},
            {"name": "uc5_data_sources", "var_type": "string", "required": False, "default_value": "", "description": "Use case 5 required data sources"},
            {"name": "uc6_name", "var_type": "string", "required": False, "default_value": "", "description": "Use case 6"},
            {"name": "uc6_status", "var_type": "string", "required": False, "default_value": "Covered", "description": "Use case 6 coverage status",
             "options": ["Covered", "Partial — rule exists, data gaps", "Partial — data exists, rule needed", "Known Gap", "Planned", "Out of Scope"]},
            {"name": "uc6_data_sources", "var_type": "string", "required": False, "default_value": "", "description": "Use case 6 required data sources"},
            {"name": "uc7_name", "var_type": "string", "required": False, "default_value": "", "description": "Use case 7"},
            {"name": "uc7_status", "var_type": "string", "required": False, "default_value": "Covered", "description": "Use case 7 coverage status",
             "options": ["Covered", "Partial — rule exists, data gaps", "Partial — data exists, rule needed", "Known Gap", "Planned", "Out of Scope"]},
            {"name": "uc7_data_sources", "var_type": "string", "required": False, "default_value": "", "description": "Use case 7 required data sources"},
            {"name": "uc8_name", "var_type": "string", "required": False, "default_value": "", "description": "Use case 8"},
            {"name": "uc8_status", "var_type": "string", "required": False, "default_value": "Covered", "description": "Use case 8 coverage status",
             "options": ["Covered", "Partial — rule exists, data gaps", "Partial — data exists, rule needed", "Known Gap", "Planned", "Out of Scope"]},
            {"name": "uc8_data_sources", "var_type": "string", "required": False, "default_value": "", "description": "Use case 8 required data sources"},
            {"name": "uc9_name", "var_type": "string", "required": False, "default_value": "", "description": "Use case 9"},
            {"name": "uc9_status", "var_type": "string", "required": False, "default_value": "Covered", "description": "Use case 9 coverage status",
             "options": ["Covered", "Partial — rule exists, data gaps", "Partial — data exists, rule needed", "Known Gap", "Planned", "Out of Scope"]},
            {"name": "uc9_data_sources", "var_type": "string", "required": False, "default_value": "", "description": "Use case 9 required data sources"},
            {"name": "uc10_name", "var_type": "string", "required": False, "default_value": "", "description": "Use case 10"},
            {"name": "uc10_status", "var_type": "string", "required": False, "default_value": "Covered", "description": "Use case 10 coverage status",
             "options": ["Covered", "Partial — rule exists, data gaps", "Partial — data exists, rule needed", "Known Gap", "Planned", "Out of Scope"]},
            {"name": "uc10_data_sources", "var_type": "string", "required": False, "default_value": "", "description": "Use case 10 required data sources"},
            # --- SOC response commitments ---
            {"name": "p1_response", "var_type": "string", "required": True, "default_value": "15 minutes", "description": "P1 (Critical) initial response time",
             "options": ["5 minutes", "15 minutes", "30 minutes", "1 hour", "2 hours", "4 hours"]},
            {"name": "p2_response", "var_type": "string", "required": True, "default_value": "1 hour", "description": "P2 (High) initial response time",
             "options": ["15 minutes", "30 minutes", "1 hour", "2 hours", "4 hours", "8 hours"]},
            {"name": "p3_response", "var_type": "string", "required": True, "default_value": "4 hours", "description": "P3 (Medium) initial response time",
             "options": ["1 hour", "2 hours", "4 hours", "8 hours", "Next business day"]},
            {"name": "p4_response", "var_type": "string", "required": True, "default_value": "Next business day", "description": "P4 (Low) initial response time",
             "options": ["4 hours", "8 hours", "Next business day", "48 hours", "5 business days"]},
            # --- Known gaps & notes ---
            {"name": "known_gaps", "var_type": "string", "required": False, "default_value": "", "description": "Known gaps summary (data sources missing, rules pending, etc.)"},
            {"name": "gap_remediation_plan", "var_type": "string", "required": False, "default_value": "", "description": "Gap remediation plan and timelines"},
            {"name": "data_quality_notes", "var_type": "string", "required": False, "default_value": "", "description": "Data quality issues, parsing problems, field mapping gaps"},
            {"name": "escalation_process", "var_type": "string", "required": False, "default_value": "", "description": "Escalation process when SLA is breached"},
            {"name": "additional_notes", "var_type": "string", "required": False, "default_value": "", "description": "Additional terms or notes"},
        ],
        "content": """# {{ doc_id }} — SOC Data Service Level Agreement

| Field | Value |
|-------|-------|
| **Document ID** | {{ doc_id }} |
| **Version** | {{ version }} |
| **Classification** | {{ classification }} |
| **Effective Date** | {{ effective_date }} |
| **Next Review** | {{ review_date }} |
| **Review Cycle** | {{ review_cycle }} |
| **Approved By** | {{ approved_by }} |

---

## 1. Parties to This Agreement

| Role | Team | Lead |
|------|------|------|
| **Service Provider (SOC)** | {{ soc_team_name }} | {{ soc_lead }} |
| **Data Provider** | {{ data_provider_team }} | {{ data_provider_lead }} |

---

## 2. Purpose & Scope

This agreement defines the commitments between the **{{ soc_team_name }}** and **{{ data_provider_team }}** regarding:

- **Data Provider commits to:** Delivering agreed log sources at defined uptime, latency, and quality standards
- **SOC commits to:** Monitoring those sources, maintaining detection rules aligned to agreed use cases, triaging alerts within response SLAs, and transparently reporting known coverage gaps

**SOC Operating Model:**

| Parameter | Commitment |
|-----------|-----------|
| Operating Hours | {{ soc_operating_hours }} |
| Capability Tier | {{ soc_tier }} |

---

## 3. Data Source Commitments

The following data sources are covered under this agreement. The Data Provider is responsible for ensuring each source meets its uptime and latency target. The SOC will alert the Data Provider if a source stops delivering or degrades below the agreed standard.

| # | Data Source | Type | Uptime Target | Max Latency | Schema | Retention |
|---|-----------|------|---------------|-------------|--------|-----------|
{% if ds1_name %}| 1 | {{ ds1_name }} | {{ ds1_type }} | {{ ds1_uptime }} | {{ ds1_latency }} | {{ ds1_format }} | {{ ds1_retention }} |
{% endif %}{% if ds2_name %}| 2 | {{ ds2_name }} | {{ ds2_type }} | {{ ds2_uptime }} | {{ ds2_latency }} | {{ ds2_format }} | {{ ds2_retention }} |
{% endif %}{% if ds3_name %}| 3 | {{ ds3_name }} | {{ ds3_type }} | {{ ds3_uptime }} | {{ ds3_latency }} | {{ ds3_format }} | {{ ds3_retention }} |
{% endif %}{% if ds4_name %}| 4 | {{ ds4_name }} | {{ ds4_type }} | {{ ds4_uptime }} | {{ ds4_latency }} | {{ ds4_format }} | {{ ds4_retention }} |
{% endif %}{% if ds5_name %}| 5 | {{ ds5_name }} | {{ ds5_type }} | {{ ds5_uptime }} | {{ ds5_latency }} | {{ ds5_format }} | {{ ds5_retention }} |
{% endif %}

### 3.1 Data Provider Obligations

- Maintain each data source at or above its agreed uptime target
- Notify SOC **within 1 hour** of any planned maintenance affecting log delivery
- Notify SOC **immediately** of any unplanned outage affecting log delivery
- Ensure log schema does not change without **5 business days** prior notice to SOC
- Provide access credentials / API keys needed for SOC to ingest data

### 3.2 SOC Obligations for Data Sources

- Monitor data source health (heartbeat / last-seen checks)
- Raise a ticket to Data Provider within **{{ p3_response }}** if a source goes silent
- Maintain parsers and ingest pipelines for each agreed source
- Report monthly on data source uptime and quality metrics

---

## 4. Use Case Coverage

The SOC maintains detection rules aligned to the following use cases. Coverage status reflects whether the SOC has working rules **and** the data needed to support them.

| # | Use Case | Status | Required Data Sources |
|---|---------|--------|----------------------|
{% if uc1_name %}| 1 | {{ uc1_name }} | {{ uc1_status }} | {{ uc1_data_sources }} |
{% endif %}{% if uc2_name %}| 2 | {{ uc2_name }} | {{ uc2_status }} | {{ uc2_data_sources }} |
{% endif %}{% if uc3_name %}| 3 | {{ uc3_name }} | {{ uc3_status }} | {{ uc3_data_sources }} |
{% endif %}{% if uc4_name %}| 4 | {{ uc4_name }} | {{ uc4_status }} | {{ uc4_data_sources }} |
{% endif %}{% if uc5_name %}| 5 | {{ uc5_name }} | {{ uc5_status }} | {{ uc5_data_sources }} |
{% endif %}{% if uc6_name %}| 6 | {{ uc6_name }} | {{ uc6_status }} | {{ uc6_data_sources }} |
{% endif %}{% if uc7_name %}| 7 | {{ uc7_name }} | {{ uc7_status }} | {{ uc7_data_sources }} |
{% endif %}{% if uc8_name %}| 8 | {{ uc8_name }} | {{ uc8_status }} | {{ uc8_data_sources }} |
{% endif %}{% if uc9_name %}| 9 | {{ uc9_name }} | {{ uc9_status }} | {{ uc9_data_sources }} |
{% endif %}{% if uc10_name %}| 10 | {{ uc10_name }} | {{ uc10_status }} | {{ uc10_data_sources }} |
{% endif %}

### Coverage Status Key

| Status | Meaning |
|--------|---------|
| **Covered** | Detection rule active, data flowing, tested and validated |
| **Partial — rule exists, data gaps** | Rule is written but required data source is missing or incomplete |
| **Partial — data exists, rule needed** | Data is available but SOC has not yet built the detection rule |
| **Known Gap** | Both data and rule are missing — documented and accepted risk |
| **Planned** | Scheduled for implementation in the next review period |
| **Out of Scope** | Not covered under this agreement |

---

## 5. SOC Response Commitments

When a detection rule fires, the SOC commits to the following initial response times (acknowledgement + initial triage):

| Priority | Description | Initial Response | Applies During |
|----------|------------|------------------|----------------|
| **P1 — Critical** | Active compromise, data exfiltration, ransomware | {{ p1_response }} | {{ soc_operating_hours }} |
| **P2 — High** | Confirmed malicious activity, privilege escalation | {{ p2_response }} | {{ soc_operating_hours }} |
| **P3 — Medium** | Suspicious activity, policy violation, anomaly | {{ p3_response }} | {{ soc_operating_hours }} |
| **P4 — Low** | Informational, tuning candidate, false positive review | {{ p4_response }} | {{ soc_operating_hours }} |

**Outside operating hours:** P1 alerts are escalated to the on-call analyst (if applicable). P2-P4 are triaged at the start of the next operating window.

---

## 6. Known Gaps

The following gaps are documented and accepted by both parties at the time of this agreement:

{{ known_gaps }}

### Remediation Plan

{{ gap_remediation_plan }}

---

## 7. Data Quality Standards

### Minimum Requirements

All data sources covered by this agreement must meet:

- **Timestamps:** UTC normalised, accurate to within 1 second of event time
- **Source identification:** Every event must include a source host/IP and data stream identifier
- **Schema consistency:** Field names and types must not change without prior notice
- **Completeness:** No silent drops — if an agent/forwarder fails, the Data Provider must have monitoring to detect it

### Known Quality Issues

{{ data_quality_notes }}

---

## 8. SLA Breach & Escalation

### What constitutes a breach

- Data source uptime falls below agreed target for a calendar month
- Ingest latency exceeds agreed maximum for more than 4 consecutive hours
- Schema change deployed without prior notice causing parser failures
- SOC response time exceeded for more than 10% of alerts in a calendar month

### Escalation Process

{{ escalation_process }}

### Default Escalation Path

1. **Operational lead** of the breaching party notified within 24 hours
2. **Joint review call** within 3 business days to agree remediation
3. If unresolved within 2 review cycles, escalate to **{{ approved_by }}** (or CISO)

---

## 9. Reporting & Review

| Activity | Frequency | Owner |
|----------|-----------|-------|
| Data source health report | Weekly | SOC |
| Use case coverage review | {{ review_cycle }} | SOC + Data Provider |
| SLA compliance report | Monthly | SOC |
| Gap remediation progress | {{ review_cycle }} | Data Provider |
| Full agreement review | {{ review_cycle }} | Both parties |

---

## 10. Additional Terms

{{ additional_notes }}

---

## 11. Signatures

| Role | Name | Signature | Date |
|------|------|-----------|------|
| SOC Lead | {{ soc_lead }} | | {{ effective_date }} |
| Data Provider Lead | {{ data_provider_lead }} | | {{ effective_date }} |
| Approved By | {{ approved_by }} | | {{ effective_date }} |

---

## 12. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {{ version }} | {{ effective_date }} | {{ soc_lead }} | Initial agreement |
""",
    },
]


# =============================================================================
# Seeding function
# =============================================================================

def seed_soc_templates() -> None:
    """Seed SOC documentation templates, collections, and framework tags.

    Idempotent - checks by name before creating.
    """
    from ion.storage.database import get_engine, get_session_factory
    from ion.storage.template_repository import TemplateRepository
    from ion.storage.version_repository import VersionRepository
    from ion.storage.collection_repository import CollectionRepository
    from ion.models.template import Collection

    engine = get_engine()
    factory = get_session_factory(engine)
    session = factory()

    try:
        template_repo = TemplateRepository(session)
        version_repo = VersionRepository(session)
        collection_repo = CollectionRepository(session)

        # --- Create collections (idempotent by name) ---
        collection_map: dict[str, int] = {}
        for cdef in COLLECTION_DEFS:
            existing = collection_repo.get_by_name(cdef["name"])
            if existing:
                collection_map[cdef["name"]] = existing.id
            else:
                col = collection_repo.create(
                    name=cdef["name"],
                    description=cdef["description"],
                    icon=cdef.get("icon"),
                )
                session.flush()
                collection_map[cdef["name"]] = col.id
                logger.info("Created SOC collection: %s", cdef["name"])

        # --- Create templates (idempotent by name) ---
        created_count = 0
        for tdef in TEMPLATE_DEFS:
            existing = template_repo.get_by_name(tdef["name"])
            if existing:
                continue

            # Create the template
            template = template_repo.create(
                name=tdef["name"],
                content=tdef["content"],
                format="markdown",
                description=tdef["description"],
            )

            # Set document type
            template.document_type = tdef["document_type"]

            # Assign to collection
            col_name = tdef.get("collection")
            if col_name and col_name in collection_map:
                template.collection_id = collection_map[col_name]

            session.flush()

            # Add framework tags
            for tag_name in tdef.get("tags", []):
                template_repo.add_tag(template, tag_name)

            # Create initial version
            version_repo.create(
                template_id=template.id,
                version_number=1,
                content=tdef["content"],
                message="Initial SOC template version",
                author="ION System",
            )

            # Register variables
            for var_def in tdef.get("variables", []):
                import json as _json
                opts = var_def.get("options")
                opts_json = _json.dumps(opts) if opts else None
                template_repo.add_variable(
                    template=template,
                    name=var_def["name"],
                    var_type=var_def.get("var_type", "string"),
                    required=var_def.get("required", True),
                    default_value=var_def.get("default_value"),
                    description=var_def.get("description"),
                    options=opts_json,
                )

            created_count += 1
            logger.info("Created SOC template: %s (%s)", tdef["name"], tdef["document_type"])

        session.commit()

        if created_count > 0:
            logger.info("Seeded %d SOC templates across %d collections", created_count, len(COLLECTION_DEFS))
        else:
            logger.debug("SOC templates already seeded, no changes needed")

    except Exception as e:
        session.rollback()
        logger.error("Failed to seed SOC templates: %s", e)
        raise
    finally:
        session.close()
