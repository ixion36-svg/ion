# SOC Documentation Templates & Framework Alignment

> **Version:** 0.9.43
> **Date:** 2026-04-07
> **Module:** `ion.services.soc_template_service`

---

## Overview

ION ships with **19 pre-built SOC documentation templates** covering all major operational document types used in Security Operations Centers. Templates are Jinja2-based, fully renderable with custom variables, and tagged with industry compliance frameworks.

All templates are **auto-seeded on first startup** (idempotent) and organized into **9 collections** by document type.

---

## Document Types

Each template is assigned a `document_type` that categorizes it for filtering and display.

| Code | Full Name | Color | Use Case |
|------|-----------|-------|----------|
| `SOP` | Standard Operating Procedure | Blue | Formalized operational procedures |
| `SOI` | Standard Operating Instruction | Teal | Tactical task-specific instructions |
| `WI` | Work Instruction | Indigo | Granular step-by-step task guidance |
| `KB` | Knowledge Base | Green | Self-service reference documentation |
| `RUNBOOK` | Runbook | Purple | Operational procedure guides |
| `IRP` | Incident Response Plan | Red | Strategic incident handling plans |
| `AAR` | After-Action Report | Orange | Post-incident retrospective analysis |
| `THREAT_ADVISORY` | Threat Advisory | Yellow | Threat advisories and actor profiles |
| `DETECTION_RULE` | Detection Rule Documentation | Cyan | Detection rule documentation |

---

## Collections

Templates are organized into 9 collections (folders):

| Collection | Templates | Description |
|-----------|-----------|-------------|
| Standard Operating Procedures | 4 | Formalized operational procedures for SOC activities |
| Standard Operating Instructions | 3 | Tactical task-specific instructions |
| Work Instructions | 3 | Granular step-by-step task guidance |
| Knowledge Base | 3 | Self-service reference documentation |
| Runbooks | 1 | Operational procedure guides for routine tasks |
| Incident Response Plans | 2 | Strategic incident handling plans |
| After-Action Reports | 1 | Post-incident retrospective analysis |
| Threat Intelligence | 1 | Threat advisories and actor profiles |
| Detection Engineering | 1 | Detection rule documentation |

---

## Template Inventory

### Standard Operating Procedures (SOP)

#### 1. SOC Monitoring & Triage SOP
- **Tags:** NIST-CSF-2.0, SOC-CMM
- **Purpose:** Defines processes for continuous security monitoring, alert triage, and initial incident response
- **Sections:** Purpose, Scope, Roles & Responsibilities, Monitoring Procedures, Severity Classification, Initial Triage Steps, Escalation Criteria, Metrics & KPIs, Shift Schedule
- **Key Variables:** `doc_id`, `version`, `classification`, `author`, `department`, `siem_tool`, `escalation_contacts`, `shift_schedule`

#### 2. Incident Escalation SOP
- **Tags:** NIST-800-61, SANS-IR
- **Purpose:** Defines escalation procedures including severity classification, notification requirements, and communication protocols
- **Sections:** Purpose, Scope, Severity Levels, Escalation Matrix, Notification Procedures, Communication Templates, Timeline Requirements, De-escalation Criteria
- **Key Variables:** `doc_id`, `version`, `author`, `escalation_matrix`, `notification_templates`, `severity_definitions`

#### 3. Evidence Handling & Chain of Custody SOP
- **Tags:** ISO-27035, NIST-800-61
- **Purpose:** Establishes procedures for digital evidence collection, handling, storage, and transfer
- **Sections:** Purpose, Scope, Evidence Types, Collection Procedures, Chain of Custody Form, Storage Requirements, Transfer Procedures, Retention Policy
- **Key Variables:** `doc_id`, `version`, `author`, `evidence_storage_location`, `forensic_tools`, `legal_contact`

#### 4. Shift Handover SOP
- **Tags:** SOC-CMM
- **Purpose:** Ensures consistent and complete shift handovers between SOC analyst teams
- **Sections:** Purpose, Scope, Handover Procedure, Checklist, Open Investigations, Pending Actions, Environment Status
- **Key Variables:** `doc_id`, `version`, `author`, `shift_times`, `handover_checklist_items`

### Standard Operating Instructions (SOI)

#### 5. Alert Triage SOI
- **Tags:** NIST-CSF-2.0, SOC-CMM
- **Purpose:** Step-by-step instructions for triaging security alerts with decision tree
- **Sections:** Objective, Prerequisites, Triage Workflow, Decision Tree, Classification, Escalation Path, Expected Outputs
- **Key Variables:** `doc_id`, `version`, `author`, `alert_source`, `triage_steps`, `classification_criteria`

#### 6. Phishing Response SOI
- **Tags:** SANS-IR, NIST-800-61
- **Purpose:** Instructions for analyzing and responding to reported phishing emails
- **Sections:** Objective, Prerequisites, Analysis Steps (Header, Content, URL/Attachment), Scope Assessment, Containment, User Notification, IOC Extraction, Reporting
- **Key Variables:** `doc_id`, `version`, `author`, `email_gateway_tool`, `sandbox_url`, `blocklist_tool`

#### 7. Malware Analysis SOI
- **Tags:** MITRE-ATT&CK, NIST-800-61
- **Purpose:** Instructions for static and dynamic malware analysis with MITRE ATT&CK mapping
- **Sections:** Objective, Prerequisites, Static Analysis, Dynamic Analysis, IOC Extraction, MITRE Mapping, Report, Containment
- **Key Variables:** `doc_id`, `version`, `author`, `sandbox_environment`, `analysis_tools`, `submission_portal`

### Work Instructions (WI)

#### 8. IOC Blocking Work Instruction
- **Tags:** MITRE-ATT&CK
- **Purpose:** Step-by-step instructions for blocking IOCs across security tools
- **Sections:** Objective, Scope, Prerequisites, IP/Domain/Hash Blocking Steps, Verification, Rollback, Documentation
- **Key Variables:** `doc_id`, `version`, `author`, `firewall_tool`, `edr_tool`, `dns_filter_tool`, `change_management_required`

#### 9. Log Source Onboarding Work Instruction
- **Tags:** NIST-CSF-2.0, SOC-CMM
- **Purpose:** Instructions for onboarding new log sources into the SIEM
- **Sections:** Objective, Log Source Identification, Collection Method, Parser Configuration, Validation, Alert Rules Setup
- **Key Variables:** `doc_id`, `version`, `author`, `siem_platform`, `log_formats`, `retention_days`

#### 10. SIEM Query & Investigation Work Instruction
- **Tags:** SOC-CMM
- **Purpose:** Query syntax reference, common queries, and correlation techniques
- **Sections:** Objective, Query Syntax Reference (KQL, Lucene), Common Queries, Correlation Techniques, Performance Tips
- **Key Variables:** `doc_id`, `version`, `author`, `siem_platform`, `query_examples`

### Knowledge Base (KB)

#### 11. Common Alert Types KB
- **Tags:** MITRE-ATT&CK
- **Purpose:** Reference for common security alert types with response guidance
- **Sections:** Overview, Alert Categories Table, Per-Category Detail (Authentication, Malware, Network, Policy)
- **Key Variables:** `doc_id`, `version`, `author`, `alert_categories`

#### 12. Threat Actor Profile KB
- **Tags:** MITRE-ATT&CK
- **Purpose:** Template for documenting threat actor profiles with TTPs and IOCs
- **Sections:** Actor Overview, Aliases, TTPs Table (MITRE ATT&CK), Campaigns, IOC Summary, Detection Recommendations
- **Key Variables:** `doc_id`, `version`, `author`, `actor_name`, `aliases`, `motivation`, `target_sectors`, `ttps`, `iocs`, `campaigns`

#### 13. Tool Configuration Guide KB
- **Tags:** SOC-CMM
- **Purpose:** Template for documenting security tool configuration and troubleshooting
- **Sections:** Overview, Prerequisites, Configuration, Integration, Troubleshooting, Maintenance
- **Key Variables:** `doc_id`, `version`, `author`, `tool_name`, `tool_version`, `purpose`, `configuration_steps`, `troubleshooting_items`

### Incident Response Plans (IRP)

#### 14. Ransomware Incident Response Plan
- **Tags:** NIST-800-61, SANS-IR
- **Purpose:** Structured response procedures for ransomware incidents (SANS phases)
- **Sections:** Purpose, Roles, Detection Indicators, SANS Phases (Identification, Containment, Eradication, Recovery), Communication Plan, Evidence Preservation, Post-Incident Review
- **Key Variables:** `doc_id`, `version`, `classification`, `author`, `approved_by`, `ir_team_contacts`, `backup_contacts`, `legal_contacts`

#### 15. Data Breach Response Plan
- **Tags:** ISO-27035, NIST-800-61
- **Purpose:** Response procedures for data breaches including regulatory notification
- **Sections:** Purpose, Breach Classification, Roles, Detection & Assessment, Containment, Notification Requirements (GDPR, CCPA, HIPAA, PCI DSS), Communication Templates, Forensic Investigation, Regulatory Reporting
- **Key Variables:** `doc_id`, `version`, `classification`, `author`, `approved_by`, `dpo_contact`, `legal_contacts`, `notification_requirements`

### After-Action Reports (AAR)

#### 16. Post-Incident After-Action Report
- **Tags:** NIST-800-61, SANS-IR, ISO-27035
- **Purpose:** Post-incident retrospective with lessons learned and improvement recommendations
- **Sections:** Executive Summary, Incident Overview, Timeline Table, What Went Well, Areas for Improvement, Findings, Recommendations (with Priority/Owner), Action Items
- **Key Variables:** `doc_id`, `version`, `classification`, `author`, `incident_id`, `incident_title`, `incident_date`, `resolution_date`, `severity`, `lead_analyst`, `participants`, `executive_summary`, `timeline_events`, `findings`, `recommendations`

### Threat Intelligence

#### 17. Threat Advisory
- **Tags:** MITRE-ATT&CK
- **Purpose:** Communicate emerging threats, IOCs, and mitigations to the organization
- **Sections:** Advisory Header, Threat Overview, Affected Systems, Technical Analysis, IOC Table, MITRE Mapping, Mitigations (Immediate + Long-term), Detection Signatures
- **Key Variables:** `doc_id`, `version`, `classification`, `author`, `advisory_title`, `severity`, `date_issued`, `tlp_level`, `affected_systems`, `threat_description`, `iocs`, `mitre_techniques`, `mitigations`

### Detection Engineering

#### 18. Detection Rule Documentation
- **Tags:** MITRE-ATT&CK
- **Purpose:** Document detection rules with MITRE mapping, data requirements, and test cases
- **Sections:** Rule Metadata, Description, MITRE Mapping, Data Requirements, Detection Logic, Query/Sigma Rule, Test Cases, False Positive Guidance, Tuning
- **Key Variables:** `doc_id`, `version`, `author`, `rule_name`, `rule_id`, `severity`, `mitre_technique`, `mitre_tactic`, `data_sources`, `detection_logic`, `query`, `false_positive_rate`, `test_cases`

### Runbooks

#### 19. Operational Runbook
- **Tags:** SOC-CMM, NIST-CSF-2.0
- **Purpose:** Operational procedure guide for routine SOC tasks with trigger conditions and rollback
- **Sections:** Overview, Trigger Conditions, Prerequisites, Procedure Steps Table, Verification, Rollback, Escalation Path
- **Key Variables:** `doc_id`, `version`, `author`, `runbook_title`, `trigger_conditions`, `prerequisites`, `procedure_steps`, `rollback_steps`, `escalation_contacts`, `success_criteria`

---

## Framework Tags

Templates are tagged with compliance framework references:

| Tag | Framework | Templates Using |
|-----|-----------|----------------|
| `NIST-800-61` | NIST SP 800-61 (Incident Handling) | 7 |
| `NIST-CSF-2.0` | NIST Cybersecurity Framework 2.0 | 5 |
| `SANS-IR` | SANS Incident Response Process | 5 |
| `SOC-CMM` | SOC Capability Maturity Model | 7 |
| `MITRE-ATT&CK` | MITRE ATT&CK Framework | 8 |
| `ISO-27035` | ISO 27035 (Incident Management) | 4 |

---

## API Reference

### List Document Types

```
GET /api/document-types
```

**Response:**
```json
{
  "types": {
    "SOP": "Standard Operating Procedure",
    "SOI": "Standard Operating Instruction",
    "WI": "Work Instruction",
    "KB": "Knowledge Base",
    "RUNBOOK": "Runbook",
    "IRP": "Incident Response Plan",
    "AAR": "After-Action Report",
    "THREAT_ADVISORY": "Threat Advisory",
    "DETECTION_RULE": "Detection Rule Documentation"
  }
}
```

### Filter Templates by Document Type

```
GET /api/templates?document_type=SOP
```

Returns only templates with `document_type` = `SOP`.

### Create Template with Document Type

```
POST /api/templates
Content-Type: application/json

{
  "name": "My Custom SOP",
  "content": "# {{ doc_id }} - My SOP\n...",
  "format": "markdown",
  "document_type": "SOP",
  "description": "Custom SOP for team use",
  "tags": ["NIST-CSF-2.0"]
}
```

### Update Template Document Type

```
PUT /api/templates/{id}
Content-Type: application/json

{
  "document_type": "IRP"
}
```

---

## UI Features

### Templates Page (`/templates`)

- **Type Filter Dropdown**: Filter templates by document type (next to format filter)
- **Type Badges**: Colored badges on each template card showing the document type
- **Folder Organization**: SOC templates auto-organized into their respective collections

### Documents Page (`/documents`)

- **Source Type Badge**: Documents rendered from typed templates display the source template's document type as a colored badge

### Template Form (`/templates/new`, `/templates/{id}/edit`)

- **Document Type Selector**: Dropdown to assign or change a template's document type

### Template View (`/templates/{id}`)

- **Type Badge**: Document type badge displayed in the metadata bar

---

## Seeding Behavior

The `seed_soc_templates()` function runs automatically on ION startup:

1. **Idempotent**: Checks each collection and template by name before creating
2. **Order**: Runs after `seed_default_playbooks()` in the startup sequence
3. **Creates**: 9 collections, 19 templates, framework tags, initial versions, and variable definitions
4. **Logging**: Logs each created item; skips silently if already exists
5. **Error handling**: Wrapped in try/except - startup continues if seeding fails

### Manual Re-seeding

If templates need to be re-seeded (e.g., after database reset):

```python
from ion.services.soc_template_service import seed_soc_templates
seed_soc_templates()
```

---

## Database Changes

### Migration

A new column `document_type` (VARCHAR(50), nullable) is added to the `templates` table. The migration runs automatically on startup via `_run_migrations()` in `database.py`.

### Schema

```sql
ALTER TABLE templates ADD COLUMN document_type VARCHAR(50);
```

---

## Customization

### Adding New Document Types

1. Add the type code and label to `DOCUMENT_TYPES` in `soc_template_service.py`
2. Add a CSS class `.doc-type-YOURTYPE` in `templates.html`, `documents.html`, and `template_view.html`
3. The API endpoint `/api/document-types` will automatically include it

### Adding New Templates

Add a new entry to `TEMPLATE_DEFS` in `soc_template_service.py` following the existing pattern:

```python
{
    "name": "Your Template Name",
    "document_type": "SOP",           # Must match a DOCUMENT_TYPES key
    "collection": "Standard Operating Procedures",  # Must match a COLLECTION_DEFS name
    "description": "Brief description",
    "tags": ["NIST-800-61"],
    "variables": [
        {"name": "var_name", "var_type": "string", "required": True, "default_value": "", "description": "..."},
    ],
    "content": """# Jinja2 template content here
{{ var_name }}
""",
}
```

Restart ION and the new template will be seeded automatically.
