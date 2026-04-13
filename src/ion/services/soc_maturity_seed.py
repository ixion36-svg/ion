"""Seed SOC maturity documentation — runbooks, communication templates, and playbooks.

Run via: POST /api/admin/seed-maturity (admin only)
Or automatically on first startup if the tables are empty.

Creates:
- 9 SOC runbook/SOP document templates
- 10 communication templates (breach, ransomware, phishing, etc.)
- 19 additional playbooks (25 total with the 6 existing)
"""

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import select, func

logger = logging.getLogger(__name__)


# =========================================================================
# 1. COMMUNICATION TEMPLATES
# =========================================================================

COMM_TEMPLATES = [
    {
        "name": "GDPR Breach Notification (72h)",
        "category": "breach_notification",
        "audience": "legal",
        "subject_template": "[URGENT] Personal Data Breach Notification — {{incident_id}}",
        "body_template": """Dear Data Protection Authority,

We are writing to notify you of a personal data breach in accordance with Article 33 of the General Data Protection Regulation (GDPR).

**Incident Reference:** {{incident_id}}
**Date/Time of Breach:** {{breach_datetime}}
**Date of Discovery:** {{discovery_datetime}}
**Nature of Breach:** {{breach_description}}

**Categories of Data Affected:**
{{data_categories}}

**Approximate Number of Data Subjects:** {{affected_count}}
**Approximate Number of Records:** {{record_count}}

**Likely Consequences:**
{{consequences}}

**Measures Taken / Proposed:**
{{remediation_steps}}

**Data Protection Officer Contact:**
Name: {{dpo_name}}
Email: {{dpo_email}}
Phone: {{dpo_phone}}

This notification is made within 72 hours of becoming aware of the breach as required by Article 33(1) GDPR.

Regards,
{{organisation_name}}""",
    },
    {
        "name": "NIS2 Incident Notification — Early Warning (24h)",
        "category": "breach_notification",
        "audience": "legal",
        "subject_template": "[NIS2 EARLY WARNING] Significant Cyber Incident — {{incident_id}}",
        "body_template": """CSIRT Early Warning Notification (NIS2 Directive Article 23)

This early warning is submitted within 24 hours of becoming aware of a significant incident.

**Incident Reference:** {{incident_id}}
**Reporting Entity:** {{organisation_name}}
**Sector:** {{sector}}
**Notification Type:** Early Warning (24-hour)

**Is this incident suspected to be caused by unlawful or malicious acts?** {{malicious_suspected}}
**Could this incident have a cross-border impact?** {{cross_border}}

**Brief Description:**
{{incident_summary}}

**Initial Impact Assessment:**
- Service disruption: {{service_impact}}
- Estimated affected users/customers: {{affected_users}}

A full incident notification will follow within 72 hours as required by Article 23(4)(b).

Submitted by: {{reporter_name}} ({{reporter_role}})
Contact: {{reporter_email}} / {{reporter_phone}}""",
    },
    {
        "name": "Ransomware Incident — Executive Brief",
        "category": "ransomware",
        "audience": "executive",
        "subject_template": "[CRITICAL] Ransomware Incident — Executive Summary — {{incident_id}}",
        "body_template": """EXECUTIVE SUMMARY — RANSOMWARE INCIDENT

**Status:** {{current_status}}
**Severity:** Critical
**Incident ID:** {{incident_id}}
**Date/Time Detected:** {{detection_time}}
**Affected Systems:** {{affected_systems}}

**SITUATION:**
{{situation_summary}}

**BUSINESS IMPACT:**
- Systems offline: {{systems_offline}}
- Users affected: {{users_affected}}
- Estimated revenue impact: {{revenue_impact}}
- Customer data at risk: {{customer_data_risk}}

**ACTIONS TAKEN:**
1. {{action_1}}
2. {{action_2}}
3. {{action_3}}

**NEXT STEPS:**
{{next_steps}}

**RANSOM DEMAND:** {{ransom_details}}
**LAW ENFORCEMENT ENGAGED:** {{le_status}}
**INSURANCE NOTIFIED:** {{insurance_status}}

**ESTIMATED RECOVERY TIME:** {{recovery_eta}}

Next update will be provided at: {{next_update_time}}

Prepared by: {{soc_lead}} — SOC Lead""",
    },
    {
        "name": "Phishing Campaign — All-Staff Advisory",
        "category": "phishing",
        "audience": "all_staff",
        "subject_template": "[SECURITY ALERT] Active Phishing Campaign — Action Required",
        "body_template": """SECURITY ADVISORY — ACTIVE PHISHING CAMPAIGN

The Security Operations Centre has identified an active phishing campaign targeting our organisation.

**WHAT TO LOOK FOR:**
- Subject line: {{phishing_subject}}
- Sender: {{phishing_sender}} (spoofed — not a legitimate sender)
- Contains: {{phishing_indicators}}

**WHAT TO DO:**
1. DO NOT click any links or open attachments in suspicious emails
2. DO NOT reply to the sender
3. Forward the email to {{phishing_report_email}}
4. Delete the email from your inbox
5. If you already clicked a link or entered credentials, contact the IT helpdesk immediately at {{helpdesk_number}}

**IF YOU ENTERED YOUR PASSWORD:**
- Change your password immediately at {{password_reset_url}}
- Enable MFA if not already active
- Report to {{helpdesk_email}} so we can check your account for unauthorised access

**ADDITIONAL CONTEXT:**
{{additional_context}}

Thank you for your vigilance.
— Security Operations Centre""",
    },
    {
        "name": "Data Loss Incident — Management Notification",
        "category": "breach_notification",
        "audience": "internal",
        "subject_template": "[CONFIDENTIAL] Data Loss Incident Report — {{incident_id}}",
        "body_template": """INTERNAL — DATA LOSS INCIDENT REPORT

**Incident ID:** {{incident_id}}
**Severity:** {{severity}}
**Date Detected:** {{detection_date}}

**SUMMARY:**
{{incident_summary}}

**DATA INVOLVED:**
- Classification: {{data_classification}}
- Volume: {{data_volume}}
- Type: {{data_type}}

**ROOT CAUSE:**
{{root_cause}}

**CONTAINMENT ACTIONS:**
{{containment_actions}}

**REGULATORY OBLIGATIONS:**
- GDPR notification required: {{gdpr_required}}
- Other regulatory notifications: {{other_notifications}}

**REMEDIATION PLAN:**
{{remediation_plan}}

**TIMELINE:**
{{timeline}}

Prepared by: {{analyst_name}}
Approved by: {{approver_name}}""",
    },
    {
        "name": "Incident Status Update",
        "category": "status_update",
        "audience": "internal",
        "subject_template": "Incident {{incident_id}} — Status Update #{{update_number}}",
        "body_template": """INCIDENT STATUS UPDATE

**Incident:** {{incident_id}} — {{incident_title}}
**Update #:** {{update_number}}
**Time:** {{update_time}}
**Status:** {{current_status}}

**SINCE LAST UPDATE:**
{{changes_since_last}}

**CURRENT SITUATION:**
{{current_situation}}

**NEXT ACTIONS:**
{{next_actions}}

**BLOCKERS / RISKS:**
{{blockers}}

**NEXT UPDATE:** {{next_update_time}}

— {{analyst_name}}, SOC""",
    },
    {
        "name": "Account Compromise — User Notification",
        "category": "breach_notification",
        "audience": "internal",
        "subject_template": "[ACTION REQUIRED] Your account may have been compromised",
        "body_template": """Dear {{user_name}},

Our security monitoring has detected suspicious activity on your account ({{username}}).

**What happened:**
{{activity_description}}

**When:** {{activity_time}}
**From:** {{source_location}}

**What you need to do now:**
1. Change your password immediately
2. Review your recent login activity
3. Check for any unauthorised changes to your profile or settings
4. Report any unrecognised activity to {{helpdesk_email}}

**What we've done:**
- Your account has been {{account_action}}
- MFA has been {{mfa_action}}
- Active sessions have been {{session_action}}

If you did not perform this activity, please contact the Security Team immediately at {{security_email}}.

— Security Operations Centre""",
    },
    {
        "name": "Third-Party / Vendor Breach Notification",
        "category": "breach_notification",
        "audience": "executive",
        "subject_template": "[VENDOR BREACH] {{vendor_name}} — Impact Assessment",
        "body_template": """VENDOR BREACH IMPACT ASSESSMENT

**Vendor:** {{vendor_name}}
**Date Notified:** {{notification_date}}
**Severity:** {{severity}}

**VENDOR INCIDENT SUMMARY:**
{{vendor_summary}}

**OUR EXPOSURE:**
- Services affected: {{our_services}}
- Data shared with vendor: {{data_shared}}
- Number of our records potentially affected: {{record_count}}

**RISK ASSESSMENT:**
{{risk_assessment}}

**ACTIONS TAKEN:**
{{actions_taken}}

**RECOMMENDATIONS:**
{{recommendations}}

**VENDOR RESPONSE:**
{{vendor_response}}

Prepared by: {{analyst_name}}""",
    },
    {
        "name": "SOC Monthly Report — Executive Summary",
        "category": "executive_brief",
        "audience": "executive",
        "subject_template": "SOC Monthly Report — {{month}} {{year}}",
        "body_template": """SOC MONTHLY EXECUTIVE REPORT — {{month}} {{year}}

**OVERALL SOC HEALTH:** {{health_grade}} ({{health_score}}/100)

**KEY METRICS:**
| Metric | This Month | Last Month | Trend |
|--------|-----------|------------|-------|
| Alerts Triaged | {{alerts_triaged}} | {{prev_alerts}} | {{alert_trend}} |
| Cases Opened | {{cases_opened}} | {{prev_cases}} | {{case_trend}} |
| Cases Closed | {{cases_closed}} | - | - |
| Mean Time to Respond | {{mttr}} | {{prev_mttr}} | {{mttr_trend}} |
| False Positive Rate | {{fp_rate}}% | {{prev_fp}}% | {{fp_trend}} |
| Detection Coverage | {{coverage}}% | {{prev_coverage}}% | - |

**NOTABLE INCIDENTS:**
{{notable_incidents}}

**THREAT LANDSCAPE:**
{{threat_landscape}}

**IMPROVEMENTS MADE:**
{{improvements}}

**PLANNED NEXT MONTH:**
{{planned_work}}

**RESOURCE STATUS:**
- Team: {{team_size}} analysts ({{vacancies}} vacancies)
- Training: {{training_hours}} hours completed
- Certifications: {{new_certs}} earned

Prepared by: {{soc_lead}} — SOC Lead""",
    },
    {
        "name": "Insider Threat — HR/Legal Notification",
        "category": "breach_notification",
        "audience": "legal",
        "subject_template": "[CONFIDENTIAL] Insider Threat Investigation — {{case_id}}",
        "body_template": """CONFIDENTIAL — INSIDER THREAT INVESTIGATION

**Case Reference:** {{case_id}}
**Classification:** {{classification}}
**Subject:** {{subject_name}} ({{subject_department}})

**SUMMARY OF ACTIVITY:**
{{activity_summary}}

**EVIDENCE COLLECTED:**
{{evidence_list}}

**CHAIN OF CUSTODY:**
{{chain_of_custody}}

**RISK TO ORGANISATION:**
{{risk_assessment}}

**RECOMMENDED ACTIONS:**
{{recommended_actions}}

**LEGAL CONSIDERATIONS:**
{{legal_notes}}

**TIMELINE OF EVENTS:**
{{timeline}}

This report is prepared for HR and Legal review. All evidence has been preserved following the organisation's forensic evidence handling procedures.

Prepared by: {{investigator_name}}
Date: {{report_date}}""",
    },
]


# =========================================================================
# 2. PLAYBOOKS (19 new + 6 existing = 25 total)
# =========================================================================

PLAYBOOKS = [
    {
        "name": "Phishing Email Investigation",
        "category": "Email",
        "description": "Investigate reported phishing emails: analyse headers, URLs, attachments, and determine scope of impact.",
        "steps": [
            {"title": "Collect the reported email", "description": "Retrieve the original email (.eml) from the reporter or email gateway logs. Preserve headers.", "action_type": "manual"},
            {"title": "Analyse email headers", "description": "Check SPF/DKIM/DMARC results, originating IP, return-path, X-headers for spoofing indicators.", "action_type": "manual"},
            {"title": "Analyse URLs and attachments", "description": "Defang URLs, check reputation (VirusTotal, URLhaus). Submit attachments to sandbox if present.", "action_type": "manual"},
            {"title": "Determine recipient scope", "description": "Query email gateway logs to find all recipients of the same campaign (subject, sender, URLs).", "action_type": "manual"},
            {"title": "Check for clicks/submissions", "description": "Query proxy logs for URL visits. Check IdP for password changes. Check for credential use from unusual locations.", "action_type": "manual"},
            {"title": "Contain", "description": "Block sender/domain in email gateway. Block URLs at proxy. Purge remaining copies from mailboxes.", "action_type": "manual"},
            {"title": "Notify affected users", "description": "Send account-compromise notification to users who clicked. Force password reset if credentials were entered.", "action_type": "manual"},
            {"title": "Document and close", "description": "Record IOCs, update block lists, create PIR if significant. Close case with findings.", "action_type": "manual"},
        ],
    },
    {
        "name": "Malware Detection (Endpoint)",
        "category": "Endpoint",
        "description": "Respond to malware detected by EDR or AV on an endpoint. Contain, investigate, remediate.",
        "steps": [
            {"title": "Verify the alert", "description": "Confirm the detection is not a false positive. Check file hash against threat intel.", "action_type": "manual"},
            {"title": "Isolate the endpoint", "description": "Network-isolate the host via EDR. Disable VPN if remote.", "action_type": "manual"},
            {"title": "Collect forensic artefacts", "description": "Capture running processes, network connections, autoruns, recent file modifications.", "action_type": "manual"},
            {"title": "Determine execution and persistence", "description": "Did the malware execute? Check for persistence (scheduled tasks, registry, services, startup).", "action_type": "manual"},
            {"title": "Assess lateral movement", "description": "Check for SMB/RDP connections to other hosts. Pivot with host-based IOCs across the fleet.", "action_type": "manual"},
            {"title": "Remediate", "description": "Remove malware, persistence mechanisms, and any dropped payloads. Re-image if rootkit suspected.", "action_type": "manual"},
            {"title": "Restore and monitor", "description": "Reconnect endpoint to network. Monitor for 48h for reinfection indicators.", "action_type": "manual"},
        ],
    },
    {
        "name": "Ransomware Response",
        "category": "Endpoint",
        "description": "Full ransomware incident response: contain spread, preserve evidence, assess damage, recover.",
        "steps": [
            {"title": "Isolate affected systems", "description": "Immediately network-isolate all known-affected hosts. Disable SMB/RDP at firewall if spread is active.", "action_type": "manual"},
            {"title": "Activate IR plan", "description": "Escalate to IR lead. Notify CISO/exec team. Engage legal if data exfiltration suspected.", "action_type": "manual"},
            {"title": "Identify the ransomware variant", "description": "Check ransom note, encrypted file extensions, threat intel for variant ID. Check ID Ransomware.", "action_type": "manual"},
            {"title": "Determine scope", "description": "Identify all encrypted systems, shared drives, backups affected. Map the blast radius.", "action_type": "manual"},
            {"title": "Preserve evidence", "description": "Image affected systems before remediation. Preserve ransom notes, malware samples, logs.", "action_type": "manual"},
            {"title": "Assess backup integrity", "description": "Verify backups exist and are not encrypted/corrupted. Test restore on isolated system.", "action_type": "manual"},
            {"title": "Eradicate", "description": "Remove ransomware and access vector (usually an exploited service or phished credential).", "action_type": "manual"},
            {"title": "Recover from backups", "description": "Restore systems from verified clean backups. Prioritise by business criticality.", "action_type": "manual"},
            {"title": "Post-incident review", "description": "Conduct PIR within 5 business days. Document lessons learned and remediation actions.", "action_type": "manual"},
        ],
    },
    {
        "name": "Account Compromise (Cloud/SaaS)",
        "category": "Identity",
        "description": "Respond to a compromised cloud account (O365, Azure AD, AWS IAM, Google Workspace).",
        "steps": [
            {"title": "Confirm compromise", "description": "Check impossible travel, unusual app consent, mail rules, forwarding changes, MFA bypass.", "action_type": "manual"},
            {"title": "Revoke sessions and tokens", "description": "Force sign-out all active sessions. Revoke OAuth app consent grants. Invalidate refresh tokens.", "action_type": "manual"},
            {"title": "Reset credentials", "description": "Reset password. Re-enroll MFA. Rotate any API keys or service account credentials.", "action_type": "manual"},
            {"title": "Audit activity during compromise window", "description": "Review all actions taken by the account: emails sent/read, files accessed, admin changes.", "action_type": "manual"},
            {"title": "Check for persistence", "description": "Look for inbox rules, mail forwarding, delegated access, new OAuth apps, new admin accounts.", "action_type": "manual"},
            {"title": "Remediate downstream impact", "description": "Reset passwords of accounts the compromised user had access to. Notify affected teams.", "action_type": "manual"},
            {"title": "Notify the user", "description": "Inform the user of the compromise, what happened, and what actions were taken on their behalf.", "action_type": "manual"},
        ],
    },
    {
        "name": "DDoS Attack Response",
        "category": "Network",
        "description": "Respond to a distributed denial-of-service attack targeting the organisation's services.",
        "steps": [
            {"title": "Confirm DDoS (not outage)", "description": "Distinguish between DDoS, misconfiguration, and infrastructure failure. Check traffic patterns.", "action_type": "manual"},
            {"title": "Engage upstream protection", "description": "Activate CDN/ISP scrubbing service. Enable rate limiting. Engage DDoS mitigation vendor.", "action_type": "manual"},
            {"title": "Identify attack vector", "description": "Volumetric (UDP flood), protocol (SYN flood), or application-layer (HTTP flood/Slowloris).", "action_type": "manual"},
            {"title": "Apply mitigations", "description": "Block source IPs/ASNs at edge. Apply WAF rules. Geofence if attack is from specific regions.", "action_type": "manual"},
            {"title": "Monitor for secondary attack", "description": "DDoS may be a diversion for a simultaneous intrusion attempt. Check for anomalies elsewhere.", "action_type": "manual"},
            {"title": "Document and report", "description": "Record timeline, traffic volumes, mitigations applied, business impact, cost. File law enforcement report.", "action_type": "manual"},
        ],
    },
    {
        "name": "Data Exfiltration Investigation",
        "category": "Data Loss",
        "description": "Investigate potential data exfiltration — large outbound transfers, cloud uploads, USB, email.",
        "steps": [
            {"title": "Identify the exfiltration channel", "description": "DNS tunnelling, HTTP/S upload, cloud storage, email attachment, USB, print.", "action_type": "manual"},
            {"title": "Determine what data was taken", "description": "Correlate with DLP alerts, file access logs, database query logs. Classify the data.", "action_type": "manual"},
            {"title": "Identify the actor", "description": "Internal user, compromised account, or external attacker? Check user activity timelines.", "action_type": "manual"},
            {"title": "Contain", "description": "Block the exfiltration channel. Revoke access. Isolate the source system if still active.", "action_type": "manual"},
            {"title": "Assess regulatory impact", "description": "Does the data include PII, PHI, financial data, or classified material? Determine notification obligations.", "action_type": "manual"},
            {"title": "Preserve evidence", "description": "Image systems, preserve network captures, retain logs for legal/HR proceedings.", "action_type": "manual"},
            {"title": "Notify stakeholders", "description": "Legal, HR (if insider), affected data owners, regulators if required.", "action_type": "manual"},
        ],
    },
    {
        "name": "Privilege Escalation Detection",
        "category": "Identity",
        "description": "Investigate alerts for privilege escalation — new admin accounts, group membership changes, sudo abuse.",
        "steps": [
            {"title": "Verify the escalation event", "description": "Is this an authorised change (change request exists) or unauthorised? Check change management.", "action_type": "manual"},
            {"title": "Identify the actor", "description": "Who made the change? From where? Was their account compromised?", "action_type": "manual"},
            {"title": "Assess scope", "description": "What privileges were gained? Admin? Domain admin? Cloud admin? What systems are now accessible?", "action_type": "manual"},
            {"title": "Revert if unauthorised", "description": "Remove the escalated privileges. Reset the account. Rotate any credentials the escalated account had access to.", "action_type": "manual"},
            {"title": "Hunt for abuse", "description": "Review actions taken with the escalated privileges. Check for data access, config changes, backdoors.", "action_type": "manual"},
        ],
    },
    {
        "name": "Command & Control (C2) Detection",
        "category": "Network",
        "description": "Investigate C2 beaconing activity — regular interval callbacks, DNS tunnelling, encrypted channels.",
        "steps": [
            {"title": "Confirm C2 behaviour", "description": "Check for regular-interval connections, unusual DNS patterns, known C2 domains/IPs, JA3 fingerprints.", "action_type": "manual"},
            {"title": "Identify the implant", "description": "What malware/framework is beaconing? Cobalt Strike, Metasploit, custom? Check payloads and certificates.", "action_type": "manual"},
            {"title": "Map all infected hosts", "description": "Search for the same C2 indicators across all endpoints. Check DNS logs, proxy logs, EDR telemetry.", "action_type": "manual"},
            {"title": "Block the C2 channel", "description": "Block C2 domain/IP at DNS, proxy, and firewall. Add to threat intel blocklist.", "action_type": "manual"},
            {"title": "Isolate infected hosts", "description": "Network-isolate all hosts communicating with the C2 infrastructure.", "action_type": "manual"},
            {"title": "Remediate", "description": "Remove the implant from all infected hosts. Patch the initial access vector. Hunt for persistence.", "action_type": "manual"},
        ],
    },
    {
        "name": "Brute Force / Credential Stuffing",
        "category": "Identity",
        "description": "Respond to brute force or credential stuffing attacks against authentication services.",
        "steps": [
            {"title": "Identify the target", "description": "Which service is being attacked? VPN, webmail, SSO portal, RDP? Check failed login volumes.", "action_type": "manual"},
            {"title": "Determine if any accounts were compromised", "description": "Check for successful logins from the same source IPs after failed attempts.", "action_type": "manual"},
            {"title": "Block attacking sources", "description": "Block source IPs at WAF/firewall. Add to blocklist. Enable progressive lockout if not already.", "action_type": "manual"},
            {"title": "Reset compromised accounts", "description": "Force password reset for any account that had a successful login from the attack source.", "action_type": "manual"},
            {"title": "Review account lockout policy", "description": "Ensure lockout thresholds are appropriate. Consider implementing CAPTCHA or IP-based rate limiting.", "action_type": "manual"},
        ],
    },
    {
        "name": "Web Application Attack",
        "category": "Application",
        "description": "Respond to SQLi, XSS, RCE, or other web application attacks detected by WAF or SIEM.",
        "steps": [
            {"title": "Confirm the attack", "description": "Review WAF logs, application logs. Is this a scanner (automated) or targeted (manual exploitation)?", "action_type": "manual"},
            {"title": "Assess if exploitation succeeded", "description": "Check for unusual responses (200 on exploit paths), database errors in logs, new files on server.", "action_type": "manual"},
            {"title": "Block the attacker", "description": "Block source IP at WAF. Add to geo/reputation blocklist if part of a campaign.", "action_type": "manual"},
            {"title": "Check for data access", "description": "If SQLi succeeded, check DB audit logs. If RCE, check for reverse shell connections.", "action_type": "manual"},
            {"title": "Patch the vulnerability", "description": "Engage the application team. Deploy a WAF virtual patch immediately. Schedule a code fix.", "action_type": "manual"},
            {"title": "Scan for similar vulnerabilities", "description": "Run a vulnerability scan against the application. Check for the same issue in other apps.", "action_type": "manual"},
        ],
    },
    {
        "name": "Cloud Infrastructure Compromise",
        "category": "Cloud",
        "description": "Respond to compromised cloud infrastructure (AWS, Azure, GCP) — leaked keys, rogue instances, data exposure.",
        "steps": [
            {"title": "Identify the compromised resource", "description": "Which account, role, or key is compromised? Check CloudTrail/Azure Activity/GCP Audit.", "action_type": "manual"},
            {"title": "Revoke compromised credentials", "description": "Rotate access keys, deactivate IAM users, revoke assumed roles. Do NOT delete (preserve for forensics).", "action_type": "manual"},
            {"title": "Audit actions taken", "description": "Review all API calls made with the compromised credentials. Check for new resources, data access, policy changes.", "action_type": "manual"},
            {"title": "Remove rogue resources", "description": "Terminate any instances, Lambda functions, or storage created by the attacker (e.g., crypto miners).", "action_type": "manual"},
            {"title": "Check for persistence", "description": "Look for new IAM users, roles, policies, federation trusts, or cross-account access.", "action_type": "manual"},
            {"title": "Assess data exposure", "description": "Were any S3 buckets/blob containers made public? Was data copied to external accounts?", "action_type": "manual"},
            {"title": "Harden", "description": "Enable MFA on root/admin. Review SCPs/policies. Enable GuardDuty/Defender/SCC if not already.", "action_type": "manual"},
        ],
    },
    {
        "name": "Cryptomining Detection",
        "category": "Endpoint",
        "description": "Investigate cryptomining activity on endpoints or cloud instances.",
        "steps": [
            {"title": "Confirm mining activity", "description": "High CPU, connections to mining pools (port 3333/14444), known miner process names.", "action_type": "manual"},
            {"title": "Identify affected systems", "description": "Search for mining pool connections across all endpoints. Check cloud compute costs for spikes.", "action_type": "manual"},
            {"title": "Determine initial access", "description": "How was the miner installed? Exploited vulnerability, compromised credentials, or supply chain?", "action_type": "manual"},
            {"title": "Remove miner and persistence", "description": "Kill the process, remove binaries, check crontabs/scheduled tasks, reverse any config changes.", "action_type": "manual"},
            {"title": "Block mining pools", "description": "Block known mining pool domains and IPs at DNS and firewall.", "action_type": "manual"},
        ],
    },
    {
        "name": "DNS Tunnelling Investigation",
        "category": "Network",
        "description": "Investigate DNS tunnelling — data exfiltration or C2 communication via DNS queries.",
        "steps": [
            {"title": "Identify the suspicious domain", "description": "Look for domains with high query volume, long subdomains (>50 chars), high entropy labels.", "action_type": "manual"},
            {"title": "Analyse the DNS traffic", "description": "Check query types (TXT, NULL, CNAME — unusual for normal traffic). Decode payload if possible.", "action_type": "manual"},
            {"title": "Identify the source host", "description": "Which internal host is generating the queries? Check the endpoint for DNS tunnel tools (iodine, dnscat2).", "action_type": "manual"},
            {"title": "Block the tunnel", "description": "Sinkhole the domain at DNS resolver. Block the authoritative nameserver IP.", "action_type": "manual"},
            {"title": "Investigate the host", "description": "The DNS tunnel is a symptom — find the malware or attacker tool that's using it.", "action_type": "manual"},
        ],
    },
    {
        "name": "MFA Bypass / Fatigue Attack",
        "category": "Identity",
        "description": "Respond to MFA bypass attempts including push notification fatigue (MFA bombing).",
        "steps": [
            {"title": "Detect the pattern", "description": "Multiple MFA push requests to a single user in short succession, especially outside business hours.", "action_type": "manual"},
            {"title": "Contact the user", "description": "Call (don't email) the user to confirm they did NOT approve the MFA prompt.", "action_type": "manual"},
            {"title": "Disable the account temporarily", "description": "If the user approved under fatigue, disable the account immediately. Revoke all sessions.", "action_type": "manual"},
            {"title": "Check for post-compromise activity", "description": "Review all actions after the MFA approval. Check for data access, email rules, new OAuth apps.", "action_type": "manual"},
            {"title": "Re-enrol with phishing-resistant MFA", "description": "Switch user to FIDO2/WebAuthn instead of push notifications. Educate on fatigue attacks.", "action_type": "manual"},
        ],
    },
    {
        "name": "Supply Chain Attack Investigation",
        "category": "Application",
        "description": "Investigate a suspected supply chain compromise — compromised update, malicious dependency, vendor breach.",
        "steps": [
            {"title": "Identify the compromised component", "description": "Which vendor/library/update is suspect? Check advisories, threat intel, vendor communications.", "action_type": "manual"},
            {"title": "Determine exposure", "description": "Which of our systems use the compromised component? Check SBOMs, package managers, deployment records.", "action_type": "manual"},
            {"title": "Isolate affected systems", "description": "If the compromise is active, isolate systems running the affected component.", "action_type": "manual"},
            {"title": "Assess impact", "description": "Did the compromised component have network access? Data access? Credentials? What could it have done?", "action_type": "manual"},
            {"title": "Remove or roll back", "description": "Downgrade to a known-good version, or remove the component entirely if alternatives exist.", "action_type": "manual"},
            {"title": "Hunt for post-compromise activity", "description": "Search for IOCs associated with the supply chain attack across all systems.", "action_type": "manual"},
            {"title": "Notify stakeholders", "description": "Inform affected teams, customers, and regulators as appropriate.", "action_type": "manual"},
        ],
    },
    {
        "name": "USB / Removable Media Violation",
        "category": "Endpoint",
        "description": "Investigate alerts for unauthorised USB device connections or data transfers.",
        "steps": [
            {"title": "Identify the device and user", "description": "Check Sysmon event 6/device connection logs. Note device serial, type, and the user who connected it.", "action_type": "manual"},
            {"title": "Determine policy applicability", "description": "Is this user authorised to use removable media? Check the USB exception register.", "action_type": "manual"},
            {"title": "Assess data transfer", "description": "Check for file copy events (Sysmon event 11, DLP). What files were transferred and in which direction?", "action_type": "manual"},
            {"title": "Classify transferred data", "description": "Were any sensitive/classified/PII files copied? Check file names, sizes, DLP classifications.", "action_type": "manual"},
            {"title": "Take action", "description": "If unauthorised: confiscate device, block USB on endpoint, notify HR/management. If authorised: document and close.", "action_type": "manual"},
        ],
    },
    {
        "name": "Lateral Movement Detection",
        "category": "Network",
        "description": "Investigate detected lateral movement — pass-the-hash, RDP hijacking, SMB pivoting.",
        "steps": [
            {"title": "Map the movement path", "description": "Source host → destination host(s). What protocols used (SMB, RDP, WMI, WinRM, SSH)?", "action_type": "manual"},
            {"title": "Identify the credentials used", "description": "Were legitimate credentials stolen (PtH, PtT) or was a vulnerability exploited (EternalBlue)?", "action_type": "manual"},
            {"title": "Determine the origin", "description": "Trace back to the initial compromise. Which host was patient zero?", "action_type": "manual"},
            {"title": "Isolate all affected hosts", "description": "Network-isolate every host in the movement chain. Block the credentials used.", "action_type": "manual"},
            {"title": "Hunt for additional compromise", "description": "Search for the same credential/tool usage across the entire environment.", "action_type": "manual"},
            {"title": "Remediate and harden", "description": "Reset all compromised credentials. Enable SMB signing. Restrict lateral admin access (LAPS, tiered admin).", "action_type": "manual"},
        ],
    },
    {
        "name": "Business Email Compromise (BEC)",
        "category": "Email",
        "description": "Investigate business email compromise — CEO fraud, invoice diversion, impersonation.",
        "steps": [
            {"title": "Confirm the BEC", "description": "Is this a spoofed external email or a compromised internal account? Check headers, SPF, DKIM.", "action_type": "manual"},
            {"title": "Identify the attack type", "description": "CEO/CFO impersonation, invoice redirect, payroll diversion, or data theft request?", "action_type": "manual"},
            {"title": "Determine if payment/data was sent", "description": "Contact the recipient. Check if funds were transferred or data was shared.", "action_type": "manual"},
            {"title": "Contact the bank (if financial)", "description": "If payment was made, contact the bank IMMEDIATELY to attempt a recall. Time is critical.", "action_type": "manual"},
            {"title": "Investigate the compromised account", "description": "If internal account was used: check for inbox rules, forwarding, OAuth apps, impossible travel.", "action_type": "manual"},
            {"title": "Notify law enforcement", "description": "File an Action Fraud (UK) / IC3 (US) report. Provide wire transfer details.", "action_type": "manual"},
            {"title": "Awareness training", "description": "Send targeted BEC awareness to finance/exec teams. Reinforce out-of-band verification for payments.", "action_type": "manual"},
        ],
    },
    {
        "name": "Zero-Day / Emerging Threat Response",
        "category": "Vulnerability",
        "description": "Rapid response to a newly disclosed zero-day vulnerability or actively exploited CVE.",
        "steps": [
            {"title": "Assess exposure", "description": "Which of our systems run the affected software/version? Check CMDB, vulnerability scanners, SBOM.", "action_type": "manual"},
            {"title": "Check for exploitation", "description": "Search logs for IOCs associated with known exploitation (published PoC, CISA KEV, vendor advisory).", "action_type": "manual"},
            {"title": "Apply immediate mitigations", "description": "WAF virtual patches, network segmentation, disable affected features, apply vendor workaround.", "action_type": "manual"},
            {"title": "Prioritise patching", "description": "Emergency patch internet-facing systems first, then internal. Follow the org's emergency change process.", "action_type": "manual"},
            {"title": "Monitor for exploitation attempts", "description": "Create or enable detection rules specific to this CVE. Monitor for 30 days post-patch.", "action_type": "manual"},
            {"title": "Update risk register", "description": "Document the vulnerability, exposure, remediation timeline, and any residual risk.", "action_type": "manual"},
        ],
    },
    {
        "name": "Insider Threat Investigation",
        "category": "Data Loss",
        "description": "Investigate a suspected insider threat — data theft, sabotage, or policy violation by an employee.",
        "steps": [
            {"title": "Receive referral", "description": "Insider threat cases typically come from HR, management, or DLP alerts. Confirm authorisation to investigate.", "action_type": "manual"},
            {"title": "Establish investigation scope", "description": "What is the allegation? Data theft, sabotage, policy violation, espionage? Define the investigation boundaries.", "action_type": "manual"},
            {"title": "Covertly collect evidence", "description": "Review logs WITHOUT alerting the subject. Email, file access, badge access, USB, print, cloud uploads.", "action_type": "manual"},
            {"title": "Timeline the activity", "description": "Build a chronological timeline of the subject's relevant actions. Correlate across all data sources.", "action_type": "manual"},
            {"title": "Assess data exposure", "description": "What data was accessed/copied/sent? Classify it. Determine the impact.", "action_type": "manual"},
            {"title": "Preserve evidence forensically", "description": "Image the subject's workstation and mobile devices. Maintain chain of custody documentation.", "action_type": "manual"},
            {"title": "Brief HR and Legal", "description": "Present findings to HR and Legal. They will determine disciplinary/legal action.", "action_type": "manual"},
        ],
    },
]


# =========================================================================
# Seeding functions
# =========================================================================

def seed_comm_templates(session: Session) -> int:
    """Seed communication templates. Returns count added."""
    from ion.models.oncall import CommTemplate

    existing = session.execute(select(func.count(CommTemplate.id))).scalar() or 0
    if existing >= len(COMM_TEMPLATES):
        return 0

    existing_names = {
        r[0] for r in session.execute(select(CommTemplate.name)).all()
    }

    added = 0
    for t in COMM_TEMPLATES:
        if t["name"] in existing_names:
            continue
        session.add(CommTemplate(
            name=t["name"],
            category=t["category"],
            audience=t["audience"],
            subject_template=t["subject_template"],
            body_template=t["body_template"],
            is_default=True,
        ))
        added += 1

    if added:
        session.commit()
    return added


def seed_playbooks(session: Session) -> int:
    """Seed playbook library. Returns count added."""
    from ion.models.playbook import Playbook, PlaybookStep, StepType

    existing_names = {
        r[0] for r in session.execute(select(Playbook.name)).all()
    }

    added = 0
    for pb in PLAYBOOKS:
        if pb["name"] in existing_names:
            continue
        playbook = Playbook(
            name=pb["name"],
            description=pb["description"],
            trigger_conditions={"category": pb.get("category", "General")},
            is_active=False,  # Start inactive — analyst activates after review
            created_by_id=1,
        )
        session.add(playbook)
        session.flush()

        for i, step in enumerate(pb["steps"]):
            session.add(PlaybookStep(
                playbook_id=playbook.id,
                step_order=i + 1,
                title=step["title"],
                description=step.get("description", ""),
                step_type=StepType.MANUAL_CHECKLIST.value,
            ))

        added += 1

    if added:
        session.commit()
    return added


def seed_all(session: Session) -> dict:
    """Seed everything — comm templates + playbooks. Returns summary."""
    comms = seed_comm_templates(session)
    playbooks = seed_playbooks(session)
    return {
        "comm_templates_added": comms,
        "playbooks_added": playbooks,
        "total_added": comms + playbooks,
    }
