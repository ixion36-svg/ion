"""Render all 19 SOC templates with realistic enterprise data.

Produces production-quality SOC documentation for Guarded Glass Security Operations.
"""

import requests
import sys

BASE = "http://127.0.0.1:8000"
ORG = "Guarded Glass"
DEPT = "Security Operations Center"

# Enterprise-realistic render data for each template (by ID)
RENDER_DATA = {
    # =========================================================================
    # 1. SOC Monitoring & Triage SOP
    # =========================================================================
    1: {
        "doc_name": "GG-SOP-MON-001 - SOC Monitoring & Triage",
        "data": {
            "doc_id": "GG-SOP-MON-001",
            "version": "1.0",
            "classification": "INTERNAL - OFFICIAL",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "department": "Guarded Glass Security Operations Center",
            "review_date": "2026-08-11",
            "approved_by": "Sarah Chen, CISO",
            "siem_tool": "Elastic SIEM (v8.11)",
            "escalation_contacts": "| Role | Name | Phone | Email |\n|------|------|-------|-------|\n| SOC Lead (Day) | Marcus Webb | +44 7700 900100 | m.webb@guardedglass.io |\n| SOC Lead (Night) | Priya Sharma | +44 7700 900101 | p.sharma@guardedglass.io |\n| IR Manager | David Okafor | +44 7700 900102 | d.okafor@guardedglass.io |\n| CISO | Sarah Chen | +44 7700 900103 | s.chen@guardedglass.io |",
            "shift_schedule": "| Shift | Hours (UTC) | Team | Lead |\n|-------|------------|------|------|\n| Day | 07:00 - 15:00 | Alpha | Marcus Webb |\n| Swing | 15:00 - 23:00 | Bravo | James Torres |\n| Night | 23:00 - 07:00 | Charlie | Priya Sharma |\n\n**Rotation**: 4 days on, 2 days off. Handover window: 30 minutes overlap.",
        },
    },

    # =========================================================================
    # 2. Incident Escalation SOP
    # =========================================================================
    2: {
        "doc_name": "GG-SOP-ESC-001 - Incident Escalation",
        "data": {
            "doc_id": "GG-SOP-ESC-001",
            "version": "1.0",
            "classification": "INTERNAL - OFFICIAL",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "escalation_matrix": "### Guarded Glass Escalation Matrix\n\n| Severity | Initial Responder | Escalation 1 (30 min) | Escalation 2 (2 hr) | Escalation 3 (4 hr) |\n|----------|-------------------|----------------------|---------------------|---------------------|\n| P1 - Critical | L1 Analyst | SOC Lead + IR Manager | CISO + Legal | CEO + Board |\n| P2 - High | L1 Analyst | L2 Analyst + SOC Lead | IR Manager | CISO |\n| P3 - Medium | L1 Analyst | L2 Analyst | SOC Lead | IR Manager |\n| P4 - Low | L1 Analyst | Documented only | - | - |",
            "notification_templates": "### P1 Notification Template\n\n**Subject:** [P1 CRITICAL] Security Incident - Immediate Action Required\n\n**Body:**\n\nA Priority 1 security incident has been confirmed.\n\n- **Incident ID:** [INC-YYYY-NNNN]\n- **Detection Time:** [YYYY-MM-DD HH:MM UTC]\n- **Summary:** [Brief description]\n- **Affected Systems:** [List]\n- **Current Status:** [Containment/Investigation/Eradication]\n- **Bridge Call:** [Link/Number]\n\nImmediate response required. Please join the bridge call.\n\n---\n\n### P2 Notification Template\n\n**Subject:** [P2 HIGH] Security Incident - Action Required\n\n**Body:**\n\nA Priority 2 security incident has been identified requiring investigation.\n\n- **Incident ID:** [INC-YYYY-NNNN]\n- **Detection Time:** [YYYY-MM-DD HH:MM UTC]\n- **Summary:** [Brief description]\n- **Next Update:** Within 2 hours",
            "severity_definitions": "### Guarded Glass Severity Definitions\n\n- **P1 Critical**: Active data breach, ransomware execution, compromise of domain admin credentials, active threat actor in environment. Business impact: Service outage or data loss imminent.\n- **P2 High**: Confirmed malware on endpoint, compromised user account, successful exploitation of vulnerability. Business impact: Potential for escalation to P1.\n- **P3 Medium**: Suspicious activity requiring investigation, multiple failed authentications, policy violation. Business impact: No immediate risk but requires validation.\n- **P4 Low**: Informational alerts, scan activity, minor misconfigurations. Business impact: None immediate.",
        },
    },

    # =========================================================================
    # 3. Evidence Handling & Chain of Custody SOP
    # =========================================================================
    3: {
        "doc_name": "GG-SOP-EVD-001 - Evidence Handling & Chain of Custody",
        "data": {
            "doc_id": "GG-SOP-EVD-001",
            "version": "1.0",
            "classification": "CONFIDENTIAL",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "evidence_storage_location": "Primary: Secure evidence locker, SOC Floor 3, Room 3.14 (keycard + PIN access, CCTV monitored)\nDigital: Evidence NAS (\\\\evidence.guardedglass.internal\\forensics) - encrypted AES-256, access restricted to IR team\nCloud: Azure Blob Storage (forensics-evidence container) - immutable retention policy enabled",
            "forensic_tools": "| Tool | Version | Purpose | License |\n|------|---------|---------|--------|\n| FTK Imager | 4.7 | Disk imaging & triage | Licensed |\n| Volatility 3 | 3.0 | Memory forensics | Open source |\n| Autopsy | 4.21 | Digital forensics platform | Open source |\n| Wireshark | 4.2 | Packet analysis | Open source |\n| KAPE | 3.0 | Artifact collection | Licensed |\n| Velociraptor | 0.72 | Endpoint forensics & IR | Open source |\n| Arsenal Image Mounter | 3.10 | Forensic image mounting | Licensed |",
            "legal_contact": "Rachel Morrison, Head of Legal - r.morrison@guardedglass.io - +44 7700 900110\nExternal counsel: Williams & Hart LLP - incident.response@williamshart.co.uk - +44 20 7946 0958",
        },
    },

    # =========================================================================
    # 4. Shift Handover SOP
    # =========================================================================
    4: {
        "doc_name": "GG-SOP-SHO-001 - Shift Handover",
        "data": {
            "doc_id": "GG-SOP-SHO-001",
            "version": "1.0",
            "classification": "INTERNAL",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "shift_times": "Day: 07:00-15:00 UTC (Alpha) | Swing: 15:00-23:00 UTC (Bravo) | Night: 23:00-07:00 UTC (Charlie)\nHandover overlap: 30 minutes | Weekend coverage: Reduced staffing (2 analysts per shift)",
            "handover_checklist_items": "- [ ] Threat intelligence bulletin reviewed (daily TI brief)\n- [ ] Vulnerability scan results checked (if scheduled)\n- [ ] Firewall change requests pending review\n- [ ] EDR agent health dashboard checked (>98% coverage required)\n- [ ] Phishing mailbox queue cleared\n- [ ] Weekly metrics report updated (if Friday handover)",
        },
    },

    # =========================================================================
    # 5. Alert Triage SOI
    # =========================================================================
    5: {
        "doc_name": "GG-SOI-TRI-001 - Alert Triage",
        "data": {
            "doc_id": "GG-SOI-TRI-001",
            "version": "1.0",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "alert_source": "Elastic SIEM (Kibana Security)",
            "triage_steps": "### Additional Guarded Glass Triage Steps\n\n5. **Asset Criticality Check**: Query CMDB for asset criticality tier\n   - Tier 1 (Critical): Domain controllers, financial systems, customer DB - auto-escalate to P2+\n   - Tier 2 (Important): Email servers, file shares, development systems\n   - Tier 3 (Standard): Workstations, printers, IoT devices\n\n6. **User Risk Score**: Check user risk score in Elastic SIEM\n   - Score > 80: High risk - escalate regardless of alert severity\n   - Score 50-80: Elevated - investigate with priority\n   - Score < 50: Normal - standard triage\n\n7. **GeoIP Validation**: Verify source IPs against expected locations\n   - Check VPN logs if remote access\n   - Flag impossible travel (>500km in <1 hour)",
            "classification_criteria": "### Guarded Glass Alert Classification\n\n| Classification | Criteria | SLA | Action |\n|---------------|----------|-----|--------|\n| True Positive - Critical | Confirmed active threat, Tier 1 asset | 15 min | Immediate escalation, containment |\n| True Positive - Standard | Confirmed threat, Tier 2/3 asset | 30 min | Escalate to L2, begin investigation |\n| Benign True Positive | Legitimate activity triggering rule | 2 hr | Close with documentation, consider tuning |\n| False Positive - Recurring | Same FP seen 3+ times | 2 hr | Close, submit tuning request (JIRA) |\n| False Positive - New | First occurrence of this FP | 4 hr | Close, document for knowledge base |",
        },
    },

    # =========================================================================
    # 6. Phishing Response SOI
    # =========================================================================
    6: {
        "doc_name": "GG-SOI-PHI-001 - Phishing Response",
        "data": {
            "doc_id": "GG-SOI-PHI-001",
            "version": "1.0",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "email_gateway_tool": "Microsoft Defender for Office 365 (EOP/MDO)",
            "sandbox_url": "https://sandbox.guardedglass.internal (Joe Sandbox Cloud) + https://app.any.run (backup)",
            "blocklist_tool": "Palo Alto Panorama (URL Filtering) + Cisco Umbrella (DNS)",
        },
    },

    # =========================================================================
    # 7. Malware Analysis SOI
    # =========================================================================
    7: {
        "doc_name": "GG-SOI-MAL-001 - Malware Analysis",
        "data": {
            "doc_id": "GG-SOI-MAL-001",
            "version": "1.0",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "sandbox_environment": "Isolated analysis VLAN (10.99.0.0/24) - No internet access\nVM Fleet: Windows 10 22H2, Windows 11 23H2, Ubuntu 22.04\nSnapshot restore after each analysis session\nNetwork capture via Security Onion sensor on analysis VLAN",
            "analysis_tools": "| Tool | Purpose |\n|------|---------|\n| IDA Pro 8.3 | Disassembly & reverse engineering |\n| Ghidra 11.0 | Decompilation & static analysis |\n| x64dbg | Dynamic debugging (Windows) |\n| Process Monitor | Runtime behaviour monitoring |\n| Wireshark | Network traffic analysis |\n| YARA 4.3 | Pattern matching & rule creation |\n| pestudio | PE file static analysis |\n| CyberChef | Data decoding & transformation |",
            "submission_portal": "https://malware.guardedglass.internal/submit (internal)\nVirusTotal Enterprise: https://www.virustotal.com (external - TLP:CLEAR samples only)\nMalware Bazaar: https://bazaar.abuse.ch (sharing)",
        },
    },

    # =========================================================================
    # 8. IOC Blocking Work Instruction
    # =========================================================================
    8: {
        "doc_name": "GG-WI-IOC-001 - IOC Blocking",
        "data": {
            "doc_id": "GG-WI-IOC-001",
            "version": "1.0",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "firewall_tool": "Palo Alto Panorama (PA-5260 cluster)",
            "edr_tool": "CrowdStrike Falcon (Falcon Insight XDR)",
            "dns_filter_tool": "Cisco Umbrella",
            "change_management_required": "Yes - ServiceNow CHG ticket required for production firewall changes.\nEmergency changes: Verbal approval from SOC Lead + retrospective CHG within 24 hours.\nEDR/DNS blocks: No CHG required, documented in case notes.",
        },
    },

    # =========================================================================
    # 9. Log Source Onboarding Work Instruction
    # =========================================================================
    9: {
        "doc_name": "GG-WI-LOG-001 - Log Source Onboarding",
        "data": {
            "doc_id": "GG-WI-LOG-001",
            "version": "1.0",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "siem_platform": "Elastic SIEM (Elasticsearch 8.11 + Kibana + Elastic Agent)",
            "log_formats": "Syslog (RFC 5424), JSON (structured), CEF (ArcSight compat), Windows Event Log (via Winlogbeat/Elastic Agent), Cloud audit logs (AWS CloudTrail JSON, Azure Activity Log, GCP Audit Log)",
            "retention_days": "Hot: 30 days (NVMe) | Warm: 90 days (SSD) | Cold: 365 days (S3-backed) | Frozen: 7 years (regulatory requirement for financial data)",
        },
    },

    # =========================================================================
    # 10. SIEM Query & Investigation Work Instruction
    # =========================================================================
    10: {
        "doc_name": "GG-WI-QRY-001 - SIEM Query & Investigation",
        "data": {
            "doc_id": "GG-WI-QRY-001",
            "version": "1.0",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "siem_platform": "Elastic SIEM (Kibana 8.11)",
            "query_examples": "### Guarded Glass Custom Queries\n\n#### Detect Lateral Movement via PsExec\n```\nevent.category: \"process\" AND process.name: \"psexec.exe\" AND\nNOT process.executable: \"C:\\\\Admin\\\\Tools\\\\*\"\n```\n\n#### Identify Data Staging (Large Archive Creation)\n```\nevent.category: \"file\" AND file.extension: (\"zip\" OR \"7z\" OR \"rar\") AND\nfile.size > 104857600\n```\n\n#### Azure AD Suspicious Sign-In\n```\nevent.dataset: \"azure.signinlogs\" AND azure.signinlogs.properties.risk_level_during_signin: (\"high\" OR \"medium\") AND\nevent.outcome: \"success\"\n```\n\n#### Detect Kerberoasting\n```\nevent.code: \"4769\" AND winlog.event_data.TicketEncryptionType: \"0x17\" AND\nNOT winlog.event_data.ServiceName: \"krbtgt\"\n```\n\n#### Hunt for Cobalt Strike Beaconing\n```\nevent.category: \"network\" AND destination.port: (80 OR 443) AND\nnetwork.bytes > 0 AND network.bytes < 1000\n| stats count, avg(network.bytes) by destination.ip\n| where count > 100 AND avg_network_bytes < 500\n```",
        },
    },

    # =========================================================================
    # 11. Common Alert Types KB
    # =========================================================================
    11: {
        "doc_name": "GG-KB-ALT-001 - Common Alert Types",
        "data": {
            "doc_id": "GG-KB-ALT-001",
            "version": "1.0",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "alert_categories": "### Guarded Glass Environment-Specific Alerts\n\n#### Cloud Security\n- **AWS GuardDuty Findings**: Reconnaissance, credential compromise, data exfiltration\n- **Azure Sentinel Incidents**: Risky sign-in, impossible travel, MFA fraud alert\n- **GCP SCC Findings**: Public bucket, service account key exposure\n\n#### Endpoint (CrowdStrike)\n- **Falcon ML Detection**: Machine learning-based behavioural detection\n- **Custom IOA**: Organisation-specific indicators of attack\n- **Sensor Tamper**: Agent stop/uninstall attempts\n\n#### Identity (Azure AD)\n- **Risky Sign-In**: Sign-in from anonymous IP, leaked credentials, atypical travel\n- **Risky User**: User flagged by Identity Protection\n- **Conditional Access Failure**: Block triggered by policy\n\n#### Network (Palo Alto)\n- **Threat Prevention**: IPS signature matches\n- **WildFire Verdict**: Malicious file detected in transit\n- **URL Filtering**: Access to malicious/phishing categories\n\n#### Email (Defender for O365)\n- **ZAP (Zero-hour Auto Purge)**: Retroactive malicious email removal\n- **Safe Attachments**: Detonation verdict malicious\n- **User Reported**: Phishing reported via Report Message button",
        },
    },

    # =========================================================================
    # 12. Threat Actor Profile KB
    # =========================================================================
    12: {
        "doc_name": "GG-KB-TA-001 - Threat Actor Profile - Scattered Spider",
        "data": {
            "doc_id": "GG-KB-TA-001",
            "version": "1.0",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "actor_name": "Scattered Spider",
            "aliases": "UNC3944, Muddled Libra, Starfraud, Octo Tempest, 0ktapus",
            "motivation": "Financial - Ransomware deployment, data theft for extortion, cryptocurrency theft",
            "target_sectors": "Telecommunications, Technology, Financial Services, Business Process Outsourcing (BPO), Hospitality, Retail",
            "ttps": "| Tactic | Technique | ID | Description |\n|--------|-----------|-----|-------------|\n| Initial Access | Phishing | T1566.004 | Spearphishing via voice (vishing) targeting IT helpdesk |\n| Initial Access | Valid Accounts | T1078.004 | Abuse of cloud/SaaS credentials obtained via social engineering |\n| Persistence | MFA Manipulation | T1556.006 | SIM swapping, MFA fatigue (push bombing) |\n| Credential Access | Unsecured Credentials | T1552.001 | Credential harvesting from code repos, SharePoint |\n| Defense Evasion | Impersonation | T1656 | Impersonation of IT staff to helpdesk for password resets |\n| Lateral Movement | Remote Services | T1021.001 | RDP to cloud-hosted VMs and Citrix infrastructure |\n| Collection | Data from Cloud Storage | T1530 | Exfiltration from SharePoint, OneDrive, AWS S3 |\n| Impact | Data Encrypted for Impact | T1486 | ALPHV/BlackCat ransomware deployment |",
            "iocs": "| IOC Type | Value | First Seen | Last Seen | Confidence |\n|----------|-------|------------|-----------|------------|\n| Domain | login-okta[.]net | 2023-06 | 2025-11 | High |\n| Domain | sso-verify[.]com | 2024-01 | 2025-09 | High |\n| Tool | Tailscale VPN | 2023-08 | 2025-12 | Medium |\n| Tool | AnyDesk | 2023-06 | 2025-12 | Medium |\n| Tool | Ngrok | 2024-03 | 2025-10 | Medium |\n| Technique | IT helpdesk vishing | 2023-01 | 2025-12 | High |",
            "campaigns": "### Notable Campaigns\n\n**1. 0ktapus Campaign (2022-2023)**\nMass phishing campaign targeting Okta credentials across 130+ organisations. Used custom phishing kits mimicking Okta login pages. Over 10,000 credentials harvested.\n\n**2. MGM/Caesars Attack (Sep 2023)**\nSocial engineering of IT helpdesk led to full domain compromise. ALPHV/BlackCat ransomware deployed. Estimated $100M+ total impact.\n\n**3. Telecom Provider Compromise (2024)**\nSIM swapping attacks against telecom employees to gain access to internal tools. Used access to perform SIM swaps for high-value targets.\n\n**4. Cloud Infrastructure Targeting (2024-2025)**\nSystematic targeting of cloud-native organisations via identity provider compromise. Focus on AWS, Azure, and GCP environments. Data exfiltration from cloud storage for extortion.",
        },
    },

    # =========================================================================
    # 13. Tool Configuration Guide KB
    # =========================================================================
    13: {
        "doc_name": "GG-KB-TOOL-001 - CrowdStrike Falcon Configuration Guide",
        "data": {
            "doc_id": "GG-KB-TOOL-001",
            "version": "1.0",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "tool_name": "CrowdStrike Falcon",
            "tool_version": "7.x (Cloud-hosted, Falcon Insight XDR)",
            "purpose": "Endpoint Detection & Response (EDR) - real-time endpoint visibility, threat detection, automated response, and forensic investigation across all managed endpoints",
            "configuration_steps": "### Sensor Deployment\n\n1. Download sensor installer from Falcon Console > Host Setup\n2. Deploy via SCCM/Intune with CID: `GGLASS-XXXXXXXXX`\n3. Verify registration in Host Management within 15 minutes\n4. Assign to appropriate sensor update policy (Production/Canary)\n\n### Prevention Policies\n\n| Policy | Scope | Settings |\n|--------|-------|----------|\n| GG-Servers-Aggressive | All servers | ML: Aggressive, Sensor anti-tamper ON, Script-based execution: Block |\n| GG-Workstations-Moderate | Workstations | ML: Moderate, Sensor anti-tamper ON, USB storage: Monitor |\n| GG-VDI-Conservative | VDI/Citrix | ML: Cautious, Reduced CPU: ON, Sensor anti-tamper ON |\n\n### Detection Policies\n\n- Cloud ML: Aggressive (all host groups)\n- Sensor ML: Moderate (servers), Aggressive (workstations)\n- Custom IOA Groups: GG-Custom-IOA-v3 (applied to all)\n- MITRE ATT&CK coverage: 92% (reviewed quarterly)\n\n### Response Policies\n\n- Real-time Response: Enabled for IR team (RTR Analyst role)\n- Network Containment: Enabled (requires SOC Lead approval for activation)\n- USB Device Control: Monitor mode (servers), Block unknown (workstations)\n\n### API Integration\n\n- SIEM Integration: Falcon SIEM Connector > Elastic SIEM (streaming API)\n- SOAR Integration: Falcon API > ION (for automated containment playbooks)\n- Ticketing: Falcon > ServiceNow (bi-directional case sync)",
            "troubleshooting_items": "### Common Issues\n\n**Sensor Not Reporting**\n1. Check sensor service: `sc query CSFalconService`\n2. Verify network connectivity to `ts01-b.cloudsink.net:443`\n3. Check proxy settings: `REG QUERY HKLM\\SYSTEM\\CrowdStrike\\{...}\\Channel`\n4. Review Windows Event Log: Application > CrowdStrike Falcon Sensor\n5. If sensor is healthy but not in console: wait 15 min, then restart `CsFalconService`\n\n**High CPU Usage**\n1. Check for scan-in-progress: `CSFalconContainer` process\n2. Review exclusions - add known high-IO paths (e.g., database files, build artifacts)\n3. Verify sensor is on latest N-1 version\n4. Open support ticket if >15% sustained CPU\n\n**False Positive Detections**\n1. Document the FP in JIRA (GG-FP-XXXX)\n2. Create ML exclusion via Falcon Console > Exclusions\n3. For custom IOA FPs: adjust IOA rule logic in Detection Engineering JIRA\n4. Validate exclusion doesn't create security gap (review with SOC Lead)",
        },
    },

    # =========================================================================
    # 14. Ransomware Incident Response Plan
    # =========================================================================
    14: {
        "doc_name": "GG-IRP-RAN-001 - Ransomware Incident Response Plan",
        "data": {
            "doc_id": "GG-IRP-RAN-001",
            "version": "1.0",
            "classification": "CONFIDENTIAL",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "approved_by": "Sarah Chen, CISO",
            "ir_team_contacts": "| Role | Name | Phone | Email | Availability |\n|------|------|-------|-------|-------------|\n| IR Manager | David Okafor | +44 7700 900102 | d.okafor@guardedglass.io | 24/7 on-call |\n| Lead Forensic Analyst | Alex Richter | +44 7700 900104 | a.richter@guardedglass.io | 24/7 on-call |\n| SOC Lead (Day) | Marcus Webb | +44 7700 900100 | m.webb@guardedglass.io | 07:00-19:00 |\n| SOC Lead (Night) | Priya Sharma | +44 7700 900101 | p.sharma@guardedglass.io | 19:00-07:00 |\n| Threat Intel Lead | Lisa Park | +44 7700 900105 | l.park@guardedglass.io | Business hours |\n\n**External IR Retainer:** Mandiant (Contract #GG-IR-2025) - Hotline: +1-800-MANDIANT",
            "backup_contacts": "| Contact | Name | Phone | Email |\n|---------|------|-------|-------|\n| Backup Infrastructure Lead | Tom Harrison | +44 7700 900120 | t.harrison@guardedglass.io |\n| Cloud Platform Lead | Aisha Patel | +44 7700 900121 | a.patel@guardedglass.io |\n| DBA Lead | Min-Jun Kim | +44 7700 900122 | m.kim@guardedglass.io |\n\n**Backup Systems:**\n- On-prem: Veeam Backup & Replication (air-gapped copies every 4 hours)\n- Cloud: Azure Backup (immutable snapshots, 30-day retention)\n- Database: SQL Always On AG + daily exports to offline storage\n- RPO Target: 4 hours | RTO Target: 24 hours (Tier 1 systems)",
            "legal_contacts": "| Contact | Name | Phone | Email |\n|---------|------|-------|-------|\n| Head of Legal | Rachel Morrison | +44 7700 900110 | r.morrison@guardedglass.io |\n| Data Protection Officer | Emma Virtanen | +44 7700 900111 | e.virtanen@guardedglass.io |\n| External Counsel | Williams & Hart LLP | +44 20 7946 0958 | incident.response@williamshart.co.uk |\n| Cyber Insurance Broker | Marsh Ltd | +44 20 7357 1000 | gg-cyber-claims@marsh.com |\n\n**Cyber Insurance Policy:** Beazley CyberPlus (Policy #GG-CYB-2025-001, Coverage: GBP 10M)",
        },
    },

    # =========================================================================
    # 15. Data Breach Response Plan
    # =========================================================================
    15: {
        "doc_name": "GG-IRP-DBR-001 - Data Breach Response Plan",
        "data": {
            "doc_id": "GG-IRP-DBR-001",
            "version": "1.0",
            "classification": "CONFIDENTIAL",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "approved_by": "Sarah Chen, CISO & Rachel Morrison, Head of Legal",
            "dpo_contact": "Emma Virtanen - e.virtanen@guardedglass.io - +44 7700 900111 (24/7 for P1 breaches)",
            "legal_contacts": "| Contact | Role | Phone | Email |\n|---------|------|-------|-------|\n| Rachel Morrison | Head of Legal | +44 7700 900110 | r.morrison@guardedglass.io |\n| Emma Virtanen | DPO | +44 7700 900111 | e.virtanen@guardedglass.io |\n| Williams & Hart LLP | External Counsel | +44 20 7946 0958 | breach.response@williamshart.co.uk |\n| Marsh Ltd | Cyber Insurance | +44 20 7357 1000 | gg-cyber-claims@marsh.com |",
            "notification_requirements": "### Guarded Glass Notification Obligations\n\n| Regulation | Jurisdiction | Timeline | Authority | Threshold |\n|-----------|-------------|----------|-----------|----------|\n| UK GDPR / DPA 2018 | United Kingdom | 72 hours | ICO (ico.org.uk) | Risk to individuals |\n| EU GDPR | European Union | 72 hours | Lead SA (Ireland DPC) | Risk to individuals |\n| NIS2 Directive | EU Member States | 24hr early warning, 72hr notification | National CSIRT | Significant impact on service |\n| FCA Requirements | UK (Financial) | Immediately | FCA via RegData | Material cyber incidents |\n| PCI DSS 4.0 | Global (Card data) | Immediately | Acquirer + Card brands | Cardholder data |\n| Contractual (Enterprise) | Per contract | Varies (24-72hr typical) | Customer CISO/DPO | Per contract terms |\n\n**Key ICO Contact:** casework@ico.org.uk | +44 0303 123 1113\n**Ireland DPC:** info@dataprotection.ie | +353 1 765 0100",
        },
    },

    # =========================================================================
    # 16. Post-Incident After-Action Report
    # =========================================================================
    16: {
        "doc_name": "GG-AAR-2026-001 - BEC Compromise After-Action Report",
        "data": {
            "doc_id": "GG-AAR-2026-001",
            "version": "1.0",
            "classification": "CONFIDENTIAL",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "incident_id": "INC-2026-0142",
            "incident_title": "Business Email Compromise - CFO Impersonation",
            "incident_date": "2026-01-28 09:15 UTC",
            "resolution_date": "2026-01-29 16:00 UTC",
            "severity": "P2 - High",
            "lead_analyst": "Marcus Webb",
            "participants": "David Okafor (IR Manager), Marcus Webb (SOC Lead), Lisa Park (L2 Analyst), Priya Sharma (L2 Analyst), Tom Harrison (IT Ops), Rachel Morrison (Legal), Claire Edwards (Finance Director)",
            "executive_summary": "On 28 January 2026, the SOC detected a business email compromise (BEC) incident involving the impersonation of the CFO's email account. The threat actor gained access via a spearphishing email targeting the CFO's executive assistant, which delivered a credential harvesting page mimicking the Microsoft 365 login portal. Using the compromised credentials, the attacker created an inbox rule to forward emails containing keywords ('payment', 'transfer', 'invoice') to an external address. The attacker then sent a fraudulent wire transfer request to the Finance team for GBP 847,000. The Finance team flagged the request as suspicious due to the unusual approval workflow, and the SOC was notified. The transfer was blocked before execution. Total financial loss: GBP 0. The compromised account was remediated within 6 hours of detection.",
            "timeline_events": "| Date/Time (UTC) | Event | Actor | Notes |\n|-----------|-------|-------|-------|\n| Jan 27, 14:22 | Spearphishing email received by EA | Threat Actor | Mimicked DocuSign notification |\n| Jan 27, 14:35 | EA clicked link, entered credentials | Victim | Credential harvesting page (login-m365[.]net) |\n| Jan 27, 15:01 | Attacker logged in from VPN (NL) | Threat Actor | IP: 185.220.101[.]42 |\n| Jan 27, 15:08 | Inbox rule created (forward to external) | Threat Actor | Rule: 'Auto-Forward-Archive' |\n| Jan 27, 15:12 | Attacker read CFO email thread re: Q1 payments | Threat Actor | Reconnaissance |\n| Jan 28, 09:15 | Fraudulent wire transfer request sent | Threat Actor | GBP 847,000 to Barclays account |\n| Jan 28, 09:45 | Finance flags request as suspicious | Finance Team | Unusual approval workflow |\n| Jan 28, 10:00 | SOC notified, investigation begins | SOC (M. Webb) | Alert created: INC-2026-0142 |\n| Jan 28, 10:30 | Compromised account identified, session revoked | SOC | Azure AD: revoke all sessions |\n| Jan 28, 10:45 | Inbox rule removed, password reset | SOC + IT | MFA re-enrolled |\n| Jan 28, 11:00 | Phishing URL blocked org-wide | SOC | Umbrella + Defender block |\n| Jan 29, 16:00 | Incident closed after 24hr monitoring | IR Manager | No further suspicious activity |",
            "findings": "### Key Findings\n\n1. **Initial access via spearphishing**: The attacker used a convincing DocuSign-themed phishing email. The URL was not blocked by email security as the domain was newly registered (<24 hours old).\n\n2. **MFA bypass**: The EA's account had MFA enabled but the phishing page was an adversary-in-the-middle (AiTM) proxy that captured the session token, bypassing MFA.\n\n3. **Inbox rule persistence**: The attacker created a mail rule within 7 minutes of access. Current monitoring did not alert on inbox rule creation.\n\n4. **Detection gap**: The initial compromise on Jan 27 was not detected for ~19 hours. Detection only occurred because Finance flagged the fraudulent request.\n\n5. **Positive finding**: Finance team's adherence to dual-approval process for transfers >GBP 50,000 prevented financial loss.",
            "recommendations": "| # | Recommendation | Priority | Owner | Deadline | Status |\n|---|---------------|----------|-------|----------|--------|\n| 1 | Deploy phishing-resistant MFA (FIDO2/passkeys) for all executives and EAs | Critical | IT Security | 2026-03-01 | In Progress |\n| 2 | Create detection rule for inbox rule creation/modification | High | Detection Eng | 2026-02-15 | Pending |\n| 3 | Implement Conditional Access policy blocking sign-in from non-managed devices for privileged users | High | IT Security | 2026-02-28 | Pending |\n| 4 | Enhance email security with anti-AiTM capabilities (token binding) | High | IT Security | 2026-03-15 | Pending |\n| 5 | Targeted BEC awareness training for Finance and Executive teams | Medium | Security Awareness | 2026-02-28 | Pending |\n| 6 | Review and reduce email forwarding rules org-wide | Medium | IT Ops | 2026-02-28 | Pending |",
        },
    },

    # =========================================================================
    # 17. Threat Advisory
    # =========================================================================
    17: {
        "doc_name": "GG-TA-2026-003 - Critical Ivanti Connect Secure Exploitation",
        "data": {
            "doc_id": "GG-TA-2026-003",
            "version": "1.0",
            "classification": "TLP:AMBER",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "advisory_title": "Active Exploitation of Ivanti Connect Secure Zero-Day (CVE-2026-XXXX)",
            "severity": "CRITICAL",
            "date_issued": "2026-02-10",
            "tlp_level": "TLP:AMBER",
            "affected_systems": "- Ivanti Connect Secure (ICS) versions 9.x and 22.x\n- Ivanti Policy Secure versions 9.x and 22.x\n- Ivanti Neurons for ZTA gateways\n\n**Guarded Glass Exposure:** 2x Ivanti Connect Secure appliances (ICS-GW-01, ICS-GW-02) running version 22.7R2.3 - VULNERABLE\n\n**Business Impact:** These appliances provide VPN access for 340 remote workers including executives and privileged administrators.",
            "threat_description": "A critical authentication bypass vulnerability has been identified in Ivanti Connect Secure, currently under active exploitation by multiple threat actors including a suspected Chinese state-sponsored group (UNC5337). The vulnerability allows unauthenticated remote code execution via a crafted HTTP request to the web management interface. Exploitation has been observed in the wild since approximately 2026-02-05.\n\nThe vulnerability exists in the SAML authentication component and does not require valid credentials. Successful exploitation grants the attacker root-level access to the appliance, enabling credential theft, network pivoting, and persistent backdoor installation.\n\nCISA has added this to the Known Exploited Vulnerabilities (KEV) catalog with a remediation deadline of 2026-02-17.",
            "iocs": "| IOC Type | Value | Context |\n|----------|-------|--------|\n| IP | 45.77.121[.]176 | C2 server observed in exploitation |\n| IP | 185.174.101[.]42 | Scanner/exploitation infrastructure |\n| IP | 103.75.190[.]11 | Post-exploitation C2 |\n| Domain | update-ivanti[.]com | Fake update domain (credential theft) |\n| Hash (SHA256) | a1b2c3d4e5f6...deadbeef | WIREFIRE webshell variant |\n| Hash (SHA256) | f7e8d9c0b1a2...cafebabe | LIGHTWIRE backdoor |\n| File Path | /home/perl/DSLogConfig.pm | Webshell location |\n| File Path | /tmp/.session_cache | Credential dump staging |\n| User-Agent | Mozilla/5.0 (compatible; MSIE 10.0) | Exploitation user-agent string |",
            "mitre_techniques": "| Tactic | Technique | ID | Description |\n|--------|-----------|-----|-------------|\n| Initial Access | Exploit Public-Facing Application | T1190 | Authentication bypass in Ivanti ICS |\n| Execution | Command and Scripting Interpreter | T1059.004 | Unix shell commands via webshell |\n| Persistence | Server Software Component: Web Shell | T1505.003 | WIREFIRE/LIGHTWIRE webshells |\n| Credential Access | OS Credential Dumping | T1003 | Extraction of cached VPN credentials |\n| Defense Evasion | Indicator Removal | T1070 | Log tampering on Ivanti appliance |\n| Lateral Movement | Remote Services: VPN | T1133 | Pivot into internal network via stolen VPN creds |\n| Collection | Data from Configuration Repository | T1602 | Extraction of appliance config including secrets |",
            "mitigations": "### Immediate Actions (Within 24 Hours)\n\n1. **Apply Ivanti mitigation XML** (published 2026-02-09) to both ICS-GW-01 and ICS-GW-02\n2. **Run Ivanti Integrity Checker Tool (ICT)** on both appliances - compare against known-good baseline\n3. **Review VPN authentication logs** for anomalous logins since 2026-02-01\n4. **Block IOC IPs** listed above at perimeter firewall (Panorama)\n5. **Reset all VPN user credentials** as a precaution (coordinate with IT Ops)\n6. **Enable enhanced logging** on Ivanti appliances (syslog to Elastic SIEM)\n\n### Long-term Recommendations\n\n1. **Apply full patch** when released by Ivanti (expected 2026-02-14)\n2. **Factory reset appliances** after patching (Ivanti recommended practice for zero-days)\n3. **Evaluate migration** to ZTNA solution (e.g., Zscaler ZPA, Cloudflare Access) to reduce VPN attack surface\n4. **Implement network segmentation** - VPN appliances should not have direct access to Tier 1 assets\n5. **Deploy detection rules** for webshell activity and anomalous VPN behaviour (see Detection Engineering)",
        },
    },

    # =========================================================================
    # 18. Detection Rule Documentation
    # =========================================================================
    18: {
        "doc_name": "GG-DET-001 - Kerberoasting Detection Rule",
        "data": {
            "doc_id": "GG-DET-001",
            "version": "1.0",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "rule_name": "Kerberoasting - RC4 Service Ticket Request",
            "rule_id": "GG-RULE-2026-0042",
            "severity": "high",
            "mitre_technique": "T1558.003 - Kerberoasting",
            "mitre_tactic": "Credential Access",
            "data_sources": "Windows Security Event Log (Event ID 4769) via Elastic Agent / Winlogbeat. Required on all Domain Controllers.",
            "detection_logic": "This rule detects Kerberos service ticket (TGS) requests using RC4 encryption (encryption type 0x17), which is the encryption type targeted by Kerberoasting attacks. Legitimate TGS requests in a modern AD environment should predominantly use AES-256 (0x12). RC4 requests for service accounts (excluding krbtgt and machine accounts) are flagged as suspicious.\n\n**Logic:**\n- Event ID 4769 (Kerberos Service Ticket Operation)\n- Ticket Encryption Type = 0x17 (RC4-HMAC)\n- Service Name does NOT end with '$' (excludes machine accounts)\n- Service Name is NOT 'krbtgt'\n- Threshold: 3+ RC4 TGS requests from same source within 5 minutes",
            "query": "event.code: \"4769\" AND\nwinlog.event_data.TicketEncryptionType: \"0x17\" AND\nNOT winlog.event_data.ServiceName: \"krbtgt\" AND\nNOT winlog.event_data.ServiceName: /.+\\$$/\n\n/* Threshold: Alert when count >= 3 from same source in 5 min window */\n/* Elastic Detection Rule: Threshold rule, group by source.ip, threshold >= 3, window 5m */",
            "false_positive_rate": "Low-Medium (estimated 2-5 FP/week in our environment)",
            "test_cases": "### Test Cases\n\n**TC-1: True Positive - Rubeus Kerberoasting**\n1. From a domain-joined Windows workstation, run: `Rubeus.exe kerberoast /rc4opsec`\n2. Expected: Alert generated within 5 minutes\n3. Verify: Source IP, target service accounts captured correctly\n\n**TC-2: True Positive - Impacket GetUserSPNs**\n1. From Linux attack machine: `GetUserSPNs.py DOMAIN/user:password -dc-ip DC_IP -request`\n2. Expected: Alert generated, source IP is Linux machine\n\n**TC-3: Benign Activity (No Alert)**\n1. Normal user authenticates to SQL Server (AES ticket)\n2. Expected: No alert - encryption type should be 0x12\n\n**TC-4: Below Threshold (No Alert)**\n1. Single RC4 TGS request from legacy application\n2. Expected: No alert - below threshold of 3\n\n### Known Exceptions\n\n| Exception | Reason | Exclusion |\n|-----------|--------|----------|\n| SVC-LEGACYAPP | Legacy app requires RC4 | Exclude ServiceName: 'SVC-LEGACYAPP' |\n| 10.50.1.100 | Legacy print server | Exclude source.ip: '10.50.1.100' |",
        },
    },

    # =========================================================================
    # 19. Operational Runbook
    # =========================================================================
    19: {
        "doc_name": "GG-RB-001 - CrowdStrike Network Containment Runbook",
        "data": {
            "doc_id": "GG-RB-001",
            "version": "1.0",
            "author": "Tomo Tomkins, Level 3 Technical Analyst",
            "runbook_title": "CrowdStrike Falcon Network Containment - Isolate Compromised Endpoint",
            "trigger_conditions": "Execute this runbook when ANY of the following conditions are met:\n\n1. **Confirmed malware execution** on endpoint (CrowdStrike severity Critical/High)\n2. **Active C2 beaconing** detected from endpoint (confirmed by L2+ analyst)\n3. **Ransomware indicators** observed (file encryption behaviour, ransom note creation)\n4. **Compromised credentials** used from the endpoint (confirmed lateral movement)\n5. **IR Manager directive** to isolate a specific host during incident response\n\n**DO NOT contain** without SOC Lead or IR Manager approval unless conditions 1 or 3 are met (auto-containment approved for these scenarios).",
            "prerequisites": "### Access Requirements\n- CrowdStrike Falcon console access (RTR Analyst role or above)\n- ServiceNow access (for CHG ticket)\n- Teams/Slack access (for SOC channel notification)\n\n### Pre-Containment Checks\n- [ ] Confirm the endpoint hostname and Falcon AID\n- [ ] Verify the endpoint is NOT a domain controller, DNS server, or Tier 1 critical system\n- [ ] If Tier 1 system: STOP - escalate to IR Manager for manual containment decision\n- [ ] Notify the asset owner (if known) that containment is imminent\n- [ ] Document the justification in the incident ticket",
            "procedure_steps": "| Step | Action | Expected Result | Verification |\n|------|--------|----------------|---------------|\n| 1 | Open Falcon Console > Host Management > search for hostname | Host details displayed with sensor status 'Online' | Sensor last seen < 5 minutes ago |\n| 2 | Click 'Network Containment' > 'Contain Host' | Confirmation dialog appears | Review hostname matches target |\n| 3 | Confirm containment action | Status changes to 'Contained' | Green 'Contained' badge appears |\n| 4 | Verify containment via RTR: `netstat -an` | Only CrowdStrike cloud IPs in ESTABLISHED state | No non-CS connections active |\n| 5 | Create ServiceNow INC ticket documenting containment | Ticket number generated | Link ticket to parent incident |\n| 6 | Post notification to #soc-operations channel | Team notified | Acknowledge from SOC Lead |\n| 7 | Begin evidence collection via RTR if required | Memory dump / triage package collected | Files uploaded to evidence store |\n| 8 | Update incident ticket with containment timestamp | Incident timeline updated | Containment time recorded |",
            "rollback_steps": "### Lift Containment (Un-contain)\n\n**Approval Required:** SOC Lead or IR Manager must approve before lifting containment.\n\n1. Confirm remediation actions are complete (malware removed, credentials reset, patches applied)\n2. Open Falcon Console > Host Management > search for contained host\n3. Click 'Lift Containment'\n4. Verify network connectivity is restored: `ping 10.0.0.1` (default gateway) via RTR\n5. Monitor endpoint for 24 hours for re-infection indicators\n6. Update incident ticket with un-containment timestamp and approver\n7. Close ServiceNow CHG ticket",
            "escalation_contacts": "| Condition | Escalate To | Method |\n|-----------|------------|--------|\n| Tier 1 system needs containment | IR Manager (David Okafor) | Phone + Teams |\n| Containment fails (sensor offline) | IT Ops (network team) for switch port shutdown | Phone |\n| Multiple hosts need containment (>5) | IR Manager + CISO | Bridge call |\n| VIP/executive endpoint | IR Manager + SOC Manager | Phone |\n| Containment causes business impact | SOC Manager + IT Ops Lead | Teams |",
            "success_criteria": "### Containment Verified When:\n\n- [ ] Falcon console shows host status as 'Contained'\n- [ ] RTR `netstat` shows only CrowdStrike cloud connections\n- [ ] No new alert activity from the contained host\n- [ ] Incident ticket updated with containment details\n- [ ] SOC team notified via operations channel\n- [ ] Asset owner notified (if business hours)\n\n### Metrics to Record:\n- Time from detection to containment decision\n- Time from decision to containment execution\n- Total containment duration\n- Business impact (if any)",
        },
    },
}


def main():
    s = requests.Session()

    # Login
    r = s.post(f"{BASE}/api/auth/login", json={"username": "admin", "password": "admin2025"})
    if r.status_code != 200:
        print(f"Login failed: {r.status_code}")
        sys.exit(1)
    print("Logged in successfully\n")

    rendered = 0
    errors = 0

    for template_id, config in sorted(RENDER_DATA.items()):
        doc_name = config["doc_name"]
        data = config["data"]

        r = s.post(
            f"{BASE}/api/templates/{template_id}/render",
            params={"document_name": doc_name},
            json={"data": data},
        )

        if r.status_code == 200:
            result = r.json()
            doc_id = result.get("document_id")
            print(f"  [{template_id:2d}] {doc_name} -> Document #{doc_id}")
            rendered += 1
        else:
            print(f"  [{template_id:2d}] FAILED: {r.status_code} - {r.text[:200]}")
            errors += 1

    print(f"\nDone: {rendered} documents rendered, {errors} errors")


if __name__ == "__main__":
    main()
