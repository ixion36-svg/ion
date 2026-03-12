"""Seed forensic investigation playbooks with structured fields."""

import requests
import json
import sys

BASE = "http://127.0.0.1:8000"

PLAYBOOKS = [
    {
        "name": "Malware Analysis Investigation",
        "description": "Structured investigation playbook for malware incidents — covers triage, evidence collection, static/dynamic analysis, and remediation.",
        "investigation_type": "malware_analysis",
        "steps": [
            {
                "title": "Initial Triage & Scoping",
                "description": "Assess the scope of the malware incident, identify affected systems, and classify initial severity.",
                "is_required": True,
                "expected_duration_hours": 2,
                "fields": [
                    {"key": "affected_hosts", "label": "Affected Hosts", "type": "list", "placeholder": "hostname or IP"},
                    {"key": "affected_users", "label": "Affected Users", "type": "list", "placeholder": "username"},
                    {"key": "alert_source", "label": "Alert Source", "type": "select", "options": ["EDR", "AV", "SIEM", "IDS/IPS", "User Report", "Email Gateway", "Threat Intel", "Other"]},
                    {"key": "initial_severity", "label": "Initial Severity Assessment", "type": "select", "options": ["Critical", "High", "Medium", "Low"]},
                    {"key": "containment_status", "label": "Containment Status", "type": "select", "options": ["Not Contained", "Partially Contained", "Fully Contained", "Not Required"]},
                    {"key": "isolated_hosts", "label": "Isolated from Network", "type": "checkbox"},
                ]
            },
            {
                "title": "Evidence Collection",
                "description": "Collect forensic images, memory dumps, and relevant logs from affected systems. Use write-blockers for disk imaging.",
                "is_required": True,
                "expected_duration_hours": 4,
                "fields": [
                    {"key": "disk_images", "label": "Disk Images Collected", "type": "table", "columns": ["Host", "Image Path", "Size (GB)", "SHA-256"]},
                    {"key": "memory_dumps", "label": "Memory Dumps", "type": "table", "columns": ["Host", "Dump Path", "Size (GB)", "SHA-256"]},
                    {"key": "network_captures", "label": "Network Captures (PCAP)", "type": "list", "placeholder": "capture file path"},
                    {"key": "log_sources", "label": "Logs Collected", "type": "list", "placeholder": "e.g. Windows Event Logs, Sysmon, EDR telemetry"},
                    {"key": "evidence_storage", "label": "Evidence Storage Location", "type": "text", "placeholder": "Secure evidence locker / NAS path"},
                ]
            },
            {
                "title": "Static Analysis",
                "description": "Examine malware samples without execution — file hashes, strings, imports, PE headers, packer identification.",
                "is_required": True,
                "expected_duration_hours": 4,
                "fields": [
                    {"key": "sample_hashes", "label": "Sample Hashes", "type": "table", "columns": ["Filename", "MD5", "SHA-256"]},
                    {"key": "malware_family", "label": "Malware Family / Variant", "type": "text", "placeholder": "e.g. Emotet Epoch 5, QakBot, Cobalt Strike"},
                    {"key": "file_type", "label": "File Type", "type": "select", "options": ["PE Executable", "DLL", "Script (PS/VBS/JS)", "Office Macro", "PDF", "ELF Binary", "JAR/Java", "Other"]},
                    {"key": "packer_detected", "label": "Packer / Obfuscation", "type": "text", "placeholder": "e.g. UPX, Themida, custom, none"},
                    {"key": "suspicious_strings", "label": "Strings of Interest", "type": "list", "placeholder": "URLs, IPs, registry keys, C2 patterns"},
                    {"key": "suspicious_imports", "label": "Suspicious Imports", "type": "list", "placeholder": "e.g. VirtualAlloc, CreateRemoteThread, URLDownloadToFile"},
                    {"key": "vt_detection_ratio", "label": "VirusTotal Detection Ratio", "type": "text", "placeholder": "e.g. 48/72"},
                ]
            },
            {
                "title": "Dynamic Analysis",
                "description": "Execute sample in isolated sandbox and document runtime behavior, network IOCs, and persistence mechanisms.",
                "is_required": False,
                "expected_duration_hours": 6,
                "fields": [
                    {"key": "sandbox_env", "label": "Sandbox Environment", "type": "text", "placeholder": "e.g. FlareVM, REMnux, Any.Run, Joe Sandbox"},
                    {"key": "c2_servers", "label": "C2 Servers Identified", "type": "table", "columns": ["IP/Domain", "Port", "Protocol", "Status"]},
                    {"key": "dns_queries", "label": "DNS Queries", "type": "list", "placeholder": "suspicious domain queried"},
                    {"key": "files_created", "label": "Files Created / Modified", "type": "list", "placeholder": "file path"},
                    {"key": "registry_changes", "label": "Registry Modifications", "type": "list", "placeholder": "registry key and value"},
                    {"key": "persistence_mechanisms", "label": "Persistence Mechanisms", "type": "list", "placeholder": "e.g. Scheduled Task, Run key, Service"},
                    {"key": "processes_spawned", "label": "Processes Spawned", "type": "list", "placeholder": "process name / command line"},
                    {"key": "network_iocs", "label": "Network IOCs", "type": "table", "columns": ["Type", "Value", "Context"]},
                ]
            },
            {
                "title": "MITRE ATT&CK Mapping",
                "description": "Map observed behaviors to MITRE ATT&CK techniques for standardized reporting and detection engineering.",
                "is_required": False,
                "expected_duration_hours": 1,
                "fields": [
                    {"key": "techniques", "label": "ATT&CK Techniques", "type": "table", "columns": ["Technique ID", "Technique Name", "Tactic", "Evidence"]},
                ]
            },
            {
                "title": "Remediation & Recommendations",
                "description": "Document containment actions taken, eradication steps, and recommendations for preventing recurrence.",
                "is_required": True,
                "expected_duration_hours": 3,
                "fields": [
                    {"key": "containment_actions", "label": "Containment Actions Taken", "type": "list", "placeholder": "action taken"},
                    {"key": "eradication_steps", "label": "Eradication Steps", "type": "list", "placeholder": "step performed"},
                    {"key": "detection_rules", "label": "Detection Rules Created", "type": "table", "columns": ["Rule Type", "Rule Name", "Description"]},
                    {"key": "blocklist_entries", "label": "Blocklist Entries", "type": "table", "columns": ["Type", "Value", "Scope"]},
                    {"key": "recovery_complete", "label": "Recovery Complete", "type": "checkbox"},
                    {"key": "user_awareness", "label": "User Awareness Needed", "type": "checkbox"},
                ]
            },
        ]
    },
    {
        "name": "Insider Threat Investigation",
        "description": "Structured playbook for investigating potential insider threats — covers subject profiling, activity review, data exfiltration analysis, and HR coordination.",
        "investigation_type": "insider_threat",
        "steps": [
            {
                "title": "Subject Identification & Background",
                "description": "Document the subject of the investigation and their organizational context. Coordinate with HR and Legal before proceeding.",
                "is_required": True,
                "expected_duration_hours": 2,
                "fields": [
                    {"key": "subject_name", "label": "Subject Name", "type": "text", "placeholder": "Full name"},
                    {"key": "employee_id", "label": "Employee ID", "type": "text"},
                    {"key": "department", "label": "Department", "type": "text"},
                    {"key": "job_title", "label": "Job Title", "type": "text"},
                    {"key": "access_level", "label": "Access Level", "type": "select", "options": ["Standard User", "Privileged User", "Admin", "Third Party / Contractor"]},
                    {"key": "hr_notified", "label": "HR Notified", "type": "checkbox"},
                    {"key": "legal_notified", "label": "Legal Notified", "type": "checkbox"},
                    {"key": "prior_incidents", "label": "Prior Incidents / Red Flags", "type": "list", "placeholder": "prior incident or concern"},
                ]
            },
            {
                "title": "Access & Activity Review",
                "description": "Review authentication logs, VPN access, file access patterns, and system activity for anomalous behavior.",
                "is_required": True,
                "expected_duration_hours": 8,
                "fields": [
                    {"key": "suspicious_logins", "label": "Suspicious Login Activity", "type": "table", "columns": ["Date/Time", "Source IP", "Location", "Status"]},
                    {"key": "vpn_sessions", "label": "VPN Sessions (Off-Hours)", "type": "table", "columns": ["Date/Time", "Duration", "Source IP", "Data Volume"]},
                    {"key": "privileged_actions", "label": "Privileged Actions", "type": "list", "placeholder": "e.g. elevated access, policy change, account creation"},
                    {"key": "accessed_resources", "label": "Sensitive Resources Accessed", "type": "table", "columns": ["Date/Time", "Resource", "Action", "Volume"]},
                    {"key": "timeframe_start", "label": "Review Period Start", "type": "text", "placeholder": "YYYY-MM-DD"},
                    {"key": "timeframe_end", "label": "Review Period End", "type": "text", "placeholder": "YYYY-MM-DD"},
                ]
            },
            {
                "title": "Data Exfiltration Analysis",
                "description": "Investigate potential data exfiltration via email, USB, cloud storage, web uploads, or print.",
                "is_required": True,
                "expected_duration_hours": 6,
                "fields": [
                    {"key": "email_exfil", "label": "Email Exfiltration", "type": "table", "columns": ["Date/Time", "Recipient", "Subject", "Attachment Size"]},
                    {"key": "usb_activity", "label": "USB Device Activity", "type": "table", "columns": ["Date/Time", "Device", "Files Copied", "Volume"]},
                    {"key": "cloud_uploads", "label": "Cloud Storage Uploads", "type": "table", "columns": ["Date/Time", "Service", "Files", "Volume"]},
                    {"key": "print_activity", "label": "Print Jobs (Sensitive Docs)", "type": "list", "placeholder": "document name / date"},
                    {"key": "data_classification", "label": "Data Classification of Exfiltrated Material", "type": "select", "options": ["Public", "Internal", "Confidential", "Restricted", "Unknown"]},
                    {"key": "estimated_volume", "label": "Estimated Total Data Volume", "type": "text", "placeholder": "e.g. 2.3 GB"},
                ]
            },
            {
                "title": "Digital Forensics (if warranted)",
                "description": "If physical device examination is authorized, collect and analyze the subject's workstation, mobile device, or other equipment.",
                "is_required": False,
                "expected_duration_hours": 8,
                "fields": [
                    {"key": "devices_collected", "label": "Devices Collected", "type": "table", "columns": ["Device", "Serial Number", "Collected By", "SHA-256"]},
                    {"key": "deleted_files", "label": "Recovered Deleted Files", "type": "list", "placeholder": "filename / path"},
                    {"key": "browser_history", "label": "Browser History of Interest", "type": "list", "placeholder": "URL / timestamp"},
                    {"key": "installed_software", "label": "Unauthorized Software Found", "type": "list", "placeholder": "software name"},
                ]
            },
            {
                "title": "Findings & Recommendations",
                "description": "Summarize findings, assess impact, and provide recommendations to HR/Legal/Management.",
                "is_required": True,
                "expected_duration_hours": 4,
                "fields": [
                    {"key": "finding_classification", "label": "Finding Classification", "type": "select", "options": ["Confirmed Malicious", "Likely Malicious", "Policy Violation", "Negligence", "False Positive / No Finding"]},
                    {"key": "data_impact", "label": "Data Impact Assessment", "type": "select", "options": ["No Data Loss", "Limited Exposure", "Significant Exposure", "Major Breach"]},
                    {"key": "recommended_actions", "label": "Recommended Actions", "type": "list", "placeholder": "e.g. terminate access, legal action, retraining"},
                    {"key": "access_revoked", "label": "Access Revoked", "type": "checkbox"},
                ]
            },
        ]
    },
    {
        "name": "Data Breach Response",
        "description": "Urgent response playbook for confirmed or suspected data breaches — covers scoping, notification requirements, and regulatory compliance.",
        "investigation_type": "data_breach",
        "steps": [
            {
                "title": "Breach Scoping & Classification",
                "description": "Determine the scope, type, and severity of the data breach. Identify what data was exposed and how many records are affected.",
                "is_required": True,
                "expected_duration_hours": 2,
                "fields": [
                    {"key": "breach_type", "label": "Breach Type", "type": "select", "options": ["Unauthorized Access", "Data Exfiltration", "Accidental Exposure", "Ransomware/Encryption", "Physical Theft", "Third-Party Compromise"]},
                    {"key": "data_types", "label": "Data Types Exposed", "type": "list", "placeholder": "e.g. PII, PHI, financial, credentials, IP"},
                    {"key": "records_affected", "label": "Estimated Records Affected", "type": "text", "placeholder": "number"},
                    {"key": "individuals_affected", "label": "Individuals Affected", "type": "text", "placeholder": "number"},
                    {"key": "affected_systems", "label": "Affected Systems / Databases", "type": "list", "placeholder": "system name"},
                    {"key": "date_of_breach", "label": "Estimated Date of Breach", "type": "text", "placeholder": "YYYY-MM-DD"},
                    {"key": "date_discovered", "label": "Date Discovered", "type": "text", "placeholder": "YYYY-MM-DD"},
                    {"key": "discovery_method", "label": "How Was It Discovered?", "type": "select", "options": ["Internal Monitoring", "Security Alert", "Employee Report", "Customer Report", "Third Party Notification", "Law Enforcement", "Public Disclosure"]},
                ]
            },
            {
                "title": "Containment & Eradication",
                "description": "Stop the breach from continuing. Contain the threat actor, patch vulnerabilities, and prevent further data loss.",
                "is_required": True,
                "expected_duration_hours": 4,
                "fields": [
                    {"key": "containment_actions", "label": "Containment Actions", "type": "list", "placeholder": "action taken with timestamp"},
                    {"key": "credentials_reset", "label": "Compromised Credentials Reset", "type": "checkbox"},
                    {"key": "vulnerability_patched", "label": "Vulnerability Patched", "type": "checkbox"},
                    {"key": "threat_actor_blocked", "label": "Threat Actor Blocked", "type": "checkbox"},
                    {"key": "affected_ips", "label": "Threat Actor IPs Blocked", "type": "list", "placeholder": "IP address"},
                    {"key": "breach_stopped_at", "label": "Breach Confirmed Stopped At", "type": "text", "placeholder": "YYYY-MM-DD HH:MM UTC"},
                ]
            },
            {
                "title": "Regulatory & Notification Assessment",
                "description": "Determine notification obligations under applicable regulations (GDPR, CCPA, HIPAA, state laws, contractual obligations).",
                "is_required": True,
                "expected_duration_hours": 4,
                "fields": [
                    {"key": "applicable_regulations", "label": "Applicable Regulations", "type": "list", "placeholder": "e.g. GDPR Art. 33, CCPA, HIPAA, PCI-DSS"},
                    {"key": "notification_required", "label": "Notification Required", "type": "checkbox"},
                    {"key": "notification_deadline", "label": "Notification Deadline", "type": "text", "placeholder": "YYYY-MM-DD (e.g. 72h for GDPR)"},
                    {"key": "dpa_notification", "label": "Data Protection Authority Notified", "type": "checkbox"},
                    {"key": "affected_notified", "label": "Affected Individuals Notified", "type": "checkbox"},
                    {"key": "legal_counsel", "label": "Legal Counsel Engaged", "type": "checkbox"},
                    {"key": "insurance_notified", "label": "Cyber Insurance Carrier Notified", "type": "checkbox"},
                ]
            },
            {
                "title": "Forensic Analysis",
                "description": "Conduct technical forensic analysis to determine root cause, attack vector, and full extent of compromise.",
                "is_required": True,
                "expected_duration_hours": 12,
                "fields": [
                    {"key": "attack_vector", "label": "Initial Attack Vector", "type": "select", "options": ["Phishing", "Credential Compromise", "Vulnerability Exploit", "Misconfiguration", "Insider", "Supply Chain", "Physical Access", "Unknown"]},
                    {"key": "iocs", "label": "Indicators of Compromise", "type": "table", "columns": ["Type", "Value", "Context"]},
                    {"key": "lateral_movement", "label": "Lateral Movement Path", "type": "list", "placeholder": "system-to-system hop"},
                    {"key": "data_access_log", "label": "Data Access Evidence", "type": "table", "columns": ["Date/Time", "Actor", "Data Accessed", "Method"]},
                    {"key": "root_cause", "label": "Root Cause Summary", "type": "textarea"},
                ]
            },
            {
                "title": "Remediation & Lessons Learned",
                "description": "Document all remediation actions and lessons learned. Update security controls to prevent recurrence.",
                "is_required": True,
                "expected_duration_hours": 4,
                "fields": [
                    {"key": "remediation_actions", "label": "Remediation Actions Completed", "type": "list", "placeholder": "action taken"},
                    {"key": "security_improvements", "label": "Security Improvements Implemented", "type": "list", "placeholder": "improvement"},
                    {"key": "monitoring_enhanced", "label": "Monitoring Enhanced", "type": "checkbox"},
                    {"key": "policies_updated", "label": "Policies/Procedures Updated", "type": "checkbox"},
                    {"key": "staff_trained", "label": "Staff Retrained", "type": "checkbox"},
                ]
            },
        ]
    },
    {
        "name": "Unauthorized Access Investigation",
        "description": "Playbook for investigating unauthorized access to systems, accounts, or data — covers access analysis, scope determination, and remediation.",
        "investigation_type": "unauthorized_access",
        "steps": [
            {
                "title": "Access Event Analysis",
                "description": "Analyze the unauthorized access event — identify the actor, method, and initial scope.",
                "is_required": True,
                "expected_duration_hours": 2,
                "fields": [
                    {"key": "target_accounts", "label": "Target Accounts", "type": "list", "placeholder": "username or service account"},
                    {"key": "target_systems", "label": "Target Systems", "type": "list", "placeholder": "hostname or IP"},
                    {"key": "access_method", "label": "Access Method", "type": "select", "options": ["Stolen Credentials", "Brute Force", "Credential Stuffing", "Session Hijacking", "Token Theft", "Privilege Escalation", "SSH Key Compromise", "API Key Compromise", "Other"]},
                    {"key": "source_ips", "label": "Source IP Addresses", "type": "list", "placeholder": "IP address"},
                    {"key": "geolocation", "label": "Source Geolocation", "type": "list", "placeholder": "city, country"},
                    {"key": "first_seen", "label": "First Unauthorized Access", "type": "text", "placeholder": "YYYY-MM-DD HH:MM UTC"},
                    {"key": "last_seen", "label": "Last Unauthorized Access", "type": "text", "placeholder": "YYYY-MM-DD HH:MM UTC"},
                ]
            },
            {
                "title": "Scope & Impact Assessment",
                "description": "Determine what the unauthorized actor accessed, modified, or exfiltrated.",
                "is_required": True,
                "expected_duration_hours": 4,
                "fields": [
                    {"key": "resources_accessed", "label": "Resources Accessed", "type": "table", "columns": ["Resource", "Access Type", "Date/Time", "Sensitivity"]},
                    {"key": "data_viewed", "label": "Data Viewed / Downloaded", "type": "list", "placeholder": "dataset or file"},
                    {"key": "modifications_made", "label": "Modifications Made", "type": "list", "placeholder": "change description"},
                    {"key": "accounts_created", "label": "Accounts / Keys Created by Actor", "type": "list", "placeholder": "account or key"},
                    {"key": "privilege_changes", "label": "Privilege Escalations", "type": "list", "placeholder": "privilege change"},
                    {"key": "data_exfiltrated", "label": "Data Exfiltration Suspected", "type": "checkbox"},
                ]
            },
            {
                "title": "Authentication Log Analysis",
                "description": "Deep-dive into authentication logs to establish the complete timeline and identify related compromised accounts.",
                "is_required": True,
                "expected_duration_hours": 4,
                "fields": [
                    {"key": "auth_events", "label": "Key Authentication Events", "type": "table", "columns": ["Timestamp", "Account", "Event Type", "Source", "Result"]},
                    {"key": "mfa_bypassed", "label": "MFA Bypassed", "type": "checkbox"},
                    {"key": "related_accounts", "label": "Related Compromised Accounts", "type": "list", "placeholder": "username"},
                    {"key": "password_spray_detected", "label": "Password Spray/Brute Force Detected", "type": "checkbox"},
                ]
            },
            {
                "title": "Containment & Credential Reset",
                "description": "Contain the unauthorized access and reset all affected credentials.",
                "is_required": True,
                "expected_duration_hours": 2,
                "fields": [
                    {"key": "sessions_terminated", "label": "Active Sessions Terminated", "type": "checkbox"},
                    {"key": "passwords_reset", "label": "Passwords Reset", "type": "list", "placeholder": "account"},
                    {"key": "api_keys_rotated", "label": "API Keys / Tokens Rotated", "type": "list", "placeholder": "key identifier"},
                    {"key": "ips_blocked", "label": "IPs Blocked", "type": "list", "placeholder": "IP address"},
                    {"key": "mfa_enforced", "label": "MFA Enforced / Re-enrolled", "type": "checkbox"},
                ]
            },
            {
                "title": "Root Cause & Prevention",
                "description": "Determine how credentials were compromised and implement controls to prevent recurrence.",
                "is_required": True,
                "expected_duration_hours": 3,
                "fields": [
                    {"key": "root_cause", "label": "Root Cause", "type": "select", "options": ["Phishing", "Password Reuse", "Weak Password", "Credential Leak (Dark Web)", "Keylogger/Stealer", "Social Engineering", "Misconfigured Access", "Unknown"]},
                    {"key": "prevention_measures", "label": "Prevention Measures Implemented", "type": "list", "placeholder": "measure"},
                    {"key": "detection_improvements", "label": "Detection Improvements", "type": "list", "placeholder": "new detection or alert rule"},
                ]
            },
        ]
    },
    {
        "name": "Network Intrusion Investigation",
        "description": "Playbook for investigating network intrusions — covers network forensics, lateral movement analysis, and threat actor profiling.",
        "investigation_type": "network_intrusion",
        "steps": [
            {
                "title": "Initial Detection & Scoping",
                "description": "Document the initial detection and determine the scope of the network intrusion.",
                "is_required": True,
                "expected_duration_hours": 2,
                "fields": [
                    {"key": "detection_source", "label": "Detection Source", "type": "select", "options": ["IDS/IPS", "Firewall", "SIEM", "EDR", "NetFlow Analysis", "DNS Monitoring", "Threat Intel Match", "Manual Discovery"]},
                    {"key": "entry_point", "label": "Suspected Entry Point", "type": "text", "placeholder": "e.g. VPN, web app, email, RDP"},
                    {"key": "compromised_hosts", "label": "Compromised Hosts", "type": "list", "placeholder": "hostname or IP"},
                    {"key": "compromised_segments", "label": "Compromised Network Segments", "type": "list", "placeholder": "VLAN or subnet"},
                    {"key": "threat_actor", "label": "Suspected Threat Actor / Campaign", "type": "text", "placeholder": "e.g. APT29, FIN7, Unknown"},
                    {"key": "first_activity", "label": "Earliest Known Activity", "type": "text", "placeholder": "YYYY-MM-DD HH:MM UTC"},
                ]
            },
            {
                "title": "Network Traffic Analysis",
                "description": "Analyze network captures and flow data to map the intrusion. Use ION PCAP Analyzer for automated detection.",
                "is_required": True,
                "expected_duration_hours": 8,
                "fields": [
                    {"key": "c2_channels", "label": "C2 Communication Channels", "type": "table", "columns": ["Dest IP/Domain", "Port", "Protocol", "Beaconing Interval", "Encryption"]},
                    {"key": "dns_indicators", "label": "DNS Indicators", "type": "table", "columns": ["Domain", "Query Type", "Indicator Type"]},
                    {"key": "exfil_channels", "label": "Exfiltration Channels", "type": "table", "columns": ["Destination", "Protocol", "Volume", "Timeframe"]},
                    {"key": "lateral_movement", "label": "Lateral Movement (Network)", "type": "table", "columns": ["Source", "Destination", "Protocol/Port", "Timestamp"]},
                    {"key": "pcap_files", "label": "PCAP Files Analyzed", "type": "list", "placeholder": "PCAP file path"},
                    {"key": "tunneling_detected", "label": "Tunneling Detected (DNS/ICMP/SSH)", "type": "checkbox"},
                ]
            },
            {
                "title": "Host-Based Analysis",
                "description": "Analyze compromised endpoints for malware, backdoors, persistence, and lateral movement artifacts.",
                "is_required": True,
                "expected_duration_hours": 8,
                "fields": [
                    {"key": "malware_found", "label": "Malware / Tools Found", "type": "table", "columns": ["Host", "Path", "SHA-256", "Classification"]},
                    {"key": "persistence_mechanisms", "label": "Persistence Mechanisms", "type": "list", "placeholder": "mechanism and location"},
                    {"key": "compromised_credentials", "label": "Compromised Credentials", "type": "list", "placeholder": "account (do NOT include passwords)"},
                    {"key": "backdoors", "label": "Backdoors / Web Shells", "type": "list", "placeholder": "path and type"},
                    {"key": "attacker_tools", "label": "Attacker Tools Identified", "type": "list", "placeholder": "e.g. Mimikatz, PsExec, Cobalt Strike"},
                ]
            },
            {
                "title": "Attack Timeline & Kill Chain",
                "description": "Construct a comprehensive attack timeline mapping to the Cyber Kill Chain or MITRE ATT&CK framework.",
                "is_required": True,
                "expected_duration_hours": 4,
                "fields": [
                    {"key": "kill_chain", "label": "Kill Chain Mapping", "type": "table", "columns": ["Phase", "Technique", "Evidence", "Timestamp"]},
                    {"key": "mitre_techniques", "label": "MITRE ATT&CK Techniques", "type": "table", "columns": ["Technique ID", "Name", "Tactic"]},
                    {"key": "dwell_time", "label": "Estimated Dwell Time", "type": "text", "placeholder": "e.g. 14 days"},
                ]
            },
            {
                "title": "Eradication & Hardening",
                "description": "Remove all attacker footholds and harden the network against re-entry.",
                "is_required": True,
                "expected_duration_hours": 6,
                "fields": [
                    {"key": "eradication_actions", "label": "Eradication Actions", "type": "list", "placeholder": "action taken"},
                    {"key": "firewall_rules", "label": "Firewall Rules Added", "type": "table", "columns": ["Rule", "Source", "Destination", "Action"]},
                    {"key": "segmentation_changes", "label": "Network Segmentation Changes", "type": "list", "placeholder": "change description"},
                    {"key": "hosts_reimaged", "label": "Hosts Reimaged / Rebuilt", "type": "list", "placeholder": "hostname"},
                    {"key": "monitoring_deployed", "label": "Additional Monitoring Deployed", "type": "list", "placeholder": "monitoring capability"},
                    {"key": "all_footholds_removed", "label": "All Attacker Footholds Removed", "type": "checkbox"},
                ]
            },
        ]
    },
    {
        "name": "Fraud Investigation",
        "description": "Playbook for investigating suspected fraud — covers financial analysis, digital trail review, and evidence preservation for legal proceedings.",
        "investigation_type": "fraud",
        "steps": [
            {
                "title": "Allegation & Scope Definition",
                "description": "Document the fraud allegation, scope the investigation, and identify key subjects and timeframes.",
                "is_required": True,
                "expected_duration_hours": 4,
                "fields": [
                    {"key": "fraud_type", "label": "Fraud Type", "type": "select", "options": ["Financial Fraud", "Expense Fraud", "Procurement Fraud", "Identity Fraud", "Account Takeover", "Insurance Fraud", "Wire Fraud", "Other"]},
                    {"key": "subjects", "label": "Subjects of Investigation", "type": "list", "placeholder": "name / identifier"},
                    {"key": "estimated_loss", "label": "Estimated Financial Loss", "type": "text", "placeholder": "e.g. $45,000"},
                    {"key": "timeframe", "label": "Suspected Timeframe", "type": "text", "placeholder": "e.g. 2025-06 to 2026-01"},
                    {"key": "reporting_source", "label": "How Was It Reported?", "type": "select", "options": ["Internal Audit", "Employee Tip", "Automated Alert", "Customer Complaint", "Law Enforcement", "External Audit"]},
                    {"key": "legal_engaged", "label": "Legal Counsel Engaged", "type": "checkbox"},
                ]
            },
            {
                "title": "Financial & Transaction Analysis",
                "description": "Analyze financial records, transaction logs, and account activity for evidence of fraud.",
                "is_required": True,
                "expected_duration_hours": 12,
                "fields": [
                    {"key": "suspicious_transactions", "label": "Suspicious Transactions", "type": "table", "columns": ["Date", "Amount", "From", "To", "Description"]},
                    {"key": "accounts_involved", "label": "Accounts Involved", "type": "list", "placeholder": "account number / name"},
                    {"key": "shell_companies", "label": "Shell Companies / Fictitious Entities", "type": "list", "placeholder": "entity name"},
                    {"key": "pattern_detected", "label": "Pattern Detected", "type": "textarea", "placeholder": "Describe the fraudulent pattern..."},
                    {"key": "total_confirmed_loss", "label": "Total Confirmed Loss", "type": "text", "placeholder": "amount"},
                ]
            },
            {
                "title": "Digital Evidence Collection",
                "description": "Collect and preserve digital evidence — emails, documents, access logs, and system records.",
                "is_required": True,
                "expected_duration_hours": 8,
                "fields": [
                    {"key": "emails_preserved", "label": "Emails Preserved", "type": "text", "placeholder": "number of emails / mailboxes"},
                    {"key": "documents_collected", "label": "Key Documents Collected", "type": "list", "placeholder": "document name / description"},
                    {"key": "access_logs", "label": "Access Logs Preserved", "type": "list", "placeholder": "system / log source"},
                    {"key": "evidence_hashes", "label": "Evidence Hashes", "type": "table", "columns": ["Evidence Item", "SHA-256"]},
                ]
            },
            {
                "title": "Findings & Legal Referral",
                "description": "Compile findings and determine if the matter should be referred to law enforcement or handled internally.",
                "is_required": True,
                "expected_duration_hours": 6,
                "fields": [
                    {"key": "finding", "label": "Finding", "type": "select", "options": ["Fraud Confirmed", "Fraud Suspected (Insufficient Evidence)", "Policy Violation (Not Fraud)", "No Finding"]},
                    {"key": "refer_to_law_enforcement", "label": "Refer to Law Enforcement", "type": "checkbox"},
                    {"key": "disciplinary_action", "label": "Disciplinary Action Recommended", "type": "checkbox"},
                    {"key": "recovery_actions", "label": "Financial Recovery Actions", "type": "list", "placeholder": "action"},
                    {"key": "control_improvements", "label": "Control Improvements Needed", "type": "list", "placeholder": "improvement"},
                ]
            },
        ]
    },
    {
        "name": "Policy Violation Investigation",
        "description": "Playbook for investigating acceptable use policy violations, data handling violations, and other policy infractions.",
        "investigation_type": "policy_violation",
        "steps": [
            {
                "title": "Violation Report & Classification",
                "description": "Document the reported policy violation and classify its type and severity.",
                "is_required": True,
                "expected_duration_hours": 2,
                "fields": [
                    {"key": "policy_violated", "label": "Policy Violated", "type": "text", "placeholder": "e.g. Acceptable Use Policy, Data Classification Policy"},
                    {"key": "violation_type", "label": "Violation Type", "type": "select", "options": ["Acceptable Use", "Data Handling", "Access Control", "Password Policy", "Remote Work", "BYOD", "Software Installation", "Data Retention", "Other"]},
                    {"key": "severity", "label": "Severity", "type": "select", "options": ["Critical", "High", "Medium", "Low"]},
                    {"key": "subject", "label": "Subject", "type": "text", "placeholder": "name / employee ID"},
                    {"key": "reported_by", "label": "Reported By", "type": "text", "placeholder": "name / system"},
                    {"key": "repeat_offender", "label": "Repeat Offender", "type": "checkbox"},
                ]
            },
            {
                "title": "Evidence Gathering",
                "description": "Collect logs, screenshots, and other evidence documenting the policy violation.",
                "is_required": True,
                "expected_duration_hours": 4,
                "fields": [
                    {"key": "evidence_items", "label": "Evidence Collected", "type": "table", "columns": ["Type", "Description", "Date", "Source"]},
                    {"key": "log_entries", "label": "Relevant Log Entries", "type": "list", "placeholder": "log entry / reference"},
                    {"key": "screenshots", "label": "Screenshots Captured", "type": "list", "placeholder": "screenshot description"},
                    {"key": "witness_statements", "label": "Witness Statements", "type": "list", "placeholder": "witness name and summary"},
                ]
            },
            {
                "title": "Impact Assessment",
                "description": "Assess the actual or potential impact of the policy violation on the organization.",
                "is_required": True,
                "expected_duration_hours": 2,
                "fields": [
                    {"key": "data_exposed", "label": "Data Exposed / At Risk", "type": "checkbox"},
                    {"key": "systems_affected", "label": "Systems Affected", "type": "list", "placeholder": "system name"},
                    {"key": "business_impact", "label": "Business Impact", "type": "select", "options": ["None", "Minor", "Moderate", "Significant", "Critical"]},
                    {"key": "regulatory_implications", "label": "Regulatory Implications", "type": "checkbox"},
                    {"key": "impact_description", "label": "Impact Description", "type": "textarea"},
                ]
            },
            {
                "title": "Findings & Recommendations",
                "description": "Document findings and recommend appropriate action in coordination with HR and management.",
                "is_required": True,
                "expected_duration_hours": 2,
                "fields": [
                    {"key": "violation_confirmed", "label": "Violation Confirmed", "type": "checkbox"},
                    {"key": "intentional", "label": "Violation Intentional", "type": "select", "options": ["Intentional", "Negligent", "Accidental", "Unknown"]},
                    {"key": "recommended_action", "label": "Recommended Action", "type": "select", "options": ["No Action", "Verbal Warning", "Written Warning", "Retraining Required", "Access Restriction", "Suspension", "Termination", "Refer to Legal"]},
                    {"key": "preventive_measures", "label": "Preventive Measures", "type": "list", "placeholder": "measure"},
                    {"key": "hr_notified", "label": "HR Notified", "type": "checkbox"},
                    {"key": "management_notified", "label": "Management Notified", "type": "checkbox"},
                ]
            },
        ]
    },
    {
        "name": "General Forensic Investigation",
        "description": "Flexible investigation playbook for cases that don't fit a specific category — provides a structured framework adaptable to any investigation type.",
        "investigation_type": "other",
        "steps": [
            {
                "title": "Case Initiation & Scoping",
                "description": "Define the scope, objectives, and constraints of the investigation.",
                "is_required": True,
                "expected_duration_hours": 2,
                "fields": [
                    {"key": "objectives", "label": "Investigation Objectives", "type": "list", "placeholder": "objective"},
                    {"key": "scope", "label": "Scope / Boundaries", "type": "textarea", "placeholder": "What is in scope and out of scope?"},
                    {"key": "key_questions", "label": "Key Questions to Answer", "type": "list", "placeholder": "question"},
                    {"key": "authorization", "label": "Authorization Reference", "type": "text", "placeholder": "e.g. ticket #, approval email"},
                    {"key": "constraints", "label": "Constraints / Limitations", "type": "list", "placeholder": "constraint"},
                ]
            },
            {
                "title": "Evidence Collection",
                "description": "Identify, collect, and preserve all relevant evidence.",
                "is_required": True,
                "expected_duration_hours": 8,
                "fields": [
                    {"key": "evidence_items", "label": "Evidence Collected", "type": "table", "columns": ["Item", "Type", "Source", "SHA-256"]},
                    {"key": "chain_of_custody", "label": "Chain of Custody Documented", "type": "checkbox"},
                    {"key": "evidence_storage", "label": "Evidence Storage Location", "type": "text", "placeholder": "storage path or locker ID"},
                ]
            },
            {
                "title": "Analysis",
                "description": "Analyze collected evidence to answer the key investigation questions.",
                "is_required": True,
                "expected_duration_hours": 12,
                "fields": [
                    {"key": "tools_used", "label": "Analysis Tools Used", "type": "list", "placeholder": "tool name and version"},
                    {"key": "iocs", "label": "Indicators of Compromise", "type": "table", "columns": ["Type", "Value", "Context"]},
                    {"key": "key_findings", "label": "Key Findings", "type": "list", "placeholder": "finding"},
                    {"key": "timeline_events", "label": "Timeline Events", "type": "table", "columns": ["Timestamp", "Event", "Source", "Significance"]},
                ]
            },
            {
                "title": "Conclusions & Recommendations",
                "description": "Summarize conclusions and provide actionable recommendations.",
                "is_required": True,
                "expected_duration_hours": 4,
                "fields": [
                    {"key": "conclusion", "label": "Conclusion Summary", "type": "textarea"},
                    {"key": "recommendations", "label": "Recommendations", "type": "list", "placeholder": "recommendation"},
                    {"key": "follow_up_required", "label": "Follow-Up Investigation Required", "type": "checkbox"},
                    {"key": "lessons_learned", "label": "Lessons Learned", "type": "list", "placeholder": "lesson"},
                ]
            },
        ]
    },
]


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else BASE
    s = requests.Session()

    # Login
    r = s.post(f"{base}/api/auth/login", json={"username": "admin", "password": "admin2025"})
    if r.status_code != 200:
        print(f"Login failed: {r.status_code} {r.text}")
        sys.exit(1)
    print("Logged in as admin")

    # Check existing playbooks
    existing = s.get(f"{base}/api/forensics/playbooks").json()
    existing_names = {p["name"] for p in existing}
    print(f"Found {len(existing)} existing playbooks")

    created = 0
    for pb in PLAYBOOKS:
        if pb["name"] in existing_names:
            print(f"  SKIP (exists): {pb['name']}")
            continue
        r = s.post(f"{base}/api/forensics/playbooks", json=pb)
        if r.status_code == 200:
            data = r.json()
            step_count = len(data.get("steps", []))
            field_count = sum(len(st.get("fields", [])) for st in data.get("steps", []))
            print(f"  CREATED: {data['name']} ({step_count} steps, {field_count} fields)")
            created += 1
        else:
            print(f"  FAILED: {pb['name']} — {r.status_code} {r.text}")

    print(f"\nDone. Created {created} playbooks, {len(PLAYBOOKS) - created} skipped.")


if __name__ == "__main__":
    main()
