"""Seed ~25 inactive SOC playbooks into the ION playbook library."""

import os
import sys
import requests

BASE_URL = os.environ.get("ION_SEED_URL", "http://127.0.0.1:8000")
ADMIN_USER = "admin"
ADMIN_PASS = os.environ.get("ION_ADMIN_PASSWORD", "admin2025")

PLAYBOOKS = [
    # ── Phishing & Email (4) ──────────────────────────────────────────────
    {
        "name": "Phishing Email Investigation",
        "description": "Structured investigation workflow for reported phishing emails, covering header analysis, URL/attachment detonation, credential exposure assessment, and remediation.",
        "is_active": False,
        "priority": 4,
        "trigger_conditions": {
            "rule_patterns": ["phish", "suspicious.*email", "email.*threat"],
            "severities": ["medium", "high", "critical"],
            "mitre_tactics": ["initial-access"],
            "mitre_techniques": ["T1566", "T1566.001", "T1566.002"],
        },
        "steps": [
            {"title": "Collect and preserve the original email (headers + body + attachments)", "description": "Obtain the raw .eml or .msg file. Document sender address, reply-to, return-path, and all Received headers.", "is_required": True},
            {"title": "Analyze email headers for spoofing indicators", "description": "Check SPF/DKIM/DMARC results, compare envelope-from vs header-from, identify originating IP and resolve geolocation."},
            {"title": "Detonate URLs and attachments in sandbox", "description": "Submit all URLs to a URL scanner (VirusTotal, URLScan.io) and attachments to a sandbox (Any.Run, Joe Sandbox). Record all IOCs."},
            {"title": "Check if any recipients clicked links or opened attachments", "description": "Query email gateway logs, proxy logs, and EDR telemetry. Identify all users who interacted with the email."},
            {"title": "Assess credential exposure", "description": "If a credential harvesting page was involved, determine if any credentials were submitted. Check for subsequent anomalous logins."},
            {"title": "Contain: block sender, quarantine similar emails, block IOCs", "description": "Add sender domain/IP to blocklist, quarantine unread copies from all mailboxes, block malicious URLs/IPs at proxy/firewall.", "is_required": True},
            {"title": "Notify affected users and enforce password resets if needed", "description": "Contact users who interacted with the phishing email. Force password resets for any compromised accounts."},
            {"title": "Document findings and update detection rules", "description": "Write investigation report. Add new IOCs to threat intel platform. Update email filtering rules to catch similar campaigns."},
        ],
    },
    {
        "name": "Business Email Compromise Response",
        "description": "Response playbook for BEC incidents involving impersonation of executives or vendors to redirect payments or steal sensitive data.",
        "is_active": False,
        "priority": 5,
        "trigger_conditions": {
            "rule_patterns": ["BEC", "business.*email.*compromise", "wire.*fraud", "invoice.*fraud", "CEO.*fraud"],
            "severities": ["high", "critical"],
            "mitre_tactics": ["initial-access"],
            "mitre_techniques": ["T1566.002", "T1534"],
        },
        "steps": [
            {"title": "Identify the compromised or impersonated account", "description": "Determine whether the attacker compromised a legitimate account (ATO) or used a lookalike domain. Check mailbox rules for auto-forwarding.", "is_required": True},
            {"title": "Review email thread and identify fraudulent instructions", "description": "Trace the full conversation thread. Identify when the attacker injected themselves and what actions were requested (wire transfer, data, gift cards)."},
            {"title": "Assess financial impact and initiate recall", "description": "If funds were transferred, contact the bank immediately to initiate a recall. Document transaction details, amounts, and destination accounts.", "is_required": True},
            {"title": "Contain the compromised account", "description": "Reset credentials, revoke active sessions, remove malicious inbox rules and OAuth app grants. Enable MFA if not already active."},
            {"title": "Search for additional BEC campaigns across the organization", "description": "Query email logs for similar impersonation patterns, lookalike domains, or forwarding rules across all mailboxes."},
            {"title": "Notify legal, finance, and executive leadership", "description": "Engage legal counsel for regulatory reporting requirements. Brief finance on any fraudulent transactions. Coordinate with law enforcement if needed.", "is_required": True},
        ],
    },
    {
        "name": "Credential Harvesting via Phishing",
        "description": "Focused playbook for phishing campaigns designed to steal credentials through fake login pages, covering credential validation, session analysis, and exposure remediation.",
        "is_active": False,
        "priority": 3,
        "trigger_conditions": {
            "rule_patterns": ["credential.*harvest", "fake.*login", "credential.*phish"],
            "severities": ["medium", "high", "critical"],
            "mitre_tactics": ["credential-access", "initial-access"],
            "mitre_techniques": ["T1566", "T1056.003", "T1078"],
        },
        "steps": [
            {"title": "Identify the credential harvesting page and capture evidence", "description": "Screenshot the fake login page, record the URL, hosting infrastructure, and SSL certificate details.", "is_required": True},
            {"title": "Determine which users submitted credentials", "description": "Correlate proxy logs showing POST requests to the harvesting URL with email recipients. Identify all affected accounts."},
            {"title": "Force password resets for exposed accounts", "description": "Immediately reset passwords for all users who submitted credentials. Invalidate active sessions and tokens.", "is_required": True},
            {"title": "Check for post-compromise activity", "description": "Review authentication logs for anomalous logins from unusual locations/IPs since the phishing campaign started. Check for mailbox rule changes, OAuth grants."},
            {"title": "Request takedown of the harvesting page", "description": "Submit abuse reports to the hosting provider and domain registrar. Use Google Safe Browsing and PhishTank to flag the URL."},
            {"title": "Block IOCs and update security controls", "description": "Block the harvesting domain, IP, and any related infrastructure at DNS, proxy, and firewall layers."},
        ],
    },
    {
        "name": "Spear Phishing Campaign Analysis",
        "description": "Deep-dive analysis of targeted spear phishing campaigns, focusing on threat actor attribution, campaign scope, and organizational targeting patterns.",
        "is_active": False,
        "priority": 3,
        "trigger_conditions": {
            "rule_patterns": ["spear.*phish", "targeted.*phish", "whaling"],
            "severities": ["high", "critical"],
            "mitre_tactics": ["initial-access", "reconnaissance"],
            "mitre_techniques": ["T1566.001", "T1566.002", "T1598"],
        },
        "steps": [
            {"title": "Map the campaign scope and timeline", "description": "Identify all recipients, sending infrastructure, and email variations. Establish when the campaign started and its delivery pattern.", "is_required": True},
            {"title": "Analyze targeting patterns", "description": "Determine why specific individuals were targeted. Check if targeting aligns with roles (finance, executive, IT) or access to sensitive systems."},
            {"title": "Extract and correlate IOCs across threat intel", "description": "Extract all IOCs (domains, IPs, hashes, email addresses) and correlate with threat intel platforms for known campaigns or threat actors."},
            {"title": "Assess payload capabilities", "description": "Perform deep analysis of any payloads (documents, executables, scripts). Identify C2 infrastructure, persistence mechanisms, and data exfiltration methods."},
            {"title": "Determine if any systems were compromised", "description": "Query EDR for execution of payloads, process creation events, and network connections to C2 infrastructure.", "is_required": True},
            {"title": "Produce threat intelligence report", "description": "Document TTPs, IOCs, and attribution indicators. Share with ISACs, threat intel sharing communities, and internal stakeholders."},
        ],
    },

    # ── Malware & Ransomware (4) ──────────────────────────────────────────
    {
        "name": "Malware Infection Containment",
        "description": "Rapid containment and investigation playbook for confirmed malware infections on endpoints, from initial detection through eradication and recovery.",
        "is_active": False,
        "priority": 4,
        "trigger_conditions": {
            "rule_patterns": ["malware", "virus", "trojan", "worm", "malicious.*file", "infection"],
            "severities": ["medium", "high", "critical"],
            "mitre_tactics": ["execution", "persistence"],
            "mitre_techniques": ["T1059", "T1204", "T1547"],
        },
        "steps": [
            {"title": "Isolate the infected endpoint from the network", "description": "Use EDR network containment or physically disconnect the device. Preserve network connectivity for EDR/forensic tools if possible.", "is_required": True},
            {"title": "Collect volatile forensic data before remediation", "description": "Capture running processes, network connections, loaded DLLs, scheduled tasks, and memory dump from the infected system."},
            {"title": "Identify the malware family and capabilities", "description": "Submit samples to sandbox and AV engines. Determine malware type (RAT, infostealer, dropper, etc.), C2 infrastructure, and persistence mechanisms."},
            {"title": "Determine initial infection vector", "description": "Trace back how the malware arrived: email attachment, drive-by download, USB, lateral movement. Check parent process chain.", "is_required": True},
            {"title": "Scan for lateral movement indicators", "description": "Check for use of stolen credentials, SMB connections to other hosts, PsExec/WMI/WinRM activity, or additional malware drops on other systems."},
            {"title": "Eradicate malware and persistence mechanisms", "description": "Remove malicious files, registry keys, scheduled tasks, services, and startup entries. Verify removal with a full AV scan."},
            {"title": "Restore system and monitor for reinfection", "description": "Reimage if necessary or verify clean state. Reconnect to network with enhanced monitoring. Watch for re-execution or beacon activity for 72 hours."},
        ],
    },
    {
        "name": "Ransomware Incident Response",
        "description": "Critical incident response playbook for ransomware attacks, covering containment, scope assessment, negotiation considerations, and recovery procedures.",
        "is_active": False,
        "priority": 5,
        "trigger_conditions": {
            "rule_patterns": ["ransomware", "encrypt.*files", "ransom.*note", "crypto.*lock"],
            "severities": ["critical"],
            "mitre_tactics": ["impact"],
            "mitre_techniques": ["T1486", "T1490", "T1489"],
        },
        "steps": [
            {"title": "Activate incident response team and establish war room", "description": "Notify CISO, IT leadership, legal, and communications. Establish dedicated communication channel (assume email may be compromised).", "is_required": True},
            {"title": "Isolate affected systems and preserve evidence", "description": "Network-isolate all affected and potentially affected systems. Do NOT power off systems — preserve memory for forensics. Block known C2 IPs/domains.", "is_required": True},
            {"title": "Determine ransomware variant and scope of encryption", "description": "Identify the ransomware family from ransom notes, file extensions, and samples. Map which systems, shares, and data are encrypted."},
            {"title": "Assess backup availability and integrity", "description": "Verify that backups exist and are not compromised. Test restoration of critical data from offline/immutable backups. Determine RPO.", "is_required": True},
            {"title": "Identify initial access vector and dwell time", "description": "Investigate how the attacker gained access (phishing, RDP, VPN exploit). Determine how long they were in the environment before deploying ransomware."},
            {"title": "Contain: reset all credentials, patch exploited vulnerabilities", "description": "Reset domain admin and service account passwords. Patch the entry point vulnerability. Disable compromised VPN/RDP access."},
            {"title": "Begin recovery from clean backups", "description": "Prioritize restoration of critical business systems. Rebuild domain controllers if compromised. Validate system integrity before reconnecting.", "is_required": True},
            {"title": "Post-incident: reporting, lessons learned, control improvements", "description": "File regulatory notifications if required. Conduct lessons-learned review. Implement improved segmentation, MFA, and backup strategies."},
        ],
    },
    {
        "name": "Fileless Malware Investigation",
        "description": "Investigation playbook for fileless malware that operates entirely in memory using legitimate tools (PowerShell, WMI, .NET) without dropping files to disk.",
        "is_active": False,
        "priority": 3,
        "trigger_conditions": {
            "rule_patterns": ["fileless", "powershell.*encoded", "in-memory", "LOLBin", "living.*off.*land"],
            "severities": ["medium", "high", "critical"],
            "mitre_tactics": ["execution", "defense-evasion"],
            "mitre_techniques": ["T1059.001", "T1059.003", "T1218", "T1055"],
        },
        "steps": [
            {"title": "Capture memory dump of affected system", "description": "Use EDR or forensic tools to capture a full memory dump before any remediation. This may be the only evidence of fileless malware.", "is_required": True},
            {"title": "Analyze PowerShell/script execution logs", "description": "Review PowerShell ScriptBlock logging, Module logging, and Transcription logs. Decode any Base64 or obfuscated commands."},
            {"title": "Investigate WMI and scheduled task persistence", "description": "Check for WMI event subscriptions, scheduled tasks with encoded commands, and registry-based persistence using LOLBins."},
            {"title": "Trace process injection activity", "description": "Look for process hollowing, DLL injection, or reflective loading. Check for anomalous parent-child process relationships."},
            {"title": "Identify C2 communication channels", "description": "Analyze network traffic for beaconing patterns, DNS tunneling, or abuse of legitimate services (Slack, Teams, Pastebin) for C2."},
            {"title": "Remediate: kill processes, remove persistence, flush caches", "description": "Terminate malicious processes, remove WMI subscriptions and scheduled tasks, clear PowerShell cache, and reboot to clear memory."},
        ],
    },
    {
        "name": "Trojan/RAT Removal Procedure",
        "description": "Step-by-step procedure for identifying, containing, and removing Remote Access Trojans (RATs) from compromised endpoints.",
        "is_active": False,
        "priority": 3,
        "trigger_conditions": {
            "rule_patterns": ["RAT", "remote.*access.*trojan", "backdoor", "C2.*beacon", "command.*control"],
            "severities": ["high", "critical"],
            "mitre_tactics": ["command-and-control", "persistence"],
            "mitre_techniques": ["T1219", "T1071", "T1095", "T1573"],
        },
        "steps": [
            {"title": "Identify the RAT variant and its capabilities", "description": "Determine the RAT family (Cobalt Strike, AsyncRAT, Quasar, njRAT, etc.) from AV alerts, process names, or network indicators.", "is_required": True},
            {"title": "Isolate the compromised host", "description": "Network-isolate the endpoint while maintaining EDR connectivity for continued monitoring and forensic collection."},
            {"title": "Map C2 infrastructure and communication patterns", "description": "Identify C2 server IPs/domains, beacon intervals, and communication protocols. Block at firewall/proxy. Check for domain fronting."},
            {"title": "Assess data exfiltration risk", "description": "Review network traffic volumes to C2, clipboard monitoring capabilities, keylogging activity, and accessed files/credentials."},
            {"title": "Remove RAT and all persistence mechanisms", "description": "Kill RAT processes, remove startup entries, services, scheduled tasks, and any dropped payloads. Scan with multiple AV engines.", "is_required": True},
            {"title": "Reset credentials used on the compromised system", "description": "Change passwords for all accounts that logged into the compromised system. Revoke any certificates or tokens."},
        ],
    },

    # ── Network Attacks (4) ───────────────────────────────────────────────
    {
        "name": "DDoS Attack Mitigation",
        "description": "Operational playbook for detecting, mitigating, and recovering from Distributed Denial of Service attacks targeting organizational infrastructure.",
        "is_active": False,
        "priority": 4,
        "trigger_conditions": {
            "rule_patterns": ["DDoS", "denial.*service", "volumetric.*attack", "flood.*attack"],
            "severities": ["high", "critical"],
            "mitre_tactics": ["impact"],
            "mitre_techniques": ["T1498", "T1499"],
        },
        "steps": [
            {"title": "Confirm DDoS attack and classify type", "description": "Distinguish from legitimate traffic spikes. Classify as volumetric (bandwidth), protocol (SYN flood), or application-layer (HTTP flood).", "is_required": True},
            {"title": "Activate DDoS mitigation service", "description": "Engage cloud DDoS protection (Cloudflare, AWS Shield, Akamai). Redirect traffic through scrubbing center if available."},
            {"title": "Implement emergency traffic filtering", "description": "Apply rate limiting, geo-blocking, and IP reputation filtering. Block known-bad source IPs/ASNs at the network edge.", "is_required": True},
            {"title": "Monitor service availability and adjust mitigations", "description": "Track service uptime, response times, and error rates. Tune mitigation rules to minimize legitimate traffic impact."},
            {"title": "Coordinate with ISP and upstream providers", "description": "Contact ISP for upstream filtering or blackhole routing of attack traffic. Share attack indicators for broader mitigation."},
            {"title": "Post-attack: analyze patterns and strengthen defenses", "description": "Document attack vectors, peak volumes, and duration. Update DDoS response plan. Consider always-on DDoS protection."},
        ],
    },
    {
        "name": "DNS Tunneling Investigation",
        "description": "Investigation playbook for suspected DNS tunneling used for data exfiltration or covert C2 communication channels.",
        "is_active": False,
        "priority": 3,
        "trigger_conditions": {
            "rule_patterns": ["DNS.*tunnel", "DNS.*exfil", "suspicious.*DNS", "DNS.*anomal"],
            "severities": ["medium", "high"],
            "mitre_tactics": ["exfiltration", "command-and-control"],
            "mitre_techniques": ["T1048.003", "T1071.004", "T1568"],
        },
        "steps": [
            {"title": "Analyze anomalous DNS query patterns", "description": "Look for high-frequency queries, unusually long subdomain labels (>30 chars), high entropy in query names, and queries to unusual TLDs.", "is_required": True},
            {"title": "Identify the tunneling domain and infrastructure", "description": "Determine the authoritative domain being used for tunneling. Check domain registration date, registrant, and hosting infrastructure."},
            {"title": "Determine the tunneling tool/protocol", "description": "Identify if this is iodine, dnscat2, DNSStager, or custom tooling based on query patterns, record types used (TXT, CNAME, MX, NULL)."},
            {"title": "Assess data volume and content", "description": "Estimate total data transferred via DNS. If possible, reassemble tunneled data from captured queries to understand what was exfiltrated."},
            {"title": "Block tunneling domain and remediate source", "description": "Sinkhole or block the tunneling domain at DNS resolvers. Investigate the source host for malware, and apply DNS filtering policies.", "is_required": True},
        ],
    },
    {
        "name": "Man-in-the-Middle Detection Response",
        "description": "Response playbook for detected MITM attacks including ARP spoofing, SSL stripping, rogue access points, and DNS hijacking.",
        "is_active": False,
        "priority": 3,
        "trigger_conditions": {
            "rule_patterns": ["MITM", "man.*in.*middle", "ARP.*spoof", "SSL.*strip", "rogue.*AP"],
            "severities": ["high", "critical"],
            "mitre_tactics": ["credential-access", "collection"],
            "mitre_techniques": ["T1557", "T1557.001", "T1557.002"],
        },
        "steps": [
            {"title": "Identify the MITM technique and affected network segment", "description": "Determine attack method (ARP spoofing, DHCP spoofing, DNS hijacking, rogue AP, BGP hijack). Identify the affected VLAN/subnet.", "is_required": True},
            {"title": "Locate the attacker's device on the network", "description": "Use MAC address tables, switch port mapping, and DHCP logs to physically locate the attacking device. Check for rogue wireless access points."},
            {"title": "Disconnect the attacking device", "description": "Administratively disable the switch port, block the MAC address, or physically remove the rogue device.", "is_required": True},
            {"title": "Assess intercepted data and credential exposure", "description": "Determine what traffic was intercepted. Identify any credentials, session tokens, or sensitive data that may have been captured."},
            {"title": "Implement network hardening measures", "description": "Enable Dynamic ARP Inspection (DAI), DHCP snooping, 802.1X port authentication, and HSTS enforcement where applicable."},
        ],
    },
    {
        "name": "Network Intrusion Investigation",
        "description": "Comprehensive investigation playbook for confirmed network intrusions, from initial detection through full scope assessment and threat eradication.",
        "is_active": False,
        "priority": 4,
        "trigger_conditions": {
            "rule_patterns": ["intrusion", "network.*breach", "unauthorized.*access", "lateral.*movement"],
            "severities": ["high", "critical"],
            "mitre_tactics": ["lateral-movement", "discovery"],
            "mitre_techniques": ["T1021", "T1018", "T1083"],
        },
        "steps": [
            {"title": "Establish timeline of intrusion activity", "description": "Correlate alerts, logs, and forensic artifacts to build a timeline from initial access through current activity. Identify patient zero.", "is_required": True},
            {"title": "Map compromised systems and accounts", "description": "Identify all systems the attacker accessed and all credentials they obtained. Use EDR and SIEM to trace lateral movement paths.", "is_required": True},
            {"title": "Analyze attacker tools, techniques, and procedures", "description": "Document all TTPs observed: tools used, exploitation methods, persistence mechanisms, privilege escalation, and data access patterns."},
            {"title": "Contain: segment affected systems, block attacker infrastructure", "description": "Implement network segmentation to isolate compromised segments. Block all identified C2 IPs/domains. Disable compromised accounts."},
            {"title": "Hunt for additional indicators of compromise", "description": "Use gathered IOCs and TTPs to proactively hunt across the entire environment for undiscovered compromised systems."},
            {"title": "Eradicate attacker presence and harden environment", "description": "Remove all backdoors, persistence mechanisms, and attacker tools. Patch exploited vulnerabilities. Reset all potentially compromised credentials.", "is_required": True},
            {"title": "Restore operations and establish enhanced monitoring", "description": "Bring cleaned systems back online with increased logging and monitoring. Deploy additional detection rules for observed TTPs."},
        ],
    },

    # ── Identity & Access (3) ─────────────────────────────────────────────
    {
        "name": "Compromised Account Response",
        "description": "Response playbook for confirmed or suspected account compromise, covering credential reset, session invalidation, and post-compromise investigation.",
        "is_active": False,
        "priority": 4,
        "trigger_conditions": {
            "rule_patterns": ["compromised.*account", "account.*takeover", "unauthorized.*login", "impossible.*travel"],
            "severities": ["medium", "high", "critical"],
            "mitre_tactics": ["initial-access", "persistence"],
            "mitre_techniques": ["T1078", "T1110", "T1539"],
        },
        "steps": [
            {"title": "Confirm account compromise and reset credentials", "description": "Verify the compromise is real (not false positive). Immediately reset the account password and revoke all active sessions/tokens.", "is_required": True},
            {"title": "Review authentication logs for anomalous activity", "description": "Check login history for unusual locations, times, user agents, and IP addresses. Identify the initial compromise point."},
            {"title": "Check for persistence mechanisms", "description": "Review MFA device registrations, OAuth app grants, mailbox forwarding rules, API keys, and service principal credentials for unauthorized additions.", "is_required": True},
            {"title": "Assess data access and actions performed", "description": "Review audit logs for files accessed, emails read/sent, admin actions taken, and data downloaded during the compromise period."},
            {"title": "Notify the account owner and enforce MFA", "description": "Contact the legitimate user, explain the compromise, and ensure MFA is properly configured. Provide guidance on credential hygiene."},
            {"title": "Block attacker infrastructure and update detections", "description": "Block source IPs and user agents used by the attacker. Create detection rules for similar compromise patterns."},
        ],
    },
    {
        "name": "Privilege Escalation Investigation",
        "description": "Investigation playbook for detected privilege escalation attempts, whether through exploitation, misconfigurations, or credential theft.",
        "is_active": False,
        "priority": 4,
        "trigger_conditions": {
            "rule_patterns": ["privilege.*escalat", "admin.*rights", "elevation.*privilege", "sudo.*abuse"],
            "severities": ["high", "critical"],
            "mitre_tactics": ["privilege-escalation"],
            "mitre_techniques": ["T1068", "T1548", "T1134", "T1078.002"],
        },
        "steps": [
            {"title": "Identify the escalation method used", "description": "Determine if escalation was via exploit (kernel, service), credential theft (mimikatz, token impersonation), misconfiguration (weak ACLs), or social engineering.", "is_required": True},
            {"title": "Determine the scope of elevated access obtained", "description": "Map what resources, systems, and data the escalated account now has access to. Check if domain admin or root was achieved."},
            {"title": "Review actions taken with elevated privileges", "description": "Audit all commands executed, files accessed, accounts created/modified, and group membership changes made with the escalated privileges.", "is_required": True},
            {"title": "Contain: revoke escalated access and fix the vulnerability", "description": "Remove the escalated privileges, patch the exploited vulnerability, fix the misconfiguration, or rotate the stolen credentials."},
            {"title": "Scan for similar vulnerabilities across the environment", "description": "Check if the same escalation path exists on other systems. Run vulnerability scans targeting the specific weakness exploited."},
        ],
    },
    {
        "name": "Insider Threat Investigation",
        "description": "Sensitive investigation playbook for potential insider threats, covering behavioral analysis, data access review, and evidence preservation with HR/Legal coordination.",
        "is_active": False,
        "priority": 4,
        "trigger_conditions": {
            "rule_patterns": ["insider.*threat", "data.*theft.*internal", "unauthorized.*data.*access", "employee.*exfil"],
            "severities": ["high", "critical"],
            "mitre_tactics": ["exfiltration", "collection"],
            "mitre_techniques": ["T1567", "T1074", "T1119"],
        },
        "steps": [
            {"title": "Coordinate with HR and Legal before investigation", "description": "Engage HR and legal counsel to ensure the investigation follows company policy and legal requirements. Document authorization to investigate.", "is_required": True},
            {"title": "Preserve and collect evidence forensically", "description": "Capture email archives, file access logs, USB usage logs, cloud storage activity, and endpoint forensic images with proper chain of custody."},
            {"title": "Analyze data access patterns and anomalies", "description": "Review DLP alerts, file downloads, print jobs, email attachments, and cloud sync activity. Compare against baseline behavior for the user's role.", "is_required": True},
            {"title": "Check for data staging and exfiltration channels", "description": "Look for large archive creation, use of personal cloud storage, USB transfers, personal email forwarding, and unauthorized file sharing."},
            {"title": "Review user behavior indicators", "description": "Check for after-hours access, access to data outside role requirements, badge/VPN patterns, and correlation with HR events (resignation, PIP, termination)."},
            {"title": "Document findings and provide report to HR/Legal", "description": "Prepare a factual, objective investigation report. Present evidence and findings to HR and legal for determination of next steps.", "is_required": True},
        ],
    },

    # ── Cloud & SaaS (3) ─────────────────────────────────────────────────
    {
        "name": "Cloud Resource Compromise Response",
        "description": "Response playbook for compromised cloud resources (AWS, Azure, GCP) including unauthorized EC2/VM instances, exposed storage, and IAM credential abuse.",
        "is_active": False,
        "priority": 4,
        "trigger_conditions": {
            "rule_patterns": ["cloud.*compromise", "AWS.*unauthorized", "Azure.*breach", "GCP.*abuse", "cloud.*misconfig"],
            "severities": ["high", "critical"],
            "mitre_tactics": ["initial-access", "persistence"],
            "mitre_techniques": ["T1078.004", "T1530", "T1580"],
        },
        "steps": [
            {"title": "Identify compromised cloud resources and credentials", "description": "Determine which IAM users/roles, access keys, instances, or services are compromised. Check CloudTrail/Activity Log for unauthorized API calls.", "is_required": True},
            {"title": "Contain: disable compromised credentials and isolate resources", "description": "Deactivate compromised access keys, revoke temporary credentials, apply restrictive security groups to affected instances.", "is_required": True},
            {"title": "Audit resource changes and data access", "description": "Review all API calls, resource creation/modification, S3/Blob access logs, and data transfer activity during the compromise window."},
            {"title": "Check for persistence: new IAM users, roles, Lambda functions", "description": "Look for attacker-created IAM users, roles with trust policies, Lambda functions, EC2 instances, or modified resource policies."},
            {"title": "Assess data exposure in storage services", "description": "Check if S3 buckets, Azure Blobs, or GCS buckets were made public or had data downloaded. Review any databases accessed."},
            {"title": "Remediate and harden cloud security posture", "description": "Remove unauthorized resources, rotate all potentially exposed credentials, enable MFA on all IAM accounts, and apply least-privilege policies."},
        ],
    },
    {
        "name": "Unauthorized Cloud Access Investigation",
        "description": "Investigation playbook for unauthorized access to cloud environments through stolen credentials, API key exposure, or misconfigured access policies.",
        "is_active": False,
        "priority": 3,
        "trigger_conditions": {
            "rule_patterns": ["cloud.*access", "API.*key.*exposed", "cloud.*credential", "S3.*public", "storage.*exposed"],
            "severities": ["medium", "high"],
            "mitre_tactics": ["initial-access", "credential-access"],
            "mitre_techniques": ["T1078.004", "T1552.005", "T1528"],
        },
        "steps": [
            {"title": "Identify the unauthorized access method", "description": "Determine if access was via stolen API keys, exposed credentials in code repos, compromised SSO, misconfigured resource policies, or SSRF.", "is_required": True},
            {"title": "Trace the source of credential exposure", "description": "Check GitHub/GitLab for committed secrets, review CI/CD pipelines, check instance metadata service access, and public code repositories."},
            {"title": "Assess the scope of unauthorized actions", "description": "Review cloud audit logs for all actions performed with the compromised credentials. Map resources accessed and data potentially exposed.", "is_required": True},
            {"title": "Rotate credentials and remediate exposure", "description": "Rotate all affected API keys, access tokens, and passwords. Remove credentials from code repositories. Implement secrets management."},
            {"title": "Deploy preventive controls", "description": "Enable credential scanning in CI/CD, implement SCPs/organization policies, enforce IMDSv2, and deploy CSPM tooling."},
        ],
    },
    {
        "name": "SaaS Account Takeover Response",
        "description": "Response playbook for account takeover attacks targeting SaaS applications (O365, Google Workspace, Salesforce, etc.).",
        "is_active": False,
        "priority": 3,
        "trigger_conditions": {
            "rule_patterns": ["SaaS.*takeover", "O365.*compromise", "Google.*workspace.*breach", "OAuth.*abuse"],
            "severities": ["medium", "high", "critical"],
            "mitre_tactics": ["initial-access", "persistence"],
            "mitre_techniques": ["T1078", "T1550.001", "T1098"],
        },
        "steps": [
            {"title": "Confirm account takeover and lock the account", "description": "Verify the takeover through login anomalies. Immediately reset the password, revoke sessions, and temporarily disable the account if needed.", "is_required": True},
            {"title": "Audit OAuth application grants and API integrations", "description": "Review all third-party app authorizations. Revoke any suspicious or unfamiliar OAuth grants, app passwords, and API tokens."},
            {"title": "Check for data access and exfiltration", "description": "Review audit logs for file downloads, email forwarding, sharing changes, and API data access. Check for new mailbox rules or delegated access.", "is_required": True},
            {"title": "Review and clean up persistence mechanisms", "description": "Remove unauthorized forwarding rules, delegates, connected apps, secondary email addresses, and recovery phone numbers."},
            {"title": "Restore account with enhanced security", "description": "Re-enable the account with MFA enforced, review sharing settings, and monitor for subsequent suspicious activity for 30 days."},
        ],
    },

    # ── Endpoint (3) ──────────────────────────────────────────────────────
    {
        "name": "Endpoint Compromise Triage",
        "description": "Rapid triage playbook for suspected endpoint compromises, designed for SOC analysts to quickly assess severity and determine escalation needs.",
        "is_active": False,
        "priority": 4,
        "trigger_conditions": {
            "rule_patterns": ["endpoint.*compromise", "host.*compromise", "workstation.*alert", "suspicious.*activity"],
            "severities": ["medium", "high", "critical"],
            "mitre_tactics": ["execution", "persistence", "defense-evasion"],
            "mitre_techniques": ["T1059", "T1547", "T1562"],
        },
        "steps": [
            {"title": "Gather endpoint context: user, hostname, OS, last patch date", "description": "Identify the affected endpoint, its owner, business criticality, OS version, and security tool coverage (EDR, AV status).", "is_required": True},
            {"title": "Review the triggering alert and associated telemetry", "description": "Examine the alert details, process tree, file hashes, network connections, and registry changes associated with the detection."},
            {"title": "Check for additional alerts on the same endpoint", "description": "Search SIEM for related alerts in the past 24-72 hours. Look for alert clusters indicating a multi-stage attack.", "is_required": True},
            {"title": "Assess process execution chain and legitimacy", "description": "Analyze the parent-child process relationship. Determine if the flagged process is expected for the user's role and system purpose."},
            {"title": "Determine severity and escalation path", "description": "Based on findings, classify as: false positive (close), true positive - low impact (remediate), or true positive - high impact (escalate to IR team).", "is_required": True},
        ],
    },
    {
        "name": "Suspicious Process Investigation",
        "description": "Deep investigation playbook for suspicious process executions detected by EDR, covering process analysis, behavioral assessment, and threat determination.",
        "is_active": False,
        "priority": 3,
        "trigger_conditions": {
            "rule_patterns": ["suspicious.*process", "unusual.*process", "anomalous.*execution", "process.*injection"],
            "severities": ["medium", "high"],
            "mitre_tactics": ["execution", "defense-evasion"],
            "mitre_techniques": ["T1059", "T1055", "T1036"],
        },
        "steps": [
            {"title": "Analyze the suspicious process and its arguments", "description": "Review the full command line, process path, digital signature status, file hash, and creation timestamp. Compare against known-good baselines.", "is_required": True},
            {"title": "Map the complete process tree", "description": "Trace parent processes back to the originating application. Identify the initial trigger (user action, scheduled task, service, exploit)."},
            {"title": "Check file reputation and behavioral indicators", "description": "Submit file hash to VirusTotal and threat intel platforms. Review process behavior: file writes, registry changes, network connections."},
            {"title": "Assess network activity from the process", "description": "Check for outbound connections, DNS queries, and data transfers initiated by the process. Look for C2 beaconing patterns.", "is_required": True},
            {"title": "Determine verdict and take action", "description": "Classify as legitimate, suspicious (needs monitoring), or malicious (needs containment). Document rationale and update detection rules."},
        ],
    },
    {
        "name": "USB/Removable Media Incident",
        "description": "Investigation playbook for unauthorized USB or removable media usage, covering data loss prevention, forensic analysis, and policy enforcement.",
        "is_active": False,
        "priority": 2,
        "trigger_conditions": {
            "rule_patterns": ["USB", "removable.*media", "external.*device", "mass.*storage"],
            "severities": ["low", "medium", "high"],
            "mitre_tactics": ["exfiltration", "initial-access"],
            "mitre_techniques": ["T1052", "T1091", "T1200"],
        },
        "steps": [
            {"title": "Identify the device and user involved", "description": "Determine the USB device type (storage, phone, hardware token), serial number, and the user who connected it. Check device registration status.", "is_required": True},
            {"title": "Review DLP alerts and file transfer activity", "description": "Check DLP logs for files copied to/from the device. Assess sensitivity of any transferred data (PII, trade secrets, source code)."},
            {"title": "Analyze the USB device if retained", "description": "If the device is available, scan for malware, check for BadUSB/Rubber Ducky indicators, and review stored file contents."},
            {"title": "Determine if policy violation or security incident", "description": "Assess whether this is a simple policy violation (requires HR notification) or a deliberate security incident (requires investigation escalation).", "is_required": True},
            {"title": "Enforce controls and document incident", "description": "Apply USB blocking policy if not already enforced. Document the incident. Provide security awareness training to the user if appropriate."},
        ],
    },

    # ── Data Protection (2) ───────────────────────────────────────────────
    {
        "name": "Data Exfiltration Investigation",
        "description": "Investigation playbook for suspected data exfiltration attempts, covering channel analysis, volume assessment, and data classification.",
        "is_active": False,
        "priority": 4,
        "trigger_conditions": {
            "rule_patterns": ["exfiltrat", "data.*leak", "data.*theft", "large.*upload", "bulk.*download"],
            "severities": ["high", "critical"],
            "mitre_tactics": ["exfiltration"],
            "mitre_techniques": ["T1048", "T1567", "T1537", "T1041"],
        },
        "steps": [
            {"title": "Identify the exfiltration channel and method", "description": "Determine the exfiltration vector: web upload, email, cloud sync, DNS tunneling, FTP, removable media, or encrypted channel.", "is_required": True},
            {"title": "Quantify the data volume and timeline", "description": "Calculate total data transferred, identify the time window, and establish if exfiltration is ongoing or completed."},
            {"title": "Classify the exfiltrated data", "description": "Determine what data was taken: PII, financial records, intellectual property, credentials, or other sensitive information. Assess business impact.", "is_required": True},
            {"title": "Identify the responsible entity", "description": "Determine if exfiltration was by a compromised account (external attacker), malware (automated), or authorized user (insider threat)."},
            {"title": "Contain the exfiltration channel", "description": "Block the exfiltration destination, disable the responsible account or process, and apply DLP rules to prevent further data loss.", "is_required": True},
            {"title": "Assess regulatory notification requirements", "description": "Based on data classification, determine if breach notification is required under GDPR, CCPA, HIPAA, or other regulations. Engage legal counsel."},
        ],
    },
    {
        "name": "Sensitive Data Exposure Response",
        "description": "Response playbook for incidents involving accidental or unauthorized exposure of sensitive data through misconfiguration, oversharing, or public disclosure.",
        "is_active": False,
        "priority": 3,
        "trigger_conditions": {
            "rule_patterns": ["data.*expos", "data.*breach", "public.*bucket", "credential.*leak", "PII.*expos"],
            "severities": ["medium", "high", "critical"],
            "mitre_tactics": ["collection", "exfiltration"],
            "mitre_techniques": ["T1530", "T1213", "T1119"],
        },
        "steps": [
            {"title": "Identify what data was exposed and for how long", "description": "Determine the type, volume, and sensitivity of exposed data. Establish the exposure window from creation/modification to discovery.", "is_required": True},
            {"title": "Immediately remediate the exposure", "description": "Remove public access, fix misconfiguration, revoke shared links, or take down the exposed resource. Verify remediation is effective.", "is_required": True},
            {"title": "Assess who accessed the exposed data", "description": "Review access logs, web server logs, or CDN logs to identify external entities that may have accessed the exposed data."},
            {"title": "Determine root cause of the exposure", "description": "Investigate whether exposure was due to misconfiguration, process failure, lack of access controls, or intentional action."},
            {"title": "Notify affected parties and regulators if required", "description": "Based on data type and applicable regulations, prepare breach notifications for affected individuals and regulatory bodies."},
        ],
    },

    # ── Compliance & Other (2) ────────────────────────────────────────────
    {
        "name": "Compliance Violation Response",
        "description": "Response playbook for detected compliance violations (PCI-DSS, HIPAA, SOX, GDPR) requiring investigation, remediation, and documentation.",
        "is_active": False,
        "priority": 2,
        "trigger_conditions": {
            "rule_patterns": ["compliance.*violat", "PCI.*violation", "HIPAA.*violation", "GDPR.*violation", "audit.*fail"],
            "severities": ["medium", "high"],
            "mitre_tactics": [],
            "mitre_techniques": [],
        },
        "steps": [
            {"title": "Document the compliance violation details", "description": "Record the specific control requirement violated, systems involved, data affected, and how the violation was detected.", "is_required": True},
            {"title": "Assess impact and determine reporting obligations", "description": "Evaluate the severity of the violation, number of records affected, and whether mandatory reporting to regulators is required.", "is_required": True},
            {"title": "Implement immediate remediation", "description": "Apply compensating controls or fix the non-compliant configuration. Verify the remediation addresses the specific control requirement."},
            {"title": "Investigate root cause and contributing factors", "description": "Determine why the violation occurred: process failure, configuration drift, lack of monitoring, or insufficient access controls."},
            {"title": "Update compliance documentation and controls", "description": "Document the violation, remediation, and preventive measures in the compliance tracking system. Schedule follow-up audit."},
        ],
    },
    {
        "name": "Third-Party/Supply Chain Incident",
        "description": "Response playbook for security incidents involving third-party vendors, supply chain compromises, or partner organization breaches.",
        "is_active": False,
        "priority": 4,
        "trigger_conditions": {
            "rule_patterns": ["supply.*chain", "third.*party.*breach", "vendor.*compromise", "SolarWinds", "dependency.*attack"],
            "severities": ["high", "critical"],
            "mitre_tactics": ["initial-access"],
            "mitre_techniques": ["T1195", "T1195.001", "T1195.002"],
        },
        "steps": [
            {"title": "Identify the compromised vendor/component and exposure", "description": "Determine which vendor, software, or service is compromised. Map all organizational systems and data that interact with the affected component.", "is_required": True},
            {"title": "Isolate or disable the compromised integration", "description": "Disable API connections, revoke vendor access credentials, block network connectivity to the vendor, or isolate affected systems.", "is_required": True},
            {"title": "Assess if the compromise propagated to your environment", "description": "Search for IOCs published about the supply chain attack. Check if malicious updates were installed, backdoors deployed, or data accessed."},
            {"title": "Coordinate with the vendor's incident response team", "description": "Establish communication with the vendor's security team. Request IOCs, timeline, scope information, and remediation guidance."},
            {"title": "Review and update third-party risk management", "description": "Re-assess the vendor's security posture. Update vendor risk assessments, contractual security requirements, and monitoring controls."},
            {"title": "Communicate internally and externally as needed", "description": "Brief leadership, legal, and affected business units. Determine if customer notification is required based on data exposure assessment."},
        ],
    },
]


def main():
    print(f"Connecting to ION at {BASE_URL}...")

    # Authenticate
    login_resp = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"username": ADMIN_USER, "password": ADMIN_PASS},
    )
    if login_resp.status_code != 200:
        print(f"Login failed: {login_resp.status_code} {login_resp.text}")
        sys.exit(1)

    token = login_resp.json().get("access_token")
    if not token:
        # Try cookie-based auth
        cookies = login_resp.cookies
        headers = {}
    else:
        cookies = None
        headers = {"Authorization": f"Bearer {token}"}

    print(f"Authenticated as {ADMIN_USER}")

    created = 0
    skipped = 0
    errors = 0

    for pb_data in PLAYBOOKS:
        name = pb_data["name"]
        payload = {
            "name": pb_data["name"],
            "description": pb_data["description"],
            "is_active": pb_data["is_active"],
            "priority": pb_data["priority"],
            "trigger_conditions": pb_data["trigger_conditions"],
            "steps": [
                {
                    "step_type": "manual_checklist",
                    "title": step["title"],
                    "description": step.get("description", ""),
                    "is_required": step.get("is_required", False),
                }
                for step in pb_data["steps"]
            ],
        }

        resp = requests.post(
            f"{BASE_URL}/api/playbooks",
            json=payload,
            headers=headers,
            cookies=cookies,
        )

        if resp.status_code == 200:
            pb_id = resp.json().get("id", "?")
            print(f"  [OK] Created: {name} (id={pb_id})")
            created += 1
        elif resp.status_code == 400 and "already exists" in resp.text.lower():
            print(f"  [SKIP] Already exists: {name}")
            skipped += 1
        else:
            print(f"  [ERR] {resp.status_code}: {name} - {resp.text[:120]}")
            errors += 1

    print(f"\nDone! Created: {created}, Skipped: {skipped}, Errors: {errors}")
    print(f"Total playbooks in library: {created + skipped}")


if __name__ == "__main__":
    main()
