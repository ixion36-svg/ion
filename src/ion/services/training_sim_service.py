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
