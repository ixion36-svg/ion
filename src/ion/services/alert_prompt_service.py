"""Alert-prompt template service.

Resolves the best-matching AlertPromptTemplate for an incoming alert dict
and renders a merged system prompt combining ION's base security prompt
(from ``ollama_service.SYSTEM_PROMPTS["security"]``) with the per-rule
investigation guide and checklist.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from sqlalchemy.orm import Session

from ion.models.alert_prompt import AlertPromptTemplate
from ion.storage.alert_prompt_repository import AlertPromptRepository

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Default seed templates — ~5 defaults for common Elastic Security rule groups.
# Each prompt_text + checklist is kept under 400 words.
# ---------------------------------------------------------------------------

_DEFAULT_TEMPLATES: list[dict] = [
    {
        "name": "Sysmon Event 1 — Process Creation",
        "description": (
            "Investigation guide for Sysmon process-creation telemetry "
            "(EventID 1). Focus on parent/child chain, command-line, and "
            "image hashes."
        ),
        "rule_groups": ["sysmon_event_1"],
        "priority": 50,
        "severity_hint": "medium",
        "prompt_text": (
            "You are investigating a Sysmon process-creation event (EventID 1). "
            "Focus on the parent-child process chain, command-line arguments, "
            "image path and hash, integrity level, and user context. Cross-check "
            "the image hash against threat intel and known LOLBin inventories "
            "(ATT&CK T1059, T1218). Flag obfuscated command-lines, encoded "
            "PowerShell, unusual parent processes (e.g. winword.exe spawning "
            "cmd.exe), writes to Temp/AppData, and signed-binary proxy execution. "
            "Correlate with Event 3 (network connection) and Event 11 (file "
            "create) from the same process GUID to build a timeline. Decide "
            "whether the activity is benign administration, a known tool, or "
            "suspected adversary execution."
        ),
        "investigation_checklist_text": (
            "- What is the parent process and its full command-line?\n"
            "- Is the image path a known-good signed binary, or in a user-"
            "writeable location?\n"
            "- Does the hash match any threat-intel hit (VT / OpenCTI / TIDE)?\n"
            "- Does the command-line contain encoded, compressed, or "
            "obfuscated payloads?\n"
            "- Is the integrity level elevated vs expected?\n"
            "- Are there related network connections (Sysmon 3) or file writes "
            "(Sysmon 11) from the same process GUID?\n"
            "- Does the activity align with any MITRE ATT&CK technique "
            "(T1059.*, T1218.*, T1036.*)?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "recommended_actions",
            "ioc_confidence",
        ],
    },
    {
        "name": "Sysmon Event 3 — Network Connection",
        "description": (
            "Investigation guide for Sysmon network-connection telemetry "
            "(EventID 3). Focus on destination reputation, beaconing, and "
            "process context."
        ),
        "rule_groups": ["sysmon_event_3"],
        "priority": 50,
        "severity_hint": "medium",
        "prompt_text": (
            "You are investigating a Sysmon network-connection event (EventID "
            "3). Determine which process initiated the connection, the "
            "destination IP/host/port, and whether the traffic pattern looks "
            "like C2, data staging, or legitimate telemetry. Check the "
            "destination against TI feeds, passive DNS, and internal asset "
            "inventory. Look for beaconing cadence, unusual ports for the "
            "protocol, DNS-over-HTTPS providers, and rare destinations for "
            "the process. ATT&CK: T1071 (application layer protocol), T1090 "
            "(proxy), T1105 (ingress tool transfer)."
        ),
        "investigation_checklist_text": (
            "- Which process initiated the connection and is that normal for "
            "it?\n"
            "- Is the destination IP/domain on any threat-intel list?\n"
            "- Is the port/protocol combination unusual for the process?\n"
            "- Are there repeated connections suggesting beaconing?\n"
            "- Do passive DNS / WHOIS records suggest recent domain "
            "registration?\n"
            "- Is the internal asset known to talk to this destination "
            "legitimately?\n"
            "- Are there paired process-create (Sysmon 1) or file-create "
            "(Sysmon 11) events that explain the origin?"
        ),
        "expected_outputs": [
            "verdict",
            "c2_indicators",
            "recommended_actions",
            "ioc_confidence",
        ],
    },
    {
        "name": "Sysmon Event 11 — File Create",
        "description": (
            "Investigation guide for Sysmon file-create telemetry "
            "(EventID 11). Focus on path, extension, and writing process."
        ),
        "rule_groups": ["sysmon_event_11"],
        "priority": 50,
        "severity_hint": "medium",
        "prompt_text": (
            "You are investigating a Sysmon file-create event (EventID 11). "
            "Identify the writing process, target path, and file type. Flag "
            "drops into Temp, AppData, Public, Startup, or Task scheduler "
            "paths. Check for double extensions, masqueraded executables, "
            "script files (.ps1/.js/.hta/.vbs), and persistence locations. "
            "Correlate with subsequent Event 1 (execution) or Event 7 "
            "(image loaded) from the same file. ATT&CK: T1547 (persistence), "
            "T1105 (tool transfer), T1036 (masquerading)."
        ),
        "investigation_checklist_text": (
            "- Which process wrote the file and is that expected behavior?\n"
            "- Is the target path a persistence location (Startup, Run keys, "
            "Scheduled Tasks staging dir)?\n"
            "- Does the file have a suspicious extension or double extension?\n"
            "- Is the file signed, and does the signer match the path?\n"
            "- Was the file subsequently executed (Sysmon 1) or loaded "
            "(Sysmon 7)?\n"
            "- Does the hash match any TI hit?\n"
            "- Is there a matching network download (Sysmon 3) that delivered "
            "the file?"
        ),
        "expected_outputs": [
            "verdict",
            "persistence_indicators",
            "recommended_actions",
            "ioc_confidence",
        ],
    },
    {
        "name": "Authentication Failure",
        "description": (
            "Investigation guide for authentication-failure alerts "
            "(brute-force, password spray, stolen creds)."
        ),
        "rule_groups": ["authentication_failed", "authentication"],
        "priority": 40,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating an authentication-failure alert. "
            "Determine whether this is targeted brute-force, password "
            "spray, credential stuffing, or a benign user lockout. "
            "Examine the source IP(s), user account(s), failure count, "
            "time window, and whether any attempt eventually succeeded. "
            "Check for impossible travel, geo anomalies, and TOR/VPN exit "
            "nodes. Cross-reference the account against privileged-access "
            "and service-account inventories. ATT&CK: T1110 (brute force), "
            "T1110.003 (password spraying), T1078 (valid accounts)."
        ),
        "investigation_checklist_text": (
            "- How many failures, from how many source IPs, in what window?\n"
            "- Is the source IP on a TI blocklist, TOR exit list, or known "
            "VPN range?\n"
            "- Did any attempt succeed afterward?\n"
            "- Is the targeted account privileged or a service account?\n"
            "- Is there impossible travel between successful and failed "
            "logons?\n"
            "- Are multiple accounts being tried from the same IP (spray)?\n"
            "- Has MFA been completed or bypassed on any success?\n"
            "- Was the account locked out; if so has the user reported it?"
        ),
        "expected_outputs": [
            "verdict",
            "attack_pattern",
            "recommended_actions",
            "account_risk",
        ],
    },
    {
        "name": "Malware Detection",
        "description": (
            "Investigation guide for AV / EDR malware-detection alerts. "
            "Focus on containment state and blast radius."
        ),
        "rule_groups": ["malware_detection", "malware"],
        "priority": 20,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating a malware-detection alert from AV or EDR. "
            "First confirm the current containment state: was the sample "
            "quarantined, blocked, or executed? Establish the detection "
            "name, family, and sample hash. Check if other hosts show the "
            "same hash, IOC, or family. Identify the delivery vector "
            "(email attachment, download, USB, lateral movement). "
            "Determine whether this is a known family with public "
            "remediation guidance, or a novel sample requiring sandbox "
            "analysis. ATT&CK: T1204 (user execution), T1566 (phishing), "
            "T1105 (ingress tool transfer)."
        ),
        "investigation_checklist_text": (
            "- Was the sample blocked/quarantined, or did it execute?\n"
            "- What is the detection name and malware family?\n"
            "- Does the hash appear on any other host in the estate?\n"
            "- What was the delivery vector (email, web, removable media, "
            "network share)?\n"
            "- Is there evidence of post-execution activity (persistence, "
            "C2, lateral movement)?\n"
            "- Should the host be isolated from the network now?\n"
            "- Are there known remediation steps for this family (registry "
            "keys, services, scheduled tasks)?\n"
            "- Do we need to rotate credentials used on the host?"
        ),
        "expected_outputs": [
            "verdict",
            "containment_state",
            "blast_radius",
            "recommended_actions",
        ],
    },
    # ------------------------------------------------------------------
    # Elastic Security Rule Templates (10)
    # ------------------------------------------------------------------
    {
        "name": "Credential Access",
        "description": (
            "Investigation guide for credential-access alerts — credential "
            "dumping, LSASS access, Kerberoasting, and pass-the-hash activity."
        ),
        "rule_groups": [
            "credential_dumping", "lsass", "mimikatz",
            "kerberoasting", "pass-the-hash",
        ],
        "rule_id_pattern": r"(?i)(credential.?dump|lsass|mimikatz|kerberoast|pass.the.hash)",
        "priority": 30,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating a credential-access alert. Determine which "
            "credential store was targeted (LSASS, SAM, NTDS.dit, Kerberos "
            "tickets, cached credentials, browser vaults). Identify the tool "
            "or technique used — Mimikatz, ProcDump, comsvcs.dll MiniDump, "
            "Rubeus, Kerberoasting via SPN enumeration, or pass-the-hash with "
            "Sekurlsa. Check the process ancestry, access rights requested on "
            "LSASS (PROCESS_VM_READ, PROCESS_QUERY_INFORMATION), and whether "
            "the caller was running as SYSTEM or with SeDebugPrivilege. "
            "Correlate with subsequent lateral movement, new logon sessions "
            "(4624 type 9/10), and TGS requests (4769) for service accounts. "
            "ATT&CK: T1003 (OS Credential Dumping), T1558 (Steal or Forge "
            "Kerberos Tickets), T1550.002 (Pass the Hash)."
        ),
        "investigation_checklist_text": (
            "- Which credential store was accessed (LSASS memory, SAM hive, "
            "NTDS.dit, Kerberos tickets)?\n"
            "- What tool or technique was used and what process performed the "
            "access?\n"
            "- Did the calling process have SeDebugPrivilege or run as "
            "SYSTEM?\n"
            "- Are there subsequent logon events (4624 type 9/10) indicating "
            "use of stolen credentials?\n"
            "- Were any TGS requests (4769) issued for high-value SPNs "
            "(Kerberoasting)?\n"
            "- Is there evidence of lateral movement following the credential "
            "access?\n"
            "- Which accounts are compromised and need password resets?\n"
            "- Has Credential Guard or LSA protection been bypassed?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "compromised_accounts",
            "recommended_actions",
        ],
    },
    {
        "name": "Lateral Movement",
        "description": (
            "Investigation guide for lateral-movement alerts — PsExec, WMI, "
            "remote services, RDP, and SMB-based movement."
        ),
        "rule_groups": [
            "lateral_movement", "psexec", "wmi_remote",
            "remote_service", "rdp", "smb",
        ],
        "rule_id_pattern": r"(?i)(lateral.?movement|psexec|wmi.?remote|remote.?service|rdp.?hijack|smb.?exec)",
        "priority": 30,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating a lateral-movement alert. Identify the "
            "source and destination hosts, the account used, and the movement "
            "mechanism (PsExec/SMB named pipe, WMI via DCOM, WinRM/PSRemoting, "
            "RDP session, schtasks /s, or service creation). Check whether the "
            "account is authorised for admin access on the target, whether the "
            "credentials are legitimate or stolen, and whether the action "
            "matches a known admin workflow. Correlate with prior credential-"
            "access alerts on the source host and post-movement activity on "
            "the destination (new processes, file drops, persistence). "
            "ATT&CK: T1021 (Remote Services), T1570 (Lateral Tool Transfer), "
            "T1047 (WMI)."
        ),
        "investigation_checklist_text": (
            "- What is the source host and destination host?\n"
            "- Which account was used and is it authorized for remote admin "
            "on that target?\n"
            "- What movement mechanism was used (PsExec, WMI, WinRM, RDP, "
            "SMB, schtasks)?\n"
            "- Was there a prior credential-access alert on the source "
            "host?\n"
            "- What activity occurred on the destination after the movement "
            "(processes, file writes, persistence)?\n"
            "- Is this part of a known admin workflow or change ticket?\n"
            "- Are there multiple targets being accessed from the same "
            "source (fan-out pattern)?\n"
            "- Should the destination host be isolated for investigation?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "movement_scope",
            "recommended_actions",
        ],
    },
    {
        "name": "Persistence Mechanism",
        "description": (
            "Investigation guide for persistence alerts — scheduled tasks, "
            "registry run keys, startup folders, service creation, and cron jobs."
        ),
        "rule_groups": [
            "scheduled_task", "registry_run_key", "startup_folder",
            "service_creation", "cron_job",
        ],
        "rule_id_pattern": r"(?i)(scheduled.?task|registry.?run|startup.?folder|service.?creat|cron.?job|persistence)",
        "priority": 35,
        "severity_hint": "medium-high",
        "prompt_text": (
            "You are investigating a persistence-mechanism alert. Identify the "
            "persistence type: scheduled task, registry Run/RunOnce key, "
            "Startup folder shortcut, new Windows service, WMI event "
            "subscription, or Linux cron job. Determine what binary or script "
            "will execute on trigger, who created the entry, and when it will "
            "fire. Check whether the payload path is in a user-writeable "
            "location, whether the binary is signed, and whether the "
            "persistence was created by a legitimate installer or admin tool. "
            "Correlate with earlier execution/download events that delivered "
            "the payload. ATT&CK: T1053 (Scheduled Task), T1547 (Boot or "
            "Logon Autostart), T1543 (Create or Modify System Process)."
        ),
        "investigation_checklist_text": (
            "- What type of persistence mechanism was created (task, registry, "
            "service, cron, WMI subscription)?\n"
            "- What binary or script is configured to execute?\n"
            "- Is the payload in a user-writeable path (Temp, AppData, /tmp)?\n"
            "- Is the binary signed by a trusted publisher?\n"
            "- Which user account created the persistence entry?\n"
            "- When is the trigger (boot, logon, scheduled time, event-"
            "based)?\n"
            "- Was there a prior download or file-create event that delivered "
            "the payload?\n"
            "- Is there a legitimate change ticket or installer that explains "
            "this activity?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "persistence_indicators",
            "recommended_actions",
        ],
    },
    {
        "name": "Defense Evasion",
        "description": (
            "Investigation guide for defense-evasion alerts — timestomping, "
            "indicator removal, process injection, DLL side-loading, and "
            "masquerading."
        ),
        "rule_groups": [
            "timestomp", "indicator_removal", "process_injection",
            "dll_side_load", "masquerading",
        ],
        "rule_id_pattern": r"(?i)(timestomp|indicator.?remov|process.?inject|dll.?side.?load|masquerad)",
        "priority": 30,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating a defense-evasion alert. Identify which "
            "evasion technique was used: timestomping (SetFileTime calls), log "
            "or indicator removal (wevtutil cl, del /q), process injection "
            "(VirtualAllocEx + WriteProcessMemory + CreateRemoteThread), DLL "
            "side-loading (legitimate exe loading a trojanised DLL from a "
            "non-standard path), or masquerading (renamed system binary, "
            "wrong directory). Check whether security tools (EDR agent, "
            "Sysmon, event log service) were tampered with. Look for process "
            "hollowing indicators: a legitimate-looking process whose image "
            "on disk differs from memory. Correlate with any preceding "
            "execution or payload delivery. ATT&CK: T1070 (Indicator "
            "Removal), T1055 (Process Injection), T1574 (Hijack Execution "
            "Flow), T1036 (Masquerading)."
        ),
        "investigation_checklist_text": (
            "- Which evasion technique was detected (timestomp, log clearing, "
            "injection, side-loading, masquerading)?\n"
            "- What process performed the evasion and what is its ancestry?\n"
            "- Were any security tools or log sources tampered with or "
            "stopped?\n"
            "- For process injection: which target process was injected into "
            "and what code was written?\n"
            "- For side-loading: does the DLL hash match the expected vendor "
            "copy?\n"
            "- For masquerading: does the file metadata (description, signer) "
            "match the filename?\n"
            "- Is there follow-on activity (C2, data access) from the "
            "evading process?\n"
            "- What compensating telemetry can still track this activity?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "evasion_details",
            "recommended_actions",
        ],
    },
    {
        "name": "Discovery / Reconnaissance",
        "description": (
            "Investigation guide for internal discovery alerts — network "
            "scanning, port scanning, AD enumeration, BloodHound, and "
            "SharpHound collection."
        ),
        "rule_groups": [
            "network_scan", "port_scan", "ad_enumeration",
            "bloodhound", "sharphound",
        ],
        "rule_id_pattern": r"(?i)(network.?scan|port.?scan|ad.?enum|bloodhound|sharphound|discovery)",
        "priority": 40,
        "severity_hint": "medium",
        "prompt_text": (
            "You are investigating a discovery/reconnaissance alert. "
            "Determine the scope: port scan (how many targets, which ports), "
            "AD enumeration (LDAP queries for privileged groups, SPNs, GPOs), "
            "or specialised tooling (BloodHound/SharpHound collection, "
            "ADRecon, PowerView). Identify the source host and user account. "
            "Assess whether this is legitimate IT operations (vulnerability "
            "scanner, Nessus, authorised pentest) or adversary reconnaissance. "
            "Check scan timing, volume, and whether the source host has prior "
            "compromise indicators. ATT&CK: T1046 (Network Service Discovery), "
            "T1087 (Account Discovery), T1069 (Permission Groups Discovery)."
        ),
        "investigation_checklist_text": (
            "- What type of discovery was performed (port scan, LDAP query, "
            "BloodHound, service enumeration)?\n"
            "- How many targets or queries were involved?\n"
            "- Is the source host an authorised scanner (Nessus, Qualys, "
            "authorised pentest)?\n"
            "- Which user account ran the activity?\n"
            "- Is there evidence of prior compromise on the source host?\n"
            "- What information was collected (admin group members, SPNs, "
            "GPO settings, network topology)?\n"
            "- Does the timing align with a scheduled scan or change "
            "window?\n"
            "- Were results exfiltrated or used in a follow-on attack?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "discovery_scope",
            "recommended_actions",
        ],
    },
    {
        "name": "Command and Control (C2)",
        "description": (
            "Investigation guide for C2 alerts — beaconing, Cobalt Strike, "
            "DNS tunnelling, and reverse shell activity."
        ),
        "rule_groups": [
            "beacon", "c2", "cobalt_strike",
            "dns_tunnel", "reverse_shell",
        ],
        "rule_id_pattern": r"(?i)(beacon|c2|cobalt.?strike|dns.?tunnel|reverse.?shell|command.?and.?control)",
        "priority": 20,
        "severity_hint": "critical",
        "prompt_text": (
            "You are investigating a command-and-control alert. This is a "
            "critical-severity finding — active C2 means an adversary has "
            "persistent remote access. Identify the C2 framework (Cobalt "
            "Strike, Metasploit, Sliver, Brute Ratel, custom), the transport "
            "(HTTPS, DNS, SMB named pipe, DoH), and the beaconing interval "
            "and jitter. Determine the implant process and its persistence. "
            "Check the destination IP/domain against TI feeds and known C2 "
            "infrastructure. Assess blast radius — which hosts and accounts "
            "has this implant touched. Correlate with credential access and "
            "lateral movement. This likely warrants immediate containment. "
            "ATT&CK: T1071 (Application Layer Protocol), T1572 (Protocol "
            "Tunneling), T1573 (Encrypted Channel)."
        ),
        "investigation_checklist_text": (
            "- What C2 framework is in use (Cobalt Strike, Metasploit, "
            "Sliver, custom)?\n"
            "- What transport protocol and port are used?\n"
            "- What is the beaconing interval and jitter pattern?\n"
            "- Is the destination IP/domain known C2 infrastructure in "
            "threat intel?\n"
            "- Which process is the implant running as and how does it "
            "persist?\n"
            "- Has the implant moved laterally to other hosts?\n"
            "- Were credentials dumped from this host?\n"
            "- Should this host be network-isolated immediately?\n"
            "- What is the total blast radius (hosts, accounts, data)?"
        ),
        "expected_outputs": [
            "verdict",
            "c2_indicators",
            "blast_radius",
            "recommended_actions",
        ],
    },
    {
        "name": "Exfiltration",
        "description": (
            "Investigation guide for data-exfiltration alerts — data staging, "
            "cloud storage uploads, and large outbound transfers."
        ),
        "rule_groups": [
            "exfiltration", "data_staging",
            "cloud_storage_upload", "large_outbound",
        ],
        "rule_id_pattern": r"(?i)(exfiltrat|data.?stag|cloud.?storage.?upload|large.?outbound)",
        "priority": 25,
        "severity_hint": "critical",
        "prompt_text": (
            "You are investigating a data-exfiltration alert. Determine what "
            "data was accessed or staged: file types, volume, sensitivity "
            "classification, and data source (file share, database, email, "
            "SharePoint, S3). Identify the exfiltration channel — upload to "
            "cloud storage (Mega, Google Drive, Dropbox), HTTP POST to "
            "external IP, DNS tunnelling, encrypted archive transfer, or "
            "physical media. Check the user account and whether access was "
            "within normal scope. Measure total data volume transferred. "
            "Correlate with prior discovery (file system enumeration) and "
            "staging (archive creation, compression). ATT&CK: T1041 "
            "(Exfiltration Over C2 Channel), T1567 (Exfiltration Over Web "
            "Service), T1048 (Exfiltration Over Alternative Protocol)."
        ),
        "investigation_checklist_text": (
            "- What data was accessed or transferred (file types, volume, "
            "classification)?\n"
            "- What exfiltration channel was used (cloud upload, HTTP, DNS, "
            "physical media)?\n"
            "- What is the total volume of data transferred?\n"
            "- Was the data staged or compressed before transfer (zip, rar, "
            "7z, password-protected archives)?\n"
            "- Which user account performed the access and is this within "
            "their normal scope?\n"
            "- Does the destination match a legitimate business partner or "
            "known file-sharing service?\n"
            "- Is there evidence of prior file-system enumeration or "
            "discovery?\n"
            "- Does this constitute a reportable data breach under "
            "applicable regulations?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "data_impact",
            "recommended_actions",
        ],
    },
    {
        "name": "Privilege Escalation",
        "description": (
            "Investigation guide for privilege-escalation alerts — UAC bypass, "
            "sudo abuse, token manipulation, and exploit-based escalation."
        ),
        "rule_groups": [
            "privilege_escalation", "uac_bypass",
            "sudo", "token_manipulation",
        ],
        "rule_id_pattern": r"(?i)(privilege.?escalat|uac.?bypass|sudo.?abuse|token.?manipulat)",
        "priority": 30,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating a privilege-escalation alert. Identify the "
            "escalation vector: UAC bypass (fodhelper, eventvwr, CMSTP), "
            "sudo misconfiguration or CVE, token theft/impersonation "
            "(DuplicateTokenEx, ImpersonateLoggedOnUser), named-pipe "
            "impersonation (PrintSpoofer, Potato family), kernel exploit, or "
            "misconfigured service permissions (unquoted path, writeable "
            "service binary). Determine the before and after privilege level. "
            "Check whether the escalation was performed by a tool (e.g. "
            "PrintSpoofer.exe, JuicyPotato) or a built-in mechanism. "
            "Correlate with subsequent high-privilege actions. ATT&CK: "
            "T1548 (Abuse Elevation Control), T1134 (Access Token "
            "Manipulation), T1068 (Exploitation for Privilege Escalation)."
        ),
        "investigation_checklist_text": (
            "- What escalation technique was used (UAC bypass, sudo, token "
            "manipulation, kernel exploit, service abuse)?\n"
            "- What was the before and after privilege level?\n"
            "- Was a known tool used (PrintSpoofer, Potato, Mimikatz)?\n"
            "- Is the vulnerable component patched on this host?\n"
            "- What actions were taken after escalation (persistence, "
            "credential access, lateral movement)?\n"
            "- Was the original low-privilege access legitimate or itself "
            "a compromise?\n"
            "- Are other hosts in the estate vulnerable to the same "
            "escalation?\n"
            "- Should the host be isolated and rebuilt?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "escalation_path",
            "recommended_actions",
        ],
    },
    {
        "name": "Suspicious Execution",
        "description": (
            "Investigation guide for suspicious execution alerts — PowerShell, "
            "WScript, mshta, certutil, bitsadmin, and rundll32 abuse."
        ),
        "rule_groups": [
            "powershell", "wscript", "mshta",
            "certutil", "bitsadmin", "rundll32",
        ],
        "rule_id_pattern": r"(?i)(powershell.?exec|wscript|mshta|certutil|bitsadmin|rundll32|suspicious.?exec)",
        "priority": 35,
        "severity_hint": "medium-high",
        "prompt_text": (
            "You are investigating a suspicious execution alert involving "
            "a living-off-the-land binary (LOLBin) or scripting engine. "
            "Identify the specific binary (PowerShell, cmd, wscript, cscript, "
            "mshta, certutil, bitsadmin, rundll32, regsvr32, msiexec) and its "
            "full command-line. Check for encoded commands (-enc, -e), download "
            "cradles (IEX/IWR, certutil -urlcache, bitsadmin /transfer), COM "
            "object abuse, or DLL execution via rundll32/regsvr32. Examine "
            "parent process — unexpected parents (winword, excel, outlook) "
            "strongly indicate exploitation. Check for AMSI bypass attempts "
            "and constrained language mode evasion. ATT&CK: T1059 (Command "
            "and Scripting Interpreter), T1218 (System Binary Proxy "
            "Execution), T1027 (Obfuscated Files)."
        ),
        "investigation_checklist_text": (
            "- Which LOLBin or scripting engine was invoked?\n"
            "- What is the full command-line and is it encoded or "
            "obfuscated?\n"
            "- What is the parent process — is it an office app, browser, "
            "or other unexpected parent?\n"
            "- Is there a download cradle (IEX, certutil -urlcache, "
            "bitsadmin /transfer, curl)?\n"
            "- Was AMSI bypassed or constrained language mode evaded?\n"
            "- What did the script or binary ultimately do (file drop, "
            "registry write, network call)?\n"
            "- Is there a matching payload file on disk?\n"
            "- Does the decoded/deobfuscated content reveal known "
            "malware or framework stager?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "execution_details",
            "recommended_actions",
        ],
    },
    {
        "name": "Initial Access",
        "description": (
            "Investigation guide for initial-access alerts — phishing, "
            "spearphishing, macro execution, public-facing exploits, and "
            "drive-by compromise."
        ),
        "rule_groups": [
            "phishing", "spearphish", "macro",
            "exploit_public", "drive_by",
        ],
        "rule_id_pattern": r"(?i)(phish|spearphish|macro.?exec|exploit.?public|drive.by)",
        "priority": 30,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating an initial-access alert. Determine the "
            "delivery vector: email phishing with attachment or link, "
            "spearphishing via messaging platform, malicious macro execution "
            "in an Office document, exploitation of a public-facing "
            "application (CVE), or drive-by download from a compromised "
            "website. For phishing, examine sender, subject, attachment "
            "name/hash, and link target. For exploits, identify the CVE, "
            "the vulnerable service, and whether a patch was available. "
            "Determine whether the payload executed successfully and what "
            "it did next. Check how many users received the same lure. "
            "ATT&CK: T1566 (Phishing), T1190 (Exploit Public-Facing "
            "Application), T1189 (Drive-by Compromise)."
        ),
        "investigation_checklist_text": (
            "- What was the delivery vector (email attachment, email link, "
            "exploit, drive-by, messaging)?\n"
            "- For phishing: who is the sender, what is the subject, and "
            "how many recipients received it?\n"
            "- For attachments: what is the file type, hash, and macro "
            "content?\n"
            "- For exploits: what CVE was targeted and is the host "
            "patched?\n"
            "- Did the payload execute successfully?\n"
            "- What post-exploitation activity occurred (download, "
            "persistence, C2 callback)?\n"
            "- Are there other users who clicked the same link or opened "
            "the same attachment?\n"
            "- Has the phishing email been reported via the SOC phishing "
            "mailbox?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "initial_access_vector",
            "recommended_actions",
        ],
    },
    # ------------------------------------------------------------------
    # Sigma Rule Category Templates (10)
    # ------------------------------------------------------------------
    {
        "name": "Web Application Attack",
        "description": (
            "Investigation guide for web-application attacks — SQL injection, "
            "XSS, web shell detection, directory traversal, and remote code "
            "execution."
        ),
        "rule_groups": [
            "sql_injection", "xss", "web_shell",
            "directory_traversal", "rce",
        ],
        "rule_id_pattern": r"(?i)(sql.?inject|xss|web.?shell|directory.?travers|rce|remote.?code)",
        "priority": 25,
        "severity_hint": "critical",
        "prompt_text": (
            "You are investigating a web-application attack alert. Identify "
            "the attack type: SQL injection (union/error-based/blind), XSS "
            "(reflected/stored/DOM), web shell upload or access, directory "
            "traversal (../), or remote code execution via deserialization or "
            "command injection. Examine the HTTP request (URI, parameters, "
            "headers, body) for payloads. Check the source IP reputation and "
            "geo. Determine whether the WAF blocked the request or it reached "
            "the application. Review server response codes and body for "
            "evidence of success (data leakage, error messages, shell output). "
            "Check for web shell artifacts on the file system (new .php/.jsp/"
            ".aspx files in web roots). ATT&CK: T1190 (Exploit Public-Facing "
            "Application), T1505.003 (Web Shell)."
        ),
        "investigation_checklist_text": (
            "- What type of web attack was attempted (SQLi, XSS, web shell, "
            "traversal, RCE)?\n"
            "- What is the full malicious request (URI, params, headers)?\n"
            "- Was the attack blocked by WAF or did it reach the "
            "application?\n"
            "- Does the server response indicate success (data leaked, "
            "error details exposed, command output)?\n"
            "- What is the source IP and does it appear in threat intel?\n"
            "- Are there new files in web-accessible directories (web "
            "shell indicators)?\n"
            "- Is the vulnerable application patched and what CVE applies?\n"
            "- Are other applications on the same host at risk?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "attack_details",
            "recommended_actions",
        ],
    },
    {
        "name": "Linux/Unix Suspicious Activity",
        "description": (
            "Investigation guide for Linux/Unix alerts — suspicious shell "
            "commands, reverse shells, crontab modification, SSH brute force, "
            "and sudo abuse."
        ),
        "rule_groups": [
            "suspicious_shell", "reverse_shell", "crontab",
            "ssh_brute", "sudo_abuse",
        ],
        "rule_id_pattern": r"(?i)(suspicious.?shell|reverse.?shell|crontab|ssh.?brute|sudo.?abuse|linux)",
        "priority": 35,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating a Linux/Unix suspicious activity alert. "
            "Identify the specific behaviour: reverse shell (bash -i >& "
            "/dev/tcp, python pty.spawn, netcat -e), crontab modification "
            "for persistence, SSH brute force attempts, sudo abuse "
            "(sudo -l enumeration, sudoers modification, CVE-2021-3156), or "
            "suspicious interactive shell (history clearing, .bashrc "
            "backdoor, /dev/shm staging). Check the user account, whether it "
            "is a service account or interactive user, and the source of the "
            "session (SSH, console, cron). Review command history and auth "
            "logs. ATT&CK: T1059.004 (Unix Shell), T1053.003 (Cron), "
            "T1110 (Brute Force), T1548.003 (Sudo and Sudo Caching)."
        ),
        "investigation_checklist_text": (
            "- What suspicious command or behavior was detected?\n"
            "- Which user account executed it and is it a service account?\n"
            "- How was the session established (SSH, console, cron)?\n"
            "- Is there a reverse shell connecting to an external host?\n"
            "- Were crontab entries modified and what do they execute?\n"
            "- For SSH brute force: how many attempts, from which IPs, "
            "and did any succeed?\n"
            "- Were sudo privileges enumerated or escalated?\n"
            "- Is there evidence of history clearing or anti-forensics "
            "(unset HISTFILE, shred)?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "host_risk",
            "recommended_actions",
        ],
    },
    {
        "name": "Cloud Security — AWS",
        "description": (
            "Investigation guide for AWS cloud alerts — CloudTrail anomalies, "
            "IAM changes, S3 bucket exposure, security group changes, and "
            "unauthorized API calls."
        ),
        "rule_groups": [
            "cloudtrail", "iam", "s3_bucket",
            "security_group", "unauthorized_api",
        ],
        "rule_id_pattern": r"(?i)(cloudtrail|iam.?change|s3.?bucket|security.?group|unauthorized.?api|aws)",
        "priority": 35,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating an AWS cloud-security alert. Identify the "
            "specific event: CloudTrail tampering (StopLogging, DeleteTrail, "
            "UpdateTrail), IAM changes (CreateUser, AttachUserPolicy, "
            "CreateAccessKey for another user), S3 bucket policy change "
            "(public access grant, ACL modification), security group change "
            "(0.0.0.0/0 ingress), or unauthorized API calls (AccessDenied "
            "patterns indicating reconnaissance). Check the actor identity "
            "(IAM user, role, assumed-role session), source IP (console vs "
            "API, corporate vs unknown), and whether MFA was used. Cross-"
            "reference with GuardDuty findings. ATT&CK: T1078.004 (Cloud "
            "Accounts), T1562 (Impair Defenses), T1537 (Transfer Data to "
            "Cloud Account)."
        ),
        "investigation_checklist_text": (
            "- What AWS API action was performed (specific event name)?\n"
            "- Who is the actor (IAM user, role, assumed-role session "
            "name)?\n"
            "- What is the source IP — is it from the corporate range, "
            "VPN, or an unknown location?\n"
            "- Was MFA used for this action?\n"
            "- For IAM changes: what permissions were granted and to whom?\n"
            "- For S3 changes: was the bucket made public or policy "
            "loosened?\n"
            "- For security groups: was 0.0.0.0/0 added for sensitive "
            "ports?\n"
            "- Are there related GuardDuty or CloudTrail Insights "
            "findings?\n"
            "- Is this action covered by an approved change request?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "cloud_impact",
            "recommended_actions",
        ],
    },
    {
        "name": "Cloud Security — Azure",
        "description": (
            "Investigation guide for Azure cloud alerts — Azure AD changes, "
            "conditional access modifications, service principal abuse, and "
            "Key Vault access."
        ),
        "rule_groups": [
            "azure_ad", "conditional_access",
            "service_principal", "key_vault",
        ],
        "rule_id_pattern": r"(?i)(azure.?ad|conditional.?access|service.?principal|key.?vault|azure)",
        "priority": 35,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating an Azure cloud-security alert. Identify the "
            "event: Azure AD change (new user, role assignment, guest invite, "
            "MFA policy change), conditional access policy modification "
            "(disabled, added exclusion), service principal credential "
            "addition or abuse, or Key Vault secret/key access by an "
            "unexpected principal. Check the actor identity (user principal "
            "name, app ID), the target resource, and the client IP. Review "
            "Azure AD sign-in logs for the actor — look for risk detections, "
            "impossible travel, or unfamiliar devices. Cross-reference with "
            "Microsoft Defender for Cloud alerts. ATT&CK: T1078.004 (Cloud "
            "Accounts), T1098 (Account Manipulation), T1552.005 (Cloud "
            "Instance Metadata API)."
        ),
        "investigation_checklist_text": (
            "- What Azure operation was performed (specific operation name "
            "from activity log)?\n"
            "- Who is the actor (UPN, app ID, managed identity)?\n"
            "- What resource was modified or accessed?\n"
            "- Were conditional access policies weakened or disabled?\n"
            "- Were credentials added to a service principal?\n"
            "- Was Key Vault accessed by an unexpected principal?\n"
            "- Does the actor's sign-in log show risk detections "
            "(impossible travel, unfamiliar location)?\n"
            "- Is this covered by an approved change request or IaC "
            "deployment?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "cloud_impact",
            "recommended_actions",
        ],
    },
    {
        "name": "Email Security / BEC",
        "description": (
            "Investigation guide for email-security alerts — suspicious "
            "forwarding rules, inbox rule creation, mail flow changes, "
            "business email compromise, and impersonation."
        ),
        "rule_groups": [
            "email_forwarding", "inbox_rule",
            "mail_flow", "bec", "impersonation",
        ],
        "rule_id_pattern": r"(?i)(email.?forward|inbox.?rule|mail.?flow|bec|impersonat|business.?email)",
        "priority": 30,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating an email-security alert. Determine the "
            "type: suspicious inbox rule creation (auto-forward, move-to-"
            "deleted, auto-reply with data), mail-flow transport rule change, "
            "business email compromise (CEO fraud, vendor impersonation, "
            "payment redirect), or display-name/domain impersonation. For "
            "inbox rules, check what conditions trigger the rule and where "
            "mail is forwarded or moved. For BEC, verify the sender identity, "
            "check reply-to address, and look for urgency cues. Review "
            "whether the account was recently compromised (impossible travel, "
            "new MFA device, password change). Check how many messages have "
            "been affected. ATT&CK: T1114 (Email Collection), T1566 "
            "(Phishing), T1534 (Internal Spearphishing)."
        ),
        "investigation_checklist_text": (
            "- What email rule or action was created/modified?\n"
            "- For forwarding rules: where are emails being forwarded to "
            "(external address)?\n"
            "- For inbox rules: what conditions trigger the rule and what "
            "action is taken (delete, move, forward)?\n"
            "- For BEC: what is the impersonated identity and what is "
            "being requested (wire transfer, gift cards, credentials)?\n"
            "- Was the email account recently compromised (check sign-in "
            "logs)?\n"
            "- How many messages have been affected by the rule?\n"
            "- Has any financial action been taken based on the fraudulent "
            "email?\n"
            "- Should the account be suspended and password reset?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "email_impact",
            "recommended_actions",
        ],
    },
    {
        "name": "DNS Anomaly",
        "description": (
            "Investigation guide for DNS anomaly alerts — DNS over HTTPS, "
            "domain generation algorithms, DNS rebinding, and excessive "
            "NXDOMAIN responses."
        ),
        "rule_groups": [
            "dns_over_https", "dga", "dns_rebinding",
            "excessive_nxdomain",
        ],
        "rule_id_pattern": r"(?i)(dns.?over.?https|dga|dns.?rebind|excessive.?nxdomain|dns.?anomal|dns.?tunnel)",
        "priority": 30,
        "severity_hint": "medium-high",
        "prompt_text": (
            "You are investigating a DNS anomaly alert. Identify the anomaly "
            "type: DNS over HTTPS (DoH) usage bypassing corporate DNS "
            "visibility, DGA-generated domains (high entropy, algorithmic "
            "patterns), DNS rebinding (rapid A-record changes between "
            "external and internal IPs), excessive NXDOMAIN responses "
            "(indicating DGA C2 check-in or reconnaissance), or DNS "
            "tunnelling (unusually long subdomains or high query volume to "
            "a single domain). Check which process is generating the queries, "
            "the query volume and entropy, and whether the destination "
            "resolvers are corporate or external. Cross-reference domains "
            "against threat intel and passive DNS. ATT&CK: T1568.002 (Domain "
            "Generation Algorithms), T1572 (Protocol Tunneling), T1071.004 "
            "(DNS)."
        ),
        "investigation_checklist_text": (
            "- What type of DNS anomaly was detected (DoH, DGA, rebinding, "
            "NXDOMAIN flood, tunnelling)?\n"
            "- Which process or host is generating the queries?\n"
            "- What is the entropy and pattern of queried domains?\n"
            "- Are the queries going to corporate DNS or external resolvers "
            "(8.8.8.8, 1.1.1.1, DoH endpoints)?\n"
            "- Do any queried domains match threat intel?\n"
            "- For DGA: what is the estimated algorithm family?\n"
            "- For tunnelling: what is the subdomain length distribution "
            "and query volume per domain?\n"
            "- Is there a corresponding C2 or data-exfiltration channel?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "dns_indicators",
            "recommended_actions",
        ],
    },
    {
        "name": "Endpoint Security Tampering",
        "description": (
            "Investigation guide for endpoint protection tampering — EDR "
            "bypass, agent uninstall, security service tampering, and "
            "exclusion changes."
        ),
        "rule_groups": [
            "edr_bypass", "tamper", "agent_uninstall",
            "exclusion_added",
        ],
        "rule_id_pattern": r"(?i)(edr.?bypass|tamper|agent.?uninstall|exclusion.?add|endpoint.?tamper|defender.?disab)",
        "priority": 20,
        "severity_hint": "critical",
        "prompt_text": (
            "You are investigating an endpoint security tampering alert. This "
            "is critical — disabling defenses is a prerequisite for undetected "
            "malware execution. Identify what was tampered: EDR agent "
            "disabled/uninstalled, Windows Defender real-time protection "
            "turned off, AMSI bypass loaded, Sysmon service stopped, AV "
            "exclusion path/process/extension added, or security event log "
            "cleared. Determine who performed the action and whether it "
            "corresponds to a legitimate admin activity (patch, upgrade, "
            "troubleshooting). Check what happened AFTER the tampering — "
            "this is likely a precursor to payload execution. ATT&CK: T1562 "
            "(Impair Defenses), T1070 (Indicator Removal on Host)."
        ),
        "investigation_checklist_text": (
            "- What endpoint security component was tampered with (EDR, "
            "AV, Sysmon, event logs, AMSI)?\n"
            "- Was the agent disabled, uninstalled, or had exclusions "
            "added?\n"
            "- Who performed the action (user account, process)?\n"
            "- Is there a legitimate change ticket or admin activity "
            "explaining this?\n"
            "- What activity occurred AFTER the tampering (payload "
            "execution, persistence, C2)?\n"
            "- For exclusion additions: what path/process/extension was "
            "excluded and why?\n"
            "- Is the security agent currently running and reporting?\n"
            "- Should the host be isolated until the agent is restored?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "tampering_details",
            "recommended_actions",
        ],
    },
    {
        "name": "Data Loss Prevention (DLP)",
        "description": (
            "Investigation guide for DLP alerts — sensitive file access, "
            "PII exposure, credit card data, and SSN detection."
        ),
        "rule_groups": [
            "dlp", "sensitive_file", "pii",
            "credit_card", "ssn",
        ],
        "rule_id_pattern": r"(?i)(dlp|sensitive.?file|pii|credit.?card|ssn|data.?loss)",
        "priority": 35,
        "severity_hint": "medium-high",
        "prompt_text": (
            "You are investigating a data loss prevention alert. Identify the "
            "data type detected: PII (names, addresses, phone numbers), "
            "financial data (credit card numbers, bank accounts), health "
            "records (PHI/HIPAA), government IDs (SSN, passport), or "
            "classified/proprietary business data. Determine the channel: "
            "email attachment, cloud upload, removable media, print job, "
            "clipboard, or screen share. Check whether the user has a "
            "business justification and whether the data was actually "
            "transmitted or only detected in transit. Assess regulatory "
            "impact (GDPR, HIPAA, PCI-DSS). ATT&CK: T1567 (Exfiltration "
            "Over Web Service), T1052 (Exfiltration Over Physical Medium)."
        ),
        "investigation_checklist_text": (
            "- What type of sensitive data was detected (PII, credit card, "
            "SSN, PHI, proprietary)?\n"
            "- What channel was used (email, cloud upload, USB, print, "
            "clipboard)?\n"
            "- Was the data actually transmitted or was it blocked by the "
            "DLP policy?\n"
            "- Does the user have a business justification for handling "
            "this data?\n"
            "- How much data was involved (record count, file size)?\n"
            "- Does this trigger a regulatory notification requirement "
            "(GDPR 72hr, HIPAA, PCI-DSS)?\n"
            "- Is the user a repeat offender in DLP logs?\n"
            "- Should the user's manager and compliance team be notified?"
        ),
        "expected_outputs": [
            "verdict",
            "data_classification",
            "regulatory_impact",
            "recommended_actions",
        ],
    },
    {
        "name": "Insider Threat",
        "description": (
            "Investigation guide for insider-threat alerts — after-hours "
            "access, mass downloads, USB activity, print anomalies, and "
            "unusual access patterns."
        ),
        "rule_groups": [
            "after_hours", "mass_download", "usb",
            "print", "unusual_access",
        ],
        "rule_id_pattern": r"(?i)(after.?hours|mass.?download|usb.?device|print.?anomal|unusual.?access|insider.?threat)",
        "priority": 35,
        "severity_hint": "medium-high",
        "prompt_text": (
            "You are investigating an insider-threat alert. These alerts "
            "require careful context — distinguish between a busy employee "
            "and malicious intent. Examine the user's baseline: is after-hours "
            "access normal for their role? Has their access pattern changed "
            "recently? Check for correlation with HR events (performance "
            "review, resignation notice, disciplinary action). Review the "
            "data accessed: is it within their normal scope or have they "
            "accessed repositories, file shares, or databases outside their "
            "job function? Check for staging behaviours: mass download, "
            "compression, USB copy, personal email forwarding, or cloud "
            "storage upload. ATT&CK: T1078 (Valid Accounts), T1530 (Data "
            "from Cloud Storage), T1213 (Data from Information Repositories)."
        ),
        "investigation_checklist_text": (
            "- What triggered the alert (after-hours access, volume anomaly, "
            "USB, print, scope deviation)?\n"
            "- Is this user's baseline consistent with this activity?\n"
            "- Has the user recently had an HR event (resignation, PIP, "
            "termination notice)?\n"
            "- What data was accessed and is it within the user's normal "
            "job scope?\n"
            "- Was data staged for removal (compressed, moved to USB, "
            "forwarded to personal email)?\n"
            "- Is there a volume spike compared to the user's 30-day "
            "average?\n"
            "- Should the user's access be restricted pending "
            "investigation?\n"
            "- Does this need to be escalated to HR and Legal?"
        ),
        "expected_outputs": [
            "verdict",
            "user_risk_score",
            "data_impact",
            "recommended_actions",
        ],
    },
    {
        "name": "Ransomware Indicators",
        "description": (
            "Investigation guide for ransomware alerts — encryption behavior, "
            "shadow copy deletion, vssadmin abuse, bcdedit changes, and "
            "ransom note detection."
        ),
        "rule_groups": [
            "ransomware", "encryption", "shadow_copy_delete",
            "vssadmin", "bcdedit",
        ],
        "rule_id_pattern": r"(?i)(ransomware|mass.?encrypt|shadow.?copy.?del|vssadmin|bcdedit|ransom)",
        "priority": 10,
        "severity_hint": "critical",
        "prompt_text": (
            "You are investigating a ransomware indicator alert. This is the "
            "highest priority — ransomware can encrypt an entire environment "
            "in minutes. IMMEDIATELY assess containment: is the host isolated? "
            "Are backups intact? Identify the indicators: mass file extension "
            "changes, ransom note file drops (README.txt, DECRYPT_*.html), "
            "shadow copy deletion (vssadmin delete shadows, wmic "
            "shadowcopy delete), boot config changes (bcdedit /set "
            "recoveryenabled no), process enumeration and service stopping "
            "(taskkill, net stop). Determine the ransomware family if "
            "possible (file extension, ransom note format, TOR payment "
            "site). Check lateral spread — is SMB, PsExec, or GPO being "
            "used to distribute the payload? ATT&CK: T1486 (Data Encrypted "
            "for Impact), T1490 (Inhibit System Recovery), T1489 (Service "
            "Stop)."
        ),
        "investigation_checklist_text": (
            "- Is the affected host isolated from the network RIGHT NOW?\n"
            "- Are backups intact and air-gapped/immutable?\n"
            "- What ransomware indicators are present (file extension "
            "changes, ransom notes, shadow copy deletion)?\n"
            "- Can the ransomware family be identified (note format, "
            "extension, payment site)?\n"
            "- Has the ransomware spread to other hosts (check SMB, "
            "PsExec, GPO, scheduled tasks)?\n"
            "- What was the initial access vector (phishing, RDP, "
            "VPN exploit, supply chain)?\n"
            "- How long was the attacker in the environment before "
            "detonation (dwell time)?\n"
            "- Has the incident been escalated to IR leadership and "
            "legal counsel?\n"
            "- Should law enforcement be notified?"
        ),
        "expected_outputs": [
            "verdict",
            "containment_state",
            "blast_radius",
            "recommended_actions",
            "ransomware_family",
        ],
    },
]


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


class AlertPromptService:
    """Thin wrapper around AlertPromptRepository + system-prompt rendering."""

    def __init__(self, session: Session):
        self.session = session
        self.repo = AlertPromptRepository(session)

    # ----------------------------------------------------------------- resolve

    def resolve_template_for_alert(
        self, alert: dict
    ) -> Optional[AlertPromptTemplate]:
        """Return best-matching enabled template for the alert, or None."""
        return self.repo.find_matching(alert)

    # ------------------------------------------------------------------ render

    def render_system_prompt(
        self,
        template: Optional[AlertPromptTemplate],
        alert: Optional[dict] = None,
    ) -> str:
        """Merge ION's base security system prompt with the template's guidance.

        If ``template`` is None, returns the base security prompt unchanged.
        """
        # Lazy import to avoid tight coupling at import time
        from ion.services.ollama_service import SYSTEM_PROMPTS

        base = SYSTEM_PROMPTS.get("security", "")
        if template is None:
            return base

        parts: list[str] = [base.rstrip()]
        parts.append("\n\n---\n")
        parts.append(f"## Per-Rule Investigation Guide: {template.name}\n")

        if template.description:
            parts.append(template.description.strip() + "\n")

        if template.severity_hint:
            parts.append(
                f"\nSeverity hint for this rule: **{template.severity_hint}**\n"
            )

        if template.prompt_text:
            parts.append("\n### Investigation Focus\n")
            parts.append(template.prompt_text.strip() + "\n")

        if template.investigation_checklist_text:
            parts.append("\n### Checklist — Answer Each\n")
            parts.append(template.investigation_checklist_text.strip() + "\n")

        expected = template.expected_outputs_json
        if expected:
            try:
                fields = json.loads(expected)
                if isinstance(fields, list) and fields:
                    parts.append("\n### Expected Output Fields\n")
                    parts.append(
                        "Produce a structured answer covering: "
                        + ", ".join(str(f) for f in fields)
                        + ".\n"
                    )
            except Exception:
                pass

        if alert:
            rule_id = AlertPromptRepository._extract_rule_id(alert) or "(unknown)"
            parts.append(f"\n_Matched alert rule id: `{rule_id}`_\n")

        return "".join(parts)


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------


def resolve_template_for_alert(
    session: Session, alert: dict
) -> Optional[AlertPromptTemplate]:
    return AlertPromptService(session).resolve_template_for_alert(alert)


def render_system_prompt(
    template: Optional[AlertPromptTemplate],
    alert: Optional[dict] = None,
    session: Optional[Session] = None,
) -> str:
    # Session isn't required for rendering; accept it for symmetry.
    svc = AlertPromptService(session) if session is not None else _DetachedRenderer()
    return svc.render_system_prompt(template, alert)


class _DetachedRenderer(AlertPromptService):
    """Render-only helper that doesn't need a DB session."""

    def __init__(self):  # noqa: D401 — intentionally bypasses parent init
        self.session = None
        self.repo = None


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------


def seed_default_templates(db: Optional[Session] = None) -> int:
    """Insert the default seed templates if the table is empty.

    Idempotent: if any rows already exist, this is a no-op. Returns the number
    of templates inserted.

    Accepts an optional session; if omitted, opens one from the default engine.
    """
    close_after = False
    if db is None:
        from ion.storage.database import get_engine, get_session_factory

        engine = get_engine()
        factory = get_session_factory(engine)
        db = factory()
        close_after = True

    inserted = 0
    try:
        repo = AlertPromptRepository(db)
        # Seed missing templates — check by name to allow adding new defaults
        existing_names = {t.name for t in repo.list_all()}

        for defn in _DEFAULT_TEMPLATES:
            if defn["name"] in existing_names:
                continue
            repo.create(
                name=defn["name"],
                prompt_text=defn.get("prompt_text", ""),
                description=defn.get("description"),
                enabled=True,
                rule_ids=defn.get("rule_ids"),
                rule_groups=defn.get("rule_groups"),
                rule_id_pattern=defn.get("rule_id_pattern"),
                priority=defn.get("priority", 100),
                investigation_checklist_text=defn.get(
                    "investigation_checklist_text"
                ),
                severity_hint=defn.get("severity_hint"),
                expected_outputs=defn.get("expected_outputs"),
                created_by_id=None,
            )
            inserted += 1

        db.commit()
        logger.info("Seeded %d default AlertPromptTemplate rows", inserted)
    except Exception:
        db.rollback()
        logger.exception("Failed to seed default AlertPromptTemplate rows")
        raise
    finally:
        if close_after:
            db.close()

    return inserted
