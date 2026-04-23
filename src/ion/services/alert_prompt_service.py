"""Alert-prompt template service.

Resolves the best-matching AlertPromptTemplate for an incoming alert dict
and renders a merged system prompt combining ION's base security prompt
(from ``ollama_service.SYSTEM_PROMPTS["security"]``) with the per-rule
investigation guide and checklist.
"""

from __future__ import annotations

import json
import logging
import os
from typing import List, Optional

from sqlalchemy.orm import Session

from ion.models.alert_prompt import AlertPromptTemplate
from ion.storage.alert_prompt_repository import AlertPromptRepository

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Few-shot gold exemplars — retrieves past, human-agreed closed cases to
# inject as reference context into Bob's system prompt. Opt-in via
# ION_FEW_SHOT_EXEMPLARS_ENABLED — default off because a fresh install has
# no AIFeedback rows to filter on.
# ---------------------------------------------------------------------------


def _few_shot_enabled() -> bool:
    return os.environ.get("ION_FEW_SHOT_EXEMPLARS_ENABLED", "").lower() in (
        "true", "1", "yes",
    )


def _kb_rag_enabled() -> bool:
    return os.environ.get("ION_KB_RAG_ENABLED", "").lower() in (
        "true", "1", "yes",
    )


def _alert_text_for_embedding(alert: dict) -> str:
    """Serialise an alert to text for embedding.

    Aligned with ``case_embedding_service._case_source_text`` so an alert
    vector is directly comparable to case vectors (same section order +
    separators). Pulls from the shapes the investigation pipeline actually
    produces: ``alert_signature``, ``rule_name``, ``host``, ``user_name``,
    ``rule_id`` (or nested ``rule.id``).
    """
    parts: list[str] = []
    title = (
        alert.get("alert_signature")
        or alert.get("rule_name")
        or (alert.get("rule") or {}).get("name")
        or alert.get("title")
    )
    if title:
        parts.append(f"Title: {title}")
    desc = alert.get("description") or alert.get("message")
    if desc:
        parts.append(f"Description: {desc}")
    host = alert.get("host") or alert.get("host_name")
    if host:
        parts.append(f"Hosts: {host}")
    user = alert.get("user_name") or alert.get("user")
    if user:
        parts.append(f"Users: {user}")
    rule_id = alert.get("rule_id") or (alert.get("rule") or {}).get("id")
    if rule_id:
        parts.append(f"Rules: {rule_id}")
    return "\n".join(parts)


def _format_exemplars_for_prompt(exemplars: List[dict]) -> str:
    """Render the "Prior Similar Cases" section. Empty list → empty string."""
    if not exemplars:
        return ""
    lines = [
        "\n\n---\n",
        "## Prior Similar Cases (analyst-verified)\n",
        "These are past cases with high semantic similarity to the current "
        "alert, closed by a human analyst whose verdict agreed with a prior "
        "AI suggestion. Use them as reference — do NOT blindly copy the "
        "verdict; the current alert may differ in substance even when the "
        "wording is similar.\n",
    ]
    for ex in exemplars:
        lines.append(
            f"\n### {ex['case_number']} — `{ex['closure_reason']}` "
            f"(similarity {ex['similarity']:.2f})\n"
        )
        if ex.get("title"):
            lines.append(f"**Title:** {ex['title']}\n")
        summary = (ex.get("summary") or "").strip()
        if summary:
            lines.append(f"**Summary:** {summary[:400]}\n")
        notes = (ex.get("closure_notes") or "").strip()
        if notes:
            lines.append(f"**Analyst closure notes:** {notes[:400]}\n")
    return "".join(lines)


def _format_kb_context_for_prompt(hits: List[dict]) -> str:
    """Render the "Knowledge Base Context" section. Empty list → empty string."""
    if not hits:
        return ""
    lines = [
        "\n\n---\n",
        "## Knowledge Base Context\n",
        "These are ION knowledge base articles most semantically similar to "
        "the current alert. Treat them as reference documentation — they "
        "describe investigation approach, playbook guidance, or detection "
        "background for the topic. They are NOT evidence about this specific "
        "alert.\n",
    ]
    for h in hits:
        lines.append(
            f"\n### {h.get('name') or 'Untitled'} "
            f"(similarity {h['similarity']:.2f})\n"
        )
        excerpt = (h.get("excerpt") or "").strip()
        if excerpt:
            lines.append(f"{excerpt[:800]}\n")
    return "".join(lines)


# ---------------------------------------------------------------------------
# Default seed templates — ~5 defaults for common Elastic Security rule groups.
# Each prompt_text + checklist is kept under 400 words.
# ---------------------------------------------------------------------------

_DEFAULT_TEMPLATES: list[dict] = [
    {
        "name": "Sysmon Event 1 — Process Creation",
        "description": (
            "Investigation guide for Sysmon process-creation telemetry "
            "(EventID 1). Focus on parent/child chain, command-line, "
            "image hashes, and live-forensics artefact collection."
        ),
        "rule_groups": ["sysmon_event_1"],
        "priority": 50,
        "severity_hint": "medium",
        "prompt_text": (
            "You are investigating a Sysmon Event 1 (process creation) "
            "alert. Examine the full command-line in "
            "`data.win.eventdata.commandLine` and the parent command-line "
            "in `data.win.eventdata.parentCommandLine`. Check "
            "`data.win.eventdata.image` (child) and "
            "`data.win.eventdata.parentImage` (parent) — unexpected "
            "parent/child pairs (winword.exe → cmd.exe, outlook.exe → "
            "powershell.exe, svchost.exe → unsigned.exe) are strong "
            "malicious indicators. Inspect "
            "`data.win.eventdata.integrityLevel` and "
            "`data.win.eventdata.user`. Decode any base64 / compressed / "
            "obfuscated command-line content. Extract the SHA256 from "
            "`data.win.eventdata.hashes` and look it up on VirusTotal: "
            "https://www.virustotal.com/gui/file/<sha256>. Correlate with "
            "Sysmon Event 3 (network connections) and Event 11 (file "
            "writes) sharing the same ProcessGuid. Assign the verdict "
            "according to the Output Contract (true_positive / "
            "false_positive / benign_true_positive / inconclusive).\n\n"
            "If the verdict after desk analysis is suspicious or worse "
            "(VT verdict >= suspicious, unusual parent/child, decoded "
            "base64 reveals malicious intent), collect live forensics "
            "from the affected host via Velociraptor in priority order:\n\n"
            "| Priority | Artifact | Why for Sysmon Event 1 |\n"
            "|---|---|---|\n"
            "| P1 | `Windows.System.Pslist` | Is the process still "
            "running? Parent/child tree now. |\n"
            "| P1 | `Windows.Forensics.Prefetch` | First-seen vs repeat "
            "execution of the binary. |\n"
            "| P2 | `Windows.Sysinternals.Autoruns` | Did the process "
            "establish persistence? |\n"
            "| P2 | `Windows.Forensics.UserAssist` | User-initiated "
            "double-click vs spawned programmatically. |\n"
            "| P3 | `Windows.Detection.Yara.Process` | YARA-scan process "
            "memory for known families. |\n"
            "| P3 | `Windows.Memory.ProcessDump` | Full memory dump. "
            "Expensive — confirmed malicious only. |\n"
            "| P3 | `Windows.NTFS.MFT` | File timeline — when dropped, "
            "renamed, deleted. |\n\n"
            "Fold Velociraptor results into `template_specific."
            "live_forensics`. ATT&CK: T1059 (Command and Scripting "
            "Interpreter), T1218 (Signed Binary Proxy Execution), T1036 "
            "(Masquerading)."
        ),
        "investigation_checklist_text": (
            "- What is `parentImage` / `parentCommandLine` — is this a "
            "normal pair for `image`?\n"
            "- Is `image` a signed system binary or a file in a user-"
            "writeable path (Temp, AppData, ProgramData)?\n"
            "- Does `commandLine` contain base64 (`-enc`), "
            "compressed/obfuscated, or download-cradle content (IEX, "
            "certutil -urlcache, bitsadmin /transfer)?\n"
            "- What SHA256 is reported in `hashes` — look it up at "
            "https://www.virustotal.com/gui/file/<sha256>\n"
            "- What is `integrityLevel` — is it elevated unexpectedly?\n"
            "- Which user (`user`) ran the process? Service account, "
            "admin, interactive user?\n"
            "- Related Sysmon 3 (network) or Sysmon 11 (file) events "
            "sharing the same `processGuid`?\n"
            "- Which MITRE techniques (T1059.*, T1218.*, T1036.*) "
            "concretely apply, based on evidence?"
        ),
        "expected_outputs": [
            "process_ancestry",
            "command_line_analysis",
            "vt_verdict",
            "live_forensics",
            "recommended_actions",
        ],
    },
    {
        "name": "Sysmon Event 3 — Network Connection",
        "description": (
            "Investigation guide for Sysmon network-connection telemetry "
            "(EventID 3). Focus on destination reputation, beaconing, "
            "and process-context."
        ),
        "rule_groups": ["sysmon_event_3"],
        "priority": 50,
        "severity_hint": "medium",
        "prompt_text": (
            "You are investigating a Sysmon Event 3 (network connection) "
            "alert. Examine `data.win.eventdata.image` (the initiating "
            "process), `data.win.eventdata.destinationIp`, "
            "`data.win.eventdata.destinationHostname`, "
            "`data.win.eventdata.destinationPort`, and "
            "`data.win.eventdata.protocol`. Ask: is this process "
            "*expected* to talk to the internet at all? rundll32, "
            "regsvr32, certutil, mshta, or newly-created unsigned "
            "binaries doing outbound is a strong red flag. Reverse-DNS / "
            "passive-DNS the destination and look up its reputation on "
            "threat intel (VirusTotal: https://www.virustotal.com/gui/"
            "ip-address/<ip>, URLScan, GreyNoise). Look for patterns: "
            "beaconing cadence (regular intervals with jitter), common "
            "C2 ports (443, 8443, 80, 53), DoH endpoints (1.1.1.1, "
            "cloudflare-dns.com), and rare-destination-for-process "
            "anomalies. Correlate with Sysmon 1 (what invoked the "
            "initiating process) and Sysmon 22 (did it resolve the "
            "destination first) via shared `processGuid`. ATT&CK: "
            "T1071 (Application Layer Protocol), T1090 (Proxy), T1105 "
            "(Ingress Tool Transfer)."
        ),
        "investigation_checklist_text": (
            "- Which process (`image`) initiated the connection — is "
            "outbound traffic expected for it?\n"
            "- What is `destinationIp` / `destinationHostname` / "
            "`destinationPort`?\n"
            "- Does the destination IP / domain appear on TI feeds "
            "(VirusTotal, GreyNoise, URLScan, OpenCTI)?\n"
            "- Is the port unusual for the declared `protocol` or for "
            "the initiating process?\n"
            "- Is there beaconing cadence (repeated connections at "
            "near-regular intervals)?\n"
            "- Did a Sysmon 22 DNS query just precede this (same "
            "`processGuid`)?\n"
            "- Did a Sysmon 1 process-create from this `processGuid` "
            "reveal a suspicious command-line?\n"
            "- Is the internal host known to talk to this destination "
            "legitimately (baseline)?"
        ),
        "expected_outputs": [
            "destination_reputation",
            "beaconing_indicators",
            "process_expected_to_connect",
            "recommended_actions",
        ],
    },
    {
        "name": "Sysmon Event 11 — File Create",
        "description": (
            "Investigation guide for Sysmon file-create telemetry "
            "(EventID 11). Focus on path, extension, writing process, "
            "and the delivery chain."
        ),
        "rule_groups": ["sysmon_event_11"],
        "priority": 50,
        "severity_hint": "medium",
        "prompt_text": (
            "You are investigating a Sysmon Event 11 (file create) "
            "alert. Examine `data.win.eventdata.image` (the writing "
            "process) and `data.win.eventdata.targetFilename` (full "
            "path). Flag drops into Temp, AppData (Roaming / Local), "
            "Public, Startup folders, ProgramData, %WINDIR%\\Tasks, or "
            "user-writeable service-path locations. Check for "
            "masquerading patterns: double-extensions (`invoice.pdf.exe`), "
            "renamed system binaries, script files (.ps1, .js, .hta, "
            ".vbs, .wsf), and LNK files in autostart locations. Extract "
            "the SHA256 if available and look it up at "
            "https://www.virustotal.com/gui/file/<sha256>. Correlate "
            "forward: did a Sysmon 1 execute the file or Sysmon 7 load "
            "it shortly after (same `processGuid` chain)? Correlate "
            "backward: was there a Sysmon 3 network connection or "
            "Sysmon 22 DNS query from the writing process that matches "
            "a download? ATT&CK: T1547 (Boot or Logon Autostart "
            "Execution), T1105 (Ingress Tool Transfer), T1036 "
            "(Masquerading)."
        ),
        "investigation_checklist_text": (
            "- Which process wrote the file (`image`) and is it "
            "expected to write to that location?\n"
            "- What is the target path (`targetFilename`) — is it "
            "user-writeable and/or an autostart location?\n"
            "- Does the file extension look legitimate or "
            "double/masqueraded?\n"
            "- If a hash is available, does the SHA256 appear on "
            "VirusTotal?\n"
            "- Was the file later executed (Sysmon 1) or loaded "
            "(Sysmon 7) within a short window, same `processGuid` "
            "chain?\n"
            "- Was there a preceding Sysmon 3 network download or "
            "Sysmon 22 DNS resolution by the writing process?\n"
            "- Is the file a LNK, script, or signed system-name "
            "masquerade?\n"
            "- Does the activity create persistence (write into Run "
            "key path, Startup folder, Scheduled Task XML dir)?"
        ),
        "expected_outputs": [
            "writer_expected",
            "target_path_category",
            "masquerade_indicators",
            "delivery_chain",
            "recommended_actions",
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
    # ------------------------------------------------------------------
    # Sysmon Event Templates (12 — ported from taylorwalton/talon with
    # ION-native envelope: specific Wazuh/Graylog field references, VT
    # URL pattern, and structured expected_outputs).
    # ------------------------------------------------------------------
    {
        "name": "Sysmon Event 2 — File Creation Time Changed",
        "description": (
            "Investigation guide for Sysmon Event 2 (file creation time "
            "change — often a timestomping precursor). Many legitimate "
            "processes change creation time, so context matters."
        ),
        "rule_groups": ["sysmon_event_2"],
        "priority": 40,
        "severity_hint": "medium",
        "prompt_text": (
            "You are investigating a Sysmon Event 2 alert — a process "
            "explicitly changed a file's creation time. Timestomping is a "
            "classic anti-forensics technique used to disguise a newly "
            "dropped backdoor as an old system file, but many legitimate "
            "processes (installers, archivers, backup tools) also set file "
            "timestamps. Examine `data.win.eventdata.image` (the process), "
            "`data.win.eventdata.targetFilename`, and the before/after "
            "creation time values. Is the target in a system path, a user "
            "Temp/AppData path, or a web root? Is the writer signed and "
            "expected to touch that path? Correlate with prior Sysmon Event "
            "11 (file create) on the same path from the same process GUID "
            "to see whether this is a drop-then-timestomp pattern. ATT&CK: "
            "T1070.006 (Indicator Removal: Timestomp)."
        ),
        "investigation_checklist_text": (
            "- Which process changed the file time (`image`) and is it "
            "expected to modify timestamps?\n"
            "- What is the target path — system, user-writeable, web "
            "server root?\n"
            "- What were the old vs new creation time values?\n"
            "- Is there a preceding Sysmon 11 file-create from the same "
            "process GUID?\n"
            "- Is the file signed and by whom?\n"
            "- Does the hash appear on VirusTotal? "
            "(https://www.virustotal.com/gui/file/<hash>)\n"
            "- Was the file subsequently executed (Sysmon 1) or loaded "
            "(Sysmon 7)?"
        ),
        "expected_outputs": [
            "timestomp_indicators",
            "delivery_chain",
            "recommended_actions",
        ],
    },
    {
        "name": "Sysmon Event 6 — Driver Loaded",
        "description": (
            "Investigation guide for Sysmon Event 6 — a driver loaded on "
            "the system. Kernel-mode code is a high-trust boundary; "
            "unsigned or rare drivers warrant close attention."
        ),
        "rule_groups": ["sysmon_event_6"],
        "priority": 25,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating a Sysmon Event 6 alert — a driver was "
            "loaded. Drivers run in kernel mode: a malicious driver can "
            "disable EDR, hide processes, and persist rootkit-style. "
            "Examine `data.win.eventdata.imageLoaded` (driver path and "
            "filename), `signature` / `signatureStatus`, and the hashes "
            "(MD5/SHA1/SHA256/IMPHASH). Is the driver signed by a trusted "
            "vendor, or is the signature Invalid/Unsigned? Rare driver "
            "names in odd paths (e.g. Temp, a user profile, C:\\Windows "
            "directly) are suspicious. Look up the SHA256 on VirusTotal: "
            "https://www.virustotal.com/gui/file/<hash>. Cross-reference "
            "against known BYOVD (bring-your-own-vulnerable-driver) lists. "
            "ATT&CK: T1543.003 (Create Windows Service), T1014 (Rootkit), "
            "T1068 (Exploitation for Privilege Escalation)."
        ),
        "investigation_checklist_text": (
            "- What is the driver file path and is it a standard driver "
            "location?\n"
            "- Is the driver digitally signed and is the signature valid?\n"
            "- Does the SHA256 hash appear on VirusTotal or BYOVD lists?\n"
            "- Is the driver name rare across the estate (first-seen / "
            "low prevalence)?\n"
            "- Was the driver loaded at boot or on-demand by a user-mode "
            "process?\n"
            "- Is there preceding file-create (Sysmon 11) or download "
            "activity for this .sys file?\n"
            "- Has this driver been flagged as vulnerable (e.g. "
            "loldrivers.io)?"
        ),
        "expected_outputs": [
            "driver_signature_state",
            "byovd_match",
            "recommended_actions",
        ],
    },
    {
        "name": "Sysmon Event 7 — Image/DLL Loaded",
        "description": (
            "Investigation guide for Sysmon Event 7 — a DLL or module was "
            "loaded into a process. High-volume; focus on rare loads, "
            "unsigned DLLs, or DLLs loaded from user-writeable paths."
        ),
        "rule_groups": ["sysmon_event_7"],
        "priority": 40,
        "severity_hint": "medium",
        "prompt_text": (
            "You are investigating a Sysmon Event 7 alert — a module was "
            "loaded into a process. Sysmon Event 7 is normally configured "
            "with tight filters because it's extremely noisy, so any alert "
            "reaching triage is usually pre-filtered on something "
            "suspicious. Examine `data.win.eventdata.image` (the loading "
            "process), `data.win.eventdata.imageLoaded` (the DLL), and "
            "`signatureStatus`. Classic attack patterns to look for: DLL "
            "side-loading (legitimate signed exe loads an unsigned/rogue "
            "DLL from its own directory), DLL search-order hijack (DLL in "
            "user path preempts the system one), and reflective DLL load "
            "(no file on disk — look at `fileVersion` blank and missing "
            "on-disk path). Check the SHA256 on VirusTotal. Compare the "
            "DLL's signer against the loading process's signer — mismatch "
            "is a strong signal. ATT&CK: T1574.002 (DLL Side-Loading), "
            "T1574.001 (DLL Search Order Hijacking), T1055.001 "
            "(Reflective DLL Injection)."
        ),
        "investigation_checklist_text": (
            "- Which process loaded the DLL (`image`) and is the DLL on "
            "its normal dependency list?\n"
            "- What is the DLL path — is it user-writeable, next to the "
            "loading exe (side-load), or standard system32?\n"
            "- Is the DLL signed, and does the signer match the loading "
            "process's signer?\n"
            "- Does the SHA256 hash appear on VirusTotal?\n"
            "- Is there a matching on-disk file, or does the load look "
            "reflective (no file version)?\n"
            "- Was there a preceding file-create (Sysmon 11) putting the "
            "DLL into that path?\n"
            "- Is the DLL name rare in your estate?"
        ),
        "expected_outputs": [
            "load_pattern",
            "signer_mismatch",
            "recommended_actions",
        ],
    },
    {
        "name": "Sysmon Event 10 — Process Access (LSASS / Credential Dumping)",
        "description": (
            "Investigation guide for Sysmon Event 10 — a process opened "
            "another process. Heavily filtered, so any alert is usually "
            "on a sensitive target like LSASS — treat as credential-"
            "access until proven otherwise."
        ),
        "rule_groups": ["sysmon_event_10"],
        "priority": 15,
        "severity_hint": "critical",
        "prompt_text": (
            "You are investigating a Sysmon Event 10 alert — a process "
            "opened another process. If the target process is lsass.exe "
            "with a memory-reading access mask, this is very likely "
            "credential dumping (Mimikatz, ProcDump, comsvcs.dll "
            "MiniDump, custom tooling). Examine "
            "`data.win.eventdata.sourceImage` (the accessor), "
            "`data.win.eventdata.targetImage` (usually lsass.exe), and "
            "`data.win.eventdata.grantedAccess` (hex mask). Access masks "
            "0x1010, 0x1410, 0x1438, 0x143A, 0x1FFFFF are classic "
            "credential-dump signatures (combinations of "
            "PROCESS_VM_READ + PROCESS_QUERY_INFORMATION). Verify the "
            "source image is expected to touch LSASS (Defender, legitimate "
            "EDR, Autoruns, Process Explorer) vs. a rare/unsigned binary. "
            "Check `callTrace` for ntdll!NtReadVirtualMemory or "
            "WerFault-looking signatures often used as LOLBin cover. "
            "Correlate with Sysmon 1 (what invoked the source image?) "
            "and with EDR credential-theft alerts. ATT&CK: T1003.001 "
            "(OS Credential Dumping: LSASS Memory), T1055 (Process "
            "Injection)."
        ),
        "investigation_checklist_text": (
            "- What is the source process (`sourceImage`) and is it "
            "expected to access other processes?\n"
            "- What is the target process — is it lsass.exe or another "
            "sensitive process?\n"
            "- What is the `grantedAccess` mask and does it indicate "
            "memory read or write?\n"
            "- Does `callTrace` mention ntdll!NtReadVirtualMemory or "
            "other memory-read primitives?\n"
            "- Is the source image signed and by whom?\n"
            "- Was the source image created recently (Sysmon 11) or "
            "downloaded recently?\n"
            "- Does the SHA256 appear on VirusTotal or in credential-"
            "dumping tool signatures?\n"
            "- Should we immediately isolate the host and force credential "
            "resets?"
        ),
        "expected_outputs": [
            "granted_access_analysis",
            "credential_dump_confidence",
            "compromised_accounts",
            "recommended_actions",
        ],
    },
    {
        "name": "Sysmon Event 12 — Registry Key/Value Create/Delete",
        "description": (
            "Investigation guide for Sysmon Event 12 — registry key or "
            "value create/delete. Focus on persistence autostart "
            "locations and security-tool tampering keys."
        ),
        "rule_groups": ["sysmon_event_12"],
        "priority": 35,
        "severity_hint": "medium-high",
        "prompt_text": (
            "You are investigating a Sysmon Event 12 alert — a registry "
            "key or value was created or deleted. Examine "
            "`data.win.eventdata.targetObject` (the key/value path) and "
            "`data.win.eventdata.image` (the modifying process). "
            "Sensitive paths: HKLM\\SOFTWARE\\Microsoft\\Windows\\"
            "CurrentVersion\\Run (user-wide startup), HKCU equivalents, "
            "Image File Execution Options (debugger hijack), Services "
            "keys, AppCompat Shims, Winlogon, Policies\\System, and the "
            "Defender Exclusions tree. Deletion of security keys (e.g. "
            "SecurityCenter, MpPreference) is high-severity defender "
            "tampering. Determine whether the modifying process is a "
            "legitimate installer/updater or an unsigned/LOLBin. "
            "Correlate with a preceding Sysmon 1 for full command-line "
            "context. ATT&CK: T1547.001 (Registry Run Keys), T1112 "
            "(Modify Registry), T1562.001 (Disable or Modify Tools)."
        ),
        "investigation_checklist_text": (
            "- What is the full `targetObject` path and which Windows "
            "feature does it control?\n"
            "- Which process modified it (`image`) and is it signed / "
            "expected?\n"
            "- Is this a create or delete operation?\n"
            "- Does the path fall in an autostart / persistence location?\n"
            "- Does the path relate to Defender / EDR configuration?\n"
            "- What command-line invoked the process (Sysmon 1 "
            "correlation)?\n"
            "- Is there a change ticket or installer run that explains "
            "this activity?"
        ),
        "expected_outputs": [
            "registry_category",
            "persistence_or_tamper",
            "recommended_actions",
        ],
    },
    {
        "name": "Sysmon Event 13 — Registry Value Set",
        "description": (
            "Investigation guide for Sysmon Event 13 — a registry value "
            "was set (DWORD/QWORD/string). Focus on autostart values, "
            "IFEO debugger, and security config flips."
        ),
        "rule_groups": ["sysmon_event_13"],
        "priority": 35,
        "severity_hint": "medium-high",
        "prompt_text": (
            "You are investigating a Sysmon Event 13 alert — a registry "
            "value was set. Examine `data.win.eventdata.targetObject`, "
            "`data.win.eventdata.details` (the value written), and "
            "`data.win.eventdata.image`. Red-flag patterns: a new value "
            "under a Run key pointing at a user-writeable path, "
            "DisableAntiSpyware / DisableRealtimeMonitoring set to 1 "
            "under Defender policy, IFEO Debugger set on a legitimate "
            "binary (redirects its execution), `AppInit_DLLs` modified, "
            "or PSReadLine history limits zeroed. Determine whether the "
            "modifying process is legitimate (Windows Update, admin "
            "console, signed installer) or suspicious (cmd.exe, "
            "powershell.exe, rundll32.exe). ATT&CK: T1547.001, T1112, "
            "T1562.001, T1574.012 (IFEO Injection)."
        ),
        "investigation_checklist_text": (
            "- What registry value was set — path plus value name?\n"
            "- What is the written data (`details`) and does it reference "
            "a binary path?\n"
            "- Does the setting control autostart, Defender, or execution "
            "flow?\n"
            "- Which process made the change (`image`) — signed or "
            "unsigned?\n"
            "- Is the referenced binary in a user-writeable path?\n"
            "- Correlate with Sysmon 1 for full command-line context.\n"
            "- Is there a preceding Sysmon 11 file-create that dropped "
            "the referenced binary?"
        ),
        "expected_outputs": [
            "registry_category",
            "value_written_analysis",
            "persistence_or_tamper",
            "recommended_actions",
        ],
    },
    {
        "name": "Sysmon Event 14 — Registry Key/Value Renamed",
        "description": (
            "Investigation guide for Sysmon Event 14 — a registry key or "
            "value was renamed. Uncommon; usually persistence evasion or "
            "config hiding."
        ),
        "rule_groups": ["sysmon_event_14"],
        "priority": 40,
        "severity_hint": "medium",
        "prompt_text": (
            "You are investigating a Sysmon Event 14 alert — a registry "
            "rename. Registry renames are uncommon, so any alert here is "
            "interesting. Examine `data.win.eventdata.targetObject` (old "
            "name) and `data.win.eventdata.newName`, plus "
            "`data.win.eventdata.image`. Common abuse: renaming a key to "
            "evade signatured detections, temporarily hiding a "
            "configuration key while other changes are made, or renaming "
            "service keys as part of a persistence hand-off. Determine "
            "whether the surrounding activity (Sysmon 12/13 on related "
            "keys) aligns with an attack story. ATT&CK: T1112 (Modify "
            "Registry), T1562 (Impair Defenses)."
        ),
        "investigation_checklist_text": (
            "- What was the old key/value name and what is the new one?\n"
            "- Which process renamed it (`image`)?\n"
            "- Is the old path tied to a security product or autostart "
            "location?\n"
            "- Are there correlated Sysmon 12/13 events on related keys "
            "from the same process GUID?\n"
            "- Does this match a known evasion technique for the "
            "target key?"
        ),
        "expected_outputs": [
            "rename_intent",
            "recommended_actions",
        ],
    },
    {
        "name": "Sysmon Event 15 — File Stream / Mark-of-the-Web",
        "description": (
            "Investigation guide for Sysmon Event 15 — named file stream "
            "created, including Zone.Identifier (Mark of the Web) on "
            "downloaded files and alternate data streams."
        ),
        "rule_groups": ["sysmon_event_15"],
        "priority": 30,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating a Sysmon Event 15 alert — a file "
            "stream was created. The two common cases are: (1) a browser "
            "writing a Zone.Identifier ADS marking a download as "
            "internet-origin, which is normal telemetry but valuable for "
            "delivery-path reconstruction; and (2) creation of an "
            "alternate data stream (ADS) used to hide payloads — `name` "
            "is non-empty and the content is executable or script. "
            "Examine `data.win.eventdata.image` (the writing process), "
            "`data.win.eventdata.targetFilename`, and the stream contents "
            "if surfaced. If the target is an exe/script with Zone "
            "Internet origin, the investigation becomes a delivery-chain "
            "trace. ATT&CK: T1564.004 (NTFS File Attributes), T1027 "
            "(Obfuscated Files / Hidden ADS)."
        ),
        "investigation_checklist_text": (
            "- Which process created the stream and is it a browser / "
            "email client / other expected writer?\n"
            "- Is this a Zone.Identifier MOTW write or a custom ADS?\n"
            "- If MOTW: what URL / zone is recorded in the stream?\n"
            "- If custom ADS: is the content executable or script?\n"
            "- Was the parent file later executed (Sysmon 1) or loaded "
            "(Sysmon 7)?\n"
            "- Does the hash of the parent file appear on VirusTotal?\n"
            "- Was the MOTW later stripped (common evasion — alternate "
            "data streams can be removed)?"
        ),
        "expected_outputs": [
            "stream_type",
            "delivery_origin",
            "recommended_actions",
        ],
    },
    {
        "name": "Sysmon Event 16 — Sysmon Configuration Change",
        "description": (
            "Investigation guide for Sysmon Event 16 — Sysmon's own "
            "configuration was changed. Treat as critical: adversaries "
            "blind telemetry before noisy actions."
        ),
        "rule_groups": ["sysmon_event_16"],
        "priority": 20,
        "severity_hint": "critical",
        "prompt_text": (
            "You are investigating a Sysmon Event 16 alert — Sysmon's "
            "filtering configuration was updated. Changes here can "
            "drastically reduce visibility, so even legitimate changes "
            "must be traceable to a change ticket. Examine "
            "`data.win.eventdata.configuration` (the new config hash / "
            "content) and the parent activity around the time of change. "
            "If no change ticket exists, assume adversary action: they "
            "may have disabled high-value event IDs (1, 3, 10, 11) or "
            "added exclusions hiding their tooling. Correlate with the "
            "account that ran the sysmon.exe update (Sysmon Event 1) and "
            "confirm it is an authorised admin or SCCM/GPO-driven push. "
            "ATT&CK: T1562.002 (Disable Windows Event Logging), T1562 "
            "(Impair Defenses)."
        ),
        "investigation_checklist_text": (
            "- Who or what process triggered the configuration change?\n"
            "- Is the change associated with an approved admin ticket or "
            "GPO / SCCM deployment?\n"
            "- What event IDs or process filters changed? (diff old vs "
            "new)\n"
            "- Have any high-value events been newly excluded?\n"
            "- Is Sysmon still reporting after the change, and is the "
            "coverage the same or reduced?\n"
            "- Is there suspicious activity on the host around the same "
            "time that the change may have been intended to hide?\n"
            "- Should we roll Sysmon back to the last known-good config?"
        ),
        "expected_outputs": [
            "change_origin",
            "coverage_impact",
            "recommended_actions",
        ],
    },
    {
        "name": "Sysmon Event 17 — Named Pipe Created",
        "description": (
            "Investigation guide for Sysmon Event 17 — named pipe "
            "created. Named pipes are commonly used by malware frameworks "
            "for IPC (Cobalt Strike, Meterpreter)."
        ),
        "rule_groups": ["sysmon_event_17"],
        "priority": 30,
        "severity_hint": "medium-high",
        "prompt_text": (
            "You are investigating a Sysmon Event 17 alert — a named "
            "pipe was created. Examine `data.win.eventdata.pipeName` and "
            "`data.win.eventdata.image`. Cobalt Strike's default pipe "
            "names (e.g. `\\postex_*`, `\\status_*`, `\\msagent_*`) and "
            "Meterpreter defaults are well known and should trigger high "
            "severity if observed. Custom but rare pipe names from "
            "unsigned processes are also suspicious. Benign cases: "
            "chrome, slack, teams, office apps, Windows Print Spooler. "
            "Check whether the creating process is signed, and whether "
            "the pipe-name pattern appears in public C2 IoC feeds. "
            "Correlate with Sysmon 18 (pipe connections) to see who "
            "connected afterwards. ATT&CK: T1055 (Process Injection — "
            "named pipe IPC), T1559 (Inter-Process Communication)."
        ),
        "investigation_checklist_text": (
            "- What is the pipe name and does it match any known C2 "
            "framework default?\n"
            "- Which process created the pipe (`image`) — signed, "
            "expected, or unsigned / rare?\n"
            "- Did other processes connect to the pipe (Sysmon 18) and "
            "from which process?\n"
            "- Is there prior Sysmon 1/10/11 activity tying the creating "
            "process to suspicious behaviour?\n"
            "- Does the pipe name appear in public C2 detection feeds?"
        ),
        "expected_outputs": [
            "c2_framework_match",
            "ipc_pattern",
            "recommended_actions",
        ],
    },
    {
        "name": "Sysmon Event 18 — Named Pipe Connected",
        "description": (
            "Investigation guide for Sysmon Event 18 — a client connected "
            "to a named pipe. Pairs with Event 17 to reconstruct IPC "
            "chains; SMB remote pipes indicate lateral movement."
        ),
        "rule_groups": ["sysmon_event_18"],
        "priority": 30,
        "severity_hint": "medium-high",
        "prompt_text": (
            "You are investigating a Sysmon Event 18 alert — a process "
            "connected to a named pipe. Examine `data.win.eventdata."
            "pipeName`, `data.win.eventdata.image` (the connecting "
            "process), and `data.win.eventdata.eventType`. Key scenarios: "
            "(1) remote SMB named-pipe connection (e.g. `\\\\target\\IPC$"
            "\\svcctl`, `\\\\target\\IPC$\\atsvc`) indicates PsExec-style "
            "lateral movement; (2) local connect to a C2-framework "
            "pipe = implant activity; (3) connection to a pipe that was "
            "just created (Sysmon 17) by a suspicious process = injection "
            "or module loader pattern. Correlate with Sysmon 1 to see "
            "what spawned the connecting process. ATT&CK: T1021.002 "
            "(SMB/Windows Admin Shares), T1055 (Process Injection)."
        ),
        "investigation_checklist_text": (
            "- What pipe was connected to, and is the path local or "
            "remote (`\\\\host\\IPC$\\...`)?\n"
            "- Which process connected (`image`) — signed, expected, "
            "or rare?\n"
            "- For remote connections: is this a known admin/management "
            "workflow (PsExec, WMI)?\n"
            "- Is there a matching Sysmon 17 create on the target "
            "endpoint?\n"
            "- Does the pipe name match C2 IoC feeds?\n"
            "- Correlate with authentication logs (4624) from the source "
            "host around the same time."
        ),
        "expected_outputs": [
            "pipe_location",
            "movement_indicator",
            "recommended_actions",
        ],
    },
    {
        "name": "Sysmon Event 22 — DNS Query",
        "description": (
            "Investigation guide for Sysmon Event 22 — a process executed "
            "a DNS query. Focus on rare domains, DGA entropy, and "
            "processes that shouldn't be resolving names."
        ),
        "rule_groups": ["sysmon_event_22"],
        "priority": 45,
        "severity_hint": "medium",
        "prompt_text": (
            "You are investigating a Sysmon Event 22 alert — a process "
            "performed a DNS query. Examine `data.win.eventdata.image` "
            "(the resolver) and `data.win.eventdata.queryName` (the "
            "domain). Determine whether the querying process is expected "
            "to resolve names at all — rundll32.exe, regsvr32.exe, "
            "certutil.exe, mshta.exe doing DNS is a strong suspicious "
            "signal. Check the domain entropy (DGA-like high-entropy "
            "subdomains), age (recently registered via passive DNS / "
            "WHOIS), reputation (TI feeds, URLScan), and whether it "
            "belongs to a known DoH provider (attempted DNS-over-HTTPS "
            "evasion). Correlate with Sysmon 3 (network connection) to "
            "see whether the resolution led to a connection attempt. "
            "ATT&CK: T1071.004 (DNS), T1568 (Dynamic Resolution), "
            "T1568.002 (Domain Generation Algorithms)."
        ),
        "investigation_checklist_text": (
            "- Which process performed the query (`image`) and is DNS "
            "expected for it?\n"
            "- What is the `queryName` — does it look DGA-like, "
            "typo-squatted, or newly registered?\n"
            "- Does the domain appear on threat-intel feeds?\n"
            "- Is the query going to an external DoH resolver (evasion)?\n"
            "- Was there a follow-up Sysmon 3 (network connection) from "
            "the same process GUID?\n"
            "- Does the domain match a known malware family or C2 "
            "infrastructure?"
        ),
        "expected_outputs": [
            "domain_reputation",
            "process_expected_to_resolve",
            "dga_likelihood",
            "recommended_actions",
        ],
    },
    # ------------------------------------------------------------------
    # Talon Windows category templates (3 — autoruns, defender, sigcheck).
    # ------------------------------------------------------------------
    {
        "name": "Windows Autoruns — Persistence Review",
        "description": (
            "Investigation guide for Sysinternals Autoruns output — "
            "review autostart entries for suspicious persistence."
        ),
        "rule_groups": ["windows_autoruns", "autoruns"],
        "priority": 40,
        "severity_hint": "medium-high",
        "prompt_text": (
            "You are investigating a Windows Autoruns alert. Autoruns "
            "enumerates every place Windows launches code at logon/boot "
            "(Run keys, Startup folders, services, scheduled tasks, "
            "IFEO, AppInit_DLLs, winlogon hooks, WMI event subscriptions, "
            "browser/office add-ins). For each suspicious entry, "
            "determine: what binary runs, who wrote the entry, when, and "
            "is the binary signed / expected in that location. User-"
            "writeable paths, unsigned binaries, and rare autostart "
            "categories (WMI, AppInit, image file execution options) are "
            "high-signal. Cross-reference the payload hash against "
            "VirusTotal. ATT&CK: T1547 (Boot or Logon Autostart), T1053 "
            "(Scheduled Task), T1543 (Create or Modify System Process), "
            "T1546 (Event Triggered Execution)."
        ),
        "investigation_checklist_text": (
            "- Which autostart categories contain new or recently "
            "modified entries?\n"
            "- What binary path does each entry reference — is the path "
            "user-writeable?\n"
            "- Is each entry's binary signed, and by whom?\n"
            "- When were the entries created, and which account created "
            "them?\n"
            "- Do the hashes appear on VirusTotal?\n"
            "- Are there entries in rare autostart categories (WMI "
            "subscriptions, AppInit_DLLs, debugger IFEO)?\n"
            "- Does this match a known persistence family pattern?"
        ),
        "expected_outputs": [
            "persistence_entries_suspicious",
            "persistence_entries_benign",
            "recommended_actions",
        ],
    },
    {
        "name": "Microsoft Defender Detection",
        "description": (
            "Investigation guide for Microsoft Defender Antivirus "
            "alerts. Confirm containment state and dig into the detection "
            "name, signature, and affected file."
        ),
        "rule_groups": ["windows_defender", "microsoft_defender", "defender"],
        "priority": 20,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating a Microsoft Defender alert. Defender "
            "detections can be from the real-time scanner, the scheduled "
            "scan, or cloud-delivered protection. Examine "
            "`data.win.eventdata.threatName` (detection name / family), "
            "`data.win.eventdata.path` (affected file), "
            "`data.win.eventdata.actionTaken` (quarantined, removed, "
            "allowed, no action), and `data.win.eventdata.severity`. "
            "Confirm the sample is actually contained. Look up the "
            "detection name on Microsoft's malware encyclopedia to "
            "understand the family and blast radius. Check the SHA256 "
            "on VirusTotal for consensus. Trace back to the delivery "
            "chain via Sysmon 1/3/11 and browser / email logs. Pay "
            "special attention to Defender being disabled, exclusions "
            "added, or definition updates blocked — those are evasion "
            "pre-cursors that can precede a new detection from a second "
            "host with weaker config. ATT&CK: T1204 (User Execution), "
            "T1566 (Phishing), T1562.001 (Disable or Modify Tools)."
        ),
        "investigation_checklist_text": (
            "- What is the detection name / signature / family?\n"
            "- What was the Defender action (quarantined, removed, "
            "allowed, detected-only)?\n"
            "- Is the file currently contained, or is it still on disk?\n"
            "- What is the affected path — system, user, removable "
            "media?\n"
            "- Does the SHA256 hash match on VirusTotal?\n"
            "- What was the delivery vector (email, web, USB, lateral "
            "movement)?\n"
            "- Did the same sample appear on other hosts in the estate?\n"
            "- Were Defender signatures up-to-date at the time of "
            "detection?"
        ),
        "expected_outputs": [
            "containment_state",
            "malware_family",
            "blast_radius",
            "recommended_actions",
        ],
    },
    {
        "name": "Sysinternals sigcheck — Unsigned/Suspicious Binary",
        "description": (
            "Investigation guide for Sysinternals sigcheck results "
            "highlighting unsigned or mis-signed binaries in expected-"
            "signed paths."
        ),
        "rule_groups": ["windows_sigcheck", "sigcheck"],
        "priority": 40,
        "severity_hint": "medium-high",
        "prompt_text": (
            "You are investigating a sigcheck alert — a binary in a "
            "normally-signed location was found unsigned, mis-signed, or "
            "with a revoked certificate. Examine the file path, the "
            "signer name (if any), the verification status (Unsigned, "
            "Invalid, Expired, Revoked), and the product/company fields. "
            "Indicators: a file in System32/Program Files that is "
            "unsigned; a signed binary whose signer does not match the "
            "declared product (e.g. Publisher: Microsoft but signer is "
            "not Microsoft); a revoked certificate (the cert was "
            "compromised and CRL'd). Check the SHA256 on VirusTotal. "
            "Correlate with Sysmon 11 (file create) to see when and how "
            "the file got into that location. ATT&CK: T1036 "
            "(Masquerading), T1553 (Subvert Trust Controls), T1036.001 "
            "(Invalid Code Signature)."
        ),
        "investigation_checklist_text": (
            "- What is the file path — does it normally contain signed "
            "binaries?\n"
            "- What is the signature status (Unsigned, Invalid, Expired, "
            "Revoked)?\n"
            "- Does the file's declared publisher match the actual "
            "signer?\n"
            "- Is this a first-seen file on the host, or a modified "
            "existing file?\n"
            "- Does the SHA256 appear on VirusTotal?\n"
            "- Which process or account placed the file there (Sysmon 11 "
            "correlation)?\n"
            "- Are other hosts carrying the same file?"
        ),
        "expected_outputs": [
            "signature_status",
            "masquerade_indicators",
            "recommended_actions",
        ],
    },
    # ------------------------------------------------------------------
    # New category templates (10) — identity, cloud runtime, CI/CD,
    # macOS, network analytics, data access, session, supply chain.
    # ------------------------------------------------------------------
    {
        "name": "Entra ID — Suspicious Sign-in",
        "description": (
            "Investigation guide for Microsoft Entra ID (Azure AD) "
            "risky sign-ins: impossible travel, unfamiliar locations, "
            "anonymous IP, token-theft indicators."
        ),
        "rule_groups": [
            "entra_id", "azure_ad_signin", "entra_signin", "risky_signin",
        ],
        "rule_id_pattern": r"(?i)(entra|azure.?ad.?sign|risky.?sign|aadsts)",
        "priority": 25,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating an Entra ID (Azure AD) suspicious "
            "sign-in alert. Examine the sign-in log: user principal name, "
            "app ID, client IP and location, device identifier, "
            "conditional-access result, authentication method (password, "
            "FIDO2, PRT, authenticator app), risk detections "
            "(impossibleTravel, unfamiliarFeatures, anonymousIpAddress, "
            "passwordSpray, adminConfirmedUserCompromised, "
            "tokenIssuerAnomaly). Token-theft patterns: sign-in from a "
            "new IP using an existing primary refresh token without a "
            "full auth prompt, session reuse across geographies, or a "
            "user agent change mid-session. Check whether MFA was "
            "satisfied and how (SMS/voice are weaker than phishing-"
            "resistant methods). Correlate with Azure AD audit log for "
            "follow-on actions (OAuth consent grants, new service "
            "principal credentials, inbox-rule creation). ATT&CK: "
            "T1078.004 (Valid Accounts: Cloud), T1550.001 (Application "
            "Access Token), T1111 (Multi-Factor Authentication "
            "Interception)."
        ),
        "investigation_checklist_text": (
            "- What Entra ID risk detections fired (impossibleTravel, "
            "anonymousIp, tokenIssuerAnomaly, …)?\n"
            "- What is the sign-in IP and geolocation vs the user's "
            "baseline?\n"
            "- Was MFA satisfied, and by what method (phishing-"
            "resistant vs SMS/voice)?\n"
            "- Did the conditional-access policy grant, block, or "
            "partially grant (MFA satisfied)?\n"
            "- What app / service principal was the sign-in scoped to?\n"
            "- Any follow-on activity in Azure AD audit "
            "(oauth2PermissionGrant, credential adds, mailbox rules)?\n"
            "- Has the user confirmed / denied the activity?\n"
            "- Should sessions be revoked (Revoke-AzureADSignedInUser"
            "AllRefreshToken) and password reset with forced MFA "
            "re-registration?"
        ),
        "expected_outputs": [
            "risk_detections",
            "token_theft_indicators",
            "post_signin_activity",
            "recommended_actions",
        ],
    },
    {
        "name": "Okta — Suspicious Activity",
        "description": (
            "Investigation guide for Okta suspicious events: factor "
            "reset, admin role assignment, new sign-in from unknown "
            "device, bypass of MFA policies."
        ),
        "rule_groups": [
            "okta_system_log", "okta_suspicious", "okta_factor_reset",
            "okta_admin_change",
        ],
        "rule_id_pattern": r"(?i)(okta.?system|okta.?factor|okta.?admin|okta.?suspicious)",
        "priority": 25,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating an Okta System Log alert. Examine "
            "eventType, actor (user / API token / service), target, "
            "client (IP, user agent, geolocation), authenticationContext "
            "(interface, externalSessionId), and debugContext. Red-flag "
            "events: `user.mfa.factor.reset_all` / `reset_single` (MFA "
            "factor reset — a classic account-takeover pivot), "
            "`user.account.privilege.grant` (new admin role), "
            "`policy.rule.deactivate` on MFA policies, `application."
            "user_membership.add` for sensitive apps, `system.api_token."
            "create`, `user.authentication.auth_via_mfa` with "
            "`factor=SMS` on a new device. Correlate with prior sign-ins "
            "from the same IP and with follow-on access to crown-jewel "
            "apps (AWS, GitHub, payroll). ATT&CK: T1078 (Valid "
            "Accounts), T1098 (Account Manipulation), T1556 (Modify "
            "Authentication Process)."
        ),
        "investigation_checklist_text": (
            "- What Okta eventType fired, and who is the actor?\n"
            "- What is the client IP, user agent, and geolocation?\n"
            "- For factor resets: was the reset initiated via support "
            "ticket, or directly by an authenticated session?\n"
            "- For privilege grants: what role was assigned and by "
            "whom?\n"
            "- For policy changes: which policy, and what did it "
            "previously enforce?\n"
            "- Was a new API token minted? If so, what scope?\n"
            "- What crown-jewel apps did the affected user access "
            "immediately after this event?\n"
            "- Should we terminate sessions and force re-enrollment?"
        ),
        "expected_outputs": [
            "event_type_category",
            "actor_legitimacy",
            "post_event_access",
            "recommended_actions",
        ],
    },
    {
        "name": "MFA Fatigue / Push Bombing",
        "description": (
            "Investigation guide for MFA push-notification flooding — "
            "attacker spams the user with approve-prompts until one is "
            "accepted."
        ),
        "rule_groups": [
            "mfa_fatigue", "mfa_push_bombing", "mfa_flood",
        ],
        "rule_id_pattern": r"(?i)(mfa.?fatigue|push.?bombing|mfa.?flood|mfa.?spam)",
        "priority": 25,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating an MFA fatigue / push-bombing alert. "
            "The pattern: multiple MFA prompts to the same user within a "
            "short window from the same source, followed by either a "
            "successful approve (the user caved) or eventual denial. "
            "Examine the IdP logs: count of MFA prompts per minute, "
            "source IP(s), the authenticating application, and whether "
            "any prompt was approved. Check whether the user's password "
            "was leaked in a recent breach (haveibeenpwned) — push-"
            "bombing follows credential theft. If an approve succeeded, "
            "trace the subsequent session's actions immediately. "
            "Compensating controls to recommend: number matching, "
            "phishing-resistant factors (FIDO2), reduced prompt "
            "frequency, user education callback. ATT&CK: T1621 "
            "(Multi-Factor Authentication Request Generation), T1078 "
            "(Valid Accounts)."
        ),
        "investigation_checklist_text": (
            "- How many MFA prompts occurred in what time window?\n"
            "- What IP / app / user agent generated the prompts?\n"
            "- Did any prompt succeed (user approved)?\n"
            "- If approved: what did the authenticated session do "
            "next?\n"
            "- Has the user's password been compromised in a known "
            "breach?\n"
            "- Is the IdP using number matching / phishing-resistant "
            "MFA?\n"
            "- Has the user been contacted to confirm / deny?\n"
            "- Should the account be immediately session-revoked and "
            "password reset?"
        ),
        "expected_outputs": [
            "prompt_count",
            "approval_outcome",
            "mfa_factor_strength",
            "recommended_actions",
        ],
    },
    {
        "name": "Container / Kubernetes Runtime Anomaly",
        "description": (
            "Investigation guide for container runtime anomalies — shell "
            "in container, privileged exec, host filesystem mount, "
            "service-account token abuse."
        ),
        "rule_groups": [
            "container_runtime", "k8s_runtime", "falco_alert",
            "container_escape", "kubectl_exec",
        ],
        "rule_id_pattern": r"(?i)(container.?runtime|k8s.?runtime|falco|container.?escape|kubectl.?exec)",
        "priority": 20,
        "severity_hint": "critical",
        "prompt_text": (
            "You are investigating a container / Kubernetes runtime "
            "anomaly alert (typically from Falco, Sysdig, or the k8s "
            "audit log). Classify the event: interactive shell spawned "
            "inside a container (`kubectl exec` or equivalent), process "
            "launched with host namespace (pid / net / ipc), privileged "
            "container started, host path mounted into a container "
            "(/etc/kubernetes, /var/run/docker.sock), service-account "
            "token read / used externally, or kube-apiserver access from "
            "an unexpected pod. Establish: which namespace / pod / "
            "container, which image and image digest, the initiating "
            "user (human vs service account), and whether the action is "
            "part of an approved operational runbook. High-severity "
            "combinations: privileged + host-mount = trivial container "
            "escape; service-account token usage from outside the "
            "cluster = supply chain / credential theft. ATT&CK: T1611 "
            "(Escape to Host), T1610 (Deploy Container), T1613 "
            "(Container and Resource Discovery), T1552.007 (Container "
            "API)."
        ),
        "investigation_checklist_text": (
            "- Which namespace / pod / container / image is involved?\n"
            "- What specific runtime behaviour triggered the alert "
            "(shell, privileged exec, host mount, token access)?\n"
            "- Was the container privileged and/or did it mount host "
            "paths?\n"
            "- Which user or service account initiated the action?\n"
            "- Was a service-account token used from outside the cluster "
            "(source IP mismatch)?\n"
            "- Is the image trusted (signed, from an internal "
            "registry)?\n"
            "- Are there downstream actions (API calls, pod creations, "
            "secret reads) from the same session?\n"
            "- Should the pod be killed and the namespace quarantined?"
        ),
        "expected_outputs": [
            "behaviour_category",
            "escape_risk",
            "cluster_blast_radius",
            "recommended_actions",
        ],
    },
    {
        "name": "CI/CD Abuse — GitHub Actions / Pipeline",
        "description": (
            "Investigation guide for CI/CD pipeline abuse — workflow "
            "injection, self-hosted runner takeover, secret exfiltration, "
            "new deploy key."
        ),
        "rule_groups": [
            "github_actions_abuse", "ci_cd_abuse", "pipeline_abuse",
            "runner_takeover", "secret_leak",
        ],
        "rule_id_pattern": r"(?i)(github.?action|ci.?cd|pipeline.?abuse|runner.?takeover|deploy.?key)",
        "priority": 20,
        "severity_hint": "critical",
        "prompt_text": (
            "You are investigating a CI/CD abuse alert. Pipelines hold "
            "long-lived secrets (cloud creds, registry tokens, signing "
            "keys) and execute arbitrary code by design, so compromise "
            "can hand an attacker the build output distribution channel. "
            "Classify the event: workflow file (.github/workflows/*.yml) "
            "modified by an external contributor via a PR that auto-"
            "runs; self-hosted runner registered without approval; "
            "GITHUB_TOKEN / OIDC token used from an unexpected job; new "
            "deploy key / PAT added; secret read by a workflow that "
            "shouldn't need it; registry publish from a forked PR. "
            "Examine actor, repo, commit SHA, workflow run ID, the diff "
            "introduced, and any secret names accessed. Check whether "
            "branch-protection / required-review was in force. ATT&CK: "
            "T1552.004 (Private Keys), T1552.007 (Container API / Cloud "
            "Secret), T1195.002 (Compromise Software Supply Chain), "
            "T1199 (Trusted Relationship)."
        ),
        "investigation_checklist_text": (
            "- What repo / workflow / run was involved?\n"
            "- Who is the actor, and are they external, internal, or a "
            "bot?\n"
            "- What change was introduced (view diff) — does it exfil "
            "secrets, add a new runner, or modify release output?\n"
            "- Was branch protection / required review bypassed, and "
            "how?\n"
            "- Which secrets were accessible to the workflow run?\n"
            "- Did the run register a new self-hosted runner or push to "
            "a registry / cloud?\n"
            "- Can we invalidate any secrets that might have "
            "leaked?\n"
            "- Should we quarantine the repo and rotate all touched "
            "secrets?"
        ),
        "expected_outputs": [
            "abuse_pattern",
            "secrets_exposed",
            "supply_chain_impact",
            "recommended_actions",
        ],
    },
    {
        "name": "macOS Persistence / Suspicious Execution",
        "description": (
            "Investigation guide for macOS suspicious activity — "
            "LaunchDaemons / LaunchAgents, osascript, Gatekeeper bypass, "
            "TCC permission grants."
        ),
        "rule_groups": [
            "macos_persistence", "macos_suspicious", "osascript",
            "launch_agent", "launch_daemon", "tcc_bypass",
        ],
        "rule_id_pattern": r"(?i)(macos|osascript|launch.?agent|launch.?daemon|gatekeeper|tcc.?bypass)",
        "priority": 35,
        "severity_hint": "medium-high",
        "prompt_text": (
            "You are investigating a macOS alert. Common adversary "
            "behaviours on macOS: LaunchAgent (~/Library/LaunchAgents/) "
            "or LaunchDaemon (/Library/LaunchDaemons/) plist creation "
            "for persistence, osascript abuse for AppleScript-based "
            "execution, curl | bash download cradles, Gatekeeper bypass "
            "via extended-attribute stripping (`xattr -d "
            "com.apple.quarantine`), TCC database modifications to grant "
            "Full Disk Access or Accessibility silently, and unsigned "
            "kexts / system extensions. Examine the file path, creating "
            "process, signing status (codesign), quarantine extended "
            "attribute, and notarization state. Correlate with "
            "networking (unusual outbound to a download domain) and "
            "process ancestry. ATT&CK: T1547.011 (Plist File "
            "Modification), T1059.002 (AppleScript), T1553.001 (Gatekeeper "
            "Bypass), T1569.001 (Launchctl)."
        ),
        "investigation_checklist_text": (
            "- What is the activity type (plist, osascript, xattr, TCC "
            "grant, kext load)?\n"
            "- Which file / plist was created or modified, and in "
            "whose user directory?\n"
            "- Is the referenced binary code-signed and notarized?\n"
            "- Has the quarantine xattr been stripped?\n"
            "- What is the process ancestry (Terminal, osascript, "
            "browser, installer)?\n"
            "- Was there a preceding curl / download / DMG mount that "
            "delivered the payload?\n"
            "- Do any TCC database modifications grant sensitive "
            "permissions without user interaction?\n"
            "- Is this consistent with a known macOS malware family?"
        ),
        "expected_outputs": [
            "persistence_location",
            "codesign_state",
            "delivery_chain",
            "recommended_actions",
        ],
    },
    {
        "name": "Zeek Network Anomaly",
        "description": (
            "Investigation guide for Zeek (Bro) network anomaly alerts — "
            "protocol anomalies, long-lived connections, suspicious TLS "
            "certs, SSH brute force, file extraction."
        ),
        "rule_groups": [
            "zeek", "bro", "zeek_notice", "network_anomaly",
            "ssl_cert_anomaly",
        ],
        "rule_id_pattern": r"(?i)(zeek|bro|network.?anomaly|ssl.?cert.?anom)",
        "priority": 40,
        "severity_hint": "medium",
        "prompt_text": (
            "You are investigating a Zeek network anomaly alert. Zeek's "
            "notice framework raises on protocol-level anomalies that "
            "Sysmon/EDR cannot see: SSH password brute-force via the "
            "intel framework, long-lived (days-weeks) connections that "
            "may indicate C2 (Connection::LONG_CONN), self-signed or "
            "LetsEncrypt TLS certs on short-lived domains, HTTP "
            "executables served with mismatched MIME types, DNS "
            "tunnelling detection (high-entropy subdomains), and "
            "SMB::Discovery. Examine Zeek `conn.log`, `ssl.log`, "
            "`x509.log`, `dns.log`, `http.log`, and `notice.log` for the "
            "affected src/dst pair. Pivot to Sysmon / endpoint logs on "
            "the internal host for the initiating process. If TLS: "
            "examine the SNI, certificate issuer / subject / validity "
            "dates, and JA3/JA3S fingerprints against public feeds. "
            "ATT&CK: T1071 (Application Layer Protocol), T1110 (Brute "
            "Force), T1572 (Protocol Tunneling), T1573 (Encrypted "
            "Channel)."
        ),
        "investigation_checklist_text": (
            "- What Zeek notice or analytic fired?\n"
            "- What are the connection 5-tuple, duration, and byte "
            "volumes?\n"
            "- For TLS: SNI, cert issuer/subject, validity, JA3/JA3S?\n"
            "- For DNS: query entropy, domain age, resolver used?\n"
            "- For HTTP: URI pattern, user agent, response MIME vs "
            "actual file type?\n"
            "- Which internal process initiated the connection (pivot "
            "to endpoint)?\n"
            "- Does the external endpoint appear on threat-intel "
            "feeds?\n"
            "- Is the pattern consistent with C2, brute force, or "
            "benign protocol quirk?"
        ),
        "expected_outputs": [
            "anomaly_type",
            "c2_confidence",
            "network_evidence",
            "recommended_actions",
        ],
    },
    {
        "name": "Database Access Anomaly",
        "description": (
            "Investigation guide for database access anomalies — "
            "unusual query volume, mass-SELECT / export, after-hours "
            "access, sensitive table access."
        ),
        "rule_groups": [
            "db_access_anomaly", "mass_select", "database_export",
            "sensitive_table_access",
        ],
        "rule_id_pattern": r"(?i)(db.?access|mass.?select|database.?export|sensitive.?table)",
        "priority": 30,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating a database access anomaly. Examine "
            "the audit log / query log: database user, source app, "
            "source host, queries executed, row counts returned, and "
            "timing vs the user's baseline. Suspicious patterns: SELECT "
            "with no WHERE clause against sensitive tables, mass exports "
            "(COPY TO, bcp, SELECT INTO OUTFILE), privilege escalation "
            "via new GRANT statements, access to backup or audit tables, "
            "and after-hours activity from an interactive user. Confirm "
            "whether the workload belongs to a legitimate reporting / "
            "ETL / backup job, or an unexpected session. For SaaS DBs "
            "(Snowflake, BigQuery, Redshift), also review role "
            "impersonation and cross-account access. ATT&CK: T1213 "
            "(Data from Information Repositories), T1530 (Data from "
            "Cloud Storage), T1078 (Valid Accounts)."
        ),
        "investigation_checklist_text": (
            "- Which DB, tables, and columns were accessed?\n"
            "- What is the volume of rows returned vs the user's "
            "baseline?\n"
            "- Which user / app / source host ran the queries?\n"
            "- Were any sensitive tables (PII, financial, credentials) "
            "touched?\n"
            "- Is the workload consistent with a known ETL / reporting "
            "job?\n"
            "- For mass exports: what is the destination path / "
            "bucket?\n"
            "- Did the session include a privilege grant or role "
            "change?\n"
            "- Is there a data-breach notification threshold crossed?"
        ),
        "expected_outputs": [
            "data_sensitivity",
            "volume_vs_baseline",
            "export_destination",
            "recommended_actions",
        ],
    },
    {
        "name": "Session Hijack / SSO Token Theft",
        "description": (
            "Investigation guide for session-token / cookie theft — "
            "replay of an authenticated session from a new IP or device "
            "without a fresh auth prompt."
        ),
        "rule_groups": [
            "session_hijack", "token_theft", "cookie_replay",
            "sso_replay", "prt_theft",
        ],
        "rule_id_pattern": r"(?i)(session.?hijack|token.?theft|cookie.?replay|sso.?replay|prt.?theft)",
        "priority": 15,
        "severity_hint": "critical",
        "prompt_text": (
            "You are investigating a session-hijack / token-theft alert. "
            "Adversaries bypass MFA by stealing post-auth session cookies "
            "or primary refresh tokens (PRTs) and replaying them from "
            "attacker infrastructure. Indicators: same session ID (or "
            "tokenId / externalSessionId) used from two IPs minutes "
            "apart, sign-in with an existing token without a full "
            "interactive MFA challenge, user agent change mid-session, "
            "geovelocity that is impossible, or access from a known "
            "residential-proxy or datacenter IP unfamiliar to the user. "
            "For Entra ID: check `signInEventTypes: interactiveUser` vs "
            "`nonInteractiveUser` with PRT details. For Okta: same "
            "`externalSessionId` from two IPs. Pivot to browser logs / "
            "EDR on the originating host to find the stealer (infostealer "
            "malware commonly harvests cookies and tokens). Immediate "
            "action: revoke all sessions, invalidate tokens, reset "
            "password with forced re-MFA. ATT&CK: T1539 (Steal Web "
            "Session Cookie), T1550.004 (Web Session Cookie Replay), "
            "T1528 (Steal Application Access Token)."
        ),
        "investigation_checklist_text": (
            "- What session / token ID was replayed?\n"
            "- From which IPs / user agents / geolocations?\n"
            "- How long between the legitimate session and the "
            "suspected replay?\n"
            "- Was a fresh MFA challenge required for the suspected "
            "replay?\n"
            "- Is there infostealer / suspicious browser-process "
            "activity on the originating endpoint?\n"
            "- Which apps did the replayed session access?\n"
            "- Has the user confirmed / denied the activity?\n"
            "- Have all sessions been revoked and credentials rotated?"
        ),
        "expected_outputs": [
            "replay_evidence",
            "origin_compromise",
            "apps_accessed",
            "recommended_actions",
        ],
    },
    {
        "name": "Supply Chain — Malicious Package / Typosquat",
        "description": (
            "Investigation guide for suspected malicious dependency "
            "(npm / pypi / rubygems / maven) — typosquat, compromised "
            "maintainer, postinstall script abuse."
        ),
        "rule_groups": [
            "supply_chain", "malicious_package", "typosquat",
            "npm_abuse", "pypi_abuse",
        ],
        "rule_id_pattern": r"(?i)(supply.?chain|malicious.?package|typosquat|postinstall|npm.?abuse|pypi.?abuse)",
        "priority": 20,
        "severity_hint": "critical",
        "prompt_text": (
            "You are investigating a supply-chain alert — a potentially "
            "malicious package was installed / requested / blocked. "
            "Malicious-package categories: typosquat (`reqeusts` for "
            "`requests`), confused-dependency (internal name published "
            "on public registry), compromised legitimate maintainer "
            "account, intentional postinstall script that exfiltrates "
            "`/etc/passwd` or environment variables. Examine the "
            "package name, version, publish date, maintainer history, "
            "download count (very low for new malicious packages), and "
            "any postinstall / install.js hooks. Determine how the "
            "package arrived: direct `npm install`, transitive "
            "dependency, lockfile change in a PR, or CI-only install. "
            "Pivot to build-server processes (Sysmon 1 / Linux "
            "execve / Falco) during the install to catch payload "
            "execution. Action: quarantine the package, pin/revert the "
            "lockfile, scan build servers for persistence, rotate any "
            "secrets the install script could have seen. ATT&CK: "
            "T1195.002 (Compromise Software Supply Chain), T1059 "
            "(Command and Scripting Interpreter), T1552 (Unsecured "
            "Credentials)."
        ),
        "investigation_checklist_text": (
            "- What package name and version were installed?\n"
            "- Is the name a typosquat / confused-dependency of an "
            "internal package?\n"
            "- Who is the maintainer and what is their publish "
            "history?\n"
            "- When was the package first published? (new packages are "
            "a red flag)\n"
            "- Does the package have postinstall / preinstall scripts, "
            "and what do they do?\n"
            "- Was the install on a developer box, a CI runner, or "
            "a production host?\n"
            "- What environment variables / files could the install "
            "script have read?\n"
            "- Have we rotated any secrets that the install could have "
            "leaked?"
        ),
        "expected_outputs": [
            "package_category",
            "install_surface",
            "exfil_risk",
            "recommended_actions",
        ],
    },
]


# ---------------------------------------------------------------------------
# MITRE ATT&CK backfill for the default templates. Keyed by template name so
# the list of _DEFAULT_TEMPLATES dicts above stays readable; the seeder merges
# these in at insert time, and the top-up path applies them to existing rows
# that pre-date the mitre_* columns.
# ---------------------------------------------------------------------------


_TEMPLATE_MITRE_MAP: dict[str, dict[str, list[str]]] = {
    # Sysmon core
    "Sysmon Event 1 — Process Creation": {
        "techniques": ["T1059", "T1218", "T1036"],
        "tactics": ["TA0002"],  # Execution
    },
    "Sysmon Event 3 — Network Connection": {
        "techniques": ["T1071", "T1090", "T1105"],
        "tactics": ["TA0011"],  # Command and Control
    },
    "Sysmon Event 11 — File Create": {
        "techniques": ["T1547", "T1105", "T1036"],
        "tactics": ["TA0003"],  # Persistence
    },
    # Cross-cutting
    "Authentication Failure": {
        "techniques": ["T1110", "T1110.003", "T1078"],
        "tactics": ["TA0006"],  # Credential Access
    },
    "Malware Detection": {
        "techniques": ["T1204", "T1566", "T1105"],
        "tactics": ["TA0001", "TA0002"],  # Initial Access, Execution
    },
    # Elastic Security categories (10)
    "Credential Access": {
        "techniques": ["T1003", "T1558", "T1550.002"],
        "tactics": ["TA0006"],
    },
    "Lateral Movement": {
        "techniques": ["T1021", "T1570", "T1047"],
        "tactics": ["TA0008"],
    },
    "Persistence Mechanism": {
        "techniques": ["T1053", "T1547", "T1543"],
        "tactics": ["TA0003"],
    },
    "Defense Evasion": {
        "techniques": ["T1070", "T1055", "T1574", "T1036"],
        "tactics": ["TA0005"],
    },
    "Discovery / Reconnaissance": {
        "techniques": ["T1046", "T1087", "T1069"],
        "tactics": ["TA0007"],
    },
    "Command and Control (C2)": {
        "techniques": ["T1071", "T1572", "T1573"],
        "tactics": ["TA0011"],
    },
    "Exfiltration": {
        "techniques": ["T1041", "T1567", "T1048"],
        "tactics": ["TA0010"],
    },
    "Privilege Escalation": {
        "techniques": ["T1548", "T1134", "T1068"],
        "tactics": ["TA0004"],
    },
    "Suspicious Execution": {
        "techniques": ["T1059", "T1218", "T1027"],
        "tactics": ["TA0002"],
    },
    "Initial Access": {
        "techniques": ["T1566", "T1190", "T1189"],
        "tactics": ["TA0001"],
    },
    # Sigma categories (10)
    "Web Application Attack": {
        "techniques": ["T1190", "T1505.003"],
        "tactics": ["TA0001", "TA0003"],
    },
    "Linux/Unix Suspicious Activity": {
        "techniques": ["T1059.004", "T1053.003", "T1110", "T1548.003"],
        "tactics": ["TA0002", "TA0003"],
    },
    "Cloud Security — AWS": {
        "techniques": ["T1078.004", "T1562", "T1537"],
        "tactics": ["TA0005", "TA0010"],
    },
    "Cloud Security — Azure": {
        "techniques": ["T1078.004", "T1098", "T1552.005"],
        "tactics": ["TA0006", "TA0007"],
    },
    "Email Security / BEC": {
        "techniques": ["T1114", "T1566", "T1534"],
        "tactics": ["TA0009", "TA0001"],
    },
    "DNS Anomaly": {
        "techniques": ["T1568.002", "T1572", "T1071.004"],
        "tactics": ["TA0011"],
    },
    "Endpoint Security Tampering": {
        "techniques": ["T1562", "T1070"],
        "tactics": ["TA0005"],
    },
    "Data Loss Prevention (DLP)": {
        "techniques": ["T1567", "T1052"],
        "tactics": ["TA0010"],
    },
    "Insider Threat": {
        "techniques": ["T1078", "T1530", "T1213"],
        "tactics": ["TA0009", "TA0007"],
    },
    "Ransomware Indicators": {
        "techniques": ["T1486", "T1490", "T1489"],
        "tactics": ["TA0040"],  # Impact
    },
    # Sysmon event gap-fills (12 — ported from Talon)
    "Sysmon Event 2 — File Creation Time Changed": {
        "techniques": ["T1070.006"],
        "tactics": ["TA0005"],  # Defense Evasion
    },
    "Sysmon Event 6 — Driver Loaded": {
        "techniques": ["T1543.003", "T1014", "T1068"],
        "tactics": ["TA0003", "TA0004", "TA0005"],
    },
    "Sysmon Event 7 — Image/DLL Loaded": {
        "techniques": ["T1574.002", "T1574.001", "T1055.001"],
        "tactics": ["TA0005", "TA0004"],
    },
    "Sysmon Event 10 — Process Access (LSASS / Credential Dumping)": {
        "techniques": ["T1003.001", "T1055"],
        "tactics": ["TA0006", "TA0005"],
    },
    "Sysmon Event 12 — Registry Key/Value Create/Delete": {
        "techniques": ["T1547.001", "T1112", "T1562.001"],
        "tactics": ["TA0003", "TA0005"],
    },
    "Sysmon Event 13 — Registry Value Set": {
        "techniques": ["T1547.001", "T1112", "T1562.001", "T1574.012"],
        "tactics": ["TA0003", "TA0005"],
    },
    "Sysmon Event 14 — Registry Key/Value Renamed": {
        "techniques": ["T1112", "T1562"],
        "tactics": ["TA0005"],
    },
    "Sysmon Event 15 — File Stream / Mark-of-the-Web": {
        "techniques": ["T1564.004", "T1027"],
        "tactics": ["TA0005"],
    },
    "Sysmon Event 16 — Sysmon Configuration Change": {
        "techniques": ["T1562.002", "T1562"],
        "tactics": ["TA0005"],
    },
    "Sysmon Event 17 — Named Pipe Created": {
        "techniques": ["T1055", "T1559"],
        "tactics": ["TA0005", "TA0011"],
    },
    "Sysmon Event 18 — Named Pipe Connected": {
        "techniques": ["T1021.002", "T1055"],
        "tactics": ["TA0008", "TA0005"],
    },
    "Sysmon Event 22 — DNS Query": {
        "techniques": ["T1071.004", "T1568", "T1568.002"],
        "tactics": ["TA0011"],
    },
    # Talon Windows categories (3)
    "Windows Autoruns — Persistence Review": {
        "techniques": ["T1547", "T1053", "T1543", "T1546"],
        "tactics": ["TA0003"],
    },
    "Microsoft Defender Detection": {
        "techniques": ["T1204", "T1566", "T1562.001"],
        "tactics": ["TA0001", "TA0002", "TA0005"],
    },
    "Sysinternals sigcheck — Unsigned/Suspicious Binary": {
        "techniques": ["T1036", "T1553", "T1036.001"],
        "tactics": ["TA0005"],
    },
    # Identity / cloud / CI-CD / macOS / network / data / session /
    # supply-chain (10)
    "Entra ID — Suspicious Sign-in": {
        "techniques": ["T1078.004", "T1550.001", "T1111"],
        "tactics": ["TA0001", "TA0006"],
    },
    "Okta — Suspicious Activity": {
        "techniques": ["T1078", "T1098", "T1556"],
        "tactics": ["TA0003", "TA0006"],
    },
    "MFA Fatigue / Push Bombing": {
        "techniques": ["T1621", "T1078"],
        "tactics": ["TA0001", "TA0006"],
    },
    "Container / Kubernetes Runtime Anomaly": {
        "techniques": ["T1611", "T1610", "T1613", "T1552.007"],
        "tactics": ["TA0002", "TA0004", "TA0007"],
    },
    "CI/CD Abuse — GitHub Actions / Pipeline": {
        "techniques": ["T1552.004", "T1552.007", "T1195.002", "T1199"],
        "tactics": ["TA0001", "TA0006"],
    },
    "macOS Persistence / Suspicious Execution": {
        "techniques": ["T1547.011", "T1059.002", "T1553.001", "T1569.001"],
        "tactics": ["TA0002", "TA0003", "TA0005"],
    },
    "Zeek Network Anomaly": {
        "techniques": ["T1071", "T1110", "T1572", "T1573"],
        "tactics": ["TA0011", "TA0006"],
    },
    "Database Access Anomaly": {
        "techniques": ["T1213", "T1530", "T1078"],
        "tactics": ["TA0009", "TA0010"],
    },
    "Session Hijack / SSO Token Theft": {
        "techniques": ["T1539", "T1550.004", "T1528"],
        "tactics": ["TA0006", "TA0001"],
    },
    "Supply Chain — Malicious Package / Typosquat": {
        "techniques": ["T1195.002", "T1059", "T1552"],
        "tactics": ["TA0001", "TA0006"],
    },
}


# ---------------------------------------------------------------------------
# Output contract — pinned to ION's CaseClosureReason enum so verdicts feed
# directly into detection-engineering tuning metrics.
# ---------------------------------------------------------------------------


_OUTPUT_CONTRACT = """

---

## Output Contract — MANDATORY

Respond with **ONE** valid JSON object. No prose, no markdown code fences,
no commentary outside the JSON. The object MUST conform to this schema:

```jsonc
{
  // --- Required envelope (always populate) ---
  "verdict": "true_positive | false_positive | benign_true_positive | inconclusive",
  "confidence": "low | medium | high",
  "severity": "info | low | medium | high | critical",
  "summary": "1-2 sentence executive summary",
  "analyst_explanation": "plain-language explanation for an L1 analyst",
  "technical_details": "expert-level analysis with exact field values",
  "mitre": {
    "tactics": ["TA0002"],
    "techniques": ["T1059.001"]
  },
  "recommended_actions": [
    {"priority": "p1|p2|p3",
     "action": "specific instruction",
     "owner": "soc|ir|it|user|auto"}
  ],
  "key_observations": [
    // The specific evidence you based the verdict on. EVERY entry must cite
    // a field that actually appears in alert_summary. This is what an
    // analyst would point at on the Kibana detail page. Example:
    //   {"field": "process.command_line",
    //    "value": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
    //    "significance": "obfuscated base64 payload — common for
    //                     living-off-the-land execution"}
    {"field": "process.command_line | destination.ip | ... (must match a key in alert_summary)",
     "value": "the exact value from that field",
     "significance": "why this matters for the verdict"}
  ],
  "suggested_closure_reason":
    "true_positive | false_positive | benign_true_positive | duplicate | insufficient_data | not_applicable",
  "tuning_recommendation": {
    "rule_needs_tuning": true,
    "rationale": "one sentence on why, or null if no tuning is needed",
    "suggested_change": "concrete exclusion/refinement or null"
  },

  // --- Optional (populate only if relevant) ---
  "iocs": [
    {"type": "sha256|md5|ipv4|domain|url|file_path|process_name|command_line|registry_key|email|user|host",
     "value": "...",
     "confidence": "low|medium|high",
     "note": "..."}
  ],
  "affected_assets": [
    {"type": "host|user|account|service",
     "identifier": "...",
     "role": "source|target|transit"}
  ],
  "timeline": [{"ts": "ISO8601", "event": "...", "source": "..."}],
  "kill_chain_phase":
    "reconnaissance|weaponization|delivery|exploitation|installation|c2|actions|unknown",
  "containment_state": "none|partial|full|not_applicable",
  "blast_radius": {"hosts_affected": 0, "accounts_affected": 0, "data_impact": "..."},
  "references": ["url1"],
  "template_specific": { /* template-specified fields, if any */ }
}
```

### Verdict semantics — these MUST match ION's case closure enum:

- **true_positive** — the rule fired on genuinely malicious/unauthorised activity.
- **false_positive** — the rule fired but the activity is benign; **the rule
  needs tuning** (fill `tuning_recommendation.suggested_change`).
- **benign_true_positive** — the rule correctly identified the behaviour it
  was looking for, but that behaviour is authorised in this environment
  (e.g. vuln scanner, approved admin tool). Rule is working as designed.
- **inconclusive** — insufficient evidence to decide; explain what's missing
  in `technical_details` and set `suggested_closure_reason` to
  `insufficient_data`.

### Rules

1. Every enum value above is lowercase exactly as shown.
2. Never invent MITRE IDs — only use IDs you can tie to evidence in the alert.
3. If you have no IOCs, use `[]` — do not omit the field.
4. `tuning_recommendation.rule_needs_tuning` is `true` ONLY for
   `verdict: "false_positive"`.
5. `key_observations` MUST reference fields that literally appear in the
   `alert_summary` payload. Do not cite fields that are not present.
   Missing evidence → verdict must be `inconclusive`.
6. Output is consumed by automation. Malformed JSON breaks the pipeline.
"""


def _load_list(raw: Optional[str]) -> list:
    """Decode a JSON list column defensively — returns [] on None/invalid."""
    if not raw:
        return []
    try:
        val = json.loads(raw)
        return val if isinstance(val, list) else []
    except Exception:
        return []


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

    # -------------------------------------------------- gold exemplars

    def _get_gold_exemplars_for_alert(
        self,
        alert: dict,
        *,
        k: int = 3,
        min_similarity: float = 0.7,
    ) -> List[dict]:
        """Return up to ``k`` past, human-agreed closed cases similar to
        ``alert``. Empty list on any failure — never raises.

        Filter: case closed (closure_reason IS NOT NULL) AND at least one
        AIFeedback row marks ``agreement=True`` (i.e. Bob and the human
        agreed on the verdict). The agreement filter is critical — we want
        Bob to learn from cases he got right, not from cases he got wrong.
        """
        if not _few_shot_enabled() or self.session is None or not alert:
            return []

        try:
            from ion.services.embedding_service import get_embedding_service
        except Exception:
            return []

        svc = get_embedding_service()
        if not svc.is_enabled:
            return []

        text = _alert_text_for_embedding(alert)
        if not text:
            return []

        vec = svc.embed(text)
        if vec is None:
            return []

        try:
            from sqlalchemy import exists
            from ion.models.ai_feedback import AIFeedback
            from ion.models.alert_triage import AlertCase
            from ion.models.case_embedding import CaseEmbedding
        except Exception as exc:
            logger.debug("Gold exemplar imports failed: %s", exc)
            return []

        try:
            distance = CaseEmbedding.embedding.cosine_distance(vec)
            agreement_subq = (
                exists()
                .where(AIFeedback.case_id == AlertCase.id)
                .where(AIFeedback.agreement.is_(True))
            )
            rows = (
                self.session.query(AlertCase, distance.label("distance"))
                .join(CaseEmbedding, CaseEmbedding.case_id == AlertCase.id)
                .filter(AlertCase.closure_reason.isnot(None))
                .filter(agreement_subq)
                .order_by(distance.asc())
                .limit(max(1, int(k)))
                .all()
            )
        except Exception as exc:
            logger.debug("Gold exemplar query failed: %s", exc)
            return []

        out: list[dict] = []
        for case, dist in rows:
            similarity = 1.0 - float(dist)
            if similarity < float(min_similarity):
                continue
            out.append({
                "case_number": case.case_number,
                "title": case.title,
                "summary": case.evidence_summary or case.description or "",
                "closure_reason": case.closure_reason,
                "closure_notes": case.closure_notes or "",
                "similarity": similarity,
            })
        return out

    # ------------------------------------------------------ KB RAG context

    def _get_kb_context_for_alert(
        self,
        alert: dict,
        *,
        k: int = 3,
        min_similarity: float = 0.65,
    ) -> List[dict]:
        """Return up to ``k`` KB articles most similar to ``alert``.

        The similarity threshold is intentionally a bit looser than gold
        exemplars (0.65 vs 0.7) because KB articles are *topic-level*
        documentation, so semantic overlap is broader by design — a KB
        article on "Kerberos attacks" should match alerts about Golden
        Ticket, Kerberoasting, AS-REP Roasting, etc.
        """
        if not _kb_rag_enabled() or self.session is None or not alert:
            return []

        try:
            from ion.services.embedding_service import get_embedding_service
        except Exception:
            return []

        svc = get_embedding_service()
        if not svc.is_enabled:
            return []

        text = _alert_text_for_embedding(alert)
        if not text:
            return []

        vec = svc.embed(text)
        if vec is None:
            return []

        try:
            from ion.models.document import Document
            from ion.models.kb_document_embedding import KBDocumentEmbedding
        except Exception as exc:
            logger.debug("KB RAG imports failed: %s", exc)
            return []

        try:
            distance = KBDocumentEmbedding.embedding.cosine_distance(vec)
            rows = (
                self.session.query(Document, distance.label("distance"))
                .join(
                    KBDocumentEmbedding,
                    KBDocumentEmbedding.document_id == Document.id,
                )
                .filter(Document.status == "active")
                .order_by(distance.asc())
                .limit(max(1, int(k)))
                .all()
            )
        except Exception as exc:
            logger.debug("KB RAG query failed: %s", exc)
            return []

        out: list[dict] = []
        for doc, dist in rows:
            similarity = 1.0 - float(dist)
            if similarity < float(min_similarity):
                continue
            # First ~800 chars of rendered content keeps the system prompt
            # tight. Full article is available via /documents/<id> if the
            # analyst (or Bob via MCP later) wants more.
            excerpt = (doc.rendered_content or "")[:800]
            out.append({
                "document_id": doc.id,
                "name": doc.name,
                "excerpt": excerpt,
                "similarity": similarity,
            })
        return out

    # ------------------------------------------------------------------ render

    def render_system_prompt(
        self,
        template: Optional[AlertPromptTemplate],
        alert: Optional[dict] = None,
    ) -> str:
        """Merge ION's base security system prompt with the template's guidance
        and append the canonical JSON output contract.

        If ``template`` is None, returns the base security prompt plus the
        output contract so callers still get a structured response.
        """
        # Lazy import to avoid tight coupling at import time
        from ion.services.ollama_service import SYSTEM_PROMPTS

        base = SYSTEM_PROMPTS.get("security", "")
        parts: list[str] = [base.rstrip()]

        if template is not None:
            parts.append("\n\n---\n")
            parts.append(f"## Per-Rule Investigation Guide: {template.name}\n")

            if template.description:
                parts.append(template.description.strip() + "\n")

            if template.severity_hint:
                parts.append(
                    f"\nSeverity hint for this rule: **{template.severity_hint}**\n"
                )

            # Pinned MITRE context — helps the model stay anchored on the
            # techniques/tactics the template is scoped to.
            techs = _load_list(template.mitre_techniques_json)
            tactics = _load_list(template.mitre_tactics_json)
            if techs or tactics:
                parts.append("\n### Scoped MITRE ATT&CK Context\n")
                if techs:
                    parts.append(f"- Techniques: {', '.join(techs)}\n")
                if tactics:
                    parts.append(f"- Tactics: {', '.join(tactics)}\n")

            if template.prompt_text:
                parts.append("\n### Investigation Focus\n")
                parts.append(template.prompt_text.strip() + "\n")

            if template.investigation_checklist_text:
                parts.append("\n### Checklist — Answer Each\n")
                parts.append(template.investigation_checklist_text.strip() + "\n")

            expected = _load_list(template.expected_outputs_json)
            if expected:
                parts.append("\n### Template-Specific Output Fields\n")
                parts.append(
                    "In addition to the required envelope fields below, populate "
                    "`template_specific` with: "
                    + ", ".join(str(f) for f in expected)
                    + ".\n"
                )

            if alert:
                rule_id = AlertPromptRepository._extract_rule_id(alert) or "(unknown)"
                parts.append(f"\n_Matched alert rule id: `{rule_id}`_\n")

        # v0.10.6: prepend "Knowledge Base Context" when KB RAG is enabled.
        # Placed BEFORE the gold exemplars so Bob's prompt priority reads:
        # per-rule playbook → KB topic grounding → prior cases → output
        # contract. The KB is general investigation background; gold
        # exemplars are specific past verdicts; the contract is the format.
        if alert is not None:
            try:
                kb_hits = self._get_kb_context_for_alert(alert)
            except Exception as exc:
                logger.debug("KB RAG retrieval failed: %s", exc)
                kb_hits = []
            if kb_hits:
                parts.append(_format_kb_context_for_prompt(kb_hits))

        # v0.10.5: "Prior Similar Cases" if few-shot is enabled and we have
        # an alert + a DB session.
        if alert is not None:
            try:
                exemplars = self._get_gold_exemplars_for_alert(alert)
            except Exception as exc:
                logger.debug("Gold exemplar retrieval failed: %s", exc)
                exemplars = []
            if exemplars:
                parts.append(_format_exemplars_for_prompt(exemplars))

        # Output contract — always appended, with or without a template
        parts.append(_OUTPUT_CONTRACT)
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
    topped_up = 0
    try:
        repo = AlertPromptRepository(db)
        # Load existing rows once; we both skip-on-insert and top-up MITRE.
        existing_by_name = {t.name: t for t in repo.list_all()}

        for defn in _DEFAULT_TEMPLATES:
            name = defn["name"]
            mitre = _TEMPLATE_MITRE_MAP.get(name, {})
            techniques = mitre.get("techniques")
            tactics = mitre.get("tactics")

            if name in existing_by_name:
                # Top-up: row pre-dates the MITRE columns — populate them from
                # the map so existing deployments gain technique/tactic matching
                # without a manual resync. We only write when currently unset so
                # user edits are preserved.
                row = existing_by_name[name]
                if techniques and not row.mitre_techniques_json:
                    row.mitre_techniques_json = json.dumps(techniques)
                    topped_up += 1
                if tactics and not row.mitre_tactics_json:
                    row.mitre_tactics_json = json.dumps(tactics)
                continue

            repo.create(
                name=name,
                prompt_text=defn.get("prompt_text", ""),
                description=defn.get("description"),
                enabled=True,
                rule_ids=defn.get("rule_ids"),
                rule_groups=defn.get("rule_groups"),
                rule_id_pattern=defn.get("rule_id_pattern"),
                mitre_techniques=techniques,
                mitre_tactics=tactics,
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
        logger.info(
            "AlertPromptTemplate seed: %d inserted, %d topped-up with MITRE",
            inserted,
            topped_up,
        )
    except Exception:
        db.rollback()
        logger.exception("Failed to seed default AlertPromptTemplate rows")
        raise
    finally:
        if close_after:
            db.close()

    return inserted
