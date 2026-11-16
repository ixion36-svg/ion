"""CyAB Onboarding Studio — code-seeded pillar + sub-profile catalogue.

Source-of-truth for the 6 pillars and 14 sub-profiles introduced in
v0.12.0. The seeder (``cyab_subprofile_service.seed_catalogue``)
UPSERTs these into the ``cyab_pillars`` and ``cyab_subprofiles``
tables on first boot, and skips any sub-profile row where
``is_custom=True`` so operator edits survive subsequent boots.

Three sub-profiles are authored to *full* depth (intake questions,
recommended tasks, detection + audit use cases with ECS|QL logic
snippets, references):

- ``active_directory``  (pillar: identity)
- ``windows_endpoint``  (pillar: endpoint)
- ``next_gen_firewall`` (pillar: network)

The remaining 11 ship as skeletons — labels + ECS anchors + expected
feeds, with empty content arrays. v0.12.1 fills them at the same
depth as the three exemplars.

See ``_research_cyab_onboarding_studio.md`` for the full design.
"""

from __future__ import annotations

from typing import Any, Dict, List

CATALOGUE_VERSION = 2  # v0.12.2 — all 15 sub-profiles authored to full depth


# ---------------------------------------------------------------------------
# Pillars (6) — Gemini gold-standard log-source priority hierarchy
# ---------------------------------------------------------------------------

PILLARS: List[Dict[str, Any]] = [
    {
        "id": "identity",
        "label": "Identity & Access",
        "icon": "fingerprint",
        "priority": 1,
        "description": (
            "Authentication, directory services, and federated identity. "
            "Tier-1 telemetry: every credential event, group change, and "
            "federation token feeds the rest of the SOC's correlation graph."
        ),
    },
    {
        "id": "endpoint",
        "label": "Endpoints & Servers",
        "icon": "cpu",
        "priority": 2,
        "description": (
            "Workstations, servers, and the EDR/Sysmon/auditd telemetry "
            "they emit. Detect process, file, registry, and inter-process "
            "behaviour inside the trust boundary."
        ),
    },
    {
        "id": "network",
        "label": "Network & Perimeter",
        "icon": "network",
        "priority": 2,
        "description": (
            "Firewalls, DNS, web/email proxies. Detect command-and-control, "
            "exfiltration, and east-west lateral movement at network layer."
        ),
    },
    {
        "id": "cloud",
        "label": "Cloud & SaaS",
        "icon": "cloud",
        "priority": 3,
        "description": (
            "Cloud control-plane audit (AWS / Azure / GCP), Microsoft 365 / "
            "Workspace, and SaaS apps. API-driven visibility for resource "
            "and consent changes."
        ),
    },
    {
        "id": "data",
        "label": "Data & Apps",
        "icon": "database",
        "priority": 3,
        "description": (
            "Databases, web applications, and data stores. The lowest layer "
            "of the kill chain — what the attacker is actually after."
        ),
    },
    {
        "id": "ot",
        "label": "OT & IoT",
        "icon": "factory",
        "priority": 4,
        "description": (
            "Industrial control, SCADA, and IoT environments. Lower-volume "
            "but high-impact telemetry; bridge between IT and physical world."
        ),
    },
]


# ---------------------------------------------------------------------------
# Sub-profiles — 3 worked exemplars + 11 skeletons
# ---------------------------------------------------------------------------

# === Identity ==============================================================

ACTIVE_DIRECTORY: Dict[str, Any] = {
    "id": "active_directory",
    "pillar_id": "identity",
    "label": "Active Directory",
    "icon": "users",
    "ecs_anchors": [
        "winlog.channel:Security",
        "event.dataset:windows.security",
    ],
    "expected_feeds": ["windows_security", "sysmon"],
    "description": (
        "On-prem domain controllers and the Security event log they emit. "
        "Tier-0 — compromise here is enterprise-wide compromise."
    ),
    "catalogue": {
        "intake_questions": [
            {
                "key": "sub_id_ad_recycle_bin",
                "text": "Is the AD Recycle Bin enabled for forensics?",
                "answer_type": "yesno",
                "feeds": [["cg", 5]],
            },
            {
                "key": "sub_id_ad_advanced_audit",
                "text": "Is Advanced Audit Policy pushed via GPO to all DCs?",
                "answer_type": "yesno",
                "feeds": [["cg", 8]],
            },
            {
                "key": "sub_id_ad_priv_group_monitor",
                "text": "Are sensitive groups (Domain Admins, Enterprise Admins) monitored for additions?",
                "answer_type": "yesno",
                "feeds": [["cg", 10]],
            },
            {
                "key": "sub_id_ad_psh_logging",
                "text": "Is PowerShell Script Block Logging enabled domain-wide?",
                "answer_type": "yesno",
                "feeds": [["cg", 6]],
            },
            {
                "key": "sub_id_ad_msa_rotation",
                "text": "How often are Managed Service Account passwords rotated?",
                "answer_type": "single",
                "options": [
                    {"value": "lt_30d", "label": "≤ 30 days"},
                    {"value": "30_90d", "label": "30–90 days"},
                    {"value": "gt_90d", "label": "> 90 days"},
                    {"value": "never", "label": "Never / unknown"},
                    {"value": "dont_know", "label": "Don't know"},
                ],
                "feeds": [["cg", 4]],
            },
            {
                "key": "sub_id_ad_ntlm_audit",
                "text": "Is NTLM auditing enabled to identify legacy authentication?",
                "answer_type": "yesno",
                "feeds": [["cg", 5]],
            },
            {
                "key": "sub_id_ad_dsa_audit",
                "text": "Is Directory Service Access auditing enabled for OU changes?",
                "answer_type": "yesno",
                "feeds": [["cg", 5]],
            },
        ],
        "recommended_tasks": [
            "Validate Event ID 4662 (Object Access) on GPO containers and the AdminSDHolder object.",
            "Configure Sysmon for enhanced process tracking on every domain controller.",
            "Set up alerts for 'Dormant Admin' activity (Domain Admin no logon >90d, then a logon).",
            "Map Tier-0 asset dependencies (KRBTGT, AdminSDHolder, DCs, ADFS).",
        ],
        "detection_use_cases": [
            {
                "id": "ad_kerberoasting",
                "title": "Kerberoasting",
                "kind": "detection",
                "risk": "high",
                "summary": "High-volume service ticket (TGS) requests for accounts with weak SPNs.",
                "description": (
                    "Detection of bulk TGS requests (Event ID 4769) using "
                    "RC4-HMAC encryption (0x17) for non-krbtgt service "
                    "accounts. Threshold-driven over a one-hour window."
                ),
                "mitre_ids": ["T1558.003"],
                "logic_snippet": (
                    "FROM logs-windows.security-* | WHERE event.code == \"4769\" "
                    "AND winlog.event_data.TicketEncryptionType == \"0x17\" "
                    "AND winlog.event_data.ServiceName != \"krbtgt\" "
                    "| STATS count = COUNT(*) BY user.name "
                    "| WHERE count > 50"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_kerberoasting_triage",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1558.003", "url": "https://attack.mitre.org/techniques/T1558/003/"},
                ],
            },
            {
                "id": "ad_dcshadow",
                "title": "DCShadow",
                "kind": "detection",
                "risk": "critical",
                "summary": "Unauthorised replication of directory objects from a non-DC host.",
                "description": (
                    "DCShadow injects rogue replication metadata. Detect "
                    "Event 4662 with ObjectName matching 'Replicating "
                    "Directory Changes' GUIDs originating from a host not "
                    "in the Domain Controllers OU."
                ),
                "mitre_ids": ["T1207"],
                "logic_snippet": (
                    "FROM logs-windows.security-* | WHERE event.code == \"4662\" "
                    "AND winlog.event_data.ObjectName LIKE \"*Replicating Directory Changes*\" "
                    "AND NOT host.name IN (\"DC01\", \"DC02\", \"DC03\")"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_replication_anomaly",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1207", "url": "https://attack.mitre.org/techniques/T1207/"},
                ],
            },
            {
                "id": "ad_asrep_roasting",
                "title": "AS-REP Roasting",
                "kind": "detection",
                "risk": "high",
                "summary": "Auth requests for users with Kerberos pre-auth disabled.",
                "description": (
                    "Detection of AS-REQ (Event ID 4768) where "
                    "PreAuthType=0, indicating the target account has "
                    "'Do not require Kerberos pre-authentication' set — "
                    "the AS-REP can then be cracked offline."
                ),
                "mitre_ids": ["T1558.004"],
                "logic_snippet": (
                    "FROM logs-windows.security-* | WHERE event.code == \"4768\" "
                    "AND winlog.event_data.PreAuthType == \"0\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_asrep_triage",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1558.004", "url": "https://attack.mitre.org/techniques/T1558/004/"},
                ],
            },
            {
                "id": "ad_dcsync",
                "title": "DCSync",
                "kind": "detection",
                "risk": "critical",
                "summary": "GetChanges / GetChangesAll replication request from a non-DC.",
                "description": (
                    "DCSync abuses MS-DRSR replication APIs to extract "
                    "credential hashes from a DC. Detect Event 4662 with "
                    "the GetChanges (1131f6aa-...) or GetChangesAll "
                    "(1131f6ad-...) GUIDs from a host not on the DC list."
                ),
                "mitre_ids": ["T1003.006"],
                "logic_snippet": (
                    "FROM logs-windows.security-* | WHERE event.code == \"4662\" "
                    "AND (winlog.event_data.Properties LIKE \"*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*\" "
                    "OR winlog.event_data.Properties LIKE \"*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*\") "
                    "AND NOT host.name IN (\"DC01\", \"DC02\", \"DC03\")"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_dcsync",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1003.006", "url": "https://attack.mitre.org/techniques/T1003/006/"},
                    {"title": "MS-DRSR §4.1.10", "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/"},
                ],
            },
            {
                "id": "ad_bloodhound",
                "title": "BloodHound enumeration",
                "kind": "detection",
                "risk": "medium",
                "summary": "High-volume LDAP / SAMR enumeration patterns from a single source.",
                "description": (
                    "BloodHound (and SharpHound) enumerate the domain via "
                    "LDAP and SAMR. Threshold-detect Event 5145 with "
                    "ShareName containing IPC$ and RelativeTargetName "
                    "samr/lsarpc, count > 100 in 5 minutes from one source."
                ),
                "mitre_ids": ["T1018", "T1087.002"],
                "logic_snippet": (
                    "FROM logs-windows.security-* | WHERE event.code == \"5145\" "
                    "AND winlog.event_data.ShareName LIKE \"*\\\\IPC$*\" "
                    "AND winlog.event_data.RelativeTargetName IN (\"samr\", \"lsarpc\") "
                    "| STATS count = COUNT(*) BY source.ip "
                    "| WHERE count > 100"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_recon_review",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1018", "url": "https://attack.mitre.org/techniques/T1018/"},
                ],
            },
        ],
        "audit_use_cases": [
            {
                "id": "ad_audit_sensitive_group_drift",
                "title": "Sensitive Group Drift",
                "kind": "audit",
                "risk": "medium",
                "summary": "Real-time auditing of users added to protected admin groups.",
                "description": (
                    "Tracks 4728 / 4732 / 4756 (member added to global / "
                    "local / universal group) for membership changes to "
                    "Domain Admins, Enterprise Admins, Schema Admins."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-windows.security-* | WHERE event.code IN (\"4728\", \"4732\", \"4756\") "
                    "AND winlog.event_data.TargetUserName IN "
                    "(\"Domain Admins\", \"Enterprise Admins\", \"Schema Admins\")"
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AC-6(7)", "CIS Microsoft AD Benchmark 5.4"],
                "references": [],
            },
            {
                "id": "ad_audit_gpo_tampering",
                "title": "GPO Tampering",
                "kind": "audit",
                "risk": "high",
                "summary": "Changes to Default Domain Policy or critical security GPOs.",
                "description": (
                    "Event 5136 (Directory Service object modified) where "
                    "ObjectClass is groupPolicyContainer. Catches edits to "
                    "GPOs that drive password policy, audit policy, etc."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-windows.security-* | WHERE event.code == \"5136\" "
                    "AND winlog.event_data.ObjectClass == \"groupPolicyContainer\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST CM-3", "CIS Microsoft AD Benchmark 4.2"],
                "references": [],
            },
            {
                "id": "ad_audit_password_policy_weakening",
                "title": "Password Policy Weakening",
                "kind": "audit",
                "risk": "low",
                "summary": "Modifications to domain password complexity / length requirements.",
                "description": "Event 4739 (Domain Policy was changed).",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-windows.security-* | WHERE event.code == \"4739\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST IA-5(1)", "CIS Microsoft AD Benchmark 5.2"],
                "references": [],
            },
            {
                "id": "ad_audit_trust_change",
                "title": "Trust Relationship Change",
                "kind": "audit",
                "risk": "high",
                "summary": "New forest or domain trusts established with external entities.",
                "description": (
                    "Events 4716 (trust modified), 4865 (trust info added), "
                    "4866 (trust info removed)."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-windows.security-* | WHERE event.code IN (\"4716\", \"4865\", \"4866\")"
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AC-3", "CIS Microsoft AD Benchmark 4.5"],
                "references": [],
            },
        ],
        "references": [
            {"title": "MITRE ATT&CK Enterprise — Active Directory techniques", "url": "https://attack.mitre.org/"},
            {"title": "CIS Microsoft Active Directory Benchmark v3", "url": "https://www.cisecurity.org/benchmark/active_directory"},
            {"title": "SANS GCIH — Kerberos attack chains", "url": "https://www.sans.org/cyber-security-courses/hacker-techniques-incident-handling/"},
        ],
    },
}


# === Endpoint ==============================================================

WINDOWS_ENDPOINT: Dict[str, Any] = {
    "id": "windows_endpoint",
    "pillar_id": "endpoint",
    "label": "Windows endpoint",
    "icon": "monitor",
    "ecs_anchors": [
        "winlog.event_id:*",
        "winlog.channel:Microsoft-Windows-Sysmon/Operational",
    ],
    "expected_feeds": ["sysmon", "windows_security", "edr"],
    "description": (
        "Windows workstations and member servers. Sysmon + Security log "
        "+ EDR triad covers process, file, registry, and inter-process "
        "behaviour."
    ),
    "catalogue": {
        "intake_questions": [
            {
                "key": "sub_ep_win_credguard",
                "text": "Is Credential Guard enabled on user-facing devices?",
                "answer_type": "yesno",
                "feeds": [["cg", 6]],
            },
            {
                "key": "sub_ep_win_proc_creation",
                "text": "Are Process Creation events (4688) captured with Command Line visibility?",
                "answer_type": "yesno",
                "feeds": [["cg", 8]],
            },
            {
                "key": "sub_ep_win_psh_transcription",
                "text": "Is PowerShell transcription enabled domain-wide?",
                "answer_type": "yesno",
                "feeds": [["cg", 6]],
            },
            {
                "key": "sub_ep_win_rdp_logs",
                "text": "Are RDP logon events (4624 Type 10) being forwarded to the SIEM?",
                "answer_type": "yesno",
                "feeds": [["cg", 5]],
            },
            {
                "key": "sub_ep_win_applocker",
                "text": "Is AppLocker or WDAC in enforcing mode on standard images?",
                "answer_type": "single",
                "options": [
                    {"value": "enforce", "label": "Enforcing"},
                    {"value": "audit", "label": "Audit only"},
                    {"value": "off", "label": "Not deployed"},
                    {"value": "dont_know", "label": "Don't know"},
                ],
                "feeds": [["cg", 7]],
            },
        ],
        "recommended_tasks": [
            "Confirm Sysmon config matches the SwiftOnSecurity / Olaf baseline plus org-specific tweaks.",
            "Validate Event 4688 captures `ProcessCommandLine` (registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\\ProcessCreationIncludeCmdLine_Enabled = 1).",
            "Cross-check Defender / EDR coverage: every host should appear in both inventory and EDR console.",
            "Ensure AppLocker / WDAC alerts are tagged as high-severity so blocks aren't silently dropped.",
        ],
        "detection_use_cases": [
            {
                "id": "ep_win_lsass_dump",
                "title": "LSASS memory dump",
                "kind": "detection",
                "risk": "critical",
                "summary": "Tools like Mimikatz or Taskmgr accessing LSASS process memory.",
                "description": (
                    "Sysmon Event 10 (ProcessAccess) targeting lsass.exe "
                    "with GrantedAccess masks containing 0x1010 / 0x1410. "
                    "Allowlist legitimate AV/EDR access patterns."
                ),
                "mitre_ids": ["T1003.001"],
                "logic_snippet": (
                    "FROM logs-windows.sysmon-* | WHERE event.code == \"10\" "
                    "AND winlog.event_data.TargetImage LIKE \"*\\\\lsass.exe\" "
                    "AND winlog.event_data.GrantedAccess IN (\"0x1010\", \"0x1410\", \"0x143A\") "
                    "AND NOT process.executable LIKE \"*MsMpEng.exe\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_lsass_dump",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1003.001", "url": "https://attack.mitre.org/techniques/T1003/001/"},
                ],
            },
            {
                "id": "ep_win_sched_task_temp",
                "title": "Scheduled Task persistence to Temp",
                "kind": "detection",
                "risk": "medium",
                "summary": "Tasks created pointing to Temp / AppData binaries.",
                "description": (
                    "Event 4698 (scheduled task created) where Action "
                    "Path resolves under \\AppData\\, \\Temp\\, or "
                    "\\Public\\."
                ),
                "mitre_ids": ["T1053.005"],
                "logic_snippet": (
                    "FROM logs-windows.security-* | WHERE event.code == \"4698\" "
                    "AND (winlog.event_data.TaskContent LIKE \"*\\\\AppData\\\\*\" "
                    "OR winlog.event_data.TaskContent LIKE \"*\\\\Temp\\\\*\")"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_sched_task_review",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1053.005", "url": "https://attack.mitre.org/techniques/T1053/005/"},
                ],
            },
            {
                "id": "ep_win_wmi_subscription",
                "title": "WMI Event Subscription",
                "kind": "detection",
                "risk": "high",
                "summary": "Persistence via WMI Event Filter / Consumer / Binding.",
                "description": (
                    "Sysmon Event IDs 19/20/21 (WmiEvent — filter, "
                    "consumer, binding) flag the classic Black Hat "
                    "WMI persistence chain."
                ),
                "mitre_ids": ["T1546.003"],
                "logic_snippet": (
                    "FROM logs-windows.sysmon-* | WHERE event.code IN (\"19\", \"20\", \"21\")"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_wmi_persistence",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1546.003", "url": "https://attack.mitre.org/techniques/T1546/003/"},
                ],
            },
            {
                "id": "ep_win_token_impersonation",
                "title": "Token impersonation",
                "kind": "detection",
                "risk": "high",
                "summary": "Process spawned with a different integrity / user token.",
                "description": (
                    "Event 4624 LogonType 9 (NewCredentials) + Sysmon 1 "
                    "child showing LogonId mismatch is a strong signal "
                    "of `runas /netonly` or token theft."
                ),
                "mitre_ids": ["T1134"],
                "logic_snippet": (
                    "FROM logs-windows.security-* | WHERE event.code == \"4624\" "
                    "AND winlog.event_data.LogonType == \"9\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_token_impersonation",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1134", "url": "https://attack.mitre.org/techniques/T1134/"},
                ],
            },
            {
                "id": "ep_win_bits_misuse",
                "title": "BITS Job misuse",
                "kind": "detection",
                "risk": "medium",
                "summary": "Background Intelligent Transfer Service used for staging or exfil.",
                "description": (
                    "Microsoft-Windows-Bits-Client/Operational events "
                    "59 / 60 / 61 with destinations outside corporate "
                    "domain ranges."
                ),
                "mitre_ids": ["T1197"],
                "logic_snippet": (
                    "FROM logs-windows.* | WHERE event.code IN (\"59\", \"60\", \"61\") "
                    "AND event.provider == \"Microsoft-Windows-Bits-Client\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_bits_review",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1197", "url": "https://attack.mitre.org/techniques/T1197/"},
                ],
            },
            {
                "id": "ep_win_run_keys",
                "title": "Registry Run/RunOnce additions",
                "kind": "detection",
                "risk": "medium",
                "summary": "Boot-persistence via HKCU / HKLM Run keys.",
                "description": (
                    "Sysmon Event 13 (RegistryValueSet) where "
                    "TargetObject contains \\Software\\Microsoft\\Windows\\CurrentVersion\\Run."
                ),
                "mitre_ids": ["T1547.001"],
                "logic_snippet": (
                    "FROM logs-windows.sysmon-* | WHERE event.code == \"13\" "
                    "AND winlog.event_data.TargetObject LIKE "
                    "\"*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run*\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_runkey_review",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1547.001", "url": "https://attack.mitre.org/techniques/T1547/001/"},
                ],
            },
        ],
        "audit_use_cases": [
            {
                "id": "ep_win_audit_local_admin_add",
                "title": "Local admin addition",
                "kind": "audit",
                "risk": "high",
                "summary": "Users added to the local Administrators group.",
                "description": (
                    "Event 4732 with TargetUserName = Administrators on a "
                    "non-DC host."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-windows.security-* | WHERE event.code == \"4732\" "
                    "AND winlog.event_data.TargetUserName == \"Administrators\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AC-6(7)", "CIS Microsoft Windows 10 5.1"],
                "references": [],
            },
            {
                "id": "ep_win_audit_av_disabled",
                "title": "Antivirus / EDR disabled",
                "kind": "audit",
                "risk": "critical",
                "summary": "Defender or third-party EDR service stop.",
                "description": (
                    "Events 7036 / 7045 (Service Control Manager) for "
                    "Defender + EDR services entering Stopped state."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-windows.system-* | WHERE event.code IN (\"7036\", \"7045\") "
                    "AND winlog.event_data.param1 LIKE \"*Defender*\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST SI-3", "CIS Microsoft Windows 10 18.9.47"],
                "references": [],
            },
            {
                "id": "ep_win_audit_firewall_change",
                "title": "Firewall profile change",
                "kind": "audit",
                "risk": "medium",
                "summary": "Domain or Private firewall profile disabled.",
                "description": (
                    "Microsoft-Windows-Windows Firewall With Advanced "
                    "Security/Firewall events 4946–4954 covering rule "
                    "additions / disablement / profile changes."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-windows.* | WHERE event.code IN (\"4947\", \"4948\", \"4950\")"
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST SC-7", "CIS Microsoft Windows 10 9.1"],
                "references": [],
            },
            {
                "id": "ep_win_audit_remote_registry",
                "title": "Remote Registry service start",
                "kind": "audit",
                "risk": "low",
                "summary": "Remote Registry service started — common lateral movement vector.",
                "description": "Event 7036 with ServiceName = RemoteRegistry, NewState = Running.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-windows.system-* | WHERE event.code == \"7036\" "
                    "AND winlog.event_data.param1 == \"Remote Registry\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AC-17"],
                "references": [],
            },
        ],
        "references": [
            {"title": "MITRE ATT&CK Enterprise — Windows", "url": "https://attack.mitre.org/matrices/enterprise/windows/"},
            {"title": "Sysmon Modular config (Olaf)", "url": "https://github.com/olafhartong/sysmon-modular"},
            {"title": "CIS Microsoft Windows 10 / 11 Benchmark", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"},
        ],
    },
}


# === Network ===============================================================

NEXT_GEN_FIREWALL: Dict[str, Any] = {
    "id": "next_gen_firewall",
    "pillar_id": "network",
    "label": "Next-Gen Firewall",
    "icon": "shield",
    "ecs_anchors": [
        "event.dataset:panw.panos",
        "event.dataset:cisco.ftd",
        "event.dataset:fortinet.firewall",
    ],
    "expected_feeds": ["firewall"],
    "description": (
        "Perimeter and internal segmentation firewalls. East-west and "
        "north-south traffic logging — denied and allowed both go to the SIEM."
    ),
    "catalogue": {
        "intake_questions": [
            {
                "key": "sub_net_fw_allow_deny_logging",
                "text": "Are both denied and allowed connections logged to the SIEM?",
                "answer_type": "single",
                "options": [
                    {"value": "both", "label": "Both — full traffic logging"},
                    {"value": "deny_only", "label": "Denied only"},
                    {"value": "sampled", "label": "Sampled / NetFlow only"},
                    {"value": "no", "label": "No"},
                    {"value": "dont_know", "label": "Don't know"},
                ],
                "feeds": [["cg", 8]],
            },
            {
                "key": "sub_net_fw_ssl_decrypt",
                "text": "Is SSL/TLS decryption enabled for outbound web traffic?",
                "answer_type": "single",
                "options": [
                    {"value": "all", "label": "All — broad decryption"},
                    {"value": "selective", "label": "Selective — high-risk categories"},
                    {"value": "none", "label": "None"},
                    {"value": "dont_know", "label": "Don't know"},
                ],
                "feeds": [["cg", 6]],
            },
            {
                "key": "sub_net_fw_netflow",
                "text": "Is NetFlow / IPFIX exported for east-west traffic visibility?",
                "answer_type": "yesno",
                "feeds": [["cg", 5]],
            },
        ],
        "recommended_tasks": [
            "Confirm syslog/CEF is configured per ECS Beats module (panw.panos / cisco.ftd / fortinet.firewall).",
            "Validate denied + allowed are both indexed (some teams cap allowed at NetFlow only — confirm the trade-off is documented).",
            "Sample 10 random outbound flows; verify destination categorisation populates threat-feed tags.",
        ],
        "detection_use_cases": [
            {
                "id": "net_fw_dns_tunnelling",
                "title": "DNS tunnelling",
                "kind": "detection",
                "risk": "high",
                "summary": "High-volume TXT / NULL record queries indicative of C2.",
                "description": (
                    "Threshold-detect dns.question.type == 'TXT' or 'NULL' "
                    "with > 50 unique question.name per source.ip in a "
                    "5-minute window."
                ),
                "mitre_ids": ["T1071.004"],
                "logic_snippet": (
                    "FROM logs-network.firewall-* | WHERE dns.question.type IN (\"TXT\", \"NULL\") "
                    "| STATS unique_q = COUNT_DISTINCT(dns.question.name) BY source.ip "
                    "| WHERE unique_q > 50"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_dns_tunnel",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1071.004", "url": "https://attack.mitre.org/techniques/T1071/004/"},
                ],
            },
            {
                "id": "net_fw_http_exfil",
                "title": "Large HTTP POST exfiltration",
                "kind": "detection",
                "risk": "high",
                "summary": "Large POSTs to uncategorised / new domains.",
                "description": (
                    "http.request.method == POST with "
                    "http.request.bytes > 10 MB to a destination that "
                    "isn't in the corporate domain list."
                ),
                "mitre_ids": ["T1041", "T1567"],
                "logic_snippet": (
                    "FROM logs-network.firewall-* | WHERE http.request.method == \"POST\" "
                    "AND http.request.body.bytes > 10485760 "
                    "AND NOT destination.domain LIKE \"*.corp.local\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_exfil_review",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1041", "url": "https://attack.mitre.org/techniques/T1041/"},
                ],
            },
            {
                "id": "net_fw_internal_portscan",
                "title": "Internal port scan",
                "kind": "detection",
                "risk": "medium",
                "summary": "Single source attempting many ports across multiple subnets.",
                "description": (
                    "Threshold-detect distinct destination.port and "
                    "destination.ip from one source.ip > 200 in 5 min."
                ),
                "mitre_ids": ["T1046"],
                "logic_snippet": (
                    "FROM logs-network.firewall-* | WHERE network.direction == \"internal\" "
                    "| STATS uniq_port = COUNT_DISTINCT(destination.port), "
                    "uniq_ip = COUNT_DISTINCT(destination.ip) BY source.ip "
                    "| WHERE uniq_port > 50 AND uniq_ip > 20"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_recon_review",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1046", "url": "https://attack.mitre.org/techniques/T1046/"},
                ],
            },
            {
                "id": "net_fw_tor_node",
                "title": "Tor exit-node connection",
                "kind": "detection",
                "risk": "medium",
                "summary": "Outbound to known Tor exit nodes.",
                "description": (
                    "Lookup against a maintained Tor exit-node list "
                    "(refresh hourly from torproject.org)."
                ),
                "mitre_ids": ["T1090.003"],
                "logic_snippet": (
                    "FROM logs-network.firewall-* | WHERE destination.ip IN [tor_exit_list]"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_anonymiser_review",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1090.003", "url": "https://attack.mitre.org/techniques/T1090/003/"},
                ],
            },
        ],
        "audit_use_cases": [
            {
                "id": "net_fw_audit_any_any",
                "title": "Any-Any rule creation",
                "kind": "audit",
                "risk": "critical",
                "summary": "Firewall rules with Source: Any AND Destination: Any.",
                "description": (
                    "Catches the classic 'temporary' diagnostic rule that "
                    "becomes permanent — a common precursor to perimeter "
                    "breach. Check rule audit logs."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-network.firewall-config-* | WHERE event.action == \"rule-add\" "
                    "AND rule.source == \"any\" AND rule.destination == \"any\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST SC-7", "PCI DSS 1.2.1"],
                "references": [],
            },
            {
                "id": "net_fw_audit_shadow_rule",
                "title": "Shadow rule (no change ticket)",
                "kind": "audit",
                "risk": "high",
                "summary": "Rules created without a corresponding change-ticket reference.",
                "description": (
                    "Cross-reference firewall rule-add events against the "
                    "change management system; any rule lacking a ticket "
                    "ID in the description field is shadow."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-network.firewall-config-* | WHERE event.action == \"rule-add\" "
                    "AND NOT rule.description LIKE \"*CHG*\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST CM-3", "ISO 27001 A.12.1.2"],
                "references": [],
            },
        ],
        "references": [
            {"title": "MITRE ATT&CK Enterprise — Network", "url": "https://attack.mitre.org/"},
            {"title": "NIST SP 800-41 r1 — Firewall Policy", "url": "https://csrc.nist.gov/pubs/sp/800/41/r1/final"},
        ],
    },
}


# === Identity (continued) ==================================================

ENTRA_OKTA: Dict[str, Any] = {
    "id": "entra_okta",
    "pillar_id": "identity",
    "label": "Entra ID / Okta",
    "icon": "globe",
    "ecs_anchors": [
        "event.dataset:azure.signinlogs",
        "event.dataset:azure.auditlogs",
        "event.dataset:okta.system",
    ],
    "expected_feeds": ["identity_provider"],
    "description": (
        "Cloud-hosted federated identity providers. Conditional access "
        "policy auditing, sign-in risk, illicit consent grants, and "
        "service-principal credential rotation."
    ),
    "catalogue": {
        "intake_questions": [
            {
                "key": "sub_id_idp_risk_auth",
                "text": "Is risk-based / conditional-access authentication enabled for staff sign-in?",
                "answer_type": "yesno",
                "feeds": [["cg", 8]],
            },
            {
                "key": "sub_id_idp_legacy_auth",
                "text": "Are legacy authentication protocols (IMAP, POP, SMTP basic auth) blocked?",
                "answer_type": "yesno",
                "feeds": [["cg", 7]],
            },
            {
                "key": "sub_id_idp_admin_mfa",
                "text": "Is MFA required for every administrative role?",
                "answer_type": "yesno",
                "feeds": [["cg", 10]],
            },
            {
                "key": "sub_id_idp_sp_credentials",
                "text": "Are service-principal credential additions monitored and alerted?",
                "answer_type": "yesno",
                "feeds": [["cg", 7]],
            },
            {
                "key": "sub_id_idp_break_glass",
                "text": "Are break-glass / emergency-access accounts excluded from CA and alerted on use?",
                "answer_type": "yesno",
                "feeds": [["cg", 6]],
            },
            {
                "key": "sub_id_idp_consent_governance",
                "text": "Is third-party OAuth consent restricted to admin approval (no end-user grants)?",
                "answer_type": "single",
                "options": [
                    {"value": "admin_only", "label": "Admin approval required"},
                    {"value": "verified_only", "label": "Verified publishers only"},
                    {"value": "open", "label": "End users can grant"},
                    {"value": "dont_know", "label": "Don't know"},
                ],
                "feeds": [["cg", 6]],
            },
        ],
        "recommended_tasks": [
            "Confirm CA policies block legacy auth and require MFA for all staff (M365 Foundations 1.1.4).",
            "Inventory break-glass accounts; verify exclusion from CA + dedicated alert pipeline.",
            "Run Microsoft Secure Score / Okta Security Health and triage gaps weekly.",
            "Pull a list of enterprise apps with high-permission OAuth grants (Mail.ReadWrite, Files.ReadWrite.All) and review.",
        ],
        "detection_use_cases": [
            {
                "id": "idp_mfa_fatigue",
                "title": "MFA fatigue (push spam)",
                "kind": "detection",
                "risk": "high",
                "summary": "Repeated MFA push denials followed by a rapid success.",
                "description": (
                    "Threshold-detect azure.signinlogs / okta.system MFA "
                    "challenges where the same user.id sees ≥5 denials in "
                    "10 minutes followed by a success — classic push-spam "
                    "social-engineering pattern."
                ),
                "mitre_ids": ["T1621"],
                "logic_snippet": (
                    "FROM logs-azure.signinlogs-* | WHERE event.action == \"mfa_challenge\" "
                    "| STATS denied = COUNT(WHERE event.outcome == \"failure\"), "
                    "approved = COUNT(WHERE event.outcome == \"success\") BY user.id "
                    "| WHERE denied >= 5 AND approved >= 1"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_mfa_fatigue",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1621", "url": "https://attack.mitre.org/techniques/T1621/"},
                ],
            },
            {
                "id": "idp_impossible_travel",
                "title": "Impossible travel",
                "kind": "detection",
                "risk": "medium",
                "summary": "Successful login from two distant regions inside a short window.",
                "description": (
                    "Two successful sign-ins for the same user from "
                    "geographically distinct cities within 90 minutes. "
                    "Tune by suppressing known VPN egress IPs."
                ),
                "mitre_ids": ["T1078.004"],
                "logic_snippet": (
                    "FROM logs-azure.signinlogs-* | WHERE event.outcome == \"success\" "
                    "| LOOKUP geo_city BY source.ip "
                    "| EVAL travel_pair = CASE(uniq_cities BY user.id WITHIN 90m > 1, true, false)"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_impossible_travel",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1078.004", "url": "https://attack.mitre.org/techniques/T1078/004/"},
                ],
            },
            {
                "id": "idp_illicit_consent",
                "title": "Illicit consent grant",
                "kind": "detection",
                "risk": "critical",
                "summary": "Third-party app granted high-privilege Mail / Files permissions.",
                "description": (
                    "AuditLogs `Add app role assignment grant to user` "
                    "where ResourceDisplayName == 'Microsoft Graph' and "
                    "claimValue ∈ Mail.ReadWrite / Files.ReadWrite.All. "
                    "Most incidents start here."
                ),
                "mitre_ids": ["T1528"],
                "logic_snippet": (
                    "FROM logs-azure.auditlogs-* | WHERE event.action == \"Add app role assignment grant to user\" "
                    "AND azure.auditlogs.properties.target_resources.modified_properties.new_value LIKE "
                    "\"*Mail.ReadWrite*\" OR LIKE \"*Files.ReadWrite.All*\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_illicit_consent",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1528", "url": "https://attack.mitre.org/techniques/T1528/"},
                ],
            },
            {
                "id": "idp_break_glass_use",
                "title": "Break-glass account use",
                "kind": "detection",
                "risk": "critical",
                "summary": "Any sign-in by an emergency-access account.",
                "description": (
                    "Direct alert (no threshold) on sign-in by accounts "
                    "tagged break-glass / emergency-access. Used only "
                    "during disasters; any other use is anomalous."
                ),
                "mitre_ids": ["T1078"],
                "logic_snippet": (
                    "FROM logs-azure.signinlogs-* | WHERE user.name IN [break_glass_accounts]"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_break_glass",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1078", "url": "https://attack.mitre.org/techniques/T1078/"},
                ],
            },
            {
                "id": "idp_new_mfa_then_reset",
                "title": "New MFA method added then password reset",
                "kind": "detection",
                "risk": "high",
                "summary": "Phone / token added, password reset within 24h — account takeover pattern.",
                "description": (
                    "Pivots on AuditLogs `User registered security info` "
                    "followed by `Reset user password` from the same "
                    "actor within a day — classic ATO chain."
                ),
                "mitre_ids": ["T1098.005"],
                "logic_snippet": (
                    "FROM logs-azure.auditlogs-* | WHERE event.action IN "
                    "(\"User registered security info\", \"Reset user password\") "
                    "| STATS chain = COUNT(*) BY user.target.id WITHIN 24h "
                    "| WHERE chain >= 2"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_ato_chain",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1098.005", "url": "https://attack.mitre.org/techniques/T1098/005/"},
                ],
            },
        ],
        "audit_use_cases": [
            {
                "id": "idp_audit_global_admin_assign",
                "title": "Global Admin assignment",
                "kind": "audit",
                "risk": "critical",
                "summary": "User assigned Global Administrator (or Super Admin) role.",
                "description": (
                    "AuditLogs `Add member to role` where role.displayName "
                    "== 'Global Administrator' (Entra) or comparable in "
                    "Okta — there should be at most a small known list of "
                    "such accounts."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-azure.auditlogs-* | WHERE event.action == \"Add member to role\" "
                    "AND azure.auditlogs.properties.target_resources.modified_properties.new_value LIKE "
                    "\"*Global Administrator*\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AC-2(7)", "CIS Microsoft 365 1.1.1"],
                "references": [],
            },
            {
                "id": "idp_audit_sp_secret_create",
                "title": "Service principal secret / cert added",
                "kind": "audit",
                "risk": "high",
                "summary": "New secret or certificate added to an enterprise app.",
                "description": (
                    "Often used post-compromise to create a persistent "
                    "back door under an existing service principal. "
                    "AuditLogs `Add service principal credentials`."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-azure.auditlogs-* | WHERE event.action == \"Add service principal credentials\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST IA-5(2)", "CIS Microsoft 365 1.3"],
                "references": [],
            },
            {
                "id": "idp_audit_ca_policy_change",
                "title": "Conditional Access policy change",
                "kind": "audit",
                "risk": "high",
                "summary": "Modification or disablement of a CA security policy.",
                "description": (
                    "CA policy changes are infrequent and high-impact. "
                    "Alert on `Update conditional access policy` and "
                    "`Disable conditional access policy`."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-azure.auditlogs-* | WHERE event.action IN "
                    "(\"Update conditional access policy\", \"Disable conditional access policy\")"
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AC-2", "CIS Microsoft 365 1.1.4"],
                "references": [],
            },
        ],
        "references": [
            {"title": "Microsoft Entra ID security operations guide", "url": "https://learn.microsoft.com/en-us/entra/architecture/security-operations-introduction"},
            {"title": "CIS Microsoft 365 Foundations Benchmark", "url": "https://www.cisecurity.org/benchmark/microsoft_365"},
            {"title": "Okta Security Best Practices", "url": "https://help.okta.com/en-us/content/topics/security/sec-best-practices.htm"},
        ],
    },
}


VPN_REMOTE: Dict[str, Any] = {
    "id": "vpn_remote",
    "pillar_id": "identity",
    "label": "VPN / Remote access",
    "icon": "key",
    "ecs_anchors": [
        "event.dataset:cisco.asa",
        "event.dataset:paloalto.panos",
        "event.dataset:fortinet.firewall.vpn",
    ],
    "expected_feeds": [],
    "description": (
        "VPN concentrators and remote-access appliances. The first hop "
        "into the network for many staff — credential reuse and phished "
        "logins surface here first."
    ),
    "catalogue": {
        "intake_questions": [
            {
                "key": "sub_id_vpn_mfa",
                "text": "Is MFA required for every VPN authentication?",
                "answer_type": "yesno",
                "feeds": [["cg", 10]],
            },
            {
                "key": "sub_id_vpn_geo_fence",
                "text": "Is geo-fencing applied (block / alert on logins from non-business countries)?",
                "answer_type": "single",
                "options": [
                    {"value": "block", "label": "Block"},
                    {"value": "alert", "label": "Alert only"},
                    {"value": "off", "label": "Off"},
                    {"value": "dont_know", "label": "Don't know"},
                ],
                "feeds": [["cg", 6]],
            },
            {
                "key": "sub_id_vpn_failed_alert",
                "text": "Is a brute-force / spray detection on failed VPN auth in place?",
                "answer_type": "yesno",
                "feeds": [["cg", 7]],
            },
            {
                "key": "sub_id_vpn_cert_rotation",
                "text": "How often are VPN client certificates / device-certs rotated?",
                "answer_type": "single",
                "options": [
                    {"value": "lt_1y", "label": "Annually or more"},
                    {"value": "1_2y", "label": "1–2 years"},
                    {"value": "gt_2y", "label": "Over 2 years"},
                    {"value": "dont_know", "label": "Don't know"},
                ],
                "feeds": [["cg", 4]],
            },
        ],
        "recommended_tasks": [
            "Confirm split-tunnel posture is documented (split vs full); SOC alerting differs.",
            "Cross-reference VPN concentrators against CISA KEV catalog quarterly (Citrix, Pulse Secure, Fortinet have repeat critical CVEs).",
            "Validate failed-auth ingestion (Cisco ASA 113015 / PAN auth-failure category).",
            "Tag VPN sessions with user.id and source.geo.country in the parser; the rest of detection depends on it.",
        ],
        "detection_use_cases": [
            {
                "id": "vpn_brute_force",
                "title": "VPN brute-force / spray",
                "kind": "detection",
                "risk": "high",
                "summary": "Many failed authentications from one source, or one credential against many users.",
                "description": (
                    "Both the classic brute force (one user, many tries) "
                    "and password spray (one password, many users) "
                    "patterns. Threshold > 20 failures from one source.ip "
                    "in 10 minutes."
                ),
                "mitre_ids": ["T1110.003", "T1110.001"],
                "logic_snippet": (
                    "FROM logs-network.vpn-* | WHERE event.outcome == \"failure\" AND event.action == \"vpn-auth\" "
                    "| STATS fails = COUNT(*), uniq_users = COUNT_DISTINCT(user.name) BY source.ip "
                    "| WHERE fails > 20"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_vpn_brute_force",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1110.003", "url": "https://attack.mitre.org/techniques/T1110/003/"},
                ],
            },
            {
                "id": "vpn_geo_anomaly",
                "title": "VPN auth from anomalous geo",
                "kind": "detection",
                "risk": "medium",
                "summary": "Successful VPN auth from a country outside business operations.",
                "description": (
                    "Leverages the parser-enriched source.geo.country_iso_code "
                    "field; alerts on values not in the org's allowed-list."
                ),
                "mitre_ids": ["T1078"],
                "logic_snippet": (
                    "FROM logs-network.vpn-* | WHERE event.outcome == \"success\" "
                    "AND NOT source.geo.country_iso_code IN (\"GB\", \"US\", \"IE\", \"FR\")"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_vpn_geo_anomaly",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1078", "url": "https://attack.mitre.org/techniques/T1078/"},
                ],
            },
            {
                "id": "vpn_post_auth_burst",
                "title": "Post-auth lateral burst",
                "kind": "detection",
                "risk": "high",
                "summary": "VPN session followed by rapid SMB / WinRM / RDP probing.",
                "description": (
                    "Within 5 minutes of a successful VPN auth, the "
                    "assigned client.ip generates ≥10 SMB/445, WinRM/5985, "
                    "or RDP/3389 attempts — internal recon."
                ),
                "mitre_ids": ["T1021"],
                "logic_snippet": (
                    "FROM logs-network.* | WHERE destination.port IN (445, 5985, 3389) "
                    "| STATS attempts = COUNT(*) BY source.ip "
                    "| WHERE attempts > 10"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_lateral_recon",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1021", "url": "https://attack.mitre.org/techniques/T1021/"},
                ],
            },
            {
                "id": "vpn_concurrent_sessions",
                "title": "Concurrent VPN sessions for one user",
                "kind": "detection",
                "risk": "medium",
                "summary": "Same user holding two active VPN tunnels from different IPs.",
                "description": (
                    "Common ATO indicator: legitimate user is online "
                    "while attacker also connects with stolen creds."
                ),
                "mitre_ids": ["T1078"],
                "logic_snippet": (
                    "FROM logs-network.vpn-* | WHERE event.action == \"vpn-session-start\" "
                    "| STATS uniq_ip = COUNT_DISTINCT(source.ip) BY user.name WITHIN 1h "
                    "| WHERE uniq_ip > 1"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_concurrent_sessions",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1078", "url": "https://attack.mitre.org/techniques/T1078/"},
                ],
            },
        ],
        "audit_use_cases": [
            {
                "id": "vpn_audit_policy_change",
                "title": "VPN policy / tunnel change",
                "kind": "audit",
                "risk": "high",
                "summary": "Group-policy or tunnel-group configuration changes on the concentrator.",
                "description": (
                    "Cisco ASA 111008 / 111009 events; PAN config-change "
                    "events. Catches loosened auth profiles."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-network.vpn-* | WHERE event.code IN (\"111008\", \"111009\") "
                    "OR event.action == \"config-change\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AC-17", "CIS 12.7"],
                "references": [],
            },
            {
                "id": "vpn_audit_account_enabled",
                "title": "Account VPN-enabled change",
                "kind": "audit",
                "risk": "medium",
                "summary": "User added to the VPN-enabled group / policy.",
                "description": (
                    "Driven by the upstream IDP — alert when a user is "
                    "added to a VPN-enabling group (e.g., AD `VPN_Users`, "
                    "Okta `VPN Access`)."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-windows.security-* | WHERE event.code == \"4728\" "
                    "AND winlog.event_data.TargetUserName == \"VPN_Users\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AC-2(7)"],
                "references": [],
            },
        ],
        "references": [
            {"title": "NIST SP 800-77 r1 — Guide to IPsec VPNs", "url": "https://csrc.nist.gov/pubs/sp/800/77/r1/final"},
            {"title": "CISA KEV — VPN appliance CVEs", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
        ],
    },
}


# === Endpoint (continued) ==================================================

LINUX_ENDPOINT: Dict[str, Any] = {
    "id": "linux_endpoint",
    "pillar_id": "endpoint",
    "label": "Linux / Unix",
    "icon": "terminal",
    "ecs_anchors": [
        "event.dataset:auditd.log",
        "event.dataset:system.auth",
        "event.dataset:system.syslog",
    ],
    "expected_feeds": ["linux_auditd"],
    "description": (
        "Linux servers and workstations. auditd syscall tracking, sudo "
        "history, SSH telemetry, kernel module loads. Often the most "
        "log-rich target in the estate."
    ),
    "catalogue": {
        "intake_questions": [
            {
                "key": "sub_ep_lin_auditd",
                "text": "Is auditd configured for syscall tracking on every host?",
                "answer_type": "single",
                "options": [
                    {"value": "all", "label": "Yes — full coverage"},
                    {"value": "most", "label": "Mostly (>80%)"},
                    {"value": "some", "label": "Some"},
                    {"value": "no", "label": "No"},
                    {"value": "dont_know", "label": "Don't know"},
                ],
                "feeds": [["cg", 9]],
            },
            {
                "key": "sub_ep_lin_sudo_history",
                "text": "Are sudo command invocations forwarded to the SIEM?",
                "answer_type": "yesno",
                "feeds": [["cg", 7]],
            },
            {
                "key": "sub_ep_lin_mac",
                "text": "Is SELinux or AppArmor in enforcing mode on production hosts?",
                "answer_type": "single",
                "options": [
                    {"value": "enforcing", "label": "Enforcing"},
                    {"value": "permissive", "label": "Permissive / audit-only"},
                    {"value": "disabled", "label": "Disabled"},
                    {"value": "dont_know", "label": "Don't know"},
                ],
                "feeds": [["cg", 6]],
            },
            {
                "key": "sub_ep_lin_ssh_keys",
                "text": "How are SSH authorized_keys files managed?",
                "answer_type": "single",
                "options": [
                    {"value": "config_mgmt", "label": "Config-managed (Ansible / Puppet / Chef)"},
                    {"value": "ca_signed", "label": "SSH CA-signed certs"},
                    {"value": "manual", "label": "Manual edits permitted"},
                    {"value": "dont_know", "label": "Don't know"},
                ],
                "feeds": [["cg", 5]],
            },
            {
                "key": "sub_ep_lin_root_login",
                "text": "Is direct root SSH login disabled (`PermitRootLogin no`)?",
                "answer_type": "yesno",
                "feeds": [["cg", 5]],
            },
        ],
        "recommended_tasks": [
            "Deploy a baseline auditd ruleset (e.g., Florian Roth's audit.rules) plus org-specific tweaks.",
            "Confirm Elastic Agent or auditbeat captures every host (cross-reference inventory).",
            "Validate sudo logs include `command` arg (sudoers entry: `Defaults log_input,log_output`).",
            "Add a daily report on hosts that emitted zero auditd events in 24h — agent dropouts.",
        ],
        "detection_use_cases": [
            {
                "id": "lin_suid_abuse",
                "title": "SUID binary abuse for privilege escalation",
                "kind": "detection",
                "risk": "high",
                "summary": "Non-standard binary with SUID bit set or executed under SUID.",
                "description": (
                    "Sysmon-for-linux Event 1 (process exec) where the "
                    "image is in /tmp / /var/tmp / /dev/shm and uid != "
                    "auid (effective != audit uid), or a chmod u+s to a "
                    "non-root-owned binary."
                ),
                "mitre_ids": ["T1548.001"],
                "logic_snippet": (
                    "FROM logs-linux.* | WHERE event.action == \"executed\" "
                    "AND process.executable LIKE \"/tmp/*\" OR LIKE \"/var/tmp/*\" OR LIKE \"/dev/shm/*\" "
                    "AND user.effective.id != user.audit.id"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_suid_abuse",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1548.001", "url": "https://attack.mitre.org/techniques/T1548/001/"},
                    {"title": "GTFOBins", "url": "https://gtfobins.github.io/"},
                ],
            },
            {
                "id": "lin_kernel_module",
                "title": "Kernel module load (LKM rootkit)",
                "kind": "detection",
                "risk": "critical",
                "summary": "insmod / modprobe of a module not in the trusted set.",
                "description": (
                    "auditd `init_module` / `finit_module` syscall, or "
                    "Sysmon-for-linux Event 1 with image in [insmod, "
                    "modprobe], where module.name not in the org's "
                    "approved kernel-module allowlist."
                ),
                "mitre_ids": ["T1547.006"],
                "logic_snippet": (
                    "FROM logs-linux.auditd-* | WHERE auditd.data.syscall IN (\"init_module\", \"finit_module\") "
                    "AND NOT auditd.data.name IN [allowlist]"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_lkm_load",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1547.006", "url": "https://attack.mitre.org/techniques/T1547/006/"},
                ],
            },
            {
                "id": "lin_reverse_shell",
                "title": "Reverse shell from interactive process",
                "kind": "detection",
                "risk": "high",
                "summary": "Outbound socket initiated from bash / python / perl / nc.",
                "description": (
                    "Sysmon-for-linux Event 3 (network connect) where "
                    "process.name in [bash, sh, python*, perl, ruby, nc, "
                    "ncat] and destination.port in [4444, 1337, 8080, 80, "
                    "443] to non-RFC1918."
                ),
                "mitre_ids": ["T1059.004", "T1071.001"],
                "logic_snippet": (
                    "FROM logs-linux.sysmon-* | WHERE event.code == \"3\" "
                    "AND process.name IN (\"bash\", \"sh\", \"python\", \"python3\", \"perl\", \"ruby\", \"nc\", \"ncat\") "
                    "AND NOT CIDR_MATCH(destination.ip, \"10.0.0.0/8\", \"172.16.0.0/12\", \"192.168.0.0/16\")"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_reverse_shell",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1059.004", "url": "https://attack.mitre.org/techniques/T1059/004/"},
                ],
            },
            {
                "id": "lin_authorized_keys_mod",
                "title": "SSH authorized_keys modified",
                "kind": "detection",
                "risk": "medium",
                "summary": "Edit to ~/.ssh/authorized_keys outside config-management.",
                "description": (
                    "auditd file watch on `~/.ssh/authorized_keys` "
                    "patterns; alert when the editing process isn't a "
                    "config-management agent (puppet, ansible, chef)."
                ),
                "mitre_ids": ["T1098.004"],
                "logic_snippet": (
                    "FROM logs-linux.auditd-* | WHERE auditd.data.name LIKE \"*/.ssh/authorized_keys\" "
                    "AND auditd.data.syscall IN (\"openat\", \"open\", \"creat\") "
                    "AND NOT process.name IN (\"puppet\", \"ansible\", \"chef-client\", \"saltstack\")"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_authorized_keys",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1098.004", "url": "https://attack.mitre.org/techniques/T1098/004/"},
                ],
            },
            {
                "id": "lin_cron_tamper",
                "title": "Cron job tampering",
                "kind": "detection",
                "risk": "medium",
                "summary": "New entries in /etc/crontab, /etc/cron.d/, or /var/spool/cron/.",
                "description": (
                    "Persistence via cron is common. Watch the standard "
                    "crontab paths for write events, then diff."
                ),
                "mitre_ids": ["T1053.003"],
                "logic_snippet": (
                    "FROM logs-linux.auditd-* | WHERE auditd.data.name IN "
                    "(\"/etc/crontab\", \"/etc/cron.d/\", \"/var/spool/cron/\") "
                    "AND auditd.data.syscall IN (\"write\", \"openat\")"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_cron_tamper",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1053.003", "url": "https://attack.mitre.org/techniques/T1053/003/"},
                ],
            },
        ],
        "audit_use_cases": [
            {
                "id": "lin_audit_sudoers_edit",
                "title": "Sudoers file edit",
                "kind": "audit",
                "risk": "high",
                "summary": "Modification to /etc/sudoers or /etc/sudoers.d/*.",
                "description": "auditd file watch on the sudoers paths for any write.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-linux.auditd-* | WHERE auditd.data.name LIKE \"/etc/sudoers*\" "
                    "AND auditd.data.syscall IN (\"openat\", \"write\", \"rename\")"
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AC-3", "CIS Distribution-Independent Linux 5.3.4"],
                "references": [],
            },
            {
                "id": "lin_audit_shadow_read",
                "title": "/etc/shadow read by non-root",
                "kind": "audit",
                "risk": "critical",
                "summary": "Unauthorised access to /etc/shadow.",
                "description": (
                    "auditd file watch flags reads outside expected "
                    "(passwd / sshd / vipw)."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-linux.auditd-* | WHERE auditd.data.name == \"/etc/shadow\" "
                    "AND auditd.data.syscall IN (\"openat\", \"open\", \"read\") "
                    "AND NOT process.name IN (\"passwd\", \"sshd\", \"vipw\", \"login\")"
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AC-3", "CIS DIL 6.1.5"],
                "references": [],
            },
            {
                "id": "lin_audit_root_login",
                "title": "Direct root SSH login",
                "kind": "audit",
                "risk": "medium",
                "summary": "Root logged in directly via SSH.",
                "description": (
                    "Hardened systems disable PermitRootLogin; surface "
                    "any successful root SSH logon."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-linux.system.auth-* | WHERE event.action == \"ssh_login\" "
                    "AND event.outcome == \"success\" AND user.name == \"root\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["CIS DIL 5.2.7"],
                "references": [],
            },
        ],
        "references": [
            {"title": "MITRE ATT&CK Enterprise — Linux matrix", "url": "https://attack.mitre.org/matrices/enterprise/linux/"},
            {"title": "CIS Distribution-Independent Linux Benchmark", "url": "https://www.cisecurity.org/benchmark/distribution_independent_linux"},
            {"title": "auditd best-practice rules — Florian Roth", "url": "https://github.com/Neo23x0/auditd"},
        ],
    },
}


MACOS_ENDPOINT: Dict[str, Any] = {
    "id": "macos_endpoint",
    "pillar_id": "endpoint",
    "label": "macOS endpoint",
    "icon": "monitor",
    "ecs_anchors": [
        "event.dataset:macos.unifiedlogs",
        "event.dataset:endgame.events",
    ],
    "expected_feeds": [],
    "description": (
        "macOS workstations. Endpoint Security Framework (ESF), unified "
        "logs, MDM telemetry. Smaller log volume than Windows but rich "
        "tamper-detection signals."
    ),
    "catalogue": {
        "intake_questions": [
            {
                "key": "sub_ep_mac_esf",
                "text": "Is an Endpoint Security Framework (ESF) agent deployed (Jamf Protect, BlockBlock, Crowdstrike, etc.)?",
                "answer_type": "yesno",
                "feeds": [["cg", 8]],
            },
            {
                "key": "sub_ep_mac_sip",
                "text": "Is System Integrity Protection (SIP) enabled on all devices?",
                "answer_type": "yesno",
                "feeds": [["cg", 7]],
            },
            {
                "key": "sub_ep_mac_gatekeeper",
                "text": "Is Gatekeeper set to 'App Store and identified developers' or stricter?",
                "answer_type": "yesno",
                "feeds": [["cg", 5]],
            },
            {
                "key": "sub_ep_mac_unified_logs",
                "text": "Are unified logs forwarded to the SIEM?",
                "answer_type": "single",
                "options": [
                    {"value": "all", "label": "Full forwarding"},
                    {"value": "filtered", "label": "Selected predicates only"},
                    {"value": "none", "label": "Local only"},
                    {"value": "dont_know", "label": "Don't know"},
                ],
                "feeds": [["cg", 6]],
            },
        ],
        "recommended_tasks": [
            "Deploy an ESF agent across the fleet; verify in MDM inventory.",
            "Confirm `csrutil status` reports enabled; alert on disabled.",
            "Forward log show predicates for processes / TCC / endpoint security.",
            "Subscribe to Apple's Rapid Security Response feed.",
        ],
        "detection_use_cases": [
            {
                "id": "mac_kext_load",
                "title": "Kernel extension (kext) load",
                "kind": "detection",
                "risk": "critical",
                "summary": "Unsigned or unexpected kext loaded into the kernel.",
                "description": (
                    "ES_EVENT_TYPE_NOTIFY_KEXTLOAD; alert on bundle "
                    "identifiers outside the small approved list. Apple "
                    "Silicon hosts should reject all kext loads."
                ),
                "mitre_ids": ["T1547.006"],
                "logic_snippet": (
                    "FROM logs-macos.endpointsecurity-* | WHERE event.action == \"kext-load\" "
                    "AND NOT process.code_signature.subject_name LIKE \"*Apple*\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_macos_kext",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1547.006", "url": "https://attack.mitre.org/techniques/T1547/006/"},
                ],
            },
            {
                "id": "mac_tcc_tamper",
                "title": "TCC database tampering",
                "kind": "detection",
                "risk": "high",
                "summary": "Direct write to the user TCC.db file (privacy DB).",
                "description": (
                    "Bypasses Privacy & Security prompts. Detect file "
                    "writes to ~/Library/Application Support/com.apple.TCC/TCC.db "
                    "from any process other than tccd."
                ),
                "mitre_ids": ["T1562.001"],
                "logic_snippet": (
                    "FROM logs-macos.endpointsecurity-* | WHERE event.action == \"file-write\" "
                    "AND file.path LIKE \"*Library/Application Support/com.apple.TCC/TCC.db\" "
                    "AND NOT process.name == \"tccd\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_tcc_tamper",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1562.001", "url": "https://attack.mitre.org/techniques/T1562/001/"},
                ],
            },
            {
                "id": "mac_persistence_launchagents",
                "title": "Persistence via LaunchAgents / LaunchDaemons",
                "kind": "detection",
                "risk": "high",
                "summary": "Plist write to ~/Library/LaunchAgents or /Library/LaunchDaemons.",
                "description": (
                    "Detect file-write events to plist files in the "
                    "launch agent paths from non-installer processes."
                ),
                "mitre_ids": ["T1543.001", "T1543.004"],
                "logic_snippet": (
                    "FROM logs-macos.endpointsecurity-* | WHERE event.action == \"file-write\" "
                    "AND (file.path LIKE \"*Library/LaunchAgents/*\" OR file.path LIKE \"*Library/LaunchDaemons/*\") "
                    "AND NOT process.name IN (\"installer\", \"system_installd\")"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_macos_persistence",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1543.001", "url": "https://attack.mitre.org/techniques/T1543/001/"},
                ],
            },
            {
                "id": "mac_profile_install",
                "title": "Configuration profile installed manually",
                "kind": "detection",
                "risk": "medium",
                "summary": "Profile installed via `profiles install` outside MDM.",
                "description": (
                    "Profiles installed by hand bypass the MDM control "
                    "plane and can apply DNS / proxy / cert changes."
                ),
                "mitre_ids": ["T1556"],
                "logic_snippet": (
                    "FROM logs-macos.unifiedlogs-* | WHERE process.name == \"profiles\" "
                    "AND process.args LIKE \"*install*\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_macos_profile",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1556", "url": "https://attack.mitre.org/techniques/T1556/"},
                ],
            },
        ],
        "audit_use_cases": [
            {
                "id": "mac_audit_sip_disabled",
                "title": "SIP disabled",
                "kind": "audit",
                "risk": "critical",
                "summary": "csrutil disable executed (requires Recovery Mode).",
                "description": "Should never happen in production. Investigate any host reporting SIP disabled.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-macos.unifiedlogs-* | WHERE message LIKE \"*csr-active-config*\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["CIS Apple macOS 2.5"],
                "references": [],
            },
            {
                "id": "mac_audit_mdm_profile_change",
                "title": "MDM enrolment / profile change",
                "kind": "audit",
                "risk": "medium",
                "summary": "MDM unenrolment or profile removal.",
                "description": "Devices unenrolling from MDM lose central security policy.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-macos.unifiedlogs-* | WHERE process.name == \"mdmclient\" "
                    "AND message LIKE \"*Removing*\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["CIS Apple macOS 2.6"],
                "references": [],
            },
        ],
        "references": [
            {"title": "CIS Apple macOS Benchmark", "url": "https://www.cisecurity.org/benchmark/apple_os"},
            {"title": "Apple Endpoint Security Framework", "url": "https://developer.apple.com/documentation/endpointsecurity"},
        ],
    },
}


# === Network (continued) ===================================================

DNS_PROFILE: Dict[str, Any] = {
    "id": "dns",
    "pillar_id": "network",
    "label": "DNS",
    "icon": "search",
    "ecs_anchors": [
        "event.dataset:zeek.dns",
        "event.dataset:bind.log",
    ],
    "expected_feeds": ["dns"],
    "description": (
        "Recursive resolvers and authoritative servers. Tunnelling, "
        "DGA, and rare-domain detection. The 'cheapest' early signal "
        "for many attack chains."
    ),
    "catalogue": {
        "intake_questions": [
            {
                "key": "sub_net_dns_full_logging",
                "text": "Are full DNS query/response logs (not just denied) forwarded to the SIEM?",
                "answer_type": "yesno",
                "feeds": [["cg", 8]],
            },
            {
                "key": "sub_net_dns_dga_detection",
                "text": "Is DGA / NXDOMAIN-spike detection deployed?",
                "answer_type": "yesno",
                "feeds": [["cg", 6]],
            },
            {
                "key": "sub_net_dns_sinkhole",
                "text": "Is a maintained sinkhole / blocklist applied at recursive resolver level?",
                "answer_type": "yesno",
                "feeds": [["cg", 6]],
            },
        ],
        "recommended_tasks": [
            "Sample DNS traffic to verify response codes and query types are populated (TXT / NULL specifically).",
            "Cross-check ECS field mapping: dns.question.name, dns.question.type, dns.answers.data.",
            "Subscribe to a threat-intel domain feed and operationalise blocklist updates.",
        ],
        "detection_use_cases": [
            {
                "id": "dns_dga",
                "title": "DGA-pattern domain queries",
                "kind": "detection",
                "risk": "high",
                "summary": "Random-looking second-level labels under unusual TLDs.",
                "description": (
                    "Use shannon entropy or trained classifier on the "
                    "label; threshold > 4.0 entropy and > 8 chars long. "
                    "Group by source.ip — single host hitting many "
                    "DGA-style names is the strong signal."
                ),
                "mitre_ids": ["T1568.002"],
                "logic_snippet": (
                    "FROM logs-network.dns-* | WHERE LENGTH(dns.question.name) > 12 "
                    "AND ENTROPY(dns.question.registered_domain) > 4.0 "
                    "| STATS uniq = COUNT_DISTINCT(dns.question.name) BY source.ip "
                    "| WHERE uniq > 20"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_dga",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1568.002", "url": "https://attack.mitre.org/techniques/T1568/002/"},
                ],
            },
            {
                "id": "dns_fast_flux",
                "title": "Fast-flux domain",
                "kind": "detection",
                "risk": "medium",
                "summary": "Single domain resolving to many distinct IPs in a short window.",
                "description": (
                    "Group by dns.question.name; alert when "
                    "COUNT_DISTINCT(dns.answers.data) > 10 within an hour."
                ),
                "mitre_ids": ["T1568.001"],
                "logic_snippet": (
                    "FROM logs-network.dns-* | WHERE dns.response_code == \"NOERROR\" "
                    "| STATS uniq_ips = COUNT_DISTINCT(dns.answers.data) BY dns.question.registered_domain WITHIN 1h "
                    "| WHERE uniq_ips > 10"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_fast_flux",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1568.001", "url": "https://attack.mitre.org/techniques/T1568/001/"},
                ],
            },
            {
                "id": "dns_txt_tunnelling",
                "title": "TXT-record tunnelling",
                "kind": "detection",
                "risk": "high",
                "summary": "High-volume TXT queries from a single source.",
                "description": (
                    "Already mirrored at the firewall layer; DNS-server "
                    "view is the authoritative one. Threshold > 50 unique "
                    "TXT names per source.ip in 5 minutes."
                ),
                "mitre_ids": ["T1071.004"],
                "logic_snippet": (
                    "FROM logs-network.dns-* | WHERE dns.question.type == \"TXT\" "
                    "| STATS uniq = COUNT_DISTINCT(dns.question.name) BY source.ip "
                    "| WHERE uniq > 50"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_dns_tunnel",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1071.004", "url": "https://attack.mitre.org/techniques/T1071/004/"},
                ],
            },
            {
                "id": "dns_nxdomain_recon",
                "title": "NXDOMAIN spike (recon)",
                "kind": "detection",
                "risk": "medium",
                "summary": "Single source generating many NXDOMAIN responses.",
                "description": (
                    "Either DGA C2 falling back to NX, or subdomain "
                    "enumeration recon. Threshold > 100 NX in 5 minutes "
                    "per source.ip."
                ),
                "mitre_ids": ["T1583.001"],
                "logic_snippet": (
                    "FROM logs-network.dns-* | WHERE dns.response_code == \"NXDOMAIN\" "
                    "| STATS nx = COUNT(*) BY source.ip "
                    "| WHERE nx > 100"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_nxdomain_recon",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1583.001", "url": "https://attack.mitre.org/techniques/T1583/001/"},
                ],
            },
        ],
        "audit_use_cases": [
            {
                "id": "dns_audit_external_resolver",
                "title": "External DNS resolver use",
                "kind": "audit",
                "risk": "medium",
                "summary": "Internal client querying a non-corporate resolver (8.8.8.8, 1.1.1.1, etc.).",
                "description": (
                    "Bypasses corporate filtering and observability; "
                    "should be blocked at the egress firewall."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-network.* | WHERE destination.port == 53 "
                    "AND NOT destination.ip IN [corp_resolvers]"
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST SC-7"],
                "references": [],
            },
            {
                "id": "dns_audit_zone_change",
                "title": "Authoritative zone modification",
                "kind": "audit",
                "risk": "high",
                "summary": "Records added / removed from internal authoritative zone.",
                "description": (
                    "Catches subdomain takeover preparation and "
                    "unauthorised CNAME redirections."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-network.dns.named-* | WHERE message LIKE \"*zone*update*\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST CM-3"],
                "references": [],
            },
        ],
        "references": [
            {"title": "NIST SP 800-81 r2 — Secure DNS Deployment", "url": "https://csrc.nist.gov/pubs/sp/800/81/r2/final"},
            {"title": "DGA detection — DomainTools whitepaper", "url": "https://www.domaintools.com/resources/"},
        ],
    },
}


WEB_PROXY: Dict[str, Any] = {
    "id": "web_proxy",
    "pillar_id": "network",
    "label": "Web proxy",
    "icon": "globe",
    "ecs_anchors": [
        "event.dataset:zscaler.zia",
        "event.dataset:bluecoat.proxy",
        "event.dataset:netskope.web",
    ],
    "expected_feeds": ["web_proxy"],
    "description": (
        "Outbound web proxy / SWG. Category-based blocking and full URL "
        "logging — best signal for malware staging and exfiltration "
        "to web destinations."
    ),
    "catalogue": {
        "intake_questions": [
            {
                "key": "sub_net_proxy_ssl_decrypt",
                "text": "Is SSL/TLS decryption enabled at the proxy?",
                "answer_type": "yesno",
                "feeds": [["cg", 8]],
            },
            {
                "key": "sub_net_proxy_user_attribution",
                "text": "Is user attribution captured (sso identity in logs)?",
                "answer_type": "yesno",
                "feeds": [["cg", 7]],
            },
            {
                "key": "sub_net_proxy_url_reputation",
                "text": "Is a URL reputation feed integrated for blocking decisions?",
                "answer_type": "yesno",
                "feeds": [["cg", 5]],
            },
            {
                "key": "sub_net_proxy_bandwidth_thresh",
                "text": "Are per-user bandwidth thresholds alerted on?",
                "answer_type": "yesno",
                "feeds": [["cg", 4]],
            },
        ],
        "recommended_tasks": [
            "Confirm decryption excludes only the categories required for compliance (banking, health).",
            "Cross-check a sample of high-bandwidth users — quick sanity check on attribution.",
            "Subscribe to newly-registered-domains feed; block or alert on first-seen <30d.",
        ],
        "detection_use_cases": [
            {
                "id": "proxy_large_dl_uncategorised",
                "title": "Large download from uncategorised domain",
                "kind": "detection",
                "risk": "high",
                "summary": "Multi-MB GET to a domain with no reputation / brand.",
                "description": (
                    "Threshold http.response.body.bytes > 50MB to "
                    "url.domain in url.category == 'uncategorised' / "
                    "'newly-registered'."
                ),
                "mitre_ids": ["T1105"],
                "logic_snippet": (
                    "FROM logs-network.proxy-* | WHERE http.request.method == \"GET\" "
                    "AND http.response.body.bytes > 52428800 "
                    "AND url.category IN (\"uncategorized\", \"newly-registered\")"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_uncategorised_dl",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1105", "url": "https://attack.mitre.org/techniques/T1105/"},
                ],
            },
            {
                "id": "proxy_403_to_malicious_cat",
                "title": "Repeated blocked traffic to malicious category",
                "kind": "detection",
                "risk": "medium",
                "summary": "≥10 blocked requests from one user to malware / phishing categories.",
                "description": (
                    "Block-and-move-on misses the host that's "
                    "infected — count blocked events per source.user.name."
                ),
                "mitre_ids": ["T1071.001"],
                "logic_snippet": (
                    "FROM logs-network.proxy-* | WHERE http.response.status_code == 403 "
                    "AND url.category IN (\"malware\", \"phishing\", \"command-control\") "
                    "| STATS blocks = COUNT(*) BY user.name "
                    "| WHERE blocks > 10"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_proxy_block_storm",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1071.001", "url": "https://attack.mitre.org/techniques/T1071/001/"},
                ],
            },
            {
                "id": "proxy_newly_registered",
                "title": "Outbound to newly-registered domain",
                "kind": "detection",
                "risk": "medium",
                "summary": "Connection to a domain registered within 7 days.",
                "description": (
                    "Newly-registered domains are heavily over-represented "
                    "in phishing / malware infrastructure."
                ),
                "mitre_ids": ["T1583.001"],
                "logic_snippet": (
                    "FROM logs-network.proxy-* | WHERE url.registered_domain.age_days < 7"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_newly_registered",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1583.001", "url": "https://attack.mitre.org/techniques/T1583/001/"},
                ],
            },
        ],
        "audit_use_cases": [
            {
                "id": "proxy_audit_bypass_rule",
                "title": "Decryption / category bypass rule added",
                "kind": "audit",
                "risk": "high",
                "summary": "New rule that exempts a destination from decryption or categorisation.",
                "description": (
                    "Catches the 'temporary' bypass that becomes permanent."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-network.proxy-config-* | WHERE event.action == \"rule-add\" "
                    "AND rule.action IN (\"bypass-decryption\", \"category-exception\")"
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST CM-3"],
                "references": [],
            },
            {
                "id": "proxy_audit_exclusion_list",
                "title": "Exclusion list entry added",
                "kind": "audit",
                "risk": "medium",
                "summary": "New entry in the URL / domain exclusion list.",
                "description": "Track diff vs. last week and require change-ticket reference.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-network.proxy-config-* | WHERE event.action == \"exclusion-add\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST CM-3", "CIS 12.4"],
                "references": [],
            },
        ],
        "references": [
            {"title": "NIST SC-7 — Boundary Protection", "url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home"},
        ],
    },
}


# === Cloud =================================================================

CLOUD_AUDIT: Dict[str, Any] = {
    "id": "cloud_audit",
    "pillar_id": "cloud",
    "label": "Cloud audit (AWS / Azure / GCP)",
    "icon": "cloud",
    "ecs_anchors": [
        "event.dataset:aws.cloudtrail",
        "event.dataset:azure.activitylogs",
        "event.dataset:gcp.audit",
    ],
    "expected_feeds": ["cloud_audit"],
    "description": (
        "Cloud control-plane audit — IAM policy changes, resource "
        "creation, key rotation, access-from-new-region. The cloud "
        "estate's equivalent of the AD security log."
    ),
    "catalogue": {
        "intake_questions": [
            {
                "key": "sub_cl_audit_all_regions",
                "text": "Is CloudTrail / Activity Logs / Audit Logs enabled in every region or subscription?",
                "answer_type": "yesno",
                "feeds": [["cg", 9]],
            },
            {
                "key": "sub_cl_audit_root_alert",
                "text": "Is root account / Global Admin login alerted on?",
                "answer_type": "yesno",
                "feeds": [["cg", 9]],
            },
            {
                "key": "sub_cl_audit_imdsv2",
                "text": "Are workloads pinned to IMDSv2 / Managed Identities (no static keys)?",
                "answer_type": "yesno",
                "feeds": [["cg", 7]],
            },
            {
                "key": "sub_cl_audit_kms_audit",
                "text": "Are KMS / Key Vault key access events captured?",
                "answer_type": "yesno",
                "feeds": [["cg", 6]],
            },
            {
                "key": "sub_cl_audit_cloudtrail_tamper",
                "text": "Is CloudTrail / Activity Logs tamper detection in place (StopLogging alarms)?",
                "answer_type": "yesno",
                "feeds": [["cg", 8]],
            },
        ],
        "recommended_tasks": [
            "Verify multi-region trail with log file validation enabled (AWS CloudTrail).",
            "Enable AWS Security Hub / Microsoft Defender for Cloud / GCP Security Command Center; tune away the noise weekly.",
            "Cross-reference IAM users with no MFA against the org joiner-mover-leaver list.",
            "Document the bastion / JIT mechanism for every cloud account; alert when bypassed.",
        ],
        "detection_use_cases": [
            {
                "id": "cl_root_use",
                "title": "Root account use",
                "kind": "detection",
                "risk": "critical",
                "summary": "Any API call by the cloud root identity.",
                "description": (
                    "AWS userIdentity.type == 'Root' or "
                    "azure.activitylogs.identity.tenant_admin == true. "
                    "Should never happen post-bootstrap."
                ),
                "mitre_ids": ["T1078.004"],
                "logic_snippet": (
                    "FROM logs-aws.cloudtrail-* | WHERE aws.cloudtrail.user_identity.type == \"Root\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_cloud_root",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1078.004", "url": "https://attack.mitre.org/techniques/T1078/004/"},
                ],
            },
            {
                "id": "cl_iam_priv_esc",
                "title": "IAM privilege escalation",
                "kind": "detection",
                "risk": "critical",
                "summary": "AttachUserPolicy / AddUserToGroup / CreatePolicyVersion patterns.",
                "description": (
                    "Detect known privilege-escalation API calls. Match "
                    "the source actor against an admin allowlist; alert "
                    "when the actor is non-admin."
                ),
                "mitre_ids": ["T1098.003"],
                "logic_snippet": (
                    "FROM logs-aws.cloudtrail-* | WHERE event.action IN "
                    "(\"AttachUserPolicy\", \"PutUserPolicy\", \"AddUserToGroup\", \"CreatePolicyVersion\") "
                    "AND NOT user.id IN [admin_allowlist]"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_iam_esc",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1098.003", "url": "https://attack.mitre.org/techniques/T1098/003/"},
                    {"title": "Rhino Security AWS escalation paths", "url": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"},
                ],
            },
            {
                "id": "cl_console_new_region",
                "title": "Console login from new region",
                "kind": "detection",
                "risk": "medium",
                "summary": "Successful console login from a region the user has never used.",
                "description": "Track per-user historical regions; alert on first-seen.",
                "mitre_ids": ["T1078.004"],
                "logic_snippet": (
                    "FROM logs-aws.cloudtrail-* | WHERE event.action == \"ConsoleLogin\" "
                    "AND event.outcome == \"success\" "
                    "AND NOT source.geo.region_iso_code IN [user_historical_regions]"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_console_geo",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1078.004", "url": "https://attack.mitre.org/techniques/T1078/004/"},
                ],
            },
            {
                "id": "cl_cloudtrail_stopped",
                "title": "CloudTrail stopped or deleted",
                "kind": "detection",
                "risk": "critical",
                "summary": "StopLogging or DeleteTrail API calls.",
                "description": (
                    "Universal precursor to cloud post-exploit. Should "
                    "alert on every occurrence — there is no benign "
                    "production reason."
                ),
                "mitre_ids": ["T1562.008"],
                "logic_snippet": (
                    "FROM logs-aws.cloudtrail-* | WHERE event.action IN (\"StopLogging\", \"DeleteTrail\")"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_cloudtrail_stopped",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1562.008", "url": "https://attack.mitre.org/techniques/T1562/008/"},
                ],
            },
            {
                "id": "cl_s3_public",
                "title": "S3 bucket made public",
                "kind": "detection",
                "risk": "high",
                "summary": "PutBucketAcl / PutBucketPolicy granting public access.",
                "description": (
                    "Flag any policy change that introduces a Principal "
                    "of '*' or AllUsers / AuthenticatedUsers grants."
                ),
                "mitre_ids": ["T1530"],
                "logic_snippet": (
                    "FROM logs-aws.cloudtrail-* | WHERE event.action IN (\"PutBucketAcl\", \"PutBucketPolicy\") "
                    "AND aws.cloudtrail.request_parameters LIKE \"*AllUsers*\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_s3_public",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1530", "url": "https://attack.mitre.org/techniques/T1530/"},
                ],
            },
        ],
        "audit_use_cases": [
            {
                "id": "cl_audit_new_admin_role",
                "title": "New admin role / group membership",
                "kind": "audit",
                "risk": "critical",
                "summary": "User added to an admin role / Privileged Identity Management.",
                "description": "Mirror of the on-prem 'sensitive group drift' control.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-azure.auditlogs-* | WHERE event.action == \"Add member to role\" "
                    "AND azure.auditlogs.properties.target_resources.modified_properties.new_value LIKE "
                    "\"*Administrator*\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AC-2(7)", "CIS AWS 1.16", "CIS Azure 1.5"],
                "references": [],
            },
            {
                "id": "cl_audit_root_mfa_disabled",
                "title": "Root MFA disabled",
                "kind": "audit",
                "risk": "critical",
                "summary": "Root or global-admin MFA was deactivated.",
                "description": "Almost always malicious; root MFA is a baseline expectation.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-aws.cloudtrail-* | WHERE event.action == \"DeactivateMFADevice\" "
                    "AND aws.cloudtrail.user_identity.type == \"Root\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["CIS AWS 1.5", "PCI DSS 8.3"],
                "references": [],
            },
            {
                "id": "cl_audit_kms_disable",
                "title": "KMS / Key Vault key disabled",
                "kind": "audit",
                "risk": "high",
                "summary": "DisableKey / ScheduleKeyDeletion call.",
                "description": "Can be precursor to a destructive attack.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-aws.cloudtrail-* | WHERE event.action IN "
                    "(\"DisableKey\", \"ScheduleKeyDeletion\")"
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST SC-12", "CIS AWS 3.7"],
                "references": [],
            },
            {
                "id": "cl_audit_open_security_group",
                "title": "Security group with 0.0.0.0/0 added",
                "kind": "audit",
                "risk": "high",
                "summary": "AuthorizeSecurityGroupIngress with public CIDR.",
                "description": "Especially risky on ports 22 / 3389 / 1433 / 3306.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-aws.cloudtrail-* | WHERE event.action == \"AuthorizeSecurityGroupIngress\" "
                    "AND aws.cloudtrail.request_parameters LIKE \"*0.0.0.0/0*\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST SC-7", "CIS AWS 5.2"],
                "references": [],
            },
        ],
        "references": [
            {"title": "CIS AWS Foundations Benchmark", "url": "https://www.cisecurity.org/benchmark/amazon_web_services"},
            {"title": "CIS Microsoft Azure Foundations Benchmark", "url": "https://www.cisecurity.org/benchmark/azure"},
            {"title": "CIS GCP Foundations Benchmark", "url": "https://www.cisecurity.org/benchmark/google_cloud_computing_platform"},
        ],
    },
}


EMAIL_PLATFORM: Dict[str, Any] = {
    "id": "email_platform",
    "pillar_id": "cloud",
    "label": "Email platform (M365 / Workspace)",
    "icon": "mail",
    "ecs_anchors": [
        "event.dataset:o365.audit.exchange",
        "event.dataset:gsuite.gmail",
    ],
    "expected_feeds": ["email_gateway"],
    "description": (
        "Cloud email platforms — mailbox auditing, phishing telemetry, "
        "OAuth grants. Email is still the #1 initial-access vector."
    ),
    "catalogue": {
        "intake_questions": [
            {
                "key": "sub_cl_email_audit",
                "text": "Is unified mailbox auditing enabled tenant-wide?",
                "answer_type": "yesno",
                "feeds": [["cg", 8]],
            },
            {
                "key": "sub_cl_email_oauth_vetting",
                "text": "Are OAuth apps with mailbox access subject to admin review?",
                "answer_type": "yesno",
                "feeds": [["cg", 7]],
            },
            {
                "key": "sub_cl_email_phish_button",
                "text": "Do staff have a one-click phishing-report button?",
                "answer_type": "yesno",
                "feeds": [["cg", 5]],
            },
            {
                "key": "sub_cl_email_safe_links",
                "text": "Is Safe Links / Workspace URL rewriting enabled?",
                "answer_type": "yesno",
                "feeds": [["cg", 6]],
            },
            {
                "key": "sub_cl_email_dmarc",
                "text": "Is DMARC enforced (p=reject) on outbound domains?",
                "answer_type": "single",
                "options": [
                    {"value": "reject", "label": "Yes — p=reject"},
                    {"value": "quarantine", "label": "p=quarantine"},
                    {"value": "none", "label": "p=none / monitor only"},
                    {"value": "absent", "label": "No DMARC record"},
                    {"value": "dont_know", "label": "Don't know"},
                ],
                "feeds": [["cg", 6]],
            },
        ],
        "recommended_tasks": [
            "Verify `Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true` for M365 tenants.",
            "Cross-check Safe Attachments / Workspace attachment scanning is configured for all domains.",
            "Operationalise the user-reported phishing inbox; SLA on triage.",
            "Run a mailbox forwarding rule audit monthly — concentrated risk.",
        ],
        "detection_use_cases": [
            {
                "id": "em_forward_rule",
                "title": "Mailbox forwarding rule created",
                "kind": "detection",
                "risk": "high",
                "summary": "New inbox rule forwarding mail externally.",
                "description": (
                    "M365 audit `New-InboxRule` / `Set-InboxRule` where "
                    "ForwardTo / RedirectTo points to an external domain. "
                    "Top BEC indicator."
                ),
                "mitre_ids": ["T1114.003"],
                "logic_snippet": (
                    "FROM logs-o365.audit.exchange-* | WHERE event.action IN (\"New-InboxRule\", \"Set-InboxRule\") "
                    "AND o365.audit.parameters LIKE \"*ForwardTo*\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_forward_rule",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1114.003", "url": "https://attack.mitre.org/techniques/T1114/003/"},
                ],
            },
            {
                "id": "em_oauth_mailbox_grant",
                "title": "OAuth grant on mailbox to suspicious app",
                "kind": "detection",
                "risk": "critical",
                "summary": "User grants Mail.ReadWrite to a recently-registered app.",
                "description": (
                    "AzureAD audit + Exchange grant; cross-check "
                    "publisher verification flag and grant-frequency."
                ),
                "mitre_ids": ["T1528"],
                "logic_snippet": (
                    "FROM logs-o365.audit-* | WHERE event.action == \"Consent to application\" "
                    "AND o365.audit.parameters LIKE \"*Mail.ReadWrite*\" "
                    "AND NOT o365.audit.publisher_verified == true"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_oauth_mailbox",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1528", "url": "https://attack.mitre.org/techniques/T1528/"},
                ],
            },
            {
                "id": "em_bec_pattern",
                "title": "BEC pattern (auto-forwarder + display-name change)",
                "kind": "detection",
                "risk": "critical",
                "summary": "Forward rule + display-name impersonation chain.",
                "description": (
                    "Within 48h: a new inbox rule + a UpdateUser event "
                    "changing displayName towards a finance / exec name. "
                    "High-fidelity BEC chain."
                ),
                "mitre_ids": ["T1534"],
                "logic_snippet": (
                    "FROM logs-o365.audit-* | WHERE event.action IN (\"New-InboxRule\", \"UpdateUser\") "
                    "| STATS chain = COUNT(*) BY user.target.id WITHIN 48h "
                    "| WHERE chain >= 2"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_bec",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1534", "url": "https://attack.mitre.org/techniques/T1534/"},
                ],
            },
            {
                "id": "em_owa_bulk_dl",
                "title": "Bulk download via OWA / web client",
                "kind": "detection",
                "risk": "high",
                "summary": "Many MailItemsAccessed events from one session.",
                "description": (
                    "Indicates programmatic mailbox extraction. "
                    "Threshold > 200 items in 1 hour from one ClientIP."
                ),
                "mitre_ids": ["T1114.002"],
                "logic_snippet": (
                    "FROM logs-o365.audit.exchange-* | WHERE event.action == \"MailItemsAccessed\" "
                    "| STATS items = COUNT(*) BY source.ip "
                    "| WHERE items > 200"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_mail_bulk_dl",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1114.002", "url": "https://attack.mitre.org/techniques/T1114/002/"},
                ],
            },
        ],
        "audit_use_cases": [
            {
                "id": "em_audit_external_delegation",
                "title": "External delegation grant",
                "kind": "audit",
                "risk": "high",
                "summary": "Mailbox delegated to an account in a different tenant.",
                "description": "Permits a third party to read the user's mail; rarely legitimate.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-o365.audit.exchange-* | WHERE event.action == \"Add-MailboxPermission\" "
                    "AND o365.audit.parameters LIKE \"*@*\" "
                    "AND NOT o365.audit.parameters LIKE \"*@corp.local*\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AC-3"],
                "references": [],
            },
            {
                "id": "em_audit_audit_disabled",
                "title": "Mailbox auditing disabled",
                "kind": "audit",
                "risk": "critical",
                "summary": "Set-MailboxAuditBypassAssociation or Set-Mailbox -AuditEnabled $false.",
                "description": "Direct precursor to undetectable mailbox tampering.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-o365.audit.exchange-* | WHERE event.action IN "
                    "(\"Set-MailboxAuditBypassAssociation\", \"Set-Mailbox\") "
                    "AND o365.audit.parameters LIKE \"*AuditEnabled*False*\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AU-9", "CIS Microsoft 365 6.1.1"],
                "references": [],
            },
            {
                "id": "em_audit_transport_rule",
                "title": "Transport rule modification",
                "kind": "audit",
                "risk": "medium",
                "summary": "New / changed mail-flow rule.",
                "description": "Transport rules can disable scanning, redirect mail, etc.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-o365.audit.exchange-* | WHERE event.action IN "
                    "(\"New-TransportRule\", \"Set-TransportRule\")"
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST CM-3"],
                "references": [],
            },
        ],
        "references": [
            {"title": "Microsoft Defender for Office 365 hunting docs", "url": "https://learn.microsoft.com/en-us/defender-office-365/"},
            {"title": "CIS Microsoft 365 Foundations Benchmark", "url": "https://www.cisecurity.org/benchmark/microsoft_365"},
        ],
    },
}


SAAS_GENERIC: Dict[str, Any] = {
    "id": "saas_generic",
    "pillar_id": "cloud",
    "label": "SaaS app (generic)",
    "icon": "box",
    "ecs_anchors": [],
    "expected_feeds": [],
    "description": (
        "Generic SaaS app — Salesforce, GitHub, Workday, ServiceNow, "
        "etc. Auth + admin + data-export controls; the long tail of the "
        "estate."
    ),
    "catalogue": {
        "intake_questions": [
            {
                "key": "sub_cl_saas_sso",
                "text": "Does the app enforce SAML SSO with no local-account fallback?",
                "answer_type": "yesno",
                "feeds": [["cg", 8]],
            },
            {
                "key": "sub_cl_saas_scim",
                "text": "Is SCIM provisioning configured (so leaver-deprovisioning is automatic)?",
                "answer_type": "yesno",
                "feeds": [["cg", 6]],
            },
            {
                "key": "sub_cl_saas_audit_export",
                "text": "Are activity / audit logs being exported to the SIEM?",
                "answer_type": "yesno",
                "feeds": [["cg", 7]],
            },
            {
                "key": "sub_cl_saas_export_controls",
                "text": "Are bulk-data export controls in place (DLP / rate limit / approval)?",
                "answer_type": "yesno",
                "feeds": [["cg", 5]],
            },
        ],
        "recommended_tasks": [
            "Inventory the SaaS app on the org's tier-list (T1 / T2 / T3) — drives detection coverage.",
            "Confirm IdP-side enforcement (Okta / Entra) requires MFA + device posture for this app.",
            "Document leaver-deprovisioning RTO; if SCIM unavailable, scripted offboarding.",
        ],
        "detection_use_cases": [
            {
                "id": "saas_bulk_export",
                "title": "Bulk data export",
                "kind": "detection",
                "risk": "high",
                "summary": "Single-user export volume above the historical baseline.",
                "description": (
                    "Per-user rolling baseline of records exported / "
                    "downloaded; alert when current exceeds 5×."
                ),
                "mitre_ids": ["T1567"],
                "logic_snippet": (
                    "FROM logs-saas.* | WHERE event.action LIKE \"*export*\" OR LIKE \"*download*\" "
                    "| STATS exports = SUM(saas.record_count) BY user.name "
                    "| WHERE exports > 5 * baseline_user(user.name)"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_saas_bulk_export",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1567", "url": "https://attack.mitre.org/techniques/T1567/"},
                ],
            },
            {
                "id": "saas_admin_grant",
                "title": "Admin role granted",
                "kind": "detection",
                "risk": "high",
                "summary": "User assigned an app-level admin role.",
                "description": "Map app-specific role names to the org's privileged-role taxonomy.",
                "mitre_ids": ["T1098"],
                "logic_snippet": (
                    "FROM logs-saas.* | WHERE event.action == \"role-grant\" "
                    "AND saas.role IN (\"admin\", \"owner\", \"super-admin\")"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_saas_admin_grant",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1098", "url": "https://attack.mitre.org/techniques/T1098/"},
                ],
            },
            {
                "id": "saas_local_login",
                "title": "Local account / SSO bypass login",
                "kind": "detection",
                "risk": "medium",
                "summary": "Login to a SaaS app via local credentials when SSO is required.",
                "description": "Some SaaS apps allow break-glass local accounts; alert on use.",
                "mitre_ids": ["T1078.003"],
                "logic_snippet": (
                    "FROM logs-saas.* | WHERE event.action == \"login\" "
                    "AND saas.auth_method != \"sso\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_saas_local_login",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1078.003", "url": "https://attack.mitre.org/techniques/T1078/003/"},
                ],
            },
        ],
        "audit_use_cases": [
            {
                "id": "saas_audit_api_token_create",
                "title": "API token created",
                "kind": "audit",
                "risk": "high",
                "summary": "New personal-access-token / OAuth-app token issued.",
                "description": (
                    "PATs can outlive the user's MFA — track creation "
                    "and tie back to the issuer."
                ),
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-saas.* | WHERE event.action LIKE \"*token-create*\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST IA-5(1)"],
                "references": [],
            },
            {
                "id": "saas_audit_webhook_add",
                "title": "Integration / webhook added",
                "kind": "audit",
                "risk": "medium",
                "summary": "New outbound webhook or third-party integration.",
                "description": "Webhooks can exfiltrate data without a user-visible UI surface.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-saas.* | WHERE event.action IN (\"webhook-add\", \"integration-add\")"
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST SR-11"],
                "references": [],
            },
        ],
        "references": [
            {"title": "Cloud Security Alliance — SaaS Governance", "url": "https://cloudsecurityalliance.org/"},
        ],
    },
}


# === Data ==================================================================

DATABASE: Dict[str, Any] = {
    "id": "database",
    "pillar_id": "data",
    "label": "Database",
    "icon": "database",
    "ecs_anchors": [
        "event.dataset:mysql.audit",
        "event.dataset:mssql.audit",
        "event.dataset:postgres.audit",
        "event.dataset:oracle.audit",
    ],
    "expected_feeds": ["database_audit"],
    "description": (
        "Database audit logs — privileged queries, schema changes, "
        "failed auth, bulk reads. The closest layer to the data the "
        "attacker is after."
    ),
    "catalogue": {
        "intake_questions": [
            {
                "key": "sub_data_db_query_audit",
                "text": "Is privileged query auditing enabled (e.g., SQL Server Audit, Postgres pgaudit)?",
                "answer_type": "yesno",
                "feeds": [["cg", 8]],
            },
            {
                "key": "sub_data_db_schema_audit",
                "text": "Are DDL / schema-change events alerted on?",
                "answer_type": "yesno",
                "feeds": [["cg", 7]],
            },
            {
                "key": "sub_data_db_jit_access",
                "text": "Is privileged DB access just-in-time (e.g., bastion / PAM)?",
                "answer_type": "yesno",
                "feeds": [["cg", 6]],
            },
            {
                "key": "sub_data_db_export_limit",
                "text": "Are bulk export / row-count thresholds alerted on?",
                "answer_type": "yesno",
                "feeds": [["cg", 5]],
            },
        ],
        "recommended_tasks": [
            "Confirm audit logs include actor, source IP, query text — query text is the load-bearing field.",
            "Tag tables containing regulated data in the parser (sensitivity:phi / sensitivity:pci).",
            "Cross-reference DBA accounts with PAM session logs; alert on drift.",
        ],
        "detection_use_cases": [
            {
                "id": "db_dba_non_bastion",
                "title": "DBA login from non-bastion host",
                "kind": "detection",
                "risk": "high",
                "summary": "Privileged DB login from a source IP outside the bastion / PAM range.",
                "description": (
                    "Allowlist the bastion CIDR per environment; alert "
                    "on any privileged login from elsewhere."
                ),
                "mitre_ids": ["T1078"],
                "logic_snippet": (
                    "FROM logs-database.audit-* | WHERE database.role IN (\"sysadmin\", \"superuser\", \"dba\") "
                    "AND NOT CIDR_MATCH(source.ip, \"10.20.30.0/24\")"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_db_dba_login",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1078", "url": "https://attack.mitre.org/techniques/T1078/"},
                ],
            },
            {
                "id": "db_schema_enum",
                "title": "Schema enumeration",
                "kind": "detection",
                "risk": "medium",
                "summary": "Many SELECT against information_schema / sys.tables.",
                "description": (
                    "Recon pattern. Threshold > 20 distinct queries to "
                    "the metadata catalog from one session."
                ),
                "mitre_ids": ["T1213"],
                "logic_snippet": (
                    "FROM logs-database.audit-* | WHERE database.query LIKE \"%information_schema%\" "
                    "OR LIKE \"%sys.tables%\" "
                    "| STATS qs = COUNT(*) BY user.name, source.ip "
                    "| WHERE qs > 20"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_db_schema_enum",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1213", "url": "https://attack.mitre.org/techniques/T1213/"},
                ],
            },
            {
                "id": "db_bulk_select_sensitive",
                "title": "Bulk SELECT from sensitive table",
                "kind": "detection",
                "risk": "high",
                "summary": "Single SELECT returning many rows from a sensitivity-tagged table.",
                "description": "Use the parser-tagged sensitivity field to scope.",
                "mitre_ids": ["T1213"],
                "logic_snippet": (
                    "FROM logs-database.audit-* | WHERE database.sensitivity IN (\"phi\", \"pci\", \"pii\") "
                    "AND database.rows_returned > 10000"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_db_bulk_sensitive",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1213", "url": "https://attack.mitre.org/techniques/T1213/"},
                ],
            },
            {
                "id": "db_failed_login_spike",
                "title": "Failed-login spike (brute force)",
                "kind": "detection",
                "risk": "medium",
                "summary": ">50 failed logins in 5 minutes from one source.",
                "description": "Often misattributed to mis-configured app; check before paging.",
                "mitre_ids": ["T1110"],
                "logic_snippet": (
                    "FROM logs-database.audit-* | WHERE event.action == \"login\" "
                    "AND event.outcome == \"failure\" "
                    "| STATS fails = COUNT(*) BY source.ip "
                    "| WHERE fails > 50"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_db_brute",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1110", "url": "https://attack.mitre.org/techniques/T1110/"},
                ],
            },
        ],
        "audit_use_cases": [
            {
                "id": "db_audit_priv_grant",
                "title": "Privilege grant",
                "kind": "audit",
                "risk": "high",
                "summary": "GRANT statement issued.",
                "description": "Should be infrequent and tied to a change ticket.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-database.audit-* | WHERE database.query LIKE \"GRANT%\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AC-3", "PCI DSS 7.1"],
                "references": [],
            },
            {
                "id": "db_audit_audit_disable",
                "title": "Audit policy disabled",
                "kind": "audit",
                "risk": "critical",
                "summary": "Audit / pgaudit / sql-audit specification disabled.",
                "description": "There is no benign reason to disable database audit in production.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-database.audit-* | WHERE database.query LIKE \"%DISABLE AUDIT%\" "
                    "OR LIKE \"%pgaudit%off%\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AU-9", "PCI DSS 10.5.5"],
                "references": [],
            },
            {
                "id": "db_audit_role_change",
                "title": "Role / login created or altered",
                "kind": "audit",
                "risk": "medium",
                "summary": "CREATE LOGIN / CREATE USER / ALTER ROLE.",
                "description": "Especially when targeting reserved roles like sa, postgres, root.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-database.audit-* | WHERE database.query LIKE \"CREATE LOGIN%\" "
                    "OR LIKE \"CREATE USER%\" OR LIKE \"ALTER ROLE%\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AC-2", "PCI DSS 7.2"],
                "references": [],
            },
        ],
        "references": [
            {"title": "CIS Database benchmarks (MySQL / Postgres / SQL Server)", "url": "https://www.cisecurity.org/benchmark"},
            {"title": "NIST AU-2 — Auditable events", "url": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home"},
        ],
    },
}


WEB_APP: Dict[str, Any] = {
    "id": "web_app",
    "pillar_id": "data",
    "label": "Web application",
    "icon": "code",
    "ecs_anchors": [
        "event.dataset:nginx.access",
        "event.dataset:apache.access",
        "event.dataset:iis.access",
    ],
    "expected_feeds": [],
    "description": (
        "Application access / error logs and WAF telemetry. OWASP "
        "Top-10 patterns, credential stuffing, and automated tooling "
        "fingerprints."
    ),
    "catalogue": {
        "intake_questions": [
            {
                "key": "sub_data_app_waf",
                "text": "Is a WAF deployed in blocking mode in front of the app?",
                "answer_type": "single",
                "options": [
                    {"value": "block", "label": "Blocking"},
                    {"value": "detect", "label": "Detection only"},
                    {"value": "off", "label": "No WAF"},
                    {"value": "dont_know", "label": "Don't know"},
                ],
                "feeds": [["cg", 8]],
            },
            {
                "key": "sub_data_app_user_attribution",
                "text": "Is user attribution (user.id / session) captured in access logs?",
                "answer_type": "yesno",
                "feeds": [["cg", 6]],
            },
            {
                "key": "sub_data_app_lockout",
                "text": "Is failed-login lockout in place?",
                "answer_type": "yesno",
                "feeds": [["cg", 5]],
            },
            {
                "key": "sub_data_app_audit_to_siem",
                "text": "Are application audit logs forwarded to the SIEM?",
                "answer_type": "yesno",
                "feeds": [["cg", 6]],
            },
            {
                "key": "sub_data_app_csp",
                "text": "Is a Content-Security-Policy header enforced (reports go to a sink)?",
                "answer_type": "yesno",
                "feeds": [["cg", 4]],
            },
        ],
        "recommended_tasks": [
            "Cross-reference Top-10 critical findings from the most recent pen-test against current detections.",
            "Verify error pages don't leak stack traces in prod.",
            "Confirm WAF rule pack is on the latest version (CRS 4.x for ModSecurity).",
        ],
        "detection_use_cases": [
            {
                "id": "app_sql_injection",
                "title": "SQL injection patterns",
                "kind": "detection",
                "risk": "high",
                "summary": "Common SQLi tokens in URL / body params.",
                "description": (
                    "OR 1=1, UNION SELECT, sleep(), benchmark(), "
                    "char(0x), and the like. Attribute to source.ip + "
                    "url.path."
                ),
                "mitre_ids": ["T1190"],
                "logic_snippet": (
                    "FROM logs-app.access-* | WHERE url.query LIKE \"%' OR 1=1%\" "
                    "OR LIKE \"%UNION SELECT%\" OR LIKE \"%sleep(%\" OR LIKE \"%benchmark(%\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_sqli",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1190", "url": "https://attack.mitre.org/techniques/T1190/"},
                    {"title": "OWASP A03:2021 Injection", "url": "https://owasp.org/Top10/A03_2021-Injection/"},
                ],
            },
            {
                "id": "app_xss",
                "title": "Reflected / stored XSS attempt",
                "kind": "detection",
                "risk": "medium",
                "summary": "<script> tag or javascript: URI in URL params.",
                "description": "Threshold per source.ip > 5 in 5 minutes; suppress single-shot.",
                "mitre_ids": ["T1190"],
                "logic_snippet": (
                    "FROM logs-app.access-* | WHERE url.query LIKE \"%<script%\" "
                    "OR LIKE \"%javascript:%\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_xss",
                "tide_rule_ids": [],
                "references": [
                    {"title": "OWASP A03:2021 Injection", "url": "https://owasp.org/Top10/A03_2021-Injection/"},
                ],
            },
            {
                "id": "app_tool_fingerprint",
                "title": "Automated tool fingerprint",
                "kind": "detection",
                "risk": "medium",
                "summary": "User-Agent matching sqlmap, nikto, Nuclei, Burp, etc.",
                "description": (
                    "Easy first-pass filter; pair with rate-limit on "
                    "the tool's source.ip."
                ),
                "mitre_ids": ["T1595"],
                "logic_snippet": (
                    "FROM logs-app.access-* | WHERE user_agent.original LIKE \"%sqlmap%\" "
                    "OR LIKE \"%nikto%\" OR LIKE \"%Nuclei%\" OR LIKE \"%Burp%\""
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_tool_fingerprint",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1595", "url": "https://attack.mitre.org/techniques/T1595/"},
                ],
            },
            {
                "id": "app_credential_stuffing",
                "title": "Credential stuffing",
                "kind": "detection",
                "risk": "high",
                "summary": "Many distinct usernames from one source attempting login.",
                "description": (
                    "Threshold > 50 distinct usernames per source.ip in "
                    "10 minutes — strong stuffing signal."
                ),
                "mitre_ids": ["T1110.004"],
                "logic_snippet": (
                    "FROM logs-app.* | WHERE event.action == \"login\" AND event.outcome == \"failure\" "
                    "| STATS uniq_users = COUNT_DISTINCT(user.name) BY source.ip "
                    "| WHERE uniq_users > 50"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_credential_stuffing",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE T1110.004", "url": "https://attack.mitre.org/techniques/T1110/004/"},
                ],
            },
        ],
        "audit_use_cases": [
            {
                "id": "app_audit_admin_user_added",
                "title": "Admin user added",
                "kind": "audit",
                "risk": "high",
                "summary": "App-level admin user creation event.",
                "description": "Tied to a change ticket.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-app.audit-* | WHERE event.action == \"user-create\" AND user.target.role == \"admin\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST AC-2", "OWASP ASVS L2 V1.4"],
                "references": [],
            },
            {
                "id": "app_audit_security_disabled",
                "title": "Security control disabled",
                "kind": "audit",
                "risk": "critical",
                "summary": "WAF rule disabled, MFA disabled, CSP relaxed.",
                "description": "Especially adjacent to a deploy event.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-app.audit-* | WHERE event.action LIKE \"*-disable\" "
                    "OR event.action == \"security-policy-relax\""
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST CM-3", "OWASP ASVS L2 V14.4"],
                "references": [],
            },
        ],
        "references": [
            {"title": "OWASP ASVS — Application Security Verification Standard", "url": "https://owasp.org/www-project-application-security-verification-standard/"},
            {"title": "OWASP Top 10 (2021)", "url": "https://owasp.org/Top10/"},
        ],
    },
}


# === OT ====================================================================

ICS_SCADA: Dict[str, Any] = {
    "id": "ics_scada",
    "pillar_id": "ot",
    "label": "ICS / SCADA",
    "icon": "factory",
    "ecs_anchors": [],
    "expected_feeds": ["ot_scada"],
    "description": (
        "Industrial control / SCADA — Modbus, BACnet, OPC. NERC-CIP "
        "and IEC 62443 alignment. Lower volume, higher impact than IT "
        "telemetry."
    ),
    "catalogue": {
        "intake_questions": [
            {
                "key": "sub_ot_segmentation",
                "text": "Is IT-OT segmentation enforced (Purdue model zone boundaries)?",
                "answer_type": "single",
                "options": [
                    {"value": "enforced", "label": "Yes — DMZ + ACLs"},
                    {"value": "partial", "label": "Partial / VLAN only"},
                    {"value": "flat", "label": "Flat / no boundary"},
                    {"value": "dont_know", "label": "Don't know"},
                ],
                "feeds": [["cg", 10]],
            },
            {
                "key": "sub_ot_eng_workstation",
                "text": "Are engineering workstations hardened and dedicated (no general internet)?",
                "answer_type": "yesno",
                "feeds": [["cg", 8]],
            },
            {
                "key": "sub_ot_passive_monitor",
                "text": "Is passive OT-protocol monitoring deployed (Claroty / Nozomi / Dragos)?",
                "answer_type": "yesno",
                "feeds": [["cg", 7]],
            },
            {
                "key": "sub_ot_baseline",
                "text": "Is a known-good asset baseline maintained for the OT estate?",
                "answer_type": "yesno",
                "feeds": [["cg", 5]],
            },
        ],
        "recommended_tasks": [
            "Map every cross-zone connection path; confirm each has explicit firewall rule + change ticket.",
            "Verify engineering workstations have no web / mail clients; if they do, document why.",
            "Subscribe to ICS-CERT advisories filtered by deployed-vendor list.",
        ],
        "detection_use_cases": [
            {
                "id": "ot_unauth_control",
                "title": "Unauthorised control command",
                "kind": "detection",
                "risk": "critical",
                "summary": "Modbus write coil / BACnet writeProperty from a non-engineering host.",
                "description": (
                    "Source.ip not in the engineering-workstation "
                    "allowlist issuing a control-write packet. Should "
                    "page operations + SOC."
                ),
                "mitre_ids": ["T0855"],
                "logic_snippet": (
                    "FROM logs-ot.* | WHERE network.protocol IN (\"modbus\", \"bacnet\") "
                    "AND ot.function IN (\"write_single_coil\", \"write_multiple_registers\", \"write_property\") "
                    "AND NOT source.ip IN [eng_workstations]"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_ot_unauth_control",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE ICS T0855", "url": "https://attack.mitre.org/techniques/T0855/"},
                ],
            },
            {
                "id": "ot_plc_program_write",
                "title": "PLC program / firmware write",
                "kind": "detection",
                "risk": "critical",
                "summary": "Function code indicating a logic upload or firmware update.",
                "description": (
                    "Stuxnet and successors all start here. Always alert; "
                    "operations confirms whether scheduled."
                ),
                "mitre_ids": ["T0843"],
                "logic_snippet": (
                    "FROM logs-ot.* | WHERE ot.function IN "
                    "(\"program_upload\", \"firmware_update\", \"start_program\", \"stop_program\")"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_ot_plc_program",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE ICS T0843", "url": "https://attack.mitre.org/techniques/T0843/"},
                ],
            },
            {
                "id": "ot_eng_lateral",
                "title": "Engineering workstation lateral movement",
                "kind": "detection",
                "risk": "high",
                "summary": "EWS connecting outside its expected control zone.",
                "description": "Cross-zone SMB / RDP / WinRM from EWS to non-OT segments.",
                "mitre_ids": ["T0859"],
                "logic_snippet": (
                    "FROM logs-network.* | WHERE source.ip IN [eng_workstations] "
                    "AND NOT CIDR_MATCH(destination.ip, [ot_zone_cidrs])"
                ),
                "logic_lang": "esql",
                "soar_playbook_id": "pb_ot_lateral",
                "tide_rule_ids": [],
                "references": [
                    {"title": "MITRE ICS T0859", "url": "https://attack.mitre.org/techniques/T0859/"},
                ],
            },
        ],
        "audit_use_cases": [
            {
                "id": "ot_audit_seg_change",
                "title": "Segmentation rule change",
                "kind": "audit",
                "risk": "critical",
                "summary": "Firewall rule modification on the IT-OT boundary.",
                "description": "Rare and high-impact — every change should map to a documented engineering activity.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-network.firewall-config-* | WHERE event.action == \"rule-modify\" "
                    "AND firewall.zone IN (\"OT-DMZ\", \"OT-Process\")"
                ),
                "logic_lang": "esql",
                "compliance_frames": ["NIST SP 800-82 r3 SC-7", "IEC 62443-3-3 SR 5.1"],
                "references": [],
            },
            {
                "id": "ot_audit_plc_auth_relax",
                "title": "PLC authentication relaxation",
                "kind": "audit",
                "risk": "high",
                "summary": "Auth disabled or password reset on a PLC.",
                "description": "Often legitimate during commissioning, but should always be flagged.",
                "mitre_ids": [],
                "logic_snippet": (
                    "FROM logs-ot.* | WHERE ot.function IN "
                    "(\"set_password\", \"disable_auth\", \"factory_reset\")"
                ),
                "logic_lang": "esql",
                "compliance_frames": ["IEC 62443-3-3 SR 1.5"],
                "references": [],
            },
        ],
        "references": [
            {"title": "NIST SP 800-82 r3 — Guide to OT Security", "url": "https://csrc.nist.gov/pubs/sp/800/82/r3/final"},
            {"title": "IEC 62443 family", "url": "https://www.iec.ch/system-level-security"},
            {"title": "MITRE ATT&CK for ICS", "url": "https://attack.mitre.org/matrices/ics/"},
        ],
    },
}


# ---------------------------------------------------------------------------
# Public accessor — full catalogue list (15 sub-profiles, all at full depth)
# ---------------------------------------------------------------------------

SUBPROFILES: List[Dict[str, Any]] = [
    # Identity
    ACTIVE_DIRECTORY,
    ENTRA_OKTA,
    VPN_REMOTE,
    # Endpoint
    WINDOWS_ENDPOINT,
    LINUX_ENDPOINT,
    MACOS_ENDPOINT,
    # Network
    NEXT_GEN_FIREWALL,
    DNS_PROFILE,
    WEB_PROXY,
    # Cloud
    CLOUD_AUDIT,
    EMAIL_PLATFORM,
    SAAS_GENERIC,
    # Data
    DATABASE,
    WEB_APP,
    # OT
    ICS_SCADA,
]


def get_pillars() -> List[Dict[str, Any]]:
    """Return the 6 pillar definitions (defensive copy)."""
    return [dict(p) for p in PILLARS]


def get_subprofiles() -> List[Dict[str, Any]]:
    """Return all 14 sub-profile definitions (defensive copy)."""
    return [dict(s) for s in SUBPROFILES]


def get_subprofile(subprofile_id: str) -> Dict[str, Any] | None:
    """Look up one sub-profile by id, or None."""
    for s in SUBPROFILES:
        if s["id"] == subprofile_id:
            return dict(s)
    return None


# ---------------------------------------------------------------------------
# Migration table — existing data_source_type strings → new subprofile_id
# ---------------------------------------------------------------------------
#
# Used by the seed/migration to backfill cyab_data_sources.subprofile_id
# from the legacy data_source_type column. Three existing types are
# ambiguous (windows_security, edr) — those map to None and the UI
# surfaces a "Confirm sub-profile" banner.

DATA_SOURCE_TYPE_MIGRATION: Dict[str, str | None] = {
    "sysmon": "windows_endpoint",
    "windows_security": None,  # split: AD-DC vs windows_endpoint — ask
    "firewall": "next_gen_firewall",
    "dns": "dns",
    "edr": None,  # OS-dependent — ask
    "cloud_audit": "cloud_audit",
    "email_gateway": "email_platform",
    "web_proxy": "web_proxy",
    "identity_provider": "entra_okta",
    "linux_auditd": "linux_endpoint",
    "database_audit": "database",
    "ot_scada": "ics_scada",
}
