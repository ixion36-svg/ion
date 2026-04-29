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

CATALOGUE_VERSION = 1


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


# === Skeleton sub-profiles (11) ============================================
#
# Authored to v0.12.0 plumbing depth. v0.12.1 fills these to the same
# depth as ACTIVE_DIRECTORY / WINDOWS_ENDPOINT / NEXT_GEN_FIREWALL.

def _stub(
    id_: str, pillar: str, label: str, icon: str,
    ecs_anchors: List[str], expected_feeds: List[str],
    description: str,
) -> Dict[str, Any]:
    return {
        "id": id_,
        "pillar_id": pillar,
        "label": label,
        "icon": icon,
        "ecs_anchors": ecs_anchors,
        "expected_feeds": expected_feeds,
        "description": description,
        "catalogue": {
            "intake_questions": [],
            "recommended_tasks": [],
            "detection_use_cases": [],
            "audit_use_cases": [],
            "references": [],
        },
    }


SKELETONS: List[Dict[str, Any]] = [
    # Identity
    _stub(
        "entra_okta", "identity", "Entra ID / Okta", "globe",
        ["event.dataset:azure.signinlogs", "event.dataset:okta.system"],
        ["identity_provider"],
        "Cloud-hosted federated identity providers. Conditional access "
        "policy auditing, sign-in risk, illicit consent grants.",
    ),
    _stub(
        "vpn_remote", "identity", "VPN / Remote access", "key",
        ["event.dataset:cisco.asa", "event.dataset:paloalto.panos"],
        [],
        "VPN concentrators and remote-access appliances.",
    ),
    # Endpoint
    _stub(
        "linux_endpoint", "endpoint", "Linux / Unix", "terminal",
        ["event.dataset:auditd.log", "event.dataset:system.auth"],
        ["linux_auditd"],
        "Linux servers and workstations, auditd / sudo / SSH telemetry.",
    ),
    _stub(
        "macos_endpoint", "endpoint", "macOS endpoint", "monitor",
        ["event.dataset:macos.unifiedlogs"],
        [],
        "macOS workstations. Endpoint Security Framework + unified logs.",
    ),
    # Network
    _stub(
        "dns", "network", "DNS", "search",
        ["event.dataset:zeek.dns", "dns.question.name:*"],
        ["dns"],
        "Recursive resolvers and authoritative servers. Tunnelling, "
        "DGA, and rare-domain detection.",
    ),
    _stub(
        "web_proxy", "network", "Web proxy", "globe",
        ["event.dataset:zscaler.zia", "event.dataset:bluecoat.proxy"],
        ["web_proxy"],
        "Outbound web proxy / SWG. Category-based blocking + URL logging.",
    ),
    # Cloud
    _stub(
        "cloud_audit", "cloud", "Cloud audit (AWS / Azure / GCP)", "cloud",
        ["event.dataset:aws.cloudtrail", "event.dataset:azure.activitylogs", "event.dataset:gcp.audit"],
        ["cloud_audit"],
        "Control-plane API audit. IAM changes, resource creation, key rotation.",
    ),
    _stub(
        "email_platform", "cloud", "Email platform (M365 / Workspace)", "mail",
        ["event.dataset:o365.audit.exchange", "event.dataset:gsuite.gmail"],
        ["email_gateway"],
        "Cloud email — mailbox auditing, phishing telemetry, OAuth grants.",
    ),
    _stub(
        "saas_generic", "cloud", "SaaS app (generic)", "box",
        [],
        [],
        "Generic SaaS application — Salesforce, GitHub, Workday, etc.",
    ),
    # Data
    _stub(
        "database", "data", "Database", "database",
        ["event.dataset:mysql.audit", "event.dataset:mssql.audit", "event.dataset:postgres.audit"],
        ["database_audit"],
        "Database audit logs — privileged queries, schema changes, failed auth.",
    ),
    _stub(
        "web_app", "data", "Web application", "code",
        ["event.dataset:nginx.access", "event.dataset:apache.access"],
        [],
        "Application access / error logs. WAF telemetry, login anomaly, "
        "OWASP Top-10 patterns.",
    ),
    # OT
    _stub(
        "ics_scada", "ot", "ICS / SCADA", "factory",
        [],
        ["ot_scada"],
        "Industrial control / SCADA. Modbus, BACnet, OPC; NERC-CIP / "
        "IEC 62443 alignment.",
    ),
]


# ---------------------------------------------------------------------------
# Public accessor — full catalogue list (3 fully authored + 11 stubs = 14)
# ---------------------------------------------------------------------------

SUBPROFILES: List[Dict[str, Any]] = [
    ACTIVE_DIRECTORY,
    WINDOWS_ENDPOINT,
    NEXT_GEN_FIREWALL,
    *SKELETONS,
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
