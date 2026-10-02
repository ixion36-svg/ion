"""Seed CyAB systems with data sources, use cases mapped against TIDE detection rules.

Creates 8 systems across departments with varied readiness levels:
  - 3 fully reviewed with good coverage
  - 3 reviewed with known gaps
  - 2 not yet reviewed (no use case mapping)

Usage: python seed_cyab_systems.py
Requires ION running at http://localhost:8000
"""

import requests
import json

BASE = "http://localhost:8000"
SESSION = requests.Session()


def login():
    r = SESSION.post(f"{BASE}/api/auth/login", json={"username": "admin", "password": "admin2025"})
    r.raise_for_status()
    print(f"Logged in as admin")


def create_system(data):
    r = SESSION.post(f"{BASE}/api/cyab/systems", json=data)
    r.raise_for_status()
    sys = r.json()
    print(f"  System: {sys['name']} (id={sys['id']})")
    return sys


def add_source(system_id, data):
    r = SESSION.post(f"{BASE}/api/cyab/systems/{system_id}/sources", json=data)
    r.raise_for_status()
    src = r.json()
    print(f"    Source: {src['name']} — readiness={src.get('readiness_score', 0)}% use_case={src.get('use_case_status', 'N/A')}")
    return src


def mark_reviewed(system_id):
    r = SESSION.post(f"{BASE}/api/cyab/systems/{system_id}/mark-reviewed")
    r.raise_for_status()


# ============================================================================
# Field mapping templates — which ECS fields each source type typically has
# ============================================================================

FULL_ENDPOINT = {
    "user.name": True, "user.domain": True, "user.id": True, "source.user.name": False,
    "@timestamp": True, "event.action": True, "event.category": True, "event.outcome": True,
    "host.name": True, "agent.name": True,
    "process.name": True, "process.command_line": True, "process.parent.name": True,
    "process.hash.sha256": True,
    "source.ip": True, "destination.ip": True, "source.port": True,
    "dns.question.name": False, "network.bytes": True, "url.full": False,
    "file.name": True, "file.hash.sha256": True,
    "source.geo.country_name": True, "threat.indicator.ip": False,
}

NETWORK_FOCUSED = {
    "user.name": False, "user.domain": False, "user.id": False, "source.user.name": False,
    "@timestamp": True, "event.action": True, "event.category": True, "event.outcome": True,
    "host.name": True, "agent.name": True,
    "process.name": False, "process.command_line": False, "process.parent.name": False,
    "process.hash.sha256": False,
    "source.ip": True, "destination.ip": True, "source.port": True,
    "dns.question.name": True, "network.bytes": True, "url.full": True,
    "file.name": False, "file.hash.sha256": False,
    "source.geo.country_name": True, "threat.indicator.ip": True,
}

AUTH_FOCUSED = {
    "user.name": True, "user.domain": True, "user.id": True, "source.user.name": True,
    "@timestamp": True, "event.action": True, "event.category": True, "event.outcome": True,
    "host.name": True, "agent.name": True,
    "process.name": False, "process.command_line": False, "process.parent.name": False,
    "process.hash.sha256": False,
    "source.ip": True, "destination.ip": False, "source.port": False,
    "dns.question.name": False, "network.bytes": False, "url.full": False,
    "file.name": False, "file.hash.sha256": False,
    "source.geo.country_name": True, "threat.indicator.ip": False,
}

MINIMAL_LOGS = {
    "user.name": False, "user.domain": False, "user.id": False, "source.user.name": False,
    "@timestamp": True, "event.action": True, "event.category": False, "event.outcome": False,
    "host.name": True, "agent.name": False,
    "process.name": False, "process.command_line": False, "process.parent.name": False,
    "process.hash.sha256": False,
    "source.ip": True, "destination.ip": True, "source.port": False,
    "dns.question.name": False, "network.bytes": False, "url.full": False,
    "file.name": False, "file.hash.sha256": False,
    "source.geo.country_name": False, "threat.indicator.ip": False,
}

EMAIL_GATEWAY = {
    "user.name": True, "user.domain": True, "user.id": False, "source.user.name": True,
    "@timestamp": True, "event.action": True, "event.category": True, "event.outcome": True,
    "host.name": True, "agent.name": True,
    "process.name": False, "process.command_line": False, "process.parent.name": False,
    "process.hash.sha256": False,
    "source.ip": True, "destination.ip": True, "source.port": False,
    "dns.question.name": True, "network.bytes": False, "url.full": True,
    "file.name": True, "file.hash.sha256": True,
    "source.geo.country_name": True, "threat.indicator.ip": True,
}

CLOUD_AUDIT = {
    "user.name": True, "user.domain": False, "user.id": True, "source.user.name": True,
    "@timestamp": True, "event.action": True, "event.category": True, "event.outcome": True,
    "host.name": False, "agent.name": False,
    "process.name": False, "process.command_line": False, "process.parent.name": False,
    "process.hash.sha256": False,
    "source.ip": True, "destination.ip": False, "source.port": False,
    "dns.question.name": False, "network.bytes": False, "url.full": True,
    "file.name": False, "file.hash.sha256": False,
    "source.geo.country_name": True, "threat.indicator.ip": False,
}


def calc_scores(field_mapping, sal_tier="SAL-2"):
    """Calculate field mapping, mandatory, and readiness scores."""
    total = len(field_mapping)
    mapped = sum(1 for v in field_mapping.values() if v)
    fm_score = int((mapped / total) * 100) if total else 0

    mandatory_fields = [
        "user.name", "@timestamp", "event.action", "event.outcome",
        "host.name", "process.name", "process.command_line",
        "source.ip", "destination.ip",
    ]
    mandatory_mapped = sum(1 for f in mandatory_fields if field_mapping.get(f, False))
    mand_score = int((mandatory_mapped / len(mandatory_fields)) * 100)

    thresholds = {"SAL-1": 90, "SAL-2": 65, "SAL-3": 35}
    threshold = thresholds.get(sal_tier, 65)
    compliance = "PASS" if fm_score >= threshold else "FAIL"

    if fm_score >= 80:
        risk = "LOW"
    elif fm_score >= 50:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    readiness = int((fm_score * 0.5 + mand_score * 0.5))

    return fm_score, mand_score, readiness, risk, compliance


# ============================================================================
# System definitions
# ============================================================================

SYSTEMS = [
    # --- FULLY REVIEWED, GOOD COVERAGE ---
    {
        "system": {
            "name": "Enterprise Endpoint Protection",
            "department": "IT Security",
            "department_lead": "Sarah Chen",
            "soc_team": "Security Operations Center",
            "soc_lead": "Marcus Williams",
            "reference": "CyAB-001",
            "version": "2.1",
            "status": "OFFICIAL",
            "icon": "shield",
            "tags": ["endpoint", "edr", "critical"],
            "review_cadence_days": 90,
            "next_review_date": "2026-06-15",
            "sign_dept_name": "Sarah Chen",
            "sign_dept_date": "2026-03-15",
            "sign_soc_name": "Marcus Williams",
            "sign_soc_date": "2026-03-15",
        },
        "sources": [
            {
                "name": "Elastic Defend — Workstations",
                "data_source_type": "EDR",
                "icon": "shield",
                "sal_tier": "SAL-1",
                "uptime_target": "99.9%",
                "max_latency": "30s",
                "retention": "180 days",
                "p1_sla": "15 minutes",
                "field_mapping": FULL_ENDPOINT,
                "use_case_status": "Reviewed — Fully Covered",
                "use_case_review_date": "2026-03-15",
                "use_case_gaps": None,
                "use_case_remediation": None,
                "field_notes": "Full ECS coverage. Process telemetry includes parent chain. Mapped to TIDE rules: Malware Detected, Credential Dumping via Mimikatz (T1003), Suspicious PowerShell Encoded Command (T1059), Phishing - Suspicious Office Document Execution (T1566).",
            },
            {
                "name": "Elastic Defend — Servers",
                "data_source_type": "EDR",
                "icon": "server",
                "sal_tier": "SAL-1",
                "uptime_target": "99.95%",
                "max_latency": "15s",
                "retention": "365 days",
                "p1_sla": "10 minutes",
                "field_mapping": FULL_ENDPOINT,
                "use_case_status": "Reviewed — Fully Covered",
                "use_case_review_date": "2026-03-15",
                "use_case_gaps": None,
                "use_case_remediation": None,
                "field_notes": "Server fleet fully instrumented. Covers TIDE rules: Lateral Movement via RDP (T1021), Brute Force SSH Login Attempts (T1110), Potential Buffer Overflow Attack (T1068/T1190). All critical use cases validated.",
            },
        ],
    },
    {
        "system": {
            "name": "Network Security Monitoring",
            "department": "Network Operations",
            "department_lead": "James O'Brien",
            "soc_team": "Security Operations Center",
            "soc_lead": "Marcus Williams",
            "reference": "CyAB-002",
            "version": "1.3",
            "status": "OFFICIAL",
            "icon": "globe",
            "tags": ["network", "ids", "ndr", "critical"],
            "review_cadence_days": 90,
            "next_review_date": "2026-07-01",
            "sign_dept_name": "James O'Brien",
            "sign_dept_date": "2026-04-01",
            "sign_soc_name": "Marcus Williams",
            "sign_soc_date": "2026-04-01",
        },
        "sources": [
            {
                "name": "Suricata IDS — Perimeter",
                "data_source_type": "IDS/IPS",
                "icon": "globe",
                "sal_tier": "SAL-1",
                "uptime_target": "99.95%",
                "max_latency": "10s",
                "retention": "365 days",
                "p1_sla": "5 minutes",
                "field_mapping": NETWORK_FOCUSED,
                "use_case_status": "Reviewed — Fully Covered",
                "use_case_review_date": "2026-04-01",
                "use_case_gaps": None,
                "use_case_remediation": None,
                "field_notes": "Full network telemetry. Maps to TIDE rules: Suspicious Outbound Connection to Rare Port (T1571), Potential Data Exfiltration via DNS (T1048). DNS query logging enriched with threat intel.",
            },
            {
                "name": "Zeek — Internal Segments",
                "data_source_type": "NSM",
                "icon": "search",
                "sal_tier": "SAL-2",
                "uptime_target": "99.5%",
                "max_latency": "60s",
                "retention": "90 days",
                "p1_sla": "30 minutes",
                "field_mapping": NETWORK_FOCUSED,
                "use_case_status": "Reviewed — Fully Covered",
                "use_case_review_date": "2026-04-01",
                "use_case_gaps": None,
                "use_case_remediation": None,
                "field_notes": "East-west visibility. Lateral movement detection via RDP/SMB session logging. Mapped to TIDE lateral movement use cases.",
            },
        ],
    },
    {
        "system": {
            "name": "Identity & Access Management",
            "department": "IT Services",
            "department_lead": "Aisha Mohammed",
            "soc_team": "Security Operations Center",
            "soc_lead": "Priya Patel",
            "reference": "CyAB-003",
            "version": "1.1",
            "status": "OFFICIAL",
            "icon": "key",
            "tags": ["identity", "authentication", "ad"],
            "review_cadence_days": 90,
            "next_review_date": "2026-06-20",
            "sign_dept_name": "Aisha Mohammed",
            "sign_dept_date": "2026-03-20",
            "sign_soc_name": "Priya Patel",
            "sign_soc_date": "2026-03-20",
        },
        "sources": [
            {
                "name": "Active Directory — Domain Controllers",
                "data_source_type": "Authentication Logs",
                "icon": "key",
                "sal_tier": "SAL-1",
                "uptime_target": "99.99%",
                "max_latency": "15s",
                "retention": "365 days",
                "p1_sla": "10 minutes",
                "field_mapping": AUTH_FOCUSED,
                "use_case_status": "Reviewed — Fully Covered",
                "use_case_review_date": "2026-03-20",
                "use_case_gaps": None,
                "use_case_remediation": None,
                "field_notes": "Windows Security Event logs (4624/4625/4648/4672/4768/4769). Maps to TIDE rules: Brute Force SSH Login Attempts (T1110), Stolen Credentials Used to Login (T1556). Full Kerberos audit trail.",
            },
            {
                "name": "Azure AD / Entra ID",
                "data_source_type": "Cloud IAM",
                "icon": "cloud",
                "sal_tier": "SAL-2",
                "uptime_target": "99.9%",
                "max_latency": "120s",
                "retention": "90 days",
                "p1_sla": "30 minutes",
                "field_mapping": CLOUD_AUDIT,
                "use_case_status": "Reviewed — Fully Covered",
                "use_case_review_date": "2026-03-20",
                "use_case_gaps": None,
                "use_case_remediation": None,
                "field_notes": "Sign-in logs, audit logs, risky user/sign-in detections. Covers cloud identity TIDE use cases. MFA events logged.",
            },
        ],
    },

    # --- REVIEWED WITH KNOWN GAPS ---
    {
        "system": {
            "name": "Email Security Gateway",
            "department": "Communications",
            "department_lead": "Tom Richardson",
            "soc_team": "Security Operations Center",
            "soc_lead": "Priya Patel",
            "reference": "CyAB-004",
            "version": "1.0",
            "status": "OFFICIAL",
            "icon": "mail",
            "tags": ["email", "phishing", "gateway"],
            "review_cadence_days": 90,
            "next_review_date": "2026-06-01",
            "sign_dept_name": "Tom Richardson",
            "sign_dept_date": "2026-03-01",
            "sign_soc_name": "Priya Patel",
            "sign_soc_date": "2026-03-01",
        },
        "sources": [
            {
                "name": "Microsoft Defender for Office 365",
                "data_source_type": "Email Gateway",
                "icon": "mail",
                "sal_tier": "SAL-2",
                "uptime_target": "99.9%",
                "max_latency": "300s",
                "retention": "90 days",
                "p1_sla": "30 minutes",
                "field_mapping": EMAIL_GATEWAY,
                "use_case_status": "Reviewed — Known Gaps",
                "use_case_review_date": "2026-03-01",
                "use_case_gaps": "UC-PHISH-003 Attachment Detonation: Missing process.command_line for sandbox analysis results. UC-PHISH-005 QR Code Phishing: No image content analysis fields. Cannot fully map to TIDE rule 'Phishing - Suspicious Office Document Execution' (T1566) — process telemetry from detonation sandbox not forwarded to SIEM.",
                "use_case_remediation": "Q2-2026: Enable Defender sandbox verdict forwarding via Graph API connector. Q3-2026: Evaluate QR code scanning add-on from vendor.",
                "field_notes": "Good email metadata coverage. Attachment hashes present. Missing execution telemetry from sandboxed attachments.",
            },
        ],
    },
    {
        "system": {
            "name": "Cloud Infrastructure — AWS",
            "department": "Cloud Engineering",
            "department_lead": "Elena Kovacs",
            "soc_team": "Security Operations Center",
            "soc_lead": "Marcus Williams",
            "reference": "CyAB-005",
            "version": "1.2",
            "status": "OFFICIAL",
            "icon": "cloud",
            "tags": ["cloud", "aws", "infrastructure"],
            "review_cadence_days": 60,
            "next_review_date": "2026-05-15",
            "sign_dept_name": "Elena Kovacs",
            "sign_dept_date": "2026-03-15",
            "sign_soc_name": "Marcus Williams",
            "sign_soc_date": "2026-03-15",
        },
        "sources": [
            {
                "name": "AWS CloudTrail",
                "data_source_type": "Cloud Audit",
                "icon": "cloud",
                "sal_tier": "SAL-1",
                "uptime_target": "99.99%",
                "max_latency": "300s",
                "retention": "365 days",
                "p1_sla": "15 minutes",
                "field_mapping": CLOUD_AUDIT,
                "use_case_status": "Reviewed — Known Gaps",
                "use_case_review_date": "2026-03-15",
                "use_case_gaps": "UC-CLOUD-002 Unusual API Calls: Missing process.name/process.command_line — cannot detect post-exploitation tools on EC2. UC-CLOUD-007 Data Exfiltration via S3: network.bytes not populated for S3 access events. Cannot map to TIDE rules requiring host-level telemetry (T1059 PowerShell, T1003 Credential Dumping).",
                "use_case_remediation": "Deploy Elastic Defend on EC2 fleet (planned Q2-2026). Enable S3 data event logging with VPC flow log enrichment for network.bytes.",
                "field_notes": "API-level audit trail only. No host-level telemetry from EC2 instances. S3/IAM/Lambda events well-covered.",
            },
            {
                "name": "AWS GuardDuty",
                "data_source_type": "Cloud Threat Detection",
                "icon": "shield",
                "sal_tier": "SAL-2",
                "uptime_target": "99.9%",
                "max_latency": "600s",
                "retention": "90 days",
                "p1_sla": "30 minutes",
                "field_mapping": MINIMAL_LOGS,
                "use_case_status": "Reviewed — Known Gaps",
                "use_case_review_date": "2026-03-15",
                "use_case_gaps": "UC-CLOUD-010 Cryptomining: Only finding-level alerts, no raw network flow data. GuardDuty findings lack ECS field mapping — manual normalisation required. Limited MITRE technique coverage compared to custom TIDE rules.",
                "use_case_remediation": "Build ECS normalisation pipeline for GuardDuty findings (Q2-2026). Evaluate GuardDuty Runtime Monitoring for container workloads.",
                "field_notes": "Finding-level alerts only. Minimal field mapping. Useful as a secondary detection layer but cannot replace host telemetry.",
            },
        ],
    },
    {
        "system": {
            "name": "Database Activity Monitoring",
            "department": "Data Services",
            "department_lead": "Chen Wei",
            "soc_team": "Security Operations Center",
            "soc_lead": "Priya Patel",
            "reference": "CyAB-006",
            "version": "1.0",
            "status": "OFFICIAL",
            "icon": "database",
            "tags": ["database", "dam", "data"],
            "review_cadence_days": 90,
            "next_review_date": "2026-05-20",
            "sign_dept_name": "Chen Wei",
            "sign_dept_date": "2026-02-20",
            "sign_soc_name": "Priya Patel",
            "sign_soc_date": "2026-02-20",
        },
        "sources": [
            {
                "name": "Imperva DAM — Production Databases",
                "data_source_type": "Database Audit",
                "icon": "database",
                "sal_tier": "SAL-2",
                "uptime_target": "99.5%",
                "max_latency": "120s",
                "retention": "180 days",
                "p1_sla": "30 minutes",
                "field_mapping": {
                    "user.name": True, "user.domain": False, "user.id": True, "source.user.name": True,
                    "@timestamp": True, "event.action": True, "event.category": True, "event.outcome": True,
                    "host.name": True, "agent.name": True,
                    "process.name": False, "process.command_line": False, "process.parent.name": False,
                    "process.hash.sha256": False,
                    "source.ip": True, "destination.ip": True, "source.port": True,
                    "dns.question.name": False, "network.bytes": False, "url.full": False,
                    "file.name": False, "file.hash.sha256": False,
                    "source.geo.country_name": True, "threat.indicator.ip": False,
                },
                "use_case_status": "Reviewed — Known Gaps",
                "use_case_review_date": "2026-02-20",
                "use_case_gaps": "UC-DATA-001 SQL Injection Detection: Missing process.command_line for application-layer correlation. UC-DATA-003 Privilege Escalation: No process tree data. Cannot correlate database activity to TIDE rules requiring endpoint telemetry (T1003, T1059).",
                "use_case_remediation": "Integrate application server logs with Elastic Agent for process correlation (Q3-2026). Enable stored procedure audit logging.",
                "field_notes": "Good query-level audit. User attribution strong. No correlation with application or OS-level activity.",
            },
        ],
    },

    # --- NOT YET REVIEWED ---
    {
        "system": {
            "name": "OT/SCADA Network Monitoring",
            "department": "Facilities Management",
            "department_lead": "Robert Shaw",
            "soc_team": "Security Operations Center",
            "soc_lead": "Marcus Williams",
            "reference": "CyAB-007",
            "version": "0.1",
            "status": "DRAFT",
            "icon": "cpu",
            "tags": ["ot", "scada", "ics", "critical-infrastructure"],
            "review_cadence_days": 180,
            "next_review_date": "2026-09-01",
        },
        "sources": [
            {
                "name": "Claroty CTD — OT Network",
                "data_source_type": "OT Security",
                "icon": "cpu",
                "sal_tier": "SAL-3",
                "uptime_target": "99.0%",
                "max_latency": "600s",
                "retention": "30 days",
                "p1_sla": "60 minutes",
                "field_mapping": MINIMAL_LOGS,
                "use_case_status": "Not Yet Reviewed",
                "use_case_review_date": None,
                "use_case_gaps": None,
                "use_case_remediation": None,
                "field_notes": "Basic alert forwarding only. No ECS normalisation. OT protocols (Modbus/DNP3) not mapped to standard fields. TIDE use case review pending — OT-specific detection rules not yet developed.",
            },
        ],
    },
    {
        "system": {
            "name": "Physical Security Systems",
            "department": "Corporate Security",
            "department_lead": "David Mitchell",
            "soc_team": "Security Operations Center",
            "soc_lead": "Marcus Williams",
            "reference": "CyAB-008",
            "version": "0.1",
            "status": "DRAFT",
            "icon": "lock",
            "tags": ["physical", "access-control", "cctv"],
            "review_cadence_days": 180,
            "next_review_date": "2026-10-01",
        },
        "sources": [
            {
                "name": "Gallagher Access Control",
                "data_source_type": "Physical Access",
                "icon": "lock",
                "sal_tier": "SAL-3",
                "uptime_target": "99.0%",
                "max_latency": "600s",
                "retention": "90 days",
                "p1_sla": "60 minutes",
                "field_mapping": {
                    "user.name": True, "user.domain": False, "user.id": True, "source.user.name": False,
                    "@timestamp": True, "event.action": True, "event.category": False, "event.outcome": True,
                    "host.name": True, "agent.name": False,
                    "process.name": False, "process.command_line": False, "process.parent.name": False,
                    "process.hash.sha256": False,
                    "source.ip": False, "destination.ip": False, "source.port": False,
                    "dns.question.name": False, "network.bytes": False, "url.full": False,
                    "file.name": False, "file.hash.sha256": False,
                    "source.geo.country_name": False, "threat.indicator.ip": False,
                },
                "use_case_status": "Not Yet Reviewed",
                "use_case_review_date": None,
                "use_case_gaps": None,
                "use_case_remediation": None,
                "field_notes": "Badge swipe logs only. No TIDE use case review — physical/cyber correlation use cases not yet defined. Potential for insider threat correlation with AD auth events.",
            },
            {
                "name": "Milestone CCTV — VMS Events",
                "data_source_type": "Video Management",
                "icon": "monitor",
                "sal_tier": "SAL-3",
                "uptime_target": "95.0%",
                "max_latency": "N/A",
                "retention": "30 days",
                "p1_sla": "N/A",
                "field_mapping": MINIMAL_LOGS,
                "use_case_status": "Not Yet Reviewed",
                "use_case_review_date": None,
                "use_case_gaps": None,
                "use_case_remediation": None,
                "field_notes": "Motion/tamper alerts only. No ECS mapping. Syslog forwarding configured but not normalised. No TIDE use case mapping applicable.",
            },
        ],
    },
]


def main():
    login()
    print()

    for entry in SYSTEMS:
        sys_data = entry["system"]
        system = create_system(sys_data)
        system_id = system["id"]

        for src_data in entry["sources"]:
            fm = src_data.get("field_mapping", {})
            sal = src_data.get("sal_tier", "SAL-2")

            if fm:
                fm_score, mand_score, readiness, risk, compliance = calc_scores(fm, sal)
                src_data["field_mapping_score"] = fm_score
                src_data["mandatory_score"] = mand_score
                src_data["readiness_score"] = readiness
                src_data["risk_rating"] = risk
                src_data["sal_compliance"] = compliance

            add_source(system_id, src_data)

        # Mark reviewed systems
        if sys_data.get("status") == "OFFICIAL":
            mark_reviewed(system_id)

        print()

    print("Done! 8 CyAB systems created with 13 data sources.")
    print("  3 fully covered (Endpoint, Network, IAM)")
    print("  3 reviewed with gaps (Email, AWS, Database)")
    print("  2 not yet reviewed (OT/SCADA, Physical Security)")


if __name__ == "__main__":
    main()
