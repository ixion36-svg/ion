"""CyAB data source templates.

Pre-built configuration profiles for common log source types. When a user
creates a new data source, they can pick a template and get SAL tier, field
mapping, retention, latency targets, and P1 SLA pre-filled — then tweak.

Every template includes the ECS field mapping appropriate for that source
type so the field_mapping_score and mandatory_score are automatically computed.
"""

# ECS mandatory fields that every SAL-1+ source must provide
MANDATORY_FIELDS = [
    "@timestamp", "event.kind", "event.category", "event.action",
    "event.outcome", "host.name", "user.name",
]

# Extended ECS fields for richer context
EXTENDED_FIELDS = [
    "source.ip", "destination.ip", "source.port", "destination.port",
    "process.name", "process.pid", "process.command_line",
    "file.name", "file.path", "file.hash.sha256",
    "url.full", "dns.question.name",
    "user.domain", "user.email",
    "agent.type", "agent.version",
    "rule.name", "rule.id",
    "threat.technique.id", "threat.tactic.name",
]

ALL_FIELDS = MANDATORY_FIELDS + EXTENDED_FIELDS


def _mapping(present: list[str]) -> dict:
    """Build a field_mapping dict: True for present fields, False for missing."""
    return {f: (f in present) for f in ALL_FIELDS}


def _scores(mapping: dict) -> tuple[int, int, int]:
    """Compute (field_mapping_score, mandatory_score, readiness_score)."""
    total = len(mapping)
    mapped = sum(1 for v in mapping.values() if v)
    fm_score = round(mapped / total * 100) if total else 0

    mandatory_mapped = sum(1 for f in MANDATORY_FIELDS if mapping.get(f))
    mandatory_score = round(mandatory_mapped / len(MANDATORY_FIELDS) * 100)

    readiness = round((fm_score * 0.6) + (mandatory_score * 0.4))
    return fm_score, mandatory_score, readiness


# ---------------------------------------------------------------------------
# Template definitions
# ---------------------------------------------------------------------------

TEMPLATES: list[dict] = [
    {
        "id": "sysmon",
        "name": "Sysmon (Windows Endpoints)",
        "data_source_type": "Endpoint Telemetry",
        "icon": "monitor",
        "sal_tier": "SAL-1",
        "uptime_target": "99.9%",
        "max_latency": "< 60 seconds",
        "retention": "90 days hot, 365 days warm",
        "p1_sla": "15 minutes",
        "fields_present": [
            "@timestamp", "event.kind", "event.category", "event.action",
            "event.outcome", "host.name", "user.name",
            "process.name", "process.pid", "process.command_line",
            "file.name", "file.path", "file.hash.sha256",
            "source.ip", "destination.ip", "source.port", "destination.port",
            "dns.question.name", "user.domain",
            "agent.type", "agent.version",
            "rule.name", "threat.technique.id", "threat.tactic.name",
        ],
        "field_notes": "Sysmon provides deep process, file, network, and registry telemetry via Winlogbeat/Elastic Agent.",
    },
    {
        "id": "windows_security",
        "name": "Windows Security Event Log",
        "data_source_type": "Authentication & Audit",
        "icon": "shield",
        "sal_tier": "SAL-1",
        "uptime_target": "99.9%",
        "max_latency": "< 60 seconds",
        "retention": "90 days hot, 365 days warm",
        "p1_sla": "15 minutes",
        "fields_present": [
            "@timestamp", "event.kind", "event.category", "event.action",
            "event.outcome", "host.name", "user.name",
            "source.ip", "user.domain",
            "agent.type", "agent.version",
        ],
        "field_notes": "Windows Security channel (4624/4625/4688/4720/etc.) via Winlogbeat. Core authentication + audit source.",
    },
    {
        "id": "firewall",
        "name": "Firewall / NGFW",
        "data_source_type": "Network Security",
        "icon": "shield",
        "sal_tier": "SAL-1",
        "uptime_target": "99.95%",
        "max_latency": "< 30 seconds",
        "retention": "90 days hot, 180 days warm",
        "p1_sla": "15 minutes",
        "fields_present": [
            "@timestamp", "event.kind", "event.category", "event.action",
            "event.outcome",
            "source.ip", "destination.ip", "source.port", "destination.port",
            "host.name", "rule.name",
            "agent.type",
        ],
        "field_notes": "Palo Alto / Fortinet / Cisco ASA firewall traffic + threat logs via syslog or API integration.",
    },
    {
        "id": "dns",
        "name": "DNS Query Logs",
        "data_source_type": "Network Telemetry",
        "icon": "globe",
        "sal_tier": "SAL-2",
        "uptime_target": "99.5%",
        "max_latency": "< 120 seconds",
        "retention": "30 days hot, 90 days warm",
        "p1_sla": "30 minutes",
        "fields_present": [
            "@timestamp", "event.kind", "event.category", "event.action",
            "host.name",
            "source.ip", "dns.question.name",
            "agent.type",
        ],
        "field_notes": "DNS resolver query logs (BIND, Windows DNS, Infoblox). Key for C2 and DGA detection.",
    },
    {
        "id": "edr",
        "name": "EDR (CrowdStrike / Defender / SentinelOne)",
        "data_source_type": "Endpoint Detection",
        "icon": "shield-alert",
        "sal_tier": "SAL-1",
        "uptime_target": "99.9%",
        "max_latency": "< 30 seconds",
        "retention": "90 days hot, 365 days warm",
        "p1_sla": "10 minutes",
        "fields_present": [
            "@timestamp", "event.kind", "event.category", "event.action",
            "event.outcome", "host.name", "user.name",
            "process.name", "process.pid", "process.command_line",
            "file.name", "file.path", "file.hash.sha256",
            "source.ip", "destination.ip",
            "user.domain",
            "agent.type", "agent.version",
            "rule.name", "rule.id",
            "threat.technique.id", "threat.tactic.name",
        ],
        "field_notes": "EDR agent telemetry with pre-built detections. Richest endpoint visibility source.",
    },
    {
        "id": "cloud_audit",
        "name": "Cloud Audit (AWS CloudTrail / Azure Activity / GCP Audit)",
        "data_source_type": "Cloud Security",
        "icon": "cloud",
        "sal_tier": "SAL-1",
        "uptime_target": "99.9%",
        "max_latency": "< 300 seconds",
        "retention": "90 days hot, 365 days warm",
        "p1_sla": "30 minutes",
        "fields_present": [
            "@timestamp", "event.kind", "event.category", "event.action",
            "event.outcome", "user.name",
            "source.ip",
            "user.email",
            "agent.type",
        ],
        "field_notes": "Cloud provider API audit trail. Covers IAM, resource changes, and data access.",
    },
    {
        "id": "email_gateway",
        "name": "Email Gateway / Exchange Online",
        "data_source_type": "Email Security",
        "icon": "mail",
        "sal_tier": "SAL-2",
        "uptime_target": "99.5%",
        "max_latency": "< 300 seconds",
        "retention": "30 days hot, 90 days warm",
        "p1_sla": "30 minutes",
        "fields_present": [
            "@timestamp", "event.kind", "event.category", "event.action",
            "event.outcome",
            "source.ip", "user.email",
            "url.full", "file.name",
            "agent.type",
        ],
        "field_notes": "Email gateway or Exchange message tracking logs. Key for phishing detection.",
    },
    {
        "id": "web_proxy",
        "name": "Web Proxy / SWG",
        "data_source_type": "Network Security",
        "icon": "globe",
        "sal_tier": "SAL-2",
        "uptime_target": "99.5%",
        "max_latency": "< 120 seconds",
        "retention": "30 days hot, 90 days warm",
        "p1_sla": "30 minutes",
        "fields_present": [
            "@timestamp", "event.kind", "event.category", "event.action",
            "event.outcome",
            "source.ip", "destination.ip",
            "url.full", "host.name", "user.name",
            "agent.type",
        ],
        "field_notes": "HTTP/S proxy or Secure Web Gateway access logs. Tracks outbound web traffic.",
    },
    {
        "id": "identity_provider",
        "name": "Identity Provider (Okta / Entra ID / AD)",
        "data_source_type": "Identity & Access",
        "icon": "users",
        "sal_tier": "SAL-1",
        "uptime_target": "99.9%",
        "max_latency": "< 60 seconds",
        "retention": "90 days hot, 365 days warm",
        "p1_sla": "15 minutes",
        "fields_present": [
            "@timestamp", "event.kind", "event.category", "event.action",
            "event.outcome", "user.name",
            "source.ip", "user.email", "user.domain",
            "agent.type",
        ],
        "field_notes": "Identity provider authentication and admin events. Critical for credential abuse detection.",
    },
    {
        "id": "linux_auditd",
        "name": "Linux auditd / Auditbeat",
        "data_source_type": "Endpoint Audit",
        "icon": "terminal",
        "sal_tier": "SAL-2",
        "uptime_target": "99.5%",
        "max_latency": "< 120 seconds",
        "retention": "30 days hot, 180 days warm",
        "p1_sla": "30 minutes",
        "fields_present": [
            "@timestamp", "event.kind", "event.category", "event.action",
            "event.outcome", "host.name", "user.name",
            "process.name", "process.pid", "process.command_line",
            "file.path",
            "agent.type", "agent.version",
        ],
        "field_notes": "Linux auditd syscall and file integrity events via Auditbeat or Filebeat.",
    },
    {
        "id": "database_audit",
        "name": "Database Audit (SQL Server / PostgreSQL / Oracle)",
        "data_source_type": "Application Audit",
        "icon": "database",
        "sal_tier": "SAL-2",
        "uptime_target": "99.5%",
        "max_latency": "< 300 seconds",
        "retention": "90 days hot, 365 days warm",
        "p1_sla": "30 minutes",
        "fields_present": [
            "@timestamp", "event.kind", "event.category", "event.action",
            "event.outcome", "host.name", "user.name",
            "source.ip", "user.domain",
        ],
        "field_notes": "Database engine audit logs. Tracks privileged queries, schema changes, and access patterns.",
    },
    {
        "id": "ot_scada",
        "name": "OT / SCADA / ICS",
        "data_source_type": "OT Network",
        "icon": "cpu",
        "sal_tier": "SAL-3",
        "uptime_target": "99.0%",
        "max_latency": "< 600 seconds",
        "retention": "30 days hot, 90 days warm",
        "p1_sla": "60 minutes",
        "fields_present": [
            "@timestamp", "event.kind", "event.category",
            "host.name",
            "source.ip", "destination.ip",
        ],
        "field_notes": "OT/ICS network monitoring via passive sensors (Nozomi, Claroty, Dragos). Limited field coverage due to protocol constraints.",
    },
]


def list_templates() -> list[dict]:
    """Return template metadata (no field mapping detail) for the picker UI."""
    out = []
    for t in TEMPLATES:
        mapping = _mapping(t["fields_present"])
        fm, ms, rs = _scores(mapping)
        out.append({
            "id": t["id"],
            "name": t["name"],
            "data_source_type": t["data_source_type"],
            "icon": t["icon"],
            "sal_tier": t["sal_tier"],
            "field_count": sum(1 for v in mapping.values() if v),
            "total_fields": len(mapping),
            "readiness_score": rs,
        })
    return out


def get_template(template_id: str) -> dict | None:
    """Return a fully expanded template ready to populate a data source form."""
    for t in TEMPLATES:
        if t["id"] == template_id:
            mapping = _mapping(t["fields_present"])
            fm, ms, rs = _scores(mapping)
            return {
                "name": t["name"],
                "data_source_type": t["data_source_type"],
                "icon": t["icon"],
                "sal_tier": t["sal_tier"],
                "uptime_target": t["uptime_target"],
                "max_latency": t["max_latency"],
                "retention": t["retention"],
                "p1_sla": t["p1_sla"],
                "field_mapping": mapping,
                "field_mapping_score": fm,
                "mandatory_score": ms,
                "readiness_score": rs,
                "field_notes": t["field_notes"],
            }
    return None
