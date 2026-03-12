"""Shared observable extraction from raw ECS/Kibana Security alert data.

This is the single source of truth for extracting observables from
Elasticsearch alert documents.  Both the API (case creation) and
the Kibana sync service (import) should call ``extract_observables_from_raw``
instead of maintaining their own extraction logic.

Context types (the "type" field in returned dicts) preserve the role/direction
of each observable so analysts can distinguish e.g. source_ip vs destination_ip
or subject_user vs target_user.  The ObservableService LEGACY_TYPE_MAP resolves
these context types to the canonical ObservableType enum for storage, while the
context string is preserved on ObservableLink.context for display.
"""

import re
from typing import Any, Dict, List


_IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def _get_nested(data: dict, dotted_key: str) -> Any:
    """Retrieve a nested value using dot notation.

    Handles both formats:
    - Flattened dot notation keys: data["source.ip"]
    - Nested objects: data["source"]["ip"]
    """
    # First try flattened dot notation (Kibana Security alerts)
    if dotted_key in data:
        return data[dotted_key]

    # Then try nested object traversal (ECS standard)
    keys = dotted_key.split(".")
    current = data
    for k in keys:
        if isinstance(current, dict):
            current = current.get(k)
        else:
            return None
    return current


def extract_observables_from_raw(raw_data: dict) -> List[Dict[str, str]]:
    """Extract observables from ECS-style and Kibana Security alert data.

    Returns a list of ``{"type": ..., "value": ...}`` dicts, deduplicated.

    The "type" field is a context-aware role string (e.g. "source_ip",
    "target_user") that preserves *where* in the log the value came from.
    """
    observables: List[Dict[str, str]] = []
    seen: set = set()

    def _add(obs_type: str, value: str) -> None:
        value = str(value).strip()
        if value and (obs_type, value) not in seen:
            seen.add((obs_type, value))
            observables.append({"type": obs_type, "value": value})

    def _extract_field(fields: list, obs_type: str) -> None:
        for field in fields:
            val = _get_nested(raw_data, field)
            if val:
                if isinstance(val, list):
                    for v in val:
                        if v:
                            _add(obs_type, str(v))
                else:
                    _add(obs_type, str(val))

    # =====================================================================
    # IP Addresses — distinguished by direction
    # =====================================================================
    _extract_field(["source.ip", "client.ip"], "source_ip")
    _extract_field(["destination.ip", "server.ip"], "destination_ip")
    _extract_field(["host.ip"], "host_ip")

    # source.address / destination.address → source_ip / destination_ip (if IP-shaped)
    for field, obs_type in (("source.address", "source_ip"), ("destination.address", "destination_ip")):
        val = _get_nested(raw_data, field)
        if val:
            vals = val if isinstance(val, list) else [val]
            for v in vals:
                v_str = str(v).strip()
                if _IP_PATTERN.match(v_str):
                    _add(obs_type, v_str)

    # Windows Security log IP fields (e.g. logon events 4624/4625)
    _extract_field(["winlog.event_data.IpAddress"], "source_ip")

    # =====================================================================
    # Hostnames — distinguished by role
    # =====================================================================
    _extract_field(["host.name", "host.hostname", "agent.hostname"], "hostname")
    _extract_field(["source.domain"], "source_hostname")
    _extract_field(["destination.domain"], "destination_hostname")

    # Windows: workstation name from logon events
    _extract_field(["winlog.event_data.WorkstationName"], "source_hostname")

    # =====================================================================
    # User Accounts — subject (who performed) vs target (who was acted on)
    # =====================================================================

    # Subject user: the account that performed the action
    _extract_field([
        "winlog.event_data.SubjectUserName",
        "winlog.event_data.SubjectUserSid",
    ], "subject_user")

    # Target user: the account being acted upon (logon, privilege change, etc.)
    _extract_field([
        "user.name",
        "winlog.event_data.TargetUserName",
        "winlog.event_data.TargetUserSid",
    ], "target_user")

    # ECS user.id (could be either; store as generic user_account)
    _extract_field(["user.id"], "user_account")

    # Domain context for users (Windows AD domain)
    _extract_field(["winlog.event_data.SubjectDomainName"], "subject_domain")
    _extract_field([
        "winlog.event_data.TargetDomainName",
        "user.domain",
    ], "target_domain")

    # =====================================================================
    # URLs and Domains
    # =====================================================================
    _extract_field(["url.full", "url.original"], "url")
    _extract_field(["url.domain", "dns.question.name"], "domain")

    # =====================================================================
    # File Information
    # =====================================================================
    _extract_field(["file.path", "file.name"], "file_path")
    _extract_field(["process.executable"], "process_path")
    _extract_field(["file.hash.sha256", "process.hash.sha256"], "sha256")
    _extract_field(["file.hash.md5", "process.hash.md5"], "md5")
    _extract_field(["file.hash.sha1", "process.hash.sha1"], "sha1")

    # =====================================================================
    # Process Information
    # =====================================================================
    _extract_field(["process.name"], "process_name")
    _extract_field(["process.command_line", "process.args"], "command_line")
    _extract_field(["process.pid"], "process_id")
    _extract_field(["process.parent.name"], "parent_process")
    _extract_field(["process.parent.executable"], "parent_process_path")

    # =====================================================================
    # Network — ports distinguished by direction
    # =====================================================================
    _extract_field(["source.port"], "source_port")
    _extract_field(["destination.port", "server.port"], "destination_port")
    _extract_field(["network.protocol", "network.transport"], "protocol")

    # Windows logon type (4624: 2=Interactive, 3=Network, 10=RemoteInteractive, etc.)
    _extract_field(["winlog.event_data.LogonType"], "logon_type")

    # =====================================================================
    # Email
    # =====================================================================
    _extract_field(["email.from.address", "email.sender.address"], "email")
    _extract_field(["email.subject"], "email_subject")

    # =====================================================================
    # Registry (Windows)
    # =====================================================================
    _extract_field(["registry.path", "registry.key"], "registry_key")
    _extract_field(["registry.value"], "registry_value")

    # =====================================================================
    # MITRE ATT&CK
    # =====================================================================
    _extract_field(["threat.technique.id", "kibana.alert.rule.threat.technique.id"], "mitre_technique")
    _extract_field(["threat.technique.name", "kibana.alert.rule.threat.technique.name"], "mitre_technique_name")
    _extract_field(["threat.tactic.name", "kibana.alert.rule.threat.tactic.name"], "mitre_tactic")

    # =====================================================================
    # Event Context
    # =====================================================================
    _extract_field(["event.action", "kibana.alert.original_event.action"], "event_action")
    _extract_field(["event.category", "kibana.alert.original_event.category"], "event_category")
    _extract_field(["event.outcome", "kibana.alert.original_event.outcome"], "event_outcome")
    _extract_field(["message"], "message")

    # Windows event ID (useful for 4624, 4625, 4688, 4720, etc.)
    _extract_field(["winlog.event_id", "event.code"], "event_id")

    # =====================================================================
    # Kibana Security Alert specific fields
    # =====================================================================
    _extract_field(["kibana.alert.rule.name", "rule.name"], "rule_name")
    _extract_field(["kibana.alert.rule.description", "rule.description"], "rule_description")
    _extract_field(["kibana.alert.reason"], "alert_reason")
    _extract_field(["kibana.alert.severity", "severity"], "severity")
    _extract_field(["kibana.alert.risk_score"], "risk_score")

    return observables
