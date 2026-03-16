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

# Types that are true observables — enrichable, trackable IOCs.
# Everything else (event metadata, rule info, ports, PIDs) is context, not an observable.
ENRICHABLE_TYPES = frozenset({
    "source_ip", "destination_ip", "host_ip",
    "hostname", "source_hostname", "destination_hostname",
    "target_user", "subject_user", "user_account",
    "url", "domain",
    "file_path", "process_path",
    "sha256", "md5", "sha1",
    "process_name", "command_line",
    "parent_process", "parent_process_path",
    "email", "email_subject",
    "registry_key", "registry_value",
})

# Values that are noise — generic system accounts, localhost, etc.
_NOISE_VALUES = frozenset({
    "-", "n/a", "na", "none", "null", "unknown", "undefined",
    "system", "local service", "network service", "local system",
    "nt authority\\system", "nt authority\\local service",
    "nt authority\\network service", "nt authority",
    "127.0.0.1", "::1", "0.0.0.0",
    "localhost",
})

# SIDs that are always system/noise
_NOISE_SID_PREFIXES = ("S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-0-0")

# Minimum length for string values to avoid garbage single-char observables
_MIN_VALUE_LEN = 2


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
        if not value or len(value) < _MIN_VALUE_LEN:
            return
        # Drop well-known noise values
        if value.lower() in _NOISE_VALUES:
            return
        # Drop Windows system SIDs
        if any(value.startswith(prefix) for prefix in _NOISE_SID_PREFIXES):
            return
        # Drop pure numeric values for user/hostname types (PIDs, port numbers leaking in)
        if obs_type in ("target_user", "subject_user", "user_account", "hostname",
                        "source_hostname", "destination_hostname") and value.isdigit():
            return
        if (obs_type, value) not in seen:
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
    _extract_field(["process.parent.name"], "parent_process")
    _extract_field(["process.parent.executable"], "parent_process_path")

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

    return observables
