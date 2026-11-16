"""Security Assurance Levels, as docs/CyAB_SAL.md defines them.

The UI offered SAL 1 to 3 while the document defines five levels, and the
level changed nothing: every system had the same three critical documents and
the same 90-day review. Here the level decides which checklist documents are
required (section 8.1), how often the system is reviewed (9.2), and who may
accept a gap and for how long (12.2).
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Tuple

LEVELS: Tuple[str, ...] = ("SAL-1", "SAL-2", "SAL-3", "SAL-4", "SAL-5")
NAMES: Dict[str, str] = {
    "SAL-1": "Foundation",
    "SAL-2": "Standard",
    "SAL-3": "Enhanced",
    "SAL-4": "Critical",
    "SAL-5": "Maximum",
}
DEFAULT = "SAL-2"

# Always required: the three items the checklist has always marked critical.
_BASE: FrozenSet[str] = frozenset({"HLD", "NETWORK_TOPOLOGY", "OWNERS"})

# Section 8.1, mapped onto the checklist's document kinds. "Recommended"
# entries are not required; "lightweight" ones are.
_REQUIRED: Dict[str, FrozenSet[str]] = {
    "SAL-1": frozenset({"CMDB"}),
    "SAL-2": frozenset({"CMDB", "RISK_ASSESSMENT"}),
    "SAL-3": frozenset({"CMDB", "RISK_ASSESSMENT", "DATA_FLOW", "IR_PLAN",
                        "VULN_REPORT", "COMPLIANCE_MAPPING"}),
    "SAL-4": frozenset({"CMDB", "RISK_ASSESSMENT", "DATA_FLOW", "IR_PLAN",
                        "VULN_REPORT", "COMPLIANCE_MAPPING", "THREAT_MODEL",
                        "DECOMMISSIONING"}),
}
_REQUIRED["SAL-5"] = _REQUIRED["SAL-4"]

# Section 9.2: the full assurance review interval.
REVIEW_DAYS: Dict[str, int] = {"SAL-1": 730, "SAL-2": 365, "SAL-3": 365, "SAL-4": 182, "SAL-5": 91}

# Section 12.2: who may accept a gap, and the longest an acceptance may run
# before it is reviewed again.
APPROVER: Dict[str, str] = {
    "SAL-1": "System owner",
    "SAL-2": "System owner",
    "SAL-3": "Cyber Assurance Manager",
    "SAL-4": "CISO",
    "SAL-5": "Board-level sponsor",
}
MAX_EXCEPTION_DAYS: Dict[str, int] = {"SAL-1": 365, "SAL-2": 365, "SAL-3": 182, "SAL-4": 91, "SAL-5": 90}


def normalise(level: object) -> str:
    """A stored level as one of LEVELS. "SAL3", "3" and "sal-3" all read as SAL-3."""
    text = str(level or "").strip().upper().replace("SAL", "").strip("- ")
    candidate = f"SAL-{text}"
    return candidate if candidate in LEVELS else DEFAULT


def required_kinds(level: object) -> FrozenSet[str]:
    return _BASE | _REQUIRED[normalise(level)]


def is_required(kind: str, is_critical: bool, level: object) -> bool:
    return bool(is_critical) or kind in required_kinds(level)
