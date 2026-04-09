"""Compliance mapping service.

Maps detection coverage (TIDE rules → MITRE ATT&CK techniques) to control
catalogues from popular compliance frameworks. Supports multiple frameworks
in parallel; the per-framework mapping is hard-coded so the page works in
air-gapped deployments without network access.

The mappings are deliberately curated (the SOC-relevant subset of each
framework, not every control) and can be extended at any time by appending
to ``FRAMEWORKS``.

Public API:
    list_frameworks() -> list[dict]                 # framework metadata
    get_framework(id) -> dict | None                # all controls for one framework
    get_compliance_posture(tide, fid='nist_csf')    # compute coverage scorecard
    get_compliance_posture_legacy(tide)             # NIST CSF for backwards compat
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Framework catalogues
# ---------------------------------------------------------------------------
#
# Each framework is a dict:
#     {
#       "id":          short slug used in URLs
#       "name":        human readable
#       "version":     version string (e.g. "v8")
#       "description": one-line summary
#       "url":         official spec URL (informational)
#       "controls":    list of {id, name, description?, techniques: [...]}
#     }
#
# `techniques` are MITRE ATT&CK technique IDs the control depends on for
# detection. A control is "fully covered" if every listed technique has at
# least one TIDE rule mapped to it (parent or sub-technique).

NIST_CSF = {
    "id": "nist_csf",
    "name": "NIST Cybersecurity Framework",
    "version": "1.1",
    "description": "US framework for managing and reducing cybersecurity risk.",
    "url": "https://www.nist.gov/cyberframework",
    "controls": [
        {"id": "DE.CM-1", "name": "Network Monitoring",
         "techniques": ["T1071", "T1572", "T1573", "T1095", "T1571"]},
        {"id": "DE.CM-3", "name": "Personnel Activity Monitoring",
         "techniques": ["T1078", "T1133", "T1098"]},
        {"id": "DE.CM-4", "name": "Malicious Code Detection",
         "techniques": ["T1059", "T1204", "T1566", "T1189"]},
        {"id": "DE.CM-5", "name": "Unauthorized Mobile Code Detection",
         "techniques": ["T1204", "T1059.007"]},
        {"id": "DE.CM-7", "name": "Unauthorized Personnel/Connections/Devices",
         "techniques": ["T1200", "T1091"]},
        {"id": "DE.AE-2", "name": "Analyzed Events for Attack Patterns",
         "techniques": ["T1190", "T1210", "T1212"]},
        {"id": "DE.AE-3", "name": "Event Data Aggregation and Correlation",
         "techniques": ["T1114", "T1119", "T1005"]},
        {"id": "PR.AC-1", "name": "Identity and Credential Management",
         "techniques": ["T1078", "T1110", "T1003"]},
        {"id": "PR.AC-3", "name": "Remote Access Management",
         "techniques": ["T1021", "T1133", "T1219"]},
        {"id": "PR.AC-4", "name": "Access Permissions and Authorizations",
         "techniques": ["T1068", "T1548", "T1134"]},
        {"id": "PR.DS-5", "name": "Data Leak Prevention",
         "techniques": ["T1048", "T1041", "T1567"]},
        {"id": "PR.PT-1", "name": "Audit/Log Records",
         "techniques": ["T1070", "T1562"]},
        {"id": "RS.AN-1", "name": "Notifications from Detection Systems",
         "techniques": ["T1486", "T1490", "T1489"]},
    ],
}


NIST_800_53 = {
    "id": "nist_800_53",
    "name": "NIST SP 800-53 (Moderate Baseline)",
    "version": "Rev 5",
    "description": "US federal control catalog. The Moderate baseline subset relevant to a SOC.",
    "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    "controls": [
        {"id": "AC-2", "name": "Account Management",
         "techniques": ["T1078", "T1098", "T1136"]},
        {"id": "AC-6", "name": "Least Privilege",
         "techniques": ["T1068", "T1134", "T1548"]},
        {"id": "AC-7", "name": "Unsuccessful Logon Attempts",
         "techniques": ["T1110", "T1110.001", "T1110.003"]},
        {"id": "AC-17", "name": "Remote Access",
         "techniques": ["T1021", "T1133", "T1021.001", "T1021.004"]},
        {"id": "AU-2", "name": "Event Logging",
         "techniques": ["T1070", "T1562", "T1562.001"]},
        {"id": "AU-6", "name": "Audit Record Review, Analysis, and Reporting",
         "techniques": ["T1078", "T1098", "T1136", "T1531"]},
        {"id": "AU-12", "name": "Audit Record Generation",
         "techniques": ["T1070", "T1070.001", "T1070.002", "T1562.002"]},
        {"id": "CM-2", "name": "Baseline Configuration",
         "techniques": ["T1543", "T1547", "T1037"]},
        {"id": "CM-7", "name": "Least Functionality",
         "techniques": ["T1059", "T1218", "T1127"]},
        {"id": "IA-5", "name": "Authenticator Management",
         "techniques": ["T1003", "T1552", "T1555", "T1110"]},
        {"id": "IR-4", "name": "Incident Handling",
         "techniques": ["T1486", "T1485", "T1490"]},
        {"id": "IR-6", "name": "Incident Reporting",
         "techniques": ["T1486", "T1490", "T1491"]},
        {"id": "SC-7", "name": "Boundary Protection",
         "techniques": ["T1071", "T1090", "T1572", "T1571"]},
        {"id": "SC-8", "name": "Transmission Confidentiality and Integrity",
         "techniques": ["T1040", "T1557", "T1573"]},
        {"id": "SI-3", "name": "Malicious Code Protection",
         "techniques": ["T1204", "T1059", "T1027", "T1566"]},
        {"id": "SI-4", "name": "Information System Monitoring",
         "techniques": ["T1071", "T1572", "T1003", "T1110", "T1486"]},
        {"id": "SI-7", "name": "Software, Firmware, and Information Integrity",
         "techniques": ["T1027", "T1140", "T1543", "T1547"]},
    ],
}


ISO_27001 = {
    "id": "iso_27001",
    "name": "ISO/IEC 27001:2022 Annex A",
    "version": "2022",
    "description": "International information security management standard. SOC-relevant Annex A controls.",
    "url": "https://www.iso.org/standard/27001",
    "controls": [
        {"id": "A.5.7", "name": "Threat intelligence",
         "techniques": ["T1071", "T1190", "T1566", "T1078"]},
        {"id": "A.5.23", "name": "Information security for use of cloud services",
         "techniques": ["T1078.004", "T1098.001", "T1530"]},
        {"id": "A.5.24", "name": "Information security incident management planning and preparation",
         "techniques": ["T1486", "T1490", "T1485"]},
        {"id": "A.5.25", "name": "Assessment and decision on information security events",
         "techniques": ["T1190", "T1210", "T1212"]},
        {"id": "A.5.26", "name": "Response to information security incidents",
         "techniques": ["T1486", "T1490", "T1491", "T1489"]},
        {"id": "A.5.28", "name": "Collection of evidence",
         "techniques": ["T1070", "T1070.001", "T1070.002", "T1070.003"]},
        {"id": "A.6.8", "name": "Information security event reporting",
         "techniques": ["T1486", "T1490", "T1485"]},
        {"id": "A.8.7", "name": "Protection against malware",
         "techniques": ["T1204", "T1059", "T1027", "T1566", "T1140"]},
        {"id": "A.8.8", "name": "Management of technical vulnerabilities",
         "techniques": ["T1190", "T1203", "T1068"]},
        {"id": "A.8.15", "name": "Logging",
         "techniques": ["T1070", "T1562", "T1562.001", "T1562.002"]},
        {"id": "A.8.16", "name": "Monitoring activities",
         "techniques": ["T1071", "T1003", "T1110", "T1078", "T1486"]},
        {"id": "A.8.20", "name": "Networks security",
         "techniques": ["T1071", "T1572", "T1090", "T1571", "T1573"]},
        {"id": "A.8.23", "name": "Web filtering",
         "techniques": ["T1189", "T1566.002", "T1071.001"]},
    ],
}


PCI_DSS_V4 = {
    "id": "pci_dss_v4",
    "name": "PCI DSS v4.0",
    "version": "4.0",
    "description": "Payment Card Industry Data Security Standard. SOC-relevant requirements.",
    "url": "https://www.pcisecuritystandards.org/document_library/",
    "controls": [
        {"id": "Req 8.3.1", "name": "Strong authentication for all access",
         "techniques": ["T1078", "T1110", "T1110.001", "T1110.003"]},
        {"id": "Req 10.2.1", "name": "Audit logs capture all individual user access events",
         "techniques": ["T1078", "T1136", "T1098"]},
        {"id": "Req 10.2.2", "name": "Audit logs capture privileged actions",
         "techniques": ["T1068", "T1134", "T1548", "T1543"]},
        {"id": "Req 10.2.5", "name": "Audit logs capture changes to identification and authentication",
         "techniques": ["T1098", "T1556", "T1110"]},
        {"id": "Req 10.2.6", "name": "Audit logs capture initialization, stopping, or pausing of audit logs",
         "techniques": ["T1070", "T1070.001", "T1562.002"]},
        {"id": "Req 10.4.1", "name": "Audit logs reviewed at least daily",
         "techniques": ["T1071", "T1003", "T1486", "T1490"]},
        {"id": "Req 10.7.1", "name": "Failure of critical security control systems detected",
         "techniques": ["T1562", "T1562.001", "T1562.002", "T1562.004"]},
        {"id": "Req 11.5.1", "name": "Intrusion detection / prevention",
         "techniques": ["T1071", "T1572", "T1190", "T1210"]},
        {"id": "Req 11.5.2", "name": "Change-detection mechanism",
         "techniques": ["T1027", "T1140", "T1543", "T1547"]},
        {"id": "Req 12.10.1", "name": "Incident response plan exists",
         "techniques": ["T1486", "T1490", "T1491"]},
        {"id": "Req 12.10.5", "name": "IR plan includes monitoring + response to alerts",
         "techniques": ["T1071", "T1003", "T1078", "T1486"]},
    ],
}


CIS_V8 = {
    "id": "cis_v8",
    "name": "CIS Controls v8",
    "version": "8",
    "description": "Center for Internet Security controls. Pragmatic, prioritised SOC-relevant subset.",
    "url": "https://www.cisecurity.org/controls/v8",
    "controls": [
        {"id": "1.1", "name": "Establish & Maintain Detailed Enterprise Asset Inventory",
         "techniques": ["T1018", "T1082", "T1083"]},
        {"id": "5.1", "name": "Establish & Maintain an Inventory of Accounts",
         "techniques": ["T1078", "T1136", "T1098", "T1087"]},
        {"id": "6.1", "name": "Establish an Access Granting Process",
         "techniques": ["T1078", "T1098"]},
        {"id": "6.2", "name": "Establish an Access Revoking Process",
         "techniques": ["T1078", "T1098", "T1531"]},
        {"id": "6.3", "name": "Require MFA for Externally-Exposed Applications",
         "techniques": ["T1078", "T1110", "T1133", "T1556"]},
        {"id": "8.2", "name": "Collect Audit Logs",
         "techniques": ["T1070", "T1562"]},
        {"id": "8.5", "name": "Collect Detailed Audit Logs",
         "techniques": ["T1070", "T1059", "T1078", "T1086"]},
        {"id": "8.11", "name": "Conduct Audit Log Reviews",
         "techniques": ["T1078", "T1003", "T1110", "T1486"]},
        {"id": "10.2", "name": "Configure Automatic Anti-Malware Signature Updates",
         "techniques": ["T1027", "T1140", "T1204"]},
        {"id": "13.1", "name": "Centralize Security Event Alerting",
         "techniques": ["T1071", "T1572", "T1003", "T1486"]},
        {"id": "13.6", "name": "Collect Network Traffic Flow Logs",
         "techniques": ["T1071", "T1572", "T1571", "T1095"]},
        {"id": "17.1", "name": "Designate Personnel to Manage Incident Handling",
         "techniques": ["T1486", "T1490"]},
        {"id": "17.6", "name": "Define Mechanisms for Communicating During Incident Response",
         "techniques": ["T1486", "T1490", "T1491"]},
    ],
}


# Master registry — append new frameworks here.
FRAMEWORKS: list[dict] = [
    NIST_CSF,
    NIST_800_53,
    ISO_27001,
    PCI_DSS_V4,
    CIS_V8,
]
_FRAMEWORK_INDEX = {f["id"]: f for f in FRAMEWORKS}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_frameworks() -> list[dict]:
    """Return metadata for every framework (no controls — small payload)."""
    return [
        {
            "id": f["id"],
            "name": f["name"],
            "version": f["version"],
            "description": f["description"],
            "url": f["url"],
            "control_count": len(f["controls"]),
        }
        for f in FRAMEWORKS
    ]


def get_framework(framework_id: str) -> Optional[dict]:
    """Return the full framework dict (including controls)."""
    return _FRAMEWORK_INDEX.get(framework_id)


def _covered_techniques(tide_service) -> set[str]:
    """Pull the set of MITRE technique IDs that have at least one TIDE rule."""
    if not tide_service or not tide_service.enabled:
        return set()
    try:
        coverage = tide_service.get_global_mitre_coverage()
    except Exception:
        logger.exception("Failed to retrieve MITRE coverage from TIDE")
        return set()
    if not coverage:
        return set()
    techniques_data = coverage.get("techniques", {})
    return {
        tid for tid, info in techniques_data.items()
        if (info or {}).get("rule_count", 0) > 0
    }


def _score_framework(framework: dict, covered: set[str]) -> dict:
    """Compute the per-control + overall score for one framework."""
    controls_out: list[dict] = []
    total_score = 0
    fully_covered = 0
    partial = 0
    no_coverage = 0

    for c in framework["controls"]:
        required = c.get("techniques") or []
        total = len(required)

        covered_techs: list[str] = []
        gap_techs: list[str] = []
        for tid in required:
            parent = tid.split(".")[0]
            if tid in covered or parent in covered:
                covered_techs.append(tid)
            else:
                gap_techs.append(tid)

        score = int(len(covered_techs) / total * 100) if total > 0 else 0
        total_score += score

        if total == 0:
            state = "unknown"
        elif score == 100:
            state = "covered"
            fully_covered += 1
        elif score > 0:
            state = "partial"
            partial += 1
        else:
            state = "blind"
            no_coverage += 1

        controls_out.append({
            "control_id": c["id"],
            "name": c["name"],
            "description": c.get("description"),
            "score": score,
            "state": state,
            "covered": len(covered_techs),
            "total": total,
            "covered_techniques": covered_techs,
            "gap_techniques": gap_techs,
        })

    overall_score = int(total_score / len(framework["controls"])) if framework["controls"] else 0

    return {
        "framework_id": framework["id"],
        "framework": framework["name"],
        "version": framework["version"],
        "url": framework["url"],
        "overall_score": overall_score,
        "controls": controls_out,
        "summary": {
            "fully_covered": fully_covered,
            "partial": partial,
            "no_coverage": no_coverage,
            "total_controls": len(framework["controls"]),
        },
    }


def get_compliance_posture(tide_service, framework_id: str = "nist_csf") -> dict:
    """Compute the posture scorecard for one framework."""
    framework = _FRAMEWORK_INDEX.get(framework_id)
    if not framework:
        return {"error": f"Unknown framework: {framework_id}"}
    if not tide_service or not tide_service.enabled:
        return {"error": "TIDE not configured", "framework_id": framework_id}
    covered = _covered_techniques(tide_service)
    if not covered:
        return {"error": "TIDE returned no coverage data", "framework_id": framework_id}
    return _score_framework(framework, covered)


def get_all_postures(tide_service) -> dict:
    """Compute scorecards for every framework in one TIDE round-trip."""
    if not tide_service or not tide_service.enabled:
        return {"error": "TIDE not configured", "frameworks": []}
    covered = _covered_techniques(tide_service)
    if not covered:
        return {"error": "TIDE returned no coverage data", "frameworks": []}
    return {
        "frameworks": [_score_framework(f, covered) for f in FRAMEWORKS],
    }


# ---------------------------------------------------------------------------
# Backwards-compatibility shim
# ---------------------------------------------------------------------------

def get_compliance_posture_legacy(tide_service) -> dict:
    """Legacy entry point — original NIST CSF scoring with the old response shape.

    Kept so existing callers (and the original /api/compliance/nist-posture
    endpoint) keep working while new callers move to get_compliance_posture().
    """
    posture = get_compliance_posture(tide_service, "nist_csf")
    if "error" in posture:
        return posture
    # Original shape returned "framework" as a string and didn't include
    # framework_id / version / url / state. Keep parity for old callers.
    return {
        "framework": posture["framework"],
        "overall_score": posture["overall_score"],
        "controls": [
            {k: v for k, v in c.items() if k not in ("state", "description")}
            for c in posture["controls"]
        ],
        "summary": {
            "fully_covered": posture["summary"]["fully_covered"],
            "partial": posture["summary"]["partial"],
            "no_coverage": posture["summary"]["no_coverage"],
        },
    }
