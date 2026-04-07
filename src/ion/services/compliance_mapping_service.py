"""Compliance mapping service — maps TIDE detection rules to NIST CSF controls."""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

NIST_CSF_MAPPING = {
    "DE.CM-1": {"name": "Network Monitoring", "techniques": ["T1071", "T1572", "T1573", "T1095", "T1571"]},
    "DE.CM-3": {"name": "Personnel Activity Monitoring", "techniques": ["T1078", "T1133", "T1098"]},
    "DE.CM-4": {"name": "Malicious Code Detection", "techniques": ["T1059", "T1204", "T1566", "T1189"]},
    "DE.CM-5": {"name": "Unauthorized Mobile Code Detection", "techniques": ["T1204", "T1059.007"]},
    "DE.CM-7": {"name": "Unauthorized Personnel/Connections/Devices", "techniques": ["T1200", "T1091"]},
    "DE.AE-2": {"name": "Analyzed Events for Attack Patterns", "techniques": ["T1190", "T1210", "T1212"]},
    "DE.AE-3": {"name": "Event Data Aggregation and Correlation", "techniques": ["T1114", "T1119", "T1005"]},
    "PR.AC-1": {"name": "Identity and Credential Management", "techniques": ["T1078", "T1110", "T1003"]},
    "PR.AC-3": {"name": "Remote Access Management", "techniques": ["T1021", "T1133", "T1219"]},
    "PR.AC-4": {"name": "Access Permissions and Authorizations", "techniques": ["T1068", "T1548", "T1134"]},
    "PR.DS-5": {"name": "Data Leak Prevention", "techniques": ["T1048", "T1041", "T1567"]},
    "PR.PT-1": {"name": "Audit/Log Records", "techniques": ["T1070", "T1562"]},
    "RS.AN-1": {"name": "Notifications from Detection Systems", "techniques": ["T1486", "T1490", "T1489"]},
}


def get_compliance_posture(tide_service) -> dict:
    if not tide_service.enabled:
        return {"error": "TIDE not configured"}

    try:
        coverage = tide_service.get_global_mitre_coverage()
    except Exception:
        logger.exception("Failed to retrieve MITRE coverage from TIDE")
        return {"error": "TIDE not configured"}

    if not coverage:
        return {"error": "TIDE not configured"}

    techniques_data = coverage.get("techniques", {})
    covered_technique_ids: set[str] = set()
    for tid, info in techniques_data.items():
        if info.get("rule_count", 0) > 0:
            covered_technique_ids.add(tid)

    controls: list[dict] = []
    total_score = 0
    fully_covered = 0
    partial = 0
    no_coverage = 0

    for control_id, mapping in NIST_CSF_MAPPING.items():
        required = mapping["techniques"]
        total = len(required)

        covered_techs = []
        gap_techs = []
        for tid in required:
            parent = tid.split(".")[0]
            if tid in covered_technique_ids or parent in covered_technique_ids:
                covered_techs.append(tid)
            else:
                gap_techs.append(tid)

        score = int(len(covered_techs) / total * 100) if total > 0 else 0
        total_score += score

        if score == 100:
            fully_covered += 1
        elif score > 0:
            partial += 1
        else:
            no_coverage += 1

        controls.append({
            "control_id": control_id,
            "name": mapping["name"],
            "score": score,
            "covered": len(covered_techs),
            "total": total,
            "covered_techniques": covered_techs,
            "gap_techniques": gap_techs,
        })

    overall_score = int(total_score / len(NIST_CSF_MAPPING)) if NIST_CSF_MAPPING else 0

    return {
        "framework": "NIST CSF",
        "overall_score": overall_score,
        "controls": controls,
        "summary": {
            "fully_covered": fully_covered,
            "partial": partial,
            "no_coverage": no_coverage,
        },
    }
