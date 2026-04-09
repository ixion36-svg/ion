"""MITRE D3FEND coverage service.

D3FEND is the defensive counterpart to MITRE ATT&CK — it catalogs *defensive*
techniques and maps each one to the *offensive* ATT&CK techniques it counters.
This service answers: "given the TIDE rules ION can run, how complete is our
D3FEND defensive coverage?"

The full D3FEND ontology has ~150 techniques. We ship a curated set of common
techniques (the ones SOCs most often discuss) hard-coded here so the page
works in air-gapped environments without network access to d3fend.mitre.org.
The taxonomy can be extended at any time by adding entries to ``D3FEND_CATALOG``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ion.services.tide_service import get_tide_service

logger = logging.getLogger(__name__)


# D3FEND tactics (top-level columns of the matrix)
D3FEND_TACTICS = [
    {"id": "model", "name": "Model", "desc": "Inventory and characterize what you defend"},
    {"id": "harden", "name": "Harden", "desc": "Reduce the attack surface before adversaries arrive"},
    {"id": "detect", "name": "Detect", "desc": "Identify adversary activity"},
    {"id": "isolate", "name": "Isolate", "desc": "Constrain adversary movement"},
    {"id": "deceive", "name": "Deceive", "desc": "Lure adversaries into traps"},
    {"id": "evict", "name": "Evict", "desc": "Remove adversary presence"},
    {"id": "restore", "name": "Restore", "desc": "Return systems to a known good state"},
]


@dataclass
class D3fendTechnique:
    """One D3FEND defensive technique."""
    id: str          # e.g. "D3-FA"
    name: str        # human readable
    tactic: str      # one of D3FEND_TACTICS ids
    description: str
    # ATT&CK technique IDs this defends against (e.g. ["T1003", "T1003.001"])
    counters_attack: List[str] = field(default_factory=list)


# Curated catalog of common D3FEND techniques and their ATT&CK mappings.
# Based on the public MITRE D3FEND → ATT&CK mapping (https://d3fend.mitre.org/).
# Not exhaustive; chosen to give a useful starter coverage view.
D3FEND_CATALOG: List[D3fendTechnique] = [
    # ---- HARDEN -----------------------------------------------------------
    D3fendTechnique(
        id="D3-MFA", name="Multi-Factor Authentication", tactic="harden",
        description="Require multiple factors to authenticate users.",
        counters_attack=["T1078", "T1110", "T1110.001", "T1110.003", "T1556"],
    ),
    D3fendTechnique(
        id="D3-SCP", name="Strong Password Policy", tactic="harden",
        description="Enforce password length, complexity, and rotation rules.",
        counters_attack=["T1110", "T1110.001", "T1110.002", "T1110.003"],
    ),
    D3fendTechnique(
        id="D3-DENCR", name="Disk Encryption", tactic="harden",
        description="Encrypt data at rest on disks and volumes.",
        counters_attack=["T1005", "T1052", "T1052.001"],
    ),
    D3fendTechnique(
        id="D3-MENCR", name="Message Encryption", tactic="harden",
        description="Encrypt data in transit between hosts.",
        counters_attack=["T1040", "T1557", "T1557.002"],
    ),
    D3fendTechnique(
        id="D3-EAL", name="Executable Allowlisting", tactic="harden",
        description="Allow only approved binaries to execute.",
        counters_attack=["T1059", "T1059.001", "T1059.003", "T1204", "T1218"],
    ),
    D3fendTechnique(
        id="D3-DLIC", name="Driver Load Integrity Checking", tactic="harden",
        description="Verify kernel driver signatures before loading.",
        counters_attack=["T1014", "T1547.006"],
    ),

    # ---- DETECT -----------------------------------------------------------
    D3fendTechnique(
        id="D3-PA", name="Process Analysis", tactic="detect",
        description="Inspect running processes for suspicious behaviour.",
        counters_attack=["T1055", "T1055.001", "T1055.002", "T1059", "T1059.001",
                          "T1059.003", "T1059.005", "T1059.007", "T1106"],
    ),
    D3fendTechnique(
        id="D3-FA", name="File Analysis", tactic="detect",
        description="Inspect files (hash, content, metadata) for indicators of compromise.",
        counters_attack=["T1027", "T1027.001", "T1027.002", "T1140", "T1204",
                          "T1204.002", "T1566", "T1566.001"],
    ),
    D3fendTechnique(
        id="D3-NTA", name="Network Traffic Analysis", tactic="detect",
        description="Monitor network flows for command and control or exfiltration.",
        counters_attack=["T1071", "T1071.001", "T1071.004", "T1090", "T1090.001",
                          "T1095", "T1568", "T1571", "T1041"],
    ),
    D3fendTechnique(
        id="D3-UBA", name="User Behavior Analysis", tactic="detect",
        description="Profile user activity and flag deviations.",
        counters_attack=["T1078", "T1078.002", "T1078.003", "T1078.004", "T1136",
                          "T1098"],
    ),
    D3fendTechnique(
        id="D3-RA", name="Registry Analysis", tactic="detect",
        description="Inspect Windows registry for persistence and configuration tampering.",
        counters_attack=["T1547", "T1547.001", "T1547.004", "T1547.009", "T1112"],
    ),
    D3fendTechnique(
        id="D3-SDM", name="System Daemon Monitoring", tactic="detect",
        description="Watch for service / daemon installation and modification.",
        counters_attack=["T1543", "T1543.001", "T1543.002", "T1543.003", "T1543.004"],
    ),
    D3fendTechnique(
        id="D3-SBV", name="Script Block Visibility", tactic="detect",
        description="Capture and inspect interpreter script content (PowerShell ScriptBlock, etc.).",
        counters_attack=["T1059.001", "T1059.003", "T1059.005", "T1059.006", "T1059.007"],
    ),
    D3fendTechnique(
        id="D3-DNSTA", name="DNS Traffic Analysis", tactic="detect",
        description="Inspect DNS queries for tunneling and DGA patterns.",
        counters_attack=["T1071.004", "T1568.002", "T1572"],
    ),
    D3fendTechnique(
        id="D3-LFAM", name="Local File Access Monitoring", tactic="detect",
        description="Audit file reads/writes on hosts.",
        counters_attack=["T1005", "T1083", "T1213", "T1552.001"],
    ),

    # ---- ISOLATE ----------------------------------------------------------
    D3fendTechnique(
        id="D3-NI", name="Network Isolation", tactic="isolate",
        description="Segment networks to limit lateral movement.",
        counters_attack=["T1021", "T1021.001", "T1021.002", "T1021.004", "T1210",
                          "T1570"],
    ),
    D3fendTechnique(
        id="D3-EI", name="Execution Isolation", tactic="isolate",
        description="Sandbox or containerize execution environments.",
        counters_attack=["T1055", "T1059", "T1106", "T1204"],
    ),
    D3fendTechnique(
        id="D3-MA", name="Mandatory Access Control", tactic="isolate",
        description="Enforce policy-based access controls (SELinux, AppArmor).",
        counters_attack=["T1068", "T1548", "T1574", "T1003"],
    ),

    # ---- DECEIVE ----------------------------------------------------------
    D3fendTechnique(
        id="D3-DO", name="Decoy Object", tactic="deceive",
        description="Plant fake files, accounts, or hosts to detect intrusions.",
        counters_attack=["T1083", "T1087", "T1087.001", "T1018", "T1135"],
    ),
    D3fendTechnique(
        id="D3-DST", name="Decoy Session Token", tactic="deceive",
        description="Issue trap tokens that alert on use.",
        counters_attack=["T1078", "T1550", "T1550.001"],
    ),
    D3fendTechnique(
        id="D3-DUC", name="Decoy User Credential", tactic="deceive",
        description="Plant honey credentials in plausible locations.",
        counters_attack=["T1003", "T1552", "T1552.001", "T1555"],
    ),

    # ---- EVICT ------------------------------------------------------------
    D3fendTechnique(
        id="D3-PE", name="Process Eviction", tactic="evict",
        description="Terminate malicious processes.",
        counters_attack=["T1055", "T1059", "T1106"],
    ),
    D3fendTechnique(
        id="D3-CE", name="Credential Eviction", tactic="evict",
        description="Force-rotate compromised credentials and revoke tokens.",
        counters_attack=["T1078", "T1098", "T1110", "T1212", "T1556"],
    ),
    D3fendTechnique(
        id="D3-FE", name="File Eviction", tactic="evict",
        description="Quarantine or delete malicious files.",
        counters_attack=["T1027", "T1105", "T1204", "T1547.001"],
    ),

    # ---- RESTORE ----------------------------------------------------------
    D3fendTechnique(
        id="D3-RS", name="Restore Object", tactic="restore",
        description="Restore corrupted or deleted files from backups.",
        counters_attack=["T1485", "T1486", "T1490", "T1491"],
    ),
    D3fendTechnique(
        id="D3-RUAA", name="Restore User Account Access", tactic="restore",
        description="Re-enable disabled accounts and recover orphaned access.",
        counters_attack=["T1098", "T1531"],
    ),
    D3fendTechnique(
        id="D3-RA2", name="Re-Authentication", tactic="restore",
        description="Force users to re-authenticate after a compromise.",
        counters_attack=["T1078", "T1556", "T1539"],
    ),

    # ---- MODEL ------------------------------------------------------------
    D3fendTechnique(
        id="D3-AI", name="Asset Inventory", tactic="model",
        description="Maintain an accurate inventory of hardware, software, and data assets.",
        counters_attack=["T1018", "T1082", "T1083", "T1213"],
    ),
    D3fendTechnique(
        id="D3-NM", name="Network Mapping", tactic="model",
        description="Maintain authoritative knowledge of the network topology.",
        counters_attack=["T1018", "T1046", "T1135", "T1590"],
    ),
    D3fendTechnique(
        id="D3-OAM", name="Operational Activity Mapping", tactic="model",
        description="Document expected business activity baselines for anomaly detection.",
        counters_attack=["T1078", "T1087", "T1136"],
    ),
]


def _normalize_tid(tid: str) -> str:
    """Strip whitespace, uppercase, and ensure leading T."""
    if not tid:
        return ""
    t = tid.strip().upper()
    return t if t.startswith("T") else f"T{t}"


def _get_tide_attack_techniques() -> Dict[str, int]:
    """Return a dict of {attack_technique_id: enabled_rule_count} from TIDE.

    Both parent and sub-technique IDs are returned. Returns an empty dict if
    TIDE is unreachable so the page can still render with all-blind state.
    """
    svc = get_tide_service()
    if not svc.enabled:
        return {}
    sql = """
    SELECT t.technique_id AS tid, COUNT(*) AS n
    FROM detection_rules dr,
         LATERAL unnest(dr.mitre_ids) AS t(technique_id)
    WHERE dr.enabled = TRUE
      AND dr.space = '{space}'
    GROUP BY t.technique_id
    """.format(space=svc.space)
    try:
        result = svc._query(sql)
    except Exception:
        result = None
    if not result or not result.get("rows"):
        return {}
    counts: Dict[str, int] = {}
    for row in result["rows"]:
        tid = _normalize_tid(row.get("tid") or "")
        if not tid:
            continue
        counts[tid] = (counts.get(tid, 0) or 0) + int(row.get("n") or 0)
    return counts


def _attack_is_covered(attack_tid: str, tide_index: Dict[str, int]) -> int:
    """Return enabled-rule count for an ATT&CK technique, considering sub-technique matches.

    A defensive technique is considered to defend against an ATT&CK ID if there
    is a TIDE rule tagged with that exact ID, OR with a sub-technique
    (e.g. tide has T1059.001, defender lists T1059), OR with the parent
    (defender lists T1059.001, tide has T1059).
    """
    attack_tid = _normalize_tid(attack_tid)
    if not attack_tid:
        return 0
    total = tide_index.get(attack_tid, 0)
    # parent → matches sub-techniques
    if "." not in attack_tid:
        prefix = attack_tid + "."
        for tid, n in tide_index.items():
            if tid.startswith(prefix):
                total += n
    else:
        # sub-technique → also count rules tagged with the parent
        parent = attack_tid.split(".", 1)[0]
        if parent in tide_index:
            total += tide_index[parent]
    return total


def get_d3fend_coverage() -> dict:
    """Compute D3FEND defensive coverage based on the configured TIDE rule set.

    Returns:
        {
          "tactics": [{id, name, desc, technique_count, covered_count, coverage_pct}, ...],
          "techniques": [
            {id, name, tactic, description, counters: [{attack_id, rule_count, covered}],
             coverage_pct, total_attacks, covered_attacks},
            ...
          ],
          "summary": {total_techniques, fully_covered, partial, blind, overall_pct}
        }
    """
    tide_index = _get_tide_attack_techniques()

    techniques_out: List[dict] = []
    tactic_stats: Dict[str, dict] = {
        t["id"]: {**t, "technique_count": 0, "covered_count": 0, "rule_count": 0}
        for t in D3FEND_TACTICS
    }

    fully_covered = 0
    partial = 0
    blind = 0

    for tech in D3FEND_CATALOG:
        counters_out: List[dict] = []
        rule_total = 0
        covered_attacks = 0
        for attack_tid in tech.counters_attack:
            n = _attack_is_covered(attack_tid, tide_index)
            counters_out.append({
                "attack_id": attack_tid,
                "rule_count": n,
                "covered": n > 0,
            })
            rule_total += n
            if n > 0:
                covered_attacks += 1
        total_attacks = len(tech.counters_attack)
        coverage_pct = round((covered_attacks / total_attacks) * 100) if total_attacks else 0

        if total_attacks == 0:
            state = "blind"
            blind += 1
        elif covered_attacks == total_attacks:
            state = "full"
            fully_covered += 1
        elif covered_attacks > 0:
            state = "partial"
            partial += 1
        else:
            state = "blind"
            blind += 1

        techniques_out.append({
            "id": tech.id,
            "name": tech.name,
            "tactic": tech.tactic,
            "description": tech.description,
            "counters": counters_out,
            "total_attacks": total_attacks,
            "covered_attacks": covered_attacks,
            "rule_count": rule_total,
            "coverage_pct": coverage_pct,
            "state": state,
        })

        ts = tactic_stats[tech.tactic]
        ts["technique_count"] += 1
        ts["rule_count"] += rule_total
        if covered_attacks > 0:
            ts["covered_count"] += 1

    # Compute per-tactic %
    for ts in tactic_stats.values():
        ts["coverage_pct"] = (
            round((ts["covered_count"] / ts["technique_count"]) * 100)
            if ts["technique_count"] else 0
        )

    total = len(D3FEND_CATALOG)
    overall_pct = round(((fully_covered + partial * 0.5) / total) * 100) if total else 0

    return {
        "tactics": list(tactic_stats.values()),
        "techniques": techniques_out,
        "summary": {
            "total_techniques": total,
            "fully_covered": fully_covered,
            "partial": partial,
            "blind": blind,
            "overall_pct": overall_pct,
            "tide_enabled": bool(tide_index),
        },
    }
