"""Multi-alert pattern detection service for ION.

Detects attack patterns by grouping alerts by host/user and evaluating
them against predefined pattern definitions. Recommends or auto-starts
playbooks when patterns are detected.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from ion.services.elasticsearch_service import ElasticsearchAlert

logger = logging.getLogger(__name__)


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class PatternDefinition:
    """Defines a multi-alert attack pattern."""

    pattern_id: str
    name: str
    severity: str  # critical, high, medium, low
    recommended_playbook: str  # name of playbook to recommend
    auto_execute: bool
    group_by: str  # "host" or "user"
    evaluate: Callable[[List[ElasticsearchAlert]], bool]
    description: str = ""


@dataclass
class DetectedPattern:
    """Result of a pattern match against a group of alerts."""

    pattern_id: str
    pattern_name: str
    severity: str
    group_by: str
    group_key: str  # the host or user value
    matched_alerts: List[ElasticsearchAlert]
    distinct_rules: Set[str]
    mitre_tactics: Set[str]
    mitre_techniques: Set[str]
    observables: Dict[str, Set[str]]
    recommended_playbook: str
    auto_execute: bool
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for API responses."""
        return {
            "pattern_id": self.pattern_id,
            "pattern_name": self.pattern_name,
            "severity": self.severity,
            "group_by": self.group_by,
            "group_key": self.group_key,
            "alert_count": len(self.matched_alerts),
            "alert_ids": [a.id for a in self.matched_alerts],
            "distinct_rules": sorted(self.distinct_rules),
            "rule_count": len(self.distinct_rules),
            "mitre_tactics": sorted(self.mitre_tactics),
            "tactic_count": len(self.mitre_tactics),
            "mitre_techniques": sorted(self.mitre_techniques),
            "observables": {k: sorted(v) for k, v in self.observables.items()},
            "recommended_playbook": self.recommended_playbook,
            "auto_execute": self.auto_execute,
            "description": self.description,
        }


# ============================================================================
# Pattern Evaluation Functions
# ============================================================================

def _eval_forensics_investigation(alerts: List[ElasticsearchAlert]) -> bool:
    """3+ distinct rules on same host, at least 1 critical/high severity."""
    rules = {a.rule_name for a in alerts if a.rule_name}
    if len(rules) < 3:
        return False
    high_sev = any(a.severity in ("critical", "high") for a in alerts)
    return high_sev


def _eval_active_intrusion(alerts: List[ElasticsearchAlert]) -> bool:
    """Alerts spanning 3+ MITRE tactics on the same host."""
    tactics = {a.mitre_tactic_name for a in alerts if a.mitre_tactic_name}
    return len(tactics) >= 3


def _eval_lateral_movement(alerts: List[ElasticsearchAlert]) -> bool:
    """Lateral movement technique + alerts on 2+ hosts from same source IP."""
    lateral_keywords = [
        "lateral", "pass.the.hash", "pass.the.ticket", "psexec",
        "wmi", "remote.service", "smb", "rdp.hijack",
    ]
    has_lateral = False
    source_ips: Set[str] = set()
    hosts: Set[str] = set()

    for a in alerts:
        tech_name = (a.mitre_technique_name or "").lower()
        tactic_name = (a.mitre_tactic_name or "").lower()
        rule = (a.rule_name or "").lower()
        combined = f"{tech_name} {tactic_name} {rule}"

        if any(kw in combined for kw in lateral_keywords):
            has_lateral = True

        if a.host:
            hosts.add(a.host)

        raw = a.raw_data or {}
        src_ip = (
            raw.get("source", {}).get("ip")
            or raw.get("source_ip")
            or raw.get("src_ip")
        )
        if src_ip and isinstance(src_ip, str):
            source_ips.add(src_ip)

    return has_lateral and len(hosts) >= 2


def _eval_data_exfiltration(alerts: List[ElasticsearchAlert]) -> bool:
    """C2/beacon + exfiltration alerts on same host."""
    c2_keywords = ["command.and.control", "c2", "beacon", "c&c", "callback"]
    exfil_keywords = ["exfiltration", "exfil", "data.theft", "upload", "staging"]

    has_c2 = False
    has_exfil = False

    for a in alerts:
        tactic = (a.mitre_tactic_name or "").lower()
        tech = (a.mitre_technique_name or "").lower()
        rule = (a.rule_name or "").lower()
        combined = f"{tactic} {tech} {rule}"

        if any(kw in combined for kw in c2_keywords):
            has_c2 = True
        if any(kw in combined for kw in exfil_keywords):
            has_exfil = True

    return has_c2 and has_exfil


def _eval_ransomware(alerts: List[ElasticsearchAlert]) -> bool:
    """File encryption/rename + privilege escalation on same host."""
    ransom_keywords = [
        "ransomware", "encrypt", "ransom", "file.rename", "mass.file",
        "crypto", "locker",
    ]
    privesc_keywords = [
        "privilege.escalation", "privesc", "elevation", "uac.bypass",
        "token.manipulation",
    ]

    has_ransom = False
    has_privesc = False

    for a in alerts:
        tactic = (a.mitre_tactic_name or "").lower()
        tech = (a.mitre_technique_name or "").lower()
        rule = (a.rule_name or "").lower()
        combined = f"{tactic} {tech} {rule}"

        if any(kw in combined for kw in ransom_keywords):
            has_ransom = True
        if any(kw in combined for kw in privesc_keywords):
            has_privesc = True

    return has_ransom and has_privesc


def _eval_compromised_account(alerts: List[ElasticsearchAlert]) -> bool:
    """Multiple auth failures + suspicious activity for same user."""
    auth_keywords = [
        "auth", "login", "logon", "brute", "credential", "password",
        "failed.login", "account.lockout",
    ]
    suspicious_keywords = [
        "suspicious", "anomal", "unusual", "impossible.travel",
        "new.device", "off.hours",
    ]

    auth_count = 0
    has_suspicious = False

    for a in alerts:
        rule = (a.rule_name or "").lower()
        tactic = (a.mitre_tactic_name or "").lower()
        tech = (a.mitre_technique_name or "").lower()
        combined = f"{rule} {tactic} {tech}"

        if any(kw in combined for kw in auth_keywords):
            auth_count += 1
        if any(kw in combined for kw in suspicious_keywords):
            has_suspicious = True

    return auth_count >= 2 and has_suspicious


# ============================================================================
# Pattern Detection Service
# ============================================================================

# Global pattern definitions
PATTERNS: List[PatternDefinition] = [
    PatternDefinition(
        pattern_id="forensics_investigation",
        name="Forensics Investigation Required",
        severity="high",
        recommended_playbook="Forensics Investigation",
        auto_execute=False,
        group_by="host",
        evaluate=_eval_forensics_investigation,
        description="Multiple distinct detection rules fired on the same host with at least one critical/high severity alert, indicating potential compromise requiring forensic investigation.",
    ),
    PatternDefinition(
        pattern_id="active_intrusion",
        name="Active Intrusion Detected",
        severity="critical",
        recommended_playbook="Active Intrusion Response",
        auto_execute=True,
        group_by="host",
        evaluate=_eval_active_intrusion,
        description="Alerts spanning 3+ MITRE ATT&CK tactics on the same host suggest an active intrusion progressing through the kill chain.",
    ),
    PatternDefinition(
        pattern_id="lateral_movement",
        name="Lateral Movement Detected",
        severity="high",
        recommended_playbook="Lateral Movement Containment",
        auto_execute=True,
        group_by="host",
        evaluate=_eval_lateral_movement,
        description="Lateral movement techniques detected alongside alerts affecting multiple hosts from the same source.",
    ),
    PatternDefinition(
        pattern_id="data_exfiltration",
        name="Data Exfiltration in Progress",
        severity="critical",
        recommended_playbook="Data Exfiltration Response",
        auto_execute=True,
        group_by="host",
        evaluate=_eval_data_exfiltration,
        description="Command-and-control communication combined with data exfiltration indicators on the same host.",
    ),
    PatternDefinition(
        pattern_id="ransomware",
        name="Ransomware Activity Detected",
        severity="critical",
        recommended_playbook="Ransomware Response",
        auto_execute=True,
        group_by="host",
        evaluate=_eval_ransomware,
        description="File encryption or mass rename activity combined with privilege escalation on the same host.",
    ),
    PatternDefinition(
        pattern_id="compromised_account",
        name="Compromised Account Suspected",
        severity="high",
        recommended_playbook="Compromised Account Investigation",
        auto_execute=False,
        group_by="user",
        evaluate=_eval_compromised_account,
        description="Multiple authentication failures combined with suspicious activity for the same user account.",
    ),
]


class PatternDetectionService:
    """Detects multi-alert attack patterns by grouping alerts."""

    def __init__(self, patterns: Optional[List[PatternDefinition]] = None):
        self.patterns = patterns or PATTERNS

    def detect_patterns(
        self, alerts: List[ElasticsearchAlert]
    ) -> List[DetectedPattern]:
        """Run all pattern evaluations against alerts grouped by host/user.

        Returns a list of DetectedPattern for every matched pattern.
        """
        detected: List[DetectedPattern] = []

        for pattern in self.patterns:
            groups = self._group_alerts_by(alerts, pattern.group_by)

            for group_key, group_alerts in groups.items():
                if not group_key:
                    continue  # skip alerts with no host/user

                if pattern.evaluate(group_alerts):
                    rules = {a.rule_name for a in group_alerts if a.rule_name}
                    tactics = {
                        a.mitre_tactic_name
                        for a in group_alerts
                        if a.mitre_tactic_name
                    }
                    techniques = {
                        a.mitre_technique_name
                        for a in group_alerts
                        if a.mitre_technique_name
                    }
                    observables = self._extract_observables(group_alerts)

                    detected.append(
                        DetectedPattern(
                            pattern_id=pattern.pattern_id,
                            pattern_name=pattern.name,
                            severity=pattern.severity,
                            group_by=pattern.group_by,
                            group_key=group_key,
                            matched_alerts=group_alerts,
                            distinct_rules=rules,
                            mitre_tactics=tactics,
                            mitre_techniques=techniques,
                            observables=observables,
                            recommended_playbook=pattern.recommended_playbook,
                            auto_execute=pattern.auto_execute,
                            description=pattern.description,
                        )
                    )

        return detected

    @staticmethod
    def _group_alerts_by(
        alerts: List[ElasticsearchAlert], field: str
    ) -> Dict[str, List[ElasticsearchAlert]]:
        """Group alerts by the specified field (host or user)."""
        groups: Dict[str, List[ElasticsearchAlert]] = {}
        for alert in alerts:
            key = getattr(alert, field, None)
            if key:
                groups.setdefault(key, []).append(alert)
        return groups

    @staticmethod
    def _extract_observables(
        alerts: List[ElasticsearchAlert],
    ) -> Dict[str, Set[str]]:
        """Extract observable values (IPs, hosts, users, domains) from alerts."""
        obs: Dict[str, Set[str]] = {
            "ips": set(),
            "hosts": set(),
            "users": set(),
            "domains": set(),
        }

        ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

        for a in alerts:
            if a.host:
                obs["hosts"].add(a.host)
            if a.user:
                obs["users"].add(a.user)

            raw = a.raw_data or {}

            # Extract IPs from common fields
            for ip_field in ("source.ip", "destination.ip", "client.ip", "server.ip"):
                parts = ip_field.split(".")
                val = raw
                for p in parts:
                    if isinstance(val, dict):
                        val = val.get(p)
                    else:
                        val = None
                        break
                if isinstance(val, str) and ip_re.match(val):
                    obs["ips"].add(val)
                elif isinstance(val, list):
                    for v in val:
                        if isinstance(v, str) and ip_re.match(v):
                            obs["ips"].add(v)

            src_ip = raw.get("source", {}).get("ip") if isinstance(raw.get("source"), dict) else raw.get("source_ip")
            if isinstance(src_ip, str) and ip_re.match(src_ip):
                obs["ips"].add(src_ip)

            dst_ip = raw.get("destination", {}).get("ip") if isinstance(raw.get("destination"), dict) else raw.get("dest_ip")
            if isinstance(dst_ip, str) and ip_re.match(dst_ip):
                obs["ips"].add(dst_ip)

            # Domains from DNS/URL fields
            dns_name = raw.get("dns", {}).get("question", {}).get("name") if isinstance(raw.get("dns"), dict) else None
            if dns_name and isinstance(dns_name, str):
                obs["domains"].add(dns_name)

            url_domain = raw.get("url", {}).get("domain") if isinstance(raw.get("url"), dict) else None
            if url_domain and isinstance(url_domain, str):
                obs["domains"].add(url_domain)

        return obs


# ============================================================================
# Seed Default Playbooks
# ============================================================================

def seed_default_playbooks() -> None:
    """Create the 6 default pattern-based playbooks if they don't already exist.

    Idempotent - checks by name before creating.
    """
    from ion.storage.database import get_engine, get_session_factory
    from ion.storage.playbook_repository import PlaybookRepository
    from ion.models.playbook import StepType
    from ion.storage.user_repository import UserRepository
    from ion.auth.service import AuthService

    engine = get_engine()
    factory = get_session_factory(engine)
    session = factory()

    try:
        repo = PlaybookRepository(session)

        # Get or create system user for seeded playbooks
        user_repo = UserRepository(session)
        system_user = user_repo.get_by_username("admin")
        if not system_user:
            # Use the first available user
            users = user_repo.list_all()
            if users:
                system_user = users[0]
            else:
                # Seed the default admin user so playbooks can be created
                auth_service = AuthService(session)
                system_user = auth_service.seed_admin_user()
                if not system_user:
                    logger.warning("Could not create admin user - cannot seed playbooks")
                    return

        user_id = system_user.id

        playbook_defs = [
            {
                "name": "Forensics Investigation",
                "description": "Full forensic investigation workflow for hosts with multiple alert detections indicating potential compromise.",
                "priority": 90,
                "trigger_conditions": {
                    "pattern_id": "forensics_investigation",
                    "severities": ["critical", "high"],
                },
                "steps": [
                    {
                        "title": "Isolate affected host",
                        "description": "Network-isolate the host via EDR or switch port. Confirm isolation is effective before proceeding.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Enrich observables",
                        "description": "Auto-enrich all IPs, domains, and hashes associated with the alerts through threat intelligence sources.",
                        "step_type": StepType.AUTO_ENRICH_OBSERVABLES.value,
                        "is_required": True,
                    },
                    {
                        "title": "Capture volatile evidence",
                        "description": "Capture memory dump and running process list. Collect network connections, scheduled tasks, and autoruns.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Preserve log artifacts",
                        "description": "Export Windows Event Logs, Sysmon, PowerShell logs. Preserve web proxy and firewall logs for the host.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Analyze timeline",
                        "description": "Construct a timeline of events from first alert to present. Identify initial access vector and attacker actions.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Create investigation case",
                        "description": "Create a formal investigation case with all evidence and findings documented.",
                        "step_type": StepType.AUTO_CREATE_CASE.value,
                        "is_required": True,
                    },
                ],
            },
            {
                "name": "Active Intrusion Response",
                "description": "Immediate incident response for active intrusions spanning multiple MITRE ATT&CK tactics.",
                "priority": 95,
                "trigger_conditions": {
                    "pattern_id": "active_intrusion",
                    "severities": ["critical"],
                },
                "steps": [
                    {
                        "title": "Confirm intrusion indicators",
                        "description": "Verify alerts are true positives. Check for persistence mechanisms, C2 callbacks, and lateral movement.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Activate IR team",
                        "description": "Notify SOC lead, escalate to IR team. Establish war-room communication channel.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Isolate compromised hosts",
                        "description": "Network-isolate all hosts showing intrusion activity. Block identified malicious IPs at perimeter.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Enrich IOCs",
                        "description": "Auto-enrich all indicators of compromise through threat intelligence feeds.",
                        "step_type": StepType.AUTO_ENRICH_OBSERVABLES.value,
                        "is_required": True,
                    },
                    {
                        "title": "Identify full scope",
                        "description": "Hunt across all endpoints for related indicators. Determine all compromised systems and accounts.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Eradicate and restore",
                        "description": "Remove attacker access, reset compromised credentials, patch exploited vulnerabilities. Restore from clean backups.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Create incident case",
                        "description": "Document the full incident with timeline, impact assessment, and remediation actions taken.",
                        "step_type": StepType.AUTO_CREATE_CASE.value,
                        "is_required": True,
                    },
                ],
            },
            {
                "name": "Lateral Movement Containment",
                "description": "Containment playbook for detected lateral movement across hosts.",
                "priority": 85,
                "trigger_conditions": {
                    "pattern_id": "lateral_movement",
                    "mitre_tactics": ["Lateral Movement"],
                },
                "steps": [
                    {
                        "title": "Map affected hosts",
                        "description": "Identify all hosts involved in lateral movement. Document source and destination hosts and the methods used.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Block lateral movement paths",
                        "description": "Disable SMB, WMI, RDP, or other protocols used for lateral movement between affected segments.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Enrich source indicators",
                        "description": "Auto-enrich source IPs, tools, and hashes used in lateral movement.",
                        "step_type": StepType.AUTO_ENRICH_OBSERVABLES.value,
                        "is_required": True,
                    },
                    {
                        "title": "Check for persistence",
                        "description": "Check all affected hosts for persistence mechanisms (scheduled tasks, services, registry keys, WMI subscriptions).",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Reset compromised credentials",
                        "description": "Reset passwords for all accounts used in lateral movement. Revoke Kerberos tickets if applicable.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Document and close",
                        "description": "Create a case documenting the lateral movement path, containment actions, and credential resets performed.",
                        "step_type": StepType.AUTO_CREATE_CASE.value,
                        "is_required": True,
                    },
                ],
            },
            {
                "name": "Data Exfiltration Response",
                "description": "Response playbook for detected data exfiltration with C2 communication.",
                "priority": 92,
                "trigger_conditions": {
                    "pattern_id": "data_exfiltration",
                    "mitre_tactics": ["Command and Control", "Exfiltration"],
                },
                "steps": [
                    {
                        "title": "Isolate affected host",
                        "description": "Immediately network-isolate the host to stop any ongoing data exfiltration.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Assess data exposure",
                        "description": "Identify what data may have been exfiltrated. Check file access logs, DLP alerts, and data classification.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Enrich C2 indicators",
                        "description": "Auto-enrich C2 domains, IPs, and communication patterns through threat intelligence.",
                        "step_type": StepType.AUTO_ENRICH_OBSERVABLES.value,
                        "is_required": True,
                    },
                    {
                        "title": "Block C2 infrastructure",
                        "description": "Block all identified C2 domains and IPs at DNS, proxy, and firewall levels.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Notify data protection officer",
                        "description": "If PII or sensitive data was potentially exfiltrated, notify DPO and legal team per breach notification policy.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": False,
                    },
                    {
                        "title": "Create exfiltration case",
                        "description": "Create a formal case with data exposure assessment, IOCs, and remediation timeline.",
                        "step_type": StepType.AUTO_CREATE_CASE.value,
                        "is_required": True,
                    },
                ],
            },
            {
                "name": "Ransomware Response",
                "description": "Emergency response playbook for ransomware activity detection.",
                "priority": 99,
                "trigger_conditions": {
                    "pattern_id": "ransomware",
                    "severities": ["critical"],
                },
                "steps": [
                    {
                        "title": "Isolate host and disable shares",
                        "description": "Immediately isolate the host. Disable network shares and mapped drives to prevent spread. Consider disabling SMBv1 network-wide.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Identify ransomware variant",
                        "description": "Collect ransom note and encrypted file samples. Identify the ransomware family and check for known decryptors.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Assess blast radius",
                        "description": "Determine how many hosts and file shares are affected. Check backup integrity and availability.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Enrich ransomware indicators",
                        "description": "Auto-enrich hashes, C2 domains, and bitcoin addresses through threat intelligence feeds.",
                        "step_type": StepType.AUTO_ENRICH_OBSERVABLES.value,
                        "is_required": True,
                    },
                    {
                        "title": "Activate business continuity plan",
                        "description": "Notify management and activate BCP. Coordinate with legal regarding ransom demand. Engage law enforcement if required.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Restore and recover",
                        "description": "Restore affected systems from clean backups. Rebuild compromised hosts. Verify integrity of restored data.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Create ransomware incident case",
                        "description": "Document full incident: initial vector, scope, impact, recovery actions, and lessons learned.",
                        "step_type": StepType.AUTO_CREATE_CASE.value,
                        "is_required": True,
                    },
                ],
            },
            {
                "name": "Compromised Account Investigation",
                "description": "Investigation playbook for suspected compromised user accounts.",
                "priority": 80,
                "trigger_conditions": {
                    "pattern_id": "compromised_account",
                    "mitre_tactics": ["Initial Access", "Credential Access"],
                },
                "steps": [
                    {
                        "title": "Disable suspected account",
                        "description": "Temporarily disable the user account in Active Directory / IdP to prevent further unauthorized access.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Review authentication logs",
                        "description": "Review successful and failed logins. Check for impossible travel, unusual source IPs, or off-hours access.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Enrich source IPs",
                        "description": "Auto-enrich all source IPs associated with the account through threat intelligence and geolocation.",
                        "step_type": StepType.AUTO_ENRICH_OBSERVABLES.value,
                        "is_required": True,
                    },
                    {
                        "title": "Check for unauthorized access",
                        "description": "Review what resources the account accessed during the suspicious period. Check email rules, file access, and admin actions.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Reset credentials and MFA",
                        "description": "Reset the account password, revoke all sessions, and re-enroll MFA. Check for any credential harvesting tools.",
                        "step_type": StepType.MANUAL_CHECKLIST.value,
                        "is_required": True,
                    },
                    {
                        "title": "Document investigation",
                        "description": "Create a case with investigation findings, account activity timeline, and remediation actions.",
                        "step_type": StepType.AUTO_CREATE_CASE.value,
                        "is_required": True,
                    },
                ],
            },
        ]

        created_count = 0
        for pb_def in playbook_defs:
            existing = repo.get_playbook_by_name(pb_def["name"])
            if existing:
                continue

            playbook = repo.create_playbook(
                name=pb_def["name"],
                description=pb_def["description"],
                trigger_conditions=pb_def["trigger_conditions"],
                priority=pb_def["priority"],
                created_by_id=user_id,
                is_active=True,
            )

            for order, step_data in enumerate(pb_def["steps"], start=1):
                repo.add_step(
                    playbook=playbook,
                    step_type=step_data["step_type"],
                    title=step_data["title"],
                    description=step_data.get("description"),
                    step_order=order,
                    is_required=step_data.get("is_required", False),
                )

            created_count += 1

        session.commit()
        if created_count:
            logger.info("Seeded %d default pattern playbooks", created_count)

    except Exception as e:
        session.rollback()
        logger.error("Failed to seed default playbooks: %s", e)
    finally:
        session.close()
