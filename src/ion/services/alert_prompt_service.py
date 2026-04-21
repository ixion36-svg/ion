"""Alert-prompt template service.

Resolves the best-matching AlertPromptTemplate for an incoming alert dict
and renders a merged system prompt combining ION's base security prompt
(from ``ollama_service.SYSTEM_PROMPTS["security"]``) with the per-rule
investigation guide and checklist.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from sqlalchemy.orm import Session

from ion.models.alert_prompt import AlertPromptTemplate
from ion.storage.alert_prompt_repository import AlertPromptRepository

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Default seed templates — ~5 defaults for common Elastic Security rule groups.
# Each prompt_text + checklist is kept under 400 words.
# ---------------------------------------------------------------------------

_DEFAULT_TEMPLATES: list[dict] = [
    {
        "name": "Sysmon Event 1 — Process Creation",
        "description": (
            "Investigation guide for Sysmon process-creation telemetry "
            "(EventID 1). Focus on parent/child chain, command-line, and "
            "image hashes."
        ),
        "rule_groups": ["sysmon_event_1"],
        "priority": 50,
        "severity_hint": "medium",
        "prompt_text": (
            "You are investigating a Sysmon process-creation event (EventID 1). "
            "Focus on the parent-child process chain, command-line arguments, "
            "image path and hash, integrity level, and user context. Cross-check "
            "the image hash against threat intel and known LOLBin inventories "
            "(ATT&CK T1059, T1218). Flag obfuscated command-lines, encoded "
            "PowerShell, unusual parent processes (e.g. winword.exe spawning "
            "cmd.exe), writes to Temp/AppData, and signed-binary proxy execution. "
            "Correlate with Event 3 (network connection) and Event 11 (file "
            "create) from the same process GUID to build a timeline. Decide "
            "whether the activity is benign administration, a known tool, or "
            "suspected adversary execution."
        ),
        "investigation_checklist_text": (
            "- What is the parent process and its full command-line?\n"
            "- Is the image path a known-good signed binary, or in a user-"
            "writeable location?\n"
            "- Does the hash match any threat-intel hit (VT / OpenCTI / TIDE)?\n"
            "- Does the command-line contain encoded, compressed, or "
            "obfuscated payloads?\n"
            "- Is the integrity level elevated vs expected?\n"
            "- Are there related network connections (Sysmon 3) or file writes "
            "(Sysmon 11) from the same process GUID?\n"
            "- Does the activity align with any MITRE ATT&CK technique "
            "(T1059.*, T1218.*, T1036.*)?"
        ),
        "expected_outputs": [
            "verdict",
            "mitre_techniques",
            "recommended_actions",
            "ioc_confidence",
        ],
    },
    {
        "name": "Sysmon Event 3 — Network Connection",
        "description": (
            "Investigation guide for Sysmon network-connection telemetry "
            "(EventID 3). Focus on destination reputation, beaconing, and "
            "process context."
        ),
        "rule_groups": ["sysmon_event_3"],
        "priority": 50,
        "severity_hint": "medium",
        "prompt_text": (
            "You are investigating a Sysmon network-connection event (EventID "
            "3). Determine which process initiated the connection, the "
            "destination IP/host/port, and whether the traffic pattern looks "
            "like C2, data staging, or legitimate telemetry. Check the "
            "destination against TI feeds, passive DNS, and internal asset "
            "inventory. Look for beaconing cadence, unusual ports for the "
            "protocol, DNS-over-HTTPS providers, and rare destinations for "
            "the process. ATT&CK: T1071 (application layer protocol), T1090 "
            "(proxy), T1105 (ingress tool transfer)."
        ),
        "investigation_checklist_text": (
            "- Which process initiated the connection and is that normal for "
            "it?\n"
            "- Is the destination IP/domain on any threat-intel list?\n"
            "- Is the port/protocol combination unusual for the process?\n"
            "- Are there repeated connections suggesting beaconing?\n"
            "- Do passive DNS / WHOIS records suggest recent domain "
            "registration?\n"
            "- Is the internal asset known to talk to this destination "
            "legitimately?\n"
            "- Are there paired process-create (Sysmon 1) or file-create "
            "(Sysmon 11) events that explain the origin?"
        ),
        "expected_outputs": [
            "verdict",
            "c2_indicators",
            "recommended_actions",
            "ioc_confidence",
        ],
    },
    {
        "name": "Sysmon Event 11 — File Create",
        "description": (
            "Investigation guide for Sysmon file-create telemetry "
            "(EventID 11). Focus on path, extension, and writing process."
        ),
        "rule_groups": ["sysmon_event_11"],
        "priority": 50,
        "severity_hint": "medium",
        "prompt_text": (
            "You are investigating a Sysmon file-create event (EventID 11). "
            "Identify the writing process, target path, and file type. Flag "
            "drops into Temp, AppData, Public, Startup, or Task scheduler "
            "paths. Check for double extensions, masqueraded executables, "
            "script files (.ps1/.js/.hta/.vbs), and persistence locations. "
            "Correlate with subsequent Event 1 (execution) or Event 7 "
            "(image loaded) from the same file. ATT&CK: T1547 (persistence), "
            "T1105 (tool transfer), T1036 (masquerading)."
        ),
        "investigation_checklist_text": (
            "- Which process wrote the file and is that expected behavior?\n"
            "- Is the target path a persistence location (Startup, Run keys, "
            "Scheduled Tasks staging dir)?\n"
            "- Does the file have a suspicious extension or double extension?\n"
            "- Is the file signed, and does the signer match the path?\n"
            "- Was the file subsequently executed (Sysmon 1) or loaded "
            "(Sysmon 7)?\n"
            "- Does the hash match any TI hit?\n"
            "- Is there a matching network download (Sysmon 3) that delivered "
            "the file?"
        ),
        "expected_outputs": [
            "verdict",
            "persistence_indicators",
            "recommended_actions",
            "ioc_confidence",
        ],
    },
    {
        "name": "Authentication Failure",
        "description": (
            "Investigation guide for authentication-failure alerts "
            "(brute-force, password spray, stolen creds)."
        ),
        "rule_groups": ["authentication_failed", "authentication"],
        "priority": 40,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating an authentication-failure alert. "
            "Determine whether this is targeted brute-force, password "
            "spray, credential stuffing, or a benign user lockout. "
            "Examine the source IP(s), user account(s), failure count, "
            "time window, and whether any attempt eventually succeeded. "
            "Check for impossible travel, geo anomalies, and TOR/VPN exit "
            "nodes. Cross-reference the account against privileged-access "
            "and service-account inventories. ATT&CK: T1110 (brute force), "
            "T1110.003 (password spraying), T1078 (valid accounts)."
        ),
        "investigation_checklist_text": (
            "- How many failures, from how many source IPs, in what window?\n"
            "- Is the source IP on a TI blocklist, TOR exit list, or known "
            "VPN range?\n"
            "- Did any attempt succeed afterward?\n"
            "- Is the targeted account privileged or a service account?\n"
            "- Is there impossible travel between successful and failed "
            "logons?\n"
            "- Are multiple accounts being tried from the same IP (spray)?\n"
            "- Has MFA been completed or bypassed on any success?\n"
            "- Was the account locked out; if so has the user reported it?"
        ),
        "expected_outputs": [
            "verdict",
            "attack_pattern",
            "recommended_actions",
            "account_risk",
        ],
    },
    {
        "name": "Malware Detection",
        "description": (
            "Investigation guide for AV / EDR malware-detection alerts. "
            "Focus on containment state and blast radius."
        ),
        "rule_groups": ["malware_detection", "malware"],
        "priority": 20,
        "severity_hint": "high",
        "prompt_text": (
            "You are investigating a malware-detection alert from AV or EDR. "
            "First confirm the current containment state: was the sample "
            "quarantined, blocked, or executed? Establish the detection "
            "name, family, and sample hash. Check if other hosts show the "
            "same hash, IOC, or family. Identify the delivery vector "
            "(email attachment, download, USB, lateral movement). "
            "Determine whether this is a known family with public "
            "remediation guidance, or a novel sample requiring sandbox "
            "analysis. ATT&CK: T1204 (user execution), T1566 (phishing), "
            "T1105 (ingress tool transfer)."
        ),
        "investigation_checklist_text": (
            "- Was the sample blocked/quarantined, or did it execute?\n"
            "- What is the detection name and malware family?\n"
            "- Does the hash appear on any other host in the estate?\n"
            "- What was the delivery vector (email, web, removable media, "
            "network share)?\n"
            "- Is there evidence of post-execution activity (persistence, "
            "C2, lateral movement)?\n"
            "- Should the host be isolated from the network now?\n"
            "- Are there known remediation steps for this family (registry "
            "keys, services, scheduled tasks)?\n"
            "- Do we need to rotate credentials used on the host?"
        ),
        "expected_outputs": [
            "verdict",
            "containment_state",
            "blast_radius",
            "recommended_actions",
        ],
    },
]


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


class AlertPromptService:
    """Thin wrapper around AlertPromptRepository + system-prompt rendering."""

    def __init__(self, session: Session):
        self.session = session
        self.repo = AlertPromptRepository(session)

    # ----------------------------------------------------------------- resolve

    def resolve_template_for_alert(
        self, alert: dict
    ) -> Optional[AlertPromptTemplate]:
        """Return best-matching enabled template for the alert, or None."""
        return self.repo.find_matching(alert)

    # ------------------------------------------------------------------ render

    def render_system_prompt(
        self,
        template: Optional[AlertPromptTemplate],
        alert: Optional[dict] = None,
    ) -> str:
        """Merge ION's base security system prompt with the template's guidance.

        If ``template`` is None, returns the base security prompt unchanged.
        """
        # Lazy import to avoid tight coupling at import time
        from ion.services.ollama_service import SYSTEM_PROMPTS

        base = SYSTEM_PROMPTS.get("security", "")
        if template is None:
            return base

        parts: list[str] = [base.rstrip()]
        parts.append("\n\n---\n")
        parts.append(f"## Per-Rule Investigation Guide: {template.name}\n")

        if template.description:
            parts.append(template.description.strip() + "\n")

        if template.severity_hint:
            parts.append(
                f"\nSeverity hint for this rule: **{template.severity_hint}**\n"
            )

        if template.prompt_text:
            parts.append("\n### Investigation Focus\n")
            parts.append(template.prompt_text.strip() + "\n")

        if template.investigation_checklist_text:
            parts.append("\n### Checklist — Answer Each\n")
            parts.append(template.investigation_checklist_text.strip() + "\n")

        expected = template.expected_outputs_json
        if expected:
            try:
                fields = json.loads(expected)
                if isinstance(fields, list) and fields:
                    parts.append("\n### Expected Output Fields\n")
                    parts.append(
                        "Produce a structured answer covering: "
                        + ", ".join(str(f) for f in fields)
                        + ".\n"
                    )
            except Exception:
                pass

        if alert:
            rule_id = AlertPromptRepository._extract_rule_id(alert) or "(unknown)"
            parts.append(f"\n_Matched alert rule id: `{rule_id}`_\n")

        return "".join(parts)


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------


def resolve_template_for_alert(
    session: Session, alert: dict
) -> Optional[AlertPromptTemplate]:
    return AlertPromptService(session).resolve_template_for_alert(alert)


def render_system_prompt(
    template: Optional[AlertPromptTemplate],
    alert: Optional[dict] = None,
    session: Optional[Session] = None,
) -> str:
    # Session isn't required for rendering; accept it for symmetry.
    svc = AlertPromptService(session) if session is not None else _DetachedRenderer()
    return svc.render_system_prompt(template, alert)


class _DetachedRenderer(AlertPromptService):
    """Render-only helper that doesn't need a DB session."""

    def __init__(self):  # noqa: D401 — intentionally bypasses parent init
        self.session = None
        self.repo = None


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------


def seed_default_templates(db: Optional[Session] = None) -> int:
    """Insert the default seed templates if the table is empty.

    Idempotent: if any rows already exist, this is a no-op. Returns the number
    of templates inserted.

    Accepts an optional session; if omitted, opens one from the default engine.
    """
    close_after = False
    if db is None:
        from ion.storage.database import get_engine, get_session_factory

        engine = get_engine()
        factory = get_session_factory(engine)
        db = factory()
        close_after = True

    inserted = 0
    try:
        repo = AlertPromptRepository(db)
        if repo.count() > 0:
            logger.info(
                "AlertPromptTemplate seed skipped — %d rows already exist",
                repo.count(),
            )
            return 0

        for defn in _DEFAULT_TEMPLATES:
            repo.create(
                name=defn["name"],
                prompt_text=defn.get("prompt_text", ""),
                description=defn.get("description"),
                enabled=True,
                rule_ids=defn.get("rule_ids"),
                rule_groups=defn.get("rule_groups"),
                rule_id_pattern=defn.get("rule_id_pattern"),
                priority=defn.get("priority", 100),
                investigation_checklist_text=defn.get(
                    "investigation_checklist_text"
                ),
                severity_hint=defn.get("severity_hint"),
                expected_outputs=defn.get("expected_outputs"),
                created_by_id=None,
            )
            inserted += 1

        db.commit()
        logger.info("Seeded %d default AlertPromptTemplate rows", inserted)
    except Exception:
        db.rollback()
        logger.exception("Failed to seed default AlertPromptTemplate rows")
        raise
    finally:
        if close_after:
            db.close()

    return inserted
