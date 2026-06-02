"""EXAMPLE AlertPromptTemplate — drop-in per-rule investigation guide for Bob.

Mirrors the real model in ``src/ion/models/alert_prompt.py``. When an alert
matches (5-tier matcher: rule_ids -> rule_id_pattern -> mitre_techniques ->
mitre_tactics -> rule_groups, most-specific wins), ``render_system_prompt``
injects this template as the "Per-Rule Investigation Guide" layer — ABOVE the
KB RAG layer — giving Bob a scoped, surgical brief for that exact rule.

Pair this with the KB article: the KB gives broad background that surfaces by
similarity; the template gives a precise checklist + expected outputs for one
known rule. Use a template when a *specific* rule's auto-closure quality is poor.

TO SEED: construct the row in your alert-prompt seed path (or via the admin API
at /api/alert-prompts). The matcher field you populate determines the tier —
populate ONE primary matcher; leave the others None. Lower ``priority`` wins.

Output MUST validate against ``CaseClosureReason`` (see docs/AI_OUTPUT_CONTRACT.md);
the canonical JSON envelope is appended automatically by render_system_prompt, so
the template body should only add rule-specific *focus*, not redefine the schema.
"""
import json

from ion.models.alert_prompt import AlertPromptTemplate


def build_kerberoasting_template(created_by_id: int | None = None) -> AlertPromptTemplate:
    """Example: a high-precision guide for the Kerberoasting detection rule.

    Matches by exact rule id first, with the MITRE technique as a broader
    safety net (parent->sub tolerant: listing T1558.003 also catches it if the
    alert is tagged only T1558).
    """
    return AlertPromptTemplate(
        name="Kerberoasting — RC4 service-ticket harvesting",
        description=(
            "Service accounts (SPNs) targeted for offline cracking via RC4 "
            "Kerberos service tickets. Scopes Bob to the 4769/RC4 signal."
        ),
        enabled=True,
        # --- 5-tier matcher: populate the most specific tier that applies ---
        rule_ids_json=json.dumps(["elastic-windows-kerberoasting-rc4"]),  # tier 1
        rule_id_pattern=None,                                             # tier 2
        mitre_techniques_json=json.dumps(["T1558.003"]),                  # tier 3 (net)
        mitre_tactics_json=json.dumps(["TA0006"]),                        # tier 4
        rule_groups_json=None,                                            # tier 5
        priority=20,  # lower = higher precedence; specific rules sit well below 100
        # --- Prompt content (focus only; envelope appended automatically) ---
        prompt_text=(
            "Focus on whether this is genuine credential-access activity vs a "
            "benign legacy/RC4-only service. Anchor on the requesting principal, "
            "the targeted SPNs, the source host, and any preceding AD recon."
        ),
        investigation_checklist_text=(
            "- Which principal requested the ticket(s), and from which source host?\n"
            "- How many DISTINCT SPNs were requested, and over what time window?\n"
            "- Is TicketEncryptionType RC4 (0x17) where AES (0x12) is the norm?\n"
            "- Are any targeted SPNs high-value (Domain Admin, unconstrained delegation)?\n"
            "- Is there preceding LDAP/BloodHound enumeration from the same host?\n"
            "- Is the requester/host on a known-tool or appliance allow-list?"
        ),
        severity_hint="high",
        expected_outputs_json=json.dumps([
            "requesting_principal",
            "targeted_spns",
            "distinct_spn_count",
            "encryption_type",
            "preceding_recon_observed",
        ]),
        # Per-template circuit-breaker override (v0.21.0); None = global default.
        confidence_threshold_override=None,
        created_by_id=created_by_id,
    )
