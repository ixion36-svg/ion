"""Standardized case description builder for ION cases."""

from typing import List, Optional


def build_case_description(
    description: str = "",
    affected_hosts: Optional[List[str]] = None,
    affected_users: Optional[List[str]] = None,
    evidence_summary: Optional[str] = None,
    observables: Optional[List[dict]] = None,
    alert_ids: Optional[List[str]] = None,
    triggered_rules: Optional[List[str]] = None,
) -> str:
    """Build a standardized markdown description for a case.

    Produces a consistent format regardless of whether the case originated
    in Kibana or ION. Kept intentionally lean: the observable enrichment and
    the linked-alert list are NOT rendered here — observables (with any OpenCTI
    enrichment) post as a separate case Note via ``post_enrichment_note``, and
    alerts show as first-class links on the case. ``observables``/``alert_ids``
    stay in the signature for callers; they just no longer render into the
    description.
    """
    parts = [description] if description else []

    if affected_hosts:
        parts.append(f"\n**Affected Hosts:** {', '.join(affected_hosts)}")

    if affected_users:
        parts.append(f"\n**Affected Users:** {', '.join(affected_users)}")

    if triggered_rules:
        parts.append(f"\n**Triggered Rules:** {', '.join(triggered_rules)}")

    if evidence_summary:
        parts.append(f"\n**Evidence Summary:**\n{evidence_summary}")

    result = "\n".join(parts).strip()
    # Kibana >= 8.19 rejects an empty case description outright (400: "The
    # description field cannot be an empty string"), and the 60s sync loop
    # would retry such a case forever. A case created with no description and
    # no enrichment produced exactly that — live-caught against 8.19.11.
    return result or "_No description provided._"
