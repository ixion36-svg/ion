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
    in Kibana or ION.
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

    if observables:
        parts.append("\n**Observables:**")
        obs_by_type: dict[str, list[str]] = {}
        for obs in observables:
            obs_type = obs.get("type", "unknown")
            if obs_type not in obs_by_type:
                obs_by_type[obs_type] = []
            obs_by_type[obs_type].append(obs.get("value", "?"))
        for obs_type, values in sorted(obs_by_type.items()):
            line = f"- **{obs_type}:** {', '.join(values[:5])}"
            if len(values) > 5:
                line += f" (+{len(values) - 5} more)"
            parts.append(line)

    if alert_ids:
        parts.append(f"\n**Linked Alert IDs ({len(alert_ids)}):**")
        for aid in alert_ids[:10]:
            parts.append(f"- `{aid}`")
        if len(alert_ids) > 10:
            parts.append(f"- ... and {len(alert_ids) - 10} more")

    return "\n".join(parts).strip()
