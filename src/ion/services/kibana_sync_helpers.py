"""Helper functions for inline Kibana sync in case management endpoints.

These replace the scattered inline Kibana sync blocks in api.py with
clean, reusable function calls.
"""

import logging
from typing import Optional, Tuple, List, Dict, Any

from ion.services.kibana_cases_service import get_kibana_cases_service
from ion.services.case_description import build_case_description

logger = logging.getLogger(__name__)


def sync_new_case_to_kibana(
    case_number: str,
    title: str,
    description: Optional[str],
    severity: Optional[str],
    affected_hosts: Optional[List[str]],
    affected_users: Optional[List[str]],
    evidence_summary: Optional[str],
    observables: Optional[List[Dict[str, Any]]],
    alert_ids: Optional[List[str]],
    triggered_rules: Optional[List[str]],
) -> Optional[Dict[str, Any]]:
    """Sync a newly created case to Kibana.

    Returns dict with kibana_case_id, kibana_case_version, kibana_url,
    or None if sync was skipped/failed.
    """
    try:
        service = get_kibana_cases_service()
        if not service.enabled:
            return None

        kibana_desc = build_case_description(
            description=description or "",
            affected_hosts=affected_hosts,
            affected_users=affected_users,
            evidence_summary=evidence_summary,
            observables=observables,
            alert_ids=alert_ids,
            triggered_rules=triggered_rules,
        )

        kibana_case = service.create_case(
            title=f"[{case_number}] {title}",
            description=kibana_desc.strip(),
            severity=severity or "low",
            tags=[case_number, "ion"],
        )
        if not kibana_case:
            return None

        result = {
            "kibana_case_id": kibana_case.get("id"),
            "kibana_case_version": kibana_case.get("version"),
            "kibana_url": service.get_case_url(kibana_case.get("id")),
        }

        # Attach alerts to Kibana case if using securitySolution owner
        if alert_ids and service.config.get("case_owner") == "securitySolution":
            try:
                space_id = service.config.get("space_id", "default")
                alert_index = f".alerts-security.alerts-{space_id}"
                service.attach_alerts_to_case(
                    case_id=kibana_case.get("id"),
                    alert_ids=alert_ids,
                    alert_index=alert_index,
                )
            except Exception as attach_err:
                logger.warning("Failed to attach alerts to Kibana case: %s", attach_err)

        return result
    except Exception as e:
        logger.warning("Failed to sync case to Kibana: %s", e)
        return None


def sync_note_to_kibana(
    kibana_case_id: Optional[str],
    username: str,
    content: str,
) -> None:
    """Sync a note to Kibana as a comment. Fire-and-forget."""
    if not kibana_case_id:
        return

    try:
        service = get_kibana_cases_service()
        if not service.enabled:
            return

        comment_text = f"**{username}:** {content}"
        service.add_comment(kibana_case_id, comment_text)
    except Exception as e:
        logger.warning("Failed to sync note to Kibana: %s", e)


def sync_case_update_to_kibana(
    kibana_case_id: Optional[str],
    case_number: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """Sync case updates to Kibana.

    Returns (kibana_case_version, kibana_url) or (None, None) if skipped/failed.
    """
    if not kibana_case_id:
        return None, None

    try:
        service = get_kibana_cases_service()
        if not service.enabled:
            return None, None

        # Map ION status to Kibana status
        kibana_status = None
        if status:
            status_map = {
                "open": "open",
                "acknowledged": "in-progress",
                "closed": "closed",
            }
            kibana_status = status_map.get(status)

        # Get current version from Kibana
        kibana_case = service.get_case(kibana_case_id)
        version = None
        if kibana_case:
            version = kibana_case.get("version")
            updated = service.update_case(
                case_id=kibana_case_id,
                version=version,
                title=f"[{case_number}] {title}" if title else None,
                description=description,
                status=kibana_status,
                severity=severity,
            )
            if updated:
                version = updated.get("version")

        kibana_url = service.get_case_url(kibana_case_id)
        return version, kibana_url
    except Exception as e:
        logger.warning("Failed to sync case update to Kibana: %s", e)
        return None, None


def get_kibana_case_url(kibana_case_id: Optional[str]) -> Optional[str]:
    """Get the Kibana URL for a case. Returns None if not available."""
    if not kibana_case_id:
        return None

    try:
        service = get_kibana_cases_service()
        if not service.enabled:
            return None
        return service.get_case_url(kibana_case_id)
    except Exception:
        return None
