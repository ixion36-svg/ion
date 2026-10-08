"""Helper functions for inline Kibana sync in case management endpoints.

These replace the scattered inline Kibana sync blocks in api.py with
clean, reusable function calls.
"""

import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple

from ion.core.config import get_config
from ion.services import integration_sync_journal_service as sync_journal
from ion.services.case_description import build_case_description
from ion.services.kibana_cases_service import (
    build_ion_custom_fields,
    get_kibana_cases_service,
)

logger = logging.getLogger(__name__)


def _content_key(content: str) -> str:
    """Stable short digest of a note's text, for a dedupe key.

    ``hash()`` is salted per process in CPython, so a dedupe key built from
    it would change across restarts and the same note would get a second
    journal row. sha256 is stable.
    """
    return hashlib.sha256((content or "").encode("utf-8")).hexdigest()[:16]


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
    assignee_elastic_uid: Optional[str] = None,
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

        assignees = [{"uid": assignee_elastic_uid}] if assignee_elastic_uid else None

        # Native Kibana case custom fields (opt-in) — map ION's case metadata
        # onto first-class fields instead of only the description.
        custom_fields = None
        if get_config().kibana_custom_fields_enabled:
            service.ensure_case_custom_fields()
            custom_fields = build_ion_custom_fields(
                case_number=case_number, severity=severity,
                triggered_rules=triggered_rules, affected_hosts=affected_hosts,
            )

        kibana_case = service.create_case(
            title=f"[{case_number}] {title}",
            description=kibana_desc.strip(),
            severity=severity or "low",
            tags=[case_number, "ion"],
            assignees=assignees,
            custom_fields=custom_fields,
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


def _add_comment(kibana_case_id: str, username: str, content: str) -> bool:
    """Post one comment to a Kibana case. True when Kibana took it.

    Shared by the live path and the journal's retry handler, so a replay
    sends exactly what the original attempt sent.
    """
    service = get_kibana_cases_service()
    if not service.enabled:
        # Nothing to sync. Distinct from a failure, and the caller must not
        # record it as either outcome.
        return False
    service.add_comment(kibana_case_id, f"**{username}:** {content}")
    return True


def _retry_note_add(payload: dict) -> bool:
    """Journal retry handler for a note comment."""
    return _add_comment(
        payload.get("kibana_case_id", ""),
        payload.get("username", "ion"),
        payload.get("content", ""),
    )


def sync_note_to_kibana(
    kibana_case_id: Optional[str],
    username: str,
    content: str,
    session=None,
    case_id: Optional[int] = None,
    note_id: Optional[int] = None,
) -> None:
    """Sync a note to Kibana as a comment. Never raises.

    With a ``session`` the outcome lands in the sync journal, so a failure
    becomes a durable row that can be shown beside the case and retried
    instead of only a log line (review 2026-10-08, stage 3). Without one the
    behaviour is exactly as before, so call sites with no session keep
    working untouched.

    Nothing is journalled when Kibana is not configured: nothing was
    attempted and nothing failed, and recording a success would assert a
    mirror that does not exist.
    """
    if not kibana_case_id:
        return

    try:
        if not get_kibana_cases_service().enabled:
            return
    except Exception as e:  # noqa: BLE001 — cannot even tell whether it is on
        logger.warning("Could not reach the Kibana cases service: %s", e)
        return

    dedupe = (
        f"kibana:note_add:{note_id}" if note_id is not None
        # No note id (several callers post a synthesised note). Key on the
        # case and the content so a repeat of the same text reuses its row
        # while a different note gets its own.
        else f"kibana:note_add:case{case_id}:{_content_key(content)}"
    )

    runner = sync_journal.journalled(
        session,
        target="kibana",
        operation="note_add",
        entity_type="note",
        entity_id=note_id if note_id is not None else "unkeyed",
        dedupe_key=dedupe,
        payload={
            "kibana_case_id": kibana_case_id,
            "username": username,
            "content": content,
        },
        case_id=case_id,
    )
    runner(lambda: _add_comment(kibana_case_id, username, content))


def sync_case_update_to_kibana(
    kibana_case_id: Optional[str],
    case_number: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assignee_elastic_uid: Optional[str] = None,
    clear_assignee: bool = False,
) -> Tuple[Optional[str], Optional[str]]:
    """Sync case updates to Kibana.

    Args:
        assignee_elastic_uid: Elastic user profile UID for the assignee.
            If provided, the Kibana case assignees list will be set to this user.
        clear_assignee: Set the Kibana assignees list to empty. Needed
            because a bare ``assignee_elastic_uid=None`` means "leave the
            Kibana assignee alone", so an ION unassignment would otherwise
            never propagate (review 2026-10-08 finding 4).

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

        # Build assignees payload if UID provided. `[]` is a real
        # instruction to Kibana (unassign); `None` leaves it untouched.
        assignees = None
        if assignee_elastic_uid is not None:
            assignees = [{"uid": assignee_elastic_uid}]
        elif clear_assignee:
            assignees = []

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
                assignees=assignees,
            )
            if updated:
                version = updated.get("version")

        kibana_url = service.get_case_url(kibana_case_id)
        return version, kibana_url
    except Exception as e:
        logger.warning("Failed to sync case update to Kibana: %s", e)
        return None, None


def push_case_status_to_kibana(session, case) -> bool:
    """Mirror a case's current ION status onto its linked Kibana case.

    The single close/transition→Kibana push every case-status writer must call,
    so the Kibana case status follows ION's without waiting for the periodic
    reconciler (which is best-effort: skipped when the Kibana breaker is open,
    races the reverse sync, and only retries next cycle). No-op when the case is
    not linked to Kibana. Best-effort and never raises — a Kibana failure must
    not break the ION-side close, and the reconciler remains the backstop.

    Returns True when Kibana was updated.
    """
    kibana_case_id = getattr(case, "kibana_case_id", None)
    if not kibana_case_id:
        return False
    status = case.status.value if hasattr(case.status, "value") else case.status
    try:
        new_version, _ = sync_case_update_to_kibana(
            kibana_case_id=kibana_case_id,
            case_number=case.case_number,
            status=status,
        )
    except Exception as e:  # noqa: BLE001 — the reconciler is the backstop
        logger.warning("push_case_status_to_kibana failed for case %s: %s",
                       getattr(case, "case_number", "?"), e)
        return False
    if new_version:
        case.kibana_case_version = new_version
        if session is not None:
            session.commit()
        return True
    return False


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


# Register the journal's retry handlers at import time. The journal has no
# dependency on this module, so the arrow points this way: the sync helper
# teaches the journal how to replay its own work.
sync_journal.register_retry_handler("kibana", "note_add", _retry_note_add)
