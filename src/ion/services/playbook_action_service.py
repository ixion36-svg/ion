"""Automated playbook action service.

Manages SOAR-style response actions (block IP, quarantine host, disable
account, etc.) that can be triggered from playbook steps.  Actions with
high risk levels require approval before execution.  In the current
release all executions are *simulated*; a real deployment would call
firewall / EDR / Active Directory APIs.
"""

import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session

from ion.models.sla import PlaybookAction, PlaybookActionLog

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default actions — seeded on first use
# ---------------------------------------------------------------------------
DEFAULT_ACTIONS = [
    {"name": "Block IP at Firewall", "action_type": "block_ip", "target_integration": "firewall", "requires_approval": False, "risk_level": "medium", "description": "Add IP to firewall block list"},
    {"name": "Block Domain at DNS", "action_type": "block_domain", "target_integration": "dns", "requires_approval": False, "risk_level": "medium", "description": "Add domain to DNS sinkhole"},
    {"name": "Disable AD Account", "action_type": "disable_account", "target_integration": "active_directory", "requires_approval": True, "risk_level": "high", "description": "Disable user account in Active Directory"},
    {"name": "Quarantine Host", "action_type": "quarantine_host", "target_integration": "edr", "requires_approval": True, "risk_level": "high", "description": "Network-isolate host via EDR agent"},
    {"name": "Block Email Sender", "action_type": "block_sender", "target_integration": "email_gateway", "requires_approval": False, "risk_level": "low", "description": "Add sender to email gateway block list"},
    {"name": "Force Password Reset", "action_type": "reset_password", "target_integration": "active_directory", "requires_approval": True, "risk_level": "high", "description": "Force password reset for user account"},
]


def _parse_json(raw: str | None, fallback=None):
    """Safely parse a JSON text column."""
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return fallback


def _action_to_dict(action: PlaybookAction) -> dict:
    """Serialise a PlaybookAction row to a plain dict."""
    return {
        "id": action.id,
        "name": action.name,
        "action_type": action.action_type,
        "description": action.description,
        "target_integration": action.target_integration,
        "config_template": _parse_json(action.config_template, {}),
        "requires_approval": action.requires_approval,
        "is_active": action.is_active,
        "risk_level": action.risk_level,
    }


def _log_to_dict(log: PlaybookActionLog) -> dict:
    """Serialise a PlaybookActionLog row to a plain dict."""
    return {
        "id": log.id,
        "action_id": log.action_id,
        "action_name": log.action.name if log.action else None,
        "action_type": log.action.action_type if log.action else None,
        "case_id": log.case_id,
        "executed_by_id": log.executed_by_id,
        "approved_by_id": log.approved_by_id,
        "target": log.target,
        "status": log.status,
        "result": _parse_json(log.result),
        "error": log.error,
        "created_at": log.created_at.isoformat() if log.created_at else None,
        "updated_at": log.updated_at.isoformat() if getattr(log, "updated_at", None) else None,
    }


# ---------------------------------------------------------------------------
# Actions CRUD
# ---------------------------------------------------------------------------

def get_available_actions(session: Session) -> list[dict]:
    """Return all active playbook actions."""
    rows = session.execute(
        select(PlaybookAction)
        .where(PlaybookAction.is_active == True)  # noqa: E712
        .order_by(PlaybookAction.name)
    ).scalars().all()
    return [_action_to_dict(a) for a in rows]


def seed_default_actions(session: Session) -> None:
    """Create the default set of playbook actions if none exist.

    This is safe to call multiple times; it only inserts when the
    ``playbook_actions`` table is empty.
    """
    count = session.execute(
        select(func.count(PlaybookAction.id))
    ).scalar() or 0

    if count > 0:
        logger.debug("Playbook actions already seeded (%d rows), skipping", count)
        return

    for defn in DEFAULT_ACTIONS:
        action = PlaybookAction(
            name=defn["name"],
            action_type=defn["action_type"],
            target_integration=defn["target_integration"],
            requires_approval=defn["requires_approval"],
            risk_level=defn["risk_level"],
            description=defn["description"],
            is_active=True,
        )
        session.add(action)

    session.commit()
    logger.info("Seeded %d default playbook actions", len(DEFAULT_ACTIONS))


# ---------------------------------------------------------------------------
# Action request / approval workflow
# ---------------------------------------------------------------------------

def request_action(
    session: Session,
    action_id: int,
    executed_by_id: int,
    target: str,
    case_id: int | None = None,
) -> dict:
    """Request execution of a playbook action.

    If the action requires approval the log entry is created with
    status ``pending_approval``.  Otherwise it is immediately set to
    ``approved`` (ready for execution).

    Args:
        session: Database session.
        action_id: ID of the PlaybookAction to execute.
        executed_by_id: User requesting the action.
        target: The target (IP address, hostname, account name, etc.).
        case_id: Optional related case ID.

    Returns:
        Dict representation of the created log entry.
    """
    action = session.get(PlaybookAction, action_id)
    if action is None:
        return {"error": "Action not found", "status": "error"}

    if not action.is_active:
        return {"error": "Action is disabled", "status": "error"}

    initial_status = "pending_approval" if action.requires_approval else "approved"

    log_entry = PlaybookActionLog(
        action_id=action_id,
        case_id=case_id,
        executed_by_id=executed_by_id,
        target=target,
        status=initial_status,
    )
    session.add(log_entry)
    session.commit()
    session.refresh(log_entry)

    logger.info(
        "Action requested: %s on %s (status=%s, log_id=%d)",
        action.action_type, target, initial_status, log_entry.id,
    )

    return _log_to_dict(log_entry)


def approve_action(
    session: Session,
    log_id: int,
    approved_by_id: int,
) -> dict:
    """Approve a pending action and simulate its execution.

    Args:
        session: Database session.
        log_id: ID of the PlaybookActionLog entry.
        approved_by_id: User approving the action.

    Returns:
        Updated log dict (status will be ``completed`` on success).
    """
    log_entry = session.get(PlaybookActionLog, log_id)
    if log_entry is None:
        return {"error": "Log entry not found", "status": "error"}

    if log_entry.status != "pending_approval":
        return {"error": f"Cannot approve action in status '{log_entry.status}'", "status": "error"}

    log_entry.approved_by_id = approved_by_id
    log_entry.status = "approved"
    session.commit()

    logger.info("Action log %d approved by user %d", log_id, approved_by_id)

    # Proceed to execute after approval
    return execute_action(session, log_id)


def reject_action(
    session: Session,
    log_id: int,
    approved_by_id: int,
) -> dict:
    """Reject a pending action request.

    Args:
        session: Database session.
        log_id: ID of the PlaybookActionLog entry.
        approved_by_id: User rejecting the action.

    Returns:
        Updated log dict with status ``rejected``.
    """
    log_entry = session.get(PlaybookActionLog, log_id)
    if log_entry is None:
        return {"error": "Log entry not found", "status": "error"}

    if log_entry.status != "pending_approval":
        return {"error": f"Cannot reject action in status '{log_entry.status}'", "status": "error"}

    log_entry.approved_by_id = approved_by_id
    log_entry.status = "rejected"
    session.commit()
    session.refresh(log_entry)

    logger.info("Action log %d rejected by user %d", log_id, approved_by_id)

    return _log_to_dict(log_entry)


def execute_action(session: Session, log_id: int) -> dict:
    """Execute (simulate) an approved playbook action.

    In the current release this records a simulated success.  A real
    deployment would dispatch to firewall, EDR, Active Directory, or
    email gateway APIs based on the action's ``target_integration``.

    Args:
        session: Database session.
        log_id: ID of the PlaybookActionLog entry.

    Returns:
        Updated log dict with execution result.
    """
    log_entry = session.get(PlaybookActionLog, log_id)
    if log_entry is None:
        return {"error": "Log entry not found", "status": "error"}

    if log_entry.status not in ("approved",):
        return {"error": f"Cannot execute action in status '{log_entry.status}'", "status": "error"}

    action = session.get(PlaybookAction, log_entry.action_id)
    action_type = action.action_type if action else "unknown"
    now = datetime.now(timezone.utc)

    log_entry.status = "executing"
    session.commit()

    try:
        # --- Simulated execution ---
        result = {
            "simulated": True,
            "message": f"Action would execute: {action_type} on {log_entry.target}",
            "integration": action.target_integration if action else "unknown",
            "executed_at": now.isoformat(),
        }

        log_entry.status = "completed"
        log_entry.result = json.dumps(result)
        log_entry.error = None
        session.commit()
        session.refresh(log_entry)

        logger.info(
            "Action log %d executed (simulated): %s on %s",
            log_id, action_type, log_entry.target,
        )

    except Exception as exc:
        logger.exception("Action log %d failed", log_id)
        log_entry.status = "failed"
        log_entry.error = str(exc)
        session.commit()
        session.refresh(log_entry)

    return _log_to_dict(log_entry)


# ---------------------------------------------------------------------------
# Action log query
# ---------------------------------------------------------------------------

def get_action_log(
    session: Session,
    case_id: int | None = None,
    limit: int = 50,
) -> list[dict]:
    """Return recent playbook action log entries.

    Args:
        session: Database session.
        case_id: If provided, filter to a specific case.
        limit: Maximum number of entries to return.

    Returns:
        List of log dicts, most recent first.
    """
    stmt = select(PlaybookActionLog)

    if case_id is not None:
        stmt = stmt.where(PlaybookActionLog.case_id == case_id)

    stmt = stmt.order_by(PlaybookActionLog.id.desc()).limit(limit)

    rows = session.execute(stmt).scalars().all()
    return [_log_to_dict(log) for log in rows]
