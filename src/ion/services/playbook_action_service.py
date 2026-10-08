"""Automated playbook action service.

Manages SOAR-style response actions (block IP, quarantine host, disable
account, etc.) that can be triggered from playbook steps.  Actions with
high risk levels require approval before execution, and a high-risk action
cannot be approved by its own requester (separation of duty). Execution runs
through the real adapter layer, but is forced to a dry-run unless
``ION_RESPONSE_ACTIONS_LIVE`` is enabled.
"""

import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from ion.core.config import get_config
from ion.core.safe_errors import safe_error
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


# ---------------------------------------------------------------------------
# Decision atomicity
# ---------------------------------------------------------------------------

#: Stable namespace for dispatch idempotency keys. Fixed for the lifetime
#: of the deployment so a key regenerated after a restart still matches the
#: one an external system already saw.
_DISPATCH_NAMESPACE = uuid.UUID("6f3d2a18-0c4b-4f8e-9a71-5d2e8b6c4f10")


def _claim_status_transition(
    session: Session,
    log_id: int,
    *,
    expected: str,
    new: str,
    **extra_fields,
) -> bool:
    """Move a log row from ``expected`` to ``new``, atomically.

    Returns True only if *this* caller made the transition. The guard is
    in the ``WHERE`` clause, so the database decides the winner:

        UPDATE playbook_action_log
           SET status = :new
         WHERE id = :log_id AND status = :expected

    Review 2026-10-08 finding 3: the previous code read ``status``, checked
    it in Python, then wrote unconditionally. Two approvals could both pass
    the check and both dispatch, and a delayed decision could overwrite a
    state another request had already advanced. Approve/reject raced the
    same way, silently discarding the losing decision.

    ``extra_fields`` are applied in the same statement, so a decision and
    the identity of its decider land together or not at all.
    """
    result = session.execute(
        update(PlaybookActionLog)
        .where(
            PlaybookActionLog.id == log_id,
            PlaybookActionLog.status == expected,
        )
        .values(status=new, **extra_fields)
    )
    won = result.rowcount == 1
    session.commit()
    if not won:
        # Someone else holds the row; drop our stale copy so the caller
        # reads the winner's state rather than its own.
        session.expire_all()
    return won


def dispatch_idempotency_key(session: Session, log_id: int) -> str | None:
    """A stable key identifying one externally-visible dispatch.

    Derived deterministically from the log row rather than generated, so
    the same request produces the same key on a retry after a crash — an
    adapter (or the system behind it) can use it to recognise work it has
    already done instead of containing the same target twice.

    Returns None if the log row does not exist.
    """
    log_entry = session.get(PlaybookActionLog, log_id)
    if log_entry is None:
        return None
    seed = "|".join(
        str(part)
        for part in (
            log_entry.id,
            log_entry.action_id,
            log_entry.target,
            log_entry.created_at.isoformat() if log_entry.created_at else "",
        )
    )
    return f"ion-act-{uuid.uuid5(_DISPATCH_NAMESPACE, seed)}"


def format_action_note(result: dict, username: str) -> str:
    """Render a response-action result as a case note.

    Review 2026-10-08 finding 6: a successful dry run is stored with
    status ``completed``, and the old note writer printed that status
    while ignoring the nested ``result.dry_run`` flag. The case journal
    and its Kibana mirror therefore stated that a response action had
    completed when nothing had been done — a note claiming an account was
    disabled when it was not is worse than no note at all.

    A simulation is now labelled as one, and the execution id and adapter
    are recorded either way so the note points at the underlying record.
    """
    inner = result.get("result") or {}
    dry_run = bool(inner.get("dry_run"))
    adapter = inner.get("adapter") or "unknown adapter"
    action_type = result.get("action_type")
    target = result.get("target")
    exec_id = result.get("id")
    failed = result.get("status") == "failed"

    if dry_run:
        headline = "**Response action — DRY RUN, no action performed**"
        outcome = "simulated only"
    elif failed:
        headline = "**Response action — failed**"
        outcome = "failed"
    else:
        headline = "**Response action — executed**"
        outcome = "succeeded"

    lines = [
        headline,
        "",
        f"- Action: `{action_type}` on `{target}`",
        f"- Outcome: {outcome}",
        f"- Adapter: `{adapter}`",
        f"- Execution ID: {exec_id}",
        f"- Approved by: {username}",
    ]
    if inner.get("message"):
        lines.append(f"- Adapter message: {inner['message']}")
    if result.get("error"):
        lines.append(f"- Error: {result['error']}")
    if dry_run:
        lines += [
            "",
            "No change was made to the target. Live execution is off "
            "(`ION_RESPONSE_ACTIONS_LIVE`), so this records intent, not "
            "containment.",
        ]
    return "\n".join(lines)


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

    Every request is created ``pending_approval`` — v1 is human-in-the-loop for
    all actions (no auto-execute), so nothing runs until a human approves it.
    ``PlaybookAction.requires_approval`` still governs separation of duty at the
    approve step (a high-risk action cannot be approved by its requester).

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

    initial_status = "pending_approval"

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

    # Separation of duty: a high-risk (approval-required) action cannot be
    # approved by the same user who requested it.
    action = session.get(PlaybookAction, log_entry.action_id)
    if action is not None and action.requires_approval and approved_by_id == log_entry.executed_by_id:
        return {
            "error": "Separation of duty: a high-risk action must be approved by a different user than the requester",
            "status": "error",
        }

    # Atomic claim: the WHERE clause decides the winner, so a second
    # approval (or a racing rejection) cannot also advance the row and
    # dispatch the action again.
    if not _claim_status_transition(
        session,
        log_id,
        expected="pending_approval",
        new="approved",
        approved_by_id=approved_by_id,
    ):
        current = session.get(PlaybookActionLog, log_id)
        return {
            "error": (
                "Action was already decided concurrently (now "
                f"'{current.status if current else 'missing'}')"
            ),
            "status": "error",
        }

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

    if not _claim_status_transition(
        session,
        log_id,
        expected="pending_approval",
        new="rejected",
        approved_by_id=approved_by_id,
    ):
        current = session.get(PlaybookActionLog, log_id)
        return {
            "error": (
                "Action was already decided concurrently (now "
                f"'{current.status if current else 'missing'}')"
            ),
            "status": "error",
        }

    log_entry = session.get(PlaybookActionLog, log_id)
    logger.info("Action log %d rejected by user %d", log_id, approved_by_id)

    return _log_to_dict(log_entry)


def execute_action(session: Session, log_id: int) -> dict:
    """Execute an approved playbook action via the adapter layer.

    Dispatches to the real firewall / EDR / AD / email-gateway adapter for the
    action's ``target_integration`` — unless ``ION_RESPONSE_ACTIONS_LIVE`` is
    off, in which case the execution is forced to a dry-run.

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

    # A separate claim from the approval one: approval decides *whether* to
    # act, this decides *who* acts. Without it two workers that both saw
    # `approved` would each dispatch to the adapter.
    if not _claim_status_transition(
        session, log_id, expected="approved", new="executing"
    ):
        current = session.get(PlaybookActionLog, log_id)
        return {
            "error": (
                "Action is already being executed elsewhere (now "
                f"'{current.status if current else 'missing'}')"
            ),
            "status": "error",
        }
    log_entry = session.get(PlaybookActionLog, log_id)
    _idempotency_key = dispatch_idempotency_key(session, log_id)

    try:
        # --- Real execution via adapter layer ---
        import asyncio

        from ion.services.playbook_executor_service import get_playbook_executor_service

        executor_service = get_playbook_executor_service()

        _force_dry = not get_config().response_actions_live

        async def _run():
            return await executor_service.execute_action(
                action_row=action,
                target_value=log_entry.target,
                params={},
                db=None,
                force_dry_run=_force_dry,
            )

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is None:
            exec_result = asyncio.run(_run())
        else:
            exec_result = loop.run_until_complete(_run())

        executor_service.apply_result_to_log(session, log_entry, exec_result)
        session.commit()
        session.refresh(log_entry)

        logger.info(
            "Action log %d executed (adapter=%s, success=%s, dry_run=%s, "
            "idempotency_key=%s): %s on %s",
            log_id, exec_result.adapter, exec_result.success, exec_result.dry_run,
            _idempotency_key, action_type, log_entry.target,
        )

    except Exception as exc:
        log_entry.status = "failed"
        log_entry.error = safe_error(exc, f"execute_action[{log_id}]")
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
    status: str | None = None,
) -> list[dict]:
    """Return recent playbook action log entries.

    Args:
        session: Database session.
        case_id: If provided, filter to a specific case.
        limit: Maximum number of entries to return.
        status: If provided, filter to one status (e.g. ``pending_approval``).

    Returns:
        List of log dicts, most recent first.
    """
    stmt = select(PlaybookActionLog)

    if case_id is not None:
        stmt = stmt.where(PlaybookActionLog.case_id == case_id)

    if status is not None:
        stmt = stmt.where(PlaybookActionLog.status == status)

    stmt = stmt.order_by(PlaybookActionLog.id.desc()).limit(limit)

    rows = session.execute(stmt).scalars().all()
    return [_log_to_dict(log) for log in rows]
