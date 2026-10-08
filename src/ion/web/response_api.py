"""Response Actions API — request / approve / reject SOAR response actions.

The whole surface is gated by ``ION_RESPONSE_ACTIONS_ENABLED`` (default off):
every route 404s before any work when disabled, so a stock deployment exposes
nothing. Execution is dry-run unless ``ION_RESPONSE_ACTIONS_LIVE`` is also on.
Approving a high-risk action needs ``response:approve`` AND a different user
than the requester (separation of duty, enforced in the service).
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.core.client_ip import get_client_ip
from ion.core.config import get_config
from ion.models.alert_triage import AlertCase, Note, NoteEntityType
from ion.models.user import User
from ion.services import playbook_action_service as actions
from ion.services.kibana_sync_helpers import sync_note_to_kibana
from ion.storage.auth_repository import AuditLogRepository
from ion.storage.database import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/response", tags=["response"])


def _require_enabled() -> None:
    # Evaluated before any auth/DB work, so a disabled deployment exposes
    # nothing — the MCP-endpoint pattern.
    if not get_config().response_actions_enabled:
        raise HTTPException(status_code=404, detail="Not found")


class ActionRequest(BaseModel):
    action_id: int
    target: str
    case_id: Optional[int] = None


def _audit(session, user, action, resource_id, details, request) -> None:
    AuditLogRepository(session).create(
        user_id=user.id,
        action=action,
        resource_type="playbook_action_log",
        resource_id=resource_id,
        details=details,
        ip_address=get_client_ip(request),
    )


def _post_execution_note(session: Session, result: dict, username: str) -> None:
    """Best-effort: record an executed action as a case Note (+ Kibana mirror).

    Calls ``sync_note_to_kibana`` (the standing note-writer requirement) so the
    action shows on the linked Kibana case, not just in ION.
    """
    case_id = result.get("case_id")
    if not case_id or result.get("status") not in ("completed", "failed"):
        return
    try:
        case = session.query(AlertCase).filter_by(id=case_id).first()
        if case is None:
            return
        # format_action_note reads the nested result.dry_run flag, so a
        # simulated action can no longer produce a note that reads like
        # real containment (review 2026-10-08 finding 6).
        content = actions.format_action_note(result, username)
        note = Note(
            entity_type=NoteEntityType.CASE,
            entity_id=str(case_id),
            user_id=case.created_by_id,
            content=content,
        )
        session.add(note)
        session.commit()
        # Journalled, so a Kibana outage leaves a retryable row against the
        # case rather than a containment note that only exists in ION.
        sync_note_to_kibana(case.kibana_case_id, username, content,
                            session=session, case_id=case_id, note_id=note.id)
    except Exception as exc:  # never fail the request on the note
        logger.warning("response action note failed for case %s: %s", case_id, exc)


@router.get("/actions", dependencies=[Depends(_require_enabled)])
def list_actions(
    _user: User = Depends(require_permission("playbook:read")),
    session: Session = Depends(get_db_session),
):
    """The response-action catalogue (seeds the defaults on first call)."""
    actions.seed_default_actions(session)
    return {"actions": actions.get_available_actions(session)}


@router.post("/actions/request", dependencies=[Depends(_require_enabled)])
def request_response_action(
    body: ActionRequest,
    request: Request,
    user: User = Depends(require_permission("playbook:execute")),
    session: Session = Depends(get_db_session),
):
    """Request an action. Always lands ``pending_approval`` (human-in-the-loop)."""
    result = actions.request_action(
        session,
        action_id=body.action_id,
        executed_by_id=user.id,
        target=body.target,
        case_id=body.case_id,
    )
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result["error"])
    _audit(
        session, user, "response_action_requested", result.get("id"),
        {"action_id": body.action_id, "target": body.target, "case_id": body.case_id},
        request,
    )
    session.commit()
    return result


@router.get("/actions/pending", dependencies=[Depends(_require_enabled)])
def pending_response_actions(
    _user: User = Depends(require_permission("response:approve")),
    session: Session = Depends(get_db_session),
):
    """The approver queue — actions awaiting a decision.

    Raw log rows. ``/actions/inbox`` is the one to render a decision from.
    """
    return {"pending": actions.get_action_log(session, status="pending_approval", limit=200)}


@router.get("/actions/inbox", dependencies=[Depends(_require_enabled)])
def response_approval_inbox(
    decided_limit: int = 50,
    _user: User = Depends(require_permission("response:approve")),
    session: Session = Depends(get_db_session),
):
    """The approval inbox: pending decisions plus recent decision history.

    ``/actions/pending`` returns the bare log rows — numeric requester and
    case ids and a status — which is not enough to decide from. This resolves
    everything a decision needs (requester, case, risk, whether a second
    person is required, adapter readiness, the mode an approval would
    actually execute in, and the dispatch idempotency key) and classifies
    each outcome, so a dry run is never presented as containment.
    """
    return actions.get_approval_inbox(
        session, decided_limit=max(1, min(decided_limit, 200))
    )


@router.post("/actions/{log_id}/approve", dependencies=[Depends(_require_enabled)])
def approve_response_action(
    log_id: int,
    request: Request,
    user: User = Depends(require_permission("response:approve")),
    session: Session = Depends(get_db_session),
):
    """Approve + execute. Rejects self-approval of a high-risk action (SoD)."""
    result = actions.approve_action(session, log_id=log_id, approved_by_id=user.id)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result["error"])
    _audit(session, user, "response_action_approved", log_id,
           {"result_status": result.get("status")}, request)
    session.commit()
    _post_execution_note(session, result, user.username)
    return result


@router.post("/actions/{log_id}/reject", dependencies=[Depends(_require_enabled)])
def reject_response_action(
    log_id: int,
    request: Request,
    user: User = Depends(require_permission("response:approve")),
    session: Session = Depends(get_db_session),
):
    """Reject a pending action."""
    result = actions.reject_action(session, log_id=log_id, approved_by_id=user.id)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result["error"])
    _audit(session, user, "response_action_rejected", log_id, {}, request)
    session.commit()
    return result


@router.get("/actions/log", dependencies=[Depends(_require_enabled)])
def response_action_log(
    limit: int = 100,
    case_id: Optional[int] = None,
    _user: User = Depends(require_permission("playbook:read")),
    session: Session = Depends(get_db_session),
):
    """Action history (optionally scoped to one case)."""
    return {"log": actions.get_action_log(session, case_id=case_id, limit=limit)}
