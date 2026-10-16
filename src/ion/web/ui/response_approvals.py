"""The response-action approval inbox: mode banner, pending cards, history.

response_approvals.html built all of it from template literals and wrote the
result into `#rap-mode` and `#rap-content` with innerHTML at four sites, 246
lines of inline JavaScript including a hand-rolled `rapEsc()`.

The one thing that is not a straight port is the Approve button. The page
rendered it on every pending card, including the card belonging to the
viewer's own high-risk request, which `approve_action` refuses outright for
separation of duty. So the page offered a decision the server answers with
an error on an inbox whose decisions change things outside ION. The buttons
are derived from the service's own rules here instead.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.response_api import (
    _APPROVE_PERM,
    response_actions_enabled,
    response_inbox_payload,
)
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/response_approvals.html"

_RISK_BADGE = {
    "critical": "badge-error",
    "high": "badge-error",
    "medium": "badge-warning",
    "low": "badge-info",
}

_STAGE_BADGE = {
    "requested": "badge-warning",
    "approved": "badge-info",
    "dispatched": "badge-success",
    "simulated": "badge-ghost",
    "rejected": "badge-ghost",
    "failed": "badge-error",
    "unknown": "badge-ghost",
}

#: Wording for how much ION actually knows about the target. "Acknowledged"
#: is not "verified": the adapter returning 200 means it took the call.
_CONFIRMATION = {
    "none": ("No external confirmation", "text-base-content/50"),
    "acknowledged": ("Adapter acknowledged the call", "text-info"),
    "verified": ("Adapter verified the target changed", "text-success"),
}

_READINESS = {
    "ready": ("Adapter ready", "badge-success"),
    "not_configured": ("Adapter not configured", "badge-warning"),
    "no_adapter": ("No adapter registered", "badge-error"),
}

#: Label and button class per decision. Only the presentation lives here;
#: which decisions a row will actually accept comes from the service, so
#: this cannot offer a button approve_action or reject_action rejects.
_DECISION_CHROME = {
    "reject": ("Reject", "btn-error btn-outline"),
    "approve": ("Approve", "btn-primary"),
}


def _text(raw: object) -> str:
    """A column's value as a plain string, enum member or not.

    `PlaybookActionLog.status`, `PlaybookAction.risk_level` and
    `AlertCase.severity` are all `String` columns today, so nothing on this
    page carries an enum member the way the change-request columns do. The
    unwrap is still routed through `ui._shared.plain` because the colour maps
    and the status comparison below are keyed by string: if any of those
    columns is ever tightened to `SQLEnum`, a bare `str()` would start
    rendering "PlaybookActionStatus.PENDING_APPROVAL" into the pill and
    silently match no colour, which is the trap two earlier conversions hit.
    """
    value = plain(raw)
    return "" if value is None else str(value)


def _action_label(entry: dict) -> str:
    name = entry.get("action_name")
    return name if name else f"Action {entry.get('action_id')}"


def _user_label(name: object, user_id: object, *, missing: str) -> str:
    """A username, or the numeric id when the user row is gone.

    `is not none` on the id: the JavaScript tested `== null` and a truthiness
    port would print `missing` for user 0.
    """
    if name is not None:
        return str(name)
    if user_id is not None:
        return f"user {user_id}"
    return missing


def _decisions(entry: dict, viewer_id: object) -> list[dict[str, str]]:
    """The decisions the service would accept for this row, from this viewer.

    Derived rather than restated. Two service rules decide it and both are
    read from what the service itself publishes:

    * `approve_action` and `reject_action` both refuse any row whose status
      is not awaiting a decision, so the gate is membership of the service's
      own `PENDING_STATUSES` tuple rather than a string compared here.
    * `approve_action` additionally refuses when the action requires approval
      and the approver is the requester (separation of duty). The inbox
      publishes that flag as `requires_second_person` and the requester as
      `requested_by_id`, which are the same two values the service's check
      reads, so this is the same predicate over the same inputs.

    Reject carries no separation-of-duty rule in the service, so a requester
    may still withdraw their own request by rejecting it.
    """
    from ion.services.playbook_action_service import PENDING_STATUSES

    if _text(entry.get("status")) not in PENDING_STATUSES:
        return []

    verbs = ["reject"]
    if not _approve_blocked(entry, viewer_id):
        # Approve last, so the destructive-looking option is not the one
        # under the cursor. Same order the page had.
        verbs.append("approve")

    live = entry.get("effective_mode") == "live"
    out = []
    for verb in verbs:
        label, css = _DECISION_CHROME[verb]
        if verb == "approve":
            label += " & dispatch" if live else " (simulate)"
        out.append({"verb": verb, "label": label, "css": css})
    return out


def _approve_blocked(entry: dict, viewer_id: object) -> bool:
    """Whether separation of duty stops *this* viewer approving this row."""
    if not entry.get("requires_second_person"):
        return False
    requester = entry.get("requested_by_id")
    return requester is not None and requester == viewer_id


def _pending_view(entry: dict, viewer_id: object) -> dict[str, Any]:
    """One card in the queue, with everything the markup needs resolved."""
    risk = _text(entry.get("risk_level")).lower()
    readiness_key = _text(entry.get("adapter_readiness"))
    readiness_label, readiness_css = _READINESS.get(
        readiness_key, _READINESS["no_adapter"]
    )
    live = entry.get("effective_mode") == "live"

    row = dict(entry)
    row.update(
        {
            "action_label": _action_label(entry),
            "risk_text": risk or "unrated",
            "risk_css": _RISK_BADGE.get(risk, "badge-ghost"),
            "readiness_label": readiness_label,
            "readiness_css": readiness_css,
            "would_live": live,
            # The adapter is registered but unconfigured and an approval
            # would really dispatch: the one case where the detail line is a
            # warning rather than background.
            "blocked": readiness_key != "ready" and live,
            "requester_label": _user_label(
                entry.get("requested_by"),
                entry.get("requested_by_id"),
                missing="an unknown user",
            ),
            "adapter_line": (
                f"{entry.get('adapter_name') or '—'} · "
                f"{entry.get('adapter_detail') or ''}"
            ),
            "case_label": (
                entry.get("case_title")
                if entry.get("case_title") is not None
                else f"Case {entry.get('case_id')}"
            ),
            "case_severity": _text(entry.get("case_severity")),
            "decisions": _decisions(entry, viewer_id),
            "approve_blocked": _approve_blocked(entry, viewer_id),
        }
    )
    return row


def _decided_view(entry: dict) -> dict[str, Any]:
    """One row of decision history, with its outcome resolved."""
    outcome = entry.get("outcome") or {}
    stage = _text(outcome.get("stage"))
    confirmation_label, confirmation_css = _CONFIRMATION.get(
        _text(outcome.get("external_confirmation")), _CONFIRMATION["none"]
    )

    row = dict(entry)
    row.update(
        {
            "action_label": _action_label(entry),
            "outcome_label": outcome.get("label") or "",
            "outcome_detail": outcome.get("detail") or "",
            "outcome_css": _STAGE_BADGE.get(stage, "badge-ghost"),
            "has_outcome": bool(outcome),
            # Only a real dispatch has anything outside ION to confirm. A
            # simulated run showing "no external confirmation" would read as
            # a dispatch that went unacknowledged.
            "show_confirmation": stage == "dispatched",
            "confirmation_label": confirmation_label,
            "confirmation_css": confirmation_css,
            "requester_label": _user_label(
                entry.get("requested_by"),
                entry.get("requested_by_id"),
                missing="an unknown user",
            ),
            "decider_label": _user_label(
                entry.get("decided_by"), entry.get("decided_by_id"),
                missing="nobody",
            ),
            "case_label": (
                entry.get("case_title")
                if entry.get("case_title")
                else entry.get("case_id")
            ),
            "decided_at": entry.get("updated_at") or entry.get("created_at"),
        }
    )
    return row


def _inbox_view(payload: dict, viewer_id: object) -> dict[str, Any]:
    mode = payload.get("mode") or {}
    return {
        "mode_reason": mode.get("reason"),
        "mode_live": mode.get("effective_mode") == "live",
        "has_mode": bool(mode),
        "pending": [
            _pending_view(e, viewer_id) for e in payload.get("pending") or []
        ],
        "decided": [_decided_view(e) for e in payload.get("decided") or []],
        "pending_count": payload.get("pending_count"),
    }


@router.get("/response-approvals", response_class=HTMLResponse)
def response_approvals_fragment(
    request: Request,
    user: User = Depends(require_permission(_APPROVE_PERM)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The approval inbox as one fragment.

    Replaces four innerHTML writes in response_approvals.html: the mode
    banner, the two sections, the disabled-surface notice and the failure
    alert. The permission is imported from response_api rather than spelled
    again, so the fragment cannot become a softer way in than
    /api/response/actions/inbox, and it is the same permission approve and
    reject are gated on, so every viewer of a button can use it.

    `user` is taken from the dependency rather than ignored: the
    separation-of-duty rule is about *who* is looking, so the buttons cannot
    be rendered without knowing.
    """
    if not response_actions_enabled():
        return templates.TemplateResponse(
            request=request,
            name=FRAGMENT,
            context={"inbox": None, "failed": False, "surface_off": True},
        )

    try:
        inbox = _inbox_view(response_inbox_payload(session), user.id)
    except Exception:
        logger.exception("Response approval fragment could not be rendered")
        # An empty queue and an unreadable one lead to opposite actions on
        # this page in particular: "nothing is waiting for you" ends the
        # shift, "we could not look" means containment decisions may be
        # sitting unanswered. Never render one as the other.
        return templates.TemplateResponse(
            request=request,
            name=FRAGMENT,
            context={"inbox": None, "failed": True, "surface_off": False},
        )

    return templates.TemplateResponse(
        request=request,
        name=FRAGMENT,
        context={"inbox": inbox, "failed": False, "surface_off": False},
    )
