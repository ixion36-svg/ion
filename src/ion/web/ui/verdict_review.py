"""The verdict-review queue and its agreement metrics, as one fragment."""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

#: Matches every route on /api/verdict-review. Spelled here because
#: verdict_review_api states it inline on each route rather than exporting a
#: constant; test_the_fragment_permission_matches_the_json_endpoint reads the
#: permission back off those live routes, so this cannot drift from them
#: without a test failing.
_PERM = "verdict:review"

#: The order the verdict buttons appear in, which a set cannot carry.
#: test_the_button_order_covers_the_services_whole_contract asserts this is
#: exactly verdict_review_service._VALID_VERDICTS, so a verdict added to the
#: service without a button here fails rather than becoming unreachable.
_VERDICT_ORDER = (
    "true_positive",
    "false_positive",
    "benign_true_positive",
    "inconclusive",
)

_VERDICT_BADGE = {
    "true_positive": "badge-error",
    "false_positive": "badge-info",
    "benign_true_positive": "badge-success",
    "inconclusive": "badge-warning",
}

_PRI_BADGE = {
    "critical": "badge-error",
    "high": "badge-warning",
    "medium": "badge-info",
    "low": "badge-success",
}

#: Observable type to the response action_types that apply to it. Mirrors
#: playbook_action_service.DEFAULT_ACTIONS, as the JavaScript's APPLIES map
#: did; an action_type with no entry here is simply never proposed.
_APPLIES = {
    "ip": ("block_ip",),
    "ipv4": ("block_ip",),
    "ipv6": ("block_ip",),
    "domain": ("block_domain",),
    "url": ("block_domain",),
    "user": ("disable_account", "reset_password"),
    "username": ("disable_account", "reset_password"),
    "host": ("quarantine_host",),
    "hostname": ("quarantine_host",),
    "email": ("block_sender",),
}


def _agreement(bob_verdict: object, option: str) -> Optional[bool]:
    """Whether Bob's suggestion agrees with `option`, or None if it abstained.

    Three states, not two. The JavaScript computed `v.bob_verdict === hv`,
    which is False both when Bob chose something else and when Bob chose
    nothing at all, and rendered those two identically. They are different
    claims about the model: "it was wrong about this alert" and "it declined
    to judge this alert" push a reliability number in opposite directions,
    and a reviewer looking at the card is the person who needs to know which
    one they are overriding.

    Returning None rather than False for the abstain case is what lets the
    template keep all three apart with `is true` / `is false` / `else`.
    """
    verdict = plain(bob_verdict)
    if verdict is None or verdict == "":
        return None
    return verdict == option


def _observable_proposals(
    observables: object, catalog: dict[str, dict]
) -> list[dict[str, Any]]:
    """One containment row per distinct (type, value) that has an action.

    Same de-duplication and same filter as containmentHtml(): a type with no
    applicable action, and a repeated observable, produce no row.
    """
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for obs in observables or []:
        if not isinstance(obs, dict):
            continue
        raw_type = obs.get("type")
        value = obs.get("value")
        if not raw_type or not value:
            continue
        key = (str(raw_type).lower(), str(value))
        if key in seen:
            continue
        seen.add(key)
        acts = [catalog[t] for t in _APPLIES.get(key[0], ()) if t in catalog]
        if not acts:
            continue
        out.append({"type": raw_type, "value": value, "actions": acts})
    return out


def _row_view(v: dict, catalog: Optional[dict[str, dict]]) -> dict[str, Any]:
    """One queue card with the derived fields the fragment needs."""
    row = dict(v)
    # plain() on both of these because each feeds a colour-map lookup AND
    # visible text. AlertTriage.status in the same table is already a
    # SQLEnum, so a later conversion of `priority` would render
    # "AlertPriority.HIGH" in the pill while the colour map kept matching on
    # value equality, which is the failure that survives a glance.
    verdict = plain(v.get("bob_verdict"))
    priority = plain(v.get("priority"))

    row["bob_verdict"] = verdict
    row["bob_badge"] = _VERDICT_BADGE.get(verdict, "badge-warning")
    row["priority"] = priority
    row["priority_badge"] = _PRI_BADGE.get(
        str(priority).lower() if priority is not None else "", "badge-ghost"
    )
    row["options"] = [
        {
            "verdict": option,
            "label": option.replace("_", " "),
            "agreement": _agreement(verdict, option),
        }
        for option in _VERDICT_ORDER
    ]
    row["proposals"] = (
        _observable_proposals(v.get("observables"), catalog) if catalog else []
    )
    return row


def _catalog(user: User, session: Session) -> Optional[dict[str, dict]]:
    """Response actions by action_type, or None when they are not available.

    The containment proposals on a card mirror GET /api/response/actions,
    which carries two gates this fragment's own `verdict:review` does not:
    ION_RESPONSE_ACTIONS_ENABLED (the route 404s before any work when the
    feature is off) and `playbook:read`. Both are re-checked here, because
    without them a reviewer holding neither would be served the catalogue by
    the fragment, which is exactly the "softer way in than the API it
    mirrors" failure.

    seed_default_actions is called because the JSON endpoint calls it, so a
    deployment whose table is still empty gets the same catalogue from either
    caller. It only inserts when the table is empty.
    """
    from ion.core.config import get_config

    if not get_config().response_actions_enabled:
        return None
    if not user.has_permission("playbook:read"):
        return None

    from ion.services import playbook_action_service as actions

    actions.seed_default_actions(session)
    return {a["action_type"]: a for a in actions.get_available_actions(session)}


@router.get("/verdict-review", response_class=HTMLResponse)
def verdict_review_fragment(
    request: Request,
    user: User = Depends(require_permission(_PERM)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The agreement metrics and the pending-verdict queue as one fragment.

    Replaces all five innerHTML sites in verdict_review.html: the metrics
    strip, the queue cards, the empty state and the two failure messages. The
    cards carried the containment proposals and a hand-rolled esc(), so the
    whole 172-line script collapses to two mutations.

    It calls verdict_review_service.list_pending_verdicts and
    verdict_metrics, the same two functions /api/verdict-review/pending and
    /metrics call. Neither JSON route holds any logic of its own to extract.

    Both reads are caught separately. The JavaScript treated metrics as
    best-effort and rendered nothing at all when they failed, which leaves
    the queue looking like the whole page loaded; the fragment says the
    metrics could not be read instead, because a missing agreement rate and
    an agreement rate of zero are opposite findings.
    """
    from ion.services import verdict_review_service as vr

    catalog: Optional[dict[str, dict]] = None
    try:
        catalog = _catalog(user, session)
    except Exception:
        # A catalogue failure must not cost the reviewer the queue: the
        # verdict buttons are the point of the page and the proposals are an
        # extra. Cards render without proposals.
        logger.exception("Verdict-review containment catalogue could not be read")

    metrics: Optional[dict] = None
    metrics_failed = False
    try:
        metrics = vr.verdict_metrics(session)
    except Exception:
        logger.exception("Verdict-review metrics could not be read")
        metrics_failed = True

    rows: Optional[list[dict]] = None
    queue_failed = False
    try:
        rows = [_row_view(v, catalog) for v in vr.list_pending_verdicts(session)]
    except Exception:
        logger.exception("Verdict-review queue could not be read")
        # A failed read is not an empty review queue. "Nothing is waiting for
        # a human" and "we could not look" lead to opposite actions, and the
        # first one is what an analyst stops checking the page over.
        queue_failed = True

    return templates.TemplateResponse(
        request=request,
        name="_fragments/verdict_review.html",
        context={
            "metrics": metrics,
            "metrics_failed": metrics_failed,
            "rows": rows,
            "queue_failed": queue_failed,
            "containment_available": catalog is not None,
        },
    )
