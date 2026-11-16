"""The Detection Proposals table, rows and action buttons together.

Replaces four innerHTML writes in de_proposals.html (the loading placeholder,
the load-failure alert, the empty state and the table) plus the hand-rolled
`dpEsc()`, `dpPill()`, `dpSource()`, `dpOutcome()` and `dpRender()` they
needed.

This page is licence-gated, same as System Quirks, so the fragment carries
both gates its JSON counterpart carries and in the same order:

  * ``require_de_module`` first, because /api/de/proposals gets it from
    ``include_router(de_router, ..., dependencies=[Depends(require_de_module)])``
    and router dependencies run before route dependencies. With the module
    off it answers 404 before authentication is considered, which is the
    point of a 404 rather than a 401: a licence-gated deployment is
    indistinguishable from one where the endpoint does not exist.
  * ``require_permission("de:read")`` second, the permission GET
    /api/de/proposals names. Not ``require_page_permission``: that redirects
    to /login, and htmx would swap a login form into the middle of the page.

Three outcomes, three different renders, because they lead to different
actions:

  module off   404, no fragment at all. static/js/htmx-errors.js says it is
               no longer available. Nothing about the proposal store leaks.
  read failed  200 with a fragment that says the read failed. Never 0 rows,
               because "no tuning drafts are waiting" and "we could not look"
               are opposite findings.
  no proposals 200 with the empty state, and a filtered empty is worded as
               a filter rather than as "nothing has ever been drafted".
"""
from __future__ import annotations

import logging
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.licensing.gating import require_de_module
from ion.models.detection_proposal import (
    DetectionProposalSource,
    DetectionProposalStatus,
)
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

#: The permission GET /api/de/proposals names. Spelled once so the fragment
#: cannot drift into being a softer way in than the endpoint it mirrors.
#: Confirmed from the live route, not from the decorator text: the list
#: fetch is require_permission('de:read') plus require_de_module from the
#: router mount. The write routes on the same path are de:propose and stay
#: JSON; this fragment only reads.
PERMISSION = "de:read"

# The JavaScript's else branch was badge-info, including draft and
# duplicate. Only the two decided states had their own colour, so a status
# the map does not name stays info rather than turning neutral.
_STATUS_CSS = {
    DetectionProposalStatus.APPLIED.value: "badge-success",
    DetectionProposalStatus.REJECTED.value: "badge-error",
}
_STATUS_FALLBACK_CSS = "badge-info"

_EDIT = {"action": "dpEdit", "label": "Edit", "css": "btn-ghost"}
_APPLY = {
    "action": "dpDecide", "label": "Apply", "css": "btn-ghost",
    "decision": "applied",
}
_REJECT = {
    "action": "dpDecide", "label": "Reject", "css": "btn-ghost btn-error",
    "decision": "rejected",
}
_MEASURE = {"action": "dpMeasure", "label": "Measure outcome", "css": "btn-ghost"}

#: Which actions a status may offer. Keyed by the enum's own values so a
#: state added to DetectionProposalStatus is a missing key here, a test
#: failure, rather than a row that silently offers nothing.
#:
#: The rules are the service's, not a second copy invented for the table:
#: update_proposal and decide_proposal reject anything that is not DRAFT,
#: measure_outcome rejects anything that is not APPLIED. A row can still
#: be APPLIED and unmeasurable (no rule, or no applied_at); that second
#: refusal is applied per row in ``_actions_for``, because a status table
#: cannot see it.
_ACTIONS: dict[str, list[dict[str, str]]] = {
    DetectionProposalStatus.DRAFT.value: [_EDIT, _APPLY, _REJECT],
    DetectionProposalStatus.APPLIED.value: [_MEASURE],
    DetectionProposalStatus.REJECTED.value: [],
    DetectionProposalStatus.DUPLICATE.value: [],
}

_MITRE_LIMIT = 6


def _js_num(value: object) -> str:
    """How JavaScript stringifies a number, which is what the old cell showed.

    ``str(0.0)`` is ``"0.0"``. The table concatenated the JSON number, and
    JavaScript prints that as ``"0"``. A measured zero has to read as zero;
    ``0.0%`` next to a row that says ``0%`` looks like two different figures.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return str(value)
    number = float(value)
    if number.is_integer():
        return str(int(number))
    # drop_pct is stored to 1 decimal and the per-day rates to 2. More
    # digits than that is float noise, and trailing zeros are not what
    # JavaScript printed.
    return f"{number:.2f}".rstrip("0").rstrip(".")


def _num_text(value: object) -> Optional[str]:
    """The display text for a number, or None when nobody recorded one.

    ``is not None``, not truthiness. Zero is a measurement.
    """
    if value is None:
        return None
    return _js_num(value)


def _mitre(raw: object) -> list[str]:
    """The first six techniques, which is as many as the JavaScript drew.

    A missing list is no techniques. It is not an error and it is not the
    string "None". Anything that is not a list is the same: the column is
    a JSON list, and slicing a string would render its characters.
    """
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        if item is None:
            continue
        out.append(item if isinstance(item, str) else str(item))
        if len(out) == _MITRE_LIMIT:
            break
    return out


def _actions_for(p: dict[str, Any], status: Optional[str]) -> list[dict[str, str]]:
    """The buttons this row may offer.

    Status first, then the measure refusal the status cannot see.
    ``measure_outcome`` raises for an applied proposal that has no rule or
    no ``applied_at``, and a button that only ever toasts that refusal is
    not an action. ``applied_at`` is compared with ``is None``: it is a
    timestamp, and a missing one is not the same claim as a stored one.
    """
    actions = list(_ACTIONS.get(status, []))
    if any(a["action"] == "dpMeasure" for a in actions):
        if not p.get("rule_name") or p.get("applied_at") is None:
            actions = [a for a in actions if a["action"] != "dpMeasure"]
    return actions


def _outcome_view(status: Optional[str], outcome: object) -> dict[str, Any]:
    """Which outcome sentence this row is allowed to say.

    The JavaScript quoted ``comparable`` and refused the top-level
    ``drop_pct``, because that one divides a full baseline by however
    little time has passed since the change and flatters a change that
    landed yesterday. That refusal is the whole point of the block, so the
    view never carries the uneven figure forward for the template to
    accidentally print.

    ``sufficient_observation`` stays three states. The JavaScript's
    ``!c.sufficient_observation`` folded "never judged" into "judged too
    short", and a proposal whose windows were not compared is not a
    proposal known to have been watched for too little time. A recorded
    ``false`` is the short window. A recorded ``true`` with no percentage
    is the other honest refusal: the windows were long enough and there
    was still nothing to divide by (no baseline). Zero is neither of
    those. A drop of 0 is a measurement that the noise did not change.

    ``lost_confirmed_threats`` stays three states for the same reason.
    Only a real ``True`` is "this change may have silenced a detection".
    """
    view: dict[str, Any] = {
        "kind": "absent",
        "legacy_drop_pct": None,
        "drop_pct": None,
        "before_count": None,
        "after_count": None,
        "window_days_exact": None,
        "before_per_day": None,
        "after_per_day": None,
        "reason": None,
        "lost": None,
        "lost_before": None,
    }
    if not isinstance(outcome, dict):
        view["kind"] = (
            "unmeasured" if status == DetectionProposalStatus.APPLIED.value else "absent"
        )
        return _with_texts(view)

    comparable = outcome.get("comparable")
    if not isinstance(comparable, dict):
        view["kind"] = "legacy"
        view["legacy_drop_pct"] = outcome.get("drop_pct")
        return _with_texts(view)

    sufficient = comparable.get("sufficient_observation")
    drop = comparable.get("drop_pct")
    view["drop_pct"] = drop
    view["before_count"] = comparable.get("before_count")
    view["after_count"] = comparable.get("after_count")
    view["window_days_exact"] = comparable.get("window_days_exact")
    view["before_per_day"] = comparable.get("before_per_day")
    view["after_per_day"] = comparable.get("after_per_day")
    reason = comparable.get("reason")
    view["reason"] = reason if isinstance(reason, str) and reason else None

    threats = outcome.get("confirmed_threats")
    if isinstance(threats, dict):
        lost = threats.get("lost_confirmed_threats")
        if lost is True:
            view["lost"] = True
        elif lost is False:
            view["lost"] = False
        else:
            view["lost"] = None
        view["lost_before"] = threats.get("before_count")

    if sufficient is True and drop is not None:
        view["kind"] = "quoted"
    elif sufficient is False:
        view["kind"] = "insufficient"
    elif sufficient is True:
        view["kind"] = "no_percentage"
    else:
        view["kind"] = "unjudged"
    return _with_texts(view)


def _with_texts(view: dict[str, Any]) -> dict[str, Any]:
    for raw, text in (
        ("legacy_drop_pct", "legacy_drop_text"),
        ("drop_pct", "drop_text"),
        ("window_days_exact", "window_text"),
        ("before_per_day", "before_rate_text"),
        ("after_per_day", "after_rate_text"),
    ):
        view[text] = _num_text(view[raw])
    return view


def _as_str(value: object) -> Optional[str]:
    """An enum member as its value, or None. Never the enum repr."""
    value = plain(value)
    if value is None:
        return None
    return str(value)


def _row(p: dict[str, Any]) -> dict[str, Any]:
    """One proposal with the fields the table needs derived."""
    row = dict(p)
    status = _as_str(p.get("status"))
    row["status"] = status
    row["status_css"] = _STATUS_CSS.get(status, _STATUS_FALLBACK_CSS)
    row["change_type"] = _as_str(p.get("change_type"))
    source = _as_str(p.get("source"))
    row["source"] = source
    row["is_bob"] = source == DetectionProposalSource.BOB.value
    row["mitre"] = _mitre(p.get("mitre_techniques"))
    row["actions"] = _actions_for(p, status)
    row["outcome_view"] = _outcome_view(status, p.get("outcome"))
    # Texts, not a decision. The template still gates on `is not none` of
    # the raw number, so a zero stays visible even if a text were dropped.
    row["fp_text"] = _num_text(p.get("expected_fp_reduction"))
    row["hours_text"] = _num_text(p.get("expected_hours_reclaimed"))
    return row


@router.get(
    "/de-proposals",
    response_class=HTMLResponse,
    dependencies=[
        Depends(require_de_module),
        Depends(require_permission(PERMISSION)),
    ],
)
def de_proposals_fragment(
    request: Request,
    # Constrained rather than bare str, so a filter value the service
    # cannot parse is a 422 instead of being caught below and worded as
    # "the read failed". A bad request and an unreadable store lead to
    # different actions, and the failure message is reserved for the second.
    # The members are the service's own states plus its "all" sentinel, and
    # a test holds them to that.
    status: Literal["all", "draft", "applied", "rejected", "duplicate"] = Query(
        "all", description="draft | applied | rejected | duplicate | all"
    ),
    source: Literal["all", "bob", "human"] = Query(
        "all", description="bob | human | all"
    ),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The filtered proposal table as one fragment.

    Calls ``de_proposal_service.list_proposals``, which is the whole body
    of GET /api/de/proposals, so the two cannot answer differently. Nothing
    was extracted into a ``*_payload()`` helper because there is nothing
    inline in that route to share: it is one call and a dict wrapper.
    """
    from ion.services.de_proposal_service import list_proposals

    context: dict[str, Any] = {"status": status, "source": source}
    try:
        proposals = [
            _row(p) for p in list_proposals(session, status=status, source=source)
        ]
    except Exception:
        logger.exception("Detection proposals fragment could not be rendered")
        context.update({"proposals": None, "failed": True})
        return templates.TemplateResponse(
            request=request, name="_fragments/de_proposals.html", context=context
        )

    context.update({"proposals": proposals, "failed": False})
    return templates.TemplateResponse(
        request=request, name="_fragments/de_proposals.html", context=context
    )
