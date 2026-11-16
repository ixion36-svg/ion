"""The Bob improvement page: scorecard, disagreement classes, proposals.

Replaces the ten innerHTML writes in de_bob.html (the scorecard, the
feedback table, the proposals table, and the loading and failure markup
each of them had) plus the hand-rolled ``bbEsc()`` they needed.

Three reads, the same three the page used to fetch, each rendered on its
own so one of them failing cannot turn the others into a zero or an empty
list:

  * ``get_bob_scorecard`` — the body of GET /api/de/scorecard
  * ``get_bob_feedback``  — the body of GET /api/de/bob-feedback. The
    scorecard already calls this for its top five classes; the table shows
    every class, which is what the feedback endpoint returns, so the
    fragment calls it too rather than painting the top five as the whole.
  * ``list_proposals``    — the body of GET /api/de/bob-proposals

Nothing was extracted into a ``*_payload()`` helper. Each JSON route is
one call and a dict wrapper, so there is no inline logic to share.

This is a licence-gated page, so the route carries both gates its JSON
counterparts carry, and in the same order:

  * ``require_de_module`` first, because /api/de/* gets it from
    ``include_router(de_router, ..., dependencies=[Depends(require_de_module)])``
    and router dependencies run before route dependencies. With the module
    off it answers 404 before authentication is considered, which is the
    point of a 404 rather than a 401: a licence-gated deployment is
    indistinguishable from one where the endpoint does not exist.
  * ``require_permission("de:read")`` second. All three GETs name that
    permission. Not ``de:approve`` and not ``de:propose``: those are the
    write routes the draft and decision buttons still call, and a read
    locked behind a write permission is a different endpoint. Not
    ``require_page_permission`` either: that redirects to /login, and htmx
    would swap a login form into the middle of the page.
"""
from __future__ import annotations

import logging
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.licensing.gating import require_de_module
from ion.models.bob_tuning_proposal import BobTuningProposalStatus
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

#: The permission the three GET endpoints name. Spelled once so the fragment
#: cannot drift into being a softer way in than the endpoints it mirrors.
PERMISSION = "de:read"

_STATUS_CSS = {
    BobTuningProposalStatus.DRAFT.value: "badge-warning",
    BobTuningProposalStatus.APPROVED.value: "badge-success",
    BobTuningProposalStatus.REJECTED.value: "badge-error",
    BobTuningProposalStatus.REVERTED.value: "badge-ghost",
}

#: Which decision buttons a row may offer, keyed by status.
#:
#: A table rather than the two-branch ``if`` the JavaScript had, because the
#: rule it encodes lives in de_bob_proposal_service and the branch was a
#: second copy of it: approve and reject refuse anything that is not DRAFT,
#: and revert refuses anything that is not APPROVED. Keying it by the enum's
#: own values means a new state added to BobTuningProposalStatus shows up as
#: a missing key here, which is a test failure rather than a row that
#: silently offers nothing.
_APPROVE = {"action": "bbApprove", "label": "Approve & apply", "css": "btn-ghost"}
_REJECT = {"action": "bbReject", "label": "Reject", "css": "btn-ghost btn-error"}
_REVERT = {"action": "bbRevert", "label": "Revert", "css": "btn-ghost btn-error"}
_ACTIONS: dict[str, list[dict[str, str]]] = {
    BobTuningProposalStatus.DRAFT.value: [_APPROVE, _REJECT],
    BobTuningProposalStatus.APPROVED.value: [_REVERT],
    BobTuningProposalStatus.REJECTED.value: [],
    BobTuningProposalStatus.REVERTED.value: [],
}


def _number(source: object, key: str) -> Optional[int | float]:
    """A measurement, or None when nobody computed one.

    ``0`` stays ``0``. The JavaScript's ``value || 0`` printed 0 for a
    missing count, and a truthiness test the other way prints nothing for a
    count that was measured at zero. A rate of zero and a rate that was
    never computed lead to opposite decisions, so neither substitution is a
    port. A bool is not a number even though ``bool`` is an ``int``: ``True``
    must not render as 1%.
    """
    if not isinstance(source, dict) or key not in source:
        return None
    value = source[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _direction(drift: object) -> Optional[str]:
    """The service's word for the drift, or None when it never said.

    ``"flat"`` is a finding: recent and older agree. A missing direction is
    not that finding, and the JavaScript's ``d.direction || 'flat'`` said it
    was. An empty string is the same absence.
    """
    if not isinstance(drift, dict) or "direction" not in drift:
        return None
    value = plain(drift["direction"])
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _enabled(few: object) -> Optional[bool]:
    """The disclosure flag, kept at three states.

    The JavaScript rendered anything falsy as "disabled", so a payload that
    never reported the flag read as retrieval being off. Only a real bool is
    a report. Anything else, including the string ``"no"``, is unknown.
    """
    if not isinstance(few, dict) or "gold_exemplar_retrieval_enabled" not in few:
        return None
    value = few["gold_exemplar_retrieval_enabled"]
    if isinstance(value, bool):
        return value
    return None


def _view(payload: object) -> dict[str, Any]:
    """The scorecard fields the stats row shows, with absences kept absent."""
    summary = payload.get("summary") if isinstance(payload, dict) else None
    if not isinstance(summary, dict):
        summary = {}
    drift = summary.get("drift")
    if not isinstance(drift, dict):
        drift = {}
    few = summary.get("few_shot")
    if not isinstance(few, dict):
        few = {}
    note = few.get("note")
    return {
        "agreement_rate": _number(summary, "agreement_rate"),
        "agreed": _number(summary, "agreed"),
        "scored": _number(summary, "scored"),
        "delta": _number(drift, "delta"),
        "direction": _direction(drift),
        "disagreement_classes": _number(summary, "disagreement_classes"),
        "total_disagreements": _number(summary, "total_disagreements"),
        "few_shot_enabled": _enabled(few),
        "few_shot_note": note if isinstance(note, str) else "",
    }


def _class_row(c: object) -> dict[str, Any]:
    """One disagreement class, with the draft button's arguments beside it.

    A class that is not an object raises, and the route treats that as the
    feedback read failing. Dropping the bad row and rendering the rest would
    under-count the disagreements, which is the same lie as printing zero
    for a read that did not finish.
    """
    if not isinstance(c, dict):
        raise TypeError("Bob feedback class was not an object")
    reasons: list[str] = []
    raw = c.get("sample_reasons")
    # A string is iterable, and walking it would render one letter per line.
    # The service returns a list; anything else is no sample, not a crash
    # and not a character-by-character table.
    if isinstance(raw, list):
        for reason in raw:
            if reason is None:
                continue
            reasons.append(str(reason))
    return {
        "rule_name": c.get("rule_name"),
        "bob_verdict": c.get("bob_verdict"),
        "human_verdict": c.get("human_verdict"),
        "count": _number(c, "count"),
        "sample_reasons": reasons,
        "draft_args": [c.get("rule_name"), c.get("bob_verdict"), c.get("human_verdict")],
    }


def _proposal_row(p: object) -> dict[str, Any]:
    """One proposal with the status pill and the decision buttons derived.

    ``status`` is a SQLEnum column. ``to_dict`` hands the member back, and
    FastAPI was what turned it into ``"draft"`` on the way out of the JSON
    route. ``plain`` does that here. A missing id offers no button: the
    delegated listener would call the action with nothing, and an id of 0
    is still an id, so the test is ``is not None`` rather than truthiness.
    """
    if not isinstance(p, dict):
        raise TypeError("Bob proposal was not an object")
    status = plain(p.get("status"))
    status = None if status is None else str(status)
    proposal_id = p.get("id")
    if isinstance(proposal_id, bool) or not isinstance(proposal_id, int):
        proposal_id = None

    def _text(key: str) -> Optional[str]:
        value = p.get(key)
        return value if isinstance(value, str) else None

    return {
        "id": proposal_id,
        "title": p.get("title") if isinstance(p.get("title"), str) else "",
        "problem_statement": _text("problem_statement") or "",
        "rule_name": _text("rule_name"),
        "status": status,
        "status_css": _STATUS_CSS.get(status, "badge-ghost"),
        "created_by_username": _text("created_by_username"),
        "decided_by_username": _text("decided_by_username"),
        "reverted_by_username": _text("reverted_by_username"),
        "actions": _ACTIONS.get(status, []) if proposal_id is not None else [],
    }


def _classes(payload: object) -> list[dict[str, Any]]:
    classes = payload.get("classes") if isinstance(payload, dict) else None
    if not isinstance(classes, list):
        raise TypeError("Bob feedback returned no class list")
    return [_class_row(c) for c in classes]


def _proposals(rows: object) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise TypeError("Bob proposals returned no list")
    return [_proposal_row(p) for p in rows]


@router.get(
    "/de-bob",
    response_class=HTMLResponse,
    dependencies=[
        Depends(require_de_module),
        Depends(require_permission(PERMISSION)),
    ],
)
def de_bob_fragment(
    request: Request,
    # The same bounds GET /api/de/scorecard and /bob-feedback declare. A
    # window the service was not written to answer is a 422, not a fragment
    # that says the read failed: a bad request and an unreadable ledger lead
    # to different actions, and the failure message is reserved for the second.
    days: int = Query(90, ge=1, le=365),
    # Constrained rather than a bare str, so a filter value the service
    # cannot parse is a 422 instead of being caught below and worded as
    # "the read failed". The members are the proposal enum's own states plus
    # the service's "all" sentinel, and a test holds them to that.
    status: Literal["all", "draft", "approved", "rejected", "reverted"] = Query(
        "all", description="draft | approved | rejected | reverted | all"
    ),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """Scorecard, disagreement classes and proposals as one fragment.

    Each read has its own try. A scorecard that cannot be computed must not
    blank the proposal queue, and a proposal query that fails must not turn
    a measured agreement rate into an error page that hides it. Within a
    failed section the fragment says the read failed. It does not print 0,
    and it does not say the analysts agree.
    """
    from ion.services.de_bob_proposal_service import list_proposals
    from ion.services.de_bob_service import get_bob_feedback, get_bob_scorecard

    context: dict[str, Any] = {
        "days": days,
        "status": status,
        "card": None,
        "scorecard_failed": False,
        "classes": None,
        "feedback_failed": False,
        "proposals": None,
        "proposals_failed": False,
    }
    try:
        context["card"] = _view(get_bob_scorecard(session, days=days))
    except Exception:
        logger.exception("Bob scorecard fragment could not be rendered")
        context["scorecard_failed"] = True
    try:
        context["classes"] = _classes(get_bob_feedback(session, days=days))
    except Exception:
        logger.exception("Bob feedback fragment could not be rendered")
        context["feedback_failed"] = True
    try:
        context["proposals"] = _proposals(list_proposals(session, status=status))
    except Exception:
        logger.exception("Bob proposals fragment could not be rendered")
        context["proposals_failed"] = True
    return templates.TemplateResponse(
        request=request, name="_fragments/de_bob.html", context=context
    )
