"""The DE Workbench: tuning requests, campaigns, proposals, quirks, content pack.

de_workbench.html fetched five endpoints and built its tables out of string
concatenation at four innerHTML sites (the request rows, the campaign rows,
the three proposal columns, and the quirks-due list) with a hand-rolled
`esc()`, an `ageOf()` and two colour tables. All of it is rendered here, and
Jinja escapes.

Five regions, five fragment routes. Four of them read, and each read is its
own request on purpose rather than four `try` blocks inside one route: the
page is a summary of four different stores, and a quirks query that times out
must not be able to blank the tuning-request queue the DE team works from.
One route would make every region share the fate of the slowest and the
flakiest of them, and the HTTP failure of that one route (a 500, a dropped
connection) would take all four down at once where separate routes take one.

Each region owns exactly one of the four KPI tiles at the top of the page,
because each tile is derived from that region's read and nothing else. The
tile is sent back as an `hx-swap-oob` element beside the region's panel, so a
region's figure and its table come from the same read. The alternative was a
fifth route re-reading all four stores to paint the tiles, which doubles the
database work and lets the tile and the table below it disagree.

The fifth region is the content pack, which reads nothing. It exists as a
fragment only so the Import control can be withheld from a viewer who does
not hold the permission the import POST checks: /de passes no user into the
template, so the page shell cannot make that decision and server.py is not
this conversion's file.

What the JavaScript got wrong, as opposed to merely built badly:

  * Every one of the four loaders turned a non-OK response into empty data.
    `r.ok ? r.json() : { requests: [] }` and its three siblings meant a 500
    or a 403 painted "No open tuning requests - the queue is clear.", a
    proposals board of three "none" columns with a KPI of 0, and "Nothing
    due within 7 days." A read that did not happen is not a finding, and
    those three sentences each end a shift.
  * `p.outcome_json.fp_reduction_pct` names two things that do not exist.
    `DetectionProposal.to_dict()` emits the column as `outcome`, and no
    code in ION writes `fp_reduction_pct`; the measured figure lives at
    `outcome["comparable"]["drop_pct"]`. So the "measured -N% FP" branch was
    unreachable and every applied proposal showed its *forecast* labelled
    "exp.", including proposals with a real measurement sitting on the row.
  * A quirk due in the future always read "review 1h". `ageOf()` divides a
    negative interval, fails the `>= 1` test, and `Math.max(1, ...)` floors
    the result at 1, so a review due in six days and one due in two hours
    printed the same word. The `.replace('d', 'd out')` that was meant to
    make it read "3d out" could never fire, because a past date took the
    overdue branch instead.
  * The overdue flag was computed in the viewer's timezone against a
    UTC-stored instant. `new Date("2026-11-01T09:00:00")` parses a zoneless
    string as local, so for an analyst at UTC+10 a quirk that lapsed up to
    ten hours ago still read as "review 1h", while `quirk_match` had already
    stopped annotating with it. The page and the engine disagreed by the
    viewer's offset. `SystemQuirk.is_expired()` is the engine's own answer
    and is what the row carries now.
  * `href="' + esc(gitlab_issue_url) + '"` escapes characters, not schemes.
    A `javascript:` value in that column rendered a link that executed on
    click. It goes through `|safe_url` now.
  * The campaign cells concatenated the numbers raw, so a campaign arriving
    without `cost_hours` rendered the literal text "nullh".
  * `Math.max.apply(null, openish.map(...))` on a request whose `created_at`
    was null measured its age from the epoch, which reads as "oldest 20700d".

The gates are the ones /api/de/* carries, in the same order:

  * ``require_de_module`` first, because the JSON endpoints get it from
    ``include_router(de_router, ..., dependencies=[Depends(require_de_module)])``
    and router dependencies resolve before route dependencies. With the
    module off every fragment here answers 404 before authentication is
    considered, which is the point: a licence-gated deployment looks exactly
    like one where the endpoint does not exist. A 401 would tell an
    unlicensed caller the feature is there and they are merely not signed in.
  * ``require_permission("de:read")`` second. All five endpoints these
    fragments mirror the reads of name that permission. Not ``de:propose``:
    that is the gate on the triage, close, draft and import writes the
    buttons still call, and a read locked behind a write permission is a
    different endpoint. Not ``require_page_permission`` either: that
    redirects to /login, and htmx would swap a login form into the middle of
    the page.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.licensing.gating import require_de_module
from ion.models.detection_proposal import DetectionProposalStatus
from ion.models.system_quirk import SystemQuirkStatus
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

# Reused from the DE pages that already own these shapes rather than defined a
# second time here. A noise campaign is de_metrics' row and a proposal is
# de_proposals' row; this page shows a summary of both, and a fifth definition
# of either is how the summary starts disagreeing with the page it summarises.
from ion.web.ui.de_metrics import campaign_rows
from ion.web.ui.de_proposals import _num_text
from ion.web.ui.de_proposals import _row as proposal_row
from ion.web.ui.de_quirks import _row as quirk_row

logger = logging.getLogger(__name__)

router = APIRouter()

#: The permission the five read endpoints this page mirrors all name. Spelled
#: once so no fragment here can drift into being a softer way in than the
#: endpoint it mirrors.
PERMISSION = "de:read"

#: The permission the writes behind this page's buttons carry: POST
#: /api/de/tuning-requests/{id}/triage, /close and /link-proposal, POST
#: /api/de/proposals/draft, POST /api/de/proposals, and POST
#: /api/de/content-pack/import. Every one of them is de:propose, so one
#: constant decides every button on the page.
#:
#: Stated here rather than imported from ui.de_metrics, which holds the same
#: string for the same reason. A permission name is not a row shape, and the
#: live route is its authority: test_the_action_gate_matches_the_write_routes
#: reads the gate back off each of those six routes, so this cannot drift from
#: them without a test failing. Importing it would couple this page's buttons
#: to a module that is mid-conversion for no gain.
PROPOSE_PERMISSION = "de:propose"

_REQUESTS_FRAGMENT = "_fragments/de_workbench_requests.html"
_CAMPAIGNS_FRAGMENT = "_fragments/de_workbench_campaigns.html"
_PROPOSALS_FRAGMENT = "_fragments/de_workbench_proposals.html"
_QUIRKS_FRAGMENT = "_fragments/de_workbench_quirks.html"
_CONTENT_PACK_FRAGMENT = "_fragments/de_workbench_content_pack.html"

#: The window /api/de/metrics was fetched with. Not a control: the page has
#: never offered one, and inventing one in a port is a new feature whose
#: absence is not a defect.
CAMPAIGN_DAYS = 30

#: How many campaigns the panel shows, from `.slice(0, 6)`.
CAMPAIGNS_SHOWN = 6

#: How many quirks the due list shows, from `.slice(0, 6)`.
QUIRKS_SHOWN = 6

#: How far ahead a review counts as due, from `7 * 864e5`.
QUIRK_WINDOW = timedelta(days=7)

#: How many proposals each decided column shows, from `.slice(0, 4)` and
#: `.slice(0, 3)`. Draft was not sliced and still is not: a draft is the
#: column somebody has to act on.
APPLIED_SHOWN = 4
REJECTED_SHOWN = 3

#: How much of a request's free-text details the cell shows, from
#: `.slice(0, 160)`.
DETAILS_CHARS = 160

#: The analyst-facing wording for each reason, keyed by the model's own
#: vocabulary so a reason added to TUNING_REQUEST_REASONS is a missing key
#: here, which a test catches, rather than a cell that renders the raw
#: `false_positive`.
REASON_LABELS: dict[str, str] = {
    "false_positive": "False positive",
    "noisy": "Too noisy",
    "threshold": "Threshold wrong",
    "duplicate": "Duplicate",
    "other": "Other",
}

#: The pill colour per status, as daisyUI badge classes rather than the old
#: `STATUS_CLS` table's bespoke utilities, which is the choice de_quirks,
#: de_proposals and de_bob already made for their pills.
#:
#: It is also the only safe choice for a class name that lives in a Python
#: module. Tailwind's `@source` list in frontend/tailwind-daisy.input.css
#: covers the templates and `src/ion/web/*.py`, and that glob does not reach
#: `src/ion/web/ui/`, so a bespoke utility named only here would stop being
#: emitted at the next CSS build. That is the same "the sweep cannot reach
#: it" failure this whole conversion exists to remove, moved from a
#: JavaScript string into a Python one. daisyUI's component classes are in
#: daisyui.css unconditionally, so they do not depend on the scan. Every
#: bespoke utility this page still uses is a literal in its templates, which
#: the scan does cover.
REQUEST_STATUS_CSS: dict[str, str] = {
    "open": "badge-error",
    "triaged": "badge-warning",
    "linked": "badge-info",
    "closed": "badge-ghost",
}
REQUEST_STATUS_FALLBACK_CSS = "badge-ghost"

_TRIAGE = {"action": "dwTriage", "label": "Triage", "css": "btn-ghost"}
_DRAFT = {"action": "dwDraftForRequest", "label": "Draft proposal", "css": "btn-primary"}
_CLOSE = {"action": "dwClose", "label": "Close", "css": "btn-ghost"}

#: Which buttons a request may offer, keyed by the model's own status
#: vocabulary so a status added to TUNING_REQUEST_STATUSES shows up as a
#: missing key here, which is a test failure rather than a row that silently
#: offers nothing.
#:
#: The rules are de_tuning_request_service's, read off its refusals rather
#: than invented for the table: `triage_request` raises for anything that is
#: not "open", and `link_proposal` and `close_request` raise for "closed".
#: That service states them inline, so there is no constant to import the way
#: investigation_queue imports CANCELLABLE_STATUSES; the table is the nearest
#: thing to a single definition this page can hold, and a test pins it to the
#: model's tuple.
REQUEST_ACTIONS: dict[str, list[dict[str, str]]] = {
    "open": [_TRIAGE, _DRAFT, _CLOSE],
    "triaged": [_DRAFT, _CLOSE],
    "linked": [_DRAFT, _CLOSE],
    "closed": [],
}

#: Which proposal statuses count as "in flight" for the KPI, and which column
#: each decided status lands in. Keyed by the enum's own values.
_DRAFT_STATUS = DetectionProposalStatus.DRAFT.value
_APPLIED_STATUS = DetectionProposalStatus.APPLIED.value
_REJECTED_STATUS = DetectionProposalStatus.REJECTED.value


def _now() -> datetime:
    """Naive UTC, which is what the DE columns store.

    Every DE service defines this line for itself (de_proposal_service,
    de_quirk_service, de_bob_proposal_service, de_content_pack_service) because
    ION has no shared definition to import. This matches theirs, and in
    particular matches the clock `SystemQuirk.is_expired` and
    `de_quirk_service._active_quirks` compare review dates against, so the
    page's idea of "due" is the register's.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _as_dt(raw: object) -> Optional[datetime]:
    """An isoformatted DE timestamp back as a datetime, or None.

    `to_dict()` isoformats the column for JSON. The parse is
    de_quirk_service's, not a second answer to what counts as a readable DE
    timestamp: it strips a "Z" and returns naive UTC, which is what these
    columns hold.
    """
    if isinstance(raw, datetime):
        return raw
    from ion.services.de_quirk_service import _parse_dt

    return _parse_dt(raw)


def _age_text(created: Optional[datetime], now: datetime) -> Optional[str]:
    """How long a request has been waiting, or None when nobody recorded when.

    A duration, not a timestamp, which is why it is computed here at all: a
    duration carries no timezone, so the server's clock gives the same answer
    as the viewer's and the `ts` macro's rule does not apply. It is as stale as
    the fragment, which is exactly as stale as the JavaScript's was, since that
    computed it once at load too. The instant itself is rendered beside it
    through the macro.

    None rather than a number when `created_at` is missing.
    `Math.max.apply(null, ...)` over `new Date(null)` measured the age from the
    epoch and printed "oldest 20700d".

    Under an hour reads "<1h" rather than "1h". `Math.max(1, round(d * 24))`
    floored everything newer than 90 minutes at the same word, so a request
    raised a minute ago and one raised an hour ago were indistinguishable.
    """
    if created is None:
        return None
    seconds = (now - created).total_seconds()
    if seconds < 0:
        # A request stamped in the future is a clock problem, not an age.
        return None
    days = seconds / 86400.0
    if days >= 1:
        return f"{int(days)}d"
    hours = seconds / 3600.0
    if hours < 1:
        return "<1h"
    return f"{int(hours)}h"


def _oldest_text(ages: list[str], count: int) -> str:
    """The sub-line under the open-request count.

    "queue clear" only when the queue really is clear, which the JavaScript
    also got right. A queue with rows but no readable timestamps says so
    instead of claiming an age.
    """
    if count == 0:
        return "queue clear"
    if not ages:
        return "age unknown"
    return f"oldest {ages[0]}"


def _clip(text: object, limit: int) -> Optional[str]:
    """The first `limit` characters, or None when there is no text at all.

    None rather than "" so the cell can tell "no details were given" from
    details that happen to be empty.
    """
    if text is None:
        return None
    value = str(text)
    return value[:limit] if value else None


def _evidence_number(request_row: dict[str, Any], key: str) -> Optional[int | float]:
    """A figure out of `evidence_json`, or None when it is not in there.

    Zero false positives in the last seven days is a measurement and the
    interesting one: it says the noise the analyst complained about has already
    stopped. A bool is not a number even though `bool` is an `int`, so `True`
    cannot render as one alert, and a string is not one either.

    The raw number, not its text. Every template here gates on the raw value
    and prints the text beside it, which is de_proposals' arrangement and the
    reason for it: `_num_text(0)` is the string "0", and a non-empty string is
    truthy, so a gate written on the text would survive being weakened to
    truthiness and the `is not none` would be decorative. A mutation pass is
    what showed that, not reading it.
    """
    evidence = request_row.get("evidence_json")
    if not isinstance(evidence, dict):
        return None
    value = evidence.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _request_row(raw: dict[str, Any], now: datetime, *, can_propose: bool) -> dict[str, Any]:
    """One tuning request as the queue needs it.

    `plain` on the status even though `TuningRequest.status` is a `String(16)`
    today. ION keeps status as a `SQLEnum` on most tables, and if this one is
    ever tightened, value equality keeps the pill's colour correct while the
    pill starts reading "TuningRequestStatus.OPEN". That is the failure that
    survives a glance, and two earlier conversions hit it independently.
    """
    status = plain(raw.get("status"))
    status = None if status is None else str(status)
    created = _as_dt(raw.get("created_at"))
    reason = raw.get("reason")
    reason = None if reason is None else str(reason)
    return {
        "id": raw.get("id"),
        "rule_name": raw.get("rule_name"),
        # The raw value when the vocabulary does not name it, which is what
        # `REASON_LABELS[r.reason] || r.reason` did. An unlabelled reason is
        # still evidence; blanking it would hide why the request was raised.
        "reason_label": REASON_LABELS.get(reason, reason),
        "details": _clip(raw.get("details"), DETAILS_CHARS),
        "created_at": created,
        "age_text": _age_text(created, now),
        # Raw and text together. The cell gates on the number and prints the
        # text, so a measured 0 stays visible and the gate stays load-bearing.
        "fp_7d": _evidence_number(raw, "fp_alerts_7d"),
        "fp_7d_text": _num_text(_evidence_number(raw, "fp_alerts_7d")),
        "gitlab_issue_url": raw.get("gitlab_issue_url"),
        "gitlab_issue_iid": raw.get("gitlab_issue_iid"),
        "status": status,
        "status_css": REQUEST_STATUS_CSS.get(status, REQUEST_STATUS_FALLBACK_CSS),
        # Both halves checked: the status the service would accept, and the
        # permission the POST behind the button checks. A button that only ever
        # produces a 403 is a worse answer than no button, and the JavaScript
        # offered all three to every reader.
        "actions": REQUEST_ACTIONS.get(status, []) if can_propose else [],
    }


def _requests_view(payload: object, *, can_propose: bool) -> dict[str, Any]:
    """The open part of the queue, with its count and its oldest age.

    "Open" is `status != 'closed'`, which is the filter the JavaScript applied
    client-side and is kept because the KPI tile says "Open requests". A
    request list that is not a list raises, and the route words that as the
    read having failed: dropping it and rendering nothing would under-count the
    queue, which is the same lie as printing zero for a read that did not
    finish.
    """
    rows = payload.get("requests") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise TypeError("tuning requests payload carried no request list")
    now = _now()
    openish = [
        _request_row(r, now, can_propose=can_propose)
        for r in rows
        if isinstance(r, dict) and plain(r.get("status")) != "closed"
    ]
    # The rows arrive newest first, so the oldest readable age is the last one
    # that has a timestamp. Sorted on the instant rather than on the age text,
    # because "9h" and "10d" do not compare as strings.
    dated = sorted(
        (r for r in openish if r["created_at"] is not None),
        key=lambda r: r["created_at"],
    )
    ages = [r["age_text"] for r in dated if r["age_text"] is not None]
    return {
        "rows": openish,
        "count": len(openish),
        "oldest_text": _oldest_text(ages, len(openish)),
    }


def _campaigns_view(payload: object) -> dict[str, Any]:
    """The costliest campaigns and the two figures the KPI tile quotes.

    The rows are `de_metrics.campaign_rows`, so the summary on this page and
    the full table on /de-metrics cannot disagree about a rule's cost. Only
    three of its columns are shown here; the rest are the drill-down that page
    has and this one does not.

    `addressable_hours` and `campaign_count` stay None when the summary did not
    carry them. The JavaScript got that right with `!= null` and the port keeps
    it: a zero here is the finding that there is no reclaimable analyst time in
    the window, and relabelling a missing measurement as that finding reads as
    "this estate has no noise".
    """
    data = payload if isinstance(payload, dict) else {}
    summary = data.get("summary")
    summary = summary if isinstance(summary, dict) else {}
    hours = summary.get("addressable_hours")
    count = summary.get("campaign_count")
    return {
        "rows": campaign_rows(data)[:CAMPAIGNS_SHOWN],
        # Raw and text together, for the reason `_evidence_number` records: a
        # tile gating on `_num_text(0)` would be gating on a truthy string.
        "hours": hours,
        "hours_text": _num_text(hours),
        "count": count,
        "count_text": _num_text(count),
    }


def _proposal_card(row: dict[str, Any]) -> dict[str, Any]:
    """One proposal as the board's card, out of de_proposals' own row.

    `proposal_row` is what /de-proposals renders a table row from, so the
    change type, the status and the outcome have one definition across the two
    pages. Its `actions` and `mitre` keys are deliberately unused: this board
    is a summary with a link to the full one, and it has never offered a
    decision button.

    `note` is the measurement and `expected` is the forecast, kept apart and
    labelled. The JavaScript meant to show the measurement and could not: it
    read `p.outcome_json.fp_reduction_pct`, and the row carries the column as
    `outcome` with the comparable figure at `comparable.drop_pct`, so the
    measured branch never ran and an applied proposal with a real measurement
    showed its forecast instead.
    """
    outcome = row.get("outcome_view") or {}
    kind = outcome.get("kind")
    note = None
    if kind == "quoted" and outcome.get("drop_pct") is not None:
        note = f"measured −{outcome['drop_text']}% FP"
    elif kind == "legacy":
        legacy = outcome.get("legacy_drop_text")
        note = (
            f"legacy −{legacy}% FP, uneven windows"
            if outcome.get("legacy_drop_pct") is not None
            else "legacy measurement, no figure"
        )
    elif kind == "insufficient":
        note = "not enough observation yet"
    elif kind == "no_percentage":
        note = "no baseline to quote a percentage against"
    elif kind == "unjudged":
        note = "comparable window not judged"
    elif kind == "unmeasured":
        note = "not yet measured"
    return {
        "change_type": row.get("change_type"),
        # The JavaScript's `p.rule_name || p.title`. A proposal with no rule is
        # titled instead, and a proposal with neither renders the dash rather
        # than the word "None".
        "label": row.get("rule_name") or row.get("title"),
        "note": note,
        "expected": (
            f"exp. −{row['fp_text']}% FP"
            if row.get("expected_fp_reduction") is not None
            else None
        ),
    }


def _proposals_view(rows: object) -> dict[str, Any]:
    """The three columns, their depths, and the in-flight count.

    Every column is sliced for display and counted before the slice, which is
    what the JavaScript did: the heading says how many there are and the column
    shows as many as fit. The KPI counts draft plus applied, unsliced.
    """
    if not isinstance(rows, list):
        raise TypeError("detection proposals returned no list")
    grouped: dict[str, list[dict[str, Any]]] = {
        _DRAFT_STATUS: [],
        _APPLIED_STATUS: [],
        _REJECTED_STATUS: [],
    }
    for raw in rows:
        row = proposal_row(raw)
        bucket = grouped.get(row.get("status"))
        if bucket is not None:
            bucket.append(row)
    draft = grouped[_DRAFT_STATUS]
    applied = grouped[_APPLIED_STATUS]
    rejected = grouped[_REJECTED_STATUS]
    return {
        "draft": [_proposal_card(p) for p in draft],
        "applied": [_proposal_card(p) for p in applied[:APPLIED_SHOWN]],
        "rejected": [_proposal_card(p) for p in rejected[:REJECTED_SHOWN]],
        "draft_count": len(draft),
        "applied_count": len(applied),
        "rejected_count": len(rejected),
        "in_flight": len(draft) + len(applied),
    }


def _quirk_due(row: dict[str, Any], now: datetime) -> Optional[dict[str, Any]]:
    """One quirk's due-list entry, or None when it is not due inside the window.

    A quirk with no review date is not due. `review_date` is mandatory on
    creation, so an absent one means a row that predates the rule or one read
    back unparseably, and neither is a review somebody has to do this week.

    `overdue` is `SystemQuirk.is_expired()`, carried on the row by `to_dict`.
    It is not recomputed: the JavaScript compared a UTC-stored instant parsed
    as local time against the browser's clock, so it disagreed with
    `quirk_match` by the viewer's offset and showed a lapsed quirk as still
    pending review.

    `due_text` is the distance to the review, which the JavaScript could not
    express: `ageOf()` on a future date always returned "1h".
    """
    review = row.get("review_date")
    if not isinstance(review, datetime):
        return None
    if review - now >= QUIRK_WINDOW:
        return None
    overdue = row.get("expired") is True
    return {
        "title": row.get("title"),
        "review_date": review,
        "overdue": overdue,
        "due_text": None if overdue else _due_text(review - now),
    }


def _due_text(remaining: timedelta) -> str:
    """How long until a review is due, in the units the row has room for."""
    seconds = remaining.total_seconds()
    if seconds <= 0:
        # Past its review date but `is_expired()` said otherwise, which only
        # happens if the two were read a moment apart. Say due rather than
        # pick a side.
        return "due now"
    days = int(seconds // 86400)
    if days >= 1:
        return f"{days}d out"
    hours = int(seconds // 3600)
    if hours >= 1:
        return f"{hours}h out"
    return "<1h out"


def _quirks_view(rows: object) -> dict[str, Any]:
    """The quirks due for review, soonest first, and the two KPI figures.

    The rows are `de_quirks._row`, so the status pill, the scope chips and the
    parse of `review_date` have one definition across the two pages. Only the
    title and the review date are shown here.
    """
    if not isinstance(rows, list):
        raise TypeError("system quirks returned no list")
    now = _now()
    active = [quirk_row(q) for q in rows]
    due = [d for d in (_quirk_due(r, now) for r in active) if d is not None]
    due.sort(key=lambda d: d["review_date"])
    return {
        "rows": due[:QUIRKS_SHOWN],
        "due_count": len(due),
        "active_count": len(active),
    }


def _render(
    request: Request, name: str, context: dict[str, Any]
) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name=name, context=context)


#: Both gates, in the order the JSON side resolves them, written once so all
#: five routes carry the same pair and the order cannot be right on four of
#: them and wrong on the fifth. The order is the whole point: the module gate
#: first means an unlicensed deployment answers 404 before authentication is
#: considered, and a 401 would confirm the feature exists.
DE_GATES = [Depends(require_de_module), Depends(require_permission(PERMISSION))]


@router.get(
    "/de-workbench/requests", response_class=HTMLResponse, dependencies=DE_GATES
)
def de_workbench_requests_fragment(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The tuning-request queue and the open-request tile.

    Calls `tuning_requests_payload`, which is now the whole body of GET
    /api/de/tuning-requests, so the page and the API cannot disagree about
    which requests are in the queue or which of them is oldest. That query was
    inline in the route; the status filter, the ordering and the limit were the
    part worth sharing.
    """
    from ion.web.de_api import tuning_requests_payload

    can_propose = bool(
        current_user and current_user.has_permission(PROPOSE_PERMISSION)
    )
    try:
        view = _requests_view(
            tuning_requests_payload(session), can_propose=can_propose
        )
    except Exception:
        logger.exception("DE workbench tuning requests could not be read")
        return _render(request, _REQUESTS_FRAGMENT, {"failed": True, "view": None})
    return _render(request, _REQUESTS_FRAGMENT, {"failed": False, "view": view})


@router.get(
    "/de-workbench/campaigns", response_class=HTMLResponse, dependencies=DE_GATES
)
def de_workbench_campaigns_fragment(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The costliest noise campaigns and the addressable-hours tile.

    Calls `get_de_metrics`, which is the whole body of GET /api/de/metrics, at
    the same 30-day window the page has always fetched.
    """
    from ion.services.de_metrics_service import get_de_metrics

    can_propose = bool(
        current_user and current_user.has_permission(PROPOSE_PERMISSION)
    )
    try:
        view = _campaigns_view(get_de_metrics(session, days=CAMPAIGN_DAYS))
    except Exception:
        logger.exception("DE workbench noise campaigns could not be read")
        return _render(
            request,
            _CAMPAIGNS_FRAGMENT,
            {"failed": True, "view": None, "can_propose": can_propose,
             "days": CAMPAIGN_DAYS},
        )
    return _render(
        request,
        _CAMPAIGNS_FRAGMENT,
        {"failed": False, "view": view, "can_propose": can_propose,
         "days": CAMPAIGN_DAYS},
    )


@router.get(
    "/de-workbench/proposals", response_class=HTMLResponse, dependencies=DE_GATES
)
def de_workbench_proposals_fragment(
    request: Request, session: Session = Depends(get_db_session)
) -> HTMLResponse:
    """The three-column proposal board and the in-flight tile.

    Calls `de_proposal_service.list_proposals` unfiltered, which is the whole
    body of GET /api/de/proposals with its default filters, because the board
    groups every status itself.
    """
    from ion.services.de_proposal_service import list_proposals

    try:
        view = _proposals_view(list_proposals(session))
    except Exception:
        logger.exception("DE workbench proposal board could not be read")
        return _render(request, _PROPOSALS_FRAGMENT, {"failed": True, "view": None})
    return _render(request, _PROPOSALS_FRAGMENT, {"failed": False, "view": view})


@router.get(
    "/de-workbench/quirks", response_class=HTMLResponse, dependencies=DE_GATES
)
def de_workbench_quirks_fragment(
    request: Request, session: Session = Depends(get_db_session)
) -> HTMLResponse:
    """The quirks due for review and the quirks-due tile.

    Calls `de_quirk_service.list_quirks` with the same `active` filter the page
    has always fetched, which is the whole body of GET
    /api/de/quirks?status=active.
    """
    from ion.services.de_quirk_service import list_quirks

    try:
        view = _quirks_view(
            list_quirks(session, status=SystemQuirkStatus.ACTIVE.value)
        )
    except Exception:
        logger.exception("DE workbench quirks due for review could not be read")
        return _render(request, _QUIRKS_FRAGMENT, {"failed": True, "view": None})
    return _render(request, _QUIRKS_FRAGMENT, {"failed": False, "view": view})


@router.get(
    "/de-workbench/content-pack",
    response_class=HTMLResponse,
    dependencies=DE_GATES,
)
def de_workbench_content_pack_fragment(
    request: Request, current_user: User = Depends(get_current_user)
) -> HTMLResponse:
    """The content-pack controls, which read nothing and so cannot fail a read.

    This is a fragment only because the Import control has to be withheld from
    a viewer who does not hold the permission POST
    /api/de/content-pack/import checks, and /de renders its template with no
    user in the context. Export is a GET gated on the same permission as this
    fragment, so every viewer who can see this can use it.
    """
    return _render(
        request,
        _CONTENT_PACK_FRAGMENT,
        {
            "can_propose": bool(
                current_user and current_user.has_permission(PROPOSE_PERMISSION)
            )
        },
    )
