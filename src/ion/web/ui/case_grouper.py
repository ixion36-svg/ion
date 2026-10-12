"""The case grouper's control panel, as one server-rendered fragment.

case_grouper.html used to fetch /api/case-grouper/status and build the whole
panel with `innerHTML`: the four stat tiles, the Last run table, the
side-effect badges and the flash line, 137 lines of inline JavaScript with a
hand-rolled `esc()` and a hand-rolled relative-time formatter. One request
renders all of it here, and Jinja escapes.

The honesty line this page has to hold is the difference between a figure of
zero and no figure at all. The grouper records a summary only after a pass
completes, so before the first pass there is no run to report, and six zeros
would claim a pass that scanned nothing and grouped nothing. The JavaScript
got this right by accident, with `s.last_result || {}` and `?? '—'`; a port
written with truthiness would turn every genuine zero into an em-dash and
every absent summary into a confident zero, in opposite directions on the
same table.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/case_grouper_status.html"

#: The Last run table: summary key, row label, and what the figure counts.
#: The order is stated here rather than taken from the recorded dict, because
#: a dict read back from the service's telemetry slot has whatever order the
#: pass that wrote it happened to use, and the table's reading order is a
#: decision about the page.
METRICS: tuple[tuple[str, str, str], ...] = (
    ("scanned", "Scanned", "open ES alerts considered"),
    ("grouped_new_cases", "New cases", "[Auto] cases opened"),
    ("grouped_extended_cases", "Extended cases",
     "open [Auto] cases appended to"),
    ("alerts_attached", "Alerts attached", "alerts put on a case"),
    ("investigations_queued", "Investigations queued",
     "autonomous investigations started"),
    ("errors", "Errors", "failures inside the pass"),
)


def metric_rows(result: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    """One row per figure of the last run, or None when there was no run.

    None is not an empty table and it is not a table of zeros. The grouper
    writes its summary into a telemetry slot after a pass finishes, so an
    absent summary means no pass has finished in this process. A pass that
    finished having scanned nothing is a different fact, and prints 0.

    A key missing from a recorded summary keeps its None and the template
    says the figure was not reported. Substituting 0 for it here is the one
    move that would make the table lie, because the reader cannot tell a
    stand-in from a count.
    """
    if result is None:
        return None
    return [
        {"label": label, "note": note, "value": result.get(key)}
        for key, label, note in METRICS
    ]


def error_note(result: dict[str, Any] | None) -> str | None:
    """The message from a pass that raised, if the recorded summary has one.

    `_tick` stores `error` alongside a summary of zeros when the pass itself
    blew up, and the JavaScript never showed it: the table rendered six
    zeros with no hint that they came from a crash rather than a quiet night.
    """
    if not result:
        return None
    message = result.get("error")
    return str(message) if message else None


@router.get(
    "/case-grouper/status",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("alert:triage"))],
)
def case_grouper_status_fragment(
    request: Request,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The whole panel body, as one fragment.

    It calls status_payload, the function /api/case-grouper/status calls, so
    the page and the API cannot disagree about whether the grouper is enabled
    or which side-effects are on. `alert:triage` matches that endpoint
    exactly; a fragment must not be a softer way in than the API it mirrors.
    """
    from ion.web.case_grouper_api import status_payload

    try:
        payload = status_payload(session)
    except Exception:
        logger.exception("Case grouper status fragment could not be rendered")
        # A failed read is not a grouper that scanned nothing. The fragment
        # says the read failed and prints no figure at all: "the last pass
        # grouped nothing" and "we could not read the grouper" lead to
        # opposite actions.
        return templates.TemplateResponse(
            request=request,
            name=FRAGMENT,
            context={"failed": True, "status": None, "metrics": None,
                     "error_note": None},
            status_code=200,
        )

    return templates.TemplateResponse(
        request=request,
        name=FRAGMENT,
        context={
            "failed": False,
            "status": payload,
            "metrics": metric_rows(payload.get("last_result")),
            "error_note": error_note(payload.get("last_result")),
        },
    )
