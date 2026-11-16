"""The investigation queue: sweep-loop state, queue depths, three tables.

investigation_queue.html built all three table bodies and each one's empty
state from template literals and wrote them into the tbodies with innerHTML
at six sites, across 280 lines of inline JavaScript carrying a hand-rolled
iqEscape(), a toLocaleString() formatter, a duration formatter and three
pill-colour tables.

Two things here are not a straight port.

`iqFetch()` caught a failed request and returned
`{running:[],pending:[],completed:[],failed:[]}`, so a queue nobody could
read rendered as "No active investigations." with four stat values of 0.
That is the one state this page must never fake: "nothing is waiting for
you" ends the shift, "we could not look" means the autonomous pipeline's
backlog is unknown. The same went for the loop: `iqLoadLoopStatus()`
returned on a non-OK response and left the button reading "Pause loop",
which asserts the loop is running.

And the per-row Cancel button was rendered from a status comparison written
out again in the page. It is derived from the service's own
CANCELLABLE_STATUSES here, and withheld from a viewer who does not hold the
permission cancel_one checks, so the only way to learn the server would
refuse is no longer to click and read the error.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.investigation_api import (
    CANCELLABLE_STATUSES,
    investigation_jobs_payload,
    sweep_loop_paused,
)
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/investigation_queue.html"

#: Matches GET /api/investigate/jobs. Spelled here because investigation_api
#: states it inline on each route; test_the_fragment_permission_matches_the_
#: json_endpoint reads the permission back off that live route, so this
#: cannot drift from it without a test failing.
_PERM = "alert:read"

#: What pause, resume and cancel take. Every control this fragment renders
#: is one of those three, so a viewer holding only _PERM is shown none of
#: them rather than being handed a button the server answers with a 403.
_TRIAGE_PERM = "alert:triage"

#: The class names already in frontend/ion-pages.css, whose comment says the
#: rows could not be restyled "without changing the script". The script is
#: gone; the names stay, so the sheet reaches the rows it was written for.
_STATUS_PILL = {
    "pending": "iq-pill-pending",
    "running": "iq-pill-running",
    "completed": "iq-pill-completed",
    "failed": "iq-pill-failed",
}

_VERDICT_PILL = {
    "true_positive": "iq-pill-tp",
    "false_positive": "iq-pill-fp",
    "benign": "iq-pill-benign",
    "inconclusive": "iq-pill-inc",
}

_SEVERITY_PILL = {
    "low": "iq-pill-sev-low",
    "medium": "iq-pill-sev-medium",
    "high": "iq-pill-sev-high",
    "critical": "iq-pill-sev-critical",
}

#: An ES `_id` is too long for the column and the JavaScript sliced it to
#: this. The full value goes in the cell's title now, because a 16-character
#: prefix is not what the manual-trigger box above the table wants.
_REF_CHARS = 16

#: A completed row's summary is prose and a failed row's is the error that
#: stopped it, which is why the JavaScript kept more of the second.
_SUMMARY_CHARS = 240
_ERROR_CHARS = 400


def _duration(ms: object) -> Optional[str]:
    """A run time as text, or None when none was recorded.

    `is not none`, not truthiness: 0 ms is a measurement, and the interesting
    one, because an investigation that returned instantly answered from cache
    or refused. The JavaScript's `ms == null` got this right, so a truthiness
    port would be a regression rather than a port.
    """
    if ms is None:
        return None
    if ms < 1000:
        return f"{ms} ms"
    seconds = ms / 1000
    if seconds < 60:
        return f"{seconds:.1f}s"
    return f"{int(seconds // 60)}m {round(seconds % 60)}s"


def _clip(text: object, limit: int) -> Optional[str]:
    """The first `limit` characters, or None when there is no text at all.

    None rather than "" so the template can tell "no summary was recorded"
    from a summary that happens to be empty.
    """
    if text is None:
        return None
    value = str(text)
    return value[:limit] if value else None


def _pill(raw: object, table: dict[str, str]) -> tuple[Optional[str], str]:
    """A column's text and its pill class.

    plain() on the way in because each of these three columns feeds a
    colour-map lookup and visible text at once. All three are String columns
    today, so nothing here carries an enum member; the unwrap is routed
    through ui._shared.plain anyway because if one is ever tightened to
    SQLEnum, value equality keeps the colour correct while the pill starts
    reading "InvestigationStatus.RUNNING". That is the failure that survives
    a glance, and two earlier conversions hit it independently.
    """
    value = plain(raw)
    if value is None:
        return None, ""
    text = str(value)
    return text, table.get(text, "")


def _active_row(inv: dict, *, can_triage: bool) -> dict[str, Any]:
    """One running or pending row, with its Cancel button decided."""
    status, pill = _pill(inv.get("status"), _STATUS_PILL)
    row = dict(inv)
    row.update(
        {
            "status_text": status if status is not None else "unknown",
            # The JavaScript's `|| "iq-pill-pending"`: an unrecognised status
            # still gets a pill rather than unstyled text.
            "status_pill": pill or "iq-pill-pending",
            "ref_short": _clip(inv.get("alert_id_ref"), _REF_CHARS),
            # Derived from the service, not restated. cancel_one's UPDATE is
            # bound to CANCELLABLE_STATUSES and gated on _TRIAGE_PERM, and
            # both halves are checked here, so a button that appears is one
            # the server would accept.
            "can_cancel": can_triage and status in CANCELLABLE_STATUSES,
        }
    )
    return row


def _completed_row(inv: dict) -> dict[str, Any]:
    verdict, verdict_pill = _pill(inv.get("verdict"), _VERDICT_PILL)
    severity, severity_pill = _pill(
        inv.get("severity_assessment"), _SEVERITY_PILL
    )
    row = dict(inv)
    row.update(
        {
            # str.replace changes every underscore where JavaScript's
            # replace("_", " ") changed only the first. Every verdict in the
            # vocabulary has one, so this is the same text today and the
            # right text if a two-underscore verdict is ever added.
            "verdict_text": verdict.replace("_", " ") if verdict else None,
            "verdict_pill": verdict_pill or "iq-pill-inc",
            "severity_text": severity,
            "severity_pill": severity_pill or "iq-pill-sev-low",
            "duration_text": _duration(inv.get("duration_ms")),
            "summary_short": _clip(inv.get("summary_text"), _SUMMARY_CHARS),
        }
    )
    return row


def _failed_row(inv: dict) -> dict[str, Any]:
    row = dict(inv)
    row.update(
        {
            # A run that failed before completed_at was stamped still has a
            # created_at, and the JavaScript used it. Without the fallback
            # the rows most worth a timestamp would carry none.
            "when": inv.get("completed_at") or inv.get("created_at"),
            "ref_short": _clip(inv.get("alert_id_ref"), _REF_CHARS),
            "summary_short": _clip(inv.get("summary_text"), _ERROR_CHARS),
        }
    )
    return row


def _jobs_view(payload: dict, *, can_triage: bool) -> dict[str, Any]:
    """The four buckets as the fragment needs them, with their depths.

    Running before pending in one table, which is the order the JavaScript's
    spread produced: a job that is working is never below one that has not
    started.
    """
    buckets = {
        key: list(payload.get(key) or ())
        for key in ("running", "pending", "completed", "failed")
    }
    return {
        "counts": {key: len(rows) for key, rows in buckets.items()},
        "active": [
            _active_row(inv, can_triage=can_triage)
            for inv in buckets["running"] + buckets["pending"]
        ],
        "completed": [_completed_row(inv) for inv in buckets["completed"]],
        "failed": [_failed_row(inv) for inv in buckets["failed"]],
    }


@router.get("/investigation-queue", response_class=HTMLResponse)
def investigation_queue_fragment(
    request: Request,
    user: User = Depends(require_permission(_PERM)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The loop banner, the four depths and the three tables as one fragment.

    It calls investigation_jobs_payload() and sweep_loop_paused(), which are
    what GET /api/investigate/jobs and GET /api/investigate/loop/status call,
    so neither the four status filters nor the flag's text coercion exists
    twice.

    There is no per-caller scope to carry: the payload takes no user and
    filters on status alone, so every analyst holding alert:read sees the
    whole queue. Inventing one here would hide rows the API returns.

    The two reads are caught separately. A flag-table hiccup must not be
    reported as "the queue could not be read", because the queue is the
    page; and a queue that read fine must still not claim the loop is
    running when that read failed.
    """
    # Resolved before the try, so a permission lookup can never be reported
    # as a queue that could not be read.
    can_triage = user.has_permission(_TRIAGE_PERM)

    jobs: Optional[dict] = None
    jobs_failed = False
    try:
        jobs = _jobs_view(investigation_jobs_payload(), can_triage=can_triage)
    except Exception:
        logger.exception("Investigation queue could not be read")
        jobs_failed = True

    # Three states on purpose: True paused, False running, None a read that
    # failed. The JavaScript had two, and treated the third as running.
    loop_paused: Optional[bool] = None
    try:
        loop_paused = sweep_loop_paused(session)
    except Exception:
        logger.exception("Investigation sweep-loop state could not be read")

    return templates.TemplateResponse(
        request=request,
        name=FRAGMENT,
        context={
            "jobs": jobs,
            "jobs_failed": jobs_failed,
            "loop_paused": loop_paused,
            "can_triage": can_triage,
        },
    )
