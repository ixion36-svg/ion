"""Analytics: the job panels.

analytics.html draws eleven panels from one read. `GET /api/analytics/jobs`
returns every analytics job with its last stored result, and a
`renderX(job)` function turns each one into a table.

All eleven opened with the same line:

    if (!job || !job.result) { container.innerHTML =
        '<div class="empty-state">No data yet. Click "Run All Jobs" to
        generate.</div>'; return; }

which is three different situations wearing one sentence. The job type is
not registered at all; the job is registered and has never run; and the job
has run and stored a result this page cannot read. Only the second is
answered by clicking Run All Jobs.

Then each one collapsed the next outcome in the same way, `job.result.rules
|| []`, `|| offenders`, `|| entities`, `|| stale_cases`, and rendered a
reassurance for it. "No stale investigations found. All items have recent
activity" is a sentence an analyst stops reading on, and a payload we could
not parse produced it.

Smaller things the same read turned up:

  * `c.severity || 'medium'` paints an alert whose severity is missing as
    medium, in a severity badge.
  * `c.days_stale > 7 ? 'danger' : 'warn'` is false for undefined, so a
    case with no staleness figure was painted as the milder state and then
    labelled "undefinedd".
  * `timeAgo(iso)` is `Date.now() - new Date(iso).getTime()` over
    isoformat() of a naive UTC column, so every elapsed time on the page
    was out by the viewer's offset. Sixth page with that one, and the first
    where it skews a duration rather than a timestamp.

Permissions. Every analytics endpoint is bare authentication, with no named
permission, while the page route is gated on `alert:read` (server.py:1303).
So these fragments take the page's permission: stricter than the endpoint,
never softer. The two mutations in that module, PATCH /jobs/{job_type} and
POST /jobs/{job_type}/run, are bare auth as well, which means any
authenticated account can disable an analytics job or change its schedule.
That is an authorisation gap rather than a rendering one and is filed
separately; nothing here widens or narrows it.
"""
from __future__ import annotations

import logging
from typing import Any, Optional, TypedDict

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import age_label, instant_label, plain, render_view

logger = logging.getLogger(__name__)

router = APIRouter()

#: What the page route requires. The endpoints require only a session.
PERMISSION = "alert:read"

#: The severities the badge has a colour for. One outside this set keeps
#: its own text under `unknown`, where the page painted it as medium.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")

#: Days stale at which the figure is drawn as urgent rather than a warning.
#: From `c.days_stale > 7 ? 'danger' : 'warn'`.
STALE_DANGER_DAYS = 7


class JobState(TypedDict):
    """What happened to one analytics job, in the four answers it has.

    "missing"    no job of this type is registered
    "never_run"  registered, never run, so Run All Jobs is the answer
    "unreadable" it ran and stored something this page cannot read
    "ok"         it ran and the result is readable
    """

    state: str
    job_type: Optional[str]
    display_name: Optional[str]
    last_run: Optional[str]
    last_run_age: Optional[str]
    last_error: Optional[str]


def job_state(job: Any) -> JobState:
    """The job's own condition, separately from whatever it produced."""
    if not isinstance(job, dict):
        return {"state": "missing", "job_type": None, "display_name": None,
                "last_run": None, "last_run_age": None, "last_error": None}
    job_type = plain(job.get("job_type"))
    name = plain(job.get("display_name"))
    error = plain(job.get("last_error"))
    result = job.get("result")
    if result is None:
        state = "never_run"
    elif isinstance(result, dict):
        state = "ok"
    else:
        state = "unreadable"
    return {
        "state": state,
        "job_type": str(job_type) if job_type is not None else None,
        "display_name": str(name) if name is not None else None,
        "last_run": instant_label(job.get("last_run_at")),
        "last_run_age": age_label(job.get("last_run_at")),
        "last_error": str(error) if error else None,
    }


def result_rows(job: Any, key: str) -> Optional[list]:
    """The list under `key` of a job's result, or None when we cannot read
    it.

    None is the outcome every panel was missing. `job.result.rules || []`
    turned a result of the wrong shape into an empty list, and each panel
    then rendered a sentence saying there was nothing to report.
    """
    if not isinstance(job, dict):
        return None
    result = job.get("result")
    if not isinstance(result, dict):
        return None
    rows = result.get(key)
    if not isinstance(rows, list):
        return None
    return rows


def severity_key(value: Any) -> str:
    """The stylesheet's key for a severity, or `unknown`.

    `c.severity || 'medium'` put an alert with no severity in the middle of
    the scale, which is a claim about how urgent it is.
    """
    marking = plain(value)
    if marking is None or str(marking) == "":
        return "unknown"
    text = str(marking)
    return text if text in SEVERITIES else "unknown"


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _text(value: Any) -> Optional[str]:
    plainest = plain(value)
    return str(plainest) if plainest is not None else None


class StaleRow(TypedDict):
    """One stale case or alert.

    `days` is None when the figure is missing, where the page printed
    "undefinedd" and painted the row as the milder of its two states.
    """

    reference: Optional[str]
    title: Optional[str]
    severity_key: str
    severity_label: Optional[str]
    assigned: Optional[str]
    last_activity: Optional[str]
    days: Optional[int]
    urgent: Optional[bool]


class StaleView(TypedDict):
    job: JobState
    cases: Optional[list[StaleRow]]
    alerts: Optional[list[StaleRow]]


def stale_row(raw: Any, *, reference_key: str) -> Optional[StaleRow]:
    if not isinstance(raw, dict):
        return None
    days = _int(raw.get("days_stale"))
    severity = raw.get("severity")
    assigned = _text(raw.get("assigned_to"))
    return {
        "reference": _text(raw.get(reference_key)),
        "title": _text(raw.get("title")),
        "severity_key": severity_key(severity),
        "severity_label": _text(severity),
        # "Unassigned" is a fact about the row; a missing field is not.
        "assigned": assigned if assigned is not None else None,
        "last_activity": age_label(raw.get("last_activity")),
        "days": days,
        # None rather than False: `days > 7` was false for undefined, so a
        # row with no figure was drawn as the milder state.
        "urgent": None if days is None else days > STALE_DANGER_DAYS,
    }


def stale_view(job: Any) -> StaleView:
    cases = result_rows(job, "stale_cases")
    alerts = result_rows(job, "stale_alerts")
    return {
        "job": job_state(job),
        "cases": (None if cases is None else
                  [r for r in (stale_row(c, reference_key="case_number")
                               for c in cases) if r is not None]),
        "alerts": (None if alerts is None else
                   [r for r in (stale_row(a, reference_key="alert_id")
                                for a in alerts) if r is not None]),
    }


def _one_job(job_type: str, current_user: User, session: Session) -> Any:
    """One job and its stored result, from the endpoint's own handler.

    The page read every job in one request and handed each panel its own.
    A panel asking for its own job is the same data, and it lets a panel
    whose job is missing or unreadable say so without the other ten
    inheriting it.

    The handler raises 404 for a job type that is not registered, which is
    the `missing` state rather than an error: job_state(None) answers it.
    """
    from fastapi import HTTPException

    from ion.web.analytics_api import get_analytics_job

    try:
        return get_analytics_job(
            job_type, current_user=current_user, session=session)
    except HTTPException as refusal:
        if refusal.status_code == 404:
            return None
        raise


@router.get(
    "/analytics/stale",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def analytics_stale_fragment(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The stale investigations panel."""
    try:
        job = _one_job("stale_investigations", current_user, session)
    except Exception:
        logger.exception("Analytics stale fragment could not read its job")
        job = None
    return render_view(request, "_fragments/analytics_stale.html",
                       stale_view(job))
