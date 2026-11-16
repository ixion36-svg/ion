"""The Job Scheduler cards, history, handler form and cron preview.

Replaces the twelve innerHTML writes in scheduler.html: the job-card grid
and its loading, empty and failure states; the execution history and its
three states; the handler ``<select>`` options; the typed settings inputs;
and the cron preview line. ``schEsc()`` went with them.

The fragment is not licence-gated. ``fragment_plan.py`` reads the gates off
the live application, and every URL this page fetches
(``GET /api/scheduler/jobs``, ``/handlers``, ``/preview-schedule``,
``/jobs/{id}/executions``) is ``require_permission("system:settings")`` and
nothing else. The scheduler router is mounted with no ``require_de_module``.
Copying that gate from the detection-engineering fragments would 404 the
scheduler on a deployment that is not licensed for that module, while
``/scheduler`` and ``/api/scheduler`` kept answering. A fragment must not be
a harder way in than the API it mirrors either.

``require_permission``, not ``require_page_permission``. The page itself is
``require_page_auth``, which redirects to ``/login``, and htmx would swap
that form into the panel. The fragment matches the JSON endpoint, which is
the stricter of the two and the one that actually returns the rows.

``last_status`` and an execution's ``status`` are ``String`` columns, not
``SQLEnum``. ``plain`` is applied anyway: the JSON endpoint handed the
script a string because FastAPI serialises a str-mixin enum by value, and a
template does not. ``str(member)`` on Python 3.12 is the repr.

The cron preview is the one timestamp that must not go through the ``ts``
macro. The expression is evaluated in UTC, and the line is labelled with
the timezone the service reports. ``ts`` on an aware instant sets
``data-ts-local="yes"``, and ``local-time.js`` then rewrites the digits
onto the viewer's clock while the label still says UTC. That is the bug
the old ``toLocaleString({timeZone: "UTC"})`` was written to avoid.

No stored URL is rendered. The only links are literal paths plus an integer
job id, so ``safe_url`` has no site here.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

#: What GET /api/scheduler/jobs names, and every other read this page does.
#: One spelling so a fragment cannot drift into being a softer way in.
PERMISSION = "system:settings"

#: How many history rows the page asked for. The JSON endpoint defaults to
#: the same number; this fragment has no limit control of its own.
_EXECUTION_LIMIT = 50

FRAGMENT = "_fragments/scheduler.html"

_GATES = [Depends(require_permission(PERMISSION))]


def _render(request: Request, **context: Any) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request, name=FRAGMENT, context=context
    )


def _status_text(raw: object) -> Optional[str]:
    """A status string, or None when nothing was recorded.

    ``plain`` unwraps an enum member before ``str()`` can turn it into
    ``JobStatus.ERROR``. Empty and whitespace-only are the same as absent:
    a blank is not a status called "running".
    """
    value = plain(raw)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _edit_payload(job: dict[str, Any]) -> dict[str, Any]:
    """The fields the edit form fills, and nothing it does not.

    ``enabled`` stays three-state. Folding None into false would open the
    dialog with Enabled set to No for a job whose flag was never read.
    """
    enabled = job.get("enabled")
    if enabled is True:
        enabled_out: Optional[bool] = True
    elif enabled is False:
        enabled_out = False
    else:
        enabled_out = None
    return {
        "id": job.get("id"),
        "name": job.get("name") or "",
        "cron_expr": job.get("cron_expr") or "",
        "handler_key": job.get("handler_key") or "",
        "description": job.get("description") or "",
        "params_json": job.get("params_json") or "",
        "enabled": enabled_out,
    }


def _job_view(job: dict[str, Any]) -> dict[str, Any]:
    """One job with the card class, badge and label already decided.

    The decision is ``is True`` / ``is False``, not truthiness. The string
    ``"yes"`` and a missing flag are neither enabled nor disabled, and a
    disabled job keeps that label even when its last run errored: the
    stripe says whether the job will fire, not how its previous fire went.
    An enabled job with no recorded status is ``pending``, which is what
    the JavaScript showed, and is a different claim from ``unknown``.
    """
    enabled = job.get("enabled")
    status = _status_text(job.get("last_status"))
    if enabled is True:
        if status == "error":
            card_cls, badge, label = "err", "badge-error", "error"
        elif status == "running":
            card_cls, badge, label = "run", "badge-warning", "running"
        else:
            card_cls, badge = "ok", "badge-success"
            label = status if status is not None else "pending"
    elif enabled is False:
        card_cls, badge, label = "off", "badge-ghost", "disabled"
    else:
        # No ``off`` class: that stripe is the disabled one, and unknown
        # is not disabled.
        card_cls, badge, label = "", "badge-ghost", "unknown"

    job_id = job.get("id")
    show = job_id is not None
    return {
        "id": job_id,
        "name": job.get("name") or "",
        "description": job.get("description") or "",
        "handler_key": job.get("handler_key") or "",
        "cron_expr": job.get("cron_expr") or "",
        "next_run_at": job.get("next_run_at"),
        "last_run_at": job.get("last_run_at"),
        "card_cls": card_cls,
        "badge_css": badge,
        "status_label": label,
        "show_actions": show,
        "edit": _edit_payload(job) if show else None,
    }


def _execution_view(row: dict[str, Any]) -> dict[str, Any]:
    """One history row. ``duration_ms`` is passed through, including 0.

    A run that finished in 0ms was measured. Dropping it on truthiness
    reads the same as a run whose duration was never written, and those
    are opposite facts about whether the handler returned.
    """
    status = _status_text(row.get("status"))
    if status == "success":
        card_cls, badge, label = "ok", "badge-success", "success"
    elif status == "error":
        card_cls, badge, label = "err", "badge-error", "error"
    elif status is not None:
        # ``running`` and any other recorded word. The word is kept; only
        # success and error have their own stripe. A missing status is not
        # this branch: calling it running would say a job is in progress.
        card_cls, badge, label = "run", "badge-warning", status
    else:
        card_cls, badge, label = "", "badge-ghost", "unknown"
    return {
        "status_label": label,
        "card_cls": card_cls,
        "badge_css": badge,
        "started_at": row.get("started_at"),
        "completed_at": row.get("completed_at"),
        "duration_ms": row.get("duration_ms"),
        "error_text": row.get("error_text") or "",
    }


def _handler_option(handler: dict[str, Any]) -> dict[str, str]:
    description = handler.get("description") or ""
    # One line. A newline inside an attribute is still an attribute, but
    # the description is a sentence and the select is a single row.
    description = " ".join(str(description).split())
    key = str(handler.get("key") or "")
    return {
        "key": key,
        "label": str(handler.get("label") or key),
        "description": description,
    }


def _parse_stored(raw: Optional[str]) -> tuple[Optional[dict], bool]:
    """``(mapping, unparseable)``.

    No stored JSON is not a parse failure: the handler's defaults are what
    the form should show. A present value that is not a JSON object is.
    Showing the defaults without saying so would let Save overwrite a
    corrupt-but-real configuration with the defaults, silently.
    """
    if raw is None or not str(raw).strip():
        return None, False
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return None, True
    if not isinstance(parsed, dict):
        return None, True
    return parsed, False


def _resolve_value(param: dict[str, Any], existing: Optional[dict]) -> object:
    """The value a field shows. A stored 0 or false beats the default.

    ``existing.get(name) or default`` turns a recorded 0 into the default
    and a recorded false into true. The key being present is the test,
    including when the stored value is None: that is "saved as empty",
    not "never saved, use the default".
    """
    name = param.get("name")
    if isinstance(existing, dict) and name in existing:
        return existing[name]
    return param.get("default")


def _parameter_view(
    param: dict[str, Any], existing: Optional[dict]
) -> Optional[dict[str, Any]]:
    name = param.get("name")
    if not name:
        return None
    kind = param.get("type") or "string"
    if kind not in ("integer", "boolean", "string"):
        kind = "string"
    return {
        "name": str(name),
        "label": str(param.get("label") or name),
        "type": kind,
        "help": str(param.get("help") or ""),
        # ``.get`` so a missing bound stays None and a bound of 0 stays 0.
        # ``or None`` would erase the 0, and the template would then drop
        # ``min="0"`` for lack of anything to render.
        "minimum": param.get("minimum"),
        "maximum": param.get("maximum"),
        "value": _resolve_value(param, existing),
    }


def _utc_clock(raw: object) -> Optional[str]:
    """``raw`` as a UTC wall clock, ``YYYY-MM-DD HH:MM``, or None.

    Aware values are converted to UTC first. Formatting the offset's own
    wall clock is how 08:00+01:00 gets printed beside a UTC label.
    A naive value is refused rather than labelled UTC: no zone was stated,
    and inventing one is the same move as printing 0 for an unmeasured
    figure. The caller skips None instead of showing a blank time.
    """
    if raw is None or raw == "":
        return None
    if isinstance(raw, datetime):
        moment = raw
    else:
        try:
            moment = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            return None
    if moment.tzinfo is None:
        return None
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M")


@router.get("/scheduler", response_class=HTMLResponse, dependencies=_GATES)
def scheduler_fragment(
    request: Request,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The job cards. Calls ``scheduler_service.list_jobs``, the whole body
    of GET /api/scheduler/jobs."""
    from ion.services.scheduler_service import list_jobs

    try:
        jobs = [_job_view(job) for job in list_jobs(session)]
    except Exception:
        logger.exception("Scheduler jobs fragment could not be rendered")
        return _render(request, view="jobs", jobs=None, failed=True)
    return _render(request, view="jobs", jobs=jobs, failed=False)


@router.get(
    "/scheduler/handlers", response_class=HTMLResponse, dependencies=_GATES
)
def scheduler_handlers_fragment(request: Request) -> HTMLResponse:
    """The ``<option>`` list. Calls ``describe_handlers``, which is the
    catalogue half of GET /api/scheduler/handlers and already covers every
    key ``list_handlers`` would return."""
    from ion.services.scheduler_service import describe_handlers

    try:
        handlers = [_handler_option(h) for h in describe_handlers()]
    except Exception:
        logger.exception("Scheduler handler catalogue could not be rendered")
        return _render(request, view="handlers", handlers=None, failed=True)
    return _render(request, view="handlers", handlers=handlers, failed=False)


@router.get(
    "/scheduler/params", response_class=HTMLResponse, dependencies=_GATES
)
def scheduler_params_fragment(
    request: Request,
    handler_key: str = "",
    params: Optional[str] = None,
) -> HTMLResponse:
    """Typed settings for one handler, or the marker that selects raw JSON.

    The metadata is ``describe_handlers`` again, the same call the options
    fragment makes, so the form and the dropdown cannot disagree about
    what a handler declares. An unknown key renders the raw marker rather
    than an error: a job can name a handler this process does not have
    loaded, and the JSON field is the only way to see what was stored.
    """
    from ion.services.scheduler_service import describe_handlers

    try:
        catalogue = describe_handlers()
    except Exception:
        logger.exception("Scheduler parameter form could not be rendered")
        return _render(
            request, view="params", mode="failed",
            parameters=None, stored_unreadable=False,
        )

    key = handler_key.strip()
    if not key:
        return _render(
            request, view="params", mode="unselected",
            parameters=None, stored_unreadable=False,
        )

    match = next((h for h in catalogue if h.get("key") == key), None)
    declared = (match or {}).get("parameters") or []
    if not isinstance(declared, list) or not declared:
        return _render(
            request, view="params", mode="raw",
            parameters=None, stored_unreadable=False,
        )

    stored, unreadable = _parse_stored(params)
    fields = [
        view for view in (_parameter_view(p, stored) for p in declared) if view
    ]
    return _render(
        request, view="params", mode="typed",
        parameters=fields, stored_unreadable=unreadable,
    )


@router.get(
    "/scheduler/preview", response_class=HTMLResponse, dependencies=_GATES
)
def scheduler_preview_fragment(
    request: Request,
    cron_expr: str = "",
    # 3, not the JSON endpoint's 5. The page asked for three firing times
    # and the preview line has room for three. Passing it through means the
    # service still does the clamping; this route does not grow a second copy.
    count: int = Query(3),
) -> HTMLResponse:
    """The plain-English schedule line. Calls ``preview_schedule``.

    A blank expression renders nothing, which is what an empty field means.
    An invalid expression renders the service's error. An exception is a
    third outcome and says the check did not run, so it cannot be read as
    "this expression is invalid".
    """
    from ion.services.scheduler_service import preview_schedule

    expr = cron_expr.strip()
    if not expr:
        return _render(
            request, view="preview", failed=False, preview=None, next_labels=[]
        )
    try:
        preview = preview_schedule(expr, count=count)
    except Exception:
        logger.exception("Scheduler preview could not be rendered")
        return _render(
            request, view="preview", failed=True, preview=None, next_labels=[]
        )

    verdict = preview.get("valid") if isinstance(preview, dict) else None
    if verdict is not True and verdict is not False:
        # A payload with no readable verdict is not a verdict. The template
        # renders neither branch for one, and a blank preview line beside a
        # filled-in field reads as "no objection", not as "not checked".
        # That is the same pair the exception branch above exists to keep
        # apart, so it takes the same answer.
        logger.error(
            "Scheduler preview returned no readable verdict: %r", preview
        )
        return _render(
            request, view="preview", failed=True, preview=None, next_labels=[]
        )

    labels = []
    if verdict is True:
        labels = [
            label for label in
            (_utc_clock(item) for item in (preview.get("next_runs") or []))
            if label
        ]
    return _render(
        request, view="preview", failed=False, preview=preview, next_labels=labels
    )


@router.get(
    "/scheduler/jobs/{job_id}/executions",
    response_class=HTMLResponse,
    dependencies=_GATES,
)
def scheduler_executions_fragment(
    request: Request,
    job_id: int,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """Recent runs of one job.

    ``get_job`` then ``list_executions``, in that order and with the same
    404 the JSON endpoint returns when the job is gone. An empty history
    and a missing job are different claims, and so is a history that could
    not be read. The job's name is resolved first so the failure fragment
    can still say which job it was; the Close button lives in the page
    shell, outside this swap target.
    """
    from ion.services.scheduler_service import get_job, list_executions

    try:
        job = get_job(session, job_id)
    except Exception:
        logger.exception(
            "Scheduler executions fragment could not load job %s", job_id
        )
        return _render(
            request, view="executions", failed=True,
            job_name=None, executions=None,
        )
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    name = job.get("name") or ""
    try:
        rows = [
            _execution_view(row)
            for row in list_executions(session, job_id, limit=_EXECUTION_LIMIT)
        ]
    except Exception:
        logger.exception(
            "Scheduler executions fragment could not list job %s", job_id
        )
        return _render(
            request, view="executions", failed=True,
            job_name=name, executions=None,
        )
    return _render(
        request, view="executions", failed=False,
        job_name=name, executions=rows,
    )
